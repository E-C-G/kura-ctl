// Package web sert l'interface de la console sur 127.0.0.1, au seul éditeur.
//
// Sécurité (specs §9) : écoute locale uniquement, contrôle de l'en-tête Host (contre
// le DNS rebinding), mot de passe maître à chaque démarrage, une seule session à la
// fois, cookie HttpOnly SameSite=Strict, jeton CSRF sur chaque formulaire, en-têtes
// de sécurité stricts (CSP sans script en ligne), verrouillage après inactivité.
// La clé d'administration ne vit qu'en mémoire tant que la console est déverrouillée.
package web

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"errors"
	"html/template"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/E-C-G/kura-ctl/internal/jobs"
	"github.com/E-C-G/kura-ctl/internal/secrets"
	"github.com/E-C-G/kura-ctl/internal/store"
	"github.com/E-C-G/kura-ctl/internal/wasabi"
)

//go:embed templates/*.html
var templateFS embed.FS

//go:embed static
var staticFS embed.FS

const (
	cookieName = "kura_session"
	// DefaultIdle : verrouillage après 30 min sans activité.
	DefaultIdle = 30 * time.Minute
	// RefreshEvery : actualisation automatique tant que la console est ouverte.
	RefreshEvery = 24 * time.Hour
)

// Server est l'interface web de la console.
type Server struct {
	Store      *store.Store
	Vault      *secrets.Vault
	NewAccount func(wasabi.Keys) jobs.Account // défaut : wasabi.NewClient
	Log        *slog.Logger
	Idle       time.Duration
	Version    string
	Now        func() time.Time

	mu        sync.Mutex
	hosts     map[string]bool // valeurs admises de l'en-tête Host
	sess      *session
	open      *unlocked
	failures  int
	lockUntil time.Time
	pages     map[string]*template.Template
}

type session struct {
	token    string
	csrf     string
	lastSeen time.Time
}

// unlocked : ce qui n'existe que console déverrouillée.
type unlocked struct {
	account jobs.Account
	runner  *jobs.Runner
	cancel  context.CancelFunc
}

func (s *Server) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// Listen ouvre l'écoute sur 127.0.0.1 (port 0 : port libre) et fixe les valeurs
// admises de l'en-tête Host.
func (s *Server) Listen(port string) (net.Listener, error) {
	ln, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", port))
	if err != nil {
		return nil, err
	}
	_, p, _ := net.SplitHostPort(ln.Addr().String())
	s.mu.Lock()
	s.hosts = map[string]bool{"127.0.0.1:" + p: true, "localhost:" + p: true}
	s.mu.Unlock()
	return ln, nil
}

// Handler renvoie le routeur complet.
func (s *Server) Handler() (http.Handler, error) {
	if s.NewAccount == nil {
		s.NewAccount = func(k wasabi.Keys) jobs.Account { return wasabi.NewClient(k) }
	}
	if s.Idle == 0 {
		s.Idle = DefaultIdle
	}
	if s.Log == nil {
		s.Log = slog.Default()
	}
	if err := s.parseTemplates(); err != nil {
		return nil, err
	}
	static, _ := fs.Sub(staticFS, "static")
	mux := http.NewServeMux()
	mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServerFS(static)))
	mux.HandleFunc("GET /setup", s.setupPage)
	mux.HandleFunc("POST /setup", s.setupSubmit)
	mux.HandleFunc("GET /unlock", s.unlockPage)
	mux.HandleFunc("POST /unlock", s.unlockSubmit)

	app := http.NewServeMux()
	app.HandleFunc("GET /{$}", s.overview)
	app.HandleFunc("POST /lock", s.lockSubmit)
	app.HandleFunc("POST /refresh", s.refresh)
	app.HandleFunc("GET /buckets", s.bucketsPage)
	app.HandleFunc("POST /buckets/import", s.importBucket)
	app.HandleFunc("GET /buckets/{name}", s.bucketPage)
	app.HandleFunc("POST /buckets/{name}/audit", s.auditBucket)
	app.HandleFunc("GET /api/usage", s.usageJSON)
	app.HandleFunc("GET /audit", s.auditPage)
	app.HandleFunc("GET /settings", s.settingsPage)
	app.HandleFunc("POST /settings", s.settingsSubmit)
	app.HandleFunc("POST /settings/password", s.passwordSubmit)
	mux.Handle("/", s.requireSession(app))
	return s.guard(mux), nil
}

// guard : contrôle de l'hôte et de l'origine, en-têtes de sécurité.
func (s *Server) guard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		okHost := s.hosts[r.Host]
		s.mu.Unlock()
		if !okHost {
			// Une page d'un autre site qui ferait pointer un nom de domaine vers
			// 127.0.0.1 (DNS rebinding) arrive avec un autre Host : refusée.
			http.Error(w, "hôte non autorisé", http.StatusMisdirectedRequest)
			return
		}
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; form-action 'self'; base-uri 'none'")
		h.Set("X-Frame-Options", "DENY")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cache-Control", "no-store")
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			if o := r.Header.Get("Origin"); o != "" && o != "http://"+r.Host {
				http.Error(w, "origine refusée", http.StatusForbidden)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

type ctxKey struct{}

// requireSession : console configurée, déverrouillée, session valide, CSRF sur POST.
func (s *Server) requireSession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if ok, err := s.Vault.Exists(); err != nil {
			s.fail(w, r, err)
			return
		} else if !ok {
			redirect(w, r, "/setup")
			return
		}
		c, err := r.Cookie(cookieName)
		s.mu.Lock()
		sess := s.sess
		valid := err == nil && sess != nil && subtle.ConstantTimeCompare([]byte(c.Value), []byte(sess.token)) == 1
		expired := valid && s.now().Sub(sess.lastSeen) > s.Idle
		if valid && !expired {
			sess.lastSeen = s.now()
		}
		s.mu.Unlock()
		if expired {
			s.lock("inactivité")
		}
		if !valid || expired {
			redirect(w, r, "/unlock")
			return
		}
		if r.Method == http.MethodPost {
			tok := r.Header.Get("X-CSRF-Token")
			if tok == "" {
				tok = r.PostFormValue("csrf")
			}
			if subtle.ConstantTimeCompare([]byte(tok), []byte(sess.csrf)) != 1 {
				http.Error(w, "jeton de formulaire invalide : recharger la page", http.StatusForbidden)
				return
			}
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxKey{}, sess)))
	})
}

func randomToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

// startSession déverrouille la console avec la clé donnée : session, client Wasabi,
// tâches de fond.
func (s *Server) startSession(w http.ResponseWriter, k secrets.Keys) {
	s.lock("nouvelle session")
	acc := s.NewAccount(wasabi.Keys{AccessKeyID: k.AccessKeyID, SecretAccessKey: k.SecretAccessKey})
	ctx, cancel := context.WithCancel(context.Background())
	runner := &jobs.Runner{Store: s.Store, Account: acc, Template: wasabi.Standard, Log: s.Log, Now: s.Now}
	sess := &session{token: randomToken(), csrf: randomToken(), lastSeen: s.now()}
	s.mu.Lock()
	s.sess = sess
	s.open = &unlocked{account: acc, runner: runner, cancel: cancel}
	s.mu.Unlock()
	go runner.Loop(ctx, RefreshEvery)
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: sess.token, Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode})
}

// lock referme la console : la clé et le client Wasabi sont oubliés.
func (s *Server) lock(reason string) {
	s.mu.Lock()
	open := s.open
	had := s.sess != nil
	s.open, s.sess = nil, nil
	s.mu.Unlock()
	if open != nil {
		open.cancel()
	}
	if had {
		s.Log.Info("console verrouillée", "raison", reason)
	}
}

// Watch verrouille la console après inactivité, même sans requête.
func (s *Server) Watch(ctx context.Context) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			s.lock("arrêt")
			return
		case <-t.C:
			s.mu.Lock()
			idle := s.sess != nil && s.now().Sub(s.sess.lastSeen) > s.Idle
			s.mu.Unlock()
			if idle {
				s.lock("inactivité")
			}
		}
	}
}

func (s *Server) current() *unlocked {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.open
}

func sessionOf(r *http.Request) *session {
	sess, _ := r.Context().Value(ctxKey{}).(*session)
	return sess
}

// redirect : avec htmx, HX-Redirect fait recharger la page entière.
func redirect(w http.ResponseWriter, r *http.Request, to string) {
	if r.Header.Get("HX-Request") == "true" {
		w.Header().Set("HX-Redirect", to)
		w.WriteHeader(http.StatusNoContent)
		return
	}
	http.Redirect(w, r, to, http.StatusSeeOther)
}

func (s *Server) fail(w http.ResponseWriter, r *http.Request, err error) {
	s.Log.Error("requête", "chemin", r.URL.Path, "err", err)
	http.Error(w, "erreur : "+err.Error(), http.StatusInternalServerError)
}

// throttle : 1 s par échec de mot de passe, puis 60 s de blocage après 5 échecs.
func (s *Server) throttle() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.now().Before(s.lockUntil) {
		return errors.New("trop d'essais : réessayer dans une minute")
	}
	return nil
}

func (s *Server) passwordFailed() {
	time.Sleep(time.Second)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failures++
	if s.failures >= 5 {
		s.failures = 0
		s.lockUntil = s.now().Add(time.Minute)
	}
}

func (s *Server) passwordOK() {
	s.mu.Lock()
	s.failures = 0
	s.mu.Unlock()
}

func trim(r *http.Request, k string) string { return strings.TrimSpace(r.PostFormValue(k)) }

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
	"sync/atomic"
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
	NewAccount func(wasabi.Keys) Wasabi // défaut : wasabi.NewClient
	Log        *slog.Logger
	Idle       time.Duration
	Version    string
	Now        func() time.Time
	// PlainHost : servir sur 127.0.0.1 seulement, sans nom d'hôte aléatoire (navigateur
	// qui ne résout pas les sous-domaines de localhost).
	PlainHost bool
	// Kit : composants du kit d'installation (kura-agent, CLI AWS) ; nil : kit
	// indisponible, le paquet .kura reste téléchargeable seul.
	Kit KitSource

	mu         sync.Mutex
	hosts      map[string]bool // valeurs admises de l'en-tête Host
	url        string          // adresse à ouvrir
	sess       *session
	open       *unlocked
	failures   int
	lockouts   int
	lockUntil  time.Time
	pages      map[string]*template.Template
	attempt    sync.Mutex  // un seul essai de mot de passe à la fois
	configured atomic.Bool // coffre présent (évite de lire le trousseau à chaque requête)
	bucketMu   sync.Map    // nom du bucket → *sync.Mutex (écritures IAM une à la fois)
}

type session struct {
	token    string
	csrf     string
	lastSeen time.Time
	flash    string // message affiché une fois, à la page suivante
}

// Wasabi est le compte vu par la console : lectures (lot 1) et écritures (lot 2).
type Wasabi interface {
	jobs.Account
	wasabi.Admin
}

// unlocked : ce qui n'existe que console déverrouillée. ctx est annulé au
// verrouillage : toute tâche qui détient la clé en dérive.
type unlocked struct {
	account Wasabi
	runner  *jobs.Runner
	ctx     context.Context
	cancel  context.CancelFunc

	mu    sync.Mutex
	id    *wasabi.Identity // identité de la clé, une fois connue
	idErr error
	idAt  time.Time
	packs map[string]*pendingPack // paquets .kura à télécharger, par jeton
	once  map[string]time.Time    // jetons de formulaire à usage unique
}

// newOnce crée un jeton de formulaire à usage unique (valable 1 h).
func (o *unlocked) newOnce() string {
	t := randomToken()
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.once == nil {
		o.once = map[string]time.Time{}
	}
	for k, at := range o.once {
		if time.Since(at) > time.Hour {
			delete(o.once, k)
		}
	}
	o.once[t] = time.Now()
	return t
}

// useOnce consomme un jeton : vrai la première fois seulement.
func (o *unlocked) useOnce(t string) bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	at, ok := o.once[t]
	delete(o.once, t)
	return ok && t != "" && time.Since(at) <= time.Hour
}

// pendingPack est un paquet généré, téléchargeable une fois tant que la console
// reste déverrouillée (30 min au plus).
type pendingPack struct {
	bucket, keyID, file string
	data                []byte
	expires             time.Time      // fin du téléchargement possible
	validUntil          time.Time      // fin de validité du paquet sur le poste
	install             bool           // paquet d'installation complète : kit zip possible
	platform            store.Platform // système du poste, pour le kit
	busy                bool           // kit en préparation : ni second kit, ni .kura seul
}

// identity : utilisateur IAM de la clé d'administration (mis en cache ; un échec
// est retenté après une minute).
func (o *unlocked) identity(ctx context.Context) (wasabi.Identity, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.id != nil {
		return *o.id, nil
	}
	if o.idErr != nil && time.Since(o.idAt) < time.Minute {
		return wasabi.Identity{}, o.idErr
	}
	id, err := o.account.Identity(ctx)
	o.idAt = time.Now()
	if err != nil {
		o.idErr = err
		return wasabi.Identity{}, err
	}
	o.id, o.idErr = &id, nil
	return id, nil
}

func (s *Server) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// Listen ouvre l'écoute sur 127.0.0.1 (port 0 : port libre) et fixe les valeurs
// admises de l'en-tête Host.
//
// Par défaut, la console est servie sous un nom aléatoire (kura-<aléa>.localhost,
// que les navigateurs résolvent vers 127.0.0.1) : un cookie ne tient pas compte du
// port, et un cookie posé pour 127.0.0.1 serait envoyé à tout autre service local
// (serveur de développement, page d'un autre utilisateur de la machine…). Sous un
// nom que personne d'autre ne connaît, le cookie de session ne part que vers la console.
func (s *Server) Listen(port string) (net.Listener, error) {
	ln, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", port))
	if err != nil {
		return nil, err
	}
	_, p, _ := net.SplitHostPort(ln.Addr().String())
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.PlainHost {
		s.hosts = map[string]bool{"127.0.0.1:" + p: true}
		s.url = "http://127.0.0.1:" + p + "/"
	} else {
		host := "kura-" + randomToken()[:16] + ".localhost:" + p
		s.hosts = map[string]bool{host: true}
		s.url = "http://" + host + "/"
	}
	return ln, nil
}

// bucketLock : verrou des écritures sur les clés d'un bucket.
func (s *Server) bucketLock(name string) *sync.Mutex {
	m, _ := s.bucketMu.LoadOrStore(name, &sync.Mutex{})
	return m.(*sync.Mutex)
}

// URL renvoie l'adresse de la console (après Listen).
func (s *Server) URL() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.url
}

// Handler renvoie le routeur complet.
func (s *Server) Handler() (http.Handler, error) {
	if s.NewAccount == nil {
		s.NewAccount = func(k wasabi.Keys) Wasabi { return wasabi.NewClient(k) }
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
	app.HandleFunc("POST /buckets/creer", s.createBucket)
	app.HandleFunc("GET /buckets/{name}", s.bucketPage)
	app.HandleFunc("POST /buckets/{name}/audit", s.auditBucket)
	app.HandleFunc("GET /api/usage", s.usageJSON)
	app.HandleFunc("GET /audit", s.auditPage)
	app.HandleFunc("GET /settings", s.settingsPage)
	app.HandleFunc("POST /settings", s.settingsSubmit)
	app.HandleFunc("POST /settings/password", s.passwordSubmit)
	app.HandleFunc("POST /settings/admin-key", s.adminKeySubmit)
	app.HandleFunc("GET /buckets/{name}/corriger/{what}", s.fixPreview)
	app.HandleFunc("POST /buckets/{name}/corriger/{what}", s.fixApply)
	app.HandleFunc("POST /buckets/{name}/cles", s.createKey)
	app.HandleFunc("GET /buckets/{name}/paquet/{token}", s.downloadPack)
	app.HandleFunc("POST /buckets/{name}/cles/{id}/{action}", s.keyAction)
	app.HandleFunc("GET /buckets/{name}/poste", s.postePage)
	app.HandleFunc("POST /buckets/{name}/poste", s.posteSubmit)
	app.HandleFunc("GET /buckets/{name}/kit/{token}", s.downloadKit)
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
		// same-origin, pas no-referrer : avec no-referrer, le navigateur envoie
		// « Origin: null » sur les formulaires, indiscernable d'une origine étrangère.
		h.Set("Referrer-Policy", "same-origin")
		h.Set("Cache-Control", "no-store")
		if r.Method != http.MethodGet && r.Method != http.MethodHead && !sameOrigin(r) {
			s.Log.Warn("requête d'une autre origine refusée", "chemin", r.URL.Path,
				"origin", r.Header.Get("Origin"), "sec-fetch-site", r.Header.Get("Sec-Fetch-Site"))
			http.Error(w, "origine refusée", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// sameOrigin : une requête qui modifie quelque chose doit venir des pages de la
// console. Les navigateurs récents envoient Sec-Fetch-Site ; tous envoient Origin
// sur un POST. Sans aucun des deux (client hors navigateur), le jeton CSRF et le
// mot de passe restent exigés.
func sameOrigin(r *http.Request) bool {
	switch r.Header.Get("Sec-Fetch-Site") {
	case "", "same-origin":
	default: // same-site (autre port de localhost…), cross-site, none
		return false
	}
	o := r.Header.Get("Origin")
	return o == "" || o == "http://"+r.Host
}

type ctxKey struct{}

// requireSession : console configurée, déverrouillée, session valide, CSRF sur POST.
func (s *Server) requireSession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.configured.Load() {
			ok, err := s.Vault.Exists()
			if err != nil {
				s.fail(w, r, err)
				return
			}
			if !ok {
				redirect(w, r, "/setup")
				return
			}
			s.configured.Store(true)
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
			s.lockIf(sess, "inactivité")
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
// tâches de fond. L'éventuelle session précédente est remplacée et annulée dans la
// même section critique : deux déverrouillages simultanés ne laissent pas de tâche
// orpheline qui garderait la clé.
func (s *Server) startSession(w http.ResponseWriter, k secrets.Keys, flash string) {
	acc := s.NewAccount(wasabi.Keys{AccessKeyID: k.AccessKeyID, SecretAccessKey: k.SecretAccessKey})
	ctx, cancel := context.WithCancel(context.Background())
	runner := &jobs.Runner{Store: s.Store, Account: acc, Template: wasabi.Standard, Log: s.Log, Now: s.Now}
	sess := &session{token: randomToken(), csrf: randomToken(), lastSeen: s.now(), flash: flash}
	s.mu.Lock()
	old, hadSess := s.open, s.sess != nil
	s.sess = sess
	s.open = &unlocked{account: acc, runner: runner, ctx: ctx, cancel: cancel, packs: map[string]*pendingPack{}}
	s.mu.Unlock()
	if old != nil {
		old.cancel()
	}
	if hadSess {
		s.Log.Info("session précédente fermée", "raison", "nouvelle session")
	}
	go runner.Loop(ctx, RefreshEvery)
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: sess.token, Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode})
}

// lock referme la console : le client Wasabi est abandonné et les tâches en cours
// sont annulées.
func (s *Server) lock(reason string) { s.lockIf(nil, reason) }

// lockIf ne referme que si la session courante est encore sess (nil : quelle qu'elle
// soit) : une session tout juste ouverte n'est pas fermée par l'expiration de la
// précédente.
func (s *Server) lockIf(sess *session, reason string) {
	s.mu.Lock()
	if sess != nil && s.sess != sess {
		s.mu.Unlock()
		return
	}
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

// flash garde un message pour la prochaine page de la session de r.
func (s *Server) flash(r *http.Request, msg string) {
	if sess := sessionOf(r); sess != nil {
		s.mu.Lock()
		sess.flash = msg
		s.mu.Unlock()
	}
}

// takeFlash renvoie et efface le message en attente.
func (s *Server) takeFlash(sess *session) string {
	if sess == nil {
		return ""
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	m := sess.flash
	sess.flash = ""
	return m
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

// errThrottled : trop d'essais de mot de passe.
var errThrottled = errors.New("trop d'essais : réessayer plus tard")

// tryPassword déchiffre le coffre avec un mot de passe. Les essais passent un par
// un (même envoyés en parallèle) : 1 s d'attente après chaque échec, puis blocage
// après 5 échecs, d'une minute la première fois et doublé à chaque fois (1 h au plus).
func (s *Server) tryPassword(pw string) (secrets.Keys, error) {
	s.attempt.Lock()
	defer s.attempt.Unlock()
	s.mu.Lock()
	blocked := s.now().Before(s.lockUntil)
	s.mu.Unlock()
	if blocked {
		return secrets.Keys{}, errThrottled
	}
	k, err := s.Vault.Unlock(pw)
	switch {
	case errors.Is(err, secrets.ErrWrongPassword):
		time.Sleep(time.Second)
		s.mu.Lock()
		s.failures++
		if s.failures >= 5 {
			s.failures = 0
			d := time.Minute << min(s.lockouts, 6)
			s.lockouts++
			s.lockUntil = s.now().Add(min(d, time.Hour))
		}
		s.mu.Unlock()
	case err == nil:
		s.mu.Lock()
		s.failures, s.lockouts = 0, 0
		s.mu.Unlock()
	}
	return k, err
}

func trim(r *http.Request, k string) string { return strings.TrimSpace(r.PostFormValue(k)) }

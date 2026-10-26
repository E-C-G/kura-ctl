package web

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"net/http"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/E-C-G/kura-ctl/internal/jobs"
	"github.com/E-C-G/kura-ctl/internal/secrets"
	"github.com/E-C-G/kura-ctl/internal/store"
	"github.com/E-C-G/kura-ctl/internal/wasabi"
)

// Réglages de la console (table settings).
const (
	setPrice    = "price_per_tb"
	setCurrency = "currency"
)

func (s *Server) parseTemplates() error {
	funcs := template.FuncMap{
		"bytes": func(b int64) string { return frNum(jobs.HumanBytes(b)) },
		"tb":    func(f float64) string { return strings.Replace(fmt.Sprintf("%.3f", f), ".", ",", 1) },
		"money": func(f float64, cur string) string {
			return strings.Replace(fmt.Sprintf("%.2f", f), ".", ",", 1) + " " + cur
		},
		"date":     func(t time.Time) string { return dateFR(t) },
		"datetime": func(t time.Time) string { return dateTimeFR(t) },
		"sevclass": func(s string) string { return "sev-" + strings.NewReplacer("é", "e", " ", "-").Replace(s) },
		"retention": func(o wasabi.ObjectLock) string {
			if !o.Enabled {
				return "désactivé"
			}
			m := map[string]string{"GOVERNANCE": "gouvernance", "COMPLIANCE": "conformité"}[o.Mode]
			if m == "" {
				return "activé, sans rétention par défaut"
			}
			return fmt.Sprintf("activé, %s %d j", m, o.Days)
		},
	}
	pages, err := fs.Glob(templateFS, "templates/*.html")
	if err != nil {
		return err
	}
	s.pages = map[string]*template.Template{}
	for _, p := range pages {
		name := path.Base(p)
		if name == "layout.html" {
			continue
		}
		t, err := template.New("layout.html").Funcs(funcs).ParseFS(templateFS, "templates/layout.html", p)
		if err != nil {
			return fmt.Errorf("gabarit %s : %w", name, err)
		}
		s.pages[strings.TrimSuffix(name, ".html")] = t
	}
	return nil
}

func frNum(s string) string { return strings.Replace(s, ".", ",", 1) }

var monthsFR = []string{"janv.", "févr.", "mars", "avr.", "mai", "juin", "juil.", "août", "sept.", "oct.", "nov.", "déc."}

func dateFR(t time.Time) string {
	if t.IsZero() {
		return "—"
	}
	t = t.Local()
	return fmt.Sprintf("%d %s %d", t.Day(), monthsFR[t.Month()-1], t.Year())
}

func dateTimeFR(t time.Time) string {
	if t.IsZero() {
		return "—"
	}
	return dateFR(t) + " " + t.Local().Format("15:04")
}

// view est passé à tous les gabarits.
type view struct {
	Title   string
	Nav     string
	CSRF    string
	Version string
	Error   string
	Notice  string
	Data    any
}

func (s *Server) render(w http.ResponseWriter, r *http.Request, page string, v view) {
	t, ok := s.pages[page]
	if !ok {
		http.Error(w, "page inconnue", http.StatusInternalServerError)
		return
	}
	if sess := sessionOf(r); sess != nil {
		v.CSRF = sess.csrf
		if v.Notice == "" {
			v.Notice = s.takeFlash(sess)
		}
	}
	v.Version = s.Version
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := t.Execute(w, v); err != nil {
		s.Log.Error("rendu", "page", page, "err", err)
	}
}

func (s *Server) pricing(ctx context.Context) jobs.Pricing {
	p, _ := s.Store.Setting(ctx, setPrice, "6.99")
	c, _ := s.Store.Setting(ctx, setCurrency, "$")
	f, err := strconv.ParseFloat(p, 64)
	if err != nil || f <= 0 {
		f = 6.99
	}
	return jobs.Pricing{PerTB: f, Currency: c}
}

// --- premier lancement et déverrouillage ---------------------------------------

func (s *Server) setupPage(w http.ResponseWriter, r *http.Request) {
	ok, err := s.Vault.Exists()
	switch {
	case err != nil:
		s.render(w, r, "setup", view{Title: "Première configuration", Error: err.Error()})
		return
	case ok:
		redirect(w, r, "/unlock")
		return
	}
	s.render(w, r, "setup", view{Title: "Première configuration"})
}

func (s *Server) setupSubmit(w http.ResponseWriter, r *http.Request) {
	// Trousseau en erreur : on ne sait pas si un coffre existe, on n'écrase rien.
	if ok, err := s.Vault.Exists(); err != nil {
		s.render(w, r, "setup", view{Title: "Première configuration", Error: err.Error()})
		return
	} else if ok {
		http.Error(w, "console déjà configurée", http.StatusConflict)
		return
	}
	pw, pw2 := r.PostFormValue("password"), r.PostFormValue("password2")
	k := secrets.Keys{AccessKeyID: trim(r, "access_key_id"), SecretAccessKey: trim(r, "secret_access_key")}
	price := strings.Replace(trim(r, "price"), ",", ".", 1)
	again := func(msg string) {
		s.render(w, r, "setup", view{Title: "Première configuration", Error: msg,
			Data: map[string]string{"AccessKeyID": k.AccessKeyID, "Price": trim(r, "price")}})
	}
	switch {
	case pw != pw2:
		again("Les deux mots de passe diffèrent.")
		return
	case secrets.CheckPassword(pw) != nil:
		again(secrets.CheckPassword(pw).Error())
		return
	case k.Valid() != nil:
		again(k.Valid().Error())
		return
	}
	if f, err := strconv.ParseFloat(price, 64); err != nil || f <= 0 {
		again("Prix au To invalide.")
		return
	}
	if err := s.Vault.Probe(); err != nil {
		again(err.Error())
		return
	}
	// La clé doit fonctionner avant d'être rangée : liste des buckets (lecture seule).
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	if _, err := s.NewAccount(wasabi.Keys{AccessKeyID: k.AccessKeyID, SecretAccessKey: k.SecretAccessKey}).ListBuckets(ctx); err != nil {
		again("Wasabi refuse cette clé : " + err.Error())
		return
	}
	if err := s.Vault.Store(pw, k); err != nil {
		again(err.Error())
		return
	}
	_ = s.Store.SetSetting(r.Context(), setPrice, price)
	_ = s.Store.SetSetting(r.Context(), setCurrency, "$")
	s.configured.Store(true)
	_ = s.Store.Audit(r.Context(), "configuration initiale", "console", store.ResultOK, "clé d'administration "+maskKey(k.AccessKeyID))
	s.startSession(w, k, "Console configurée. Importez vos buckets.")
	redirect(w, r, "/buckets")
}

func (s *Server) unlockPage(w http.ResponseWriter, r *http.Request) {
	if ok, err := s.Vault.Exists(); err != nil {
		s.render(w, r, "unlock", view{Title: "Déverrouiller", Error: err.Error()})
		return
	} else if !ok {
		redirect(w, r, "/setup")
		return
	}
	s.render(w, r, "unlock", view{Title: "Déverrouiller"})
}

func (s *Server) unlockSubmit(w http.ResponseWriter, r *http.Request) {
	k, err := s.tryPassword(r.PostFormValue("password"))
	switch {
	case errors.Is(err, secrets.ErrNotSetUp):
		s.configured.Store(false)
		redirect(w, r, "/setup")
		return
	case errors.Is(err, secrets.ErrWrongPassword):
		_ = s.Store.Audit(r.Context(), "déverrouillage", "console", store.ResultError, "mot de passe incorrect")
		s.render(w, r, "unlock", view{Title: "Déverrouiller", Error: "Mot de passe incorrect."})
		return
	case err != nil:
		s.render(w, r, "unlock", view{Title: "Déverrouiller", Error: err.Error()})
		return
	}
	_ = s.Store.Audit(r.Context(), "déverrouillage", "console", store.ResultOK, "")
	s.startSession(w, k, "")
	redirect(w, r, "/")
}

func (s *Server) lockSubmit(w http.ResponseWriter, r *http.Request) {
	s.lock("demande de l'utilisateur")
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteStrictMode})
	redirect(w, r, "/unlock")
}

func maskKey(id string) string {
	if len(id) <= 6 {
		return "…"
	}
	return id[:4] + "…" + id[len(id)-2:]
}

// --- vue d'ensemble ----------------------------------------------------------------

type overviewData struct {
	jobs.Overview
	Pricing jobs.Pricing
	Report  jobs.Report
}

func (s *Server) overview(w http.ResponseWriter, r *http.Request) {
	p := s.pricing(r.Context())
	ov, err := jobs.BuildOverview(r.Context(), s.Store, p, s.now())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if len(ov.Buckets) == 0 {
		redirect(w, r, "/buckets")
		return
	}
	var rep jobs.Report
	if o := s.current(); o != nil {
		rep = o.runner.Last()
	}
	s.render(w, r, "overview", view{Title: "Vue d'ensemble", Nav: "overview", Data: overviewData{Overview: ov, Pricing: p, Report: rep}})
}

func (s *Server) refresh(w http.ResponseWriter, r *http.Request) {
	o := s.current()
	if o == nil {
		redirect(w, r, "/unlock")
		return
	}
	go func() {
		if _, err := o.runner.Refresh(o.ctx); err != nil && !errors.Is(err, jobs.ErrBusy) {
			s.Log.Warn("actualisation", "err", err)
		}
	}()
	back := r.PostFormValue("back")
	if !strings.HasPrefix(back, "/") || strings.HasPrefix(back, "//") {
		back = "/"
	}
	redirect(w, r, back)
}

// --- buckets -------------------------------------------------------------------------

type bucketsData struct {
	Imported   []jobs.BucketSummary
	Available  []wasabi.BucketInfo
	Clients    []store.Client
	ListError  string
	SuggestFor map[string]string
}

func (s *Server) bucketsPage(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	ov, err := jobs.BuildOverview(ctx, s.Store, s.pricing(ctx), s.now())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	d := bucketsData{Imported: ov.Buckets, SuggestFor: map[string]string{}}
	d.Clients, _ = s.Store.Clients(ctx)
	if o := s.current(); o != nil {
		lctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		all, err := o.account.ListBuckets(lctx)
		cancel()
		if err != nil {
			d.ListError = err.Error()
		}
		imported := map[string]bool{}
		for _, b := range ov.Buckets {
			imported[b.Name] = true
		}
		for _, b := range all {
			if !imported[b.Name] {
				d.Available = append(d.Available, b)
				// Suggestion de code client : ce qui précède le premier tiret (acme-srv01 → acme).
				if i := strings.IndexByte(b.Name, '-'); i > 0 {
					d.SuggestFor[b.Name] = b.Name[:i]
				}
			}
		}
	}
	s.render(w, r, "buckets", view{Title: "Buckets", Nav: "buckets", Data: d})
}

var codePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,19}$`)

func (s *Server) importBucket(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	o := s.current()
	if o == nil {
		redirect(w, r, "/unlock")
		return
	}
	name, client := trim(r, "bucket"), strings.ToLower(trim(r, "client_code"))
	clientName, poste := trim(r, "client_name"), trim(r, "poste")
	if !codePattern.MatchString(client) {
		s.flash(r, "Code client invalide : minuscules, chiffres et tirets, 20 caractères au plus.")
		redirect(w, r, "/buckets")
		return
	}
	if _, err := s.Store.Bucket(ctx, name); err == nil { // double clic, second onglet…
		redirect(w, r, "/buckets/"+name)
		return
	}
	if clientName == "" {
		clientName = client
	}
	// Le bucket doit exister dans le compte : on reprend sa région chez Wasabi.
	lctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	all, err := o.account.ListBuckets(lctx)
	cancel()
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var info *wasabi.BucketInfo
	for i := range all {
		if all[i].Name == name {
			info = &all[i]
		}
	}
	if info == nil || info.Err != "" {
		msg := "Bucket inconnu du compte Wasabi : " + name
		if info != nil {
			msg = "Région du bucket " + name + " illisible : " + info.Err
		}
		s.flash(r, msg)
		redirect(w, r, "/buckets")
		return
	}
	if err := s.Store.EnsureClient(ctx, store.Client{Code: client, Name: clientName}); err != nil {
		s.fail(w, r, err)
		return
	}
	err = s.Store.ImportBucket(ctx, store.Bucket{Name: info.Name, Region: info.Region, ClientCode: client, Poste: poste})
	result, detail := store.ResultOK, fmt.Sprintf("client %s, région %s", client, info.Region)
	if err != nil {
		result, detail = store.ResultError, err.Error()
	}
	_ = s.Store.Audit(ctx, "import du bucket", name, result, detail)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	// Relevé et collecte tout de suite, en arrière-plan (un an d'historique).
	// Interrompus si la console est verrouillée entre-temps (o.ctx).
	go func() {
		_ = o.runner.AuditBucket(o.ctx, info.Name, info.Region)
		_, _ = o.runner.CollectBucket(o.ctx, info.Name)
	}()
	s.flash(r, "Bucket importé : relevé des réglages et collecte d'un an d'usage en cours.")
	redirect(w, r, "/buckets/"+name)
}

type bucketData struct {
	jobs.BucketSummary
	Recent  []store.Usage
	Pricing jobs.Pricing
}

func (s *Server) bucketPage(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	name := r.PathValue("name")
	ov, err := jobs.BuildOverview(ctx, s.Store, s.pricing(ctx), s.now())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var d bucketData
	found := false
	for _, b := range ov.Buckets {
		if b.Name == name {
			d.BucketSummary, found = b, true
		}
	}
	if !found {
		http.NotFound(w, r)
		return
	}
	d.Pricing = s.pricing(ctx)
	now := s.now().UTC()
	d.Recent, _ = s.Store.UsageRange(ctx, name, now.AddDate(0, 0, -30).Format("2006-01-02"), now.Format("2006-01-02"))
	sort.Slice(d.Recent, func(i, j int) bool { return d.Recent[i].Day > d.Recent[j].Day })
	s.render(w, r, "bucket", view{Title: name, Nav: "buckets", Data: d})
}

func (s *Server) auditBucket(w http.ResponseWriter, r *http.Request) {
	o := s.current()
	if o == nil {
		redirect(w, r, "/unlock")
		return
	}
	b, err := s.Store.Bucket(r.Context(), r.PathValue("name"))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), time.Minute)
	defer cancel()
	msg := "Réglages relevés."
	if err := o.runner.AuditBucket(ctx, b.Name, b.Region); err != nil {
		msg = "Relevé incomplet : " + err.Error()
	}
	s.flash(r, msg)
	redirect(w, r, "/buckets/"+b.Name)
}

// usageJSON alimente les graphiques : ?bucket=<nom> (vide : tous), ?days=<n>.
func (s *Server) usageJSON(w http.ResponseWriter, r *http.Request) {
	days, _ := strconv.Atoi(r.URL.Query().Get("days"))
	if days <= 0 || days > 3660 {
		days = 365
	}
	now := s.now().UTC()
	rows, err := s.Store.UsageRange(r.Context(), r.URL.Query().Get("bucket"), now.AddDate(0, 0, -days).Format("2006-01-02"), now.Format("2006-01-02"))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	type point struct {
		Day     string  `json:"day"`
		Bucket  string  `json:"bucket"`
		Padded  float64 `json:"padded_gb"`
		Deleted float64 `json:"deleted_gb"`
		Raw     float64 `json:"raw_gb"`
	}
	out := make([]point, 0, len(rows))
	for _, u := range rows {
		const gib = 1 << 30 // Go de facturation Wasabi (1024³ octets)
		out = append(out, point{u.Day, u.Bucket, float64(u.PaddedBytes+u.MetadataBytes) / gib, float64(u.DeletedBytes) / gib, float64(u.ActiveBytes) / gib})
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}

// --- journal et réglages -------------------------------------------------------------

func (s *Server) auditPage(w http.ResponseWriter, r *http.Request) {
	log, err := s.Store.AuditLog(r.Context(), 500)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.render(w, r, "audit", view{Title: "Journal d'audit", Nav: "audit", Data: log})
}

func (s *Server) settingsPage(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, "settings", view{Title: "Réglages", Nav: "settings", Data: s.pricing(r.Context())})
}

func (s *Server) settingsSubmit(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	price := strings.Replace(trim(r, "price"), ",", ".", 1)
	cur := trim(r, "currency")
	if f, err := strconv.ParseFloat(price, 64); err != nil || f <= 0 || f > 1000 || cur == "" || len(cur) > 5 {
		s.render(w, r, "settings", view{Title: "Réglages", Nav: "settings", Error: "Prix ou devise invalide.", Data: s.pricing(ctx)})
		return
	}
	_ = s.Store.SetSetting(ctx, setPrice, price)
	_ = s.Store.SetSetting(ctx, setCurrency, cur)
	_ = s.Store.Audit(ctx, "réglages", "tarif", store.ResultOK, price+" "+cur+" par To et par mois")
	s.flash(r, "Réglages enregistrés.")
	redirect(w, r, "/settings")
}

func (s *Server) passwordSubmit(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	again := func(msg string) {
		s.render(w, r, "settings", view{Title: "Réglages", Nav: "settings", Error: msg, Data: s.pricing(ctx)})
	}
	k, err := s.tryPassword(r.PostFormValue("current"))
	if errors.Is(err, errThrottled) {
		again(err.Error())
		return
	}
	if err != nil {
		_ = s.Store.Audit(ctx, "changement du mot de passe maître", "console", store.ResultError, "mot de passe actuel incorrect")
		again("Mot de passe actuel incorrect.")
		return
	}
	pw, pw2 := r.PostFormValue("password"), r.PostFormValue("password2")
	if pw != pw2 {
		again("Les deux nouveaux mots de passe diffèrent.")
		return
	}
	if err := s.Vault.Store(pw, k); err != nil {
		again(err.Error())
		return
	}
	_ = s.Store.Audit(ctx, "changement du mot de passe maître", "console", store.ResultOK, "")
	s.flash(r, "Mot de passe maître changé.")
	redirect(w, r, "/settings")
}

package web

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/E-C-G/kura-ctl/internal/secrets"
	"github.com/E-C-G/kura-ctl/internal/store"
	"github.com/E-C-G/kura-ctl/internal/wasabi"
	"github.com/zalando/go-keyring"
)

type memKeyring struct {
	mu sync.Mutex
	m  map[string]string
}

func (k *memKeyring) Get(s, u string) (string, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	v, ok := k.m[s+u]
	if !ok {
		return "", keyring.ErrNotFound
	}
	return v, nil
}
func (k *memKeyring) Set(s, u, v string) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.m[s+u] = v
	return nil
}
func (k *memKeyring) Delete(s, u string) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	delete(k.m, s+u)
	return nil
}

// fakeAccount : compte Wasabi en mémoire (lectures, réglages, IAM).
type fakeAccount struct {
	mu       sync.Mutex
	keys     wasabi.Keys
	readOnly bool // la clé ne lit pas son identité IAM
	root     bool
	settings map[string]wasabi.Settings
	users    map[string]bool
	policies map[string]string
	akeys    map[string][]wasabi.AccessKey
	n        int
	writes   []string
}

func newFakeAccount(k wasabi.Keys) *fakeAccount {
	return &fakeAccount{keys: k, settings: map[string]wasabi.Settings{}, users: map[string]bool{},
		policies: map[string]string{}, akeys: map[string][]wasabi.AccessKey{}}
}

func (f *fakeAccount) ListBuckets(context.Context) ([]wasabi.BucketInfo, error) {
	if f.keys.SecretAccessKey == "mauvaise" {
		return nil, io.ErrUnexpectedEOF
	}
	return []wasabi.BucketInfo{{Name: "acme-srv01", Region: "eu-central-1", Created: time.Date(2025, 1, 2, 0, 0, 0, 0, time.UTC)}}, nil
}
func (f *fakeAccount) ReadSettings(_ context.Context, name, region string) wasabi.Settings {
	f.mu.Lock()
	defer f.mu.Unlock()
	st, ok := f.settings[name]
	if !ok {
		st = wasabi.Settings{Versioning: "Enabled",
			Lifecycle: wasabi.Lifecycle{Present: true, NoncurrentDays: 90}}
		f.settings[name] = st
	}
	st.Name, st.Region, st.ReadAt = name, region, time.Now()
	return st
}
func (f *fakeAccount) BucketDaily(_ context.Context, b, from, to string) ([]wasabi.DailyUsage, error) {
	return []wasabi.DailyUsage{{Day: to, PaddedBytes: 600 << 30, RawBytes: 590 << 30, Objects: 1234}}, nil
}
func (f *fakeAccount) Identity(context.Context) (wasabi.Identity, error) {
	switch {
	case f.readOnly:
		return wasabi.Identity{}, errors.New("accès refusé : la clé de la console n'a pas ce droit")
	case f.root:
		return wasabi.Identity{Arn: "arn:aws:iam::100000000042:root", AccountID: "100000000042"}, nil
	}
	return wasabi.Identity{Arn: "arn:aws:iam::100000000042:user/kura-ctl-admin", UserName: "kura-ctl-admin", AccountID: "100000000042"}, nil
}
func (f *fakeAccount) edit(bucket string, fn func(*wasabi.Settings) error) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	st := f.settings[bucket]
	if err := fn(&st); err != nil {
		return err
	}
	f.settings[bucket] = st
	return nil
}
func (f *fakeAccount) PutBucketPolicy(_ context.Context, bucket, _, doc string) error {
	f.writes = append(f.writes, "policy "+bucket)
	return f.edit(bucket, func(s *wasabi.Settings) error {
		s.Policy = wasabi.Policy{Present: true, DenyInsecureTransport: true, DenyVersionDeletion: true, Document: doc}
		return nil
	})
}
func (f *fakeAccount) PutLifecycle(_ context.Context, bucket, _ string, t wasabi.Template) error {
	f.writes = append(f.writes, "lifecycle "+bucket)
	return f.edit(bucket, func(s *wasabi.Settings) error {
		s.Lifecycle = wasabi.Lifecycle{Present: true, NoncurrentDays: t.NoncurrentDays, ExpiredDeleteMarker: t.ExpiredDeleteMarker, AbortMultipartDays: t.AbortMultipartDays}
		return nil
	})
}
func (f *fakeAccount) PutDefaultRetention(_ context.Context, bucket, _, mode string, days int) error {
	f.writes = append(f.writes, "retention "+bucket)
	return f.edit(bucket, func(s *wasabi.Settings) error {
		if !s.ObjectLock.Enabled {
			return errors.New("InvalidBucketState")
		}
		s.ObjectLock.Mode, s.ObjectLock.Days = mode, days
		return nil
	})
}
func (f *fakeAccount) EnsureUser(_ context.Context, name string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	created := !f.users[name]
	f.users[name] = true
	return created, nil
}
func (f *fakeAccount) PutUserPolicy(_ context.Context, user, name, doc string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.policies[user+"/"+name] = doc
	return nil
}
func (f *fakeAccount) CreateAccessKey(_ context.Context, user string) (wasabi.AccessKey, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.akeys[user]) >= 2 {
		return wasabi.AccessKey{}, errors.New("LimitExceeded")
	}
	f.n++
	k := wasabi.AccessKey{ID: fmt.Sprintf("AKIDPOSTE%04d", f.n), Secret: fmt.Sprintf("secret-poste-%04d", f.n), Active: true}
	f.akeys[user] = append(f.akeys[user], k)
	return k, nil
}
func (f *fakeAccount) ListAccessKeys(_ context.Context, user string) ([]wasabi.AccessKey, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []wasabi.AccessKey
	for _, k := range f.akeys[user] {
		k.Secret = ""
		out = append(out, k)
	}
	return out, nil
}
func (f *fakeAccount) SetAccessKeyActive(_ context.Context, user, id string, active bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i, k := range f.akeys[user] {
		if k.ID == id {
			f.akeys[user][i].Active = active
			return nil
		}
	}
	return errors.New("NoSuchEntity")
}
func (f *fakeAccount) DeleteAccessKey(_ context.Context, user, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	ks := f.akeys[user][:0]
	for _, k := range f.akeys[user] {
		if k.ID != id {
			ks = append(ks, k)
		}
	}
	f.akeys[user] = ks
	return nil
}
func (f *fakeAccount) AccessKeyLastUsed(context.Context, string) (time.Time, error) {
	return time.Time{}, nil
}

type harness struct {
	t      *testing.T
	srv    *Server
	h      http.Handler
	host   string
	cookie *http.Cookie
	st     *store.Store

	clock   sync.Mutex
	nowTime time.Time

	accMu    sync.Mutex
	accounts []*fakeAccount
	accHook  func(*fakeAccount)
}

// account crée le faux compte d'une clé et le garde pour les vérifications.
func (hn *harness) account(k wasabi.Keys) *fakeAccount {
	a := newFakeAccount(k)
	hn.accMu.Lock()
	defer hn.accMu.Unlock()
	if hn.accHook != nil {
		hn.accHook(a)
	}
	hn.accounts = append(hn.accounts, a)
	return a
}

// last : faux compte de la session en cours.
func (hn *harness) last() *fakeAccount {
	hn.accMu.Lock()
	defer hn.accMu.Unlock()
	return hn.accounts[len(hn.accounts)-1]
}

func (hn *harness) now() time.Time { hn.clock.Lock(); defer hn.clock.Unlock(); return hn.nowTime }
func (hn *harness) advance(d time.Duration) {
	hn.clock.Lock()
	hn.nowTime = hn.nowTime.Add(d)
	hn.clock.Unlock()
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "k.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	hn := &harness{t: t, st: st, nowTime: time.Date(2026, 10, 26, 10, 0, 0, 0, time.UTC)}
	st.SetClock(hn.now) // une seule horloge pour la console et la base
	hn.srv = &Server{
		Store: st, Vault: &secrets.Vault{Keyring: &memKeyring{m: map[string]string{}}, Iterations: 1000},
		NewAccount: func(k wasabi.Keys) Wasabi { return hn.account(k) },
		Log:        slog.New(slog.NewTextHandler(io.Discard, nil)),
		Now:        hn.now,
	}
	ln, err := hn.srv.Listen("0")
	if err != nil {
		t.Fatal(err)
	}
	hn.host = strings.TrimSuffix(strings.TrimPrefix(hn.srv.URL(), "http://"), "/")
	if !strings.HasPrefix(hn.host, "kura-") || !strings.Contains(hn.host, ".localhost:") {
		t.Fatalf("nom d'hôte aléatoire attendu : %s", hn.host)
	}
	ln.Close()
	if hn.h, err = hn.srv.Handler(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { hn.srv.lock("fin du test") })
	return hn
}

func (hn *harness) do(method, path string, form url.Values, hdr map[string]string) *httptest.ResponseRecorder {
	hn.t.Helper()
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	req := httptest.NewRequest(method, path, body)
	req.Host = hn.host
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	if hn.cookie != nil {
		req.AddCookie(hn.cookie)
	}
	rec := httptest.NewRecorder()
	hn.h.ServeHTTP(rec, req)
	for _, c := range rec.Result().Cookies() {
		if c.Name == cookieName {
			if c.MaxAge < 0 {
				hn.cookie = nil
			} else {
				hn.cookie = c
			}
		}
	}
	return rec
}

var csrfRe = regexp.MustCompile(`name="csrf" value="([0-9a-f]+)"`)

func (hn *harness) csrf(path string) string {
	hn.t.Helper()
	rec := hn.do("GET", path, nil, nil)
	m := csrfRe.FindStringSubmatch(rec.Body.String())
	if m == nil {
		hn.t.Fatalf("pas de jeton CSRF sur %s (%d) :\n%s", path, rec.Code, rec.Body.String())
	}
	return m[1]
}

func expectRedirect(t *testing.T, rec *httptest.ResponseRecorder, to string) {
	t.Helper()
	if rec.Code != http.StatusSeeOther || !strings.HasPrefix(rec.Header().Get("Location"), to) {
		t.Fatalf("redirection vers %s attendue, reçu %d %q\n%s", to, rec.Code, rec.Header().Get("Location"), rec.Body.String())
	}
}

func setupForm(pw, secret string) url.Values {
	return url.Values{"password": {pw}, "password2": {pw}, "access_key_id": {"AKIDADMIN"}, "secret_access_key": {secret}, "price": {"6,99"}}
}

func TestFullFlow(t *testing.T) {
	hn := newHarness(t)

	// En-tête Host d'un autre site (DNS rebinding), ou 127.0.0.1 hors --plain-host : refusé.
	_, port, _ := net.SplitHostPort(hn.host)
	for _, h := range []string{"evil.example:80", "127.0.0.1:" + port, "localhost:" + port} {
		req := httptest.NewRequest("GET", "/", nil)
		req.Host = h
		rec := httptest.NewRecorder()
		hn.h.ServeHTTP(rec, req)
		if rec.Code != http.StatusMisdirectedRequest {
			t.Fatalf("hôte %s : %d", h, rec.Code)
		}
	}
	var rec *httptest.ResponseRecorder

	expectRedirect(t, hn.do("GET", "/", nil, nil), "/setup")
	rec = hn.do("GET", "/setup", nil, nil)
	if !strings.Contains(rec.Header().Get("Content-Security-Policy"), "script-src 'self'") || rec.Header().Get("X-Frame-Options") != "DENY" {
		t.Fatalf("en-têtes de sécurité : %v", rec.Header())
	}
	if rec := hn.do("POST", "/setup", setupForm("court", "s"), nil); !strings.Contains(rec.Body.String(), "trop court") {
		t.Fatalf("mot de passe court accepté :\n%s", rec.Body.String())
	}
	if rec := hn.do("POST", "/setup", setupForm("un mot de passe solide", "mauvaise"), nil); !strings.Contains(rec.Body.String(), "Wasabi refuse cette clé") {
		t.Fatalf("clé refusée par Wasabi mais enregistrée :\n%s", rec.Body.String())
	}
	expectRedirect(t, hn.do("POST", "/setup", setupForm("un mot de passe solide", "SECRET"), nil), "/buckets")
	if hn.cookie == nil || !hn.cookie.HttpOnly || hn.cookie.SameSite != http.SameSiteStrictMode {
		t.Fatalf("cookie de session : %+v", hn.cookie)
	}
	if rec := hn.do("POST", "/setup", setupForm("un mot de passe solide", "SECRET"), nil); rec.Code != http.StatusConflict {
		t.Fatalf("seconde configuration acceptée : %d", rec.Code)
	}

	// Sans bucket importé, la vue d'ensemble renvoie vers l'import.
	expectRedirect(t, hn.do("GET", "/", nil, nil), "/buckets")
	rec = hn.do("GET", "/buckets", nil, nil)
	if !strings.Contains(rec.Body.String(), "acme-srv01") || !strings.Contains(rec.Body.String(), `value="acme"`) {
		t.Fatalf("bucket disponible non proposé :\n%s", rec.Body.String())
	}
	tok := hn.csrf("/buckets")
	imp := url.Values{"bucket": {"acme-srv01"}, "client_code": {"acme"}, "client_name": {"ACME"}, "poste": {"SRV01"}}
	if rec := hn.do("POST", "/buckets/import", imp, nil); rec.Code != http.StatusForbidden {
		t.Fatalf("import sans jeton CSRF : %d", rec.Code)
	}
	imp.Set("csrf", tok)
	for _, h := range []map[string]string{
		{"Origin": "http://evil.example"},
		{"Origin": "null"},
		{"Sec-Fetch-Site": "same-site", "Origin": "http://localhost:8888"},
		{"Sec-Fetch-Site": "cross-site"},
	} {
		if rec := hn.do("POST", "/buckets/import", imp, h); rec.Code != http.StatusForbidden {
			t.Fatalf("import depuis une autre origine %v : %d", h, rec.Code)
		}
	}
	if rp := hn.do("GET", "/buckets", nil, nil).Header().Get("Referrer-Policy"); rp == "no-referrer" {
		t.Fatal("no-referrer : les navigateurs enverraient « Origin: null » sur les formulaires")
	}
	// Comme un navigateur : Origin et Sec-Fetch-Site de la console elle-même.
	browser := map[string]string{"Origin": "http://" + hn.host, "Sec-Fetch-Site": "same-origin"}
	expectRedirect(t, hn.do("POST", "/buckets/import", imp, browser), "/buckets/acme-srv01")
	// Double clic : pas d'erreur, renvoi vers le bucket.
	expectRedirect(t, hn.do("POST", "/buckets/import", imp, nil), "/buckets/acme-srv01")
	if rec := hn.do("GET", "/buckets/acme-srv01", nil, nil); !strings.Contains(rec.Body.String(), "Bucket importé") {
		t.Fatalf("message après import absent :\n%s", rec.Body.String())
	}
	if rec := hn.do("GET", "/buckets/acme-srv01?ok=Ressaisissez+votre+cl%C3%A9", nil, nil); strings.Contains(rec.Body.String(), "Ressaisissez") {
		t.Fatal("message injecté par l'URL affiché")
	}
	b, err := hn.st.Bucket(context.Background(), "acme-srv01")
	if err != nil || b.Region != "eu-central-1" || b.ClientCode != "acme" {
		t.Fatalf("bucket importé : %+v %v", b, err)
	}
	// Relevé immédiat (synchrone ici, la collecte d'arrière-plan peut ne pas être finie).
	if rec := hn.do("POST", "/buckets/acme-srv01/audit", url.Values{"csrf": {tok}}, nil); rec.Code != http.StatusSeeOther {
		t.Fatalf("relevé : %d", rec.Code)
	}
	rec = hn.do("GET", "/buckets/acme-srv01", nil, nil)
	for _, want := range []string{"pas d&#39;Object Lock", "anciennes versions : 90 j", "SRV01"} {
		if !strings.Contains(rec.Body.String(), want) {
			t.Fatalf("page du bucket sans %q :\n%s", want, rec.Body.String())
		}
	}
	waitFor(t, func() bool { d, _ := hn.st.LastUsageDay(context.Background(), "acme-srv01"); return d != "" })
	rec = hn.do("GET", "/", nil, nil)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "minimum facturé") {
		t.Fatalf("vue d'ensemble : %d\n%s", rec.Code, rec.Body.String())
	}
	rec = hn.do("GET", "/api/usage?bucket=acme-srv01", nil, nil)
	if !strings.Contains(rec.Body.String(), `"padded_gb":600,`) {
		t.Fatalf("API d'usage : %s", rec.Body.String())
	}
	if rec := hn.do("GET", "/audit", nil, nil); !strings.Contains(rec.Body.String(), "import du bucket") || strings.Contains(rec.Body.String(), "SECRET") {
		t.Fatalf("journal d'audit :\n%s", rec.Body.String())
	}

	// Verrouillage puis déverrouillage.
	expectRedirect(t, hn.do("POST", "/lock", url.Values{"csrf": {tok}}, nil), "/unlock")
	expectRedirect(t, hn.do("GET", "/", nil, nil), "/unlock")
	if rec := hn.do("POST", "/unlock", url.Values{"password": {"faux mot de passe"}}, nil); !strings.Contains(rec.Body.String(), "incorrect") {
		t.Fatalf("mauvais mot de passe accepté :\n%s", rec.Body.String())
	}
	expectRedirect(t, hn.do("POST", "/unlock", url.Values{"password": {"un mot de passe solide"}}, nil), "/")
	if old := tok; hn.csrf("/settings") == old {
		t.Fatal("jeton CSRF réutilisé d'une session à l'autre")
	}

	// Inactivité : la session expire.
	hn.advance(DefaultIdle + time.Minute)
	expectRedirect(t, hn.do("GET", "/", nil, nil), "/unlock")
	if hn.srv.current() != nil {
		t.Fatal("clé encore en mémoire après expiration")
	}
}

func TestSettingsAndPassword(t *testing.T) {
	hn := newHarness(t)
	hn.do("POST", "/setup", setupForm("un mot de passe solide", "SECRET"), nil)
	tok := hn.csrf("/settings")
	expectRedirect(t, hn.do("POST", "/settings", url.Values{"csrf": {tok}, "price": {"7,50"}, "currency": {"€"}}, nil), "/settings")
	if p := hn.srv.pricing(context.Background()); p.PerTB != 7.5 || p.Currency != "€" {
		t.Fatalf("tarif : %+v", p)
	}
	pw := url.Values{"csrf": {tok}, "current": {"un mot de passe solide"}, "password": {"un nouveau mot de passe"}, "password2": {"un nouveau mot de passe"}}
	expectRedirect(t, hn.do("POST", "/settings/password", pw, nil), "/settings")
	if _, err := hn.srv.Vault.Unlock("un nouveau mot de passe"); err != nil {
		t.Fatalf("nouveau mot de passe : %v", err)
	}
}

// Des essais envoyés en parallèle passent un par un : la limite tient.
func TestPasswordAttemptsSerialized(t *testing.T) {
	hn := newHarness(t)
	hn.do("POST", "/setup", setupForm("un mot de passe solide", "SECRET"), nil)
	hn.do("POST", "/lock", url.Values{"csrf": {hn.csrf("/settings")}}, nil)
	var wg sync.WaitGroup
	var mu sync.Mutex
	evaluated := 0
	start := time.Now()
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := hn.srv.tryPassword("faux mot de passe")
			if errors.Is(err, secrets.ErrWrongPassword) {
				mu.Lock()
				evaluated++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if evaluated != 5 {
		t.Fatalf("%d essais évalués, 5 attendus avant blocage", evaluated)
	}
	if d := time.Since(start); d < 5*time.Second {
		t.Fatalf("essais non sérialisés : %v", d)
	}
	if _, err := hn.srv.tryPassword("un mot de passe solide"); !errors.Is(err, errThrottled) {
		t.Fatalf("bon mot de passe accepté pendant le blocage : %v", err)
	}
	hn.advance(time.Minute + time.Second)
	if _, err := hn.srv.tryPassword("un mot de passe solide"); err != nil {
		t.Fatalf("après le blocage : %v", err)
	}
}

// Deux déverrouillages : la session remplacée n'a plus de tâche vivante.
func TestStartSessionCancelsPrevious(t *testing.T) {
	hn := newHarness(t)
	k := secrets.Keys{AccessKeyID: "AKIDADMIN", SecretAccessKey: "SECRET"}
	hn.srv.startSession(httptest.NewRecorder(), k, "")
	first := hn.srv.current()
	hn.srv.startSession(httptest.NewRecorder(), k, "")
	select {
	case <-first.ctx.Done():
	default:
		t.Fatal("tâches de la première session encore actives")
	}
	hn.srv.lock("test")
	if hn.srv.current() != nil {
		t.Fatal("console encore ouverte")
	}
}

func waitFor(t *testing.T, ok func() bool) {
	t.Helper()
	for i := 0; i < 200; i++ {
		if ok() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("condition jamais remplie")
}

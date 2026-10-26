package web

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/E-C-G/kura-ctl/internal/jobs"
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

type fakeAccount struct {
	mu   sync.Mutex
	keys wasabi.Keys
}

func (f *fakeAccount) ListBuckets(context.Context) ([]wasabi.BucketInfo, error) {
	if f.keys.SecretAccessKey == "mauvaise" {
		return nil, io.ErrUnexpectedEOF
	}
	return []wasabi.BucketInfo{{Name: "acme-srv01", Region: "eu-central-1", Created: time.Date(2025, 1, 2, 0, 0, 0, 0, time.UTC)}}, nil
}
func (f *fakeAccount) ReadSettings(_ context.Context, name, region string) wasabi.Settings {
	return wasabi.Settings{Name: name, Region: region, Versioning: "Enabled", Lifecycle: wasabi.Lifecycle{Present: true, NoncurrentDays: 90}}
}
func (f *fakeAccount) BucketDaily(_ context.Context, b, from, to string) ([]wasabi.DailyUsage, error) {
	return []wasabi.DailyUsage{{Day: to, PaddedBytes: 600e9, RawBytes: 590e9, Objects: 1234}}, nil
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
	hn.srv = &Server{
		Store: st, Vault: &secrets.Vault{Keyring: &memKeyring{m: map[string]string{}}, Iterations: 1000},
		NewAccount: func(k wasabi.Keys) jobs.Account { return &fakeAccount{keys: k} },
		Log:        slog.New(slog.NewTextHandler(io.Discard, nil)),
		Now:        hn.now,
	}
	ln, err := hn.srv.Listen("0")
	if err != nil {
		t.Fatal(err)
	}
	hn.host = ln.Addr().String()
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

	// En-tête Host d'un autre site (DNS rebinding) : refusé.
	req := httptest.NewRequest("GET", "/", nil)
	req.Host = "evil.example:80"
	rec := httptest.NewRecorder()
	hn.h.ServeHTTP(rec, req)
	if rec.Code != http.StatusMisdirectedRequest {
		t.Fatalf("hôte étranger : %d", rec.Code)
	}

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
	if rec := hn.do("POST", "/buckets/import", imp, map[string]string{"Origin": "http://evil.example"}); rec.Code != http.StatusForbidden {
		t.Fatalf("import depuis une autre origine : %d", rec.Code)
	}
	expectRedirect(t, hn.do("POST", "/buckets/import", imp, nil), "/buckets/acme-srv01")
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
	if !strings.Contains(rec.Body.String(), `"padded_gb":600`) {
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

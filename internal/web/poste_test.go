package web

import (
	"archive/zip"
	"bytes"
	"context"
	"errors"
	"html"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/E-C-G/kura-agent/pkg/pack"
	"github.com/E-C-G/kura-ctl/internal/kit"
	"github.com/E-C-G/kura-ctl/internal/poste"
	"github.com/E-C-G/kura-ctl/internal/store"
)

type fakeKit struct {
	t     *testing.T
	err   error
	calls atomic.Int32
	dir   string
	gate  chan struct{} // non nil : Prepare attend sa fermeture
}

func (f *fakeKit) Prepare(context.Context) (kit.Components, func(), error) {
	f.calls.Add(1)
	if f.gate != nil {
		<-f.gate
	}
	if f.err != nil {
		return kit.Components{}, nil, f.err
	}
	write := func(name, content string) string {
		p := filepath.Join(f.dir, name)
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			f.t.Fatal(err)
		}
		return p
	}
	return kit.Components{AgentVersion: "0.6.0", AgentExe: write("kura-agent.exe", "MZ agent"), AgentWExe: write("kura-agentw.exe", "MZ agentw"),
		AgentSHA256: strings.Repeat("a", 64), MSI: write(kit.MSIName, "msi"), MSISHA256: strings.Repeat("b", 64)}, func() {}, nil
}

var (
	yamlRe   = regexp.MustCompile(`(?s)<textarea name="yaml"[^>]*>(.*?)</textarea>`)
	kitURLRe = regexp.MustCompile(`href="(/buckets/acme-srv01/kit/[0-9a-f]+)"`)
)

func (hn *harness) savePoste(tok, text string) *http.Response {
	hn.t.Helper()
	return hn.do("POST", "/buckets/acme-srv01/poste", url.Values{"csrf": {tok}, "yaml": {text}}, nil).Result()
}

func TestPosteConfigPage(t *testing.T) {
	hn, tok := adminHarness(t, nil)
	ctx := context.Background()
	body := hn.do("GET", "/buckets/acme-srv01", nil, nil).Body.String()
	if !strings.Contains(body, "Préparer la configuration du poste") || strings.Contains(body, "Créer une clé et le kit") {
		t.Fatal("page du bucket : configuration du poste absente ou kit proposé sans configuration")
	}
	m := yamlRe.FindStringSubmatch(hn.do("GET", "/buckets/acme-srv01/poste", nil, nil).Body.String())
	if m == nil {
		t.Fatal("modèle absent")
	}
	tmpl := html.UnescapeString(m[1])
	if !strings.Contains(tmpl, "bucket: acme-srv01") || !strings.Contains(tmpl, "https://s3.eu-central-1.wasabisys.com") {
		t.Fatalf("modèle :\n%s", tmpl)
	}

	// Refusée : rien n'est enregistré, le texte saisi est réaffiché avec l'erreur.
	bad := strings.Replace(tmpl, "url: credential:hc-url", "url: https://hc-ping.com/0000", 1)
	rec := hn.do("POST", "/buckets/acme-srv01/poste", url.Values{"csrf": {tok}, "yaml": {bad}}, nil)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "notify.report.url") || !strings.Contains(rec.Body.String(), "hc-ping.com/0000") {
		t.Fatalf("refus : %d", rec.Code)
	}
	if _, err := hn.st.PosteConfig(ctx, "acme-srv01"); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("configuration refusée enregistrée")
	}
	// Sans jeton CSRF : refusée.
	if rec := hn.do("POST", "/buckets/acme-srv01/poste", url.Values{"yaml": {tmpl}}, nil); rec.Code != http.StatusForbidden {
		t.Fatalf("sans CSRF : %d", rec.Code)
	}

	expectRedirect(t, hn.do("POST", "/buckets/acme-srv01/poste", url.Values{"csrf": {tok}, "yaml": {strings.ReplaceAll(tmpl, "\n", "\r\n")}}, nil), "/buckets/acme-srv01")
	pc, err := hn.st.PosteConfig(ctx, "acme-srv01")
	if err != nil || pc.YAML != tmpl {
		t.Fatalf("enregistrée : %v", err)
	}
	body = hn.do("GET", "/buckets/acme-srv01", nil, nil).Body.String()
	for _, want := range []string{"prête", "Créer une clé et le kit", `name="secret-hc-url"`, "credential:wasabi"} {
		if !strings.Contains(body, want) {
			t.Errorf("page du bucket sans %q", want)
		}
	}
	if !strings.Contains(hn.do("GET", "/audit", nil, nil).Body.String(), "configuration du poste enregistrée") {
		t.Fatal("audit")
	}
}

func installForm(hn *harness, tok string, secrets map[string]string) url.Values {
	f := url.Values{"csrf": {tok}, "confirm": {"acme-srv01"}, "paquet": {"installation"}, "once": {hn.once()}}
	for k, v := range secrets {
		f.Set("secret-"+k, v)
	}
	return f
}

func TestInstallPackageAndKit(t *testing.T) {
	hn, tok := adminHarness(t, nil)
	fk := &fakeKit{t: t, dir: t.TempDir()}
	hn.srv.Kit = fk
	ctx := context.Background()
	b, _ := hn.st.Bucket(ctx, "acme-srv01")

	// Sans configuration : aucune clé créée.
	hn.do("POST", "/buckets/acme-srv01/cles", installForm(hn, tok, nil), nil)
	if keys, _ := hn.st.Keys(ctx, "acme-srv01"); len(keys) != 0 || hn.keyCount() != 0 {
		t.Fatal("clé créée sans configuration du poste")
	}
	text := poste.Template(b)
	if r := hn.savePoste(tok, text); r.StatusCode != http.StatusSeeOther {
		t.Fatalf("enregistrement : %d", r.StatusCode)
	}
	// Secret manquant ou invalide : refus avant toute création chez Wasabi.
	for _, v := range []string{"", "http://hc-ping.com/x"} {
		hn.do("POST", "/buckets/acme-srv01/cles", installForm(hn, tok, map[string]string{"hc-url": v}), nil)
		if hn.keyCount() != 0 {
			t.Fatalf("clé créée avec hc-url=%q", v)
		}
	}

	rec := hn.do("POST", "/buckets/acme-srv01/cles", installForm(hn, tok, map[string]string{"hc-url": "https://hc-ping.example/uuid-poste"}), nil)
	page := rec.Body.String()
	pm, km, um := passwordRe.FindStringSubmatch(page), kitURLRe.FindStringSubmatch(page), packURLRe.FindStringSubmatch(page)
	if pm == nil || km == nil || um == nil || !strings.Contains(page, "install --package") {
		t.Fatalf("page du kit :\n%s", page)
	}
	if strings.Contains(hn.do("GET", "/audit", nil, nil).Body.String(), "uuid-poste") {
		t.Fatal("secret dans le journal")
	}

	// Kit impossible : le paquet n'est pas consommé.
	fk.err = errors.New("GitHub injoignable")
	if rec := hn.do("GET", km[1], nil, nil); rec.Code != http.StatusBadGateway || !strings.Contains(rec.Body.String(), "GitHub injoignable") {
		t.Fatalf("kit en échec : %d", rec.Code)
	}
	fk.err = nil
	rec = hn.do("GET", km[1], nil, nil)
	if rec.Code != 200 || rec.Header().Get("Content-Type") != "application/zip" {
		t.Fatalf("kit : %d %v", rec.Code, rec.Header())
	}
	zr, err := zip.NewReader(bytes.NewReader(rec.Body.Bytes()), int64(rec.Body.Len()))
	if err != nil {
		t.Fatal(err)
	}
	files := map[string][]byte{}
	for _, f := range zr.File {
		rc, _ := f.Open()
		files[f.Name], _ = io.ReadAll(rc)
		rc.Close()
	}
	var packData []byte
	for name, data := range files {
		if strings.HasSuffix(name, ".kura") {
			packData = data
		}
	}
	for _, want := range []string{"kura-acme-srv01/kura-agent.exe", "kura-acme-srv01/kura-agentw.exe", "kura-acme-srv01/AWSCLIV2.msi", "kura-acme-srv01/LISEZMOI.txt"} {
		if files[want] == nil {
			t.Errorf("%s absent du kit", want)
		}
	}
	readme := string(files["kura-acme-srv01/LISEZMOI.txt"])
	if !strings.Contains(readme, "install --package acme-srv01-") || strings.Contains(readme, pm[1]) {
		t.Fatalf("LISEZMOI :\n%s", readme)
	}
	c, err := pack.Open(packData, pm[1])
	if err != nil || c.Kind != pack.KindInstall || c.Config != text || len(c.Credentials) != 2 ||
		c.Credentials[0].Name != "wasabi" || c.Credentials[0].SecretAccessKey == "" ||
		c.Credentials[1].Name != "hc-url" || c.Credentials[1].Value != "https://hc-ping.example/uuid-poste" {
		t.Fatalf("paquet : %+v %v", c, err)
	}
	// Une seule fois : ni second kit, ni .kura seul.
	if rec := hn.do("GET", km[1], nil, nil); rec.Code != http.StatusGone {
		t.Fatalf("second kit : %d", rec.Code)
	}
	if rec := hn.do("GET", um[1], nil, nil); rec.Code != http.StatusGone {
		t.Fatalf(".kura après le kit : %d", rec.Code)
	}
	if k, _ := hn.st.Key(ctx, c.Credentials[0].AccessKeyID); k.DownloadedAt.IsZero() {
		t.Fatal("téléchargement non enregistré")
	}

	// Paquet seul : le kit n'est plus disponible ensuite.
	rec = hn.do("POST", "/buckets/acme-srv01/cles", installForm(hn, tok, map[string]string{"hc-url": "https://hc-ping.example/uuid-2"}), nil)
	km, um = kitURLRe.FindStringSubmatch(rec.Body.String()), packURLRe.FindStringSubmatch(rec.Body.String())
	if rec := hn.do("GET", um[1], nil, nil); rec.Code != 200 {
		t.Fatalf(".kura seul : %d", rec.Code)
	}
	if rec := hn.do("GET", km[1], nil, nil); rec.Code != http.StatusGone {
		t.Fatalf("kit après le .kura : %d", rec.Code)
	}

	// Configuration devenue invalide (règles plus strictes) : plus de paquet d'installation.
	if err := hn.st.SavePosteConfig(ctx, "acme-srv01", strings.Replace(text, "bucket: acme-srv01", "bucket: autre", 1)); err != nil {
		t.Fatal(err)
	}
	n := hn.keyCount()
	hn.do("POST", "/buckets/acme-srv01/cles", installForm(hn, tok, map[string]string{"hc-url": "https://hc-ping.example/uuid-3"}), nil)
	if hn.keyCount() != n {
		t.Fatal("clé créée avec une configuration refusée")
	}
	if !strings.Contains(hn.do("GET", "/buckets/acme-srv01", nil, nil).Body.String(), "à corriger") {
		t.Fatal("configuration refusée non signalée")
	}
}

func TestKeyOnlyPackStillWorks(t *testing.T) {
	hn, tok := adminHarness(t, nil)
	pw, link := hn.createKey(tok)
	rec := hn.do("GET", link, nil, nil)
	c, err := pack.Open(rec.Body.Bytes(), pw)
	if err != nil || c.Kind != pack.KindCredentials || c.Config != "" {
		t.Fatalf("%+v %v", c, err)
	}
	if strings.Contains(hn.do("GET", "/buckets/acme-srv01/kit/"+strings.TrimPrefix(link, "/buckets/acme-srv01/paquet/"), nil, nil).Body.String(), "PK") {
		t.Fatal("kit pour un paquet « clé seule »")
	}
}

// keyCount : clés créées chez Wasabi pour l'utilisateur du poste.
func (hn *harness) keyCount() int {
	a := hn.last()
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.akeys["kura-acme-srv01"])
}

func TestKitBusyAndTokenKinds(t *testing.T) {
	hn, tok := adminHarness(t, nil)
	fk := &fakeKit{t: t, dir: t.TempDir(), gate: make(chan struct{})}
	hn.srv.Kit = fk
	b, _ := hn.st.Bucket(context.Background(), "acme-srv01")
	hn.savePoste(tok, poste.Template(b))
	rec := hn.do("POST", "/buckets/acme-srv01/cles", installForm(hn, tok, map[string]string{"hc-url": "https://hc-ping.example/u"}), nil)
	km, um := kitURLRe.FindStringSubmatch(rec.Body.String()), packURLRe.FindStringSubmatch(rec.Body.String())
	res := make(chan int)
	go func() { res <- hn.do("GET", km[1], nil, nil).Code }()
	for fk.calls.Load() == 0 {
		runtime.Gosched()
	}
	// Kit en préparation : ni .kura, ni second kit.
	if c := hn.do("GET", um[1], nil, nil).Code; c != http.StatusConflict {
		t.Fatalf(".kura pendant le kit : %d", c)
	}
	if c := hn.do("GET", km[1], nil, nil).Code; c != http.StatusConflict {
		t.Fatalf("second kit : %d", c)
	}
	close(fk.gate)
	if c := <-res; c != 200 {
		t.Fatalf("kit : %d", c)
	}
	// Jeton expiré : refusé.
	rec = hn.do("POST", "/buckets/acme-srv01/cles", installForm(hn, tok, map[string]string{"hc-url": "https://hc-ping.example/u"}), nil)
	km = kitURLRe.FindStringSubmatch(rec.Body.String())
	hn.advance(20 * time.Minute)
	hn.do("GET", "/buckets/acme-srv01", nil, nil) // activité : la session reste ouverte
	hn.advance(11 * time.Minute)
	if c := hn.do("GET", km[1], nil, nil).Code; c != http.StatusGone {
		t.Fatalf("kit expiré : %d", c)
	}
}

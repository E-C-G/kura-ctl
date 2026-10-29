package web

import (
	"archive/zip"
	"bytes"
	"context"
	"errors"
	"html"
	"io"
	"net/http"
	"net/http/httptest"
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
	last  kit.Target
}

func (f *fakeKit) Prepare(_ context.Context, t kit.Target) (kit.Components, func(), error) {
	f.calls.Add(1)
	f.last = t
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
	c := kit.Components{Target: t, AgentVersion: "0.7.0", AgentSHA256: strings.Repeat("a", 64), AWSFile: t.AWSName(), AWSSHA256: strings.Repeat("b", 64)}
	if t.Linux() {
		c.AgentFile = kit.DebName("0.7.0", t.Arch)
		c.Files = []kit.File{{Name: c.AgentFile, Path: write(c.AgentFile, "!<arch>\ndebian-binary")}}
	} else {
		c.AgentFile = "kura-agent.exe"
		c.Files = []kit.File{{Name: "kura-agent.exe", Path: write("kura-agent.exe", "MZ agent")}, {Name: "kura-agentw.exe", Path: write("kura-agentw.exe", "MZ agentw")}}
	}
	c.Files = append(c.Files, kit.File{Name: c.AWSFile, Path: write(c.AWSFile, "aws")})
	if t.Linux() {
		c.Files = append(c.Files, kit.File{Name: c.AWSFile + ".sig", Path: write(c.AWSFile+".sig", "sig")})
	}
	return c, func() {}, nil
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
	if fk.last != kit.Windows || !strings.Contains(readme, "kura-agent.exe install --package acme-srv01-") || !strings.Contains(readme, "\r\n") || strings.Contains(readme, pm[1]) {
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
	if err := hn.st.SavePosteConfig(ctx, "acme-srv01", store.PlatformWindows, strings.Replace(text, "bucket: acme-srv01", "bucket: autre", 1)); err != nil {
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

func TestLinuxPosteAndKit(t *testing.T) {
	hn, tok := adminHarness(t, nil)
	fk := &fakeKit{t: t, dir: t.TempDir()}
	hn.srv.Kit = fk
	ctx := context.Background()
	b, _ := hn.st.Bucket(ctx, "acme-srv01")

	// Modèle de départ Ubuntu, choisi par lien.
	page := hn.do("GET", "/buckets/acme-srv01/poste?systeme=linux-amd64", nil, nil).Body.String()
	m := yamlRe.FindStringSubmatch(page)
	if m == nil || !strings.Contains(html.UnescapeString(m[1]), "source: /home/") || !strings.Contains(page, `<option value="linux-amd64" selected>`) {
		t.Fatalf("modèle Ubuntu :\n%s", page)
	}
	text := poste.TemplateFor(b, store.PlatformLinuxAMD64)
	save := func(platform, yaml string) *httptest.ResponseRecorder {
		return hn.do("POST", "/buckets/acme-srv01/poste", url.Values{"csrf": {tok}, "yaml": {yaml}, "platform": {platform}}, nil)
	}
	// Modèle Windows pour un poste Ubuntu, ou système inconnu : refusés, rien d'enregistré.
	for _, c := range [][2]string{{"linux-amd64", poste.TemplateFor(b, store.PlatformWindows)}, {"darwin-arm64", text}} {
		if rec := save(c[0], c[1]); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "refus") && !strings.Contains(rec.Body.String(), "inconnu") {
			t.Fatalf("%s : %d\n%s", c[0], rec.Code, rec.Body.String())
		}
	}
	if _, err := hn.st.PosteConfig(ctx, "acme-srv01"); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("configuration refusée enregistrée")
	}
	expectRedirect(t, save("linux-amd64", text), "/buckets/acme-srv01")
	if b, _ := hn.st.Bucket(ctx, "acme-srv01"); b.Platform != store.PlatformLinuxAMD64 {
		t.Fatalf("système : %q", b.Platform)
	}
	body := hn.do("GET", "/buckets/acme-srv01", nil, nil).Body.String()
	if !strings.Contains(body, "Ubuntu 24.04 (amd64)") || !strings.Contains(body, "sudo apt install") {
		t.Fatal("page du bucket sans le système du poste")
	}

	rec := hn.do("POST", "/buckets/acme-srv01/cles", installForm(hn, tok, map[string]string{"hc-url": "https://hc-ping.example/uuid-poste"}), nil)
	page = rec.Body.String()
	pm, km := passwordRe.FindStringSubmatch(page), kitURLRe.FindStringSubmatch(page)
	if pm == nil || km == nil || !strings.Contains(page, "sudo kura-agent install --package") || !strings.Contains(page, "sudo apt install") || strings.Contains(page, "kura-agent.exe install") {
		t.Fatalf("page du kit :\n%s", page)
	}
	// Le système change après la création du paquet : le kit suit le paquet.
	if err := hn.st.SavePosteConfig(ctx, "acme-srv01", store.PlatformLinuxARM64, text); err != nil {
		t.Fatal(err)
	}
	rec = hn.do("GET", km[1], nil, nil)
	if rec.Code != 200 || fk.last != (kit.Target{OS: "linux", Arch: "amd64"}) {
		t.Fatalf("kit : %d, cible %v", rec.Code, fk.last)
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
	for _, want := range []string{"kura-agent_0.7.0_amd64.deb", "awscli-exe-linux-x86_64.zip", "awscli-exe-linux-x86_64.zip.sig", "LISEZMOI.txt"} {
		if files["kura-acme-srv01/"+want] == nil {
			t.Errorf("%s absent du kit", want)
		}
	}
	if files["kura-acme-srv01/kura-agent.exe"] != nil || files["kura-acme-srv01/AWSCLIV2.msi"] != nil {
		t.Error("fichiers Windows dans le kit Ubuntu")
	}
	readme := string(files["kura-acme-srv01/LISEZMOI.txt"])
	for _, want := range []string{"Ubuntu 24.04 (amd64)", "sudo apt install ./kura-agent_0.7.0_amd64.deb", "sudo kura-agent install --package acme-srv01-", "systemctl start --no-block kura-sync.service"} {
		if !strings.Contains(readme, want) {
			t.Errorf("LISEZMOI sans %q :\n%s", want, readme)
		}
	}
	if strings.Contains(readme, "\r") || strings.Contains(readme, pm[1]) {
		t.Fatalf("LISEZMOI :\n%q", readme)
	}
	if !strings.Contains(hn.do("GET", "/audit", nil, nil).Body.String(), "linux/amd64") {
		t.Fatal("audit sans le système du kit")
	}
}

func TestRunNowHint(t *testing.T) {
	if !strings.Contains(runNowHint(store.PlatformLinuxARM64), "systemctl start") || !strings.Contains(runNowHint(store.PlatformWindows), "icône") {
		t.Fatal(runNowHint(store.PlatformLinuxARM64))
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

// Configuration avec préparations : enregistrée, la page du poste montre les commandes de
// création du rôle et les destinataires du chiffrement ; le mot de passe de la base est
// demandé à la création du paquet.
func TestPostePreparations(t *testing.T) {
	hn, tok := adminHarness(t, nil)
	text := strings.Replace(poste.Template(store.Bucket{Name: "acme-srv01", Region: "eu-central-1", Poste: "SRV01"}), "\njobs:\n", `
tools:
  pg_dump: "C:/Program Files/PostgreSQL/17/bin/pg_dump.exe"
prepare:
  - id: compta-db
    type: db_export
    engine: postgresql
    user: kura_backup
    password: credential:compta-db
  - id: compta-chiffre
    type: age
    input: compta-db
    recipients:
      - age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p

jobs:
  - id: compta
    source: "${STAGING:compta-chiffre}"
    destination: BASES/COMPTA
`, 1)
	expectRedirect(t, hn.do("POST", "/buckets/acme-srv01/poste", url.Values{"csrf": {tok}, "yaml": {text}}, nil), "/buckets/acme-srv01")
	page := html.UnescapeString(hn.do("GET", "/buckets/acme-srv01/poste", nil, nil).Body.String())
	for _, want := range []string{"Rôles des bases", `CREATE ROLE "kura_backup" LOGIN PASSWORD '…';`, "Chiffrement",
		"age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p", "préparation compta-db"} {
		if !strings.Contains(page, want) {
			t.Errorf("page du poste sans %q", want)
		}
	}
	if body := hn.do("GET", "/buckets/acme-srv01", nil, nil).Body.String(); !strings.Contains(body, `name="secret-compta-db"`) {
		t.Fatal("mot de passe de la base non demandé à la création du paquet")
	}
	// Clair envoyé : refusé, rien n'est enregistré à la place.
	bad := strings.Replace(text, "${STAGING:compta-chiffre}", "${STAGING:compta-db}", 1)
	if rec := hn.do("POST", "/buckets/acme-srv01/poste", url.Values{"csrf": {tok}, "yaml": {bad}}, nil); !strings.Contains(rec.Body.String(), "son clair ne part jamais") {
		t.Fatal("clair envoyé accepté")
	}
}

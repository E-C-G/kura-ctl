package kit

import (
	"archive/zip"
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type fakeGitHub struct {
	srv      *httptest.Server
	tag      string
	zip      []byte
	debs     map[string][]byte // par architecture
	sums     string
	aws      map[string][]byte // fichiers de la CLI AWS, par nom
	awsCalls atomic.Int32
	zipCalls atomic.Int32
	debCalls atomic.Int32
	awsDown  bool
}

func agentZip(t *testing.T, ver string, exes map[string][]byte) []byte {
	var b bytes.Buffer
	zw := zip.NewWriter(&b)
	dir := "kura-agent_" + ver + "_windows_amd64/"
	for name, data := range exes {
		f, _ := zw.Create(dir + name)
		f.Write(data)
	}
	f, _ := zw.Create(dir + "README.md")
	f.Write([]byte("# kura-agent"))
	zw.Close()
	return b.Bytes()
}

func (g *fakeGitHub) setSums() {
	ver := strings.TrimPrefix(g.tag, "v")
	g.sums = fmt.Sprintf("%s  kura-agent_%s_windows_amd64.zip\n%s  kura-agent_%s_windows_amd64.exe\n", sha256Hex(g.zip), ver, strings.Repeat("0", 64), ver)
	for arch, deb := range g.debs {
		g.sums += fmt.Sprintf("%s  %s\n", sha256Hex(deb), DebName(ver, arch))
	}
}

func newFake(t *testing.T, ver string) *fakeGitHub {
	g := &fakeGitHub{tag: "v" + ver}
	g.zip = agentZip(t, ver, map[string][]byte{"kura-agent.exe": []byte("MZ agent"), "kura-agentw.exe": []byte("MZ agentw")})
	g.debs = map[string][]byte{}
	for _, arch := range []string{"amd64", "arm64"} {
		g.debs[arch] = append(append([]byte{}, debMagic...), []byte(" paquet "+arch)...)
	}
	g.setSums()
	g.aws = map[string][]byte{
		MSIName:                            append(append([]byte{}, msiMagic...), []byte("contenu du msi")...),
		"awscli-exe-linux-x86_64.zip":      append(append([]byte{}, zipMagic...), []byte("zip x86_64")...),
		"awscli-exe-linux-x86_64.zip.sig":  []byte("-----BEGIN PGP SIGNATURE-----\nx86_64\n-----END PGP SIGNATURE-----\n"),
		"awscli-exe-linux-aarch64.zip":     append(append([]byte{}, zipMagic...), []byte("zip aarch64")...),
		"awscli-exe-linux-aarch64.zip.sig": {0x89, 0x02, 0x33},
	}
	g.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		base := "https://" + r.Host
		ver := strings.TrimPrefix(g.tag, "v")
		switch {
		case r.URL.Path == "/releases/latest":
			fmt.Fprintf(w, `{"tag_name":%q,"assets":[{"name":"kura-agent_%[2]s_windows_amd64.zip","browser_download_url":"%[3]s/dl/zip"},`+
				`{"name":%[4]q,"browser_download_url":"%[3]s/dl/deb-amd64"},{"name":%[5]q,"browser_download_url":"%[3]s/dl/deb-arm64"},`+
				`{"name":"SHA256SUMS","browser_download_url":"%[3]s/dl/sums"}]}`,
				g.tag, ver, base, DebName(ver, "amd64"), DebName(ver, "arm64"))
		case r.URL.Path == "/dl/zip":
			g.zipCalls.Add(1)
			w.Write(g.zip)
		case strings.HasPrefix(r.URL.Path, "/dl/deb-"):
			g.debCalls.Add(1)
			w.Write(g.debs[strings.TrimPrefix(r.URL.Path, "/dl/deb-")])
		case r.URL.Path == "/dl/sums":
			io.WriteString(w, g.sums)
		case strings.HasPrefix(r.URL.Path, "/aws/"):
			b, ok := g.aws[strings.TrimPrefix(r.URL.Path, "/aws/")]
			if !ok {
				http.NotFound(w, r)
				return
			}
			g.awsCalls.Add(1)
			if g.awsDown {
				http.Error(w, "indisponible", http.StatusServiceUnavailable)
				return
			}
			w.Write(b)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(g.srv.Close)
	return g
}

func (g *fakeGitHub) source(dir string, now time.Time) *Source {
	return &Source{HTTP: g.srv.Client(), ReleasesAPI: g.srv.URL + "/releases/latest", AWSBaseURL: g.srv.URL + "/aws/",
		AssetPrefix: g.srv.URL + "/dl/", CacheDir: dir, Now: func() time.Time { return now }}
}

func unzip(t *testing.T, b []byte) map[string]string {
	t.Helper()
	zr, err := zip.NewReader(bytes.NewReader(b), int64(len(b)))
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, f := range zr.File {
		rc, _ := f.Open()
		data, _ := io.ReadAll(rc)
		rc.Close()
		got[f.Name] = string(data)
	}
	return got
}

func sameFiles(t *testing.T, got, want map[string]string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("contenu : %v", got)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %q", k, got[k])
		}
	}
}

func TestPrepareAndWrite(t *testing.T) {
	g := newFake(t, "0.7.0")
	dir := t.TempDir()
	now := time.Now()
	src := g.source(dir, now)
	c, release, err := src.Prepare(context.Background(), Windows)
	if err != nil {
		t.Fatal(err)
	}
	release()
	if c.AgentVersion != "0.7.0" || c.AgentFile != "kura-agent.exe" || c.AgentSHA256 != sha256Hex([]byte("MZ agent")) ||
		c.AWSFile != MSIName || c.AWSSHA256 != sha256Hex(g.aws[MSIName]) || c.AWSDate.IsZero() {
		t.Fatalf("%+v", c)
	}
	// Deuxième préparation : tout vient du cache.
	if _, release, err := src.Prepare(context.Background(), Windows); err != nil || g.zipCalls.Load() != 1 || g.awsCalls.Load() != 1 {
		t.Fatalf("cache non utilisé : %v zip=%d aws=%d", err, g.zipCalls.Load(), g.awsCalls.Load())
	} else {
		release()
	}

	var out bytes.Buffer
	if err := Write(&out, Kit{Folder: "kura-acme-srv01", PackName: "acme-srv01.kura", Pack: []byte(`{"format":"kura-pack"}`),
		Readme: "ligne 1\nligne 2\n", Components: c, GeneratedAt: now}); err != nil {
		t.Fatal(err)
	}
	sameFiles(t, unzip(t, out.Bytes()), map[string]string{
		"kura-acme-srv01/LISEZMOI.txt":    "ligne 1\r\nligne 2\r\n",
		"kura-acme-srv01/acme-srv01.kura": `{"format":"kura-pack"}`,
		"kura-acme-srv01/kura-agent.exe":  "MZ agent",
		"kura-acme-srv01/kura-agentw.exe": "MZ agentw",
		"kura-acme-srv01/AWSCLIV2.msi":    string(g.aws[MSIName]),
	})
}

func TestPrepareLinux(t *testing.T) {
	g := newFake(t, "0.7.0")
	dir := t.TempDir()
	now := time.Now()
	src := g.source(dir, now)
	for _, c := range []struct{ arch, aws string }{{"amd64", "awscli-exe-linux-x86_64.zip"}, {"arm64", "awscli-exe-linux-aarch64.zip"}} {
		tg := Target{OS: "linux", Arch: c.arch}
		comp, release, err := src.Prepare(context.Background(), tg)
		if err != nil {
			t.Fatalf("%s : %v", c.arch, err)
		}
		release()
		deb := "kura-agent_0.7.0_" + c.arch + ".deb"
		if comp.AgentFile != deb || comp.AgentSHA256 != sha256Hex(g.debs[c.arch]) || comp.AWSFile != c.aws || comp.AWSSHA256 != sha256Hex(g.aws[c.aws]) {
			t.Fatalf("%+v", comp)
		}
		var out bytes.Buffer
		if err := Write(&out, Kit{Folder: "kura-acme-portable01", PackName: "acme-portable01.kura", Pack: []byte("paquet"),
			Readme: "ligne 1\r\nligne 2\n", Components: comp, GeneratedAt: now}); err != nil {
			t.Fatal(err)
		}
		sameFiles(t, unzip(t, out.Bytes()), map[string]string{
			"kura-acme-portable01/LISEZMOI.txt":         "ligne 1\nligne 2\n", // fins de ligne Unix
			"kura-acme-portable01/acme-portable01.kura": "paquet",
			"kura-acme-portable01/" + deb:               string(g.debs[c.arch]),
			"kura-acme-portable01/" + c.aws:             string(g.aws[c.aws]),
			"kura-acme-portable01/" + c.aws + ".sig":    string(g.aws[c.aws+".sig"]),
		})
	}
	// Cache : rien n'est retéléchargé.
	debs, aws := g.debCalls.Load(), g.awsCalls.Load()
	if _, release, err := src.Prepare(context.Background(), Target{OS: "linux", Arch: "amd64"}); err != nil {
		t.Fatal(err)
	} else {
		release()
	}
	if g.debCalls.Load() != debs || g.awsCalls.Load() != aws || g.zipCalls.Load() != 0 {
		t.Fatalf("cache non utilisé : deb %d→%d, aws %d→%d, zip Windows %d", debs, g.debCalls.Load(), aws, g.awsCalls.Load(), g.zipCalls.Load())
	}
}

func TestPrepareLinuxRefusals(t *testing.T) {
	linux := Target{OS: "linux", Arch: "amd64"}
	t.Run("version sans paquet .deb", func(t *testing.T) {
		g := newFake(t, "0.6.0")
		if _, _, err := g.source(t.TempDir(), time.Now()).Prepare(context.Background(), linux); err == nil || !strings.Contains(err.Error(), MinAgentLinux) {
			t.Fatal(err)
		}
	})
	t.Run("somme fausse", func(t *testing.T) {
		g := newFake(t, "0.7.0")
		g.sums = strings.Replace(g.sums, sha256Hex(g.debs["amd64"]), strings.Repeat("a", 64), 1)
		if _, _, err := g.source(t.TempDir(), time.Now()).Prepare(context.Background(), linux); err == nil || !strings.Contains(err.Error(), "SHA") {
			t.Fatal(err)
		}
	})
	t.Run("pas un paquet Debian", func(t *testing.T) {
		g := newFake(t, "0.7.0")
		g.debs["amd64"] = []byte("<html>erreur</html>")
		g.setSums()
		if _, _, err := g.source(t.TempDir(), time.Now()).Prepare(context.Background(), linux); err == nil || !strings.Contains(err.Error(), "Debian") {
			t.Fatal(err)
		}
	})
	t.Run("signature absente", func(t *testing.T) {
		g := newFake(t, "0.7.0")
		delete(g.aws, "awscli-exe-linux-x86_64.zip.sig")
		if _, _, err := g.source(t.TempDir(), time.Now()).Prepare(context.Background(), linux); err == nil || !strings.Contains(err.Error(), ".sig") {
			t.Fatal(err)
		}
	})
	t.Run("signature illisible", func(t *testing.T) {
		g := newFake(t, "0.7.0")
		g.aws["awscli-exe-linux-x86_64.zip.sig"] = []byte("<html>")
		if _, _, err := g.source(t.TempDir(), time.Now()).Prepare(context.Background(), linux); err == nil {
			t.Fatal("accepté")
		}
	})
	t.Run("système inconnu", func(t *testing.T) {
		g := newFake(t, "0.7.0")
		for _, tg := range []Target{{OS: "darwin", Arch: "arm64"}, {OS: "linux", Arch: "386"}, {OS: "windows", Arch: "arm64"}} {
			if _, _, err := g.source(t.TempDir(), time.Now()).Prepare(context.Background(), tg); err == nil {
				t.Fatalf("%s accepté", tg)
			}
		}
	})
}

func TestDebName(t *testing.T) {
	if got := DebName("0.8.0-rc1", "arm64"); got != "kura-agent_0.8.0~rc1_arm64.deb" {
		t.Fatal(got)
	}
}

func TestPrepareRefusals(t *testing.T) {
	t.Run("version trop ancienne", func(t *testing.T) {
		g := newFake(t, "0.5.2")
		if _, _, err := g.source(t.TempDir(), time.Now()).Prepare(context.Background(), Windows); err == nil || !strings.Contains(err.Error(), MinAgent) {
			t.Fatal(err)
		}
	})
	t.Run("somme fausse", func(t *testing.T) {
		g := newFake(t, "0.6.0")
		g.sums = strings.Replace(g.sums, sha256Hex(g.zip), strings.Repeat("a", 64), 1)
		if _, _, err := g.source(t.TempDir(), time.Now()).Prepare(context.Background(), Windows); err == nil || !strings.Contains(err.Error(), "SHA") {
			t.Fatal(err)
		}
	})
	t.Run("exécutable manquant", func(t *testing.T) {
		g := newFake(t, "0.6.0")
		g.zip = agentZip(t, "0.6.0", map[string][]byte{"kura-agent.exe": []byte("MZ agent")})
		g.setSums()
		if _, _, err := g.source(t.TempDir(), time.Now()).Prepare(context.Background(), Windows); err == nil {
			t.Fatal("accepté")
		}
	})
	t.Run("pas un MSI", func(t *testing.T) {
		g := newFake(t, "0.6.0")
		g.aws[MSIName] = []byte("<html>erreur</html>")
		if _, _, err := g.source(t.TempDir(), time.Now()).Prepare(context.Background(), Windows); err == nil {
			t.Fatal("accepté")
		}
	})
}

func TestMSIRefreshAndOffline(t *testing.T) {
	g := newFake(t, "0.6.0")
	dir := t.TempDir()
	now := time.Now()
	if _, _, err := g.source(dir, now).Prepare(context.Background(), Windows); err != nil {
		t.Fatal(err)
	}
	// Vieux de plus de 30 jours : retéléchargé.
	later := now.Add(AWSMaxAge + time.Hour)
	if _, _, err := g.source(dir, later).Prepare(context.Background(), Windows); err != nil || g.awsCalls.Load() != 2 {
		t.Fatalf("%v, %d appels", err, g.awsCalls.Load())
	}
	// AWS injoignable : le MSI en cache sert encore.
	g.awsDown = true
	c, _, err := g.source(dir, later.Add(AWSMaxAge+time.Hour)).Prepare(context.Background(), Windows)
	if err != nil || c.AWSFile != MSIName {
		t.Fatalf("hors ligne : %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, MSIName+".part")); !os.IsNotExist(err) {
		t.Fatal("fichier partiel laissé")
	}
}

func TestLinuxAWSRefreshAndOffline(t *testing.T) {
	g := newFake(t, "0.7.0")
	dir := t.TempDir()
	now := time.Now()
	linux := Target{OS: "linux", Arch: "amd64"}
	if _, r, err := g.source(dir, now).Prepare(context.Background(), linux); err != nil {
		t.Fatal(err)
	} else {
		r()
	}
	if n := g.awsCalls.Load(); n != 2 {
		t.Fatalf("zip et signature : %d téléchargements", n)
	}
	// Signature en cache abîmée : la paire est retéléchargée.
	sig := filepath.Join(dir, "awscli-exe-linux-x86_64.zip.sig")
	os.WriteFile(sig, nil, 0o600)
	if _, r, err := g.source(dir, now).Prepare(context.Background(), linux); err != nil || g.awsCalls.Load() != 4 {
		t.Fatalf("%v, %d appels", err, g.awsCalls.Load())
	} else {
		r()
	}
	// Périmée et AWS injoignable : la paire en cache sert encore.
	g.awsDown = true
	c, r, err := g.source(dir, now.Add(AWSMaxAge+time.Hour)).Prepare(context.Background(), linux)
	if err != nil || len(c.Files) != 3 {
		t.Fatalf("hors ligne : %v %+v", err, c)
	}
	r()
	for _, f := range c.Files {
		if _, err := os.Stat(f.Path + ".part"); !os.IsNotExist(err) {
			t.Fatalf("fichier partiel laissé : %s", f.Path)
		}
	}
	// Rien en cache et AWS injoignable : refusé.
	if _, _, err := g.source(t.TempDir(), now).Prepare(context.Background(), linux); err == nil {
		t.Fatal("kit sans CLI AWS")
	}
}

func TestAtLeast(t *testing.T) {
	for _, c := range []struct {
		v    string
		want bool
	}{{"0.6.0", true}, {"0.6.1", true}, {"1.0.0", true}, {"0.10.0", true}, {"0.5.9", false}, {"0.6.0-rc1", true}, {"x", false}, {"", false}} {
		if AtLeast(c.v, "0.6.0") != c.want {
			t.Errorf("%q", c.v)
		}
	}
}

func TestAssetHostRestricted(t *testing.T) {
	g := newFake(t, "0.6.0")
	src := g.source(t.TempDir(), time.Now())
	src.AssetPrefix = "https://github.com/E-C-G/kura-agent/releases/download/"
	if _, _, err := src.Prepare(context.Background(), Windows); err == nil || !strings.Contains(err.Error(), "adresse inattendue") {
		t.Fatal(err)
	}
}

func TestPrepareBlocksRefreshWhileWriting(t *testing.T) {
	g := newFake(t, "0.6.0")
	dir := t.TempDir()
	src := g.source(dir, time.Now())
	_, release, err := src.Prepare(context.Background(), Windows)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		if _, r, err := src.Prepare(context.Background(), Windows); err == nil {
			r()
		}
		close(done)
	}()
	select {
	case <-done:
		t.Fatal("préparation pendant l'écriture d'un kit")
	case <-time.After(100 * time.Millisecond):
	}
	release()
	<-done
}

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
	sums     string
	msi      []byte
	msiCalls atomic.Int32
	zipCalls atomic.Int32
	msiDown  bool
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

func newFake(t *testing.T, ver string) *fakeGitHub {
	g := &fakeGitHub{tag: "v" + ver}
	g.zip = agentZip(t, ver, map[string][]byte{"kura-agent.exe": []byte("MZ agent"), "kura-agentw.exe": []byte("MZ agentw")})
	g.sums = fmt.Sprintf("%s  kura-agent_%s_windows_amd64.zip\n%s  kura-agent_%s_windows_amd64.exe\n", sha256Hex(g.zip), ver, strings.Repeat("0", 64), ver)
	g.msi = append(append([]byte{}, msiMagic...), []byte("contenu du msi")...)
	g.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		base := "https://" + r.Host
		switch r.URL.Path {
		case "/releases/latest":
			fmt.Fprintf(w, `{"tag_name":%q,"assets":[{"name":"kura-agent_%[2]s_windows_amd64.zip","browser_download_url":"%[3]s/dl/zip"},{"name":"SHA256SUMS","browser_download_url":"%[3]s/dl/sums"}]}`,
				g.tag, strings.TrimPrefix(g.tag, "v"), base)
		case "/dl/zip":
			g.zipCalls.Add(1)
			w.Write(g.zip)
		case "/dl/sums":
			io.WriteString(w, g.sums)
		case "/AWSCLIV2.msi":
			g.msiCalls.Add(1)
			if g.msiDown {
				http.Error(w, "indisponible", http.StatusServiceUnavailable)
				return
			}
			w.Write(g.msi)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(g.srv.Close)
	return g
}

func (g *fakeGitHub) source(dir string, now time.Time) *Source {
	return &Source{HTTP: g.srv.Client(), ReleasesAPI: g.srv.URL + "/releases/latest", MSIURL: g.srv.URL + "/AWSCLIV2.msi",
		AssetPrefix: g.srv.URL + "/dl/", CacheDir: dir, Now: func() time.Time { return now }}
}

func TestPrepareAndWrite(t *testing.T) {
	g := newFake(t, "0.6.0")
	dir := t.TempDir()
	now := time.Now()
	src := g.source(dir, now)
	c, release, err := src.Prepare(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	release()
	if c.AgentVersion != "0.6.0" || c.AgentSHA256 != sha256Hex([]byte("MZ agent")) || c.MSISHA256 != sha256Hex(g.msi) {
		t.Fatalf("%+v", c)
	}
	// Deuxième préparation : tout vient du cache.
	if _, release, err := src.Prepare(context.Background()); err != nil || g.zipCalls.Load() != 1 || g.msiCalls.Load() != 1 {
		t.Fatalf("cache non utilisé : %v zip=%d msi=%d", err, g.zipCalls.Load(), g.msiCalls.Load())
	} else {
		release()
	}

	var out bytes.Buffer
	if err := Write(&out, Kit{Folder: "kura-acme-srv01", PackName: "acme-srv01.kura", Pack: []byte(`{"format":"kura-pack"}`),
		Readme: "ligne 1\nligne 2\n", Components: c, GeneratedAt: now}); err != nil {
		t.Fatal(err)
	}
	zr, err := zip.NewReader(bytes.NewReader(out.Bytes()), int64(out.Len()))
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, f := range zr.File {
		rc, _ := f.Open()
		b, _ := io.ReadAll(rc)
		rc.Close()
		got[f.Name] = string(b)
	}
	want := map[string]string{
		"kura-acme-srv01/LISEZMOI.txt":    "ligne 1\r\nligne 2\r\n",
		"kura-acme-srv01/acme-srv01.kura": `{"format":"kura-pack"}`,
		"kura-acme-srv01/kura-agent.exe":  "MZ agent",
		"kura-acme-srv01/kura-agentw.exe": "MZ agentw",
		"kura-acme-srv01/AWSCLIV2.msi":    string(g.msi),
	}
	if len(got) != len(want) {
		t.Fatalf("contenu : %v", got)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %q", k, got[k])
		}
	}
}

func TestPrepareRefusals(t *testing.T) {
	t.Run("version trop ancienne", func(t *testing.T) {
		g := newFake(t, "0.5.2")
		if _, _, err := g.source(t.TempDir(), time.Now()).Prepare(context.Background()); err == nil || !strings.Contains(err.Error(), MinAgent) {
			t.Fatal(err)
		}
	})
	t.Run("somme fausse", func(t *testing.T) {
		g := newFake(t, "0.6.0")
		g.sums = strings.Replace(g.sums, sha256Hex(g.zip), strings.Repeat("a", 64), 1)
		if _, _, err := g.source(t.TempDir(), time.Now()).Prepare(context.Background()); err == nil || !strings.Contains(err.Error(), "SHA") {
			t.Fatal(err)
		}
	})
	t.Run("exécutable manquant", func(t *testing.T) {
		g := newFake(t, "0.6.0")
		g.zip = agentZip(t, "0.6.0", map[string][]byte{"kura-agent.exe": []byte("MZ agent")})
		g.sums = fmt.Sprintf("%s  kura-agent_0.6.0_windows_amd64.zip\n", sha256Hex(g.zip))
		if _, _, err := g.source(t.TempDir(), time.Now()).Prepare(context.Background()); err == nil {
			t.Fatal("accepté")
		}
	})
	t.Run("pas un MSI", func(t *testing.T) {
		g := newFake(t, "0.6.0")
		g.msi = []byte("<html>erreur</html>")
		if _, _, err := g.source(t.TempDir(), time.Now()).Prepare(context.Background()); err == nil {
			t.Fatal("accepté")
		}
	})
}

func TestMSIRefreshAndOffline(t *testing.T) {
	g := newFake(t, "0.6.0")
	dir := t.TempDir()
	now := time.Now()
	if _, _, err := g.source(dir, now).Prepare(context.Background()); err != nil {
		t.Fatal(err)
	}
	// Vieux de plus de 30 jours : retéléchargé.
	later := now.Add(MSIMaxAge + time.Hour)
	if _, _, err := g.source(dir, later).Prepare(context.Background()); err != nil || g.msiCalls.Load() != 2 {
		t.Fatalf("%v, %d appels", err, g.msiCalls.Load())
	}
	// AWS injoignable : le MSI en cache sert encore.
	g.msiDown = true
	c, _, err := g.source(dir, later.Add(MSIMaxAge+time.Hour)).Prepare(context.Background())
	if err != nil || c.MSI == "" {
		t.Fatalf("hors ligne : %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, MSIName+".part")); !os.IsNotExist(err) {
		t.Fatal("fichier partiel laissé")
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
	if _, _, err := src.Prepare(context.Background()); err == nil || !strings.Contains(err.Error(), "adresse inattendue") {
		t.Fatal(err)
	}
}

func TestPrepareBlocksRefreshWhileWriting(t *testing.T) {
	g := newFake(t, "0.6.0")
	dir := t.TempDir()
	src := g.source(dir, time.Now())
	_, release, err := src.Prepare(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		if _, r, err := src.Prepare(context.Background()); err == nil {
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

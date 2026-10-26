// Package kit assemble le kit d'installation d'un poste : un zip avec kura-agent
// (dernière version publiée), le MSI de la CLI AWS v2 et le paquet .kura, plus un
// LISEZMOI. Sur le poste, une seule commande installe tout :
//
//	kura-agent.exe install --package <bucket>.kura
//
// Les composants sont téléchargés une fois et gardés en cache dans le dossier de
// données de la console. Le zip de kura-agent est vérifié avec le SHA256SUMS de sa
// release ; la signature Authenticode du MSI (Amazon) est vérifiée par kura-agent,
// sur le poste, avant de l'installer.
package kit

import (
	"archive/zip"
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	// ReleasesAPI : dernière release publiée de kura-agent (dépôt public).
	ReleasesAPI = "https://api.github.com/repos/E-C-G/kura-agent/releases/latest"
	// MSIURL : CLI AWS v2 pour Windows, dernière version.
	MSIURL = "https://awscli.amazonaws.com/AWSCLIV2.msi"
	// MSIName : nom attendu par kura-agent à côté du paquet.
	MSIName = "AWSCLIV2.msi"
	// MinAgent : première version de kura-agent qui installe depuis un paquet.
	MinAgent = "0.6.0"
	// MSIMaxAge : au-delà, le MSI en cache est retéléchargé (versions récentes).
	MSIMaxAge = 30 * 24 * time.Hour

	maxMSI      = 300 << 20
	maxAgentZip = 100 << 20
	maxExe      = 60 << 20
)

// msiMagic : en-tête d'un fichier composé OLE (format MSI).
var msiMagic = []byte{0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1}

// Source télécharge et garde en cache les composants du kit.
type Source struct {
	HTTP        *http.Client
	ReleasesAPI string
	MSIURL      string
	CacheDir    string
	Now         func() time.Time

	mu sync.Mutex // une préparation à la fois (fichiers du cache)
}

// NewSource : source réelle, cache dans dir.
func NewSource(dir string) *Source {
	return &Source{HTTP: &http.Client{Timeout: 15 * time.Minute}, ReleasesAPI: ReleasesAPI, MSIURL: MSIURL, CacheDir: dir, Now: time.Now}
}

// Components : fichiers prêts à mettre dans le kit.
type Components struct {
	AgentVersion        string
	AgentExe, AgentWExe string // chemins dans le cache
	AgentSHA256         string // kura-agent.exe
	MSI                 string
	MSISHA256           string
	MSIDate             time.Time
}

type release struct {
	TagName string `json:"tag_name"`
	Assets  []struct {
		Name string `json:"name"`
		URL  string `json:"browser_download_url"`
	} `json:"assets"`
}

// Prepare garantit la présence en cache de la dernière version de kura-agent et du
// MSI de la CLI AWS.
func (s *Source) Prepare(ctx context.Context) (Components, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := os.MkdirAll(s.CacheDir, 0o700); err != nil {
		return Components{}, err
	}
	c, err := s.agent(ctx)
	if err != nil {
		return Components{}, fmt.Errorf("kura-agent : %w", err)
	}
	if err := s.msi(ctx, &c); err != nil {
		return Components{}, fmt.Errorf("CLI AWS : %w", err)
	}
	return c, nil
}

func (s *Source) agent(ctx context.Context) (Components, error) {
	var rel release
	body, err := s.get(ctx, s.ReleasesAPI, 1<<20)
	if err != nil {
		return Components{}, fmt.Errorf("dernière release : %w", err)
	}
	if err := json.Unmarshal(body, &rel); err != nil {
		return Components{}, fmt.Errorf("dernière release illisible : %w", err)
	}
	ver := strings.TrimPrefix(rel.TagName, "v")
	if !AtLeast(ver, MinAgent) {
		return Components{}, fmt.Errorf("dernière version publiée %q : %s ou plus récente nécessaire pour installer depuis un paquet", rel.TagName, MinAgent)
	}
	c := Components{AgentVersion: ver}
	dir := filepath.Join(s.CacheDir, "kura-agent-"+ver)
	c.AgentExe, c.AgentWExe = filepath.Join(dir, "kura-agent.exe"), filepath.Join(dir, "kura-agentw.exe")
	if sum, err := os.ReadFile(filepath.Join(dir, "kura-agent.exe.sha256")); err == nil && exists(c.AgentExe) && exists(c.AgentWExe) {
		c.AgentSHA256 = strings.TrimSpace(string(sum))
		if h, err := fileSHA256(c.AgentExe); err == nil && h == c.AgentSHA256 {
			return c, nil
		}
	}

	zipName := "kura-agent_" + ver + "_windows_amd64.zip"
	urls := map[string]string{}
	for _, a := range rel.Assets {
		urls[a.Name] = a.URL
	}
	if urls[zipName] == "" || urls["SHA256SUMS"] == "" {
		return Components{}, fmt.Errorf("release %s incomplète (%s et SHA256SUMS attendus)", rel.TagName, zipName)
	}
	sums, err := s.get(ctx, urls["SHA256SUMS"], 64<<10)
	if err != nil {
		return Components{}, fmt.Errorf("SHA256SUMS : %w", err)
	}
	want := sumFor(sums, zipName)
	if want == "" {
		return Components{}, fmt.Errorf("%s absent de SHA256SUMS", zipName)
	}
	data, err := s.get(ctx, urls[zipName], maxAgentZip)
	if err != nil {
		return Components{}, fmt.Errorf("%s : %w", zipName, err)
	}
	if got := sha256Hex(data); got != want {
		return Components{}, fmt.Errorf("%s : somme SHA-256 %s, SHA256SUMS annonce %s", zipName, got, want)
	}
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return Components{}, fmt.Errorf("%s : %w", zipName, err)
	}
	found := map[string][]byte{}
	for _, f := range zr.File {
		base := f.Name[strings.LastIndex(f.Name, "/")+1:]
		if base != "kura-agent.exe" && base != "kura-agentw.exe" {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return Components{}, err
		}
		b, err := io.ReadAll(io.LimitReader(rc, maxExe+1))
		rc.Close()
		if err != nil {
			return Components{}, err
		}
		if len(b) > maxExe || !bytes.HasPrefix(b, []byte("MZ")) {
			return Components{}, fmt.Errorf("%s : %s n'est pas un exécutable Windows", zipName, base)
		}
		found[base] = b
	}
	if found["kura-agent.exe"] == nil || found["kura-agentw.exe"] == nil {
		return Components{}, fmt.Errorf("%s : kura-agent.exe ou kura-agentw.exe absent", zipName)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return Components{}, err
	}
	for name, b := range found {
		if err := writeAtomic(filepath.Join(dir, name), b); err != nil {
			return Components{}, err
		}
	}
	c.AgentSHA256 = sha256Hex(found["kura-agent.exe"])
	if err := writeAtomic(filepath.Join(dir, "kura-agent.exe.sha256"), []byte(c.AgentSHA256+"\n")); err != nil {
		return Components{}, err
	}
	return c, nil
}

func (s *Source) msi(ctx context.Context, c *Components) error {
	c.MSI = filepath.Join(s.CacheDir, MSIName)
	st, err := os.Stat(c.MSI)
	if err != nil || s.Now().Sub(st.ModTime()) > MSIMaxAge || !hasMSIMagic(c.MSI) {
		tmp := c.MSI + ".part"
		if err := s.download(ctx, s.MSIURL, tmp, maxMSI); err != nil {
			os.Remove(tmp)
			if err2 := checkCached(c.MSI); err2 == nil {
				// Hors ligne : le MSI en cache reste utilisable (kura-agent vérifie
				// sa signature sur le poste).
				return s.describeMSI(c)
			}
			return err
		}
		if !hasMSIMagic(tmp) {
			os.Remove(tmp)
			return errors.New("le fichier téléchargé n'est pas un MSI")
		}
		if err := os.Rename(tmp, c.MSI); err != nil {
			return err
		}
	}
	return s.describeMSI(c)
}

func checkCached(p string) error {
	if !hasMSIMagic(p) {
		return errors.New("pas de MSI en cache")
	}
	return nil
}

func (s *Source) describeMSI(c *Components) error {
	st, err := os.Stat(c.MSI)
	if err != nil {
		return err
	}
	c.MSIDate = st.ModTime()
	c.MSISHA256, err = fileSHA256(c.MSI)
	return err
}

func (s *Source) get(ctx context.Context, url string, limit int64) ([]byte, error) {
	if !strings.HasPrefix(url, "https://") {
		return nil, fmt.Errorf("adresse non HTTPS refusée : %s", url)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "kura-ctl")
	resp, err := s.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %s", resp.Status)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err == nil && int64(len(b)) > limit {
		err = errors.New("réponse anormalement grosse")
	}
	return b, err
}

func (s *Source) download(ctx context.Context, url, dst string, limit int64) error {
	if !strings.HasPrefix(url, "https://") {
		return fmt.Errorf("adresse non HTTPS refusée : %s", url)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "kura-ctl")
	resp, err := s.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %s", resp.Status)
	}
	f, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	n, err := io.Copy(f, io.LimitReader(resp.Body, limit+1))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil && n > limit {
		err = errors.New("fichier anormalement gros")
	}
	return err
}

// Kit décrit un kit à écrire.
type Kit struct {
	Folder      string // dossier racine dans le zip
	PackName    string // <bucket>.kura
	Pack        []byte
	Readme      string // LISEZMOI.txt (fins de ligne converties en CRLF)
	Components  Components
	GeneratedAt time.Time
}

// Write écrit le zip du kit dans w.
func Write(w io.Writer, k Kit) error {
	zw := zip.NewWriter(w)
	add := func(name string, r io.Reader) error {
		h := &zip.FileHeader{Name: k.Folder + "/" + name, Method: zip.Deflate, Modified: k.GeneratedAt}
		f, err := zw.CreateHeader(h)
		if err != nil {
			return err
		}
		_, err = io.Copy(f, r)
		return err
	}
	addFile := func(name, path string) error {
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		defer f.Close()
		return add(name, bufio.NewReader(f))
	}
	readme := strings.ReplaceAll(strings.ReplaceAll(k.Readme, "\r\n", "\n"), "\n", "\r\n")
	steps := []func() error{
		func() error { return add("LISEZMOI.txt", strings.NewReader(readme)) },
		func() error { return add(k.PackName, bytes.NewReader(k.Pack)) },
		func() error { return addFile("kura-agent.exe", k.Components.AgentExe) },
		func() error { return addFile("kura-agentw.exe", k.Components.AgentWExe) },
		func() error { return addFile(MSIName, k.Components.MSI) },
	}
	for _, step := range steps {
		if err := step(); err != nil {
			return err
		}
	}
	return zw.Close()
}

// AtLeast compare deux versions x.y.z (suffixe -… ignoré).
func AtLeast(v, min string) bool {
	parse := func(s string) [3]int {
		s, _, _ = strings.Cut(s, "-")
		var out [3]int
		for i, p := range strings.SplitN(s, ".", 3) {
			n, err := strconv.Atoi(p)
			if err != nil {
				return [3]int{-1}
			}
			out[i] = n
		}
		return out
	}
	a, b := parse(v), parse(min)
	if a[0] < 0 {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return a[i] > b[i]
		}
	}
	return true
}

func sumFor(sums []byte, name string) string {
	for _, line := range strings.Split(string(sums), "\n") {
		f := strings.Fields(line)
		if len(f) == 2 && strings.TrimPrefix(f[1], "*") == name && len(f[0]) == 64 {
			return strings.ToLower(f[0])
		}
	}
	return ""
}

func sha256Hex(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func fileSHA256(p string) (string, error) {
	f, err := os.Open(p)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func hasMSIMagic(p string) bool {
	f, err := os.Open(p)
	if err != nil {
		return false
	}
	defer f.Close()
	b := make([]byte, len(msiMagic))
	if _, err := io.ReadFull(f, b); err != nil {
		return false
	}
	return bytes.Equal(b, msiMagic)
}

func exists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && st.Mode().IsRegular()
}

func writeAtomic(p string, b []byte) error {
	tmp := p + ".part"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, p)
}

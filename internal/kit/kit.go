// Package kit assemble le kit d'installation d'un poste : un zip avec kura-agent
// (dernière version publiée), la CLI AWS v2 telle qu'AWS la distribue et le paquet
// .kura, plus un LISEZMOI. Sur le poste, une seule commande installe tout :
//
//	Windows   kura-agent.exe install --package <bucket>.kura
//	          (kura-agent.exe, kura-agentw.exe, AWSCLIV2.msi)
//	Ubuntu    sudo apt install ./kura-agent_<version>_<arch>.deb
//	          sudo kura-agent install --package <bucket>.kura
//	          (paquet .deb, awscli-exe-linux-<arch>.zip et sa signature .sig)
//
// Les composants sont téléchargés une fois et gardés en cache dans le dossier de
// données de la console. kura-agent (zip Windows ou paquet .deb) est vérifié avec le
// SHA256SUMS de sa release ; la signature de la CLI AWS (Authenticode du MSI, PGP du
// zip Linux) est vérifiée par kura-agent, sur le poste, avant de l'installer.
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
	// AWSBaseURL : distribution officielle de la CLI AWS v2.
	AWSBaseURL = "https://awscli.amazonaws.com/"
	// MSIName : CLI AWS v2 pour Windows, nom attendu par kura-agent à côté du paquet.
	MSIName = "AWSCLIV2.msi"
	// MinAgent : première version de kura-agent qui installe depuis un paquet (Windows).
	MinAgent = "0.6.0"
	// MinAgentLinux : première version publiée en paquet .deb, qui installe sous Linux.
	MinAgentLinux = "0.7.0"
	// AssetPrefix : seules adresses de téléchargement acceptées pour kura-agent.
	AssetPrefix = "https://github.com/E-C-G/kura-agent/releases/download/"
	// AWSMaxAge : au-delà, la CLI AWS en cache est retéléchargée (versions récentes).
	AWSMaxAge = 30 * 24 * time.Hour

	maxAWS      = 300 << 20
	maxSig      = 64 << 10
	maxAgentZip = 100 << 20
	maxDeb      = 100 << 20
	maxExe      = 60 << 20
)

var (
	// msiMagic : en-tête d'un fichier composé OLE (format MSI).
	msiMagic = []byte{0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1}
	zipMagic = []byte("PK\x03\x04")
	// debMagic : archive ar dont le premier membre est debian-binary.
	debMagic = []byte("!<arch>\ndebian-binary")
)

// Target : système et architecture du poste (GOOS et GOARCH de kura-agent).
type Target struct{ OS, Arch string }

// Windows : poste Windows 64 bits.
var Windows = Target{OS: "windows", Arch: "amd64"}

func (t Target) String() string { return t.OS + "/" + t.Arch }

// Linux : poste Linux (Ubuntu), paquet .deb.
func (t Target) Linux() bool { return t.OS == "linux" }

// awsArch : architecture dans le nom du zip de la CLI AWS pour Linux.
func (t Target) awsArch() string {
	return map[string]string{"amd64": "x86_64", "arm64": "aarch64"}[t.Arch]
}

func (t Target) check() error {
	switch {
	case t == Windows:
		return nil
	case t.Linux() && t.awsArch() != "":
		return nil
	}
	return fmt.Errorf("pas de kit pour %s", t)
}

// AWSName : fichier de la CLI AWS pour ce système, nom attendu par kura-agent.
func (t Target) AWSName() string {
	if t.Linux() {
		return "awscli-exe-linux-" + t.awsArch() + ".zip"
	}
	return MSIName
}

// Source télécharge et garde en cache les composants du kit.
type Source struct {
	HTTP        *http.Client
	ReleasesAPI string
	AWSBaseURL  string
	AssetPrefix string
	CacheDir    string
	Now         func() time.Time

	// mu : une préparation à la fois ; les kits en cours d'écriture tiennent un
	// verrou en lecture, pour qu'aucune préparation ne remplace un fichier lu.
	mu sync.RWMutex
}

// NewSource : source réelle, cache dans dir.
func NewSource(dir string) *Source {
	return &Source{HTTP: &http.Client{Timeout: 15 * time.Minute, CheckRedirect: httpsOnly}, ReleasesAPI: ReleasesAPI, AWSBaseURL: AWSBaseURL,
		AssetPrefix: AssetPrefix, CacheDir: dir, Now: time.Now}
}

// httpsOnly refuse une redirection vers une adresse non HTTPS.
func httpsOnly(r *http.Request, via []*http.Request) error {
	if r.URL.Scheme != "https" {
		return fmt.Errorf("redirection non HTTPS refusée : %s", r.URL)
	}
	if len(via) >= 10 {
		return errors.New("trop de redirections")
	}
	return nil
}

// File : fichier du cache à mettre dans le kit.
type File struct {
	Name string // nom dans le kit
	Path string // chemin dans le cache
}

// Components : fichiers prêts à mettre dans le kit.
type Components struct {
	Target       Target
	AgentVersion string
	AgentFile    string // kura-agent.exe, ou le paquet .deb
	AgentSHA256  string // de AgentFile
	AWSFile      string // AWSCLIV2.msi, ou awscli-exe-linux-<arch>.zip (avec .sig)
	AWSSHA256    string
	AWSDate      time.Time
	Files        []File // dans l'ordre du kit, LISEZMOI et paquet .kura en plus
}

type release struct {
	TagName string `json:"tag_name"`
	Assets  []struct {
		Name string `json:"name"`
		URL  string `json:"browser_download_url"`
	} `json:"assets"`
}

// Prepare garantit la présence en cache de la dernière version de kura-agent et de
// la CLI AWS pour le système t. En cas de succès, release doit être appelé une fois
// le kit écrit : jusque-là, les fichiers du cache ne sont pas remplacés.
func (s *Source) Prepare(ctx context.Context, t Target) (c Components, release func(), err error) {
	if err := t.check(); err != nil {
		return Components{}, nil, err
	}
	s.mu.Lock()
	c, err = s.prepare(ctx, t)
	s.mu.Unlock()
	if err != nil {
		return Components{}, nil, err
	}
	s.mu.RLock()
	return c, s.mu.RUnlock, nil
}

func (s *Source) prepare(ctx context.Context, t Target) (Components, error) {
	if err := os.MkdirAll(s.CacheDir, 0o700); err != nil {
		return Components{}, err
	}
	c := Components{Target: t}
	var err error
	if t.Linux() {
		err = s.agentDeb(ctx, &c)
	} else {
		err = s.agentWindows(ctx, &c)
	}
	if err != nil {
		return Components{}, fmt.Errorf("kura-agent : %w", err)
	}
	if err := s.awsCLI(ctx, &c); err != nil {
		return Components{}, fmt.Errorf("CLI AWS : %w", err)
	}
	return c, nil
}

// latest lit la dernière release et vérifie qu'elle convient au système.
func (s *Source) latest(ctx context.Context, min string) (release, string, error) {
	var rel release
	body, err := s.get(ctx, s.ReleasesAPI, 1<<20)
	if err != nil {
		return rel, "", fmt.Errorf("dernière release : %w", err)
	}
	if err := json.Unmarshal(body, &rel); err != nil {
		return rel, "", fmt.Errorf("dernière release illisible : %w", err)
	}
	ver := strings.TrimPrefix(rel.TagName, "v")
	if !AtLeast(ver, min) {
		return rel, "", fmt.Errorf("dernière version publiée %q : %s ou plus récente nécessaire pour installer depuis un paquet", rel.TagName, min)
	}
	return rel, ver, nil
}

// asset télécharge un fichier de la release, vérifié avec son SHA256SUMS.
func (s *Source) asset(ctx context.Context, rel release, name string, limit int64) ([]byte, error) {
	urls := map[string]string{}
	for _, a := range rel.Assets {
		urls[a.Name] = a.URL
	}
	if urls[name] == "" || urls["SHA256SUMS"] == "" {
		return nil, fmt.Errorf("release %s incomplète (%s et SHA256SUMS attendus)", rel.TagName, name)
	}
	for _, n := range []string{name, "SHA256SUMS"} {
		if !strings.HasPrefix(urls[n], s.AssetPrefix) {
			return nil, fmt.Errorf("%s : adresse inattendue %s", n, urls[n])
		}
	}
	sums, err := s.get(ctx, urls["SHA256SUMS"], 64<<10)
	if err != nil {
		return nil, fmt.Errorf("SHA256SUMS : %w", err)
	}
	want := sumFor(sums, name)
	if want == "" {
		return nil, fmt.Errorf("%s absent de SHA256SUMS", name)
	}
	data, err := s.get(ctx, urls[name], limit)
	if err != nil {
		return nil, fmt.Errorf("%s : %w", name, err)
	}
	if got := sha256Hex(data); got != want {
		return nil, fmt.Errorf("%s : somme SHA-256 %s, SHA256SUMS annonce %s", name, got, want)
	}
	return data, nil
}

// cachedSHA256 : somme enregistrée à côté de p, si p est intact.
func cachedSHA256(p string) (string, bool) {
	sum, err := os.ReadFile(p + ".sha256")
	if err != nil || !exists(p) {
		return "", false
	}
	want := strings.TrimSpace(string(sum))
	h, err := fileSHA256(p)
	return want, err == nil && h == want
}

func (s *Source) agentWindows(ctx context.Context, c *Components) error {
	rel, ver, err := s.latest(ctx, MinAgent)
	if err != nil {
		return err
	}
	c.AgentVersion, c.AgentFile = ver, "kura-agent.exe"
	dir := filepath.Join(s.CacheDir, "kura-agent-"+ver)
	exe, wexe := filepath.Join(dir, "kura-agent.exe"), filepath.Join(dir, "kura-agentw.exe")
	c.Files = []File{{"kura-agent.exe", exe}, {"kura-agentw.exe", wexe}}
	if sum, ok := cachedSHA256(exe); ok && exists(wexe) {
		c.AgentSHA256 = sum
		return nil
	}

	zipName := "kura-agent_" + ver + "_windows_amd64.zip"
	data, err := s.asset(ctx, rel, zipName, maxAgentZip)
	if err != nil {
		return err
	}
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return fmt.Errorf("%s : %w", zipName, err)
	}
	found := map[string][]byte{}
	for _, f := range zr.File {
		base := f.Name[strings.LastIndex(f.Name, "/")+1:]
		if base != "kura-agent.exe" && base != "kura-agentw.exe" {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return err
		}
		b, err := io.ReadAll(io.LimitReader(rc, maxExe+1))
		rc.Close()
		if err != nil {
			return err
		}
		if len(b) > maxExe || !bytes.HasPrefix(b, []byte("MZ")) {
			return fmt.Errorf("%s : %s n'est pas un exécutable Windows", zipName, base)
		}
		found[base] = b
	}
	if found["kura-agent.exe"] == nil || found["kura-agentw.exe"] == nil {
		return fmt.Errorf("%s : kura-agent.exe ou kura-agentw.exe absent", zipName)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	for name, b := range found {
		if err := writeAtomic(filepath.Join(dir, name), b); err != nil {
			return err
		}
	}
	c.AgentSHA256 = sha256Hex(found["kura-agent.exe"])
	return writeAtomic(exe+".sha256", []byte(c.AgentSHA256+"\n"))
}

// DebName : nom du paquet .deb d'une version (préversion 0.8.0-rc1 : 0.8.0~rc1).
func DebName(ver, arch string) string {
	return "kura-agent_" + strings.Replace(ver, "-", "~", 1) + "_" + arch + ".deb"
}

func (s *Source) agentDeb(ctx context.Context, c *Components) error {
	rel, ver, err := s.latest(ctx, MinAgentLinux)
	if err != nil {
		return err
	}
	name := DebName(ver, c.Target.Arch)
	dir := filepath.Join(s.CacheDir, "kura-agent-"+ver)
	deb := filepath.Join(dir, name)
	c.AgentVersion, c.AgentFile = ver, name
	c.Files = []File{{name, deb}}
	if sum, ok := cachedSHA256(deb); ok {
		c.AgentSHA256 = sum
		return nil
	}
	data, err := s.asset(ctx, rel, name, maxDeb)
	if err != nil {
		return err
	}
	if !bytes.HasPrefix(data, debMagic) {
		return fmt.Errorf("%s n'est pas un paquet Debian", name)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if err := writeAtomic(deb, data); err != nil {
		return err
	}
	c.AgentSHA256 = sha256Hex(data)
	return writeAtomic(deb+".sha256", []byte(c.AgentSHA256+"\n"))
}

// awsCLI garde en cache la CLI AWS du système (et sa signature sous Linux), rafraîchie
// après AWSMaxAge. AWS injoignable : la copie en cache reste utilisable, kura-agent
// vérifiant la signature sur le poste.
func (s *Source) awsCLI(ctx context.Context, c *Components) error {
	name := c.Target.AWSName()
	main := File{Name: name, Path: filepath.Join(s.CacheDir, name)}
	files := []File{main}
	valid := func(p string) bool { return hasMagic(p, msiMagic) }
	if c.Target.Linux() {
		files = append(files, File{Name: name + ".sig", Path: main.Path + ".sig"})
		valid = func(p string) bool { return hasMagic(p, zipMagic) }
	}
	ok := func(suffix string) bool {
		if !valid(main.Path + suffix) {
			return false
		}
		return len(files) == 1 || validSig(files[1].Path+suffix)
	}
	st, err := os.Stat(main.Path)
	if err != nil || s.Now().Sub(st.ModTime()) > AWSMaxAge || !ok("") {
		err := s.downloadAll(ctx, files)
		if err == nil && !ok(".part") {
			err = fmt.Errorf("le fichier téléchargé n'est pas %s", name)
		}
		if err == nil {
			for _, f := range files {
				if err = os.Rename(f.Path+".part", f.Path); err != nil {
					break
				}
			}
		}
		for _, f := range files {
			os.Remove(f.Path + ".part")
		}
		if err != nil && !ok("") {
			return err
		}
	}
	st, err = os.Stat(main.Path)
	if err != nil {
		return err
	}
	c.AWSFile, c.AWSDate = name, st.ModTime()
	if c.AWSSHA256, err = fileSHA256(main.Path); err != nil {
		return err
	}
	c.Files = append(c.Files, files...)
	return nil
}

func (s *Source) downloadAll(ctx context.Context, files []File) error {
	for i, f := range files {
		limit := int64(maxAWS)
		if i > 0 {
			limit = maxSig
		}
		if err := s.download(ctx, s.AWSBaseURL+f.Name, f.Path+".part", limit); err != nil {
			return fmt.Errorf("%s : %w", f.Name, err)
		}
	}
	return nil
}

// validSig : signature PGP détachée, armurée ou binaire.
func validSig(p string) bool {
	b, err := os.ReadFile(p)
	if err != nil || len(b) == 0 || len(b) > maxSig {
		return false
	}
	return bytes.HasPrefix(b, []byte("-----BEGIN PGP SIGNATURE-----")) || b[0]&0x80 != 0
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
	Readme      string // LISEZMOI.txt (fins de ligne CRLF pour Windows)
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
	readme := strings.ReplaceAll(k.Readme, "\r\n", "\n")
	if !k.Components.Target.Linux() {
		readme = strings.ReplaceAll(readme, "\n", "\r\n")
	}
	if err := add("LISEZMOI.txt", strings.NewReader(readme)); err != nil {
		return err
	}
	if err := add(k.PackName, bytes.NewReader(k.Pack)); err != nil {
		return err
	}
	for _, f := range k.Components.Files {
		if err := addFile(f.Name, f.Path); err != nil {
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

func hasMagic(p string, magic []byte) bool {
	f, err := os.Open(p)
	if err != nil {
		return false
	}
	defer f.Close()
	b := make([]byte, len(magic))
	if _, err := io.ReadFull(f, b); err != nil {
		return false
	}
	return bytes.Equal(b, magic)
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

package web

import (
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/E-C-G/kura-ctl/internal/secrets"
	"github.com/E-C-G/kura-ctl/internal/store"
	"github.com/E-C-G/kura-ctl/internal/wasabi"
)

// TestServeForBrowser sert la console (compte Wasabi factice) pour un essai dans un
// vrai navigateur : KURA_E2E=<fichier> y écrit l'adresse, puis sert jusqu'à ce que
// <fichier>.fin existe (2 min au plus). Ignoré sans KURA_E2E.
func TestServeForBrowser(t *testing.T) {
	out := os.Getenv("KURA_E2E")
	if out == "" {
		t.Skip("KURA_E2E non défini")
	}
	st, err := store.Open(filepath.Join(t.TempDir(), "k.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	srv := &Server{
		Store: st, Vault: &secrets.Vault{Keyring: &memKeyring{m: map[string]string{}}, Iterations: 1000},
		NewAccount: func(k wasabi.Keys) Wasabi { return newFakeAccount(k) },
		Log:        slog.New(slog.NewTextHandler(io.Discard, nil)),
		Kit:        &fakeKit{t: t, dir: t.TempDir()},
		// Horloge en avance sur le délai de grâce : une clé désactivée peut être
		// supprimée tout de suite (deux clés au plus chez Wasabi).
		Now: func() time.Time { return time.Now().Add(KeyGrace + time.Hour) },
	}
	ln, err := srv.Listen("0")
	if err != nil {
		t.Fatal(err)
	}
	h, err := srv.Handler()
	if err != nil {
		t.Fatal(err)
	}
	go http.Serve(ln, h)
	if err := os.WriteFile(out, []byte(srv.URL()), 0o600); err != nil {
		t.Fatal(err)
	}
	for end := time.Now().Add(2 * time.Minute); time.Now().Before(end); time.Sleep(200 * time.Millisecond) {
		if _, err := os.Stat(out + ".fin"); err == nil {
			break
		}
	}
	srv.lock("fin")
	ln.Close()
}

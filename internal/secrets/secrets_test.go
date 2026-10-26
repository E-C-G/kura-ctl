package secrets

import (
	"errors"
	"strings"
	"testing"

	"github.com/zalando/go-keyring"
)

type memKeyring map[string]string

func (m memKeyring) Get(s, u string) (string, error) {
	v, ok := m[s+"/"+u]
	if !ok {
		return "", keyring.ErrNotFound
	}
	return v, nil
}
func (m memKeyring) Set(s, u, v string) error { m[s+"/"+u] = v; return nil }
func (m memKeyring) Delete(s, u string) error {
	if _, ok := m[s+"/"+u]; !ok {
		return keyring.ErrNotFound
	}
	delete(m, s+"/"+u)
	return nil
}

func TestStoreUnlock(t *testing.T) {
	kr := memKeyring{}
	v := &Vault{Keyring: kr, Iterations: 1000}
	if ok, err := v.Exists(); ok || err != nil {
		t.Fatalf("coffre vide : %v %v", ok, err)
	}
	if _, err := v.Unlock("peu importe"); !errors.Is(err, ErrNotSetUp) {
		t.Fatalf("attendu ErrNotSetUp, reçu %v", err)
	}
	k := Keys{AccessKeyID: "AKIDTEST", SecretAccessKey: "secret/éè+xyz"}
	if err := v.Store("court", k); err == nil {
		t.Fatal("mot de passe trop court accepté")
	}
	if err := v.Store("un mot de passe solide", Keys{AccessKeyID: "x"}); err == nil {
		t.Fatal("clé incomplète acceptée")
	}
	if err := v.Store("un mot de passe solide", k); err != nil {
		t.Fatal(err)
	}
	blob := kr["kura-ctl/wasabi-admin"]
	if strings.Contains(blob, "AKIDTEST") || strings.Contains(blob, "secret") {
		t.Fatalf("clé en clair dans le trousseau : %s", blob)
	}
	if _, err := v.Unlock("un autre mot de passe"); !errors.Is(err, ErrWrongPassword) {
		t.Fatalf("mauvais mot de passe : %v", err)
	}
	got, err := v.Unlock("un mot de passe solide")
	if err != nil || got != k {
		t.Fatalf("déverrouillage : %+v %v", got, err)
	}
	// Deux enregistrements du même secret donnent des chiffrés différents (sel et nonce).
	_ = v.Store("un mot de passe solide", k)
	if kr["kura-ctl/wasabi-admin"] == blob {
		t.Fatal("chiffré identique : sel ou nonce réutilisé")
	}
	// Coffre altéré : refusé.
	b := []byte(kr["kura-ctl/wasabi-admin"])
	b[len(b)-2] ^= 1
	kr["kura-ctl/wasabi-admin"] = string(b)
	if _, err := v.Unlock("un mot de passe solide"); err == nil {
		t.Fatal("coffre altéré accepté")
	}
	if err := v.Reset(); err != nil || v.Reset() != nil {
		t.Fatal("reset")
	}
	if ok, _ := v.Exists(); ok {
		t.Fatal("coffre encore présent après reset")
	}
}

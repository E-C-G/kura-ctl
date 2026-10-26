// Package secrets garde la clé d'administration Wasabi de la console.
//
// La clé est chiffrée (AES-256-GCM) avec une clé dérivée du mot de passe maître
// (PBKDF2-SHA256), puis rangée dans le trousseau du système : Gestionnaire
// d'identifiants Windows, Trousseau macOS, Secret Service sous Linux. Le trousseau
// seul ne suffit donc pas à la lire, ni le mot de passe seul : il faut les deux.
// Elle n'est jamais écrite en clair sur disque ni journalisée.
package secrets

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/zalando/go-keyring"
)

const (
	service    = "kura-ctl"
	account    = "wasabi-admin"
	iterations = 600_000 // recommandation OWASP 2023 pour PBKDF2-HMAC-SHA256
	// maxIterations : au-delà, le coffre est tenu pour altéré (déverrouillage interminable).
	maxIterations = 10_000_000
	saltLen       = 16
	version       = "v1"
)

// MinPasswordLen : longueur minimale du mot de passe maître.
const MinPasswordLen = 12

var (
	// ErrNotSetUp : aucun coffre n'existe encore (premier lancement).
	ErrNotSetUp = errors.New("console pas encore configurée")
	// ErrWrongPassword : le mot de passe maître ne déchiffre pas le coffre.
	ErrWrongPassword = errors.New("mot de passe maître incorrect")
)

// Keys est la clé d'administration Wasabi.
type Keys struct {
	AccessKeyID     string `json:"access_key_id"`
	SecretAccessKey string `json:"secret_access_key"`
}

// Valid vérifie que les deux parties sont présentes.
func (k Keys) Valid() error {
	if strings.TrimSpace(k.AccessKeyID) == "" || strings.TrimSpace(k.SecretAccessKey) == "" {
		return errors.New("identifiant et clé secrète obligatoires")
	}
	return nil
}

// Keyring est le trousseau ; remplaçable dans les tests.
type Keyring interface {
	Get(service, user string) (string, error)
	Set(service, user, secret string) error
	Delete(service, user string) error
}

type systemKeyring struct{}

func (systemKeyring) Get(s, u string) (string, error) { return keyring.Get(s, u) }
func (systemKeyring) Set(s, u, v string) error        { return keyring.Set(s, u, v) }
func (systemKeyring) Delete(s, u string) error        { return keyring.Delete(s, u) }

// Vault est le coffre de la console.
type Vault struct {
	Keyring    Keyring
	Iterations int // 0 = valeur par défaut ; réduit dans les tests
}

// System renvoie le coffre adossé au trousseau du système.
func System() *Vault { return &Vault{Keyring: systemKeyring{}} }

func (v *Vault) iter() int {
	if v.Iterations > 0 {
		return v.Iterations
	}
	return iterations
}

// Exists indique si la console a déjà été configurée.
func (v *Vault) Exists() (bool, error) {
	_, err := v.Keyring.Get(service, account)
	if errors.Is(err, keyring.ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("trousseau du système : %w", err)
	}
	return true, nil
}

// Probe vérifie que le trousseau accepte une écriture, avant de demander quoi que
// ce soit d'autre (Linux sans Secret Service, trousseau verrouillé…).
func (v *Vault) Probe() error {
	if err := v.Keyring.Set(service, account+"-test", "ok"); err != nil {
		return fmt.Errorf("trousseau du système inutilisable : %w", err)
	}
	_ = v.Keyring.Delete(service, account+"-test")
	return nil
}

// CheckPassword vérifie la solidité minimale d'un nouveau mot de passe maître.
func CheckPassword(p string) error {
	if utf8.RuneCountInString(p) < MinPasswordLen {
		return fmt.Errorf("mot de passe maître trop court : %d caractères au moins", MinPasswordLen)
	}
	return nil
}

// Store chiffre la clé avec le mot de passe maître et la range dans le trousseau,
// en remplaçant la précédente.
func (v *Vault) Store(password string, k Keys) error {
	if err := CheckPassword(password); err != nil {
		return err
	}
	if err := k.Valid(); err != nil {
		return err
	}
	plain, err := json.Marshal(k)
	if err != nil {
		return err
	}
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return err
	}
	aead, err := v.aead(password, salt)
	if err != nil {
		return err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	sealed := aead.Seal(nil, nonce, plain, []byte(version))
	enc := base64.RawStdEncoding
	blob := strings.Join([]string{version, fmt.Sprint(v.iter()), enc.EncodeToString(salt),
		enc.EncodeToString(nonce), enc.EncodeToString(sealed)}, ".")
	if err := v.Keyring.Set(service, account, blob); err != nil {
		return fmt.Errorf("trousseau du système : %w", err)
	}
	return nil
}

// Unlock déchiffre la clé avec le mot de passe maître.
func (v *Vault) Unlock(password string) (Keys, error) {
	blob, err := v.Keyring.Get(service, account)
	if errors.Is(err, keyring.ErrNotFound) {
		return Keys{}, ErrNotSetUp
	}
	if err != nil {
		return Keys{}, fmt.Errorf("trousseau du système : %w", err)
	}
	parts := strings.Split(blob, ".")
	if len(parts) != 5 || parts[0] != version {
		return Keys{}, errors.New("coffre illisible (format inconnu)")
	}
	var iter int
	if _, err := fmt.Sscan(parts[1], &iter); err != nil || iter < 1 || iter > maxIterations {
		return Keys{}, errors.New("coffre illisible (itérations)")
	}
	enc := base64.RawStdEncoding
	salt, err1 := enc.DecodeString(parts[2])
	nonce, err2 := enc.DecodeString(parts[3])
	sealed, err3 := enc.DecodeString(parts[4])
	if err := errors.Join(err1, err2, err3); err != nil {
		return Keys{}, errors.New("coffre illisible (encodage)")
	}
	key, err := pbkdf2.Key(sha256.New, password, salt, iter, 32)
	if err != nil {
		return Keys{}, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return Keys{}, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return Keys{}, err
	}
	if len(nonce) != aead.NonceSize() {
		return Keys{}, errors.New("coffre illisible (nonce)")
	}
	plain, err := aead.Open(nil, nonce, sealed, []byte(version))
	if err != nil {
		return Keys{}, ErrWrongPassword
	}
	var k Keys
	if err := json.Unmarshal(plain, &k); err != nil {
		return Keys{}, errors.New("coffre illisible (contenu)")
	}
	return k, nil
}

// Reset efface le coffre (mot de passe oublié : il faudra ressaisir la clé).
func (v *Vault) Reset() error {
	err := v.Keyring.Delete(service, account)
	if errors.Is(err, keyring.ErrNotFound) {
		return nil
	}
	return err
}

func (v *Vault) aead(password string, salt []byte) (cipher.AEAD, error) {
	key, err := pbkdf2.Key(sha256.New, password, salt, v.iter(), 32)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

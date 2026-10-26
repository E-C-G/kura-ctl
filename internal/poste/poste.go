// Package poste prépare la configuration d'un poste (le config.yaml de kura-agent) dans
// la console : modèle de départ tiré du bucket, puis vérification avec le code même de
// l'agent (pkg/config) et des règles propres à la console.
//
// La configuration est conservée telle que saisie (commentaires compris) et remise au
// poste dans le paquet d'installation. Elle ne contient aucun secret : ils n'y figurent
// que par référence credential:<nom> et sont saisis à la création du paquet.
package poste

import (
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/E-C-G/kura-agent/pkg/config"
	"github.com/E-C-G/kura-agent/pkg/pack"
	"github.com/E-C-G/kura-ctl/internal/store"
	"github.com/E-C-G/kura-ctl/internal/wasabi"
)

// Template renvoie une configuration de départ pour le poste d'un bucket.
func Template(b store.Bucket) string {
	name := b.Poste
	if name == "" {
		name = b.Name
	}
	return fmt.Sprintf(`# Configuration du poste %[1]s (bucket %[2]s), préparée dans kura-ctl.
# Aucun secret dans ce fichier : les valeurs des références credential:<nom> sont
# saisies à la création du paquet d'installation et rangées dans le coffre du poste.
version: 1

profile:
  name: %[1]s
  aws_credentials: credential:wasabi   # clé du poste, créée par la console
  endpoint: %[3]s
  region: %[4]s
  bucket: %[2]s
  # aws_cli vide : CLI AWS cherchée dans le PATH, installée par kura-agent si absente

schedule:
  type: daily                    # daily | weekly | hourly
  time: "22:30"
  run_if_missed: true            # rattrapage si le poste était éteint
  max_duration: 6h

jobs:
  - id: data
    name: Données
    source: "D:/Donnees"         # à adapter
    destination: DATA            # préfixe dans le bucket
    delete: true
    exclude:
      - "*$RECYCLE.BIN*"
      - "*System Volume Information*"

notify:
  toast_on: [failure, warning]
  report:
    type: healthchecks
    url: credential:hc-url       # URL de ping, saisie à la création du paquet

logging:
  level: info
  retention_days: 90
`, name, b.Name, wasabi.S3Endpoint(b.Region), regionOrDefault(b.Region))
}

func regionOrDefault(r string) string {
	if r == "" {
		return "us-east-1"
	}
	return r
}

// Secret est un secret que le paquet d'installation doit apporter, hors clé du poste.
type Secret struct {
	Name  string // nom dans le coffre du poste
	Field string // champ de la configuration qui y fait référence
}

// Checked est une configuration acceptée.
type Checked struct {
	Config *config.Config
	// KeyName : nom du secret de la clé du poste (profile.aws_credentials).
	KeyName string
	// Secrets : autres secrets à saisir à la création du paquet.
	Secrets []Secret
}

// fakeEnv : la console ne connaît pas la machine du poste. Les comptes sont supposés
// exister ; kura-agent install les vérifie sur place.
type fakeEnv struct{}

func (fakeEnv) LookupEnv(string) (string, bool)           { return "", false }
func (fakeEnv) ProfileDir(account string) (string, error) { return `C:\Users\` + account, nil }
func (fakeEnv) AccountExists(string) bool                 { return true }

// Check vérifie une configuration pour le poste du bucket b.
func Check(text string, b store.Bucket) (Checked, error) {
	if strings.TrimSpace(text) == "" {
		return Checked{}, errors.New("configuration vide")
	}
	if len(text) > pack.MaxConfigSize {
		return Checked{}, fmt.Errorf("configuration trop grande (%d Ko au plus)", pack.MaxConfigSize>>10)
	}
	cfg, err := config.Parse([]byte(text), config.LoadOptions{Env: fakeEnv{}})
	if err != nil {
		return Checked{}, err
	}
	var errs []string
	add := func(format string, a ...any) { errs = append(errs, fmt.Sprintf(format, a...)) }
	p := cfg.Profile
	if p.Bucket != b.Name {
		add("profile.bucket : %q, ce poste sauvegarde dans %s", p.Bucket, b.Name)
	}
	if !endpointOK(p.Endpoint, b.Region) {
		add("profile.endpoint : %q, attendu %s (région du bucket)", p.Endpoint, wasabi.S3Endpoint(b.Region))
	}
	if p.Region != "" && b.Region != "" && p.Region != b.Region {
		add("profile.region : %q, le bucket est en %s", p.Region, b.Region)
	}
	if p.AWSProfile != "" {
		add("profile.aws_profile : la clé du poste passe par profile.aws_credentials, pas par un profil ~/.aws")
	}
	keyName, isRef := strings.CutPrefix(p.AWSCredentials, config.CredentialPrefix)
	if !isRef || !pack.CredentialName.MatchString(keyName) {
		add("profile.aws_credentials : credential:<nom> attendu (ex. credential:wasabi)")
	}
	// La base de la console n'est pas chiffrée : aucun secret en clair dans la
	// configuration qu'elle conserve.
	if w := cfg.Notify.Webhook; w != nil && (w.URL != "" || w.Token != "") {
		add("notify.webhook : ancienne forme, utiliser notify.report")
	}
	if r := cfg.Notify.Report; r != nil {
		if r.URL != "" && !strings.HasPrefix(r.URL, config.CredentialPrefix) {
			add("notify.report.url : en clair, elle suffit à envoyer un faux bilan ; utiliser credential:<nom> (valeur saisie à la création du paquet)")
		}
		if r.Token != "" && !strings.HasPrefix(r.Token, config.CredentialPrefix) {
			add("notify.report.token : en clair ; utiliser credential:<nom>")
		}
		for field, v := range map[string]string{"notify.report.url": r.URL, "notify.report.token": r.Token} {
			if isRef && v == config.CredentialPrefix+keyName {
				add("%s : credential:%s désigne déjà la clé du poste", field, keyName)
			}
		}
	}
	c := Checked{Config: cfg, KeyName: keyName}
	for _, ref := range cfg.CredentialRefs() {
		if !pack.CredentialName.MatchString(ref.Name) {
			add("%s : nom de secret %q invalide (minuscules, chiffres et '-', 40 caractères au plus)", ref.Field, ref.Name)
			continue
		}
		if ref.AWS {
			continue
		}
		c.Secrets = append(c.Secrets, Secret{Name: ref.Name, Field: ref.Field})
	}
	if len(errs) > 0 {
		return Checked{}, fmt.Errorf("configuration refusée (%d erreur(s)) :\n- %s", len(errs), strings.Join(errs, "\n- "))
	}
	return c, nil
}

func endpointOK(endpoint, region string) bool {
	e := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(endpoint)), "/")
	return e == wasabi.S3Endpoint(region) || e == "https://s3."+regionOrDefault(region)+".wasabisys.com"
}

// CheckSecret vérifie la valeur saisie pour un secret de la configuration.
func CheckSecret(s Secret, value string) error {
	if value == "" {
		return fmt.Errorf("%s (%s) : valeur manquante", s.Name, s.Field)
	}
	if strings.ContainsAny(value, "\r\n") {
		return fmt.Errorf("%s : une seule ligne attendue", s.Name)
	}
	if s.Field == "notify.report.url" {
		u, err := url.Parse(value)
		if err != nil || u.Scheme != "https" || u.Host == "" {
			return fmt.Errorf("%s : adresse https://… attendue", s.Name)
		}
	}
	return nil
}

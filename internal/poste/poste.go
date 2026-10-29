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

// Template renvoie une configuration de départ pour le poste d'un bucket, selon son
// système (b.Platform ; Windows par défaut).
func Template(b store.Bucket) string {
	return TemplateFor(b, b.Platform)
}

// TemplateFor renvoie la configuration de départ pour le système p.
func TemplateFor(b store.Bucket, p store.Platform) string {
	name := b.Poste
	if name == "" {
		name = b.Name
	}
	tmpl := windowsTemplate
	if p.Linux() {
		tmpl = linuxTemplate
	}
	return fmt.Sprintf(tmpl, name, b.Name, wasabi.S3Endpoint(b.Region), regionOrDefault(b.Region))
}

const windowsTemplate = `# Configuration du poste %[1]s (bucket %[2]s), préparée dans kura-ctl.
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

# Préparations avant les jobs (facultatif) : archive zip, export de base, chiffrement
# gpg ou age. Outils installés sur le poste, déclarés par chemin complet ; le résultat
# part par un job dont la source est ${STAGING:<id>}. Voir le README de kura-agent.
# tools:
#   zip: "C:/Program Files/7-Zip/7z.exe"
#   pg_dump: "C:/Program Files/PostgreSQL/17/bin/pg_dump.exe"
# encryption:
#   age:
#     recipients:
#       - age1…                         # clé publique ; la clé privée reste hors du poste
# prepare:
#   - id: compta-db
#     type: db_export
#     engine: postgresql                # postgresql | mysql | sqlserver (Windows)
#     user: kura_backup                 # rôle en lecture seule (commandes affichées ici)
#     password: credential:compta-db    # saisi à la création du paquet
#   - id: compta-chiffre
#     type: age
#     input: compta-db                  # export chiffré au fil de l'eau
# et dans jobs :
#   - id: compta
#     source: "${STAGING:compta-chiffre}"
#     destination: BASES/COMPTA

notify:
  toast_on: [failure, warning]
  report:
    type: healthchecks
    url: credential:hc-url       # URL de ping, saisie à la création du paquet

# Proxy vers GitHub pour la recherche des nouvelles versions de l'agent (self-update),
# si le réseau du poste en impose un ; sans identifiants.
# update:
#   proxy: http://proxy.example.com:3128

logging:
  level: info
  retention_days: 90
`

const linuxTemplate = `# Configuration du poste %[1]s (bucket %[2]s, Ubuntu), préparée dans kura-ctl.
# Aucun secret dans ce fichier : les valeurs des références credential:<nom> sont
# saisies à la création du paquet d'installation et rangées dans le coffre du poste
# (systemd-creds). La sauvegarde tourne sous le compte kura-agent, en lecture seule.
version: 1

profile:
  name: %[1]s
  aws_credentials: credential:wasabi   # clé du poste, créée par la console
  endpoint: %[3]s
  region: %[4]s
  bucket: %[2]s
  # aws_cli vide : CLI AWS officielle (/usr/local/bin/aws), installée par kura-agent si absente

schedule:
  type: daily                    # daily | weekly | hourly
  time: "22:30"
  run_if_missed: true            # rattrapage au démarrage si le poste était éteint
  max_duration: 6h

jobs:
  - id: documents
    name: Documents
    source: /home/utilisateur/Documents   # à adapter
    destination: home/utilisateur/Documents
    delete: true
    exclude:
      - "*/.cache/*"
      - "*/node_modules/*"

# Préparations avant les jobs (facultatif) : archive zip, export de base, chiffrement
# gpg ou age. Outils installés sur le poste, déclarés par chemin complet ; le résultat
# part par un job dont la source est ${STAGING:<id>}. Voir le README de kura-agent.
# tools:
#   zip: /usr/bin/zip
#   pg_dump: /usr/lib/postgresql/16/bin/pg_dump
# encryption:
#   age:
#     recipients:
#       - age1…                         # clé publique ; la clé privée reste hors du poste
# prepare:
#   - id: compta-db
#     type: db_export
#     engine: postgresql                # postgresql | mysql | sqlserver (Windows)
#     user: kura_backup                 # rôle en lecture seule (commandes affichées ici)
#     password: credential:compta-db    # saisi à la création du paquet
#   - id: compta-chiffre
#     type: age
#     input: compta-db                  # export chiffré au fil de l'eau
#   - id: appli                         # volumes Docker (Docker Engine en root)
#     type: docker_volume
#     volumes: [appli_db, appli_uploads]   # docker volume ls
#     pause: true                       # défaut : conteneurs gelés pendant la lecture
#     max_pause: 15m                    # défaut ; au-delà : dégel, préparation en échec
# et dans jobs :
#   - id: compta
#     source: "${STAGING:compta-chiffre}"
#     destination: BASES/COMPTA
#   - id: appli
#     source: "${STAGING:appli}"
#     destination: DOCKER/APPLI

notify:
  report:
    type: healthchecks
    url: credential:hc-url       # URL de ping, saisie à la création du paquet

# Proxy vers GitHub pour la recherche des nouvelles versions de l'agent (self-update),
# si le réseau du poste en impose un ; sans identifiants.
# update:
#   proxy: http://proxy.example.com:3128

logging:
  level: info
  retention_days: 90
`

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
	// Secrets : autres secrets à saisir à la création du paquet (mots de passe des
	// bases compris).
	Secrets []Secret
	// Warnings : ce qui n'empêche pas d'installer mais mérite d'être lu.
	Warnings []string
	// Roles : commandes de création du rôle de chaque export de base, à lancer sur le
	// serveur de la base ; Encryptions : destinataires de chaque chiffrement.
	Roles       []RoleHelp
	Encryptions []Encryption
	// Dockers : volumes de chaque préparation docker_volume, arrêt attendu, rechargement.
	Dockers []Docker
}

// fakeEnv : la console ne connaît pas la machine du poste. Les comptes sont supposés
// exister ; kura-agent install les vérifie sur place.
type fakeEnv struct{ linux bool }

func (fakeEnv) LookupEnv(string) (string, bool) { return "", false }
func (e fakeEnv) ProfileDir(account string) (string, error) {
	if e.linux {
		return "/home/" + account, nil
	}
	return `C:\Users\` + account, nil
}
func (fakeEnv) AccountExists(string) bool { return true }

// Check vérifie une configuration pour le poste du bucket b, selon son système.
func Check(text string, b store.Bucket) (Checked, error) {
	return CheckFor(text, b, b.Platform)
}

// CheckFor vérifie une configuration pour le poste du bucket b sous le système p.
func CheckFor(text string, b store.Bucket, p store.Platform) (Checked, error) {
	if p == "" {
		p = store.PlatformWindows
	}
	if !p.Valid() {
		return Checked{}, fmt.Errorf("système du poste inconnu : %q", p)
	}
	if strings.TrimSpace(text) == "" {
		return Checked{}, errors.New("configuration vide")
	}
	if len(text) > pack.MaxConfigSize {
		return Checked{}, fmt.Errorf("configuration trop grande (%d Ko au plus)", pack.MaxConfigSize>>10)
	}
	cfg, err := config.Parse([]byte(text), config.LoadOptions{Env: fakeEnv{linux: p.Linux()}})
	if err != nil {
		return Checked{}, err
	}
	var errs []string
	add := func(format string, a ...any) { errs = append(errs, fmt.Sprintf(format, a...)) }
	prof := cfg.Profile
	if prof.Bucket != b.Name {
		add("profile.bucket : %q, ce poste sauvegarde dans %s", prof.Bucket, b.Name)
	}
	if !endpointOK(prof.Endpoint, b.Region) {
		add("profile.endpoint : %q, attendu %s (région du bucket)", prof.Endpoint, wasabi.S3Endpoint(b.Region))
	}
	if prof.Region != "" && b.Region != "" && prof.Region != b.Region {
		add("profile.region : %q, le bucket est en %s", prof.Region, b.Region)
	}
	if prof.AWSProfile != "" {
		add("profile.aws_profile : la clé du poste passe par profile.aws_credentials, pas par un profil ~/.aws")
	}
	for _, e := range platformErrors(cfg, p) {
		add("%s", e)
	}
	keyName, isRef := strings.CutPrefix(prof.AWSCredentials, config.CredentialPrefix)
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
	c := Checked{Config: cfg, KeyName: keyName, Warnings: append(cfg.Warnings(), dockerWarnings(cfg)...), Roles: roleHelps(cfg),
		Encryptions: encryptions(cfg), Dockers: dockers(cfg)}
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

// platformErrors : ce que le système du poste ne permet pas (chemins d'un autre
// système, fonctions propres à Windows). kura-agent le refuserait à l'installation.
func platformErrors(cfg *config.Config, p store.Platform) []string {
	var errs []string
	errs = append(errs, prepareErrors(cfg, p)...)
	if !p.Linux() {
		for i, j := range cfg.Jobs {
			if j.Prepare == "" && !windowsAbs(j.Source) { // ${STAGING:x} : zone de préparation du poste
				errs = append(errs, fmt.Sprintf("jobs[%d].source : %q, chemin Windows complet attendu (D:/Donnees, ${PROFILE:compte}/Documents, \\\\serveur\\partage)", i, j.Source))
			}
		}
		if a := cfg.Profile.AWSCLI; a != "" && !windowsAbs(a) {
			errs = append(errs, fmt.Sprintf("profile.aws_cli : %q, chemin Windows complet attendu", a))
		}
		return errs
	}
	for i, j := range cfg.Jobs {
		if j.Prepare == "" && !strings.HasPrefix(j.Source, "/") {
			errs = append(errs, fmt.Sprintf("jobs[%d].source : %q, chemin Linux complet attendu (/home/compte/Documents)", i, j.Source))
		}
	}
	if a := cfg.Profile.AWSCLI; a != "" {
		switch {
		case !strings.HasPrefix(a, "/"):
			errs = append(errs, fmt.Sprintf("profile.aws_cli : %q, chemin Linux complet attendu (ou vide)", a))
		case strings.HasPrefix(a, "/snap/"):
			errs = append(errs, "profile.aws_cli : la CLI AWS en snap ne fonctionne pas sous le compte du service ; laisser vide (CLI officielle installée par kura-agent)")
		}
	}
	if len(cfg.PreTasks) > 0 {
		errs = append(errs, "pre_tasks : fermeture d'applications non prise en charge sous Linux")
	}
	if len(cfg.PostTasks) > 0 {
		errs = append(errs, "post_tasks : non pris en charge sous Linux")
	}
	if len(cfg.Tray.Users) > 0 || len(cfg.Tray.AllowRunNow) > 0 {
		errs = append(errs, "tray : pas d'icône sous Linux (suivi par le journal et notify.report)")
	}
	return errs
}

// windowsAbs : C:/…, C:\…, \\serveur\partage ou //serveur/partage.
func windowsAbs(p string) bool {
	if len(p) >= 3 && p[1] == ':' && (p[2] == '/' || p[2] == '\\') {
		c := p[0] | 0x20
		return c >= 'a' && c <= 'z'
	}
	return strings.HasPrefix(p, `\\`) || strings.HasPrefix(p, "//")
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

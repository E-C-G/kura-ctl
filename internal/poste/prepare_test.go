package poste

import (
	"strings"
	"testing"
	"time"

	"github.com/E-C-G/kura-agent/pkg/config"
	"github.com/E-C-G/kura-ctl/internal/store"
)

const gpgKey = `        key: |
          -----BEGIN PGP PUBLIC KEY BLOCK-----

          mDMEZx+…
          -----END PGP PUBLIC KEY BLOCK-----
`

// ageRecipient : clé publique age de la documentation d'age (valide, sans usage réel).
func ageRecipient(*testing.T) string {
	return "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p"
}

// withPreparations ajoute au modèle Windows un export PostgreSQL chiffré par age, une
// archive chiffrée par gpg et un export SQL Server.
func withPreparations(t *testing.T) string {
	t.Helper()
	text := strings.Replace(Template(bucket), "\njobs:\n", `
tools:
  zip: "C:/Program Files/7-Zip/7z.exe"
  pg_dump: "C:/Program Files/PostgreSQL/17/bin/pg_dump.exe"
  sqlcmd: "C:/Program Files/SqlCmd/sqlcmd.exe"
  gpg: "C:/Program Files (x86)/GnuPG/bin/gpg.exe"
encryption:
  age:
    recipients:
      - `+ageRecipient(t)+`
prepare:
  - id: compta-db
    type: db_export
    engine: postgresql
    user: kura_backup
    password: credential:compta-db
    databases: [compta]
  - id: compta-chiffre
    type: age
    input: compta-db
  - id: courrier
    type: zip
    source: "${PROFILE:alice}/Courrier"
  - id: courrier-chiffre
    type: gpg
    input: courrier
    recipients:
      - fingerprint: 0123456789ABCDEF0123456789ABCDEF01234567
`+gpgKey+`  - id: gestion-db
    type: db_export
    engine: sqlserver
    instance: 'localhost\SQLEXPRESS'
    databases: [Gestion, "L'Atelier]"]
    verify: true

jobs:
  - id: compta
    source: "${STAGING:compta-chiffre}"
    destination: BASES/COMPTA
  - id: courrier
    source: "${STAGING:courrier-chiffre}"
    destination: COURRIER
  - id: gestion
    source: "${STAGING:gestion-db}"
    destination: BASES/GESTION
`, 1)
	return text
}

func TestPreparationsAccepted(t *testing.T) {
	c, err := Check(withPreparations(t), bucket)
	if err != nil {
		t.Fatal(err)
	}
	var secrets []string
	for _, s := range c.Secrets {
		secrets = append(secrets, s.Name+"="+s.Field)
	}
	if strings.Join(secrets, " ") != "hc-url=notify.report.url compta-db=prepare[0].password" {
		t.Fatalf("secrets du paquet : %v", secrets)
	}
	if len(c.Roles) != 2 || c.Roles[0].ID != "compta-db" || c.Roles[1].ID != "gestion-db" {
		t.Fatalf("rôles : %+v", c.Roles)
	}
	pg := c.Roles[0].SQL
	if !strings.Contains(pg, `CREATE ROLE "kura_backup" LOGIN PASSWORD '…';`) || !strings.Contains(pg, "pg_read_all_data") {
		t.Fatalf("PostgreSQL :\n%s", pg)
	}
	ms := c.Roles[1].SQL
	for _, want := range []string{`CREATE LOGIN [NT AUTHORITY\SYSTEM] FROM WINDOWS`, "USE [L'Atelier]]];", "IF USER_ID(N'NT AUTHORITY\\SYSTEM')",
		"ALTER ROLE db_backupoperator ADD MEMBER [NT AUTHORITY\\SYSTEM];", "GRANT CREATE ANY DATABASE"} {
		if !strings.Contains(ms, want) {
			t.Errorf("SQL Server : %q absent de\n%s", want, ms)
		}
	}
	if len(c.Encryptions) != 2 {
		t.Fatalf("chiffrements : %+v", c.Encryptions)
	}
	if e := c.Encryptions[0]; e.ID != "compta-chiffre" || !e.Default || !strings.HasPrefix(e.Recipients[0], "age1") || e.From != "préparation compta-db" {
		t.Errorf("%+v", e)
	}
	if e := c.Encryptions[1]; e.Default || e.Recipients[0] != "0123 4567 89AB CDEF 0123 4567 89AB CDEF 0123 4567" {
		t.Errorf("%+v", e)
	}
	// Le texte enregistré garde ${STAGING:x} tel quel.
	if c.Config.Jobs[0].Source != "${STAGING:compta-chiffre}" {
		t.Errorf("source du job : %q", c.Config.Jobs[0].Source)
	}
}

func TestPreparationsRefused(t *testing.T) {
	base := withPreparations(t)
	cases := map[string][3]string{
		"Info-ZIP sous Windows": {`zip: "C:/Program Files/7-Zip/7z.exe"`, `zip: "C:/Outils/zip.exe"`, "seul 7-Zip"},
		"outil Linux":           {`pg_dump: "C:/Program Files/PostgreSQL/17/bin/pg_dump.exe"`, "pg_dump: /usr/bin/pg_dump", "tools.pg_dump"},
		"outil sur un partage":  {`gpg: "C:/Program Files (x86)/GnuPG/bin/gpg.exe"`, `gpg: "//nas/outils/gpg.exe"`, "partage réseau"},
		"source Linux":          {`source: "${PROFILE:alice}/Courrier"`, "source: /srv/courrier", "prepare[2].source"},
		"socket sous Windows":   {"    user: kura_backup\n    password: credential:compta-db\n", "    socket: /run/postgresql\n", "pas de socket local"},
		"mot de passe en clair": {"password: credential:compta-db", "password: S3cret", "prepare[0].password"},
		"clair envoyé":          {"${STAGING:courrier-chiffre}", "${STAGING:courrier}", "son clair ne part jamais"},
		"identité age privée":   {"      - age1", "      - AGE-SECRET-KEY-1QQQQ\n      - age1", "identité privée"},
		"clé privée gpg":        {"BEGIN PGP PUBLIC KEY BLOCK", "BEGIN PGP PRIVATE KEY BLOCK", "clé privée"},
		"instance distante":     {`'localhost\SQLEXPRESS'`, `'srv-sql\SQLEXPRESS'`, "instance locale"},
	}
	for name, c := range cases {
		text := strings.Replace(base, c[0], c[1], 1)
		if text == base {
			t.Fatalf("%s : remplacement sans effet", name)
		}
		if _, err := Check(text, bucket); err == nil || !strings.Contains(err.Error(), c[2]) {
			t.Errorf("%s : %v", name, err)
		}
	}
}

func TestPreparationsLinux(t *testing.T) {
	linux := linuxBucket(store.PlatformLinuxAMD64)
	text := strings.Replace(Template(linux), "\njobs:\n", `
tools:
  pg_dump: /usr/lib/postgresql/16/bin/pg_dump
  mysqldump: /usr/bin/mariadb-dump
  zip: /usr/bin/zip
prepare:
  - id: compta-db
    type: db_export
    engine: postgresql
    socket: /run/postgresql
  - id: site-db
    type: db_export
    engine: mysql
    host: db.example.lan
    user: kura_backup
    password: credential:site-db
  - id: courrier
    type: zip
    source: /home/alice/Courrier

jobs:
  - id: compta
    source: "${STAGING:compta-db}"
    destination: BASES/COMPTA
  - id: site
    source: "${STAGING:site-db}"
    destination: BASES/SITE
  - id: courrier
    source: "${STAGING:courrier}"
    destination: COURRIER
`, 1)
	c, err := Check(text, linux)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Roles) != 2 || c.Roles[0].Account != "kura-agent" || !strings.Contains(c.Roles[0].SQL, `CREATE ROLE "kura-agent" LOGIN;`) {
		t.Fatalf("rôle peer : %+v", c.Roles)
	}
	if my := c.Roles[1].SQL; !strings.Contains(my, "CREATE USER 'kura_backup'@'%' IDENTIFIED BY '…';") || !strings.Contains(my, "PROCESS ON *.*") {
		t.Fatalf("MySQL :\n%s", my)
	}
	ms := strings.Replace(strings.Replace(text, "engine: mysql\n    host: db.example.lan\n    user: kura_backup\n    password: credential:site-db",
		"engine: sqlserver", 1), "  zip: /usr/bin/zip\n", "  zip: /usr/bin/zip\n  sqlcmd: /opt/mssql-tools18/bin/sqlcmd\n", 1)
	if _, err := Check(ms, linux); err == nil || !strings.Contains(err.Error(), "sous Windows seulement") {
		t.Errorf("SQL Server sous Linux : %v", err)
	}
	for name, r := range map[string][3]string{
		"outil en snap":  {"zip: /usr/bin/zip", "zip: /snap/bin/zip", "snap"},
		"source Windows": {"source: /home/alice/Courrier", `source: "D:/Courrier"`, "prepare[2].source"},
	} {
		bad := strings.Replace(text, r[0], r[1], 1)
		if _, err := Check(bad, linux); err == nil || !strings.Contains(err.Error(), r[2]) {
			t.Errorf("%s : %v", name, err)
		}
	}
}

// Les modèles de départ restent valides, et ne déclarent aucune préparation.
func TestTemplatesHaveNoPreparation(t *testing.T) {
	for _, p := range store.Platforms {
		b := bucket
		if p.Linux() {
			b = linuxBucket(p)
		}
		c, err := CheckFor(TemplateFor(b, p), b, p)
		if err != nil {
			t.Fatalf("%s : %v", p, err)
		}
		if len(c.Config.Prepare) != 0 || c.Config.Tools != (config.Tools{}) || len(c.Roles) != 0 {
			t.Fatalf("%s : %+v", p, c.Config.Prepare)
		}
	}
}

const dockerPrepare = `
encryption:
  age:
    recipients:
      - age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p
prepare:
  - id: appli
    type: docker_volume
    volumes: [appli_db, appli_uploads]
    max_pause: 10m
  - id: appli-chiffre
    type: age
    input: appli
  - id: certificats
    type: docker_volume
    volumes: [traefik_certs]
    pause: false

jobs:
  - id: appli
    source: "${STAGING:appli-chiffre}"
    destination: DOCKER/APPLI
  - id: certificats
    source: "${STAGING:certificats}"
    destination: DOCKER/CERTIFICATS
`

// Volumes Docker : acceptés sous Linux, avec l'arrêt attendu et les avertissements ;
// refusés pour un poste Windows.
func TestDockerVolumes(t *testing.T) {
	linux := linuxBucket(store.PlatformLinuxARM64)
	text := strings.Replace(Template(linux), "\njobs:\n", dockerPrepare, 1)
	c, err := Check(text, linux)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Dockers) != 2 {
		t.Fatalf("%+v", c.Dockers)
	}
	a, s := c.Dockers[0], c.Dockers[1]
	if a.ID != "appli" || !a.Pause || a.MaxPause != "10 min" || a.Sent != "appli-chiffre" || a.Sealed != ".age" || len(a.Volumes) != 2 {
		t.Fatalf("appli : %+v", a)
	}
	if s.Pause || s.Sent != "certificats" || s.Sealed != "" {
		t.Fatalf("certificats : %+v", s)
	}
	warn := strings.Join(c.Warnings, "\n")
	if !strings.Contains(warn, "appli : conteneurs gelés") || !strings.Contains(warn, "groupe docker") ||
		!strings.Contains(warn, "certificats : pause: false, copie non figée") {
		t.Fatalf("avertissements :\n%s", warn)
	}
	if strings.Contains(warn, "certificats : conteneurs gelés") {
		t.Fatal("gel annoncé sans pause")
	}
	win := strings.Replace(Template(bucket), "\njobs:\n", dockerPrepare, 1)
	if _, err := Check(win, bucket); err == nil || !strings.Contains(err.Error(), "prepare[0] (appli) : docker_volume, volumes Docker sous Linux seulement") ||
		!strings.Contains(err.Error(), "prepare[2] (certificats)") {
		t.Fatalf("poste Windows : %v", err)
	}
	for d, want := range map[time.Duration]string{15 * time.Minute: "15 min", time.Hour: "1 h", 90 * time.Minute: "1 h 30 min", 90 * time.Second: "1m30s"} {
		if got := minutes(d); got != want {
			t.Errorf("%s : %q", d, got)
		}
	}
}

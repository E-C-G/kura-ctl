package poste

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/E-C-G/kura-agent/pkg/config"
	"github.com/E-C-G/kura-ctl/internal/store"
)

// Préparations (prepare, tools, encryption) : pkg/config vérifie leur forme ; la console
// ajoute ce qui dépend du système du poste. L'existence des outils, leurs droits et les
// clés gpg elles-mêmes sont vérifiés sur le poste (kura-agent validate, install).

// prepareErrors : chemins d'outils et de sources du système du poste, fonctions propres
// à un système.
func prepareErrors(cfg *config.Config, p store.Platform) []string {
	var errs []string
	add := func(format string, a ...any) { errs = append(errs, fmt.Sprintf(format, a...)) }
	tools := []struct{ field, path string }{
		{"tools.pg_dump", cfg.Tools.PgDump}, {"tools.mysqldump", cfg.Tools.MySQLDump}, {"tools.sqlcmd", cfg.Tools.SQLCmd},
		{"tools.zip", cfg.Tools.Zip}, {"tools.gpg", cfg.Tools.GPG},
	}
	for _, t := range tools {
		switch {
		case t.path == "":
		case !p.Linux() && (!windowsAbs(t.path) || strings.HasPrefix(t.path, `\\`) || strings.HasPrefix(t.path, "//")):
			add("%s : %q, chemin Windows complet sur un disque du poste attendu (ex. C:/Program Files/…), jamais un partage réseau", t.field, t.path)
		case p.Linux() && !strings.HasPrefix(t.path, "/"):
			add("%s : %q, chemin Linux complet attendu (ex. /usr/bin/…)", t.field, t.path)
		case p.Linux() && strings.HasPrefix(t.path, "/snap/"):
			add("%s : %q, outil en snap inutilisable par le service ; installer le paquet Debian (/usr/bin/…)", t.field, t.path)
		}
	}
	if z := cfg.Tools.Zip; z != "" && !p.Linux() && config.ZipFlavor(z) != config.Zip7Zip {
		add("tools.zip : %q, sous Windows seul 7-Zip est accepté (C:/Program Files/7-Zip/7z.exe)", z)
	}
	if s := cfg.Tools.SQLCmd; s != "" && p.Linux() {
		add("tools.sqlcmd : export SQL Server sous Windows seulement")
	}
	for i, pr := range cfg.Prepare {
		f := fmt.Sprintf("prepare[%d]", i)
		if pr.Source != "" && pr.Unavailable == "" {
			if p.Linux() && !strings.HasPrefix(pr.Source, "/") {
				add("%s.source : %q, chemin Linux complet attendu", f, pr.Source)
			}
			if !p.Linux() && !windowsAbs(pr.Source) {
				add("%s.source : %q, chemin Windows complet attendu (D:/Courrier, ${PROFILE:compte}/Documents)", f, pr.Source)
			}
		}
		if pr.Type == config.PrepareDocker && !p.Linux() {
			add("%s (%s) : docker_volume, volumes Docker sous Linux seulement (Docker Engine installé en root)", f, pr.ID)
		}
		if pr.Type != config.PrepareDBExport {
			continue
		}
		switch {
		case pr.Engine == config.EngineSQLServer && p.Linux():
			add("%s.engine : sqlserver, export SQL Server sous Windows seulement", f)
		case pr.Socket != "" && !p.Linux():
			add("%s.socket : pas de socket local sous Windows ; host, port, user et password", f)
		}
	}
	return errs
}

// RoleHelp : commandes qui créent, sur le serveur de la base, le rôle dédié en lecture
// seule d'une préparation db_export. Le mot de passe n'y figure jamais (« … » à
// remplacer, puis saisi à la création du paquet).
type RoleHelp struct {
	ID, Engine, Account, Where string
	SQL                        string
	Notes                      []string
}

func roleHelps(cfg *config.Config) []RoleHelp {
	var out []RoleHelp
	for _, p := range cfg.Prepare {
		if p.Type != config.PrepareDBExport {
			continue
		}
		var h RoleHelp
		switch p.Engine {
		case config.EnginePostgreSQL:
			h = pgRole(p)
		case config.EngineMySQL:
			h = myRole(p)
		case config.EngineSQLServer:
			h = msRole(p)
		default:
			continue
		}
		h.ID, h.Engine = p.ID, p.Engine
		out = append(out, h)
	}
	return out
}

func pgIdent(s string) string { return `"` + strings.ReplaceAll(s, `"`, `""`) + `"` }

func pgRole(p config.Prepare) RoleHelp {
	h := RoleHelp{Where: "psql, en superutilisateur (postgres)"}
	user := p.User
	if user == "" {
		// Socket local, authentification peer : le rôle porte le nom du compte du service.
		user = "kura-agent"
		h.SQL = fmt.Sprintf("CREATE ROLE %s LOGIN;\nGRANT pg_read_all_data TO %s;\n", pgIdent(user), pgIdent(user))
		h.Notes = append(h.Notes, "connexion par le socket local, authentification peer : dans pg_hba.conf, une ligne « local all kura-agent peer » avant les autres.")
	} else {
		h.SQL = fmt.Sprintf("CREATE ROLE %s LOGIN PASSWORD '…';\nGRANT pg_read_all_data TO %s;\n", pgIdent(user), pgIdent(user))
		h.Notes = append(h.Notes, "remplacer « … » par le mot de passe, saisi ensuite à la création du paquet ("+p.Password+").")
	}
	h.Account = user
	h.Notes = append(h.Notes, "pg_read_all_data : PostgreSQL 14 ou plus récent ; avant, GRANT SELECT sur chaque table et chaque séquence.")
	return h
}

func myString(s string) string {
	return "'" + strings.NewReplacer(`\`, `\\`, `'`, `''`).Replace(s) + "'"
}

func myRole(p config.Prepare) RoleHelp {
	h := RoleHelp{Where: "client mysql ou mariadb, en root"}
	user, host := p.User, "localhost"
	auth := " IDENTIFIED BY '…'"
	if user == "" {
		user = "kura-agent"
		auth = " IDENTIFIED VIA unix_socket"
		h.Notes = append(h.Notes, "socket local : MariaDB IDENTIFIED VIA unix_socket ; MySQL : IDENTIFIED WITH auth_socket.")
	} else {
		h.Notes = append(h.Notes, "remplacer « … » par le mot de passe, saisi ensuite à la création du paquet ("+p.Password+").")
	}
	if p.Socket == "" && p.Host != "localhost" && p.Host != "127.0.0.1" && p.Host != "::1" {
		host = "%"
		h.Notes = append(h.Notes, "serveur distant : remplacer '%' par l'adresse du poste.")
	}
	acct := myString(user) + "@" + myString(host)
	h.Account = user
	h.SQL = fmt.Sprintf("CREATE USER %s%s;\nGRANT SELECT, SHOW VIEW, TRIGGER, EVENT, LOCK TABLES, PROCESS ON *.* TO %s;\n", acct, auth, acct)
	return h
}

func msIdent(s string) string  { return "[" + strings.ReplaceAll(s, "]", "]]") + "]" }
func msString(s string) string { return "N'" + strings.ReplaceAll(s, "'", "''") + "'" }

func msRole(p config.Prepare) RoleHelp {
	h := RoleHelp{Where: "sqlcmd ou SQL Server Management Studio, en administrateur de l'instance " + p.Instance}
	login := p.User
	var b strings.Builder
	if login == "" {
		login = `NT AUTHORITY\SYSTEM`
		fmt.Fprintf(&b, "IF SUSER_ID(%s) IS NULL CREATE LOGIN %s FROM WINDOWS;\n", msString(login), msIdent(login))
	} else {
		fmt.Fprintf(&b, "CREATE LOGIN %s WITH PASSWORD = N'…', CHECK_POLICY = ON;\n", msIdent(login))
		h.Notes = append(h.Notes, "remplacer « … » par le mot de passe, saisi ensuite à la création du paquet ("+p.Password+").")
	}
	dbs := p.Databases
	if len(dbs) == 0 {
		dbs = []string{"<base>"}
		h.Notes = append(h.Notes, "toutes les bases : répéter le bloc USE … pour chaque base utilisateur (et pour chaque base créée ensuite).")
	}
	for _, db := range dbs {
		fmt.Fprintf(&b, "USE %s;\nIF USER_ID(%s) IS NULL CREATE USER %s FOR LOGIN %s;\nALTER ROLE db_backupoperator ADD MEMBER %s;\n",
			msIdent(db), msString(login), msIdent(login), msIdent(login), msIdent(login))
	}
	if p.Verify {
		fmt.Fprintf(&b, "USE master;\nGRANT CREATE ANY DATABASE TO %s;\n", msIdent(login))
		h.Notes = append(h.Notes, "verify : RESTORE VERIFYONLY demande CREATE ANY DATABASE.")
	}
	h.Account, h.SQL = login, b.String()
	return h
}

// Docker : une préparation docker_volume, telle que la page du poste la présente.
type Docker struct {
	ID       string
	Volumes  []string
	Pause    bool   // conteneurs gelés le temps de la lecture
	MaxPause string // durée maximale du gel
	Sent     string // préparation envoyée par le job : elle-même, ou son chiffrement
	Sealed   string // extension du chiffrement (.age, .gpg) ; vide : en clair
}

func dockers(cfg *config.Config) []Docker {
	var out []Docker
	for _, p := range cfg.Prepare {
		if p.Type != config.PrepareDocker {
			continue
		}
		d := Docker{ID: p.ID, Volumes: p.Volumes, Pause: p.Paused(), MaxPause: minutes(p.MaxPause.Duration), Sent: p.ID}
		for _, e := range cfg.Prepare {
			if e.Input == p.ID && (e.Type == config.PrepareAge || e.Type == config.PrepareGPG) {
				d.Sent, d.Sealed = e.ID, "."+e.Type
			}
		}
		out = append(out, d)
	}
	return out
}

// minutes : durée lisible (15 min, 1 h 30 min) ; à la seconde au besoin.
func minutes(d time.Duration) string {
	if d%time.Minute != 0 {
		return d.String()
	}
	h, m := int(d/time.Hour), int(d%time.Hour/time.Minute)
	switch {
	case h == 0:
		return fmt.Sprintf("%d min", m)
	case m == 0:
		return fmt.Sprintf("%d h", h)
	}
	return fmt.Sprintf("%d h %d min", h, m)
}

// dockerWarnings : ce que le gel coûte (droits du service), ou ce que son absence coûte.
func dockerWarnings(cfg *config.Config) []string {
	var paused, unpaused []string
	for _, d := range dockers(cfg) {
		if d.Pause {
			paused = append(paused, d.ID)
		} else {
			unpaused = append(unpaused, d.ID)
		}
	}
	var out []string
	if len(paused) > 0 {
		out = append(out, fmt.Sprintf("%s : conteneurs gelés pendant la lecture ; le service kura-agent rejoint pour cela le groupe docker, "+
			"l'équivalent des droits root sur la machine (pause: false et db_export pour s'en passer)", strings.Join(paused, ", ")))
	}
	if len(unpaused) > 0 {
		out = append(out, fmt.Sprintf("%s : pause: false, copie non figée : un conteneur peut écrire pendant la lecture "+
			"(avertissement à chaque sauvegarde) ; à réserver aux volumes que rien n'écrit", strings.Join(unpaused, ", ")))
	}
	return out
}

// Encryption : un chiffrement et ses destinataires, tels que les fichiers les auront.
type Encryption struct {
	ID, Type, From string
	Default        bool     // destinataires de la section encryption
	Recipients     []string // empreintes gpg (groupées par 4) ou clés age
}

func encryptions(cfg *config.Config) []Encryption {
	var out []Encryption
	for _, p := range cfg.Prepare {
		if p.Type != config.PrepareGPG && p.Type != config.PrepareAge {
			continue
		}
		e := Encryption{ID: p.ID, Type: p.Type, Default: len(p.Recipients) == 0}
		if p.Input != "" {
			e.From = "préparation " + p.Input
		} else {
			e.From = p.Source
		}
		for _, r := range cfg.RecipientsOf(p) {
			if p.Type == config.PrepareGPG {
				e.Recipients = append(e.Recipients, groupFingerprint(config.NormalizeFingerprint(r.Fingerprint)))
			} else {
				e.Recipients = append(e.Recipients, strings.TrimSpace(r.Age))
			}
		}
		sort.Strings(e.Recipients)
		out = append(out, e)
	}
	return out
}

// groupFingerprint : empreinte par groupes de 4, comme gpg et Kleopatra l'affichent.
func groupFingerprint(fp string) string {
	var parts []string
	for i := 0; i < len(fp); i += 4 {
		parts = append(parts, fp[i:min(i+4, len(fp))])
	}
	return strings.Join(parts, " ")
}

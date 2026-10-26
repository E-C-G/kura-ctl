// Package store est la base locale de la console : un fichier SQLite dans le dossier
// de données de l'utilisateur. Clients, buckets importés, réglages relevés, usage
// quotidien, journal d'audit (ajout seul). Aucun secret n'y est écrit.
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"time"
)

// Store est la base ouverte.
type Store struct {
	db  *sql.DB
	who string // compte du système, pour l'audit
	now func() time.Time
}

// Open ouvre (ou crée) la base et applique les migrations.
func Open(path string) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	db, err := sql.Open(driverName, path)
	if err != nil {
		return nil, err
	}
	// Une seule connexion : les PRAGMA (clés étrangères…) valent par connexion, et la
	// console n'a qu'un utilisateur.
	db.SetMaxOpenConns(1)
	for _, p := range []string{"PRAGMA foreign_keys = ON", "PRAGMA journal_mode = WAL", "PRAGMA busy_timeout = 5000"} {
		if _, err := db.Exec(p); err != nil {
			db.Close()
			return nil, fmt.Errorf("%s : %w", p, err)
		}
	}
	s := &Store{db: db, now: time.Now, who: "inconnu"}
	if u, err := user.Current(); err == nil {
		s.who = u.Username
	}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, fmt.Errorf("migration de la base : %w", err)
	}
	return s, nil
}

// Close ferme la base.
func (s *Store) Close() error { return s.db.Close() }

var migrations = []string{
	// 1 : schéma initial (lot 1 : observer).
	`CREATE TABLE settings (
		key   TEXT PRIMARY KEY,
		value TEXT NOT NULL
	);
	CREATE TABLE clients (
		code       TEXT PRIMARY KEY,
		name       TEXT NOT NULL,
		created_at TEXT NOT NULL
	);
	CREATE TABLE buckets (
		name            TEXT PRIMARY KEY,
		region          TEXT NOT NULL,
		client_code     TEXT NOT NULL REFERENCES clients(code),
		poste           TEXT NOT NULL DEFAULT '',
		imported_at     TEXT NOT NULL,
		audited_at      TEXT,
		settings_json   TEXT,
		deviations_json TEXT,
		audit_error     TEXT NOT NULL DEFAULT ''
	);
	CREATE TABLE usage_daily (
		bucket          TEXT NOT NULL REFERENCES buckets(name) ON DELETE CASCADE,
		day             TEXT NOT NULL,
		active_bytes    INTEGER NOT NULL,
		padded_bytes    INTEGER NOT NULL,
		deleted_bytes   INTEGER NOT NULL,
		objects         INTEGER NOT NULL,
		deleted_objects INTEGER NOT NULL,
		upload_bytes    INTEGER NOT NULL DEFAULT 0,
		download_bytes  INTEGER NOT NULL DEFAULT 0,
		PRIMARY KEY (bucket, day)
	);
	CREATE TABLE audit (
		id     INTEGER PRIMARY KEY AUTOINCREMENT,
		at     TEXT NOT NULL,
		who    TEXT NOT NULL,
		action TEXT NOT NULL,
		target TEXT NOT NULL,
		result TEXT NOT NULL,
		detail TEXT NOT NULL DEFAULT ''
	);
	CREATE TRIGGER audit_no_update BEFORE UPDATE ON audit
		BEGIN SELECT RAISE(ABORT, 'journal d''audit en ajout seul'); END;
	CREATE TRIGGER audit_no_delete BEFORE DELETE ON audit
		BEGIN SELECT RAISE(ABORT, 'journal d''audit en ajout seul'); END;`,
}

func (s *Store) migrate() error {
	if _, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL)`); err != nil {
		return err
	}
	var v int
	err := s.db.QueryRow(`SELECT version FROM schema_version`).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		if _, err := s.db.Exec(`INSERT INTO schema_version VALUES (0)`); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	if v > len(migrations) {
		return fmt.Errorf("base en version %d, plus récente que cette console (%d) : mettre à jour kura-ctl", v, len(migrations))
	}
	for i := v; i < len(migrations); i++ {
		tx, err := s.db.Begin()
		if err != nil {
			return err
		}
		if _, err := tx.Exec(migrations[i]); err != nil {
			tx.Rollback()
			return fmt.Errorf("migration %d : %w", i+1, err)
		}
		if _, err := tx.Exec(`UPDATE schema_version SET version = ?`, i+1); err != nil {
			tx.Rollback()
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}

func ts(t time.Time) string { return t.UTC().Format(time.RFC3339) }

func parseTS(s string) time.Time {
	t, _ := time.Parse(time.RFC3339, s)
	return t
}

// --- audit --------------------------------------------------------------------

// Résultats d'une action auditée.
const (
	ResultOK    = "ok"
	ResultError = "erreur"
)

// AuditEntry est une ligne du journal d'audit.
type AuditEntry struct {
	ID     int64
	At     time.Time
	Who    string
	Action string
	Target string
	Result string
	Detail string
}

// Audit ajoute une ligne au journal. Ne jamais y mettre de secret.
func (s *Store) Audit(ctx context.Context, action, target, result, detail string) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO audit (at, who, action, target, result, detail) VALUES (?, ?, ?, ?, ?, ?)`,
		ts(s.now()), s.who, action, target, result, detail)
	return err
}

// AuditLog renvoie les dernières lignes du journal, la plus récente d'abord.
func (s *Store) AuditLog(ctx context.Context, limit int) ([]AuditEntry, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, at, who, action, target, result, detail FROM audit ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AuditEntry
	for rows.Next() {
		var e AuditEntry
		var at string
		if err := rows.Scan(&e.ID, &at, &e.Who, &e.Action, &e.Target, &e.Result, &e.Detail); err != nil {
			return nil, err
		}
		e.At = parseTS(at)
		out = append(out, e)
	}
	return out, rows.Err()
}

// --- réglages ----------------------------------------------------------------

// Setting lit un réglage ; def s'il est absent.
func (s *Store) Setting(ctx context.Context, key, def string) (string, error) {
	var v string
	err := s.db.QueryRowContext(ctx, `SELECT value FROM settings WHERE key = ?`, key).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return def, nil
	}
	return v, err
}

// SetSetting enregistre un réglage.
func (s *Store) SetSetting(ctx context.Context, key, value string) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO settings (key, value) VALUES (?, ?)
		ON CONFLICT(key) DO UPDATE SET value = excluded.value`, key, value)
	return err
}

// --- clients et buckets --------------------------------------------------------

// Client regroupe des postes.
type Client struct {
	Code string
	Name string
}

// EnsureClient crée le client s'il n'existe pas.
func (s *Store) EnsureClient(ctx context.Context, c Client) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO clients (code, name, created_at) VALUES (?, ?, ?)
		ON CONFLICT(code) DO NOTHING`, c.Code, c.Name, ts(s.now()))
	return err
}

// Clients renvoie les clients, par code.
func (s *Store) Clients(ctx context.Context) ([]Client, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT code, name FROM clients ORDER BY code`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Client
	for rows.Next() {
		var c Client
		if err := rows.Scan(&c.Code, &c.Name); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// Bucket est un bucket importé dans la console.
type Bucket struct {
	Name           string
	Region         string
	ClientCode     string
	Poste          string
	ImportedAt     time.Time
	AuditedAt      time.Time // zéro : jamais audité
	SettingsJSON   string    // réglages relevés (wasabi.Settings)
	DeviationsJSON string    // écarts au modèle ([]wasabi.Deviation)
	AuditError     string
}

// ErrNotFound : bucket inconnu de la console.
var ErrNotFound = errors.New("bucket inconnu de la console")

// ImportBucket déclare un bucket existant (aucune écriture chez Wasabi).
func (s *Store) ImportBucket(ctx context.Context, b Bucket) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO buckets (name, region, client_code, poste, imported_at) VALUES (?, ?, ?, ?, ?)`,
		b.Name, b.Region, b.ClientCode, b.Poste, ts(s.now()))
	return err
}

const bucketCols = `name, region, client_code, poste, imported_at, COALESCE(audited_at, ''),
	COALESCE(settings_json, ''), COALESCE(deviations_json, ''), audit_error`

func scanBucket(sc interface{ Scan(...any) error }) (Bucket, error) {
	var b Bucket
	var imported, audited string
	err := sc.Scan(&b.Name, &b.Region, &b.ClientCode, &b.Poste, &imported, &audited, &b.SettingsJSON, &b.DeviationsJSON, &b.AuditError)
	b.ImportedAt, b.AuditedAt = parseTS(imported), parseTS(audited)
	return b, err
}

// Buckets renvoie les buckets importés, par client puis nom.
func (s *Store) Buckets(ctx context.Context) ([]Bucket, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+bucketCols+` FROM buckets ORDER BY client_code, name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Bucket
	for rows.Next() {
		b, err := scanBucket(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

// Bucket renvoie un bucket importé.
func (s *Store) Bucket(ctx context.Context, name string) (Bucket, error) {
	b, err := scanBucket(s.db.QueryRowContext(ctx, `SELECT `+bucketCols+` FROM buckets WHERE name = ?`, name))
	if errors.Is(err, sql.ErrNoRows) {
		return Bucket{}, ErrNotFound
	}
	return b, err
}

// SaveBucketAudit enregistre le résultat d'un audit des réglages.
func (s *Store) SaveBucketAudit(ctx context.Context, name, settingsJSON, deviationsJSON, auditErr string) error {
	res, err := s.db.ExecContext(ctx, `UPDATE buckets SET audited_at = ?, settings_json = ?, deviations_json = ?, audit_error = ? WHERE name = ?`,
		ts(s.now()), settingsJSON, deviationsJSON, auditErr, name)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// --- usage --------------------------------------------------------------------

// Usage est l'utilisation d'un bucket un jour donné (API Stats de Wasabi).
type Usage struct {
	Bucket         string
	Day            string // YYYY-MM-DD (UTC)
	ActiveBytes    int64  // RawStorageSizeBytes : données courantes et versions
	PaddedBytes    int64  // PaddedStorageSizeBytes : stockage facturé (objets arrondis à 4 Ko)
	DeletedBytes   int64  // DeletedStorageSizeBytes : supprimé avant 90 jours, encore facturé
	Objects        int64
	DeletedObjects int64
	UploadBytes    int64
	DownloadBytes  int64
}

// UpsertUsage enregistre (ou remplace) des journées d'usage, en une transaction.
func (s *Store) UpsertUsage(ctx context.Context, rows []Usage) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	st, err := tx.PrepareContext(ctx, `INSERT INTO usage_daily
		(bucket, day, active_bytes, padded_bytes, deleted_bytes, objects, deleted_objects, upload_bytes, download_bytes)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(bucket, day) DO UPDATE SET
			active_bytes = excluded.active_bytes, padded_bytes = excluded.padded_bytes,
			deleted_bytes = excluded.deleted_bytes, objects = excluded.objects,
			deleted_objects = excluded.deleted_objects, upload_bytes = excluded.upload_bytes,
			download_bytes = excluded.download_bytes`)
	if err != nil {
		return err
	}
	defer st.Close()
	for _, u := range rows {
		if _, err := st.ExecContext(ctx, u.Bucket, u.Day, u.ActiveBytes, u.PaddedBytes, u.DeletedBytes,
			u.Objects, u.DeletedObjects, u.UploadBytes, u.DownloadBytes); err != nil {
			return fmt.Errorf("usage %s %s : %w", u.Bucket, u.Day, err)
		}
	}
	return tx.Commit()
}

// LastUsageDay renvoie le dernier jour enregistré pour un bucket ("" si aucun).
func (s *Store) LastUsageDay(ctx context.Context, bucket string) (string, error) {
	var d sql.NullString
	err := s.db.QueryRowContext(ctx, `SELECT MAX(day) FROM usage_daily WHERE bucket = ?`, bucket).Scan(&d)
	return d.String, err
}

// UsageRange renvoie l'usage d'un bucket entre deux jours inclus, par jour croissant.
// bucket vide : tous les buckets.
func (s *Store) UsageRange(ctx context.Context, bucket, from, to string) ([]Usage, error) {
	q := `SELECT bucket, day, active_bytes, padded_bytes, deleted_bytes, objects, deleted_objects, upload_bytes, download_bytes
		FROM usage_daily WHERE day >= ? AND day <= ?`
	args := []any{from, to}
	if bucket != "" {
		q += ` AND bucket = ?`
		args = append(args, bucket)
	}
	rows, err := s.db.QueryContext(ctx, q+` ORDER BY day, bucket`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Usage
	for rows.Next() {
		var u Usage
		if err := rows.Scan(&u.Bucket, &u.Day, &u.ActiveBytes, &u.PaddedBytes, &u.DeletedBytes,
			&u.Objects, &u.DeletedObjects, &u.UploadBytes, &u.DownloadBytes); err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

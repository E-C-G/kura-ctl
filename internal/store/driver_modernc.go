//go:build !mattn

package store

// Pilote livré : modernc.org/sqlite, en Go pur (sans CGO), compilable pour les trois
// systèmes depuis n'importe lequel.
import _ "modernc.org/sqlite"

const driverName = "sqlite"

// dsn : réglages appliqués à chaque connexion ouverte par database/sql.
func dsn(path string) string {
	return path + "?_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)"
}

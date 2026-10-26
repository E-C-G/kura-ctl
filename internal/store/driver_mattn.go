//go:build mattn

package store

// Pilote de développement (go test -tags mattn) : même moteur SQLite, en CGO, pour
// tester là où modernc.org/sqlite n'est pas disponible.
import _ "github.com/mattn/go-sqlite3"

const driverName = "sqlite3"

// dsn : réglages appliqués à chaque connexion ouverte par database/sql.
func dsn(path string) string {
	return path + "?_foreign_keys=1&_busy_timeout=5000&_journal_mode=WAL"
}

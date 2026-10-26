//go:build mattn

package store

// Pilote de développement (go test -tags mattn) : même moteur SQLite, en CGO, pour
// tester là où modernc.org/sqlite n'est pas disponible.
import _ "github.com/mattn/go-sqlite3"

const driverName = "sqlite3"

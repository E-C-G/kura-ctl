//go:build !mattn

package store

// Pilote livré : modernc.org/sqlite, en Go pur (sans CGO), compilable pour les trois
// systèmes depuis n'importe lequel.
import _ "modernc.org/sqlite"

const driverName = "sqlite"

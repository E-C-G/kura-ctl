package wasabi

import (
	"fmt"
	"sort"
)

// Template est un modèle de réglages de bucket (specs §5).
type Template struct {
	Name                  string
	ObjectLockMode        string // GOVERNANCE | COMPLIANCE
	ObjectLockDays        int
	NoncurrentDays        int
	ExpiredDeleteMarker   bool
	AbortMultipartDays    int
	DenyInsecureTransport bool
	DenyVersionDeletion   bool
}

// Standard est le modèle « sauvegarde standard ».
var Standard = Template{
	Name:                  "sauvegarde-standard",
	ObjectLockMode:        "GOVERNANCE",
	ObjectLockDays:        30,
	NoncurrentDays:        90,
	ExpiredDeleteMarker:   true,
	AbortMultipartDays:    7,
	DenyInsecureTransport: true,
	DenyVersionDeletion:   true,
}

// Gravités d'un écart.
const (
	Critical = "critique"
	High     = "haute"
	Medium   = "moyenne"
	Info     = "info"
)

// Corrections possibles.
const (
	FixAfter     = "corrigeable après coup"
	FixNewBucket = "bucket neuf nécessaire (Object Lock seulement à la création)"
	FixKey       = "droit à ajouter à la clé de la console"
)

// Deviation est un écart entre un bucket et le modèle.
type Deviation struct {
	Code     string `json:"code"`
	Severity string `json:"severity"`
	Message  string `json:"message"`
	Fix      string `json:"fix"`
}

// known : réglage lu à ce relevé, ou valeur précédente conservée.
func (s Settings) known(name string) bool {
	if _, unread := s.ReadErrors[name]; !unread {
		return true
	}
	_, kept := s.Kept[name]
	return kept
}

// Audit compare les réglages relevés au modèle. L'ordre suit la gravité.
func (t Template) Audit(s Settings) []Deviation {
	var out []Deviation
	add := func(code, sev, fix, format string, a ...any) {
		out = append(out, Deviation{Code: code, Severity: sev, Fix: fix, Message: fmt.Sprintf(format, a...)})
	}
	names := make([]string, 0, len(s.ReadErrors))
	for name := range s.ReadErrors {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		msg := s.ReadErrors[name]
		if at, ok := s.Kept[name]; ok {
			add("illisible-"+name, High, FixKey, "%s illisible : %s (écarts évalués sur la valeur lue le %s)",
				label(name), msg, at.Format("2006-01-02"))
		} else {
			add("illisible-"+name, High, FixKey, "%s illisible : %s", label(name), msg)
		}
	}

	if s.known("versioning") && s.Versioning != "Enabled" {
		add("versioning", Critical, FixAfter,
			"versioning %s : un fichier écrasé ou supprimé par la synchronisation n'est pas récupérable", lower(s.Versioning))
	}
	if s.Lifecycle.ExpiresCurrentDays != 0 {
		add("cycle-courantes", Critical, FixAfter,
			"le cycle de vie expire les versions courantes : des fichiers toujours présents sur le poste disparaissent du bucket")
	}
	if s.known("object_lock") {
		switch {
		case !s.ObjectLock.Enabled:
			add("object-lock", High, FixNewBucket,
				"pas d'Object Lock : une clé qui aurait le droit de supprimer des versions pourrait purger l'historique")
		case s.ObjectLock.Mode != t.ObjectLockMode || s.ObjectLock.Days != t.ObjectLockDays:
			add("object-lock-retention", Medium, FixAfter,
				"rétention par défaut %s, attendu %s", retention(s.ObjectLock.Mode, s.ObjectLock.Days), retention(t.ObjectLockMode, t.ObjectLockDays))
		}
	}
	if s.known("policy") {
		switch {
		case !s.Policy.Present:
			add("strategie", High, FixAfter, "pas de stratégie de bucket : aucune deuxième barrière si la stratégie d'une clé de poste est trop large")
		default:
			if t.DenyVersionDeletion && !s.Policy.DenyVersionDeletion {
				add("strategie-versions", High, FixAfter, "la stratégie de bucket n'interdit pas la suppression de versions")
			}
			if t.DenyInsecureTransport && !s.Policy.DenyInsecureTransport {
				add("strategie-https", Medium, FixAfter, "la stratégie de bucket n'interdit pas l'accès sans HTTPS")
			}
		}
	}
	if s.known("lifecycle") {
		switch {
		case s.Lifecycle.NoncurrentDays == 0:
			add("cycle-versions", Medium, FixAfter, "anciennes versions jamais supprimées : le volume facturé ne fait que croître")
		case s.Lifecycle.NoncurrentDays != t.NoncurrentDays:
			add("cycle-versions-duree", Info, FixAfter, "anciennes versions supprimées après %d jours (modèle : %d)", s.Lifecycle.NoncurrentDays, t.NoncurrentDays)
		}
		if t.ExpiredDeleteMarker && !s.Lifecycle.ExpiredDeleteMarker && s.Lifecycle.ExpiresCurrentDays == 0 {
			add("cycle-marqueurs", Info, FixAfter, "marqueurs de suppression orphelins non nettoyés")
		}
		if t.AbortMultipartDays > 0 && (s.Lifecycle.AbortMultipartDays == 0 || s.Lifecycle.AbortMultipartDays > t.AbortMultipartDays) {
			kept := "sans limite fixée par le cycle de vie"
			if s.Lifecycle.AbortMultipartDays > 0 {
				kept = fmt.Sprintf("%d jours", s.Lifecycle.AbortMultipartDays)
			}
			add("cycle-multipart", Info, FixAfter, "envois interrompus gardés %s (modèle : %d jours)", kept, t.AbortMultipartDays)
		}
		for _, r := range s.Lifecycle.PartialRules {
			add("cycle-partiel", Info, FixAfter, "règle de cycle de vie non prise en compte : %s", r)
		}
	}
	sortBySeverity(out)
	return out
}

var severityRank = map[string]int{Critical: 0, High: 1, Medium: 2, Info: 3}

func sortBySeverity(d []Deviation) {
	for i := 1; i < len(d); i++ { // tri par insertion stable : peu d'éléments
		for j := i; j > 0 && severityRank[d[j].Severity] < severityRank[d[j-1].Severity]; j-- {
			d[j], d[j-1] = d[j-1], d[j]
		}
	}
}

func label(name string) string {
	switch name {
	case "versioning":
		return "versioning"
	case "object_lock":
		return "Object Lock"
	case "lifecycle":
		return "cycle de vie"
	case "policy":
		return "stratégie de bucket"
	}
	return name
}

func lower(s string) string {
	switch s {
	case "Suspended":
		return "suspendu"
	case "Disabled", "":
		return "inactif"
	}
	return s
}

func retention(mode string, days int) string {
	if mode == "" {
		return "aucune"
	}
	m := map[string]string{"GOVERNANCE": "gouvernance", "COMPLIANCE": "conformité"}[mode]
	if m == "" {
		m = mode
	}
	return fmt.Sprintf("%s %d j", m, days)
}

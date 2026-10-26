package jobs

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/E-C-G/kura-ctl/internal/store"
	"github.com/E-C-G/kura-ctl/internal/wasabi"
)

// TB : unité de facturation de Wasabi, en base 1024 (1 To = 1024 Go de 1024³ octets).
const TB = 1 << 40

// MinBilledTB : en paiement à l'usage, Wasabi facture chaque jour au moins 1 To de
// stockage actif par compte ; le stockage supprimé encore facturé s'y ajoute.
const MinBilledTB = 1.0

// Window : période de l'estimation des coûts (30 jours glissants : une estimation
// est disponible même en début de mois, quand Wasabi n'a encore rien publié).
const Window = 30

// Pricing sert à estimer les coûts.
type Pricing struct {
	PerTB    float64 // prix au To et par mois
	Currency string
}

// BucketSummary résume un bucket pour la vue d'ensemble.
type BucketSummary struct {
	store.Bucket
	LastDay      string
	Last         store.Usage // dernière journée connue
	MonthAvgTB   float64     // moyenne sur 30 jours : actif (arrondi + métadonnées) + supprimé facturé
	MonthCost    float64     // part du bucket, hors minimum du compte
	Deviations   []wasabi.Deviation
	BySeverity   map[string]int
	Settings     *wasabi.Settings
	GrowthAlerts []Alert
}

// Alert est une alerte de la console.
type Alert struct {
	Severity string
	Bucket   string
	Message  string
	Link     string // action proposée (facultative)
	LinkText string
}

// Overview est la vue d'ensemble.
type Overview struct {
	Buckets     []BucketSummary
	TotalTB     float64 // stockage facturé du jour le plus récent
	MonthAvgTB  float64 // moyenne sur 30 jours, tous buckets
	MonthCost   float64 // somme des buckets (usage réel)
	BilledCost  float64 // avec le minimum d'1 To de stockage actif
	MinimumHits bool    // le minimum s'applique au moins un jour
	Days        int     // journées prises en compte
	Alerts      []Alert
}

// Croissance qui déclenche l'alerte : +20 % en un jour et au moins 1 Go de plus,
// hors des 7 premiers jours d'un bucket (envoi initial).
const (
	GrowthThreshold = 0.20
	GrowthMinBytes  = 1 << 30
	GrowthGrace     = 7
)

// Échéances des clés de poste.
const (
	KeyConfirmAfter = 3 * 24 * time.Hour  // clé remise sans confirmation d'installation
	KeyRotateAfter  = 90 * 24 * time.Hour // rotation recommandée
)

// BuildOverview calcule la vue d'ensemble à partir de la base.
//
// Coût, selon la formule publiée par Wasabi : chaque jour,
// (max(actif, 1 To) + supprimé) × tarif / 30, l'actif étant la somme, sur le compte,
// du stockage arrondi et des métadonnées. L'estimation mensuelle est la moyenne
// journalière des 30 derniers jours connus × tarif.
func BuildOverview(ctx context.Context, st *store.Store, p Pricing, now time.Time) (Overview, error) {
	now = now.UTC()
	var ov Overview
	buckets, err := st.Buckets(ctx)
	if err != nil {
		return ov, err
	}
	today := now.Format("2006-01-02")
	since := now.AddDate(0, 0, -Window).Format("2006-01-02")
	recent := now.AddDate(0, 0, -7).Format("2006-01-02")
	type dayTotal struct{ active, deleted float64 }
	perDay := map[string]*dayTotal{}
	for _, b := range buckets {
		bs := BucketSummary{Bucket: b, BySeverity: map[string]int{}}
		if b.SettingsJSON != "" {
			var s wasabi.Settings
			if json.Unmarshal([]byte(b.SettingsJSON), &s) == nil {
				bs.Settings = &s
			}
		}
		if b.DeviationsJSON != "" {
			_ = json.Unmarshal([]byte(b.DeviationsJSON), &bs.Deviations)
		}
		for _, d := range bs.Deviations {
			bs.BySeverity[d.Severity]++
			if d.Severity == wasabi.Critical || d.Severity == wasabi.High {
				ov.Alerts = append(ov.Alerts, Alert{Severity: d.Severity, Bucket: b.Name, Message: d.Message})
			}
		}
		if b.AuditError != "" && len(bs.Deviations) == 0 {
			ov.Alerts = append(ov.Alerts, Alert{Severity: wasabi.High, Bucket: b.Name, Message: "dernier relevé en échec : " + b.AuditError})
		}
		if b.CollectError != "" {
			ov.Alerts = append(ov.Alerts, Alert{Severity: wasabi.High, Bucket: b.Name, Message: "collecte de l'usage en échec : " + b.CollectError})
		}
		first, err := st.FirstUsageDay(ctx, b.Name)
		if err != nil {
			return ov, err
		}
		graceEnd := ""
		if t, err := time.Parse("2006-01-02", first); err == nil {
			graceEnd = t.AddDate(0, 0, GrowthGrace).Format("2006-01-02")
		}
		rows, err := st.UsageRange(ctx, b.Name, since, today)
		if err != nil {
			return ov, err
		}
		var sum float64
		for i, u := range rows {
			active := float64(u.PaddedBytes + u.MetadataBytes)
			sum += active + float64(u.DeletedBytes)
			if perDay[u.Day] == nil {
				perDay[u.Day] = &dayTotal{}
			}
			perDay[u.Day].active += active
			perDay[u.Day].deleted += float64(u.DeletedBytes)
			if i == 0 || u.Day < recent || u.Day <= graceEnd {
				continue
			}
			prev := rows[i-1]
			delta := u.PaddedBytes - prev.PaddedBytes
			if prev.PaddedBytes > 0 && delta >= GrowthMinBytes && float64(delta)/float64(prev.PaddedBytes) > GrowthThreshold {
				a := Alert{Severity: wasabi.High, Bucket: b.Name, Message: fmt.Sprintf(
					"croissance de %+.0f %% le %s (%s → %s) : vérifier le poste (fichiers chiffrés par un rançongiciel ?)",
					100*float64(delta)/float64(prev.PaddedBytes), u.Day, HumanBytes(prev.PaddedBytes), HumanBytes(u.PaddedBytes))}
				bs.GrowthAlerts = append(bs.GrowthAlerts, a)
				ov.Alerts = append(ov.Alerts, a)
			}
		}
		if len(rows) > 0 {
			bs.Last = rows[len(rows)-1]
			bs.LastDay = bs.Last.Day
			bs.MonthAvgTB = sum / float64(len(rows)) / TB
			bs.MonthCost = bs.MonthAvgTB * p.PerTB
			ov.TotalTB += float64(bs.Last.PaddedBytes+bs.Last.MetadataBytes+bs.Last.DeletedBytes) / TB
		} else if last, _ := st.LastUsageDay(ctx, b.Name); last != "" {
			bs.LastDay = last
		}
		if bs.LastDay == "" || bs.LastDay < now.AddDate(0, 0, -3).Format("2006-01-02") {
			msg := "aucune statistique collectée"
			if bs.LastDay != "" {
				msg = "pas de statistique depuis le " + bs.LastDay
			}
			ov.Alerts = append(ov.Alerts, Alert{Severity: wasabi.Medium, Bucket: b.Name, Message: msg})
		}
		ov.MonthCost += bs.MonthCost
		ov.Buckets = append(ov.Buckets, bs)
	}
	// Clés des postes : installation à confirmer, rotation due (specs §6).
	keys, err := st.Keys(ctx, "")
	if err != nil {
		return ov, err
	}
	for _, k := range keys {
		switch {
		case k.Status == store.KeyIssued && now.Sub(k.CreatedAt) > KeyConfirmAfter:
			ov.Alerts = append(ov.Alerts, Alert{Severity: wasabi.Medium, Bucket: k.Bucket, Message: fmt.Sprintf(
				"clé %s remise le %s, installation jamais confirmée (à confirmer, ou à désactiver si le paquet est perdu)", k.ID, k.CreatedAt.Format("2006-01-02")),
				Link: "/buckets/" + k.Bucket + "#cles", LinkText: "clés du poste"})
		case k.Status == store.KeyInstalled && now.Sub(k.CreatedAt) > KeyRotateAfter:
			ov.Alerts = append(ov.Alerts, Alert{Severity: wasabi.Medium, Bucket: k.Bucket, Message: fmt.Sprintf(
				"clé %s créée le %s : rotation due (plus de %d jours)", k.ID, k.CreatedAt.Format("2006-01-02"), int(KeyRotateAfter.Hours()/24)),
				Link: "/buckets/" + k.Bucket + "#cles", LinkText: "créer la clé suivante (paquet « clé seule »)"})
		}
	}
	var billed, real float64
	for _, d := range perDay {
		active := d.active / TB
		real += active + d.deleted/TB
		if active < MinBilledTB {
			active = MinBilledTB
			ov.MinimumHits = true
		}
		billed += active + d.deleted/TB
	}
	if ov.Days = len(perDay); ov.Days > 0 {
		ov.MonthAvgTB = real / float64(ov.Days)
		ov.BilledCost = billed / float64(ov.Days) * p.PerTB
	} else {
		ov.BilledCost = MinBilledTB * p.PerTB
		ov.MinimumHits = true
	}
	rank := map[string]int{wasabi.Critical: 0, wasabi.High: 1, wasabi.Medium: 2, wasabi.Info: 3}
	sort.SliceStable(ov.Alerts, func(i, j int) bool { return rank[ov.Alerts[i].Severity] < rank[ov.Alerts[j].Severity] })
	return ov, nil
}

// HumanBytes écrit une taille en base 1024, comme la facturation Wasabi
// (1 Go = 1024³ octets).
func HumanBytes(b int64) string {
	f := float64(b)
	units := []string{"o", "Ko", "Mo", "Go", "To", "Po"}
	i := 0
	for f >= 1024 && i < len(units)-1 {
		f /= 1024
		i++
	}
	if i == 0 {
		return fmt.Sprintf("%d o", b)
	}
	return fmt.Sprintf("%.2f %s", f, units[i])
}

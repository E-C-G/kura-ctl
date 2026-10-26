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

// TB : Wasabi facture au téraoctet (10^12 octets).
const TB = 1e12

// MinBilledTB : en paiement à l'usage, Wasabi facture au moins 1 To par mois et par compte.
const MinBilledTB = 1.0

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
	MonthAvgTB   float64     // stockage facturé moyen du mois (actif arrondi + supprimé facturé)
	MonthCost    float64
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
}

// Overview est la vue d'ensemble.
type Overview struct {
	Month       string
	Buckets     []BucketSummary
	TotalTB     float64 // stockage facturé du jour le plus récent
	MonthAvgTB  float64
	MonthCost   float64 // somme des buckets
	BilledCost  float64 // avec le minimum facturé du compte
	MinimumHits bool    // le minimum d'1 To s'applique
	Alerts      []Alert
}

// GrowthThreshold : croissance journalière qui déclenche l'alerte (+20 %).
const GrowthThreshold = 0.20

// BuildOverview calcule la vue d'ensemble à partir de la base.
func BuildOverview(ctx context.Context, st *store.Store, p Pricing, now time.Time) (Overview, error) {
	now = now.UTC()
	ov := Overview{Month: now.Format("2006-01")}
	buckets, err := st.Buckets(ctx)
	if err != nil {
		return ov, err
	}
	monthStart := now.Format("2006-01") + "-01"
	since := now.AddDate(0, 0, -30).Format("2006-01-02")
	if monthStart < since {
		since = monthStart
	}
	today := now.Format("2006-01-02")
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
		rows, err := st.UsageRange(ctx, b.Name, since, today)
		if err != nil {
			return ov, err
		}
		var sum float64
		var n int
		for i, u := range rows {
			if u.Day >= monthStart {
				sum += float64(u.PaddedBytes + u.DeletedBytes)
				n++
			}
			if i > 0 {
				prev := rows[i-1]
				if prev.PaddedBytes > 0 && float64(u.PaddedBytes-prev.PaddedBytes)/float64(prev.PaddedBytes) > GrowthThreshold &&
					u.Day >= now.AddDate(0, 0, -7).Format("2006-01-02") {
					a := Alert{Severity: wasabi.Critical, Bucket: b.Name, Message: fmt.Sprintf(
						"croissance de %+.0f %% le %s (%s → %s) : vérifier le poste (chiffrement par un rançongiciel ?)",
						100*float64(u.PaddedBytes-prev.PaddedBytes)/float64(prev.PaddedBytes), u.Day,
						HumanBytes(prev.PaddedBytes), HumanBytes(u.PaddedBytes))}
					bs.GrowthAlerts = append(bs.GrowthAlerts, a)
					ov.Alerts = append(ov.Alerts, a)
				}
			}
		}
		if len(rows) > 0 {
			bs.Last = rows[len(rows)-1]
			bs.LastDay = bs.Last.Day
			ov.TotalTB += float64(bs.Last.PaddedBytes+bs.Last.DeletedBytes) / TB
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
		if n > 0 {
			bs.MonthAvgTB = sum / float64(n) / TB
			bs.MonthCost = bs.MonthAvgTB * p.PerTB
		}
		ov.MonthAvgTB += bs.MonthAvgTB
		ov.MonthCost += bs.MonthCost
		ov.Buckets = append(ov.Buckets, bs)
	}
	ov.BilledCost = ov.MonthCost
	if ov.MonthAvgTB < MinBilledTB {
		ov.MinimumHits = true
		ov.BilledCost = MinBilledTB * p.PerTB
	}
	rank := map[string]int{wasabi.Critical: 0, wasabi.High: 1, wasabi.Medium: 2, wasabi.Info: 3}
	sort.SliceStable(ov.Alerts, func(i, j int) bool { return rank[ov.Alerts[i].Severity] < rank[ov.Alerts[j].Severity] })
	return ov, nil
}

// HumanBytes écrit une taille en unités décimales (comme la facturation Wasabi).
func HumanBytes(b int64) string {
	f := float64(b)
	units := []string{"o", "Ko", "Mo", "Go", "To", "Po"}
	i := 0
	for f >= 1000 && i < len(units)-1 {
		f /= 1000
		i++
	}
	if i == 0 {
		return fmt.Sprintf("%d o", b)
	}
	return fmt.Sprintf("%.2f %s", f, units[i])
}

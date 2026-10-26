package jobs

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/E-C-G/kura-ctl/internal/store"
	"github.com/E-C-G/kura-ctl/internal/wasabi"
)

// fakeAccount fabrique une journée d'usage par jour demandé.
type fakeAccount struct {
	calls    [][3]string
	settings wasabi.Settings
	bytes    func(day string) int64
	fail     error
}

func (f *fakeAccount) ListBuckets(context.Context) ([]wasabi.BucketInfo, error) { return nil, nil }
func (f *fakeAccount) ReadSettings(_ context.Context, name, region string) wasabi.Settings {
	s := f.settings
	s.Name, s.Region = name, region
	return s
}
func (f *fakeAccount) BucketDaily(_ context.Context, b, from, to string) ([]wasabi.DailyUsage, error) {
	f.calls = append(f.calls, [3]string{b, from, to})
	if f.fail != nil {
		return nil, f.fail
	}
	var out []wasabi.DailyUsage
	start, _ := time.Parse("2006-01-02", from)
	end, _ := time.Parse("2006-01-02", to)
	for d := start; !d.After(end); d = d.AddDate(0, 0, 1) {
		day := d.Format("2006-01-02")
		v := int64(500e9)
		if f.bytes != nil {
			v = f.bytes(day)
		}
		out = append(out, wasabi.DailyUsage{Day: day, RawBytes: v, PaddedBytes: v, Objects: 10})
	}
	return out, nil
}

func setup(t *testing.T) (*store.Store, *Runner, *fakeAccount, *time.Time) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "k.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	ctx := context.Background()
	st.EnsureClient(ctx, store.Client{Code: "acme", Name: "Acme"})
	st.ImportBucket(ctx, store.Bucket{Name: "acme-srv01", Region: "eu-central-1", ClientCode: "acme"})
	now := time.Date(2026, 10, 26, 9, 0, 0, 0, time.UTC)
	acc := &fakeAccount{settings: wasabi.Settings{Versioning: "Enabled"}}
	r := &Runner{Store: st, Account: acc, Template: wasabi.Standard, Now: func() time.Time { return now }}
	return st, r, acc, &now
}

func TestCatchUpAfterTenDaysClosed(t *testing.T) {
	st, r, acc, now := setup(t)
	ctx := context.Background()
	rep, err := r.Refresh(ctx)
	if err != nil || len(rep.Errors) != 0 {
		t.Fatalf("première actualisation : %+v %v", rep, err)
	}
	if acc.calls[0][1] != "2025-10-26" || acc.calls[0][2] != "2026-10-26" {
		t.Fatalf("première collecte : un an d'historique attendu, reçu %v", acc.calls[0])
	}
	*now = now.AddDate(0, 0, 10) // console fermée 10 jours
	rep, _ = r.Refresh(ctx)
	if got := acc.calls[1]; got[1] != "2026-10-25" || got[2] != "2026-11-05" {
		t.Fatalf("rattrapage : du dernier jour - 1 à aujourd'hui attendu, reçu %v", got)
	}
	rows, _ := st.UsageRange(ctx, "acme-srv01", "2026-10-27", "2026-11-05")
	if len(rows) != 10 || rep.Days != 12 {
		t.Fatalf("10 journées rattrapées attendues : %d (rapport %d)", len(rows), rep.Days)
	}
	b, _ := st.Bucket(ctx, "acme-srv01")
	if b.AuditedAt.IsZero() || !strings.Contains(b.DeviationsJSON, "object-lock") {
		t.Fatalf("audit non enregistré : %+v", b)
	}
	log, _ := st.AuditLog(ctx, 10)
	if len(log) < 4 {
		t.Fatalf("journal d'audit : %+v", log)
	}
}

func TestRefreshReportsErrorsPerBucket(t *testing.T) {
	_, r, acc, _ := setup(t)
	acc.fail = errors.New("API Stats : accès refusé")
	acc.settings.ReadErrors = map[string]string{"policy": "accès refusé"}
	rep, err := r.Refresh(context.Background())
	if err != nil || !strings.Contains(rep.Errors["acme-srv01"], "illisible") || !strings.Contains(rep.Errors["acme-srv01"], "Stats") {
		t.Fatalf("rapport : %+v %v", rep, err)
	}
}

func TestOverviewCostsAndGrowth(t *testing.T) {
	st, r, acc, now := setup(t)
	ctx := context.Background()
	acc.bytes = func(day string) int64 {
		if day >= "2026-10-25" {
			return 900e9 // +80 % la veille : alerte
		}
		return 500e9
	}
	r.Refresh(ctx)
	ov, err := BuildOverview(ctx, st, Pricing{PerTB: 7, Currency: "$"}, *now)
	if err != nil {
		t.Fatal(err)
	}
	bs := ov.Buckets[0]
	// Octobre : 24 jours à 0,5 To puis 2 jours à 0,9 To.
	want := (24*0.5 + 2*0.9) / 26
	if d := bs.MonthAvgTB - want; d > 1e-9 || d < -1e-9 {
		t.Fatalf("moyenne du mois %.6f, attendu %.6f", bs.MonthAvgTB, want)
	}
	if !ov.MinimumHits || ov.BilledCost != 7 {
		t.Fatalf("minimum d'1 To : %+v", ov)
	}
	if len(bs.GrowthAlerts) != 1 || !strings.Contains(bs.GrowthAlerts[0].Message, "+80 %") {
		t.Fatalf("alerte de croissance : %+v", bs.GrowthAlerts)
	}
	if ov.Alerts[0].Severity != wasabi.Critical {
		t.Fatalf("alertes triées par gravité : %+v", ov.Alerts)
	}
	if HumanBytes(1_500_000_000) != "1.50 Go" || HumanBytes(12) != "12 o" {
		t.Fatal("HumanBytes")
	}
}

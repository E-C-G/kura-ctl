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
	deleted  int64
	fail     error
}

func (f *fakeAccount) ListBuckets(context.Context) ([]wasabi.BucketInfo, error) { return nil, nil }
func (f *fakeAccount) ReadSettings(_ context.Context, name, region string) wasabi.Settings {
	s := f.settings
	s.Name, s.Region, s.ReadAt = name, region, time.Now()
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
		out = append(out, wasabi.DailyUsage{Day: day, RawBytes: v, PaddedBytes: v, DeletedBytes: f.deleted, Objects: 10})
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
	const gib = 1 << 30
	acc.bytes = func(day string) int64 {
		if day >= "2026-10-25" {
			return 900 * gib // +80 % la veille : alerte
		}
		return 500 * gib
	}
	r.Refresh(ctx)
	ov, err := BuildOverview(ctx, st, Pricing{PerTB: 7, Currency: "$"}, *now)
	if err != nil {
		t.Fatal(err)
	}
	bs := ov.Buckets[0]
	// 30 derniers jours (26/09 → 26/10 inclus, 31 journées) : 29 à 500 Go puis 2 à 900 Go.
	want := (29*500.0 + 2*900) / 31 / 1024
	if d := bs.MonthAvgTB - want; d > 1e-9 || d < -1e-9 || ov.Days != 31 {
		t.Fatalf("moyenne %.6f sur %d jours, attendu %.6f sur 31", bs.MonthAvgTB, ov.Days, want)
	}
	if !ov.MinimumHits || ov.BilledCost != 7 {
		t.Fatalf("minimum d'1 To : %+v", ov)
	}
	if len(bs.GrowthAlerts) != 1 || !strings.Contains(bs.GrowthAlerts[0].Message, "+80 %") {
		t.Fatalf("alerte de croissance : %+v", bs.GrowthAlerts)
	}
	if ov.Alerts[0].Severity != wasabi.High {
		t.Fatalf("alertes triées par gravité : %+v", ov.Alerts)
	}
	if HumanBytes(1536*1024*1024) != "1.50 Go" || HumanBytes(12) != "12 o" {
		t.Fatal("HumanBytes")
	}
}

// Le minimum d'1 To ne porte que sur le stockage actif : le supprimé s'y ajoute.
func TestMinimumAppliesToActiveOnly(t *testing.T) {
	st, r, acc, now := setup(t)
	ctx := context.Background()
	acc.bytes = func(string) int64 { return 600 << 30 }
	acc.deleted = 512 << 30
	r.Refresh(ctx)
	ov, _ := BuildOverview(ctx, st, Pricing{PerTB: 10}, *now)
	if d := ov.BilledCost - 15; d > 1e-9 || d < -1e-9 {
		t.Fatalf("coût %.4f, attendu 15 (1 To minimum + 0,5 To supprimé)", ov.BilledCost)
	}
}

// Petites variations et envoi initial : pas d'alerte de croissance.
func TestNoGrowthAlertForSmallOrInitial(t *testing.T) {
	st, r, acc, now := setup(t)
	ctx := context.Background()
	acc.bytes = func(day string) int64 {
		switch {
		case day < "2026-10-20":
			return 0 // bucket vide, envoi initial le 20
		case day < "2026-10-24":
			return int64(day[9]-'0') * (100 << 30)
		case day < "2026-10-26":
			return 4 << 10
		}
		return 10 << 20 // de 4 Ko à 10 Mo : sous le seuil absolu
	}
	r.Refresh(ctx)
	ov, _ := BuildOverview(ctx, st, Pricing{PerTB: 7}, *now)
	if a := ov.Buckets[0].GrowthAlerts; len(a) != 0 {
		t.Fatalf("alertes inattendues : %+v", a)
	}
}

// Une panne passagère ne fait pas disparaître un écart critique déjà relevé.
func TestUnreadableSettingKeepsKnownDeviation(t *testing.T) {
	st, r, acc, now := setup(t)
	ctx := context.Background()
	acc.settings.Versioning = "Suspended"
	if err := r.AuditBucket(ctx, "acme-srv01", "eu-central-1"); err != nil {
		t.Fatal(err)
	}
	acc.settings.Versioning = ""
	acc.settings.ReadErrors = map[string]string{"versioning": "Wasabi injoignable"}
	r.AuditBucket(ctx, "acme-srv01", "eu-central-1")
	ov, _ := BuildOverview(ctx, st, Pricing{PerTB: 7}, *now)
	var crit, unreadable bool
	for _, a := range ov.Alerts {
		crit = crit || (a.Severity == wasabi.Critical && strings.Contains(a.Message, "versioning suspendu"))
		unreadable = unreadable || (a.Severity == wasabi.High && strings.Contains(a.Message, "illisible"))
	}
	if !crit || !unreadable {
		t.Fatalf("alertes : %+v", ov.Alerts)
	}
}

// Collecte en échec : visible sur le bucket et en alerte, effacée au succès suivant.
func TestCollectErrorRecorded(t *testing.T) {
	st, r, acc, now := setup(t)
	ctx := context.Background()
	acc.fail = errors.New("API Stats : accès refusé")
	r.CollectBucket(ctx, "acme-srv01")
	b, _ := st.Bucket(ctx, "acme-srv01")
	if b.CollectError == "" || b.CollectedAt.IsZero() {
		t.Fatalf("erreur de collecte non enregistrée : %+v", b)
	}
	ov, _ := BuildOverview(ctx, st, Pricing{PerTB: 7}, *now)
	if !strings.Contains(ov.Alerts[0].Message, "collecte de l'usage en échec") {
		t.Fatalf("alertes : %+v", ov.Alerts)
	}
	acc.fail = nil
	r.CollectBucket(ctx, "acme-srv01")
	if b, _ = st.Bucket(ctx, "acme-srv01"); b.CollectError != "" {
		t.Fatalf("erreur non effacée : %q", b.CollectError)
	}
}

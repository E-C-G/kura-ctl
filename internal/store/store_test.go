package store

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func open(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "kura-ctl.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestMigrationsAreIdempotent(t *testing.T) {
	p := filepath.Join(t.TempDir(), "k.db")
	for i := 0; i < 2; i++ {
		s, err := Open(p)
		if err != nil {
			t.Fatalf("ouverture %d : %v", i, err)
		}
		s.Close()
	}
}

func TestAuditIsAppendOnly(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	if err := s.Audit(ctx, "import", "acme-srv01", ResultOK, "client acme"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`UPDATE audit SET result = 'x'`); err == nil {
		t.Fatal("modification du journal acceptée")
	}
	if _, err := s.db.Exec(`DELETE FROM audit`); err == nil {
		t.Fatal("suppression dans le journal acceptée")
	}
	log, err := s.AuditLog(ctx, 10)
	if err != nil || len(log) != 1 || log[0].Action != "import" || log[0].Who == "" {
		t.Fatalf("journal : %+v %v", log, err)
	}
}

func TestBucketsAndUsage(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	if err := s.ImportBucket(ctx, Bucket{Name: "acme-srv01", Region: "eu-central-1", ClientCode: "acme"}); err == nil {
		t.Fatal("bucket importé pour un client inexistant")
	}
	if err := s.EnsureClient(ctx, Client{Code: "acme", Name: "Acme"}); err != nil {
		t.Fatal(err)
	}
	if err := s.EnsureClient(ctx, Client{Code: "acme", Name: "Autre nom"}); err != nil {
		t.Fatal(err)
	}
	if err := s.ImportBucket(ctx, Bucket{Name: "acme-srv01", Region: "eu-central-1", ClientCode: "acme", Poste: "SRV01"}); err != nil {
		t.Fatal(err)
	}
	if err := s.ImportBucket(ctx, Bucket{Name: "acme-srv01", Region: "eu-central-1", ClientCode: "acme"}); err == nil {
		t.Fatal("double import accepté")
	}
	if _, err := s.Bucket(ctx, "absent"); err != ErrNotFound {
		t.Fatalf("bucket absent : %v", err)
	}
	if err := s.SaveBucketAudit(ctx, "acme-srv01", `{"versioning":"Enabled"}`, `[]`, ""); err != nil {
		t.Fatal(err)
	}
	b, err := s.Bucket(ctx, "acme-srv01")
	if err != nil || b.Poste != "SRV01" || b.AuditedAt.IsZero() || b.SettingsJSON == "" {
		t.Fatalf("bucket : %+v %v", b, err)
	}

	if d, _ := s.LastUsageDay(ctx, "acme-srv01"); d != "" {
		t.Fatalf("aucun usage attendu, reçu %q", d)
	}
	rows := []Usage{
		{Bucket: "acme-srv01", Day: "2026-10-24", ActiveBytes: 100, PaddedBytes: 110, Objects: 3},
		{Bucket: "acme-srv01", Day: "2026-10-25", ActiveBytes: 120, PaddedBytes: 130, Objects: 4},
	}
	if err := s.UpsertUsage(ctx, rows); err != nil {
		t.Fatal(err)
	}
	rows[1].ActiveBytes = 125 // la journée est recalculée par Wasabi : remplacée
	if err := s.UpsertUsage(ctx, rows[1:]); err != nil {
		t.Fatal(err)
	}
	if d, _ := s.LastUsageDay(ctx, "acme-srv01"); d != "2026-10-25" {
		t.Fatalf("dernier jour %q", d)
	}
	got, err := s.UsageRange(ctx, "acme-srv01", "2026-10-01", "2026-10-31")
	if err != nil || len(got) != 2 || got[1].ActiveBytes != 125 {
		t.Fatalf("usage : %+v %v", got, err)
	}
	if err := s.UpsertUsage(ctx, []Usage{{Bucket: "inconnu", Day: "2026-10-25"}}); err == nil {
		t.Fatal("usage d'un bucket non importé accepté")
	}
}

func TestSettings(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	if v, _ := s.Setting(ctx, "price_per_tb", "6.99"); v != "6.99" {
		t.Fatalf("défaut : %q", v)
	}
	s.SetSetting(ctx, "price_per_tb", "7.50")
	s.SetSetting(ctx, "price_per_tb", "8")
	if v, _ := s.Setting(ctx, "price_per_tb", "6.99"); v != "8" {
		t.Fatalf("réglage : %q", v)
	}
	_ = time.Now
}

func TestAccessKeys(t *testing.T) {
	st := open(t)
	ctx := context.Background()
	st.EnsureClient(ctx, Client{Code: "acme", Name: "Acme"})
	st.ImportBucket(ctx, Bucket{Name: "acme-srv01", Region: "eu-central-1", ClientCode: "acme"})
	if err := st.AddKey(ctx, AccessKey{ID: "AKID1", UserName: "kura-acme-srv01", Bucket: "acme-srv01", CredentialName: "wasabi"}); err != nil {
		t.Fatal(err)
	}
	if err := st.AddKey(ctx, AccessKey{ID: "AKID2", UserName: "kura-acme-srv01", Bucket: "inconnu", CredentialName: "wasabi"}); err == nil {
		t.Fatal("clé d'un bucket inconnu acceptée")
	}
	st.MarkKeyDownloaded(ctx, "AKID1")
	st.SetKeyStatus(ctx, "AKID1", KeyInstalled)
	st.SetKeyStatus(ctx, "AKID1", KeyDeactivated)
	k, err := st.Key(ctx, "AKID1")
	if err != nil || k.Status != KeyDeactivated || k.DownloadedAt.IsZero() || k.InstalledAt.IsZero() || k.DeactivatedAt.IsZero() {
		t.Fatalf("clé : %+v %v", k, err)
	}
	st.SetKeyStatus(ctx, "AKID1", KeyInstalled) // réactivée
	if k, _ = st.Key(ctx, "AKID1"); !k.DeactivatedAt.IsZero() {
		t.Fatal("date de désactivation conservée après réactivation")
	}
	if err := st.SetKeyStatus(ctx, "AKIDX", KeyInstalled); err != ErrNotFound {
		t.Fatalf("clé inconnue : %v", err)
	}
}

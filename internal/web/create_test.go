package web

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"testing"

	"github.com/E-C-G/kura-ctl/internal/store"
	"github.com/E-C-G/kura-ctl/internal/wasabi"
)

func init() { createRetryDelays = nil }

func createForm(hn *harness, tok string, v map[string]string) url.Values {
	hn.t.Helper()
	m := onceRe.FindStringSubmatch(hn.do("GET", "/buckets", nil, nil).Body.String())
	if m == nil {
		hn.t.Fatal("formulaire de création sans jeton")
	}
	f := url.Values{"csrf": {tok}, "once": {m[1]}, "client_code": {"acme"}, "client_name": {"Acme"}, "poste": {"Portable 01"}, "region": {"eu-central-2"}}
	for k, x := range v {
		f.Set(k, x)
	}
	return f
}

func TestCreateBucket(t *testing.T) {
	hn, tok := adminHarness(t, nil)
	ctx := context.Background()
	body := hn.do("GET", "/buckets", nil, nil).Body.String()
	if !strings.Contains(body, "Créer le bucket") || !strings.Contains(body, `value="eu-central-2"`) {
		t.Fatalf("formulaire de création absent :\n%s", body)
	}
	expectRedirect(t, hn.do("POST", "/buckets/creer", createForm(hn, tok, nil), nil), "/buckets/kura-acme-portable-01")
	acc := hn.last()
	got := strings.Join(acc.writes, " ; ")
	for _, w := range []string{"create kura-acme-portable-01 eu-central-2", "retention kura-acme-portable-01", "lifecycle kura-acme-portable-01", "policy kura-acme-portable-01"} {
		if !strings.Contains(got, w) {
			t.Errorf("écriture manquante %q : %s", w, got)
		}
	}
	if !acc.users["kura-kura-acme-portable-01"] || !strings.Contains(acc.policies["kura-kura-acme-portable-01/"+PosteUserPolicy], "kura-acme-portable-01/*") {
		t.Fatalf("utilisateur du poste : %v %v", acc.users, acc.policies)
	}
	b, err := hn.st.Bucket(ctx, "kura-acme-portable-01")
	if err != nil || b.Region != "eu-central-2" || b.ClientCode != "acme" || b.Poste != "Portable 01" || b.AuditedAt.IsZero() {
		t.Fatalf("bucket suivi : %+v %v", b, err)
	}
	// Relecture : conforme au modèle, stratégie nommant l'utilisateur du poste.
	if devs := bucketDeviations(b); len(devs) != 0 {
		t.Fatalf("écarts après création : %+v", devs)
	}
	page := hn.do("GET", "/buckets/kura-acme-portable-01", nil, nil).Body.String()
	if !strings.Contains(page, "relecture conforme") {
		t.Fatalf("message de fin :\n%s", page)
	}
	if !strings.Contains(hn.do("GET", "/audit", nil, nil).Body.String(), "création du bucket") {
		t.Fatal("journal d'audit")
	}
	// Jeton de formulaire usé : pas de seconde création.
	f := createForm(hn, tok, map[string]string{"bucket": "kura-acme-autre"})
	hn.do("POST", "/buckets/creer", f, nil)
	n := len(acc.created)
	hn.do("POST", "/buckets/creer", f, nil)
	if len(acc.created) != n {
		t.Fatal("formulaire rejoué")
	}
}

func TestCreateBucketRefusals(t *testing.T) {
	hn, tok := adminHarness(t, nil)
	for name, v := range map[string]map[string]string{
		"code client":  {"client_code": "ACME!"},
		"poste vide":   {"poste": ""},
		"région":       {"region": "mars-1"},
		"nom invalide": {"bucket": "Kura_X"},
		"nom réservé":  {"bucket": "ctl-acme"},
		"déjà suivi":   {"bucket": "acme-srv01"},
	} {
		hn.do("POST", "/buckets/creer", createForm(hn, tok, v), nil)
		if c := hn.last().created; len(c) != 0 {
			t.Fatalf("%s : bucket créé %+v", name, c)
		}
	}
	// Nom déjà pris chez Wasabi : refus clair, rien d'importé.
	hn.last().failOn = map[string]error{"create": errors.New("kura-acme-x : " + wasabi.ErrBucketTaken.Error())}
	rec := hn.do("POST", "/buckets/creer", createForm(hn, tok, map[string]string{"bucket": "kura-acme-x"}), nil)
	expectRedirect(t, rec, "/buckets")
	if _, err := hn.st.Bucket(context.Background(), "kura-acme-x"); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("bucket non créé importé")
	}
	if !strings.Contains(hn.do("GET", "/buckets", nil, nil).Body.String(), "déjà pris") {
		t.Fatal("message du nom pris")
	}
}

// Un réglage qui échoue après la création : bucket suivi, échec signalé, écart visible.
func TestCreateBucketPartialFailure(t *testing.T) {
	hn, tok := adminHarness(t, func(a *fakeAccount) { a.failOn = map[string]error{"retention": errors.New("InvalidBucketState")} })
	expectRedirect(t, hn.do("POST", "/buckets/creer", createForm(hn, tok, map[string]string{"bucket": "kura-acme-p2"}), nil), "/buckets/kura-acme-p2")
	page := hn.do("GET", "/buckets/kura-acme-p2", nil, nil).Body.String()
	if !strings.Contains(page, "rétention par défaut : InvalidBucketState") || !strings.Contains(page, "Sécuriser le bucket") {
		t.Fatalf("échec partiel non signalé :\n%s", page)
	}
	b, _ := hn.st.Bucket(context.Background(), "kura-acme-p2")
	found := false
	for _, d := range bucketDeviations(b) {
		found = found || d.Code == "object-lock-retention"
	}
	if !found {
		t.Fatalf("écart de rétention absent : %+v", bucketDeviations(b))
	}
}

func TestSuggestBucketName(t *testing.T) {
	for in, want := range map[[2]string]string{
		{"acme", "Portable 01"}: "kura-acme-portable-01", {"acme", "SRV01"}: "kura-acme-srv01", {"acme", "  "}: "kura-acme", {"acme", "Poste_É"}: "kura-acme-poste",
	} {
		if got := suggestBucketName(in[0], in[1]); got != want {
			t.Errorf("%v : %s", in, got)
		}
	}
}

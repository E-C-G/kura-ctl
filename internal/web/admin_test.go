package web

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/E-C-G/kura-agent/pkg/pack"
	"github.com/E-C-G/kura-ctl/internal/store"
	"github.com/E-C-G/kura-ctl/internal/wasabi"
)

// adminHarness : console configurée, bucket acme-srv01 importé et relevé.
func adminHarness(t *testing.T, hook func(*fakeAccount)) (*harness, string) {
	t.Helper()
	hn := newHarness(t)
	hn.accHook = hook
	hn.do("POST", "/setup", setupForm("un mot de passe solide", "SECRET"), nil)
	tok := hn.csrf("/buckets")
	imp := url.Values{"csrf": {tok}, "bucket": {"acme-srv01"}, "client_code": {"acme"}, "client_name": {"Acme"}, "poste": {"SRV01"}}
	expectRedirect(t, hn.do("POST", "/buckets/import", imp, nil), "/buckets/acme-srv01")
	expectRedirect(t, hn.do("POST", "/buckets/acme-srv01/audit", url.Values{"csrf": {tok}}, nil), "/buckets/acme-srv01")
	return hn, tok
}

var (
	seenRe = regexp.MustCompile(`name="seen" value="([0-9a-f]+)"`)
	onceRe = regexp.MustCompile(`name="once" value="([0-9a-f]+)"`)
)

// fix : aperçu puis application d'une correction, comme dans le navigateur.
func (hn *harness) fix(tok, what string) *httptest.ResponseRecorder {
	hn.t.Helper()
	m := seenRe.FindStringSubmatch(hn.do("GET", "/buckets/acme-srv01/corriger/"+what, nil, nil).Body.String())
	if m == nil {
		hn.t.Fatalf("aperçu %s sans empreinte", what)
	}
	return hn.do("POST", "/buckets/acme-srv01/corriger/"+what, url.Values{"csrf": {tok}, "confirm": {"acme-srv01"}, "seen": {m[1]}}, nil)
}

func (hn *harness) once() string {
	hn.t.Helper()
	m := onceRe.FindStringSubmatch(hn.do("GET", "/buckets/acme-srv01", nil, nil).Body.String())
	if m == nil {
		hn.t.Fatal("formulaire de clé sans jeton")
	}
	return m[1]
}

func withObjectLock(a *fakeAccount) {
	a.settings["acme-srv01"] = wasabi.Settings{Versioning: "Enabled", ObjectLock: wasabi.ObjectLock{Enabled: true}}
}

func TestReadOnlyKeyCannotWrite(t *testing.T) {
	hn, tok := adminHarness(t, func(a *fakeAccount) { a.readOnly = true })
	if body := hn.do("GET", "/buckets/acme-srv01", nil, nil).Body.String(); !strings.Contains(body, "lecture seule") || strings.Contains(body, "Créer une clé") {
		t.Fatalf("clé en lecture seule : écritures proposées\n%s", body)
	}
	hn.do("POST", "/buckets/acme-srv01/corriger/strategie", url.Values{"csrf": {tok}, "confirm": {"acme-srv01"}}, nil)
	hn.do("POST", "/buckets/acme-srv01/cles", url.Values{"csrf": {tok}, "confirm": {"acme-srv01"}, "credential": {"wasabi"}}, nil)
	if w := hn.last().writes; len(w) != 0 || len(hn.last().users) != 0 {
		t.Fatalf("écritures avec une clé en lecture seule : %v %v", w, hn.last().users)
	}
}

func TestFixesPreviewConfirmApplyVerify(t *testing.T) {
	hn, tok := adminHarness(t, withObjectLock)
	rec := hn.do("GET", "/buckets/acme-srv01/corriger/strategie", nil, nil)
	body := rec.Body.String()
	if !strings.Contains(body, "Aucun utilisateur de poste") || strings.Contains(body, "kura-ctl-admin") || strings.Contains(body, ":root") {
		t.Fatalf("aperçu de la stratégie :\n%s", body)
	}
	// Sans le nom du bucket retapé : rien n'est écrit.
	seen := seenRe.FindStringSubmatch(body)[1]
	if rec := hn.do("POST", "/buckets/acme-srv01/corriger/strategie", url.Values{"csrf": {tok}, "confirm": {"acme"}, "seen": {seen}}, nil); !strings.Contains(rec.Body.String(), "retaper exactement") {
		t.Fatalf("confirmation manquante acceptée :\n%s", rec.Body.String())
	}
	// Réglage changé chez Wasabi depuis l'aperçu : refusé, l'aperçu à jour est montré.
	hn.last().edit("acme-srv01", func(s *wasabi.Settings) error {
		s.Policy = wasabi.Policy{Present: true, Document: `{"Statement":[{"Sid":"AccesPartenaire","Effect":"Allow"}]}`}
		return nil
	})
	rec = hn.do("POST", "/buckets/acme-srv01/corriger/strategie", url.Values{"csrf": {tok}, "confirm": {"acme-srv01"}, "seen": {seen}}, nil)
	if !strings.Contains(rec.Body.String(), "a changé chez Wasabi") || !strings.Contains(rec.Body.String(), "AccesPartenaire") {
		t.Fatalf("écriture sur un aperçu périmé :\n%s", rec.Body.String())
	}
	if len(hn.last().writes) != 0 {
		t.Fatal("écriture sans confirmation valable")
	}
	expectRedirect(t, hn.fix(tok, "strategie"), "/buckets/acme-srv01")
	if body := hn.do("GET", "/buckets/acme-srv01", nil, nil).Body.String(); !strings.Contains(body, "Seule la règle HTTPS est posée") {
		t.Fatalf("stratégie sans poste :\n%s", body)
	}
	for _, what := range []string{"cycle-de-vie", "retention"} {
		expectRedirect(t, hn.fix(tok, what), "/buckets/acme-srv01")
		if body := hn.do("GET", "/buckets/acme-srv01", nil, nil).Body.String(); !strings.Contains(body, "appliqué et vérifié par relecture") {
			t.Fatalf("%s : pas de vérification\n%s", what, body)
		}
	}
	// Clé du poste créée : la stratégie est à réappliquer pour la nommer.
	hn.createKey(tok)
	hn.do("POST", "/buckets/acme-srv01/audit", url.Values{"csrf": {tok}}, nil)
	b, _ := hn.st.Bucket(context.Background(), "acme-srv01")
	if !strings.Contains(b.DeviationsJSON, "strategie-versions") {
		t.Fatalf("écart attendu après création de la clé : %s", b.DeviationsJSON)
	}
	if body := hn.do("GET", "/buckets/acme-srv01/corriger/strategie", nil, nil).Body.String(); !strings.Contains(body, "arn:aws:iam::100000000042:user/kura-acme-srv01") {
		t.Fatalf("aperçu sans l'utilisateur du poste :\n%s", body)
	}
	expectRedirect(t, hn.fix(tok, "strategie"), "/buckets/acme-srv01")
	if body := hn.do("GET", "/buckets/acme-srv01", nil, nil).Body.String(); !strings.Contains(body, "appliqué et vérifié par relecture") {
		t.Fatalf("stratégie avec poste :\n%s", body)
	}
	b, _ = hn.st.Bucket(context.Background(), "acme-srv01")
	if strings.Contains(b.DeviationsJSON, "strategie") || strings.Contains(b.DeviationsJSON, "cycle-") || strings.Contains(b.DeviationsJSON, "object-lock") {
		t.Fatalf("écarts restants : %s", b.DeviationsJSON)
	}
	if w := strings.Join(hn.last().writes, ","); w != "policy acme-srv01,lifecycle acme-srv01,retention acme-srv01,policy acme-srv01" {
		t.Fatalf("écritures : %s", w)
	}
	log, _ := hn.st.AuditLog(context.Background(), 50)
	var seenLog int
	for _, e := range log {
		if (strings.HasSuffix(e.Action, "appliquée") || strings.HasSuffix(e.Action, "appliqué")) && strings.Contains(e.Detail, "avant :") {
			seenLog++
		}
	}
	if seenLog != 4 {
		t.Fatalf("journal : %d corrections consignées avec l'état précédent", seenLog)
	}
}

func TestRetentionBlockedWithoutObjectLock(t *testing.T) {
	hn, tok := adminHarness(t, nil)
	rec := hn.do("POST", "/buckets/acme-srv01/corriger/retention", url.Values{"csrf": {tok}, "confirm": {"acme-srv01"}}, nil)
	if !strings.Contains(rec.Body.String(), "ne s&#39;active qu&#39;à la création") || len(hn.last().writes) != 0 {
		t.Fatalf("rétention sans Object Lock :\n%s", rec.Body.String())
	}
}

var (
	passwordRe = regexp.MustCompile(`<strong class="password">([A-Z0-9-]+)</strong>`)
	packURLRe  = regexp.MustCompile(`href="(/buckets/acme-srv01/paquet/[0-9a-f]+)"`)
)

func (hn *harness) createKey(tok string) (pw, link string) {
	hn.t.Helper()
	rec := hn.do("POST", "/buckets/acme-srv01/cles", url.Values{"csrf": {tok}, "confirm": {"acme-srv01"}, "credential": {"wasabi"}, "once": {hn.once()}}, nil)
	pm, um := passwordRe.FindStringSubmatch(rec.Body.String()), packURLRe.FindStringSubmatch(rec.Body.String())
	if pm == nil || um == nil {
		hn.t.Fatalf("page du paquet :\n%s", rec.Body.String())
	}
	return pm[1], um[1]
}

func TestPosteKeyLifecycle(t *testing.T) {
	hn, tok := adminHarness(t, nil)
	ctx := context.Background()
	pw, link := hn.createKey(tok)
	acc := hn.last()
	if !acc.users["kura-acme-srv01"] || !strings.Contains(acc.policies["kura-acme-srv01/"+PosteUserPolicy], `"arn:aws:s3:::acme-srv01/*"`) {
		t.Fatalf("utilisateur ou stratégie du poste : %v %v", acc.users, acc.policies)
	}
	rec := hn.do("GET", link, nil, nil)
	if rec.Code != 200 || !strings.Contains(rec.Header().Get("Content-Disposition"), "acme-srv01-") {
		t.Fatalf("téléchargement : %d %v", rec.Code, rec.Header())
	}
	c, err := pack.Open(rec.Body.Bytes(), strings.ToLower(pw))
	if err != nil || c.Bucket != "acme-srv01" || c.Host != "SRV01" || c.Credentials[0].SecretAccessKey != "secret-poste-0001" ||
		c.Credentials[0].Name != "wasabi" || !c.ExpiresAt.After(c.CreatedAt.Add(71*time.Hour)) {
		t.Fatalf("paquet : %+v %v", c, err)
	}
	if rec := hn.do("GET", link, nil, nil); rec.Code != http.StatusGone {
		t.Fatalf("second téléchargement : %d", rec.Code)
	}
	if strings.Contains(hn.do("GET", "/audit", nil, nil).Body.String(), "secret-poste") {
		t.Fatal("secret dans le journal")
	}
	k1, _ := hn.st.Key(ctx, "AKIDPOSTE0001")
	if k1.Status != store.KeyIssued || k1.DownloadedAt.IsZero() {
		t.Fatalf("clé 1 : %+v", k1)
	}

	// Rotation : nouvelle clé (paquet de la première perdu), installée sur le poste.
	hn.createKey(tok)
	inst := func(id string, extra ...string) *httptest.ResponseRecorder {
		f := url.Values{"csrf": {tok}, "confirm": {"acme-srv01"}}
		for _, e := range extra {
			f.Set(e, "on")
		}
		return hn.do("POST", "/buckets/acme-srv01/cles/"+id+"/installee", f, nil)
	}
	// Sans le nom du bucket : rien.
	hn.do("POST", "/buckets/acme-srv01/cles/AKIDPOSTE0002/installee", url.Values{"csrf": {tok}}, nil)
	// Clé qui n'a jamais servi : rien n'est désactivé.
	rec = inst("AKIDPOSTE0002")
	if k, _ := hn.st.Key(ctx, "AKIDPOSTE0002"); k.Status != store.KeyIssued {
		t.Fatalf("installation confirmée sans preuve : %+v", k)
	}
	if body := hn.do("GET", "/buckets/acme-srv01", nil, nil).Body.String(); rec.Code != http.StatusSeeOther || !strings.Contains(body, "vérifié sur le poste") {
		t.Fatalf("message sans la case à cocher :\n%s", body)
	}
	acc.used["AKIDPOSTE0002"] = time.Now()
	// Confirmer la plus ancienne (jamais servie) ne désactive jamais la plus récente.
	inst("AKIDPOSTE0001")
	live, _ := acc.ListAccessKeys(ctx, "kura-acme-srv01")
	if !live[1].Active {
		t.Fatal("clé la plus récente désactivée")
	}
	expectRedirect(t, inst("AKIDPOSTE0002"), "/buckets/acme-srv01")
	k1, _ = hn.st.Key(ctx, "AKIDPOSTE0001")
	k2, _ := hn.st.Key(ctx, "AKIDPOSTE0002")
	live, _ = acc.ListAccessKeys(ctx, "kura-acme-srv01")
	if k1.Status != store.KeyDeactivated || k2.Status != store.KeyInstalled || live[0].Active || !live[1].Active {
		t.Fatalf("rotation : %+v %+v %+v", k1, k2, live)
	}
	// Deux clés chez Wasabi : une troisième est refusée.
	hn.do("POST", "/buckets/acme-srv01/cles", url.Values{"csrf": {tok}, "confirm": {"acme-srv01"}, "credential": {"wasabi"}, "once": {hn.once()}}, nil)
	if body := hn.do("GET", "/buckets/acme-srv01", nil, nil).Body.String(); !strings.Contains(body, "déjà deux clés") {
		t.Fatalf("troisième clé :\n%s", body)
	}
	// Suppression : seulement 7 jours après la désactivation.
	del := url.Values{"csrf": {tok}, "confirm": {"acme-srv01"}}
	hn.do("POST", "/buckets/acme-srv01/cles/AKIDPOSTE0001/supprimer", del, nil)
	if k1, _ = hn.st.Key(ctx, "AKIDPOSTE0001"); k1.Status != store.KeyDeactivated {
		t.Fatal("clé supprimée avant 7 jours")
	}
	hn.advance(KeyGrace + time.Hour) // la session a expiré entre-temps
	expectRedirect(t, hn.do("POST", "/unlock", url.Values{"password": {"un mot de passe solide"}}, nil), "/")
	tok = hn.csrf("/buckets/acme-srv01")
	del.Set("csrf", tok)
	expectRedirect(t, hn.do("POST", "/buckets/acme-srv01/cles/AKIDPOSTE0001/supprimer", del, nil), "/buckets/acme-srv01")
	if k1, _ = hn.st.Key(ctx, "AKIDPOSTE0001"); k1.Status != store.KeyDeleted {
		t.Fatalf("suppression : %+v", k1)
	}
}

func TestAdminKeyChange(t *testing.T) {
	hn, tok := adminHarness(t, func(a *fakeAccount) { a.readOnly = a.keys.AccessKeyID == "AKIDADMIN" })
	if !strings.Contains(hn.do("GET", "/settings", nil, nil).Body.String(), `arn:aws:iam::*:user/kura-ctl*`) {
		t.Fatal("stratégie kura-ctl-admin absente des réglages")
	}
	form := url.Values{"csrf": {tok}, "current": {"un mot de passe solide"}, "access_key_id": {"AKIDNEWADMIN"}, "secret_access_key": {"NEWSECRET"}}
	hn.accHook = func(a *fakeAccount) { a.root = true }
	if body := hn.do("POST", "/settings/admin-key", form, nil).Body.String(); !strings.Contains(body, "compte racine") {
		t.Fatalf("clé racine acceptée :\n%s", body)
	}
	hn.accHook = nil
	expectRedirect(t, hn.do("POST", "/settings/admin-key", form, nil), "/settings")
	if body := hn.do("GET", "/settings", nil, nil).Body.String(); !strings.Contains(body, "écritures possibles") || !strings.Contains(body, "kura-ctl-admin") {
		t.Fatalf("après changement :\n%s", body)
	}
	if k, err := hn.srv.Vault.Unlock("un mot de passe solide"); err != nil || k.AccessKeyID != "AKIDNEWADMIN" {
		t.Fatalf("coffre : %+v %v", k, err)
	}
}

// Wasabi ne dit pas si la clé a servi : confirmation possible seulement en cochant
// « vérifié sur le poste ».
// Wasabi n'indique pas encore d'utilisation (date mise à jour avec retard) : la case
// « vérifié sur le poste » suffit.
func TestInstallConfirmVerifiedBeforeWasabi(t *testing.T) {
	hn, tok := adminHarness(t, nil)
	hn.createKey(tok)
	f := url.Values{"csrf": {tok}, "confirm": {"acme-srv01"}, "verifie": {"on"}}
	hn.do("POST", "/buckets/acme-srv01/cles/AKIDPOSTE0001/installee", f, nil)
	if k, _ := hn.st.Key(context.Background(), "AKIDPOSTE0001"); k.Status != store.KeyInstalled {
		t.Fatalf("confirmation vérifiée refusée : %+v", k)
	}
	if !strings.Contains(hn.do("GET", "/audit", nil, nil).Body.String(), "pas encore d&#39;utilisation") {
		t.Fatal("audit sans la nature de la preuve")
	}
}

func TestInstallConfirmWithoutLastUsed(t *testing.T) {
	hn, tok := adminHarness(t, func(a *fakeAccount) { a.usedErr = errors.New("NotImplemented") })
	hn.createKey(tok)
	f := url.Values{"csrf": {tok}, "confirm": {"acme-srv01"}}
	hn.do("POST", "/buckets/acme-srv01/cles/AKIDPOSTE0001/installee", f, nil)
	if k, _ := hn.st.Key(context.Background(), "AKIDPOSTE0001"); k.Status != store.KeyIssued {
		t.Fatal("confirmée sans vérification")
	}
	f.Set("verifie", "on")
	hn.do("POST", "/buckets/acme-srv01/cles/AKIDPOSTE0001/installee", f, nil)
	if k, _ := hn.st.Key(context.Background(), "AKIDPOSTE0001"); k.Status != store.KeyInstalled {
		t.Fatalf("confirmation vérifiée refusée : %+v", k)
	}
}

// Double soumission, nom de secret refusé par le coffre de l'agent, utilisateur
// existant qui sert à autre chose : aucune clé créée.
func TestCreateKeyGuards(t *testing.T) {
	hn, tok := adminHarness(t, nil)
	once := hn.once()
	form := url.Values{"csrf": {tok}, "confirm": {"acme-srv01"}, "credential": {"wasabi"}, "once": {once}}
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); hn.do("POST", "/buckets/acme-srv01/cles", form, nil) }()
	}
	wg.Wait()
	if keys, _ := hn.st.Keys(context.Background(), "acme-srv01"); len(keys) != 1 {
		t.Fatalf("double soumission : %d clés", len(keys))
	}
	hn.do("POST", "/buckets/acme-srv01/cles", form, nil) // jeton déjà consommé
	if keys, _ := hn.st.Keys(context.Background(), "acme-srv01"); len(keys) != 1 {
		t.Fatalf("jeton réutilisé : %d clés", len(keys))
	}
	for _, name := range []string{"Wasabi.Acme", "wasabi_acme"} {
		hn.do("POST", "/buckets/acme-srv01/cles", url.Values{"csrf": {tok}, "confirm": {"acme-srv01"}, "credential": {name}, "once": {hn.once()}}, nil)
	}
	hn.last().other["kura-acme-srv01"] = "AdministratorAccess"
	hn.do("POST", "/buckets/acme-srv01/cles", url.Values{"csrf": {tok}, "confirm": {"acme-srv01"}, "credential": {"wasabi"}, "once": {hn.once()}}, nil)
	if keys, _ := hn.st.Keys(context.Background(), "acme-srv01"); len(keys) != 1 || hn.last().n != 1 {
		t.Fatalf("clés créées malgré les refus : %d en base, %d chez Wasabi", len(keys), hn.last().n)
	}
}

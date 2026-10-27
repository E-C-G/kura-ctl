package web

// Lot 2 : écritures chez Wasabi. Chaque action montre d'abord ce qui sera écrit,
// exige de retaper le nom du bucket, écrit, relit chez Wasabi et consigne le
// résultat dans le journal d'audit.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/E-C-G/kura-agent/pkg/pack"
	"github.com/E-C-G/kura-ctl/internal/poste"
	"github.com/E-C-G/kura-ctl/internal/secrets"
	"github.com/E-C-G/kura-ctl/internal/store"
	"github.com/E-C-G/kura-ctl/internal/wasabi"
)

// Délais du paquet : téléchargeable 30 min dans la console, ouvrable 72 h sur le poste.
const (
	packDownloadFor = 30 * time.Minute
	packValidFor    = 72 * time.Hour
	// KeyGrace : délai entre la désactivation d'une clé et sa suppression possible.
	KeyGrace = 7 * 24 * time.Hour
	// PosteUserPolicy : nom de la stratégie en ligne des utilisateurs de poste.
	PosteUserPolicy = wasabi.PosteUserPolicy
)

// adminState dit si la clé de la console permet les écritures du lot 2.
type adminState struct {
	OK       bool
	Identity wasabi.Identity
	Reason   string // pourquoi les écritures sont indisponibles
}

func (s *Server) adminState(ctx context.Context, o *unlocked) adminState {
	if o == nil {
		return adminState{Reason: "console verrouillée"}
	}
	id, err := o.identity(ctx)
	switch {
	case err != nil:
		return adminState{Reason: "la clé de la console ne peut pas lire son identité IAM (clé en lecture seule ?) : " +
			"installer la clé kura-ctl-admin dans Réglages pour corriger les buckets et créer les clés des postes"}
	case id.Root():
		return adminState{Identity: id, Reason: "la console utilise la clé du compte racine : la remplacer par la clé kura-ctl-admin (Réglages)"}
	}
	return adminState{OK: true, Identity: id}
}

// --- aperçu et application des corrections ----------------------------------------

type fixView struct {
	Bucket   store.Bucket
	What     string
	Title    string
	Current  string
	Proposed string
	Notes    []string
	Blocked  string // correction impossible (et pourquoi)
	Seen     string // empreinte de l'état montré : l'écriture est refusée s'il a changé
	field    string // réglage relu après l'écriture (policy, lifecycle, object_lock)
	users    []string
}

func pretty(doc string) string {
	var b bytes.Buffer
	if json.Indent(&b, []byte(doc), "", "  ") == nil {
		return b.String()
	}
	return doc
}

func lifecycleLines(l wasabi.Lifecycle) string {
	if !l.Present {
		return "(aucune règle)"
	}
	var out []string
	if l.NoncurrentDays > 0 {
		out = append(out, fmt.Sprintf("anciennes versions supprimées après %d jours", l.NoncurrentDays))
	} else {
		out = append(out, "anciennes versions jamais supprimées")
	}
	if l.ExpiresCurrentDays != 0 {
		out = append(out, "VERSIONS COURANTES EXPIRÉES")
	}
	if l.ExpiredDeleteMarker {
		out = append(out, "marqueurs de suppression orphelins supprimés")
	}
	if l.AbortMultipartDays > 0 {
		out = append(out, fmt.Sprintf("envois interrompus abandonnés après %d jours", l.AbortMultipartDays))
	}
	for _, r := range l.PartialRules {
		out = append(out, "règle "+r)
	}
	return strings.Join(out, "\n")
}

func templateLifecycle(t wasabi.Template) string {
	return lifecycleLines(wasabi.Lifecycle{Present: true, NoncurrentDays: t.NoncurrentDays,
		ExpiredDeleteMarker: t.ExpiredDeleteMarker, AbortMultipartDays: t.AbortMultipartDays})
}

var modeFR = map[string]string{"GOVERNANCE": "gouvernance", "COMPLIANCE": "conformité"}

// posteUsers : utilisateurs des postes de ce bucket, créés par la console.
func (s *Server) posteUsers(ctx context.Context, bucket string) ([]string, error) {
	keys, err := s.Store.Keys(ctx, bucket)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var users []string
	for _, k := range keys {
		if k.Status != store.KeyDeleted && !seen[k.UserName] {
			seen[k.UserName] = true
			users = append(users, k.UserName)
		}
	}
	return users, nil
}

func fingerprint(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:8])
}

func retentionText(o wasabi.ObjectLock) string {
	if !o.Enabled {
		return "Object Lock désactivé"
	}
	if o.Mode == "" {
		return "aucune rétention par défaut : rien n'est verrouillé"
	}
	return fmt.Sprintf("%s, %d jours", modeFR[o.Mode], o.Days)
}

// fixFor prépare l'aperçu d'une correction, d'après les réglages relus chez Wasabi à
// l'instant (pas le dernier relevé : quelqu'un a pu les changer depuis).
// err : correction inconnue.
func (s *Server) fixFor(ctx context.Context, o *unlocked, b store.Bucket, what string) (fixView, error) {
	v := fixView{Bucket: b, What: what}
	if _, ok := fixedCodes[what]; !ok {
		return v, errors.New("correction inconnue")
	}
	if o == nil {
		v.Blocked = "console verrouillée"
		return v, nil
	}
	lctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	st := o.account.ReadSettings(lctx, b.Name, b.Region)
	cancel()
	t := wasabi.Standard
	switch what {
	case "strategie":
		v.Title = "Stratégie de bucket"
		v.field = "policy"
		v.Current = "(aucune)"
		if st.Policy.Document != "" {
			v.Current = pretty(st.Policy.Document)
		}
		if _, unread := st.ReadErrors["policy"]; unread {
			v.Blocked = "stratégie actuelle illisible : impossible de montrer ce qui serait remplacé"
		}
		adm := s.adminState(ctx, o)
		if !adm.OK {
			v.Blocked = adm.Reason
			break
		}
		users, err := s.posteUsers(ctx, b.Name)
		if err != nil {
			v.Blocked = err.Error()
			break
		}
		v.users = users
		doc, err := wasabi.BucketPolicy(t, b.Name, adm.Identity.AccountID, users)
		if err != nil {
			v.Blocked = err.Error()
			break
		}
		v.Proposed = doc
		v.Notes = []string{
			"La stratégie actuelle est remplacée en entier : vérifier qu'elle ne contient rien d'autre à garder (elle est conservée dans le journal d'audit).",
			"Refus du HTTP non chiffré, pour tous.",
		}
		if len(users) == 0 {
			v.Notes = append(v.Notes, "Aucun utilisateur de poste créé par la console pour ce bucket : seule la règle HTTPS est posée. "+
				"Créer la clé du poste (page du bucket), puis réappliquer la stratégie pour refuser la suppression de versions à son utilisateur.")
		} else {
			v.Notes = append(v.Notes, "Refusé à "+strings.Join(users, ", ")+" : "+strings.Join(wasabi.ProtectedActions, ", ")+".")
		}
		v.Notes = append(v.Notes,
			"Ni la console ni le compte racine ne sont visés : la stratégie ne peut pas les enfermer hors du bucket.",
			"Une clé de poste créée à la main dans Wasabi n'est pas concernée : la remplacer par une clé créée ici.")
	case "cycle-de-vie":
		v.Title = "Cycle de vie"
		v.field = "lifecycle"
		v.Current = lifecycleLines(st.Lifecycle)
		v.Proposed = templateLifecycle(t)
		if _, unread := st.ReadErrors["lifecycle"]; unread {
			v.Blocked = "cycle de vie actuel illisible : impossible de montrer ce qui serait remplacé"
		}
		v.Notes = []string{"Les règles actuelles sont remplacées par celles du modèle ; les versions courantes ne sont jamais expirées."}
		if len(st.Lifecycle.PartialRules) > 0 {
			v.Notes = append(v.Notes, "Règles actuelles supprimées : "+strings.Join(st.Lifecycle.PartialRules, ", ")+".")
		}
	case "retention":
		v.Title = "Rétention par défaut (Object Lock)"
		v.field = "object_lock"
		v.Current = retentionText(st.ObjectLock)
		v.Proposed = fmt.Sprintf("%s, %d jours", modeFR[t.ObjectLockMode], t.ObjectLockDays)
		if _, unread := st.ReadErrors["object_lock"]; unread {
			v.Blocked = "Object Lock illisible : impossible de montrer ce qui serait remplacé"
		} else if !st.ObjectLock.Enabled {
			v.Blocked = "Object Lock n'est pas activé sur ce bucket : il ne s'active qu'à la création (bucket neuf, lot 4)"
		}
		v.Notes = []string{"S'applique aux objets envoyés ensuite ; les objets déjà présents restent sans verrou."}
		if t.ObjectLockMode == "COMPLIANCE" {
			v.Notes = append(v.Notes, "Mode conformité : personne, pas même le compte racine, ne pourra effacer une version avant la fin de sa rétention. Irréversible pour chaque objet envoyé.")
		} else {
			v.Notes = append(v.Notes, "Mode gouvernance : une clé de poste ne peut pas effacer une version verrouillée ; "+
				"un utilisateur qui a le droit s3:BypassGovernanceRetention (le compte racine, un administrateur) le peut.")
		}
	}
	v.Seen = fingerprint(v.Current + "\x00" + v.Proposed)
	return v, nil
}

func (s *Server) fixPreview(w http.ResponseWriter, r *http.Request) {
	b, err := s.Store.Bucket(r.Context(), r.PathValue("name"))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	v, err := s.fixFor(r.Context(), s.current(), b, r.PathValue("what"))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	s.render(w, r, "fix", view{Title: v.Title + " · " + b.Name, Nav: "buckets", Data: v})
}

// fixedCodes : écarts que chaque correction doit faire disparaître.
var fixedCodes = map[string][]string{
	"strategie":    {"strategie", "strategie-versions", "strategie-https", "strategie-postes"},
	"cycle-de-vie": {"cycle-versions", "cycle-versions-duree", "cycle-marqueurs", "cycle-multipart", "cycle-partiel", "cycle-courantes"},
	"retention":    {"object-lock-retention"},
}

func confirmed(r *http.Request, b store.Bucket) bool {
	return strings.TrimSpace(r.PostFormValue("confirm")) == b.Name
}

func (s *Server) fixApply(w http.ResponseWriter, r *http.Request) {
	o := s.current()
	if o == nil {
		redirect(w, r, "/unlock")
		return
	}
	b, err := s.Store.Bucket(r.Context(), r.PathValue("name"))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	what := r.PathValue("what")
	v, err := s.fixFor(r.Context(), o, b, what)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	again := func(msg string) {
		s.render(w, r, "fix", view{Title: v.Title + " · " + b.Name, Nav: "buckets", Error: msg, Data: v})
	}
	if v.Blocked != "" {
		again(v.Blocked)
		return
	}
	if !confirmed(r, b) {
		again("Pour confirmer, retaper exactement le nom du bucket.")
		return
	}
	if r.PostFormValue("seen") != v.Seen {
		again("Le réglage a changé chez Wasabi depuis l'aperçu : vérifier l'aperçu ci-dessus, à jour, puis confirmer à nouveau.")
		return
	}
	ctx, cancel := context.WithTimeout(o.ctx, time.Minute)
	defer cancel()
	t := wasabi.Standard
	var action string
	switch what {
	case "strategie":
		action = "stratégie de bucket appliquée"
		err = o.account.PutBucketPolicy(ctx, b.Name, b.Region, v.Proposed)
	case "cycle-de-vie":
		action = "cycle de vie appliqué"
		err = o.account.PutLifecycle(ctx, b.Name, b.Region, t)
	case "retention":
		action = "rétention par défaut appliquée"
		err = o.account.PutDefaultRetention(ctx, b.Name, b.Region, t.ObjectLockMode, t.ObjectLockDays)
	}
	before := "avant : " + strings.Join(strings.Fields(v.Current), " ")
	if err != nil {
		_ = s.Store.Audit(r.Context(), action, b.Name, store.ResultError, err.Error()+" ; "+before)
		again("Wasabi a refusé : " + err.Error())
		return
	}
	// Relecture : la correction n'est réussie que si Wasabi montre le nouveau réglage.
	note := ""
	if err := o.runner.AuditBucket(ctx, b.Name, b.Region); err != nil {
		note = "relecture incomplète (" + err.Error() + ")"
	}
	after, _ := s.Store.Bucket(r.Context(), b.Name)
	var st wasabi.Settings
	_ = json.Unmarshal([]byte(after.SettingsJSON), &st)
	if _, unread := st.ReadErrors[v.field]; unread && note == "" {
		note = "réglage illisible à la relecture"
	}
	var devs []wasabi.Deviation
	_ = json.Unmarshal([]byte(after.DeviationsJSON), &devs)
	var left []string
	for _, d := range devs {
		// Sans utilisateur de poste, la stratégie ne peut pas encore refuser la
		// suppression de versions : écart attendu, expliqué dans l'aperçu.
		if what == "strategie" && len(v.users) == 0 && d.Code == "strategie-versions" {
			continue
		}
		for _, c := range fixedCodes[what] {
			if d.Code == c {
				left = append(left, d.Message)
			}
		}
	}
	switch {
	case note != "":
		_ = s.Store.Audit(r.Context(), action, b.Name, store.ResultError, "écrit, non vérifié : "+note+" ; "+before)
		s.flash(r, "Écrit chez Wasabi, mais non vérifié : "+note+". Cliquer sur « Relever les réglages » pour contrôler.")
	case len(left) > 0:
		_ = s.Store.Audit(r.Context(), action, b.Name, store.ResultError, "écrit, mais la relecture montre encore : "+strings.Join(left, " ; ")+" ; "+before)
		s.flash(r, "Écrit chez Wasabi, mais la relecture montre encore : "+strings.Join(left, " ; "))
	default:
		_ = s.Store.Audit(r.Context(), action, b.Name, store.ResultOK, "modèle "+t.Name+", vérifié par relecture ; "+before)
		msg := v.Title + " : appliqué et vérifié par relecture."
		if what == "strategie" && len(v.users) == 0 {
			msg += " Seule la règle HTTPS est posée : réappliquer après la création de la clé du poste."
		}
		s.flash(r, msg)
	}
	redirect(w, r, "/buckets/"+b.Name)
}

// --- clés des postes ---------------------------------------------------------------

// credNamePattern : le motif des noms de secret du coffre de l'agent
// (kura-agent pkg/pack.CredentialName) ; un nom refusé à l'import laisserait chez
// Wasabi une clé active sans usage.
var credNamePattern = regexp.MustCompile(`^[a-z0-9-]{1,40}$`)

type keyView struct {
	store.AccessKey
	Live      string // état chez Wasabi : active, inactive, absente, ou erreur
	LastUsed  time.Time
	CanDelete bool
	DeleteOn  time.Time
}

type keysView struct {
	Admin    adminState
	UserName string
	Keys     []keyView
	Error    string
	Once     string // jeton à usage unique du formulaire de création de clé
}

func (s *Server) keysFor(ctx context.Context, o *unlocked, b store.Bucket) keysView {
	kv := keysView{Admin: s.adminState(ctx, o)}
	kv.UserName, _ = wasabi.UserNameFor(b.Name)
	if o != nil {
		kv.Once = o.newOnce()
	}
	rows, err := s.Store.Keys(ctx, b.Name)
	if err != nil {
		kv.Error = err.Error()
		return kv
	}
	live := map[string]map[string]bool{} // utilisateur → clé → active
	for _, k := range rows {
		view := keyView{AccessKey: k}
		if k.Status == store.KeyDeactivated {
			view.DeleteOn = k.DeactivatedAt.Add(KeyGrace)
			view.CanDelete = !s.now().Before(view.DeleteOn)
		}
		if kv.Admin.OK && k.Status != store.KeyDeleted {
			if _, ok := live[k.UserName]; !ok {
				lctx, cancel := context.WithTimeout(ctx, 15*time.Second)
				keys, err := o.account.ListAccessKeys(lctx, k.UserName)
				cancel()
				m := map[string]bool{}
				if err != nil {
					kv.Error = err.Error()
				}
				for _, x := range keys {
					m[x.ID] = x.Active
				}
				live[k.UserName] = m
			}
			if active, ok := live[k.UserName][k.ID]; !ok {
				view.Live = "absente chez Wasabi"
			} else if active {
				view.Live = "active"
				lctx, cancel := context.WithTimeout(ctx, 10*time.Second)
				view.LastUsed, _ = o.account.AccessKeyLastUsed(lctx, k.ID)
				cancel()
			} else {
				view.Live = "inactive"
			}
		}
		kv.Keys = append(kv.Keys, view)
	}
	return kv
}

type packView struct {
	Bucket   store.Bucket
	KeyID    string
	UserName string
	CredName string
	Password string
	URL      string
	File     string
	Expires  time.Time
	Install  bool     // paquet d'installation complète
	KitURL   string   // kit zip (installation complète)
	Others   []string // autres secrets du paquet
	Platform store.Platform
	Linux    bool
}

func (s *Server) createKey(w http.ResponseWriter, r *http.Request) {
	o := s.current()
	if o == nil {
		redirect(w, r, "/unlock")
		return
	}
	ctx := r.Context()
	b, err := s.Store.Bucket(ctx, r.PathValue("name"))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	fail := func(msg string) {
		s.flash(r, msg)
		redirect(w, r, "/buckets/"+b.Name)
	}
	adm := s.adminState(ctx, o)
	credName := strings.TrimSpace(r.PostFormValue("credential"))
	switch {
	case !adm.OK:
		fail(adm.Reason)
		return
	case !confirmed(r, b):
		fail("Clé non créée : pour confirmer, retaper exactement le nom du bucket.")
		return
	}
	// Paquet d'installation complète : configuration enregistrée, revérifiée, et
	// secrets saisis maintenant (jamais conservés par la console). Tout est contrôlé
	// avant de créer la clé chez Wasabi : un refus ne laisse pas de clé orpheline.
	install := r.PostFormValue("paquet") == "installation"
	var cfgYAML string
	var others []pack.Credential
	if install {
		pc, err := s.Store.PosteConfig(ctx, b.Name)
		if err != nil {
			fail("Clé non créée : aucune configuration du poste enregistrée (« Préparer la configuration du poste »).")
			return
		}
		chk, err := poste.Check(pc.YAML, b)
		if err != nil {
			fail("Clé non créée : configuration du poste à corriger. " + err.Error())
			return
		}
		cfgYAML, credName = pc.YAML, chk.KeyName
		for _, sec := range chk.Secrets {
			v := strings.TrimSpace(r.PostFormValue("secret-" + sec.Name))
			if err := poste.CheckSecret(sec, v); err != nil {
				fail("Clé non créée : " + err.Error())
				return
			}
			others = append(others, pack.Credential{Name: sec.Name, Kind: "secret", Value: v})
		}
	}
	if !credNamePattern.MatchString(credName) {
		fail("Nom du secret sur le poste invalide (minuscules, chiffres et tirets, 40 caractères au plus).")
		return
	}
	// Une seule création à la fois par bucket, et un formulaire ne sert qu'une fois :
	// un double clic ne crée pas deux clés.
	lock := s.bucketLock(b.Name)
	if !lock.TryLock() {
		fail("Création de clé déjà en cours pour ce bucket.")
		return
	}
	defer lock.Unlock()
	if !o.useOnce(r.PostFormValue("once")) {
		fail("Formulaire déjà envoyé : aucune nouvelle clé créée. Recharger la page pour en créer une autre.")
		return
	}
	user, err := wasabi.UserNameFor(b.Name)
	if err != nil {
		fail(err.Error())
		return
	}
	wctx, cancel := context.WithTimeout(o.ctx, time.Minute)
	defer cancel()
	audit := func(result, detail string) { _ = s.Store.Audit(ctx, "clé de poste créée", b.Name, result, detail) }
	created, err := o.account.EnsureUser(wctx, user)
	if err == nil && !created {
		// Utilisateur déjà là : il ne doit servir qu'à ce bucket, sans autre droit.
		err = o.account.CheckPosteUser(wctx, user, b.Name)
	}
	if err == nil {
		err = o.account.PutUserPolicy(wctx, user, PosteUserPolicy, wasabi.PostePolicy(b.Name))
	}
	var existing []wasabi.AccessKey
	if err == nil {
		existing, err = o.account.ListAccessKeys(wctx, user)
	}
	if err == nil && len(existing) >= 2 {
		err = fmt.Errorf("%s a déjà deux clés (le maximum) : désactiver puis supprimer l'une d'elles", user)
	}
	var k wasabi.AccessKey
	if err == nil {
		k, err = o.account.CreateAccessKey(wctx, user)
	}
	if err != nil {
		audit(store.ResultError, "utilisateur "+user+" : "+err.Error())
		fail("Clé non créée : " + err.Error())
		return
	}
	if err := s.Store.AddKey(ctx, store.AccessKey{ID: k.ID, UserName: user, Bucket: b.Name, CredentialName: credName}); err != nil {
		audit(store.ResultError, "clé "+maskKey(k.ID)+" créée chez Wasabi mais non enregistrée : "+err.Error())
		fail("Clé créée chez Wasabi (" + k.ID + ") mais non enregistrée dans la console : la désactiver dans Wasabi. " + err.Error())
		return
	}
	pw, err := pack.NewPassword()
	var data []byte
	now := s.now()
	if err == nil {
		c := pack.Contents{Kind: pack.KindCredentials, CreatedAt: now, ExpiresAt: now.Add(packValidFor),
			Client: b.ClientCode, Host: b.Poste, Bucket: b.Name, Endpoint: wasabi.S3Endpoint(b.Region), Region: b.Region,
			Credentials: append([]pack.Credential{{Name: credName, Kind: "aws", AccessKeyID: k.ID, SecretAccessKey: k.Secret}}, others...)}
		if install {
			c.Kind, c.Config = pack.KindInstall, cfgYAML
		}
		data, err = pack.Seal(c, pw, 0)
	}
	if err != nil {
		audit(store.ResultError, "clé "+maskKey(k.ID)+" créée, paquet impossible : "+err.Error())
		fail("Clé créée mais paquet impossible : " + err.Error() + ". Désactiver la clé et recommencer.")
		return
	}
	detail := fmt.Sprintf("utilisateur %s, clé %s, paquet « clé seule » généré (secret %s)", user, maskKey(k.ID), credName)
	if install {
		names := []string{credName}
		for _, c := range others {
			names = append(names, c.Name)
		}
		detail = fmt.Sprintf("utilisateur %s, clé %s, paquet d'installation complète généré (secrets %s)", user, maskKey(k.ID), strings.Join(names, ", "))
	}
	if created {
		detail = "utilisateur " + user + " créé ; " + detail
	}
	audit(store.ResultOK, detail)
	token := randomToken()
	file := fmt.Sprintf("%s-%s.kura", b.Name, now.Format("20060102"))
	o.mu.Lock()
	o.packs[token] = &pendingPack{bucket: b.Name, keyID: k.ID, file: file, data: data, expires: now.Add(packDownloadFor),
		validUntil: now.Add(packValidFor), install: install, platform: b.Platform}
	o.mu.Unlock()
	pv := packView{Bucket: b, KeyID: k.ID, UserName: user, CredName: credName, Password: pw,
		URL: "/buckets/" + b.Name + "/paquet/" + token, File: file, Expires: now.Add(packValidFor), Install: install,
		Platform: platformOr(b), Linux: platformOr(b).Linux()}
	if install {
		pv.KitURL = "/buckets/" + b.Name + "/kit/" + token
		for _, c := range others {
			pv.Others = append(pv.Others, c.Name)
		}
	}
	s.render(w, r, "pack", view{Title: "Paquet de " + b.Name, Nav: "buckets", Data: pv})
}

func (s *Server) downloadPack(w http.ResponseWriter, r *http.Request) {
	o := s.current()
	if o == nil {
		redirect(w, r, "/unlock")
		return
	}
	token := r.PathValue("token")
	o.mu.Lock()
	p := o.packs[token]
	if p != nil && p.busy {
		o.mu.Unlock()
		http.Error(w, "kit en cours de préparation avec ce paquet", http.StatusConflict)
		return
	}
	delete(o.packs, token) // téléchargeable une seule fois
	o.mu.Unlock()
	if p == nil || p.bucket != r.PathValue("name") || s.now().After(p.expires) {
		http.Error(w, "paquet déjà téléchargé ou expiré : en générer un nouveau (et désactiver la clé de celui-ci)", http.StatusGone)
		return
	}
	if err := s.Store.MarkKeyDownloaded(r.Context(), p.keyID); err != nil {
		_ = s.Store.Audit(r.Context(), "paquet téléchargé", p.bucket, store.ResultError, "clé "+maskKey(p.keyID)+", état non enregistré : "+err.Error())
	} else {
		_ = s.Store.Audit(r.Context(), "paquet téléchargé", p.bucket, store.ResultOK, "clé "+maskKey(p.keyID))
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", `attachment; filename="`+p.file+`"`)
	_, _ = w.Write(p.data)
}

func (s *Server) keyAction(w http.ResponseWriter, r *http.Request) {
	o := s.current()
	if o == nil {
		redirect(w, r, "/unlock")
		return
	}
	ctx := r.Context()
	b, err := s.Store.Bucket(ctx, r.PathValue("name"))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	k, err := s.Store.Key(ctx, r.PathValue("id"))
	if err != nil || k.Bucket != b.Name {
		http.NotFound(w, r)
		return
	}
	done := func(msg string) {
		s.flash(r, msg)
		redirect(w, r, "/buckets/"+b.Name)
	}
	if adm := s.adminState(ctx, o); !adm.OK {
		done(adm.Reason)
		return
	}
	action := r.PathValue("action")
	if !confirmed(r, b) {
		done("Rien n'a été fait : pour confirmer, retaper exactement le nom du bucket.")
		return
	}
	wctx, cancel := context.WithTimeout(o.ctx, time.Minute)
	defer cancel()
	audit := func(what, result, detail string) {
		_ = s.Store.Audit(ctx, what, b.Name, result, "clé "+maskKey(k.ID)+" ("+k.UserName+")"+detail)
	}
	switch action {
	case "installee":
		if k.Status != store.KeyIssued {
			done("Cette clé n'est pas en attente de confirmation.")
			return
		}
		// Preuve que le poste s'en sert : Wasabi a vu la clé travailler. Sans elle,
		// désactiver les autres clés arrêterait la sauvegarde.
		lastUsed, err := o.account.AccessKeyLastUsed(wctx, k.ID)
		switch {
		case err != nil && r.PostFormValue("verifie") != "on":
			done("Wasabi ne dit pas si la clé a servi (" + err.Error() + ") : vérifier sur le poste qu'une sauvegarde a réussi avec elle, puis cocher « vérifié sur le poste » et confirmer.")
			return
		case err == nil && lastUsed.IsZero():
			done("Cette clé n'a encore jamais servi : lancer une sauvegarde sur le poste (" + runNowHint(b.Platform) + "), puis confirmer. Rien n'a été désactivé.")
			return
		}
		if err := s.Store.SetKeyStatus(ctx, k.ID, store.KeyInstalled); err != nil {
			done("Installation non enregistrée : " + err.Error())
			return
		}
		proof := "utilisée chez Wasabi le " + dateTimeFR(lastUsed)
		if lastUsed.IsZero() {
			proof = "sauvegarde vérifiée sur le poste (utilisation non disponible chez Wasabi)"
		}
		audit("installation de la clé confirmée", store.ResultOK, " : "+proof)
		// Les clés créées avant elle sont désactivées ; jamais une clé plus récente
		// (un paquet généré après celui-ci, peut-être déjà installé).
		var off, failed []string
		others, _ := s.Store.Keys(ctx, b.Name) // les plus récentes d'abord
		older := false
		for _, x := range others {
			if x.ID == k.ID {
				older = true
				continue
			}
			if !older || (x.Status != store.KeyIssued && x.Status != store.KeyInstalled) {
				continue
			}
			if err := o.account.SetAccessKeyActive(wctx, x.UserName, x.ID, false); err != nil {
				failed = append(failed, maskKey(x.ID)+" : "+err.Error())
				_ = s.Store.Audit(ctx, "clé désactivée", b.Name, store.ResultError, "clé "+maskKey(x.ID)+" : "+err.Error())
				continue
			}
			if err := s.Store.SetKeyStatus(ctx, x.ID, store.KeyDeactivated); err != nil {
				failed = append(failed, maskKey(x.ID)+" désactivée chez Wasabi, état non enregistré : "+err.Error())
			}
			_ = s.Store.Audit(ctx, "clé désactivée", b.Name, store.ResultOK, "clé "+maskKey(x.ID)+" remplacée par "+maskKey(k.ID))
			off = append(off, maskKey(x.ID))
		}
		msg := "Installation confirmée."
		if len(off) > 0 {
			msg += " Ancienne(s) clé(s) désactivée(s) : " + strings.Join(off, ", ") + " (supprimables dans 7 jours)."
		}
		if len(failed) > 0 {
			msg += " Échec de désactivation : " + strings.Join(failed, " ; ") + "."
		}
		msg += " Si le poste utilisait auparavant une clé créée à la main dans Wasabi, la désactiver dans la console Wasabi (Users → l'utilisateur → Access Keys)."
		done(msg)
	case "desactiver", "reactiver":
		active := action == "reactiver"
		if (active && k.Status != store.KeyDeactivated) || (!active && k.Status != store.KeyIssued && k.Status != store.KeyInstalled) {
			done("Action impossible dans l'état actuel de la clé.")
			return
		}
		what := map[bool]string{true: "clé réactivée", false: "clé désactivée"}[active]
		if err := o.account.SetAccessKeyActive(wctx, k.UserName, k.ID, active); err != nil {
			audit(what, store.ResultError, " : "+err.Error())
			done("Wasabi a refusé : " + err.Error())
			return
		}
		st := store.KeyDeactivated
		if active {
			st = store.KeyIssued
			if !k.InstalledAt.IsZero() {
				st = store.KeyInstalled
			}
		}
		if err := s.Store.SetKeyStatus(ctx, k.ID, st); err != nil {
			audit(what, store.ResultError, " : fait chez Wasabi, état non enregistré : "+err.Error())
			done("Fait chez Wasabi, mais l'état n'a pas été enregistré dans la console : " + err.Error())
			return
		}
		audit(what, store.ResultOK, "")
		if active {
			done("Clé réactivée.")
		} else {
			done("Clé désactivée : le poste qui l'utilise ne peut plus sauvegarder avec elle. Réactivable pendant 7 jours, supprimable ensuite.")
		}
	case "supprimer":
		if k.Status != store.KeyDeactivated || s.now().Before(k.DeactivatedAt.Add(KeyGrace)) {
			done("Une clé n'est supprimable que 7 jours après sa désactivation.")
			return
		}
		if err := o.account.DeleteAccessKey(wctx, k.UserName, k.ID); err != nil {
			audit("clé supprimée", store.ResultError, " : "+err.Error())
			done("Wasabi a refusé : " + err.Error())
			return
		}
		if err := s.Store.SetKeyStatus(ctx, k.ID, store.KeyDeleted); err != nil {
			audit("clé supprimée", store.ResultError, " : supprimée chez Wasabi, état non enregistré : "+err.Error())
			done("Supprimée chez Wasabi, mais l'état n'a pas été enregistré dans la console : " + err.Error())
			return
		}
		audit("clé supprimée", store.ResultOK, "")
		done("Clé supprimée.")
	default:
		http.NotFound(w, r)
	}
}

// --- clé d'administration -------------------------------------------------------------

type adminSettings struct {
	Admin  adminState
	Policy string
}

func (s *Server) adminSettings(ctx context.Context) adminSettings {
	return adminSettings{Admin: s.adminState(ctx, s.current()), Policy: wasabi.AdminPolicy()}
}

func (s *Server) adminKeySubmit(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	again := func(msg string) {
		s.render(w, r, "settings", view{Title: "Réglages", Nav: "settings", Error: msg, Data: s.settingsData(ctx)})
	}
	k := secrets.Keys{AccessKeyID: trim(r, "access_key_id"), SecretAccessKey: trim(r, "secret_access_key")}
	if err := k.Valid(); err != nil {
		again(err.Error())
		return
	}
	pw := r.PostFormValue("current")
	if _, err := s.tryPassword(pw); err != nil {
		_ = s.Store.Audit(ctx, "changement de la clé d'administration", "console", store.ResultError, "mot de passe maître incorrect")
		again("Mot de passe maître incorrect.")
		return
	}
	acc := s.NewAccount(wasabi.Keys{AccessKeyID: k.AccessKeyID, SecretAccessKey: k.SecretAccessKey})
	vctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if _, err := acc.ListBuckets(vctx); err != nil {
		again("Wasabi refuse cette clé : " + err.Error())
		return
	}
	note := "Clé d'administration remplacée."
	id, err := acc.Identity(vctx)
	switch {
	case err == nil && id.Root():
		again("C'est la clé du compte racine : la console ne doit jamais la détenir. Créer l'utilisateur kura-ctl-admin.")
		return
	case err != nil:
		note += " Elle ne lit pas son identité IAM : écritures du lot 2 indisponibles avec cette clé."
	default:
		note += " Utilisateur " + id.UserName + "."
	}
	if err := s.Vault.Store(pw, k); err != nil {
		again(err.Error())
		return
	}
	_ = s.Store.Audit(ctx, "changement de la clé d'administration", "console", store.ResultOK, "nouvelle clé "+maskKey(k.AccessKeyID))
	s.startSession(w, k, note)
	redirect(w, r, "/settings")
}

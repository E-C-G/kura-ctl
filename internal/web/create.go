package web

// Lot 4 : création d'un bucket depuis le modèle « sauvegarde standard » : Object Lock
// et versioning à la création, rétention par défaut, cycle de vie, utilisateur du
// poste et stratégie de bucket, puis relecture des réglages et import.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/E-C-G/kura-ctl/internal/store"
	"github.com/E-C-G/kura-ctl/internal/wasabi"
)

// createRetryDelays : attentes entre les essais d'un réglage juste après la création
// (un bucket neuf peut ne pas être encore visible de tous les serveurs de Wasabi).
var createRetryDelays = []time.Duration{time.Second, 2 * time.Second, 4 * time.Second}

var slugInvalid = regexp.MustCompile(`[^a-z0-9]+`)

// suggestBucketName : kura-<client>-<poste>, en minuscules.
func suggestBucketName(client, poste string) string {
	p := strings.Trim(slugInvalid.ReplaceAllString(strings.ToLower(poste), "-"), "-")
	if p == "" {
		return "kura-" + client
	}
	return "kura-" + client + "-" + p
}

func retrying(ctx context.Context, fn func() error) error {
	err := fn()
	for _, d := range createRetryDelays {
		if err == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return err
		case <-time.After(d):
		}
		err = fn()
	}
	return err
}

func (s *Server) createBucket(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	o := s.current()
	if o == nil {
		redirect(w, r, "/unlock")
		return
	}
	back := func(msg string) {
		s.flash(r, msg)
		redirect(w, r, "/buckets")
	}
	client := strings.ToLower(trim(r, "client_code"))
	clientName, poste, region := trim(r, "client_name"), trim(r, "poste"), trim(r, "region")
	name := strings.ToLower(trim(r, "bucket"))
	switch {
	case !codePattern.MatchString(client):
		back("Bucket non créé : code client invalide (minuscules, chiffres et tirets, 20 caractères au plus).")
		return
	case poste == "":
		back("Bucket non créé : nom du poste manquant.")
		return
	case !wasabi.KnownRegion(region):
		back("Bucket non créé : région inconnue.")
		return
	}
	if name == "" {
		name = suggestBucketName(client, poste)
	}
	if err := wasabi.CheckNewBucketName(name); err != nil {
		back("Bucket non créé : " + err.Error())
		return
	}
	if _, err := s.Store.Bucket(ctx, name); err == nil {
		back("Bucket non créé : " + name + " est déjà suivi par la console.")
		return
	}
	adm := s.adminState(ctx, o)
	if !adm.OK {
		back("Bucket non créé : " + adm.Reason)
		return
	}
	user, err := wasabi.UserNameFor(name)
	if err != nil {
		back("Bucket non créé : " + err.Error())
		return
	}
	// Un formulaire ne sert qu'une fois : un double clic ne lance pas deux créations.
	if !o.useOnce(r.PostFormValue("once")) {
		back("Formulaire déjà envoyé : rien n'a été créé de nouveau. Recharger la page pour créer un autre bucket.")
		return
	}
	if clientName == "" {
		clientName = client
	}
	wctx, cancel := context.WithTimeout(o.ctx, 2*time.Minute)
	defer cancel()
	t := wasabi.Standard
	audit := func(what, result, detail string) { _ = s.Store.Audit(ctx, what, name, result, detail) }

	if err := o.account.CreateBucket(wctx, name, region); err != nil {
		audit("création du bucket", store.ResultError, err.Error())
		back("Bucket non créé : " + err.Error())
		return
	}
	audit("création du bucket", store.ResultOK, fmt.Sprintf("région %s, Object Lock et versioning, client %s, poste %s", region, client, poste))

	// Suivi tout de suite : même si un réglage échoue ensuite, le bucket est visible
	// dans la console, avec ses écarts, et se corrige depuis sa page.
	if err := s.Store.EnsureClient(ctx, store.Client{Code: client, Name: clientName}); err == nil {
		err = s.Store.ImportBucket(ctx, store.Bucket{Name: name, Region: region, ClientCode: client, Poste: poste})
	}
	if err != nil {
		audit("import du bucket", store.ResultError, err.Error())
		back("Bucket " + name + " créé chez Wasabi mais non enregistré dans la console (" + err.Error() + ") : l'importer depuis cette page.")
		return
	}
	audit("import du bucket", store.ResultOK, fmt.Sprintf("client %s, région %s (créé par la console)", client, region))

	steps := []struct {
		what string
		run  func() error
	}{
		{"rétention par défaut", func() error {
			return o.account.PutDefaultRetention(wctx, name, region, t.ObjectLockMode, t.ObjectLockDays)
		}},
		{"cycle de vie", func() error { return o.account.PutLifecycle(wctx, name, region, t) }},
		{"utilisateur du poste", func() error {
			created, err := o.account.EnsureUser(wctx, user)
			if err == nil && !created {
				err = o.account.CheckPosteUser(wctx, user, name)
			}
			if err == nil {
				err = o.account.PutUserPolicy(wctx, user, PosteUserPolicy, wasabi.PostePolicy(name))
			}
			return err
		}},
		{"stratégie de bucket", func() error {
			doc, err := wasabi.BucketPolicy(t, name, adm.Identity.AccountID, []string{user})
			if err != nil {
				return err
			}
			return o.account.PutBucketPolicy(wctx, name, region, doc)
		}},
	}
	var failed []string
	for _, st := range steps {
		if err := retrying(wctx, st.run); err != nil {
			audit(st.what+" (création)", store.ResultError, err.Error())
			failed = append(failed, st.what+" : "+err.Error())
			// La stratégie nomme l'utilisateur du poste : sans lui, elle attend.
			if st.what == "utilisateur du poste" {
				failed = append(failed, "stratégie de bucket : non posée (utilisateur du poste absent)")
				break
			}
			continue
		}
		audit(st.what+" (création)", store.ResultOK, "modèle "+t.Name)
	}

	// Relecture : les écarts au modèle sont ceux du bucket tel que Wasabi le décrit.
	_ = o.runner.AuditBucket(wctx, name, region)
	go func() { _, _ = o.runner.CollectBucket(o.ctx, name) }()
	deviations := 0
	if b, err := s.Store.Bucket(ctx, name); err == nil {
		deviations = len(bucketDeviations(b))
	}
	switch {
	case len(failed) > 0:
		s.flash(r, fmt.Sprintf("Bucket %s créé (%s, Object Lock), mais : %s. Corriger depuis « Sécuriser le bucket » ci-dessous.",
			name, region, strings.Join(failed, " ; ")))
	case deviations > 0:
		s.flash(r, fmt.Sprintf("Bucket %s créé (%s, Object Lock) ; la relecture trouve %d écart(s) au modèle : voir ci-dessous.", name, region, deviations))
	default:
		s.flash(r, fmt.Sprintf("Bucket %s créé (%s) avec Object Lock, rétention, cycle de vie et stratégie du modèle ; relecture conforme. Étape suivante : préparer la configuration du poste.", name, region))
	}
	redirect(w, r, "/buckets/"+name)
}

// bucketDeviations : écarts au modèle du dernier relevé enregistré.
func bucketDeviations(b store.Bucket) []wasabi.Deviation {
	var devs []wasabi.Deviation
	_ = json.Unmarshal([]byte(b.DeviationsJSON), &devs)
	return devs
}

package web

// Lot 3 : configuration du poste préparée dans la console, paquet d'installation
// complète et kit zip (kura-agent, CLI AWS, paquet).

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/E-C-G/kura-ctl/internal/kit"
	"github.com/E-C-G/kura-ctl/internal/poste"
	"github.com/E-C-G/kura-ctl/internal/store"
)

// KitSource fournit les composants du kit d'installation (kit.Source en production).
type KitSource interface {
	Prepare(ctx context.Context) (kit.Components, error)
}

// posteView : état de la configuration du poste, sur la page du bucket.
type posteView struct {
	Saved     bool
	UpdatedAt time.Time
	Err       string // configuration enregistrée mais refusée par les règles actuelles
	Checked   poste.Checked
}

func (s *Server) posteFor(ctx context.Context, b store.Bucket) posteView {
	pc, err := s.Store.PosteConfig(ctx, b.Name)
	if errors.Is(err, store.ErrNotFound) {
		return posteView{}
	}
	if err != nil {
		return posteView{Err: err.Error()}
	}
	v := posteView{Saved: true, UpdatedAt: pc.UpdatedAt}
	if v.Checked, err = poste.Check(pc.YAML, b); err != nil {
		v.Err = err.Error()
	}
	return v
}

type posteEdit struct {
	Bucket    store.Bucket
	YAML      string
	Saved     bool
	UpdatedAt time.Time
	Err       string
	Checked   poste.Checked
}

func (s *Server) postePage(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	b, err := s.Store.Bucket(ctx, r.PathValue("name"))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	d := posteEdit{Bucket: b}
	pc, err := s.Store.PosteConfig(ctx, b.Name)
	switch {
	case err == nil:
		d.YAML, d.Saved, d.UpdatedAt = pc.YAML, true, pc.UpdatedAt
		if d.Checked, err = poste.Check(pc.YAML, b); err != nil {
			d.Err = err.Error()
		}
	case errors.Is(err, store.ErrNotFound):
		d.YAML = poste.Template(b)
	default:
		s.fail(w, r, err)
		return
	}
	s.render(w, r, "poste", view{Title: "Configuration du poste · " + b.Name, Nav: "buckets", Data: d})
}

func (s *Server) posteSubmit(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	b, err := s.Store.Bucket(ctx, r.PathValue("name"))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	text := strings.ReplaceAll(r.PostFormValue("yaml"), "\r\n", "\n")
	d := posteEdit{Bucket: b, YAML: text}
	if old, err := s.Store.PosteConfig(ctx, b.Name); err == nil {
		d.Saved, d.UpdatedAt = true, old.UpdatedAt
	}
	if d.Checked, err = poste.Check(text, b); err != nil {
		// Rien n'est enregistré : la page réaffiche le texte saisi avec l'erreur (en
		// 200 : htmx n'affiche pas une réponse 4xx).
		d.Err = err.Error()
		s.render(w, r, "poste", view{Title: "Configuration du poste · " + b.Name, Nav: "buckets", Data: d})
		return
	}
	if err := s.Store.SavePosteConfig(ctx, b.Name, text); err != nil {
		s.fail(w, r, err)
		return
	}
	detail := fmt.Sprintf("%d job(s), secret de la clé %s", len(d.Checked.Config.Jobs), d.Checked.KeyName)
	if n := len(d.Checked.Secrets); n > 0 {
		names := make([]string, n)
		for i, sec := range d.Checked.Secrets {
			names[i] = sec.Name
		}
		detail += ", autres secrets : " + strings.Join(names, ", ")
	}
	_ = s.Store.Audit(ctx, "configuration du poste enregistrée", b.Name, store.ResultOK, detail)
	s.flash(r, "Configuration du poste enregistrée. Le paquet d'installation complète se crée dans « Clés du poste ».")
	redirect(w, r, "/buckets/"+b.Name)
}

// kitReadme : LISEZMOI.txt du kit.
func kitReadme(b store.Bucket, p *pendingPack, c kit.Components, now time.Time) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "Kit d'installation Kura : poste %s, bucket %s (client %s)\n", orDash(b.Poste), b.Name, b.ClientCode)
	fmt.Fprintf(&sb, "Préparé par kura-ctl le %s. Paquet ouvrable jusqu'au %s.\n\n", dateTimeFR(now), dateTimeFR(p.validUntil))
	sb.WriteString("Contenu\n")
	fmt.Fprintf(&sb, "  kura-agent.exe, kura-agentw.exe  kura-agent %s\n", c.AgentVersion)
	fmt.Fprintf(&sb, "                                   SHA-256 de kura-agent.exe : %s\n", c.AgentSHA256)
	fmt.Fprintf(&sb, "  %s                     CLI AWS v2, installée seulement si elle manque\n", kit.MSIName)
	fmt.Fprintf(&sb, "                                   SHA-256 : %s\n", c.MSISHA256)
	fmt.Fprintf(&sb, "  %-33s configuration du poste et secrets, chiffrés\n\n", p.file)
	sb.WriteString("Installation\n")
	sb.WriteString("  1. Décompresser ce dossier sur le poste.\n")
	sb.WriteString("  2. Ouvrir une invite de commandes « Exécuter en tant qu'administrateur », puis :\n")
	fmt.Fprintf(&sb, "       cd <dossier du kit>\n       kura-agent.exe install --package %s\n", p.file)
	sb.WriteString("  3. Saisir le mot de passe du paquet, affiché une seule fois par la console\n")
	sb.WriteString("     (il ne voyage jamais avec ce kit).\n")
	sb.WriteString("     install vérifie la signature Amazon du MSI avant d'installer la CLI AWS,\n")
	sb.WriteString("     range les secrets dans le coffre, vérifie l'accès au bucket, crée la tâche\n")
	sb.WriteString("     planifiée et supprime le paquet.\n")
	sb.WriteString("  4. Lancer une sauvegarde (icône Kura > Sauvegarder maintenant, ou\n")
	sb.WriteString("     schtasks /Run /TN \\Kura\\Sync), vérifier qu'elle réussit, puis confirmer\n")
	sb.WriteString("     l'installation de la clé sur la page du bucket dans la console.\n\n")
	sb.WriteString("Après l'installation, supprimer ce dossier : le paquet contenait la clé du poste.\n")
	return sb.String()
}

func orDash(s string) string {
	if s == "" {
		return "—"
	}
	return s
}

func (s *Server) downloadKit(w http.ResponseWriter, r *http.Request) {
	o := s.current()
	if o == nil {
		redirect(w, r, "/unlock")
		return
	}
	token := r.PathValue("token")
	o.mu.Lock()
	p := o.packs[token]
	if p == nil || !p.install || p.busy || p.bucket != r.PathValue("name") || s.now().After(p.expires) {
		busy := p != nil && p.busy
		o.mu.Unlock()
		if busy {
			http.Error(w, "kit en cours de préparation", http.StatusConflict)
			return
		}
		http.Error(w, "paquet déjà téléchargé ou expiré : en générer un nouveau (et désactiver la clé de celui-ci)", http.StatusGone)
		return
	}
	p.busy = true
	o.mu.Unlock()
	release := func(consumed bool) {
		o.mu.Lock()
		if consumed {
			delete(o.packs, token)
		} else {
			p.busy = false
		}
		o.mu.Unlock()
	}
	ctx := r.Context()
	b, err := s.Store.Bucket(ctx, p.bucket)
	if err != nil || s.Kit == nil {
		release(false)
		http.Error(w, "kit indisponible", http.StatusInternalServerError)
		return
	}
	pctx, cancel := context.WithTimeout(ctx, 15*time.Minute)
	defer cancel()
	c, err := s.Kit.Prepare(pctx)
	if err != nil {
		// Le paquet n'est pas consommé : le .kura seul reste téléchargeable.
		release(false)
		_ = s.Store.Audit(ctx, "kit d'installation", p.bucket, store.ResultError, err.Error())
		http.Error(w, "Kit impossible à préparer : "+err.Error()+
			"\nLe paquet .kura reste téléchargeable seul depuis la page précédente (la CLI AWS sera alors téléchargée par le poste).", http.StatusBadGateway)
		return
	}
	release(true)
	if err := s.Store.MarkKeyDownloaded(ctx, p.keyID); err != nil {
		_ = s.Store.Audit(ctx, "paquet téléchargé", p.bucket, store.ResultError, "clé "+maskKey(p.keyID)+", état non enregistré : "+err.Error())
	}
	now := s.now()
	_ = s.Store.Audit(ctx, "kit d'installation téléchargé", p.bucket, store.ResultOK,
		fmt.Sprintf("clé %s, kura-agent %s, CLI AWS %s", maskKey(p.keyID), c.AgentVersion, c.MSISHA256[:12]))
	folder := "kura-" + b.Name
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", `attachment; filename="`+folder+"-"+now.Format("20060102")+`.zip"`)
	if err := kit.Write(w, kit.Kit{Folder: folder, PackName: p.file, Pack: p.data, Readme: kitReadme(b, p, c, now),
		Components: c, GeneratedAt: now}); err != nil {
		s.Log.Error("kit", "bucket", b.Name, "err", err)
	}
}

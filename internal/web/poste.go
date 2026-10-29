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
	// Prepare renvoie les composants ; release, appelé une fois le kit écrit, libère
	// les fichiers du cache.
	Prepare(ctx context.Context, t kit.Target) (c kit.Components, release func(), err error)
}

// kitTarget : cible du kit pour le système du poste.
func kitTarget(p store.Platform) kit.Target {
	if p == "" {
		return kit.Windows
	}
	return kit.Target{OS: p.OS(), Arch: p.Arch()}
}

// runNowHint : comment lancer une sauvegarde tout de suite sur le poste.
func runNowHint(p store.Platform) string {
	if p.Linux() {
		return "sudo systemctl start --no-block kura-sync.service"
	}
	return "icône Kura → Sauvegarder maintenant"
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
	Platform  store.Platform   // système choisi dans le formulaire
	Platforms []store.Platform // choix possibles
	Template  bool             // modèle de départ affiché à la place de la configuration enregistrée
}

func (s *Server) postePage(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	b, err := s.Store.Bucket(ctx, r.PathValue("name"))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	d := posteEdit{Bucket: b, Platform: platformOr(b), Platforms: store.Platforms}
	// ?systeme=… : modèle de départ pour ce système (rien n'est enregistré).
	if q := store.Platform(r.URL.Query().Get("systeme")); q.Valid() {
		d.Platform, d.Template = q, true
	}
	pc, err := s.Store.PosteConfig(ctx, b.Name)
	switch {
	case err == nil:
		d.Saved, d.UpdatedAt = true, pc.UpdatedAt
		if !d.Template {
			d.YAML = pc.YAML
			if d.Checked, err = poste.Check(pc.YAML, b); err != nil {
				d.Err = err.Error()
			}
		}
	case errors.Is(err, store.ErrNotFound):
		d.Template = true
	default:
		s.fail(w, r, err)
		return
	}
	if d.Template {
		d.YAML = poste.TemplateFor(b, d.Platform)
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
	platform := store.Platform(r.PostFormValue("platform"))
	if platform == "" {
		platform = platformOr(b)
	}
	d := posteEdit{Bucket: b, YAML: text, Platform: platform, Platforms: store.Platforms}
	if old, err := s.Store.PosteConfig(ctx, b.Name); err == nil {
		d.Saved, d.UpdatedAt = true, old.UpdatedAt
	}
	if d.Checked, err = poste.CheckFor(text, b, platform); err != nil {
		// Rien n'est enregistré : la page réaffiche le texte saisi avec l'erreur (en
		// 200 : htmx n'affiche pas une réponse 4xx).
		d.Err = err.Error()
		s.render(w, r, "poste", view{Title: "Configuration du poste · " + b.Name, Nav: "buckets", Data: d})
		return
	}
	if err := s.Store.SavePosteConfig(ctx, b.Name, platform, text); err != nil {
		s.fail(w, r, err)
		return
	}
	detail := fmt.Sprintf("%s, %d job(s), secret de la clé %s", platform.Label(), len(d.Checked.Config.Jobs), d.Checked.KeyName)
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
	fmt.Fprintf(&sb, "Kit d'installation Kura : poste %s, bucket %s (client %s), %s\n", orDash(b.Poste), b.Name, b.ClientCode, platformOr(store.Bucket{Platform: p.platform}).Label())
	fmt.Fprintf(&sb, "Préparé par kura-ctl le %s. Paquet ouvrable jusqu'au %s.\n\n", dateTimeFR(now), dateTimeFR(p.validUntil))
	sb.WriteString("Contenu\n")
	row := func(name, text string) { fmt.Fprintf(&sb, "  %-38s %s\n", name, text) }
	if c.Target.Linux() {
		row(c.AgentFile, "kura-agent "+c.AgentVersion+" (paquet Debian/Ubuntu)")
		row("", "SHA-256 : "+c.AgentSHA256)
		row(c.AWSFile+" (+ .sig)", "CLI AWS v2, installée seulement si elle manque")
		row("", "SHA-256 : "+c.AWSSHA256)
		row(p.file, "configuration du poste et secrets, chiffrés")
		sb.WriteString("\nInstallation\n")
		sb.WriteString("  1. Décompresser ce dossier sur le poste et ouvrir un terminal dedans.\n")
		sb.WriteString("  2. Installer kura-agent :\n")
		fmt.Fprintf(&sb, "       sudo apt install ./%s\n", c.AgentFile)
		sb.WriteString("  3. Installer le poste :\n")
		fmt.Fprintf(&sb, "       sudo kura-agent install --package %s\n", p.file)
		sb.WriteString("     Saisir le mot de passe du paquet, affiché une seule fois par la console\n")
		sb.WriteString("     (il ne voyage jamais avec ce kit).\n")
		sb.WriteString("     install vérifie la signature PGP d'AWS avant d'installer la CLI AWS, crée le\n")
		sb.WriteString("     compte kura-agent (lecture seule), range les secrets dans le coffre\n")
		sb.WriteString("     (systemd-creds), vérifie l'accès au bucket, crée le minuteur kura-sync.timer\n")
		sb.WriteString("     et supprime le paquet.\n")
		sb.WriteString("  4. Lancer une sauvegarde :\n")
		sb.WriteString("       sudo systemctl start --no-block kura-sync.service\n")
		sb.WriteString("     la suivre (journalctl -u kura-sync.service -f, ou kura-agent status), vérifier\n")
		sb.WriteString("     qu'elle réussit, puis confirmer l'installation de la clé sur la page du bucket\n")
		sb.WriteString("     dans la console.\n\n")
	} else {
		row("kura-agent.exe, kura-agentw.exe", "kura-agent "+c.AgentVersion)
		row("", "SHA-256 de kura-agent.exe : "+c.AgentSHA256)
		row(c.AWSFile, "CLI AWS v2, installée seulement si elle manque")
		row("", "SHA-256 : "+c.AWSSHA256)
		row(p.file, "configuration du poste et secrets, chiffrés")
		sb.WriteString("\nInstallation\n")
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
	}
	if c.NewerAgent != "" {
		fmt.Fprintf(&sb, "kura-agent %s est publié ; ce kit livre %s, dernière version de la série dont\nla console vérifie les configurations. Mettre à jour kura-ctl pour livrer la suivante.\n\n", c.NewerAgent, c.AgentVersion)
	}
	sb.WriteString("Après l'installation, supprimer ce dossier : le paquet contenait la clé du poste.\n")
	return sb.String()
}

// platformOr : système du poste, Windows si inconnu.
func platformOr(b store.Bucket) store.Platform {
	if b.Platform.Valid() {
		return b.Platform
	}
	return store.PlatformWindows
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
	c, done, err := s.Kit.Prepare(pctx, kitTarget(p.platform))
	if err != nil {
		// Le paquet n'est pas consommé : le .kura seul reste téléchargeable.
		release(false)
		_ = s.Store.Audit(ctx, "kit d'installation", p.bucket, store.ResultError, err.Error())
		http.Error(w, "Kit impossible à préparer : "+err.Error()+
			"\nLe paquet .kura reste téléchargeable seul depuis la page précédente (la CLI AWS sera alors téléchargée par le poste).", http.StatusBadGateway)
		return
	}
	defer done()
	now := s.now()
	folder := "kura-" + b.Name
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", `attachment; filename="`+folder+"-"+now.Format("20060102")+`.zip"`)
	if err := kit.Write(w, kit.Kit{Folder: folder, PackName: p.file, Pack: p.data, Readme: kitReadme(b, p, c, now),
		Components: c, GeneratedAt: now}); err != nil {
		// Envoi interrompu : le paquet reste téléchargeable.
		release(false)
		s.Log.Error("kit", "bucket", b.Name, "err", err)
		_ = s.Store.Audit(ctx, "kit d'installation", p.bucket, store.ResultError, "envoi interrompu : "+err.Error())
		return
	}
	// Envoyé en entier : le paquet est consommé.
	release(true)
	if err := s.Store.MarkKeyDownloaded(ctx, p.keyID); err != nil {
		_ = s.Store.Audit(ctx, "paquet téléchargé", p.bucket, store.ResultError, "clé "+maskKey(p.keyID)+", état non enregistré : "+err.Error())
	}
	_ = s.Store.Audit(ctx, "kit d'installation téléchargé", p.bucket, store.ResultOK,
		fmt.Sprintf("clé %s, %s, kura-agent %s, CLI AWS %s", maskKey(p.keyID), c.Target, c.AgentVersion, short(c.AWSSHA256)))
}

func short(h string) string {
	if len(h) > 12 {
		return h[:12]
	}
	return h
}

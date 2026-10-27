package poste

import (
	"strings"
	"testing"

	"github.com/E-C-G/kura-ctl/internal/store"
)

var bucket = store.Bucket{Name: "acme-srv01", Region: "eu-central-1", ClientCode: "acme", Poste: "SRV01"}

func TestTemplateIsValid(t *testing.T) {
	c, err := Check(Template(bucket), bucket)
	if err != nil {
		t.Fatal(err)
	}
	if c.KeyName != "wasabi" || len(c.Secrets) != 1 || c.Secrets[0].Name != "hc-url" || c.Secrets[0].Field != "notify.report.url" {
		t.Fatalf("%+v", c)
	}
	if c.Config.Profile.AWSCLI != "" {
		t.Fatal("aws_cli doit rester vide : kura-agent installe la CLI si besoin")
	}
}

func TestCheckRefusals(t *testing.T) {
	base := Template(bucket)
	cases := map[string][2]string{
		"bucket":       {"bucket: acme-srv01\n", "bucket: autre\n"},
		"endpoint":     {"endpoint: https://s3.eu-central-1.wasabisys.com", "endpoint: https://s3.us-west-1.wasabisys.com"},
		"region":       {"region: eu-central-1", "region: us-west-1"},
		"clé en clair": {"aws_credentials: credential:wasabi", "aws_credentials: AKID:secret"},
		"url en clair": {"url: credential:hc-url", "url: https://hc-ping.com/00000000-0000-0000-0000-000000000000"},
		"aws_profile":  {"  bucket: acme-srv01\n", "  bucket: acme-srv01\n  aws_profile: wasabi\n"},
		"nom invalide": {"url: credential:hc-url", "url: credential:HC_URL"},
		"même nom":     {"url: credential:hc-url", "url: credential:wasabi"},
		"syntaxe":      {"jobs:", "jobs: ["},
	}
	for name, c := range cases {
		text := strings.Replace(base, c[0], c[1], 1)
		if text == base {
			t.Fatalf("%s : remplacement sans effet", name)
		}
		if _, err := Check(text, bucket); err == nil {
			t.Errorf("%s : accepté", name)
		}
	}
	if _, err := Check("  ", bucket); err == nil {
		t.Error("vide accepté")
	}
}

func TestCheckWebhookToken(t *testing.T) {
	text := strings.Replace(Template(bucket), "    type: healthchecks\n    url: credential:hc-url       # URL de ping, saisie à la création du paquet\n",
		"    type: webhook\n    url: credential:hook-url\n    token: credential:hook-token\n", 1)
	c, err := Check(text, bucket)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Secrets) != 2 || c.Secrets[0].Name != "hook-url" || c.Secrets[1].Name != "hook-token" {
		t.Fatalf("%+v", c.Secrets)
	}
}

func TestCheckSecret(t *testing.T) {
	url := Secret{Name: "hc-url", Field: "notify.report.url"}
	if err := CheckSecret(url, "https://hc-ping.com/uuid"); err != nil {
		t.Fatal(err)
	}
	for _, v := range []string{"", "http://hc-ping.com/uuid", "hc-ping.com/uuid", "https://a\nb"} {
		if err := CheckSecret(url, v); err == nil {
			t.Errorf("%q accepté", v)
		}
	}
	if err := CheckSecret(Secret{Name: "tok", Field: "notify.report.token"}, "abc"); err != nil {
		t.Fatal(err)
	}
}

func linuxBucket(p store.Platform) store.Bucket {
	b := bucket
	b.Platform = p
	return b
}

func TestLinuxTemplate(t *testing.T) {
	for _, p := range []store.Platform{store.PlatformLinuxAMD64, store.PlatformLinuxARM64} {
		b := linuxBucket(p)
		text := Template(b)
		if text != TemplateFor(bucket, p) || !strings.Contains(text, "source: /home/") || strings.Contains(text, "toast_on") {
			t.Fatalf("%s : modèle Linux attendu :\n%s", p, text)
		}
		c, err := Check(text, b)
		if err != nil {
			t.Fatalf("%s : %v", p, err)
		}
		if c.KeyName != "wasabi" || len(c.Secrets) != 1 || c.Config.Profile.AWSCLI != "" {
			t.Fatalf("%+v", c)
		}
	}
}

func TestCheckPlatformPaths(t *testing.T) {
	linux := linuxBucket(store.PlatformLinuxAMD64)
	// Modèle d'un système vérifié pour l'autre : sources refusées.
	if _, err := Check(Template(bucket), linux); err == nil || !strings.Contains(err.Error(), "chemin Linux complet") {
		t.Fatalf("source Windows acceptée sous Linux : %v", err)
	}
	if _, err := Check(Template(linux), bucket); err == nil || !strings.Contains(err.Error(), "chemin Windows complet") {
		t.Fatalf("source Linux acceptée sous Windows : %v", err)
	}
	// ${PROFILE:compte} : dossier personnel du système du poste.
	text := strings.Replace(Template(linux), "source: /home/utilisateur/Documents", "source: ${PROFILE:alice}/Documents", 1)
	c, err := Check(text, linux)
	if err != nil || c.Config.Jobs[0].Source != "/home/alice/Documents" {
		t.Fatalf("%v %+v", err, c.Config)
	}
	if _, err := CheckFor(Template(bucket), bucket, "macos"); err == nil {
		t.Fatal("système inconnu accepté")
	}
}

func TestCheckLinuxRefusals(t *testing.T) {
	linux := linuxBucket(store.PlatformLinuxAMD64)
	base := Template(linux)
	cases := map[string][3]string{
		"aws_cli snap":    {"  bucket: acme-srv01\n", "  bucket: acme-srv01\n  aws_cli: /snap/bin/aws\n", "snap"},
		"aws_cli relatif": {"  bucket: acme-srv01\n", "  bucket: acme-srv01\n  aws_cli: aws\n", "aws_cli"},
		"pre_tasks":       {"jobs:\n", "pre_tasks:\n  - type: close_process\n    process: thunderbird\n    force: true\njobs:\n", "pre_tasks"},
		"post_tasks":      {"jobs:\n", "post_tasks:\n  - type: start_process\n    process: thunderbird\njobs:\n", "post_tasks"},
		"tray":            {"notify:\n", "tray:\n  users: [alice]\nnotify:\n", "tray"},
		"source Windows":  {"source: /home/utilisateur/Documents", `source: "C:/Users/alice"`, "chemin Linux"},
	}
	for name, c := range cases {
		text := strings.Replace(base, c[0], c[1], 1)
		if text == base {
			t.Fatalf("%s : remplacement sans effet", name)
		}
		if _, err := Check(text, linux); err == nil || !strings.Contains(err.Error(), c[2]) {
			t.Errorf("%s : %v", name, err)
		}
	}
	// aws_cli officiel accepté.
	text := strings.Replace(base, "  bucket: acme-srv01\n", "  bucket: acme-srv01\n  aws_cli: /usr/local/bin/aws\n", 1)
	if _, err := Check(text, linux); err != nil {
		t.Fatal(err)
	}
}

func TestWindowsAbs(t *testing.T) {
	for p, want := range map[string]bool{
		"D:/Donnees": true, `C:\Users\alice`: true, `\\nas\partage`: true, "//nas/partage": true,
		"/home/alice": false, "Donnees": false, "D:": false, "1:/x": false, "": false,
	} {
		if windowsAbs(p) != want {
			t.Errorf("%q : %v", p, !want)
		}
	}
}

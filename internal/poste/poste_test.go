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

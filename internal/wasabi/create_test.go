package wasabi

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCheckNewBucketName(t *testing.T) {
	for _, ok := range []string{"kura-acme-portable01", "abc", "a.b-c", strings.Repeat("a", 59)} {
		if err := CheckNewBucketName(ok); err != nil {
			t.Errorf("%q : %v", ok, err)
		}
	}
	for _, bad := range []string{"", "ab", "Kura", "-kura", "kura-", "a..b", "a_b", "192.168.1.10", "ctl-x", strings.Repeat("a", 60)} {
		if err := CheckNewBucketName(bad); err == nil {
			t.Errorf("%q accepté", bad)
		}
	}
}

func TestRegions(t *testing.T) {
	if !KnownRegion("eu-central-2") || !KnownRegion("us-east-1") || KnownRegion("eu-west-9") || KnownRegion("") {
		t.Fatal("régions")
	}
	if Regions[0].Place != "Paris" {
		t.Fatal("Paris en premier")
	}
	seen := map[string]bool{}
	for _, r := range Regions {
		if seen[r.Code] || r.Place == "" {
			t.Fatalf("région %+v", r)
		}
		seen[r.Code] = true
	}
}

// La requête de création demande Object Lock et la région ; le versioning est reposé.
func TestCreateBucketRequests(t *testing.T) {
	var got []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		got = append(got, r.Method+" "+r.URL.Path+"?"+r.URL.RawQuery+" lock="+r.Header.Get("X-Amz-Bucket-Object-Lock-Enabled")+" "+string(body))
		if r.URL.Path == "/pris" {
			w.WriteHeader(http.StatusConflict)
			io.WriteString(w, `<Error><Code>BucketAlreadyExists</Code><Message>pris</Message></Error>`)
			return
		}
		if r.URL.Path == "/refuse" {
			w.WriteHeader(http.StatusForbidden)
			io.WriteString(w, `<Error><Code>AccessDenied</Code><Message>non</Message></Error>`)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	c := NewClient(Keys{AccessKeyID: "AK", SecretAccessKey: "SK"})
	c.endpoint = func(string) string { return srv.URL }
	if err := c.CreateBucket(context.Background(), "kura-acme-portable01", "eu-central-2"); err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || !strings.HasPrefix(got[0], "PUT /kura-acme-portable01? lock=true") || !strings.Contains(got[0], "<LocationConstraint>eu-central-2</LocationConstraint>") ||
		!strings.HasPrefix(got[1], "PUT /kura-acme-portable01?versioning") || !strings.Contains(got[1], "<Status>Enabled</Status>") {
		t.Fatalf("requêtes :\n%s", strings.Join(got, "\n"))
	}
	if err := c.CreateBucket(context.Background(), "pris", "eu-central-2"); !errors.Is(err, ErrBucketTaken) {
		t.Fatalf("nom pris : %v", err)
	}
	if err := c.CreateBucket(context.Background(), "refuse", "eu-central-2"); err == nil || !strings.Contains(err.Error(), "s3:CreateBucket") {
		t.Fatalf("droit manquant : %v", err)
	}
	if err := c.CreateBucket(context.Background(), "kura-x", "mars-1"); err == nil {
		t.Fatal("région inconnue acceptée")
	}
}

package wasabi

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// fakeS3 répond comme Wasabi en adressage par chemin : /<bucket>?<sous-ressource>.
type fakeS3 struct {
	buckets map[string]fakeBucket
	auth    []string
}

type fakeBucket struct {
	region, versioning, objectLock, lifecycle, policy string
	denyAll                                           bool // AccessDenied sur tout sauf versioning
}

func s3err(w http.ResponseWriter, status int, code string) {
	w.WriteHeader(status)
	fmt.Fprintf(w, `<?xml version="1.0" encoding="UTF-8"?><Error><Code>%s</Code><Message>%s</Message></Error>`, code, code)
}

func (f *fakeS3) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.auth = append(f.auth, r.Header.Get("Authorization"))
	name := strings.Trim(r.URL.Path, "/")
	w.Header().Set("Content-Type", "application/xml")
	if name == "" {
		fmt.Fprint(w, `<ListAllMyBucketsResult><Buckets>`)
		for n := range f.buckets {
			fmt.Fprintf(w, `<Bucket><Name>%s</Name><CreationDate>2026-01-02T03:04:05.000Z</CreationDate></Bucket>`, n)
		}
		fmt.Fprint(w, `</Buckets></ListAllMyBucketsResult>`)
		return
	}
	b, ok := f.buckets[name]
	if !ok {
		s3err(w, 404, "NoSuchBucket")
		return
	}
	q := r.URL.Query()
	switch {
	case q.Has("location"):
		fmt.Fprintf(w, `<LocationConstraint>%s</LocationConstraint>`, b.region)
	case q.Has("versioning"):
		fmt.Fprintf(w, `<VersioningConfiguration>%s</VersioningConfiguration>`, b.versioning)
	case b.denyAll:
		s3err(w, 403, "AccessDenied")
	case q.Has("object-lock"):
		if b.objectLock == "" {
			s3err(w, 404, "ObjectLockConfigurationNotFoundError")
			return
		}
		fmt.Fprint(w, b.objectLock)
	case q.Has("lifecycle"):
		if b.lifecycle == "" {
			s3err(w, 404, "NoSuchLifecycleConfiguration")
			return
		}
		fmt.Fprint(w, b.lifecycle)
	case q.Has("policy"):
		if b.policy == "" {
			s3err(w, 404, "NoSuchBucketPolicy")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, b.policy)
	default:
		s3err(w, 400, "NotImplemented")
	}
}

func testClient(t *testing.T, f *fakeS3) *Client {
	t.Helper()
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	c := NewClient(Keys{AccessKeyID: "AKIDTEST", SecretAccessKey: "SECRETTEST"})
	c.endpoint = func(string) string { return srv.URL }
	return c
}

// Bucket « historique » : versioning actif, cycle de vie 90 j, rien d'autre.
var legacy = fakeBucket{
	region:     "eu-central-1",
	versioning: `<Status>Enabled</Status>`,
	lifecycle: `<LifecycleConfiguration><Rule><ID>versions-90j</ID><Filter><Prefix></Prefix></Filter><Status>Enabled</Status>
		<NoncurrentVersionExpiration><NoncurrentDays>90</NoncurrentDays></NoncurrentVersionExpiration></Rule></LifecycleConfiguration>`,
}

// Bucket conforme au modèle.
var standard = fakeBucket{
	region:     "eu-central-1",
	versioning: `<Status>Enabled</Status>`,
	objectLock: `<ObjectLockConfiguration><ObjectLockEnabled>Enabled</ObjectLockEnabled><Rule><DefaultRetention>
		<Mode>GOVERNANCE</Mode><Days>30</Days></DefaultRetention></Rule></ObjectLockConfiguration>`,
	lifecycle: `<LifecycleConfiguration>
		<Rule><ID>anciennes-versions</ID><Filter></Filter><Status>Enabled</Status><NoncurrentVersionExpiration><NoncurrentDays>90</NoncurrentDays></NoncurrentVersionExpiration></Rule>
		<Rule><ID>marqueurs</ID><Filter></Filter><Status>Enabled</Status><Expiration><ExpiredObjectDeleteMarker>true</ExpiredObjectDeleteMarker></Expiration></Rule>
		<Rule><ID>envois</ID><Filter></Filter><Status>Enabled</Status><AbortIncompleteMultipartUpload><DaysAfterInitiation>7</DaysAfterInitiation></AbortIncompleteMultipartUpload></Rule>
		</LifecycleConfiguration>`,
	policy: `{"Version":"2012-10-17","Statement":[
		{"Effect":"Deny","Principal":"*","Action":"s3:*","Resource":["arn:aws:s3:::acme-srv01/*"],"Condition":{"Bool":{"aws:SecureTransport":"false"}}},
		{"Effect":"Deny","Principal":"*","Action":["s3:DeleteObjectVersion","s3:PutLifecycleConfiguration"],"Resource":["arn:aws:s3:::acme-srv01/*"]}]}`,
}

func codes(d []Deviation) string {
	var c []string
	for _, x := range d {
		c = append(c, x.Code)
	}
	return strings.Join(c, " ")
}

func TestReadSettingsAndAudit(t *testing.T) {
	f := &fakeS3{buckets: map[string]fakeBucket{"legacy-test": legacy, "acme-srv01": standard}}
	c := testClient(t, f)
	ctx := context.Background()

	list, err := c.ListBuckets(ctx)
	if err != nil || len(list) != 2 || list[0].Name != "acme-srv01" || list[0].Region != "eu-central-1" || list[0].Created.IsZero() {
		t.Fatalf("liste : %+v %v", list, err)
	}

	s := c.ReadSettings(ctx, "legacy-test", "eu-central-1")
	if s.Versioning != "Enabled" || s.ObjectLock.Enabled || s.Policy.Present || s.Lifecycle.NoncurrentDays != 90 || s.ReadErrors != nil {
		t.Fatalf("réglages hérités : %+v", s)
	}
	if got := codes(Standard.Audit(s)); got != "object-lock strategie cycle-marqueurs cycle-multipart" {
		t.Fatalf("écarts du bucket hérité : %s", got)
	}

	s = c.ReadSettings(ctx, "acme-srv01", "eu-central-1")
	if !s.ObjectLock.Enabled || s.ObjectLock.Mode != "GOVERNANCE" || s.ObjectLock.Days != 30 ||
		!s.Policy.DenyInsecureTransport || !s.Policy.DenyVersionDeletion || !s.Lifecycle.ExpiredDeleteMarker || s.Lifecycle.AbortMultipartDays != 7 {
		t.Fatalf("réglages du modèle : %+v", s)
	}
	if d := Standard.Audit(s); len(d) != 0 {
		t.Fatalf("un bucket conforme ne doit avoir aucun écart : %+v", d)
	}
	for _, a := range f.auth {
		if !strings.HasPrefix(a, "AWS4-HMAC-SHA256 Credential=AKIDTEST/") || strings.Contains(a, "SECRETTEST") {
			t.Fatalf("en-tête de signature inattendu : %q", a)
		}
	}
}

func TestDangerousAndUnreadable(t *testing.T) {
	bad := legacy
	bad.versioning = `<Status>Suspended</Status>`
	bad.lifecycle = `<LifecycleConfiguration><Rule><ID>tout-90j</ID><Filter><Prefix></Prefix></Filter><Status>Enabled</Status>
		<Expiration><Days>90</Days></Expiration></Rule>
		<Rule><ID>docs</ID><Filter><Prefix>docs/</Prefix></Filter><Status>Enabled</Status><NoncurrentVersionExpiration><NoncurrentDays>5</NoncurrentDays></NoncurrentVersionExpiration></Rule></LifecycleConfiguration>`
	denied := legacy
	denied.denyAll = true
	c := testClient(t, &fakeS3{buckets: map[string]fakeBucket{"bad": bad, "denied": denied}})
	ctx := context.Background()

	d := Standard.Audit(c.ReadSettings(ctx, "bad", "eu-central-1"))
	got := codes(d)
	if !strings.HasPrefix(got, "versioning cycle-courantes object-lock strategie cycle-versions") || !strings.Contains(got, "cycle-partiel") {
		t.Fatalf("écarts : %s", got)
	}
	if d[0].Severity != Critical || d[1].Severity != Critical {
		t.Fatalf("les écarts critiques doivent venir en tête : %+v", d[:2])
	}

	s := c.ReadSettings(ctx, "denied", "eu-central-1")
	if len(s.ReadErrors) != 3 || !strings.Contains(s.ReadErrors["policy"], "accès refusé") {
		t.Fatalf("erreurs de lecture : %+v", s.ReadErrors)
	}
	got = codes(Standard.Audit(s))
	if strings.Contains(got, "object-lock ") || strings.Contains(got, "strategie ") || !strings.Contains(got, "illisible-policy") {
		t.Fatalf("un réglage illisible ne doit pas être déclaré absent : %s", got)
	}
}

func TestBucketDaily(t *testing.T) {
	var auth []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth = append(auth, r.Header.Get("Authorization"))
		if r.URL.Path != "/v1/standalone/utilizations/bucket/acme-srv01" || r.URL.Query().Get("from") != "2026-10-01" {
			w.WriteHeader(400)
			return
		}
		page := r.URL.Query().Get("pageNum")
		day := map[string]string{"0": "2026-10-01T00:00:00Z", "1": "2026-10-02T00:00:00Z"}[page]
		fmt.Fprintf(w, `{"PageInfo":{"RecordCount":2,"PageCount":2,"PageSize":1,"PageNum":%s},
			"Records":[{"StartTime":%q,"Bucket":"acme-srv01","RawStorageSizeBytes":1000,"PaddedStorageSizeBytes":4096,
			"DeletedStorageSizeBytes":10,"NumBillableObjects":3,"NumBillableDeletedObjects":1,"UploadBytes":5,"DownloadBytes":0}]}`, page, day)
	}))
	defer srv.Close()
	old := statsBase
	statsBase = srv.URL
	defer func() { statsBase = old }()

	c := NewClient(Keys{AccessKeyID: "AK", SecretAccessKey: "SK"})
	got, err := c.BucketDaily(context.Background(), "acme-srv01", "2026-10-01", "2026-10-02")
	if err != nil || len(got) != 2 || got[0].Day != "2026-10-01" || got[1].Day != "2026-10-02" || got[0].PaddedBytes != 4096 {
		t.Fatalf("usage : %+v %v", got, err)
	}
	if auth[0] != "AK:SK" {
		t.Fatalf("authentification Stats : %q", auth[0])
	}

	denied := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(403) }))
	defer denied.Close()
	statsBase = denied.URL
	if _, err := c.BucketDaily(context.Background(), "x", "2026-10-01", "2026-10-02"); err == nil || !strings.Contains(err.Error(), "WasabiBucketStatsAccess") {
		t.Fatalf("refus : %v", err)
	}
}

func TestSummarizePolicyCases(t *testing.T) {
	cases := []struct {
		name          string
		doc           string
		https, delver bool
	}{
		{"https seul : le refus s3:* conditionnel ne protège pas les versions",
			`{"Statement":[{"Effect":"Deny","Principal":"*","Action":"s3:*","Resource":"*","Condition":{"Bool":{"aws:SecureTransport":"false"}}}]}`, true, false},
		{"Statement en objet unique",
			`{"Statement":{"Effect":"Deny","Principal":"*","Action":"s3:DeleteObjectVersion","Resource":"*"}}`, false, true},
		{"condition en tableau",
			`{"Statement":[{"Effect":"Deny","Action":["s3:*"],"Condition":{"Bool":{"aws:SecureTransport":["false"]}}}]}`, true, false},
		{"booléen JSON",
			`{"Statement":[{"Effect":"Deny","Action":"s3:*","Condition":{"Bool":{"aws:SecureTransport":false}}}]}`, true, false},
		{"Action *",
			`{"Statement":[{"Effect":"Deny","Action":"*","Resource":"*"}]}`, false, true},
		{"Allow ignoré",
			`{"Statement":[{"Effect":"Allow","Action":"s3:DeleteObjectVersion"}]}`, false, false},
	}
	for _, c := range cases {
		p := summarizePolicy(c.doc)
		if !p.Present || p.DenyInsecureTransport != c.https || p.DenyVersionDeletion != c.delver {
			t.Errorf("%s : %+v", c.name, p)
		}
	}
}

func TestKeepPrevious(t *testing.T) {
	at := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	prev := Settings{ReadAt: at, Versioning: "Suspended", Policy: Policy{Present: true}}
	cur := Settings{ReadAt: at.AddDate(0, 0, 1), ReadErrors: map[string]string{"versioning": "délai dépassé"}}
	cur.KeepPrevious(prev)
	if cur.Versioning != "Suspended" || !cur.Kept["versioning"].Equal(at) {
		t.Fatalf("valeur non reprise : %+v", cur)
	}
	d := Standard.Audit(cur)
	if d[0].Severity != Critical || d[0].Code != "versioning" {
		t.Fatalf("écart critique perdu : %+v", d)
	}
	// Deuxième relevé illisible : la date d'origine est conservée.
	next := Settings{ReadAt: at.AddDate(0, 0, 2), ReadErrors: map[string]string{"versioning": "délai dépassé"}}
	next.KeepPrevious(cur)
	if !next.Kept["versioning"].Equal(at) || next.Versioning != "Suspended" {
		t.Fatalf("seconde reprise : %+v", next)
	}
}

func TestObjectLockWithoutDefaultRetention(t *testing.T) {
	d := Standard.Audit(Settings{Versioning: "Enabled", ObjectLock: ObjectLock{Enabled: true}})
	for _, x := range d {
		if x.Code == "object-lock-retention" {
			if x.Severity != High {
				t.Fatalf("gravité %s, attendu haute", x.Severity)
			}
			return
		}
	}
	t.Fatalf("écart absent : %+v", d)
}

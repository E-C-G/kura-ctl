package wasabi

import (
	"context"
	"crypto/md5"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
)

// writableS3 : buckets dont la stratégie, le cycle de vie et l'Object Lock s'écrivent.
type writableS3 struct {
	mu      sync.Mutex
	region  string
	objLock bool
	docs    map[string]string // sous-ressource → corps écrit
	md5ok   map[string]bool
}

func (f *writableS3) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	q := r.URL.Query()
	sub := ""
	for _, k := range []string{"policy", "lifecycle", "object-lock", "versioning", "location"} {
		if q.Has(k) {
			sub = k
		}
	}
	w.Header().Set("Content-Type", "application/xml")
	switch r.Method {
	case http.MethodPut:
		body, _ := io.ReadAll(r.Body)
		sum := md5.Sum(body)
		f.md5ok[sub] = r.Header.Get("Content-MD5") == base64.StdEncoding.EncodeToString(sum[:])
		if sub == "object-lock" && !f.objLock {
			s3err(w, 409, "InvalidBucketState")
			return
		}
		f.docs[sub] = string(body)
		w.WriteHeader(200)
	case http.MethodGet:
		switch sub {
		case "location":
			fmt.Fprintf(w, `<LocationConstraint>%s</LocationConstraint>`, f.region)
		case "versioning":
			fmt.Fprint(w, `<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>`)
		default:
			doc, ok := f.docs[sub]
			if !ok {
				if sub == "object-lock" && f.objLock {
					fmt.Fprint(w, `<ObjectLockConfiguration><ObjectLockEnabled>Enabled</ObjectLockEnabled></ObjectLockConfiguration>`)
					return
				}
				s3err(w, 404, map[string]string{"policy": "NoSuchBucketPolicy", "lifecycle": "NoSuchLifecycleConfiguration",
					"object-lock": "ObjectLockConfigurationNotFoundError"}[sub])
				return
			}
			fmt.Fprint(w, doc)
		}
	}
}

// fakeIAM : API IAM par requêtes POST de formulaire, réponses XML.
type fakeIAM struct {
	mu       sync.Mutex
	self     string // utilisateur de la clé
	users    map[string]bool
	policies map[string]string // utilisateur/nom → document
	keys     map[string][]AccessKey
	n        int
}

func (f *fakeIAM) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	r.ParseForm()
	act, user := r.Form.Get("Action"), r.Form.Get("UserName")
	w.Header().Set("Content-Type", "text/xml")
	reply := func(body string) {
		fmt.Fprintf(w, `<%sResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/"><%sResult>%s</%sResult><ResponseMetadata><RequestId>r</RequestId></ResponseMetadata></%sResponse>`,
			act, act, body, act, act)
	}
	fail := func(status int, code string) {
		w.WriteHeader(status)
		fmt.Fprintf(w, `<ErrorResponse><Error><Type>Sender</Type><Code>%s</Code><Message>%s</Message></Error><RequestId>r</RequestId></ErrorResponse>`, code, code)
	}
	userXML := func(n string) string {
		return fmt.Sprintf(`<User><Path>/</Path><UserName>%s</UserName><UserId>ID%s</UserId><Arn>arn:aws:iam::100000000042:user/%s</Arn><CreateDate>2026-10-01T00:00:00Z</CreateDate></User>`, n, n, n)
	}
	switch act {
	case "GetUser":
		if user == "" {
			user = f.self
		}
		if !f.users[user] {
			fail(404, "NoSuchEntity")
			return
		}
		reply(userXML(user))
	case "CreateUser":
		f.users[user] = true
		reply(userXML(user))
	case "PutUserPolicy":
		f.policies[user+"/"+r.Form.Get("PolicyName")] = r.Form.Get("PolicyDocument")
		reply("")
	case "CreateAccessKey":
		if len(f.keys[user]) >= 2 {
			fail(409, "LimitExceeded")
			return
		}
		f.n++
		k := AccessKey{ID: fmt.Sprintf("AKIDPOSTE%04d", f.n), Secret: fmt.Sprintf("secret%04d", f.n), Active: true}
		f.keys[user] = append(f.keys[user], k)
		reply(fmt.Sprintf(`<AccessKey><UserName>%s</UserName><AccessKeyId>%s</AccessKeyId><Status>Active</Status><SecretAccessKey>%s</SecretAccessKey><CreateDate>2026-10-26T10:00:00Z</CreateDate></AccessKey>`, user, k.ID, k.Secret))
	case "ListAccessKeys":
		var b strings.Builder
		for _, k := range f.keys[user] {
			st := "Inactive"
			if k.Active {
				st = "Active"
			}
			fmt.Fprintf(&b, `<member><UserName>%s</UserName><AccessKeyId>%s</AccessKeyId><Status>%s</Status><CreateDate>2026-10-26T10:00:00Z</CreateDate></member>`, user, k.ID, st)
		}
		reply(`<AccessKeyMetadata>` + b.String() + `</AccessKeyMetadata><IsTruncated>false</IsTruncated>`)
	case "UpdateAccessKey":
		for i, k := range f.keys[user] {
			if k.ID == r.Form.Get("AccessKeyId") {
				f.keys[user][i].Active = r.Form.Get("Status") == "Active"
			}
		}
		reply("")
	case "DeleteAccessKey":
		ks := f.keys[user][:0]
		for _, k := range f.keys[user] {
			if k.ID != r.Form.Get("AccessKeyId") {
				ks = append(ks, k)
			}
		}
		f.keys[user] = ks
		reply("")
	case "GetAccessKeyLastUsed":
		reply(`<UserName>x</UserName><AccessKeyLastUsed><LastUsedDate>2026-10-26T12:00:00Z</LastUsedDate><ServiceName>s3</ServiceName><Region>eu-central-1</Region></AccessKeyLastUsed>`)
	default:
		fail(400, "InvalidAction")
	}
}

func adminClient(t *testing.T) (*Client, *writableS3, *fakeIAM) {
	t.Helper()
	s := &writableS3{region: "eu-central-1", objLock: true, docs: map[string]string{}, md5ok: map[string]bool{}}
	i := &fakeIAM{self: "kura-ctl-admin", users: map[string]bool{"kura-ctl-admin": true}, policies: map[string]string{}, keys: map[string][]AccessKey{}}
	ss, is := httptest.NewServer(s), httptest.NewServer(i)
	t.Cleanup(ss.Close)
	t.Cleanup(is.Close)
	c := NewClient(Keys{AccessKeyID: "AKIDADMIN", SecretAccessKey: "SECRETADMIN"})
	c.endpoint = func(string) string { return ss.URL }
	c.iamURL = is.URL
	return c, s, i
}

func TestApplyTemplateThenAuditIsClean(t *testing.T) {
	c, s, _ := adminClient(t)
	ctx := context.Background()
	id, err := c.Identity(ctx)
	if err != nil || id.AccountID != "100000000042" || id.UserName != "kura-ctl-admin" || id.Root() {
		t.Fatalf("identité : %+v %v", id, err)
	}
	doc, err := BucketPolicy(Standard, "acme-srv01", id)
	if err != nil {
		t.Fatal(err)
	}
	for _, step := range []error{
		c.PutBucketPolicy(ctx, "acme-srv01", "eu-central-1", doc),
		c.PutLifecycle(ctx, "acme-srv01", "eu-central-1", Standard),
		c.PutDefaultRetention(ctx, "acme-srv01", "eu-central-1", "GOVERNANCE", 30),
	} {
		if step != nil {
			t.Fatal(step)
		}
	}
	for _, sub := range []string{"policy", "lifecycle", "object-lock"} {
		if !s.md5ok[sub] {
			t.Errorf("%s : Content-MD5 absent ou faux", sub)
		}
	}
	st := c.ReadSettings(ctx, "acme-srv01", "eu-central-1")
	if d := Standard.Audit(st); len(d) != 0 {
		t.Fatalf("écarts après application du modèle : %+v\nstratégie : %s\ncycle de vie : %s", d, s.docs["policy"], s.docs["lifecycle"])
	}
	if !strings.Contains(strings.Join(st.Policy.Exceptions, " "), "user/kura-ctl-admin") {
		t.Fatalf("exceptions : %v", st.Policy.Exceptions)
	}
	// Bucket sans Object Lock : la rétention par défaut est refusée par Wasabi.
	s.objLock = false
	if err := c.PutDefaultRetention(ctx, "acme-srv01", "eu-central-1", "GOVERNANCE", 30); err == nil {
		t.Fatal("rétention posée sans Object Lock")
	}
}

func TestBucketPolicyShape(t *testing.T) {
	doc, err := BucketPolicy(Standard, "acme-srv01", Identity{AccountID: "100000000042", UserName: "kura-ctl-admin"})
	if err != nil {
		t.Fatal(err)
	}
	var d policyDoc
	if err := json.Unmarshal([]byte(doc), &d); err != nil {
		t.Fatal(err)
	}
	for _, st := range d.Statement {
		for _, a := range st.Action {
			if a == "s3:PutBucketPolicy" || a == "s3:DeleteBucketPolicy" {
				t.Fatal("la console ne doit jamais pouvoir s'interdire de corriger la stratégie")
			}
		}
	}
	if !strings.Contains(doc, `"arn:aws:iam::100000000042:root"`) || !strings.Contains(doc, `"arn:aws:iam::100000000042:user/kura-ctl-admin"`) {
		t.Fatalf("exceptions absentes :\n%s", doc)
	}
	if _, err := BucketPolicy(Standard, "b", Identity{AccountID: "1"}); err == nil {
		t.Fatal("stratégie sans utilisateur de console")
	}
	// Un refus qui excepte d'autres conditions (adresse IP) ne vaut pas protection.
	p := summarizePolicy(`{"Statement":[{"Effect":"Deny","Action":"s3:DeleteObjectVersion","Condition":{"NotIpAddress":{"aws:SourceIp":"1.2.3.4/32"}}}]}`)
	if p.DenyVersionDeletion {
		t.Fatal("refus conditionné par IP compté comme protection")
	}
}

func TestPosteAndAdminPolicies(t *testing.T) {
	p := PostePolicy("acme-srv01")
	for _, forbidden := range []string{"DeleteObjectVersion", "Bypass", "PutBucket", "PutLifecycle", "iam:"} {
		if strings.Contains(p, forbidden) {
			t.Errorf("stratégie de poste avec %s", forbidden)
		}
	}
	if !strings.Contains(p, `"arn:aws:s3:::acme-srv01/*"`) || strings.Contains(p, `"*"`) {
		t.Errorf("stratégie de poste hors de son bucket :\n%s", p)
	}
	a := AdminPolicy()
	if strings.Contains(a, "Bypass") || strings.Contains(a, "s3:GetObject") || strings.Contains(a, "DeleteObject") {
		t.Errorf("stratégie de la console trop large :\n%s", a)
	}
	if !strings.Contains(a, `"arn:aws:iam::*:user/kura-ctl*"`) {
		t.Error("la console peut agir sur son propre utilisateur")
	}
	for _, c := range []struct{ client, poste, bucket, want string }{
		{"acme", "SRV01", "acme-srv01", "kura-acme-srv01"},
		{"poste", "Dell XPS", "poste-x", "kura-poste-dell-xps"},
		{"acme", "", "acme-srv01", "kura-acme-srv01"},
	} {
		if got, err := UserNameFor(c.client, c.poste, c.bucket); err != nil || got != c.want {
			t.Errorf("%v : %q %v", c, got, err)
		}
	}
	if _, err := UserNameFor("ctl", "admin", "x"); err == nil {
		t.Error("nom kura-ctl… accepté")
	}
}

func TestPosteUserAndKeys(t *testing.T) {
	c, _, i := adminClient(t)
	ctx := context.Background()
	created, err := c.EnsureUser(ctx, "kura-acme-srv01")
	if err != nil || !created {
		t.Fatalf("création : %v %v", created, err)
	}
	if created, _ := c.EnsureUser(ctx, "kura-acme-srv01"); created {
		t.Fatal("utilisateur recréé")
	}
	if err := c.PutUserPolicy(ctx, "kura-acme-srv01", "kura-acces-bucket", PostePolicy("acme-srv01")); err != nil {
		t.Fatal(err)
	}
	doc, _ := url.QueryUnescape(i.policies["kura-acme-srv01/kura-acces-bucket"])
	if !strings.Contains(doc, "acme-srv01") {
		t.Fatalf("stratégie posée : %q", doc)
	}
	k, err := c.CreateAccessKey(ctx, "kura-acme-srv01")
	if err != nil || k.Secret == "" || !k.Active {
		t.Fatalf("clé : %+v %v", k, err)
	}
	if err := c.SetAccessKeyActive(ctx, "kura-acme-srv01", k.ID, false); err != nil {
		t.Fatal(err)
	}
	keys, _ := c.ListAccessKeys(ctx, "kura-acme-srv01")
	if len(keys) != 1 || keys[0].Active || keys[0].Secret != "" {
		t.Fatalf("liste : %+v", keys)
	}
	if used, err := c.AccessKeyLastUsed(ctx, k.ID); err != nil || used.IsZero() {
		t.Fatalf("dernière utilisation : %v %v", used, err)
	}
	if err := c.DeleteAccessKey(ctx, "kura-acme-srv01", k.ID); err != nil {
		t.Fatal(err)
	}
	if keys, _ := c.ListAccessKeys(ctx, "kura-absent"); keys != nil {
		t.Fatal("utilisateur absent : liste non vide")
	}
}

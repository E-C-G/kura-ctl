// Package wasabi parle aux API de Wasabi : S3 (réglages des buckets) par le SDK AWS
// v2, et Stats (usage quotidien) par un client HTTP. Le lot 1 ne fait que lire.
package wasabi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
)

// Keys est une clé d'accès Wasabi.
type Keys struct {
	AccessKeyID     string
	SecretAccessKey string
}

// Client lit les buckets du compte.
type Client struct {
	keys     Keys
	http     *http.Client
	endpoint func(region string) string // URL S3 d'une région
}

// NewClient prépare un client pour la clé donnée.
func NewClient(k Keys) *Client {
	return &Client{keys: k, http: &http.Client{Timeout: 60 * time.Second}, endpoint: S3Endpoint}
}

// S3Endpoint renvoie l'URL S3 d'une région Wasabi (us-east-1 : s3.wasabisys.com).
func S3Endpoint(region string) string {
	if region == "" || region == "us-east-1" {
		return "https://s3.wasabisys.com"
	}
	return "https://s3." + region + ".wasabisys.com"
}

func (c *Client) s3(region string) *s3.Client {
	if region == "" {
		region = "us-east-1"
	}
	k := c.keys
	return s3.New(s3.Options{
		Region:       region,
		BaseEndpoint: aws.String(c.endpoint(region)),
		UsePathStyle: true,
		HTTPClient:   c.http,
		Credentials: aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
			return aws.Credentials{AccessKeyID: k.AccessKeyID, SecretAccessKey: k.SecretAccessKey, Source: "kura-ctl"}, nil
		}),
		// Wasabi n'a pas besoin des sommes de contrôle ajoutées par défaut par les SDK récents.
		RequestChecksumCalculation: aws.RequestChecksumCalculationWhenRequired,
		ResponseChecksumValidation: aws.ResponseChecksumValidationWhenRequired,
	})
}

// BucketInfo est un bucket du compte.
type BucketInfo struct {
	Name    string
	Region  string // vide si Err
	Created time.Time
	Err     string // région illisible (droit refusé, bucket supprimé entre-temps…)
}

// ListBuckets liste tous les buckets du compte, avec leur région. Une région
// illisible n'arrête pas la liste : elle est notée dans Err.
func (c *Client) ListBuckets(ctx context.Context) ([]BucketInfo, error) {
	cl := c.s3("us-east-1")
	out, err := cl.ListBuckets(ctx, &s3.ListBucketsInput{})
	if err != nil {
		return nil, fmt.Errorf("liste des buckets : %w", explain(err))
	}
	res := make([]BucketInfo, len(out.Buckets))
	var wg sync.WaitGroup
	sem := make(chan struct{}, 8) // appels simultanés
	for i, b := range out.Buckets {
		res[i] = BucketInfo{Name: aws.ToString(b.Name), Created: aws.ToTime(b.CreationDate)}
		wg.Add(1)
		go func(bi *BucketInfo) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			loc, err := cl.GetBucketLocation(ctx, &s3.GetBucketLocationInput{Bucket: aws.String(bi.Name)})
			if err != nil {
				bi.Err = explain(err).Error()
				return
			}
			bi.Region = string(loc.LocationConstraint)
			if bi.Region == "" {
				bi.Region = "us-east-1"
			}
		}(&res[i])
	}
	wg.Wait()
	sort.Slice(res, func(i, j int) bool { return res[i].Name < res[j].Name })
	return res, nil
}

// Settings sont les réglages relevés sur un bucket.
type Settings struct {
	Name       string     `json:"name"`
	Region     string     `json:"region"`
	ReadAt     time.Time  `json:"read_at"`
	Versioning string     `json:"versioning"` // Enabled | Suspended | Disabled
	ObjectLock ObjectLock `json:"object_lock"`
	Lifecycle  Lifecycle  `json:"lifecycle"`
	Policy     Policy     `json:"policy"`
	// ReadErrors : réglages qui n'ont pas pu être lus (droit manquant…), par nom.
	ReadErrors map[string]string `json:"read_errors,omitempty"`
	// Kept : réglages illisibles à ce relevé dont la valeur précédente est conservée,
	// avec la date du relevé qui l'a lue.
	Kept map[string]time.Time `json:"kept,omitempty"`
}

// KeepPrevious reprend, pour chaque réglage illisible, la valeur lue par un relevé
// précédent : une panne passagère ne fait pas disparaître un écart déjà connu.
func (s *Settings) KeepPrevious(prev Settings) {
	for name := range s.ReadErrors {
		if _, unread := prev.ReadErrors[name]; unread {
			if at, ok := prev.Kept[name]; ok { // déjà reprise : on garde la date d'origine
				s.keep(name, prev, at)
			}
			continue
		}
		if prev.ReadAt.IsZero() {
			continue
		}
		s.keep(name, prev, prev.ReadAt)
	}
}

func (s *Settings) keep(name string, prev Settings, at time.Time) {
	switch name {
	case "versioning":
		s.Versioning = prev.Versioning
	case "object_lock":
		s.ObjectLock = prev.ObjectLock
	case "lifecycle":
		s.Lifecycle = prev.Lifecycle
	case "policy":
		s.Policy = prev.Policy
	default:
		return
	}
	if s.Kept == nil {
		s.Kept = map[string]time.Time{}
	}
	s.Kept[name] = at
}

// ObjectLock résume la configuration Object Lock.
type ObjectLock struct {
	Enabled bool   `json:"enabled"`
	Mode    string `json:"mode,omitempty"` // GOVERNANCE | COMPLIANCE
	Days    int    `json:"days,omitempty"` // rétention par défaut, en jours
}

// Lifecycle résume les règles de cycle de vie actives qui portent sur tout le bucket.
type Lifecycle struct {
	Present             bool     `json:"present"`
	NoncurrentDays      int      `json:"noncurrent_days,omitempty"`      // anciennes versions supprimées après N jours
	ExpiresCurrentDays  int      `json:"expires_current_days,omitempty"` // versions courantes expirées après N jours (dangereux)
	ExpiredDeleteMarker bool     `json:"expired_delete_marker,omitempty"`
	AbortMultipartDays  int      `json:"abort_multipart_days,omitempty"`
	PartialRules        []string `json:"partial_rules,omitempty"` // règles limitées à un préfixe ou désactivées
}

// Policy résume la stratégie de bucket.
type Policy struct {
	Present               bool `json:"present"`
	DenyInsecureTransport bool `json:"deny_insecure_transport,omitempty"`
	DenyVersionDeletion   bool `json:"deny_version_deletion,omitempty"`
}

// ReadSettings relève les réglages d'un bucket. Un réglage illisible n'arrête pas
// le relevé : il est noté dans ReadErrors et l'audit le signale.
func (c *Client) ReadSettings(ctx context.Context, name, region string) Settings {
	cl := c.s3(region)
	st := Settings{Name: name, Region: region, ReadAt: time.Now().UTC(), ReadErrors: map[string]string{}}
	b := aws.String(name)

	if v, err := cl.GetBucketVersioning(ctx, &s3.GetBucketVersioningInput{Bucket: b}); err != nil {
		st.ReadErrors["versioning"] = explain(err).Error()
	} else {
		st.Versioning = string(v.Status)
		if st.Versioning == "" {
			st.Versioning = "Disabled"
		}
	}

	if ol, err := cl.GetObjectLockConfiguration(ctx, &s3.GetObjectLockConfigurationInput{Bucket: b}); err != nil {
		if code(err) != "ObjectLockConfigurationNotFoundError" {
			st.ReadErrors["object_lock"] = explain(err).Error()
		}
	} else if c := ol.ObjectLockConfiguration; c != nil {
		st.ObjectLock.Enabled = c.ObjectLockEnabled == types.ObjectLockEnabledEnabled
		if r := c.Rule; r != nil && r.DefaultRetention != nil {
			st.ObjectLock.Mode = string(r.DefaultRetention.Mode)
			st.ObjectLock.Days = int(aws.ToInt32(r.DefaultRetention.Days)) + 365*int(aws.ToInt32(r.DefaultRetention.Years))
		}
	}

	if lc, err := cl.GetBucketLifecycleConfiguration(ctx, &s3.GetBucketLifecycleConfigurationInput{Bucket: b}); err != nil {
		if code(err) != "NoSuchLifecycleConfiguration" {
			st.ReadErrors["lifecycle"] = explain(err).Error()
		}
	} else {
		st.Lifecycle = summarizeLifecycle(lc.Rules)
	}

	if p, err := cl.GetBucketPolicy(ctx, &s3.GetBucketPolicyInput{Bucket: b}); err != nil {
		if code(err) != "NoSuchBucketPolicy" {
			st.ReadErrors["policy"] = explain(err).Error()
		}
	} else {
		st.Policy = summarizePolicy(aws.ToString(p.Policy))
	}
	if len(st.ReadErrors) == 0 {
		st.ReadErrors = nil
	}
	return st
}

func summarizeLifecycle(rules []types.LifecycleRule) Lifecycle {
	l := Lifecycle{Present: len(rules) > 0}
	for _, r := range rules {
		id := aws.ToString(r.ID)
		if id == "" {
			id = "(sans nom)"
		}
		if r.Status != types.ExpirationStatusEnabled {
			l.PartialRules = append(l.PartialRules, id+" (désactivée)")
			continue
		}
		if !wholeBucket(r) {
			l.PartialRules = append(l.PartialRules, id+" (limitée à une partie du bucket)")
			continue
		}
		if n := r.NoncurrentVersionExpiration; n != nil && aws.ToInt32(n.NoncurrentDays) > 0 {
			l.NoncurrentDays = int(aws.ToInt32(n.NoncurrentDays))
		}
		if e := r.Expiration; e != nil {
			if aws.ToInt32(e.Days) > 0 || e.Date != nil {
				l.ExpiresCurrentDays = int(aws.ToInt32(e.Days))
				if l.ExpiresCurrentDays == 0 {
					l.ExpiresCurrentDays = -1 // à une date fixe
				}
			}
			if aws.ToBool(e.ExpiredObjectDeleteMarker) {
				l.ExpiredDeleteMarker = true
			}
		}
		if a := r.AbortIncompleteMultipartUpload; a != nil && aws.ToInt32(a.DaysAfterInitiation) > 0 {
			l.AbortMultipartDays = int(aws.ToInt32(a.DaysAfterInitiation))
		}
	}
	return l
}

func wholeBucket(r types.LifecycleRule) bool {
	if aws.ToString(r.Prefix) != "" {
		return false
	}
	f := r.Filter
	if f == nil {
		return true
	}
	return aws.ToString(f.Prefix) == "" && f.Tag == nil && f.And == nil &&
		f.ObjectSizeGreaterThan == nil && f.ObjectSizeLessThan == nil
}

// summarizePolicy repère dans une stratégie de bucket les deux refus du modèle :
// refus du HTTP non chiffré (condition aws:SecureTransport = false) et refus sans
// condition de la suppression de versions.
func summarizePolicy(doc string) Policy {
	p := Policy{Present: strings.TrimSpace(doc) != ""}
	var d struct {
		Statement json.RawMessage `json:"Statement"`
	}
	if err := json.Unmarshal([]byte(doc), &d); err != nil {
		return p
	}
	type statement struct {
		Effect    string                    `json:"Effect"`
		Action    json.RawMessage           `json:"Action"`
		Condition map[string]map[string]any `json:"Condition"`
	}
	var stmts []statement
	if json.Unmarshal(d.Statement, &stmts) != nil {
		var one statement // Statement peut être un objet unique
		if json.Unmarshal(d.Statement, &one) != nil {
			return p
		}
		stmts = []statement{one}
	}
	for _, s := range stmts {
		if !strings.EqualFold(s.Effect, "Deny") {
			continue
		}
		for op, kv := range s.Condition {
			if !strings.EqualFold(op, "Bool") {
				continue
			}
			for k, v := range kv {
				if strings.EqualFold(k, "aws:SecureTransport") && isFalse(v) {
					p.DenyInsecureTransport = true
				}
			}
		}
		// Un refus conditionnel (HTTP seulement, adresse IP…) laisse la suppression
		// possible hors de la condition : il ne compte pas.
		if len(s.Condition) > 0 {
			continue
		}
		for _, a := range actions(s.Action) {
			switch strings.ToLower(a) {
			case "s3:deleteobjectversion", "s3:*", "s3:delete*", "*":
				p.DenyVersionDeletion = true
			}
		}
	}
	return p
}

// isFalse : "false", false ou ["false"].
func isFalse(v any) bool {
	switch x := v.(type) {
	case string:
		return strings.EqualFold(x, "false")
	case bool:
		return !x
	case []any:
		return len(x) == 1 && isFalse(x[0])
	}
	return false
}

func actions(raw json.RawMessage) []string {
	var one string
	if json.Unmarshal(raw, &one) == nil {
		return []string{one}
	}
	var many []string
	_ = json.Unmarshal(raw, &many)
	return many
}

func code(err error) string {
	var ae smithy.APIError
	if errors.As(err, &ae) {
		return ae.ErrorCode()
	}
	return ""
}

// explain rend une erreur S3 lisible, sans URL signée ni clé.
func explain(err error) error {
	var ae smithy.APIError
	if errors.As(err, &ae) {
		switch ae.ErrorCode() {
		case "AccessDenied":
			return errors.New("accès refusé : la clé de la console n'a pas ce droit")
		case "InvalidAccessKeyId", "SignatureDoesNotMatch":
			return errors.New("clé d'administration refusée par Wasabi (identifiant ou secret incorrect)")
		case "NoSuchBucket":
			return errors.New("bucket introuvable")
		}
		return fmt.Errorf("%s : %s", ae.ErrorCode(), ae.ErrorMessage())
	}
	var ue *url.Error
	if errors.As(err, &ue) {
		return fmt.Errorf("Wasabi injoignable : %v", ue.Err)
	}
	return err
}

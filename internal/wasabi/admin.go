package wasabi

import (
	"bytes"
	"context"
	"crypto/md5"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go/middleware"
	smithyhttp "github.com/aws/smithy-go/transport/http"
)

// IAMEndpoint est l'API IAM de Wasabi (une seule pour toutes les régions).
const IAMEndpoint = "https://iam.wasabisys.com"

// Admin regroupe les écritures du lot 2 : réglages des buckets, utilisateurs et clés
// des postes. Implémenté par *Client.
type Admin interface {
	Identity(ctx context.Context) (Identity, error)
	PutBucketPolicy(ctx context.Context, bucket, region, doc string) error
	PutLifecycle(ctx context.Context, bucket, region string, t Template) error
	PutDefaultRetention(ctx context.Context, bucket, region, mode string, days int) error
	CreateBucket(ctx context.Context, name, region string) error
	EnsureUser(ctx context.Context, name string) (created bool, err error)
	CheckPosteUser(ctx context.Context, user, bucket string) error
	PutUserPolicy(ctx context.Context, user, name, doc string) error
	CreateAccessKey(ctx context.Context, user string) (AccessKey, error)
	ListAccessKeys(ctx context.Context, user string) ([]AccessKey, error)
	SetAccessKeyActive(ctx context.Context, user, id string, active bool) error
	DeleteAccessKey(ctx context.Context, user, id string) error
	AccessKeyLastUsed(ctx context.Context, id string) (time.Time, error)
}

// Identity est l'utilisateur IAM de la clé de la console.
type Identity struct {
	Arn       string
	UserName  string // vide pour le compte racine
	AccountID string
}

// Root indique une clé du compte racine (à ne jamais confier à la console).
func (i Identity) Root() bool { return strings.HasSuffix(i.Arn, ":root") }

// AccessKey est une clé d'accès IAM. Secret n'est renseigné qu'à la création.
type AccessKey struct {
	ID      string
	Secret  string
	Active  bool
	Created time.Time
}

var arnAccount = regexp.MustCompile(`^arn:aws:iam::(\d+):`)

func (c *Client) iam() *iam.Client {
	k := c.keys
	return iam.New(iam.Options{
		Region:       "us-east-1",
		BaseEndpoint: aws.String(c.iamEndpoint()),
		HTTPClient:   c.http,
		Credentials: aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
			return aws.Credentials{AccessKeyID: k.AccessKeyID, SecretAccessKey: k.SecretAccessKey, Source: "kura-ctl"}, nil
		}),
	})
}

func (c *Client) iamEndpoint() string {
	if c.iamURL != "" {
		return c.iamURL
	}
	return IAMEndpoint
}

// Identity interroge IAM sur l'utilisateur de la clé (GetUser sans nom).
func (c *Client) Identity(ctx context.Context) (Identity, error) {
	out, err := c.iam().GetUser(ctx, &iam.GetUserInput{})
	if err != nil {
		return Identity{}, fmt.Errorf("identité de la clé : %w", explain(err))
	}
	id := Identity{Arn: aws.ToString(out.User.Arn), UserName: aws.ToString(out.User.UserName)}
	if m := arnAccount.FindStringSubmatch(id.Arn); m != nil {
		id.AccountID = m[1]
	}
	if id.AccountID == "" {
		return id, fmt.Errorf("identité de la clé : ARN inattendu %q", id.Arn)
	}
	return id, nil
}

// withContentMD5 ajoute l'en-tête Content-MD5 aux écritures de réglages : les
// services compatibles S3 l'exigent souvent, alors que les SDK récents envoient à la
// place une somme CRC32.
func withContentMD5(o *s3.Options) {
	o.APIOptions = append(o.APIOptions, func(st *middleware.Stack) error {
		return st.Build.Add(middleware.BuildMiddlewareFunc("KuraContentMD5",
			func(ctx context.Context, in middleware.BuildInput, next middleware.BuildHandler) (middleware.BuildOutput, middleware.Metadata, error) {
				if req, ok := in.Request.(*smithyhttp.Request); ok && req.Header.Get("Content-MD5") == "" {
					if s := req.GetStream(); s != nil && req.IsStreamSeekable() {
						body, err := io.ReadAll(s)
						if err != nil {
							return middleware.BuildOutput{}, middleware.Metadata{}, err
						}
						sum := md5.Sum(body)
						req.Header.Set("Content-MD5", base64.StdEncoding.EncodeToString(sum[:]))
						if err := req.RewindStream(); err != nil {
							return middleware.BuildOutput{}, middleware.Metadata{}, err
						}
					}
				}
				return next.HandleBuild(ctx, in)
			}), middleware.After)
	})
}

// PutBucketPolicy remplace la stratégie du bucket.
func (c *Client) PutBucketPolicy(ctx context.Context, bucket, region, doc string) error {
	if !json.Valid([]byte(doc)) {
		return errors.New("stratégie de bucket : JSON invalide")
	}
	_, err := c.s3(region).PutBucketPolicy(ctx, &s3.PutBucketPolicyInput{Bucket: aws.String(bucket), Policy: aws.String(doc)}, withContentMD5)
	if err != nil {
		return fmt.Errorf("stratégie de bucket : %w", explain(err))
	}
	return nil
}

// LifecycleRules sont les règles de cycle de vie du modèle, sur tout le bucket.
func LifecycleRules(t Template) []types.LifecycleRule {
	all := &types.LifecycleRuleFilter{Prefix: aws.String("")}
	var rules []types.LifecycleRule
	if t.NoncurrentDays > 0 {
		rules = append(rules, types.LifecycleRule{ID: aws.String("anciennes-versions"), Status: types.ExpirationStatusEnabled, Filter: all,
			NoncurrentVersionExpiration: &types.NoncurrentVersionExpiration{NoncurrentDays: aws.Int32(int32(t.NoncurrentDays))}})
	}
	if t.ExpiredDeleteMarker {
		rules = append(rules, types.LifecycleRule{ID: aws.String("marqueurs-orphelins"), Status: types.ExpirationStatusEnabled, Filter: all,
			Expiration: &types.LifecycleExpiration{ExpiredObjectDeleteMarker: aws.Bool(true)}})
	}
	if t.AbortMultipartDays > 0 {
		rules = append(rules, types.LifecycleRule{ID: aws.String("envois-interrompus"), Status: types.ExpirationStatusEnabled, Filter: all,
			AbortIncompleteMultipartUpload: &types.AbortIncompleteMultipartUpload{DaysAfterInitiation: aws.Int32(int32(t.AbortMultipartDays))}})
	}
	return rules
}

// PutLifecycle remplace le cycle de vie du bucket par celui du modèle. Les versions
// courantes ne sont jamais expirées.
func (c *Client) PutLifecycle(ctx context.Context, bucket, region string, t Template) error {
	rules := LifecycleRules(t)
	for _, r := range rules {
		if r.Expiration != nil && (r.Expiration.Days != nil || r.Expiration.Date != nil) {
			return errors.New("cycle de vie : règle qui expire les versions courantes refusée")
		}
	}
	_, err := c.s3(region).PutBucketLifecycleConfiguration(ctx, &s3.PutBucketLifecycleConfigurationInput{
		Bucket: aws.String(bucket), LifecycleConfiguration: &types.BucketLifecycleConfiguration{Rules: rules}}, withContentMD5)
	if err != nil {
		return fmt.Errorf("cycle de vie : %w", explain(err))
	}
	return nil
}

// PutDefaultRetention fixe la rétention par défaut d'un bucket où Object Lock est actif.
func (c *Client) PutDefaultRetention(ctx context.Context, bucket, region, mode string, days int) error {
	if mode != "GOVERNANCE" && mode != "COMPLIANCE" {
		return fmt.Errorf("rétention : mode %q inconnu", mode)
	}
	if days < 1 || days > 3650 {
		return fmt.Errorf("rétention : %d jours hors limites", days)
	}
	_, err := c.s3(region).PutObjectLockConfiguration(ctx, &s3.PutObjectLockConfigurationInput{
		Bucket: aws.String(bucket),
		ObjectLockConfiguration: &types.ObjectLockConfiguration{ObjectLockEnabled: types.ObjectLockEnabledEnabled,
			Rule: &types.ObjectLockRule{DefaultRetention: &types.DefaultRetention{Mode: types.ObjectLockRetentionMode(mode), Days: aws.Int32(int32(days))}}},
	}, withContentMD5)
	if err != nil {
		return fmt.Errorf("rétention par défaut : %w", explain(err))
	}
	return nil
}

// EnsureUser crée l'utilisateur s'il n'existe pas.
func (c *Client) EnsureUser(ctx context.Context, name string) (bool, error) {
	cl := c.iam()
	if _, err := cl.GetUser(ctx, &iam.GetUserInput{UserName: aws.String(name)}); err == nil {
		return false, nil
	} else if code(err) != "NoSuchEntity" {
		return false, fmt.Errorf("utilisateur %s : %w", name, explain(err))
	}
	if _, err := cl.CreateUser(ctx, &iam.CreateUserInput{UserName: aws.String(name), Path: aws.String("/")}); err != nil {
		return false, fmt.Errorf("création de l'utilisateur %s : %w", name, explain(err))
	}
	return true, nil
}

// PosteUserPolicy : nom de la stratégie en ligne des utilisateurs de poste.
const PosteUserPolicy = "kura-acces-bucket"

// CheckPosteUser vérifie qu'un utilisateur de poste existant n'a pas d'autre droit
// que sa stratégie de poste, et que celle-ci vise bien ce bucket : la console ne
// réutilise jamais un utilisateur qui servirait à autre chose.
func (c *Client) CheckPosteUser(ctx context.Context, user, bucket string) error {
	cl := c.iam()
	pols, err := cl.ListUserPolicies(ctx, &iam.ListUserPoliciesInput{UserName: aws.String(user)})
	if err != nil {
		return fmt.Errorf("stratégies de %s : %w", user, explain(err))
	}
	for _, name := range pols.PolicyNames {
		if name != PosteUserPolicy {
			return fmt.Errorf("%s a une autre stratégie (%s) : utilisateur non créé par la console, à vérifier dans Wasabi", user, name)
		}
		out, err := cl.GetUserPolicy(ctx, &iam.GetUserPolicyInput{UserName: aws.String(user), PolicyName: aws.String(name)})
		if err != nil {
			return fmt.Errorf("stratégie de %s : %w", user, explain(err))
		}
		doc := aws.ToString(out.PolicyDocument)
		if d, err := url.QueryUnescape(doc); err == nil { // IAM renvoie le document encodé en URL
			doc = d
		}
		if b := PosteBucketOf(doc); b != bucket {
			return fmt.Errorf("%s donne déjà accès au bucket %q, pas à %s", user, b, bucket)
		}
	}
	att, err := cl.ListAttachedUserPolicies(ctx, &iam.ListAttachedUserPoliciesInput{UserName: aws.String(user)})
	if err != nil {
		return fmt.Errorf("stratégies attachées à %s : %w", user, explain(err))
	}
	if len(att.AttachedPolicies) > 0 {
		return fmt.Errorf("%s a des stratégies attachées (%s) : utilisateur non créé par la console, à vérifier dans Wasabi",
			user, aws.ToString(att.AttachedPolicies[0].PolicyName))
	}
	groups, err := cl.ListGroupsForUser(ctx, &iam.ListGroupsForUserInput{UserName: aws.String(user)})
	if err != nil {
		return fmt.Errorf("groupes de %s : %w", user, explain(err))
	}
	if len(groups.Groups) > 0 {
		return fmt.Errorf("%s appartient au groupe %s : utilisateur non créé par la console, à vérifier dans Wasabi",
			user, aws.ToString(groups.Groups[0].GroupName))
	}
	return nil
}

// PosteBucketOf renvoie le bucket visé par une stratégie de poste ("" si aucun ou
// plusieurs).
func PosteBucketOf(doc string) string {
	var d struct {
		Statement []struct {
			Resource json.RawMessage `json:"Resource"`
		} `json:"Statement"`
	}
	if json.Unmarshal([]byte(doc), &d) != nil {
		return ""
	}
	found := ""
	for _, st := range d.Statement {
		for _, r := range actions(st.Resource) {
			b := strings.TrimSuffix(strings.TrimPrefix(r, "arn:aws:s3:::"), "/*")
			if b == r || b == "" || strings.ContainsAny(b, "*?/") {
				return ""
			}
			if found != "" && found != b {
				return ""
			}
			found = b
		}
	}
	return found
}

// PutUserPolicy pose (ou remplace) la stratégie en ligne d'un utilisateur.
func (c *Client) PutUserPolicy(ctx context.Context, user, name, doc string) error {
	if _, err := c.iam().PutUserPolicy(ctx, &iam.PutUserPolicyInput{UserName: aws.String(user), PolicyName: aws.String(name), PolicyDocument: aws.String(doc)}); err != nil {
		return fmt.Errorf("stratégie de %s : %w", user, explain(err))
	}
	return nil
}

// CreateAccessKey crée une clé ; le secret n'est connu qu'à cet instant.
func (c *Client) CreateAccessKey(ctx context.Context, user string) (AccessKey, error) {
	out, err := c.iam().CreateAccessKey(ctx, &iam.CreateAccessKeyInput{UserName: aws.String(user)})
	if err != nil {
		return AccessKey{}, fmt.Errorf("création de la clé de %s : %w", user, explain(err))
	}
	k := out.AccessKey
	return AccessKey{ID: aws.ToString(k.AccessKeyId), Secret: aws.ToString(k.SecretAccessKey),
		Active: k.Status == iamtypes.StatusTypeActive, Created: aws.ToTime(k.CreateDate)}, nil
}

// ListAccessKeys liste les clés d'un utilisateur (sans secret).
func (c *Client) ListAccessKeys(ctx context.Context, user string) ([]AccessKey, error) {
	out, err := c.iam().ListAccessKeys(ctx, &iam.ListAccessKeysInput{UserName: aws.String(user)})
	if err != nil {
		if code(err) == "NoSuchEntity" {
			return nil, nil
		}
		return nil, fmt.Errorf("clés de %s : %w", user, explain(err))
	}
	var keys []AccessKey
	for _, k := range out.AccessKeyMetadata {
		keys = append(keys, AccessKey{ID: aws.ToString(k.AccessKeyId), Active: k.Status == iamtypes.StatusTypeActive, Created: aws.ToTime(k.CreateDate)})
	}
	return keys, nil
}

// SetAccessKeyActive active ou désactive une clé.
func (c *Client) SetAccessKeyActive(ctx context.Context, user, id string, active bool) error {
	st := iamtypes.StatusTypeInactive
	if active {
		st = iamtypes.StatusTypeActive
	}
	if _, err := c.iam().UpdateAccessKey(ctx, &iam.UpdateAccessKeyInput{UserName: aws.String(user), AccessKeyId: aws.String(id), Status: st}); err != nil {
		return fmt.Errorf("clé %s : %w", id, explain(err))
	}
	return nil
}

// DeleteAccessKey supprime une clé.
func (c *Client) DeleteAccessKey(ctx context.Context, user, id string) error {
	if _, err := c.iam().DeleteAccessKey(ctx, &iam.DeleteAccessKeyInput{UserName: aws.String(user), AccessKeyId: aws.String(id)}); err != nil {
		return fmt.Errorf("suppression de la clé %s : %w", id, explain(err))
	}
	return nil
}

// AccessKeyLastUsed renvoie la dernière utilisation d'une clé (zéro : jamais).
func (c *Client) AccessKeyLastUsed(ctx context.Context, id string) (time.Time, error) {
	out, err := c.iam().GetAccessKeyLastUsed(ctx, &iam.GetAccessKeyLastUsedInput{AccessKeyId: aws.String(id)})
	if err != nil {
		return time.Time{}, fmt.Errorf("utilisation de la clé %s : %w", id, explain(err))
	}
	if out.AccessKeyLastUsed == nil {
		return time.Time{}, nil
	}
	return aws.ToTime(out.AccessKeyLastUsed.LastUsedDate), nil
}

// --- documents générés --------------------------------------------------------------

type policyDoc struct {
	Version   string      `json:"Version"`
	Statement []statement `json:"Statement"`
}

type statement struct {
	Sid       string                    `json:"Sid"`
	Effect    string                    `json:"Effect"`
	Principal any                       `json:"Principal,omitempty"`
	Action    []string                  `json:"Action"`
	Resource  []string                  `json:"Resource"`
	Condition map[string]map[string]any `json:"Condition,omitempty"`
}

func render(d policyDoc) string {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	_ = enc.Encode(d)
	return strings.TrimSpace(b.String())
}

// ProtectedActions : refusées aux utilisateurs des postes par la stratégie de bucket,
// deuxième barrière si la stratégie d'une clé de poste était trop large.
var ProtectedActions = []string{
	"s3:DeleteObjectVersion",
	"s3:BypassGovernanceRetention",
	"s3:PutObjectRetention",
	"s3:PutLifecycleConfiguration",
	"s3:PutBucketVersioning",
	"s3:PutBucketObjectLockConfiguration",
	"s3:PutBucketPolicy",
	"s3:DeleteBucketPolicy",
	"s3:DeleteBucket",
}

// UserArn : ARN d'un utilisateur IAM du compte.
func UserArn(accountID, user string) string { return "arn:aws:iam::" + accountID + ":user/" + user }

// BucketPolicy génère la stratégie de bucket du modèle :
//   - refus du HTTP non chiffré, à tous (condition aws:SecureTransport, documentée
//     par Wasabi) ;
//   - refus des actions protégées aux seuls utilisateurs des postes de ce bucket,
//     nommés un par un. Pas de refus « à tous sauf la console » : il faudrait une
//     clé de condition sur l'identité (aws:PrincipalArn) que Wasabi ne documente
//     pas, et une clé absente rendrait le refus applicable à tous, console et compte
//     racine compris. Nommer les principaux refusés ne peut, au pire, que ne pas
//     protéger ; jamais enfermer la console hors du bucket.
//
// Sans utilisateur de poste connu, seule la règle HTTPS est générée.
func BucketPolicy(t Template, bucket, accountID string, posteUsers []string) (string, error) {
	if accountID == "" {
		return "", errors.New("stratégie de bucket : numéro de compte inconnu")
	}
	res := []string{"arn:aws:s3:::" + bucket, "arn:aws:s3:::" + bucket + "/*"}
	d := policyDoc{Version: "2012-10-17"}
	if t.DenyInsecureTransport {
		d.Statement = append(d.Statement, statement{Sid: "HTTPSObligatoire", Effect: "Deny", Principal: map[string]string{"AWS": "*"},
			Action: []string{"s3:*"}, Resource: res,
			Condition: map[string]map[string]any{"Bool": {"aws:SecureTransport": "false"}}})
	}
	if t.DenyVersionDeletion && len(posteUsers) > 0 {
		var arns []string
		for _, u := range posteUsers {
			if !strings.HasPrefix(u, "kura-") || strings.HasPrefix(u, "kura-ctl") {
				return "", fmt.Errorf("stratégie de bucket : %q n'est pas un utilisateur de poste", u)
			}
			arns = append(arns, UserArn(accountID, u))
		}
		d.Statement = append(d.Statement, statement{Sid: "PostesSansSuppression", Effect: "Deny", Principal: map[string]any{"AWS": arns},
			Action: ProtectedActions, Resource: res})
	}
	return render(d), nil
}

// PostePolicy génère la stratégie de l'utilisateur d'un poste : lire, écrire et poser
// des marqueurs de suppression dans son seul bucket ; jamais supprimer une version,
// contourner une rétention, régler le bucket ni toucher à IAM (specs §6).
func PostePolicy(bucket string) string {
	return render(policyDoc{Version: "2012-10-17", Statement: []statement{
		{Sid: "ListerSonBucket", Effect: "Allow",
			Action:   []string{"s3:ListBucket", "s3:ListBucketVersions", "s3:GetBucketLocation"},
			Resource: []string{"arn:aws:s3:::" + bucket}},
		{Sid: "LireEcrireSonBucket", Effect: "Allow",
			Action: []string{"s3:GetObject", "s3:GetObjectVersion", "s3:PutObject", "s3:DeleteObject",
				"s3:AbortMultipartUpload", "s3:ListMultipartUploadParts"},
			Resource: []string{"arn:aws:s3:::" + bucket + "/*"}},
	}})
}

// AdminPolicy est la stratégie à donner à l'utilisateur de la console (kura-ctl-admin),
// avec la stratégie gérée WasabiBucketStatsAccess. Seuls les droits dont la console se
// sert : gérer les utilisateurs kura-* et leurs clés, créer un bucket (avec Object
// Lock et versioning, lot 4), lire et écrire les réglages des buckets (stratégie,
// cycle de vie, rétention par défaut). Ni lecture des données, ni suppression de
// bucket, ni contournement de rétention.
//
// Limite à connaître : pouvoir poser la stratégie d'un utilisateur kura-* permet à
// qui détient cette clé de créer un utilisateur aux droits étendus, et poser une
// stratégie de bucket lui permet de s'ouvrir les données. Cette clé vaut donc, si
// elle est volée, un accès étendu au compte : seules les versions verrouillées en
// mode conformité (COMPLIANCE) y résistent. Elle ne vit que chiffrée dans le
// trousseau du poste de l'éditeur.
func AdminPolicy() string {
	return render(policyDoc{Version: "2012-10-17", Statement: []statement{
		{Sid: "SeConnaitre", Effect: "Allow", Action: []string{"iam:GetUser"}, Resource: []string{"*"}},
		{Sid: "GererLesUtilisateursDesPostes", Effect: "Allow",
			Action: []string{"iam:CreateUser", "iam:GetUser", "iam:PutUserPolicy", "iam:GetUserPolicy", "iam:ListUserPolicies",
				"iam:ListAttachedUserPolicies", "iam:ListGroupsForUser",
				"iam:CreateAccessKey", "iam:ListAccessKeys", "iam:UpdateAccessKey", "iam:DeleteAccessKey", "iam:GetAccessKeyLastUsed"},
			Resource: []string{"arn:aws:iam::*:user/kura-*"}},
		{Sid: "PasSurLaConsoleElleMeme", Effect: "Deny",
			Action: []string{"iam:CreateUser", "iam:DeleteUser", "iam:UpdateUser", "iam:PutUserPolicy", "iam:DeleteUserPolicy",
				"iam:AttachUserPolicy", "iam:DetachUserPolicy", "iam:CreateAccessKey", "iam:UpdateAccessKey", "iam:DeleteAccessKey",
				"iam:CreateLoginProfile", "iam:UpdateLoginProfile", "iam:AddUserToGroup"},
			Resource: []string{"arn:aws:iam::*:user/kura-ctl*"}},
		{Sid: "ReglerLesBuckets", Effect: "Allow",
			Action: []string{"s3:ListAllMyBuckets", "s3:CreateBucket", "s3:GetBucketLocation", "s3:GetBucketVersioning", "s3:PutBucketVersioning",
				"s3:GetBucketObjectLockConfiguration", "s3:PutBucketObjectLockConfiguration",
				"s3:GetLifecycleConfiguration", "s3:PutLifecycleConfiguration",
				"s3:GetBucketPolicy", "s3:PutBucketPolicy"},
			Resource: []string{"*"}},
	}})
}

var bucketName = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]*[a-z0-9]$`)

// UserNameFor nomme l'utilisateur du poste qui sauvegarde dans un bucket :
// kura-<bucket>. Un bucket = un utilisateur : les noms de bucket étant uniques dans
// le compte, deux postes ne peuvent pas recevoir le même utilisateur (le second
// retirerait l'accès au premier). Jamais kura-ctl… (réservé à la console), jamais
// tronqué.
func UserNameFor(bucket string) (string, error) {
	if !bucketName.MatchString(bucket) {
		return "", fmt.Errorf("nom de bucket %q inattendu", bucket)
	}
	name := "kura-" + bucket
	if len(name) > 64 {
		return "", fmt.Errorf("nom de bucket trop long pour nommer son utilisateur (%s : 64 caractères au plus)", name)
	}
	if strings.HasPrefix(name, "kura-ctl") {
		return "", fmt.Errorf("nom d'utilisateur %q réservé à la console", name)
	}
	return name, nil
}

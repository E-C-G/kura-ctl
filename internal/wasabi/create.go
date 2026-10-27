package wasabi

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
)

// Region : région de stockage Wasabi.
type Region struct{ Code, Place string }

// Regions : régions de stockage Wasabi (documentation « Service URLs for Wasabi's
// Storage Regions »), Europe d'abord.
var Regions = []Region{
	{"eu-west-2", "Paris"}, {"eu-central-1", "Amsterdam"}, {"eu-central-2", "Francfort"},
	{"eu-west-1", "Royaume-Uni"}, {"eu-west-3", "Royaume-Uni (2)"}, {"eu-south-1", "Milan"},
	{"us-east-1", "Virginie du Nord"}, {"us-east-2", "Virginie du Nord (2)"}, {"us-central-1", "Texas"},
	{"us-west-1", "Oregon"}, {"us-west-2", "San José"}, {"ca-central-1", "Toronto"},
	{"ap-northeast-1", "Tokyo"}, {"ap-northeast-2", "Osaka"}, {"ap-southeast-1", "Singapour"},
	{"ap-southeast-2", "Sydney"},
}

// KnownRegion : code de région Wasabi connu.
func KnownRegion(code string) bool {
	for _, r := range Regions {
		if r.Code == code {
			return true
		}
	}
	return false
}

// CheckNewBucketName vérifie le nom d'un bucket à créer : règles de Wasabi (3 à 63
// caractères, minuscules, chiffres, points et tirets) et nommage de l'utilisateur du
// poste (kura-<bucket>, 64 caractères au plus, jamais kura-ctl…).
func CheckNewBucketName(name string) error {
	switch {
	case len(name) < 3:
		return errors.New("nom de bucket trop court (3 caractères au moins)")
	case !bucketName.MatchString(name) || strings.Contains(name, ".."):
		return fmt.Errorf("nom de bucket %q : minuscules, chiffres, points et tirets, sans commencer ni finir par un point ou un tiret", name)
	case looksLikeIP(name):
		return fmt.Errorf("nom de bucket %q : une adresse IP n'est pas un nom de bucket", name)
	}
	_, err := UserNameFor(name)
	return err
}

func looksLikeIP(name string) bool {
	parts := strings.Split(name, ".")
	if len(parts) != 4 {
		return false
	}
	for _, p := range parts {
		if p == "" || strings.Trim(p, "0123456789") != "" {
			return false
		}
	}
	return true
}

// ErrBucketTaken : le nom est déjà pris (dans ce compte ou chez un autre client de
// Wasabi : les noms de bucket sont uniques pour tout Wasabi).
var ErrBucketTaken = errors.New("nom de bucket déjà pris")

// CreateBucket crée un bucket avec Object Lock (seul moment où il peut être activé ;
// il active aussi le versioning, reposé ensuite explicitement).
func (c *Client) CreateBucket(ctx context.Context, name, region string) error {
	if err := CheckNewBucketName(name); err != nil {
		return err
	}
	if !KnownRegion(region) {
		return fmt.Errorf("région %q inconnue", region)
	}
	in := &s3.CreateBucketInput{Bucket: aws.String(name), ObjectLockEnabledForBucket: aws.Bool(true)}
	if region != "us-east-1" {
		in.CreateBucketConfiguration = &types.CreateBucketConfiguration{LocationConstraint: types.BucketLocationConstraint(region)}
	}
	if _, err := c.s3(region).CreateBucket(ctx, in); err != nil {
		var ae smithy.APIError
		if errors.As(err, &ae) {
			switch ae.ErrorCode() {
			case "BucketAlreadyExists", "BucketAlreadyOwnedByYou":
				return fmt.Errorf("%s : %w", name, ErrBucketTaken)
			case "AccessDenied":
				return errors.New("création refusée : la clé de la console n'a pas le droit s3:CreateBucket (mettre à jour la stratégie kura-ctl-admin, page Réglages)")
			}
		}
		return fmt.Errorf("création du bucket : %w", explain(err))
	}
	_, err := c.s3(region).PutBucketVersioning(ctx, &s3.PutBucketVersioningInput{Bucket: aws.String(name),
		VersioningConfiguration: &types.VersioningConfiguration{Status: types.BucketVersioningStatusEnabled}})
	if err != nil {
		return fmt.Errorf("versioning : %w", explain(err))
	}
	return nil
}

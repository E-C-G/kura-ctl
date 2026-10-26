package wasabi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// StatsURL est l'API Stats de Wasabi.
const StatsURL = "https://stats.wasabisys.com"

// DailyUsage est l'usage d'un bucket un jour donné.
type DailyUsage struct {
	Day            string // YYYY-MM-DD, jour de début de la mesure (UTC)
	RawBytes       int64  // RawStorageSizeBytes
	PaddedBytes    int64  // PaddedStorageSizeBytes : base de la facturation
	DeletedBytes   int64  // DeletedStorageSizeBytes : supprimé avant 90 jours, encore facturé
	Objects        int64  // NumBillableObjects
	DeletedObjects int64  // NumBillableDeletedObjects
	UploadBytes    int64
	DownloadBytes  int64
}

// statsRecord : champs utiles d'un enregistrement de l'API Stats.
type statsRecord struct {
	StartTime                 string `json:"StartTime"`
	Bucket                    string `json:"Bucket"`
	RawStorageSizeBytes       int64  `json:"RawStorageSizeBytes"`
	PaddedStorageSizeBytes    int64  `json:"PaddedStorageSizeBytes"`
	DeletedStorageSizeBytes   int64  `json:"DeletedStorageSizeBytes"`
	NumBillableObjects        int64  `json:"NumBillableObjects"`
	NumBillableDeletedObjects int64  `json:"NumBillableDeletedObjects"`
	UploadBytes               int64  `json:"UploadBytes"`
	DownloadBytes             int64  `json:"DownloadBytes"`
}

type statsPage struct {
	PageInfo struct {
		PageCount int `json:"PageCount"`
		PageNum   int `json:"PageNum"`
	} `json:"PageInfo"`
	Records []statsRecord `json:"Records"`
}

// statsBase est remplaçable dans les tests.
var statsBase = StatsURL

// BucketDaily renvoie l'usage quotidien d'un bucket entre deux dates incluses
// (YYYY-MM-DD), toutes pages confondues. La clé doit avoir le droit de lire les
// statistiques (stratégie WasabiBucketStatsAccess pour un sous-utilisateur).
func (c *Client) BucketDaily(ctx context.Context, bucket, from, to string) ([]DailyUsage, error) {
	var out []DailyUsage
	for page := 0; ; page++ {
		q := url.Values{"from": {from}, "to": {to}, "pageSize": {"100"}, "pageNum": {fmt.Sprint(page)}}
		u := statsBase + "/v1/standalone/utilizations/bucket/" + url.PathEscape(bucket) + "?" + q.Encode()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			return nil, err
		}
		// Format documenté par Wasabi : la clé et son secret, séparés par « : ».
		req.Header.Set("Authorization", c.keys.AccessKeyID+":"+c.keys.SecretAccessKey)
		req.Header.Set("Accept", "application/json")
		resp, err := c.http.Do(req)
		if err != nil {
			var ue *url.Error
			if errors.As(err, &ue) {
				return nil, fmt.Errorf("API Stats injoignable : %v", ue.Err)
			}
			return nil, err
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
		resp.Body.Close()
		if err != nil {
			return nil, err
		}
		switch {
		case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
			return nil, errors.New("API Stats : accès refusé (la clé de la console a-t-elle la stratégie WasabiBucketStatsAccess ?)")
		case resp.StatusCode != http.StatusOK:
			return nil, fmt.Errorf("API Stats : réponse %d : %s", resp.StatusCode, strings.TrimSpace(string(body[:min(len(body), 200)])))
		}
		var p statsPage
		if err := json.Unmarshal(body, &p); err != nil {
			return nil, fmt.Errorf("API Stats : réponse illisible : %w", err)
		}
		for _, r := range p.Records {
			day, err := statsDay(r.StartTime)
			if err != nil {
				return nil, err
			}
			out = append(out, DailyUsage{Day: day, RawBytes: r.RawStorageSizeBytes, PaddedBytes: r.PaddedStorageSizeBytes,
				DeletedBytes: r.DeletedStorageSizeBytes, Objects: r.NumBillableObjects, DeletedObjects: r.NumBillableDeletedObjects,
				UploadBytes: r.UploadBytes, DownloadBytes: r.DownloadBytes})
		}
		if len(p.Records) == 0 || page+1 >= p.PageInfo.PageCount {
			return out, nil
		}
		if page > 1000 {
			return nil, errors.New("API Stats : pagination sans fin")
		}
	}
}

func statsDay(s string) (string, error) {
	for _, layout := range []string{time.RFC3339Nano, "2006-01-02T15:04:05", "2006-01-02 15:04:05", "2006-01-02"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC().Format("2006-01-02"), nil
		}
	}
	return "", fmt.Errorf("API Stats : date %q illisible", s)
}

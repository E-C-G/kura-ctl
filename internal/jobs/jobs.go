// Package jobs regroupe les tâches de fond de la console : relevé des réglages des
// buckets importés (audit des écarts au modèle) et collecte de l'usage quotidien
// par l'API Stats, avec rattrapage des jours manqués pendant que la console était
// fermée. Rien n'est écrit chez Wasabi.
package jobs

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/E-C-G/kura-ctl/internal/store"
	"github.com/E-C-G/kura-ctl/internal/wasabi"
)

// Account est le compte Wasabi vu par la console (wasabi.Client).
type Account interface {
	ListBuckets(ctx context.Context) ([]wasabi.BucketInfo, error)
	ReadSettings(ctx context.Context, name, region string) wasabi.Settings
	BucketDaily(ctx context.Context, bucket, from, to string) ([]wasabi.DailyUsage, error)
}

// History : profondeur de la première collecte d'un bucket importé.
const History = 365 * 24 * time.Hour

// Refetch : jours déjà enregistrés relus à chaque collecte (Wasabi peut recalculer
// la dernière journée après coup).
const Refetch = 2

// Runner exécute les tâches. Il ne vit que tant que la console est déverrouillée.
type Runner struct {
	Store    *store.Store
	Account  Account
	Template wasabi.Template
	Log      *slog.Logger
	Now      func() time.Time

	mu      sync.Mutex
	last    Report
	running bool
}

// Report est le résultat de la dernière actualisation.
type Report struct {
	At      time.Time
	Days    int               // journées d'usage enregistrées
	Errors  map[string]string // par bucket (ou « compte »)
	Running bool
}

func (r *Runner) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

// Last renvoie le dernier rapport (et si une actualisation est en cours).
func (r *Runner) Last() Report {
	r.mu.Lock()
	defer r.mu.Unlock()
	rep := r.last
	rep.Running = r.running
	return rep
}

// ErrBusy : une actualisation est déjà en cours.
var ErrBusy = errors.New("actualisation déjà en cours")

// Refresh relève les réglages et collecte l'usage de tous les buckets importés.
func (r *Runner) Refresh(ctx context.Context) (Report, error) {
	r.mu.Lock()
	if r.running {
		r.mu.Unlock()
		return Report{}, ErrBusy
	}
	r.running = true
	r.mu.Unlock()
	defer func() {
		r.mu.Lock()
		r.running = false
		r.mu.Unlock()
	}()

	rep := Report{At: r.now(), Errors: map[string]string{}}
	buckets, err := r.Store.Buckets(ctx)
	if err != nil {
		return rep, err
	}
	for _, b := range buckets {
		if err := r.AuditBucket(ctx, b.Name, b.Region); err != nil {
			rep.Errors[b.Name] = err.Error()
		}
		n, err := r.CollectBucket(ctx, b.Name)
		rep.Days += n
		if err != nil {
			if prev := rep.Errors[b.Name]; prev != "" {
				rep.Errors[b.Name] = prev + " ; " + err.Error()
			} else {
				rep.Errors[b.Name] = err.Error()
			}
		}
	}
	r.mu.Lock()
	r.last = rep
	r.mu.Unlock()
	return rep, nil
}

// AuditBucket relève les réglages d'un bucket et enregistre les écarts au modèle.
func (r *Runner) AuditBucket(ctx context.Context, name, region string) error {
	s := r.Account.ReadSettings(ctx, name, region)
	dev := r.Template.Audit(s)
	sj, _ := json.Marshal(s)
	dj, _ := json.Marshal(dev)
	errText := ""
	if len(s.ReadErrors) > 0 {
		errText = fmt.Sprintf("%d réglage(s) illisible(s)", len(s.ReadErrors))
	}
	if err := r.Store.SaveBucketAudit(ctx, name, string(sj), string(dj), errText); err != nil {
		return err
	}
	result := store.ResultOK
	if errText != "" {
		result = store.ResultError
	}
	_ = r.Store.Audit(ctx, "relevé des réglages", name, result, fmt.Sprintf("%d écart(s) au modèle %s", len(dev), r.Template.Name))
	if errText != "" {
		return errors.New(errText)
	}
	return nil
}

// CollectBucket récupère l'usage quotidien manquant d'un bucket et renvoie le nombre
// de journées enregistrées. Première collecte : un an d'historique.
func (r *Runner) CollectBucket(ctx context.Context, name string) (int, error) {
	today := r.now().UTC()
	last, err := r.Store.LastUsageDay(ctx, name)
	if err != nil {
		return 0, err
	}
	from := today.Add(-History)
	if last != "" {
		if t, err := time.Parse("2006-01-02", last); err == nil {
			from = t.AddDate(0, 0, -(Refetch - 1))
		}
	}
	f, to := from.Format("2006-01-02"), today.Format("2006-01-02")
	days, err := r.Account.BucketDaily(ctx, name, f, to)
	if err != nil {
		_ = r.Store.Audit(ctx, "collecte de l'usage", name, store.ResultError, err.Error())
		return 0, err
	}
	rows := make([]store.Usage, 0, len(days))
	for _, d := range days {
		rows = append(rows, store.Usage{Bucket: name, Day: d.Day, ActiveBytes: d.RawBytes, PaddedBytes: d.PaddedBytes,
			DeletedBytes: d.DeletedBytes, Objects: d.Objects, DeletedObjects: d.DeletedObjects,
			UploadBytes: d.UploadBytes, DownloadBytes: d.DownloadBytes})
	}
	if err := r.Store.UpsertUsage(ctx, rows); err != nil {
		return 0, err
	}
	_ = r.Store.Audit(ctx, "collecte de l'usage", name, store.ResultOK, fmt.Sprintf("%d journée(s) du %s au %s", len(rows), f, to))
	return len(rows), nil
}

// Loop actualise tout de suite, puis toutes les 24 h, jusqu'à la fin de ctx.
func (r *Runner) Loop(ctx context.Context, every time.Duration) {
	for {
		if rep, err := r.Refresh(ctx); err != nil && !errors.Is(err, ErrBusy) {
			r.Log.Warn("actualisation", "err", err)
		} else if len(rep.Errors) > 0 {
			r.Log.Warn("actualisation incomplète", "erreurs", rep.Errors)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(every):
		}
	}
}

package monitor

import (
	"context"
	"fmt"
	"time"
)

// KVMetadataTarget describes a KV v2 secret to inspect.
type KVMetadataTarget struct {
	Mount string
	Path  string
}

// kvMetadataChecker is the interface satisfied by vault.KVMetadataChecker.
type kvMetadataChecker interface {
	GetMetadata(mount, path string) (interface{ GetMaxVersions() int; GetCurrentVersion() int }, error)
}

// kvMetaGetter is a minimal interface for the checker used in this job.
type kvMetaGetter interface {
	GetMetadata(mount, path string) (kvMetaResult, error)
}

type kvMetaResult interface {
	MaxVers() int
	CurrentVer() int
	Updated() time.Time
}

// KVMetadataJob monitors KV v2 secret metadata for stale or uncapped secrets.
type KVMetadataJob struct {
	checker  kvMetaFetcher
	targets  []KVMetadataTarget
	notifier alertSink
	maxVersionsThreshold int
	staleDays            int
}

type kvMetaFetcher interface {
	GetMetadata(mount, path string) (kvMetaInfo, error)
}

type kvMetaInfo struct {
	CurrentVersion int
	MaxVersions    int
	UpdatedTime    time.Time
}

// NewKVMetadataJob creates a job that checks KV v2 metadata.
func NewKVMetadataJob(checker kvMetaFetcher, targets []KVMetadataTarget, notifier alertSink, maxVersionsThreshold, staleDays int) *KVMetadataJob {
	return &KVMetadataJob{
		checker:              checker,
		targets:              targets,
		notifier:             notifier,
		maxVersionsThreshold: maxVersionsThreshold,
		staleDays:            staleDays,
	}
}

// Run executes the metadata checks for all targets.
func (j *KVMetadataJob) Run(ctx context.Context) error {
	for _, t := range j.targets {
		meta, err := j.checker.GetMetadata(t.Mount, t.Path)
		if err != nil {
			continue
		}
		if j.maxVersionsThreshold > 0 && meta.MaxVersions < j.maxVersionsThreshold {
			j.notifier.Send(Alert{
				Level:   LevelWarning,
				Message: fmt.Sprintf("KV secret %s/%s has max_versions=%d below threshold %d", t.Mount, t.Path, meta.MaxVersions, j.maxVersionsThreshold),
			})
		}
		if j.staleDays > 0 && !meta.UpdatedTime.IsZero() {
			age := time.Since(meta.UpdatedTime)
			if age > time.Duration(j.staleDays)*24*time.Hour {
				j.notifier.Send(Alert{
					Level:   LevelWarning,
					Message: fmt.Sprintf("KV secret %s/%s has not been updated in %d days", t.Mount, t.Path, int(age.Hours()/24)),
				})
			}
		}
	}
	return nil
}

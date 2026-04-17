package monitor_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/yourusername/vaultwatch/internal/monitor"
)

type stubKVMetaFetcher struct {
	info monitor.KVMetaInfoExport
	err  error
}

func (s *stubKVMetaFetcher) GetMetadata(mount, path string) (monitor.KVMetaInfoExport, error) {
	return s.info, s.err
}

func kvMetaJobWithStub(fetcher *stubKVMetaFetcher, targets []monitor.KVMetadataTarget, sink *collectingSink) *monitor.KVMetadataJob {
	return monitor.NewKVMetadataJob(fetcher, targets, sink, 5, 30)
}

func TestKVMetadataJob_NoAlertWhenHealthy(t *testing.T) {
	fetcher := &stubKVMetaFetcher{info: monitor.KVMetaInfoExport{
		CurrentVersion: 2,
		MaxVersions:    10,
		UpdatedTime:    time.Now().Add(-5 * 24 * time.Hour),
	}}
	sink := &collectingSink{}
	targets := []monitor.KVMetadataTarget{{Mount: "secret", Path: "app/db"}}
	job := kvMetaJobWithStub(fetcher, targets, sink)
	_ = job.Run(context.Background())
	if len(sink.alerts) != 0 {
		t.Errorf("expected no alerts, got %d", len(sink.alerts))
	}
}

func TestKVMetadataJob_AlertWhenMaxVersionsBelowThreshold(t *testing.T) {
	fetcher := &stubKVMetaFetcher{info: monitor.KVMetaInfoExport{
		CurrentVersion: 1,
		MaxVersions:    2,
		UpdatedTime:    time.Now(),
	}}
	sink := &collectingSink{}
	targets := []monitor.KVMetadataTarget{{Mount: "secret", Path: "app/db"}}
	job := kvMetaJobWithStub(fetcher, targets, sink)
	_ = job.Run(context.Background())
	if len(sink.alerts) == 0 {
		t.Fatal("expected alert for low max_versions")
	}
	if !strings.Contains(sink.alerts[0].Message, "max_versions") {
		t.Errorf("unexpected message: %s", sink.alerts[0].Message)
	}
}

func TestKVMetadataJob_AlertWhenStale(t *testing.T) {
	fetcher := &stubKVMetaFetcher{info: monitor.KVMetaInfoExport{
		CurrentVersion: 1,
		MaxVersions:    10,
		UpdatedTime:    time.Now().Add(-60 * 24 * time.Hour),
	}}
	sink := &collectingSink{}
	targets := []monitor.KVMetadataTarget{{Mount: "secret", Path: "old/creds"}}
	job := kvMetaJobWithStub(fetcher, targets, sink)
	_ = job.Run(context.Background())
	if len(sink.alerts) == 0 {
		t.Fatal("expected stale alert")
	}
}

package monitor

import (
	"context"
	"errors"
	"testing"

	"github.com/yourusername/vaultwatch/internal/vault"
)

type stubAuditLister struct {
	devices []vault.AuditDevice
	err     error
}

func (s *stubAuditLister) ListAuditDevices(_ context.Context) ([]vault.AuditDevice, error) {
	return s.devices, s.err
}

type captureAuditSender struct {
	alerts []Alert
}

func (c *captureAuditSender) Send(_ context.Context, a Alert) error {
	c.alerts = append(c.alerts, a)
	return nil
}

func TestAuditJob_NoAlertWhenDevicesPresent(t *testing.T) {
	lister := &stubAuditLister{
		devices: []vault.AuditDevice{
			{Path: "file/", Type: "file", Enabled: true},
		},
	}
	sender := &captureAuditSender{}
	job := NewAuditJob(lister, sender)
	job.Run(context.Background())

	if len(sender.alerts) != 0 {
		t.Errorf("expected no alerts, got %d", len(sender.alerts))
	}
}

func TestAuditJob_AlertWhenNoDevices(t *testing.T) {
	lister := &stubAuditLister{devices: []vault.AuditDevice{}}
	sender := &captureAuditSender{}
	job := NewAuditJob(lister, sender)
	job.Run(context.Background())

	if len(sender.alerts) != 1 {
		t.Fatalf("expected 1 alert, got %d", len(sender.alerts))
	}
	if sender.alerts[0].Level != Critical {
		t.Errorf("expected Critical alert, got %v", sender.alerts[0].Level)
	}
}

func TestAuditJob_SkipsAlertOnListerError(t *testing.T) {
	lister := &stubAuditLister{err: errors.New("vault unreachable")}
	sender := &captureAuditSender{}
	job := NewAuditJob(lister, sender)
	job.Run(context.Background())

	if len(sender.alerts) != 0 {
		t.Errorf("expected no alerts on error, got %d", len(sender.alerts))
	}
}

package reporter

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/vaultwatch/internal/monitor"
	"github.com/vaultwatch/internal/monitor/lease"
)

func makeAlert(path string, severity monitor.Severity, secondsRemaining int, msg string) monitor.Alert {
	expiry := time.Now().Add(time.Duration(secondsRemaining) * time.Second)
	return monitor.Alert{
		Lease:    lease.Lease{Path: path, Expiry: expiry},
		Severity: severity,
		Message:  msg,
	}
}

func TestNew_DefaultsToStdout(t *testing.T) {
	r := New(nil, FormatTable)
	if r.out == nil {
		t.Fatal("expected non-nil writer")
	}
}

func TestWriteTable_ContainsHeaders(t *testing.T) {
	var buf bytes.Buffer
	r := New(&buf, FormatTable)
	alerts := []monitor.Alert{
		makeAlert("secret/db", monitor.SeverityWarning, 3600, "expiring soon"),
	}
	if err := r.Write(alerts); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()
	for _, expected := range []string{"PATH", "STATUS", "TIME REMAINING", "MESSAGE", "secret/db", "warning"} {
		if !strings.Contains(out, expected) {
			t.Errorf("expected output to contain %q, got:\n%s", expected, out)
		}
	}
}

func TestWriteJSON_ContainsFields(t *testing.T) {
	var buf bytes.Buffer
	r := New(&buf, FormatJSON)
	alerts := []monitor.Alert{
		makeAlert("secret/api", monitor.SeverityCritical, 300, "critical expiry"),
	}
	if err := r.Write(alerts); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()
	for _, expected := range []string{"secret/api", "critical", "critical expiry"} {
		if !strings.Contains(out, expected) {
			t.Errorf("expected JSON to contain %q, got:\n%s", expected, out)
		}
	}
}

func TestFormatDuration_Expired(t *testing.T) {
	result := formatDuration(-1 * time.Second)
	if result != "expired" {
		t.Errorf("expected 'expired', got %q", result)
	}
}

func TestFormatDuration_HoursMinutesSeconds(t *testing.T) {
	d := 2*time.Hour + 15*time.Minute + 30*time.Second
	result := formatDuration(d)
	if result != "2h15m30s" {
		t.Errorf("expected '2h15m30s', got %q", result)
	}
}

func TestFormatDuration_MinutesSeconds(t *testing.T) {
	d := 5*time.Minute + 45*time.Second
	result := formatDuration(d)
	if result != "5m45s" {
		t.Errorf("expected '5m45s', got %q", result)
	}
}

func TestWriteTable_EmptyAlerts(t *testing.T) {
	var buf bytes.Buffer
	r := New(&buf, FormatTable)
	if err := r.Write([]monitor.Alert{}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(buf.String(), "PATH") {
		t.Error("expected headers even with empty alerts")
	}
}

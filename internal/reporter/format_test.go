package reporter

import (
	"testing"
	"time"
)

func TestFormatDuration_SecondsOnly(t *testing.T) {
	tests := []struct {
		name     string
		input    time.Duration
		expected string
	}{
		{"zero", 0, "expired"},
		{"negative", -5 * time.Second, "expired"},
		{"seconds only", 45 * time.Second, "45s"},
		{"one minute", 60 * time.Second, "1m0s"},
		{"one hour", 3600 * time.Second, "1h0m0s"},
		{"complex", 3*time.Hour + 7*time.Minute + 9*time.Second, "3h7m9s"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := formatDuration(tt.input)
			if got != tt.expected {
				t.Errorf("formatDuration(%v) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}

func TestFormat_Constants(t *testing.T) {
	if FormatTable != "table" {
		t.Errorf("expected FormatTable to be 'table', got %q", FormatTable)
	}
	if FormatJSON != "json" {
		t.Errorf("expected FormatJSON to be 'json', got %q", FormatJSON)
	}
}

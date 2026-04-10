package reporter

import (
	"fmt"
	"io"
	"os"
	"text/tabwriter"
	"time"

	"github.com/vaultwatch/internal/monitor"
)

// Format represents the output format for the report.
type Format string

const (
	FormatTable Format = "table"
	FormatJSON  Format = "json"
)

// Reporter writes lease status reports to an output writer.
type Reporter struct {
	out    io.Writer
	format Format
}

// New creates a new Reporter with the given format.
// If out is nil, os.Stdout is used.
func New(out io.Writer, format Format) *Reporter {
	if out == nil {
		out = os.Stdout
	}
	return &Reporter{out: out, format: format}
}

// Write renders the provided alerts to the reporter's output.
func (r *Reporter) Write(alerts []monitor.Alert) error {
	switch r.format {
	case FormatJSON:
		return r.writeJSON(alerts)
	default:
		return r.writeTable(alerts)
	}
}

func (r *Reporter) writeTable(alerts []monitor.Alert) error {
	w := tabwriter.NewWriter(r.out,, ' ', 0)
	fmt.Fprintln(w, "PATH\tSTATUS\tTIME REMAINING\tMESSAGE")
	fmt.Fprintln(w, "----\t------\t--------------\t-------")
	for _, a := range alerts {
		remaining := formatDuration(a.Lease.TimeRemaining())
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n",
			a.Lease.Path,
			a.Severity,
			remaining,
			a.Message,
		)
	}
	return w.Flush()
}

func (r *Reporter) writeJSON(alerts []monitor.Alert) error {
	fmt.Fprintln(r.out, "[")
	for i, a := range alerts {
		comma := ","
		if i == len(alerts)-1 {
			comma = ""
		}
		remaining := a.Lease.TimeRemaining()
		fmt.Fprintf(r.out, "  {\"path\":%q,\"severity\":%q,\"remaining_seconds\":%d,\"message\":%q}%s\n",
			a.Lease.Path,
			a.Severity,
			int(remaining.Seconds()),
			a.Message,
			comma,
		)
	}
	fmt.Fprintln(r.out, "]")
	return nil
}

func formatDuration(d time.Duration) string {
	if d <= 0 {
		return "expired"
	}
	h := int(d.Hours())
	m := int(d.Minutes()) % 60
	s := int(d.Seconds()) % 60
	if h > 0 {
		return fmt.Sprintf("%dh%dm%ds", h, m, s)
	}
	if m > 0 {
		return fmt.Sprintf("%dm%ds", m, s)
	}
	return fmt.Sprintf("%ds", s)
}

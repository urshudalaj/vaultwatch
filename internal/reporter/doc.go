// Package reporter provides formatted output for Vault lease alert reports.
//
// It supports multiple output formats (table and JSON) and writes
// alert summaries — including lease path, severity, time remaining,
// and descriptive message — to any io.Writer.
//
// Usage:
//
//	r := reporter.New(os.Stdout, reporter.FormatTable)
//	if err := r.Write(alerts); err != nil {
//		log.Fatal(err)
//	}
package reporter

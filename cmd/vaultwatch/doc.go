// Package main is the entry point for the vaultwatch CLI tool.
//
// vaultwatch connects to a HashiCorp Vault instance, scans configured
// secret paths for expiring leases, and sends alerts via the configured
// notification channels (log, Slack, etc.) before leases expire.
//
// Configuration is driven by environment variables or a YAML config file.
// See internal/config for available options.
//
// Usage:
//
//	vaultwatch [options]
//
// Flags:
//
//	-version   Print the current version and exit.
//	-help      Print usage information and exit.
package main

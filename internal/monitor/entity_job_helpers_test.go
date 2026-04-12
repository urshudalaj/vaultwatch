package monitor_test

import "github.com/yourusername/vaultwatch/internal/monitor"

// VaultEntityInfo is re-exported via the monitor package for test stubs.
// This file provides any shared helpers for entity job tests.

var _ monitor.EntityJobChecker = (*stubEntityChecker)(nil)

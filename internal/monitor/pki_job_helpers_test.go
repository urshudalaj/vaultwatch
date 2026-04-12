package monitor_test

import "github.com/yourusername/vaultwatch/internal/monitor"

// Ensure stubPKIChecker satisfies the interface at compile time.
var _ monitor.PKIRoleGetter = (*stubPKIChecker)(nil)

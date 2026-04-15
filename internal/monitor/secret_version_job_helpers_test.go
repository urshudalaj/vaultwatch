package monitor

import "github.com/user/vaultwatch/internal/vault"

// Ensure stubSecretVersionChecker satisfies SecretVersionInfoer at compile time.
var _ SecretVersionInfoer = (*stubSecretVersionChecker)(nil)

// Ensure SecretVersionInfo is imported (used in test stubs).
var _ = vault.SecretVersionInfo{}

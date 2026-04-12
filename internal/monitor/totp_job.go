package monitor

import (
	"context"
	"fmt"

	"github.com/yourusername/vaultwatch/internal/vault"
)

// TOTPKeyTarget identifies a TOTP key to inspect.
type TOTPKeyTarget struct {
	Mount   string
	KeyName string
}

// totpKeyGetter abstracts the vault.TOTPChecker for testing.
type totpKeyGetter interface {
	GetKey(mount, keyName string) (*vault.TOTPKey, error)
}

// NewTOTPJob returns a RunnerFunc that checks TOTP key configuration.
// It raises a warning alert when a key has a non-standard period (not 30s)
// or uses a weak algorithm (not SHA1/SHA256/SHA512).
func NewTOTPJob(checker totpKeyGetter, targets []TOTPKeyTarget, send func(Alert)) func(context.Context) error {
	validAlgorithms := map[string]bool{
		"SHA1": true, "SHA256": true, "SHA512": true,
	}
	return func(_ context.Context) error {
		for _, t := range targets {
			key, err := checker.GetKey(t.Mount, t.KeyName)
			if err != nil {
				send(Alert{
					Level:   Critical,
					Message: fmt.Sprintf("totp: failed to read key %s/%s: %v", t.Mount, t.KeyName, err),
				})
				continue
			}
			if key.Period != 30 {
				send(Alert{
					Level:   Warning,
					Message: fmt.Sprintf("totp: key %s/%s has non-standard period %ds (expected 30)", t.Mount, t.KeyName, key.Period),
				})
			}
			if !validAlgorithms[key.Algorithm] {
				send(Alert{
					Level:   Warning,
					Message: fmt.Sprintf("totp: key %s/%s uses unrecognised algorithm %q", t.Mount, t.KeyName, key.Algorithm),
				})
			}
		}
		return nil
	}
}

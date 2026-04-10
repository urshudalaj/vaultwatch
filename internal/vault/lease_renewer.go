package vault

import (
	"context"
	"fmt"
	"time"

	vaultapi "github.com/hashicorp/vault/api"
)

// RenewResult holds the outcome of a lease renewal attempt.
type RenewResult struct {
	LeaseID   string
	RenewedAt time.Time
	NewTTL    time.Duration
	Err       error
}

// LeaseRenewer handles renewal of Vault leases.
type LeaseRenewer struct {
	client *vaultapi.Client
}

// NewLeaseRenewer creates a LeaseRenewer backed by the given Vault client.
func NewLeaseRenewer(c *Client) *LeaseRenewer {
	return &LeaseRenewer{client: c.underlying}
}

// Renew attempts to renew the given leaseID by the requested increment.
// If increment is zero, Vault uses the default TTL for the lease.
func (r *LeaseRenewer) Renew(ctx context.Context, leaseID string, increment time.Duration) RenewResult {
	if leaseID == "" {
		return RenewResult{Err: fmt.Errorf("leaseID must not be empty")}
	}

	incrementSecs := int(increment.Seconds())

	secret, err := r.client.Sys().RenewWithContext(ctx, leaseID, incrementSecs)
	if err != nil {
		return RenewResult{LeaseID: leaseID, Err: fmt.Errorf("renew lease %q: %w", leaseID, err)}
	}

	var newTTL time.Duration
	if secret != nil {
		newTTL = time.Duration(secret.LeaseDuration) * time.Second
	}

	return RenewResult{
		LeaseID:   leaseID,
		RenewedAt: time.Now(),
		NewTTL:    newTTL,
	}
}

// RenewMany renews multiple leases concurrently and returns a result per lease.
func (r *LeaseRenewer) RenewMany(ctx context.Context, leaseIDs []string, increment time.Duration) []RenewResult {
	results := make([]RenewResult, len(leaseIDs))
	ch := make(chan struct {
		idx int
		res RenewResult
	}, len(leaseIDs))

	for i, id := range leaseIDs {
		go func(idx int, leaseID string) {
			ch <- struct {
				idx int
				res RenewResult
			}{idx, r.Renew(ctx, leaseID, increment)}
		}(i, id)
	}

	for range leaseIDs {
		v := <-ch
		results[v.idx] = v.res
	}
	return results
}

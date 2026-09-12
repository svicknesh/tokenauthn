// Package tokenauthn implements a small, secure library for issuing,
// verifying, and revoking opaque, stateful HMAC-SHA3-256 bearer tokens.
//
// tokenauthn is independent of any HTTP framework, CLI framework, or
// deployment mechanism. Callers supply the master secret and a Store
// implementation; tokenauthn owns the cryptographic construction, wire
// format, and verification logic only. See README.md for the threat model,
// wire format, and worked examples.
//
// V1's MAC construction is HMAC-SHA3-256, a deliberate algorithm choice
// locked in before tokenauthn's first release — it is not a fix for a
// weakness in HMAC-SHA-256, which was never externally released. The V1
// wire format is cryptographically tied to this specific construction;
// changing the hash algorithm after release would require an intentional
// new format version (see the "Versioning and compatibility" section of
// README.md).
package tokenauthn

import (
	"context"
	"crypto/hmac"
	"fmt"
	"time"
)

// minSecretSize is the minimum length, in bytes, of master secret key
// material accepted by NewAuthenticator. Anything shorter is rejected.
const minSecretSize = 32

// Authenticator mints, verifies, and revokes opaque bearer tokens against a
// caller-supplied master secret and Store. An Authenticator is safe for
// concurrent use by multiple goroutines as long as its Store is.
type Authenticator struct {
	secret []byte
	store  Store
}

// NewAuthenticator constructs an Authenticator. secret is the master key
// material used to derive every token MAC; it must be at least
// minSecretSize (32) bytes. NewAuthenticator copies secret internally, so
// mutating the caller's original slice afterwards has no effect on the
// returned Authenticator. store is the caller-supplied persistence
// implementation and must not be nil.
//
// The master secret is never read from an environment variable, file, or
// any other implicit source by this library — the caller is always
// responsible for supplying and protecting it.
func NewAuthenticator(secret []byte, store Store) (a *Authenticator, err error) {
	if len(secret) < minSecretSize {
		return nil, fmt.Errorf("newauthenticator: master secret must be at least %d bytes, got %d", minSecretSize, len(secret))
	}
	if store == nil {
		return nil, fmt.Errorf("newauthenticator: store cannot be nil")
	}

	a = new(Authenticator)
	a.secret = append([]byte(nil), secret...) // copy: caller mutation of their slice must not affect us
	a.store = store

	return a, nil
}

// Mint issues a new bearer token with no expiry. It generates a fresh
// token ID and token seed from crypto/rand, derives the token's MAC,
// persists the verification record via the configured Store, and returns
// the bearer token string only after persistence succeeds. If persistence
// fails, no token is returned.
//
// If the randomly generated token ID collides with an existing record (this
// is expected to be extremely rare given the 128-bit ID space), the
// returned error wraps ErrTokenIDExists. Mint does not retry automatically;
// callers may call Mint again to generate a fresh ID.
func (a *Authenticator) Mint(ctx context.Context) (token string, id TokenID, err error) {
	return a.mint(ctx, time.Time{})
}

// MintWithExpiry issues a new bearer token like Mint, but the record
// expires ttl after the call. ttl must be positive. A token that has passed
// its expiry is treated identically to any other invalid credential by
// Verify (see ErrInvalidToken).
func (a *Authenticator) MintWithExpiry(ctx context.Context, ttl time.Duration) (token string, id TokenID, err error) {
	if ttl <= 0 {
		return "", TokenID{}, fmt.Errorf("mintwithexpiry: ttl must be positive, got %s", ttl)
	}
	return a.mint(ctx, time.Now().Add(ttl))
}

func (a *Authenticator) mint(ctx context.Context, expiresAt time.Time) (token string, id TokenID, err error) {
	id, err = generateTokenID()
	if err != nil {
		return "", TokenID{}, fmt.Errorf("mint: %w", err)
	}

	seed, err := generateTokenSeed()
	if err != nil {
		return "", TokenID{}, fmt.Errorf("mint: %w", err)
	}

	mac := computeMAC(a.secret, id[:], seed)

	record := &Record{
		TokenID:   id,
		TokenSeed: seed,
		CreatedAt: time.Now(),
		ExpiresAt: expiresAt,
	}

	if err = a.store.Create(ctx, record); err != nil {
		return "", TokenID{}, fmt.Errorf("mint: create record -> %w", err)
	}

	return encodeBearerToken(id, mac), id, nil
}

// Verify strictly parses bearerToken, loads its record via the configured
// Store, and returns the token's TokenID only if every check passes:
// well-formed V1 wire format, a known and non-revoked (and non-expired, if
// an expiry was set) record, and a MAC that matches exactly under
// constant-time comparison.
//
// Every credential-shaped failure — malformed input, unknown version,
// unknown token ID, revoked record, expired record, or a bad MAC — returns
// the single sentinel ErrInvalidToken (use errors.Is to check). Callers
// must not attempt to distinguish these cases; doing so creates an oracle
// for an attacker probing the endpoint.
//
// A Store failure that is not "record not found" is returned wrapped, and
// is distinguishable from ErrInvalidToken via errors.Is — callers should
// treat it as an operational failure, not as a rejected credential.
func (a *Authenticator) Verify(ctx context.Context, bearerToken string) (id TokenID, err error) {
	id, mac, err := parseBearerToken(bearerToken)
	if err != nil {
		return TokenID{}, err
	}

	record, err := a.store.Load(ctx, id)
	if err != nil {
		if isNotFound(err) {
			return TokenID{}, ErrInvalidToken
		}
		return TokenID{}, fmt.Errorf("verify: load record -> %w", err)
	}

	if record.Revoked {
		return TokenID{}, ErrInvalidToken
	}

	if !record.ExpiresAt.IsZero() && time.Now().After(record.ExpiresAt) {
		return TokenID{}, ErrInvalidToken
	}

	expectedMAC := computeMAC(a.secret, id[:], record.TokenSeed)
	if !hmac.Equal(mac, expectedMAC) {
		return TokenID{}, ErrInvalidToken
	}

	return id, nil
}

// Revoke marks the record for id as revoked via the configured Store. It
// does not delete the record; retaining revocation metadata is the Store
// implementation's concern. A token that verified successfully before
// Revoke returns will fail Verify (with ErrInvalidToken) as soon as the
// Store reflects the revocation.
func (a *Authenticator) Revoke(ctx context.Context, id TokenID) (err error) {
	if err = a.store.Revoke(ctx, id); err != nil {
		return fmt.Errorf("revoke: %w", err)
	}
	return nil
}

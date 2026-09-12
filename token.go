package tokenauthn

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
)

const (
	// tokenIDSize is the length in bytes of a token ID (128 bits).
	tokenIDSize = 16

	// tokenSeedSize is the length in bytes of a token seed (256 bits).
	tokenSeedSize = 32
)

// TokenID is the opaque identifier for a minted token. It is safe to use as
// a store lookup key and to include in logs — unlike the token seed, the MAC,
// or the bearer token string, a token ID alone does not allow forging or
// verifying a token.
type TokenID [tokenIDSize]byte

// String returns the canonical lowercase hex encoding of id.
func (id TokenID) String() string {
	return hex.EncodeToString(id[:])
}

// generateTokenID returns a new token ID sourced from crypto/rand.
func generateTokenID() (id TokenID, err error) {
	if _, err = rand.Read(id[:]); err != nil {
		return TokenID{}, fmt.Errorf("generatetokenid: read random bytes -> %w", err)
	}
	return id, nil
}

// generateTokenSeed returns new per-token verification material sourced from
// crypto/rand. The seed is server-side-only: it is bound into the MAC but
// never included in the bearer token string, never logged, and never
// returned to the caller after Mint.
func generateTokenSeed() (seed []byte, err error) {
	seed = make([]byte, tokenSeedSize)
	if _, err = rand.Read(seed); err != nil {
		return nil, fmt.Errorf("generatetokenseed: read random bytes -> %w", err)
	}
	return seed, nil
}

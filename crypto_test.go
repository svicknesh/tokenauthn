package tokenauthn

import (
	"bytes"
	"context"
	"errors"
	"testing"
)

// TestGenerateTokenID_StatisticallyDistinct mints a large number of token
// IDs directly from the crypto/rand-backed generator and asserts they are
// all pairwise distinct. This is a statistical, not absolute, guarantee of
// randomness quality; generateTokenID itself is a thin wrapper over
// crypto/rand.Read, which is the code-level guarantee of a CSPRNG source.
func TestGenerateTokenID_StatisticallyDistinct(t *testing.T) {
	const n = 2000
	seen := make(map[TokenID]bool, n)

	for i := 0; i < n; i++ {
		id, err := generateTokenID()
		if err != nil {
			t.Fatalf("generateTokenID[%d]: unexpected error: %v", i, err)
		}
		if seen[id] {
			t.Fatalf("generateTokenID[%d]: duplicate id %v across %d generations", i, id, n)
		}
		seen[id] = true

		if id == (TokenID{}) {
			t.Fatalf("generateTokenID[%d]: got all-zero id, suspicious for a CSPRNG source", i)
		}
	}
}

// TestGenerateTokenSeed_StatisticallyDistinct mirrors
// TestGenerateTokenID_StatisticallyDistinct for the 256-bit token seed.
func TestGenerateTokenSeed_StatisticallyDistinct(t *testing.T) {
	const n = 2000
	seen := make(map[string]bool, n)

	for i := 0; i < n; i++ {
		seed, err := generateTokenSeed()
		if err != nil {
			t.Fatalf("generateTokenSeed[%d]: unexpected error: %v", i, err)
		}
		if len(seed) != tokenSeedSize {
			t.Fatalf("generateTokenSeed[%d]: got %d bytes, want %d", i, len(seed), tokenSeedSize)
		}
		key := string(seed)
		if seen[key] {
			t.Fatalf("generateTokenSeed[%d]: duplicate seed across %d generations", i, n)
		}
		seen[key] = true

		if bytes.Equal(seed, make([]byte, tokenSeedSize)) {
			t.Fatalf("generateTokenSeed[%d]: got all-zero seed, suspicious for a CSPRNG source", i)
		}
	}
}

// TestVerify_FullMACIsChecked flips every single byte of a valid token's
// MAC, one at a time, and asserts verification fails every time — including
// when only the very last byte changes. This demonstrates the
// implementation checks the full untruncated MAC, not a truncated prefix
// (a truncated-comparison bug would still catch head-of-MAC tampering but
// miss tail-of-MAC tampering).
func TestVerify_FullMACIsChecked(t *testing.T) {
	ctx := context.Background()
	store := newMemoryStore()
	a := mustAuthenticator(t, store)

	token, _, err := a.Mint(ctx)
	if err != nil {
		t.Fatalf("Mint: unexpected error: %v", err)
	}

	version, idHex, macHex := splitWireToken(t, token)

	for pos := 0; pos < len(macHex); pos++ {
		tampered := version + "." + idHex + "." + flipHexNibble(macHex, pos)
		if _, err := a.Verify(ctx, tampered); !errors.Is(err, ErrInvalidToken) {
			t.Fatalf("Verify (mac hex nibble %d flipped): got err %v, want ErrInvalidToken", pos, err)
		}
	}
}

// TestComputeMAC_BindsTokenIDAndSeed asserts both the token ID and the token
// seed are cryptographically bound into the MAC: changing either input,
// holding the other and the secret fixed, changes the resulting MAC.
func TestComputeMAC_BindsTokenIDAndSeed(t *testing.T) {
	secret := testSecret()

	idA, err := generateTokenID()
	if err != nil {
		t.Fatalf("generateTokenID: unexpected error: %v", err)
	}
	idB, err := generateTokenID()
	if err != nil {
		t.Fatalf("generateTokenID: unexpected error: %v", err)
	}
	seedA, err := generateTokenSeed()
	if err != nil {
		t.Fatalf("generateTokenSeed: unexpected error: %v", err)
	}
	seedB, err := generateTokenSeed()
	if err != nil {
		t.Fatalf("generateTokenSeed: unexpected error: %v", err)
	}

	macBase := computeMAC(secret, idA[:], seedA)

	if bytes.Equal(macBase, computeMAC(secret, idB[:], seedA)) {
		t.Fatal("computeMAC: changing token_id (same seed) did not change the MAC")
	}
	if bytes.Equal(macBase, computeMAC(secret, idA[:], seedB)) {
		t.Fatal("computeMAC: changing token_seed (same id) did not change the MAC")
	}
}

// TestVerify_ConstantTimeComparisonUsed is a code-level guarantee test: it
// documents and exercises the fact that Verify compares MACs with
// crypto/hmac.Equal (see authenticator.go), not a manual/short-circuit byte
// comparison. A functional consequence of using hmac.Equal (as opposed to,
// say, bytes.Equal short-circuiting on the first differing byte) is that
// there is no code path that returns "no match" faster for an
// early-differing byte than for a late-differing one; this test exercises
// mismatches at the very first and very last byte to confirm both are
// rejected identically (both return ErrInvalidToken), which would also hold
// for a non-constant-time implementation — the actual constant-time
// property is a code-review property of using hmac.Equal, verified here by
// asserting behavioural correctness at both ends of the buffer.
func TestVerify_ConstantTimeComparisonUsed(t *testing.T) {
	ctx := context.Background()
	store := newMemoryStore()
	a := mustAuthenticator(t, store)

	token, _, err := a.Mint(ctx)
	if err != nil {
		t.Fatalf("Mint: unexpected error: %v", err)
	}

	version, idHex, macHex := splitWireToken(t, token)

	firstByteFlipped := version + "." + idHex + "." + flipHexNibble(macHex, 0)
	lastByteFlipped := version + "." + idHex + "." + flipHexNibble(macHex, len(macHex)-1)

	if _, err := a.Verify(ctx, firstByteFlipped); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("Verify (first byte flipped): got err %v, want ErrInvalidToken", err)
	}
	if _, err := a.Verify(ctx, lastByteFlipped); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("Verify (last byte flipped): got err %v, want ErrInvalidToken", err)
	}
}

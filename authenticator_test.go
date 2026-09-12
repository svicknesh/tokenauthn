package tokenauthn

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"
)

// testSecret returns deterministic, exactly-32-byte master secret material
// for use across the test suite. It is a repeated pattern, not real secret
// material, and is only used in tests.
func testSecret() []byte {
	return bytes.Repeat([]byte("t3st-"), 7)[:minSecretSize] // exactly 32 bytes
}

func mustAuthenticator(t *testing.T, store Store) *Authenticator {
	t.Helper()
	a, err := NewAuthenticator(testSecret(), store)
	if err != nil {
		t.Fatalf("NewAuthenticator: unexpected error: %v", err)
	}
	return a
}

func TestNewAuthenticator_RejectsShortSecret(t *testing.T) {
	store := newMemoryStore()

	cases := []struct {
		name   string
		secret []byte
	}{
		{"nil secret", nil},
		{"empty secret", []byte{}},
		{"31 bytes", make([]byte, 31)},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := NewAuthenticator(tc.secret, store); err == nil {
				t.Fatal("expected error for undersized secret, got nil")
			}
		})
	}
}

func TestNewAuthenticator_RejectsNilStore(t *testing.T) {
	if _, err := NewAuthenticator(testSecret(), nil); err == nil {
		t.Fatal("expected error for nil store, got nil")
	}
}

func TestNewAuthenticator_CopiesSecret(t *testing.T) {
	secret := testSecret()
	store := newMemoryStore()

	a := mustAuthenticator(t, store)
	_ = a

	// mutate the caller's slice after construction
	secretCopyBeforeMutation := append([]byte(nil), secret...)
	for i := range secret {
		secret[i] = 0x00
	}

	// mint+verify a token using a fresh authenticator constructed from the
	// mutated slice's ORIGINAL bytes to prove NewAuthenticator captured its
	// own copy rather than aliasing the caller's slice.
	a2, err := NewAuthenticator(secretCopyBeforeMutation, store)
	if err != nil {
		t.Fatalf("NewAuthenticator: unexpected error: %v", err)
	}

	ctx := context.Background()
	token, _, err := a2.Mint(ctx)
	if err != nil {
		t.Fatalf("Mint: unexpected error: %v", err)
	}
	if _, err := a2.Verify(ctx, token); err != nil {
		t.Fatalf("Verify: unexpected error: %v", err)
	}
}

func TestMintVerify_RoundTrip(t *testing.T) {
	ctx := context.Background()
	store := newMemoryStore()
	a := mustAuthenticator(t, store)

	token, id, err := a.Mint(ctx)
	if err != nil {
		t.Fatalf("Mint: unexpected error: %v", err)
	}
	if token == "" {
		t.Fatal("Mint: expected non-empty token")
	}

	gotID, err := a.Verify(ctx, token)
	if err != nil {
		t.Fatalf("Verify: unexpected error: %v", err)
	}
	if gotID != id {
		t.Fatalf("Verify: got id %v, want %v", gotID, id)
	}
}

func TestMint_MultipleTokensDoNotCrossVerify(t *testing.T) {
	ctx := context.Background()
	store := newMemoryStore()
	a := mustAuthenticator(t, store)

	const n = 25
	tokens := make([]string, n)
	ids := make([]TokenID, n)
	for i := 0; i < n; i++ {
		token, id, err := a.Mint(ctx)
		if err != nil {
			t.Fatalf("Mint[%d]: unexpected error: %v", i, err)
		}
		tokens[i] = token
		ids[i] = id
	}

	for i := 0; i < n; i++ {
		gotID, err := a.Verify(ctx, tokens[i])
		if err != nil {
			t.Fatalf("Verify[%d]: unexpected error: %v", i, err)
		}
		if gotID != ids[i] {
			t.Fatalf("Verify[%d]: got id %v, want %v", i, gotID, ids[i])
		}
	}

	// no two minted tokens should ever be equal, and none should verify
	// under a different token's identity.
	for i := 0; i < n; i++ {
		for j := i + 1; j < n; j++ {
			if tokens[i] == tokens[j] {
				t.Fatalf("tokens[%d] and tokens[%d] are identical: %q", i, j, tokens[i])
			}
			if ids[i] == ids[j] {
				t.Fatalf("ids[%d] and ids[%d] are identical: %v", i, j, ids[i])
			}
		}
	}
}

func TestRevoke_ThenVerifyFails(t *testing.T) {
	ctx := context.Background()
	store := newMemoryStore()
	a := mustAuthenticator(t, store)

	token, id, err := a.Mint(ctx)
	if err != nil {
		t.Fatalf("Mint: unexpected error: %v", err)
	}

	if _, err := a.Verify(ctx, token); err != nil {
		t.Fatalf("Verify (pre-revoke): unexpected error: %v", err)
	}

	if err := a.Revoke(ctx, id); err != nil {
		t.Fatalf("Revoke: unexpected error: %v", err)
	}

	if _, err := a.Verify(ctx, token); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("Verify (post-revoke): got err %v, want ErrInvalidToken", err)
	}
}

func TestMintWithExpiry_ValidBeforeExpiry(t *testing.T) {
	ctx := context.Background()
	store := newMemoryStore()
	a := mustAuthenticator(t, store)

	token, _, err := a.MintWithExpiry(ctx, time.Hour)
	if err != nil {
		t.Fatalf("MintWithExpiry: unexpected error: %v", err)
	}

	if _, err := a.Verify(ctx, token); err != nil {
		t.Fatalf("Verify: unexpected error: %v", err)
	}
}

func TestMintWithExpiry_RejectsNonPositiveTTL(t *testing.T) {
	ctx := context.Background()
	store := newMemoryStore()
	a := mustAuthenticator(t, store)

	for _, ttl := range []time.Duration{0, -time.Second} {
		if _, _, err := a.MintWithExpiry(ctx, ttl); err == nil {
			t.Fatalf("MintWithExpiry(%v): expected error, got nil", ttl)
		}
	}
}

func TestVerify_ExpiredTokenFails(t *testing.T) {
	ctx := context.Background()
	store := newMemoryStore()
	a := mustAuthenticator(t, store)

	token, id, err := a.MintWithExpiry(ctx, time.Hour)
	if err != nil {
		t.Fatalf("MintWithExpiry: unexpected error: %v", err)
	}

	// force expiry without sleeping for real wall-clock time.
	store.setExpiresAt(id, time.Now().Add(-time.Minute))

	if _, err := a.Verify(ctx, token); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("Verify (expired): got err %v, want ErrInvalidToken", err)
	}
}

func TestMint_ReturnsNoTokenOnStoreCreateError(t *testing.T) {
	ctx := context.Background()
	store := newMemoryStore()
	store.createErr = errors.New("simulated datastore outage")
	a := mustAuthenticator(t, store)

	token, id, err := a.Mint(ctx)
	if err == nil {
		t.Fatal("Mint: expected error, got nil")
	}
	if token != "" {
		t.Fatalf("Mint: expected empty token on error, got %q", token)
	}
	if id != (TokenID{}) {
		t.Fatalf("Mint: expected zero id on error, got %v", id)
	}
	if errors.Is(err, ErrInvalidToken) {
		t.Fatal("Mint: store failure must not be reported as ErrInvalidToken")
	}
}

func TestMint_CollisionSurfacesErrTokenIDExists(t *testing.T) {
	ctx := context.Background()
	store := newMemoryStore()
	store.createErr = ErrTokenIDExists
	a := mustAuthenticator(t, store)

	token, _, err := a.Mint(ctx)
	if token != "" {
		t.Fatalf("Mint: expected empty token on collision, got %q", token)
	}
	if !errors.Is(err, ErrTokenIDExists) {
		t.Fatalf("Mint: got err %v, want wrapped ErrTokenIDExists", err)
	}
	if errors.Is(err, ErrInvalidToken) {
		t.Fatal("Mint: collision must not be reported as ErrInvalidToken")
	}
}

func TestVerify_UnknownTokenIDFails(t *testing.T) {
	ctx := context.Background()
	store := newMemoryStore()
	a := mustAuthenticator(t, store)

	otherStore := newMemoryStore()
	otherA := mustAuthenticator(t, otherStore)
	token, _, err := otherA.Mint(ctx)
	if err != nil {
		t.Fatalf("Mint: unexpected error: %v", err)
	}

	// token references an ID that doesn't exist in `store`.
	if _, err := a.Verify(ctx, token); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("Verify (unknown id): got err %v, want ErrInvalidToken", err)
	}
}

func TestVerify_StoreLoadErrorIsDistinguishableFromErrInvalidToken(t *testing.T) {
	ctx := context.Background()
	store := newMemoryStore()
	a := mustAuthenticator(t, store)

	token, _, err := a.Mint(ctx)
	if err != nil {
		t.Fatalf("Mint: unexpected error: %v", err)
	}

	simulated := errors.New("simulated datastore read outage")
	store.loadErr = simulated

	_, err = a.Verify(ctx, token)
	if err == nil {
		t.Fatal("Verify: expected error, got nil")
	}
	if errors.Is(err, ErrInvalidToken) {
		t.Fatal("Verify: store read failure must not be reported as ErrInvalidToken")
	}
	if !errors.Is(err, simulated) {
		t.Fatalf("Verify: expected wrapped simulated error, got %v", err)
	}
}

func TestRevoke_StoreErrorIsSurfaced(t *testing.T) {
	ctx := context.Background()
	store := newMemoryStore()
	a := mustAuthenticator(t, store)

	simulated := errors.New("simulated datastore write outage")
	store.revokeErr = simulated

	err := a.Revoke(ctx, TokenID{})
	if err == nil {
		t.Fatal("Revoke: expected error, got nil")
	}
	if !errors.Is(err, simulated) {
		t.Fatalf("Revoke: expected wrapped simulated error, got %v", err)
	}
}

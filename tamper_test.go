package tokenauthn

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
)

// splitWireToken splits a well-formed V1 wire token into its three fields,
// failing the test if the token is not shaped as expected. It exists only
// to let tampering tests build variants of a real, validly-minted token.
func splitWireToken(t *testing.T, token string) (version, idHex, macHex string) {
	t.Helper()
	parts := strings.Split(token, wireSeparator)
	if len(parts) != 3 {
		t.Fatalf("splitWireToken: expected 3 fields, got %d in %q", len(parts), token)
	}
	return parts[0], parts[1], parts[2]
}

func flipHexNibble(s string, pos int) string {
	b := []byte(s)
	// flip within the hex alphabet so the string stays valid hex but
	// changes the underlying byte value.
	switch b[pos] {
	case '0':
		b[pos] = '1'
	default:
		b[pos] = '0'
	}
	return string(b)
}

func TestVerify_TamperedMACFails(t *testing.T) {
	ctx := context.Background()
	store := newMemoryStore()
	a := mustAuthenticator(t, store)

	token, _, err := a.Mint(ctx)
	if err != nil {
		t.Fatalf("Mint: unexpected error: %v", err)
	}

	version, idHex, macHex := splitWireToken(t, token)

	tampered := version + "." + idHex + "." + flipHexNibble(macHex, 0)
	if _, err := a.Verify(ctx, tampered); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("Verify (tampered MAC head): got err %v, want ErrInvalidToken", err)
	}

	tamperedTail := version + "." + idHex + "." + flipHexNibble(macHex, len(macHex)-1)
	if _, err := a.Verify(ctx, tamperedTail); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("Verify (tampered MAC tail / last byte): got err %v, want ErrInvalidToken", err)
	}
}

func TestVerify_TamperedTokenIDFails(t *testing.T) {
	ctx := context.Background()
	store := newMemoryStore()
	a := mustAuthenticator(t, store)

	token, _, err := a.Mint(ctx)
	if err != nil {
		t.Fatalf("Mint: unexpected error: %v", err)
	}

	version, idHex, macHex := splitWireToken(t, token)
	tampered := version + "." + flipHexNibble(idHex, 0) + "." + macHex

	if _, err := a.Verify(ctx, tampered); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("Verify (tampered token id): got err %v, want ErrInvalidToken", err)
	}
}

func TestVerify_TamperedVersionFails(t *testing.T) {
	ctx := context.Background()
	store := newMemoryStore()
	a := mustAuthenticator(t, store)

	token, _, err := a.Mint(ctx)
	if err != nil {
		t.Fatalf("Mint: unexpected error: %v", err)
	}

	_, idHex, macHex := splitWireToken(t, token)

	for _, badVersion := range []string{"v2", "V1", "v0", "v10", "vv", ""} {
		tampered := badVersion + "." + idHex + "." + macHex
		if _, err := a.Verify(ctx, tampered); !errors.Is(err, ErrInvalidToken) {
			t.Fatalf("Verify (version %q): got err %v, want ErrInvalidToken", badVersion, err)
		}
	}
}

func TestVerify_FieldsReorderedRemovedOrAddedFails(t *testing.T) {
	ctx := context.Background()
	store := newMemoryStore()
	a := mustAuthenticator(t, store)

	token, _, err := a.Mint(ctx)
	if err != nil {
		t.Fatalf("Mint: unexpected error: %v", err)
	}

	version, idHex, macHex := splitWireToken(t, token)

	variants := []string{
		idHex + "." + version + "." + macHex,            // reordered
		macHex + "." + idHex + "." + version,            // reordered
		version + "." + macHex + "." + idHex,            // reordered
		version + "." + idHex,                           // field removed
		idHex + "." + macHex,                            // field removed
		version + "." + idHex + "." + macHex + ".extra", // field added
		version + "." + idHex + "." + macHex + ".",      // trailing separator/extra empty field
	}

	for _, variant := range variants {
		if _, err := a.Verify(ctx, variant); !errors.Is(err, ErrInvalidToken) {
			t.Fatalf("Verify (%q): got err %v, want ErrInvalidToken", variant, err)
		}
	}
}

func TestVerify_TruncatedOrOversizedMACFails(t *testing.T) {
	ctx := context.Background()
	store := newMemoryStore()
	a := mustAuthenticator(t, store)

	token, _, err := a.Mint(ctx)
	if err != nil {
		t.Fatalf("Mint: unexpected error: %v", err)
	}

	version, idHex, macHex := splitWireToken(t, token)

	truncated := version + "." + idHex + "." + macHex[:len(macHex)-2]
	if _, err := a.Verify(ctx, truncated); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("Verify (truncated mac): got err %v, want ErrInvalidToken", err)
	}

	oversized := version + "." + idHex + "." + macHex + "ab"
	if _, err := a.Verify(ctx, oversized); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("Verify (oversized mac): got err %v, want ErrInvalidToken", err)
	}
}

func TestVerify_InvalidEncodingFails(t *testing.T) {
	ctx := context.Background()
	store := newMemoryStore()
	a := mustAuthenticator(t, store)

	token, _, err := a.Mint(ctx)
	if err != nil {
		t.Fatalf("Mint: unexpected error: %v", err)
	}

	version, idHex, macHex := splitWireToken(t, token)

	// non-hex characters in place of valid hex digits.
	badIDHex := "zz" + idHex[2:]
	if _, err := a.Verify(ctx, version+"."+badIDHex+"."+macHex); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("Verify (non-hex token id): got err %v, want ErrInvalidToken", err)
	}

	badMACHex := "zz" + macHex[2:]
	if _, err := a.Verify(ctx, version+"."+idHex+"."+badMACHex); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("Verify (non-hex mac): got err %v, want ErrInvalidToken", err)
	}

	// uppercase hex is a non-canonical encoding of the same bytes and must
	// be rejected, not silently normalized.
	upperIDHex := strings.ToUpper(idHex)
	if _, err := a.Verify(ctx, version+"."+upperIDHex+"."+macHex); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("Verify (uppercase token id hex): got err %v, want ErrInvalidToken", err)
	}

	upperMACHex := strings.ToUpper(macHex)
	if _, err := a.Verify(ctx, version+"."+idHex+"."+upperMACHex); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("Verify (uppercase mac hex): got err %v, want ErrInvalidToken", err)
	}
}

func TestVerify_WrongSecretFails(t *testing.T) {
	ctx := context.Background()
	store := newMemoryStore()

	aliceSecret := bytes.Repeat([]byte("alice-"), 6)[:minSecretSize]
	bobSecret := bytes.Repeat([]byte("bob-01"), 6)[:minSecretSize]

	alice, err := NewAuthenticator(aliceSecret, store)
	if err != nil {
		t.Fatalf("NewAuthenticator(alice): unexpected error: %v", err)
	}
	bob, err := NewAuthenticator(bobSecret, store)
	if err != nil {
		t.Fatalf("NewAuthenticator(bob): unexpected error: %v", err)
	}

	token, _, err := alice.Mint(ctx)
	if err != nil {
		t.Fatalf("Mint: unexpected error: %v", err)
	}

	// same store, same token ID exists, but bob's secret must not verify
	// a token minted under alice's secret.
	if _, err := bob.Verify(ctx, token); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("Verify (wrong secret): got err %v, want ErrInvalidToken", err)
	}

	// sanity: alice's own secret still verifies it.
	if _, err := alice.Verify(ctx, token); err != nil {
		t.Fatalf("Verify (correct secret): unexpected error: %v", err)
	}
}

func TestVerify_StoredSeedChangedServerSideFails(t *testing.T) {
	ctx := context.Background()
	store := newMemoryStore()
	a := mustAuthenticator(t, store)

	token, id, err := a.Mint(ctx)
	if err != nil {
		t.Fatalf("Mint: unexpected error: %v", err)
	}

	// simulate the stored seed being changed without the bearer token (and
	// therefore its MAC) being reissued.
	store.mutateSeed(id, bytes.Repeat([]byte{0x00}, tokenSeedSize))

	if _, err := a.Verify(ctx, token); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("Verify (mutated stored seed): got err %v, want ErrInvalidToken", err)
	}
}

func TestVerify_CrossedMACAndTokenIDFail(t *testing.T) {
	ctx := context.Background()
	store := newMemoryStore()
	a := mustAuthenticator(t, store)

	tokenX, _, err := a.Mint(ctx)
	if err != nil {
		t.Fatalf("Mint(X): unexpected error: %v", err)
	}
	tokenY, _, err := a.Mint(ctx)
	if err != nil {
		t.Fatalf("Mint(Y): unexpected error: %v", err)
	}

	versionX, idHexX, macHexX := splitWireToken(t, tokenX)
	_, idHexY, macHexY := splitWireToken(t, tokenY)

	// X's token_id combined with Y's MAC.
	crossed1 := versionX + "." + idHexX + "." + macHexY
	if _, err := a.Verify(ctx, crossed1); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("Verify (idX+macY): got err %v, want ErrInvalidToken", err)
	}

	// Y's token_id combined with X's MAC.
	crossed2 := versionX + "." + idHexY + "." + macHexX
	if _, err := a.Verify(ctx, crossed2); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("Verify (idY+macX): got err %v, want ErrInvalidToken", err)
	}
}

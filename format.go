package tokenauthn

import (
	"encoding/hex"
	"strings"
)

// wireVersion is the literal, exact version field required at the start of
// every V1 bearer token. Unknown versions must fail closed.
const wireVersion = "v1"

// wireSeparator joins the three fields of the bearer token wire format.
const wireSeparator = "."

// wireTokenIDHexLen and wireMACHexLen are the exact, canonical hex-encoded
// lengths of the token ID and MAC fields. The V1 wire format has no
// variable-length fields, so the full token string has exactly one valid
// length.
const (
	wireTokenIDHexLen = tokenIDSize * 2
	wireMACHexLen     = macSize * 2
)

// wireTokenLen is the exact length, in bytes, of every valid V1 bearer
// token string: "v1" + "." + 32 hex chars + "." + 64 hex chars.
const wireTokenLen = len(wireVersion) + len(wireSeparator) + wireTokenIDHexLen + len(wireSeparator) + wireMACHexLen

// encodeBearerToken renders the canonical V1 bearer token string for id and
// mac. This is the single canonical representation for a minted token: hex
// encoding is always lowercase, and field order/separators never vary.
func encodeBearerToken(id TokenID, mac []byte) string {
	var b strings.Builder
	b.Grow(wireTokenLen)
	b.WriteString(wireVersion)
	b.WriteString(wireSeparator)
	b.WriteString(hex.EncodeToString(id[:]))
	b.WriteString(wireSeparator)
	b.WriteString(hex.EncodeToString(mac))
	return b.String()
}

// parseBearerToken strictly parses a V1 bearer token string, enforcing exact
// length, exact field count, an exact version match, and canonical
// (lowercase, correctly-sized) hex encoding for every field. Any malformed,
// oversized, truncated, or non-canonical input is rejected with
// ErrInvalidToken before any datastore access is attempted.
func parseBearerToken(token string) (id TokenID, mac []byte, err error) {
	// Fixed-length check first and cheapest: the V1 format has no
	// variable-length fields, so any string of the wrong length is
	// rejected immediately without further parsing work.
	if len(token) != wireTokenLen {
		return TokenID{}, nil, ErrInvalidToken
	}

	parts := strings.Split(token, wireSeparator)
	if len(parts) != 3 {
		return TokenID{}, nil, ErrInvalidToken
	}

	if parts[0] != wireVersion {
		return TokenID{}, nil, ErrInvalidToken
	}

	idBytes, ok := decodeCanonicalHex(parts[1], tokenIDSize)
	if !ok {
		return TokenID{}, nil, ErrInvalidToken
	}

	macBytes, ok := decodeCanonicalHex(parts[2], macSize)
	if !ok {
		return TokenID{}, nil, ErrInvalidToken
	}

	copy(id[:], idBytes)
	return id, macBytes, nil
}

// decodeCanonicalHex decodes s as hex and reports whether s is the single
// canonical encoding of exactly wantLen bytes. Canonical means: exact
// expected string length, valid hex, and lowercase — re-encoding the decoded
// bytes must reproduce s exactly. This rejects non-canonical forms such as
// uppercase hex digits, which would otherwise let the same bytes be
// represented by more than one wire string.
func decodeCanonicalHex(s string, wantLen int) (b []byte, ok bool) {
	if len(s) != wantLen*2 {
		return nil, false
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, false
	}
	if hex.EncodeToString(b) != s {
		return nil, false
	}
	return b, true
}

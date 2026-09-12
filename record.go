package tokenauthn

import (
	"encoding/json"
	"fmt"
	"time"
)

// redactedSeedText is what a TokenSeed renders as through fmt formatting
// (%v, %+v, %s, %#v) and generic JSON encoding, instead of ever exposing
// the underlying key material through those paths.
const redactedSeedText = "tokenauthn.TokenSeed(REDACTED)"

// TokenSeed is the per-token verification secret generated at Mint time. It
// never appears in the bearer token string, must never be logged, and must
// never be returned to the token holder after Mint.
//
// TokenSeed is a named byte-slice type specifically so it can carry its own
// String/GoString/MarshalJSON overrides below: ordinary fmt formatting of a
// TokenSeed (or of any struct containing one, such as Record, via %v, %+v,
// %s, or %#v) and generic encoding/json serialization both render it as a
// fixed redacted placeholder rather than the raw key material. This closes
// off the most common accidental-disclosure paths — application logging,
// structured/request-response dumping, and ad hoc JSON persistence of a
// whole Record — without changing how a Store adapter that genuinely needs
// the seed obtains it.
//
// TokenSeed's underlying type is []byte, so a Store adapter that needs to
// persist or restore the seed deliberately (its intended and only supported
// use — see the Store interface documentation) still does so through a
// plain, explicit conversion:
//
//	raw := []byte(record.TokenSeed)              // persist raw bytes
//	record.TokenSeed = tokenauthn.TokenSeed(raw) // restore raw bytes
//
// That conversion is an ordinary, explicit line of code in the adapter —
// never something that happens automatically through generic formatting or
// serialization.
type TokenSeed []byte

// String implements fmt.Stringer. It never returns the underlying key
// material, including when a TokenSeed is formatted as a field of another
// struct (such as Record) via %v, %+v, or %s.
func (s TokenSeed) String() string {
	return redactedSeedText
}

// GoString implements fmt.GoStringer, so %#v also redacts rather than
// dumping the underlying byte slice.
func (s TokenSeed) GoString() string {
	return redactedSeedText
}

// MarshalJSON implements json.Marshaler. Generic JSON encoding of a
// TokenSeed — including as a field of an encoding/json-marshaled Record —
// never contains the underlying key material.
func (s TokenSeed) MarshalJSON() ([]byte, error) {
	return json.Marshal(redactedSeedText)
}

// UnmarshalJSON implements json.Unmarshaler. Generic JSON decoding into a
// TokenSeed is intentionally unsupported and always fails: since
// MarshalJSON never emits the real key material, round-tripping a Record
// through encoding/json cannot restore a usable seed, and silently
// succeeding with a zero-value seed would be a worse, harder-to-notice
// failure than an explicit error. A Store adapter that needs to restore a
// seed must assign tokenauthn.TokenSeed(rawBytes) explicitly instead, as
// documented on the TokenSeed type.
func (s *TokenSeed) UnmarshalJSON(data []byte) error {
	return fmt.Errorf("tokenauthn: TokenSeed does not support generic JSON deserialization; a Store adapter must restore it explicitly via tokenauthn.TokenSeed(rawBytes)")
}

// Record is the persisted, per-token verification state that a Store
// implementation must keep. It holds only what tokenauthn needs to verify
// and manage a token later.
//
// A Record must NEVER be used to persist the bearer token string, the
// wire-format MAC, or the master secret — none of those are part of this
// struct, and Store implementations must not add them elsewhere.
type Record struct {
	// TokenID is the opaque identifier used as the store lookup key.
	TokenID TokenID

	// TokenSeed is the per-token verification secret generated at Mint time.
	// It never appears in the bearer token string, must never be logged, and
	// must never be returned to the token holder after Mint. See the
	// TokenSeed type documentation for how a Store adapter persists and
	// restores it explicitly.
	TokenSeed TokenSeed

	// CreatedAt is when the record was minted.
	CreatedAt time.Time

	// Revoked marks the record as no longer valid for verification. A Store
	// implementation is responsible for persisting this durably; tokenauthn
	// only reads it during Verify and sets it via Store.Revoke.
	Revoked bool

	// RevokedAt is when the record was revoked. Zero if never revoked.
	RevokedAt time.Time

	// ExpiresAt is the optional expiry time for the record. The zero value
	// means the record never expires.
	ExpiresAt time.Time
}

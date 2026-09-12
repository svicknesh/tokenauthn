package tokenauthn

import "errors"

// ErrInvalidToken is returned by Verify for every credential-shaped failure:
// malformed wire format, unknown/unsupported version, wrong field count or
// length, non-canonical encoding, unknown token ID, revoked token, expired
// token, or a bad MAC.
//
// Callers must never attempt to distinguish these cases from error content,
// error type, or timing. Doing so would create an oracle that leaks which
// specific check failed to anyone probing the endpoint. Use errors.Is(err,
// ErrInvalidToken) to detect a rejected credential.
var ErrInvalidToken = errors.New("tokenauthn: invalid token")

// ErrTokenIDExists is returned by a Store implementation's Create method (and
// wrapped and surfaced by Mint) when the randomly generated token ID already
// exists in the store. This is an operational, mint-time condition — not a
// credential failure. Mint does not retry automatically; callers may call
// Mint again, which generates a fresh random token ID.
var ErrTokenIDExists = errors.New("tokenauthn: token id already exists")

// ErrTokenNotFound is returned by a Store implementation's Load method when
// no record exists for the given token ID. Verify treats a not-found record
// as credential-shaped and converts it to ErrInvalidToken; Store
// implementations should return this sentinel (or wrap it) rather than
// ErrInvalidToken directly, so operational callers can still tell "no such
// record" apart from other store failures if they need to.
var ErrTokenNotFound = errors.New("tokenauthn: token not found")

// isNotFound reports whether err is or wraps ErrTokenNotFound.
func isNotFound(err error) bool {
	return errors.Is(err, ErrTokenNotFound)
}

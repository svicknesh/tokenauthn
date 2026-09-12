# tokenauthn

`tokenauthn` is a small Go library for minting, verifying, and revoking
opaque, stateful, HMAC-SHA3-256 bearer tokens. It is deliberately narrow:
authentication only, no authorization/permissions logic, no HTTP/CLI
framework coupling, no environment-variable secret handling, and no
production persistence implementation.

You supply the master secret and a `Store` implementation; `tokenauthn` owns
the cryptographic construction, the wire format, and the verification
logic.

## What tokenauthn does

- Issues opaque bearer tokens (`Mint`) backed by a random 128-bit token ID
  and a random 256-bit per-token seed, both generated via `crypto/rand`.
- Verifies bearer tokens (`Verify`) against a caller-supplied `Store`,
  returning the token's `TokenID` only if every check passes.
- Revokes tokens (`Revoke`), which is durable and stateful (records are
  marked revoked, not deleted).
- Optionally expires tokens (`MintWithExpiry`), if a consumer wants it.

## Threat model

**tokenauthn protects against:**

- Forging a bearer token without knowledge of the master secret (the MAC
  is a full, untruncated HMAC-SHA3-256 over an unambiguous, domain-separated
  encoding, verified with a constant-time comparison).
- Tampering with any part of a bearer token (version, token ID, or MAC) —
  any modification is rejected.
- Guessing a valid token ID or seed — both are drawn from `crypto/rand`
  with 128 and 256 bits of entropy respectively.
- Continued use of a revoked token, once the `Store` reflects the
  revocation.
- Leaking a stable "why did this fail" signal to a caller probing the
  verify endpoint — every credential-shaped failure returns the same
  `ErrInvalidToken` sentinel.

**tokenauthn does NOT protect against:**

- **Unprotected transport.** This is a bearer-token scheme: whoever
  presents a valid token string is treated as authenticated. tokenauthn has
  no built-in replay or transport protection. **Bearer tokens must only be
  transmitted over TLS.** Do not use this library over plaintext HTTP or
  any other unencrypted channel.
- **A compromised master secret.** Anyone who obtains the master secret can
  forge tokens for any token ID they choose. Protect the master secret like
  any other root credential.
- **A compromised `Store`.** tokenauthn's security model assumes the
  `Store` faithfully returns what it was given and does not leak stored
  seeds. A `Store` implementation must protect stored records (in
  particular, `TokenSeed`) at least as carefully as the master secret.
- **Revocation propagation delay.** If a `Store` implementation caches or
  replicates records with lag, a revoked token may keep verifying
  successfully until that lag clears. That is a `Store`-implementation
  concern, not something tokenauthn controls.
- **Authorization.** tokenauthn tells you *which* opaque token ID was
  verified. It has no concept of roles, scopes, or permissions — build that
  in your application layer, keyed off the returned `TokenID`.
- **Key rotation / key-ring management.** V1 supports exactly one master
  secret per `Authenticator`. See "Master-secret rotation" below.

## Conceptual token structure

A bearer token is a canonical, versioned string:

```
v1.<32 hex chars: token_id>.<64 hex chars: mac>
```

- `v1` — the literal, exact wire format version. Unknown versions fail
  closed.
- `token_id` — 16 random bytes (128 bits), canonically lowercase-hex
  encoded. This is the `Store` lookup key. It is opaque and safe to log; on
  its own it does not allow forging or verifying a token.
- `mac` — the full 32-byte (256-bit) HMAC-SHA3-256 output, canonically
  lowercase-hex encoded. Never truncated.

The bearer token string **never** contains the token seed or the master
secret. There is exactly one canonical representation for any minted
token — non-canonical variants (wrong case, wrong length, extra/missing
fields, wrong separators) are all rejected by `Verify`, not normalized.

### MAC construction

```
MAC = HMAC-SHA3-256(master_secret, domain_v1 || version_byte || token_id || token_seed)
```

`HMAC-SHA3-256` is Go's standard library `crypto/hmac` construction using
`crypto/sha3`'s `New256` (SHA3-256) as the underlying hash — not a raw
(non-HMAC) SHA3 construction, and not a hand-rolled HMAC implementation.

This is a deliberate V1 algorithm choice locked in before tokenauthn's
first release, not a fix for a weakness in HMAC-SHA-256 — HMAC-SHA-256 was
never externally released as part of this library. The V1 wire format is
cryptographically tied to this specific construction: changing the hash
algorithm after release would require an intentional new format version
(see "Versioning and compatibility" below).

Every field in that concatenation has a fixed, known-in-advance length
(`domain_v1` is the constant 13-byte string `"tokenauthn/v1"`, `version_byte`
is the constant single byte `0x01`, `token_id` is always 16 bytes, and
`token_seed` is always 32 bytes), so the concatenation is unambiguous
without needing length prefixes or separators — no field's bytes can be
reinterpreted as belonging to an adjacent field.

Both `token_id` and `token_seed` are cryptographically bound into the MAC.
This is why a stored seed can never be swapped out from under a token, and
why a token ID and MAC pair from two different tokens can never be
recombined into a valid third token — see `crypto_test.go` and
`tamper_test.go` for the executable proofs.

## `Store` interface responsibilities

```go
type Store interface {
    Create(ctx context.Context, record *Record) error
    Load(ctx context.Context, id TokenID) (*Record, error)
    Revoke(ctx context.Context, id TokenID) error
}
```

`tokenauthn` defines this interface but does not ship a production
implementation. **You must implement your own `Store`** backed by whatever
datastore your service already uses (SQL, TrailBase, Redis, etc.).

A `Record` holds only:

- `TokenID` — the lookup key.
- `TokenSeed` — the per-token verification secret (treat like a secret; see
  below).
- `CreatedAt` — informational.
- `Revoked` / `RevokedAt` — revocation state.
- `ExpiresAt` — optional expiry (zero value means "never expires").

**A `Store` must never persist the bearer token string or the MAC.** Those
are wire-format artifacts, not verification state, and persisting them adds
attack surface for no benefit.

`Create` must reject a token ID collision (return `ErrTokenIDExists`)
instead of silently overwriting an existing record. `Load` must return
`ErrTokenNotFound` for an unknown ID. `Mint` and `Verify` rely on these
exact sentinels (or errors that wrap them) to tell an operational failure
apart from "this credential doesn't exist."

## Master-secret requirements

- Supplied entirely by the caller, via `NewAuthenticator`. tokenauthn never
  reads it from an environment variable, file, or any other implicit
  source.
- Must be at least 32 bytes. `NewAuthenticator` rejects anything shorter
  (including empty/nil).
- Copied internally by `NewAuthenticator` — mutating your original slice
  after construction has no effect on an already-constructed
  `Authenticator`.
- Never exposed back out through any getter, field, log line, or error
  message.

tokenauthn does not — and cannot — guarantee that Go reliably erases the
secret from process memory. Go's garbage collector and runtime make secure
memory wiping unreliable in general; treat process memory itself as
something to protect at the OS/deployment level if that threat matters to
you.

## Token-seed treatment

The token seed is generated once at `Mint` time, stored via `Store.Create`,
and never appears anywhere else:

- It is never included in the bearer token string.
- It is never returned to the caller after `Mint`.
- It must never be logged by `tokenauthn` or by your `Store`
  implementation.

`Record.TokenSeed` is the named type `tokenauthn.TokenSeed` (underlying type
`[]byte`), not a plain `[]byte`, specifically so it can carry redaction
behavior as defense-in-depth against accidental disclosure:

- Formatting it with `fmt` (`%v`, `%+v`, `%s`, `%#v`) — including as a field
  of a `Record` passed to a logger — always prints a fixed placeholder,
  never the underlying bytes.
- Encoding it with `encoding/json` (directly, or as a field of a `Record`)
  always emits the same fixed placeholder, never the underlying bytes.
- Decoding it with `encoding/json` always fails with an explicit error,
  rather than silently producing an empty seed — a `Record` cannot be
  round-tripped through generic JSON encoding and still verify.

A `Store` adapter that needs to persist or restore the seed still does so
through a plain, explicit conversion — this is unchanged and remains the
only supported mechanism:

```go
// persist:
raw := []byte(record.TokenSeed)

// restore:
record.TokenSeed = tokenauthn.TokenSeed(raw)
```

## Revocation semantics

`Revoke` marks a record revoked; it does not delete it. `Verify` treats a
revoked record as an invalid credential (`ErrInvalidToken`) as soon as the
`Store`'s `Load` reflects the revocation. Retaining revocation metadata
(e.g., for audit purposes) is entirely up to your `Store` implementation —
tokenauthn only reads the `Revoked` field.

## Effect of master-secret rotation

There is no key-ring or multi-key support in V1. An `Authenticator` is
constructed with exactly one master secret. **Rotating the master secret
invalidates every outstanding token minted under the old secret** — none of
them will re-verify, because the MAC no longer matches. If you need
zero-downtime rotation, you must build a dual-verification window in your
own application layer (e.g., run two `Authenticator`s briefly and try both
during a cutover), or explicitly re-mint tokens for your callers before
rotating.

## Wiring up persistence and transport

```go
package main

import (
    "context"
    "fmt"
    "net/http"

    "github.com/svicknesh/tokenauthn"
)

func main() {
    // NEVER hardcode a real secret. Load it from your own secret-management
    // mechanism (this library intentionally does not do that for you).
    secret := []byte("replace-with-32+-bytes-of-real-secret-material")

    store := NewYourStore() // your own tokenauthn.Store implementation

    auth, err := tokenauthn.NewAuthenticator(secret, store)
    if err != nil {
        panic(err)
    }

    // Minting a token, e.g. after a successful login:
    ctx := context.Background()
    bearerToken, id, err := auth.Mint(ctx)
    if err != nil {
        // no token was returned — persistence failed
        panic(err)
    }
    fmt.Println("minted token for id:", id, "token:", bearerToken)

    // Middleware verifying an incoming request. This example assumes a
    // TLS-terminated listener — see the Transport section below.
    mux := http.NewServeMux()
    mux.HandleFunc("/protected", func(w http.ResponseWriter, r *http.Request) {
        bearer := extractBearerToken(r) // e.g. from the Authorization header

        id, err := auth.Verify(r.Context(), bearer)
        if err != nil {
            http.Error(w, "unauthorized", http.StatusUnauthorized)
            return
        }

        // id (tokenauthn.TokenID) identifies the authenticated caller;
        // authorization decisions are your application's responsibility.
        _ = id
        w.WriteHeader(http.StatusOK)
    })

    // Serve mux over TLS only. See "Transport requirements" below.
}

func extractBearerToken(r *http.Request) string {
    const prefix = "Bearer "
    auth := r.Header.Get("Authorization")
    if len(auth) > len(prefix) && auth[:len(prefix)] == prefix {
        return auth[len(prefix):]
    }
    return ""
}
```

## Transport requirements

**tokenauthn bearer tokens require a protected transport (TLS).** This is a
classic bearer-token scheme: anyone who obtains the token string can use it
until it expires or is revoked. There is no built-in replay protection, no
proof-of-possession, and no binding to a specific connection. Serve every
endpoint that accepts a tokenauthn bearer token over TLS, and never log the
raw `Authorization` header or bearer token value.

## Versioning and compatibility

The V1 wire format (`v1.<token_id>.<mac>` with the exact byte layout and
hash selection documented in `mac.go`, pinned by the known-answer tests in
`knownanswer_test.go`) is **frozen as of tokenauthn's first release**. It
will not change silently.

The V1 wire format is cryptographically tied to its specific construction —
HMAC-SHA3-256 over the documented domain-separated, fixed-width byte
layout. Changing the underlying hash algorithm, or any other part of that
construction, after release would require an intentional new format
version, not a silent edit to V1's behavior.

Any future incompatible change to the token construction, MAC input
layout, or wire format will ship as a new version (e.g., `v2`), verified by
its own explicit branch in `Verify`'s parsing logic — `v1` tokens will
continue to be handled exactly as documented here for as long as V1 support
exists in this library.

## Design rationale

- **Full, untruncated MAC.** Truncating an HMAC output trades security
  margin for a shorter string, for no benefit here — token strings are not
  a scarce resource in this design, so the full 256-bit MAC is used.
- **Domain separation constant.** `domain_v1` ensures a MAC computed by
  tokenauthn cannot be confused with a MAC computed by an unrelated
  protocol that happens to reuse the same master secret bytes.
- **Fixed-width binary fields instead of string concatenation.** Every
  field fed into the MAC has a constant, known length. This avoids the
  classic ambiguous-concatenation bug class (e.g., `HMAC(secret, a + b)`
  where a variable split point in `a` could produce the same bytes as a
  different `a`/`b` pair). Because every field here has a fixed length,
  no field boundary can ever move regardless of the field content.
- **Single `ErrInvalidToken` sentinel for all credential failures.**
  Returning distinct errors for "unknown ID" vs. "bad MAC" vs. "revoked"
  would let an attacker probing `Verify` learn which check failed,
  narrowing their search space. A single sentinel closes that oracle.
- **Store errors kept distinguishable from `ErrInvalidToken`.** An
  operational failure (e.g., a database outage) is not the same thing as
  "this credential is invalid," and conflating the two would cause
  operational failures to look like widespread credential rejection (or
  vice versa) to anything monitoring `Verify`'s error rate.
- **No production `Store` implementation shipped.** Persistence
  requirements (durability, latency, replication, backup) vary enormously
  by consumer; tokenauthn only defines the narrow contract it actually
  needs.
- **Mint returns no token on any persistence failure.** A token that exists
  only in the caller's hand and not in the `Store` can never be verified,
  so returning it on failure would be actively misleading.
- **HMAC-SHA3-256, chosen before release, not as remediation.** V1 uses
  Go's standard library `crypto/hmac` construction over `crypto/sha3`'s
  `New256`. This was a deliberate algorithm choice made before tokenauthn's
  first release; it does not fix or respond to any known weakness in
  HMAC-SHA-256, which was never externally released as part of this
  library.
- **`TokenSeed` as a named type, not a plain `[]byte`.** Giving the seed its
  own type lets it carry `String`/`GoString`/`MarshalJSON` overrides that
  redact it from ordinary `fmt` formatting and generic JSON encoding —
  closing off the most common accidental-disclosure paths — while a `Store`
  adapter that genuinely needs the raw bytes still gets them through a
  plain, explicit `[]byte(...)` / `TokenSeed(...)` conversion.

## Minimal usage example

```go
package main

import (
    "context"
    "fmt"

    "github.com/svicknesh/tokenauthn"
)

// exampleStore is a toy in-memory Store for illustration only. Do not use
// this in production — see the Store interface responsibilities section
// above for what a real implementation must guarantee.
type exampleStore struct {
    records map[tokenauthn.TokenID]*tokenauthn.Record
}

func newExampleStore() *exampleStore {
    return &exampleStore{records: make(map[tokenauthn.TokenID]*tokenauthn.Record)}
}

func (s *exampleStore) Create(ctx context.Context, r *tokenauthn.Record) error {
    if _, exists := s.records[r.TokenID]; exists {
        return tokenauthn.ErrTokenIDExists
    }
    s.records[r.TokenID] = r
    return nil
}

func (s *exampleStore) Load(ctx context.Context, id tokenauthn.TokenID) (*tokenauthn.Record, error) {
    r, ok := s.records[id]
    if !ok {
        return nil, tokenauthn.ErrTokenNotFound
    }
    return r, nil
}

func (s *exampleStore) Revoke(ctx context.Context, id tokenauthn.TokenID) error {
    r, ok := s.records[id]
    if !ok {
        return tokenauthn.ErrTokenNotFound
    }
    r.Revoked = true
    return nil
}

func main() {
    // NEVER hardcode a real secret; this is a placeholder for illustration.
    secret := []byte("replace-with-32+-bytes-of-real-secret-material")

    auth, err := tokenauthn.NewAuthenticator(secret, newExampleStore())
    if err != nil {
        panic(err)
    }

    ctx := context.Background()

    token, id, err := auth.Mint(ctx)
    if err != nil {
        panic(err)
    }
    fmt.Println("minted:", token, "id:", id)

    gotID, err := auth.Verify(ctx, token)
    if err != nil {
        panic(err)
    }
    fmt.Println("verified id:", gotID)

    if err := auth.Revoke(ctx, id); err != nil {
        panic(err)
    }

    if _, err := auth.Verify(ctx, token); err != nil {
        fmt.Println("verify after revoke correctly failed:", err)
    }
}
```

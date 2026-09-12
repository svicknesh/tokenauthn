package tokenauthn

import "context"

// Store is the narrow persistence interface tokenauthn requires from a
// consumer-supplied backing store. tokenauthn defines this interface but
// does not ship a production implementation — consumers (for example, a
// service backed by TrailBase or any other datastore) implement it against
// their own storage.
//
// Implementations must:
//   - never persist the bearer token string or the wire-format MAC;
//   - use context for cancellation/timeout of the underlying storage call;
//   - be safe for concurrent use by multiple goroutines, matching whatever
//     concurrency guarantees the caller's application requires.
type Store interface {
	// Create persists a new record. If a record already exists for
	// record.TokenID, Create must not overwrite it; it must return
	// ErrTokenIDExists (or an error that wraps it) instead.
	Create(ctx context.Context, record *Record) error

	// Load returns the record for id. If no record exists for id, Load must
	// return ErrTokenNotFound (or an error that wraps it).
	Load(ctx context.Context, id TokenID) (*Record, error)

	// Revoke marks the record for id as revoked. It must not delete the
	// record. If no record exists for id, Revoke must return
	// ErrTokenNotFound (or an error that wraps it).
	Revoke(ctx context.Context, id TokenID) error
}

package tokenauthn

import (
	"context"
	"sync"
	"time"
)

// memoryStore is a minimal, non-durable, non-concurrency-hardened-beyond-a-
// mutex Store implementation used ONLY by this package's own test suite. It
// is deliberately unexported and lives in a _test.go file so it is never
// part of tokenauthn's public API and never compiled into consumer builds.
//
// Consumers of this library must supply their own production Store
// implementation (for example, one backed by a real datastore). memoryStore
// is not a reference implementation and must not be treated as one — it has
// no persistence across process restarts and no production-grade
// concurrency, durability, or error-injection semantics beyond what the
// tests below need.
type memoryStore struct {
	mu      sync.Mutex
	records map[TokenID]*Record

	// Error injection hooks for state/error-handling tests. Each, if set,
	// is returned in place of normal behaviour by the corresponding method.
	createErr error
	loadErr   error
	revokeErr error
}

// newMemoryStore returns an empty memoryStore, ready for test use.
func newMemoryStore() *memoryStore {
	return &memoryStore{records: make(map[TokenID]*Record)}
}

func (m *memoryStore) Create(ctx context.Context, record *Record) error {
	if m.createErr != nil {
		return m.createErr
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.records[record.TokenID]; exists {
		return ErrTokenIDExists
	}

	// store a defensive copy so later mutation of the caller's Record (or
	// its TokenSeed slice) cannot reach back into the store's state.
	cp := *record
	cp.TokenSeed = append([]byte(nil), record.TokenSeed...)
	m.records[record.TokenID] = &cp

	return nil
}

func (m *memoryStore) Load(ctx context.Context, id TokenID) (*Record, error) {
	if m.loadErr != nil {
		return nil, m.loadErr
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	record, ok := m.records[id]
	if !ok {
		return nil, ErrTokenNotFound
	}

	// return a defensive copy so callers mutating the returned Record
	// cannot silently corrupt the store's internal state outside of the
	// exported Store methods.
	cp := *record
	cp.TokenSeed = append([]byte(nil), record.TokenSeed...)
	return &cp, nil
}

func (m *memoryStore) Revoke(ctx context.Context, id TokenID) error {
	if m.revokeErr != nil {
		return m.revokeErr
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	record, ok := m.records[id]
	if !ok {
		return ErrTokenNotFound
	}

	record.Revoked = true
	return nil
}

// mutateSeed directly overwrites the stored seed for id, bypassing the
// Store interface entirely. It exists only to simulate "stored seed changed
// server-side" scenarios in tests, which is not something achievable
// through the narrow public Store contract by design.
func (m *memoryStore) mutateSeed(id TokenID, seed []byte) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if record, ok := m.records[id]; ok {
		record.TokenSeed = seed
	}
}

// setExpiresAt directly overwrites the stored expiry for id, bypassing the
// Store interface, so expiry tests do not have to sleep for real wall-clock
// time.
func (m *memoryStore) setExpiresAt(id TokenID, t time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if record, ok := m.records[id]; ok {
		record.ExpiresAt = t
	}
}

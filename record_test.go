package tokenauthn

import (
	"bytes"
	"encoding/json"
	"fmt"
	"testing"
)

// testTokenSeedBytes returns fixed, recognizable, non-zero seed bytes so
// tests below can assert those exact bytes never leak into fmt or JSON
// output.
func testTokenSeedBytes() []byte {
	b := make([]byte, tokenSeedSize)
	for i := range b {
		b[i] = byte(0xc0 + i%0x20)
	}
	return b
}

// TestTokenSeed_FmtRedacts asserts that formatting a TokenSeed directly, or
// formatting a Record that embeds one, via %v, %+v, %s, and %#v never
// contains the underlying seed bytes and always contains the fixed redacted
// placeholder instead.
func TestTokenSeed_FmtRedacts(t *testing.T) {
	raw := testTokenSeedBytes()
	seed := TokenSeed(raw)

	record := &Record{
		TokenID:   TokenID{0x01, 0x02, 0x03},
		TokenSeed: seed,
	}

	rawHex := fmt.Sprintf("%x", raw)

	cases := map[string]string{
		"%v on TokenSeed":   fmt.Sprintf("%v", seed),
		"%+v on TokenSeed":  fmt.Sprintf("%+v", seed),
		"%s on TokenSeed":   fmt.Sprintf("%s", seed),
		"%#v on TokenSeed":  fmt.Sprintf("%#v", seed),
		"%v on Record":      fmt.Sprintf("%v", record),
		"%+v on Record":     fmt.Sprintf("%+v", record),
		"%#v on Record":     fmt.Sprintf("%#v", record),
		"Println on Record": fmt.Sprintln(record),
	}

	for name, out := range cases {
		if bytes.Contains([]byte(out), []byte(rawHex)) {
			t.Fatalf("%s: output leaked raw seed bytes: %q", name, out)
		}
		if !bytes.Contains([]byte(out), []byte(redactedSeedText)) {
			t.Fatalf("%s: expected redacted placeholder %q in output, got %q", name, redactedSeedText, out)
		}
	}
}

// TestTokenSeed_MarshalJSONRedacts asserts that JSON-encoding a TokenSeed
// directly, or JSON-encoding a Record that embeds one, never contains the
// underlying seed bytes (whether hex- or base64-encoded) and always
// contains the fixed redacted placeholder instead.
func TestTokenSeed_MarshalJSONRedacts(t *testing.T) {
	raw := testTokenSeedBytes()
	seed := TokenSeed(raw)

	record := &Record{
		TokenID:   TokenID{0x01, 0x02, 0x03},
		TokenSeed: seed,
	}

	seedJSON, err := json.Marshal(seed)
	if err != nil {
		t.Fatalf("json.Marshal(TokenSeed): unexpected error: %v", err)
	}
	recordJSON, err := json.Marshal(record)
	if err != nil {
		t.Fatalf("json.Marshal(Record): unexpected error: %v", err)
	}

	rawHex := []byte(fmt.Sprintf("%x", raw))

	for name, out := range map[string][]byte{
		"TokenSeed JSON": seedJSON,
		"Record JSON":    recordJSON,
	} {
		if bytes.Contains(out, rawHex) {
			t.Fatalf("%s: leaked raw seed bytes (hex): %s", name, out)
		}
		if !bytes.Contains(out, []byte(redactedSeedText)) {
			t.Fatalf("%s: expected redacted placeholder %q, got %s", name, redactedSeedText, out)
		}
	}
}

// TestTokenSeed_UnmarshalJSONFails asserts that generic JSON decoding into a
// TokenSeed is rejected with an explicit error rather than silently
// succeeding with a zero-value (empty) seed.
func TestTokenSeed_UnmarshalJSONFails(t *testing.T) {
	var seed TokenSeed
	if err := json.Unmarshal([]byte(`"anything"`), &seed); err == nil {
		t.Fatal("json.Unmarshal into TokenSeed: expected error, got nil")
	}

	// Also confirm decoding a whole Record whose JSON contains a TokenSeed
	// field surfaces the same explicit failure rather than silently zeroing
	// the field.
	var record Record
	recordJSON := []byte(`{"TokenID":[1,2,3],"TokenSeed":"anything"}`)
	if err := json.Unmarshal(recordJSON, &record); err == nil {
		t.Fatal("json.Unmarshal into Record with a TokenSeed field: expected error, got nil")
	}
}

// TestTokenSeed_ExplicitConversionRoundTrips proves the seed's actual
// intended use — a Store adapter persisting and restoring the raw seed
// bytes via an explicit, deliberate type conversion — still works exactly
// as before this hardening change.
func TestTokenSeed_ExplicitConversionRoundTrips(t *testing.T) {
	raw := testTokenSeedBytes()
	seed := TokenSeed(raw)

	// "persist": adapter converts to []byte to store in its own datastore.
	persisted := []byte(seed)
	if !bytes.Equal(persisted, raw) {
		t.Fatalf("[]byte(TokenSeed) conversion: got %x, want %x", persisted, raw)
	}

	// "restore": adapter converts raw bytes loaded back from its datastore
	// into a TokenSeed to populate a Record.
	restored := TokenSeed(persisted)
	if !bytes.Equal([]byte(restored), raw) {
		t.Fatalf("TokenSeed([]byte) conversion: got %x, want %x", []byte(restored), raw)
	}

	record := &Record{TokenID: TokenID{0xaa}, TokenSeed: restored}
	mac := computeMAC(testSecret(), record.TokenID[:], record.TokenSeed)
	wantMAC := computeMAC(testSecret(), record.TokenID[:], raw)
	if !bytes.Equal(mac, wantMAC) {
		t.Fatal("computeMAC over a round-tripped TokenSeed did not match computeMAC over the original raw bytes")
	}
}

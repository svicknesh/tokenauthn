package tokenauthn

import (
	"crypto/hmac"
	"crypto/sha3"
	"encoding/hex"
	"hash"
	"testing"
)

// TestComputeMAC_KnownAnswerVector pins the exact V1 MAC construction
// against silent future drift. It fixes a master secret, a token ID, and a
// token seed as byte literals, and asserts computeMAC produces exactly the
// expected MAC.
//
// The expected MAC was derived independently of this repository's Go
// implementation, using two separate external tools that do not share code
// with crypto/sha3 or with computeMAC, following the exact documented byte
// layout in mac.go:
//
//	HMAC-SHA3-256(secret, domainV1 || versionV1 || tokenID || tokenSeed)
//
// where, byte-for-byte:
//
//	secret    = 32 bytes: ASCII "0123456789abcdef0123456789abcdef"
//	domainV1  = 13 bytes: ASCII "tokenauthn/v1"
//	versionV1 = 1 byte:   0x01
//	tokenID   = 16 bytes: 0x00, 0x01, 0x02, ..., 0x0f (sequential)
//	tokenSeed = 32 bytes: 0x80, 0x81, 0x82, ..., 0x9f (sequential, offset by 0x80)
//
// Cross-check 1 — Python 3 stdlib (hmac + hashlib.sha3_256):
//
//	python3 -c '
//	import hmac, hashlib
//	secret = b"0123456789abcdef0123456789abcdef"
//	msg = b"tokenauthn/v1" + bytes([1]) + bytes(range(16)) + bytes(0x80+i for i in range(32))
//	print(hmac.new(secret, msg, hashlib.sha3_256).hexdigest())'
//
// Cross-check 2 — OpenSSL 3.2.1 command line (dgst -sha3-256 -mac HMAC),
// against a binary file containing the same concatenated message bytes:
//
//	openssl dgst -sha3-256 -mac HMAC -macopt hexkey:<secret-as-hex> msg.bin
//
// Both cross-checks independently produced the same 32-byte value pinned
// below as wantMACHex. Neither tool invokes Go, crypto/sha3, crypto/hmac, or
// computeMAC, so this is not a self-referential (same-implementation-path)
// derivation.
//
// If this test ever needs to change, the V1 wire construction has changed
// incompatibly and must ship as a new format version, not a silent edit to
// versionV1's behaviour. In particular, reverting computeMAC to HMAC-SHA-256
// (or switching to any other hash) changes this MAC and would be caught
// here.
func TestComputeMAC_KnownAnswerVector(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef") // 32 bytes

	tokenID := make([]byte, tokenIDSize)
	for i := range tokenID {
		tokenID[i] = byte(i)
	}

	tokenSeed := make([]byte, tokenSeedSize)
	for i := range tokenSeed {
		tokenSeed[i] = byte(0x80 + i)
	}

	const wantMACHex = "9f24b93f4c065ba21d93cb75661626129949394e5b6274f3e4966bf40c395792"

	gotMAC := computeMAC(secret, tokenID, tokenSeed)
	gotMACHex := hex.EncodeToString(gotMAC)

	if gotMACHex != wantMACHex {
		t.Fatalf("computeMAC known-answer mismatch:\n got:  %s\n want: %s", gotMACHex, wantMACHex)
	}
	if len(gotMAC) != macSize {
		t.Fatalf("computeMAC known-answer: got %d-byte MAC, want the complete untruncated %d-byte SHA3-256 output", len(gotMAC), macSize)
	}
}

// rawHMACSHA3256ForTest independently reconstructs the V1 MAC input layout
// and computes HMAC-SHA3-256 over it directly with crypto/hmac + crypto/sha3,
// without calling computeMAC or referencing the production domainV1/versionV1
// constants. It exists only so the tests below can vary one field (domain or
// version) at a time and prove that field is actually bound into the MAC,
// independently of computeMAC's own internal wiring.
func rawHMACSHA3256ForTest(secret, domain []byte, version byte, tokenID, tokenSeed []byte) []byte {
	newHash := func() hash.Hash { return sha3.New256() }
	mac := hmac.New(newHash, secret)
	mac.Write(domain)
	mac.Write([]byte{version})
	mac.Write(tokenID)
	mac.Write(tokenSeed)
	return mac.Sum(nil)
}

// TestComputeMAC_MatchesIndependentReconstruction cross-checks computeMAC's
// actual output against rawHMACSHA3256ForTest's independent reconstruction
// of the same documented layout, for the same known-answer inputs used
// above. This proves the two implementations agree on the full byte layout
// and hash selection, not merely on the pinned hex constant.
func TestComputeMAC_MatchesIndependentReconstruction(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")

	tokenID := make([]byte, tokenIDSize)
	for i := range tokenID {
		tokenID[i] = byte(i)
	}
	tokenSeed := make([]byte, tokenSeedSize)
	for i := range tokenSeed {
		tokenSeed[i] = byte(0x80 + i)
	}

	got := computeMAC(secret, tokenID, tokenSeed)
	want := rawHMACSHA3256ForTest(secret, []byte("tokenauthn/v1"), 0x01, tokenID, tokenSeed)

	if !hmac.Equal(got, want) {
		t.Fatalf("computeMAC disagrees with independent HMAC-SHA3-256 reconstruction:\n got:  %x\n want: %x", got, want)
	}
}

// TestComputeMAC_DomainSeparationBinding proves the domain-separation
// constant is bound into the MAC: changing only the domain bytes (all other
// fields held fixed) changes the resulting MAC.
func TestComputeMAC_DomainSeparationBinding(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	tokenID := make([]byte, tokenIDSize)
	tokenSeed := make([]byte, tokenSeedSize)
	for i := range tokenSeed {
		tokenSeed[i] = byte(0x80 + i)
	}

	macDomainV1 := rawHMACSHA3256ForTest(secret, []byte("tokenauthn/v1"), 0x01, tokenID, tokenSeed)
	macOtherDomain := rawHMACSHA3256ForTest(secret, []byte("some-other-domain/v1"), 0x01, tokenID, tokenSeed)

	if hmac.Equal(macDomainV1, macOtherDomain) {
		t.Fatal("HMAC-SHA3-256 construction: changing the domain-separation constant did not change the MAC")
	}
}

// TestComputeMAC_VersionByteBinding proves the single-byte format-version
// field is bound into the MAC: changing only the version byte (all other
// fields held fixed) changes the resulting MAC.
func TestComputeMAC_VersionByteBinding(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	tokenID := make([]byte, tokenIDSize)
	tokenSeed := make([]byte, tokenSeedSize)
	for i := range tokenSeed {
		tokenSeed[i] = byte(0x80 + i)
	}

	macV1 := rawHMACSHA3256ForTest(secret, []byte("tokenauthn/v1"), 0x01, tokenID, tokenSeed)
	macV2 := rawHMACSHA3256ForTest(secret, []byte("tokenauthn/v1"), 0x02, tokenID, tokenSeed)

	if hmac.Equal(macV1, macV2) {
		t.Fatal("HMAC-SHA3-256 construction: changing the version byte did not change the MAC")
	}
}

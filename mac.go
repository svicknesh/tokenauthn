package tokenauthn

import (
	"crypto/hmac"
	"crypto/sha3"
	"hash"
)

// macSize is the length in bytes of a full, untruncated HMAC-SHA3-256
// output. crypto/sha3 does not export a named size constant for the
// SHA3-256 variant (unlike crypto/sha256's sha256.Size), so this is pinned
// as a literal here and cross-checked by the known-answer tests in
// knownanswer_test.go.
const macSize = 32 // HMAC-SHA3-256 (256-bit) output length in bytes

// domainV1 is the tokenauthn-specific V1 domain-separation constant mixed
// into every MAC. It exists so that a MAC computed by tokenauthn can never
// collide in meaning with a MAC computed by an unrelated protocol that
// happens to reuse the same master secret. This value is part of the frozen
// V1 wire construction: changing it would invalidate every previously issued
// V1 token.
var domainV1 = []byte("tokenauthn/v1")

// versionV1 is the single-byte format version mixed into the MAC input, in
// addition to being carried explicitly (as the literal string "v1") in the
// bearer token's wire format.
const versionV1 = byte(0x01)

// newSHA3_256 adapts crypto/sha3.New256 — which returns the concrete *sha3.SHA3
// type — to the func() hash.Hash constructor signature crypto/hmac.New
// requires. crypto/sha3.SHA3 implements hash.Hash; this is purely a type
// adaptation, not a custom hash or HMAC implementation.
func newSHA3_256() hash.Hash {
	return sha3.New256()
}

// computeMAC derives the HMAC-SHA3-256 MAC for a token using the exact V1
// byte layout, in order, with no separators:
//
//	domainV1     13 bytes  fixed constant: "tokenauthn/v1"
//	versionV1     1 byte   fixed constant: 0x01
//	tokenID      16 bytes  fixed width (tokenIDSize)
//	tokenSeed    32 bytes  fixed width (tokenSeedSize)
//
// Every field in this layout has a fixed, constant, known-in-advance length.
// That makes the concatenation unambiguous without needing length prefixes
// or separators: no field's bytes can ever be reinterpreted as belonging to
// an adjacent field, regardless of the field's content, because the field
// boundaries never move.
//
// The hash function is the standard library's crypto/hmac construction over
// crypto/sha3's New256 (SHA3-256), not a hand-rolled HMAC or a raw
// (non-HMAC) SHA3 construction. This is a deliberate V1 algorithm choice
// made before tokenauthn's first release — not a fix for a weakness in
// HMAC-SHA-256, which was never externally released.
//
// This layout is part of the frozen V1 wire construction (see the
// known-answer tests in knownanswer_test.go, which pin this exact byte
// layout and hash selection against silent future drift). A future
// incompatible change must ship as a new version, not a change to this
// function's behaviour for versionV1.
func computeMAC(secret, tokenID, tokenSeed []byte) []byte {
	mac := hmac.New(newSHA3_256, secret)
	mac.Write(domainV1)
	mac.Write([]byte{versionV1})
	mac.Write(tokenID)
	mac.Write(tokenSeed)
	return mac.Sum(nil)
}

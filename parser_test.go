package tokenauthn

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestVerify_ParserHardening(t *testing.T) {
	ctx := context.Background()
	store := newMemoryStore()
	a := mustAuthenticator(t, store)

	validToken, _, err := a.Mint(ctx)
	if err != nil {
		t.Fatalf("Mint: unexpected error: %v", err)
	}

	cases := map[string]string{
		"empty input":               "",
		"single char":               "v",
		"random garbage short":      "not-a-token-at-all",
		"random garbage long":       strings.Repeat("garbage-input-not-a-token-", 20),
		"oversized input":           strings.Repeat("a", 1_000_000),
		"only separators":           "..",
		"no separators at all":      strings.ReplaceAll(validToken, ".", ""),
		"unsupported version v0":    strings.Replace(validToken, "v1.", "v0.", 1),
		"unsupported version v2":    strings.Replace(validToken, "v1.", "v2.", 1),
		"unsupported version blank": strings.Replace(validToken, "v1.", ".", 1),
		"leading whitespace":        " " + validToken,
		"trailing whitespace":       validToken + " ",
		"embedded newline":          strings.Replace(validToken, ".", "\n", 1),
		"null bytes":                "v1.\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00." + strings.Repeat("0", wireMACHexLen),
	}

	for name, input := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := a.Verify(ctx, input); !errors.Is(err, ErrInvalidToken) {
				t.Fatalf("Verify(%q): got err %v, want ErrInvalidToken", truncateForLog(input), err)
			}
		})
	}
}

// truncateForLog keeps test failure output readable for the oversized-input
// case without printing a megabyte of garbage into the test log.
func truncateForLog(s string) string {
	const max = 80
	if len(s) <= max {
		return s
	}
	return s[:max] + "...(truncated)"
}

func TestParseBearerToken_NeverPanics(t *testing.T) {
	inputs := []string{
		"",
		".",
		"..",
		"...",
		"v1..",
		"v1.." + strings.Repeat("0", wireMACHexLen),
		"v1." + strings.Repeat("0", wireTokenIDHexLen) + "..",
		strings.Repeat(".", 200),
		strings.Repeat("v1.", 50),
	}

	for _, in := range inputs {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("parseBearerToken(%q) panicked: %v", in, r)
				}
			}()
			_, _, _ = parseBearerToken(in)
		}()
	}
}

// FuzzVerify targets the bearer-token parse/verify boundary directly, using
// the public Authenticator.Verify entry point. It is seeded with a validly
// minted token plus known edge cases, and its only assertion (enforced by
// the Go fuzzing engine itself) is that Verify never panics on arbitrary
// input.
func FuzzVerify(f *testing.F) {
	ctx := context.Background()
	store := newMemoryStore()
	a, err := NewAuthenticator(testSecret(), store)
	if err != nil {
		f.Fatalf("NewAuthenticator: unexpected error: %v", err)
	}

	validToken, _, err := a.Mint(ctx)
	if err != nil {
		f.Fatalf("Mint: unexpected error: %v", err)
	}

	seeds := []string{
		validToken,
		"",
		"v1..",
		"v1.a.b",
		strings.Repeat("a", 1000),
		strings.ToUpper(validToken),
		strings.Replace(validToken, "v1.", "v2.", 1),
		strings.Replace(validToken, ".", "\n", 1),
		validToken[:len(validToken)-1],
		validToken + "x",
		"v1." + strings.Repeat("0", wireTokenIDHexLen) + "." + strings.Repeat("0", wireMACHexLen),
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, input string) {
		// The only property under test here is "no panic" — any error
		// return (or, extremely unlikely for random input, a successful
		// verify of a token that happens to encode a real stored ID/MAC
		// pair) is an acceptable outcome.
		_, _ = a.Verify(ctx, input)
	})
}

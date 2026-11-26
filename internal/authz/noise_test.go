package authz

import "testing"

// TestSameButNoise: two answers are one page when only random-looking
// values differ, each replaced the same way; a changed name, flag or layout
// makes them two pages (issue #95).
func TestSameButNoise(t *testing.T) {
	page := func(body string) Answer { return Answer{Status: 200, Body: []byte(body)} }
	for _, c := range []struct {
		name string
		x, y string
		want bool
	}{
		{"same", `<p>a</p>`, `<p>a</p>`, true},
		{"nonce", `<s nonce="d1BP6ubL90Ty+o9jGUOi1w==">x</s><s nonce="d1BP6ubL90Ty+o9jGUOi1w==">`, `<s nonce="JvulLOsYqhAEeQpIwge54g==">x</s><s nonce="JvulLOsYqhAEeQpIwge54g==">`, true}, // gitleaks:allow (nonces and React IDs from a page, not secrets)
		// Porchlet: the nonce and React's per-request IDs.
		{"nonce and IDs", `n="d1BP6ubL90Ty+o9jGUOi1w==" "kAnTlOIUp1dw9U6hkULEiv" "kAnTlOIUp1dw9U6hkULEim"`, `n="JvulLOsYqhAEeQpIwge54g==" "qTrFdTZMZolUZS5fVyVebv" "qTrFdTZMZolUZS5fVyVebm"`, true}, // gitleaks:allow (nonces and React IDs from a page, not secrets)
		{"one token two ways", `"kAnTlOIUp1dw9U6hkULEiv" "kAnTlOIUp1dw9U6hkULEiv"`, `"qTrFdTZMZolUZS5fVyVebv" "JvulLOsYqhAEeQpIwge54g"`, false},                                                     // gitleaks:allow (nonces and React IDs from a page, not secrets)
		{"flag", `{"deleted":false,"n":"d1BP6ubL90Ty+o9jGUOi1w=="}`, `{"deleted":true,"n":"JvulLOsYqhAEeQpIwge54g=="}`, false},                                                                      // gitleaks:allow (nonces and React IDs from a page, not secrets)
		{"name", `<p>Alice</p>`, `<p>Bob</p>`, false},
		{"layout", `<s>push("a")</s>`, `<s>push("a");</s><s>push("b")</s>`, false},
	} {
		if got := sameButNoise(page(c.x), page(c.y)); got != c.want {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
	if sameButNoise(Answer{Status: 200, Body: []byte("a")}, Answer{Status: 404, Body: []byte("a")}) {
		t.Error("different status: same")
	}
}

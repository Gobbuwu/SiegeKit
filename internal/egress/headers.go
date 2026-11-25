package egress

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
)

// ExtraHeadersEnv holds headers sent on every request to the target (ADR
// 0070), one "Name: value" per line, such as a hosting provider's bypass
// header for a protected preview. It is read from the environment so the
// value stays out of shell history, and every value is hidden in the
// reports.
const ExtraHeadersEnv = "SIEGEKIT_EXTRA_HEADERS"

// MinExtraValue is the shortest value ParseExtraHeaders accepts. Every
// value is treated as a secret and hidden wherever it appears in a report;
// hiding a shorter one would also hide ordinary text.
const MinExtraValue = 8

// maxExtraHeaders caps the variable's size.
const maxExtraHeaders = 8 << 10

// ParseExtraHeaders reads ExtraHeadersEnv. It refuses, without quoting the
// text (which may hold the secret): a variable with no header, a line
// without "Name: value", a header name that is not a valid token, an empty
// or short value or one with control characters, a name given twice, and
// the headers SiegeKit or the transport own (Host, User-Agent, the
// connection, transfer and proxy headers, and Content-Type, which each
// request sets for its own body). Session headers are refused by
// the caller, which knows them (authz.IsSessionHeader).
func ParseExtraHeaders(s string) (http.Header, error) {
	if len(s) > maxExtraHeaders {
		return nil, fmt.Errorf("%s is longer than %d KiB", ExtraHeadersEnv, maxExtraHeaders>>10)
	}
	h := http.Header{}
	for i, line := range strings.Split(strings.ReplaceAll(s, "\r\n", "\n"), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		n := i + 1
		name, value, ok := strings.Cut(line, ":")
		name, value = strings.TrimSpace(name), strings.TrimSpace(value)
		switch {
		case !ok:
			return nil, fmt.Errorf("%s line %d has no \":\"; write one \"Name: value\" header per line", ExtraHeadersEnv, n)
		case !validName(name):
			return nil, fmt.Errorf("%s line %d: the header name is not valid", ExtraHeadersEnv, n)
		case value == "":
			return nil, fmt.Errorf("%s line %d: the value of %s is empty (was the secret pasted?)", ExtraHeadersEnv, n, http.CanonicalHeaderKey(name))
		case !validValue(value):
			return nil, fmt.Errorf("%s line %d: the value of %s has a control character", ExtraHeadersEnv, n, http.CanonicalHeaderKey(name))
		case len(value) < MinExtraValue:
			return nil, fmt.Errorf("%s line %d: the value of %s is shorter than %d characters; every value is hidden in the reports as a secret, and a shorter one would hide ordinary text", ExtraHeadersEnv, n, http.CanonicalHeaderKey(name), MinExtraValue)
		}
		k := http.CanonicalHeaderKey(name)
		if fixedHeader[k] || k == "Content-Type" || strings.HasPrefix(k, "Proxy-") {
			return nil, fmt.Errorf("%s cannot set %s: SiegeKit, each request or the connection sets it", ExtraHeadersEnv, k)
		}
		if h[k] != nil {
			return nil, fmt.Errorf("%s names %s twice", ExtraHeadersEnv, k)
		}
		h[k] = []string{value}
	}
	if len(h) == 0 {
		return nil, errors.New(ExtraHeadersEnv + " is set but holds no header (was the secret pasted?); write one \"Name: value\" per line, or unset it")
	}
	return h, nil
}

// validName reports whether s is an RFC 9110 token.
func validName(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.IndexByte("!#$%&'*+-.^_`|~", c) >= 0) {
			return false
		}
	}
	return true
}

// validValue reports whether s has no control characters (RFC 9110
// field-value; tab is allowed inside).
func validValue(s string) bool {
	for i := 0; i < len(s); i++ {
		if c := s[i]; c < ' ' && c != '\t' || c == 0x7f {
			return false
		}
	}
	return true
}

// addExtra sets cfg's extra headers on h, replacing a header of the same
// name that a tool or check set, so the target gets exactly what the
// person gave.
func addExtra(h http.Header, extra http.Header) {
	for k, vs := range extra {
		h[k] = append([]string(nil), vs...)
	}
}

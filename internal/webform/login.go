package webform

import (
	"net/url"
	"strings"
	"unicode"
)

// loginWords in a redirect's path mean "log in first".
var loginWords = map[string]bool{"login": true, "logon": true, "signin": true, "auth": true, "sso": true, "oauth": true, "oauth2": true, "authorize": true}

// LoginPage reports whether loc, a URL or a path, is a login page: a
// segment of its path is a login word ("login", "signin", "auth", "sso",
// "oauth2", "authorize" and the like) or holds one, in any case and with
// "-" or "_" inside ("sign_in", "signIn"). The query is not read, so
// "/w/1?next=/login" is not one. An empty or unparsable loc is not one.
// The write check (internal/authz) and the rate-limit check use it to tell
// a login wall from the app's own answer (ADR 0073).
func LoginPage(loc string) bool {
	u, err := url.Parse(loc)
	if loc == "" || err != nil {
		return false
	}
	for _, seg := range strings.Split(u.Path, "/") {
		joined := strings.NewReplacer("-", "", "_", "").Replace(strings.ToLower(seg))
		if loginWords[joined] {
			return true
		}
		for _, w := range Words(seg) {
			if loginWords[w] {
				return true
			}
		}
	}
	return false
}

// Words splits s into lower-case words at characters other than letters
// and digits, and where a lower-case letter meets an upper-case one.
func Words(s string) []string {
	var out []string
	var cur []rune
	var prev rune
	flush := func() {
		if len(cur) > 0 {
			out = append(out, strings.ToLower(string(cur)))
			cur = cur[:0]
		}
	}
	for _, r := range s {
		switch {
		case !unicode.IsLetter(r) && !unicode.IsDigit(r):
			flush()
		case unicode.IsUpper(r) && unicode.IsLower(prev):
			flush()
			cur = append(cur, r)
		default:
			cur = append(cur, r)
		}
		prev = r
	}
	flush()
	return out
}

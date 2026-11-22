package coderoutes

import (
	"strings"
)

// normalizePath turns a route pattern into the sweep's form: path
// parameters as {name} (gorilla and chi {name:regex}, Express, gin and
// echo :name), a leading slash, no trailing slash, no empty segments. It
// refuses a pattern with a wildcard (*, {name...}) or a parameter it
// cannot name: what such a route matches is not one path. A parameter
// whose pattern only lists words ({type:issues|pulls}) is a choice of
// fixed segments: one path is returned for each word, at most
// maxAlternatives in all.
func normalizePath(p string) ([]string, bool) {
	out := []string{""}
	write := func(s string) {
		for i := range out {
			out[i] += s
		}
	}
	for i := 0; i < len(p); i++ {
		c := p[i]
		switch c {
		case '{':
			depth, j := 0, i
			for ; j < len(p); j++ {
				if p[j] == '{' {
					depth++
				} else if p[j] == '}' {
					depth--
					if depth == 0 {
						break
					}
				}
			}
			if j >= len(p) {
				return nil, false
			}
			name, pattern := p[i+1:j], ""
			if k := strings.IndexByte(name, ':'); k >= 0 {
				name, pattern = name[:k], name[k+1:]
			}
			name = strings.TrimSpace(name)
			if name == "" || strings.HasSuffix(name, "...") || !isName(name) {
				return nil, false
			}
			if words := wordChoice(pattern); words != nil && len(out)*len(words) <= maxAlternatives {
				var next []string
				for _, o := range out {
					for _, wd := range words {
						next = append(next, o+wd)
					}
				}
				out = next
			} else {
				write("{" + name + "}")
			}
			i = j
		case ':':
			// :name at the start of a segment (Express, gin, echo). A
			// colon inside a segment (Rocket.Chat's "a:b"?) is kept.
			if i == 0 || p[i-1] == '/' {
				j := i + 1
				for j < len(p) && (isNameByte(p[j])) {
					j++
				}
				if j == i+1 {
					return nil, false
				}
				name := p[i+1 : j]
				// Express optional (:id?) and regex (:id(\d+)) forms.
				if j < len(p) && (p[j] == '?' || p[j] == '(') {
					return nil, false
				}
				write("{" + name + "}")
				i = j - 1
				continue
			}
			write(string(c))
		case '*':
			return nil, false
		default:
			write(string(c))
		}
	}
	for i, o := range out {
		if !strings.HasPrefix(o, "/") {
			o = "/" + o
		}
		for strings.Contains(o, "//") {
			o = strings.ReplaceAll(o, "//", "/")
		}
		if len(o) > 1 {
			o = strings.TrimSuffix(o, "/")
		}
		if strings.ContainsAny(o, " \t\n\r?#") {
			return nil, false
		}
		out[i] = o
	}
	return out, true
}

const maxAlternatives = 16

// wordChoice returns the words of a pattern that is only words joined by
// "|" (teams|channels), or nil.
func wordChoice(pattern string) []string {
	if !strings.Contains(pattern, "|") {
		return nil
	}
	words := strings.Split(pattern, "|")
	for _, w := range words {
		if !isName(w) {
			return nil
		}
	}
	return words
}

func isNameByte(c byte) bool {
	return c == '_' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
}

func isName(s string) bool {
	for i := 0; i < len(s); i++ {
		if !isNameByte(s[i]) && s[i] != '-' {
			return false
		}
	}
	return s != ""
}

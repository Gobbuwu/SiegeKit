// Package htmltag reads HTML start tags the way a browser's tokenizer
// does, closely enough for the links of the served-files check (ADR 0032)
// and the login forms of ADR 0062: tag and attribute names in lower case,
// attribute values quoted or not, with character references decoded. It
// never fails; text it cannot read is skipped.
package htmltag

import (
	"bytes"
	"html"
)

// Read reads the tag that starts at page[i] ('<'). lower is page with ASCII
// letters in lower case (see Lower), so indexes match. It returns the tag
// name in lower case ("" for an end tag, a doctype or a stray '<'), its
// attributes (names in lower case, the first of each kept, values decoded
// and not trimmed; an attribute with no value is ""), and the index after
// the tag. A value longer than maxValue bytes is left out.
func Read(page, lower []byte, i, maxValue int) (string, map[string]string, int) {
	n := i + 1
	for n < len(page) && isNameByte(page[n]) {
		n++
	}
	if n == i+1 {
		return "", nil, i + 1
	}
	name := string(lower[i+1 : n])
	attrs := map[string]string{}
	p := n
	for p < len(page) {
		for p < len(page) && (IsSpace(page[p]) || page[p] == '/') {
			p++
		}
		if p >= len(page) {
			break
		}
		if page[p] == '>' {
			return name, attrs, p + 1
		}
		s := p
		for p < len(page) && !IsSpace(page[p]) && page[p] != '=' && page[p] != '>' && page[p] != '/' {
			p++
		}
		if p == s { // a lone '=' or similar: skip it
			p++
			continue
		}
		an := string(lower[s:p])
		for p < len(page) && IsSpace(page[p]) {
			p++
		}
		val := ""
		if p < len(page) && page[p] == '=' {
			p++
			for p < len(page) && IsSpace(page[p]) {
				p++
			}
			if p < len(page) && (page[p] == '"' || page[p] == '\'') {
				q := page[p]
				p++
				e := bytes.IndexByte(page[p:], q)
				if e < 0 {
					e = len(page) - p
				}
				val = string(page[p : p+e])
				p += e + 1
			} else {
				s := p
				for p < len(page) && !IsSpace(page[p]) && page[p] != '>' {
					p++
				}
				val = string(page[s:p])
			}
		}
		if _, ok := attrs[an]; !ok && len(val) <= maxValue {
			attrs[an] = html.UnescapeString(val)
		}
	}
	return name, attrs, min(p, len(page))
}

// IsSpace reports whether c is HTML white space.
func IsSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f'
}

func isNameByte(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-'
}

// Lower lower-cases ASCII letters only, so indexes stay the same.
func Lower(b []byte) []byte {
	out := make([]byte, len(b))
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		out[i] = c
	}
	return out
}

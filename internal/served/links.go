package served

import (
	"bytes"
	"html"
	"strings"
)

// Link is a reference to a file found in a page.
type Link struct {
	Kind Kind
	Ref  string // as written in the page, entities decoded
}

// maxRef caps the length of a reference that is followed.
const maxRef = 2048

// Links returns the scripts, styles and JSON files that an HTML page links:
// <script src>, and <link href> with rel stylesheet, modulepreload,
// manifest, or preload and prefetch with as script, style or fetch. It
// reads the page as a browser's tokenizer would, closely enough for links:
// comments and the content of <script> and <style> are skipped, and
// attribute values may be quoted or not. It never fails; text it cannot
// read is skipped.
func Links(page []byte) []Link {
	lower := asciiLower(page)
	var out []Link
	for i := 0; i < len(page); {
		j := bytes.IndexByte(page[i:], '<')
		if j < 0 {
			break
		}
		i += j
		if bytes.HasPrefix(page[i:], []byte("<!--")) {
			k := bytes.Index(page[i+4:], []byte("-->"))
			if k < 0 {
				break
			}
			i += 4 + k + 3
			continue
		}
		name, attrs, end := readTag(page, lower, i)
		i = end
		switch name {
		case "script", "style":
			if name == "script" {
				if ref := attrs["src"]; ref != "" {
					out = append(out, Link{Script, ref})
				}
			}
			// The content is not HTML: skip to the closing tag.
			k := bytes.Index(lower[i:], []byte("</"+name))
			if k < 0 {
				return out
			}
			i += k
		case "link":
			if k := linkKind(attrs["rel"], attrs["as"]); k != "" && attrs["href"] != "" {
				out = append(out, Link{k, attrs["href"]})
			}
		}
	}
	return out
}

func linkKind(rel, as string) Kind {
	as = strings.ToLower(as)
	for _, r := range strings.Fields(strings.ToLower(rel)) {
		switch r {
		case "stylesheet":
			return Style
		case "modulepreload":
			return Script
		case "manifest":
			return JSON
		case "preload", "prefetch":
			switch as {
			case "script":
				return Script
			case "style":
				return Style
			case "fetch":
				return JSON
			}
		}
	}
	return ""
}

// readTag reads the tag that starts at page[i] ('<'). It returns the tag
// name in lower case ("" for an end tag, a doctype or a stray '<'), its
// attributes (names in lower case, the first of each kept) and the index
// after the tag.
func readTag(page, lower []byte, i int) (string, map[string]string, int) {
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
		for p < len(page) && (isSpace(page[p]) || page[p] == '/') {
			p++
		}
		if p >= len(page) {
			break
		}
		if page[p] == '>' {
			return name, attrs, p + 1
		}
		s := p
		for p < len(page) && !isSpace(page[p]) && page[p] != '=' && page[p] != '>' && page[p] != '/' {
			p++
		}
		if p == s { // a lone '=' or similar: skip it
			p++
			continue
		}
		an := string(lower[s:p])
		for p < len(page) && isSpace(page[p]) {
			p++
		}
		val := ""
		if p < len(page) && page[p] == '=' {
			p++
			for p < len(page) && isSpace(page[p]) {
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
				for p < len(page) && !isSpace(page[p]) && page[p] != '>' {
					p++
				}
				val = string(page[s:p])
			}
		}
		if _, ok := attrs[an]; !ok && len(val) <= maxRef {
			attrs[an] = strings.TrimSpace(html.UnescapeString(val))
		}
	}
	return name, attrs, min(p, len(page))
}

// SourceMapRef returns the source map that a script or style names in its
// last sourceMappingURL comment, or "".
func SourceMapRef(body []byte) string {
	const key = "sourceMappingURL="
	i := bytes.LastIndex(body, []byte(key))
	if i < 4 {
		return ""
	}
	switch string(body[i-4 : i]) {
	case "//# ", "//@ ", "/*# ", "/*@ ":
	default:
		return ""
	}
	v := body[i+len(key):]
	e := 0
	for e < len(v) && !isSpace(v[e]) && !bytes.HasPrefix(v[e:], []byte("*/")) {
		e++
	}
	if e == 0 || e > maxRef {
		return ""
	}
	return string(v[:e])
}

func isNameByte(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-'
}

func isSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f'
}

// asciiLower lower-cases ASCII letters only, so indexes stay the same.
func asciiLower(b []byte) []byte {
	out := make([]byte, len(b))
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		out[i] = c
	}
	return out
}

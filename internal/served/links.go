package served

import (
	"bytes"
	"strings"

	"github.com/Gobbuwu/SiegeKit/internal/htmltag"
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
	lower := htmltag.Lower(page)
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
		name, attrs, end := htmltag.Read(page, lower, i, maxRef)
		for k, v := range attrs {
			attrs[k] = strings.TrimSpace(v)
		}
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
	for e < len(v) && !htmltag.IsSpace(v[e]) && !bytes.HasPrefix(v[e:], []byte("*/")) {
		e++
	}
	if e == 0 || e > maxRef {
		return ""
	}
	return string(v[:e])
}

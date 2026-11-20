// Package openapi finds and checks the OpenAPI spec that Schemathesis tests
// against (ADR 0025 item 4, ADR 0028). The check is only a sanity check
// that the document is an OpenAPI or Swagger spec; Schemathesis parses it.
// A spec is untrusted input: it is size-limited and never interpreted here
// beyond its top-level keys.
package openapi

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

// MaxSize is the largest spec accepted, in bytes.
const MaxSize = 10 << 20

// DefaultPaths are the paths tried, in order, on a local target when no
// spec is given. Each costs one GET request.
var DefaultPaths = []string{
	"/openapi.json",
	"/openapi.yaml",
	"/swagger.json",
	"/swagger.yaml",
	"/v3/api-docs",
	"/v2/api-docs",
	"/api-docs",
	"/api/openapi.json",
	"/api/swagger.json",
	"/swagger/v1/swagger.json",
}

var (
	reYAMLVersion = regexp.MustCompile(`(?m)^(openapi:[ \t]*['"]?3\.[0-9]|swagger:[ \t]*['"]?2\.0)`)
	reYAMLPaths   = regexp.MustCompile(`(?m)^paths:`)
)

// Check reports whether b is an OpenAPI 3 or Swagger 2.0 spec and returns
// its format, "json" or "yaml". JSON needs a top-level "openapi" string
// starting with "3." or "swagger" equal to "2.0", and a "paths" object.
// YAML needs the same keys on top-level lines.
func Check(b []byte) (string, error) {
	if len(b) > MaxSize {
		return "", fmt.Errorf("spec larger than %d bytes", MaxSize)
	}
	b = bytes.TrimPrefix(b, []byte("\xef\xbb\xbf"))
	t := bytes.TrimSpace(b)
	if len(t) == 0 {
		return "", errors.New("empty document")
	}
	if t[0] == '{' {
		var doc struct {
			OpenAPI any             `json:"openapi"`
			Swagger any             `json:"swagger"`
			Paths   json.RawMessage `json:"paths"`
		}
		if err := json.Unmarshal(t, &doc); err != nil {
			return "", fmt.Errorf("not valid JSON: %w", err)
		}
		v, _ := doc.OpenAPI.(string)
		sw, _ := doc.Swagger.(string)
		if !strings.HasPrefix(v, "3.") && sw != "2.0" {
			return "", errors.New(`no "openapi": "3.x" or "swagger": "2.0"`)
		}
		if p := bytes.TrimSpace(doc.Paths); len(p) == 0 || p[0] != '{' {
			return "", errors.New(`no "paths" object`)
		}
		return "json", nil
	}
	if t[0] == '<' {
		return "", errors.New("an HTML page, not a spec")
	}
	if !reYAMLVersion.Match(b) || !reYAMLPaths.Match(b) {
		return "", errors.New("no top-level openapi: 3.x or swagger: 2.0 and paths: lines")
	}
	return "yaml", nil
}

// BasePath returns the path that the spec's operation paths are relative
// to, without a trailing slash ("" for the root), and whether it could be
// read. Schemathesis keeps this path when SiegeKit gives it the target's
// origin (measured with 4.33.4 for a relative and an absolute OpenAPI 3
// server URL and a Swagger 2.0 basePath, 2026-11-20). OpenAPI 3 uses the
// first server URL, with its variables' defaults; Swagger 2.0 uses
// basePath. For YAML only plain block-style lines are read; anything else
// reports false, and the caller says the path is relative.
func BasePath(b []byte, format string) (string, bool) {
	b = bytes.TrimPrefix(b, []byte("\xef\xbb\xbf"))
	var raw string
	switch format {
	case "json":
		var doc struct {
			BasePath *string `json:"basePath"`
			Servers  []struct {
				URL       string `json:"url"`
				Variables map[string]struct {
					Default string `json:"default"`
				} `json:"variables"`
			} `json:"servers"`
		}
		if json.Unmarshal(b, &doc) != nil {
			return "", false
		}
		switch {
		case doc.BasePath != nil:
			raw = *doc.BasePath
		case len(doc.Servers) > 0:
			s := doc.Servers[0]
			raw = reVariable.ReplaceAllStringFunc(s.URL, func(v string) string {
				if d, ok := s.Variables[v[1:len(v)-1]]; ok {
					return d.Default
				}
				return v
			})
		default:
			return "", true
		}
	case "yaml":
		var ok bool
		if raw, ok = yamlBase(string(b)); !ok {
			return "", false
		}
	default:
		return "", false
	}
	return cleanBase(raw)
}

var (
	reVariable  = regexp.MustCompile(`\{[^{}]*\}`)
	reYAMLKey   = regexp.MustCompile(`^(basePath|servers):(.*)$`)
	reYAMLItem  = regexp.MustCompile(`^[ \t]*- url:(.*)$`)
	reYAMLPlain = regexp.MustCompile(`^[^'"\[\]{}&*!|>%@#,` + "`" + `\s][^#\s]*$`)
)

// yamlBase reads a top-level "basePath: value", or "servers:" followed by
// "  - url: value" on the next line that is not blank or a comment.
func yamlBase(s string) (string, bool) {
	lines := strings.Split(strings.ReplaceAll(s, "\r\n", "\n"), "\n")
	base, servers := -1, -1
	for i, l := range lines {
		m := reYAMLKey.FindStringSubmatch(l)
		if m == nil {
			continue
		}
		if m[1] == "basePath" {
			base = i
		} else {
			servers = i
		}
	}
	switch {
	case base >= 0:
		return yamlScalar(reYAMLKey.FindStringSubmatch(lines[base])[2])
	case servers < 0:
		return "", true
	}
	if rest := strings.TrimSpace(reYAMLKey.FindStringSubmatch(lines[servers])[2]); rest != "" && !strings.HasPrefix(rest, "#") {
		return "", false // flow style or an anchor
	}
	for _, l := range lines[servers+1:] {
		if t := strings.TrimSpace(l); t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		m := reYAMLItem.FindStringSubmatch(l)
		if m == nil {
			return "", false
		}
		return yamlScalar(m[1])
	}
	return "", false
}

// yamlScalar reads a plain or quoted scalar without escapes, with an
// optional trailing comment.
func yamlScalar(s string) (string, bool) {
	s = strings.TrimSpace(s)
	for _, q := range []string{`'`, `"`} {
		if strings.HasPrefix(s, q) {
			v, rest, ok := strings.Cut(s[1:], q)
			rest = strings.TrimSpace(rest)
			if !ok || strings.ContainsAny(v, `\'"`) || rest != "" && !strings.HasPrefix(rest, "#") {
				return "", false
			}
			return v, true
		}
	}
	if i := strings.Index(s, " #"); i >= 0 {
		s = strings.TrimSpace(s[:i])
	}
	if !reYAMLPlain.MatchString(s) {
		return "", false
	}
	return s, true
}

// cleanBase turns a server URL or basePath into a path without a trailing
// slash. Relative server URLs other than absolute paths, unresolved
// variables, paths with dot segments and characters that a URI must not
// hold unescaped are not read.
func cleanBase(raw string) (string, bool) {
	if raw == "" {
		return "", true
	}
	if strings.ContainsAny(raw, "{}") {
		return "", false
	}
	p := raw
	if !strings.HasPrefix(raw, "/") {
		u, err := url.Parse(raw)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return "", false
		}
		p = u.EscapedPath()
	}
	bad := func(r rune) bool { return r <= ' ' || r > '~' || strings.ContainsRune(`"<>\^`+"`"+`|`, r) }
	if strings.HasPrefix(p, "//") || strings.ContainsAny(p, "?#") || strings.ContainsFunc(p, bad) || len(p) > 1024 {
		return "", false
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == "." || seg == ".." {
			return "", false
		}
	}
	return strings.TrimRight(p, "/"), true
}

// Spec is the OpenAPI spec a run tests against.
type Spec struct {
	Data   []byte
	Format string // "json" or "yaml", from Check
	Source string // where it came from, for reports
}

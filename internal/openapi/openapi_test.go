package openapi

import (
	"strings"
	"testing"
)

func TestCheck(t *testing.T) {
	for in, want := range map[string]string{
		`{"openapi":"3.0.3","info":{},"paths":{}}`:              "json",
		"\xef\xbb\xbf" + `{"swagger":"2.0","paths":{"/a":{}}}`:  "json",
		"openapi: 3.1.0\ninfo:\n  title: t\npaths:\n  /a: {}\n": "yaml",
		"swagger: '2.0'\npaths: {}\n":                           "yaml",
	} {
		if got, err := Check([]byte(in)); got != want || err != nil {
			t.Errorf("%q: %q %v, want %q", in, got, err, want)
		}
	}
	for _, in := range []string{
		"", "   ", `{"openapi":"2.0","paths":{}}`, `{"openapi":3,"paths":{}}`, `{"openapi":"3.0.0"}`,
		`{"openapi":"3.0.0","paths":[]}`, `{"openapi":"3.0.0",`, "<!doctype html><html></html>",
		"openapi: 3.0.0\n", "  openapi: 3.0.0\npaths:\n", "hello", strings.Repeat(" ", MaxSize+1),
	} {
		if got, err := Check([]byte(in)); err == nil {
			t.Errorf("%.40q accepted as %s", in, got)
		}
	}
}

func FuzzCheck(f *testing.F) {
	f.Add([]byte(`{"openapi":"3.0.3","paths":{}}`))
	f.Add([]byte("openapi: 3.0.0\npaths:\n"))
	f.Fuzz(func(t *testing.T, b []byte) {
		if got, err := Check(b); err == nil && got != "json" && got != "yaml" {
			t.Fatalf("format %q", got)
		}
	})
}

func TestBasePath(t *testing.T) {
	for _, c := range []struct {
		in, format, want string
		ok               bool
	}{
		{`{"openapi":"3.0.3","paths":{}}`, "json", "", true},
		{`{"openapi":"3.0.3","servers":[{"url":"/api/"}],"paths":{}}`, "json", "/api", true},
		{`{"openapi":"3.0.3","servers":[{"url":"https://prod.example.com/v1"},{"url":"/x"}],"paths":{}}`, "json", "/v1", true},
		{`{"openapi":"3.0.3","servers":[{"url":"https://h/{v}","variables":{"v":{"default":"v2"}}}],"paths":{}}`, "json", "/v2", true},
		{`{"openapi":"3.0.3","servers":[{"url":"https://h/{v}"}],"paths":{}}`, "json", "", false},
		{`{"openapi":"3.0.3","servers":[{"url":"v1"}],"paths":{}}`, "json", "", false},
		{`{"openapi":"3.0.3","servers":[{"url":"/a/../b"}],"paths":{}}`, "json", "", false},
		{`{"swagger":"2.0","basePath":"/api","paths":{}}`, "json", "/api", true},
		{`{"swagger":"2.0","basePath":"/","paths":{}}`, "json", "", true},
		{`{"swagger":`, "json", "", false},
		{"openapi: 3.0.0\npaths: {}\n", "yaml", "", true},
		{"openapi: 3.0.0\nservers:\n  # prod\n  - url: https://h/api/v1 # main\npaths: {}\n", "yaml", "/api/v1", true},
		{"openapi: 3.0.0\nservers:\n- url: '/api'\npaths: {}\n", "yaml", "/api", true},
		{"openapi: 3.0.0\nservers:\n  - url: \"/api\"\npaths: {}\n", "yaml", "/api", true},
		{"openapi: 3.0.0\nservers:\n  - description: x\n    url: /api\npaths: {}\n", "yaml", "", false},
		{"openapi: 3.0.0\nservers: [{url: /api}]\npaths: {}\n", "yaml", "", false},
		{"openapi: 3.0.0\nservers:\n  - url: *a\npaths: {}\n", "yaml", "", false},
		{"openapi: 3.0.0\nservers:\n  - url: \"/a\\\"b\"\n", "yaml", "", false},
		{"swagger: '2.0'\r\nbasePath: /v2\r\npaths: {}\r\n", "yaml", "/v2", true},
		{"swagger: '2.0'\nbasePath: /v2 x\npaths: {}\n", "yaml", "", false},
		{"x", "xml", "", false},
	} {
		got, ok := BasePath([]byte(c.in), c.format)
		if got != c.want || ok != c.ok {
			t.Errorf("%q: %q %v, want %q %v", c.in, got, ok, c.want, c.ok)
		}
	}
}

func FuzzBasePath(f *testing.F) {
	f.Add([]byte("openapi: 3.0.0\nservers:\n  - url: https://h/api\n"), true)
	f.Add([]byte(`{"swagger":"2.0","basePath":"/api"}`), false)
	f.Fuzz(func(t *testing.T, b []byte, yaml bool) {
		format := "json"
		if yaml {
			format = "yaml"
		}
		p, ok := BasePath(b, format)
		if !ok && p != "" || ok && p != "" && (!strings.HasPrefix(p, "/") || strings.HasSuffix(p, "/") || strings.ContainsAny(p, "{}?# \t\n")) {
			t.Fatalf("%q %v", p, ok)
		}
	})
}

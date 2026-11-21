package openapi

import (
	"bytes"
	"encoding/json"
	"os"
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
	f.Add([]byte("var options = {\n  \"swaggerDoc\": {\"openapi\":\"3.0.0\",\"paths\":{}},\n  \"x\": function() {}\n};"))
	f.Fuzz(func(t *testing.T, b []byte) {
		if got, err := Check(b); err == nil && got != "json" && got != "yaml" {
			t.Fatalf("format %q", got)
		}
		// The setup script of ADR 0046: what it returns is one JSON value
		// taken from b.
		if spec, err := FromSwaggerUIInit(b); err == nil && (!json.Valid(spec) || !bytes.Contains(b, spec)) {
			t.Fatalf("spec %q from %q", spec, b)
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

// The setup script that Juice Shop v20.4.0 serves at /api-docs/
// swagger-ui-init.js (swagger-ui-express 5.0.1), saved on 2026-11-21.
func TestFromSwaggerUIInit(t *testing.T) {
	b, err := os.ReadFile("testdata/swagger-ui-init-juice-shop.js")
	if err != nil {
		t.Fatal(err)
	}
	spec, err := FromSwaggerUIInit(b)
	if err != nil {
		t.Fatal(err)
	}
	if f, err := Check(spec); err != nil || f != "json" {
		t.Fatalf("Check = %q, %v", f, err)
	}
	if base, ok := BasePath(spec, "json"); !ok || base != "/b2b/v2" {
		t.Errorf("BasePath = %q, %v", base, ok)
	}
	for _, tc := range []struct{ name, in string }{
		{"html", "<!doctype html><html></html>"},
		{"no options", "window.onload = function() {}"},
		{"url only", "var options = {\n  \"customOptions\": {},\n  \"swaggerUrl\": \"/spec.json\"\n};"},
		{"broken", "var options = {\n  \"swaggerDoc\": {\"openapi\": \"3.0.0\",\n"},
	} {
		if _, err := FromSwaggerUIInit([]byte(tc.in)); err == nil {
			t.Errorf("%s: no error", tc.name)
		}
	}
	// Functions in later options do not matter.
	in := "var options = {\n  \"swaggerDoc\": {\"openapi\": \"3.0.1\", \"paths\": {}},\n  \"customOptions\": {\"f\": function() {}}\n};"
	spec, err = FromSwaggerUIInit([]byte(in))
	if err != nil || string(spec) != `{"openapi": "3.0.1", "paths": {}}` {
		t.Errorf("got %q, %v", spec, err)
	}
}

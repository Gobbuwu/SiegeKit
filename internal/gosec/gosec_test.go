package gosec

import (
	"slices"
	"strings"
	"testing"
)

// The "Golang errors" part of a gosec 2.30.0 JSON report, trimmed from a
// real offline run on go-chi/chi@c64ed7d (2026-11-21): one file with type
// errors and one package that could not be loaded at all.
const offlineReport = `{
	"Golang errors": {
		"/target/_examples/rest/main.go": [
			{"line": 46, "column": 2, "error": "could not import github.com/go-chi/docgen (invalid package name: \"\")"}
		],
		"/target/_examples/versions": [
			{"line": 0, "column": 0, "error": "github.com/go-chi/render@v1.0.1: module lookup disabled by GOPROXY=off"}
		],
		"/target/_examples/versions/data": [
			{"line": 0, "column": 0, "error": "module lookup disabled"}
		]
	},
	"Issues": [],
	"Stats": {"files": 70, "lines": 9000, "nosec": 0, "found": 70}
}`

func TestUncovered(t *testing.T) {
	got, err := Uncovered(strings.NewReader(offlineReport), "/target")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"_examples/rest", "_examples/versions", "_examples/versions/data"}
	if !slices.Equal(got, want) {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestUncoveredNone(t *testing.T) {
	got, err := Uncovered(strings.NewReader(`{"Golang errors": {}, "Issues": [], "Stats": {}}`), "/target")
	if err != nil || len(got) != 0 {
		t.Fatalf("got %q %v, want none", got, err)
	}
}

func TestUncoveredRejects(t *testing.T) {
	for name, in := range map[string]string{
		"not json":     "not json",
		"no error key": `{"Issues": []}`,
		"wrong type":   `{"Golang errors": []}`,
		"too large":    `{"Golang errors": {}, "x": "` + strings.Repeat("a", MaxSize) + `"}`,
	} {
		if _, err := Uncovered(strings.NewReader(in), "/target"); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestDir(t *testing.T) {
	for in, want := range map[string]string{
		"/target/main.go":          ".",
		"/target":                  ".",
		"/target/a/b":              "a/b",
		"/target/a/b/c.go":         "a/b",
		"/target/../etc/x.go":      "etc", // cleaned; outside the mount it is shown as is
		"/other/pkg":               "other/pkg",
		"/target/a\\b.go":          "a",
		"/targetx/y.go":            "targetx",
		"/target/a/./b/../c/d.go":  "a/c",
		"relative/path/to/file.go": "relative/path/to",
	} {
		if got := dir(in, "/target"); got != want {
			t.Errorf("dir(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestReason(t *testing.T) {
	one := Reason([]string{"cmd/app"})
	if !strings.Contains(one, "1 Go package,") || !strings.Contains(one, "cmd/app") || !strings.Contains(one, "Findings in the other packages are kept") {
		t.Errorf("one: %s", one)
	}
	var many []string
	for i := range 12 {
		many = append(many, "p"+string(rune('a'+i)))
	}
	r := Reason(many)
	if !strings.Contains(r, "12 Go packages") || !strings.Contains(r, "pj and 2 more") || strings.Contains(r, "pk") {
		t.Errorf("many: %s", r)
	}
}

func FuzzGosecErrors(f *testing.F) {
	f.Add(offlineReport)
	f.Add(`{"Golang errors": {}}`)
	f.Add(`{"Golang errors": {"": null, "/": [], "/target/../..": {}}}`)
	f.Fuzz(func(t *testing.T, in string) {
		dirs, err := Uncovered(strings.NewReader(in), "/target")
		if err != nil {
			return
		}
		if !slices.IsSorted(dirs) {
			t.Fatalf("not sorted: %q", dirs)
		}
		for _, d := range dirs {
			if strings.HasPrefix(d, "/") {
				t.Fatalf("absolute: %q", d)
			}
		}
		if len(dirs) > 0 && Reason(dirs) == "" {
			t.Fatal("empty reason")
		}
	})
}

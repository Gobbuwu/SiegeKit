package gosec

import (
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
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
	"Stats": {"files": 49, "lines": 9000, "nosec": 0, "found": 70}
}`

// Uncovered returns the package directories, relative to mount and sorted,
// that gosec reported load or type errors for.
func Uncovered(r io.Reader, mount string) ([]string, error) {
	res, err := Read(r, mount)
	return res.Uncovered, err
}

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
	got, err := Uncovered(strings.NewReader(`{"Golang errors": {}, "Issues": [], "Stats": {"files": 3}}`), "/target")
	if err != nil || len(got) != 0 {
		t.Fatalf("got %q %v, want none", got, err)
	}
}

func TestUncoveredRejects(t *testing.T) {
	for name, in := range map[string]string{
		"not json":       "not json",
		"no error key":   `{"Issues": [], "Stats": {"files": 1}}`,
		"wrong type":     `{"Golang errors": [], "Stats": {"files": 1}}`,
		"no stats":       `{"Golang errors": {}}`,
		"no file count":  `{"Golang errors": {}, "Stats": {}}`,
		"negative count": `{"Golang errors": {}, "Stats": {"files": -1}}`,
		"too large":      `{"Golang errors": {}, "Stats": {"files": 1}, "x": "` + strings.Repeat("a", MaxSize) + `"}`,
	} {
		if _, err := Uncovered(strings.NewReader(in), "/target"); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// tree writes files (path -> content) under a new directory.
func tree(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for p, c := range files {
		full := filepath.Join(root, filepath.FromSlash(p))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(c), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

// TestExpected counts the files gosec 2.30.0 checks, as measured on 10
// repositories (2026-11-21): never more than gosec checked with the
// modules present.
func TestExpected(t *testing.T) {
	root := tree(t, map[string]string{
		"main.go":                "package main\n",
		"main_test.go":           "package main\n",                      // tests: gosec runs without -tests
		"os_windows.go":          "package main\n",                      // not for Linux
		"os_linux.go":            "package main\n",                      // for Linux
		"ignored.go":             "//go:build ignore\n\npackage main\n", // build constraint
		"cgo.go":                 "package main\n\nimport \"C\"\n",      // checked as generated code
		"_hidden.go":             "package main\n",                      // go/build ignores _ and . files
		"_examples/a/a.go":       "package a\n",                         // gosec walks _ directories
		"testdata/t.go":          "package t\n",                         // and testdata
		"vendor/x/x.go":          "package x\n",                         // gosec's default -exclude-dir
		"internal/vendored/v.go": "package v\n",                         // the vendor pattern is a substring
		"two/a.go":               "package a\n",                         // two packages: an error gosec reports
		"two/b.go":               "package b\n",
		"onlytests/x_test.go":    "package x\n",
		"README.md":              "not go",
	})
	if err := os.Symlink("/etc/hostname", filepath.Join(root, "link.go")); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(filepath.Join(root, "fifo.go"), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := Expected(root, "/target")
	if err != nil {
		t.Fatal(err)
	}
	// main.go, os_linux.go, _examples/a/a.go, testdata/t.go.
	if got != 4 {
		t.Fatalf("got %d, want 4", got)
	}
}

func TestCheck(t *testing.T) {
	root := tree(t, map[string]string{"main.go": "package main\n", "lib/lib.go": "package lib\n"})
	for name, c := range map[string]struct{ in, want string }{
		"complete":     {`{"Golang errors": {}, "Stats": {"files": 2}}`, ""},
		"more checked": {`{"Golang errors": {}, "Stats": {"files": 3}}`, ""},
		"files missed": {`{"Golang errors": {}, "Stats": {"files": 0}}`, "gosec checked 0 of the 2 Go files it should have"},
		"named":        {`{"Golang errors": {"/target/lib": []}, "Stats": {"files": 1}}`, "gosec could not load 1 Go package,"},
	} {
		got, err := Check(strings.NewReader(c.in), root, "/target")
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if (c.want == "") != (got == "") || !strings.Contains(got, c.want) {
			t.Errorf("%s: got %q, want %q", name, got, c.want)
		}
	}
	if _, err := Check(strings.NewReader(`{"Golang errors": {}, "Stats": {"files": 2}}`), filepath.Join(root, "missing"), "/target"); err == nil {
		t.Error("missing root accepted")
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
	f.Add(`{"Golang errors": {}, "Stats": {"files": 0}}`)
	f.Add(`{"Golang errors": {"": null, "/": [], "/target/../..": {}}, "Stats": {"files": 9}}`)
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

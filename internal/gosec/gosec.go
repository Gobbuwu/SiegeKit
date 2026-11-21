// Package gosec reads the part of gosec's JSON report that its SARIF report
// leaves out: the Go packages gosec could not load or type-check
// ("Golang errors"). gosec skips such packages, still exits 0, and writes
// no trace of them into SARIF (measured with gosec 2.30.0, 2026-11-21), so
// SiegeKit reads the JSON report as well to say which packages were not
// checked (ADR 0040). The report is untrusted input (threat model T7): size
// is limited and values are only decoded.
package gosec

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
	"slices"
	"strings"

	"github.com/Gobbuwu/SiegeKit/internal/sarif"
)

// MaxSize is the largest report accepted, in bytes.
const MaxSize = sarif.MaxSize

// MaxListed is how many package directories Uncovered names; the rest are
// counted.
const MaxListed = 10

type report struct {
	// Errors maps a file (or a package directory) to the errors gosec saw
	// while loading it. Present, possibly empty, in every gosec 2.30.0
	// JSON report.
	Errors *map[string]json.RawMessage `json:"Golang errors"`
}

// Uncovered returns the package directories, relative to mount and sorted,
// that gosec reported load or type errors for. An empty list means gosec
// analyzed every package it found.
func Uncovered(r io.Reader, mount string) ([]string, error) {
	b, err := io.ReadAll(io.LimitReader(r, MaxSize+1))
	if err != nil {
		return nil, err
	}
	if len(b) > MaxSize {
		return nil, fmt.Errorf("gosec JSON report is larger than %d bytes", MaxSize)
	}
	var rep report
	if err := json.Unmarshal(b, &rep); err != nil {
		return nil, fmt.Errorf("read gosec JSON report: %w", err)
	}
	if rep.Errors == nil {
		// A report without the key is not one gosec 2.30.0 writes: fail
		// rather than guess that nothing was skipped.
		return nil, errors.New(`gosec JSON report has no "Golang errors" list`)
	}
	var dirs []string
	for p := range *rep.Errors {
		d := dir(p, mount)
		if !slices.Contains(dirs, d) {
			dirs = append(dirs, d)
		}
	}
	slices.Sort(dirs)
	return dirs, nil
}

// dir turns a file or directory path from the report into a package
// directory relative to mount ("." for the top level).
func dir(p, mount string) string {
	p = path.Clean(strings.ReplaceAll(p, "\\", "/"))
	if path.Ext(p) == ".go" {
		p = path.Dir(p)
	}
	if mount != "" {
		m := path.Clean(mount)
		switch {
		case p == m:
			return "."
		case strings.HasPrefix(p, m+"/"):
			return strings.TrimPrefix(p, m+"/")
		}
	}
	return strings.TrimPrefix(p, "/")
}

// Reason says which packages were not checked, for the plugin's reason in
// reports. dirs is the list from Uncovered and must not be empty.
func Reason(dirs []string) string {
	shown := dirs
	more := ""
	if len(shown) > MaxListed {
		shown = shown[:MaxListed]
		more = fmt.Sprintf(" and %d more", len(dirs)-MaxListed)
	}
	noun := "packages"
	if len(dirs) == 1 {
		noun = "package"
	}
	return fmt.Sprintf("gosec could not load %d Go %s, so their code was not checked: %s%s. Usually these import modules that are not in the repository (scans have no network; vendor the modules with 'go mod vendor' to check them). Findings in the other packages are kept",
		len(dirs), noun, strings.Join(shown, ", "), more)
}

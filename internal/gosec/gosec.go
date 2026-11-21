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
	"go/build"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
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
	// Stats.Files is the number of Go files gosec checked.
	Stats *struct {
		Files *int `json:"files"`
	} `json:"Stats"`
}

// Result is what a gosec JSON report says about the work gosec did.
type Result struct {
	// Uncovered lists the package directories, relative to the mount and
	// sorted, that gosec reported load or type errors for.
	Uncovered []string
	// Files is the number of Go files gosec checked.
	Files int
}

// Read reads a gosec JSON report. Paths in it are under mount.
func Read(r io.Reader, mount string) (Result, error) {
	b, err := io.ReadAll(io.LimitReader(r, MaxSize+1))
	if err != nil {
		return Result{}, err
	}
	if len(b) > MaxSize {
		return Result{}, fmt.Errorf("gosec JSON report is larger than %d bytes", MaxSize)
	}
	var rep report
	if err := json.Unmarshal(b, &rep); err != nil {
		return Result{}, fmt.Errorf("read gosec JSON report: %w", err)
	}
	// A report without these keys is not one gosec 2.30.0 writes: fail
	// rather than guess that nothing was skipped.
	if rep.Errors == nil {
		return Result{}, errors.New(`gosec JSON report has no "Golang errors" list`)
	}
	if rep.Stats == nil || rep.Stats.Files == nil || *rep.Stats.Files < 0 {
		return Result{}, errors.New("gosec JSON report has no file count")
	}
	res := Result{Files: *rep.Stats.Files}
	for p := range *rep.Errors {
		d := dir(p, mount)
		if !slices.Contains(res.Uncovered, d) {
			res.Uncovered = append(res.Uncovered, d)
		}
	}
	slices.Sort(res.Uncovered)
	return res, nil
}

// gosec 2.30.0 leaves out the directories its default -exclude-dir values
// match ("vendor" and "\.git/"), tested against the container path of the
// directory that holds each .go file (cmd/gosec/main.go, ExcludedDirsRegExp).
var excluded = []*regexp.Regexp{
	regexp.MustCompile(`([\\/])?vendor([\\/])?`),
	regexp.MustCompile(`([\\/])?\.git\/([\\/])?`),
}

// MaxDirs is the most package directories Expected looks at.
const MaxDirs = 100000

// Expected counts the Go files gosec 2.30.0 should check when it scans
// mount/... with root mounted at mount: in each directory that holds a .go
// file (vendor and .git left out, as gosec does), the non-test files that
// go/build selects for Linux on this architecture. Files that need cgo are
// not counted: gosec checks the code cgo generates in their place, under
// names that do not end in .go. Only regular files are read, so a symlink
// or a FIFO counts as no file and cannot make SiegeKit read outside root
// or wait. The count can be lower than what gosec checks (for example a
// file for a newer Go release), never higher for the files it reads.
func Expected(root, mount string) (int, error) {
	dirs := map[string]bool{}
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if filepath.Ext(p) != ".go" {
			return nil
		}
		dir := filepath.Dir(p)
		rel, err := filepath.Rel(root, dir)
		if err != nil {
			return err
		}
		c := path.Join(mount, filepath.ToSlash(rel))
		for _, x := range excluded {
			if x.MatchString(c) {
				return nil
			}
		}
		dirs[dir] = true
		if len(dirs) > MaxDirs {
			return fmt.Errorf("more than %d Go package directories", MaxDirs)
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	ctxt := build.Default
	ctxt.GOOS, ctxt.GOARCH = "linux", runtime.GOARCH
	ctxt.CgoEnabled = false
	ctxt.BuildTags = nil
	ctxt.ReadDir = readRegular
	ctxt.OpenFile = openRegular
	n := 0
	for d := range dirs {
		// An error here (no buildable file, two packages in one
		// directory) is one gosec reports as well; such a directory
		// counts no file.
		if p, err := ctxt.ImportDir(d, build.ImportComment); err == nil {
			n += len(p.GoFiles)
		}
	}
	return n, nil
}

// readRegular lists the regular files and directories in dir, so a symlink
// or a FIFO is not counted and does not hide the rest of its directory.
func readRegular(dir string) ([]fs.FileInfo, error) {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var out []fs.FileInfo
	for _, e := range ents {
		if !e.Type().IsRegular() && !e.IsDir() {
			continue
		}
		fi, err := e.Info()
		if err != nil {
			continue // removed meanwhile
		}
		out = append(out, fi)
	}
	return out, nil
}

func openRegular(p string) (io.ReadCloser, error) {
	fi, err := os.Lstat(p)
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", p)
	}
	return os.Open(p) // #nosec G304 -- a file in the scanned repository, read only for its build constraints
}

// Check says what gosec did not check, "" if nothing: the packages it could
// not load, or, when it names none, how many Go files it left out. root is
// the scanned directory, mounted at mount in gosec's container.
func Check(r io.Reader, root, mount string) (string, error) {
	res, err := Read(r, mount)
	if err != nil {
		return "", err
	}
	if len(res.Uncovered) > 0 {
		return Reason(res.Uncovered), nil
	}
	want, err := Expected(root, mount)
	if err != nil {
		return "", fmt.Errorf("count the Go files gosec should check: %w", err)
	}
	if res.Files < want {
		return fmt.Sprintf("gosec checked %d of the %d Go files it should have and reported no error for the others, so their code was not checked. Findings in the files it checked are kept", res.Files, want), nil
	}
	return "", nil
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

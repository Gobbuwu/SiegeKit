// Package gosec reads the part of gosec's JSON report that its SARIF report
// leaves out: the Go packages gosec could not load or type-check
// ("Golang errors"). gosec skips such packages, still exits 0, and writes
// no trace of them into SARIF (measured with gosec 2.30.0, 2026-11-21), so
// SiegeKit reads the JSON report as well to say which packages were not
// checked (ADR 0040). The report is untrusted input (threat model T7): size
// is limited and values are only decoded.
package gosec

import (
	"bufio"
	"bytes"
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
	// NoSpace is set when gosec reported "no space left on device".
	NoSpace bool
	// GoNeeded and GoHave are set when Go refused the packages because
	// the go.mod or go.work files ask for a newer Go than gosec's image
	// has ("go.work requires go >= 1.27.4 (running go 1.27.3; ...)").
	GoNeeded, GoHave string
	// MissingModules is set when an error says a module is not in the
	// module cache or not required by go.mod (missingModule).
	MissingModules bool
}

// missingModule holds what Go's package loader says, with GOPROXY=off, when
// a module the code imports is not available (measured with go 1.24.7 and
// in gosec 2.30.0's reports, 2026-11-21 and 2026-11-24): not in the module
// cache, not in go.sum, or not required by go.mod.
var missingModule = []string{
	"module lookup disabled by GOPROXY=off",
	"missing go.sum entry",
	"no required module provides package",
}

// reGoTooOld matches Go's refusal to load a module that needs a newer Go
// while GOTOOLCHAIN=local forbids downloading one.
var reGoTooOld = regexp.MustCompile(`requires go >= ([0-9][0-9a-z.]{0,30}) \(running go ([0-9][0-9a-z.]{0,30})[;)]`)

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
	res := Result{Files: *rep.Stats.Files, NoSpace: bytes.Contains(b, noSpace)}
	for p, raw := range *rep.Errors {
		var errs []struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(raw, &errs) == nil {
			for _, e := range errs {
				if m := reGoTooOld.FindStringSubmatch(e.Error); m != nil && res.GoNeeded == "" {
					res.GoNeeded, res.GoHave = m[1], m[2]
				}
				for _, w := range missingModule {
					if strings.Contains(e.Error, w) {
						res.MissingModules = true
					}
				}
			}
		}
		d := dir(p, mount)
		if p == "" {
			// gosec 2.30.0 keys some errors by no file at all (a cgo
			// package's compile errors, seen on containerd): not the top
			// directory.
			d = unnamed
		}
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
func Check(r, logr io.Reader, root, mount string) (string, error) {
	res, err := Read(r, mount)
	if err != nil {
		return "", err
	}
	lg, err := ReadLog(logr, mount)
	if err != nil {
		return "", err
	}
	var why []string
	if res.NoSpace || lg.NoSpace {
		why = append(why, "gosec ran out of disk space (no space left on device), so it may have left packages out without naming them. Free disk space where SiegeKit keeps its data (~/.local/share/siegekit) and scan again.")
	}
	if res.GoNeeded != "" {
		why = append(why, fmt.Sprintf("Your go.mod or go.work files ask for Go %s or newer, and the Go in gosec's pinned image is %s, so Go refused to load packages; SiegeKit never downloads another Go into the image. A SiegeKit release with a newer gosec image fixes this.", res.GoNeeded, res.GoHave))
	}
	if len(res.Uncovered) > 0 {
		why = append(why, Reason(res.Uncovered, res.MissingModules))
	}
	var skipped []string
	for _, d := range lg.SSASkipped {
		if !slices.Contains(res.Uncovered, d) {
			skipped = append(skipped, d)
		}
	}
	if len(skipped) > 0 {
		why = append(why, SSAReason(skipped))
	}
	if len(why) > 0 {
		return strings.Join(why, " "), nil
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

// unnamed stands for errors gosec gives no file or directory for.
const unnamed = "(errors gosec named no folder for)"

// noSpace is how Go and gosec report a full disk.
var noSpace = []byte("no space left on device")

// Log is what gosec's log (its standard error) says about the work it did.
type Log struct {
	// SSASkipped lists the package directories, relative to the mount and
	// sorted, whose SSA-based rules gosec skipped.
	SSASkipped []string
	// NoSpace is set when the log says "no space left on device".
	NoSpace bool
}

// Log lines of gosec 2.30.0 (analyzer.go). With -concurrency 1 one worker
// loads each directory ("Import directory: DIR") and then checks its
// packages, building each one's SSA form, before it loads the next, so a
// skipped SSA build belongs to the directory last imported. The message
// names only the package ("main"), which cannot tell two directories apart
// (ADR 0045, 0066).
const (
	logImport  = "Import directory: "
	logSSAFail = "Error building the SSA representation of the package "
)

// logStamp is the time log.LstdFlags puts after gosec's "[gosec] " prefix.
var logStamp = regexp.MustCompile(`^\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2} `)

// MaxLogLine is the longest log line read; a longer one is an error.
const MaxLogLine = 1 << 20

// ReadLog reads gosec's log, run with -concurrency 1, with the scanned
// directory mounted at mount. The log is untrusted input (threat model
// T7): it is only matched against fixed text.
func ReadLog(r io.Reader, mount string) (Log, error) {
	var lg Log
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64<<10), MaxLogLine)
	cur := ""
	for sc.Scan() {
		line := sc.Bytes()
		if bytes.Contains(line, noSpace) {
			lg.NoSpace = true
		}
		// Only gosec's own log lines count, so a file name with these words
		// in a "Checking file:" line is not read as one.
		msg, ok := bytes.CutPrefix(line, []byte("[gosec] "))
		if !ok || !logStamp.Match(msg) {
			continue
		}
		msg = msg[len("2006/01/02 15:04:05 "):]
		if after, ok := bytes.CutPrefix(msg, []byte(logImport)); ok {
			cur = dir(string(after), mount)
			continue
		}
		if after, ok := bytes.CutPrefix(msg, []byte(logSSAFail)); ok {
			d := cur
			if d == "" {
				// No directory imported yet: not what gosec 2.30.0
				// writes. Name the package rather than drop it.
				name, _, _ := bytes.Cut(after, []byte(":"))
				d = "package " + strings.ToValidUTF8(string(name), "?")
			}
			if !slices.Contains(lg.SSASkipped, d) {
				lg.SSASkipped = append(lg.SSASkipped, d)
			}
		}
	}
	if err := sc.Err(); err != nil {
		return Log{}, fmt.Errorf("read gosec's log: %w", err)
	}
	slices.Sort(lg.SSASkipped)
	return lg, nil
}

// SSAReason says in which packages gosec skipped its SSA-based rules, for
// the plugin's reason in reports. dirs must not be empty.
func SSAReason(dirs []string) string {
	shown, more := dirs, ""
	if len(shown) > MaxListed {
		shown = shown[:MaxListed]
		more = fmt.Sprintf(" and %d more", len(dirs)-MaxListed)
	}
	noun := "packages"
	if len(dirs) == 1 {
		noun = "package"
	}
	return fmt.Sprintf("gosec skipped its SSA-based rules (G115, G407, G602, the G7xx data-flow rules and others) in %d Go %s, because they did not type-check, for example because they import a package gosec could not load: %s%s. Its other rules checked them.",
		len(dirs), noun, strings.Join(shown, ", "), more)
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
// reports. dirs is the list from Uncovered and must not be empty; missing
// says whether gosec's errors name a missing module, the only cause the Go
// module download fixes.
func Reason(dirs []string, missing bool) string {
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
	hint := "gosec's errors for them name no missing Go module, so the Go module download does not help: the code does not compile as gosec checks it, for example test fixtures broken on purpose, files a build step makes outside the repository, or cgo code that needs C headers gosec's image lacks."
	if missing {
		hint = "Some import modules that are neither in the repository nor in SiegeKit's Go module cache (scans have no network: allow the Go module download when SiegeKit asks, or pass --yes)."
	}
	return fmt.Sprintf("gosec could not load %d Go %s, so their code was not checked: %s%s. %s Findings in the other packages are kept.",
		len(dirs), noun, strings.Join(shown, ", "), more, hint)
}

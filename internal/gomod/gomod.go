// Package gomod finds the Go modules of a scanned repository and runs the
// consented module download for tools that load Go packages, such as
// gosec (ADR 0066). The download runs `go mod download` in the tool's own
// pinned image, with network but without the repository: only copies of
// its go.mod, go.sum, go.work and go.work.sum files are mounted. Modules go
// into one shared cache that scans then mount read-only, with no network.
//
// The module files are untrusted input (threat model T7): only regular
// files are read, sizes and counts are limited, and nothing in them is
// executed on the host. Go itself checks every download against go.sum
// and the checksum database.
package gomod

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/Gobbuwu/SiegeKit/internal/sandbox"
)

// Limits on what Find reads from a repository.
const (
	MaxFiles    = 2000      // module files
	MaxFileSize = 16 << 20  // bytes in one file
	MaxTotal    = 128 << 20 // bytes in all files
)

// fileNames are the files `go mod download` reads.
var fileNames = []string{"go.mod", "go.sum", "go.work", "go.work.sum"}

// Tree is what Find read from a repository.
type Tree struct {
	// Dirs are the directories holding a go.mod, relative to the
	// repository and slash-separated ("." for the top), sorted.
	Dirs []string
	// Required is the number of distinct module paths the go.mod files
	// require, for the install question.
	Required int
	files    map[string][]byte // relative, slash-separated path -> contents
}

// Find reads the module files under root, leaving out directories named
// vendor or .git, as the measured download did (ADR 0066). A tree with no
// go.mod gives a Tree with no Dirs.
func Find(ctx context.Context, root string) (*Tree, error) {
	t := &Tree{files: map[string][]byte{}}
	required := map[string]bool{}
	total := 0
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if d.IsDir() {
			if p != root && (d.Name() == "vendor" || d.Name() == ".git") {
				return filepath.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() || !slices.Contains(fileNames, d.Name()) {
			return nil
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return err
		}
		if len(t.files) >= MaxFiles {
			return fmt.Errorf("more than %d Go module files", MaxFiles)
		}
		b, err := readRegular(p)
		if err != nil {
			return err
		}
		if total += len(b); total > MaxTotal {
			return fmt.Errorf("module files larger than %d bytes in all", MaxTotal)
		}
		rel = filepath.ToSlash(rel)
		t.files[rel] = b
		if d.Name() == "go.mod" {
			t.Dirs = append(t.Dirs, path.Dir(rel))
			for _, r := range Requires(b) {
				required[r] = true
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	slices.Sort(t.Dirs)
	t.Required = len(required)
	return t, nil
}

// readRegular reads a regular file of at most MaxFileSize bytes without
// following a symlink.
func readRegular(p string) ([]byte, error) {
	f, err := os.OpenFile(p, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0) // #nosec G304 -- a go.mod, go.sum, go.work or go.work.sum file in the scanned repository; symlinks refused
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", p)
	}
	b, err := io.ReadAll(io.LimitReader(f, MaxFileSize+1))
	if err != nil {
		return nil, err
	}
	if len(b) > MaxFileSize {
		return nil, fmt.Errorf("%s is larger than %d bytes", p, MaxFileSize)
	}
	return b, nil
}

// Requires lists the module paths in a go.mod file's require directives,
// in single-line and block form. It is only used to count modules for the
// install question; Go itself reads the files for the download.
func Requires(gomod []byte) []string {
	var out []string
	block := false
	sc := bufio.NewScanner(bytes.NewReader(gomod))
	sc.Buffer(make([]byte, 64<<10), MaxFileSize)
	for sc.Scan() {
		line := sc.Text()
		if i := strings.Index(line, "//"); i >= 0 {
			line = line[:i]
		}
		f := strings.Fields(line)
		switch {
		case len(f) == 0:
		case block && f[0] == ")":
			block = false
		case block:
			out = append(out, strings.Trim(f[0], "\"`"))
		case f[0] == "require" && len(f) == 2 && f[1] == "(":
			block = true
		case f[0] == "require" && len(f) >= 3:
			out = append(out, strings.Trim(f[1], "\"`"))
		}
	}
	return out
}

// Stage writes the module files under dir, which must exist: directories
// 0755 and files 0644, so that a container user other than the caller can
// read them. dir's parent should be private to the caller.
func (t *Tree) Stage(dir string) error {
	for _, rel := range slices.Sorted(maps.Keys(t.files)) {
		p := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil { // #nosec G301 -- read by the container user; the parent is private
			return err
		}
		if err := os.WriteFile(p, t.files[rel], 0o644); err != nil { // #nosec G306 -- read by the container user; the parent is private
			return err
		}
	}
	// Directories MkdirAll made are subject to the umask.
	return filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || !d.IsDir() {
			return err
		}
		return os.Chmod(p, 0o755) // #nosec G302 -- as above
	})
}

// CacheDir is the shared module cache under SiegeKit's data root (ADR 0066,
// 4A).
func CacheDir(dataRoot string) string { return filepath.Join(dataRoot, "gomod") }

// CacheMount is where the module cache is mounted in containers.
const CacheMount = "/data/gomod"

// Executor runs one sandboxed container. *sandbox.Engine implements it.
type Executor interface {
	Run(ctx context.Context, s sandbox.Spec) (*sandbox.Result, error)
}

// Job is how the download and the presence check run.
type Job struct {
	Image     string // the tool's pinned image, which has Go on its PATH
	CPUs      int
	MemoryMiB int
	Timeout   time.Duration // for each module directory
	DataRoot  string        // SiegeKit's data root; the cache is CacheDir(DataRoot)
	Egress    sandbox.Egress
	// Private holds GOPRIVATE and GONOPROXY, when set (see PrivateEnv).
	// Go then never asks the proxy for matching modules, and with
	// GOVCS=*:off it does not fetch them any other way (measured, ADR 0066).
	Private map[string]string
}

// env is the environment of the download and the presence check.
func (j Job) env(proxy string) map[string]string {
	env := map[string]string{
		"GOMODCACHE":  CacheMount,
		"GOPATH":      "/tmp/go",
		"GOTOOLCHAIN": "local",
		"GOPROXY":     proxy,
		"GOFLAGS":     "-mod=mod",
		"GOVCS":       "*:off",
	}
	for k, v := range j.Private {
		env[k] = v
	}
	return env
}

// Present reports whether the cache already holds every module the tree's
// modules need, with no network: `go mod download` with GOPROXY=off in
// each module directory, the cache mounted read-only (ADR 0066).
func Present(ctx context.Context, ex Executor, t *Tree, j Job) (bool, error) {
	cache := CacheDir(j.DataRoot)
	if st, err := os.Lstat(cache); err != nil || !st.IsDir() {
		return false, nil
	}
	ok := true
	err := eachDir(ctx, ex, t, j, func(rel string, s sandbox.Spec) (bool, error) {
		s.Network = "none"
		s.Env = j.env("off")
		s.DataDir, s.DataMount = cache, CacheMount
		res, err := ex.Run(ctx, s)
		if err != nil {
			return false, err
		}
		if res.Status != sandbox.Completed || res.ExitCode != 0 {
			ok = false
			return false, nil
		}
		return true, nil
	})
	return ok && err == nil, err
}

// Download runs `go mod download` with network in each module directory
// of t. Directories that fail are named in the returned error; the others
// are still downloaded.
func Download(ctx context.Context, ex Executor, t *Tree, j Job) error {
	cache := CacheDir(j.DataRoot)
	if err := os.MkdirAll(j.DataRoot, 0o700); err != nil {
		return err
	}
	if err := os.Mkdir(cache, 0o755); err != nil && !errors.Is(err, fs.ErrExist) { // #nosec G301 -- read by any container user; the data root is private
		return err
	}
	// Two SiegeKit runs must not download at once: each opens the cache
	// to the container user for its run and closes it afterwards.
	unlock, err := lock(cache + ".lock")
	if err != nil {
		return err
	}
	defer unlock()
	var failed []string
	err = eachDir(ctx, ex, t, j, func(rel string, s sandbox.Spec) (bool, error) {
		s.Network = "egress"
		s.Egress = j.Egress
		s.Env = j.env(sandbox.GoProxy)
		s.DataDir, s.DataMount, s.DataWritable = cache, CacheMount, true
		res, err := ex.Run(ctx, s)
		switch {
		case err != nil:
			return false, err
		case res.Status == sandbox.TimedOut:
			failed = append(failed, fmt.Sprintf("%s (stopped after %s)", rel, j.Timeout))
		case res.Status != sandbox.Completed || res.ExitCode != 0:
			failed = append(failed, fmt.Sprintf("%s (%s)", rel, LastLine(res.Stderr)))
		}
		return true, nil
	})
	if err != nil {
		return err
	}
	if len(failed) > 0 {
		return fmt.Errorf("go mod download failed in %d of %d module folders: %s", len(failed), len(t.Dirs), strings.Join(failed, "; "))
	}
	return nil
}

// eachDir stages t in a private directory and calls run with a spec for
// each module directory until run returns false or an error.
func eachDir(ctx context.Context, ex Executor, t *Tree, j Job, run func(rel string, s sandbox.Spec) (bool, error)) error {
	work, err := os.MkdirTemp("", "siegekit-gomod-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(work)
	in := filepath.Join(work, "in")
	if err := os.Mkdir(in, 0o755); err != nil { // #nosec G301 -- read by the container user; work is private
		return err
	}
	if err := t.Stage(in); err != nil {
		return fmt.Errorf("copy the Go module files: %w", err)
	}
	for i, rel := range t.Dirs {
		if err := ctx.Err(); err != nil {
			return err
		}
		out := filepath.Join(work, fmt.Sprintf("out%d", i))
		if err := os.Mkdir(out, 0o700); err != nil {
			return err
		}
		more, err := run(rel, sandbox.Spec{
			Image:      j.Image,
			Entrypoint: "go",
			// -C must come first; the path is an argument, never a shell word.
			Args:      []string{"-C", path.Join(sandbox.InputMount, rel), "mod", "download"},
			InputDir:  in,
			OutDir:    out,
			CPUs:      j.CPUs,
			MemoryMiB: j.MemoryMiB,
			Timeout:   j.Timeout,
		})
		if err != nil || !more {
			return err
		}
	}
	return nil
}

// LastLine is the last non-empty line of s without control characters,
// cut to its last 300 characters.
func LastLine(s string) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	l := strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, strings.ToValidUTF8(strings.TrimSpace(lines[len(lines)-1]), ""))
	if l == "" {
		return "no error output"
	}
	if r := []rune(l); len(r) > 300 {
		l = "…" + string(r[len(r)-300:])
	}
	return l
}

// lock takes an exclusive lock on the file p, waiting for another
// SiegeKit run to finish its download.
func lock(p string) (func(), error) {
	f, err := os.OpenFile(p, os.O_RDWR|os.O_CREATE|syscall.O_NOFOLLOW, 0o600) // #nosec G304 -- a lock file next to the cache in SiegeKit's private data root
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil { // #nosec G115 -- a file descriptor fits in an int
		f.Close()
		return nil, err
	}
	return func() {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN) // #nosec G115 -- as above
		f.Close()
	}, nil
}

// PrivateEnv returns GOPRIVATE and GONOPROXY as Go on this machine would
// see them: from the environment when set there, otherwise from Go's own
// settings file (`go env -w`), read as text; Go on the host is never run
// (ADR 0016). getenv is os.Getenv outside tests.
func PrivateEnv(getenv func(string) string) map[string]string {
	file := map[string]string{}
	if p := goEnvFile(getenv); p != "" {
		if b, err := readRegular(p); err == nil {
			for _, line := range strings.Split(string(b), "\n") {
				line = strings.TrimSpace(line)
				if k, v, ok := strings.Cut(line, "="); ok && !strings.HasPrefix(line, "#") {
					file[strings.TrimSpace(k)] = strings.TrimSpace(v)
				}
			}
		}
	}
	out := map[string]string{}
	for _, k := range []string{"GOPRIVATE", "GONOPROXY"} {
		v := getenv(k)
		if v == "" {
			v = file[k]
		}
		if v != "" {
			out[k] = v
		}
	}
	return out
}

// goEnvFile is the path of Go's settings file: $GOENV, or "go/env" in the
// user's configuration directory; "" for none.
func goEnvFile(getenv func(string) string) string {
	if p := getenv("GOENV"); p != "" {
		if p == "off" || !filepath.IsAbs(p) {
			return ""
		}
		return p
	}
	dir, err := os.UserConfigDir()
	if err != nil {
		return ""
	}
	return filepath.Join(dir, "go", "env")
}

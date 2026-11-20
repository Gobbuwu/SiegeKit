// Package checks holds SiegeKit's own static checks (ADR 0015). They only
// read files under the target directory: they never execute anything from it
// and never use the network, so they run in the SiegeKit process instead of a
// container. Every file read is size-limited and symlinks are never followed.
package checks

import (
	"bytes"
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/Gobbuwu/SiegeKit/internal/findings"
)

// Check is one built-in check.
type Check struct {
	ID      string
	Name    string
	Family  string
	Targets []string
	// Run scans root (an absolute directory) and returns findings with
	// relative URIs, plus a one-line result for the report when the check
	// has more to say than its findings (empty otherwise).
	Run func(ctx context.Context, root string) ([]findings.Finding, string, error)
}

// noResult adapts a check that only returns findings.
func noResult(run func(context.Context, string) ([]findings.Finding, error)) func(context.Context, string) ([]findings.Finding, string, error) {
	return func(ctx context.Context, root string) ([]findings.Finding, string, error) {
		fs, err := run(ctx, root)
		return fs, "", err
	}
}

// Builtin returns every built-in check.
func Builtin() []Check {
	return []Check{backendRules, dotenv, weakPasswords}
}

// Limits on what a check reads, so a hostile repository cannot exhaust memory
// or time.
const (
	MaxFileSize = 1 << 20
	MaxFiles    = 200_000
	MaxDepth    = 40
)

// skipDirs are never descended into: dependencies and version control.
var skipDirs = map[string]bool{".git": true, "node_modules": true, "vendor": true, ".venv": true, "venv": true, "__pycache__": true}

// ErrTooManyFiles is returned when a tree has more than MaxFiles entries.
var ErrTooManyFiles = errors.New("too many files; the check stopped early")

// walk calls fn with the slash-separated relative path of every regular file
// under root that want accepts, without following symlinks.
func walk(ctx context.Context, root string, want func(rel string) bool, fn func(rel string, data []byte) error) error {
	return walkTree(ctx, root, func(p, rel string) error {
		if !want(rel) {
			return nil
		}
		data, err := readFile(p)
		if err != nil || data == nil {
			return err
		}
		return fn(rel, data)
	})
}

// walkTree calls visit with the path and slash-separated relative path of
// every regular file under root, within the limits above.
func walkTree(ctx context.Context, root string, visit func(p, rel string) error) error {
	n := 0
	return filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if n++; n > MaxFiles {
			return ErrTooManyFiles
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if d.IsDir() {
			if p != root && (skipDirs[d.Name()] || strings.Count(rel, "/") >= MaxDepth) {
				return filepath.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		return visit(p, rel)
	})
}

var errFound = errors.New("found")

// HasFile reports whether root holds a regular file whose base name matches
// one of patterns (path.Match syntax). It uses the same limits and skipped
// directories as the checks; a tree too large to search returns
// ErrTooManyFiles.
func HasFile(ctx context.Context, root string, patterns []string) (bool, error) {
	err := walkTree(ctx, root, func(_, rel string) error {
		base := path.Base(rel)
		for _, pat := range patterns {
			if ok, _ := path.Match(pat, base); ok {
				return errFound
			}
		}
		return nil
	})
	if errors.Is(err, errFound) {
		return true, nil
	}
	return false, err
}

// readFile reads a regular file without following symlinks. Files larger
// than MaxFileSize are skipped (nil, nil).
func readFile(p string) ([]byte, error) {
	f, err := os.OpenFile(p, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0) // #nosec G304 -- reading the target is the check's job; symlinks refused, size limited
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() || st.Size() > MaxFileSize {
		return nil, nil
	}
	data, err := io.ReadAll(io.LimitReader(f, MaxFileSize+1))
	if err != nil || len(data) > MaxFileSize {
		return nil, err
	}
	return data, nil
}

// CountMarker counts the lines under root that contain marker, such as an
// inline "gitleaks:allow" comment. It uses the same limits and skipped
// directories as the checks; a tree too large to search returns the count so
// far with ErrTooManyFiles.
func CountMarker(ctx context.Context, root, marker string) (int, error) {
	if marker == "" {
		return 0, nil
	}
	m := []byte(marker)
	n := 0
	err := walkTree(ctx, root, func(p, _ string) error {
		data, err := readFile(p)
		if err != nil || data == nil {
			return nil // unreadable or too large: not counted
		}
		for _, line := range bytes.Split(data, []byte("\n")) {
			if bytes.Contains(line, m) {
				n++
			}
		}
		return nil
	})
	return n, err
}

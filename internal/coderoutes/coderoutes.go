// Package coderoutes lists an app's HTTP routes from its server code, the
// way an attacker who has the code finds routes no client calls (ADR 0053).
// It reads Go and JavaScript or TypeScript files under a directory and
// never runs them. Each extractor knows one way of registering routes:
// Go routers (gorilla/mux, chi, Gitea's web.Router, gin, echo, net/http)
// read with go/parser, Rocket.Chat's REST API (API.v1.addRoute and
// API.v1.get) and Express (app.get('/path')) read with a small tokenizer.
//
// Only GET routes (and routes registered for any method) are returned,
// because the route sweep that uses them reads (ADR 0052). A route whose
// path the extractor cannot work out from the code (built at run time, a
// wildcard, a mounted router) is counted, never guessed.
package coderoutes

import (
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/Gobbuwu/SiegeKit/internal/authz"
	"github.com/Gobbuwu/SiegeKit/internal/testpath"
)

// Limits on what is read: a person's source tree is trusted no more than a
// HAR file. Files and directories past them are counted, not read.
const (
	MaxFiles     = 50_000    // source files read
	MaxFileSize  = 64 << 20  // bytes per file (a server bundle is 20 to 24 MB)
	MaxTotalSize = 512 << 20 // bytes in all
	maxDepth     = 64        // directory depth
)

// Result is what the extractors found.
type Result struct {
	Routes []authz.SpecRoute // GET routes, sorted by path, one per path
	// Found counts the distinct GET route paths each extractor found; a
	// path two extractors found is counted under both.
	Found map[string]int
	Files int // source files read
	// TooBig counts files over MaxFileSize, and files past MaxFiles or
	// MaxTotalSize; Unparsed counts Go files go/parser refused.
	TooBig, Unparsed int
	// Truncated is set when the Go walk stopped at its limit: routes
	// after it were not found.
	Truncated bool
	// Unresolved counts GET route registrations whose path the code
	// builds in a way the extractor cannot follow; they are not returned.
	Unresolved int
}

// Extractor names, as reported.
const (
	KindGo         = "Go routers"
	KindRocketChat = "Rocket.Chat REST API"
	KindExpress    = "Express"
)

// skipDir reports directories that hold no server routes of the app:
// dependencies, version control, build caches, tests (the shared
// definition, testpath), and browser code ("client"), whose HTTP calls
// (sdk.rest.get('/v1/x', params)) look like Express routes: in Rocket.Chat
// 8.9.1 they gave 16 paths no server registers.
func skipDir(name string) bool {
	switch name {
	case ".git", ".hg", ".svn", "node_modules", "vendor", ".meteor", ".next", ".cache", "coverage", "dist-tests", "client":
		return true
	}
	return testpath.IsTestDir(name)
}

// skipFile reports test files and type declarations.
func skipFile(name string) bool {
	return strings.HasSuffix(name, ".d.ts") || testpath.IsTestFile(name)
}

func isJS(name string) bool {
	for _, s := range []string{".js", ".mjs", ".cjs", ".ts", ".mts", ".cts"} {
		if strings.HasSuffix(name, s) {
			return true
		}
	}
	return false
}

// ErrNoSource is returned when the path holds no Go, JavaScript or
// TypeScript file.
var ErrNoSource = errors.New("no Go, JavaScript or TypeScript file found")

// FromPath reads the server code at root (a directory or one file) and
// returns its GET routes. Symbolic links are not followed.
func FromPath(root string) (Result, error) {
	res := Result{Found: map[string]int{}}
	st, err := os.Lstat(root)
	if err != nil {
		return res, err
	}
	var goFiles []srcFile
	var jsRes jsResult
	jsCount, total := 0, int64(0)
	add := func(path string, size int64) {
		name := filepath.Base(path)
		js := isJS(name)
		if !strings.HasSuffix(name, ".go") && !js || skipFile(name) {
			return
		}
		if size > MaxFileSize || len(goFiles)+jsCount >= MaxFiles || total+size > MaxTotalSize {
			res.TooBig++
			return
		}
		b, err := os.ReadFile(path) // #nosec G304 -- the person's own source tree, read only
		if err != nil {
			res.Unparsed++
			return
		}
		total += int64(len(b))
		if js {
			// Read and dropped one at a time: a server bundle is tens of
			// megabytes (Rocket.Chat's app.js, 20 to 24 MB).
			jsCount++
			jsScan(b, &jsRes)
		} else {
			goFiles = append(goFiles, srcFile{path: path, data: b})
		}
	}
	if st.Mode().IsRegular() {
		add(root, st.Size())
	} else if st.IsDir() {
		err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil // unreadable entries are skipped
			}
			if d.IsDir() {
				rel, _ := filepath.Rel(root, path)
				if path != root && (skipDir(d.Name()) || strings.Count(rel, string(filepath.Separator)) >= maxDepth) {
					return filepath.SkipDir
				}
				return nil
			}
			if !d.Type().IsRegular() {
				return nil // symbolic links and devices are not followed
			}
			info, err := d.Info()
			if err != nil {
				return nil
			}
			add(path, info.Size())
			return nil
		})
		if err != nil {
			return res, err
		}
	} else {
		return res, errors.New("not a file or directory")
	}
	res.Files = len(goFiles) + jsCount
	if res.Files == 0 {
		return res, ErrNoSource
	}

	var all []found
	if len(goFiles) > 0 {
		g := goRoutes(goFiles, root)
		res.Unparsed += g.unparsed
		res.Unresolved += g.unresolved
		res.Truncated = g.truncated
		all = append(all, g.routes...)
	}
	res.Unresolved += jsRes.unresolved
	all = append(all, jsRes.routes...)
	seen := map[string]bool{}
	for _, f := range all {
		if k := f.kind + " " + f.path; !seen[k] {
			seen[k] = true
			res.Found[f.kind]++
		}
	}
	res.Routes = merge(all)
	return res, nil
}

type srcFile struct {
	path string
	data []byte
}

// found is one GET route an extractor found, with the query parameter
// names its handler reads.
type found struct {
	kind  string
	path  string // with {name} path parameters
	query []string
}

// merge turns found routes into sweep routes: one per path, the query
// parameters of every registration of that path joined.
func merge(fs []found) []authz.SpecRoute {
	byPath := map[string]map[string]bool{}
	for _, f := range fs {
		if byPath[f.path] == nil {
			byPath[f.path] = map[string]bool{}
		}
		for _, q := range f.query {
			byPath[f.path][q] = true
		}
	}
	paths := make([]string, 0, len(byPath))
	for p := range byPath {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	out := make([]authz.SpecRoute, 0, len(paths))
	for _, p := range paths {
		out = append(out, toRoute(p, byPath[p]))
	}
	return out
}

var (
	rePathParam = regexp.MustCompile(`\{([^{}/]+)\}`)
	// reLowerBound matches a query parameter that sets an earliest date.
	// Each name it matches is also one the sweep fills with the earliest
	// date (authz fillValue).
	reLowerBound = regexp.MustCompile(`(?i)since|after|^from$`)
)

// toRoute builds the sweep route for a path. Every {name} is a required
// path parameter. The code does not say which query parameters are
// required, so of those the handler reads: one whose name asks for an
// object ID is filled when A's recording has an ID for it and left out
// otherwise (an ID is what an outsider test needs); a lower date bound
// such as Rocket.Chat's "since" is always sent with the earliest date
// (refused when missing, and it narrows nothing); others (paging, search
// text, upper date bounds) are left out.
func toRoute(path string, query map[string]bool) authz.SpecRoute {
	rt := authz.SpecRoute{Path: path, FromCode: true}
	seen := map[string]bool{}
	for _, m := range rePathParam.FindAllStringSubmatch(path, -1) {
		if !seen[m[1]] {
			seen[m[1]] = true
			rt.Params = append(rt.Params, authz.SpecParam{Name: m[1], In: "path", Required: true, Type: "string"})
		}
	}
	names := make([]string, 0, len(query))
	for q := range query {
		names = append(names, q)
	}
	sort.Strings(names)
	for _, q := range names {
		p := authz.SpecParam{Name: q, In: "query", Type: "string"}
		switch {
		case p.IsIDParam():
			p.Fill = true
		case reLowerBound.MatchString(q):
			p.Required = true
		default:
			continue
		}
		rt.Params = append(rt.Params, p)
	}
	return rt
}

// readSmall reads a small file (go.mod), at most 1 MiB.
func readSmall(path string) ([]byte, error) {
	f, err := os.Open(path) // #nosec G304 -- a go.mod inside the person's source tree
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, 1<<20))
}

// Package backend is SiegeKit's live hosted-backend check (ADR 0011 item 3,
// ADR 0037). Many apps read their data straight from the browser with a
// public key: Supabase (PostgREST) and Firebase Realtime Database. When a
// table has no row-level security, or a database path has no read rule,
// anyone who loads the app can read it. This check sends one read-only GET
// per table or path with the app's own public key and reports those that
// answer with data. It keeps the column names, never the values.
package backend

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/Gobbuwu/SiegeKit/internal/egress"
	"github.com/Gobbuwu/SiegeKit/internal/findings"
	"github.com/Gobbuwu/SiegeKit/internal/target"
)

// ID, Name and Family describe the check in plans and reports.
const (
	ID     = "backend-live"
	Name   = "Hosted backend read check"
	Family = "dast"
)

// Limits of answer 8a: one GET per name, at most MaxNames names, at most
// one request per Interval, and at most MaxAnswer bytes read per answer
// (one row, or a shallow list of keys).
const (
	MaxNames  = 200
	MaxAnswer = 1 << 20
	Interval  = 200 * time.Millisecond
)

// Kind is the backend product.
type Kind string

// The backends SiegeKit can check.
const (
	Supabase Kind = "Supabase"
	Firebase Kind = "Firebase Realtime Database"
)

// Backend is the --backend-url value.
type Backend struct {
	URL  *target.URL
	Kind Kind   // "" when the host name does not tell; the app's scripts then do
	NS   string // Firebase emulator namespace (?ns=), "" otherwise
}

// String is the URL as given, without a query.
func (b *Backend) String() string {
	s := b.URL.String()
	if b.NS != "" {
		s += "?ns=" + b.NS
	}
	return s
}

var reNS = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

// Parse checks --backend-url: an http or https URL with no user name,
// fragment or query, except ns=NAME for the Firebase emulator. Hosted
// Supabase (*.supabase.co) and Firebase (*.firebaseio.com,
// *.firebasedatabase.app) are known by their host name; any other host
// (a local backend) is told apart by the app's scripts.
func Parse(raw string) (*Backend, error) {
	pu, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("--backend-url: not a valid URL: %w", err)
	}
	if pu.Fragment != "" || strings.Contains(raw, "#") {
		return nil, errors.New("--backend-url must not have a fragment")
	}
	b := &Backend{}
	if pu.RawQuery != "" {
		q, err := url.ParseQuery(pu.RawQuery)
		if err != nil || len(q) != 1 || len(q["ns"]) != 1 || !reNS.MatchString(q.Get("ns")) {
			return nil, errors.New("--backend-url may have only one query parameter, ns=NAME (the Firebase emulator's database name)")
		}
		b.NS, b.Kind = q.Get("ns"), Firebase
	}
	pathURL, _, _ := strings.Cut(raw, "?")
	if b.URL, err = target.Parse(pathURL); err != nil {
		return nil, fmt.Errorf("--backend-url: %w", err)
	}
	if b.URL.Path != "/" {
		return nil, errors.New("--backend-url must be the backend's address with no path, such as https://PROJECT.supabase.co or https://DB.firebaseio.com")
	}
	h, hosted := b.URL.Host, true
	switch {
	case strings.HasSuffix(h, ".supabase.co"):
		if b.Kind == Firebase {
			return nil, errors.New("--backend-url: ns= applies only to the Firebase emulator")
		}
		b.Kind = Supabase
	case strings.HasSuffix(h, ".firebaseio.com") || strings.HasSuffix(h, ".firebasedatabase.app"):
		b.Kind = Firebase
	default:
		hosted = false
	}
	if hosted && b.URL.Scheme != "https" {
		return nil, errors.New("--backend-url: hosted Supabase and Firebase use https")
	}
	return b, nil
}

// Scripts is what the app's served files say about the backend.
type Scripts struct {
	HostSeen bool   // the backend's host appears in a served file
	Kind     Kind   // from the host name, or from the files that name the host
	Key      string // Supabase public key: an anon JWT or a publishable key
	KeyFile  string // the file the key came from
	Tables   []string
	Paths    []string // Firebase paths, without the root
}

var (
	reJWT         = regexp.MustCompile(`eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}`)
	rePublishable = regexp.MustCompile(`\bsb_publishable_[A-Za-z0-9_-]{8,}`)
	// .from("table") as supabase-js writes it; minifiers keep method names.
	// Storage buckets (storage.from) and Array.from are left out.
	reFrom = regexp.MustCompile(`([A-Za-z0-9_$]+\s*)?\.\s*from\s*\(\s*["'\x60]([^"'\x60\\$]{1,63})["'\x60]\s*\)`)
	// ref(db, "path"), db.ref("path") and .child("path"). Modular SDK
	// bundles often rename ref(), so paths also come from the rules file.
	// A template literal counts up to its first ${...}.
	reRef = regexp.MustCompile(`(?:\bref|\.child)\s*\(\s*(?:[A-Za-z_$][\w$.]*\s*,\s*)?["'\x60]([^"'\x60\\$]{1,200})(?:["'\x60]|\$\{)`)
)

// notClient are objects with a from() that is not a query: storage
// buckets and JavaScript's own constructors.
var notClient = map[string]bool{
	"storage": true, "Array": true, "Buffer": true, "Set": true, "Map": true, "Object": true, "Iterator": true,
	"Uint8Array": true, "Uint16Array": true, "Uint32Array": true, "Int8Array": true, "Int16Array": true,
	"Int32Array": true, "Float32Array": true, "Float64Array": true, "Observable": true,
}

var reTable = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_$ -]{0,62}$`)

// ReadScripts reads the fetched files (name to content). It never returns
// a service-role or secret key: only keys meant to be public.
func ReadScripts(b *Backend, files map[string][]byte) Scripts {
	s := Scripts{Kind: b.Kind}
	host := strings.ToLower(b.URL.Origin())
	host = strings.TrimPrefix(strings.TrimPrefix(host, "https://"), "http://")
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	var naming []string // files that name the backend's host
	for _, n := range names {
		if strings.Contains(strings.ToLower(string(files[n])), host) {
			s.HostSeen = true
			naming = append(naming, n)
		}
	}
	if s.Kind == "" {
		s.Kind = detectKind(files, naming)
		if s.Kind == "" {
			s.Kind = detectKind(files, names)
		}
	}
	tables, paths := map[string]bool{}, map[string]bool{}
	var jwtKey, jwtFile, pubKey, pubFile string
	ref := ProjectRef(b.URL.Host)
	for _, n := range names {
		data := string(files[n])
		for _, m := range reFrom.FindAllStringSubmatch(data, -1) {
			obj := strings.TrimSpace(m[1])
			if notClient[obj] || !reTable.MatchString(m[2]) {
				continue
			}
			tables[m[2]] = true
		}
		for _, m := range reRef.FindAllStringSubmatch(data, -1) {
			if p := FirebasePath(m[1]); p != "" {
				paths[p] = true
			}
		}
		if jwtKey == "" {
			for _, k := range reJWT.FindAllString(data, -1) {
				if anonKey(k, ref) {
					jwtKey, jwtFile = k, n
					break
				}
			}
		}
		if pubKey == "" {
			if k := rePublishable.FindString(data); k != "" {
				pubKey, pubFile = k, n
			}
		}
	}
	switch {
	case jwtKey != "":
		s.Key, s.KeyFile = jwtKey, jwtFile
	case pubKey != "":
		s.Key, s.KeyFile = pubKey, pubFile
	}
	s.Tables = sortedKeys(tables)
	s.Paths = sortedKeys(paths)
	return s
}

func detectKind(files map[string][]byte, names []string) Kind {
	var sb, fb bool
	for _, n := range names {
		low := strings.ToLower(string(files[n]))
		sb = sb || strings.Contains(low, "supabase")
		fb = fb || strings.Contains(low, "firebase")
	}
	switch {
	case sb && !fb:
		return Supabase
	case fb && !sb:
		return Firebase
	}
	return ""
}

// anonKey reports whether k is a Supabase anon JWT, for project ref when
// ref is known. Its signature is not checked: the backend checks it.
func anonKey(k, ref string) bool {
	role, r, ok := jwtClaims(k)
	return ok && role == "anon" && (ref == "" || r == "" || r == ref)
}

// FirebasePath turns a path from code or rules into at most two segments
// ("users", "users/profiles"), or "" when it is not a usable literal path.
// Firebase keys cannot hold . $ # [ ] or control characters.
func FirebasePath(p string) string {
	var segs []string
	for _, s := range strings.Split(strings.Trim(p, "/"), "/") {
		if s == "" || len(segs) == 2 {
			break
		}
		if strings.ContainsAny(s, ".$#[]{}\"'` \t\r\n") || len(s) > 128 {
			break
		}
		segs = append(segs, s)
	}
	return strings.Join(segs, "/")
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Names joins the names from the scripts and from the repository, sorted
// and without duplicates, and caps them at MaxNames. It returns the names
// and how many were left out.
func Names(lists ...[]string) ([]string, int) {
	set := map[string]bool{}
	for _, l := range lists {
		for _, n := range l {
			set[n] = true
		}
	}
	all := sortedKeys(set)
	if len(all) > MaxNames {
		return all[:MaxNames], len(all) - MaxNames
	}
	return all, 0
}

// Readable is a table or path that answered with data.
type Readable struct {
	Name     string   // table, or Firebase path ("" is the root)
	Columns  []string // Supabase: the first row's column names
	Children int      // Firebase: keys under the path (1 for a single value)
}

// Result is what the check saw.
type Result struct {
	Kind      Kind
	Tested    int // names sent a request
	Readable  []Readable
	Empty     int // Supabase: no rows (empty, or hidden by row-level security); Firebase: no data
	Denied    int // 401 or 403
	Missing   int // 404: no such table or database
	Errors    int // any other answer
	OverLimit int // names over MaxNames, not tested
	Requests  int // requests the backend answered
	RootOpen  bool
}

// Summary says the result in one line, for reports.
func (r Result) Summary() string {
	if r.RootOpen {
		return "the database root is readable without signing in"
	}
	what := "tables"
	if r.Kind == Firebase {
		what = "paths"
	}
	parts := []string{fmt.Sprintf("%d readable", len(r.Readable))}
	empty := "empty or protected by row-level security"
	if r.Kind == Firebase {
		empty = "empty"
	}
	for _, c := range []struct {
		n    int
		text string
	}{{r.Empty, empty}, {r.Denied, "refused (401 or 403)"}, {r.Missing, "not found (404)"}, {r.Errors, "other answers"}, {r.OverLimit, fmt.Sprintf("over the %d-name limit, not tested", MaxNames)}} {
		if c.n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", c.n, c.text))
		}
	}
	return fmt.Sprintf("%d %s tested: %s", r.Tested, what, strings.Join(parts, ", "))
}

// send and sleep are replaced in tests.
var (
	send  = egress.SendHeader
	sleep = func(ctx context.Context, d time.Duration) error {
		t := time.NewTimer(d)
		defer t.Stop()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
			return nil
		}
	}
)

// Check sends one GET per name, at most one per Interval, on a read-only
// configuration. Supabase: GET /rest/v1/TABLE?select=*&limit=1 with the
// public key. Firebase: the root first, then each path, with
// /PATH.json?shallow=true and no key; when the root is readable the paths
// are not sent. It fails when the backend does not answer, or gives no
// answer it can read.
func Check(ctx context.Context, cfg egress.Config, b *Backend, kind Kind, key string, names []string, overLimit int) (Result, error) {
	if !cfg.ReadOnly {
		return Result{}, errors.New("the backend check runs only on a read-only configuration")
	}
	r := Result{Kind: kind, OverLimit: overLimit}
	var header http.Header
	switch kind {
	case Supabase:
		if key == "" {
			return r, ErrNoKey
		}
		header = supabaseHeader(key)
		header.Set("Accept", "application/json")
	case Firebase:
		names = append([]string{""}, slices.DeleteFunc(slices.Clone(names), func(n string) bool { return n == "" })...)
	default:
		return r, errors.New("cannot tell whether the backend is Supabase or Firebase")
	}
	if len(names) == 0 {
		return r, errors.New("no table names were found in the app's scripts; pass --source with the app's repository so they are read from its migrations")
	}
	var lastErr error
	for i, n := range names {
		if i > 0 {
			if err := sleep(ctx, Interval); err != nil {
				return r, err
			}
		}
		p := RequestPath(kind, n, b.NS)
		a, err := send(ctx, cfg, http.MethodGet, p, header, nil, MaxAnswer)
		r.Tested++
		if a == nil {
			if ctx.Err() != nil {
				return r, ctx.Err()
			}
			lastErr = err
			r.Errors++
			continue
		}
		r.Requests++
		switch {
		case err != nil: // too large: data came back, but SiegeKit does not read it
			if a.Status == http.StatusOK {
				r.Readable = append(r.Readable, Readable{Name: n})
			} else {
				r.Errors++
			}
		case a.Status == http.StatusOK:
			if rd, ok := readable(kind, n, a.Body); ok {
				r.Readable = append(r.Readable, rd)
			} else if empty(kind, a.Body) {
				r.Empty++
			} else {
				r.Errors++
			}
		case a.Status == http.StatusUnauthorized || a.Status == http.StatusForbidden:
			r.Denied++
		case a.Status == http.StatusNotFound:
			r.Missing++
		default:
			r.Errors++
		}
		if kind == Firebase && n == "" && len(r.Readable) == 1 {
			r.RootOpen = true
			return r, nil
		}
	}
	if r.Requests == 0 {
		return r, fmt.Errorf("the backend did not answer: %v", lastErr)
	}
	if r.Errors == r.Tested {
		return r, fmt.Errorf("the backend gave no answer this check can read in %d request(s); check --backend-url", r.Tested)
	}
	return r, nil
}

// RequestPath is the path and query of the GET for name.
func RequestPath(kind Kind, name, ns string) string {
	if kind == Supabase {
		return "/rest/v1/" + url.PathEscape(name) + "?select=*&limit=1"
	}
	var segs []string
	for _, s := range strings.Split(name, "/") {
		if s != "" {
			segs = append(segs, url.PathEscape(s))
		}
	}
	p := "/" + strings.Join(segs, "/") + ".json?shallow=true"
	if ns != "" {
		p += "&ns=" + url.QueryEscape(ns)
	}
	return p
}

// readable reads an answer that has data, keeping only column names.
func readable(kind Kind, name string, body []byte) (Readable, bool) {
	if kind == Supabase {
		var rows []map[string]json.RawMessage
		if json.Unmarshal(body, &rows) != nil || len(rows) == 0 {
			return Readable{}, false
		}
		cols := make([]string, 0, len(rows[0]))
		for c := range rows[0] {
			cols = append(cols, c)
		}
		sort.Strings(cols)
		return Readable{Name: name, Columns: cols}, true
	}
	var v any
	if json.Unmarshal(body, &v) != nil || v == nil {
		return Readable{}, false
	}
	n := 1
	if m, ok := v.(map[string]any); ok {
		n = len(m)
	}
	return Readable{Name: name, Children: n}, true
}

func empty(kind Kind, body []byte) bool {
	s := strings.TrimSpace(string(body))
	if kind == Supabase {
		return s == "[]"
	}
	return s == "null"
}

// Findings turns readable tables and paths into findings: high, CWE-284
// and CWE-862 (owner answer 3a), with names only. keyFrom is where the
// Supabase key came from (a served file or KeyEnv); Firebase ignores it.
func Findings(b *Backend, r Result, keyFrom string) []findings.Finding {
	var out []findings.Finding
	for _, rd := range r.Readable {
		p, _, _ := strings.Cut(RequestPath(r.Kind, rd.Name, ""), "?")
		f := findings.Finding{
			Severity: findings.High,
			CWEs:     []string{"CWE-284", "CWE-862"},
			Location: findings.Location{URI: strings.TrimSuffix(b.URL.Origin(), "/") + p},
			Family:   Family,
		}
		if r.Kind == Supabase {
			cols := "not read (the answer was over the size limit)"
			if len(rd.Columns) > 0 {
				cols = strings.Join(rd.Columns, ", ")
			}
			f.RuleID, f.Title = "supabase-table-readable", "Supabase table is readable with the project's public key"
			with, anyone := keyReach(keyFrom)
			f.Message = fmt.Sprintf("GET %s?select=*&limit=1 %s returned a row, so %s can read this table. Columns: %s. Enable row-level security on %s and add policies that return only the rows a user may see (for example auth.uid() = user_id). If the table is meant to be public, such as a product list, check the columns above and ignore this. SiegeKit read one row and kept only the column names.", p, with, anyone, cols, rd.Name)
		} else {
			name := "/" + rd.Name
			f.RuleID, f.Title = "firebase-rtdb-readable", "Realtime Database data is readable without signing in"
			f.Message = fmt.Sprintf("GET %s?shallow=true with no login returned data (%d key(s) at %s). Anyone can read it. Add a \".read\" rule with a condition, such as \"auth != null && auth.uid === $uid\". SiegeKit kept only the number of keys, not the data.", p, rd.Children, name)
		}
		f.Sources = []findings.Source{{Plugin: ID, RuleID: f.RuleID}}
		f.ComputeFingerprint()
		out = append(out, f)
	}
	return out
}

// Package authz is SiegeKit's access-control check between accounts
// (ADR 0011 item 1, ADR 0035). It replays the GET and HEAD requests of a
// browser recording (a HAR file) made as account A three times: as A, as
// account B and with no login. A request whose answer B gets exactly as A
// does, while a request with no login is refused, is reported as data B can
// likely read. One whose answer comes back to a request with no login,
// holding A's login name, is reported as data anyone can read. It sends no
// other method, so it changes nothing.
package authz

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/Gobbuwu/SiegeKit/internal/egress"
	"github.com/Gobbuwu/SiegeKit/internal/findings"
	"github.com/Gobbuwu/SiegeKit/internal/target"
)

// ID, Name and Family describe the check in plans and reports.
const (
	ID     = "access-control"
	Name   = "Access control between accounts"
	Family = "dast"
)

// Limits (ADR 0035).
const (
	MaxRequests = 100      // requests replayed, each sent up to three times
	MaxHARSize  = 64 << 20 // bytes read from the HAR file
	MaxAnswer   = 2 << 20  // bytes read from each answer
	maxSession  = 8 << 10  // bytes of SIEGEKIT_SESSION_B
)

// SessionEnv names the environment variable that holds account B's session
// headers, one "Name: value" per line (answer 2a).
const SessionEnv = "SIEGEKIT_SESSION_B"

// sessionHeaders carry a login. They are taken from A's requests for B and
// for the request with no login; B's own header names are added to them.
var sessionHeaders = []string{"Authorization", "Cookie", "X-Api-Key", "X-Auth-Token", "X-Access-Token", "X-Session-Token"}

// skipHeaders are never replayed: the transport and SiegeKit set them, or
// they only make sense in the browser.
var skipHeaders = map[string]bool{
	"Host": true, "User-Agent": true, "Content-Length": true, "Connection": true, "Keep-Alive": true,
	"Transfer-Encoding": true, "Te": true, "Trailer": true, "Upgrade": true, "Accept-Encoding": true,
	"If-None-Match": true, "If-Modified-Since": true, "Cache-Control": true, "Pragma": true,
}

// staticExt are files the browser loads for the page itself; replaying them
// tells nothing about access control.
var staticExt = map[string]bool{
	".js": true, ".mjs": true, ".css": true, ".map": true, ".png": true, ".jpg": true, ".jpeg": true, ".gif": true,
	".svg": true, ".ico": true, ".webp": true, ".avif": true, ".woff": true, ".woff2": true, ".ttf": true, ".otf": true,
	".eot": true, ".mp4": true, ".webm": true, ".mp3": true,
}

// Request is one request to replay.
type Request struct {
	Method string
	Path   string // path and query on the target's origin
	Header http.Header
}

// HAR is what was taken from a HAR file.
type HAR struct {
	Requests    []Request
	Static      int // static files, not replayed
	OtherMethod int // not GET or HEAD
	OtherOrigin int // on another origin (ADR 0005)
	BadPath     int // a path that does not start with a single / (ADR 0042)
	Duplicate   int
	OverLimit   int // past MaxRequests
	FromSpec    int // added from the OpenAPI spec by AddSpecRoutes
}

type harFile struct {
	Log struct {
		Entries []struct {
			Request struct {
				Method  string `json:"method"`
				URL     string `json:"url"`
				Headers []struct {
					Name  string `json:"name"`
					Value string `json:"value"`
				} `json:"headers"`
			} `json:"request"`
		} `json:"entries"`
	} `json:"log"`
}

// ParseHAR reads a HAR file recorded as account A and keeps the GET and
// HEAD requests to the target's origin, in order, without duplicates and
// without static files, at most MaxRequests.
func ParseHAR(data []byte, t *target.URL) (*HAR, error) {
	if len(data) > MaxHARSize {
		return nil, fmt.Errorf("the HAR file is larger than %d MiB", MaxHARSize>>20)
	}
	var f harFile
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("not a HAR file: %v", err)
	}
	if len(f.Log.Entries) == 0 {
		return nil, errors.New("the HAR file holds no requests")
	}
	h := &HAR{}
	seen := map[string]bool{}
	for _, e := range f.Log.Entries {
		r := e.Request
		u, err := url.Parse(r.URL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil {
			h.OtherOrigin++
			continue
		}
		o, err := target.Parse(u.Scheme + "://" + u.Host + "/")
		if err != nil || o.Origin() != t.Origin() {
			h.OtherOrigin++
			continue
		}
		method := strings.ToUpper(r.Method)
		if method != http.MethodGet && method != http.MethodHead {
			h.OtherMethod++
			continue
		}
		if staticExt[strings.ToLower(path.Ext(u.Path))] {
			h.Static++
			continue
		}
		p := u.EscapedPath()
		if p == "" {
			p = "/"
		}
		if !target.SendablePath(p) {
			h.BadPath++
			continue
		}
		if u.RawQuery != "" {
			p += "?" + u.RawQuery
		}
		if seen[method+" "+p] {
			h.Duplicate++
			continue
		}
		seen[method+" "+p] = true
		if len(h.Requests) == MaxRequests {
			h.OverLimit++
			continue
		}
		hd := http.Header{}
		for _, kv := range r.Headers {
			k := http.CanonicalHeaderKey(kv.Name)
			if k == "" || strings.HasPrefix(kv.Name, ":") || skipHeaders[k] || strings.HasPrefix(k, "Proxy-") || strings.HasPrefix(k, "Sec-") {
				continue
			}
			hd.Add(k, kv.Value)
		}
		h.Requests = append(h.Requests, Request{Method: method, Path: p, Header: hd})
	}
	if len(h.Requests) == 0 {
		return nil, fmt.Errorf("the HAR file has no GET or HEAD request to %s other than static files", t.Origin())
	}
	return h, nil
}

// SpecRoutes returns the GET paths of a JSON OpenAPI or Swagger spec that
// take no path parameter, sorted. A YAML spec gives none: SiegeKit has no
// YAML reader (ADR 0035). Paths with a parameter are left out because no
// value for it is known.
func SpecRoutes(data []byte, format string) []string {
	if format != "json" {
		return nil
	}
	var doc struct {
		Paths map[string]map[string]json.RawMessage `json:"paths"`
	}
	if json.Unmarshal(bytes.TrimPrefix(data, []byte("\xef\xbb\xbf")), &doc) != nil {
		return nil
	}
	var out []string
	for p, ops := range doc.Paths {
		if _, ok := ops["get"]; !ok || !strings.HasPrefix(p, "/") || strings.HasPrefix(p, "//") || strings.ContainsAny(p, "{}?#\\ \t\r\n\x00") {
			continue
		}
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// AddSpecRoutes adds GET requests for the spec's routes under base (the
// spec's base path, "" for the root) after the HAR's own requests, without
// duplicates and within MaxRequests. They carry account A's session
// headers from the last HAR request that has any; with none, nothing is
// added, because A's answer would be the same as no login.
func (h *HAR) AddSpecRoutes(routes []string, base string) {
	var session http.Header
	for i := len(h.Requests) - 1; i >= 0 && session == nil; i-- {
		for _, k := range sessionHeaders {
			if vs := h.Requests[i].Header.Values(k); len(vs) > 0 {
				if session == nil {
					session = http.Header{}
				}
				session[k] = append([]string(nil), vs...)
			}
		}
	}
	if session == nil {
		return
	}
	seen := map[string]bool{}
	for _, r := range h.Requests {
		seen[r.Method+" "+r.Path] = true
	}
	for _, r := range routes {
		p := base + r
		if seen["GET "+p] {
			continue
		}
		seen["GET "+p] = true
		if len(h.Requests) == MaxRequests {
			h.OverLimit++
			continue
		}
		h.Requests = append(h.Requests, Request{Method: http.MethodGet, Path: p, Header: session.Clone()})
		h.FromSpec++
	}
}

var reHeaderName = regexp.MustCompile(`^[A-Za-z0-9!#$%&'*+.^_|~-]+$`)

// ParseSession reads account B's session headers: one "Name: value" per
// line, for example "Authorization: Bearer ..." or "Cookie: session=...".
func ParseSession(s string) (http.Header, error) {
	if len(s) > maxSession {
		return nil, fmt.Errorf("%s is longer than %d KiB", SessionEnv, maxSession>>10)
	}
	h := http.Header{}
	for _, line := range strings.Split(strings.ReplaceAll(s, "\r\n", "\n"), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		name, value, ok := strings.Cut(line, ":")
		name, value = strings.TrimSpace(name), strings.TrimSpace(value)
		if !ok || !reHeaderName.MatchString(name) || value == "" || strings.ContainsAny(value, "\r\n\x00") {
			return nil, fmt.Errorf("%s must hold one \"Name: value\" header per line", SessionEnv)
		}
		k := http.CanonicalHeaderKey(name)
		if skipHeaders[k] || strings.HasPrefix(k, "Proxy-") {
			return nil, fmt.Errorf("%s cannot set %s", SessionEnv, k)
		}
		h.Add(k, value)
	}
	if len(h) == 0 {
		return nil, fmt.Errorf("%s is empty", SessionEnv)
	}
	return h, nil
}

// Answer is what one replay got back.
type Answer struct {
	Status int
	Body   []byte
	Err    string // the target did not answer, or the answer was too large
}

// Replay is one request replayed as A, as B and with no login.
type Replay struct {
	Request
	A, B, None Answer
	BTested    bool
}

// Result is what Check did.
type Result struct {
	Replays  []Replay
	Requests int // requests the target answered
	ATried   int // requests replayed as A
	AFailed  int // A's replay did not answer 2xx: B and no login not sent
	BRefused int // B's replay refused with 401 or 403
	BTested  bool
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

// Check replays the requests one at a time, at most rate per second. b is
// account B's session, nil to test only requests with no login. cfg must
// be read-only: only GET and HEAD are sent.
func Check(ctx context.Context, cfg egress.Config, reqs []Request, b http.Header, rate float64) (Result, error) {
	if !cfg.ReadOnly {
		return Result{}, errors.New("the access-control check sends only GET and HEAD: pass a read-only configuration")
	}
	var interval time.Duration
	if rate > 0 {
		interval = time.Duration(float64(time.Second) / rate)
	}
	res := Result{BTested: b != nil}
	var last time.Time
	do := func(r Request, h http.Header) (Answer, error) {
		if !last.IsZero() {
			if err := sleep(ctx, interval-time.Since(last)); err != nil {
				return Answer{}, err
			}
		}
		last = time.Now()
		a, err := send(ctx, cfg, r.Method, r.Path, h, nil, MaxAnswer)
		if ctx.Err() != nil {
			return Answer{}, ctx.Err()
		}
		if a == nil {
			return Answer{Err: errString(err)}, nil
		}
		res.Requests++
		if err != nil {
			return Answer{Status: a.Status, Err: errString(err)}, nil
		}
		return Answer{Status: a.Status, Body: a.Body}, nil
	}
	session := sessionNames(b)
	for _, r := range reqs {
		rp := Replay{Request: r}
		var err error
		res.ATried++
		if rp.A, err = do(r, r.Header); err != nil {
			return res, err
		}
		if !ok2xx(rp.A) {
			res.AFailed++
			res.Replays = append(res.Replays, rp)
			continue
		}
		none := without(r.Header, session)
		if b != nil {
			hb := none.Clone()
			for k, vs := range b {
				hb[k] = append([]string(nil), vs...)
			}
			if rp.B, err = do(r, hb); err != nil {
				return res, err
			}
			rp.BTested = true
			if rp.B.Status == http.StatusUnauthorized || rp.B.Status == http.StatusForbidden {
				res.BRefused++
			}
		}
		if rp.None, err = do(r, none); err != nil {
			return res, err
		}
		res.Replays = append(res.Replays, rp)
	}
	return res, nil
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func ok2xx(a Answer) bool { return a.Err == "" && a.Status >= 200 && a.Status < 300 }

// sessionNames are the headers removed for B and for no login.
func sessionNames(b http.Header) map[string]bool {
	m := map[string]bool{}
	for _, k := range sessionHeaders {
		m[k] = true
	}
	for k := range b {
		m[http.CanonicalHeaderKey(k)] = true
	}
	return m
}

func without(h http.Header, names map[string]bool) http.Header {
	out := http.Header{}
	for k, vs := range h {
		if !names[http.CanonicalHeaderKey(k)] {
			out[k] = append([]string(nil), vs...)
		}
	}
	return out
}

// refused: the request with no login was turned away (answer 4a).
func refused(a Answer) bool {
	return a.Err == "" && (a.Status == http.StatusUnauthorized || a.Status == http.StatusForbidden || (a.Status >= 300 && a.Status < 400))
}

func same(x, y Answer) bool {
	return ok2xx(x) && ok2xx(y) && x.Status == y.Status && bytes.Equal(x.Body, y.Body)
}

// CrossAccount reports whether B got A's data (answer 4a): the same status
// and body as A, a request with no login refused, and data in the answer.
func (r Replay) CrossAccount() bool {
	return r.BTested && same(r.A, r.B) && refused(r.None) && HoldsData(r.A.Body)
}

// NoLogin reports whether a request with no login got A's data (answer 6a):
// the same status and body as A, with data and A's login name in it.
func (r Replay) NoLogin(loginName string) bool {
	return same(r.A, r.None) && HoldsData(r.A.Body) && namesA(r.A.Body, loginName)
}

// namesA reports whether an answer holds A's login name, in any case.
func namesA(body []byte, loginName string) bool {
	return loginName != "" && bytes.Contains(bytes.ToLower(body), []byte(strings.ToLower(loginName)))
}

// statusKeys hold an answer's status, not its data.
var statusKeys = map[string]bool{"status": true, "message": true, "msg": true, "result": true, "error": true, "code": true, "ok": true, "success": true}

// HoldsData reports whether an answer holds data: for JSON, a non-empty
// array, a non-zero number, true, or a non-empty string outside status
// fields, anywhere inside; any other non-blank body counts as data.
func HoldsData(body []byte) bool {
	b := bytes.TrimSpace(body)
	if len(b) == 0 {
		return false
	}
	var v any
	if err := json.Unmarshal(b, &v); err != nil {
		return true
	}
	return holds(v, 0)
}

func holds(v any, depth int) bool {
	if depth > 64 {
		return true
	}
	switch x := v.(type) {
	case nil:
		return false
	case bool:
		return x
	case float64:
		return x != 0
	case string:
		return x != ""
	case []any:
		return len(x) > 0
	case map[string]any:
		for k, e := range x {
			if statusKeys[strings.ToLower(k)] {
				continue
			}
			if holds(e, depth+1) {
				return true
			}
		}
	}
	return false
}

// Summary says what was replayed in one line, for reports.
func (r Result) Summary(h *HAR, loginName string, c Counts) string {
	s := fmt.Sprintf("replayed %d request(s) from the HAR file", r.ATried)
	if h != nil && h.FromSpec > 0 {
		s = fmt.Sprintf("replayed %d request(s) (%d from the HAR file, %d from the OpenAPI spec)", r.ATried, r.ATried-h.FromSpec, h.FromSpec)
	}
	if r.BTested {
		s += fmt.Sprintf(": %d readable by account B", c.Cross)
	} else {
		s += ": account B not tested (" + SessionEnv + " not set)"
	}
	if loginName != "" {
		s += fmt.Sprintf(", %d readable with no login", c.NoLogin)
	} else {
		s += ", no-login reads not reported (no --har-user)"
	}
	s += fmt.Sprintf(", %d with secret fields for no login", c.Secrets)
	var notes []string
	if r.AFailed > 0 {
		notes = append(notes, fmt.Sprintf("%d did not answer account A with 2xx and were not sent further", r.AFailed))
	}
	if r.BTested && r.BRefused > 0 && r.BRefused == r.ATried-r.AFailed {
		notes = append(notes, "account B was refused on every request: check that its session in "+SessionEnv+" is still valid")
	}
	if h != nil {
		for _, x := range []struct {
			n    int
			what string
		}{
			{h.Static, "static files"}, {h.OtherMethod, "not GET or HEAD"}, {h.OtherOrigin, "on another origin"}, {h.BadPath, "with a path that does not start with a single /"},
			{h.Duplicate, "duplicates"}, {h.OverLimit, fmt.Sprintf("over the %d-request limit", MaxRequests)},
		} {
			if x.n > 0 {
				notes = append(notes, fmt.Sprintf("%d %s not replayed", x.n, x.what))
			}
		}
	}
	if len(notes) > 0 {
		s += "; " + strings.Join(notes, "; ")
	}
	return s
}

var reID = regexp.MustCompile(`^(?:\d+|[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}|[0-9a-fA-F]{16,})$`)

// hasID reports whether the path or query holds what looks like an object
// ID: a number, a UUID or a long hex string.
func hasID(p string) bool {
	pathPart, query, _ := strings.Cut(p, "?")
	for _, seg := range strings.Split(pathPart, "/") {
		if reID.MatchString(seg) {
			return true
		}
	}
	if q, err := url.ParseQuery(query); err == nil {
		for _, vs := range q {
			for _, v := range vs {
				if reID.MatchString(v) {
					return true
				}
			}
		}
	}
	return false
}

// Findings turns the replays into findings at the request's URL, without
// the query. Answers are described by status and size; their content is
// not copied into the report.
func Findings(origin string, res Result, loginName string) []findings.Finding {
	var out []findings.Finding
	for _, r := range res.Replays {
		pathOnly, _, _ := strings.Cut(r.Path, "?")
		loc := findings.Location{URI: origin + pathOnly}
		switch {
		case r.CrossAccount():
			cwe := "CWE-862"
			if hasID(r.Path) {
				cwe = "CWE-639"
			}
			// High only with a sign that the answer is A's own: an ID in
			// the URL or A's login name in it. Otherwise two new accounts
			// can get the same default answer (measured on Gitea's
			// /user/settings, ADR 0035).
			sev, note := findings.Medium, " The URL holds no ID and the answer does not name account A, so this may be an answer every account gets, such as default settings: check it by hand."
			if hasID(r.Path) || namesA(r.A.Body, loginName) {
				sev, note = findings.High, ""
			}
			f := findings.Finding{
				RuleID:   "cross-account-read",
				Title:    "Another account can read this data",
				Message:  fmt.Sprintf("%s %s answered account B exactly as it answered account A (status %d, %d bytes), while a request with no login was refused (status %d). Account B can likely read account A's data here: broken access control (OWASP API1 and API5). This is a heuristic, not proof: compare both answers yourself.%s", r.Method, pathOnly, r.A.Status, len(r.A.Body), r.None.Status, note),
				Severity: sev,
				CWEs:     []string{cwe},
				Location: loc,
				Family:   Family,
			}
			out = append(out, f)
		case r.NoLogin(loginName):
			out = append(out, findings.Finding{
				RuleID:   "no-login-read",
				Title:    "Account data is readable with no login",
				Message:  fmt.Sprintf("%s %s answered a request with no login exactly as it answered account A (status %d, %d bytes), and the answer holds A's login name. Anyone may be able to read this account's data: missing authentication (OWASP API2). Public pages such as profiles or commit lists also name their author by design, so check it by hand.", r.Method, pathOnly, r.A.Status, len(r.A.Body)),
				Severity: findings.Medium,
				CWEs:     []string{"CWE-306"},
				Location: loc,
				Family:   Family,
			})
		}
		if fields := r.NoLoginSecrets(); len(fields) > 0 {
			out = append(out, findings.Finding{
				RuleID:   "no-login-secret",
				Title:    "Secrets are readable with no login",
				Message:  fmt.Sprintf("%s %s answered a request with no login (status %d, %d bytes) with fields named like secrets that hold a value: %s. Anyone can likely read them, such as password hashes, tokens or keys: excessive data exposure (OWASP API3). The values are not copied into this report; check the answer yourself.", r.Method, pathOnly, r.None.Status, len(r.None.Body), strings.Join(fields, ", ")),
				Severity: findings.High,
				CWEs:     []string{"CWE-200"},
				Location: loc,
				Family:   Family,
			})
		}
	}
	for i := range out {
		out[i].Sources = []findings.Source{{Plugin: ID, RuleID: out[i].RuleID}}
		out[i].ComputeFingerprint()
	}
	return out
}

// secretKeys are field names (lower case, without "_", "-" and spaces)
// that hold credentials or keys (ADR 0035 item 7). Generic names such as
// "token" or "key" are left out: public answers carry CSRF tokens and
// lookup keys by design.
var secretKeys = map[string]bool{
	"password": true, "passwd": true, "pwd": true, "passwordhash": true, "hashedpassword": true, "encryptedpassword": true,
	"passwordsalt": true, "salt": true, "totpsecret": true, "otpsecret": true, "mfasecret": true, "twofactorsecret": true,
	"secret": true, "clientsecret": true, "apisecret": true, "secretkey": true, "privatekey": true, "apikey": true,
	"accesstoken": true, "refreshtoken": true, "sessiontoken": true, "authtoken": true, "resettoken": true,
	"passwordresettoken": true, "deluxetoken": true, "ssn": true, "socialsecuritynumber": true, "cardnumber": true,
	"cardnum": true, "cvv": true, "cvc": true,
}

// notSecret are values that say a field is empty, hidden or a setting.
var notSecret = map[string]bool{"true": true, "false": true, "null": true, "none": true, "nil": true, "undefined": true, "redacted": true, "[redacted]": true, "hidden": true, "[hidden]": true, "[filtered]": true, "masked": true}

// translationDirs are path segments of translation files, whose JSON maps
// words such as "password" to labels.
var translationDirs = map[string]bool{"i18n": true, "locale": true, "locales": true, "lang": true, "langs": true, "translations": true, "l10n": true}

// SecretFields returns the names of fields in a JSON answer that are named
// like secrets and hold a value: a number other than 0, or a string with no
// space that is not masked ("****") or a word such as "null" or "redacted".
// Names are returned once each, sorted, at most 5.
func SecretFields(body []byte) []string {
	var v any
	if json.Unmarshal(bytes.TrimSpace(body), &v) != nil {
		return nil
	}
	found := map[string]bool{}
	secretsIn(v, found, 0)
	out := make([]string, 0, len(found))
	for k := range found {
		out = append(out, k)
	}
	sort.Strings(out)
	if len(out) > 5 {
		out = out[:5]
	}
	return out
}

func secretsIn(v any, found map[string]bool, depth int) {
	if depth > 64 || len(found) > 5 {
		return
	}
	switch x := v.(type) {
	case []any:
		for _, e := range x {
			secretsIn(e, found, depth+1)
		}
	case map[string]any:
		for k, e := range x {
			name := strings.NewReplacer("_", "", "-", "", " ", "").Replace(strings.ToLower(k))
			if secretKeys[name] && holdsSecret(e) {
				found[k] = true
			}
			secretsIn(e, found, depth+1)
		}
	}
}

func holdsSecret(v any) bool {
	switch x := v.(type) {
	case float64:
		return x != 0
	case string:
		s := strings.TrimSpace(x)
		return s != "" && !strings.ContainsAny(s, " \t\r\n*•") && !notSecret[strings.ToLower(s)] && strings.Trim(strings.ToLower(s), "x") != ""
	}
	return false
}

// NoLoginSecrets returns the secret fields in the answer to the request
// with no login (ADR 0035 item 7), except in translation files.
func (r Replay) NoLoginSecrets() []string {
	if !ok2xx(r.None) {
		return nil
	}
	pathOnly, _, _ := strings.Cut(r.Path, "?")
	for _, seg := range strings.Split(strings.ToLower(pathOnly), "/") {
		if translationDirs[seg] {
			return nil
		}
	}
	return SecretFields(r.None.Body)
}

// Counts are how many replays each rule reported.
type Counts struct{ Cross, NoLogin, Secrets int }

// Count counts the replays each rule reports.
func Count(res Result, loginName string) Counts {
	var c Counts
	for _, r := range res.Replays {
		switch {
		case r.CrossAccount():
			c.Cross++
		case r.NoLogin(loginName):
			c.NoLogin++
		}
		if len(r.NoLoginSecrets()) > 0 {
			c.Secrets++
		}
	}
	return c
}

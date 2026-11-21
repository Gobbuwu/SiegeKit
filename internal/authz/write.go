package authz

// Write replay (ADR 0049, ARTEX item 2). The access-control-write check
// replays the POST, PUT, PATCH and DELETE requests of a HAR file recorded
// as account A, as account B and with no login, on local targets only.
// Before each replay it makes a fresh object of A's by sending A's
// recorded create again, so the replay changes that copy and not the one
// A recorded. A replay that answers 2xx is reported: high when it was a
// PUT, PATCH or DELETE and A's own read of the same URL changed, medium
// otherwise. It changes data in the app for real.

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/Gobbuwu/SiegeKit/internal/egress"
	"github.com/Gobbuwu/SiegeKit/internal/findings"
	"github.com/Gobbuwu/SiegeKit/internal/target"
)

// WriteID, WriteName and Family describe the check in plans and reports.
const (
	WriteID   = "access-control-write"
	WriteName = "Write access between accounts"
)

// MaxWrites is how many recorded writes are replayed (ADR 0049 item 5).
// With account B and no login, each replay is at most 4 requests (A's
// create, A's read before, the write, A's read after): 400 at most.
const MaxWrites = 50

// writeMethods are the recorded methods this check replays.
var writeMethods = map[string]bool{http.MethodPost: true, http.MethodPut: true, http.MethodPatch: true, http.MethodDelete: true}

// Write is a recorded request that changes data.
type Write struct {
	Method string
	Path   string // path and query on the target's origin
	Header http.Header
	Body   []byte
	// Create is A's recorded request that made this write's object, nil
	// when no recorded create's answer holds an ID the write uses.
	Create *Create
	// RecordedStatus is the answer A got in the recording.
	RecordedStatus int
	// CSRF: the write carries an anti-forgery token from A's session, in
	// a header or the body. A refusal of B's or the no-login replay may
	// come from that token, not from access control (ADR 0049).
	CSRF bool
	// GraphQL names the mutation of a GraphQL request ("mutation" when it
	// has no name), empty for other requests. GraphQL answers a refused
	// operation with 200 and an "errors" list, so Accepted reads the body.
	GraphQL string
}

// Label is the write as people read it: method and path, plus the
// GraphQL mutation, since every GraphQL write shares one path.
func (w Write) Label() string {
	if w.GraphQL != "" {
		return w.Method + " " + w.Path + " (GraphQL " + w.GraphQL + ")"
	}
	return w.Method + " " + w.Path
}

// Create is a recorded POST whose answer gave the ID a later write uses.
type Create struct {
	Path   string
	Header http.Header
	Body   []byte
	Field  []string // keys leading to the ID in the create's JSON answer
	OldID  string   // the ID in the recorded answer
}

// Writes is what ParseWrites took from a HAR file.
type Writes struct {
	Writes []Write
	// Lockout counts writes never replayed because they could lock an
	// account out or log one in (ADR 0049 item 4); LockoutPaths names
	// them, each once.
	Lockout      int
	LockoutPaths []string
	NoBody       int // the HAR file holds form fields but not the body text
	Duplicate    int
	OverLimit    int // past MaxWrites
	// GraphQLReads counts GraphQL queries and subscriptions sent with
	// POST: they read, so they are not replayed as writes.
	GraphQLReads int
}

type harWriteFile struct {
	Log struct {
		Entries []struct {
			Request struct {
				Method   string       `json:"method"`
				URL      string       `json:"url"`
				Headers  []harHeader  `json:"headers"`
				PostData *harPostBody `json:"postData"`
			} `json:"request"`
			Response struct {
				Status  int `json:"status"`
				Content struct {
					MimeType string `json:"mimeType"`
					Text     string `json:"text"`
					Encoding string `json:"encoding"`
				} `json:"content"`
			} `json:"response"`
		} `json:"entries"`
	} `json:"log"`
}

type harPostBody struct {
	MimeType string            `json:"mimeType"`
	Text     *string           `json:"text"`
	Params   []json.RawMessage `json:"params"`
}

// recordedCreate is a recorded POST with the IDs its answer holds.
type recordedCreate struct {
	index int
	c     Create
	ids   []idField
}

type idField struct {
	field []string
	value string
}

// ParseWrites reads the writes of a HAR file recorded as account A: its
// POST, PUT, PATCH and DELETE requests to the target's origin, in order,
// without duplicates, at most MaxWrites, leaving out those that could lock
// an account out. For each it looks for the recorded create of its object
// (ADR 0049 item 2).
func ParseWrites(data []byte, t *target.URL) (*Writes, error) {
	if len(data) > MaxHARSize {
		return nil, fmt.Errorf("the HAR file is larger than %d MiB", MaxHARSize>>20)
	}
	var f harWriteFile
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("not a HAR file: %v", err)
	}
	w := &Writes{}
	seen := map[string]bool{}
	var creates []recordedCreate
	type pending struct {
		index int
		w     Write
	}
	var kept []pending
	for i, e := range f.Log.Entries {
		r := e.Request
		method := strings.ToUpper(r.Method)
		if !writeMethods[method] {
			continue
		}
		u, err := url.Parse(r.URL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil {
			continue
		}
		o, err := target.Parse(u.Scheme + "://" + u.Host + "/")
		if err != nil || o.Origin() != t.Origin() {
			continue
		}
		p := u.EscapedPath()
		if p == "" {
			p = "/"
		}
		if !target.SendablePath(p) {
			continue
		}
		if u.RawQuery != "" {
			p += "?" + u.RawQuery
		}
		if why := lockoutReason(method, p); why != "" {
			w.Lockout++
			name := method + " " + strings.SplitN(p, "?", 2)[0]
			if !containsString(w.LockoutPaths, name) {
				w.LockoutPaths = append(w.LockoutPaths, name)
			}
			continue
		}
		var body []byte
		hd := replayHeaders(r.Headers)
		if pd := r.PostData; pd != nil {
			switch {
			case pd.Text != nil:
				body = []byte(*pd.Text)
			case len(pd.Params) > 0:
				w.NoBody++
				continue
			}
			if pd.MimeType != "" && len(body) > 0 {
				hd.Set("Content-Type", pd.MimeType)
			}
		}
		if len(body) == 0 {
			hd.Del("Content-Type")
		}
		wr := Write{Method: method, Path: p, Header: hd, Body: body, CSRF: carriesCSRF(hd, body), RecordedStatus: e.Response.Status}
		if kind, name, ok := graphQLOp(body); ok {
			if kind != "mutation" {
				w.GraphQLReads++
				continue
			}
			wr.GraphQL = name
		}
		if method == http.MethodPost {
			depth := 3
			if wr.GraphQL != "" {
				// GraphQL nests one level more: data, the mutation, its payload.
				depth = 4
			}
			if ids := answerIDs(e.Response.Status, e.Response.Content.Text, e.Response.Content.Encoding, depth); len(ids) > 0 {
				creates = append(creates, recordedCreate{index: i, c: Create{Path: p, Header: hd.Clone(), Body: body}, ids: ids})
			}
		}
		key := method + " " + p + " " + string(body)
		if seen[key] {
			w.Duplicate++
			continue
		}
		seen[key] = true
		if len(kept) == MaxWrites {
			w.OverLimit++
			continue
		}
		kept = append(kept, pending{index: i, w: wr})
	}
	for _, k := range kept {
		k.w.Create = findCreate(k.w, k.index, creates)
		w.Writes = append(w.Writes, k.w)
	}
	return w, nil
}

func containsString(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// idNames are the answer keys taken as the new object's ID, in the order
// they are preferred: "number" is Gitea's issue number, which its URLs use
// instead of the ID (prototype, 2026-11-21).
var idNames = []string{"id", "_id", "uuid", "guid", "number"}

func idRank(key string) int {
	k := strings.ToLower(key)
	for i, n := range idNames {
		if k == n {
			return i
		}
	}
	return -1
}

// answerIDs returns the ID fields of a 2xx JSON answer: keys named like
// idNames whose value is a whole number or a short string without "/" or
// spaces, in objects at most maxDepth deep (3, or 4 for GraphQL; not
// inside arrays), nearest first and by idNames order.
func answerIDs(status int, text, encoding string, maxDepth int) []idField {
	if status < 200 || status >= 300 || text == "" {
		return nil
	}
	b := []byte(text)
	if encoding == "base64" {
		d, err := base64.StdEncoding.DecodeString(text)
		if err != nil {
			return nil
		}
		b = d
	}
	var v any
	if json.Unmarshal(bytes.TrimSpace(b), &v) != nil {
		return nil
	}
	var out []idField
	level := []struct {
		obj  map[string]any
		path []string
	}{}
	if m, ok := v.(map[string]any); ok {
		level = append(level, struct {
			obj  map[string]any
			path []string
		}{m, nil})
	}
	for depth := 0; depth < maxDepth && len(level) > 0; depth++ {
		next := level[:0:0]
		for _, l := range level {
			keys := make([]string, 0, len(l.obj))
			for k := range l.obj {
				keys = append(keys, k)
			}
			sort.Slice(keys, func(i, j int) bool {
				ri, rj := idRank(keys[i]), idRank(keys[j])
				if (ri < 0) != (rj < 0) {
					return ri >= 0
				}
				if ri != rj {
					return ri < rj
				}
				return keys[i] < keys[j]
			})
			for _, k := range keys {
				p := append(append([]string(nil), l.path...), k)
				if idRank(k) >= 0 {
					if s, ok := idValue(l.obj[k]); ok {
						out = append(out, idField{field: p, value: s})
					}
				}
				if m, ok := l.obj[k].(map[string]any); ok {
					next = append(next, struct {
						obj  map[string]any
						path []string
					}{m, p})
				}
			}
		}
		level = next
	}
	return out
}

// idValue is v as an ID: a whole number, or a string of 1 to 128
// characters with no "/" and no space.
func idValue(v any) (string, bool) {
	switch x := v.(type) {
	case float64:
		if x >= 0 && x == math.Trunc(x) && x < 1<<53 {
			return strconv.FormatInt(int64(x), 10), true
		}
	case string:
		if x != "" && len(x) <= 128 && !strings.ContainsAny(x, "/ \t\r\n") {
			return x, true
		}
	}
	return "", false
}

// findCreate returns the recorded create before index whose answer holds
// an ID the write uses (a path segment, a query value, or a body value at
// an ID-named key equal to it). When several do, it takes the one whose
// path shares the most leading segments with the write's, then the latest:
// in a browser recording on Juice Shop, a new address and a new card both
// got ID 7, and DELETE /api/Addresss/7 came after the card (measured
// 2026-11-21, ADR 0049).
func findCreate(w Write, index int, creates []recordedCreate) *Create {
	uses := writeIDs(w)
	var best *Create
	bestScore := -1
	for i := len(creates) - 1; i >= 0; i-- {
		c := creates[i]
		if c.index >= index {
			continue
		}
		for _, id := range c.ids {
			if !uses[id.value] {
				continue
			}
			if s := commonSegments(c.c.Path, w.Path); s > bestScore {
				cc := c.c
				cc.Field, cc.OldID = id.field, id.value
				best, bestScore = &cc, s
			}
			break
		}
	}
	return best
}

// commonSegments counts the leading path segments a and b share, in any
// case.
func commonSegments(a, b string) int {
	as := strings.Split(strings.Trim(pathOf(a), "/"), "/")
	bs := strings.Split(strings.Trim(pathOf(b), "/"), "/")
	n := 0
	for n < len(as) && n < len(bs) && strings.EqualFold(as[n], bs[n]) {
		n++
	}
	return n
}

// writeIDs are the values a write could name its object by.
func writeIDs(w Write) map[string]bool {
	m := map[string]bool{}
	p, q, _ := strings.Cut(w.Path, "?")
	for _, seg := range strings.Split(p, "/") {
		if s, err := url.PathUnescape(seg); err == nil && s != "" {
			m[s] = true
		}
	}
	if vals, err := url.ParseQuery(q); err == nil {
		for _, vs := range vals {
			for _, v := range vs {
				m[v] = true
			}
		}
	}
	var v any
	if json.Unmarshal(w.Body, &v) == nil {
		walkIDKeys(v, 0, func(_ map[string]any, _ string, s string) { m[s] = true })
	}
	return m
}

// idKey: a body key that names an object: an idNames key or one ending in
// "id" ("BasketId", "issue_id").
func idKey(k string) bool {
	l := strings.ToLower(k)
	return idRank(k) >= 0 || strings.HasSuffix(l, "id") || strings.HasSuffix(l, "_id")
}

// walkIDKeys calls fn for each ID-like value at an ID-named key in v.
func walkIDKeys(v any, depth int, fn func(obj map[string]any, key, value string)) {
	if depth > 8 {
		return
	}
	switch x := v.(type) {
	case map[string]any:
		for k, e := range x {
			if idKey(k) {
				if s, ok := idValue(e); ok {
					fn(x, k, s)
				}
			}
			walkIDKeys(e, depth+1, fn)
		}
	case []any:
		for _, e := range x {
			walkIDKeys(e, depth+1, fn)
		}
	}
}

// withID is w with oldID replaced by newID in its path segments, query
// values, and JSON or form body values at ID-named keys.
func (w Write) withID(oldID, newID string) Write {
	out := w
	out.Header = w.Header.Clone()
	p, q, hasQ := strings.Cut(w.Path, "?")
	segs := strings.Split(p, "/")
	for i, seg := range segs {
		if s, err := url.PathUnescape(seg); err == nil && s == oldID {
			segs[i] = url.PathEscape(newID)
		}
	}
	out.Path = strings.Join(segs, "/")
	if hasQ {
		if vals, err := url.ParseQuery(q); err == nil {
			changed := false
			for k, vs := range vals {
				for i, v := range vs {
					if v == oldID {
						vals[k][i], changed = newID, true
					}
				}
			}
			if changed {
				q = vals.Encode()
			}
		}
		out.Path += "?" + q
	}
	ct := strings.ToLower(w.Header.Get("Content-Type"))
	var v any
	switch {
	case len(w.Body) > 0 && json.Unmarshal(w.Body, &v) == nil:
		walkIDKeys(v, 0, func(obj map[string]any, k, s string) {
			if s != oldID {
				return
			}
			if _, isNum := obj[k].(float64); isNum {
				if n, err := strconv.ParseInt(newID, 10, 64); err == nil {
					obj[k] = n
					return
				}
			}
			obj[k] = newID
		})
		if b, err := json.Marshal(v); err == nil {
			out.Body = b
		}
	case strings.HasPrefix(ct, "application/x-www-form-urlencoded"):
		if vals, err := url.ParseQuery(string(w.Body)); err == nil {
			for k, vs := range vals {
				for i, x := range vs {
					if idKey(k) && x == oldID {
						vals[k][i] = newID
					}
				}
			}
			out.Body = []byte(vals.Encode())
		}
	}
	return out
}

// csrfWords mark an anti-forgery token in a header or field name, in any
// case and without "-" and "_": Gitea's _csrf and X-Csrf-Token (measured
// 2026-11-21), Rails' authenticity_token, Django's csrfmiddlewaretoken,
// ASP.NET's __RequestVerificationToken.
var csrfWords = []string{"csrf", "xsrf", "authenticitytoken", "requestverificationtoken"}

func csrfName(name string) bool {
	n := strings.NewReplacer("-", "", "_", "").Replace(strings.ToLower(name))
	for _, w := range csrfWords {
		if strings.Contains(n, w) {
			return true
		}
	}
	return false
}

// carriesCSRF reports whether a recorded write holds a CSRF token: a
// header so named, or a form, multipart or JSON field so named.
func carriesCSRF(h http.Header, body []byte) bool {
	for k := range h {
		if csrfName(k) {
			return true
		}
	}
	if len(body) == 0 {
		return false
	}
	lower := bytes.ToLower(body)
	for _, w := range []string{"csrf", "xsrf", "authenticity_token", "requestverificationtoken"} {
		if bytes.Contains(lower, []byte(w)) {
			return true
		}
	}
	return false
}

// lockoutWords are path words of requests never replayed: they log in or
// out, register, or change passwords, second factors, tokens or sessions,
// so a replay could lock account A or B out (ADR 0049 item 4).
var lockoutWords = map[string]bool{
	"logout": true, "logoff": true, "signout": true, "login": true, "logon": true, "signin": true,
	"register": true, "registration": true, "signup": true,
	"password": true, "passwords": true, "passwd": true, "pwd": true,
	"2fa": true, "mfa": true, "totp": true, "otp": true, "twofactor": true, "webauthn": true, "passkey": true, "passkeys": true,
	"token": true, "tokens": true, "apikey": true, "apikeys": true, "session": true, "sessions": true,
}

// accountNouns: a DELETE whose last path word (IDs left out) is one of
// these deletes an account.
var accountNouns = map[string]bool{"user": true, "users": true, "account": true, "accounts": true, "me": true, "self": true, "profile": true}

// lockoutReason says why a write is never replayed, or "".
func lockoutReason(method, p string) string {
	pathPart, query, _ := strings.Cut(p, "?")
	var last string
	for _, seg := range strings.Split(pathPart, "/") {
		s, err := url.PathUnescape(seg)
		if err != nil || s == "" {
			continue
		}
		if w := lockoutWord(s); w != "" {
			return "its path names " + w
		}
		if !reID.MatchString(s) {
			last = strings.ToLower(s)
		}
	}
	if vals, err := url.ParseQuery(query); err == nil {
		for k, vs := range vals {
			for _, s := range append([]string{k}, vs...) {
				if w := lockoutWord(s); w != "" {
					return "its query names " + w
				}
			}
		}
	}
	if method == http.MethodDelete && accountNouns[last] {
		return "it deletes an account"
	}
	return ""
}

// lockoutWord returns the lockout word s names, or "": s whole without
// "-", "_" and ".", or any of its words split at those and at camelCase.
func lockoutWord(s string) string {
	joined := strings.NewReplacer("-", "", "_", "", ".", "").Replace(strings.ToLower(s))
	if lockoutWords[joined] {
		return joined
	}
	ws := splitWords(s)
	for i, w := range ws {
		if lockoutWords[w] {
			return w
		}
		if i+1 < len(ws) && lockoutWords[w+ws[i+1]] {
			return w + ws[i+1]
		}
	}
	return ""
}

// splitWords splits s into lower-case words at characters other than
// letters and digits, and where a lower-case letter meets an upper-case one.
func splitWords(s string) []string {
	var out []string
	var cur []rune
	var prev rune
	flush := func() {
		if len(cur) > 0 {
			out = append(out, strings.ToLower(string(cur)))
			cur = cur[:0]
		}
	}
	for _, r := range s {
		switch {
		case !unicode.IsLetter(r) && !unicode.IsDigit(r):
			flush()
		case unicode.IsUpper(r) && unicode.IsLower(prev):
			flush()
			cur = append(cur, r)
		default:
			cur = append(cur, r)
		}
		prev = r
	}
	flush()
	return out
}

// Who replayed a write.
const (
	AsB       = "B"
	AsNoLogin = "no login"
)

// WriteReplay is one write replayed as B or with no login.
type WriteReplay struct {
	Write
	Who  string
	Sent string // the path as sent, with the re-created object's ID
	// Recreated: A's create was sent again and the write used its new
	// object. RecreateFailed: it was sent and gave no ID, so the write
	// used A's recorded object.
	Recreated, RecreateFailed bool
	// Read: A read the same URL before and after (PUT, PATCH, DELETE).
	Read                  bool
	Before, Answer, After Answer
	// NotSent says why this identity was not sent, or "".
	NotSent string
	// CleanedUp: A deleted the copy after the replay.
	CleanedUp bool
	// CSRFSwapped: the replay carried a CSRF token fetched as its sender.
	CSRFSwapped bool
	Location    string // the write answer's Location header
}

// WriteResult is what WriteCheck did.
type WriteResult struct {
	Replays   []WriteReplay
	Requests  int // requests the target answered
	Recreated int // objects re-created for A
	CleanedUp int // of those, deleted again by A after the replay
	// PlainCreates are writes not sent as B: they create an object that
	// names no ID or login, which B may make as its own.
	PlainCreates []string
	BTested      bool
}

// plainCreate: a POST whose path holds no ID and not A's login name, and
// whose body has no ID-named key with an ID value. B sending it makes B's
// own object, which apps allow by design.
func plainCreate(w Write, loginName string) bool {
	if w.Method != http.MethodPost || hasID(w.Path) {
		return false
	}
	if loginName != "" {
		for _, seg := range strings.Split(pathOf(w.Path), "/") {
			if s, err := url.PathUnescape(seg); err == nil && strings.EqualFold(s, loginName) {
				return false
			}
		}
	}
	found := false
	var v any
	if json.Unmarshal(w.Body, &v) == nil {
		walkIDKeys(v, 0, func(map[string]any, string, string) { found = true })
	} else if vals, err := url.ParseQuery(string(w.Body)); err == nil && strings.HasPrefix(strings.ToLower(w.Header.Get("Content-Type")), "application/x-www-form-urlencoded") {
		for k, vs := range vals {
			for _, x := range vs {
				if _, ok := idValue(x); ok && idKey(k) {
					found = true
				}
			}
		}
	}
	return !found
}

// WriteCheck replays the writes as account B (b, nil for none) and with no
// login, one request at a time, at most rate per second. It changes data,
// so it runs only on local targets with a configuration that allows
// writes (ADR 0049).
func WriteCheck(ctx context.Context, cfg egress.Config, ws []Write, b http.Header, loginName string, rate float64, mode target.Mode) (WriteResult, error) {
	if mode != target.Local {
		return WriteResult{}, errors.New("the write replay runs only on local targets")
	}
	if cfg.ReadOnly {
		return WriteResult{}, errors.New("the write replay sends POST, PUT, PATCH and DELETE: a read-only configuration cannot")
	}
	var interval time.Duration
	if rate > 0 {
		interval = time.Duration(float64(time.Second) / rate)
	}
	res := WriteResult{BTested: b != nil}
	var last time.Time
	var lastHeader http.Header
	do := func(method, p string, h http.Header, body []byte) (Answer, error) {
		lastHeader = nil
		if !last.IsZero() {
			if err := sleep(ctx, interval-now().Sub(last)); err != nil {
				return Answer{}, err
			}
		}
		last = now()
		a, err := send(ctx, cfg, method, p, h, body, MaxAnswer)
		if ctx.Err() != nil {
			return Answer{}, ctx.Err()
		}
		if a == nil {
			return Answer{Err: errString(err)}, nil
		}
		res.Requests++
		lastHeader = a.Header
		if err != nil {
			return Answer{Status: a.Status, Err: errString(err)}, nil
		}
		return Answer{Status: a.Status, Body: a.Body}, nil
	}
	session := sessionNames(b)
	for _, w := range ws {
		bOnRecorded := false // B's replay was accepted on A's recorded object
		plain := plainCreate(w, loginName)
		for _, who := range []string{AsB, AsNoLogin} {
			if who == AsB && (b == nil || plain) {
				if b != nil {
					res.PlainCreates = appendOnce(res.PlainCreates, w.Method+" "+pathOf(w.Path))
				}
				continue
			}
			rp := WriteReplay{Write: w, Who: who, Sent: w.Path}
			sw := w
			var copyID string
			if w.Create != nil {
				ca, err := do(http.MethodPost, w.Create.Path, w.Create.Header, w.Create.Body)
				if err != nil {
					return res, err
				}
				if id, ok := newID(ca, w.Create.Field); ok {
					sw = w.withID(w.Create.OldID, id)
					rp.Recreated, rp.Sent, copyID = true, sw.Path, id
					res.Recreated++
				} else {
					rp.RecreateFailed = true
				}
			}
			if !rp.Recreated && who == AsNoLogin && bOnRecorded {
				rp.NotSent = "account B's replay was accepted on account A's recorded object, which it may have changed or deleted"
				res.Replays = append(res.Replays, rp)
				continue
			}
			readHeader := sw.Header.Clone()
			readHeader.Del("Content-Type")
			rp.Read = w.Method != http.MethodPost
			var err error
			if rp.Read {
				if rp.Before, err = do(http.MethodGet, sw.Path, readHeader, nil); err != nil {
					return res, err
				}
			}
			h := without(sw.Header, session)
			if who == AsB {
				for k, vs := range b {
					h[k] = append([]string(nil), vs...)
				}
			}
			body := sw.Body
			if w.CSRF {
				if old := csrfValue(sw); old != "" {
					page := "/"
					if ref, err := url.Parse(sw.Header.Get("Referer")); err == nil && ref.Path != "" && target.SendablePath(ref.EscapedPath()) {
						page = ref.EscapedPath()
					}
					ph := h.Clone()
					ph.Del("Content-Type")
					pa, err := do(http.MethodGet, page, ph, nil)
					if err != nil {
						return res, err
					}
					tok, cookies := pageCSRF(pa, lastHeader)
					if tok != "" {
						body = bytes.ReplaceAll(body, []byte(old), []byte(tok))
						for k, vs := range h {
							for i, v := range vs {
								h[k][i] = strings.ReplaceAll(v, old, tok)
							}
						}
						rp.CSRFSwapped = true
					}
					if len(cookies) > 0 {
						h.Set("Cookie", mergeCookies(h.Get("Cookie"), cookies))
					}
				}
			}
			if rp.Answer, err = do(sw.Method, sw.Path, h, body); err != nil {
				return res, err
			}
			rp.Location = lastHeader.Get("Location")
			if rp.Read && ok2xx(rp.Before) {
				if rp.After, err = do(http.MethodGet, sw.Path, readHeader, nil); err != nil {
					return res, err
				}
			}
			// A deletes the copy it made, so A's create works again for the
			// next replay on apps that refuse a second identical object
			// (ADR 0049 item 2).
			if rp.Recreated && strings.HasSuffix(pathOf(sw.Path), "/"+url.PathEscape(copyID)) &&
				!(w.Method == http.MethodDelete && rp.Accepted()) {
				ca, err := do(http.MethodDelete, pathOf(sw.Path), readHeader, nil)
				if err != nil {
					return res, err
				}
				rp.CleanedUp = ok2xx(ca)
				if rp.CleanedUp {
					res.CleanedUp++
				}
			}
			if who == AsB && !rp.Recreated && rp.Accepted() && (w.Method != http.MethodPost || hasID(w.Path)) {
				bOnRecorded = true
			}
			res.Replays = append(res.Replays, rp)
		}
	}
	return res, nil
}

// newID reads the re-created object's ID from A's create answer.
func newID(a Answer, field []string) (string, bool) {
	if !ok2xx(a) || len(field) == 0 {
		return "", false
	}
	var v any
	if json.Unmarshal(bytes.TrimSpace(a.Body), &v) != nil {
		return "", false
	}
	for _, k := range field {
		m, ok := v.(map[string]any)
		if !ok {
			return "", false
		}
		v = m[k]
	}
	return idValue(v)
}

// Accepted reports whether the app took the replayed write: a 2xx answer,
// or a redirect when A's own recorded write was answered with a redirect
// too and this one does not lead to a login page. Server-rendered forms
// answer a successful write with 303 (4 of 13 Gitea web writes, measured
// 2026-11-21, ADR 0049).
func (r WriteReplay) Accepted() bool {
	if ok2xx(r.Answer) {
		return r.GraphQL == "" || !graphQLRefused(r.Answer.Body)
	}
	return r.Answer.Err == "" && r.Answer.Status >= 300 && r.Answer.Status < 400 &&
		r.RecordedStatus >= 300 && r.RecordedStatus < 400 && !toLogin(r.Location) && !echoed(r.Location, r.Sent, r.Body)
}

// echoed reports whether a redirect only goes where the request asked: its
// target is a value of the request's query or form body. Gitea's
// /-/fetch-redirect answers anyone with 303 to its "redirect" field and
// changes nothing (4 false medium findings before this rule, measured
// 2026-11-21, ADR 0049).
func echoed(loc, sent string, body []byte) bool {
	if loc == "" {
		return false
	}
	_, q, _ := strings.Cut(sent, "?")
	for _, raw := range []string{q, string(body)} {
		vals, err := url.ParseQuery(raw)
		if err != nil {
			continue
		}
		for _, vs := range vals {
			for _, v := range vs {
				if v != "" && (v == loc || strings.HasSuffix(loc, v) && strings.HasPrefix(v, "/")) {
					return true
				}
			}
		}
	}
	return false
}

// loginWords in a redirect's path mean "log in first".
var loginWords = map[string]bool{"login": true, "logon": true, "signin": true, "auth": true, "sso": true, "oauth": true, "oauth2": true, "authorize": true}

// toLogin reports whether a redirect leads to a login page, or nowhere.
func toLogin(loc string) bool {
	u, err := url.Parse(loc)
	if loc == "" || err != nil {
		return true
	}
	for _, seg := range strings.Split(u.Path, "/") {
		joined := strings.NewReplacer("-", "", "_", "").Replace(strings.ToLower(seg))
		if loginWords[joined] {
			return true
		}
		for _, w := range splitWords(seg) {
			if loginWords[w] {
				return true
			}
		}
	}
	return false
}

// Severity is the replay's tier (ADR 0049 item 1), and false when it is
// not reported: high when a PUT, PATCH or DELETE was accepted and A's read
// of the same URL changed, medium for any other accepted (2xx) replay.
func (r WriteReplay) Severity() (findings.Severity, bool) {
	if r.NotSent != "" || !r.Accepted() {
		return 0, false
	}
	if r.Read && ok2xx(r.Before) && r.After.Err == "" && r.After.Status != 0 &&
		(r.After.Status != r.Before.Status || !bytes.Equal(r.After.Body, r.Before.Body)) {
		return findings.High, true
	}
	return findings.Medium, true
}

// WriteFindings turns the accepted replays into findings at the recorded
// write's URL, without the query.
func WriteFindings(origin string, res WriteResult) []findings.Finding {
	var out []findings.Finding
	for _, r := range res.Replays {
		sev, ok := r.Severity()
		if !ok {
			continue
		}
		pathOnly, _, _ := strings.Cut(r.Path, "?")
		f := findings.Finding{Severity: sev, Location: findings.Location{URI: origin + pathOnly}, Family: Family}
		proof := fmt.Sprintf("Account A's read of the same URL changed (status %d, %d bytes before; status %d, %d bytes after).", r.Before.Status, len(r.Before.Body), r.After.Status, len(r.After.Body))
		if sev != findings.High {
			proof = "SiegeKit could not see account A's data change (only a PUT, PATCH or DELETE whose URL A can read is checked), and some apps allow this by design, such as a comment on a public item: check it by hand."
		}
		obj := "account A's recorded object"
		if r.Recreated {
			obj = "a copy of account A's object that SiegeKit made first with A's recorded create"
		}
		if r.Who == AsB {
			cwe := "CWE-862"
			if hasID(r.Path) {
				cwe = "CWE-639"
			}
			f.RuleID, f.Title, f.CWEs = "cross-account-write", "Another account can change this data", []string{cwe}
			f.Message = fmt.Sprintf("%s %s, recorded as account A and sent as account B on %s, was accepted (status %d). Account B can likely change or delete account A's data: broken access control (OWASP API1 and API5). %s", r.Method, gqlPath(pathOnly, r.GraphQL), obj, r.Answer.Status, proof)
		} else {
			f.RuleID, f.Title, f.CWEs = "no-login-write", "Data can be changed with no login", []string{"CWE-306"}
			f.Message = fmt.Sprintf("%s %s, recorded as account A and sent with no login on %s, was accepted (status %d). Anyone may be able to change this data: missing authentication (OWASP API2). %s", r.Method, gqlPath(pathOnly, r.GraphQL), obj, r.Answer.Status, proof)
		}
		out = append(out, f)
	}
	for i := range out {
		out[i].Sources = []findings.Source{{Plugin: WriteID, RuleID: out[i].RuleID}}
		out[i].ComputeFingerprint()
	}
	return out
}

// WriteSummary says in one line what was replayed and what may have
// changed, so the person knows what to reset (ADR 0049 item 6).
func (r WriteResult) WriteSummary(w *Writes) string {
	var high, medium, sent int
	var accepted, recreatedAt, notSent, recreateFailed []string
	for _, rp := range r.Replays {
		if rp.NotSent != "" {
			notSent = appendOnce(notSent, rp.Method+" "+pathOf(rp.Path))
			continue
		}
		sent++
		if sev, ok := rp.Severity(); ok && sev == findings.High {
			high++
		} else if ok {
			medium++
		}
		if rp.Accepted() {
			accepted = appendOnce(accepted, fmt.Sprintf("%s as %s", Write{Method: rp.Method, Path: pathOf(rp.Sent), GraphQL: rp.GraphQL}.Label(), whoName(rp.Who)))
		}
		if rp.Recreated && rp.Create != nil {
			recreatedAt = appendOnce(recreatedAt, "POST "+pathOf(rp.Create.Path))
		}
		if rp.RecreateFailed {
			recreateFailed = appendOnce(recreateFailed, rp.Method+" "+pathOf(rp.Path))
		}
	}
	who := "as account B and with no login"
	if !r.BTested {
		who = "with no login (" + SessionEnv + " not set: account B is not tested)"
	}
	s := fmt.Sprintf("replayed %d write(s) from the HAR file %s (%d replay(s)): %d high, %d medium", len(uniqueWrites(r.Replays)), who, sent, high, medium)
	if len(accepted) > 0 {
		s += fmt.Sprintf("; %d accepted and may have changed data: %s", len(accepted), strings.Join(accepted, ", "))
	} else {
		s += "; none was accepted"
	}
	if r.Recreated > 0 {
		s += fmt.Sprintf("; %d object(s) made for account A", r.Recreated)
		if len(recreatedAt) > 0 {
			s += " with " + strings.Join(recreatedAt, ", ")
		}
		if r.CleanedUp > 0 {
			s += fmt.Sprintf(", %d of them deleted again by A", r.CleanedUp)
		}
	}
	var notes []string
	if len(recreateFailed) > 0 {
		notes = append(notes, "A's create gave no new ID for "+strings.Join(recreateFailed, ", ")+", so A's recorded object was used")
	}
	if len(r.PlainCreates) > 0 {
		notes = append(notes, "not sent as account B because they make a new object that names no ID or login: "+strings.Join(r.PlainCreates, ", "))
	}
	if len(notSent) > 0 {
		notes = append(notes, "not tested with no login, because B's replay was accepted on A's recorded object: "+strings.Join(notSent, ", "))
	}
	if w != nil {
		if w.Lockout > 0 {
			notes = append(notes, fmt.Sprintf("%d not replayed because they could log in, log out or lock an account out: %s", w.Lockout, strings.Join(w.LockoutPaths, ", ")))
		}
		for _, x := range []struct {
			n    int
			what string
		}{{w.NoBody, "with form fields but no body text in the HAR file"}, {w.GraphQLReads, "GraphQL queries or subscriptions (reads)"}, {w.Duplicate, "duplicates"}, {w.OverLimit, fmt.Sprintf("over the %d-write limit", MaxWrites)}} {
			if x.n > 0 {
				notes = append(notes, fmt.Sprintf("%d %s not replayed", x.n, x.what))
			}
		}
	}
	swapped, stale := csrfWrites(r.Replays)
	if swapped > 0 {
		notes = append(notes, fmt.Sprintf("%d write(s) were sent with the sender's own CSRF token, taken from a page", swapped))
	}
	if stale > 0 {
		notes = append(notes, fmt.Sprintf("%d write(s) were sent with account A's CSRF token because no page gave the sender one, so a refusal of them says nothing about access control", stale))
	}
	return s + "; " + strings.Join(notes, "; ")
}

// csrfWrites counts the CSRF-carrying writes sent with the sender's own
// token (swapped) and those sent with A's because no token was found.
func csrfWrites(rs []WriteReplay) (swapped, stale int) {
	sw, st := map[string]bool{}, map[string]bool{}
	for _, r := range rs {
		if !r.CSRF || r.NotSent != "" {
			continue
		}
		k := r.Method + " " + r.Path + " " + string(r.Body)
		if r.CSRFSwapped {
			sw[k] = true
		} else {
			st[k] = true
		}
	}
	return len(sw), len(st)
}

func whoName(who string) string {
	if who == AsB {
		return "account B"
	}
	return "no login"
}

func pathOf(p string) string {
	s, _, _ := strings.Cut(p, "?")
	return s
}

func appendOnce(list []string, s string) []string {
	if containsString(list, s) {
		return list
	}
	return append(list, s)
}

func uniqueWrites(rs []WriteReplay) map[string]bool {
	m := map[string]bool{}
	for _, r := range rs {
		m[r.Method+" "+r.Path+" "+string(r.Body)] = true
	}
	return m
}

// csrfValue returns A's recorded CSRF token: a CSRF-named header's value,
// or a CSRF-named form, multipart or JSON field's value.
func csrfValue(w Write) string {
	for k, vs := range w.Header {
		if csrfName(k) && len(vs) > 0 && vs[0] != "" {
			return vs[0]
		}
	}
	if m := reMultipartCSRF.FindSubmatch(w.Body); m != nil {
		return string(m[1])
	}
	if vals, err := url.ParseQuery(string(w.Body)); err == nil {
		for k, vs := range vals {
			if csrfName(k) && len(vs) > 0 && vs[0] != "" {
				return vs[0]
			}
		}
	}
	var v map[string]any
	if json.Unmarshal(w.Body, &v) == nil {
		for k, x := range v {
			if s, ok := x.(string); ok && csrfName(k) && s != "" {
				return s
			}
		}
	}
	return ""
}

var (
	reMultipartCSRF = regexp.MustCompile(`(?i)name="[^"]*csrf[^"]*"\r?\n\r?\n([^\r\n]+)`)
	reMetaCSRF      = regexp.MustCompile(`(?i)<meta[^>]+name="[^"]*csrf[^"]*"[^>]+content="([^"]+)"`)
	reScriptCSRF    = regexp.MustCompile(`(?i)csrf_?token["']?\s*[:=]\s*["']([^"']{8,})["']`)
	reInputCSRF     = regexp.MustCompile(`(?i)<input[^>]+name="[^"]*(?:csrf|authenticity_token|requestverificationtoken)[^"]*"[^>]+value="([^"]+)"`)
)

// pageCSRF returns the CSRF token a page gives its viewer (a meta tag or a
// hidden field, else a CSRF-named cookie) and the cookies it sets.
func pageCSRF(a Answer, h http.Header) (string, []*http.Cookie) {
	var cookies []*http.Cookie
	if h != nil {
		cookies = (&http.Response{Header: h}).Cookies()
	}
	if m := reMetaCSRF.FindSubmatch(a.Body); m != nil {
		return string(m[1]), cookies
	}
	if m := reInputCSRF.FindSubmatch(a.Body); m != nil {
		return string(m[1]), cookies
	}
	if m := reScriptCSRF.FindSubmatch(a.Body); m != nil {
		return string(m[1]), cookies
	}
	for _, c := range cookies {
		if csrfName(c.Name) && c.Value != "" {
			return c.Value, cookies
		}
	}
	return "", cookies
}

// mergeCookies sets the new cookies in a Cookie header, replacing those of
// the same name.
func mergeCookies(header string, set []*http.Cookie) string {
	var out []string
	names := map[string]bool{}
	for _, c := range set {
		names[c.Name] = true
	}
	for _, part := range strings.Split(header, ";") {
		name, _, _ := strings.Cut(strings.TrimSpace(part), "=")
		if name != "" && !names[name] {
			out = append(out, strings.TrimSpace(part))
		}
	}
	for _, c := range set {
		if c.MaxAge >= 0 && c.Value != "" {
			out = append(out, c.Name+"="+c.Value)
		}
	}
	return strings.Join(out, "; ")
}

// graphQLOp reads a GraphQL-over-HTTP request body: a JSON object, or a
// batch of them, with a "query" string. kind is "mutation" when the
// operation it runs (operationName, else the first one) is a mutation,
// else "query" or "subscription"; name is the mutation's name. A body
// without query text, such as a persisted query sent by its hash, is not
// recognised (ok false) and stays a write.
func graphQLOp(body []byte) (kind, name string, ok bool) {
	var one map[string]any
	if json.Unmarshal(body, &one) == nil {
		return graphQLDoc(one)
	}
	var batch []map[string]any
	if json.Unmarshal(body, &batch) != nil || len(batch) == 0 {
		return "", "", false
	}
	kind = "query"
	for _, b := range batch {
		k, n, isGQL := graphQLDoc(b)
		if !isGQL {
			return "", "", false
		}
		if k == "mutation" && kind != "mutation" {
			kind, name = k, n
		}
	}
	return kind, name, true
}

var (
	reGraphQLComment = regexp.MustCompile(`#[^\n]*`)
	reGraphQLOp      = regexp.MustCompile(`(?:^|[\s}])(query|mutation|subscription)\b\s*([_A-Za-z][_0-9A-Za-z]*)?`)
)

func graphQLDoc(m map[string]any) (kind, name string, ok bool) {
	q, isString := m["query"].(string)
	if !isString || strings.TrimSpace(q) == "" {
		return "", "", false
	}
	q = reGraphQLComment.ReplaceAllString(q, "")
	want, _ := m["operationName"].(string)
	ops := reGraphQLOp.FindAllStringSubmatch(q, -1)
	if len(ops) == 0 {
		// The shorthand "{ field }" is a query.
		if strings.HasPrefix(strings.TrimSpace(q), "{") {
			return "query", "", true
		}
		return "", "", false
	}
	op := ops[0]
	for _, o := range ops {
		if want != "" && o[2] == want {
			op = o
			break
		}
	}
	if op[1] != "mutation" {
		return op[1], "", true
	}
	if op[2] == "" {
		return "mutation", "mutation", true
	}
	return "mutation", op[2], true
}

// graphQLRefused reports whether a 2xx GraphQL answer refused the
// operation: an "errors" list and no data (absent, null, or only null
// fields). GraphQL over HTTP answers such errors with 200.
func graphQLRefused(body []byte) bool {
	var batch []json.RawMessage
	if json.Unmarshal(body, &batch) == nil && len(batch) > 0 {
		for _, b := range batch {
			if !graphQLRefused(b) {
				return false
			}
		}
		return true
	}
	var a struct {
		Data   map[string]any    `json:"data"`
		Errors []json.RawMessage `json:"errors"`
	}
	if json.Unmarshal(body, &a) != nil || len(a.Errors) == 0 {
		return false
	}
	for _, v := range a.Data {
		if v != nil {
			return false
		}
	}
	return true
}

func gqlPath(path, op string) string {
	if op == "" {
		return path
	}
	return path + " (GraphQL " + op + ")"
}

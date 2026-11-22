package authz

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"path"
	"strings"

	"github.com/Gobbuwu/SiegeKit/internal/target"
)

// MaxTries caps the writes SiegeKit tries on account A's objects beyond
// the recording (ADR 0049 item 2c).
const MaxTries = 50

// maxSteps is how many of A's earlier writes are sent again before a write
// on an object A prepared (ADR 0049 item 2d).
const maxSteps = 3

// recordedRead is a recorded 2xx GET to the target's origin.
type recordedRead struct {
	index  int
	path   string // without the query
	header http.Header
	body   []byte // the answer, when it is a JSON object
}

// objectRead returns the recorded GET as a read of an object, leaving out
// other origins, static files and paths SiegeKit cannot send.
func objectRead(index int, raw string, hs []harHeader, status int, text, encoding string, t *target.URL) (recordedRead, bool) {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || status < 200 || status >= 300 {
		return recordedRead{}, false
	}
	o, err := target.Parse(u.Scheme + "://" + u.Host + "/")
	if err != nil || o.Origin() != t.Origin() || staticExt[strings.ToLower(path.Ext(u.Path))] {
		return recordedRead{}, false
	}
	p := u.EscapedPath()
	if p == "" || !target.SendablePath(p) {
		return recordedRead{}, false
	}
	rd := recordedRead{index: index, path: p, header: replayHeaders(hs)}
	b := []byte(text)
	if encoding == "base64" {
		if b, err = base64.StdEncoding.DecodeString(text); err != nil {
			b = nil
		}
	}
	var m map[string]any
	if json.Unmarshal(b, &m) == nil {
		rd.body = b
	}
	return rd, true
}

// lastSegment is the path's last non-empty segment, unescaped.
func lastSegment(p string) string {
	segs := strings.Split(strings.Trim(pathOf(p), "/"), "/")
	s, err := url.PathUnescape(segs[len(segs)-1])
	if err != nil {
		return ""
	}
	return s
}

// shapeOf is the path with its ID segments replaced, so that PUT on
// /api/Addresss/7 and on /api/Addresss/8 are one shape.
func shapeOf(p string) string {
	segs := strings.Split(strings.TrimSuffix(pathOf(p), "/"), "/")
	for i, s := range segs {
		if reID.MatchString(s) {
			segs[i] = "{id}"
		}
	}
	return strings.ToLower(strings.Join(segs, "/"))
}

// objectBody is the body of a PUT or PATCH on an object: A's own read of
// it, inside its "data" field when the app wraps objects that way (Juice
// Shop), or nil when A's read was not a JSON object.
func objectBody(b []byte) []byte {
	var m map[string]any
	if json.Unmarshal(b, &m) != nil {
		return nil
	}
	if d, ok := m["data"].(map[string]any); ok {
		if out, err := json.Marshal(d); err == nil {
			return out
		}
	}
	return b
}

// triesFor returns the PUT, PATCH and DELETE requests the recording did not
// make on objects account A read (a recorded 2xx GET whose last segment is
// an ID) or made (a recorded create's collection and the ID in its
// answer), so that a missing check on a method the person never used is
// still tested. A method is left out when the recording made it on the
// same shape of path, and DELETE tries come last. Measured on Juice Shop
// (2026-11-21): B deleting A's feedback and a product changed with no
// login, neither in the recording; on Gitea's web UI every try answered
// 405 (ADR 0049 item 2c).
func triesFor(ws []Write, reads []recordedRead, creates []recordedCreate) ([]Write, int) {
	done := map[string]bool{}
	for _, w := range ws {
		done[w.Method+" "+shapeOf(w.Path)] = true
	}
	type object struct {
		path   string
		header http.Header
		body   []byte
		create *Create
	}
	var objs []object
	seen := map[string]bool{}
	add := func(o object) {
		if seen[o.path] || !reID.MatchString(lastSegment(o.path)) {
			return
		}
		seen[o.path] = true
		objs = append(objs, o)
	}
	for _, c := range creates {
		if _, _, _, gql := graphQLOp(c.c.Body); gql || len(c.ids) == 0 || len(c.ids[0].field) == 0 {
			continue
		}
		cc := c.c
		cc.Field, cc.OldID = c.ids[0].field, c.ids[0].value
		var body []byte
		if plainJSONObject(cc.Body) {
			body = cc.Body
		}
		add(object{path: strings.TrimSuffix(pathOf(cc.Path), "/") + "/" + url.PathEscape(cc.OldID), header: cc.Header, body: body, create: &cc})
	}
	for _, r := range reads {
		add(object{path: r.path, header: r.header, body: objectBody(r.body)})
	}
	var first, last []Write
	over := 0
	for _, o := range objs {
		for _, m := range []string{http.MethodPut, http.MethodPatch, http.MethodDelete} {
			key := m + " " + shapeOf(o.path)
			if done[key] || lockoutReason(m, o.path) != "" || (m != http.MethodDelete && o.body == nil) {
				continue
			}
			done[key] = true
			if len(first)+len(last) == MaxTries {
				over++
				continue
			}
			h := o.header.Clone()
			h.Del("Content-Type")
			w := Write{Method: m, Path: o.path, Header: h, Tried: true, Create: o.create}
			if m != http.MethodDelete {
				w.Body = o.body
				w.Header.Set("Content-Type", "application/json")
			}
			if m == http.MethodDelete {
				last = append(last, w)
			} else {
				first = append(first, w)
			}
		}
	}
	return append(first, last...), over
}

// plainJSONObject reports whether b is a JSON object (not GraphQL).
func plainJSONObject(b []byte) bool {
	var m map[string]any
	if json.Unmarshal(b, &m) != nil {
		return false
	}
	_, gql := m["query"].(string)
	return !gql
}

// stepsFor finds A's earlier recorded writes that named w's object (an ID
// in w's path that SiegeKit does not copy) in their body, at an ID-named key (POST /api/BasketItems with "BasketId":
// "6" before POST /rest/basket/6/checkout), the last maxSteps of them. For
// a POST it also finds the object's recorded read: the longest recorded
// 2xx GET before w whose path is a leading part of w's and ends with that
// ID. Measured on Juice Shop (2026-11-21): after the recording's checkout
// A's basket was empty, so B's checkout of it changed nothing to see;
// with the basket items sent again first, A's basket went from one item
// to none (ADR 0049 item 2d).
func stepsFor(w Write, index int, earlier []pending, reads []recordedRead) ([]Step, string, http.Header) {
	ids := map[string]bool{}
	for _, seg := range strings.Split(pathOf(w.Path), "/") {
		if s, err := url.PathUnescape(seg); err == nil && reID.MatchString(s) && (w.Create == nil || s != w.Create.OldID) {
			ids[s] = true
		}
	}
	// Only a POST: a PUT, PATCH or DELETE already reads its own URL, and
	// steps before it re-sent unrelated writes in measurement (a basket
	// item naming product 1 before a review of product 1).
	if len(ids) == 0 || w.Method != http.MethodPost {
		return nil, "", nil
	}
	var steps []Step
	named := map[string]bool{}
	for _, e := range earlier {
		if e.index >= index || e.w.Method == http.MethodDelete || e.w.GraphQL != "" {
			continue
		}
		var hit string
		var v any
		if json.Unmarshal(e.w.Body, &v) == nil {
			walkIDKeys(v, 0, func(_ map[string]any, _ string, s string) {
				if ids[s] {
					hit = s
				}
			})
		}
		if hit == "" || writeInPath(e.w.Path, hit) {
			continue
		}
		named[hit] = true
		steps = append(steps, Step{Method: e.w.Method, Path: e.w.Path, Header: e.w.Header.Clone(), Body: e.w.Body})
	}
	if len(steps) > maxSteps {
		steps = steps[len(steps)-maxSteps:]
	}
	if len(steps) == 0 {
		return nil, "", nil
	}
	best, bestLen := "", 0
	var bestHeader http.Header
	wp := strings.TrimSuffix(pathOf(w.Path), "/")
	for _, r := range reads {
		rp := strings.TrimSuffix(r.path, "/")
		if r.index >= index || !named[lastSegment(rp)] || !strings.HasPrefix(wp, rp+"/") || len(rp) <= bestLen {
			continue
		}
		best, bestLen, bestHeader = rp, len(rp), r.header
	}
	return steps, best, bestHeader
}

// writeInPath reports whether id is a segment of p's path: such a write
// acts on the object itself rather than adding to it.
func writeInPath(p, id string) bool {
	for _, seg := range strings.Split(pathOf(p), "/") {
		if s, err := url.PathUnescape(seg); err == nil && s == id {
			return true
		}
	}
	return false
}

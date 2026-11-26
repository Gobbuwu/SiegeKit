package authz

// Method calls sent as POST (ADR 0050). Some apps send every action, reads
// included, as a POST that names a method: Meteor apps such as Rocket.Chat
// put a DDP method message inside a JSON string (POST
// /api/v1/method.call/<method> with {"message":"{\"msg\":\"method\",...}"},
// measured on Rocket.Chat 6.13.1, 2026-11-22), and JSON-RPC puts the method
// and its params in the body. The write replay reads the method's name to
// tell reads from writes, looks for object IDs in its params only (the
// envelope's own "id" numbers the call, not an object), and reads refusals
// that the app reports inside a 2xx answer.

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/url"
	"regexp"
	"strings"

	"github.com/Gobbuwu/SiegeKit/internal/webform"
)

// RPC kinds.
const (
	rpcDDP     = "DDP"
	rpcJSONRPC = "JSON-RPC"
)

// readVerbs: a method or last path word that starts with one of these
// reads. From the measured Rocket.Chat recording (get, load, is, fetch:
// public-settings/get, loadHistory, license:isEnterprise,
// /__meteor__/dynamic-import/fetch) and the usual read verbs of RPC APIs.
// "read" is left out: Rocket.Chat's readMessages marks a room read, a
// write.
var readVerbs = setOf("get list fetch find search load query count lookup describe is has can")

// writeVerbs veto a read verb anywhere in the name ("getOrCreate",
// "fetchAndUpdate"): ADR 0048's action words plus verbs that are not
// actions of a GET page but are writes in a method name.
var writeVerbs = func() map[string]bool {
	m := setOf("send set mark write post put")
	for w := range actionWords {
		m[w] = true
	}
	return m
}()

// readName reports whether a method name, or a path's last word, names a
// read: the name is cut into parts at every character other than a letter
// or digit (".", ":", "/", "_", "-"), a part's first word (split at
// camelCase) is a read verb, and no part starts with a write verb and no
// write verb follows "or" or "and".
// "public-settings/get", "loadHistory", "license:isEnterprise" and
// "eth_getBalance" read; "sendMessage", "updateMessage", "readMessages" and
// "getOrCreateRoom" do not.
func readName(name string) bool {
	read := false
	for _, part := range strings.FieldsFunc(name, func(r rune) bool {
		return !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9')
	}) {
		ws := webform.Words(part)
		if len(ws) > 0 && readVerbs[ws[0]] {
			read = true
		}
		for i, w := range ws {
			// A write verb vetoes when it acts: the first word of a part,
			// or after "or"/"and" ("getOrCreateRoom"). As a noun later in
			// the name it does not ("getImportProgress", "getRoomJoinCode":
			// 5 Rocket.Chat reads, measured 2026-11-22).
			if writeVerbs[w] && (i == 0 || ws[i-1] == "or" || ws[i-1] == "and") {
				return false
			}
		}
	}
	return read
}

// readPath reports whether a POST's path ends in a read verb: its last
// segment that is not an ID names a read (readName).
// /__meteor__/dynamic-import/fetch, Meteor's code-bundle fetch, was 13 of
// the 16 false medium findings on Rocket.Chat before this rule.
func readPath(p string) bool {
	segs := strings.Split(pathOf(p), "/")
	for i := len(segs) - 1; i >= 0; i-- {
		s := segs[i]
		if u, err := url.PathUnescape(s); err == nil {
			s = u
		}
		if s == "" || reID.MatchString(s) {
			continue
		}
		return readName(s)
	}
	return false
}

// rpcCall is the method call a POST body carries.
type rpcCall struct {
	kind    string
	methods []string // one per call; JSON-RPC may batch
}

// rpcOp reads a DDP method message inside a JSON string field "message"
// (Rocket.Chat's method.call and method.callAnon), or a JSON-RPC request:
// an object, or a batch of them, with a "method" string and either a
// "jsonrpc" member or both "params" and "id" (JSON-RPC 1.0). A body with
// only a "method" field is a plain JSON body (a payment method, say).
func rpcOp(body []byte) (rpcCall, bool) {
	if inner, _, ok := ddpMessage(body); ok {
		return rpcCall{kind: rpcDDP, methods: []string{inner["method"].(string)}}, true
	}
	var one map[string]any
	if json.Unmarshal(body, &one) == nil {
		if m, ok := jsonRPCMethod(one); ok {
			return rpcCall{kind: rpcJSONRPC, methods: []string{m}}, true
		}
		return rpcCall{}, false
	}
	var batch []map[string]any
	if json.Unmarshal(body, &batch) != nil || len(batch) == 0 {
		return rpcCall{}, false
	}
	c := rpcCall{kind: rpcJSONRPC}
	for _, b := range batch {
		m, ok := jsonRPCMethod(b)
		if !ok {
			return rpcCall{}, false
		}
		c.methods = append(c.methods, m)
	}
	return c, true
}

func jsonRPCMethod(m map[string]any) (string, bool) {
	name, ok := m["method"].(string)
	if !ok || name == "" {
		return "", false
	}
	_, hasVersion := m["jsonrpc"]
	_, hasParams := m["params"]
	_, hasID := m["id"]
	return name, hasVersion || hasParams && hasID
}

// ddpMessage decodes a DDP method message from the body's "message"
// string: the outer object and the inner message.
func ddpMessage(body []byte) (inner, outer map[string]any, ok bool) {
	if json.Unmarshal(body, &outer) != nil {
		return nil, nil, false
	}
	s, isString := outer["message"].(string)
	if !isString || json.Unmarshal([]byte(s), &inner) != nil {
		return nil, nil, false
	}
	if msg, _ := inner["msg"].(string); msg != "method" {
		return nil, nil, false
	}
	if name, _ := inner["method"].(string); name == "" {
		return nil, nil, false
	}
	return inner, outer, true
}

// reads reports whether every call reads, and the first one that writes.
func (c rpcCall) reads() (bool, string) {
	for _, m := range c.methods {
		if !readName(m) {
			return false, m
		}
	}
	return true, ""
}

// idScope returns the part of a JSON body where object IDs are looked for
// and changed, and a function that encodes the whole body again after the
// scope was changed in place: a method call's params (DDP or JSON-RPC),
// else the whole body. ok is false when the body is not JSON.
func idScope(body []byte) (scope any, encode func() ([]byte, error), ok bool) {
	if inner, outer, isDDP := ddpMessage(body); isDDP {
		return inner["params"], func() ([]byte, error) {
			b, err := json.Marshal(inner)
			if err != nil {
				return nil, err
			}
			outer["message"] = string(b)
			return json.Marshal(outer)
		}, true
	}
	var v any
	if len(body) == 0 || json.Unmarshal(body, &v) != nil {
		return nil, nil, false
	}
	enc := func() ([]byte, error) { return json.Marshal(v) }
	if _, isRPC := rpcOp(body); isRPC {
		switch x := v.(type) {
		case map[string]any:
			return x["params"], enc, true
		case []any:
			var ps []any
			for _, e := range x {
				if m, isObj := e.(map[string]any); isObj {
					ps = append(ps, m["params"])
				}
			}
			return ps, enc, true
		}
	}
	return v, enc, true
}

// rpcResult is the result inside a method call's answer: the DDP message's
// "result" inside the "message" string, or JSON-RPC's "result". v is the
// decoded answer; it is returned as it is when it is neither.
func rpcResult(v any) any {
	m, ok := v.(map[string]any)
	if !ok {
		return v
	}
	if s, isString := m["message"].(string); isString {
		var inner map[string]any
		if json.Unmarshal([]byte(s), &inner) == nil {
			if r, has := inner["result"]; has {
				return r
			}
		}
		return nil
	}
	if r, has := m["result"]; has {
		return r
	}
	return nil
}

// envelopeRefused reports whether a 2xx JSON answer to a write reports a
// refusal: a top-level "success" that is false (Rocket.Chat's REST style),
// for any write; for a DDP call, an "error" in the DDP message inside
// "message" (Rocket.Chat answers B's updateMessage on A's message with 200
// and "error":"error-action-not-allowed" there, measured 2026-11-22); for
// a JSON-RPC call, a non-null "error" member (JSON-RPC 2.0 specification),
// and for a batch, every answer in it refused.
func envelopeRefused(body []byte, kind string) bool {
	body = bytes.TrimSpace(body)
	if kind == rpcJSONRPC {
		var batch []json.RawMessage
		if json.Unmarshal(body, &batch) == nil && len(batch) > 0 {
			for _, b := range batch {
				if !envelopeRefused(b, kind) {
					return false
				}
			}
			return true
		}
	}
	var m map[string]any
	if json.Unmarshal(body, &m) != nil {
		return false
	}
	if s, isBool := m["success"].(bool); isBool && !s {
		return true
	}
	switch kind {
	case rpcDDP:
		s, _ := m["message"].(string)
		var inner map[string]any
		if json.Unmarshal([]byte(s), &inner) == nil {
			if e, has := inner["error"]; has && e != nil {
				return true
			}
		}
	case rpcJSONRPC:
		if e, has := m["error"]; has && e != nil {
			return true
		}
	}
	return false
}

// opLabel is the path a finding names: the path, plus the GraphQL mutation
// or the method when the path does not already end with it.
func opLabel(path, graphQL, method string) string {
	switch {
	case graphQL != "":
		return path + " (GraphQL " + graphQL + ")"
	case method != "" && !strings.HasSuffix(unescaped(pathOf(path)), "/"+method):
		return path + " (method " + method + ")"
	}
	return path
}

func unescaped(p string) string {
	if u, err := url.PathUnescape(p); err == nil {
		return u
	}
	return p
}

// freshSelfID: a write that makes an object under an ID its own body
// chose (ClientID) is sent with a fresh ID in that place (ADR 0050).
var freshSelfID = true

// clientIDs returns the IDs of a recorded POST's answer that its own body
// already held at a key of the same name (in a method call's params): the
// client chose the new object's ID. Rocket.Chat's sendMessage sends the
// message's _id and answers with it; sent again with that _id it answers
// 200 with no result and makes nothing (measured 2026-11-22). The keys must
// match so that a reference that happens to equal the new ID (a
// "ProductId" of 1 and a new "id" of 1) is not taken.
func clientIDs(body []byte, ids []idField) map[string]bool {
	out := map[string]bool{}
	scope, _, ok := idScope(body)
	if !ok {
		return out
	}
	walkIDKeys(scope, 0, func(_ map[string]any, k, v string) {
		for _, id := range ids {
			if id.value == v && strings.EqualFold(id.field[len(id.field)-1], k) {
				out[v] = true
			}
		}
	})
	return out
}

var reUUID = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// freshID returns a new random ID shaped like old: a random version 4
// UUID for a UUID; otherwise each digit becomes a random digit, each
// letter a random letter of the same case (hex digits stay hex when old is
// all hex), other characters stay. A first digit stays non-zero.
func freshID(old string) string {
	rnd := func(n int) int {
		var b [1]byte
		for {
			if _, err := rand.Read(b[:]); err != nil {
				panic(err)
			}
			if int(b[0]) < 256-256%n {
				return int(b[0]) % n
			}
		}
	}
	if reUUID.MatchString(old) {
		var b [16]byte
		if _, err := rand.Read(b[:]); err != nil {
			panic(err)
		}
		b[6] = b[6]&0x0f | 0x40
		b[8] = b[8]&0x3f | 0x80
		h := hex.EncodeToString(b[:])
		s := h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
		if strings.ToUpper(old) == old {
			s = strings.ToUpper(s)
		}
		return s
	}
	isHex := reHex.MatchString(old) && strings.Trim(old, "0123456789") != ""
	out := []byte(old)
	for i, c := range out {
		switch {
		case c >= '0' && c <= '9':
			if i == 0 && len(out) > 1 {
				out[i] = digits[1+rnd(9)]
			} else {
				out[i] = digits[rnd(10)]
			}
		case c >= 'a' && c <= 'z':
			if isHex {
				out[i] = "abcdef"[rnd(6)]
			} else {
				out[i] = lower[rnd(26)]
			}
		case c >= 'A' && c <= 'Z':
			if isHex {
				out[i] = "ABCDEF"[rnd(6)]
			} else {
				out[i] = upper[rnd(26)]
			}
		}
	}
	return string(out)
}

var reHex = regexp.MustCompile(`^[0-9a-fA-F]+$`)

// The characters freshID picks from, by index (no integer conversions).
const (
	digits = "0123456789"
	lower  = "abcdefghijklmnopqrstuvwxyz"
	upper  = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
)

// resultField marks an ID that is a method call's whole result.
const resultField = ""

// createVerbs: a method whose name starts a part with one of these makes
// an object. Kanboard's createTask and createComment answer with the new
// ID as the whole result ({"result":1}, measured 2026-11-22).
var createVerbs = setOf("create add new insert make")

func createName(name string) bool {
	for _, part := range strings.FieldsFunc(name, func(r rune) bool {
		return !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9')
	}) {
		if ws := webform.Words(part); len(ws) > 0 && createVerbs[ws[0]] {
			return true
		}
	}
	return false
}

// scalarID is v as an ID when it is a number or a string (not an object,
// a list or a boolean).
func scalarID(v any) (string, bool) {
	switch v.(type) {
	case float64, string:
		return idValue(v)
	}
	return "", false
}

// sameNoun reports whether a method call w names the ID value under a key
// whose noun is the last word of the create's method name: "task_id" or
// updateTask's "id" against createTask. All of Kanboard's creates answer
// 1 on a new project (project, task, comment), and closeTask's task_id
// went to the latest, the comment, before this rule (measured
// 2026-11-22).
func sameNoun(w Write, value, createMethod string) bool {
	cw := webform.Words(createMethod)
	if len(cw) < 2 {
		return false
	}
	want := strings.TrimSuffix(cw[len(cw)-1], "s")
	scope, _, ok := idScope(w.Body)
	if !ok {
		return false
	}
	found := false
	walkIDKeys(scope, 0, func(_ map[string]any, k, v string) {
		if v != value || found {
			return
		}
		nouns := webform.Words(k)
		if l := strings.ToLower(k); l == "id" || l == "_id" {
			nouns = webform.Words(w.RPC)
			if len(nouns) > 0 {
				nouns = nouns[1:]
			}
		}
		for _, n := range nouns {
			if n != "id" && n != "ids" && strings.TrimSuffix(n, "s") == want {
				found = true
			}
		}
	})
	return found
}

// sockJSParts are the last path segments of SockJS's fallback transports
// (/<prefix>/<server>/<session>/xhr_send and so on).
var sockJSParts = setOf("xhr xhr_send xhr_streaming jsonp jsonp_send eventsource htmlfile")

// socketTransport reports whether a request is a WebSocket fallback
// transport: SockJS (Rocket.Chat's DDP fell back to /sockjs/<server>/
// <session>/xhr_send when its WebSocket failed, carrying connect, sub, a
// resume login and method calls, measured 2026-11-22) or Engine.IO polling
// (Socket.IO, ?EIO=4&transport=polling on Juice Shop). The session ID in
// the URL is what lets a request in, not the account's session, so a
// replay as B or with no login tests nothing about access control.
func socketTransport(p string) bool {
	pathPart, query, _ := strings.Cut(p, "?")
	segs := strings.Split(strings.Trim(pathPart, "/"), "/")
	if n := len(segs); n >= 3 && sockJSParts[segs[n-1]] && segs[n-2] != "" && segs[n-3] != "" &&
		!strings.Contains(segs[n-2], ".") && !strings.Contains(segs[n-3], ".") {
		return true
	}
	q, err := url.ParseQuery(query)
	return err == nil && q.Get("EIO") != "" && q.Get("transport") == "polling"
}

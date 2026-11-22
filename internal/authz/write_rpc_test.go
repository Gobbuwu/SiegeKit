package authz

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"

	"github.com/Gobbuwu/SiegeKit/internal/egress"
	"github.com/Gobbuwu/SiegeKit/internal/findings"
	"github.com/Gobbuwu/SiegeKit/internal/target"
)

func TestReadName(t *testing.T) {
	for name, want := range map[string]bool{
		// Measured on Rocket.Chat 6.13.1 (2026-11-22).
		"public-settings/get": true, "subscriptions/get": true, "public-settings:get": true, "loadHistory": true, "license:isEnterprise": true, "subscriptions:get": true,
		"license:getModules": true, "getUserRoles": true, "listCustomSounds": true, "getRoomByTypeAndName": true,
		"sendMessage": false, "updateMessage": false, "deleteMessage": false, "userSetUtcOffset": false,
		"readMessages": false, "setReaction": false,
		// Other shapes.
		"eth_getBalance": true, "user.get": true, "get_user_info": true, "users.list": true,
		"getOrCreateRoom": false, "fetchAndUpdate": false, "issue": false, "targetList": false, "": false,
	} {
		if got := readName(name); got != want {
			t.Errorf("readName(%q) = %v, want %v", name, got, want)
		}
	}
}

func TestReadPath(t *testing.T) {
	for p, want := range map[string]bool{
		"/__meteor__/dynamic-import/fetch":           true,
		"/-/fetch-redirect":                          true,
		"/api/v1/method.call/license%3AisEnterprise": true,
		"/api/search?q=1":                            true,
		"/api/items/search/42":                       true,
		"/api/v1/method.call/sendMessage":            false,
		"/rest/basket/6/checkout":                    false,
		"/api/Feedbacks/":                            false,
		"/alice/pub/issues/new":                      false,
		"/rest/user/data-export":                     false,
		"/":                                          false,
	} {
		if got := readPath(p); got != want {
			t.Errorf("readPath(%q) = %v, want %v", p, got, want)
		}
	}
}

func ddpBody(id, method, params string) string {
	inner := fmt.Sprintf(`{"msg":"method","id":%q,"method":%q,"params":%s}`, id, method, params)
	b, _ := json.Marshal(map[string]string{"message": inner})
	return string(b)
}

func ddpAnswer(id, result string) string {
	inner := fmt.Sprintf(`{"msg":"result","id":%q`, id)
	if result != "" {
		inner += `,"result":` + result
	}
	b, _ := json.Marshal(map[string]any{"message": inner + "}", "success": true})
	return string(b)
}

func TestRPCOp(t *testing.T) {
	for _, c := range []struct {
		body, kind string
		methods    []string
	}{
		{ddpBody("1", "sendMessage", `[{"_id":"x"}]`), rpcDDP, []string{"sendMessage"}},
		{`{"jsonrpc":"2.0","method":"user.get","params":{"id":1},"id":5}`, rpcJSONRPC, []string{"user.get"}},
		{`{"method":"save","params":[1],"id":5}`, rpcJSONRPC, []string{"save"}},
		{`[{"jsonrpc":"2.0","method":"a.get","id":1},{"jsonrpc":"2.0","method":"b.update","id":2}]`, rpcJSONRPC, []string{"a.get", "b.update"}},
		{`{"method":"card","amount":5}`, "", nil},                        // a payment method, not a call
		{`{"message":"hello"}`, "", nil},                                 // a plain message
		{`{"message":"{\"msg\":\"result\",\"id\":\"1\"}"}`, "", nil},     // a DDP answer, not a call
		{`[{"jsonrpc":"2.0","method":"a.get","id":1},{"x":1}]`, "", nil}, // mixed batch
		{`{"query":"mutation { a }"}`, "", nil},
	} {
		got, ok := rpcOp([]byte(c.body))
		if ok != (c.kind != "") || got.kind != c.kind || strings.Join(got.methods, ",") != strings.Join(c.methods, ",") {
			t.Errorf("rpcOp(%s) = %+v %v", c.body, got, ok)
		}
	}
}

func TestEnvelopeRefused(t *testing.T) {
	ddpErr := `{"message":"{\"msg\":\"result\",\"id\":\"3\",\"error\":{\"error\":\"error-action-not-allowed\"}}","success":true}`
	for _, c := range []struct {
		body, kind string
		want       bool
	}{
		{ddpErr, rpcDDP, true},
		{ddpAnswer("3", ""), rpcDDP, false},
		{ddpAnswer("3", `{"_id":"x"}`), rpcDDP, false},
		{`{"success":false,"error":"no"}`, "", true},
		{`{"success":true}`, "", false},
		{`{"jsonrpc":"2.0","error":{"code":-32000,"message":"denied"},"id":1}`, rpcJSONRPC, true},
		{`{"jsonrpc":"2.0","result":{"ok":true},"error":null,"id":1}`, rpcJSONRPC, false},
		{`[{"jsonrpc":"2.0","error":{"code":1},"id":1},{"jsonrpc":"2.0","result":1,"id":2}]`, rpcJSONRPC, false},
		{`[{"jsonrpc":"2.0","error":{"code":1},"id":1},{"jsonrpc":"2.0","error":{"code":1},"id":2}]`, rpcJSONRPC, true},
		// A REST answer with an "error" field is not a call's error.
		{`{"id":5,"error":"none yet"}`, "", false},
		{`not json`, rpcDDP, false},
	} {
		if got := envelopeRefused([]byte(c.body), c.kind); got != c.want {
			t.Errorf("envelopeRefused(%s, %q) = %v", c.body, c.kind, got)
		}
	}
}

func TestWithIDRPC(t *testing.T) {
	w := Write{Method: "POST", Path: "/api/v1/method.call/updateMessage", Header: http.Header{}, Body: []byte(ddpBody("7", "updateMessage", `[{"_id":"7","rid":"GENERAL","msg":"x"}]`))}
	got := w.withID("7", "NEW")
	inner, _, ok := ddpMessage(got.Body)
	if !ok || inner["id"] != "7" || inner["params"].([]any)[0].(map[string]any)["_id"] != "NEW" {
		t.Errorf("DDP: %s", got.Body)
	}
	j := Write{Method: "POST", Path: "/rpc", Header: http.Header{}, Body: []byte(`{"jsonrpc":"2.0","method":"note.update","params":{"id":7},"id":7}`)}
	var m map[string]any
	if json.Unmarshal(j.withID("7", "9").Body, &m) != nil || m["id"] != float64(7) || m["params"].(map[string]any)["id"] != float64(9) {
		t.Errorf("JSON-RPC: %v", m)
	}
	// The envelope's own ids are not object IDs.
	if ids := writeIDs(Write{Path: "/rpc", Body: []byte(`{"jsonrpc":"2.0","method":"a.b","params":{"x":1},"id":7}`)}); ids["7"] {
		t.Errorf("writeIDs: %v", ids)
	}
}

func TestFreshID(t *testing.T) {
	for _, old := range []string{"KP4XXmrG3gs9RoAt5", "12345", "deadbeef0011", "DEADBEEF", "0b4f9c2e-6a1d-4e3b-9f7a-1c2d3e4f5a6b", "a-b_C9"} {
		got := freshID(old)
		if got == old || len(got) != len(old) {
			t.Errorf("freshID(%q) = %q", old, got)
		}
		for i := range old {
			o, g := old[i], got[i]
			class := func(c byte) int {
				switch {
				case c >= '0' && c <= '9':
					return 0
				case c >= 'a' && c <= 'z':
					return 1
				case c >= 'A' && c <= 'Z':
					return 2
				}
				return int(c)
			}
			if reUUID.MatchString(old) {
				break
			}
			if class(o) != class(g) {
				t.Errorf("freshID(%q) = %q: character %d changed class", old, got, i)
			}
		}
	}
	if !reUUID.MatchString(freshID("0b4f9c2e-6a1d-4e3b-9f7a-1c2d3e4f5a6b")) || !reID.MatchString(freshID("12345")) || freshID("12345")[0] == '0' {
		t.Error("shape")
	}
	if g := freshID("deadbeef0011"); !reHex.MatchString(g) {
		t.Errorf("hex: %q", g)
	}
}

// TestParseWritesRPC: a Rocket.Chat-shaped recording. The login is never
// replayed, reads by name or path are counted and not replayed, the
// message edit is linked to the send through the _id in its params, and
// the send chose that _id itself. A JSON-RPC update is linked to its
// create through the result, not the envelope's id; a POST that names an
// ID seen earlier is not a client-made ID.
func TestParseWritesRPC(t *testing.T) {
	u := "http://127.0.0.1:3000"
	mc := u + "/api/v1/method.call/"
	har := writeHAR(t, []writeEntry{
		{method: "POST", url: u + "/api/v1/method.callAnon/login", mime: "application/json", body: ddpBody("1", "login", `[{"resume":"x"}]`), status: 200, answer: ddpAnswer("1", `{"id":"u"}`)},
		{method: "POST", url: u + "/__meteor__/dynamic-import/fetch", mime: "application/json", body: `{"/node_modules/x":1}`, status: 200, answer: `{}`},
		{method: "POST", url: mc + "public-settings%3Aget", mime: "application/json", body: ddpBody("2", "public-settings:get", `[]`), status: 200, answer: ddpAnswer("2", `[]`)},
		{method: "POST", url: mc + "loadHistory", mime: "application/json", body: ddpBody("3", "loadHistory", `["GENERAL",null,50]`), status: 200, answer: ddpAnswer("3", `{"messages":[{"_id":"OLDMSG"}]}`)},
		{method: "POST", url: mc + "sendMessage", mime: "application/json", body: ddpBody("16", "sendMessage", `[{"_id":"KP4XXmrG3gs9RoAt5","rid":"GENERAL","msg":"hi"}]`), status: 200, answer: ddpAnswer("16", `{"_id":"KP4XXmrG3gs9RoAt5","rid":"GENERAL","u":{"_id":"alice1"}}`)},
		{method: "POST", url: mc + "updateMessage", mime: "application/json", body: ddpBody("18", "updateMessage", `[{"_id":"KP4XXmrG3gs9RoAt5","rid":"GENERAL","msg":"edited"}]`), status: 200, answer: ddpAnswer("18", "")},
		{method: "POST", url: mc + "pinMessage", mime: "application/json", body: ddpBody("19", "pinMessage", `[{"_id":"OLDMSG"}]`), status: 200, answer: ddpAnswer("19", `{"_id":"OLDMSG"}`)},
		{method: "POST", url: u + "/rpc", mime: "application/json", body: `{"jsonrpc":"2.0","method":"note.create","params":{"text":"x"},"id":1}`, status: 200, answer: `{"jsonrpc":"2.0","result":{"id":7},"id":1}`},
		{method: "POST", url: u + "/rpc", mime: "application/json", body: `{"jsonrpc":"2.0","method":"note.update","params":{"id":7,"text":"y"},"id":1}`, status: 200, answer: `{"jsonrpc":"2.0","result":true,"id":1}`},
		{method: "POST", url: u + "/rpc", mime: "application/json", body: `{"jsonrpc":"2.0","method":"auth.logout","id":2}`, status: 200, answer: `{"jsonrpc":"2.0","result":true,"id":2}`},
	})
	ws, err := ParseWrites(har, mustTarget(t, u+"/"))
	if err != nil {
		t.Fatal(err)
	}
	if ws.Lockout != 2 || ws.RPCReads != 2 || ws.ReadPOSTs != 1 || len(ws.ReadNames) != 3 {
		t.Errorf("counts: %+v", ws)
	}
	var labels []string
	byRPC := map[string]Write{}
	for _, w := range ws.Writes {
		labels = append(labels, w.Label())
		byRPC[w.RPC] = w
	}
	want := "POST /api/v1/method.call/sendMessage,POST /api/v1/method.call/updateMessage,POST /api/v1/method.call/pinMessage,POST /rpc (method note.create),POST /rpc (method note.update)"
	if strings.Join(labels, ",") != want {
		t.Errorf("labels %v", labels)
	}
	send, upd := byRPC["sendMessage"], byRPC["updateMessage"]
	if send.ClientID != "KP4XXmrG3gs9RoAt5" || send.RPCKind != rpcDDP || send.Create != nil {
		t.Errorf("send: %+v", send)
	}
	if c := upd.Create; c == nil || !c.RPC || !c.ClientID || strings.Join(c.Field, ".") != "_id" || c.OldID != "KP4XXmrG3gs9RoAt5" {
		t.Errorf("update's create: %+v", upd.Create)
	}
	if pin := byRPC["pinMessage"]; pin.ClientID != "" {
		t.Errorf("an ID from an earlier answer is not client-made: %+v", pin)
	}
	if c := byRPC["note.update"].Create; c == nil || !c.RPC || c.ClientID || strings.Join(c.Field, ".") != "id" || c.OldID != "7" {
		t.Errorf("JSON-RPC update's create: %+v", c)
	}
	if plainCreate(send, "alice") {
		t.Error("sendMessage names a room: not a plain create")
	}
	if !plainCreate(byRPC["note.create"], "alice") {
		t.Error("note.create names nothing")
	}
}

// TestWriteCheckRPC: a server shaped like Rocket.Chat's method.call. A's
// send is sent again with a fresh _id (the server ignores a known one) and
// B's edit of that copy is refused inside a 200 answer; B's own send goes
// with a fresh _id too, and is a medium finding.
func TestWriteCheckRPC(t *testing.T) {
	var mu sync.Mutex
	msgs := map[string]string{"KP4XXmrG3gs9RoAt5": "alice"}
	var sentIDs []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		who := map[string]string{"ta": "alice", "tb": "bob"}[r.Header.Get("X-Auth-Token")]
		if who == "" {
			w.WriteHeader(401)
			fmt.Fprint(w, `{"status":"error","message":"You must be logged in to do this."}`)
			return
		}
		var outer struct{ Message string }
		json.NewDecoder(r.Body).Decode(&outer)
		var in struct {
			ID     string           `json:"id"`
			Method string           `json:"method"`
			Params []map[string]any `json:"params"`
		}
		json.Unmarshal([]byte(outer.Message), &in)
		id, _ := in.Params[0]["_id"].(string)
		sentIDs = append(sentIDs, who+" "+in.Method+" "+id)
		switch in.Method {
		case "sendMessage":
			if msgs[id] != "" {
				fmt.Fprint(w, ddpAnswer(in.ID, ""))
				return
			}
			msgs[id] = who
			fmt.Fprint(w, ddpAnswer(in.ID, fmt.Sprintf(`{"_id":%q}`, id)))
		case "updateMessage":
			if msgs[id] != who {
				b, _ := json.Marshal(map[string]any{"message": fmt.Sprintf(`{"msg":"result","id":%q,"error":{"error":"error-action-not-allowed"}}`, in.ID), "success": true})
				w.Write(b)
				return
			}
			fmt.Fprint(w, ddpAnswer(in.ID, ""))
		}
	}))
	defer srv.Close()
	noSleep(t)
	a := map[string]string{"X-Auth-Token": "ta", "X-User-Id": "alice1"}
	mc := srv.URL + "/api/v1/method.call/"
	har := writeHAR(t, []writeEntry{
		{method: "POST", url: mc + "sendMessage", headers: a, mime: "application/json", body: ddpBody("16", "sendMessage", `[{"_id":"KP4XXmrG3gs9RoAt5","rid":"GENERAL","msg":"hi"}]`), status: 200, answer: ddpAnswer("16", `{"_id":"KP4XXmrG3gs9RoAt5"}`)},
		{method: "POST", url: mc + "updateMessage", headers: a, mime: "application/json", body: ddpBody("18", "updateMessage", `[{"_id":"KP4XXmrG3gs9RoAt5","rid":"GENERAL","msg":"edited"}]`), status: 200, answer: ddpAnswer("18", "")},
	})
	tu := mustTarget(t, srv.URL+"/")
	ws, err := ParseWrites(har, tu)
	if err != nil || len(ws.Writes) != 2 {
		t.Fatalf("%v %+v", err, ws)
	}
	cfg := egress.Config{Target: tu, Addrs: []netip.Addr{netip.MustParseAddr("127.0.0.1")}, Version: "test"}
	res, err := WriteCheck(context.Background(), cfg, ws.Writes, http.Header{"X-Auth-Token": {"tb"}, "X-User-Id": {"bob1"}}, "alice", 10, target.Local)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range sentIDs {
		if strings.HasSuffix(s, " KP4XXmrG3gs9RoAt5") {
			t.Errorf("the recorded _id was sent again: %v", sentIDs)
		}
	}
	if res.Recreated != 2 {
		t.Errorf("copies: %d %v", res.Recreated, sentIDs)
	}
	fs := WriteFindings(srv.URL, res)
	if len(fs) != 1 || fs[0].Severity != findings.Medium || fs[0].Location.URI != srv.URL+"/api/v1/method.call/sendMessage" {
		t.Errorf("findings: %+v", fs)
	}
	for _, rp := range res.Replays {
		if rp.RPC == "updateMessage" && (rp.Accepted() || !rp.Recreated) {
			t.Errorf("B's edit of A's copy: %+v", rp)
		}
	}
	if msgs["KP4XXmrG3gs9RoAt5"] != "alice" {
		t.Error("A's recorded message changed")
	}
}

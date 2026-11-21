package runner

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"testing"

	"github.com/Gobbuwu/SiegeKit/internal/authz"
	"github.com/Gobbuwu/SiegeKit/internal/egress"
	"github.com/Gobbuwu/SiegeKit/internal/target"
)

// TestAuthzFindsPlantedIssues replays a HAR recorded as alice against the
// vulnerable app, as bob and with no login: the order any account can
// read, the profile anyone can read and the password hashes anyone can
// read are reported, and the orders that check their owner or differ per
// account are not.
func TestAuthzFindsPlantedIssues(t *testing.T) {
	srv := httptest.NewServer(vulnApp())
	defer srv.Close()
	tu, err := target.Parse(srv.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	type header struct {
		Name  string `json:"name"`
		Value string `json:"value"`
	}
	type entry struct {
		Request struct {
			Method  string   `json:"method"`
			URL     string   `json:"url"`
			Headers []header `json:"headers"`
		} `json:"request"`
	}
	var har struct {
		Log struct {
			Entries []entry `json:"entries"`
		} `json:"log"`
	}
	for _, p := range []string{"/", "/static/app.js", "/api/orders/7", "/api/own-orders/7", "/api/my/orders", "/account/profile", "/api/members", "/item?id=1"} {
		var e entry
		e.Request.Method, e.Request.URL = "GET", srv.URL+p
		e.Request.Headers = []header{{"Authorization", "Bearer token-a"}, {"Accept", "application/json"}}
		har.Log.Entries = append(har.Log.Entries, e)
	}
	data, err := json.Marshal(har)
	if err != nil {
		t.Fatal(err)
	}
	h, err := authz.ParseHAR(data, tu)
	if err != nil || len(h.Requests) != 7 || h.Static != 1 {
		t.Fatalf("%+v %v", h, err)
	}
	cfg := egress.Config{Target: tu, Addrs: []netip.Addr{netip.MustParseAddr("127.0.0.1")}, Version: "test", ReadOnly: true}
	res, err := authz.Check(context.Background(), cfg, h.Requests, http.Header{"Authorization": {"Bearer token-b"}}, 100)
	if err != nil || res.Requests != 21 {
		t.Fatalf("%+v %v", res, err)
	}
	found := map[string]bool{}
	fs := authz.Findings(srv.URL, res, "alice@shop.test")
	for _, f := range fs {
		u, _ := url.Parse(f.Location.URI)
		found[f.RuleID+" "+u.Path] = true
	}
	for rule, issue := range vulnAppIssues[authz.ID] {
		if !found[rule] {
			t.Errorf("missed %s (rule %s)", issue, rule)
		}
	}
	if len(fs) != len(vulnAppIssues[authz.ID]) {
		t.Errorf("%d findings, want %d: %+v", len(fs), len(vulnAppIssues[authz.ID]), fs)
	}
}

// TestAuthzWriteFindsPlantedIssue replays a HAR recorded as alice (she
// makes cart 1, changes it and deletes another cart of hers) as bob and
// with no login: bob changing alice's cart is reported high; deleting
// another account's cart and anything with no login are refused.
func TestAuthzWriteFindsPlantedIssue(t *testing.T) {
	srv := httptest.NewServer(vulnApp())
	defer srv.Close()
	tu, err := target.Parse(srv.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	a := []map[string]string{{"name": "Authorization", "value": "Bearer token-a"}, {"name": "Content-Type", "value": "application/json"}}
	entry := func(method, path, body string, status int, answer string) map[string]any {
		e := map[string]any{"request": map[string]any{"method": method, "url": srv.URL + path, "headers": a}, "response": map[string]any{"status": status, "content": map[string]any{"text": answer}}}
		if body != "" {
			e["request"].(map[string]any)["postData"] = map[string]any{"mimeType": "application/json", "text": body}
		}
		return e
	}
	data, err := json.Marshal(map[string]any{"log": map[string]any{"entries": []any{
		entry("POST", "/api/carts/", "{}", 201, `{"status":"success","data":{"id":1}}`),
		entry("PUT", "/api/carts/1", `{"qty":2}`, 200, `{"status":"success"}`),
		entry("POST", "/api/carts/", "{}", 201, `{"status":"success","data":{"id":2}}`),
		entry("DELETE", "/api/carts/2", "", 200, `{"status":"success"}`),
	}}})
	if err != nil {
		t.Fatal(err)
	}
	// alice's recorded carts as the recording left them: 1 is still there.
	cfg := egress.Config{Target: tu, Addrs: []netip.Addr{netip.MustParseAddr("127.0.0.1")}, Version: "test"}
	if ans, err := egress.SendHeader(context.Background(), cfg, "POST", "/api/carts/", http.Header{"Authorization": {"Bearer token-a"}}, []byte("{}"), 1<<10); err != nil || ans.Status != 201 {
		t.Fatal(ans, err)
	}
	w, err := authz.ParseWrites(data, tu)
	// The second identical create is a duplicate.
	if err != nil || len(w.Writes) != 3 || w.Duplicate != 1 || w.Writes[1].Create == nil || w.Writes[2].Create == nil {
		t.Fatalf("%+v %v", w, err)
	}
	res, err := authz.WriteCheck(context.Background(), cfg, w.Writes, http.Header{"Authorization": {"Bearer token-b"}}, "alice@shop.test", 100, target.Local)
	if err != nil {
		t.Fatal(err)
	}
	found := map[string]bool{}
	fs := authz.WriteFindings(srv.URL, res)
	for _, f := range fs {
		u, _ := url.Parse(f.Location.URI)
		found[f.RuleID+" "+u.Path] = true
		if f.Severity.String() != "high" {
			t.Errorf("%+v", f)
		}
	}
	for rule, issue := range vulnAppIssues[authz.WriteID] {
		if !found[rule] {
			t.Errorf("missed %s (rule %s)", issue, rule)
		}
	}
	if len(fs) != len(vulnAppIssues[authz.WriteID]) {
		t.Errorf("%d findings, want %d: %+v", len(fs), len(vulnAppIssues[authz.WriteID]), fs)
	}
	// alice's recorded cart 1 is untouched: every replay used a copy.
	ans, err := egress.SendHeader(context.Background(), cfg, "GET", "/api/carts/1", http.Header{"Authorization": {"Bearer token-a"}}, nil, 1<<10)
	if err != nil || string(ans.Body) != `{"data":{"qty":1}}` {
		t.Errorf("alice's cart: %v %s", err, ans.Body)
	}
}

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
	"github.com/Gobbuwu/SiegeKit/internal/findings"
	"github.com/Gobbuwu/SiegeKit/internal/target"
)

// TestAuthzOutsiderFindsPlantedIssues replays alice's recording against the
// vulnerable app as carol (C, outside team 3), as bob (B, a member) and
// with no login (ADR 0051): the leaks any account can use are C's
// findings, at the tier they had for B; what only the member gets is low.
func TestAuthzOutsiderFindsPlantedIssues(t *testing.T) {
	srv := httptest.NewServer(vulnApp())
	defer srv.Close()
	tu, err := target.Parse(srv.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	acc := authz.Accounts{B: http.Header{"Authorization": {"Bearer token-b"}}, C: http.Header{"Authorization": {"Bearer token-c"}}}
	a := []map[string]string{{"name": "Authorization", "value": "Bearer token-a"}, {"name": "Accept", "value": "application/json"}}
	var entries []any
	for _, p := range []string{"/", "/api/orders/7", "/api/own-orders/7", "/api/my/orders", "/account/profile", "/api/members", "/api/teams/3", "/api/teams/3/deleted"} {
		entries = append(entries, map[string]any{"request": map[string]any{"method": "GET", "url": srv.URL + p, "headers": a}})
	}
	data, err := json.Marshal(map[string]any{"log": map[string]any{"entries": entries}})
	if err != nil {
		t.Fatal(err)
	}
	h, err := authz.ParseHAR(data, tu)
	if err != nil || len(h.Requests) != 8 {
		t.Fatalf("%+v %v", h, err)
	}
	cfg := egress.Config{Target: tu, Addrs: []netip.Addr{netip.MustParseAddr("127.0.0.1")}, Version: "test", ReadOnly: true}
	res, err := authz.Check(context.Background(), cfg, h.Requests, acc, 100)
	// 32, and A's /api/my/orders again (issue #95).
	if err != nil || res.Requests != 33 || !res.CWorks() {
		t.Fatalf("%+v %v", res, err)
	}
	checkPlanted(t, srv.URL, authz.Findings(srv.URL, res, "alice@shop.test"), vulnAppOutsiderIssues[authz.ID])
}

// TestAuthzWriteOutsiderFindsPlantedIssues: carol changes alice's cart
// (any logged-in account can), bob renames the team he shares with alice
// and carol cannot (low).
func TestAuthzWriteOutsiderFindsPlantedIssues(t *testing.T) {
	srv := httptest.NewServer(vulnApp())
	defer srv.Close()
	tu, err := target.Parse(srv.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	acc := authz.Accounts{B: http.Header{"Authorization": {"Bearer token-b"}}, C: http.Header{"Authorization": {"Bearer token-c"}}}
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
		entry("GET", "/api/teams/3", "", 200, `{"id":3}`),
		entry("PUT", "/api/teams/3", `{"name":"x"}`, 200, `{"status":"success"}`),
	}}})
	if err != nil {
		t.Fatal(err)
	}
	cfg := egress.Config{Target: tu, Addrs: []netip.Addr{netip.MustParseAddr("127.0.0.1")}, Version: "test"}
	if ans, err := egress.SendHeader(context.Background(), cfg, "POST", "/api/carts/", http.Header{"Authorization": {"Bearer token-a"}}, []byte("{}"), 1<<10); err != nil || ans.Status != 201 {
		t.Fatal(ans, err)
	}
	w, err := authz.ParseWrites(data, tu)
	if err != nil {
		t.Fatal(err)
	}
	res, err := authz.WriteCheck(context.Background(), cfg, w.Writes, acc, "alice@shop.test", 100, target.Local)
	if err != nil || !res.CWorks() {
		t.Fatalf("%+v %v", res, err)
	}
	fs := authz.WriteFindings(srv.URL, res)
	checkPlanted(t, srv.URL, fs, vulnAppOutsiderIssues[authz.WriteID])
	for _, f := range fs {
		if want := map[string]findings.Severity{"cross-account-write": findings.High, "b-only-write": findings.Low}[f.RuleID]; f.Severity != want {
			t.Errorf("%s: %s, want %s", f.RuleID, f.Severity, want)
		}
	}
}

func checkPlanted(t *testing.T, origin string, fs []findings.Finding, want map[string]string) {
	t.Helper()
	found := map[string]bool{}
	for _, f := range fs {
		u, _ := url.Parse(f.Location.URI)
		found[f.RuleID+" "+u.Path] = true
	}
	for rule, issue := range want {
		if !found[rule] {
			t.Errorf("missed %s (rule %s)", issue, rule)
		}
	}
	if len(fs) != len(want) {
		t.Errorf("%d findings, want %d: %+v", len(fs), len(want), fs)
	}
}

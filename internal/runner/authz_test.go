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

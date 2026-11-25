package runner

import (
	"context"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"testing"

	"github.com/Gobbuwu/SiegeKit/internal/egress"
	"github.com/Gobbuwu/SiegeKit/internal/ratelimit"
	"github.com/Gobbuwu/SiegeKit/internal/target"
)

// TestRateLimitFindsPlantedIssue runs the rate-limit check against the
// vulnerable app, with the real clock: the search without a limit is
// reported, and the report limited to 3 requests is not.
func TestRateLimitFindsPlantedIssue(t *testing.T) {
	if testing.Short() {
		t.Skip("sends requests one per second")
	}
	srv := httptest.NewServer(vulnApp())
	defer srv.Close()
	tu, err := target.Parse(srv.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	cfg := egress.Config{Target: tu, Addrs: []netip.Addr{netip.MustParseAddr("127.0.0.1")}, Version: "test"}
	const n = ratelimit.DefaultRequests // fewer give no "not limited" finding (ADR 0062 item 7)
	e, err := ratelimit.Parse(srv.URL+"/api/suggest?q=apple", "", tu)
	if err != nil {
		t.Fatal(err)
	}
	r, err := ratelimit.Check(context.Background(), cfg, e, n)
	if err != nil || r.Limited || r.Requests != n || r.Baseline != 200 {
		t.Fatalf("%+v %v", r, err)
	}
	found := map[string]bool{}
	for _, f := range ratelimit.Findings(e, r, n) {
		u, _ := url.Parse(f.Location.URI)
		found[f.RuleID+" "+u.Path] = true
	}
	for rule, issue := range vulnAppIssues[ratelimit.ID] {
		if !found[rule] {
			t.Errorf("missed %s (rule %s)", issue, rule)
		}
	}

	e, err = ratelimit.Parse(srv.URL+"/api/report", `{"from":"2026-01-01"}`, tu)
	if err != nil {
		t.Fatal(err)
	}
	r, err = ratelimit.Check(context.Background(), cfg, e, n)
	if err != nil || !r.Limited || r.Requests != 4 || r.Signal != "answered 429" || len(ratelimit.Findings(e, r, n)) != 0 {
		t.Errorf("limited report: %+v %v", r, err)
	}
}

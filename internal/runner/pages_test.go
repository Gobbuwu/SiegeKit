package runner

import (
	"context"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"testing"

	"github.com/Gobbuwu/SiegeKit/internal/egress"
	"github.com/Gobbuwu/SiegeKit/internal/findings"
	"github.com/Gobbuwu/SiegeKit/internal/login"
	"github.com/Gobbuwu/SiegeKit/internal/ratelimit"
	"github.com/Gobbuwu/SiegeKit/internal/target"
)

// TestPagesFindPlantedIssues runs the reset, sign-up and code checks and
// spraying against the test app with a real clock (ADR 0055): each planted
// missing limit is reported, and each planted limit is seen with no
// finding.
func TestPagesFindPlantedIssues(t *testing.T) {
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
	const n = 5
	found := map[string]map[string]bool{}
	add := func(id string, fs []findings.Finding) {
		if found[id] == nil {
			found[id] = map[string]bool{}
		}
		for _, f := range fs {
			u, _ := url.Parse(f.Location.URI)
			found[id][f.RuleID+" "+u.Path] = true
		}
	}
	for _, c := range []struct {
		p           ratelimit.Page
		path, body  string
		limited     bool
		wantFinding bool
	}{
		{ratelimit.Reset, "/account/forgot-password", "email=tester%40shop.test", false, true},
		{ratelimit.Reset, "/account/forgot-password-limited", "email=tester%40shop.test", true, false},
		{ratelimit.SignUp, "/account/sign-up", "username={new}&password=Passw0rd%21", false, true},
		{ratelimit.Code, "/account/2fa", `{"code":"{wrong}"}`, false, true},
		{ratelimit.Code, "/account/2fa-limited", `{"code":"{wrong}"}`, true, false},
		{ratelimit.Code, "/account/2fa-loose", `{"code":"{wrong}"}`, true, true},
	} {
		e, err := ratelimit.ParsePage(c.p, srv.URL+c.path, c.body, tu)
		if err != nil {
			t.Fatal(err)
		}
		r, err := ratelimit.Check(context.Background(), cfg, e, n)
		fs := ratelimit.Findings(e, r, n)
		if err != nil || r.Limited != c.limited || (len(fs) > 0) != c.wantFinding {
			t.Errorf("%s: %+v %v %v", c.path, r, err, fs)
		}
		add(c.p.ID(), fs)
	}
	// Spraying after a limit on one account: the per-account lock lets it
	// through, the limit for everyone does not.
	for _, c := range []struct {
		path        string
		wantFinding bool
	}{
		{"/account/sign-in-limited", true},
		{"/account/sign-in-guarded", false},
	} {
		l, err := login.Parse(srv.URL+c.path, "tester", "username={user}&password={password}", tu)
		if err != nil {
			t.Fatal(err)
		}
		if r, err := login.Check(context.Background(), cfg, l, n); err != nil || !r.Limited {
			t.Fatalf("%s: login-throttle %+v %v", c.path, r, err)
		}
		r, err := login.Spray(context.Background(), cfg, l, n)
		fs := login.SprayFindings(l, r, n)
		if err != nil || r.Limited == c.wantFinding || (len(fs) > 0) != c.wantFinding {
			t.Errorf("%s: spray %+v %v %v", c.path, r, err, fs)
		}
		add(login.SprayID, fs)
	}
	for _, id := range []string{ratelimit.ResetID, ratelimit.SignUpID, ratelimit.CodeID, login.SprayID} {
		for rule, issue := range vulnAppIssues[id] {
			if !found[id][rule] {
				t.Errorf("%s missed %s (rule %s)", id, issue, rule)
			}
		}
		for rule := range found[id] {
			if _, ok := vulnAppIssues[id][rule]; !ok {
				t.Errorf("%s reported %s, which is not planted", id, rule)
			}
		}
	}
}

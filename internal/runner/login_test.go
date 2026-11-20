package runner

import (
	"context"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"testing"

	"github.com/Gobbuwu/SiegeKit/internal/egress"
	"github.com/Gobbuwu/SiegeKit/internal/login"
	"github.com/Gobbuwu/SiegeKit/internal/target"
)

// TestLoginFindsPlantedIssue runs the login throttling check against the
// vulnerable app, with the real clock: the login without a limit is
// reported, and the one that locks the account is not.
func TestLoginFindsPlantedIssue(t *testing.T) {
	if testing.Short() {
		t.Skip("sends logins one per second")
	}
	srv := httptest.NewServer(vulnApp())
	defer srv.Close()
	tu, err := target.Parse(srv.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	cfg := egress.Config{Target: tu, Addrs: []netip.Addr{netip.MustParseAddr("127.0.0.1")}, Version: "test"}
	const attempts = 4
	l, err := login.Parse(srv.URL+"/account/sign-in", "tester@shop.test", `{"email":"{user}","password":"{password}"}`, tu)
	if err != nil {
		t.Fatal(err)
	}
	r, err := login.Check(context.Background(), cfg, l, attempts)
	if err != nil || r.Limited || r.Attempts != attempts {
		t.Fatalf("%+v %v", r, err)
	}
	found := map[string]bool{}
	for _, f := range login.Findings(l, r, attempts) {
		u, _ := url.Parse(f.Location.URI)
		found[f.RuleID+" "+u.Path] = true
	}
	for rule, issue := range vulnAppIssues[login.ID] {
		if !found[rule] {
			t.Errorf("missed %s (rule %s)", issue, rule)
		}
	}

	l, err = login.Parse(srv.URL+"/account/sign-in-limited", "tester", "username={user}&password={password}", tu)
	if err != nil {
		t.Fatal(err)
	}
	r, err = login.Check(context.Background(), cfg, l, attempts)
	if err != nil || !r.Limited || r.Attempts != 3 || r.Signal != "answered 423" || len(login.Findings(l, r, attempts)) != 0 {
		t.Errorf("limited login: %+v %v", r, err)
	}
}

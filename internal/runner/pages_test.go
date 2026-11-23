package runner

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/Gobbuwu/SiegeKit/internal/egress"
	"github.com/Gobbuwu/SiegeKit/internal/findings"
	"github.com/Gobbuwu/SiegeKit/internal/login"
	"github.com/Gobbuwu/SiegeKit/internal/mailcatcher"
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
	// The test app sends its reset emails to vulnMail, counted through a
	// Mailpit stand-in (ADR 0056).
	mp := httptest.NewServer(vulnMail)
	defer mp.Close()
	mu, err := mailcatcher.Parse(mp.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	catcher, err := mailcatcher.Open(context.Background(), nil, mu, "test")
	if err != nil {
		t.Fatal(err)
	}
	oq := mailcatcher.Quiet
	mailcatcher.Quiet = time.Second
	defer func() { mailcatcher.Quiet = oq }()
	for _, c := range []struct {
		p           ratelimit.Page
		path, body  string
		limited     bool
		wantFinding bool
		mail        bool
	}{
		{ratelimit.Reset, "/account/forgot-password-mailed", "email=tester%40shop.test", false, true, true},
		{ratelimit.Reset, "/account/forgot-password-mail-limited", "email=tester%40shop.test", false, false, true},
		{ratelimit.Reset, "/account/forgot-password", "email=tester%40shop.test", false, true, false},
		{ratelimit.Reset, "/account/forgot-password-limited", "email=tester%40shop.test", true, false, false},
		{ratelimit.SignUp, "/account/sign-up", "username={new}&password=Passw0rd%21", false, true, false},
		{ratelimit.Code, "/account/2fa", `{"code":"{wrong}"}`, false, true, false},
		{ratelimit.Code, "/account/2fa-limited", `{"code":"{wrong}"}`, true, false, false},
		{ratelimit.Code, "/account/2fa-loose", `{"code":"{wrong}"}`, true, true, false},
	} {
		e, err := ratelimit.ParsePage(c.p, srv.URL+c.path, c.body, tu)
		if err != nil {
			t.Fatal(err)
		}
		var mark mailcatcher.Mark
		if c.mail {
			if mark, err = catcher.Mark(context.Background()); err != nil {
				t.Fatal(err)
			}
		}
		r, err := ratelimit.Check(context.Background(), cfg, e, n)
		if c.mail && err == nil {
			tl, err := catcher.Settle(context.Background(), mark, r.To)
			if err != nil {
				t.Fatal(err)
			}
			r.Mail = &ratelimit.Mail{Catcher: mp.URL + "/", Emails: tl.Emails, Settled: tl.Settled}
		}
		fs := ratelimit.Findings(e, r, n)
		if err != nil || r.Limited != c.limited || (len(fs) > 0) != c.wantFinding || c.mail && r.MailLimited() == c.wantFinding {
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

// vulnMail is the test app's mail catcher: a Mailpit stand-in with
// v1.27.11's answers (internal/mailcatcher's testdata), newest first.
var vulnMail = &mailbox{}

type mailbox struct {
	mu sync.Mutex
	to []string
}

func (m *mailbox) add(to string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.to = append([]string{to}, m.to...)
}

func (m *mailbox) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	m.mu.Lock()
	defer m.mu.Unlock()
	switch r.URL.Path {
	case "/api/v1/info":
		fmt.Fprintf(w, `{"Version":"v1.27.11","Messages":%d}`, len(m.to))
	case "/api/v1/messages":
		start, _ := strconv.Atoi(r.URL.Query().Get("start"))
		limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
		msgs := []map[string]any{}
		for i := start; i < min(start+limit, len(m.to)); i++ {
			msgs = append(msgs, map[string]any{"ID": fmt.Sprintf("m%d", len(m.to)-i), "To": []map[string]string{{"Address": m.to[i]}}})
		}
		json.NewEncoder(w).Encode(map[string]any{"total": len(m.to), "messages": msgs})
	default:
		http.NotFound(w, r)
	}
}

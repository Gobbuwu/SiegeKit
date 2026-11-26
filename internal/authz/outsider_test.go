package authz

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/Gobbuwu/SiegeKit/internal/egress"
	"github.com/Gobbuwu/SiegeKit/internal/findings"
	"github.com/Gobbuwu/SiegeKit/internal/target"
)

// spaceApp is a test app shaped like the shared spaces measured on
// Rocket.Chat, Gitea and Mattermost (ADR 0051): alice and bob share
// project 5, carol is outside it, and "Bearer X" is an expired session.
//   - /api/projects/5: members read it and rename it (PUT), carol gets 403.
//   - /api/projects/5/deleted: any logged-in account reads it (the leak
//     Rocket.Chat's chat.getDeletedMessages has).
//   - /api/projects/5/topic: any logged-in account changes it (PUT).
//   - /api/projects/5/busy: carol always gets 429.
//   - /api/me: each account's own name.
func spaceApp(t *testing.T) (*httptest.Server, *[]string) {
	var mu sync.Mutex
	var seen []string
	name, topic := "secret-ab", "plans"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		who := map[string]string{"Bearer A": "alice", "Bearer B": "bob", "Bearer C": "carol"}[r.Header.Get("Authorization")]
		if r.Header.Get("X-Carol") != "" && who != "carol" {
			t.Errorf("carol's header sent as %q: %s %s", who, r.Method, r.URL.Path)
		}
		seen = append(seen, r.Method+" "+r.URL.Path+" "+who)
		if who == "" {
			http.Error(w, "log in first", http.StatusUnauthorized)
			return
		}
		member := who == "alice" || who == "bob"
		w.Header().Set("Content-Type", "application/json")
		switch r.Method + " " + r.URL.Path {
		case "GET /api/me":
			fmt.Fprintf(w, `{"name":%q}`, who)
		case "GET /api/projects/5":
			if !member {
				http.Error(w, `{"error":"not a member"}`, http.StatusForbidden)
				return
			}
			fmt.Fprintf(w, `{"id":5,"name":%q,"members":["alice","bob"]}`, name)
		case "PUT /api/projects/5":
			if !member {
				http.Error(w, `{"error":"not a member"}`, http.StatusForbidden)
				return
			}
			name += "!"
			fmt.Fprint(w, `{"success":true}`)
		case "GET /api/projects/5/deleted":
			fmt.Fprint(w, `{"ids":["m1","m2"]}`)
		case "GET /api/projects/5/topic":
			fmt.Fprintf(w, `{"topic":%q}`, topic)
		case "PUT /api/projects/5/topic":
			topic += "!"
			fmt.Fprint(w, `{"success":true}`)
		case "GET /api/projects/5/busy":
			if who == "carol" {
				http.Error(w, `{"error":"slow down"}`, http.StatusTooManyRequests)
				return
			}
			fmt.Fprint(w, `{"id":5,"unread":3}`)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, &seen
}

func spaceReads(t *testing.T, srv *httptest.Server) *HAR {
	t.Helper()
	var es []entry
	for _, p := range []string{"/api/me", "/api/projects/5", "/api/projects/5/deleted", "/api/projects/5/busy"} {
		es = append(es, entry{"GET", srv.URL + p})
	}
	h, err := ParseHAR(har(t, es, map[string]string{"Authorization": "Bearer A"}), mustTarget(t, srv.URL+"/"))
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func ruleList(fs []findings.Finding, origin string) []string {
	var out []string
	for _, f := range fs {
		out = append(out, f.RuleID+" "+strings.TrimPrefix(f.Location.URI, origin)+" "+f.Severity.String())
	}
	slices.Sort(out)
	return out
}

var (
	sessB = http.Header{"Authorization": {"Bearer B"}}
	sessC = http.Header{"Authorization": {"Bearer C"}, "X-Carol": {"1"}}
	sessX = http.Header{"Authorization": {"Bearer X"}}
)

func TestCheckWithC(t *testing.T) {
	srv, seen := spaceApp(t)
	noSleep(t)
	cfg := egress.Config{Target: mustTarget(t, srv.URL+"/"), Addrs: []netip.Addr{netip.MustParseAddr("127.0.0.1")}, Version: "test", ReadOnly: true}
	h := spaceReads(t, srv)
	// 16, and A's /api/me again (C's and B's answers line up with A's).
	res, err := Check(context.Background(), cfg, h.Requests, Accounts{B: sessB, C: sessC}, 10)
	if err != nil || !res.CTested || !res.CWorks() || res.Requests != 17 {
		t.Fatalf("%+v %v", res, err)
	}
	// C is sent before B, for every request: A, C, B, no login, and for
	// /api/me A again (the first request).
	for i := 0; i < len(*seen); i += 4 {
		if who := []string{(*seen)[i+1], (*seen)[i+2]}; !strings.HasSuffix(who[0], " carol") || !strings.HasSuffix(who[1], " bob") {
			t.Errorf("order %v", (*seen)[i:i+4])
		}
		if i == 0 {
			if (*seen)[4] != "GET /api/me alice" {
				t.Errorf("A's second read %v", (*seen)[:5])
			}
			i++
		}
	}
	fs := Findings(srv.URL, res, "alice")
	// The member's read of the shared project is low; the deleted list any
	// account reads is C's finding (high: an ID in the URL); carol's 429
	// says nothing, so bob's read there keeps its tier; /api/me differs
	// per account.
	want := []string{"b-only-read /api/projects/5 low", "cross-account-read /api/projects/5/busy high", "cross-account-read /api/projects/5/deleted high"}
	if got := ruleList(fs, srv.URL); !slices.Equal(got, want) {
		t.Errorf("findings %v, want %v", got, want)
	}
	for _, f := range fs {
		switch strings.TrimPrefix(f.Location.URI, srv.URL) {
		case "/api/projects/5":
			if !strings.Contains(f.Message, "account C (SIEGEKIT_SESSION_C") || !strings.Contains(f.Message, "status 403") || f.CWEs[0] != "CWE-639" {
				t.Errorf("%s", f.Message)
			}
		case "/api/projects/5/deleted":
			if !strings.Contains(f.Message, "answered account C") || !strings.Contains(f.Message, "Account B got the same answer.") {
				t.Errorf("%s", f.Message)
			}
		case "/api/projects/5/busy":
			if !strings.Contains(f.Message, "answered account B") || !strings.Contains(f.Message, "no clear answer (status 429)") {
				t.Errorf("%s", f.Message)
			}
		}
	}
	c := Count(res, "alice")
	if c != (Counts{Cross: 2, BOnly: 1}) {
		t.Errorf("count %+v", c)
	}
	if s := res.Summary(h, "alice", c); !strings.Contains(s, "2 readable by account C or B, 1 only by account B (low)") {
		t.Errorf("summary %q", s)
	}
}

func TestCheckOnlyC(t *testing.T) {
	srv, _ := spaceApp(t)
	noSleep(t)
	cfg := egress.Config{Target: mustTarget(t, srv.URL+"/"), Addrs: []netip.Addr{netip.MustParseAddr("127.0.0.1")}, Version: "test", ReadOnly: true}
	h := spaceReads(t, srv)
	// 12, and A's /api/me again: C's answer lines up with A's word by
	// word, so A's is read twice to tell noise from data (issue #95); the
	// name A got both times differs from C's, so it is not reported.
	res, err := Check(context.Background(), cfg, h.Requests, Accounts{C: sessC}, 10)
	if err != nil || res.BTested || res.Requests != 13 {
		t.Fatalf("%+v %v", res, err)
	}
	fs := Findings(srv.URL, res, "alice")
	if got := ruleList(fs, srv.URL); !slices.Equal(got, []string{"cross-account-read /api/projects/5/deleted high"}) {
		t.Errorf("%v", got)
	}
	if s := res.Summary(h, "alice", Count(res, "alice")); !strings.Contains(s, "1 readable by account C; account B not tested (SIEGEKIT_SESSION_B not set)") {
		t.Errorf("summary %q", s)
	}
}

// An expired C session gets the no-login answers everywhere: nothing of
// B's is lowered, and the summary says why.
func TestCheckExpiredC(t *testing.T) {
	srv, _ := spaceApp(t)
	noSleep(t)
	cfg := egress.Config{Target: mustTarget(t, srv.URL+"/"), Addrs: []netip.Addr{netip.MustParseAddr("127.0.0.1")}, Version: "test", ReadOnly: true}
	h := spaceReads(t, srv)
	res, err := Check(context.Background(), cfg, h.Requests, Accounts{B: sessB, C: sessX}, 10)
	if err != nil || res.CWorks() {
		t.Fatalf("%+v %v", res, err)
	}
	fs := Findings(srv.URL, res, "alice")
	want := []string{"cross-account-read /api/projects/5 high", "cross-account-read /api/projects/5/busy high", "cross-account-read /api/projects/5/deleted high"}
	if got := ruleList(fs, srv.URL); !slices.Equal(got, want) {
		t.Errorf("findings %v, want %v", got, want)
	}
	for _, f := range fs {
		if !strings.Contains(f.Message, "Account C was not compared: its session got the same status as a request with no login on every request") {
			t.Errorf("%s", f.Message)
		}
	}
	if s := res.Summary(h, "alice", Count(res, "alice")); !strings.Contains(s, "account C got the same status as a request with no login on every request, so its session may have expired") {
		t.Errorf("summary %q", s)
	}
}

func TestParseSessionC(t *testing.T) {
	if _, err := ParseSessionFrom(SessionEnvC, "no colon"); err == nil || !strings.Contains(err.Error(), "SIEGEKIT_SESSION_C must hold") {
		t.Errorf("%v", err)
	}
	if h, err := ParseSessionFrom(SessionEnvC, "Authorization: Bearer C\n"); err != nil || h.Get("Authorization") != "Bearer C" {
		t.Errorf("%v %v", h, err)
	}
}

func spaceWrites(srv *httptest.Server) []Write {
	a := http.Header{"Authorization": {"Bearer A"}, "Content-Type": {"application/json"}}
	return []Write{
		{Method: "PUT", Path: "/api/projects/5", Header: a, Body: []byte(`{"name":"x"}`), RecordedStatus: 200},
		{Method: "PUT", Path: "/api/projects/5/topic", Header: a, Body: []byte(`{"topic":"x"}`), RecordedStatus: 200},
	}
}

func TestWriteCheckWithC(t *testing.T) {
	srv, seen := spaceApp(t)
	noSleep(t)
	cfg := egress.Config{Target: mustTarget(t, srv.URL+"/"), Addrs: []netip.Addr{netip.MustParseAddr("127.0.0.1")}, Version: "test"}
	res, err := WriteCheck(context.Background(), cfg, spaceWrites(srv), Accounts{B: sessB, C: sessC}, "alice", 10, target.Local)
	if err != nil || !res.CTested || !res.CWorks() {
		t.Fatalf("%+v %v", res, err)
	}
	// The rename: no login and C refused first, then B accepted on A's
	// recorded project. The topic: no login refused, then C accepted on
	// A's recorded project, so B is not sent; no login always goes first,
	// so C's acceptance never keeps it from being sent (issue #95).
	var got []string
	for _, r := range res.Replays {
		got = append(got, fmt.Sprintf("%s %s %d %v", pathOf(r.Path), r.Who, r.Answer.Status, r.NotSent != ""))
	}
	want := []string{"/api/projects/5 no login 401 false", "/api/projects/5 C 403 false", "/api/projects/5 B 200 false",
		"/api/projects/5/topic no login 401 false", "/api/projects/5/topic C 200 false", "/api/projects/5/topic B 0 true"}
	if !slices.Equal(got, want) {
		t.Errorf("replays %v, want %v", got, want)
	}
	if n, c := slices.Index(*seen, "PUT /api/projects/5/topic "), slices.Index(*seen, "PUT /api/projects/5/topic carol"); n < 0 || c < n {
		t.Errorf("topic not sent with no login before C: %v", *seen)
	}
	fs := WriteFindings(srv.URL, res)
	if got := ruleList(fs, srv.URL); !slices.Equal(got, []string{"b-only-write /api/projects/5 low", "cross-account-write /api/projects/5/topic high"}) {
		t.Errorf("findings %v", got)
	}
	for _, f := range fs {
		if f.RuleID == "b-only-write" && (!strings.Contains(f.Message, "refused (status 403)") || !strings.Contains(f.Message, "Account A read the same URL twice before the replay and once after: it changed")) {
			t.Errorf("%s", f.Message)
		}
		if f.RuleID == "cross-account-write" && !strings.Contains(f.Message, "as account C (SIEGEKIT_SESSION_C") {
			t.Errorf("%s", f.Message)
		}
	}
	s := res.WriteSummary(nil)
	for _, part := range []string{"as account C, as account B and with no login", "1 high, 0 medium, 1 low (accepted for account B only)",
		"not sent as account B, because account C's replay was accepted on A's recorded object: PUT /api/projects/5/topic"} {
		if !strings.Contains(s, part) {
			t.Errorf("summary %q\nlacks %q", s, part)
		}
	}
}

func TestWriteCheckExpiredC(t *testing.T) {
	srv, _ := spaceApp(t)
	noSleep(t)
	cfg := egress.Config{Target: mustTarget(t, srv.URL+"/"), Addrs: []netip.Addr{netip.MustParseAddr("127.0.0.1")}, Version: "test"}
	res, err := WriteCheck(context.Background(), cfg, spaceWrites(srv)[:1], Accounts{B: sessB, C: sessX}, "alice", 10, target.Local)
	if err != nil || res.CWorks() {
		t.Fatalf("%+v %v", res, err)
	}
	fs := WriteFindings(srv.URL, res)
	if len(fs) != 1 || fs[0].RuleID != "cross-account-write" || fs[0].Severity != findings.High || !strings.Contains(fs[0].Message, "Account C was not compared: account C got the same status as a request with no login on every write sent both ways") {
		t.Errorf("%+v", fs)
	}
	if s := res.WriteSummary(nil); !strings.Contains(s, "so its session may have expired") {
		t.Errorf("%q", s)
	}
}

// WriteFindings on results no live app above gives: C's refusal with A's
// stale CSRF token, and B's proof folded into C's finding.
func TestWriteFindingsWithC(t *testing.T) {
	ok := Answer{Status: 200, Body: []byte(`{"success":true}`)}
	w := Write{Method: "PUT", Path: "/api/projects/5", RecordedStatus: 200}
	none := WriteReplay{Write: w, Who: AsNoLogin, Answer: Answer{Status: 401}}
	changed := func(r WriteReplay) WriteReplay {
		r.Read, r.Before, r.After = true, Answer{Status: 200, Body: []byte("a")}, Answer{Status: 200, Body: []byte("b")}
		return r
	}
	// C refused, but it carried A's CSRF token: B is not lowered.
	csrf := w
	csrf.CSRF = true
	res := WriteResult{CTested: true, BTested: true, Replays: []WriteReplay{
		{Write: csrf, Who: AsC, Answer: Answer{Status: 403}}, changed(WriteReplay{Write: csrf, Who: AsB, Answer: ok}), {Write: csrf, Who: AsNoLogin, Answer: Answer{Status: 401}},
	}}
	fs := WriteFindings("", res)
	if len(fs) != 1 || fs[0].RuleID != "cross-account-write" || fs[0].Severity != findings.High || !strings.Contains(fs[0].Message, "no page gave account C its own CSRF token") {
		t.Errorf("%+v", fs)
	}
	// C accepted with no visible change (medium), B's replay changed A's
	// read (high): one finding, high, with B's proof.
	res = WriteResult{CTested: true, BTested: true, Replays: []WriteReplay{
		{Write: w, Who: AsC, Answer: ok}, changed(WriteReplay{Write: w, Who: AsB, Answer: ok}), none,
	}}
	fs = WriteFindings("", res)
	if len(fs) != 1 || fs[0].Severity != findings.High || !strings.Contains(fs[0].Message, "the proof below is from B's replay") || !strings.Contains(fs[0].Message, "as account C") {
		t.Errorf("%+v", fs)
	}
	// Both accepted at the same tier: one finding, C's.
	res.Replays[1] = WriteReplay{Write: w, Who: AsB, Answer: ok}
	if fs = WriteFindings("", res); len(fs) != 1 || fs[0].Severity != findings.Medium || !strings.Contains(fs[0].Message, "Account B's replay was accepted too.") {
		t.Errorf("%+v", fs)
	}
	// C got a 500: B keeps its tier.
	res.Replays[0] = WriteReplay{Write: w, Who: AsC, Answer: Answer{Status: 500}}
	if fs = WriteFindings("", res); len(fs) != 1 || fs[0].RuleID != "cross-account-write" || !strings.Contains(fs[0].Message, "no clear answer (status 500)") {
		t.Errorf("%+v", fs)
	}
}

func TestSeenLoggedIn(t *testing.T) {
	for _, c := range []struct {
		c, none Answer
		want    bool
	}{
		{Answer{Status: 403}, Answer{Status: 401}, true},  // an outsider refused, no login asked to log in
		{Answer{Status: 400}, Answer{Status: 401}, true},  // Rocket.Chat's subscriptions.read for carol
		{Answer{Status: 401}, Answer{Status: 401}, false}, // an expired session
		{Answer{Status: 401}, Answer{Status: 303}, false}, // a bad token answered 401, no login redirected
		{Answer{Status: 302}, Answer{Status: 401}, false}, // a redirect, as to a login page
		{Answer{Status: 200}, Answer{Status: 200}, false}, // a public page, or Rocket.Chat's avatar DELETE
		{Answer{Status: 200}, Answer{Err: "x"}, false},
		{Answer{}, Answer{Status: 401}, false},
	} {
		if got := seenLoggedIn(c.c, c.none); got != c.want {
			t.Errorf("%+v %+v: %v", c.c, c.none, got)
		}
	}
	// An expired C that is accepted where anyone is (no login not sent
	// there) does not count as working.
	w := Write{Method: "DELETE", Path: "/avatar/room/5"}
	res := WriteResult{CTested: true, Replays: []WriteReplay{
		{Write: w, Who: AsC, Answer: Answer{Status: 200, Body: []byte("<svg/>")}},
		{Write: w, Who: AsNoLogin, NotSent: "account C's replay was accepted on account A's recorded object, which it may have changed or deleted"},
		{Write: w, Index: 1, Who: AsC, Answer: Answer{Status: 401}}, {Write: w, Index: 1, Who: AsNoLogin, Answer: Answer{Status: 401}},
	}}
	if res.CWorks() {
		t.Error("C counted as working")
	}
}

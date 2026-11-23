package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Gobbuwu/SiegeKit/internal/egress"
	"github.com/Gobbuwu/SiegeKit/internal/mailcatcher"
	"github.com/Gobbuwu/SiegeKit/internal/ratelimit"
	"github.com/Gobbuwu/SiegeKit/internal/report"
)

// mailbox is a Mailpit stand-in with v1.27.11's answers (see
// internal/mailcatcher's testdata): its version, and messages newest first.
type mailbox struct {
	mu   sync.Mutex
	to   []string // newest first
	gets []string
}

func (m *mailbox) add(to string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.to = append([]string{to}, m.to...)
}

func (m *mailbox) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.gets = append(m.gets, r.Method+" "+r.URL.Path)
	switch r.URL.Path {
	case "/api/v1/info":
		fmt.Fprintf(w, `{"Version":"v1.27.11","Messages":%d}`, len(m.to))
	case "/api/v1/messages":
		var start, limit int
		fmt.Sscan(r.URL.Query().Get("start"), &start)
		fmt.Sscan(r.URL.Query().Get("limit"), &limit)
		msgs := []map[string]any{}
		for i := start; i < min(start+limit, len(m.to)); i++ {
			msgs = append(msgs, map[string]any{"ID": fmt.Sprintf("m%d", len(m.to)-i), "To": []map[string]string{{"Address": m.to[i]}}})
		}
		json.NewEncoder(w).Encode(map[string]any{"total": len(m.to), "messages": msgs})
	default:
		http.NotFound(w, r)
	}
}

// TestScanURLMailCatcher: the reset and sign-up checks count the emails at
// --mail-catcher (ADR 0056).
func TestScanURLMailCatcher(t *testing.T) {
	old := resolver
	resolver = fakeResolver{"localhost": "127.0.0.1"}
	t.Cleanup(func() { resolver = old })
	oq, om, op := mailcatcher.Quiet, mailcatcher.Max, mailcatcher.Poll
	mailcatcher.Quiet, mailcatcher.Max, mailcatcher.Poll = 300*time.Millisecond, 2*time.Second, 50*time.Millisecond
	t.Cleanup(func() { mailcatcher.Quiet, mailcatcher.Max, mailcatcher.Poll = oq, om, op })
	scan := func(args ...string) (int, string) {
		t.Helper()
		var out, errb bytes.Buffer
		code := run(append([]string{"scan", "--no-save", "--authorized-host", "localhost"}, args...), &out, &errb)
		return code, out.String() + errb.String()
	}
	readReport := func() report.Run {
		t.Helper()
		b, err := os.ReadFile(filepath.Join("siegekit-report", "report.json"))
		var r report.Run
		if err != nil || json.Unmarshal(b, &r) != nil {
			t.Fatalf("report %v", err)
		}
		return r
	}
	plugin := func(r report.Run, id string) report.PluginResult {
		t.Helper()
		for _, p := range r.Plugins {
			if p.ID == id {
				return p
			}
		}
		t.Fatalf("no %s", id)
		return report.PluginResult{}
	}

	// Mistakes are refused before any request or audit entry.
	for _, c := range []struct {
		args []string
		code int
		want string
	}{
		{[]string{"--mail-catcher", "http://127.0.0.1:8025/?all=1", "http://localhost:3000/"}, exitInvalid, "--mail-catcher must not have a query"},
		{[]string{"--mail-catcher", "localhost:8025", "http://localhost:3000/"}, exitInvalid, "--mail-catcher"},
		{[]string{"--mail-catcher", "http://127.0.0.1:8025/", t.TempDir()}, exitUsage, "--mail-catcher, the --login flags"},
	} {
		f := useActive(t)
		data := useData(t)
		calls := useRateLimit(t, ratelimit.Result{}, nil)
		code, out := scan(c.args...)
		if code != c.code || !strings.Contains(out, c.want) || len(f.specs)+len(*calls) != 0 {
			t.Errorf("%v: exit %d\n%s", c.args, code, out)
		}
		if _, err := os.Stat(filepath.Join(data, "siegekit", "audit.log")); err == nil {
			t.Errorf("%v: audit entry written", c.args)
		}
	}

	// Gitea's case (1 email for 20 resets) and Mattermost's sign-up (an
	// email to each new address); the code page is not counted.
	box := &mailbox{}
	box.add("earlier@shop.test")
	srv := httptest.NewServer(box)
	defer srv.Close()
	var pages []ratelimit.Page
	oldCheck := rateLimitCheck
	rateLimitCheck = func(_ context.Context, _ egress.Config, e *ratelimit.Endpoint, n int) (ratelimit.Result, error) {
		pages = append(pages, e.Page)
		r := ratelimit.Result{Requests: n, Baseline: 200, Accepted: n}
		switch e.Page {
		case ratelimit.Reset:
			r.To = []string{"tester@shop.test"}
			go func() { time.Sleep(100 * time.Millisecond); box.add("tester@shop.test") }()
		case ratelimit.SignUp:
			for i := range n {
				a := fmt.Sprintf("siegekit-new-%d@example.com", i)
				r.To = append(r.To, a)
				box.add(a)
			}
			box.add("someone-else@shop.test") // not counted
		case ratelimit.Code:
			r.Baseline, r.Accepted = 401, 0
		}
		return r, nil
	}
	t.Cleanup(func() { rateLimitCheck = oldCheck })
	useActive(t)
	useData(t)
	code, out := scan(append(slices.Clone(pageArgs), "--fail-on", "low", "--mail-catcher", srv.URL+"/", "http://localhost:3000/")...)
	if code != report.ExitFindings || !slices.Equal(pages, ratelimit.Pages) {
		t.Fatalf("exit %d, %v\n%s", code, pages, out)
	}
	catcher := srv.URL + "/ (Mailpit v1.27.11)"
	if strings.Count(out, "then counts the emails that arrive at "+catcher+", waiting up to 2s") != 2 {
		t.Errorf("plan:\n%s", out)
	}
	r := readReport()
	reset, signup, codep := plugin(r, "reset-limit"), plugin(r, "signup-limit"), plugin(r, "code-limit")
	if reset.Input != "POST http://localhost:3000/rest/user/reset-password (from --reset-url); emails counted at "+catcher || reset.Findings != 0 ||
		reset.Result != "no 429, 503 or rate-limit header in 20 requests, all answered 200, but only 1 email arrived at the mail catcher "+srv.URL+"/ to the addresses sent for the 20 requests answered below 400: the app limits these emails" {
		t.Errorf("reset %+v", reset)
	}
	if signup.Findings != 1 || !strings.Contains(signup.Result, "; 20 emails arrived at the mail catcher "+srv.URL+"/ to the addresses sent for 20 requests answered below 400; 20 answered below 400, so up to 20 accounts were made") {
		t.Errorf("sign-up %+v", signup)
	}
	if strings.Contains(codep.Input, "emails counted") || strings.Contains(codep.Result, "mail catcher") {
		t.Errorf("code %+v", codep)
	}
	for _, g := range box.gets {
		if !strings.HasPrefix(g, "GET /api/v1/") {
			t.Errorf("sent %s to the mail catcher", g)
		}
	}

	// Something else at that address: the reset and sign-up checks fail
	// before sending anything; the code page still runs.
	other := httptest.NewServer(http.NotFoundHandler())
	defer other.Close()
	pages = nil
	useActive(t)
	useData(t)
	code, out = scan(append(slices.Clone(pageArgs), "--mail-catcher", other.URL+"/", "http://localhost:3000/")...)
	r = readReport()
	if code != report.ExitIncomplete || !slices.Equal(pages, []ratelimit.Page{ratelimit.Code}) {
		t.Errorf("not Mailpit: exit %d, %v\n%s", code, pages, out)
	}
	for _, id := range []string{"reset-limit", "signup-limit"} {
		if p := plugin(r, id); p.Status != report.Failed || !strings.Contains(p.Reason, "the mail catcher answered 404 to GET /api/v1/info") || !strings.Contains(p.Reason, "no request was sent to the") {
			t.Errorf("%s %+v", id, p)
		}
	}

	// No reset or sign-up check runs: the catcher is not asked anything.
	box.gets = nil
	useActive(t)
	useData(t)
	if code, out := scan("--code-url", "http://localhost:3000/c", "--code-body", "c={wrong}", "--only", "code-limit,reset-limit", "--mail-catcher", srv.URL+"/", "http://localhost:3000/"); code == exitInvalid || len(box.gets) != 0 {
		t.Errorf("unused: exit %d, %v\n%s", code, box.gets, out)
	}
}

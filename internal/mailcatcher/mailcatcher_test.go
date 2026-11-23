package mailcatcher

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeMailpit answers Mailpit's API as v1.27.11 does (testdata holds its
// real answers, captured 2026-11-23): info, and the message list newest
// first with start and limit.
type fakeMailpit struct {
	mu       sync.Mutex
	messages []map[string]any // newest first
	n        int
	gets     []string
	onList   func() // runs before each list answer
}

func (f *fakeMailpit) add(to ...string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.n++
	var as []map[string]string
	for _, a := range to {
		as = append(as, map[string]string{"Name": "", "Address": a})
	}
	m := map[string]any{"ID": fmt.Sprintf("id%04d", f.n), "To": as, "Cc": nil, "Bcc": nil, "Subject": "Recover your account"}
	f.messages = append([]map[string]any{m}, f.messages...)
}

func (f *fakeMailpit) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.gets = append(f.gets, r.Method+" "+r.URL.RequestURI())
	f.mu.Unlock()
	if r.Method != http.MethodGet {
		http.Error(w, "no", http.StatusMethodNotAllowed)
		return
	}
	switch strings.TrimPrefix(r.URL.Path, "/mp") {
	case "/api/v1/info":
		f.mu.Lock()
		fmt.Fprintf(w, `{"Version":"v1.27.11","Messages":%d,"Unread":0}`, len(f.messages))
		f.mu.Unlock()
	case "/api/v1/messages":
		if f.onList != nil {
			f.onList()
		}
		start, _ := strconv.Atoi(r.URL.Query().Get("start"))
		limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
		f.mu.Lock()
		defer f.mu.Unlock()
		end := min(start+limit, len(f.messages))
		page := []map[string]any{}
		if start < end {
			page = f.messages[start:end]
		}
		json.NewEncoder(w).Encode(map[string]any{"total": len(f.messages), "start": start, "count": len(page), "messages": page})
	default:
		http.NotFound(w, r)
	}
}

type fixedResolver map[string]string

func (r fixedResolver) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	if a, ok := r[host]; ok {
		return []netip.Addr{netip.MustParseAddr(a)}, nil
	}
	return nil, fmt.Errorf("no such host %s", host)
}

func open(t *testing.T, f http.Handler, base string) *Catcher {
	t.Helper()
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	u, err := Parse(srv.URL + base)
	if err != nil {
		t.Fatal(err)
	}
	c, err := Open(context.Background(), nil, u, "test")
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestParse(t *testing.T) {
	for raw, want := range map[string]string{
		"http://127.0.0.1:8025/":           "",
		"http://localhost:8025":            "",
		"https://mail.lan/mailpit/":        "",
		"http://127.0.0.1:8025/?x=1":       "must not have a query",
		"http://127.0.0.1:8025/#inbox":     "must not have a query or fragment",
		"http://user:pw@127.0.0.1:8025/":   "user name or password",
		"ftp://127.0.0.1/":                 "http:// or https://",
		"http://127.0.0.1:8025//evil.test": "single /",
		"127.0.0.1:8025":                   "--mail-catcher",
	} {
		_, err := Parse(raw)
		if want == "" && err != nil || want != "" && (err == nil || !strings.Contains(err.Error(), want)) {
			t.Errorf("Parse(%q) = %v, want %q", raw, err, want)
		}
	}
}

// TestOpen checks the address rules and that only Mailpit's answer is
// taken: SiegeKit counts at a local Mailpit, never at a hosted mailbox.
func TestOpen(t *testing.T) {
	f := &fakeMailpit{}
	c := open(t, f, "/")
	if c.Version != "v1.27.11" || !strings.Contains(c.String(), "(Mailpit v1.27.11)") {
		t.Errorf("version %q, %s", c.Version, c)
	}
	// A webroot (Mailpit's --webroot) is kept.
	c = open(t, f, "/mp/")
	if c.path("info") != "/mp/api/v1/info" {
		t.Errorf("path %s", c.path("info"))
	}
	for host, addr := range map[string]string{"mail.example": "93.184.215.14", "meta.example": "169.254.169.254"} {
		u, _ := Parse("http://" + host + ":8025/")
		if _, err := Open(context.Background(), fixedResolver{host: addr}, u, "test"); err == nil || !strings.Contains(err.Error(), "not on this machine or a private network") {
			t.Errorf("%s: %v", host, err)
		}
	}
	u, _ := Parse("http://nowhere.invalid:8025/")
	if _, err := Open(context.Background(), fixedResolver{}, u, "test"); err == nil || !strings.Contains(err.Error(), "could not be looked up") {
		t.Errorf("unresolvable: %v", err)
	}
	// Something else at the address: a 404 (Gitea's API), a page, JSON
	// that is not Mailpit's, a closed port.
	for name, h := range map[string]http.HandlerFunc{
		"404":   http.NotFound,
		"html":  func(w http.ResponseWriter, _ *http.Request) { fmt.Fprint(w, "<html>") },
		"json":  func(w http.ResponseWriter, _ *http.Request) { fmt.Fprint(w, `{"Version":"1.0"}`) },
		"login": func(w http.ResponseWriter, _ *http.Request) { http.Error(w, "auth", http.StatusUnauthorized) },
	} {
		srv := httptest.NewServer(h)
		u, _ := Parse(srv.URL + "/")
		if _, err := Open(context.Background(), nil, u, "test"); err == nil {
			t.Errorf("%s: opened", name)
		}
		srv.Close()
	}
	srv := httptest.NewServer(f)
	srv.Close()
	u, _ = Parse(srv.URL + "/")
	if _, err := Open(context.Background(), nil, u, "test"); err == nil || !strings.Contains(err.Error(), "did not answer") {
		t.Errorf("closed: %v", err)
	}
	// Only GETs were sent.
	for _, g := range f.gets {
		if !strings.HasPrefix(g, "GET ") {
			t.Errorf("sent %s", g)
		}
	}
}

// TestRealAnswers reads Mailpit v1.27.11's real answers (testdata).
func TestRealAnswers(t *testing.T) {
	info, err := os.ReadFile("testdata/info-v1.27.11.json")
	if err != nil {
		t.Fatal(err)
	}
	msgs, err := os.ReadFile("testdata/messages-v1.27.11.json")
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/api/v1/info":
			w.Write(info)
		case r.URL.Query().Get("start") == "0" || r.URL.Query().Get("limit") == "1":
			w.Write(msgs)
		default:
			fmt.Fprint(w, `{"total":22,"messages":[]}`)
		}
	}))
	defer srv.Close()
	u, _ := Parse(srv.URL + "/")
	c, err := Open(context.Background(), nil, u, "test")
	if err != nil || c.Version != "v1.27.11" {
		t.Fatalf("%v %+v", err, c)
	}
	m, err := c.Mark(context.Background())
	if err != nil || m.newest != "VSmMR8dzkFpdtfDZQXrAZA" {
		t.Fatalf("mark %+v %v", m, err)
	}
	// Counted from an empty mark: bob's and alice's, or bob's alone.
	for to, want := range map[string]int{"": 2, "BOB@siegekit.test": 1, "carol@siegekit.test": 0} {
		var list []string
		if to != "" {
			list = []string{to}
		}
		if n, err := c.Count(context.Background(), Mark{}, list); err != nil || n != want {
			t.Errorf("%q: %d %v", to, n, err)
		}
	}
}

func TestCount(t *testing.T) {
	ctx := context.Background()
	f := &fakeMailpit{}
	for range 3 {
		f.add("old@shop.test")
	}
	c := open(t, f, "/")
	m, err := c.Mark(ctx)
	if err != nil || m.newest != "id0003" {
		t.Fatalf("%+v %v", m, err)
	}
	// More than a page arrives: 60 for the account, 7 for others, one to
	// it as Cc and one as Bcc, in any case.
	for i := range 60 {
		if i%9 == 0 {
			f.add("someone@else.test")
		}
		f.add("tester@shop.test")
	}
	f.mu.Lock()
	f.messages[0]["To"], f.messages[0]["Cc"] = nil, []map[string]string{{"Address": "Tester@Shop.test"}}
	f.messages[1]["To"], f.messages[1]["Bcc"] = nil, []map[string]string{{"Address": "tester@shop.test"}}
	f.mu.Unlock()
	if n, err := c.Count(ctx, m, []string{"tester@shop.test"}); err != nil || n != 60 {
		t.Errorf("for the account: %d %v", n, err)
	}
	if n, err := c.Count(ctx, m, nil); err != nil || n != 67 {
		t.Errorf("any address: %d %v", n, err)
	}
	// An empty catcher: every message is new.
	f2 := &fakeMailpit{}
	c2 := open(t, f2, "/")
	m2, _ := c2.Mark(ctx)
	f2.add("tester@shop.test")
	if n, err := c2.Count(ctx, m2, []string{"tester@shop.test"}); err != nil || n != 1 || m2.newest != "" {
		t.Errorf("empty: %d %v %+v", n, err, m2)
	}
	// Messages that arrive while the pages are read move them: none is
	// counted twice.
	f.onList = func() { f.add("tester@shop.test") }
	n, err := c.Count(ctx, m, []string{"tester@shop.test"})
	if err != nil || n < 60 || n > 62 {
		t.Errorf("arriving: %d %v", n, err)
	}
	f.onList = nil
	// The marked message is gone (deleted, or pushed out by Mailpit's
	// limit): no count, rather than a wrong one.
	f.mu.Lock()
	f.messages = f.messages[:10]
	f.mu.Unlock()
	if _, err := c.Count(ctx, m, nil); err == nil || !strings.Contains(err.Error(), "is gone") {
		t.Errorf("gone: %v", err)
	}
	// More than 500 new ones: refused, not cut short.
	f3 := &fakeMailpit{}
	f3.add("old@shop.test")
	c3 := open(t, f3, "/")
	m3, _ := c3.Mark(ctx)
	for range 501 {
		f3.add("tester@shop.test")
	}
	if _, err := c3.Count(ctx, m3, nil); err == nil || !strings.Contains(err.Error(), "more than 500") {
		t.Errorf("over 500: %v", err)
	}
	for _, g := range slices.Concat(f.gets, f2.gets, f3.gets) {
		if !strings.HasPrefix(g, "GET /api/v1/") {
			t.Errorf("sent %s", g)
		}
	}
}

// TestSettle checks the waits with a fixed clock: the count stops when no
// email arrived for Quiet, or at Max while they keep arriving.
func TestSettle(t *testing.T) {
	ctx := context.Background()
	clock := time.Unix(0, 0)
	oldNow, oldSleep := now, sleep
	t.Cleanup(func() { now, sleep = oldNow, oldSleep })
	now = func() time.Time { return clock }
	f := &fakeMailpit{}
	c := open(t, f, "/")
	m, _ := c.Mark(ctx)
	// Two emails arrive 1 s and 3 s after the last request.
	polls := 0
	sleep = func(_ context.Context, d time.Duration) error {
		clock = clock.Add(d)
		polls++
		if polls == 1 || polls == 3 {
			f.add("tester@shop.test")
		}
		return nil
	}
	tl, err := c.Settle(ctx, m, []string{"tester@shop.test"})
	if err != nil || tl.Emails != 2 || !tl.Settled || tl.Waited != 3*time.Second+Quiet {
		t.Errorf("late emails: %+v %v", tl, err)
	}
	// None arrives: Quiet, then 0.
	m, _ = c.Mark(ctx)
	sleep = func(_ context.Context, d time.Duration) error { clock = clock.Add(d); return nil }
	if tl, err := c.Settle(ctx, m, nil); err != nil || tl.Emails != 0 || !tl.Settled || tl.Waited != Quiet {
		t.Errorf("none: %+v %v", tl, err)
	}
	// One arrives every second: SiegeKit stops at Max and says so.
	m, _ = c.Mark(ctx)
	sleep = func(_ context.Context, d time.Duration) error { clock = clock.Add(d); f.add("x@shop.test"); return nil }
	if tl, err := c.Settle(ctx, m, nil); err != nil || tl.Settled || tl.Waited != Max || tl.Emails != int(Max/Poll) {
		t.Errorf("still arriving: %+v %v", tl, err)
	}
	// A cancel stops it.
	cctx, cancel := context.WithCancel(ctx)
	cancel()
	sleep = oldSleep
	if _, err := c.Settle(cctx, m, nil); err == nil {
		t.Error("cancelled: no error")
	}
}

func TestAddresses(t *testing.T) {
	for _, c := range []struct {
		body string
		form bool
		want []string
	}{
		{"email=tester%40shop.test&answer=x", true, []string{"tester@shop.test"}},
		{"user_name=siegekit-new-ab&email=siegekit-new-ab%40example.com&password=a%40b", true, []string{"siegekit-new-ab@example.com"}},
		{`{"email":"Tester@Shop.test","answer":"siegekit-wrong-x"}`, false, []string{"tester@shop.test"}},
		{`{"a":"one@x.test","b":["two+tag@y.test."]}`, false, []string{"one@x.test", "two+tag@y.test"}},
		{"username=tester&answer=x", true, nil},
		{`{"note":"a@b","x":"@x.test","y":"a@@b.test"}`, false, nil},
		{"email=a+b%40x.test", true, []string{"b@x.test"}}, // a form's + is a space: "a b@x.test"
	} {
		if got := Addresses([]byte(c.body), c.form); !slices.Equal(got, c.want) {
			t.Errorf("Addresses(%q) = %q, want %q", c.body, got, c.want)
		}
	}
}

func FuzzAddresses(f *testing.F) {
	f.Add([]byte("email=tester%40shop.test"), true)
	f.Add([]byte(`{"email":"a@b.test"}`), false)
	f.Fuzz(func(t *testing.T, body []byte, form bool) {
		for _, a := range Addresses(body, form) {
			at := strings.IndexByte(a, '@')
			if at <= 0 || at != strings.LastIndexByte(a, '@') || !strings.Contains(a[at:], ".") || a != strings.ToLower(a) {
				t.Fatalf("%q from %q", a, body)
			}
		}
	})
}

package ratelimit

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Gobbuwu/SiegeKit/internal/egress"
	"github.com/Gobbuwu/SiegeKit/internal/findings"
	"github.com/Gobbuwu/SiegeKit/internal/target"
)

func mustTarget(t *testing.T, raw string) *target.URL {
	t.Helper()
	u, err := target.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func TestParse(t *testing.T) {
	tu := mustTarget(t, "http://localhost:3000/app/")
	g, err := Parse("http://localhost:3000/rest/products/search?q=apple%20juice", "", tu)
	if err != nil {
		t.Fatal(err)
	}
	if g.Method != http.MethodGet || g.Path != "/rest/products/search?q=apple%20juice" || g.URL != "http://localhost:3000/rest/products/search?q=apple%20juice" || g.ContentType() != "" || g.body != nil {
		t.Errorf("GET %+v", g)
	}
	j, err := Parse("http://localhost:3000/api/ask", ` {"q":"hi"}`, tu)
	if err != nil || j.Method != http.MethodPost || j.ContentType() != "application/json" || string(j.body) != ` {"q":"hi"}` || j.Path != "/api/ask" {
		t.Errorf("JSON %+v %v", j, err)
	}
	f, err := Parse("http://localhost:3000/search", "q=a&page=2", tu)
	if err != nil || f.Method != http.MethodPost || f.ContentType() != "application/x-www-form-urlencoded" {
		t.Errorf("form %+v %v", f, err)
	}
	for _, c := range []struct{ url, body, want string }{
		{"http://localhost:3001/search", "", "not on the target's origin"},
		{"https://localhost:3000/search", "", "not on the target's origin"},
		{"http://evil.test/search", "", "not on the target's origin"},
		{"http://localhost:3000/search#x", "", "fragment"},
		{"ftp://localhost:3000/search", "", "--rate-limit-url"},
		{"http://localhost:3000/search?q=%zz", "", "invalid query"},
		{"http://localhost:3000/search?q=a b", "", "spaces"},
		{"http://localhost:3000//evil.test/", "", "single /"},
		{"http://localhost:3000/search", `{"q":`, "not valid JSON"},
		{"http://localhost:3000/search", "q=%zz", "not valid JSON or a valid form body"},
		{"http://localhost:3000/search", "q=" + strings.Repeat("x", 8<<10), "longer than"},
	} {
		if _, err := Parse(c.url, c.body, tu); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("Parse(%q, %.40q): %v, want %q", c.url, c.body, err, c.want)
		}
	}
}

func TestSignal(t *testing.T) {
	for _, c := range []struct {
		status int
		h      http.Header
		want   string
	}{
		{200, nil, ""},
		{400, http.Header{"X-Request-Id": {"1"}, "Ratelimiter": {"x"}}, ""},
		{429, nil, "answered 429"},
		{503, nil, "answered 503"},
		{200, http.Header{"Retry-After": {"30"}}, "Retry-After"},
		{200, http.Header{"Ratelimit": {"limit=100, remaining=99, reset=50"}}, "a Ratelimit header"},
		{200, http.Header{"Ratelimit-Policy": {"100;w=300"}}, "a Ratelimit-Policy header"},
		{200, http.Header{"X-Ratelimit-Remaining": {"99"}}, "a X-Ratelimit-Remaining header"},
		{200, http.Header{"x-ratelimit-limit": {"100"}}, "a X-Ratelimit-Limit header"},
	} {
		if got := Signal(c.status, c.h); (c.want == "") != (got == "") || !strings.Contains(got, c.want) {
			t.Errorf("Signal(%d, %v) = %q, want %q", c.status, c.h, got, c.want)
		}
	}
}

// fake replaces send and sleep: answer(i) answers the i-th request (from 0).
type fake struct {
	mu    sync.Mutex
	sent  int
	waits []time.Duration
}

func (f *fake) install(t *testing.T, e *Endpoint, answer func(i int) (*egress.Answer, error)) {
	oldSend, oldSleep, oldNow := send, sleep, now
	t.Cleanup(func() { send, sleep, now = oldSend, oldSleep, oldNow })
	start := time.Now()
	now = func() time.Time { return start }
	send = func(ctx context.Context, cfg egress.Config, method, path, ct string, body []byte, max int64) (*egress.Answer, error) {
		f.mu.Lock()
		defer f.mu.Unlock()
		if method != e.Method || path != e.Path || ct != e.ContentType() || string(body) != string(e.body) || max != MaxAnswer {
			t.Errorf("sent %s %s %q %q max %d", method, path, ct, body, max)
		}
		f.sent++
		a, err := answer(f.sent - 1)
		if a != nil && a.Header == nil {
			a.Header = http.Header{}
		}
		return a, err
	}
	sleep = func(ctx context.Context, d time.Duration) error {
		f.waits = append(f.waits, d)
		return nil
	}
}

func testEndpoint(t *testing.T, body string) (*Endpoint, egress.Config) {
	tu := mustTarget(t, "http://localhost:3000/")
	e, err := Parse("http://localhost:3000/search?q=x", body, tu)
	if err != nil {
		t.Fatal(err)
	}
	return e, egress.Config{Target: tu, Addrs: []netip.Addr{netip.MustParseAddr("127.0.0.1")}, Version: "test"}
}

func answer(status int, h http.Header) *egress.Answer {
	return &egress.Answer{Status: status, Header: h, Body: []byte("ok"), Took: 5 * time.Millisecond}
}

func TestCheckNoLimit(t *testing.T) {
	e, cfg := testEndpoint(t, "")
	var f fake
	f.install(t, e, func(int) (*egress.Answer, error) { return answer(200, nil), nil })
	r, err := Check(context.Background(), cfg, e, DefaultRequests)
	if err != nil || r.Limited || r.Requests != DefaultRequests || r.Baseline != 200 {
		t.Fatalf("%+v %v", r, err)
	}
	if f.sent != DefaultRequests || len(f.waits) != DefaultRequests-1 {
		t.Fatalf("%d requests, %d waits", f.sent, len(f.waits))
	}
	for _, w := range f.waits {
		if w != Interval {
			t.Errorf("waited %s before a request, want %s", w, Interval)
		}
	}
	fs := Findings(e, r, DefaultRequests)
	if len(fs) != 1 || fs[0].RuleID != "rate-not-limited" || fs[0].Severity != findings.Low || fs[0].CWEs[0] != "CWE-770" ||
		fs[0].Location.URI != "http://localhost:3000/search" || fs[0].Sources[0].Plugin != ID || fs[0].Fingerprint == "" ||
		!strings.Contains(fs[0].Message, "20 GET requests") || !strings.Contains(fs[0].Message, "all answered 200") {
		t.Errorf("%+v", fs)
	}
	if s := r.Summary(DefaultRequests); s != "no limit seen in 20 requests, all answered 200 with no rate-limit header" {
		t.Error(s)
	}
	// A client error the app gives to every request (a 400 for a missing
	// parameter) is still a baseline: the same request, never limited.
	f = fake{}
	f.install(t, e, func(int) (*egress.Answer, error) { return answer(400, nil), nil })
	if r, err := Check(context.Background(), cfg, e, 3); err != nil || r.Limited || r.Baseline != 400 {
		t.Errorf("400: %+v %v", r, err)
	}
	// A POST sends its body each time.
	p, cfg := testEndpoint(t, `{"q":"x"}`)
	f = fake{}
	f.install(t, p, func(int) (*egress.Answer, error) { return answer(201, nil), nil })
	if r, err := Check(context.Background(), cfg, p, 3); err != nil || r.Requests != 3 || f.sent != 3 || !strings.Contains(Findings(p, r, 3)[0].Message, "3 POST requests") {
		t.Errorf("POST: %+v %v", r, err)
	}
}

func TestCheckLimited(t *testing.T) {
	for _, c := range []struct {
		name  string
		after *egress.Answer // the 4th answer
		want  string
	}{
		{"429", answer(429, nil), "answered 429"},
		{"503", answer(503, nil), "answered 503"},
		{"retry-after", answer(200, http.Header{"Retry-After": {"30"}}), "Retry-After"},
		{"draft header", answer(200, http.Header{"Ratelimit-Remaining": {"0"}}), "Ratelimit-Remaining"},
		{"x header", answer(200, http.Header{"X-Ratelimit-Remaining": {"0"}}), "X-Ratelimit-Remaining"},
	} {
		t.Run(c.name, func(t *testing.T) {
			e, cfg := testEndpoint(t, "")
			var f fake
			f.install(t, e, func(i int) (*egress.Answer, error) {
				if i == 3 {
					return c.after, nil
				}
				return answer(200, nil), nil
			})
			r, err := Check(context.Background(), cfg, e, DefaultRequests)
			if err != nil || !r.Limited || r.Requests != 4 || !strings.Contains(r.Signal, c.want) {
				t.Fatalf("%+v %v, want signal %q", r, err, c.want)
			}
			// The check stops at the first sign of a limit.
			if f.sent != 4 || Findings(e, r, DefaultRequests) != nil {
				t.Errorf("%d requests sent", f.sent)
			}
			if !strings.HasPrefix(r.Summary(DefaultRequests), "limit seen after 4 of 20 requests: ") {
				t.Error(r.Summary(DefaultRequests))
			}
		})
	}
	// A header on the first answer (Juice Shop's limit of 100 per 5
	// minutes, which a burst of 20 never reaches) counts, and says so.
	e, cfg := testEndpoint(t, "")
	var f fake
	f.install(t, e, func(int) (*egress.Answer, error) {
		return answer(200, http.Header{"X-Ratelimit-Limit": {"100"}, "X-Ratelimit-Remaining": {"99"}}), nil
	})
	r, err := Check(context.Background(), cfg, e, DefaultRequests)
	if err != nil || !r.Limited || r.Requests != 1 || f.sent != 1 || !strings.Contains(r.Signal, "already at the first request") {
		t.Errorf("%+v %v", r, err)
	}
}

func TestCheckFails(t *testing.T) {
	for _, c := range []struct {
		name   string
		answer func(i int) (*egress.Answer, error)
		want   string
		sent   int
	}{
		{"401", func(int) (*egress.Answer, error) { return answer(401, nil), nil }, "needs a login", 1},
		{"403", func(int) (*egress.Answer, error) { return answer(403, nil), nil }, "needs a login", 1},
		{"404", func(int) (*egress.Answer, error) { return answer(404, nil), nil }, "answered 404 to a GET", 1},
		{"405", func(int) (*egress.Answer, error) { return answer(405, nil), nil }, "answered 405", 1},
		{"501", func(int) (*egress.Answer, error) { return answer(501, nil), nil }, "answered 501", 1},
		{"500 first", func(int) (*egress.Answer, error) { return answer(500, nil), nil }, "a server error", 1},
		{"no answer", func(int) (*egress.Answer, error) { return nil, io.EOF }, "did not answer", 1},
		{"500 later", func(i int) (*egress.Answer, error) {
			if i == 2 {
				return answer(500, nil), nil
			}
			return answer(200, nil), nil
		}, "answered 500 (a server error) after 2 request(s)", 3},
		{"stops answering", func(i int) (*egress.Answer, error) {
			if i == 2 {
				return nil, io.EOF
			}
			return answer(200, nil), nil
		}, "stopped answering after 2 request(s)", 3},
	} {
		t.Run(c.name, func(t *testing.T) {
			e, cfg := testEndpoint(t, "")
			var f fake
			f.install(t, e, c.answer)
			if _, err := Check(context.Background(), cfg, e, DefaultRequests); err == nil || !strings.Contains(err.Error(), c.want) {
				t.Errorf("%v, want %q", err, c.want)
			}
			if f.sent != c.sent {
				t.Errorf("%d requests sent, want %d", f.sent, c.sent)
			}
		})
	}
	// An answer cut at MaxAnswer still counts as an answer.
	e, cfg := testEndpoint(t, "")
	var f fake
	f.install(t, e, func(int) (*egress.Answer, error) { return answer(200, nil), egress.ErrTooLarge })
	if r, err := Check(context.Background(), cfg, e, 3); err != nil || r.Requests != 3 {
		t.Errorf("too large: %+v %v", r, err)
	}
}

// The request count and read-only (deployed) targets are checked before
// any request is sent; a GET is allowed on a read-only target.
func TestCheckLimits(t *testing.T) {
	e, cfg := testEndpoint(t, "q=x")
	var f fake
	f.install(t, e, func(int) (*egress.Answer, error) { return answer(200, nil), nil })
	for _, n := range []int{-1, 0, 1, MaxRequests + 1, 1000} {
		if _, err := Check(context.Background(), cfg, e, n); err == nil {
			t.Errorf("%d requests accepted", n)
		}
	}
	cfg.ReadOnly = true
	if _, err := Check(context.Background(), cfg, e, DefaultRequests); err == nil || !strings.Contains(err.Error(), "does not allow") {
		t.Errorf("read-only target: %v", err)
	}
	if f.sent != 0 {
		t.Errorf("%d requests sent", f.sent)
	}
	cfg.ReadOnly = false
	if r, err := Check(context.Background(), cfg, e, MaxRequests); err != nil || r.Requests != MaxRequests || f.sent != MaxRequests {
		t.Errorf("%+v %v, %d sent", r, err, f.sent)
	}
	g, cfg := testEndpoint(t, "")
	cfg.ReadOnly = true
	f = fake{}
	f.install(t, g, func(int) (*egress.Answer, error) { return answer(200, nil), nil })
	if r, err := Check(context.Background(), cfg, g, 2); err != nil || r.Requests != 2 {
		t.Errorf("read-only GET: %+v %v", r, err)
	}
}

// A real server and the real clock: requests arrive at least a second
// apart, with the query and body as given.
func TestCheckRate(t *testing.T) {
	var mu sync.Mutex
	var times []time.Time
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		times = append(times, time.Now())
		mu.Unlock()
		b, _ := io.ReadAll(r.Body)
		if r.Method != http.MethodPost || r.URL.Path != "/search" || r.URL.RawQuery != "page=2" || r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" || string(b) != "q=apple" {
			t.Errorf("%s %s %s %q", r.Method, r.URL, r.Header.Get("Content-Type"), b)
		}
	}))
	defer srv.Close()
	tu := mustTarget(t, srv.URL+"/")
	e, err := Parse(srv.URL+"/search?page=2", "q=apple", tu)
	if err != nil {
		t.Fatal(err)
	}
	cfg := egress.Config{Target: tu, Addrs: []netip.Addr{netip.MustParseAddr("127.0.0.1")}, Version: "test"}
	r, err := Check(context.Background(), cfg, e, 3)
	if err != nil || r.Limited || r.Requests != 3 || r.Baseline != 200 {
		t.Fatalf("%+v %v", r, err)
	}
	if len(times) != 3 {
		t.Fatalf("%d requests arrived", len(times))
	}
	for i := 1; i < len(times); i++ {
		if d := times[i].Sub(times[i-1]); d < 950*time.Millisecond {
			t.Errorf("requests %d and %d arrived %s apart", i, i+1, d)
		}
	}
	// Interrupting the run stops the wait.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Check(ctx, cfg, e, 3); err == nil {
		t.Error("a cancelled run kept going")
	}
}

// FuzzParse checks that an accepted URL stays on the target's origin, that
// the request path starts with a single /, and that a body is sent as given.
func FuzzParse(f *testing.F) {
	for _, s := range []string{"http://localhost:3000/search?q=x", "http://localhost:3000//evil.test/", "http://localhost:3000/a?b", "http://localhost:3000@evil.test/", "http://localhost:3000/%2e%2e/"} {
		f.Add(s, "")
		f.Add(s, `{"q":1}`)
	}
	tu, _ := target.Parse("http://localhost:3000/")
	f.Fuzz(func(t *testing.T, raw, body string) {
		e, err := Parse(raw, body, tu)
		if err != nil {
			return
		}
		if !strings.HasPrefix(e.URL, "http://localhost:3000/") || !strings.HasPrefix(e.Path, "/") || strings.HasPrefix(e.Path, "//") || string(e.body) != body {
			t.Errorf("Parse(%q, %q) = %+v", raw, body, e)
		}
		if (body == "") != (e.Method == http.MethodGet) {
			t.Errorf("Parse(%q, %q): method %s", raw, body, e.Method)
		}
	})
}

package egress

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Gobbuwu/SiegeKit/internal/target"
)

// blockApp stands in for an app whose host starts answering every request
// with one 403 page from request after (counted without the watch's own
// fetches), as Vercel's Security Checkpoint did (ADR 0071). Before that,
// "/" answers 200 and other paths a 404 not-found page. The block page is
// 25,000 bytes plus up to 10, different on every answer, like the real one.
type blockApp struct {
	srv     *httptest.Server
	after   atomic.Int64 // 0: never blocks
	lift    atomic.Bool  // the block ends at the next start-page fetch after it began
	gzip    atomic.Bool  // answers are gzipped when the request accepts gzip
	n       atomic.Int64 // requests counted, without start-page fetches
	pages   atomic.Int64 // start-page fetches
	blocked atomic.Int64 // block pages answered to counted requests
	mu      sync.Mutex
	agents  []string // User-Agent of each start-page fetch
	headers []string // X-Bypass of each start-page fetch
	on      bool
}

func newBlockApp(t *testing.T, after int64) *blockApp {
	t.Helper()
	a := &blockApp{}
	a.after.Store(after)
	a.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		page := strings.HasSuffix(r.UserAgent(), startPageAgent)
		var i int64
		if page {
			a.pages.Add(1)
			a.mu.Lock()
			a.agents = append(a.agents, r.UserAgent())
			a.headers = append(a.headers, r.Header.Get("X-Bypass"))
			a.mu.Unlock()
		} else {
			i = a.n.Add(1)
		}
		a.mu.Lock()
		if after := a.after.Load(); !page && after > 0 && i >= after {
			a.on = true
		}
		on := a.on
		if on && page && a.lift.Load() {
			a.on = false
		}
		a.mu.Unlock()
		if on {
			if !page {
				a.blocked.Add(1)
			}
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			body := strings.Repeat("c", 25000+int(i%11))
			if a.gzip.Load() && strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
				var b bytes.Buffer
				z := gzip.NewWriter(&b)
				z.Write([]byte(body))
				z.Close()
				body = b.String()
				w.Header().Set("Content-Encoding", "gzip")
			}
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprint(w, body)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if r.URL.Path != "/" {
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprint(w, "<h1>404: This page could not be found.</h1>")
			return
		}
		fmt.Fprint(w, "<html>the app</html>")
	}))
	t.Cleanup(a.srv.Close)
	return a
}

func (a *blockApp) config(t *testing.T) Config {
	t.Helper()
	su, _ := url.Parse(a.srv.URL)
	port, _ := strconv.Atoi(su.Port())
	tu, err := target.Parse(fmt.Sprintf("http://app.test:%d/", port))
	if err != nil {
		t.Fatal(err)
	}
	return Config{
		Target: tu, Addrs: []netip.Addr{netip.MustParseAddr("127.0.0.1")},
		Client: netip.MustParsePrefix("127.0.0.0/8"),
		Rate:   1000, Burst: 100, MaxConns: 8, MaxServerErrors: 5, Version: "test",
	}
}

func TestShapeLike(t *testing.T) {
	page := Shape{403, "text/html", 25124}
	for _, c := range []struct {
		s    Shape
		want bool
	}{
		{Shape{403, "text/html", 25134}, true},  // Vercel's checkpoint, 10 bytes apart
		{Shape{403, "text/html", 23868}, true},  // 5% of the longer
		{Shape{403, "text/html", 23867}, false}, // more than 5%
		{Shape{404, "text/html", 25124}, false},
		{Shape{403, "application/json", 25124}, false},
		{Shape{403, "text/html", -1}, false},
	} {
		if got := page.Like(c.s); got != c.want {
			t.Errorf("%v like %v = %v", page, c.s, got)
		}
	}
	b := &Block{Page: page}
	if !b.Matches(403, 25130) || b.Matches(200, 25124) || b.Matches(403, 1000) || (&Block{}).Matches(0, 0) || (*Block)(nil).Matches(403, 25124) {
		t.Error("Matches")
	}
}

// TestWatchBeginEnd checks D1: the run's first check records the start
// page; a later check whose start page has another status, or cannot be
// fetched, is blocked before it sends anything; End fetches it again.
func TestWatchBeginEnd(t *testing.T) {
	a := newBlockApp(t, 0)
	cfg := a.config(t)
	cfg.Header = http.Header{"X-Bypass": {"secret-value"}}
	w := NewWatch(cfg)
	ctx := context.Background()
	u := w.Begin(ctx)
	if u.Block() != nil || u.End(ctx) != nil {
		t.Fatal("blocked with no block")
	}
	a.after.Store(1)
	a.n.Store(0)
	if _, err := Send(ctx, cfg, http.MethodGet, "/x", "", nil, 1<<20); err != nil { // turns the block on
		t.Fatal(err)
	}
	u = w.Begin(ctx)
	b := u.Block()
	if b == nil || b.Page.Status != 403 || !strings.Contains(b.Reason, "before this check: the start page answered 403 (text/html, 250") || !strings.Contains(b.Reason, "first check it answered 200") {
		t.Fatalf("block %+v", b)
	}
	if u.End(ctx) != b {
		t.Error("End must keep the block")
	}
	a.mu.Lock()
	for i := range a.agents {
		if a.agents[i] != "SiegeKit/test (start page check)" || a.headers[i] != "secret-value" {
			t.Errorf("start-page fetch %d: agent %q, extra header %q", i, a.agents[i], a.headers[i])
		}
	}
	a.mu.Unlock()

	// D1 after: the block began in the check's last answers.
	a2 := newBlockApp(t, 0)
	cfg2 := a2.config(t)
	w2 := NewWatch(cfg2)
	u2 := w2.Begin(ctx)
	cfg2.Watch = u2
	a2.after.Store(3)
	for range 3 {
		if _, err := Send(ctx, cfg2, http.MethodGet, "/x", "", nil, 1<<20); err != nil {
			t.Fatal(err)
		}
	}
	if b := u2.End(ctx); b == nil || !strings.Contains(b.Reason, "during this check: after it, the start page answered 403") {
		t.Fatalf("End: %+v", b)
	}

	// A start page that cannot be fetched blocks the next check.
	w3 := NewWatch(cfg2)
	w3.cfg.Addrs = []netip.Addr{netip.MustParseAddr("127.0.0.1")}
	a2.srv.Close()
	if b := w3.Begin(ctx).Block(); b == nil || b.Page.Status != 0 || !strings.Contains(b.Reason, "could not be fetched") {
		t.Errorf("unreachable start page: %+v", b)
	}

	// A nil watch watches nothing.
	var nw *Watch
	if nu := nw.Begin(ctx); nu != nil || nu.Block() != nil || nu.End(ctx) != nil || nu.answer(ctx, Shape{}) != nil {
		t.Error("nil watch")
	}
}

// TestWatchSendStops checks D3 on SiegeKit's own checks: after
// StreakAnswers block pages in a row the start page is fetched, Send
// returns a BlockedError for that answer, and later requests are not sent.
func TestWatchSendStops(t *testing.T) {
	a := newBlockApp(t, 0)
	cfg := a.config(t)
	ctx := context.Background()
	cfg.Watch = NewWatch(cfg).Begin(ctx)
	a.after.Store(21)
	var got error
	var last *Answer
	sent := 0
	for i := range 100 {
		ans, err := Send(ctx, cfg, http.MethodGet, fmt.Sprintf("/p%d", i), "", nil, 1<<20)
		if err != nil {
			got, last = err, ans
			break
		}
		sent++
	}
	// The answer that set off the stop is returned without its body, so
	// the caller counts it as answered by the target.
	if last == nil || last.Status != http.StatusForbidden || last.Body != nil {
		t.Errorf("the stopping answer: %+v", last)
	}
	var be *BlockedError
	if !errors.As(got, &be) || !strings.Contains(got.Error(), "stopped by SiegeKit: the host stopped serving the app: 10 answers in a row and the start page were the same page, 403 (text/html,") {
		t.Fatalf("after %d: %v", sent, got)
	}
	if n := a.blocked.Load(); n != StreakAnswers {
		t.Errorf("%d block pages answered before the stop, want %d", n, StreakAnswers)
	}
	before := a.n.Load()
	if _, err := Send(ctx, cfg, http.MethodGet, "/after", "", nil, 1<<20); !errors.As(err, &be) || a.n.Load() != before {
		t.Errorf("a request was sent after the stop: %v", err)
	}
	// 20 not-found pages in a row cost one start-page fetch and no stop.
	b := newBlockApp(t, 0)
	cfgB := b.config(t)
	cfgB.Watch = NewWatch(cfgB).Begin(ctx)
	for i := range 40 {
		if _, err := Send(ctx, cfgB, http.MethodGet, fmt.Sprintf("/missing%d", i), "", nil, 1<<20); err != nil {
			t.Fatal(err)
		}
	}
	if p := b.pages.Load(); p != 2 || cfgB.Watch.Block() != nil {
		t.Errorf("not-found pages: %d start-page fetches, block %v", p, cfgB.Watch.Block())
	}
}

// TestWatchProxyStops checks D3 on tool traffic: the proxy stops once the
// watch sees the block page, keeps the block for the runner, and refuses
// every later request.
func TestWatchProxyStops(t *testing.T) {
	a := newBlockApp(t, 0)
	ctx := context.Background()
	w := NewWatch(a.config(t))
	unit := w.Begin(ctx)
	u := &upstream{srv: a.srv}
	p, c, origin := start(t, u, "http", "app.test", func(c *Config) {
		c.Watch = unit
		c.MaxConns = 1
	})
	a.after.Store(1001)
	refused := 0
	for i := range 2000 {
		code, _, err := get(t, c, fmt.Sprintf("%s/w%d", origin, i), nil)
		if err != nil {
			t.Fatal(err)
		}
		if code == http.StatusServiceUnavailable {
			refused++
		}
	}
	if b := p.Block(); b == nil || unit.Block() != b || !strings.Contains(p.StopReason(), "10 answers in a row") {
		t.Fatalf("not stopped: %q", p.StopReason())
	}
	select {
	case <-p.Stopped():
	default:
		t.Error("Stopped not closed")
	}
	if n := a.blocked.Load(); n != StreakAnswers {
		t.Errorf("%d block pages forwarded, want %d", n, StreakAnswers)
	}
	if refused != 2000-1000-StreakAnswers {
		t.Errorf("%d refused", refused)
	}
	// One fetch at Begin, one for the not-found pages, one for the block.
	if n := a.pages.Load(); n != 3 {
		t.Errorf("%d start-page fetches", n)
	}
}

// TestWatchProxyStopsCompressed checks D3 on a host that compresses its
// answers for a tool that accepts gzip (Go's client asks for it by itself,
// as ffuf and Nuclei do): the block page the tool gets and the start page
// the watch fetches must be measured alike, or they never match.
func TestWatchProxyStopsCompressed(t *testing.T) {
	a := newBlockApp(t, 0)
	a.gzip.Store(true)
	ctx := context.Background()
	unit := NewWatch(a.config(t)).Begin(ctx)
	u := &upstream{srv: a.srv}
	p, c, origin := start(t, u, "http", "app.test", func(c *Config) {
		c.Watch = unit
		c.MaxConns = 1
	})
	a.after.Store(11)
	for i := range 100 {
		if _, _, err := get(t, c, fmt.Sprintf("%s/w%d", origin, i), nil); err != nil {
			t.Fatal(err)
		}
	}
	if p.Block() == nil || !strings.Contains(p.StopReason(), "10 answers in a row") {
		t.Fatalf("not stopped: %q", p.StopReason())
	}
	if n := a.blocked.Load(); n != StreakAnswers {
		t.Errorf("%d block pages forwarded, want %d", n, StreakAnswers)
	}
}

// TestWatchBlockLifts checks that a check after a block that ended runs:
// the next Begin finds the start page as it was.
func TestWatchBlockLifts(t *testing.T) {
	a := newBlockApp(t, 0)
	cfg := a.config(t)
	ctx := context.Background()
	w := NewWatch(cfg)
	cfg.Watch = w.Begin(ctx)
	a.lift.Store(true) // the D3 fetch sees the block, then it ends
	a.after.Store(5)
	var err error
	for i := 0; err == nil && i < 50; i++ {
		_, err = Send(ctx, cfg, http.MethodGet, "/x", "", nil, 1<<20)
	}
	if cfg.Watch.Block() == nil {
		t.Fatalf("not stopped: %v", err)
	}
	a.after.Store(0)
	if b := w.Begin(ctx).Block(); b != nil {
		t.Errorf("the next check is blocked after the block ended: %v", b.Reason)
	}
}

// TestWatchStreamedAnswer checks that the proxy does not hold an answer
// back to measure it: the tool reads the first part of a streamed body
// before the app has finished sending it.
func TestWatchStreamedAnswer(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/stream" {
			fmt.Fprint(w, "first part")
			w.(http.Flusher).Flush()
			<-release
		}
		fmt.Fprint(w, "rest")
	}))
	t.Cleanup(srv.Close)
	t.Cleanup(func() {
		select {
		case <-release:
		default:
			close(release)
		}
	})
	u := &upstream{srv: srv}
	ctx := context.Background()
	var w *Watch
	_, c, origin := start(t, u, "http", "app.test", func(c *Config) {
		w = NewWatch(*c)
		c.Watch = w.Begin(ctx)
	})
	resp, err := c.Get(origin + "/stream")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	buf := make([]byte, len("first part"))
	done := make(chan error, 1)
	go func() { _, err := io.ReadFull(resp.Body, buf); done <- err }()
	select {
	case err := <-done:
		if err != nil || string(buf) != "first part" {
			t.Fatalf("%q %v", buf, err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the proxy held the streamed answer back")
	}
	close(release)
}

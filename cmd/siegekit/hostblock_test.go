package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/Gobbuwu/SiegeKit/internal/authz"
	"github.com/Gobbuwu/SiegeKit/internal/egress"
	"github.com/Gobbuwu/SiegeKit/internal/ratelimit"
	"github.com/Gobbuwu/SiegeKit/internal/report"
	"github.com/Gobbuwu/SiegeKit/internal/served"
	"github.com/Gobbuwu/SiegeKit/internal/target"
)

// hostPage is the start page the run's watch fetches (ADR 0071): 200,
// or a 25,000-byte 403 block page once blocked is set.
type hostPage struct {
	blocked atomic.Bool
	fetches atomic.Int32
	cfg     egress.Config
	url     *target.URL // the host page's own address
}

func useHostPage(t *testing.T, f *fakeActive) *hostPage {
	t.Helper()
	h := &hostPage{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		h.fetches.Add(1)
		if h.blocked.Load() {
			w.WriteHeader(http.StatusForbidden)
			w.Write(bytes.Repeat([]byte("c"), 25000))
			return
		}
		w.Write([]byte("the app"))
	}))
	t.Cleanup(srv.Close)
	u, err := target.Parse("http://localhost:" + strconv.Itoa(srv.Listener.Addr().(*net.TCPAddr).Port) + "/")
	if err != nil {
		t.Fatal(err)
	}
	h.url = u
	f.watch = func(c egress.Config) *egress.Watch {
		h.cfg = c
		c.Target, c.Addrs = u, []netip.Addr{netip.MustParseAddr("127.0.0.1")}
		return egress.NewWatch(c)
	}
	return h
}

func readRun(t *testing.T) report.Run {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("siegekit-report", "report.json"))
	var r report.Run
	if err != nil || json.Unmarshal(b, &r) != nil {
		t.Fatalf("report: %v", err)
	}
	return r
}

func pluginByID(r report.Run, id string) report.PluginResult {
	for _, p := range r.Plugins {
		if p.ID == id {
			return p
		}
	}
	return report.PluginResult{}
}

// TestScanURLHostBlocked checks SiegeKit's own checks when the host stops
// serving the app (ADR 0071): a block that begins while the start page and
// its files are fetched stops served-secrets and public-maps, and a block
// that begins during the spec probe stops the plugins that need the spec;
// every later check, the throttle checks included, sends nothing while the
// host still blocks.
func TestScanURLHostBlocked(t *testing.T) {
	old := resolver
	resolver = fakeResolver{"localhost": "127.0.0.1"}
	t.Cleanup(func() { resolver = old })

	// The block begins while the start page's files are fetched.
	f := useActive(t)
	useData(t)
	h := useHostPage(t, f)
	t.Setenv("SIEGEKIT_EXTRA_HEADERS", "X-Bypass: secret-value")
	oldCollect := servedCollect
	servedCollect = func(ctx context.Context, cfg egress.Config, rate float64, dir string) (served.Result, error) {
		if cfg.Watch == nil {
			t.Error("the fetch of the start page and its files is not watched")
		}
		h.blocked.Store(true)
		return oldCollect(ctx, cfg, rate, dir) // the fake's files
	}
	t.Cleanup(func() { servedCollect = oldCollect })
	var out, errb bytes.Buffer
	code := run([]string{"scan", "--no-save", "--only", "served-secrets,public-maps,zap", "http://localhost:3000/"}, &out, &errb)
	r := readRun(t)
	for _, id := range []string{"served-secrets", "public-maps", "zap"} {
		p := pluginByID(r, id)
		if p.Status != report.Failed || p.Stop != report.StopHostBlocked || !strings.Contains(p.Reason, "stopped by SiegeKit: the host stopped serving the app") {
			t.Errorf("%s: %+v", id, p)
		}
	}
	if !strings.Contains(pluginByID(r, "served-secrets").Reason, "during this check: after it, the start page answered 403 (text/plain, 25000 bytes)") {
		t.Errorf("served-secrets reason %q", pluginByID(r, "served-secrets").Reason)
	}
	if code != report.ExitIncomplete || len(f.specs) != 0 || h.cfg.Header.Get("X-Bypass") != "secret-value" {
		t.Errorf("exit %d, %d tool runs, watch headers %v\n%s%s", code, len(f.specs), h.cfg.Header, out.String(), errb.String())
	}
	// Before the fetch, after it, before public-maps' spec probe, before ZAP.
	if n := h.fetches.Load(); n != 4 {
		t.Errorf("%d start-page fetches", n)
	}

	// The block begins during the spec probe: the plugins that need the
	// spec fail with the stop, and rate-limit, which runs next, sends
	// nothing.
	f = useActive(t)
	useData(t)
	h = useHostPage(t, f)
	calls := useRateLimit(t, ratelimit.Result{}, nil)
	oldGet := specGet
	specGet = func(ctx context.Context, cfg egress.Config, p string, max int64) (int, []byte, error) {
		if cfg.Watch == nil {
			t.Error("the spec probe is not watched")
		}
		h.blocked.Store(true)
		return oldGet(ctx, cfg, p, max)
	}
	f.served = map[string]string{} // no spec
	out.Reset()
	errb.Reset()
	code = run(append([]string{"scan", "--no-save", "--only", "schemathesis,rate-limit", "--authorized-host", "localhost"}, append(rateArgs, "http://localhost:3000/")...), &out, &errb)
	r = readRun(t)
	if p := pluginByID(r, "schemathesis"); p.Status != report.Failed || p.Stop != report.StopHostBlocked || !strings.Contains(p.Reason, "stopped by SiegeKit: the host stopped serving the app during this check") {
		t.Errorf("schemathesis: %+v", p)
	}
	if p := pluginByID(r, ratelimit.ID); p.Status != report.Failed || p.Stop != report.StopHostBlocked || p.Requests != 0 || !strings.Contains(p.Reason, "before this check: the start page answered 403") {
		t.Errorf("rate-limit: %+v", p)
	}
	if code != report.ExitIncomplete || len(*calls) != 0 || len(f.specs) != 0 {
		t.Errorf("exit %d, %d rate-limit runs, %d tool runs\n%s%s", code, len(*calls), len(f.specs), out.String(), errb.String())
	}
	specGet = oldGet

	// The block begins in access-control's last answers (D1 after it):
	// the check fails with the stop and keeps the finding it made before.
	f = useActive(t)
	useData(t)
	h = useHostPage(t, f)
	t.Setenv(authz.SessionEnv, "Authorization: Bearer B")
	useAuthz(t, authz.Result{ATried: 1, Requests: 3, BTested: true, Replays: []authz.Replay{{
		Request: authz.Request{Method: "GET", Path: "/rest/basket/1"},
		A:       authz.Answer{Status: 200, Body: []byte(`{"data":{"id":1}}`)},
		B:       authz.Answer{Status: 200, Body: []byte(`{"data":{"id":1}}`)},
		None:    authz.Answer{Status: 401}, BTested: true,
	}}}, nil)
	stub := authzCheck
	authzCheck = func(ctx context.Context, cfg egress.Config, reqs []authz.Request, acc authz.Accounts, rate float64) (authz.Result, error) {
		if cfg.Watch == nil {
			t.Error("access-control is not watched")
		}
		h.blocked.Store(true)
		return stub(ctx, cfg, reqs, acc, rate)
	}
	stdinIsTerminal = func() bool { return true }
	stdin = strings.NewReader("test accounts\n")
	t.Cleanup(func() { stdinIsTerminal = func() bool { return false } })
	out.Reset()
	errb.Reset()
	code = run([]string{"scan", "--no-save", "--har", writeHAR(t, "http://localhost:3000/rest/basket/1"), "--only", "access-control", "http://localhost:3000/"}, &out, &errb)
	r = readRun(t)
	p := pluginByID(r, authz.ID)
	if p.Status != report.Failed || p.Stop != report.StopHostBlocked || p.Findings != 1 || len(r.Findings) != 1 ||
		!strings.Contains(p.Reason, "during this check: after it, the start page answered 403") || !strings.Contains(p.Reason, "the 1 finding(s) reported before the stop are kept") {
		t.Errorf("access-control: exit %d, %+v\n%s%s", code, p, out.String(), errb.String())
	}
}

// TestScanURLHostBlockedDuringReplay checks access-control when the block
// begins in the middle of its replay (D3): the replay ends at the 10th
// block page, and the check fails with the stop but keeps what it read
// before, as when D1 sees the block after it (ADR 0071).
func TestScanURLHostBlockedDuringReplay(t *testing.T) {
	f := useActive(t)
	useData(t)
	h := useHostPage(t, f)
	t.Setenv(authz.SessionEnv, "Authorization: Bearer B")
	useAuthz(t, authz.Result{ATried: 1, Requests: 3, BTested: true, Replays: []authz.Replay{{
		Request: authz.Request{Method: "GET", Path: "/rest/basket/1"},
		A:       authz.Answer{Status: 200, Body: []byte(`{"data":{"id":1}}`)},
		B:       authz.Answer{Status: 200, Body: []byte(`{"data":{"id":1}}`)},
		None:    authz.Answer{Status: 401}, BTested: true,
	}}}, nil)
	stub := authzCheck
	authzCheck = func(ctx context.Context, cfg egress.Config, reqs []authz.Request, acc authz.Accounts, rate float64) (authz.Result, error) {
		res, _ := stub(ctx, cfg, reqs, acc, rate)
		h.blocked.Store(true)
		c := cfg
		c.Target, c.Addrs = h.url, []netip.Addr{netip.MustParseAddr("127.0.0.1")}
		for range egress.StreakAnswers {
			if _, err := egress.SendHeader(ctx, c, http.MethodGet, "/rest/basket/2", nil, nil, 1<<20); egress.IsBlocked(err) {
				res.Requests += egress.StreakAnswers
				return res, err
			}
		}
		t.Error("the watch did not stop the replay")
		return res, nil
	}
	stdinIsTerminal = func() bool { return true }
	stdin = strings.NewReader("test accounts\n")
	t.Cleanup(func() { stdinIsTerminal = func() bool { return false } })
	var out, errb bytes.Buffer
	code := run([]string{"scan", "--no-save", "--har", writeHAR(t, "http://localhost:3000/rest/basket/1"), "--only", "access-control", "http://localhost:3000/"}, &out, &errb)
	r := readRun(t)
	p := pluginByID(r, authz.ID)
	if p.Status != report.Failed || p.Stop != report.StopHostBlocked || p.Findings != 1 || len(r.Findings) != 1 || p.Requests != 13 ||
		!strings.Contains(p.Reason, "10 answers in a row and the start page were the same page, 403") || !strings.Contains(p.Reason, "the 1 finding(s) reported before the stop are kept") {
		t.Errorf("access-control: exit %d, %+v\n%s%s", code, p, out.String(), errb.String())
	}
}

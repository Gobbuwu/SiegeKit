package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/Gobbuwu/SiegeKit/internal/audit"
	"github.com/Gobbuwu/SiegeKit/internal/egress"
	"github.com/Gobbuwu/SiegeKit/internal/findings"
	"github.com/Gobbuwu/SiegeKit/internal/ratelimit"
	"github.com/Gobbuwu/SiegeKit/internal/report"
	"github.com/Gobbuwu/SiegeKit/internal/verify"
)

type rateCall struct {
	cfg egress.Config
	e   *ratelimit.Endpoint
	n   int
}

// useRateLimit replaces the rate-limit check and records its calls.
func useRateLimit(t *testing.T, res ratelimit.Result, err error) *[]rateCall {
	t.Helper()
	var calls []rateCall
	old := rateLimitCheck
	rateLimitCheck = func(_ context.Context, cfg egress.Config, e *ratelimit.Endpoint, n int) (ratelimit.Result, error) {
		calls = append(calls, rateCall{cfg, e, n})
		return res, err
	}
	t.Cleanup(func() { rateLimitCheck = old })
	return &calls
}

var rateArgs = []string{"--rate-limit-url", "http://localhost:3000/rest/products/search?q=apple", "--rate-limit-requests", "20"}

func TestScanURLRateLimit(t *testing.T) {
	old := resolver
	resolver = fakeResolver{"localhost": "127.0.0.1", "shop.example": "93.184.215.14"}
	t.Cleanup(func() { resolver = old })
	scan := func(tty bool, input string, args ...string) (int, string) {
		t.Helper()
		stdinIsTerminal = func() bool { return tty }
		stdin = strings.NewReader(input)
		t.Cleanup(func() { stdinIsTerminal = func() bool { return false } })
		var out, errb bytes.Buffer
		code := run(append([]string{"scan", "--no-save"}, args...), &out, &errb)
		return code, out.String() + errb.String()
	}
	readReport := func() report.Run {
		t.Helper()
		b, err := os.ReadFile(filepath.Join("siegekit-report", "report.json"))
		var r report.Run
		if err != nil || json.Unmarshal(b, &r) != nil || r.Plugins[0].ID != ratelimit.ID {
			t.Fatalf("report %+v %v", r.Plugins, err)
		}
		return r
	}

	// Mistakes are refused before any lookup, request or audit entry.
	for _, c := range []struct {
		args []string
		code int
		want string
	}{
		{[]string{"--rate-limit-body", "q=a", "http://localhost:3000/"}, exitUsage, "need --rate-limit-url"},
		{[]string{"--rate-limit-requests", "5", "http://localhost:3000/"}, exitUsage, "need --rate-limit-url"},
		{[]string{"--rate-limit-url", "http://localhost:3000/s", "--rate-limit-requests", "51", "http://localhost:3000/"}, exitUsage, "from 2 to 50"},
		{[]string{"--rate-limit-url", "http://localhost:3000/s", "--rate-limit-requests", "1", "http://localhost:3000/"}, exitUsage, "from 2 to 50"},
		{append(slices.Clone(rateArgs), t.TempDir()), exitUsage, "only apply to URL targets"},
		{[]string{"--rate-limit-url", "http://localhost:3001/s", "http://localhost:3000/"}, exitInvalid, "not on the target's origin"},
		{[]string{"--rate-limit-url", "http://localhost:3000/s", "--rate-limit-body", "{x", "http://localhost:3000/"}, exitInvalid, "not valid JSON"},
	} {
		f := useActive(t)
		data := useData(t)
		calls := useRateLimit(t, ratelimit.Result{}, nil)
		code, out := scan(false, "", c.args...)
		if code != c.code || !strings.Contains(out, c.want) || len(f.specs)+len(*calls) != 0 {
			t.Errorf("%v: exit %d, %d runs, %d checks\n%s", c.args, code, len(f.specs), len(*calls), out)
		}
		if _, err := os.Stat(filepath.Join(data, "siegekit", "audit.log")); err == nil {
			t.Errorf("%v: audit entry written", c.args)
		}
	}

	// A local GET needs no confirmation; no limit seen is a low finding.
	f := useActive(t)
	data := useData(t)
	calls := useRateLimit(t, ratelimit.Result{Requests: 20, Baseline: 200}, nil)
	code, out := scan(false, "", append(slices.Clone(rateArgs), "--only", "rate-limit,zap", "--fail-on", "low", "http://localhost:3000/")...)
	if code != report.ExitFindings || len(*calls) != 1 || len(f.specs) != 1 || strings.Contains(out, "Type yes") ||
		!strings.Contains(out, "rate-limit           siegekit 0.0.0-dev: up to 20 requests GET http://localhost:3000/rest/products/search?q=apple, one per second, stopping at the first sign of a limit") {
		t.Fatalf("exit %d, %d checks, %d runs\n%s", code, len(*calls), len(f.specs), out)
	}
	if c := (*calls)[0]; c.cfg.ReadOnly || c.cfg.VerifyTLS || c.n != 20 || c.e.Path != "/rest/products/search?q=apple" || c.e.Method != "GET" {
		t.Errorf("call %+v", c)
	}
	b, err := os.ReadFile(filepath.Join(data, "siegekit", "audit.log"))
	var e audit.Entry
	if err != nil || json.Unmarshal(b, &e) != nil || !slices.Equal(e.Plugins, []string{"zap", "rate-limit"}) || e.Verification != "loopback" {
		t.Errorf("audit entry %+v %v", e, err)
	}
	r := readReport()
	p := r.Plugins[0]
	if p.Status != report.Ran || p.Requests != 20 || p.Findings != 1 || p.Input != "GET http://localhost:3000/rest/products/search?q=apple" || p.Result != "no limit seen in 20 requests, all answered 200 with no rate-limit header" {
		t.Errorf("plugin %+v", p)
	}
	var rf *findings.Finding
	for i := range r.Findings {
		if r.Findings[i].RuleID == "rate-not-limited" {
			rf = &r.Findings[i]
		}
	}
	if rf == nil || rf.Severity != findings.Low || rf.Location.URI != "http://localhost:3000/rest/products/search" || rf.CWEs[0] != "CWE-770" {
		t.Errorf("findings %+v", r.Findings)
	}

	// A limit seen is a result, not a finding; a failed check makes the run
	// incomplete.
	useActive(t)
	useData(t)
	useRateLimit(t, ratelimit.Result{Requests: 1, Limited: true, Signal: "answered with a X-Ratelimit-Limit header, already at the first request"}, nil)
	scan(false, "", append(slices.Clone(rateArgs), "--only", "rate-limit", "http://localhost:3000/")...)
	if p := readReport().Plugins[0]; p.Status != report.Ran || p.Findings != 0 || !strings.HasPrefix(p.Result, "limit seen after 1 of 20 requests: ") {
		t.Errorf("limited: %+v", p)
	}
	useActive(t)
	useData(t)
	useRateLimit(t, ratelimit.Result{}, errors.New("the URL answered 404 to a GET"))
	if code, _ := scan(false, "", append(slices.Clone(rateArgs), "--only", "rate-limit", "http://localhost:3000/")...); code != report.ExitIncomplete || readReport().Plugins[0].Status != report.Failed {
		t.Errorf("failed check: exit %d %+v", code, readReport().Plugins[0])
	}

	// A POST can change data, so loopback needs a person's confirmation.
	post := []string{"--rate-limit-url", "http://localhost:3000/api/ask", "--rate-limit-body", `{"q":"hi"}`, "--only", "rate-limit"}
	for _, c := range []struct {
		name  string
		tty   bool
		input string
		extra []string
		runs  int
		want  string
	}{
		{"typed yes", true, "yes\n", nil, 1, "rate-limit sends up to 20 POST requests to http://localhost:3000/api/ask, which can change data. Type yes"},
		{"typed no", true, "no\n", nil, 0, `not confirmed: "yes" was not typed`},
		{"no terminal", false, "", nil, 0, "needs a person's confirmation"},
		{"authorized host", false, "", []string{"--authorized-host", "localhost"}, 1, "rate-limit"},
	} {
		t.Run(c.name, func(t *testing.T) {
			useActive(t)
			useData(t)
			calls := useRateLimit(t, ratelimit.Result{Requests: 20, Baseline: 200}, nil)
			code, out := scan(c.tty, c.input, append(append(slices.Clone(post), c.extra...), "http://localhost:3000/")...)
			if len(*calls) != c.runs || !strings.Contains(out, c.want) {
				t.Errorf("exit %d, %d checks\n%s", code, len(*calls), out)
			}
			if c.runs == 1 && ((*calls)[0].e.Method != "POST" || (*calls)[0].e.ContentType() != "application/json") {
				t.Errorf("call %+v", (*calls)[0].e)
			}
		})
	}

	// --profile quick leaves it out; naming it with --only is an error.
	useActive(t)
	useData(t)
	calls = useRateLimit(t, ratelimit.Result{}, nil)
	if code, out := scan(false, "", append(slices.Clone(rateArgs), "--profile", "quick", "--only", "dast", "http://localhost:3000/")...); len(*calls) != 0 || !strings.Contains(out, "rate-limit           not run - not run with --profile quick") {
		t.Errorf("quick: exit %d\n%s", code, out)
	}
	// Left out by the profile is not a missing dependency (ADR 0041).
	if code, out := scan(false, "", append(slices.Clone(rateArgs), "--require-all", "--profile", "quick", "--only", "dast", "http://localhost:3000/")...); code != exitOK || !strings.Contains(out, "rate-limit           not run - not run with --profile quick") {
		t.Errorf("quick --require-all: exit %d\n%s", code, out)
	}
	if code, out := scan(false, "", append(slices.Clone(rateArgs), "--profile", "quick", "--only", "zap,rate-limit", "http://localhost:3000/")...); code != exitInvalid || !strings.Contains(out, "--only names rate-limit, which --profile quick does not run") {
		t.Errorf("--only with quick: exit %d\n%s", code, out)
	}

	// Not on Linux: failed, nothing sent.
	useActive(t)
	useData(t)
	calls = useRateLimit(t, ratelimit.Result{}, nil)
	hostOS = "darwin"
	scan(false, "", append(slices.Clone(rateArgs), "--only", "rate-limit", "http://localhost:3000/")...)
	hostOS = "linux"
	if len(*calls) != 0 || readReport().Plugins[0].Status != report.Failed {
		t.Errorf("darwin: %+v", readReport().Plugins[0])
	}

	// Deployed targets: never run until M2.10 (answer 7a), even a GET.
	useActive(t)
	data = useData(t)
	calls = useRateLimit(t, ratelimit.Result{}, nil)
	tok, err := verify.Token(filepath.Join(data, "siegekit", "verify"), "shop.example")
	if err != nil {
		t.Fatal(err)
	}
	useProver(t, &fakeProver{published: map[string]string{"shop.example": verify.Value(tok)}})
	code, out = scan(true, "shop.example\n", "--deployed", "--rate-limit-url", "https://shop.example/search?q=a", "--only", "rate-limit,zap", "https://shop.example/")
	if code != exitOK || len(*calls) != 0 || !strings.Contains(out, "rate-limit           not run - runs only on local targets") {
		t.Errorf("deployed: exit %d, %d checks\n%s", code, len(*calls), out)
	}
	if p := readReport().Plugins[0]; p.Status != report.Skipped || p.Requests != 0 {
		t.Errorf("deployed: %+v", p)
	}
}

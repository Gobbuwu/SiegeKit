package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/Gobbuwu/SiegeKit/internal/audit"
	"github.com/Gobbuwu/SiegeKit/internal/egress"
	"github.com/Gobbuwu/SiegeKit/internal/runner"
	"github.com/Gobbuwu/SiegeKit/internal/sandbox"
	"github.com/Gobbuwu/SiegeKit/internal/target"
	"github.com/Gobbuwu/SiegeKit/internal/verify"
)

const testBypass = "s3cr3t-bypass-0123456789abcdefXY"

// Every refusal comes before any DNS lookup or request: the host does not
// resolve, so a refusal naming the variable came first.
func TestScanURLExtraHeadersRefused(t *testing.T) {
	old := resolver
	resolver = fakeResolver{}
	t.Cleanup(func() { resolver = old })
	f := useActive(t)
	p := &fakeProver{}
	useProver(t, p)
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	for name, tc := range map[string]struct {
		value, url string
		deployed   bool
		want       string
	}{
		"empty":         {"", "http://nowhere.example", false, "holds no header"},
		"empty value":   {"X-Vercel-Protection-Bypass:", "http://nowhere.example", false, "is empty"},
		"Host":          {"Host: " + testBypass, "http://nowhere.example", false, "cannot set Host"},
		"hop-by-hop":    {"Connection: " + testBypass, "http://nowhere.example", false, "cannot set Connection"},
		"Cookie":        {"Cookie: s=" + testBypass, "http://nowhere.example", false, "cannot set Cookie: it carries a login"},
		"Authorization": {"Authorization: Bearer " + testBypass, "http://nowhere.example", false, "cannot set Authorization: it carries a login"},
		"X-Api-Key":     {"X-Api-Key: " + testBypass, "http://nowhere.example", false, "cannot set X-Api-Key: it carries a login"},
		"deployed http": {"X-Vercel-Protection-Bypass: " + testBypass, "http://nowhere.example", true, "only over https"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Setenv(egress.ExtraHeadersEnv, tc.value)
			stdinIsTerminal = func() bool { return true }
			args := []string{"scan", "--no-save"}
			if tc.deployed {
				args = append(args, "--deployed")
			}
			var out, errb bytes.Buffer
			code := run(append(args, tc.url), &out, &errb)
			all := out.String() + errb.String()
			if code != exitInvalid || !strings.Contains(all, egress.ExtraHeadersEnv) || !strings.Contains(all, tc.want) || strings.Contains(all, "no such host") {
				t.Errorf("exit %d, want refusal %q:\n%s", code, tc.want, all)
			}
			if strings.Contains(all, testBypass) {
				t.Errorf("output quotes the value:\n%s", all)
			}
		})
	}
	if len(p.calls) != 0 || len(f.specs) != 0 {
		t.Errorf("%d proof checks and %d runs after refusals", len(p.calls), len(f.specs))
	}
}

// A header that a session sets is refused too: the no-login requests of
// the access-control check would carry it.
func TestExtraHeadersSessionNames(t *testing.T) {
	u, _ := target.Parse("https://app.test/")
	b := http.Header{"X-Team-Session": {"b-session-value"}}
	if _, err := extraHeaders("x-team-session: "+testBypass, u, false, b, nil); err == nil || !strings.Contains(err.Error(), "carries a login") {
		t.Errorf("session B's header accepted: %v", err)
	}
	if h, err := extraHeaders("X-Vercel-Protection-Bypass: "+testBypass, u, true, b, nil); err != nil || h.Get("X-Vercel-Protection-Bypass") != testBypass {
		t.Errorf("%v %v", h, err)
	}
}

// The header reaches the proof fetch and every check's requests, the plan
// and the audit log name it without its value, and the value is in no
// output, report, saved run or log, even when the target echoes it into
// a tool's findings.
func TestScanURLExtraHeaders(t *testing.T) {
	old := resolver
	resolver = fakeResolver{"shop.example": "93.184.215.14"}
	t.Cleanup(func() { resolver = old })
	f := useActive(t)
	data := useData(t)
	tok, err := verify.Token(filepath.Join(data, "siegekit", "verify"), "shop.example")
	if err != nil {
		t.Fatal(err)
	}
	p := &fakeProver{published: map[string]string{"shop.example": verify.Value(tok)}}
	useProver(t, p)
	var reachCfg, specCfg egress.Config
	oldReach, oldSpec := reachable, specGet
	reachable = func(_ context.Context, c egress.Config) error { reachCfg = c; return nil }
	specGet = func(ctx context.Context, c egress.Config, path string, max int64) (int, []byte, error) {
		specCfg = c
		return oldSpec(ctx, c, path, max)
	}
	t.Cleanup(func() { reachable, specGet = oldReach, oldSpec })
	// The target echoes request headers: ZAP's finding quotes the value.
	tool := activeRunner
	activeRunner = func(ctx context.Context, s sandbox.Spec, c egress.Config) (*runner.ActiveResult, error) {
		r, err := tool(ctx, s, c)
		echo := strings.Replace(zapSARIF, "no X-Frame-Options", "request had X-Vercel-Protection-Bypass: "+testBypass, 1)
		if werr := os.WriteFile(filepath.Join(s.OutDir, "zap.json"), []byte(strings.Replace(echo, "TARGET", c.Target.String(), 1)), 0o600); werr != nil {
			return nil, werr
		}
		return r, err
	}
	t.Setenv(egress.ExtraHeadersEnv, "x-vercel-protection-bypass: "+testBypass+"\n")
	stdinIsTerminal = func() bool { return true }
	stdin = strings.NewReader("shop.example\n")
	reports := t.TempDir()
	var out, errb bytes.Buffer
	code := run([]string{"scan", "--deployed", "--only", "zap,served-secrets,public-maps", "--report-dir", reports, "https://shop.example/"}, &out, &errb)
	all := out.String() + errb.String()
	if code != exitOK && code != 3 {
		t.Fatalf("exit %d\n%s", code, all)
	}
	if !strings.Contains(all, "Every request to https://shop.example carries X-Vercel-Protection-Bypass from SIEGEKIT_EXTRA_HEADERS (values hidden") {
		t.Errorf("plan does not name the header:\n%s", all)
	}
	want := http.Header{"X-Vercel-Protection-Bypass": {testBypass}}
	is := func(h http.Header) bool { return h.Get("X-Vercel-Protection-Bypass") == testBypass && len(h) == 1 }
	if len(p.headers) != 1 || !is(p.headers[0]) {
		t.Errorf("proof fetch headers %v, want %v", p.headers, want)
	}
	if !is(reachCfg.Header) || !is(specCfg.Header) {
		t.Errorf("reachable %v, spec %v", reachCfg.Header, specCfg.Header)
	}
	if len(f.cfgs) == 0 || len(f.servedCfg) == 0 {
		t.Fatalf("%d tool runs, %d collections", len(f.cfgs), len(f.servedCfg))
	}
	for _, c := range slices.Concat(f.cfgs, f.servedCfg) {
		if !is(c.Header) {
			t.Errorf("check config without the header: %+v", c)
		}
	}
	b, err := os.ReadFile(filepath.Join(data, "siegekit", "audit.log"))
	if err != nil {
		t.Fatal(err)
	}
	var e audit.Entry
	if err := json.Unmarshal(b, &e); err != nil || !slices.Equal(e.ExtraHeaders, []string{"X-Vercel-Protection-Bypass"}) {
		t.Errorf("audit entry %+v %v", e, err)
	}
	r, err := os.ReadFile(filepath.Join(reports, "report.json"))
	if err != nil || !strings.Contains(string(r), "[hidden: SIEGEKIT_EXTRA_HEADERS value]") {
		t.Errorf("report does not show the hidden value: %v\n%s", err, r)
	}
	// The value is nowhere: output, reports, the saved run, the audit log.
	if strings.Contains(all, testBypass) {
		t.Errorf("output holds the value:\n%s", all)
	}
	n := 0
	for _, dir := range []string{reports, data} {
		filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return err
			}
			n++
			if b, _ := os.ReadFile(path); bytes.Contains(b, []byte(testBypass)) {
				t.Errorf("%s holds the value", path)
			}
			return nil
		})
	}
	if n < 5 {
		t.Errorf("only %d files searched", n)
	}
}

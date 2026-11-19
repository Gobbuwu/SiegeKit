package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/Gobbuwu/SiegeKit/internal/audit"
	"github.com/Gobbuwu/SiegeKit/internal/egress"
	"github.com/Gobbuwu/SiegeKit/internal/manifest"
	"github.com/Gobbuwu/SiegeKit/internal/report"
	"github.com/Gobbuwu/SiegeKit/internal/runner"
	"github.com/Gobbuwu/SiegeKit/internal/sandbox"
	"github.com/Gobbuwu/SiegeKit/internal/target"
	"github.com/Gobbuwu/SiegeKit/internal/verify"
	"github.com/Gobbuwu/SiegeKit/plugins"
)

// fakeProver accepts a token when published[host] holds its value, the
// way a well-known file would.
type fakeProver struct {
	published map[string]string
	calls     [][]netip.Addr
}

func (f *fakeProver) Check(_ context.Context, u *target.URL, addrs []netip.Addr, token string) (string, error) {
	f.calls = append(f.calls, addrs)
	if f.published[u.Host] == verify.Value(token) {
		return "well-known file", nil
	}
	return "", errors.New("no proof of control found")
}

func useProver(t *testing.T, p *fakeProver) {
	old := prover
	prover = p
	t.Cleanup(func() { prover = old })
}

type fakeResolver map[string]string

func (f fakeResolver) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	if a, ok := f[host]; ok {
		return []netip.Addr{netip.MustParseAddr(a)}, nil
	}
	return nil, errors.New("no such host")
}

// zapSARIF is a minimal ZAP report with one alert.
const zapSARIF = `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"ZAP","rules":[{"id":"10020","name":"Missing Anti-clickjacking Header",
"properties":{"references":["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options"]},
"relationships":[{"target":{"id":"1021","toolComponent":{"name":"CWE"}}}]}]}},
"results":[{"ruleId":"10020","level":"warning","message":{"text":"no X-Frame-Options"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"TARGET"},"region":{"startLine":1}}}]}]}]}`

// fakeActive records active runs and writes a ZAP report for each.
type fakeActive struct {
	specs []sandbox.Spec
	cfgs  []egress.Config
}

func useActive(t *testing.T) *fakeActive {
	t.Helper()
	f := &fakeActive{}
	old := activeRunner
	activeRunner = func(_ context.Context, s sandbox.Spec, c egress.Config) (*runner.ActiveResult, error) {
		f.specs, f.cfgs = append(f.specs, s), append(f.cfgs, c)
		if err := os.WriteFile(filepath.Join(s.OutDir, "zap.json"), []byte(strings.Replace(zapSARIF, "TARGET", c.Target.String(), 1)), 0o600); err != nil {
			return nil, err
		}
		return &runner.ActiveResult{Result: &sandbox.Result{Status: sandbox.Completed}, Stats: egress.Stats{Requests: 3}}, nil
	}
	useEngine(t, &fakeEngine{}, nil)
	oldReach := reachable
	reachable = func(context.Context, egress.Config) error { return nil }
	t.Cleanup(func() { activeRunner, reachable = old, oldReach })
	t.Chdir(t.TempDir()) // reports go to ./siegekit-report
	return f
}

func TestScanURL(t *testing.T) {
	old := resolver
	resolver = fakeResolver{"localhost": "127.0.0.1", "nas.lan": "192.168.1.20", "shop.example": "93.184.215.14", "meta.example": "169.254.169.254"}
	t.Cleanup(func() { resolver = old })
	useActive(t)
	useProver(t, &fakeProver{})
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	for _, tc := range []struct {
		name  string
		args  []string
		tty   bool
		input string
		code  int
		want  string
	}{
		{"loopback", []string{"http://localhost:3000"}, false, "", exitOK, "Target allowed (loopback)"},
		{"private with flag", []string{"--authorized-host", "NAS.lan", "http://nas.lan"}, false, "", exitOK, "Target allowed (--authorized-host)"},
		{"private flag mismatch", []string{"--authorized-host", "other.lan", "http://nas.lan"}, false, "", exitInvalid, "does not match"},
		{"private no terminal", []string{"http://nas.lan"}, false, "", exitInvalid, "pass --authorized-host nas.lan"},
		{"private typed", []string{"http://nas.lan"}, true, "nas.lan\n", exitOK, "Target allowed (typed confirmation)"},
		{"private typed wrong", []string{"http://nas.lan"}, true, "nas\n", exitInvalid, "did not match"},
		{"loopback flag mismatch", []string{"--authorized-host", "x", "http://localhost"}, false, "", exitInvalid, "does not match"},
		{"public in local mode", []string{"https://shop.example"}, false, "", exitInvalid, "--deployed"},
		{"public deployed", []string{"--deployed", "https://shop.example"}, true, "", exitInvalid, "siegekit-verify="},
		{"metadata", []string{"http://meta.example"}, false, "", exitInvalid, "never tests"},
		{"bad url", []string{"http://user:pw@localhost"}, false, "", exitInvalid, "user name or password"},
		{"unresolvable", []string{"http://nowhere.example"}, false, "", exitInvalid, "no such host"},
		{"flag on directory", []string{"--deployed", "."}, false, "", exitUsage, "only apply to URL targets"},
		{"update on URL", []string{"--update", "http://localhost"}, false, "", exitUsage, "only applies to directory scans"},
		{"other scheme", []string{"ftp://localhost/"}, false, "", exitUsage, "ftp:// URLs cannot be scanned"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("XDG_DATA_HOME", t.TempDir()) // runs in the same second share an ID
			stdinIsTerminal = func() bool { return tc.tty }
			stdin = strings.NewReader(tc.input)
			var out, errb bytes.Buffer
			code := run(append([]string{"scan"}, tc.args...), &out, &errb)
			if code != tc.code || !strings.Contains(out.String()+errb.String(), tc.want) {
				t.Errorf("exit %d (want %d), output %q (want %q)", code, tc.code, out.String()+errb.String(), tc.want)
			}
		})
	}
}

func TestScanURLDeployed(t *testing.T) {
	old := resolver
	resolver = fakeResolver{"shop.example": "93.184.215.14", "api.shop.example": "93.184.215.15", "rebind.example": "10.0.0.5"}
	t.Cleanup(func() { resolver = old })
	useActive(t)
	data := t.TempDir()
	t.Setenv("XDG_DATA_HOME", data)
	tokenOf := func(host string) string {
		tok, err := verify.Token(filepath.Join(data, "siegekit", "verify"), host)
		if err != nil {
			t.Fatal(err)
		}
		return tok
	}
	scan := func(tty bool, input string, args ...string) (int, string) {
		stdinIsTerminal = func() bool { return tty }
		stdin = strings.NewReader(input)
		var out, errb bytes.Buffer
		code := run(append([]string{"scan", "--deployed", "--no-save"}, args...), &out, &errb)
		return code, out.String() + errb.String()
	}
	p := &fakeProver{published: map[string]string{}}
	useProver(t, p)

	// No proof yet: refused, with instructions naming this host's token.
	code, out := scan(true, "shop.example\n", "https://shop.example")
	if code != exitInvalid || !strings.Contains(out, verify.Value(tokenOf("shop.example"))) || !strings.Contains(out, "_siegekit-verify.shop.example") {
		t.Fatalf("no proof: exit %d\n%s", code, out)
	}
	if !slices.Equal(p.calls[0], []netip.Addr{netip.MustParseAddr("93.184.215.14")}) {
		t.Errorf("checked addresses %v, want the pinned one", p.calls[0])
	}

	p.published["shop.example"] = verify.Value(tokenOf("shop.example"))
	for _, tc := range []struct {
		name  string
		tty   bool
		input string
		args  []string
		code  int
		want  string
	}{
		{"typed", true, "Shop.Example.\n", []string{"https://shop.example/app"}, exitOK, "Target allowed (well-known file + typed confirmation)"},
		{"typed wrong", true, "api.shop.example\n", []string{"https://shop.example"}, exitInvalid, "did not match"},
		{"no terminal", false, "", []string{"https://shop.example"}, exitInvalid, "typed in a terminal"},
		{"flag refused", true, "shop.example\n", []string{"--authorized-host", "shop.example", "https://shop.example"}, exitInvalid, "not accepted for deployed targets"},
		{"flag refused before lookup", true, "", []string{"--authorized-host", "nowhere.example", "https://nowhere.example"}, exitInvalid, "not accepted for deployed targets"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, out := scan(tc.tty, tc.input, tc.args...)
			if code != tc.code || !strings.Contains(out, tc.want) {
				t.Errorf("exit %d (want %d)\n%s", code, tc.code, out)
			}
			if tc.code == exitOK && !strings.Contains(out, "penetration-testing policy") {
				t.Errorf("no hosting-policy reminder:\n%s", out)
			}
		})
	}

	// Without a terminal, or with the flag, nothing is sent to the target.
	n0 := len(p.calls)
	scan(false, "", "https://shop.example")
	scan(true, "shop.example\n", "--authorized-host", "shop.example", "https://shop.example")
	if len(p.calls) != n0 {
		t.Errorf("proof checked although confirmation cannot be given")
	}

	// A subdomain has its own token: the parent's value does not prove it.
	p.published["api.shop.example"] = p.published["shop.example"]
	if code, out := scan(true, "api.shop.example\n", "https://api.shop.example"); code != exitInvalid {
		t.Errorf("parent's token accepted for a subdomain: %s", out)
	}

	// A stale token (the token file was replaced) no longer proves control.
	if err := os.Remove(filepath.Join(data, "siegekit", "verify", "shop.example.token")); err != nil {
		t.Fatal(err)
	}
	if code, out := scan(true, "shop.example\n", "https://shop.example"); code != exitInvalid || !strings.Contains(out, verify.Value(tokenOf("shop.example"))) {
		t.Errorf("stale token accepted: exit %d\n%s", code, out)
	}

	// A name that now resolves to a private address is refused before any
	// request, even with a valid-looking proof.
	p.published["rebind.example"] = verify.Value(tokenOf("rebind.example"))
	n := len(p.calls)
	if code, out := scan(true, "rebind.example\n", "https://rebind.example"); code != exitInvalid || !strings.Contains(out, "not a public address") || len(p.calls) != n {
		t.Errorf("private address in deployed mode: exit %d, %d checks\n%s", code, len(p.calls)-n, out)
	}
}

func TestScanURLRunsActivePlugins(t *testing.T) {
	old := resolver
	resolver = fakeResolver{"localhost": "127.0.0.1"}
	t.Cleanup(func() { resolver = old })
	f := useActive(t)
	data := t.TempDir()
	t.Setenv("XDG_DATA_HOME", data)
	var out, errb bytes.Buffer
	code := run([]string{"scan", "--fail-on", "medium", "--authorized-host", "localhost", "http://localhost:3000/app"}, &out, &errb)
	if code != report.ExitFindings {
		t.Fatalf("exit %d\n%s%s", code, out.String(), errb.String())
	}
	for _, want := range []string{
		"Plan: http://localhost:3000/app, local mode, addresses 127.0.0.1.",
		"zap-active   zap 2.17.0: ZAP attack scan (local targets only)",
		"only http://localhost:3000 is reachable",
		"(3 request(s) answered by the target, 0 refused by SiegeKit)",
	} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("output lacks %q:\n%s", want, out.String())
		}
	}
	// Both plugins ran through the egress proxy with the local limits, each
	// with its configuration naming the target as a JSON string.
	if len(f.specs) != 2 {
		t.Fatalf("%d active runs", len(f.specs))
	}
	for i, s := range f.specs {
		c := f.cfgs[i]
		if c.Target.String() != "http://localhost:3000/app" || c.VerifyTLS || c.Rate != runner.LocalLimits.Rate || !slices.Equal(c.Addrs, []netip.Addr{netip.MustParseAddr("127.0.0.1")}) {
			t.Errorf("run %d egress config %+v", i, c)
		}
		if !slices.Contains(s.Args, sandbox.ConfigMount) || s.ConfigFile == "" {
			t.Errorf("run %d: config not passed: %v", i, s.Args)
		}
	}
	// The run is in the audit log before any traffic.
	b, err := os.ReadFile(filepath.Join(data, "siegekit", "audit.log"))
	if err != nil {
		t.Fatal(err)
	}
	var e audit.Entry
	if err := json.Unmarshal(b, &e); err != nil || e.Target != "http://localhost:3000/app" || e.Mode != "local" || e.Verification != "loopback + --authorized-host" || e.Confirmed != "localhost" || !slices.Equal(e.Plugins, []string{"zap", "zap-active"}) {
		t.Errorf("audit entry %+v %v", e, err)
	}
	// The report names the URL and the request counts.
	b, err = os.ReadFile(filepath.Join("siegekit-report", "report.json"))
	if err != nil {
		t.Fatal(err)
	}
	var r report.Run
	if err := json.Unmarshal(b, &r); err != nil || r.Target != "http://localhost:3000/app" || len(r.Findings) != 1 || r.Plugins[0].Requests != 3 {
		t.Errorf("report %+v %v", r, err)
	}
	if f := r.Findings[0]; f.Location.URI != "http://localhost:3000/app" || !slices.Equal(f.CWEs, []string{"CWE-1021"}) || !strings.HasPrefix(f.HelpURI, "https://developer.mozilla.org/") {
		t.Errorf("finding %+v", f)
	}
}

// TestScanURLDestructiveNeedsConfirmation checks that the attack scan on a
// loopback target runs only after a person typed yes or passed
// --authorized-host (ADR 0005, owner decision 2026-11-19); --yes does not
// count.
func TestScanURLDestructiveNeedsConfirmation(t *testing.T) {
	old := resolver
	resolver = fakeResolver{"localhost": "127.0.0.1"}
	t.Cleanup(func() { resolver = old })
	for _, tc := range []struct {
		name         string
		args         []string
		tty          bool
		input        string
		runs         int
		verification string
		want         string
	}{
		{"no terminal", nil, false, "", 1, "loopback", "pass --authorized-host localhost if you"},
		{"--yes does not count", []string{"--yes"}, false, "", 1, "loopback", "needs a person's confirmation"},
		{"typed yes", nil, true, "yes\n", 2, "loopback + typed yes", "Type yes to run them"},
		{"typed no", nil, true, "no\n", 1, "loopback", `"yes" was not typed`},
		{"flag", []string{"--authorized-host", "LOCALHOST"}, false, "", 2, "loopback + --authorized-host", "zap-active"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := useActive(t)
			data := t.TempDir()
			t.Setenv("XDG_DATA_HOME", data)
			stdinIsTerminal = func() bool { return tc.tty }
			stdin = strings.NewReader(tc.input)
			t.Cleanup(func() { stdinIsTerminal = func() bool { return false } })
			var out, errb bytes.Buffer
			run(append(append([]string{"scan", "--no-save"}, tc.args...), "http://localhost:3000"), &out, &errb)
			if len(f.specs) != tc.runs || !strings.Contains(out.String(), tc.want) {
				t.Errorf("%d runs (want %d), output lacks %q:\n%s%s", len(f.specs), tc.runs, tc.want, out.String(), errb.String())
			}
			b, err := os.ReadFile(filepath.Join(data, "siegekit", "audit.log"))
			var e audit.Entry
			if err != nil || json.Unmarshal(b, &e) != nil || e.Verification != tc.verification || len(e.Plugins) != tc.runs {
				t.Errorf("audit entry %+v %v", e, err)
			}
			if tc.runs == 1 {
				b, err := os.ReadFile(filepath.Join("siegekit-report", "report.json"))
				var r report.Run
				if err != nil || json.Unmarshal(b, &r) != nil || len(r.Plugins) != 2 || r.Plugins[1].ID != "zap-active" || r.Plugins[1].Status != report.Skipped {
					t.Errorf("report %+v %v", r.Plugins, err)
				}
			}
		})
	}
}

// TestScanURLUnreachable checks that a target that does not answer the
// first GET is sent no scan.
func TestScanURLUnreachable(t *testing.T) {
	old := resolver
	resolver = fakeResolver{"localhost": "127.0.0.1"}
	t.Cleanup(func() { resolver = old })
	f := useActive(t)
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	reachable = func(context.Context, egress.Config) error {
		return errors.New("the target did not answer: connection refused")
	}
	var out, errb bytes.Buffer
	code := run([]string{"scan", "--no-save", "http://localhost:3000"}, &out, &errb)
	if code != exitInvalid || len(f.specs) != 0 || !strings.Contains(errb.String(), "connection refused; no test was sent") {
		t.Errorf("exit %d, %d runs\n%s%s", code, len(f.specs), out.String(), errb.String())
	}
}

func TestScanURLNotRun(t *testing.T) {
	old := resolver
	resolver = fakeResolver{"localhost": "127.0.0.1"}
	t.Cleanup(func() { resolver = old })
	f := useActive(t)
	t.Setenv("XDG_DATA_HOME", t.TempDir())

	// Not on Linux: nothing runs and the run is incomplete.
	hostOS = "darwin"
	var out, errb bytes.Buffer
	code := run([]string{"scan", "--no-save", "http://localhost"}, &out, &errb)
	hostOS = "linux"
	if code != report.ExitIncomplete || len(f.specs) != 0 || !strings.Contains(out.String(), "only on Linux") {
		t.Errorf("macOS: exit %d, %d runs\n%s", code, len(f.specs), out.String())
	}

	// The relay image missing and no terminal: nothing is installed, every
	// active plugin is skipped, and no audit entry or traffic follows.
	e := &fakeEngine{have: map[string]bool{}}
	for _, id := range []string{"zap", "zap-active"} {
		img, _ := runner.ImageFor(builtinManifest(t, id))
		e.have[img] = true
	}
	useEngine(t, e, nil)
	out.Reset()
	code = run([]string{"scan", "--no-save", "http://localhost"}, &out, &errb)
	if code != report.ExitIncomplete || len(f.specs) != 0 || len(e.pulled) != 0 || !strings.Contains(out.String(), "is not installed (no terminal to ask; use --yes)") {
		t.Errorf("relay missing: exit %d, %d runs, pulled %v\n%s", code, len(f.specs), e.pulled, out.String())
	}
	if _, err := os.Stat(filepath.Join(os.Getenv("XDG_DATA_HOME"), "siegekit", "audit.log")); err == nil {
		t.Error("audit entry written although nothing ran")
	}
}

func builtinManifest(t *testing.T, id string) *manifest.Manifest {
	t.Helper()
	all, err := plugins.Builtin()
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range all {
		if m.ID == id {
			return m
		}
	}
	t.Fatalf("no plugin %s", id)
	return nil
}

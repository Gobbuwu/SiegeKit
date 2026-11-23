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
	"github.com/Gobbuwu/SiegeKit/internal/deps"
	"github.com/Gobbuwu/SiegeKit/internal/egress"
	"github.com/Gobbuwu/SiegeKit/internal/files"
	"github.com/Gobbuwu/SiegeKit/internal/findings"
	"github.com/Gobbuwu/SiegeKit/internal/login"
	"github.com/Gobbuwu/SiegeKit/internal/manifest"
	"github.com/Gobbuwu/SiegeKit/internal/openapi"
	"github.com/Gobbuwu/SiegeKit/internal/publicmaps"
	"github.com/Gobbuwu/SiegeKit/internal/report"
	"github.com/Gobbuwu/SiegeKit/internal/runner"
	"github.com/Gobbuwu/SiegeKit/internal/sandbox"
	"github.com/Gobbuwu/SiegeKit/internal/served"
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

// fakeActive records active runs and writes an empty report for each
// tool: a ZAP report with one alert, and Nuclei's and ffuf's with none.
type fakeActive struct {
	specs []sandbox.Spec
	cfgs  []egress.Config
	// served maps paths on the target to the bodies specGet returns;
	// other paths answer 404. got lists the paths asked for.
	served map[string]string
	got    []string
	// spec holds the files in the OpenAPI mount of the last run.
	spec map[string]string
	// collected is what the served-secrets check fetched; leaks is the
	// Gitleaks report it gets. scanned lists the files Gitleaks was given.
	collected served.Result
	leaks     string
	scanned   []string
	servedCfg []egress.Config
	// content holds the bodies of collected files by name; others are "x".
	content map[string]string
}

// noLeaks is an empty Gitleaks report.
const noLeaks = `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"gitleaks"}},"results":[]}]}`

const testSpec = `{"openapi":"3.0.3","info":{"title":"t","version":"1"},"servers":[{"url":"/api"}],"paths":{"/items":{"get":{"responses":{"200":{"description":"ok"}}}}}}`

func useActive(t *testing.T) *fakeActive {
	t.Helper()
	f := &fakeActive{}
	old := activeRunner
	activeRunner = func(_ context.Context, s sandbox.Spec, c egress.Config) (*runner.ActiveResult, error) {
		f.specs, f.cfgs = append(f.specs, s), append(f.cfgs, c)
		for _, m := range s.Files {
			if m.Mount == runner.OpenAPIMount {
				f.spec = map[string]string{}
				es, _ := os.ReadDir(m.Host)
				for _, e := range es {
					b, _ := os.ReadFile(filepath.Join(m.Host, e.Name()))
					f.spec[e.Name()] = string(b)
				}
			}
		}
		if err := os.WriteFile(filepath.Join(s.OutDir, "zap.json"), []byte(strings.Replace(zapSARIF, "TARGET", c.Target.String(), 1)), 0o600); err != nil {
			return nil, err
		}
		if err := os.WriteFile(filepath.Join(s.OutDir, "nuclei.jsonl"), nil, 0o600); err != nil {
			return nil, err
		}
		if err := os.WriteFile(filepath.Join(s.OutDir, "ffuf.json"), []byte(`{"results":[]}`), 0o600); err != nil {
			return nil, err
		}
		if err := os.WriteFile(filepath.Join(s.OutDir, "schemathesis.json"), []byte(`{"complete":true,"operations":{"selected":1,"tested":1},"failures":[],"errors":[]}`), 0o600); err != nil {
			return nil, err
		}
		return &runner.ActiveResult{Result: &sandbox.Result{Status: sandbox.Completed}, Stats: egress.Stats{Requests: 3}}, nil
	}
	f.collected = served.Result{Files: []served.File{{Name: "001-page.html", URL: "start", Kind: served.Page}}, Requests: 1}
	f.leaks = noLeaks
	useEngine(t, &fakeEngine{run: fakeExec(func(s sandbox.Spec) (*sandbox.Result, error) {
		es, _ := os.ReadDir(s.TargetDir)
		for _, e := range es {
			f.scanned = append(f.scanned, e.Name())
		}
		return &sandbox.Result{Status: sandbox.Completed}, os.WriteFile(filepath.Join(s.OutDir, "gitleaks.sarif"), []byte(f.leaks), 0o644)
	})}, nil)
	oldCollect := servedCollect
	servedCollect = func(_ context.Context, cfg egress.Config, _ float64, dir string) (served.Result, error) {
		f.servedCfg = append(f.servedCfg, cfg)
		for _, file := range f.collected.Files {
			body, ok := f.content[file.Name]
			if !ok {
				body = "x"
			}
			if err := os.WriteFile(filepath.Join(dir, file.Name), []byte(body), 0o644); err != nil {
				return served.Result{}, err
			}
		}
		return f.collected, nil
	}
	t.Cleanup(func() { servedCollect = oldCollect })
	// These tests check the Linux path on every host; macOS is refused
	// (TestScanURLNotRun).
	f.served = map[string]string{"/openapi.json": testSpec}
	oldReach, oldFetch, oldOS, oldGet := reachable, deps.FetchFile, hostOS, specGet
	reachable, hostOS = func(context.Context, egress.Config) error { return nil }, "linux"
	specGet = func(_ context.Context, _ egress.Config, p string, _ int64) (int, []byte, error) {
		f.got = append(f.got, p)
		if b, ok := f.served[p]; ok {
			return 200, []byte(b), nil
		}
		return 404, []byte("not found"), nil
	}
	deps.FetchFile = func(context.Context, string, manifest.Artifact) error {
		return errors.New("tests download nothing")
	}
	t.Cleanup(func() {
		activeRunner, reachable, deps.FetchFile, hostOS, specGet = old, oldReach, oldFetch, oldOS, oldGet
	})
	t.Chdir(t.TempDir()) // reports go to ./siegekit-report
	return f
}

// useData gives the test its own data directory with every pinned file of
// the built-in plugins already installed, so no test downloads anything.
func useData(t *testing.T) string {
	t.Helper()
	data := t.TempDir()
	t.Setenv("XDG_DATA_HOME", data)
	all, err := plugins.Builtin()
	if err != nil {
		t.Fatal(err)
	}
	root := rootsIn(filepath.Join(data, "siegekit")).Files
	for _, m := range all {
		for _, a := range runner.FilesFor(m) {
			if err := os.MkdirAll(files.Dir(root, a), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(files.Dir(root, a)+".ok", nil, 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
	return data
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
	f := useActive(t)
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
		// Checks left out on deployed targets, or for want of a login, are
		// not missing dependencies (ADR 0041).
		{"typed --require-all", true, "shop.example\n", []string{"--require-all", "--only", "zap,zap-active,login-throttle,rate-limit,backend-live,access-control", "https://shop.example/app"}, exitOK, "Target allowed"},
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

	// public-maps sends only GETs, so it runs on deployed targets: each
	// spec path is tried once. The spec it finds is reported, not given
	// to Schemathesis, which does not run there (ADR 0046, ADR 0028).
	f.got = nil
	code, out = scan(true, "shop.example\n", "--only", "public-maps,schemathesis", "--report-dir", t.TempDir(), "https://shop.example/")
	if code != exitOK && code != report.ExitFindings || !slices.Equal(f.got, publicmaps.Paths()) ||
		!strings.Contains(out, "public-maps          ran        1 finding(s)") || !strings.Contains(out, "schemathesis         skipped") {
		t.Errorf("deployed public-maps: exit %d, spec requests %v\n%s", code, f.got, out)
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
	data := useData(t)
	var out, errb bytes.Buffer
	code := run([]string{"scan", "--fail-on", "medium", "--authorized-host", "localhost", "http://localhost:3000/app"}, &out, &errb)
	if code != report.ExitFindings {
		t.Fatalf("exit %d\n%s%s", code, out.String(), errb.String())
	}
	for _, want := range []string{
		"Plan: http://localhost:3000/app, local mode, addresses 127.0.0.1.",
		"zap-active           zap 2.17.0: ZAP attack scan (local targets only)",
		"only http://localhost:3000 is reachable",
		"(3 request(s) answered by the target, 0 refused by SiegeKit)",
	} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("output lacks %q:\n%s", want, out.String())
		}
	}
	// All seven plugins ran through the egress proxy with the local limits;
	// the ZAP plugins got their configuration naming the target as a JSON
	// string.
	if len(f.specs) != 7 {
		t.Fatalf("%d active runs", len(f.specs))
	}
	for i, s := range f.specs {
		c := f.cfgs[i]
		if c.Target.String() != "http://localhost:3000/app" || c.VerifyTLS || c.Rate != runner.LocalLimits.Rate || !slices.Equal(c.Addrs, []netip.Addr{netip.MustParseAddr("127.0.0.1")}) {
			t.Errorf("run %d egress config %+v", i, c)
		}
		if strings.HasPrefix(s.Image, "docker.io/zaproxy/") && (!slices.Contains(s.Args, sandbox.ConfigMount) || s.ConfigFile == "") {
			t.Errorf("run %d: config not passed: %v", i, s.Args)
		}
	}
	// The run is in the audit log before any traffic.
	b, err := os.ReadFile(filepath.Join(data, "siegekit", "audit.log"))
	if err != nil {
		t.Fatal(err)
	}
	var e audit.Entry
	if err := json.Unmarshal(b, &e); err != nil || e.Target != "http://localhost:3000/app" || e.Mode != "local" || e.Verification != "loopback + --authorized-host" || e.Confirmed != "localhost" || !slices.Equal(e.Plugins, []string{"ffuf", "nuclei", "nuclei-default-login", "nuclei-intrusive", "schemathesis", "zap", "zap-active", "served-secrets", "public-maps"}) {
		t.Errorf("audit entry %+v %v", e, err)
	}
	// The report names the URL and the request counts.
	b, err = os.ReadFile(filepath.Join("siegekit-report", "report.json"))
	if err != nil {
		t.Fatal(err)
	}
	var r report.Run
	if err := json.Unmarshal(b, &r); err != nil || r.Target != "http://localhost:3000/app" || len(r.Findings) != 2 || r.Plugins[12].Requests != 3 || r.Plugins[10].ID != "access-control" || r.Plugins[10].Status != report.Skipped ||
		r.Plugins[11].ID != "access-control-write" || r.Plugins[11].Status != report.Skipped || r.Plugins[11].Cause != report.CauseNoInput || !strings.Contains(r.Plugins[11].Reason, "--replay-writes") ||
		r.Plugins[9].ID != "public-maps" || r.Plugins[9].Status != report.Ran || r.Plugins[9].Requests != len(publicmaps.Paths()) || r.Plugins[9].Findings != 1 ||
		r.Plugins[8].ID != "storage-write" || r.Plugins[8].Status != report.Skipped || r.Plugins[8].Cause != report.CauseNoInput || !strings.Contains(r.Plugins[8].Reason, "--storage-url") ||
		r.Plugins[7].ID != "backend-live" || r.Plugins[7].Status != report.Skipped || !strings.Contains(r.Plugins[7].Reason, "no backend URL was given") || r.Plugins[6].ID != "served-secrets" || r.Plugins[6].Status != report.Ran ||
		r.Plugins[3].ID != "reset-limit" || r.Plugins[3].Status != report.Skipped || r.Plugins[3].Cause != report.CauseNoInput || !strings.Contains(r.Plugins[3].Reason, "--reset-url and --reset-body") ||
		r.Plugins[4].ID != "signup-limit" || r.Plugins[4].Status != report.Skipped || r.Plugins[5].ID != "code-limit" || r.Plugins[5].Status != report.Skipped ||
		r.Plugins[1].ID != "login-spray" || r.Plugins[1].Status != report.Skipped || r.Plugins[1].Cause != report.CauseNoInput ||
		r.Plugins[2].ID != "rate-limit" || r.Plugins[2].Status != report.Skipped || !strings.Contains(r.Plugins[2].Reason, "no URL was given") || r.Plugins[0].ID != "login-throttle" || r.Plugins[0].Status != report.Skipped || !strings.Contains(r.Plugins[0].Reason, "no login was given") {
		t.Errorf("report %+v %v", r, err)
	}
	if f := r.Findings[0]; f.Location.URI != "http://localhost:3000/app" || !slices.Equal(f.CWEs, []string{"CWE-1021"}) || !strings.HasPrefix(f.HelpURI, "https://developer.mozilla.org/") {
		t.Errorf("finding %+v", f)
	}
	// The spec served at the first default path is an "attack map" (ADR 0046).
	if f := r.Findings[1]; f.RuleID != "public-api-spec" || f.Location.URI != "http://localhost:3000/openapi.json" || f.Severity != findings.Low {
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
		{"no terminal", nil, false, "", 3, "loopback", "pass --authorized-host localhost if you"},
		{"--yes does not count", []string{"--yes"}, false, "", 3, "loopback", "needs a person's confirmation"},
		{"typed yes", nil, true, "yes\n", 7, "loopback + typed yes", "Type yes to run them"},
		{"typed no", nil, true, "no\n", 3, "loopback", `"yes" was not typed`},
		{"flag", []string{"--authorized-host", "LOCALHOST"}, false, "", 7, "loopback + --authorized-host", "zap-active"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := useActive(t)
			data := useData(t)
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
			if err != nil || json.Unmarshal(b, &e) != nil || e.Verification != tc.verification || len(e.Plugins) != tc.runs+2 || e.Plugins[tc.runs] != "served-secrets" || e.Plugins[tc.runs+1] != "public-maps" {
				t.Errorf("audit entry %+v %v", e, err)
			}
			if tc.runs == 3 { // the four destructive plugins were skipped
				b, err := os.ReadFile(filepath.Join("siegekit-report", "report.json"))
				var r report.Run
				if err != nil || json.Unmarshal(b, &r) != nil || len(r.Plugins) != 19 {
					t.Fatalf("report %+v %v", r.Plugins, err)
				}
				for _, p := range r.Plugins {
					destructive := slices.Contains([]string{"nuclei-default-login", "nuclei-intrusive", "schemathesis", "zap-active"}, p.ID)
					if destructive && (p.Status != report.Skipped || p.Reason == "") || !destructive && !slices.Contains([]string{"login-throttle", "login-spray", "rate-limit", "reset-limit", "signup-limit", "code-limit"}, p.ID) && p.ID != "access-control" && p.ID != "access-control-write" && p.ID != "backend-live" && p.ID != "storage-write" && p.Status != report.Ran {
						t.Errorf("plugin %+v", p)
					}
				}
				// When Schemathesis does not run, the spec paths are tried
				// only for public-maps, once each, after the plugins that
				// skip (ADR 0046).
				if !slices.Equal(f.got, publicmaps.Paths()) {
					t.Errorf("spec requests %v", f.got)
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

	// The relay image missing and no terminal: nothing is installed and
	// every plugin is skipped. Only public-maps, which needs no image,
	// sends its GET requests (ADR 0046).
	e := &fakeEngine{have: map[string]bool{}}
	for _, id := range []string{"zap", "zap-active"} {
		img, _ := runner.ImageFor(builtinManifest(t, id))
		e.have[img] = true
	}
	useEngine(t, e, nil)
	out.Reset()
	code = run([]string{"scan", "--no-save", "http://localhost"}, &out, &errb)
	if code == report.ExitIncomplete || len(f.specs) != 0 || len(e.pulled) != 0 || !strings.Contains(out.String(), "is not installed (no terminal to ask; use --yes)") {
		t.Errorf("relay missing: exit %d, %d runs, pulled %v\n%s", code, len(f.specs), e.pulled, out.String())
	}
	b, err := os.ReadFile(filepath.Join(os.Getenv("XDG_DATA_HOME"), "siegekit", "audit.log"))
	var a audit.Entry
	if err != nil || json.Unmarshal(b, &a) != nil || !slices.Equal(a.Plugins, []string{"public-maps"}) {
		t.Errorf("audit entry %+v %v", a, err)
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

// TestScanURLOpenAPI checks how Schemathesis gets its spec (ADR 0025 item
// 4, ADR 0028): --openapi FILE is read before any request, --openapi URL
// must be on the target's origin, and without the flag the default paths
// are tried on local targets, after the run is in the audit log.
func TestScanURLOpenAPI(t *testing.T) {
	old := resolver
	resolver = fakeResolver{"localhost": "127.0.0.1"}
	t.Cleanup(func() { resolver = old })
	specFile := filepath.Join(t.TempDir(), "api.yaml")
	if err := os.WriteFile(specFile, []byte("openapi: 3.0.3\nservers:\n  - url: /v1\npaths: {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name    string
		openapi string
		served  map[string]string
		code    int
		status  report.Status
		want    string // in the plugin's input or reason, or in stderr when refused
		gets    int
	}{
		{"file", specFile, nil, report.ExitClean, report.Ran, "OpenAPI spec " + specFile, 0},
		{"url", "http://localhost:3000/docs/spec.json", map[string]string{"/docs/spec.json": testSpec}, report.ExitClean, report.Ran, "OpenAPI spec http://localhost:3000/docs/spec.json", 1},
		{"url not served", "http://localhost:3000/docs/spec.json", nil, report.ExitIncomplete, report.Failed, "could not be used: answered 404", 1},
		{"url not a spec", "http://localhost:3000/docs", map[string]string{"/docs": "<html></html>"}, report.ExitIncomplete, report.Failed, "an HTML page", 1},
		// Every path is tried once, for public-maps too (ADR 0046); the first spec is used.
		{"default path", "", map[string]string{"/v3/api-docs": testSpec, "/api/openapi.json": testSpec}, report.ExitClean, report.Ran, "OpenAPI spec http://localhost:3000/v3/api-docs", len(publicmaps.Paths())},
		{"swagger ui", "", map[string]string{openapi.SwaggerUIInitPath: "var options = {\n  \"swaggerDoc\": " + testSpec + "\n};"}, report.ExitClean, report.Ran,
			"OpenAPI spec http://localhost:3000/api-docs/swagger-ui-init.js (the spec in the Swagger UI setup script)", len(publicmaps.Paths())},
		{"none found", "", map[string]string{}, report.ExitIncomplete, report.Skipped, "none was found at /openapi.json, /openapi.yaml", len(publicmaps.Paths())},
		{"other origin", "http://localhost:3001/spec.json", nil, exitInvalid, "", "is not on the target's origin", 0},
		// F7 of the full project check (ADR 0042): refused here, not later by the proxy.
		{"double slash", "http://localhost:3000//x/openapi.json", nil, exitInvalid, "", "--openapi must have a path that starts with a single /", 0},
		{"query", "http://localhost:3000/spec.json?v=1", nil, exitInvalid, "", "--openapi must not have a query", 0},
		{"missing file", filepath.Join(t.TempDir(), "nope.json"), nil, exitInvalid, "", "no such file", 0},
		{"file not a spec", "/dev/null", nil, exitInvalid, "", "empty document", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := useActive(t)
			useData(t)
			if tc.served != nil {
				f.served = tc.served
			}
			args := []string{"scan", "--no-save", "--authorized-host", "localhost", "--only", "schemathesis"}
			if tc.openapi != "" {
				args = append(args, "--openapi", tc.openapi)
			}
			var out, errb bytes.Buffer
			code := run(append(args, "http://localhost:3000/"), &out, &errb)
			if code != tc.code || len(f.got) != tc.gets {
				t.Fatalf("exit %d (want %d), spec requests %v (want %d)\n%s%s", code, tc.code, f.got, tc.gets, out.String(), errb.String())
			}
			if tc.code == exitInvalid {
				if !strings.Contains(errb.String(), tc.want) || len(f.specs) != 0 {
					t.Errorf("stderr lacks %q or a test ran:\n%s", tc.want, errb.String())
				}
				return
			}
			b, err := os.ReadFile(filepath.Join("siegekit-report", "report.json"))
			var r report.Run
			if err != nil || json.Unmarshal(b, &r) != nil || len(r.Plugins) != 1 {
				t.Fatalf("report %+v %v", r, err)
			}
			p := r.Plugins[0]
			if p.Status != tc.status || !strings.Contains(p.Input+p.Reason, tc.want) {
				t.Errorf("plugin %+v, want %s with %q", p, tc.status, tc.want)
			}
			if tc.status != report.Ran {
				if len(f.specs) != 0 {
					t.Errorf("%d runs", len(f.specs))
				}
				return
			}
			// The spec is mounted read-only, and Schemathesis gets the
			// target's origin so that the spec's base path applies.
			s := f.specs[0]
			name := "spec.json"
			if tc.name == "file" {
				name = "spec.yaml"
			}
			if joined := strings.Join(s.Args, " "); !strings.Contains(joined, "run /siegekit/files/openapi/"+name+" --origin http://localhost:3000 ") {
				t.Errorf("args %s", joined)
			}
			if len(f.spec) != 1 || !strings.Contains(f.spec[name], "openapi: 3.0.3") && f.spec[name] != testSpec {
				t.Errorf("spec mounted: %v", f.spec)
			}
		})
	}
	// --openapi is only for URL targets.
	var out, errb bytes.Buffer
	if code := run([]string{"scan", "--openapi", specFile, t.TempDir()}, &out, &errb); code != exitUsage {
		t.Errorf("directory scan with --openapi: exit %d", code)
	}
}

// TestScanURLProfile checks --profile (owner decision 2026-11-20): quick
// leaves out the attack tests and says so in the report, without asking
// for confirmation; full is the default; other names are usage errors.
func TestScanURLProfile(t *testing.T) {
	old := resolver
	resolver = fakeResolver{"localhost": "127.0.0.1"}
	t.Cleanup(func() { resolver = old })
	f := useActive(t)
	useData(t)
	var out, errb bytes.Buffer
	code := run([]string{"scan", "--no-save", "--profile", "quick", "http://localhost:3000/"}, &out, &errb)
	if code != report.ExitClean && code != report.ExitFindings || len(f.specs) != 3 || strings.Contains(out.String(), "Type yes") || len(f.got) != len(publicmaps.Paths()) {
		t.Fatalf("exit %d, %d runs, spec requests %v\n%s%s", code, len(f.specs), f.got, out.String(), errb.String())
	}
	b, err := os.ReadFile(filepath.Join("siegekit-report", "report.json"))
	var r report.Run
	if err != nil || json.Unmarshal(b, &r) != nil || len(r.Plugins) != 19 {
		t.Fatalf("report %+v %v", r.Plugins, err)
	}
	for _, p := range r.Plugins {
		if p.ID == "access-control" || p.ID == "backend-live" { // GET and HEAD only, so in the quick profile; skipped here for want of input
			if p.Status != report.Skipped || !strings.Contains(p.Reason, "no HAR file") && !strings.Contains(p.Reason, "no backend URL") {
				t.Errorf("plugin %+v", p)
			}
			continue
		}
		quick := p.ID == "ffuf" || p.ID == "nuclei" || p.ID == "zap" || p.ID == "served-secrets" || p.ID == "public-maps"
		if quick && p.Status != report.Ran || !quick && (p.Status != report.Skipped || !strings.Contains(p.Reason, "--profile quick")) {
			t.Errorf("plugin %+v", p)
		}
	}
	for _, c := range []struct {
		args []string
		code int
		want string
	}{
		{[]string{"--profile", "fast"}, exitUsage, "--profile must be one of full, quick"},
		{[]string{"--profile", "quick", "--only", "zap-active"}, exitInvalid, "--only names zap-active, which --profile quick does not run"},
	} {
		f := useActive(t)
		var out, errb bytes.Buffer
		if code := run(append(append([]string{"scan", "--no-save"}, c.args...), "http://localhost:3000/"), &out, &errb); code != c.code || !strings.Contains(errb.String(), c.want) || len(f.specs) != 0 {
			t.Errorf("%v: exit %d, %d runs:\n%s", c.args, code, len(f.specs), errb.String())
		}
	}
}

// useLogin replaces the login throttling check and records its calls.
func useLogin(t *testing.T, res login.Result, err error) *[]egress.Config {
	t.Helper()
	var calls []egress.Config
	old := loginCheck
	t.Setenv(login.PasswordEnv, testPassword)
	loginCheck = func(_ context.Context, cfg egress.Config, l *login.Login, attempts int, right string) (login.Result, error) {
		calls = append(calls, cfg)
		if l.User != "tester" || l.Path != "/rest/user/login" || attempts != 7 || right != testPassword {
			t.Errorf("login check %+v, %d attempts", l, attempts)
		}
		return res, err
	}
	t.Cleanup(func() { loginCheck = old })
	return &calls
}

// testPassword is the test account's password in SIEGEKIT_LOGIN_PASSWORD.
const testPassword = "Tester-pw-77"

var loginArgs = []string{"--login-url", "http://localhost:3000/rest/user/login", "--login-user", "tester", "--login-body", `{"email":"{user}","password":"{password}"}`, "--login-attempts", "7"}

func TestScanURLLogin(t *testing.T) {
	old := resolver
	resolver = fakeResolver{"localhost": "127.0.0.1", "shop.example": "93.184.215.14"}
	t.Cleanup(func() { resolver = old })
	scan := func(tty bool, input string, args ...string) (int, string) {
		t.Helper()
		stdinIsTerminal = func() bool { return tty }
		stdin = strings.NewReader(input)
		var out, errb bytes.Buffer
		code := run(append([]string{"scan", "--no-save"}, args...), &out, &errb)
		return code, out.String() + errb.String()
	}
	readReport := func() report.Run {
		t.Helper()
		b, err := os.ReadFile(filepath.Join("siegekit-report", "report.json"))
		var r report.Run
		if err != nil || json.Unmarshal(b, &r) != nil || r.Plugins[0].ID != "login-throttle" {
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
		{[]string{"--login-url", "http://localhost:3000/login", "http://localhost:3000/"}, exitUsage, "needed together"},
		{[]string{"--login-attempts", "5", "http://localhost:3000/"}, exitUsage, "--login-attempts needs"},
		{append(slices.Clone(loginArgs[:6]), "--login-attempts", "51", "http://localhost:3000/"), exitUsage, "from 2 to 50"},
		{append(slices.Clone(loginArgs[:6]), "--login-attempts", "1", "http://localhost:3000/"), exitUsage, "from 2 to 50"},
		{append(slices.Clone(loginArgs), t.TempDir()), exitUsage, "only apply to URL targets"},
		{[]string{"--login-url", "http://localhost:3001/login", "--login-user", "tester", "--login-body", "u={user}&p={password}", "http://localhost:3000/"}, exitInvalid, "not on the target's origin"},
		{[]string{"--login-url", "http://localhost:3000/login", "--login-user", "tester", "--login-body", "u={user}", "http://localhost:3000/"}, exitInvalid, "must contain {user} and {password}"},
	} {
		f := useActive(t)
		data := useData(t)
		calls := useLogin(t, login.Result{}, nil)
		code, out := scan(false, "", c.args...)
		if code != c.code || !strings.Contains(out, c.want) || len(f.specs)+len(*calls) != 0 {
			t.Errorf("%v: exit %d, %d runs, %d login checks\n%s", c.args, code, len(f.specs), len(*calls), out)
		}
		if _, err := os.Stat(filepath.Join(data, "siegekit", "audit.log")); err == nil {
			t.Errorf("%v: audit entry written", c.args)
		}
	}

	// Confirmed local run: the check runs first, with POST allowed, and a
	// login without a limit is a medium finding.
	f := useActive(t)
	data := useData(t)
	calls := useLogin(t, login.Result{Attempts: 7, Requests: 8, Baseline: 401, Right: "answered 200"}, nil)
	code, out := scan(false, "", append(slices.Clone(loginArgs), "--authorized-host", "localhost", "--only", "login-throttle,zap", "http://localhost:3000/")...)
	if code != report.ExitClean || len(*calls) != 1 || (*calls)[0].ReadOnly || len(f.specs) != 1 ||
		!strings.Contains(out, `login-throttle       siegekit 0.0.0-dev: 1 login for "tester" with its password from SIEGEKIT_LOGIN_PASSWORD, then 7 with a random wrong password, POST http://localhost:3000/rest/user/login, one per second; the account may be locked`) {
		t.Fatalf("exit %d, %d checks, %d runs\n%s", code, len(*calls), len(f.specs), out)
	}
	b, err := os.ReadFile(filepath.Join(data, "siegekit", "audit.log"))
	var e audit.Entry
	if err != nil || json.Unmarshal(b, &e) != nil || !slices.Equal(e.Plugins, []string{"zap", "login-throttle"}) || e.Verification != "loopback + --authorized-host" {
		t.Errorf("audit entry %+v %v", e, err)
	}
	r := readReport()
	p := r.Plugins[0]
	if p.Status != report.Ran || p.Requests != 8 || p.Findings != 1 || p.Input != `POST http://localhost:3000/rest/user/login as "tester"` || p.Result != "no limit seen in 7 attempts, all answered 401; the right password answered 200" {
		t.Errorf("plugin %+v", p)
	}
	// The password is never written: not in the output, the report or the
	// audit log.
	rb, _ := os.ReadFile(filepath.Join("siegekit-report", "report.json"))
	if strings.Contains(out+string(b)+string(rb), testPassword) {
		t.Error("the password was written")
	}
	var lf *findings.Finding
	for i := range r.Findings {
		if r.Findings[i].RuleID == "login-not-limited" {
			lf = &r.Findings[i]
		}
	}
	if lf == nil || lf.Severity != findings.Medium || lf.Location.URI != "http://localhost:3000/rest/user/login" || len(r.Findings) != 2 {
		t.Errorf("findings %+v", r.Findings)
	}
	// --fail-on medium makes it fail the run.
	useActive(t)
	useData(t)
	useLogin(t, login.Result{Attempts: 7, Baseline: 401}, nil)
	if code, out := scan(false, "", append(slices.Clone(loginArgs), "--authorized-host", "localhost", "--only", "login-throttle", "--fail-on", "medium", "http://localhost:3000/")...); code != report.ExitFindings {
		t.Errorf("--fail-on medium: exit %d\n%s", code, out)
	}

	// A limit seen is a result, not a finding; a failed check makes the run
	// incomplete.
	useActive(t)
	useData(t)
	useLogin(t, login.Result{Attempts: 4, Limited: true, Signal: "answered 429", Baseline: 401}, nil)
	scan(false, "", append(slices.Clone(loginArgs), "--authorized-host", "localhost", "--only", "login-throttle", "http://localhost:3000/")...)
	if p := readReport().Plugins[0]; p.Status != report.Ran || p.Findings != 0 || p.Result != "limited after 4 of 7 attempts: answered 429" {
		t.Errorf("limited: %+v", p)
	}
	useActive(t)
	useData(t)
	useLogin(t, login.Result{}, errors.New("the login URL answered 404 to a POST; check --login-url"))
	if code, _ := scan(false, "", append(slices.Clone(loginArgs), "--authorized-host", "localhost", "--only", "login-throttle", "http://localhost:3000/")...); code != report.ExitIncomplete || readReport().Plugins[0].Status != report.Failed {
		t.Errorf("failed check: exit %d %+v", code, readReport().Plugins[0])
	}

	// Loopback needs a person's confirmation: typed yes runs it, anything
	// else skips it, and --profile quick leaves it out.
	for _, c := range []struct {
		name  string
		tty   bool
		input string
		extra []string
		runs  int
		want  string
	}{
		{"typed yes", true, "yes\n", nil, 1, `login-throttle can lock the test account "tester". Type yes`},
		{"typed no", true, "no\n", nil, 0, `not confirmed: "yes" was not typed`},
		{"no terminal", false, "", nil, 0, "needs a person's confirmation"},
		{"quick", true, "yes\n", []string{"--profile", "quick", "--only", "dast"}, 0, "not run with --profile quick"},
	} {
		t.Run(c.name, func(t *testing.T) {
			useActive(t)
			useData(t)
			calls := useLogin(t, login.Result{Attempts: 7, Baseline: 401}, nil)
			extra := c.extra
			if extra == nil {
				extra = []string{"--only", "login-throttle"}
			}
			args := append(append(slices.Clone(loginArgs), extra...), "http://localhost:3000/")
			code, out := scan(c.tty, c.input, args...)
			if len(*calls) != c.runs || !strings.Contains(out, c.want) {
				t.Errorf("exit %d, %d checks\n%s", code, len(*calls), out)
			}
		})
	}
	if code, out := scan(true, "yes\n", append(slices.Clone(loginArgs), "--profile", "quick", "--only", "zap,login-throttle", "http://localhost:3000/")...); code != exitInvalid || !strings.Contains(out, "--only names login-throttle, which --profile quick does not run") {
		t.Errorf("--only with quick: exit %d\n%s", code, out)
	}

	// Deployed targets: never run, whatever is confirmed (ADR 0025).
	useActive(t)
	data = useData(t)
	calls = useLogin(t, login.Result{Attempts: 7, Baseline: 401}, nil)
	tok, err := verify.Token(filepath.Join(data, "siegekit", "verify"), "shop.example")
	if err != nil {
		t.Fatal(err)
	}
	useProver(t, &fakeProver{published: map[string]string{"shop.example": verify.Value(tok)}})
	deployedArgs := []string{"--deployed", "--login-url", "https://shop.example/rest/user/login", "--login-user", "tester", "--login-body", "u={user}&p={password}", "--login-attempts", "7", "--only", "login-throttle,zap", "https://shop.example/"}
	code, out = scan(true, "shop.example\n", deployedArgs...)
	if code != exitOK || len(*calls) != 0 || !strings.Contains(out, "login-throttle       not run - runs only on local targets") {
		t.Errorf("deployed: exit %d, %d checks\n%s", code, len(*calls), out)
	}
	if p := readReport().Plugins[0]; p.Status != report.Skipped || p.Requests != 0 {
		t.Errorf("deployed: %+v", p)
	}

	// No password: skipped with the reason; a bad one is refused before
	// any request (ADR 0062).
	useActive(t)
	useData(t)
	calls = useLogin(t, login.Result{Attempts: 7, Baseline: 401}, nil)
	os.Unsetenv(login.PasswordEnv)
	code, out = scan(false, "", append(slices.Clone(loginArgs), "--authorized-host", "localhost", "--only", "login-throttle", "http://localhost:3000/")...)
	if p := readReport().Plugins[0]; len(*calls) != 0 || p.Status != report.Skipped || p.Cause != report.CauseNoInput || !strings.Contains(p.Reason, "set SIEGEKIT_LOGIN_PASSWORD") {
		t.Errorf("no password: exit %d %+v\n%s", code, p, out)
	}
	for _, pw := range []string{"", "a\nb"} {
		f := useActive(t)
		useData(t)
		calls = useLogin(t, login.Result{}, nil)
		t.Setenv(login.PasswordEnv, pw)
		code, out = scan(false, "", append(slices.Clone(loginArgs), "--authorized-host", "localhost", "--only", "login-throttle", "http://localhost:3000/")...)
		if code != exitInvalid || len(*calls)+len(f.specs) != 0 || !strings.Contains(out, "SIEGEKIT_LOGIN_PASSWORD") || strings.Contains(out, "a\nb") {
			t.Errorf("password %q: exit %d\n%s", pw, code, out)
		}
	}

	// --login-page: the form on the page; not with --login-url.
	useActive(t)
	useData(t)
	var pages []*login.Login
	old2 := loginCheck
	t.Cleanup(func() { loginCheck = old2 })
	t.Setenv(login.PasswordEnv, testPassword)
	loginCheck = func(_ context.Context, cfg egress.Config, l *login.Login, attempts int, right string) (login.Result, error) {
		pages = append(pages, l)
		return login.Result{Attempts: 7, Requests: 16, Baseline: 303, Redirect: "/error", Right: "answered 303 to /", URL: "http://localhost:3000/login", Form: `multipart/form-data, button "Log in"`}, nil
	}
	pageArgs := []string{"--login-page", "http://localhost:3000/login", "--login-user", "tester", "--login-body", "email={user}&password={password}", "--login-attempts", "7", "--authorized-host", "localhost", "--only", "login-throttle", "http://localhost:3000/"}
	code, out = scan(false, "", pageArgs...)
	p = readReport().Plugins[0]
	if len(pages) != 1 || !pages[0].Page || pages[0].URL != "http://localhost:3000/login" || p.Requests != 16 ||
		p.Input != `the form on http://localhost:3000/login (POST http://localhost:3000/login, multipart/form-data, button "Log in") as "tester"` ||
		!strings.Contains(out, "then 7 with a random wrong password, the form on http://localhost:3000/login, one per second") {
		t.Errorf("--login-page: exit %d %+v\n%s", code, p, out)
	}
	for _, c := range []struct {
		args []string
		want string
	}{
		{append([]string{"--login-url", "http://localhost:3000/login"}, pageArgs...), "cannot be used together"},
		{[]string{"--login-page", "http://localhost:3000/login", "--login-user", "tester", "--login-body", `{"e":"{user}","p":"{password}"}`, "http://localhost:3000/"}, "as a form body"},
	} {
		if code, out := scan(false, "", c.args...); code == exitOK || !strings.Contains(out, c.want) || len(pages) != 1 {
			t.Errorf("%v: exit %d\n%s", c.args, code, out)
		}
	}
}

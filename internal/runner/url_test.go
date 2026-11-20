package runner

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

	"github.com/Gobbuwu/SiegeKit/internal/egress"
	"github.com/Gobbuwu/SiegeKit/internal/files"
	"github.com/Gobbuwu/SiegeKit/internal/manifest"
	"github.com/Gobbuwu/SiegeKit/internal/openapi"
	"github.com/Gobbuwu/SiegeKit/internal/report"
	"github.com/Gobbuwu/SiegeKit/internal/sandbox"
	"github.com/Gobbuwu/SiegeKit/internal/target"
	"github.com/Gobbuwu/SiegeKit/internal/wordlists"
)

const zapReport = `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"ZAP","rules":[{"id":"10021","name":"X-Content-Type-Options Header Missing",
"relationships":[{"target":{"id":"693","toolComponent":{"name":"CWE"}}}]}]}},
"results":[{"ruleId":"10021","level":"note","message":{"text":"missing"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"http://app.test:8000/"},"region":{"startLine":1}}}]}]}]}`

func urlOpts(t *testing.T) URLOptions {
	t.Helper()
	u, err := target.Parse("http://app.test:8000/")
	if err != nil {
		t.Fatal(err)
	}
	return URLOptions{Version: "test", Target: u, Addrs: []netip.Addr{netip.MustParseAddr("127.0.0.1")}, Limits: LocalLimits}
}

func TestRunURL(t *testing.T) {
	zap, active := builtin(t, "zap"), builtin(t, "zap-active")
	var configs []map[string]any
	result := func(res *ActiveResult) ActiveRunner {
		return func(_ context.Context, sp sandbox.Spec, c egress.Config) (*ActiveResult, error) {
			b, err := os.ReadFile(sp.ConfigFile)
			if err != nil {
				return nil, err
			}
			var m map[string]any
			if err := json.Unmarshal(b, &m); err != nil {
				return nil, err
			}
			configs = append(configs, m)
			if c.Target.String() != "http://app.test:8000/" || c.MaxServerErrors != LocalLimits.MaxServerErrors || c.ReadOnly {
				t.Errorf("egress config %+v", c)
			}
			os.WriteFile(filepath.Join(sp.OutDir, "zap.json"), []byte(zapReport), 0o600)
			return res, nil
		}
	}
	ok := &ActiveResult{Result: &sandbox.Result{Status: sandbox.Completed}, Stats: egress.Stats{Requests: 5, Refused: 1}}
	r, err := RunURL(context.Background(), result(ok), []*manifest.Manifest{zap, active}, urlOpts(t))
	if err != nil {
		t.Fatal(err)
	}
	if r.Target != "http://app.test:8000/" || r.Mode != "local" || len(r.Plugins) != 2 || len(r.Findings) != 1 {
		t.Fatalf("run %+v", r)
	}
	for _, p := range r.Plugins {
		if p.Status != report.Ran || p.Requests != 5 || p.Refused != 1 || p.Findings != 1 {
			t.Errorf("plugin %+v", p)
		}
	}
	if f := r.Findings[0]; f.Location.URI != "http://app.test:8000/" || len(f.CWEs) != 1 || f.CWEs[0] != "CWE-693" || len(f.Sources) != 2 {
		t.Errorf("finding %+v", f)
	}
	// The configuration names the target as JSON strings.
	ctx := configs[0]["env"].(map[string]any)["contexts"].([]any)[0].(map[string]any)
	if ctx["urls"].([]any)[0] != "http://app.test:8000/" || ctx["includePaths"].([]any)[0] != `http://app\.test:8000/.*` {
		t.Errorf("context %v", ctx)
	}

	// Deployed: the attack scan is skipped, and the proxy checks TLS.
	opt := urlOpts(t)
	opt.Deployed, opt.Limits = true, DeployedLimits
	r, err = RunURL(context.Background(), func(_ context.Context, sp sandbox.Spec, c egress.Config) (*ActiveResult, error) {
		if !c.VerifyTLS || c.Rate != DeployedLimits.Rate || !c.ReadOnly {
			t.Errorf("deployed egress config %+v", c)
		}
		os.WriteFile(filepath.Join(sp.OutDir, "zap.json"), []byte(zapReport), 0o600)
		return ok, nil
	}, []*manifest.Manifest{zap, active}, opt)
	if err != nil || r.Mode != "deployed" || r.Plugins[0].Status != report.Ran || r.Plugins[1].Status != report.Skipped || !strings.Contains(r.Plugins[1].Reason, "only on local targets") {
		t.Errorf("deployed: %+v %v", r, err)
	}

	for name, tc := range map[string]struct {
		res  *ActiveResult
		err  error
		want report.Status
		why  string
	}{
		"stopped":     {&ActiveResult{Result: &sandbox.Result{Status: sandbox.Failed, ExitCode: -1}, Stats: egress.Stats{Requests: 9}, Stopped: "3 server errors in a row"}, nil, report.Failed, "stopped by SiegeKit: 3 server errors"},
		"timed out":   {&ActiveResult{Result: &sandbox.Result{Status: sandbox.TimedOut}, Stats: egress.Stats{Requests: 9}}, nil, report.TimedOut, "stopped after"},
		"exit code":   {&ActiveResult{Result: &sandbox.Result{Status: sandbox.Completed, ExitCode: 1, Stderr: "Automation plan failures"}, Stats: egress.Stats{Requests: 9}}, nil, report.Failed, "Automation plan failures"},
		"no requests": {&ActiveResult{Result: &sandbox.Result{Status: sandbox.Completed}}, nil, report.Failed, "answered no request"},
		"relay error": {nil, errors.New("start relay: no image"), report.Failed, "start relay"},
	} {
		r, err := RunURL(context.Background(), func(context.Context, sandbox.Spec, egress.Config) (*ActiveResult, error) {
			return tc.res, tc.err
		}, []*manifest.Manifest{zap}, urlOpts(t))
		if err != nil || r.Plugins[0].Status != tc.want || !strings.Contains(r.Plugins[0].Reason, tc.why) || len(r.Findings) != 0 {
			t.Errorf("%s: %+v %v", name, r.Plugins, err)
		}
	}

	// Plugins missing a dependency are reported, not run.
	opt = urlOpts(t)
	opt.Unavailable = map[string]Unavailable{"zap": {Status: report.Skipped, Reason: "you declined"}}
	r, err = RunURL(context.Background(), nil, []*manifest.Manifest{zap}, opt)
	if err != nil || r.Plugins[0].Status != report.Skipped {
		t.Errorf("unavailable: %+v %v", r, err)
	}
	if _, err := RunURL(context.Background(), nil, nil, URLOptions{}); err == nil {
		t.Error("no target accepted")
	}
}

func TestConfigForKeepsTargetAString(t *testing.T) {
	in := map[string]any{"a": []any{"{target}", map[string]any{"b": "x{target-regex}y"}}, "n": 3.0, "t": true}
	b, err := json.Marshal(configFor(in, `http://h/"}],"x":{"`))
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	if len(out) != 3 || out["a"].([]any)[0] != `http://h/"}],"x":{"` || out["n"] != 3.0 {
		t.Errorf("config %s", b)
	}
	if got := out["a"].([]any)[1].(map[string]any)["b"]; got != `xhttp://h/"\}\],"x":\{"y` {
		t.Errorf("regex %q", got)
	}
}

func TestSkipReason(t *testing.T) {
	zap, active, gitleaks := builtin(t, "zap"), builtin(t, "zap-active"), builtin(t, "gitleaks")
	if SkipReason(zap, false) != "" || SkipReason(zap, true) != "" || SkipReason(active, false) != "" {
		t.Error("runnable plugin skipped")
	}
	if !strings.Contains(SkipReason(active, true), "only on local targets") || !strings.Contains(SkipReason(gitleaks, false), "only active plugins") {
		t.Error("missing skip reason")
	}
	destructive := *zap
	d := true
	destructive.Destructive = &d
	if !strings.Contains(SkipReason(&destructive, true), "does not run on deployed targets") {
		t.Error("destructive plugin not skipped on a deployed target")
	}
}

// TestWordlist checks that a URL plugin gets the shipped list for the
// target's mode, mounted read-only at {wordlist} (ADR 0027).
func TestWordlist(t *testing.T) {
	m := builtin(t, "ffuf")
	root := t.TempDir()
	for _, a := range FilesFor(m) {
		if err := os.MkdirAll(files.Dir(root, a), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(files.Dir(root, a)+".ok", nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for _, deployed := range []bool{false, true} {
		opt := urlOpts(t)
		opt.FilesRoot, opt.Deployed = root, deployed
		want, _ := wordlists.Get("seclists-common.txt")
		if deployed {
			opt.Limits = DeployedLimits
			want, _ = wordlists.Get("deployed.txt")
		}
		var got []byte
		r, err := RunURL(context.Background(), func(_ context.Context, sp sandbox.Spec, _ egress.Config) (*ActiveResult, error) {
			if !slices.Contains(sp.Args, WordlistMount+"/paths.txt") || !slices.Contains(sp.Args, "http://app.test:8000/FUZZ") {
				t.Errorf("args %v", sp.Args)
			}
			for _, f := range sp.Files {
				if f.Mount == WordlistMount {
					got, _ = os.ReadFile(filepath.Join(f.Host, "paths.txt"))
				}
			}
			os.WriteFile(filepath.Join(sp.OutDir, "ffuf.json"), []byte(`{"results":[{"status":200,"length":3,"url":"http://app.test:8000/.env"}]}`), 0o600)
			return &ActiveResult{Result: &sandbox.Result{Status: sandbox.Completed}, Stats: egress.Stats{Requests: 1}}, nil
		}, []*manifest.Manifest{m}, opt)
		if err != nil || r.Plugins[0].Status != report.Ran || len(r.Findings) != 1 {
			t.Errorf("deployed %v: %+v %v", deployed, r, err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("deployed %v: mounted list of %d bytes, want %d", deployed, len(got), len(want))
		}
	}
}

// TestOpenAPISpec checks that Schemathesis is skipped without a spec, gets
// the spec mounted read-only and the target's origin, that its exit code 1
// (failures found) is read as a result while others are failures, and that
// finding locations carry the spec's base path (ADR 0028).
func TestOpenAPISpec(t *testing.T) {
	m := builtin(t, "schemathesis")
	never := func(context.Context, sandbox.Spec, egress.Config) (*ActiveResult, error) {
		t.Fatal("ran without a spec")
		return nil, nil
	}
	opt := urlOpts(t)
	opt.NoOpenAPI = "none found at the default paths"
	r, err := RunURL(context.Background(), never, []*manifest.Manifest{m}, opt)
	if err != nil || r.Plugins[0].Status != report.Skipped || r.Plugins[0].Reason != opt.NoOpenAPI {
		t.Fatalf("%+v %v", r, err)
	}
	opt.OpenAPI = &openapi.Spec{Data: []byte(`{"openapi":"3.0.3","servers":[{"url":"/api/"}],"paths":{}}`), Format: "json", Source: "http://app.test:8000/openapi.json"}
	const rep = `{"complete":true,"operations":{"selected":1,"tested":1},"errors":[],"failures":[{"code":"ST101","title":"Server error","operations":["GET /items/{id}"]}]}`
	for _, exit := range []int{0, 1, 2} {
		var got []byte
		r, err := RunURL(context.Background(), func(_ context.Context, sp sandbox.Spec, _ egress.Config) (*ActiveResult, error) {
			if !slices.Contains(sp.Args, OpenAPIMount+"/spec.json") || !slices.Contains(sp.Args, "http://app.test:8000") {
				t.Errorf("args %v", sp.Args)
			}
			for _, f := range sp.Files {
				if f.Mount == OpenAPIMount {
					got, _ = os.ReadFile(filepath.Join(f.Host, "spec.json"))
				}
			}
			os.WriteFile(filepath.Join(sp.OutDir, "schemathesis.json"), []byte(rep), 0o600)
			return &ActiveResult{Result: &sandbox.Result{Status: sandbox.Completed, ExitCode: exit}, Stats: egress.Stats{Requests: 1}}, nil
		}, []*manifest.Manifest{m}, opt)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, opt.OpenAPI.Data) {
			t.Errorf("mounted spec %q", got)
		}
		p := r.Plugins[0]
		if exit == 2 {
			if p.Status != report.Failed || !strings.Contains(p.Reason, "exited with code 2") {
				t.Errorf("exit 2: %+v", p)
			}
			continue
		}
		if p.Status != report.Ran || p.Input != "OpenAPI spec http://app.test:8000/openapi.json" || len(r.Findings) != 1 || r.Findings[0].Location.URI != "http://app.test:8000/api/items/{id}" {
			t.Errorf("exit %d: %+v %+v", exit, p, r.Findings)
		}
	}
}

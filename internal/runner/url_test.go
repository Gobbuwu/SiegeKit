package runner

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Gobbuwu/SiegeKit/internal/egress"
	"github.com/Gobbuwu/SiegeKit/internal/manifest"
	"github.com/Gobbuwu/SiegeKit/internal/report"
	"github.com/Gobbuwu/SiegeKit/internal/sandbox"
	"github.com/Gobbuwu/SiegeKit/internal/target"
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
			if c.Target.String() != "http://app.test:8000/" || c.MaxServerErrors != LocalLimits.MaxServerErrors {
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
		if !c.VerifyTLS || c.Rate != DeployedLimits.Rate {
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
		"no requests": {&ActiveResult{Result: &sandbox.Result{Status: sandbox.Completed}}, nil, report.Failed, "sent no request"},
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
	if !strings.Contains(SkipReason(&destructive, true), "--allow-destructive") {
		t.Error("destructive plugin not skipped on a deployed target")
	}
}

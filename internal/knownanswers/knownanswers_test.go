package knownanswers

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/Gobbuwu/SiegeKit/internal/findings"
	"github.com/Gobbuwu/SiegeKit/internal/report"
)

func TestKey(t *testing.T) {
	for _, c := range []struct {
		rule, uri string
		line      int
		want      string
	}{
		{"G401", "main.go", 10, "G401 main.go:10"},
		{"CVE-1", "go.sum", 0, "CVE-1 go.sum"},
		{"10038", "http://127.0.0.1:3000/", 0, "10038 /"},
		{"10038", "http://127.0.0.1:3000", 0, "10038 /"},
		{"40018", "http://127.0.0.1:3000/rest/products/search?q=x", 0, "40018 /rest/products/search"},
		{"x", "https://h.test/a%20b", 0, "x /a%20b"},
	} {
		if got := Key(c.rule, c.uri, c.line); got != c.want {
			t.Errorf("Key(%q, %q, %d) = %q, want %q", c.rule, c.uri, c.line, got, c.want)
		}
	}
}

func run(engine string) *report.Run {
	return &report.Run{
		Environment: &report.Environment{OS: "linux", Arch: "amd64", Engine: &report.Engine{Name: engine, Version: "1", Rootless: engine == "podman", Cgroup: "v2"}},
		Plugins: []report.PluginResult{
			{ID: "gosec", Status: report.Ran, Findings: 2},
			{ID: "zap-active", Status: report.Ran, Requests: 3443, Findings: 1},
			{ID: "bandit", Status: report.Skipped, Cause: report.CauseNoFiles, Reason: "no files matching *.py"},
		},
		Findings: []findings.Finding{
			{RuleID: "a", Location: findings.Location{URI: "main.go", StartLine: 3}, Sources: []findings.Source{{Plugin: "gosec", RuleID: "G401"}}},
			{RuleID: "b", Location: findings.Location{URI: "x.go", StartLine: 1}, Sources: []findings.Source{{Plugin: "gosec", RuleID: "G104"}}},
			{RuleID: "c", Location: findings.Location{URI: "http://127.0.0.1:3000/"}, Sources: []findings.Source{{Plugin: "zap-active", RuleID: "10104"}}},
		},
	}
}

func answers() *Answers {
	return &Answers{
		Fixture: "test", Measured: "test",
		Checks: map[string]Check{
			"gosec":      {Status: "ran", Match: Exact, Findings: []string{"G104 x.go:1", "G401 main.go:3"}, Count: 2},
			"zap-active": {Status: "ran", Match: Includes, Findings: []string{"10104 /"}, MinRequests: 3000},
			"bandit":     {Status: "skipped", Reason: "no files matching", Cause: "no-files"},
		},
		NotMetYet: []Gap{{Check: "zap-active", Finding: "40018 /rest/products/search", Needs: "part 5", Confirmed: "by hand"}},
	}
}

func TestCompareMet(t *testing.T) {
	res := Compare(answers(), run("podman"), "podman")
	if len(res.Failures) > 0 {
		t.Errorf("failures: %v", res.Failures)
	}
	if want := []string{"zap-active: 40018 /rest/products/search (needs part 5)"}; !slices.Equal(res.NotMetYet, want) {
		t.Errorf("not met yet = %v", res.NotMetYet)
	}
}

func TestCompareShortfalls(t *testing.T) {
	for name, c := range map[string]struct {
		change func(r *report.Run, a *Answers)
		want   string
	}{
		"cut short": {func(r *report.Run, _ *Answers) { r.Plugins[1].Requests = 944 }, "zap-active: sent 944 requests, a complete run sends at least 3000"},
		"dropped":   {func(r *report.Run, _ *Answers) { r.Findings = r.Findings[1:] }, "gosec: missed G401 main.go:3"},
		"new": {func(_ *report.Run, a *Answers) {
			a.Checks["gosec"] = Check{Status: "ran", Match: Exact, Findings: []string{"G401 main.go:3"}}
		}, "gosec: new finding G104 x.go:1, not in the known answer"},
		"count":     {func(r *report.Run, _ *Answers) { r.Plugins[0].Findings = 1 }, "gosec: 1 findings, known answer is 2"},
		"failed":    {func(r *report.Run, _ *Answers) { r.Plugins[0].Status, r.Plugins[0].Reason = report.Failed, "exit 137" }, "gosec: failed exit 137, known answer is ran"},
		"reason":    {func(r *report.Run, _ *Answers) { r.Plugins[2].Reason = "disabled" }, `bandit: reason "disabled", known answer contains "no files matching"`},
		"cause":     {func(r *report.Run, _ *Answers) { r.Plugins[2].Cause = report.CauseDeclined }, `bandit: cause "declined", known answer is "no-files"`},
		"no answer": {func(_ *report.Run, a *Answers) { delete(a.Checks, "bandit") }, "bandit: no known answer for this check on test"},
		"missing":   {func(r *report.Run, _ *Answers) { r.Plugins = r.Plugins[:2] }, "bandit: not in the report"},
		"met now": {func(r *report.Run, _ *Answers) {
			r.Findings = append(r.Findings, findings.Finding{Location: findings.Location{URI: "http://127.0.0.1:3000/rest/products/search?q=1"}, Sources: []findings.Source{{Plugin: "zap-active", RuleID: "40018"}}})
		}, `zap-active: now finds "40018 /rest/products/search", listed as not met yet (part 5): move it into the check's findings`},
	} {
		t.Run(name, func(t *testing.T) {
			r, a := run("podman"), answers()
			c.change(r, a)
			res := Compare(a, r, "podman")
			if !slices.Contains(res.Failures, c.want) {
				t.Errorf("failures = %q, want %q", res.Failures, c.want)
			}
		})
	}
}

func TestCompareIncludesAllowsMore(t *testing.T) {
	r := run("podman")
	r.Findings = append(r.Findings, findings.Finding{Location: findings.Location{URI: "http://127.0.0.1:3000/a"}, Sources: []findings.Source{{Plugin: "zap-active", RuleID: "10021"}}})
	if res := Compare(answers(), r, "podman"); len(res.Failures) > 0 {
		t.Errorf("failures: %v", res.Failures)
	}
}

func TestCompareByEngine(t *testing.T) {
	a := answers()
	c := a.Checks["zap-active"]
	c.Why = "explained"
	c.ByEngine = map[string]Check{"docker": {Status: "ran", Match: Includes, Findings: []string{"10104 /"}, MinRequests: 5000}}
	a.Checks["zap-active"] = c
	if res := Compare(a, run("podman"), "podman"); len(res.Failures) > 0 {
		t.Errorf("podman: %v", res.Failures)
	}
	if res := Compare(a, run("docker"), "docker"); !slices.Contains(res.Failures, "zap-active: sent 3443 requests, a complete run sends at least 5000") {
		t.Errorf("docker: %v", res.Failures)
	}
}

func TestCompareByRuleAndUnstable(t *testing.T) {
	a := answers()
	a.Checks["zap-active"] = Check{Status: "ran", Match: Includes, ByRule: true, Findings: []string{"10104"}, Why: "crawl varies"}
	a.Checks["gosec"] = Check{Status: "ran", Match: Exact, Findings: []string{"G104 x.go:1"}, Unstable: []string{"G401 main.go:3"}, Why: "taint rules vary"}
	r := run("podman")
	r.Findings[2].Location.URI = "http://127.0.0.1:3000/other/page"
	res := Compare(a, r, "podman")
	if len(res.Failures) > 0 {
		t.Errorf("failures: %v", res.Failures)
	}
	if len(res.Unstable) != 1 || !strings.Contains(res.Unstable[0], "G401 main.go:3") {
		t.Errorf("unstable = %v", res.Unstable)
	}
	// The unstable finding may also be absent; a stable one may not.
	r.Findings = r.Findings[1:]
	if res := Compare(a, r, "podman"); len(res.Failures) > 0 {
		t.Errorf("unstable finding absent: %v", res.Failures)
	}
	r.Findings = nil
	if res := Compare(a, r, "podman"); !slices.Contains(res.Failures, "gosec: missed G104 x.go:1") || !slices.Contains(res.Failures, "zap-active: missed 10104") {
		t.Errorf("stable findings dropped: %v", res.Failures)
	}
}

func TestLoadRejects(t *testing.T) {
	for name, body := range map[string]string{
		"unknown field":   `{"fixture":"f","measured":"m","checks":{"a":{"status":"ran"}},"extra":1}`,
		"no checks":       `{"fixture":"f","measured":"m","checks":{}}`,
		"bad status":      `{"fixture":"f","measured":"m","checks":{"a":{"status":"failed"}}}`,
		"no match":        `{"fixture":"f","measured":"m","checks":{"a":{"status":"ran","findings":["x y"]}}}`,
		"skip no reason":  `{"fixture":"f","measured":"m","checks":{"a":{"status":"skipped"}}}`,
		"skip findings":   `{"fixture":"f","measured":"m","checks":{"a":{"status":"skipped","reason":"r","cause":"no-files","match":"exact"}}}`,
		"skip no cause":   `{"fixture":"f","measured":"m","checks":{"a":{"status":"skipped","reason":"r"}}}`,
		"skip bad cause":  `{"fixture":"f","measured":"m","checks":{"a":{"status":"skipped","reason":"r","cause":"no files"}}}`,
		"ran with cause":  `{"fixture":"f","measured":"m","checks":{"a":{"status":"ran","cause":"no-files"}}}`,
		"engine no why":   `{"fixture":"f","measured":"m","checks":{"a":{"status":"ran","byEngine":{"docker":{"status":"ran"}}}}}`,
		"unknown engine":  `{"fixture":"f","measured":"m","checks":{"a":{"status":"ran","why":"w","byEngine":{"lxc":{"status":"ran"}}}}}`,
		"gap no check":    `{"fixture":"f","measured":"m","checks":{"a":{"status":"ran"}},"notMetYet":[{"check":"b","finding":"x","needs":"n","confirmed":"c"}]}`,
		"unstable no why": `{"fixture":"f","measured":"m","checks":{"a":{"status":"ran","unstable":["x y"]}}}`,
		"both":            `{"fixture":"f","measured":"m","checks":{"a":{"status":"ran","match":"exact","findings":["x y"],"unstable":["x y"],"why":"w"}}}`,
		"count unstable":  `{"fixture":"f","measured":"m","checks":{"a":{"status":"ran","match":"exact","findings":["x y"],"count":1,"unstable":["z y"],"why":"w"}}}`,
		"gap unconfirmed": `{"fixture":"f","measured":"m","checks":{"a":{"status":"ran"}},"notMetYet":[{"check":"a","finding":"x","needs":"n"}]}`,
		"failed no why":   `{"fixture":"f","measured":"m","checks":{"a":{"status":"failed","reason":"r"}}}`,
	} {
		p := filepath.Join(t.TempDir(), "a.json")
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(p); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// The same error on every run: Go ranges over a map in a different order
// each time.
func TestLoadSameErrorEachRun(t *testing.T) {
	p := filepath.Join(t.TempDir(), "a.json")
	body := `{"fixture":"f","measured":"m","checks":{"b":{"status":"failed"},"a":{"status":"ran","why":"w","byEngine":{"lxc":{"status":"ran"},"kvm":{"status":"ran"}}}}}`
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	for range 200 {
		if _, err := Load(p); err == nil || !strings.HasSuffix(err.Error(), `check a: unknown engine "kvm"`) {
			t.Fatalf("Load: %v", err)
		}
	}
}

// TestAnswerFromRoundTrip: an answer written from a run is met by that run,
// and keeps the reviewed parts of the old answer.
func TestAnswerFromRoundTrip(t *testing.T) {
	r := run("docker")
	a := AnswerFrom("test", "m", r, answers())
	b, err := json.Marshal(a)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "a.json")
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	back, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if res := Compare(back, r, "docker"); len(res.Failures) > 0 {
		t.Errorf("failures: %v", res.Failures)
	}
	if c := back.Checks["zap-active"]; c.Match != Includes || c.MinRequests != 3000 {
		t.Errorf("reviewed fields lost: %+v", c)
	}
	if c := back.Checks["bandit"]; c.Reason != "no files matching" {
		t.Errorf("reason = %q", c.Reason)
	}
	if len(back.NotMetYet) != 1 || !strings.Contains(string(b), "40018") {
		t.Errorf("not-met-yet list lost: %s", b)
	}
}

// TestFixtureFiles loads every answer file in the repository, so a broken
// one fails here before CI's gate reads it.
func TestFixtureFiles(t *testing.T) {
	paths, err := filepath.Glob("../../testdata/known-answers/*.json")
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) == 0 {
		t.Fatal("no known-answer files")
	}
	for _, p := range paths {
		if _, err := Load(p); err != nil {
			t.Error(err)
		}
	}
}

// TestFailedAnswer: a known incomplete run (ADR 0040) is met only by the
// same status and reason, and its findings are still compared.
func TestFailedAnswer(t *testing.T) {
	p := filepath.Join(t.TempDir(), "a.json")
	body := `{"fixture":"f","measured":"m","checks":{"gosec":{"status":"failed","reason":"could not load 2 Go packages","why":"modules not in the repository","match":"exact","findings":["G104 a.go:1"]}}}`
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	a, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	ok := Observed{Status: "failed", Reason: "gosec could not load 2 Go packages, so ...", Findings: []string{"G104 a.go:1"}}
	if f := compareCheck("gosec", a.Checks["gosec"], ok); len(f) != 0 {
		t.Errorf("met answer failed: %v", f)
	}
	for name, o := range map[string]Observed{
		"ran":            {Status: "ran", Findings: []string{"G104 a.go:1"}},
		"other reason":   {Status: "failed", Reason: "could not read the tool's error list", Findings: []string{"G104 a.go:1"}},
		"missed finding": {Status: "failed", Reason: "could not load 2 Go packages"},
	} {
		if f := compareCheck("gosec", a.Checks["gosec"], o); len(f) == 0 {
			t.Errorf("%s: met", name)
		}
	}
}

// TestEngineOf: a run of SiegeKit's own checks only started no container
// and holds for every engine; any other run without an engine is refused
// (ADR 0054).
func TestEngineOf(t *testing.T) {
	own := []report.PluginResult{{ID: "access-control-write", Tool: "siegekit"}}
	if e, err := EngineOf(&report.Run{Environment: &report.Environment{Engine: &report.Engine{Name: "podman"}}}); err != nil || e != "podman" {
		t.Errorf("engine: %q %v", e, err)
	}
	if e, err := EngineOf(&report.Run{Environment: &report.Environment{OS: "linux"}, Plugins: own}); err != nil || e != "" {
		t.Errorf("own checks only: %q %v", e, err)
	}
	if _, err := EngineOf(&report.Run{Plugins: append(own, report.PluginResult{ID: "zap", Tool: "zap"})}); err == nil {
		t.Error("a tool ran with no engine named: accepted")
	}
	if _, err := EngineOf(&report.Run{}); err == nil {
		t.Error("no checks, no engine: accepted")
	}
}

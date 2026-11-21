package runner

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/Gobbuwu/SiegeKit/internal/checks"
	"github.com/Gobbuwu/SiegeKit/internal/findings"
	"github.com/Gobbuwu/SiegeKit/internal/manifest"
	"github.com/Gobbuwu/SiegeKit/internal/report"
	"github.com/Gobbuwu/SiegeKit/internal/sandbox"
	"github.com/Gobbuwu/SiegeKit/plugins"
)

// fake simulates the sandbox: act runs with the spec and may write into OutDir.
type fake struct {
	act   func(s sandbox.Spec) (*sandbox.Result, error)
	specs []sandbox.Spec
}

func (f *fake) Run(_ context.Context, s sandbox.Spec) (*sandbox.Result, error) {
	f.specs = append(f.specs, s)
	return f.act(s)
}

const gitleaksSARIF = `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"gitleaks","rules":[{"id":"github-pat","shortDescription":{"text":"GitHub token"}}]}},"results":[
{"ruleId":"github-pat","message":{"text":"found"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"/target/config.py"},"region":{"startLine":1,"snippet":{"text":"ghp_0123456789abcdef"}}}}]}]}]}`

func builtin(t *testing.T, id string) *manifest.Manifest {
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

func opts(t *testing.T) Options {
	return Options{Version: "test", TargetDir: t.TempDir(), WorkDir: t.TempDir()}
}

func write(t *testing.T, dir, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestRunConvertsReport(t *testing.T) {
	f := &fake{act: func(s sandbox.Spec) (*sandbox.Result, error) {
		write(t, s.OutDir, "gitleaks.sarif", gitleaksSARIF)
		return &sandbox.Result{Status: sandbox.Completed}, nil
	}}
	o := opts(t)
	r, err := Run(context.Background(), f, []*manifest.Manifest{builtin(t, "gitleaks")}, o)
	if err != nil {
		t.Fatal(err)
	}
	s := f.specs[0]
	if s.TargetDir != o.TargetDir || s.Network != "none" || !strings.Contains(s.Image, "@sha256:") {
		t.Errorf("unexpected spec %+v", s)
	}
	if !slices.Contains(s.Args, "/target") || !slices.Contains(s.Args, "/out/gitleaks.sarif") {
		t.Errorf("placeholders not substituted: %v", s.Args)
	}
	if len(r.Plugins) != 1 || r.Plugins[0].Status != report.Ran || r.Plugins[0].Findings != 1 {
		t.Fatalf("plugins %+v", r.Plugins)
	}
	got := r.Findings[0]
	if got.Severity != findings.High || got.Location.URI != "config.py" || strings.Contains(got.Snippet, "0123456789") {
		t.Errorf("finding %+v", got)
	}
	if r.ExitCode(findings.High) != report.ExitFindings {
		t.Errorf("exit code %d", r.ExitCode(findings.High))
	}
	// The private work directory is removed after the run.
	if entries, _ := os.ReadDir(o.WorkDir); len(entries) != 0 {
		t.Errorf("work directory left behind: %v", entries)
	}
}

func TestRunRecordsFailures(t *testing.T) {
	cases := map[string]struct {
		act    func(s sandbox.Spec) (*sandbox.Result, error)
		status report.Status
		reason string
	}{
		"timeout": {func(sandbox.Spec) (*sandbox.Result, error) {
			return &sandbox.Result{Status: sandbox.TimedOut, ExitCode: -1}, nil
		}, report.TimedOut, "stopped after"},
		"engine failure": {func(sandbox.Spec) (*sandbox.Result, error) {
			return &sandbox.Result{Status: sandbox.Failed, ExitCode: 125, Stderr: "pull failed\nno such image\n"}, nil
		}, report.Failed, "no such image"},
		"tool error": {func(sandbox.Spec) (*sandbox.Result, error) {
			return &sandbox.Result{Status: sandbox.Completed, ExitCode: 1, Stderr: "\x1b[31mboom\x1b[0m"}, nil
		}, report.Failed, "code 1: [31mboom[0m"},
		"sandbox refused": {func(sandbox.Spec) (*sandbox.Result, error) {
			return nil, errors.New("refused")
		}, report.Failed, "refused"},
		"no report": {func(sandbox.Spec) (*sandbox.Result, error) {
			return &sandbox.Result{Status: sandbox.Completed}, nil
		}, report.Failed, "wrote no report"},
		"bad report": {func(s sandbox.Spec) (*sandbox.Result, error) {
			write(t, s.OutDir, "gitleaks.sarif", `{"version":"1.0"}`)
			return &sandbox.Result{Status: sandbox.Completed}, nil
		}, report.Failed, "unsupported SARIF version"},
		"symlinked report": {func(s sandbox.Spec) (*sandbox.Result, error) {
			secret := filepath.Join(t.TempDir(), "secret")
			write(t, filepath.Dir(secret), "secret", gitleaksSARIF)
			if err := os.Symlink(secret, filepath.Join(s.OutDir, "gitleaks.sarif")); err != nil {
				t.Fatal(err)
			}
			return &sandbox.Result{Status: sandbox.Completed}, nil
		}, report.Failed, "open report"},
		"directory report": {func(s sandbox.Spec) (*sandbox.Result, error) {
			if err := os.Mkdir(filepath.Join(s.OutDir, "gitleaks.sarif"), 0o700); err != nil {
				t.Fatal(err)
			}
			return &sandbox.Result{Status: sandbox.Completed}, nil
		}, report.Failed, "not a regular file"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			r, err := Run(context.Background(), &fake{act: tc.act}, []*manifest.Manifest{builtin(t, "gitleaks")}, opts(t))
			if err != nil {
				t.Fatal(err)
			}
			p := r.Plugins[0]
			if p.Status != tc.status || !strings.Contains(p.Reason, tc.reason) {
				t.Fatalf("got %s %q, want %s containing %q", p.Status, p.Reason, tc.status, tc.reason)
			}
			if strings.ContainsRune(p.Reason, 0x1b) {
				t.Errorf("escape character kept in reason %q", p.Reason)
			}
			if r.Complete() || r.ExitCode(findings.High) != report.ExitIncomplete {
				t.Error("a failed plugin must make the run incomplete")
			}
		})
	}
}

func TestRunContinuesAfterFailure(t *testing.T) {
	f := &fake{act: func(s sandbox.Spec) (*sandbox.Result, error) {
		if strings.Contains(s.Image, "checkov") {
			return &sandbox.Result{Status: sandbox.TimedOut, ExitCode: -1}, nil
		}
		write(t, s.OutDir, "gitleaks.sarif", gitleaksSARIF)
		return &sandbox.Result{Status: sandbox.Completed}, nil
	}}
	ms := []*manifest.Manifest{builtin(t, "checkov"), builtin(t, "gitleaks")}
	r, err := Run(context.Background(), f, ms, opts(t))
	if err != nil {
		t.Fatal(err)
	}
	if r.Plugins[0].Status != report.TimedOut || r.Plugins[1].Status != report.Ran || len(r.Findings) != 1 {
		t.Fatalf("got %+v", r.Plugins)
	}
}

func TestRunCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	f := &fake{act: func(sandbox.Spec) (*sandbox.Result, error) { t.Fatal("must not run"); return nil, nil }}
	if _, err := Run(ctx, f, []*manifest.Manifest{builtin(t, "gitleaks")}, opts(t)); !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v", err)
	}
}

func TestRunRejectsRelativeTarget(t *testing.T) {
	o := opts(t)
	o.TargetDir = "rel"
	if _, err := Run(context.Background(), &fake{}, nil, o); err == nil {
		t.Fatal("expected rejection")
	}
}

func TestSelect(t *testing.T) {
	all, err := plugins.Builtin()
	if err != nil {
		t.Fatal(err)
	}
	ids := func(ms []*manifest.Manifest) []string {
		var out []string
		for _, m := range ms {
			out = append(out, m.ID)
		}
		return out
	}
	if got, _, _ := Select(all, nil, "repo", nil, nil); !slices.Equal(ids(got), []string{"bandit", "checkov", "gitleaks", "gitleaks-history", "gosec", "trivy"}) {
		t.Errorf("all: %v", ids(got))
	}
	if got, _, _ := Select(all, nil, "repo", []string{"gitleaks"}, nil); !slices.Equal(ids(got), []string{"gitleaks"}) {
		t.Errorf("only: %v", ids(got))
	}
	if got, _, _ := Select(all, nil, "repo", nil, []string{"gitleaks"}); !slices.Equal(ids(got), []string{"bandit", "checkov", "gitleaks-history", "gosec", "trivy"}) {
		t.Errorf("skip: %v", ids(got))
	}
	for name, c := range map[string][2][]string{
		"unknown only": {{"nope"}, nil},
		"unknown skip": {nil, {"nope"}},
		"nothing left": {{"gitleaks"}, {"gitleaks"}},
	} {
		if _, _, err := Select(all, nil, "repo", c[0], c[1]); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
	if _, _, err := Select(all, nil, "url", []string{"gitleaks"}, nil); err == nil {
		t.Error("wrong target kind: expected error")
	}
}

// TestSelectFamilies checks that --only and --skip accept family names
// (ADR 0004), mixed with IDs, and that a family with nothing for the
// target kind is an error.
func TestSelectFamilies(t *testing.T) {
	all, err := plugins.Builtin()
	if err != nil {
		t.Fatal(err)
	}
	builtins := checks.Builtin()
	ids := func(ms []*manifest.Manifest, cs []checks.Check) []string {
		var out []string
		for _, m := range ms {
			out = append(out, m.ID)
		}
		for _, c := range builtins {
			if slices.ContainsFunc(cs, func(x checks.Check) bool { return x.ID == c.ID }) {
				out = append(out, c.ID)
			}
		}
		return out
	}
	for _, c := range []struct {
		kind       string
		only, skip []string
		want       []string
	}{
		{"repo", []string{"secrets"}, nil, []string{"gitleaks", "gitleaks-history", "dotenv-gitignore", "weak-passwords"}},
		{"repo", []string{"sast", "trivy"}, nil, []string{"bandit", "gosec", "trivy"}},
		{"repo", nil, []string{"secrets", "iac"}, []string{"bandit", "gosec", "trivy"}},
		{"repo", []string{"secrets"}, []string{"gitleaks-history"}, []string{"gitleaks", "dotenv-gitignore", "weak-passwords"}},
		{"url", []string{"dast"}, []string{"zap-active"}, []string{"ffuf", "nuclei", "nuclei-default-login", "nuclei-intrusive", "schemathesis", "zap"}},
	} {
		ms, cs, err := Select(all, builtins, c.kind, c.only, c.skip)
		if got := ids(ms, cs); err != nil || !slices.Equal(got, c.want) {
			t.Errorf("%s only %v skip %v: %v %v, want %v", c.kind, c.only, c.skip, got, err, c.want)
		}
	}
	for _, c := range []struct {
		kind, name, err string
	}{
		{"url", "secrets", "no secrets plugin can scan a url target"},
		{"repo", "dast", "no dast plugin can scan a repo target"},
		{"repo", "sats", `unknown plugin or family "sats"`},
	} {
		if _, _, err := Select(all, builtins, c.kind, []string{c.name}, nil); err == nil || !strings.Contains(err.Error(), c.err) {
			t.Errorf("%s %s: %v", c.kind, c.name, err)
		}
	}
	// A plugin or check named like a family would make --only ambiguous.
	for _, m := range all {
		if slices.Contains(manifest.Families, m.ID) {
			t.Errorf("plugin %s has a family's name", m.ID)
		}
	}
	for _, c := range builtins {
		if slices.Contains(manifest.Families, c.ID) {
			t.Errorf("check %s has a family's name", c.ID)
		}
	}
}

func TestSubstituteRejectsRateLimit(t *testing.T) {
	if _, err := substitute([]string{"--rate", "{ratelimit}"}, 1, ""); err == nil {
		t.Fatal("expected rejection")
	}
	if _, err := substitute([]string{"{data}"}, 1, ""); err == nil {
		t.Fatal("expected rejection of {data} without data")
	}
	got, err := substitute([]string{"{target}", "{outdir}/x", "{workdir}", "-j{threads}", "{data}"}, 3, "/tmp/db")
	if err != nil || !slices.Equal(got, []string{"/target", "/out/x", "/tmp/work", "-j3", "/tmp/db"}) {
		t.Fatalf("got %v %v", got, err)
	}
}

func TestLastLine(t *testing.T) {
	for in, want := range map[string]string{
		"":                       "no error output",
		"a\nb\n\n":               "b",
		"x\x07y\u0085z":          "xyz",
		strings.Repeat("é", 400): "…" + strings.Repeat("é", 300),
		"bad\xffutf8":            "badutf8",
	} {
		if got := lastLine(in); got != want {
			t.Errorf("lastLine(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSelectAndRunBuiltinChecks(t *testing.T) {
	all, err := plugins.Builtin()
	if err != nil {
		t.Fatal(err)
	}
	ms, cs, err := Select(all, checks.Builtin(), "repo", []string{"backend-rules"}, nil)
	if err != nil || len(ms) != 0 || len(cs) != 1 {
		t.Fatalf("%d %d %v", len(ms), len(cs), err)
	}
	if _, cs, _ := Select(all, checks.Builtin(), "repo", nil, []string{"backend-rules"}); len(cs) != 2 || cs[0].ID != "dotenv-gitignore" || cs[1].ID != "weak-passwords" {
		t.Error("skip ignored")
	}
	o := opts(t)
	os.WriteFile(filepath.Join(o.TargetDir, "database.rules.json"), []byte(`{"rules":{".read":true}}`), 0o644)
	o.Checks = cs
	failing := checks.Check{ID: "broken", Family: "iac", Run: func(context.Context, string) ([]findings.Finding, string, error) {
		return nil, "", errors.New("boom")
	}}
	saying := checks.Check{ID: "saying", Family: "secrets", Run: func(context.Context, string) ([]findings.Finding, string, error) {
		return nil, "nothing seen", nil
	}}
	o.Checks = append(o.Checks, failing, saying)
	r, err := Run(context.Background(), &fake{}, nil, o)
	if err != nil {
		t.Fatal(err)
	}
	if r.Plugins[0].Status != report.Ran || r.Plugins[0].Findings != 1 || r.Plugins[0].Tool != "siegekit" || r.Plugins[0].Version != o.Version {
		t.Errorf("%+v", r.Plugins[0])
	}
	if r.Plugins[1].Status != report.Failed || r.Plugins[1].Reason != "boom" || r.Complete() {
		t.Errorf("%+v", r.Plugins[1])
	}
	if r.Plugins[2].Status != report.Ran || r.Plugins[2].Result != "nothing seen" {
		t.Errorf("%+v", r.Plugins[2])
	}
}

func TestRunSkipsPluginWithoutMatchingFiles(t *testing.T) {
	f := &fake{act: func(s sandbox.Spec) (*sandbox.Result, error) {
		write(t, s.OutDir, "gosec.sarif", `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"gosec"}},"results":[]}]}`)
		write(t, s.OutDir, s.StdoutFile, `{"Golang errors": {}, "Stats": {"files": 1000}}`) // gosec's JSON on stdout (ADR 0040); more files than the target has
		return &sandbox.Result{Status: sandbox.Completed}, nil
	}}
	o := opts(t)
	write(t, o.TargetDir, "app.py", "")
	gosec := []*manifest.Manifest{builtin(t, "gosec")}
	r, err := Run(context.Background(), f, gosec, o)
	if err != nil {
		t.Fatal(err)
	}
	p := r.Plugins[0]
	if p.Status != report.Skipped || p.Reason != "no files matching *.go" || len(f.specs) != 0 {
		t.Fatalf("plugin %+v, %d runs", p, len(f.specs))
	}
	// A skipped plugin does not make the run incomplete.
	if !r.Complete() {
		t.Error("run marked incomplete")
	}
	if err := os.MkdirAll(filepath.Join(o.TargetDir, "cmd", "app"), 0o755); err != nil {
		t.Fatal(err)
	}
	write(t, o.TargetDir, "cmd/app/main.go", "package main\n")
	if r, err = Run(context.Background(), f, gosec, o); err != nil {
		t.Fatal(err)
	}
	if r.Plugins[0].Status != report.Ran || len(f.specs) != 1 {
		t.Fatalf("plugin %+v, %d runs", r.Plugins[0], len(f.specs))
	}
}

func TestRunSkipsGitPluginOutsideRepository(t *testing.T) {
	f := &fake{act: func(s sandbox.Spec) (*sandbox.Result, error) {
		write(t, s.OutDir, "gitleaks-history.sarif", `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"gitleaks"}},"results":[]}]}`)
		return &sandbox.Result{Status: sandbox.Completed}, nil
	}}
	m := []*manifest.Manifest{builtin(t, "gitleaks-history")}
	o := opts(t)
	r, err := Run(context.Background(), f, m, o)
	if err != nil {
		t.Fatal(err)
	}
	if p := r.Plugins[0]; p.Status != report.Skipped || !strings.Contains(p.Reason, "not a git repository") || len(f.specs) != 0 {
		t.Fatalf("plugin %+v, %d runs", p, len(f.specs))
	}
	// A .git file (worktree) is not enough: it points outside the target.
	write(t, o.TargetDir, ".git", "gitdir: /elsewhere")
	if r, _ = Run(context.Background(), f, m, o); r.Plugins[0].Status != report.Skipped {
		t.Fatalf(".git file: %+v", r.Plugins[0])
	}
	o = opts(t)
	if err := os.Mkdir(filepath.Join(o.TargetDir, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	r, err = Run(context.Background(), f, m, o)
	if err != nil || r.Plugins[0].Status != report.Ran || len(f.specs) != 1 {
		t.Fatalf("in a repository: %+v %v", r.Plugins, err)
	}
	if env := f.specs[0].Env; env["GITLEAKS_CONFIG_TOML"] == "" || env["GIT_CONFIG_VALUE_0"] != sandbox.TargetMount {
		t.Errorf("environment not passed: %v", env)
	}
}

// The repository's own ignore settings are obeyed by the tool, and reported
// (owner decision, 2026-11-19).
func TestRunReportsRepoIgnores(t *testing.T) {
	const suppressedSARIF = `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"gitleaks"}},"results":[
{"ruleId":"github-pat","message":{"text":"found"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"/target/a.py"},"region":{"startLine":1}}}],"suppressions":[{"kind":"inSource"}]}]}]}`
	f := &fake{act: func(s sandbox.Spec) (*sandbox.Result, error) {
		write(t, s.OutDir, "gitleaks.sarif", suppressedSARIF)
		return &sandbox.Result{Status: sandbox.Completed}, nil
	}}
	o := opts(t)
	write(t, o.TargetDir, ".gitleaksignore", "x\n")
	write(t, o.TargetDir, "a.py", "k = 1  # gitleaks:allow\n")
	if err := os.Mkdir(filepath.Join(o.TargetDir, ".gitleaks.toml"), 0o755); err != nil { // not a file: not listed
		t.Fatal(err)
	}
	r, err := Run(context.Background(), f, []*manifest.Manifest{builtin(t, "gitleaks")}, o)
	if err != nil {
		t.Fatal(err)
	}
	p := r.Plugins[0]
	if p.Status != report.Ran || p.Findings != 0 || p.Suppressed != 1 || !slices.Equal(p.RepoSettings, []string{".gitleaksignore"}) || p.IgnoreMarkers != 1 {
		t.Errorf("plugin %+v", p)
	}
	if note := p.IgnoreNote(); !strings.Contains(note, "1 finding(s) suppressed") || !strings.Contains(note, ".gitleaksignore") || !strings.Contains(note, "1 line(s)") {
		t.Errorf("note %q", note)
	}
}

// As root, tools run as a fixed non-root user. Files that user cannot read
// make the checks that need them incomplete (owner decision, 2026-11-19).
func TestRunMarksUnreadableFilesIncomplete(t *testing.T) {
	oldUID, oldGID := getuid, getgid
	t.Cleanup(func() { getuid, getgid = oldUID, oldGID })
	f := &fake{act: func(s sandbox.Spec) (*sandbox.Result, error) {
		if strings.Contains(s.Image, "gitleaks") {
			write(t, s.OutDir, "gitleaks.sarif", gitleaksSARIF)
		} else {
			write(t, s.OutDir, "bandit.json", `{"results":[],"errors":[]}`)
		}
		return &sandbox.Result{Status: sandbox.Completed}, nil
	}}
	o := opts(t)
	write(t, o.TargetDir, "app.py", "x = 1\n")
	write(t, o.TargetDir, ".env", "KEY=1\n")
	if err := os.Chmod(filepath.Join(o.TargetDir, ".env"), 0o600); err != nil {
		t.Fatal(err)
	}
	selected := []*manifest.Manifest{builtin(t, "gitleaks"), builtin(t, "bandit")}

	getuid, getgid = func() int { return 0 }, func() int { return 0 }
	r, err := Run(context.Background(), f, selected, o)
	if err != nil {
		t.Fatal(err)
	}
	gl, bd := r.Plugins[0], r.Plugins[1]
	if gl.Status != report.Failed || !strings.Contains(gl.Reason, "could not read 1 path(s): .env") || gl.Findings != 1 {
		t.Errorf("gitleaks: %+v", gl)
	}
	if bd.Status != report.Ran { // bandit reads only *.py, which is readable
		t.Errorf("bandit: %+v", bd)
	}
	if len(r.Findings) != 1 || r.Complete() {
		t.Errorf("findings %d, complete %v: findings must be kept and the run incomplete", len(r.Findings), r.Complete())
	}

	// An unreadable directory affects every check.
	if err := os.Chmod(filepath.Join(o.TargetDir, ".env"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(o.TargetDir, "private"), 0o700); err != nil {
		t.Fatal(err)
	}
	r, err = Run(context.Background(), f, selected, o)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range r.Plugins {
		if p.Status != report.Failed || !strings.Contains(p.Reason, "private/") {
			t.Errorf("unreadable directory: %+v", p)
		}
	}

	// Not running as root: nothing is checked or changed.
	getuid = func() int { return 1000 }
	r, err = Run(context.Background(), f, selected, o)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range r.Plugins {
		if p.Status != report.Ran {
			t.Errorf("not root: %+v", p)
		}
	}
}

const gosecSARIF = `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"gosec","rules":[{"id":"G404","shortDescription":{"text":"weak random"}}]}},"results":[
{"ruleId":"G404","level":"error","message":{"text":"weak random"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"/target/main.go"},"region":{"startLine":3}}}]}]}]}`

// TestRunGosecSkippedPackagesIncomplete: packages gosec could not load make
// the run incomplete, with their names, and the other findings are kept
// (ADR 0040).
func TestRunGosecSkippedPackagesIncomplete(t *testing.T) {
	for _, c := range []struct {
		name, stdout string
		write        bool
		status       report.Status
		reason       string
	}{
		// The target holds main.go and lib/lib.go: 2 Go files.
		{"complete", `{"Golang errors": {}, "Issues": [], "Stats": {"files": 2}}`, true, report.Ran, ""},
		{"skipped packages", `{"Golang errors": {"/target/cmd/app/main.go": [{"line": 4, "column": 2, "error": "could not import example.com/dep"}], "/target/internal/x": []}, "Issues": [], "Stats": {"files": 2}}`, true, report.Failed, "gosec could not load 2 Go packages, so their code was not checked: cmd/app, internal/x."},
		// gosec dropped files and named no error, as when Go cannot
		// create its module cache (measured 2026-11-21).
		{"files left out silently", `{"Golang errors": {}, "Issues": [], "Stats": {"files": 1}}`, true, report.Failed, "gosec checked 1 of the 2 Go files"},
		{"no error list", `{"Issues": [], "Stats": {"files": 2}}`, true, report.Failed, "could not read the tool's error list"},
		{"no file count", `{"Golang errors": {}, "Issues": []}`, true, report.Failed, "could not read the tool's error list"},
		{"no stdout", "", false, report.Failed, "could not read the tool's error list"},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := &fake{act: func(s sandbox.Spec) (*sandbox.Result, error) {
				write(t, s.OutDir, "gosec.sarif", gosecSARIF)
				if c.write {
					write(t, s.OutDir, s.StdoutFile, c.stdout)
				}
				return &sandbox.Result{Status: sandbox.Completed}, nil
			}}
			o := opts(t)
			write(t, o.TargetDir, "main.go", "package main\n")
			if err := os.MkdirAll(filepath.Join(o.TargetDir, "lib"), 0o755); err != nil {
				t.Fatal(err)
			}
			write(t, filepath.Join(o.TargetDir, "lib"), "lib.go", "package lib\n")
			r, err := Run(context.Background(), f, []*manifest.Manifest{builtin(t, "gosec")}, o)
			if err != nil {
				t.Fatal(err)
			}
			if f.specs[0].StdoutFile != "gosec-stdout.json" {
				t.Errorf("stdout file %q", f.specs[0].StdoutFile)
			}
			p := r.Plugins[0]
			if p.Status != c.status || !strings.Contains(p.Reason, c.reason) || p.Findings != 1 || len(r.Findings) != 1 {
				t.Fatalf("plugin %+v, %d findings", p, len(r.Findings))
			}
			wantExit := report.ExitClean
			if c.status == report.Failed {
				wantExit = report.ExitIncomplete
			}
			if got := r.ExitCode(findings.Critical); got != wantExit {
				t.Errorf("exit %d, want %d", got, wantExit)
			}
		})
	}
}

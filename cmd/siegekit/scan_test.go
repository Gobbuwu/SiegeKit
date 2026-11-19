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
	"time"

	"github.com/Gobbuwu/SiegeKit/internal/deps"
	"github.com/Gobbuwu/SiegeKit/internal/findings"
	"github.com/Gobbuwu/SiegeKit/internal/report"
	"github.com/Gobbuwu/SiegeKit/internal/runner"
	"github.com/Gobbuwu/SiegeKit/internal/sandbox"
	"github.com/Gobbuwu/SiegeKit/internal/store"
	"github.com/Gobbuwu/SiegeKit/plugins"
)

type fakeExec func(s sandbox.Spec) (*sandbox.Result, error)

func (f fakeExec) Run(_ context.Context, s sandbox.Spec) (*sandbox.Result, error) { return f(s) }

// fakeEngine runs tools with run and holds the images in have.
type fakeEngine struct {
	run     runner.Executor
	have    map[string]bool // nil: every image is present
	hasErr  error
	pullErr error
	pulled  []string
}

func (f *fakeEngine) Run(ctx context.Context, s sandbox.Spec) (*sandbox.Result, error) {
	return f.run.Run(ctx, s)
}

func (f *fakeEngine) HasImage(_ context.Context, image string) (bool, error) {
	return f.have == nil || f.have[image], f.hasErr
}

func (f *fakeEngine) Pull(_ context.Context, image string) error {
	if f.pullErr != nil {
		return f.pullErr
	}
	f.pulled = append(f.pulled, image)
	if f.have != nil {
		f.have[image] = true
	}
	return nil
}

type fakeSizer struct{}

func (fakeSizer) DownloadSize(context.Context, string, string) (int64, error) { return 42 << 20, nil }

// useExecutor makes every image present and runs tools with ex.
func useExecutor(t *testing.T, ex runner.Executor, err error) {
	t.Helper()
	var e *fakeEngine
	if ex != nil {
		e = &fakeEngine{run: ex}
	}
	useEngine(t, e, err)
}

func useEngine(t *testing.T, e *fakeEngine, err error) {
	t.Helper()
	old, oldSizer, oldIn, oldTTY := newEngine, sizer, stdin, stdinIsTerminal
	newEngine = func() (engine, error) {
		if err != nil {
			return nil, err
		}
		return e, nil
	}
	sizer = fakeSizer{}
	stdin = strings.NewReader("")
	stdinIsTerminal = func() bool { return false }
	t.Cleanup(func() { newEngine, sizer, stdin, stdinIsTerminal = old, oldSizer, oldIn, oldTTY })
}

// emptySARIF makes every plugin complete with no findings.
var emptySARIF = fakeExec(func(s sandbox.Spec) (*sandbox.Result, error) {
	if s.DataWritable { // an update run
		return &sandbox.Result{Status: sandbox.Completed}, os.WriteFile(filepath.Join(s.DataDir, "db"), []byte("x"), 0o644)
	}
	for _, name := range []string{"gitleaks.sarif", "results_sarif.sarif", "trivy.sarif", "gosec.sarif"} {
		doc := `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"x"}},"results":[]}]}`
		if err := os.WriteFile(filepath.Join(s.OutDir, name), []byte(doc), 0o644); err != nil {
			return nil, err
		}
	}
	if err := os.WriteFile(filepath.Join(s.OutDir, "bandit.json"), []byte(`{"results":[]}`), 0o644); err != nil {
		return nil, err
	}
	return &sandbox.Result{Status: sandbox.Completed}, nil
})

func TestScan(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	target := t.TempDir()
	// Bandit and gosec run only when there is Python or Go code.
	for _, name := range []string{"app.py", "main.go"} {
		if err := os.WriteFile(filepath.Join(target, name), nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	reports := filepath.Join(t.TempDir(), "rep")
	useExecutor(t, emptySARIF, nil)
	var out, errb bytes.Buffer
	// Without a terminal nothing is installed: trivy is skipped and says why.
	if code := run([]string{"scan", target, "--no-save", "--report-dir", reports}, &out, &errb); code != exitOK || !strings.Contains(out.String(), "trivy data is not installed (no terminal to ask; use --yes)") {
		t.Fatalf("exit %d: %s %s", code, out.String(), errb.String())
	}
	// --require-all turns that into an incomplete run.
	if code := run([]string{"scan", target, "--no-save", "--require-all", "--report-dir", reports}, &out, &errb); code != 4 {
		t.Fatalf("--require-all: exit %d: %s", code, out.String())
	}
	out.Reset()
	if code := run([]string{"scan", "--yes", "--update", target, "--report-dir", reports}, &out, &errb); code != exitOK {
		t.Fatalf("exit %d: %s %s", code, out.String(), errb.String())
	}
	if !strings.Contains(out.String(), "No issues found by the 7 check(s) that ran.") || !strings.Contains(out.String(), "Saved run") {
		t.Errorf("output: %s", out.String())
	}
	for _, name := range []string{"report.html", "report.json", "report.sarif"} {
		st, err := os.Stat(filepath.Join(reports, name))
		if err != nil || st.Mode().Perm() != 0o600 {
			t.Errorf("%s: %v %v", name, st, err)
		}
	}
	var r struct{ Findings []any }
	b, _ := os.ReadFile(filepath.Join(reports, "report.json"))
	if err := json.Unmarshal(b, &r); err != nil || r.Findings == nil {
		t.Errorf("findings must be an empty list, got %s", b)
	}
}

func TestScanErrors(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	dir := t.TempDir()
	file := filepath.Join(dir, "f")
	os.WriteFile(file, nil, 0o644)
	for _, tc := range []struct {
		name string
		args []string
		ex   runner.Executor
		err  error
		code int
		msg  string
	}{
		{"help", []string{"-h"}, nil, nil, exitOK, "Usage: siegekit scan"},
		{"no dir", nil, nil, nil, exitUsage, "Usage"},
		{"two dirs", []string{dir, dir}, nil, nil, exitUsage, "Usage"},
		{"bad flag", []string{"--nope", dir}, nil, nil, exitUsage, "flag provided but not defined"},
		{"bad level", []string{"--fail-on", "severe", dir}, nil, nil, exitUsage, "unknown severity"},
		{"missing dir", []string{filepath.Join(dir, "missing")}, nil, nil, exitInvalid, "no such file"},
		{"not a dir", []string{file}, nil, nil, exitInvalid, "not a directory"},
		{"unknown plugin", []string{"--only", "nmap", dir}, nil, nil, exitInvalid, `unknown plugin "nmap"`},
		{"yes and no-install", []string{"--yes", "--no-install", dir}, nil, nil, exitUsage, "cannot be used together"},
		{"no engine", []string{"--no-save", "--report-dir", filepath.Join(dir, "r0"), dir}, nil, errors.New("no container engine found"), exitOK, "SiegeKit does not install one"},
		{"incomplete", []string{"--no-save", "--report-dir", filepath.Join(dir, "r"), dir}, fakeExec(func(sandbox.Spec) (*sandbox.Result, error) {
			return &sandbox.Result{Status: sandbox.TimedOut}, nil
		}), nil, 4, "incomplete"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			useExecutor(t, tc.ex, tc.err)
			var out, errb bytes.Buffer
			code := run(append([]string{"scan"}, tc.args...), &out, &errb)
			if code != tc.code || !strings.Contains(out.String()+errb.String(), tc.msg) {
				t.Fatalf("exit %d (want %d), output %q (want %q)", code, tc.code, out.String()+errb.String(), tc.msg)
			}
		})
	}
}

func TestPluginsList(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run([]string{"plugins", "list"}, &out, &errb); code != exitOK || !strings.Contains(out.String(), "gitleaks 8.30.1") {
		t.Fatalf("exit %d: %s", code, out.String())
	}
}

func TestUpdate(t *testing.T) {
	data := t.TempDir()
	t.Setenv("XDG_DATA_HOME", data)
	useExecutor(t, emptySARIF, nil)
	var out, errb bytes.Buffer
	if code := run([]string{"update"}, &out, &errb); code != exitOK || !strings.Contains(out.String(), "trivy      updated") {
		t.Fatalf("exit %d: %s %s", code, out.String(), errb.String())
	}
	if _, err := os.Stat(filepath.Join(data, "siegekit", "data", "trivy", "db")); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"update", "--only", "gitleaks"}, {"update", "--only", "nope"}} {
		if code := run(args, &out, &errb); code != exitInvalid {
			t.Errorf("%v: exit %d", args, code)
		}
	}
	if code := run([]string{"update", "extra"}, &out, &errb); code != exitUsage {
		t.Errorf("extra argument: exit %d", code)
	}
	useExecutor(t, fakeExec(func(sandbox.Spec) (*sandbox.Result, error) {
		return &sandbox.Result{Status: sandbox.Completed, ExitCode: 1, Stderr: "network unreachable"}, nil
	}), nil)
	out.Reset()
	if code := run([]string{"update"}, &out, &errb); code != exitInvalid || !strings.Contains(out.String(), "network unreachable") {
		t.Errorf("failed update: exit %d %s", code, out.String())
	}
}

func TestScanDependencyConsent(t *testing.T) {
	all, err := plugins.Builtin()
	if err != nil {
		t.Fatal(err)
	}
	ref := map[string]string{}
	for _, m := range all {
		ref[m.ID], _ = runner.ImageFor(m)
	}
	oldLook := deps.LookPath
	deps.LookPath = func(name string) (string, error) {
		if name == "trivy" {
			return "/usr/local/bin/trivy", nil
		}
		return "", errors.New("not found")
	}
	t.Cleanup(func() { deps.LookPath = oldLook })

	for _, tc := range []struct {
		name    string
		args    []string
		answer  string
		eng     *fakeEngine
		code    int
		pulled  []string
		want    []string
		wantNot []string
	}{
		{
			name: "user picks one", args: nil, answer: "1\n",
			eng: &fakeEngine{run: emptySARIF, have: map[string]bool{}}, code: exitOK,
			pulled: []string{ref["bandit"]},
			want: []string{"1. bandit 1.9.4 container image (42 MiB download), needed by: bandit",
				"trivy was found on your system at /usr/local/bin/trivy, but SiegeKit uses its own sandboxed, pinned copy.",
				"bandit             ran", "gitleaks           skipped    0 finding(s) - you declined gitleaks 8.30.1 container image",
				"trivy              skipped    0 finding(s) - you declined trivy 0.76.2 container image",
				"Skipped because a dependency is not installed: checkov, gitleaks, gitleaks-history, gosec, trivy.", "3. gitleaks 8.30.1 container image (42 MiB download), needed by: gitleaks, gitleaks-history\n  4. gosec"},
		},
		{
			name: "invalid answers then none", answer: "9\nx\nq\n",
			eng: &fakeEngine{run: emptySARIF, have: map[string]bool{}}, code: exitOK,
			want: []string{"Please answer a, n, or numbers from the list.", "you declined bandit"},
		},
		{
			name: "images installed, data accepted", answer: "a\n",
			eng: &fakeEngine{run: emptySARIF}, code: exitOK,
			want:    []string{"Already installed (not downloaded again): bandit 1.9.4 container image", "1. trivy data (size not known in advance), needed by: trivy", "trivy              ran"},
			wantNot: []string{"was found on your system", "Skipped because"},
		},
		{
			name: "no-install", args: []string{"--no-install"},
			eng: &fakeEngine{run: emptySARIF, have: map[string]bool{}}, code: exitOK,
			want: []string{"bandit 1.9.4 container image is not installed (--no-install)"},
		},
		{
			name: "download fails", args: []string{"--yes"},
			eng: &fakeEngine{run: emptySARIF, have: map[string]bool{}, pullErr: errors.New("registry unreachable")}, code: 4,
			want: []string{"failed     0 finding(s) - could not install bandit 1.9.4 container image: registry unreachable"},
		},
		{
			name: "engine not working",
			eng:  &fakeEngine{run: emptySARIF, hasErr: errors.New("container engine is not working: daemon down")}, code: 4,
			want: []string{"The container engine is not working", "backend-rules      ran", "gitleaks           failed"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("XDG_DATA_HOME", t.TempDir())
			target := t.TempDir()
			for _, name := range []string{"app.py", "main.go"} {
				os.WriteFile(filepath.Join(target, name), nil, 0o644)
			}
			useEngine(t, tc.eng, nil)
			stdin = strings.NewReader(tc.answer)
			stdinIsTerminal = func() bool { return true }
			var out, errb bytes.Buffer
			args := append([]string{"scan", "--no-save", "--report-dir", filepath.Join(t.TempDir(), "r"), target}, tc.args...)
			code := run(args, &out, &errb)
			if code != tc.code {
				t.Errorf("exit %d, want %d", code, tc.code)
			}
			if !slices.Equal(tc.eng.pulled, tc.pulled) {
				t.Errorf("pulled %v, want %v", tc.eng.pulled, tc.pulled)
			}
			for _, w := range tc.want {
				if !strings.Contains(out.String(), w) {
					t.Errorf("missing %q", w)
				}
			}
			for _, w := range tc.wantNot {
				if strings.Contains(out.String(), w) {
					t.Errorf("unexpected %q", w)
				}
			}
			if t.Failed() {
				t.Log(out.String(), errb.String())
			}
		})
	}
}

func TestUpdateAsksForMissingImage(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	useEngine(t, &fakeEngine{run: emptySARIF, have: map[string]bool{}}, nil)
	var out, errb bytes.Buffer
	if code := run([]string{"update"}, &out, &errb); code != exitInvalid || !strings.Contains(out.String(), "trivy      skipped - trivy 0.76.2 container image is not installed (no terminal to ask; use --yes)") {
		t.Fatalf("exit %d: %s", code, out.String())
	}
	out.Reset()
	if code := run([]string{"update", "--yes"}, &out, &errb); code != exitOK || !strings.Contains(out.String(), "trivy      updated") {
		t.Fatalf("--yes: exit %d: %s", code, out.String())
	}
}

// A saved run of the same target is compared with the new one (ADR 0013),
// also with --no-save.
func TestScanComparesWithLastRun(t *testing.T) {
	data := t.TempDir()
	t.Setenv("XDG_DATA_HOME", data)
	target, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	gone := findings.Finding{RuleID: "aws-key", Title: "AWS key", Severity: findings.High, Location: findings.Location{URI: "a.env", StartLine: 1}, Sources: []findings.Source{{Plugin: "gitleaks", RuleID: "aws-key"}}}
	gone.ComputeFingerprint()
	st := &store.Store{Dir: filepath.Join(data, "siegekit", "runs")}
	if _, err := st.Save(&report.Run{SiegeKitVersion: "old", Target: target, Started: time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC), Findings: []findings.Finding{gone}}, "t"); err != nil {
		t.Fatal(err)
	}
	reports := filepath.Join(t.TempDir(), "rep")
	useExecutor(t, emptySARIF, nil)
	var out, errb bytes.Buffer
	if code := run([]string{"scan", target, "--no-save", "--report-dir", reports}, &out, &errb); code != exitOK {
		t.Fatalf("exit %d: %s %s", code, out.String(), errb.String())
	}
	if !strings.Contains(out.String(), "Since the last scan of this target (2026-11-01 00:00 UTC): 0 new, 1 fixed, 0 still present.") ||
		!strings.Contains(out.String(), "The previous run used SiegeKit old") {
		t.Errorf("output: %s", out.String())
	}
	var r report.Run
	b, _ := os.ReadFile(filepath.Join(reports, "report.json"))
	if err := json.Unmarshal(b, &r); err != nil || r.Comparison == nil || len(r.Comparison.Fixed) != 1 || r.Comparison.Fixed[0].Fingerprint != gone.Fingerprint {
		t.Fatalf("comparison in report.json: %s %v", b, err)
	}
	h, _ := os.ReadFile(filepath.Join(reports, "report.html"))
	if !strings.Contains(string(h), "Since the last scan") || !strings.Contains(string(h), "AWS key") {
		t.Errorf("HTML report has no comparison")
	}
	// Another target is not compared.
	out.Reset()
	if code := run([]string{"scan", t.TempDir(), "--no-save", "--report-dir", reports}, &out, &errb); code != exitOK || strings.Contains(out.String(), "Since the last scan") {
		t.Errorf("exit %d: %s", code, out.String())
	}
}

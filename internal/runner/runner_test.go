package runner

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

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
	if got, _ := Select(all, "repo", nil, nil); !slices.Equal(ids(got), []string{"checkov", "gitleaks"}) {
		t.Errorf("all: %v", ids(got))
	}
	if got, _ := Select(all, "repo", []string{"gitleaks"}, nil); !slices.Equal(ids(got), []string{"gitleaks"}) {
		t.Errorf("only: %v", ids(got))
	}
	if got, _ := Select(all, "repo", nil, []string{"gitleaks"}); !slices.Equal(ids(got), []string{"checkov"}) {
		t.Errorf("skip: %v", ids(got))
	}
	for name, c := range map[string][2][]string{
		"unknown only": {{"nope"}, nil},
		"unknown skip": {nil, {"nope"}},
		"nothing left": {{"gitleaks"}, {"gitleaks"}},
	} {
		if _, err := Select(all, "repo", c[0], c[1]); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
	if _, err := Select(all, "url", []string{"gitleaks"}, nil); err == nil {
		t.Error("wrong target kind: expected error")
	}
}

func TestSubstituteRejectsRateLimit(t *testing.T) {
	if _, err := substitute([]string{"--rate", "{ratelimit}"}, 1); err == nil {
		t.Fatal("expected rejection")
	}
	got, err := substitute([]string{"{target}", "{outdir}/x", "{workdir}", "-j{threads}"}, 3)
	if err != nil || !slices.Equal(got, []string{"/target", "/out/x", "/tmp/work", "-j3"}) {
		t.Fatalf("got %v %v", got, err)
	}
}

func TestLastLine(t *testing.T) {
	for in, want := range map[string]string{
		"":                       "no error output",
		"a\nb\n\n":               "b",
		"x\x07y\u0085z":          "xyz",
		strings.Repeat("é", 400): strings.Repeat("é", 300) + "…",
		"bad\xffutf8":            "badutf8",
	} {
		if got := lastLine(in); got != want {
			t.Errorf("lastLine(%q) = %q, want %q", in, got, want)
		}
	}
}

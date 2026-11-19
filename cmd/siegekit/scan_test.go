package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Gobbuwu/SiegeKit/internal/runner"
	"github.com/Gobbuwu/SiegeKit/internal/sandbox"
)

type fakeExec func(s sandbox.Spec) (*sandbox.Result, error)

func (f fakeExec) Run(_ context.Context, s sandbox.Spec) (*sandbox.Result, error) { return f(s) }

func useExecutor(t *testing.T, ex runner.Executor, err error) {
	t.Helper()
	old := newExecutor
	newExecutor = func() (runner.Executor, error) { return ex, err }
	t.Cleanup(func() { newExecutor = old })
}

// emptySARIF makes every plugin complete with no findings.
var emptySARIF = fakeExec(func(s sandbox.Spec) (*sandbox.Result, error) {
	for _, name := range []string{"gitleaks.sarif", "results_sarif.sarif"} {
		doc := `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"x"}},"results":[]}]}`
		if err := os.WriteFile(filepath.Join(s.OutDir, name), []byte(doc), 0o644); err != nil {
			return nil, err
		}
	}
	return &sandbox.Result{Status: sandbox.Completed}, nil
})

func TestScan(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	target := t.TempDir()
	reports := filepath.Join(t.TempDir(), "rep")
	useExecutor(t, emptySARIF, nil)
	var out, errb bytes.Buffer
	if code := run([]string{"scan", target, "--report-dir", reports}, &out, &errb); code != exitOK {
		t.Fatalf("exit %d: %s %s", code, out.String(), errb.String())
	}
	if !strings.Contains(out.String(), "No issues found by the 2 check(s) that ran.") || !strings.Contains(out.String(), "Saved run") {
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
		{"no engine", []string{dir}, nil, errors.New("no container engine found"), exitInvalid, "no container engine"},
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

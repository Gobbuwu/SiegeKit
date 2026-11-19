package deps

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Gobbuwu/SiegeKit/internal/manifest"
	"github.com/Gobbuwu/SiegeKit/internal/report"
	"github.com/Gobbuwu/SiegeKit/internal/runner"
	"github.com/Gobbuwu/SiegeKit/internal/sandbox"
	"github.com/Gobbuwu/SiegeKit/plugins"
)

type eng struct {
	have   map[string]bool
	pulled int
}

func (e *eng) HasImage(_ context.Context, image string) (bool, error) { return e.have[image], nil }
func (e *eng) Pull(_ context.Context, image string) error {
	e.pulled++
	e.have[image] = true
	return nil
}

type noRun struct{ t *testing.T }

func (n noRun) Run(context.Context, sandbox.Spec) (*sandbox.Result, error) {
	n.t.Error("nothing should run")
	return nil, errors.New("no")
}

type badSizer struct{}

func (badSizer) DownloadSize(context.Context, string, string) (int64, error) {
	return 0, errors.New("offline")
}

func trivy(t *testing.T) []*manifest.Manifest {
	all, err := plugins.Builtin()
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range all {
		if m.ID == "trivy" {
			return []*manifest.Manifest{m}
		}
	}
	t.Fatal("no trivy")
	return nil
}

func TestPlanAndInstall(t *testing.T) {
	LookPath = func(string) (string, error) { return "", errors.New("none") }
	t.Cleanup(func() { LookPath = defaultLookPath })
	ms := trivy(t)
	root := t.TempDir()
	e := &eng{have: map[string]bool{}}
	ds, err := Plan(context.Background(), e, ms, root)
	if err != nil || len(ds) != 2 || ds[0].Kind != Image || ds[1].Kind != Data || ds[0].Installed || ds[1].Installed {
		t.Fatalf("plan %+v %v", ds, err)
	}
	AddSizes(context.Background(), badSizer{}, ds)
	if ds[0].Size != -1 {
		t.Errorf("unknown size should stay -1, got %d", ds[0].Size)
	}
	var out bytes.Buffer
	Describe(&out, ds)
	if !strings.Contains(out.String(), "1. trivy 0.76.2 container image (size not known in advance)") {
		t.Errorf("describe: %s", out.String())
	}
	// Data was chosen but its image was not: nothing is downloaded and the
	// reason names the image.
	un, err := Install(context.Background(), e, noRun{t}, ds, ds[1:], root, func(d Dep) string { return "declined " + d.Name() }, &out)
	if err != nil || un["trivy"].Status != report.Skipped || un["trivy"].Reason != "declined trivy 0.76.2 container image" || e.pulled != 0 {
		t.Errorf("install %+v %v pulled %d", un, err, e.pulled)
	}
	// Data counts as installed only with its stamp.
	os.Mkdir(filepath.Join(root, "trivy"), 0o700)
	if dataInstalled(root, "trivy") {
		t.Error("data without stamp counted as installed")
	}
	os.WriteFile(filepath.Join(root, "trivy.updated"), []byte("x"), 0o600)
	if !dataInstalled(root, "trivy") || dataInstalled("", "trivy") {
		t.Error("dataInstalled")
	}
}

func TestParseAnswer(t *testing.T) {
	ms := trivy(t)
	missing := []Dep{{Kind: Image, Plugin: ms[0]}, {Kind: Data, Plugin: ms[0]}}
	for a, want := range map[string]int{"a": 2, "YES": 2, "": 0, "n": 0, "none": 0, "2": 1, "1, 2": 2, "1 1": 1} {
		got, ok := parseAnswer(a, missing)
		if !ok || len(got) != want {
			t.Errorf("%q: %d %v, want %d", a, len(got), ok, want)
		}
	}
	for _, a := range []string{"3", "0", "-1", "x", "1,x"} {
		if _, ok := parseAnswer(a, missing); ok {
			t.Errorf("%q accepted", a)
		}
	}
	var out bytes.Buffer
	if got := Ask(strings.NewReader("x\n2"), &out, missing); len(got) != 1 || got[0].Kind != Data {
		t.Errorf("ask: %+v %s", got, out.String())
	}
}

func TestHumanSize(t *testing.T) {
	for n, want := range map[int64]string{1: "1 KiB", 42 << 20: "42 MiB", 3 << 29: "1.5 GiB"} {
		if got := humanSize(n); got != want {
			t.Errorf("%d: %q, want %q", n, got, want)
		}
	}
}

func TestEngineHelp(t *testing.T) {
	if !strings.Contains(EngineHelp("darwin"), "Docker Desktop") || !strings.Contains(EngineHelp("linux"), "docs.docker.com/engine/install") {
		t.Error("help text")
	}
}

type pullFail struct {
	eng
	err error
}

func (e *pullFail) Pull(context.Context, string) error { return e.err }

type hasErr struct{ eng }

func (hasErr) HasImage(context.Context, string) (bool, error) {
	return false, errors.New("daemon down")
}

type sizer int64

func (s sizer) DownloadSize(context.Context, string, string) (int64, error) { return int64(s), nil }

// dataRun is an update container: it writes data when ok, fails otherwise.
type dataRun struct{ ok bool }

func (d dataRun) Run(_ context.Context, s sandbox.Spec) (*sandbox.Result, error) {
	if !d.ok {
		return &sandbox.Result{Status: sandbox.Completed, ExitCode: 1, Stderr: "no network"}, nil
	}
	if err := os.WriteFile(filepath.Join(s.DataDir, "db"), []byte("x"), 0o600); err != nil {
		return nil, err
	}
	return &sandbox.Result{Status: sandbox.Completed}, nil
}

func builtins(t *testing.T, ids ...string) []*manifest.Manifest {
	t.Helper()
	all, err := plugins.Builtin()
	if err != nil {
		t.Fatal(err)
	}
	var out []*manifest.Manifest
	for _, id := range ids {
		for _, m := range all {
			if m.ID == id {
				out = append(out, m)
			}
		}
	}
	if len(out) != len(ids) {
		t.Fatalf("found %d of %v", len(out), ids)
	}
	return out
}

func TestPlanSharedImageAndHostTool(t *testing.T) {
	LookPath = func(name string) (string, error) { return "/usr/bin/" + name, nil }
	t.Cleanup(func() { LookPath = defaultLookPath })
	ms := builtins(t, "gitleaks", "gitleaks-history", "checkov")
	e := &eng{have: map[string]bool{}}
	img, _ := runner.ImageFor(ms[2])
	e.have[img] = true // checkov installed
	ds, err := Plan(context.Background(), e, ms, "")
	if err != nil || len(ds) != 2 {
		t.Fatalf("plan %+v %v", ds, err)
	}
	if ds[0].NeededBy() != "gitleaks, gitleaks-history" || ds[0].HostPath != "/usr/bin/gitleaks" {
		t.Errorf("shared image %+v needed by %q", ds[0], ds[0].NeededBy())
	}
	if !ds[1].Installed || ds[1].HostPath != "" {
		t.Errorf("installed image %+v", ds[1])
	}
	AddSizes(context.Background(), sizer(24<<20), ds)
	if ds[0].Size != 24<<20 || ds[1].Size != -1 {
		t.Errorf("sizes %d %d", ds[0].Size, ds[1].Size)
	}
	var out bytes.Buffer
	Describe(&out, ds)
	for _, want := range []string{
		"Already installed (not downloaded again): checkov",
		"1. gitleaks 8.30.1 container image (24 MiB download), needed by: gitleaks, gitleaks-history",
		"gitleaks was found on your system at /usr/bin/gitleaks, but SiegeKit uses its own sandboxed, pinned copy.",
	} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("describe lacks %q:\n%s", want, out.String())
		}
	}
	// Nothing missing: only the installed line.
	out.Reset()
	Describe(&out, ds[1:])
	if strings.Contains(out.String(), "Missing") {
		t.Errorf("describe: %s", out.String())
	}
	if _, err := Plan(context.Background(), &hasErr{}, ms, ""); err == nil {
		t.Error("engine error not returned")
	}
}

func TestInstallPullsAndUpdates(t *testing.T) {
	LookPath = func(string) (string, error) { return "", errors.New("none") }
	t.Cleanup(func() { LookPath = defaultLookPath })
	ms := builtins(t, "trivy", "gitleaks")
	root := filepath.Join(t.TempDir(), "data")
	e := &eng{have: map[string]bool{}}
	ds, err := Plan(context.Background(), e, ms, root)
	if err != nil || len(ds) != 3 {
		t.Fatalf("plan %+v %v", ds, err)
	}
	var out bytes.Buffer
	never := func(Dep) string { t.Error("everything was chosen"); return "" }

	// Everything chosen, data update fails: trivy fails, gitleaks is fine.
	un, err := Install(context.Background(), e, dataRun{ok: false}, ds, ds, root, never, &out)
	if err != nil || e.pulled != 2 || len(un) != 1 || un["trivy"].Status != report.Failed || !strings.Contains(un["trivy"].Reason, "could not download data") {
		t.Fatalf("install %+v %v pulled %d", un, err, e.pulled)
	}
	if !strings.Contains(out.String(), "Downloading trivy 0.76.2 container image...") || !strings.Contains(out.String(), "Downloading tool data") {
		t.Errorf("output: %s", out.String())
	}

	// Images now installed; the data update succeeds.
	ds, _ = Plan(context.Background(), e, ms, root)
	un, err = Install(context.Background(), e, dataRun{ok: true}, ds, ds, root, never, &out)
	if err != nil || len(un) != 0 || !dataInstalled(root, "trivy") {
		t.Errorf("install %+v %v, data installed %v", un, err, dataInstalled(root, "trivy"))
	}

	// Data chosen but no data directory known.
	empty := &eng{have: map[string]bool{}}
	ds, _ = Plan(context.Background(), empty, ms[:1], "")
	if _, err := Install(context.Background(), empty, dataRun{ok: true}, ds, ds, "", never, &out); err == nil {
		t.Error("no error without a data directory")
	}
}

func TestInstallPullFailure(t *testing.T) {
	LookPath = func(string) (string, error) { return "", errors.New("none") }
	t.Cleanup(func() { LookPath = defaultLookPath })
	ms := builtins(t, "trivy", "gitleaks", "gitleaks-history")
	e := &pullFail{eng: eng{have: map[string]bool{}}, err: errors.New("registry unreachable")}
	ds, err := Plan(context.Background(), e, ms, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	un, err := Install(context.Background(), e, noRun{t}, ds, ds, t.TempDir(), func(Dep) string { return "" }, &out)
	if err != nil {
		t.Fatal(err)
	}
	// Every user of a failed image fails; trivy's data is not attempted.
	for _, id := range []string{"trivy", "gitleaks", "gitleaks-history"} {
		if un[id].Status != report.Failed || !strings.Contains(un[id].Reason, "registry unreachable") {
			t.Errorf("%s: %+v", id, un[id])
		}
	}
	if strings.Contains(out.String(), "tool data") {
		t.Errorf("data downloaded without its image: %s", out.String())
	}

	// A cancelled run returns the context error, not a per-plugin failure.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Install(ctx, e, noRun{t}, ds, ds, t.TempDir(), func(Dep) string { return "" }, &out); !errors.Is(err, context.Canceled) {
		t.Errorf("cancelled: %v", err)
	}
}

func TestNoEngine(t *testing.T) {
	ms := builtins(t, "trivy", "gitleaks")
	un := NoEngine(ms, "no engine")
	if len(un) != 2 || un["trivy"].Status != report.Skipped || un["gitleaks"].Reason != "no engine" {
		t.Errorf("%+v", un)
	}
}

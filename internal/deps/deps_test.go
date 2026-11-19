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

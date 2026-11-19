package runner

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Gobbuwu/SiegeKit/internal/manifest"
	"github.com/Gobbuwu/SiegeKit/internal/report"
	"github.com/Gobbuwu/SiegeKit/internal/sandbox"
)

func TestUpdateReplacesDataOnlyOnSuccess(t *testing.T) {
	m := builtin(t, "trivy")
	root := filepath.Join(t.TempDir(), "data")
	write1 := &fake{act: func(s sandbox.Spec) (*sandbox.Result, error) {
		if s.Network != "egress" || s.TargetDir != "" || !s.DataWritable || s.DataMount != "/tmp/trivy/db" || s.TmpMiB != 1024 {
			t.Errorf("unsafe update spec %+v", s)
		}
		if strings.Join(s.Args, " ") != "image --cache-dir /tmp/trivy --download-db-only --no-progress" {
			t.Errorf("args %v", s.Args)
		}
		return &sandbox.Result{Status: sandbox.Completed}, os.WriteFile(filepath.Join(s.DataDir, "trivy.db"), []byte("v1"), 0o644)
	}}
	res, err := Update(context.Background(), write1, []*manifest.Manifest{builtin(t, "gitleaks"), m}, root, t.TempDir())
	if err != nil || len(res) != 1 || res[0].Err != nil {
		t.Fatalf("%+v %v", res, err)
	}
	if st, _ := os.Stat(root); st.Mode().Perm() != 0o700 {
		t.Errorf("data root mode %v", st.Mode().Perm())
	}
	if b, _ := os.ReadFile(filepath.Join(root, "trivy", "trivy.db")); string(b) != "v1" {
		t.Fatalf("data %q", b)
	}
	if _, warn, err := dataFor(root, m, time.Now()); err != nil || warn != "" {
		t.Fatalf("fresh data: %q %v", warn, err)
	}

	for name, act := range map[string]func(s sandbox.Spec) (*sandbox.Result, error){
		"tool error": func(s sandbox.Spec) (*sandbox.Result, error) {
			os.WriteFile(filepath.Join(s.DataDir, "trivy.db"), []byte("partial"), 0o644)
			return &sandbox.Result{Status: sandbox.Completed, ExitCode: 1}, nil
		},
		"timeout": func(sandbox.Spec) (*sandbox.Result, error) {
			return &sandbox.Result{Status: sandbox.TimedOut}, nil
		},
		"no data": func(sandbox.Spec) (*sandbox.Result, error) {
			return &sandbox.Result{Status: sandbox.Completed}, nil
		},
	} {
		res, err := Update(context.Background(), &fake{act: act}, []*manifest.Manifest{m}, root, t.TempDir())
		if err != nil || res[0].Err == nil {
			t.Errorf("%s: expected failure, got %+v %v", name, res, err)
		}
		if b, _ := os.ReadFile(filepath.Join(root, "trivy", "trivy.db")); string(b) != "v1" {
			t.Errorf("%s: old data lost, got %q", name, b)
		}
	}
	entries, _ := os.ReadDir(root)
	if len(entries) != 2 { // trivy/ and trivy.updated
		t.Errorf("leftover entries: %v", entries)
	}
}

func TestUpdateRejectsRelativeRoot(t *testing.T) {
	if _, err := Update(context.Background(), &fake{}, nil, "rel", ""); err == nil {
		t.Fatal("expected rejection")
	}
}

func TestDataFor(t *testing.T) {
	m := builtin(t, "trivy")
	root := t.TempDir()
	now := time.Date(2026, 11, 19, 0, 0, 0, 0, time.UTC)
	if _, _, err := dataFor(root, m, now); err == nil || !strings.Contains(err.Error(), "siegekit update") {
		t.Fatalf("missing data: %v", err)
	}
	if _, _, err := dataFor("", m, now); err == nil {
		t.Fatal("empty root accepted")
	}
	os.Mkdir(filepath.Join(root, "trivy"), 0o755)
	if _, warn, _ := dataFor(root, m, now); !strings.Contains(warn, "unknown") {
		t.Errorf("no stamp: %q", warn)
	}
	writeStamp(root, "trivy", now.Add(-10*24*time.Hour))
	if _, warn, _ := dataFor(root, m, now); warn != "data is 10 days old; run 'siegekit update'" {
		t.Errorf("stale: %q", warn)
	}
}

func TestScanMountsDataReadOnly(t *testing.T) {
	m := builtin(t, "trivy")
	o := opts(t)
	o.DataRoot = t.TempDir()
	os.Mkdir(filepath.Join(o.DataRoot, "trivy"), 0o755)
	writeStamp(o.DataRoot, "trivy", time.Now())
	f := &fake{act: func(s sandbox.Spec) (*sandbox.Result, error) {
		if s.DataWritable || s.Network != "none" || s.DataDir != filepath.Join(o.DataRoot, "trivy") || s.DataMount != "/tmp/trivy/db" {
			t.Errorf("scan spec %+v", s)
		}
		doc := `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"Trivy"}},"results":[]}]}`
		return &sandbox.Result{Status: sandbox.Completed}, os.WriteFile(filepath.Join(s.OutDir, "trivy.sarif"), []byte(doc), 0o644)
	}}
	r, err := Run(context.Background(), f, []*manifest.Manifest{m}, o)
	if err != nil || r.Plugins[0].Status != report.Ran {
		t.Fatalf("%+v %v", r.Plugins, err)
	}
}

func TestRemoveLeftovers(t *testing.T) {
	root := t.TempDir()
	for _, d := range []string{".trivy-new-abc", ".trivy-old-xyz", "trivy", ".other-new-1"} {
		if err := os.MkdirAll(filepath.Join(root, d, "sub"), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := removeLeftovers(root, "trivy"); err != nil {
		t.Fatal(err)
	}
	entries, _ := os.ReadDir(root)
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	if strings.Join(names, ",") != ".other-new-1,trivy" {
		t.Errorf("left %v", names)
	}
}

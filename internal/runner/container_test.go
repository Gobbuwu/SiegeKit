package runner

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Gobbuwu/SiegeKit/internal/findings"
	"github.com/Gobbuwu/SiegeKit/internal/report"
	"github.com/Gobbuwu/SiegeKit/internal/sandbox"
	"github.com/Gobbuwu/SiegeKit/plugins"
)

// TestBuiltinPluginsFindPlantedIssues runs the real pinned tool images. CI
// enables it on Linux with SIEGEKIT_CONTAINER_TESTS=1.
func TestBuiltinPluginsFindPlantedIssues(t *testing.T) {
	if os.Getenv("SIEGEKIT_CONTAINER_TESTS") != "1" {
		t.Skip("set SIEGEKIT_CONTAINER_TESTS=1 to run container tests")
	}
	e, err := sandbox.Detect()
	if err != nil {
		t.Fatal(err)
	}
	target := t.TempDir()
	// The token is assembled at run time so this repository never contains
	// a string that secret scanners would flag.
	token := "ghp_" + strings.Repeat("1a2B3c4D5e6F", 3)
	for name, body := range map[string]string{
		"config.py":        "GITHUB_TOKEN = \"" + token + "\"\n",
		"Dockerfile":       "FROM ubuntu:latest\nRUN apt-get update\nUSER root\n",
		"requirements.txt": "django==2.2.0\n",
		"app.py":           "import subprocess\n\ndef run(cmd):\n    return subprocess.call(cmd, shell=True)\n",
		"go.mod":           "module example.test/app\n\ngo 1.22\n",
		"main.go":          "package main\n\nimport (\n\t\"crypto/md5\"\n\t\"fmt\"\n\t\"os\"\n)\n\nfunc main() {\n\tfmt.Printf(\"%x\\n\", md5.Sum([]byte(os.Args[1])))\n}\n",
	} {
		if err := os.WriteFile(filepath.Join(target, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// When the tests run as root the container user is 65532, which needs to
	// read the target.
	if err := os.Chmod(target, 0o755); err != nil {
		t.Fatal(err)
	}
	all, err := plugins.Builtin()
	if err != nil {
		t.Fatal(err)
	}
	// SIEGEKIT_TEST_DATA_ROOT reuses already downloaded data (for networks
	// where the update container cannot reach the publisher); otherwise the
	// real update runs first.
	dataRoot := os.Getenv("SIEGEKIT_TEST_DATA_ROOT")
	if dataRoot == "" {
		dataRoot = filepath.Join(t.TempDir(), "data")
		res, err := Update(context.Background(), e, all, dataRoot, "")
		if err != nil {
			t.Fatal(err)
		}
		for _, u := range res {
			if u.Err != nil {
				t.Fatalf("update %s: %v", u.ID, u.Err)
			}
		}
	}
	r, err := Run(context.Background(), e, all, Options{Version: "test", TargetDir: target, DataRoot: dataRoot})
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range r.Plugins {
		if p.Status != report.Ran {
			t.Fatalf("%s: %s %s", p.ID, p.Status, p.Reason)
		}
	}
	var secret, root, vuln, py, gocode bool
	for _, f := range r.Findings {
		t.Logf("%s %s %s:%d", f.Severity, f.RuleID, f.Location.URI, f.Location.StartLine)
		if strings.Contains(f.Snippet+f.Message, token[4:12]) {
			t.Errorf("secret value in finding %+v", f)
		}
		switch {
		case f.Sources[0].Plugin == "gitleaks" && f.Location.URI == "config.py" && f.Severity == findings.High:
			secret = true
		case f.RuleID == "CVE-2019-14234" && f.Location.URI == "requirements.txt" && f.Severity == findings.Critical:
			vuln = true
		case f.Sources[0].Plugin == "bandit" && f.Location.URI == "app.py" && f.Location.StartLine == 4:
			py = true
		case f.Sources[0].Plugin == "gosec" && f.Location.URI == "main.go":
			gocode = true
		case f.RuleID == "CKV_DOCKER_8" && f.Location.URI == "Dockerfile" && f.Location.StartLine == 3 && f.Severity == findings.Medium:
			root = true
		}
	}
	if !secret || !root || !vuln || !py || !gocode {
		t.Errorf("planted issues not found: secret=%v root-user=%v vulnerable-dependency=%v python=%v go=%v", secret, root, vuln, py, gocode)
	}
}

// TestPinnedImageVersions checks that each pinned image contains the tool
// version its manifest claims. Some publishers tag images only as "latest",
// so the digest alone does not say which version it is.
func TestPinnedImageVersions(t *testing.T) {
	if os.Getenv("SIEGEKIT_CONTAINER_TESTS") != "1" {
		t.Skip("set SIEGEKIT_CONTAINER_TESTS=1 to run container tests")
	}
	e, err := sandbox.Detect()
	if err != nil {
		t.Fatal(err)
	}
	// gosec's image wraps it in an entrypoint script that prints nothing for
	// -version, so its SARIF output (which names the tool version) is read.
	versionArgs := map[string][]string{
		"bandit": {"--version"}, "checkov": {"--version"}, "gitleaks": {"version"},
		"gosec": {"-fmt", "sarif", "-out", "/out/v.sarif", "-no-fail", "/target/..."}, "trivy": {"--version"},
	}
	all, err := plugins.Builtin()
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range all {
		args, ok := versionArgs[m.ID]
		if !ok {
			t.Errorf("%s: no version check", m.ID)
			continue
		}
		image, ok := imageFor(m)
		if !ok {
			t.Logf("%s: no image for this platform", m.ID)
			continue
		}
		out := t.TempDir()
		// A minimal Go module, so gosec has a package to report on.
		src := t.TempDir()
		os.WriteFile(filepath.Join(src, "go.mod"), []byte("module v.test\n\ngo 1.22\n"), 0o644)
		os.WriteFile(filepath.Join(src, "main.go"), []byte("package main\n\nfunc main() {}\n"), 0o644)
		os.Chmod(src, 0o755)
		r, err := e.Run(context.Background(), sandbox.Spec{
			Image: image, Args: args, OutDir: out, TargetDir: src, Network: "none",
			CPUs: 1, MemoryMiB: 512, Timeout: 120 * time.Second,
		})
		if err != nil {
			t.Fatalf("%s: %v", m.ID, err)
		}
		got := r.Stderr
		if b, err := os.ReadFile(filepath.Join(out, "v.sarif")); err == nil {
			got = string(b)
			if len(got) > 2000 {
				got = got[:2000]
			}
		}
		if !strings.Contains(got, `"version": "`+m.Tool.Version+`"`) && !strings.Contains(got, m.Tool.Version+"\n") && !strings.Contains(got, " "+m.Tool.Version) && !strings.Contains(got, "v"+m.Tool.Version) {
			cfg, _ := exec.Command(e.Bin, "image", "inspect", "--format", "{{json .Config.Entrypoint}} {{json .Config.Cmd}}", image).CombinedOutput()
			t.Errorf("%s: image does not report version %s (exit %d, entrypoint/cmd %s):\n%s", m.ID, m.Tool.Version, r.ExitCode, cfg, got)
		}
	}
}

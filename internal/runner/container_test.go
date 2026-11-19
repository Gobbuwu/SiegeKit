package runner

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Gobbuwu/SiegeKit/internal/checks"
	"github.com/Gobbuwu/SiegeKit/internal/findings"
	"github.com/Gobbuwu/SiegeKit/internal/manifest"
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
		"config.py":                         "GITHUB_TOKEN = \"" + token + "\"\n",
		"Dockerfile":                        "FROM ubuntu:latest\nRUN apt-get update\nUSER root\n# checkov:skip=CKV_DOCKER_2: planted suppression\n",
		"requirements.txt":                  "django==2.2.0\n",
		"app.py":                            "import subprocess\n\ndef run(cmd):\n    return subprocess.call(cmd, shell=True)\n\ndef ls():\n    return subprocess.call(\"ls\", shell=True)  # nosec\n",
		"go.mod":                            "module example.test/app\n\ngo 1.22\n",
		"main.go":                           "package main\n\nimport (\n\t\"crypto/md5\"\n\t\"fmt\"\n\t\"os\"\n)\n\nfunc main() {\n\tfmt.Printf(\"%x\\n\", md5.Sum([]byte(os.Args[1])))\n}\n\nfunc sum(b []byte) [16]byte { return md5.Sum(b) } // #nosec G401 -- planted suppression\n",
		"firestore.rules":                   "rules_version = '2';\nservice cloud.firestore {\n  match /databases/{database}/documents {\n    match /{document=**} {\n      allow read, write: if true;\n    }\n  }\n}\n",
		"supabase/migrations/0001_init.sql": "create table profiles (id uuid primary key);\n",
		// The repository's own ignore settings: obeyed, but reported.
		".gitleaksignore": "# none\n",
		"notes.txt":       "example = 1 # gitleaks:allow\n",
	} {
		if err := os.MkdirAll(filepath.Dir(filepath.Join(target, name)), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(target, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// History: a .env committed and then removed from the tree. The history
	// plugin must still find it, and .gitignore does not exclude .env.
	git := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-c", "user.name=test", "-c", "user.email=test@example.invalid", "-c", "commit.gpgsign=false"}, args...)...)
		cmd.Dir = target
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	git("init", "-q")
	if err := os.WriteFile(filepath.Join(target, ".env"), []byte("DATABASE_URL=postgres://app@db/app\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	git("add", ".")
	git("commit", "-q", "-m", "initial")
	git("rm", "-q", ".env")
	git("commit", "-q", "-m", "remove .env")
	// When the tests run as root the container user is 65532, which needs to
	// read the target.
	if err := os.Chmod(target, 0o755); err != nil {
		t.Fatal(err)
	}
	all, err := plugins.Builtin()
	if err != nil {
		t.Fatal(err)
	}
	pullAll(t, e, all)
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
	r, err := Run(context.Background(), e, all, Options{Version: "test", TargetDir: target, DataRoot: dataRoot, Checks: checks.Builtin()})
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range r.Plugins {
		if p.Status != report.Ran {
			t.Fatalf("%s: %s %s", p.ID, p.Status, p.Reason)
		}
	}
	var secret, root, vuln, py, gocode, firebase, supabase, envHistory, envIgnore bool
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
		case f.RuleID == "firebase-public-access" && f.Location.URI == "firestore.rules" && f.Location.StartLine == 5 && f.Severity == findings.Critical:
			firebase = true
		case f.RuleID == "supabase-table-without-rls" && f.Location.URI == "supabase/migrations/0001_init.sql" && f.Location.StartLine == 1:
			supabase = true
		case f.RuleID == "env-file-committed" && f.Location.URI == ".env" && f.Sources[0].Plugin == "gitleaks-history":
			envHistory = true
		case f.RuleID == "gitignore-missing-env" && f.Sources[0].Plugin == "dotenv-gitignore":
			envIgnore = true
		case f.RuleID == "CKV_DOCKER_8" && f.Location.URI == "Dockerfile" && f.Location.StartLine == 3 && f.Severity == findings.Medium:
			root = true
		}
	}
	// Suppressions in the code are obeyed but counted (owner decision,
	// 2026-11-19), using what each real tool reports.
	byID := map[string]report.PluginResult{}
	for _, p := range r.Plugins {
		byID[p.ID] = p
	}
	for _, id := range []string{"bandit", "gosec", "checkov"} {
		if byID[id].Suppressed < 1 {
			t.Errorf("%s: planted suppression not counted: %+v", id, byID[id])
		}
	}
	for _, id := range []string{"gitleaks", "gitleaks-history"} {
		if p := byID[id]; !slices.Contains(p.RepoSettings, ".gitleaksignore") || p.IgnoreMarkers != 1 {
			t.Errorf("%s: repository ignores not reported: %+v", id, p)
		}
	}
	if !secret || !root || !vuln || !py || !gocode || !firebase || !supabase || !envHistory || !envIgnore {
		t.Errorf("planted issues not found: secret=%v root-user=%v vulnerable-dependency=%v python=%v go=%v firebase=%v supabase=%v env-in-history=%v env-not-ignored=%v", secret, root, vuln, py, gocode, firebase, supabase, envHistory, envIgnore)
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
	// -version, and its binary reports version "dev" (seen in CI, 2026-11-19),
	// so for gosec only the tool name is checked; its version rests on the
	// 2.30.0 tag that the digest was resolved from (THIRD_PARTY.md).
	unversioned := map[string]bool{"gosec": true}
	versionArgs := map[string][]string{
		"bandit": {"--version"}, "checkov": {"--version"}, "gitleaks": {"version"},
		"gosec": {"-fmt", "sarif", "-out", "/out/v.sarif", "-no-fail", "/target/..."}, "trivy": {"--version"}, "gitleaks-history": {"version"},
	}
	all, err := plugins.Builtin()
	if err != nil {
		t.Fatal(err)
	}
	pullAll(t, e, all)
	for _, m := range all {
		args, ok := versionArgs[m.ID]
		if !ok {
			t.Errorf("%s: no version check", m.ID)
			continue
		}
		image, ok := ImageFor(m)
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
			var l struct {
				Runs []struct {
					Tool struct {
						Driver json.RawMessage `json:"driver"`
					} `json:"tool"`
				} `json:"runs"`
			}
			if err := json.Unmarshal(b, &l); err != nil || len(l.Runs) == 0 {
				t.Fatalf("%s: bad SARIF: %v", m.ID, err)
			}
			got = string(l.Runs[0].Tool.Driver)
			if len(got) > 1000 {
				got = got[:1000]
			}
		}
		if unversioned[m.ID] {
			if !strings.Contains(got, `"name": "`+m.Tool.Name+`"`) {
				t.Errorf("%s: image is not %s:\n%s", m.ID, m.Tool.Name, got)
			}
			continue
		}
		if !strings.Contains(got, `"version": "`+m.Tool.Version+`"`) && !strings.Contains(got, m.Tool.Version+"\n") && !strings.Contains(got, " "+m.Tool.Version) && !strings.Contains(got, "v"+m.Tool.Version) {
			cfg, _ := exec.Command(e.Bin, "image", "inspect", "--format", "{{json .Config.Entrypoint}} {{json .Config.Cmd}}", image).CombinedOutput()
			t.Errorf("%s: image does not report version %s (exit %d, entrypoint/cmd %s):\n%s", m.ID, m.Tool.Version, r.ExitCode, cfg, got)
		}
	}
}

// pullAll downloads each plugin's pinned image: runs never pull (ADR 0016).
func pullAll(t *testing.T, e *sandbox.Engine, ms []*manifest.Manifest) {
	t.Helper()
	for _, m := range ms {
		image, ok := ImageFor(m)
		if !ok {
			continue
		}
		// Only missing images: a pull asks the registry even when the image
		// is present, and registries rate-limit those requests.
		if has, err := e.HasImage(context.Background(), image); err != nil {
			t.Fatalf("%s: %v", m.ID, err)
		} else if !has {
			if err := e.Pull(context.Background(), image); err != nil {
				t.Fatalf("%s: %v", m.ID, err)
			}
		}
	}
}

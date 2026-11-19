package sandbox

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// testImage is Alpine 3.20 pinned by digest (multi-architecture index).
const testImage = "docker.io/library/alpine@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc"

func spec(t *testing.T, args ...string) Spec {
	t.Helper()
	target := t.TempDir()
	if err := os.WriteFile(filepath.Join(target, "app.txt"), []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}
	return Spec{
		Image: testImage, Args: args, TargetDir: target, OutDir: t.TempDir(),
		Network: "none", CPUs: 1, MemoryMiB: 128, Timeout: 60 * time.Second,
	}
}

func TestEngineArgsHardening(t *testing.T) {
	s := spec(t, "true")
	args, err := s.EngineArgs("siegekit-test", 1000, 1000)
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(args, " ")
	for _, want := range []string{
		"--network none", "--cap-drop ALL", "--security-opt no-new-privileges", "--read-only",
		"--user 1000:1000", "--pids-limit 256", "--memory 128m", "--memory-swap 128m",
		",target=/target,readonly", "--rm",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing %q in %s", want, joined)
		}
	}
	for _, banned := range []string{"--privileged", "docker.sock", "--network host", "--cap-add", "--entrypoint"} {
		if strings.Contains(joined, banned) {
			t.Errorf("must not contain %q", banned)
		}
	}
	if args[len(args)-2] != testImage || args[len(args)-1] != "true" {
		t.Errorf("image and args must come last: %v", args[len(args)-2:])
	}
}

func TestEngineArgsData(t *testing.T) {
	s := spec(t, "scan")
	s.DataDir, s.DataMount = t.TempDir(), "/tmp/tool/db"
	args, err := s.EngineArgs("n", 1000, 1000)
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(args, " ")
	if !strings.Contains(joined, "target=/tmp/tool/db,readonly") || !strings.Contains(joined, "--network none") {
		t.Errorf("scan data must be read-only and offline: %s", joined)
	}

	u := spec(t, "update")
	u.TargetDir, u.Network = "", "egress"
	u.DataDir, u.DataMount, u.DataWritable = t.TempDir(), "/tmp/tool/db", true
	args, err = u.EngineArgs("n", 1000, 1000)
	if err != nil {
		t.Fatal(err)
	}
	joined = strings.Join(args, " ")
	if strings.Contains(joined, "--network") || strings.Contains(joined, "/tmp/tool/db,readonly") || strings.Contains(joined, "target=/target") {
		t.Errorf("update run: %s", joined)
	}
	u.TmpMiB = 64
	args, _ = u.EngineArgs("n", 1000, 1000)
	joined = strings.Join(args, " ")
	for _, want := range []string{"--cap-drop ALL", "--read-only", "--user 1000:1000", "target=/tmp/tool/db", "/tmp:rw,nosuid,nodev,size=64m"} {
		if !strings.Contains(joined, want) {
			t.Errorf("update run missing %q: %s", want, joined)
		}
	}
}

func TestEngineArgsNeverRoot(t *testing.T) {
	s := spec(t, "true")
	args, err := s.EngineArgs("n", 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	i := slices.Index(args, "--user")
	if i < 0 || args[i+1] != "65532:65532" {
		t.Fatalf("root caller must map to non-root user, got %v", args)
	}
}

func TestSpecRejections(t *testing.T) {
	cases := map[string]func(s *Spec){
		"unpinned image":   func(s *Spec) { s.Image = "alpine:3.20" },
		"network":          func(s *Spec) { s.Network = "target-only" },
		"no args":          func(s *Spec) { s.Args = nil },
		"relative target":  func(s *Spec) { s.TargetDir = "relative/dir" },
		"unclean target":   func(s *Spec) { s.TargetDir = s.TargetDir + "/../x" },
		"comma injection":  func(s *Spec) { s.TargetDir = s.TargetDir + ",readonly=false" },
		"missing out dir":  func(s *Spec) { s.OutDir = "" },
		"zero timeout":     func(s *Spec) { s.Timeout = 0 },
		"tmp above memory": func(s *Spec) { s.TmpMiB = s.MemoryMiB + 1 },
		"negative tmp":     func(s *Spec) { s.TmpMiB = -1 },
		"target not a dir": func(s *Spec) { s.TargetDir = filepath.Join(s.TargetDir, "app.txt") },
		"egress with target": func(s *Spec) {
			s.Network, s.DataDir, s.DataMount, s.DataWritable = "egress", s.OutDir, "/tmp/db", true
		},
		"egress without data": func(s *Spec) { s.TargetDir, s.Network = "", "egress" },
		"writable data with target": func(s *Spec) {
			s.DataDir, s.DataMount, s.DataWritable = s.OutDir, "/tmp/db", true
		},
		"data mount on target":   func(s *Spec) { s.DataDir, s.DataMount = s.OutDir, "/target" },
		"data mount traversal":   func(s *Spec) { s.DataDir, s.DataMount = s.OutDir, "/tmp/../etc" },
		"data mount in workdir":  func(s *Spec) { s.DataDir, s.DataMount = s.OutDir, "/tmp/work/x" },
		"data mount comma":       func(s *Spec) { s.DataDir, s.DataMount = s.OutDir, "/tmp/db,readonly=false" },
		"data dir without mount": func(s *Spec) { s.DataDir = s.OutDir },
		"data dir comma": func(s *Spec) {
			s.DataDir, s.DataMount = s.TargetDir+",readonly=false", "/tmp/db"
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			s := spec(t, "true")
			mutate(&s)
			if _, err := s.EngineArgs("n", 1000, 1000); err == nil {
				t.Fatal("expected rejection")
			}
		})
	}
	t.Run("non-empty out dir", func(t *testing.T) {
		s := spec(t, "true")
		os.WriteFile(filepath.Join(s.OutDir, "x"), nil, 0o644)
		if _, err := s.EngineArgs("n", 1000, 1000); err == nil {
			t.Fatal("expected rejection")
		}
	})
}

func TestRunRefusesSharedParent(t *testing.T) {
	shared := t.TempDir()
	if err := os.Chmod(shared, 0o755); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(shared, "out")
	if err := os.Mkdir(out, 0o700); err != nil {
		t.Fatal(err)
	}
	s := spec(t, "true")
	s.OutDir = out
	e := &Engine{Bin: "/bin/false"}
	if _, err := e.Run(context.Background(), s); err == nil || !strings.Contains(err.Error(), "accessible only by its owner") {
		t.Fatalf("expected refusal, got %v", err)
	}
}

func TestTailBuffer(t *testing.T) {
	var b tailBuffer
	b.Write([]byte(strings.Repeat("a", tailMax)))
	b.Write([]byte("END"))
	if s := b.String(); len(s) != tailMax || !strings.HasSuffix(s, "END") {
		t.Fatalf("len %d", len(s))
	}
}

// Container tests need a working engine. CI enables them on Linux with
// SIEGEKIT_CONTAINER_TESTS=1.
func engine(t *testing.T) *Engine {
	t.Helper()
	if os.Getenv("SIEGEKIT_CONTAINER_TESTS") != "1" {
		t.Skip("set SIEGEKIT_CONTAINER_TESTS=1 to run container tests")
	}
	e, err := Detect()
	if err != nil {
		t.Fatal(err)
	}
	// Runs never pull (ADR 0016), so the test image is pulled explicitly,
	// once: a pull asks the registry even when the image is present, and
	// registries rate-limit those requests.
	if ok, err := e.HasImage(context.Background(), testImage); err != nil {
		t.Fatal(err)
	} else if !ok {
		if err := e.Pull(context.Background(), testImage); err != nil {
			t.Fatal(err)
		}
	}
	return e
}

func TestHasImageAndPull(t *testing.T) {
	e := engine(t)
	ctx := context.Background()
	if ok, err := e.HasImage(ctx, testImage); !ok || err != nil {
		t.Fatalf("pulled image not found: %v %v", ok, err)
	}
	absent := "docker.io/library/alpine@sha256:" + strings.Repeat("0", 64)
	if ok, err := e.HasImage(ctx, absent); ok || err != nil {
		t.Errorf("absent image: %v %v", ok, err)
	}
	if err := e.Pull(ctx, absent); err == nil {
		t.Error("pulling a digest that does not exist succeeded")
	}
	for _, bad := range []string{"alpine:3.20", "docker.io/library/alpine:latest"} {
		if _, err := e.HasImage(ctx, bad); err == nil {
			t.Errorf("HasImage accepted unpinned %q", bad)
		}
		if err := e.Pull(ctx, bad); err == nil {
			t.Errorf("Pull accepted unpinned %q", bad)
		}
	}
}

func run(t *testing.T, e *Engine, s Spec) *Result {
	t.Helper()
	r, err := e.Run(context.Background(), s)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestContainerIsolation(t *testing.T) {
	e := engine(t)
	t.Setenv("SIEGEKIT_TEST_SECRET", "do-not-leak")
	script := `
set -u
echo "uid=$(id -u)"
grep CapEff /proc/self/status
cat /target/app.txt && echo " target-readable"
(echo x > /target/new.txt) 2>/dev/null && echo "TARGET-WRITABLE" || echo "target-readonly"
(echo x > /etc/x) 2>/dev/null && echo "ROOTFS-WRITABLE" || echo "rootfs-readonly"
echo result > /out/result.txt && echo "out-writable"
(wget -q -T 3 -O- http://1.1.1.1 >/dev/null 2>&1) && echo "NETWORK-OPEN" || echo "network-blocked"
env | grep -q SIEGEKIT_TEST_SECRET && echo "ENV-LEAKED" || echo "env-clean"
`
	s := spec(t, "sh", "-c", script)
	r := run(t, e, s)
	if r.Status != Completed || r.ExitCode != 0 {
		t.Fatalf("status %s exit %d: %s", r.Status, r.ExitCode, r.Stderr)
	}
	out := r.Stderr
	t.Logf("container output:\n%s", out)
	for _, want := range []string{"CapEff:\t0000000000000000", "hello target-readable", "target-readonly", "rootfs-readonly", "out-writable", "network-blocked", "env-clean"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in output:\n%s", want, out)
		}
	}
	if strings.Contains(out, "uid=0\n") {
		t.Errorf("tool ran as root:\n%s", out)
	}
	if b, err := os.ReadFile(filepath.Join(s.OutDir, "result.txt")); err != nil || string(b) != "result\n" {
		t.Errorf("output file: %q %v", b, err)
	}
	if _, err := os.Stat(filepath.Join(s.TargetDir, "new.txt")); err == nil {
		t.Error("tool wrote into the target directory")
	}
}

func TestContainerTimeoutKillsContainer(t *testing.T) {
	e := engine(t)
	s := spec(t, "sleep", "300")
	s.Timeout = 3 * time.Second
	start := time.Now()
	r := run(t, e, s)
	if r.Status != TimedOut {
		t.Fatalf("status %s, want timed-out", r.Status)
	}
	if time.Since(start) > 45*time.Second {
		t.Fatalf("timeout took %v", time.Since(start))
	}
	out, err := exec.Command(e.Bin, "ps", "--all", "--filter", "name=siegekit-", "--format", "{{.Names}}").Output()
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(out)) != "" {
		t.Fatalf("containers left behind: %s", out)
	}
}

func TestContainerOutputLimit(t *testing.T) {
	e := engine(t)
	s := spec(t, "sh", "-c", "head -c 2000000 /dev/zero > /out/big")
	s.OutputLimit = 1 << 20
	r := run(t, e, s)
	if r.Status != Failed || !strings.Contains(r.Stderr, "output exceeded") {
		t.Fatalf("status %s: %s", r.Status, r.Stderr)
	}
}

func TestContainerToolExitCodeIsNotEngineFailure(t *testing.T) {
	e := engine(t)
	r := run(t, e, spec(t, "sh", "-c", "exit 1"))
	if r.Status != Completed || r.ExitCode != 1 {
		t.Fatalf("got %s %d", r.Status, r.ExitCode)
	}
	r = run(t, e, spec(t, "/no/such/binary"))
	if r.Status != Failed {
		t.Fatalf("missing binary should be an engine failure, got %s %d", r.Status, r.ExitCode)
	}
}

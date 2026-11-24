package sandbox

import (
	"context"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
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
	for _, want := range []string{"--cap-drop ALL", "--read-only", "--user 1000:1000", "target=/tmp/tool/db", "/tmp:rw,nosuid,nodev,noexec,size=64m"} {
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
		"stdout path":      func(s *Spec) { s.StdoutFile = "../x.json" },
		"stdout dot file":  func(s *Spec) { s.StdoutFile = ".x" },
		"stderr path":      func(s *Spec) { s.StderrFile = "a/x.txt" },
		"stderr = stdout":  func(s *Spec) { s.StdoutFile, s.StderrFile = "x.txt", "x.txt" },
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
	// 299 marks this test's container: other packages' tests run containers
	// of the same image, with the same name prefix, at the same time.
	s := spec(t, "sleep", "299")
	s.Timeout = 3 * time.Second
	start := time.Now()
	r := run(t, e, s)
	if r.Status != TimedOut {
		t.Fatalf("status %s, want timed-out", r.Status)
	}
	if time.Since(start) > 45*time.Second {
		t.Fatalf("timeout took %v", time.Since(start))
	}
	out, err := exec.Command(e.Bin, "ps", "--all", "--no-trunc", "--filter", "name=siegekit-", "--filter", "ancestor="+testImage, "--format", "{{.Names}} {{.Command}}").Output()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), "sleep 299") {
		t.Fatalf("container left behind: %s", out)
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

func TestCappedWriter(t *testing.T) {
	var b strings.Builder
	c := &cappedWriter{w: &b, left: 5}
	for _, p := range []string{"abc", "defg", "hij"} {
		if n, err := c.Write([]byte(p)); n != len(p) || err != nil {
			t.Fatalf("write %q: %d %v", p, n, err)
		}
	}
	if b.String() != "abcde" {
		t.Fatalf("got %q", b.String())
	}
}

// TestContainerStdoutFile: the tool's standard output goes to its own file
// and not into Stderr, and counts against the output limit (ADR 0040).
func TestContainerStdoutFile(t *testing.T) {
	e := engine(t)
	s := spec(t, "sh", "-c", "echo out-line; echo err-line >&2")
	s.StdoutFile = "stdout.json"
	r := run(t, e, s)
	b, err := os.ReadFile(filepath.Join(s.OutDir, "stdout.json"))
	if err != nil || string(b) != "out-line\n" || r.Status != Completed {
		t.Fatalf("status %s, file %q %v", r.Status, b, err)
	}
	if strings.Contains(r.Stderr, "out-line") || !strings.Contains(r.Stderr, "err-line") {
		t.Fatalf("stderr %q", r.Stderr)
	}
	s = spec(t, "sh", "-c", "head -c 2000000 /dev/zero")
	s.StdoutFile, s.OutputLimit = "stdout.json", 1<<20
	if r = run(t, e, s); r.Status != Failed || !strings.Contains(r.Stderr, "output exceeded") {
		t.Fatalf("status %s: %s", r.Status, r.Stderr)
	}
}

// TestContainerStderrFile: the tool's standard error goes in full to its
// own file, Stderr keeps it too, and it counts against the output limit
// (ADR 0066).
func TestContainerStderrFile(t *testing.T) {
	e := engine(t)
	s := spec(t, "sh", "-c", "echo out-line; echo err-line >&2")
	s.StdoutFile, s.StderrFile = "stdout.json", "log.txt"
	r := run(t, e, s)
	b, err := os.ReadFile(filepath.Join(s.OutDir, "log.txt"))
	if err != nil || string(b) != "err-line\n" || r.Status != Completed || !strings.Contains(r.Stderr, "err-line") || strings.Contains(r.Stderr, "out-line") {
		t.Fatalf("status %s, file %q %v, stderr %q", r.Status, b, err, r.Stderr)
	}
	s = spec(t, "sh", "-c", "head -c 2000000 /dev/zero >&2")
	s.StderrFile, s.OutputLimit = "log.txt", 1<<20
	if r = run(t, e, s); r.Status != Failed || !strings.Contains(r.Stderr, "output exceeded") {
		t.Fatalf("status %s: %.200s", r.Status, r.Stderr)
	}
}

// TestContainerTimeoutStopsWrites: when a run times out, its container is
// stopped before Run returns, so nothing writes to its scratch folder any
// more and the folder can be deleted. The tool ignores SIGTERM, as a shell
// as PID 1 does (gosec's entrypoint is bash). On rootless Podman a timed-out
// gosec left a folder whose cleanup said "Directory not empty" (CI run
// 45340299829, 2026-11-24).
func TestContainerTimeoutStopsWrites(t *testing.T) {
	e := engine(t)
	s := spec(t, "sh", "-c", "i=0; while :; do mkdir -p "+ScratchMount+"/d/$i; i=$((i+1)); done")
	s.ScratchDir = t.TempDir()
	s.Timeout = 3 * time.Second
	// With rootless Podman the folders belong to a user of Podman's
	// namespace, which the test's own user cannot delete; a container
	// deletes them, as runner.removeScratch does. Registered after
	// t.TempDir, so it runs before the folder is removed.
	t.Cleanup(func() {
		c := spec(t, "rm", "-rf", ScratchMount+"/d")
		c.ScratchDir = s.ScratchDir
		if r, err := e.Run(context.Background(), c); err != nil || r.Status != Completed || r.ExitCode != 0 {
			t.Errorf("cleanup container: %v %+v", err, r)
		}
	})
	start := time.Now()
	r := run(t, e, s)
	if r.Status != TimedOut {
		t.Fatalf("status %s: %s", r.Status, r.Stderr)
	}
	returned := time.Since(start)
	count := func() int {
		entries, err := os.ReadDir(filepath.Join(s.ScratchDir, "d"))
		if err != nil {
			t.Fatal(err)
		}
		return len(entries)
	}
	n := count()
	time.Sleep(3 * time.Second)
	if m := count(); m != n || n == 0 {
		t.Fatalf("Run returned after %v, then the container wrote on: %d entries, %d three seconds later", returned, n, m)
	}
	t.Logf("Run returned after %v with %d entries written", returned, n)
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

func TestEngineArgsEnv(t *testing.T) {
	s := spec(t, "scan")
	s.Env = map[string]string{"B_VAR": "two words", "A_VAR": "line1\nline2"}
	args, err := s.EngineArgs("n", 1000, 1000)
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(args, "|")
	if !strings.Contains(joined, "--env|A_VAR=line1\nline2|--env|B_VAR=two words") {
		t.Errorf("env not passed in sorted order as separate arguments: %q", joined)
	}
	if args[len(args)-2] != testImage {
		t.Errorf("image must come after the environment: %v", args)
	}
	for _, bad := range []map[string]string{
		{"LD_PRELOAD": "/x.so"}, {"DYLD_INSERT_LIBRARIES": "x"}, {"HTTPS_PROXY": "http://x"}, {"no_proxy": "*"},
		{"PATH": "/x"}, {"HOME": "/"}, {"SSL_CERT_FILE": "/x"}, {"SIEGEKIT_X": "1"}, {"A=B": "c"}, {"": "x"},
		{"OK": "nul\x00"}, {"OK": strings.Repeat("x", 16<<10+1)},
		{"REQUESTS_CA_BUNDLE": "/x"}, {"CURL_CA_BUNDLE": "/x"}, {"NODE_EXTRA_CA_CERTS": "/x"},
	} {
		s.Env = bad
		if _, err := s.EngineArgs("n", 1000, 1000); err == nil {
			t.Errorf("accepted env %.40q", bad)
		}
	}
	many := map[string]string{}
	for i := range 17 {
		many[fmt.Sprintf("V%d", i)] = "x"
	}
	if CheckEnv(many) == nil {
		t.Error("accepted 17 variables")
	}
	// The same error on every run: Go ranges over a map in a different
	// order each time.
	for range 200 {
		if err := CheckEnv(map[string]string{"PATH": "x", "LD_PRELOAD": "y"}); err == nil || err.Error() != "environment variable LD_PRELOAD is not allowed" {
			t.Fatalf("CheckEnv: %v", err)
		}
	}
}

// target-only runs (ADR 0018, ADR 0019): only through a SiegeKit relay, on
// Linux, with the proxy and CA settings set by SiegeKit.
func TestTargetOnlySpec(t *testing.T) {
	old := goos
	t.Cleanup(func() { goos = old })
	goos = "linux"
	const relay = "siegekit-relay-0123456789abcdef"
	good := func(t *testing.T) Spec {
		s := spec(t, "true")
		s.Network, s.Relay = "target-only", relay
		s.CAFile = filepath.Join(t.TempDir(), "ca.pem")
		if err := os.WriteFile(s.CAFile, []byte("cert"), 0o644); err != nil {
			t.Fatal(err)
		}
		return s
	}
	s := good(t)
	args, err := s.EngineArgs("n", 1000, 1000)
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(args, "|")
	for _, want := range []string{
		"--network|container:" + relay,
		"--env|HTTP_PROXY=http://127.0.0.1:8080", "--env|HTTPS_PROXY=http://127.0.0.1:8080",
		"--env|http_proxy=http://127.0.0.1:8080", "--env|https_proxy=http://127.0.0.1:8080",
		"--env|NO_PROXY=", "--env|no_proxy=",
		"type=bind,source=" + s.CAFile + ",target=/siegekit/ca.pem,readonly",
		"--env|SSL_CERT_FILE=/siegekit/ca.pem", "--env|NODE_EXTRA_CA_CERTS=/siegekit/ca.pem",
		"--cap-drop|ALL", "--read-only",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing %q in %v", want, args)
		}
	}
	if strings.Contains(joined, "--network|none") || strings.Count(joined, "--network|") != 1 {
		t.Errorf("exactly one network flag expected: %v", args)
	}

	link := filepath.Join(t.TempDir(), "link.pem")
	if err := os.Symlink(s.CAFile, link); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(s *Spec){
		"not linux":          func(*Spec) { goos = "darwin" },
		"no relay":           func(s *Spec) { s.Relay = "" },
		"foreign container":  func(s *Spec) { s.Relay = "my-database" },
		"relay injection":    func(s *Spec) { s.Relay = relay + " --privileged" },
		"writable data":      func(s *Spec) { s.DataDir, s.DataMount, s.DataWritable = s.OutDir, "/tmp/db", true },
		"relative CA":        func(s *Spec) { s.CAFile = "ca.pem" },
		"CA comma":           func(s *Spec) { s.CAFile += ",readonly=false" },
		"CA symlink":         func(s *Spec) { s.CAFile = link },
		"CA missing":         func(s *Spec) { s.CAFile += ".missing" },
		"relay without mode": func(s *Spec) { s.Network = "none" },
		"CA without mode":    func(s *Spec) { s.Network, s.Relay = "none", "" },
	} {
		t.Run(name, func(t *testing.T) {
			goos = "linux"
			s := good(t)
			mutate(&s)
			if _, err := s.EngineArgs("n", 1000, 1000); err == nil {
				t.Error("accepted")
			}
		})
	}
	goos = "linux"
	s = good(t)
	s.CAFile = "" // an http target needs no CA
	if args, err := s.EngineArgs("n", 1000, 1000); err != nil || strings.Contains(strings.Join(args, " "), "ca.pem") {
		t.Errorf("http target: %v %v", args, err)
	}
}

func TestStartRelayRefusals(t *testing.T) {
	old := goos
	t.Cleanup(func() { goos = old })
	e := &Engine{Bin: "/nonexistent/docker"}
	bin, _ := os.Executable()
	goos = "darwin"
	if _, err := e.StartRelay(context.Background(), t.TempDir(), bin); err == nil || !strings.Contains(err.Error(), "only on Linux") {
		t.Errorf("macOS: %v", err)
	}
	goos = "linux"
	if _, err := e.StartRelay(context.Background(), t.TempDir()+",readonly=false", bin); err == nil {
		t.Error("accepted an injected mount path")
	}
	// Not an executable: refused before any container starts.
	notExe := filepath.Join(t.TempDir(), "x")
	if err := os.WriteFile(notExe, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := e.StartRelay(context.Background(), t.TempDir(), notExe); err == nil || !strings.Contains(err.Error(), "not a Linux executable") {
		t.Errorf("script accepted as relay: %v", err)
	}
}

// The relay runs SiegeKit's own binary in a minimal image, so the binary must
// be statically linked (ADR 0021).
func TestCheckStatic(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("ELF checks need a Linux build")
	}
	dir := t.TempDir()
	build := func(name, cgo string) string {
		t.Helper()
		out := filepath.Join(dir, name)
		cmd := exec.Command("go", "build", "-o", out, "../../cmd/siegekit")
		cmd.Env = append(os.Environ(), "CGO_ENABLED="+cgo)
		if b, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("go build (CGO_ENABLED=%s): %v\n%s", cgo, err, b)
		}
		return out
	}
	if err := CheckStatic(build("static", "0")); err != nil {
		t.Errorf("static build refused: %v", err)
	}
	if _, err := exec.LookPath("gcc"); err == nil {
		if err := CheckStatic(build("dynamic", "1")); err == nil || !strings.Contains(err.Error(), "CGO_ENABLED=0") {
			t.Errorf("dynamic build accepted: %v", err)
		}
	}
	if err := CheckStatic(filepath.Join(dir, "missing")); err == nil {
		t.Error("missing file accepted")
	}
}

func TestConfigFile(t *testing.T) {
	s := spec(t, "true")
	s.ConfigFile = filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(s.ConfigFile, []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	args, err := s.EngineArgs("n", 1000, 1000)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(args, "|"), "type=bind,source="+s.ConfigFile+",target=/siegekit/config.json,readonly") {
		t.Errorf("config mount missing: %v", args)
	}
	toml := s
	toml.ConfigFile = filepath.Join(t.TempDir(), "gitleaks-config.toml")
	if err := os.WriteFile(toml.ConfigFile, []byte("title = \"x\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	args, err = toml.EngineArgs("n", 1000, 1000)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(args, "|"), "type=bind,source="+toml.ConfigFile+",target=/siegekit/config.toml,readonly") {
		t.Errorf("TOML config mount missing: %v", args)
	}
	link := filepath.Join(t.TempDir(), "link.json")
	if err := os.Symlink(s.ConfigFile, link); err != nil {
		t.Fatal(err)
	}
	for name, p := range map[string]string{
		"relative":  "config.json",
		"unclean":   filepath.Dir(s.ConfigFile) + "/../x/config.json",
		"injection": s.ConfigFile + ",readonly=false",
		"symlink":   link,
		"missing":   filepath.Join(t.TempDir(), "none.json"),
		"directory": t.TempDir(),
	} {
		bad := s
		bad.ConfigFile = p
		if _, err := bad.EngineArgs("n", 1000, 1000); err == nil {
			t.Errorf("%s: config file %q accepted", name, p)
		}
	}
}

func TestCopyExecutable(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	if err := os.WriteFile(src, []byte("binary"), 0o600); err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(dir, "dst")
	if err := copyExecutable(src, dst); err != nil {
		t.Fatal(err)
	}
	if b, err := os.ReadFile(dst); err != nil || string(b) != "binary" {
		t.Errorf("copy: %q %v", b, err)
	}
	if st, err := os.Stat(dst); err != nil || st.Mode().Perm() != 0o755 {
		t.Errorf("mode: %v %v", st.Mode(), err)
	}
	// An existing destination is never overwritten.
	if err := copyExecutable(src, dst); err == nil {
		t.Error("overwrote an existing file")
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(src, link); err != nil {
		t.Fatal(err)
	}
	if err := copyExecutable(link, filepath.Join(dir, "d2")); err == nil {
		t.Error("followed a symlinked source")
	}
	if err := copyExecutable(dir, filepath.Join(dir, "d3")); err == nil {
		t.Error("copied a directory")
	}
	if err := copyExecutable(filepath.Join(dir, "missing"), filepath.Join(dir, "d4")); err == nil {
		t.Error("copied a missing file")
	}
}

// TestRelayStartStop starts the relay with a static SiegeKit build and
// checks that StopRelay removes it. The relay's traffic is tested in the
// runner's active tests.
func TestRelayStartStop(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the relay runs only on Linux")
	}
	e := engine(t)
	if ok, err := e.HasImage(context.Background(), RelayImage); err != nil {
		t.Fatal(err)
	} else if !ok {
		if err := e.Pull(context.Background(), RelayImage); err != nil {
			t.Fatal(err)
		}
	}
	bin := filepath.Join(t.TempDir(), "siegekit")
	build := exec.Command("go", "build", "-o", bin, "../../cmd/siegekit")
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o711); err != nil { // the relay's user must reach its binary
		t.Fatal(err)
	}
	name, err := e.StartRelay(context.Background(), dir, bin)
	if err != nil {
		t.Fatal(err)
	}
	running := func() string {
		out, err := exec.Command(e.Bin, "ps", "--all", "--filter", "name="+name, "--format", "{{.Names}}").Output()
		if err != nil {
			t.Fatal(err)
		}
		return strings.TrimSpace(string(out))
	}
	if running() != name {
		t.Fatalf("relay %s not running", name)
	}
	e.StopRelay("not-a-relay") // ignored
	if running() != name {
		t.Fatal("StopRelay acted on a name that is not a relay's")
	}
	e.StopRelay(name)
	if got := running(); got != "" {
		t.Errorf("relay left behind: %s", got)
	}
	// The relay directory holds a fresh copy for each run.
	if _, err := e.StartRelay(context.Background(), dir, bin); err == nil || !strings.Contains(err.Error(), "copy relay binary") {
		t.Errorf("second start in the same directory: %v", err)
	}
}

func TestFileMounts(t *testing.T) {
	s := spec(t, "true")
	a, b := t.TempDir(), t.TempDir()
	s.Files = []FileMount{{Host: a, Mount: "/siegekit/files/tool"}, {Host: b, Mount: "/siegekit/files/list"}}
	args, err := s.EngineArgs("n", 1000, 1000)
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(args, "|")
	for _, want := range []string{
		"type=bind,source=" + a + ",target=/siegekit/files/tool,readonly",
		"type=bind,source=" + b + ",target=/siegekit/files/list,readonly",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("mount %q missing: %v", want, args)
		}
	}
	for name, f := range map[string][]FileMount{
		"same mount":    {{Host: a, Mount: "/siegekit/files/x"}, {Host: b, Mount: "/siegekit/files/x"}},
		"outside files": {{Host: a, Mount: "/tmp/x"}},
		"files itself":  {{Host: a, Mount: "/siegekit/files"}},
		"nested":        {{Host: a, Mount: "/siegekit/files/x/y"}},
		"traversal":     {{Host: a, Mount: "/siegekit/files/.."}},
		"mount comma":   {{Host: a, Mount: "/siegekit/files/x,readonly=false"}},
		"host comma":    {{Host: a + ",readonly=false", Mount: "/siegekit/files/x"}},
		"host relative": {{Host: "files", Mount: "/siegekit/files/x"}},
		"host missing":  {{Host: filepath.Join(a, "none"), Mount: "/siegekit/files/x"}},
		"host unclean":  {{Host: a + "/../x", Mount: "/siegekit/files/x"}},
	} {
		bad := s
		bad.Files = f
		if _, err := bad.EngineArgs("n", 1000, 1000); err == nil {
			t.Errorf("%s: %+v accepted", name, f)
		}
	}
}

// TestContainerFileMount checks that a pinned file runs and reads in the
// container as its non-root user, and cannot be changed (ADR 0024). Fetch
// leaves the unpacked directory at mode 0755, as here.
func TestContainerFileMount(t *testing.T) {
	e := engine(t)
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "tool"), []byte("#!/bin/sh\necho tool-ran\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "words.txt"), []byte("admin\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	script := `
/siegekit/files/tool/tool
cat /siegekit/files/tool/words.txt
(echo x > /siegekit/files/tool/words.txt) 2>/dev/null && echo "FILE-WRITABLE" || echo "file-readonly"
(echo x > /siegekit/files/tool/new) 2>/dev/null && echo "DIR-WRITABLE" || echo "dir-readonly"
`
	s := spec(t, "sh", "-c", script)
	s.Files = []FileMount{{Host: dir, Mount: "/siegekit/files/tool"}}
	r := run(t, e, s)
	if r.Status != Completed || r.ExitCode != 0 {
		t.Fatalf("status %s exit %d: %s", r.Status, r.ExitCode, r.Stderr)
	}
	for _, want := range []string{"tool-ran", "admin", "file-readonly", "dir-readonly"} {
		if !strings.Contains(r.Stderr, want) {
			t.Errorf("missing %q in output:\n%s", want, r.Stderr)
		}
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "words.txt")); string(b) != "admin\n" {
		t.Errorf("file changed: %q", b)
	}
}

func TestParseInfo(t *testing.T) {
	for _, c := range []struct {
		engine, out string
		want        Info
	}{
		{"podman", "5.7.0\tv2\ttrue", Info{Engine: "podman", Version: "5.7.0", Rootless: true, Cgroup: "v2"}},
		{"podman", "4.9.3\tv1\tfalse", Info{Engine: "podman", Version: "4.9.3", Cgroup: "v1"}},
		{"docker", "29.10.0\t1\tname=seccomp,profile=builtin,", Info{Engine: "docker", Version: "29.10.0", Cgroup: "v1"}},
		{"docker", "29.4.2\t2\tname=seccomp,profile=builtin,name=rootless,name=cgroupns,", Info{Engine: "docker", Version: "29.4.2", Rootless: true, Cgroup: "v2"}},
		{"docker", "29.4.2\t\tname=rootlessish,", Info{Engine: "docker", Version: "29.4.2"}},
	} {
		got, err := parseInfo(c.engine, c.out)
		if err != nil || got != c.want {
			t.Errorf("parseInfo(%q, %q) = %+v, %v; want %+v", c.engine, c.out, got, err, c.want)
		}
	}
	for _, bad := range []string{"", "5.7.0", "5.7.0\tv2", "\tv2\ttrue", "5.7.0\tv2\ttrue\nx", strings.Repeat("9", 65) + "\tv2\ttrue"} {
		if _, err := parseInfo("podman", bad); err == nil {
			t.Errorf("parseInfo(%q) accepted", bad)
		}
	}
}

// TestDescribe checks Describe against the engine that runs the container
// tests. CI sets SIEGEKIT_EXPECT_ENGINE, so a change of engine on GitHub's
// runners fails here instead of going unnoticed (ADR 0038).
func TestDescribe(t *testing.T) {
	e := engine(t)
	i, err := e.Describe(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("engine: %+v", i)
	if i.Version == "" || (i.Engine != "docker" && i.Engine != "podman") || (runtime.GOOS == "linux" && i.Cgroup == "") {
		t.Errorf("Describe = %+v", i)
	}
	if want := os.Getenv("SIEGEKIT_EXPECT_ENGINE"); want != "" {
		got := i.Engine + " rootful"
		if i.Rootless {
			got = i.Engine + " rootless"
		}
		if got != want {
			t.Errorf("engine is %q, expected %q", got, want)
		}
	}
}

// TestSameSandboxOnEveryEngine checks what a tool may write and run, and
// that the answer does not depend on the engine (ADR 0039). Docker adds
// noexec to --tmpfs and Podman does not; with --read-only, Podman also
// mounts writable /run and /var/tmp. CI runs this on both engines.
func TestSameSandboxOnEveryEngine(t *testing.T) {
	e := engine(t)
	script := `
probe() { if (eval "$2") >/dev/null 2>&1; then echo "$1=yes"; else echo "$1=no"; fi; }
probe write-root 'echo x > /x'
probe write-etc 'echo x > /etc/x'
probe write-run 'echo x > /run/x'
probe write-var-tmp 'echo x > /var/tmp/x'
probe write-target 'echo x > /target/x'
probe write-out 'echo x > /out/x'
probe write-tmp 'echo x > /tmp/x'
probe exec-tmp 'cp /bin/busybox /tmp/bb && /tmp/bb true'
probe write-dev-shm 'echo x > /dev/shm/x'
probe exec-dev-shm 'cp /bin/busybox /dev/shm/bb && /dev/shm/bb true'
grep -E ' /(tmp|run|var/tmp|dev/shm) ' /proc/mounts | sed 's/^/mount: /'
`
	r := run(t, e, spec(t, "sh", "-c", script))
	if r.Status != Completed || r.ExitCode != 0 {
		t.Fatalf("status %s exit %d: %s", r.Status, r.ExitCode, r.Stderr)
	}
	t.Logf("container output (%s):\n%s", e.Bin, r.Stderr)
	want := []string{
		"write-root=no", "write-etc=no", "write-run=no", "write-var-tmp=no", "write-target=no",
		"write-out=yes", "write-tmp=yes", "exec-tmp=no", "write-dev-shm=yes", "exec-dev-shm=no",
	}
	for _, w := range want {
		if !strings.Contains(r.Stderr, w+"\n") {
			t.Errorf("want %s; container output:\n%s", w, r.Stderr)
		}
	}
}

func TestSameOnEveryEngineArgs(t *testing.T) {
	args := []string{"run", "--read-only", "--tmpfs", "/tmp:rw"}
	if got := (&Engine{}).sameOnEveryEngine(slices.Clone(args)); !slices.Equal(got, args) {
		t.Errorf("Docker args changed: %v", got)
	}
	got := (&Engine{Podman: true}).sameOnEveryEngine(slices.Clone(args))
	if want := []string{"run", "--read-only", "--read-only-tmpfs=false", "--tmpfs", "/tmp:rw"}; !slices.Equal(got, want) {
		t.Errorf("Podman args = %v, want %v", got, want)
	}
	s := spec(t, "true")
	a, err := s.EngineArgs("n", 1000, 1000)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.ContainsFunc(a, func(x string) bool { return strings.HasPrefix(x, "/tmp:") && strings.Contains(x, ",noexec,") }) {
		t.Errorf("/tmp is not mounted noexec: %v", a)
	}
}

func TestDetectEngineEnv(t *testing.T) {
	t.Setenv(EngineEnv, "lxc")
	if _, err := Detect(); err == nil || !strings.Contains(err.Error(), "must be") {
		t.Errorf("Detect with %s=lxc: %v", EngineEnv, err)
	}
	dir := t.TempDir()
	t.Setenv("PATH", dir)
	t.Setenv(EngineEnv, "podman")
	if _, err := Detect(); err == nil || !strings.Contains(err.Error(), "not installed") {
		t.Errorf("Detect with no podman: %v", err)
	}
	if runtime.GOOS == "windows" {
		return
	}
	// A "docker" on PATH that is really Podman is detected as Podman.
	fake := filepath.Join(dir, "docker")
	if err := os.WriteFile(fake, []byte("#!/bin/sh\necho 'podman version 5.7.0'\n"), 0o755); err != nil { // #nosec G306 -- a test script that must be executable
		t.Fatal(err)
	}
	t.Setenv(EngineEnv, "docker")
	e, err := Detect()
	if err != nil || e.Bin != fake || !e.Podman {
		t.Errorf("Detect = %+v, %v", e, err)
	}
}

func TestEgressSpec(t *testing.T) {
	ca := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(ca, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	s := Spec{
		Image: testImage, Args: []string{"mod", "download"}, OutDir: t.TempDir(), Network: "egress",
		DataDir: t.TempDir(), DataMount: "/data/gomod", DataWritable: true, InputDir: t.TempDir(), Entrypoint: "go",
		CPUs: 1, MemoryMiB: 128, Timeout: time.Minute,
		Egress: Egress{CAFile: ca, Proxy: "http://proxy.example:3128"},
	}
	args, err := s.EngineArgs("n", 1000, 1000)
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(args, " ")
	for _, want := range []string{
		"--env HTTPS_PROXY=http://proxy.example:3128", "--env HTTP_PROXY=http://proxy.example:3128",
		"--env https_proxy=http://proxy.example:3128", "--env http_proxy=http://proxy.example:3128",
		"source=" + ca + ",target=" + CAMount + ",readonly", "--env SSL_CERT_FILE=" + CAMount,
		",target=" + InputMount + ",readonly", "--entrypoint go " + testImage + " mod download",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing %q in %s", want, joined)
		}
	}
	if strings.Contains(joined, "--network") {
		t.Errorf("egress uses the engine's default network: %s", joined)
	}
}

func TestScratchSpec(t *testing.T) {
	s := spec(t, "scan")
	s.ScratchDir = t.TempDir()
	args, err := s.EngineArgs("n", 1000, 1000)
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(args, " ")
	if !strings.Contains(joined, "source="+s.ScratchDir+",target="+ScratchMount+" ") || strings.Contains(joined, ScratchMount+",readonly") {
		t.Errorf("scratch must be mounted read-write: %s", joined)
	}
}

func TestEgressRejections(t *testing.T) {
	ca := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(ca, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	cases := map[string]func(s *Spec){
		"proxy on a scan":      func(s *Spec) { s.Egress.Proxy = "http://p:1" },
		"CA file on a scan":    func(s *Spec) { s.Egress.CAFile = ca },
		"scratch with network": func(s *Spec) { s.TargetDir, s.Network, s.ScratchDir = "", "egress", s.OutDir },
		"entrypoint path":      func(s *Spec) { s.Entrypoint = "/bin/sh" },
		"entrypoint option":    func(s *Spec) { s.Entrypoint = "--privileged" },
		"input comma":          func(s *Spec) { s.InputDir = s.TargetDir + ",readonly=false" },
		"scratch not a dir":    func(s *Spec) { s.ScratchDir = filepath.Join(s.TargetDir, "app.txt") },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			s := spec(t, "true")
			s.DataDir, s.DataMount = t.TempDir(), "/data/gomod"
			mutate(&s)
			if s.Network == "egress" {
				s.DataWritable = true
			}
			if _, err := s.EngineArgs("n", 1000, 1000); err == nil {
				t.Fatal("expected rejection")
			}
		})
	}
	t.Run("egress CA file missing", func(t *testing.T) {
		s := Spec{Image: testImage, Args: []string{"x"}, OutDir: t.TempDir(), Network: "egress", DataDir: t.TempDir(), DataMount: "/data/x",
			DataWritable: true, CPUs: 1, MemoryMiB: 128, Timeout: time.Minute, Egress: Egress{CAFile: "/nonexistent/ca.pem"}}
		if _, err := s.EngineArgs("n", 1000, 1000); err == nil {
			t.Fatal("expected rejection")
		}
	})
}

func TestCheckProxy(t *testing.T) {
	for _, ok := range []string{"http://proxy:3128", "https://proxy.example.com:8443", "http://10.0.0.1:3128/", "http://host.docker.internal:3128", "http://[::1]:3128"} {
		if err := CheckProxy(ok); err != nil {
			t.Errorf("%s: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "proxy:3128", "socks5://p:1", "http://user:pw@p:1", "http://user@p:1", "http://p:1/path", "http://p:1?x=1", "http://p:1#f", "http://", "http://p:1\n"} {
		if err := CheckProxy(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	if err := CheckProxy("http://user:secret@p:1"); err == nil || strings.Contains(err.Error(), "secret") {
		t.Errorf("the error must not repeat the password: %v", err)
	}
}

func TestCheckEnvGoProxy(t *testing.T) {
	for _, v := range []string{"off", GoProxy} {
		if err := CheckEnv(map[string]string{"GOPROXY": v, "GONOPROXY": "corp.example"}); err != nil {
			t.Errorf("GOPROXY=%s: %v", v, err)
		}
	}
	for _, env := range []map[string]string{
		{"GOPROXY": "https://evil.example"}, {"GOPROXY": GoProxy + ",direct"}, {"HTTPS_PROXY": "http://p:1"}, {"ALL_PROXY": "x"}, {"NO_PROXY": "x"},
	} {
		if err := CheckEnv(env); err == nil {
			t.Errorf("%v accepted", env)
		}
	}
}

func TestTooManyPullsHint(t *testing.T) {
	// Engine output seen on 2026-11-24 in the development sandbox.
	hub := `Error response from daemon: unknown: failed to resolve reference "docker.io/library/registry:2": unexpected status from HEAD request to https://registry-1.docker.io/v2/library/registry/manifests/2: 429 Too Many Requests`
	if h := TooManyPullsHint("docker.io/aquasec/trivy@sha256:x", hub); !strings.Contains(h, "docker login") || !strings.Contains(h, "mirror.gcr.io") {
		t.Errorf("Docker Hub hint: %q", h)
	}
	if h := TooManyPullsHint("docker.io/x@sha256:x", "toomanyrequests: You have reached your unauthenticated pull rate limit."); h == "" {
		t.Error("toomanyrequests not recognised")
	}
	if h := TooManyPullsHint("ghcr.io/x@sha256:x", hub); h == "" || strings.Contains(h, "docker login") {
		t.Errorf("other registry: %q", h)
	}
	if h := TooManyPullsHint("docker.io/x@sha256:x", "manifest unknown"); h != "" {
		t.Errorf("unrelated error: %q", h)
	}
}

// TestEngineCommandsShareEnv: every engine command is built by
// Engine.command (or isPodman, before there is an Engine), so all get
// minimalEnv. When "rm" and "ps" alone saw the caller's XDG_DATA_HOME,
// rootless Podman looked for a timed-out container in another store and
// it kept running (measurement run 45347080293).
func TestEngineCommandsShareEnv(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "sandbox.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range f.Decls {
		fn, ok := d.(*ast.FuncDecl)
		if !ok || fn.Name.Name == "command" || fn.Name.Name == "isPodman" {
			continue
		}
		ast.Inspect(fn, func(n ast.Node) bool {
			if sel, ok := n.(*ast.SelectorExpr); ok {
				if x, ok := sel.X.(*ast.Ident); ok && x.Name == "exec" && strings.HasPrefix(sel.Sel.Name, "Command") {
					t.Errorf("%s: %s builds an engine command itself; use Engine.command", fset.Position(sel.Pos()), fn.Name.Name)
				}
			}
			return true
		})
	}
	for _, k := range []string{"XDG_DATA_HOME", "XDG_CONFIG_HOME", "CONTAINERS_REGISTRIES_CONF"} {
		t.Setenv(k, "/x")
		if !slices.Contains(minimalEnv(), k+"=/x") {
			t.Errorf("%s is not passed to the engine", k)
		}
	}
	t.Setenv("GITHUB_TOKEN", "secret")
	if slices.ContainsFunc(minimalEnv(), func(v string) bool { return strings.HasPrefix(v, "GITHUB_TOKEN=") }) {
		t.Error("the engine got an unrelated variable")
	}
}

package sandbox

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// The waiter's counters decide whether a run was cut short (ADR 0067). The
// cases are the ones measured for the design: a child killed for memory
// while the tool exits 0, and processes refused in the last moment.

func TestContainerWaiterCounters(t *testing.T) {
	e := engine(t)
	s := spec(t, "sh", "-c", "echo out > /out/r.txt; sleep 1")
	r := run(t, e, s)
	if r.Status != Completed || r.ExitCode != 0 || r.Stop != "" {
		t.Fatalf("status %s exit %d stop %q: %s", r.Status, r.ExitCode, r.Stop, r.Stderr)
	}
	u := r.Usage
	if u == nil || u.Samples == 0 || u.MemoryPeak <= 0 || u.ProcessesPeak <= 0 || len(u.Errors) > 0 {
		t.Fatalf("usage %+v", u)
	}
	if u.Cgroup != "v1" && u.Cgroup != "v2" {
		t.Errorf("cgroup %q", u.Cgroup)
	}
	t.Logf("usage: %+v", *u)
	if _, err := os.Lstat(filepath.Join(s.OutDir, StatusFile)); err == nil {
		t.Error("status file left in the output directory")
	}
	if b, err := os.ReadFile(filepath.Join(s.OutDir, "r.txt")); err != nil || string(b) != "out\n" {
		t.Errorf("tool output: %q %v", b, err)
	}
}

func TestContainerMemoryKillIsAStop(t *testing.T) {
	e := engine(t)
	// The child is killed; the tool goes on and exits 0, as the tools
	// measured for ADR 0067 did.
	s := spec(t, "sh", "-c", "echo partial > /out/r.txt; head -c 300m /dev/zero | tail > /dev/null; exit 0")
	s.MemoryMiB = 64
	s.TmpMiB = 16
	r := run(t, e, s)
	t.Logf("status %s exit %d stop %q usage %+v", r.Status, r.ExitCode, r.Stop, r.Usage)
	// Counters, or exit 137 when the waiter itself was killed (ADR 0067).
	switch r.Stop {
	case StopMemoryKill:
		if r.Usage == nil || r.Usage.MemoryKills < 1 {
			t.Fatalf("usage %+v", r.Usage)
		}
	case StopKilled:
		if r.ExitCode != 137 {
			t.Fatalf("killed with exit %d", r.ExitCode)
		}
	default:
		t.Fatalf("stop %q, want memory-kill or killed: %s", r.Stop, r.Stderr)
	}
	if r.Status != Failed || !strings.HasSuffix(strings.TrimSpace(r.Stderr), r.StopReason) {
		t.Errorf("status %s; the last line must be the reason: %q", r.Status, r.Stderr)
	}
	if b, err := os.ReadFile(filepath.Join(s.OutDir, "r.txt")); err != nil || string(b) != "partial\n" {
		t.Errorf("output written before the stop must be kept: %q %v", b, err)
	}
}

func TestContainerProcessLimitIsAStop(t *testing.T) {
	e := engine(t)
	s := spec(t, "sh", "-c", `for i in $(seq 1 40); do sleep 30 & done 2>/dev/null; exit 0`)
	s.PidsLimit = 20
	r := run(t, e, s)
	if r.Stop != StopProcessLimit || r.Status != Failed || r.Usage == nil || r.Usage.ProcessesRefused < 1 {
		t.Fatalf("status %s stop %q usage %+v: %s", r.Status, r.Stop, r.Usage, r.Stderr)
	}
	if !strings.Contains(r.StopReason, "limit of 20 processes") {
		t.Errorf("reason %q", r.StopReason)
	}
}

func TestContainerToolCannotReplaceCounters(t *testing.T) {
	e := engine(t)
	// The waiter creates the status file before the tool starts and
	// writes it after the tool exits, so a tool's own contents are replaced.
	s := spec(t, "sh", "-c", `echo '{"version":1,"exit":0,"memoryKills":0,"processesRefused":0,"memoryPeak":12345,"processesPeak":1,"samples":1}' > /out/`+StatusFile+`; sleep 1`)
	r := run(t, e, s)
	if r.Status != Completed || r.Stop != "" || r.Usage == nil || r.Usage.MemoryPeak == 12345 {
		t.Fatalf("status %s stop %q usage %+v: %s", r.Status, r.Stop, r.Usage, r.Stderr)
	}
}

func TestContainerSpecEntrypointUnderWaiter(t *testing.T) {
	e := engine(t)
	s := spec(t, "-c", "echo via-entrypoint $0")
	s.Entrypoint = "sh"
	r := run(t, e, s)
	if r.Status != Completed || r.Stop != "" || !strings.Contains(r.Stderr, "via-entrypoint sh") {
		t.Fatalf("status %s stop %q: %s", r.Status, r.Stop, r.Stderr)
	}
}

func TestWithWaiter(t *testing.T) {
	s := spec(t, "-x", "y")
	s.Entrypoint = "go"
	args, err := s.EngineArgs("n", 1000, 1000)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	got, err := withWaiter(args, s, []string{"/bin/tool", "sub"}, dir)
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(strings.Join(got, " "), "--entrypoint"); n != 1 {
		t.Fatalf("%d --entrypoint flags: %q", n, got)
	}
	i := slices.Index(got, s.Image)
	want := []string{s.Image, OutMount + "/" + StatusFile, "/bin/tool", "sub", "-x", "y"}
	if i < 0 || !slices.Equal(got[i:], want) {
		t.Fatalf("after the image: %q, want %q", got[i:], want)
	}
	if !slices.Contains(got[:i], "type=bind,source="+dir+",target="+WaiterMount+",readonly") || got[i-1] != WaiterMount+"/"+waiterFile || got[i-2] != "--entrypoint" {
		t.Fatalf("waiter mount or entrypoint missing: %q", got[:i])
	}
	// Engine options other than the entrypoint are kept in order.
	var before []string
	for j := 0; j < len(args)-len(s.Args)-1; j++ {
		if args[j] == "--entrypoint" {
			j++
			continue
		}
		before = append(before, args[j])
	}
	if !slices.Equal(got[:len(before)], before) {
		t.Fatalf("options changed:\n%q\n%q", got[:len(before)], before)
	}
	if _, err := withWaiter(args, s, nil, "relative"); err == nil {
		t.Error("want a refusal of a relative waiter directory")
	}
}

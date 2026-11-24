package runner

import (
	"context"
	"os"
	"slices"
	"testing"
	"time"

	"github.com/Gobbuwu/SiegeKit/internal/sandbox"
	"github.com/Gobbuwu/SiegeKit/plugins"
)

// TestContainerWaiterInEveryImage runs every pinned tool image's own
// entrypoint under the waiter, as SiegeKit's sandbox runs it, and requires
// the kernel's counters to be read in each (ADR 0067, Unverified: the
// counters inside the ZAP, Checkov, Schemathesis and ffuf images).
func TestContainerWaiterInEveryImage(t *testing.T) {
	if os.Getenv("SIEGEKIT_CONTAINER_TESTS") != "1" {
		t.Skip("set SIEGEKIT_CONTAINER_TESTS=1 to run container tests")
	}
	e, err := sandbox.Detect()
	if err != nil {
		t.Fatal(err)
	}
	all, err := plugins.Builtin()
	if err != nil {
		t.Fatal(err)
	}
	// Arguments that make each tool print its version and exit; the exit
	// code does not matter, the counters do.
	version := map[string][]string{
		"bandit": {"--version"}, "checkov": {"--version"}, "gitleaks": {"version"}, "gosec": {"-version"},
		"nuclei": {"-version"}, "schemathesis": {"--version"}, "trivy": {"--version"},
		"zap": {"zap.sh", "-version"}, "ffuf": {"sh", "-c", "echo alpine"},
	}
	var seen []string
	for _, m := range all {
		image, ok := ImageFor(m)
		if !ok || slices.Contains(seen, image) {
			continue
		}
		seen = append(seen, image)
		args, ok := version[m.ID]
		if !ok {
			t.Errorf("no version command for %s's image", m.ID)
			continue
		}
		t.Run(m.ID, func(t *testing.T) {
			ctx := context.Background()
			if has, err := e.HasImage(ctx, image); err != nil {
				t.Fatal(err)
			} else if !has {
				if err := e.Pull(ctx, image); err != nil {
					t.Fatal(err)
				}
			}
			r, err := e.Run(ctx, sandbox.Spec{
				Image: image, Args: args, OutDir: t.TempDir(), Network: "none",
				CPUs: 1, MemoryMiB: m.Resources.MemoryMiB, Timeout: 5 * time.Minute, TmpMiB: m.Resources.MemoryMiB / 2,
			})
			if err != nil {
				t.Fatal(err)
			}
			u := r.Usage
			t.Logf("exit %d, status %s, usage %+v, last output %q", r.ExitCode, r.Status, u, lastLine(r.Stderr))
			if u == nil || len(u.Errors) > 0 || u.Samples == 0 || r.Stop != "" {
				t.Fatalf("counters not read: stop %q usage %+v: %s", r.Stop, u, r.Stderr)
			}
		})
	}
}

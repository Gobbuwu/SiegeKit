package plugins

import (
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/Gobbuwu/SiegeKit/internal/sandbox"
)

func TestBuiltin(t *testing.T) {
	ms, err := Builtin()
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"bandit", "checkov", "gitleaks", "gitleaks-history", "gosec", "trivy", "zap", "zap-active"}
	if len(ms) != len(want) {
		t.Fatalf("got %d plugins, want %v", len(ms), want)
	}
	for i, m := range ms {
		if m.ID != want[i] {
			t.Errorf("plugin %d is %q, want %q", i, m.ID, want[i])
		}
		// Built-in plugins must be real pins, not test placeholders.
		for _, a := range m.Tool.Artifacts {
			if strings.Contains(a.SHA256, strings.Repeat("0", 16)) || strings.Contains(a.Ref, ".invalid") {
				t.Errorf("%s: placeholder artifact %s", m.ID, a.Ref)
			}
		}
		switch m.Mode {
		case "passive":
			if *m.Destructive || m.Network != "none" || !slices.Equal(m.Targets, []string{"repo"}) {
				t.Errorf("%s: passive built-ins must be non-destructive, offline and scan directories", m.ID)
			}
		case "active":
			// Only the plugins the owner placed in M2.4 (ADR 0023): the
			// attack scan never runs on deployed targets.
			if m.Network != "target-only" || !slices.Equal(m.Targets, []string{"url"}) || *m.Destructive != m.LocalOnly {
				t.Errorf("%s: active built-ins scan URLs through the egress proxy; destructive ones are local only", m.ID)
			}
			// ZAP must use the relay's port as its outbound proxy.
			if !slices.Contains(m.Run.Args, "network.connection.httpProxy.port="+strconv.Itoa(sandbox.RelayPort)) {
				t.Errorf("%s: outbound proxy port is not the relay's", m.ID)
			}
			// zap.sh sizes the Java heap from the host's memory on cgroup v2
			// hosts, not from the container limit, so the container is
			// killed (exit 137, seen in CI 2026-11-19). The heap must be
			// set and leave room for /tmp and the JVM's own memory.
			heap := 0
			for _, a := range m.Run.Args {
				if v, ok := strings.CutPrefix(a, "-Xmx"); ok {
					heap, _ = strconv.Atoi(strings.TrimSuffix(v, "m"))
				}
			}
			// ZAP's spider fills in and submits forms, POST forms included,
			// unless told not to (found by the security review of M2.4a,
			// reproduced 2026-11-19). A plugin that runs on deployed targets
			// must not submit forms.
			if !*m.Destructive {
				jobs, _ := m.Run.Config["jobs"].([]any)
				for _, j := range jobs {
					job, _ := j.(map[string]any)
					if job["type"] != "spider" {
						continue
					}
					p, _ := job["parameters"].(map[string]any)
					if p["processForm"] != false || p["postForm"] != false {
						t.Errorf("%s: a non-destructive spider must set processForm and postForm to false", m.ID)
					}
				}
			}
			if heap <= 0 || heap > m.Resources.MemoryMiB/2 {
				t.Errorf("%s: Java heap %d MiB must be set and at most half of %d MiB", m.ID, heap, m.Resources.MemoryMiB)
			}
		default:
			t.Errorf("%s: mode %s", m.ID, m.Mode)
		}
	}
}

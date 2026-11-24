package waiter

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseStatus(t *testing.T) {
	good := `{"version":1,"exit":0,"cgroup":"v2","memoryKills":1,"processesRefused":0,"memoryPeak":10,"processesPeak":3,"samples":2}`
	st, err := ParseStatus([]byte(good))
	if err != nil || st.MemoryKills != 1 || st.Cgroup != "v2" {
		t.Fatalf("%+v %v", st, err)
	}
	for name, bad := range map[string]string{
		"empty":         ``,
		"other version": `{"version":2,"exit":0}`,
		"unknown field": `{"version":1,"exit":0,"oomKilled":false}`,
		"negative":      `{"version":1,"exit":0,"memoryKills":-1}`,
		"exit range":    `{"version":1,"exit":300}`,
		"too large":     `{"version":1,"exit":0,"errors":["` + strings.Repeat("x", MaxStatusSize) + `"]}`,
		"two values":    good + good,
	} {
		if _, err := ParseStatus([]byte(bad)); err == nil {
			t.Errorf("%s: accepted %.80q", name, bad)
		}
	}
}

func TestStatValue(t *testing.T) {
	p := filepath.Join(t.TempDir(), "memory.events")
	if err := os.WriteFile(p, []byte("low 0\nhigh 0\nmax 4\noom 2\noom_kill 1\noom_group_kill 0\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if v, err := statValue(p, "oom_kill"); err != nil || v != 1 {
		t.Fatalf("oom_kill %d %v", v, err)
	}
	if _, err := statValue(p, "anon"); err == nil {
		t.Fatal("a missing key must be an error, never 0")
	}
}

// FuzzStatus feeds hostile status files to the parser: the tool can write
// the file, so it is untrusted (threat model T29).
func FuzzStatus(f *testing.F) {
	f.Add([]byte(`{"version":1,"exit":0,"cgroup":"v2","memoryKills":0,"processesRefused":0,"memoryPeak":1,"processesPeak":1,"samples":1}`))
	f.Add([]byte(`{"version":1,"exit":137,"errors":["pids.events: open: no such file"]}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		st, err := ParseStatus(b)
		if err == nil && (st.Version != StatusVersion || st.Exit < 0 || st.Exit > 255 || st.MemoryKills < 0 || len(st.Errors) > 32) {
			t.Fatalf("accepted out-of-range status %+v", st)
		}
	})
}

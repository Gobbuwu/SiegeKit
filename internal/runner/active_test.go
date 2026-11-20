package runner

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Gobbuwu/SiegeKit/internal/egress"
	"github.com/Gobbuwu/SiegeKit/internal/files"
	"github.com/Gobbuwu/SiegeKit/internal/manifest"
	"github.com/Gobbuwu/SiegeKit/internal/report"
	"github.com/Gobbuwu/SiegeKit/internal/sandbox"
	"github.com/Gobbuwu/SiegeKit/internal/target"
)

// activeTestImage is a pinned Alpine with busybox wget and nslookup.
const activeTestImage = "docker.io/library/alpine@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc"

var (
	relayBinOnce sync.Once
	relayBinPath string
	relayBinErr  error
)

// relayBin builds a static SiegeKit binary for the relay (ADR 0021): the
// test binary itself has no relay command and may be dynamically linked.
func relayBin(t *testing.T) string {
	t.Helper()
	relayBinOnce.Do(func() {
		dir, err := os.MkdirTemp("", "siegekit-relay-bin-")
		if err != nil {
			relayBinErr = err
			return
		}
		relayBinPath = filepath.Join(dir, "siegekit")
		cmd := exec.Command("go", "build", "-o", relayBinPath, "../../cmd/siegekit")
		cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
		if out, err := cmd.CombinedOutput(); err != nil {
			relayBinErr = fmt.Errorf("build relay binary: %v\n%s", err, out)
		}
	})
	if relayBinErr != nil {
		t.Fatal(relayBinErr)
	}
	return relayBinPath
}

func activeSetup(t *testing.T, status int) (*sandbox.Engine, egress.Config, *atomic.Int32, int) {
	t.Helper()
	if os.Getenv("SIEGEKIT_CONTAINER_TESTS") != "1" {
		t.Skip("set SIEGEKIT_CONTAINER_TESTS=1 to run container tests")
	}
	e, err := sandbox.Detect()
	if err != nil {
		t.Fatal(err)
	}
	for _, img := range []string{activeTestImage, sandbox.RelayImage} {
		if has, err := e.HasImage(context.Background(), img); err != nil {
			t.Fatal(err)
		} else if !has {
			if err := e.Pull(context.Background(), img); err != nil {
				t.Fatal(err)
			}
		}
	}
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(status)
		fmt.Fprint(w, "hello-from-target")
	}))
	t.Cleanup(srv.Close)
	su, _ := url.Parse(srv.URL)
	port, _ := strconv.Atoi(su.Port())
	tu, err := target.Parse(fmt.Sprintf("http://app.test:%d/", port))
	if err != nil {
		t.Fatal(err)
	}
	cfg := egress.Config{
		Target: tu, Addrs: []netip.Addr{netip.MustParseAddr("127.0.0.1")},
		Rate: 100, Burst: 10, MaxConns: 8, MaxServerErrors: 3, Version: "test",
	}
	return e, cfg, &hits, port
}

func activeSpec(t *testing.T, script string) sandbox.Spec {
	t.Helper()
	work := t.TempDir()
	if err := os.Chmod(work, 0o700); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(work, "out")
	if err := os.Mkdir(out, 0o755); err != nil {
		t.Fatal(err)
	}
	return sandbox.Spec{Image: activeTestImage, Args: []string{"sh", "-c", script}, OutDir: out, CPUs: 1, MemoryMiB: 128, Timeout: 90 * time.Second}
}

func noRelaysLeft(t *testing.T, e *sandbox.Engine) {
	t.Helper()
	out, err := exec.Command(e.Bin, "ps", "-a", "--filter", "name=siegekit-relay-", "--format", "{{.Names}}").CombinedOutput()
	if err != nil || strings.TrimSpace(string(out)) != "" {
		t.Errorf("relay containers left behind: %q %v", out, err)
	}
}

// TestActiveRunOnlyReachesTarget runs a container behind the relay and the
// egress proxy and tries every other way out (ADR 0019).
func TestActiveRunOnlyReachesTarget(t *testing.T) {
	e, cfg, hits, port := activeSetup(t, http.StatusOK)
	script := fmt.Sprintf(`
echo "allowed=$(wget -qO- http://app.test:%[1]d/ok 2>&1)"
echo "other=$(wget -qO- http://other.test:%[1]d/ 2>&1)"
echo "metadata=$(wget -qO- http://169.254.169.254/latest/meta-data/ 2>&1)"
echo "direct=$(env -u http_proxy -u HTTP_PROXY wget -T 3 -qO- http://1.1.1.1/ 2>&1)"
echo "gateway=$(env -u http_proxy -u HTTP_PROXY wget -T 3 -qO- http://172.17.0.1/ 2>&1)"
echo "dns=$(nslookup example.com 2>&1 | tr '\n' ' ')"
echo "routes=$(ip route | wc -l)"
echo "interfaces=$(ip -o addr | grep -v ' lo ' | wc -l)"
`, port)
	res, err := RunTargetOnly(context.Background(), e, activeSpec(t, script), cfg, t.TempDir(), relayBin(t))
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, line := range strings.Split(res.Stderr, "\n") {
		if k, v, ok := strings.Cut(line, "="); ok {
			got[k] = v
		}
	}
	t.Logf("%v", got)
	for k, want := range map[string]string{
		"allowed": "hello-from-target", "other": "403", "metadata": "403",
		"direct": "unreachable", "gateway": "unreachable", "routes": "0", "interfaces": "0",
	} {
		if !strings.Contains(got[k], want) {
			t.Errorf("%s: %q, want %q", k, got[k], want)
		}
	}
	if strings.Contains(got["dns"], "Address: ") && !strings.Contains(got["dns"], "unreachable") {
		t.Errorf("DNS resolved: %q", got["dns"])
	}
	if hits.Load() != 1 || res.Stats.Requests != 1 || res.Stats.Refused < 2 {
		t.Errorf("target hits %d, stats %+v", hits.Load(), res.Stats)
	}
	noRelaysLeft(t, e)
}

// TestActiveRunStopsOnServerErrors checks that the run ends early when the
// target keeps failing (ADR 0005 item 3).
func TestActiveRunStopsOnServerErrors(t *testing.T) {
	e, cfg, hits, port := activeSetup(t, http.StatusInternalServerError)
	script := fmt.Sprintf(`for i in 1 2 3 4 5 6 7 8 9 10; do wget -qO- http://app.test:%d/ >/dev/null 2>&1; done; sleep 80`, port)
	start := time.Now()
	res, err := RunTargetOnly(context.Background(), e, activeSpec(t, script), cfg, t.TempDir(), relayBin(t))
	if err != nil {
		t.Fatal(err)
	}
	if res.Stopped == "" || !strings.Contains(res.Stopped, "3 server errors in a row") {
		t.Errorf("not stopped: %+v", res)
	}
	if d := time.Since(start); d > 60*time.Second {
		t.Errorf("run took %v; the stop did not end it", d)
	}
	if hits.Load() != 3 {
		t.Errorf("target received %d requests, want 3", hits.Load())
	}
	noRelaysLeft(t, e)
}

// TestZAPFindsPlantedIssues runs the zap and zap-active plugins with the
// pinned ZAP image against SiegeKit's vulnerable test app, behind the relay
// and the egress proxy, and checks that every planted issue is found (M2.4).
func TestZAPFindsPlantedIssues(t *testing.T) {
	findsPlanted(t, "", "zap", "zap-active")
}

// TestNucleiFindsPlantedIssues runs nuclei and nuclei-intrusive with the
// pinned image and templates (downloaded and checked as in ADR 0024) against
// the vulnerable test app (M2.5b). SIEGEKIT_TEST_FILES_ROOT names a
// directory that already holds the pinned files, for machines that cannot
// download them.
func TestNucleiFindsPlantedIssues(t *testing.T) {
	if os.Getenv("SIEGEKIT_CONTAINER_TESTS") != "1" {
		t.Skip("set SIEGEKIT_CONTAINER_TESTS=1 to run container tests")
	}
	ms := []*manifest.Manifest{builtin(t, "nuclei"), builtin(t, "nuclei-intrusive")}
	root := os.Getenv("SIEGEKIT_TEST_FILES_ROOT")
	if root == "" {
		root = t.TempDir()
	}
	for _, m := range ms {
		for _, a := range FilesFor(m) {
			if !files.Installed(root, a) {
				if err := files.Fetch(context.Background(), files.Client(), root, a); err != nil {
					t.Fatal(err)
				}
			}
		}
	}
	findsPlanted(t, root, "nuclei", "nuclei-intrusive")
}

// findsPlanted runs the plugins ids against the vulnerable test app behind
// the relay and the egress proxy, and checks that each planted issue listed
// for them in vulnAppIssues is found.
func findsPlanted(t *testing.T, filesRoot string, ids ...string) {
	t.Helper()
	e, cfg, _, _ := activeSetup(t, http.StatusOK)
	// Requests for the planted files are counted, so a miss shows whether
	// the tool asked for them at all.
	var mu sync.Mutex
	asked := map[string]int{}
	app := vulnApp()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if p := r.URL.Path; p == "/.env" || p == "/.git/config" {
			mu.Lock()
			asked[r.Method+" "+p]++
			mu.Unlock()
		}
		app.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)
	su, _ := url.Parse(srv.URL)
	tu, err := target.Parse("http://app.test:" + su.Port() + "/")
	if err != nil {
		t.Fatal(err)
	}
	var ms []*manifest.Manifest
	for _, id := range ids {
		ms = append(ms, builtin(t, id))
	}
	for _, m := range ms {
		img, _ := ImageFor(m)
		if has, err := e.HasImage(context.Background(), img); err != nil {
			t.Fatal(err)
		} else if !has {
			if err := e.Pull(context.Background(), img); err != nil {
				t.Fatal(err)
			}
		}
	}
	bin := relayBin(t)
	var logs []string // tool output, in the order the plugins ran
	run := func(ctx context.Context, s sandbox.Spec, c egress.Config) (*ActiveResult, error) {
		res, err := RunTargetOnly(ctx, e, s, c, t.TempDir(), bin)
		if res != nil && res.Result != nil {
			logs = append(logs, res.Stderr)
		}
		return res, err
	}
	r, err := RunURL(context.Background(), run, ms, URLOptions{
		Version: "test", Target: tu, Addrs: cfg.Addrs, Limits: LocalLimits, FilesRoot: filesRoot,
	})
	if err != nil {
		t.Fatal(err)
	}
	found := map[string]map[string]bool{}
	for _, f := range r.Findings {
		for _, s := range f.Sources {
			if found[s.Plugin] == nil {
				found[s.Plugin] = map[string]bool{}
			}
			found[s.Plugin][s.RuleID] = true
		}
	}
	for i, p := range r.Plugins {
		t.Logf("%s: %s %q, %d findings, %d requests, %d refused, rules %v", p.ID, p.Status, p.Reason, p.Findings, p.Requests, p.Refused, found[p.ID])
		if p.Status != report.Ran || p.Requests == 0 {
			t.Errorf("%s did not run: %+v", p.ID, p)
		}
		for rule, issue := range vulnAppIssues[p.ID] {
			if !found[p.ID][rule] {
				t.Errorf("%s missed %s (rule %s); planted files asked for: %v", p.ID, issue, rule, asked)
				if len(logs) == len(r.Plugins) {
					t.Logf("%s output, warnings and errors:\n%s", p.ID, warnings(logs[i]))
				}
			}
		}
	}
	for _, f := range r.Findings {
		// The target, with or without the trailing slash (Nuclei is given
		// it without, ADR 0026).
		base := "http://app.test:" + su.Port()
		if f.Location.URI != base && !strings.HasPrefix(f.Location.URI, base+"/") {
			t.Errorf("finding outside the target: %s %+v: %s", f.RuleID, f.Location, f.Message)
		}
	}
	noRelaysLeft(t, e)
}

// warnings returns the last 40 lines of a tool's output that report a
// warning or an error.
func warnings(log string) string {
	var out []string
	for _, l := range strings.Split(log, "\n") {
		if strings.Contains(l, "WRN") || strings.Contains(l, "ERR") || strings.Contains(l, "rror") {
			out = append(out, l)
		}
	}
	return strings.Join(out[max(0, len(out)-40):], "\n")
}

package plugins

import (
	"io/fs"
	"slices"
	"strconv"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/Gobbuwu/SiegeKit/internal/manifest"
	"github.com/Gobbuwu/SiegeKit/internal/runner"
	"github.com/Gobbuwu/SiegeKit/internal/sandbox"
)

func TestBuiltin(t *testing.T) {
	ms, err := Builtin()
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"bandit", "checkov", "ffuf", "gitleaks", "gitleaks-history", "gosec", "nuclei", "nuclei-default-login", "nuclei-intrusive", "schemathesis", "trivy", "zap", "zap-active"}
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
			// Attack scans never run on deployed targets (ADR 0023, 0025).
			if m.Network != "target-only" || !slices.Equal(m.Targets, []string{"url"}) || *m.Destructive != m.LocalOnly {
				t.Errorf("%s: active built-ins scan URLs through the egress proxy; destructive ones are local only", m.ID)
			}
			switch m.Tool.Name {
			case "zap":
				checkZAP(t, m)
			case "nuclei":
				checkNuclei(t, m)
			case "ffuf":
				checkFFUF(t, m)
			case "schemathesis":
				checkSchemathesis(t, m)
			default:
				t.Errorf("%s: no rules for active tool %s", m.ID, m.Tool.Name)
			}
		default:
			t.Errorf("%s: mode %s", m.ID, m.Mode)
		}
	}
}

// checkNuclei holds the owner's M2.5 decisions (ADR 0025): pinned
// templates only, no update checks, no out-of-band callbacks, the relay as
// proxy, and on non-destructive plugins no intrusive, denial-of-service,
// fuzzing, brute-force or default-login templates. Default-login templates
// run only in nuclei-default-login: destructive, so local only, never
// retried, so each credential is sent once (ADR 0010, ADR 0031).
func checkNuclei(t *testing.T, m *manifest.Manifest) {
	t.Helper()
	args := strings.Join(m.Run.Args, " ")
	for _, want := range []string{"-duc", "-ni", "-pt http", "-t /siegekit/files/nuclei-templates/", "-proxy http://127.0.0.1:" + strconv.Itoa(sandbox.RelayPort), "-rl {ratelimit}"} {
		if !strings.Contains(args, want) {
			t.Errorf("%s: args lack %q", m.ID, want)
		}
	}
	excluded := ""
	for i, a := range m.Run.Args {
		if a == "-etags" && i+1 < len(m.Run.Args) {
			excluded = m.Run.Args[i+1]
		}
	}
	tags := strings.Split(excluded, ",")
	mustExclude := []string{"dos", "fuzz", "dast", "local", "bruteforce", "txt-service", "default-login"}
	if m.ID == "nuclei-default-login" {
		mustExclude = mustExclude[:6]
		if !*m.Destructive || !strings.Contains(args, "-tags default-login") || !strings.Contains(args, "-retries 0") || slices.Contains(tags, "default-login") {
			t.Errorf("%s: must be destructive and run only default-login templates, without retries", m.ID)
		}
		// The one fuzz-tagged template added back (owner decision
		// 2026-11-20); password-list guessing stays out (ADR 0010).
		if !strings.Contains(args, "-it /siegekit/files/nuclei-templates/nuclei-templates-10.5.2/http/default-logins/oracle/peoplesoft-default-login.yaml ") || strings.Contains(args, "wordpress-weak-credentials") || strings.Count(args, " -it ") != 1 {
			t.Errorf("%s: must add back only the PeopleSoft template", m.ID)
		}
	}
	for _, tag := range mustExclude {
		if !slices.Contains(tags, tag) {
			t.Errorf("%s: does not exclude %s templates", m.ID, tag)
		}
	}
	if !*m.Destructive && !slices.Contains(tags, "intrusive") {
		t.Errorf("%s: a non-destructive Nuclei plugin must exclude intrusive templates", m.ID)
	}
}

// checkFFUF holds the owner's M2.5 decisions (ADR 0025, 0027): the shipped
// SecLists list on local targets and SiegeKit's short list on deployed
// ones, through the relay, at SiegeKit's rate, with auto-calibration so an
// app that answers every path does not flood the report.
func checkFFUF(t *testing.T, m *manifest.Manifest) {
	t.Helper()
	args := strings.Join(m.Run.Args, " ")
	for _, want := range []string{"-w {wordlist}", "-x http://127.0.0.1:" + strconv.Itoa(sandbox.RelayPort), "-rate {ratelimit}", "-ac", "-noninteractive", "-of json", "-u {target-base}/FUZZ"} {
		if !strings.Contains(args, want) {
			t.Errorf("%s: args lack %q", m.ID, want)
		}
	}
	if w := m.Run.Wordlist; w == nil || w.Local != "seclists-common.txt" || w.Deployed != "deployed.txt" {
		t.Errorf("%s: wordlist %+v", m.ID, w)
	}
	if img, _ := runner.ImageFor(m); img != sandbox.RelayImage {
		t.Errorf("%s: runs in %s, not the pinned Alpine image", m.ID, img)
	}
}

// checkSchemathesis holds ADR 0025 item 4 and ADR 0028: local targets
// only, the spec SiegeKit found or was given, the target's origin (so the
// spec's base path applies), the relay as proxy, the rate limit, no
// shrinking and no --max-time, and exit code 1 (failures found) read as a
// result.
func checkSchemathesis(t *testing.T, m *manifest.Manifest) {
	t.Helper()
	args := strings.Join(m.Run.Args, " ")
	for _, want := range []string{"run {openapi} ", "--origin {target-origin}", "--proxy http://127.0.0.1:" + strconv.Itoa(sandbox.RelayPort), "--rate-limit {ratelimit}/s", "--report json", "--report-json-path {outdir}/" + m.Output.File} {
		if !strings.Contains(args, want) {
			t.Errorf("%s: args lack %q", m.ID, want)
		}
	}
	if !m.LocalOnly || !*m.Destructive || !slices.Equal(m.Run.FindingsExitCodes, []int{1}) || m.Run.Env["SCHEMATHESIS_COVERAGE"] != "false" {
		t.Errorf("%s: must be local only and destructive, read exit code 1 as findings and write no coverage report", m.ID)
	}
	// With --max-time, Schemathesis 4.33.4 sent one failing request again
	// until the time ran out: 6,173 times in 40 seconds, against 6
	// requests in all without it (measured 2026-11-20, ADR 0028). Shrinking
	// also repeats failing requests, and SiegeKit reports no examples.
	if slices.Contains(m.Run.Args, "--max-time") || !slices.Contains(m.Run.Args, "--no-shrink") {
		t.Errorf("%s: must use --no-shrink and not --max-time", m.ID)
	}
}

func checkZAP(t *testing.T, m *manifest.Manifest) {
	t.Helper()
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
}

func TestLoadRefusesBrokenManifests(t *testing.T) {
	good, err := files.ReadFile("gitleaks/plugin.json")
	if err != nil {
		t.Fatal(err)
	}
	for name, tc := range map[string]struct {
		fsys fstest.MapFS
		want string
	}{
		"invalid":         {fstest.MapFS{"x/plugin.json": {Data: []byte(`{}`)}}, "x/plugin.json"},
		"wrong directory": {fstest.MapFS{"other/plugin.json": {Data: good}}, `does not match directory "other"`},
		"unreadable":      {fstest.MapFS{"gitleaks/plugin.json": {Mode: fs.ModeDir}}, "gitleaks/plugin.json"},
	} {
		if _, err := load(tc.fsys); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: got %v, want %q", name, err, tc.want)
		}
	}
	ms, err := load(fstest.MapFS{"gitleaks/plugin.json": {Data: good}})
	if err != nil || len(ms) != 1 || ms[0].ID != "gitleaks" {
		t.Errorf("good manifest: %v %v", ms, err)
	}
}

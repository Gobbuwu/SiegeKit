package runner

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/Gobbuwu/SiegeKit/internal/egress"
	"github.com/Gobbuwu/SiegeKit/internal/findings"
	"github.com/Gobbuwu/SiegeKit/internal/manifest"
	"github.com/Gobbuwu/SiegeKit/internal/openapi"
	"github.com/Gobbuwu/SiegeKit/internal/report"
	"github.com/Gobbuwu/SiegeKit/internal/sandbox"
	"github.com/Gobbuwu/SiegeKit/internal/target"
	"github.com/Gobbuwu/SiegeKit/internal/wordlists"
)

// Limits are the egress proxy's limits for one active run (ADR 0005, 0018).
type Limits struct {
	Rate            float64 // requests per second
	Burst           int
	MaxConns        int
	MaxServerErrors int // consecutive 5xx or unreachable answers before the run stops
}

// Provisional limits until M2.10 measures them (ADR 0023). Deployed targets
// get a low rate and stop early; local targets are the user's own copy.
var (
	LocalLimits    = Limits{Rate: 100, Burst: 20, MaxConns: 16, MaxServerErrors: 100}
	DeployedLimits = Limits{Rate: 10, Burst: 5, MaxConns: 8, MaxServerErrors: 10}
)

// ActiveRunner runs one target-only spec behind an egress proxy configured
// by cfg. Production uses RunTargetOnly; tests replace it.
type ActiveRunner func(ctx context.Context, s sandbox.Spec, cfg egress.Config) (*ActiveResult, error)

// URLOptions describe one active run against a URL target.
type URLOptions struct {
	Version  string
	Target   *target.URL
	Addrs    []netip.Addr // pinned under ADR 0005
	Deployed bool
	Limits   Limits
	WorkDir  string // parent for the private temporary directory; "" means the OS default
	// FilesRoot is where pinned files are kept (ADR 0024).
	FilesRoot string
	// Environment names the machine and engine for the report (ADR 0038).
	Environment *report.Environment
	// Unavailable records plugins that cannot run because a dependency is
	// missing (ADR 0016), keyed by plugin ID.
	Unavailable map[string]Unavailable
	// OpenAPI is the spec for plugins that use {openapi}. When it is nil
	// they are skipped, with NoOpenAPI as the reason (ADR 0028).
	OpenAPI   *openapi.Spec
	NoOpenAPI string
}

// RunURL runs each selected active plugin against the target in turn, each
// behind its own egress proxy and relay (ADR 0019, ADR 0023). A plugin that
// fails is recorded and the run continues. Only setup problems return an
// error.
func RunURL(ctx context.Context, run ActiveRunner, selected []*manifest.Manifest, opt URLOptions) (*report.Run, error) {
	if opt.Target == nil || len(opt.Addrs) == 0 {
		return nil, errors.New("target and pinned addresses are required")
	}
	work, err := os.MkdirTemp(opt.WorkDir, "siegekit-run-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(work)
	mode := "local"
	if opt.Deployed {
		mode = "deployed"
	}
	out := &report.Run{SiegeKitVersion: opt.Version, Target: opt.Target.String(), Mode: mode, Started: time.Now().UTC(), Environment: opt.Environment}
	var all []findings.Finding
	for _, m := range selected {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if u, ok := opt.Unavailable[m.ID]; ok {
			out.Plugins = append(out.Plugins, u.Result(m))
			continue
		}
		pr, fs := runActive(ctx, run, m, opt, work)
		out.Plugins = append(out.Plugins, pr)
		all = append(all, fs...)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	out.Findings = findings.Dedupe(all)
	if out.Findings == nil {
		out.Findings = []findings.Finding{}
	}
	out.Finished = time.Now().UTC()
	return out, nil
}

// SkipReason says why m does not run against a target in this mode, or "".
func SkipReason(m *manifest.Manifest, deployed bool) string {
	switch {
	case m.Mode != "active" || m.Network != "target-only":
		return "only active plugins scan URLs"
	case deployed && m.LocalOnly:
		return "runs only on local targets: deployed targets get passive checks until request limits are measured (M2.10)"
	case deployed && *m.Destructive:
		return "can change data on the target, so it does not run on deployed targets (no opt-in before request limits are measured in M2.10)"
	}
	return ""
}

// SkipCause is the cause of a non-empty SkipReason.
func SkipCause(m *manifest.Manifest) report.Cause {
	if m.Mode != "active" || m.Network != "target-only" {
		return report.CauseUnsupported
	}
	return report.CauseTargetMode
}

func runActive(ctx context.Context, run ActiveRunner, m *manifest.Manifest, opt URLOptions, work string) (report.PluginResult, []findings.Finding) {
	pr := report.PluginResult{ID: m.ID, Family: m.Family, Tool: m.Tool.Name, Version: m.Tool.Version}
	fail := func(status report.Status, format string, a ...any) (report.PluginResult, []findings.Finding) {
		pr.Status = status
		pr.Reason = fmt.Sprintf(format, a...)
		return pr, nil
	}
	skip := func(cause report.Cause, format string, a ...any) (report.PluginResult, []findings.Finding) {
		pr.Cause = cause
		return fail(report.Skipped, format, a...)
	}
	if r := SkipReason(m, opt.Deployed); r != "" {
		return skip(SkipCause(m), "%s", r)
	}
	image, ok := ImageFor(m)
	if !ok {
		return skip(report.CausePlatform, "no container image for linux/%s", runtime.GOARCH)
	}
	fileMounts, err := FileMounts(m, opt.FilesRoot)
	if err != nil {
		return fail(report.Failed, "%v", err)
	}
	if w := m.Run.Wordlist; w != nil {
		name := w.Local
		if opt.Deployed {
			name = w.Deployed
		}
		dir, err := writeWordlist(work, m.ID, name)
		if err != nil {
			return fail(report.Failed, "write wordlist: %v", err)
		}
		fileMounts = append(fileMounts, sandbox.FileMount{Host: dir, Mount: WordlistMount})
	}
	rc := reportContext{Origin: opt.Target.Origin()}
	specFile := ""
	if UsesOpenAPI(m) {
		if opt.OpenAPI == nil {
			reason := opt.NoOpenAPI
			if reason == "" {
				reason = "no OpenAPI spec was given"
			}
			return skip(report.CauseNoInput, "%s", reason)
		}
		dir, name, err := writeSpec(work, m.ID, opt.OpenAPI)
		if err != nil {
			return fail(report.Failed, "write OpenAPI spec: %v", err)
		}
		fileMounts = append(fileMounts, sandbox.FileMount{Host: dir, Mount: OpenAPIMount})
		specFile = OpenAPIMount + "/" + name
		rc.BasePath, rc.BaseKnown = openapi.BasePath(opt.OpenAPI.Data, opt.OpenAPI.Format)
		pr.Input = "OpenAPI spec " + opt.OpenAPI.Source
	}
	cpus := min(m.Resources.CPUs, runtime.NumCPU())
	u := opt.Target.String()
	args := substituteURL(m.Run.Args, opt.Target, cpus, opt.Limits.Rate, specFile)
	var configFile string
	if m.Run.Config != nil {
		b, err := json.Marshal(configFor(m.Run.Config, u))
		if err != nil {
			return fail(report.Failed, "write tool configuration: %v", err)
		}
		configFile = filepath.Join(work, m.ID+"-config.json")
		// The container user may differ from ours; the file holds nothing
		// secret (the target URL and fixed settings).
		if err := os.WriteFile(configFile, b, 0o644); err != nil { // #nosec G306 -- read by the tool's user; no secrets
			return fail(report.Failed, "write tool configuration: %v", err)
		}
	}
	outDir, err := os.MkdirTemp(work, m.ID+"-")
	if err != nil {
		return fail(report.Failed, "create output directory: %v", err)
	}
	cfg := egress.Config{
		Target: opt.Target, Addrs: opt.Addrs, VerifyTLS: opt.Deployed,
		Rate: opt.Limits.Rate, Burst: opt.Limits.Burst, MaxConns: opt.Limits.MaxConns,
		MaxServerErrors: opt.Limits.MaxServerErrors, Version: opt.Version,
		// Deployed targets get read-only requests from plugins that are not
		// destructive, whatever the tool's own settings (ADR 0023).
		ReadOnly: opt.Deployed && !*m.Destructive,
	}
	res, err := run(ctx, sandbox.Spec{
		Image: image, Args: args, Env: m.Run.Env, OutDir: outDir, ConfigFile: configFile, Files: fileMounts,
		CPUs: cpus, MemoryMiB: m.Resources.MemoryMiB,
		Timeout: time.Duration(m.Resources.TimeoutSeconds) * time.Second,
		// Java tools keep their working files in /tmp.
		TmpMiB: m.Resources.MemoryMiB / 2,
	}, cfg)
	if err != nil {
		return fail(report.Failed, "%v", err)
	}
	pr.Requests, pr.Refused, pr.RefusedTo = res.Stats.Requests, res.Stats.Refused, res.Stats.RefusedTo
	switch {
	case res.Stopped != "":
		return fail(report.Failed, "stopped by SiegeKit: %s", res.Stopped)
	case res.Status == sandbox.TimedOut:
		return fail(report.TimedOut, "stopped after %d seconds", m.Resources.TimeoutSeconds)
	case res.Status == sandbox.Failed:
		return fail(report.Failed, "%s", lastLine(res.Stderr))
	case res.ExitCode != 0 && !slices.Contains(m.Run.FindingsExitCodes, res.ExitCode):
		return fail(report.Failed, "tool exited with code %d: %s", res.ExitCode, lastLine(res.Stderr))
	case res.Stats.Requests == 0:
		// A tool that never reached the target found nothing because it
		// tested nothing (ADR 0009).
		return fail(report.Failed, "the target answered no request from the tool")
	}
	fs, err := readReport(filepath.Join(outDir, m.Output.File), m, nil, rc)
	if err != nil {
		return fail(report.Failed, "%v", err)
	}
	for i := range fs {
		fs[i].RedactCredentials()
	}
	pr.Status, pr.Findings = report.Ran, len(fs)
	return pr, fs
}

// substituteURL replaces placeholders for an active run. The manifest
// validator already allows only known placeholders; {target} is the URL
// and specFile the mounted OpenAPI spec, if any.
func substituteURL(args []string, t *target.URL, cpus int, rate float64, specFile string) []string {
	u := t.String()
	r := strings.NewReplacer(
		// Scheme, host and port: Schemathesis keeps the spec's base path
		// when given only the origin (ADR 0028).
		"{target-origin}", t.Origin(),
		"{openapi}", specFile,
		"{target}", u,
		// The target without a trailing slash, for tools that append paths
		// to it: Nuclei turns "http://host/" into "http://host//.env", which
		// servers that redirect double slashes never answer (ADR 0026).
		"{target-base}", strings.TrimSuffix(u, "/"),
		"{outdir}", sandbox.OutMount,
		"{workdir}", sandbox.WorkDir,
		"{threads}", strconv.Itoa(cpus),
		"{ratelimit}", strconv.Itoa(max(1, int(rate))),
		"{config}", sandbox.ConfigMount,
		"{wordlist}", WordlistMount+"/"+wordlistFile,
	)
	out := make([]string, len(args))
	for i, a := range args {
		out[i] = r.Replace(a)
	}
	return out
}

// WordlistMount is where a plugin's path list is mounted (ADR 0027).
const WordlistMount = manifest.WordlistMount

// OpenAPIMount is where the OpenAPI spec is mounted (ADR 0028).
const OpenAPIMount = manifest.OpenAPIMount

// UsesOpenAPI reports whether m tests from an OpenAPI spec ({openapi}).
func UsesOpenAPI(m *manifest.Manifest) bool {
	return m.Run != nil && slices.ContainsFunc(m.Run.Args, func(a string) bool { return strings.Contains(a, "{openapi}") })
}

// writeSpec writes the spec into a new directory under work, as spec.json
// or spec.yaml, and returns the directory, which is mounted read-only.
func writeSpec(work, id string, s *openapi.Spec) (string, string, error) {
	if s.Format != "json" && s.Format != "yaml" {
		return "", "", fmt.Errorf("unknown spec format %q", s.Format)
	}
	dir, err := os.MkdirTemp(work, id+"-openapi-")
	if err != nil {
		return "", "", err
	}
	// Read by the tool's user, which may differ from ours. The spec is the
	// user's own API description; it is not kept after the run.
	if err := os.Chmod(dir, 0o755); err != nil { // #nosec G302 -- read by the tool's user; removed with the run directory
		return "", "", err
	}
	name := "spec." + s.Format
	if err := os.WriteFile(filepath.Join(dir, name), s.Data, 0o644); err != nil { // #nosec G306 -- read by the tool's user; removed with the run directory
		return "", "", err
	}
	return dir, name, nil
}

const wordlistFile = "paths.txt"

// writeWordlist writes the shipped list name into a new directory under
// work and returns the directory, which is mounted read-only.
func writeWordlist(work, id, name string) (string, error) {
	b, err := wordlists.Get(name)
	if err != nil {
		return "", err
	}
	dir, err := os.MkdirTemp(work, id+"-wordlist-")
	if err != nil {
		return "", err
	}
	// Read by the tool's user, which may differ from ours; the list is
	// public and holds nothing secret.
	if err := os.Chmod(dir, 0o755); err != nil { // #nosec G302 -- read by the tool's user; public data
		return "", err
	}
	if err := os.WriteFile(filepath.Join(dir, wordlistFile), b, 0o644); err != nil { // #nosec G306 -- read by the tool's user; public data
		return "", err
	}
	return dir, nil
}

// configFor substitutes {target} and {target-regex} in every string of a
// run.config value. The result is marshalled as JSON, so the target can
// only ever be a string value.
func configFor(v any, u string) any {
	r := strings.NewReplacer("{target-regex}", regexp.QuoteMeta(u), "{target}", u)
	var walk func(any) any
	walk = func(v any) any {
		switch t := v.(type) {
		case string:
			return r.Replace(t)
		case map[string]any:
			m := make(map[string]any, len(t))
			for k, x := range t {
				m[k] = walk(x)
			}
			return m
		case []any:
			s := make([]any, len(t))
			for i, x := range t {
				s[i] = walk(x)
			}
			return s
		}
		return v
	}
	return walk(v)
}

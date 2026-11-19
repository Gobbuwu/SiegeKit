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
	"strconv"
	"strings"
	"time"

	"github.com/Gobbuwu/SiegeKit/internal/egress"
	"github.com/Gobbuwu/SiegeKit/internal/findings"
	"github.com/Gobbuwu/SiegeKit/internal/manifest"
	"github.com/Gobbuwu/SiegeKit/internal/report"
	"github.com/Gobbuwu/SiegeKit/internal/sandbox"
	"github.com/Gobbuwu/SiegeKit/internal/target"
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
	// Unavailable records plugins that cannot run because a dependency is
	// missing (ADR 0016), keyed by plugin ID.
	Unavailable map[string]Unavailable
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
	out := &report.Run{SiegeKitVersion: opt.Version, Target: opt.Target.String(), Mode: mode, Started: time.Now().UTC()}
	var all []findings.Finding
	for _, m := range selected {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if u, ok := opt.Unavailable[m.ID]; ok {
			out.Plugins = append(out.Plugins, report.PluginResult{
				ID: m.ID, Family: m.Family, Tool: m.Tool.Name, Version: m.Tool.Version,
				Status: u.Status, Reason: u.Reason,
			})
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
		return "can change data on the target, so it does not run on deployed targets (opting in comes with --allow-destructive in M2.5)"
	}
	return ""
}

func runActive(ctx context.Context, run ActiveRunner, m *manifest.Manifest, opt URLOptions, work string) (report.PluginResult, []findings.Finding) {
	pr := report.PluginResult{ID: m.ID, Family: m.Family, Tool: m.Tool.Name, Version: m.Tool.Version}
	fail := func(status report.Status, format string, a ...any) (report.PluginResult, []findings.Finding) {
		pr.Status = status
		pr.Reason = fmt.Sprintf(format, a...)
		return pr, nil
	}
	if r := SkipReason(m, opt.Deployed); r != "" {
		return fail(report.Skipped, "%s", r)
	}
	image, ok := ImageFor(m)
	if !ok {
		return fail(report.Skipped, "no container image for linux/%s", runtime.GOARCH)
	}
	cpus := min(m.Resources.CPUs, runtime.NumCPU())
	u := opt.Target.String()
	args := substituteURL(m.Run.Args, u, cpus, opt.Limits.Rate)
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
		Image: image, Args: args, Env: m.Run.Env, OutDir: outDir, ConfigFile: configFile,
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
	case res.ExitCode != 0:
		return fail(report.Failed, "tool exited with code %d: %s", res.ExitCode, lastLine(res.Stderr))
	case res.Stats.Requests == 0:
		// A tool that never reached the target found nothing because it
		// tested nothing (ADR 0009).
		return fail(report.Failed, "the target answered no request from the tool")
	}
	fs, err := readReport(filepath.Join(outDir, m.Output.File), m, nil)
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
// validator already allows only known placeholders; {target} is the URL.
func substituteURL(args []string, u string, cpus int, rate float64) []string {
	r := strings.NewReplacer(
		"{target}", u,
		"{outdir}", sandbox.OutMount,
		"{workdir}", sandbox.WorkDir,
		"{threads}", strconv.Itoa(cpus),
		"{ratelimit}", strconv.Itoa(max(1, int(rate))),
		"{config}", sandbox.ConfigMount,
	)
	out := make([]string, len(args))
	for i, a := range args {
		out[i] = r.Replace(a)
	}
	return out
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

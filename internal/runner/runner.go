// Package runner runs the selected plugins against one target and builds the
// run report. In M1 it runs passive plugins against a source directory.
package runner

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/Gobbuwu/SiegeKit/internal/bandit"
	"github.com/Gobbuwu/SiegeKit/internal/checks"
	"github.com/Gobbuwu/SiegeKit/internal/findings"
	"github.com/Gobbuwu/SiegeKit/internal/manifest"
	"github.com/Gobbuwu/SiegeKit/internal/report"
	"github.com/Gobbuwu/SiegeKit/internal/sandbox"
	"github.com/Gobbuwu/SiegeKit/internal/sarif"
)

// Executor runs one sandboxed tool. *sandbox.Engine implements it.
type Executor interface {
	Run(ctx context.Context, s sandbox.Spec) (*sandbox.Result, error)
}

// Select returns the plugins and built-in checks that scan targetKind,
// filtered by only (if not empty) and skip. Naming one that does not exist,
// or one that cannot scan targetKind, is an error so a typo never silently
// drops a check.
func Select(all []*manifest.Manifest, builtins []checks.Check, targetKind string, only, skip []string) ([]*manifest.Manifest, []checks.Check, error) {
	targets := map[string][]string{}
	for _, m := range all {
		targets[m.ID] = m.Targets
	}
	for _, c := range builtins {
		targets[c.ID] = c.Targets
	}
	for _, id := range slices.Concat(only, skip) {
		t, ok := targets[id]
		if !ok {
			return nil, nil, fmt.Errorf("unknown plugin %q", id)
		}
		if !slices.Contains(t, targetKind) {
			return nil, nil, fmt.Errorf("plugin %q cannot scan a %s target", id, targetKind)
		}
	}
	want := func(id string, t []string) bool {
		return slices.Contains(t, targetKind) && !slices.Contains(skip, id) && (len(only) == 0 || slices.Contains(only, id))
	}
	var ms []*manifest.Manifest
	for _, m := range all {
		if want(m.ID, m.Targets) {
			ms = append(ms, m)
		}
	}
	var cs []checks.Check
	for _, c := range builtins {
		if want(c.ID, c.Targets) {
			cs = append(cs, c)
		}
	}
	if len(ms)+len(cs) == 0 {
		return nil, nil, errors.New("no plugins selected")
	}
	return ms, cs, nil
}

// Options for one run.
type Options struct {
	Version   string         // SiegeKit version recorded in the report
	TargetDir string         // absolute path of the source directory to scan
	WorkDir   string         // parent for the private temporary directory; "" means the OS default
	DataRoot  string         // where 'siegekit update' keeps tool data (ADR 0014)
	Checks    []checks.Check // built-in checks to run (ADR 0015)
	// Unavailable records plugins that cannot run because a dependency is
	// missing (ADR 0016), keyed by plugin ID. They are reported, not run.
	Unavailable map[string]Unavailable
}

// Unavailable is the reported outcome of a plugin that was not run.
type Unavailable struct {
	Status report.Status // report.Skipped or report.Failed
	Reason string
}

// MaxReportSize is the largest tool report read, matching the SARIF limit.
const MaxReportSize = sarif.MaxSize

// Run executes each plugin in turn and returns the combined report. A plugin
// that fails or times out is recorded as such and the run continues; the
// report then says the run is incomplete. Only setup problems return an error.
func Run(ctx context.Context, ex Executor, selected []*manifest.Manifest, opt Options) (*report.Run, error) {
	if !filepath.IsAbs(opt.TargetDir) {
		return nil, fmt.Errorf("target %q must be an absolute path", opt.TargetDir)
	}
	// MkdirTemp creates the directory with mode 0700, which the sandbox
	// requires of the parent of each output directory.
	work, err := os.MkdirTemp(opt.WorkDir, "siegekit-run-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(work)

	run := &report.Run{
		SiegeKitVersion: opt.Version,
		Target:          opt.TargetDir,
		Mode:            "local",
		Started:         time.Now().UTC(),
	}
	var all []findings.Finding
	for _, c := range opt.Checks {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		pr := report.PluginResult{ID: c.ID, Family: c.Family, Tool: "siegekit", Version: c.Version}
		fs, err := c.Run(ctx, opt.TargetDir)
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if err != nil {
			pr.Status, pr.Reason = report.Failed, err.Error()
		} else {
			pr.Status, pr.Findings = report.Ran, len(fs)
			all = append(all, fs...)
		}
		run.Plugins = append(run.Plugins, pr)
	}
	for _, m := range selected {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if u, ok := opt.Unavailable[m.ID]; ok {
			run.Plugins = append(run.Plugins, report.PluginResult{
				ID: m.ID, Family: m.Family, Tool: m.Tool.Name, Version: m.Tool.Version,
				Status: u.Status, Reason: u.Reason,
			})
			continue
		}
		pr, fs := runPlugin(ctx, ex, m, opt, work)
		run.Plugins = append(run.Plugins, pr)
		all = append(all, fs...)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	run.Findings = findings.Dedupe(all)
	if run.Findings == nil {
		run.Findings = []findings.Finding{}
	}
	run.Finished = time.Now().UTC()
	return run, nil
}

func runPlugin(ctx context.Context, ex Executor, m *manifest.Manifest, opt Options, work string) (report.PluginResult, []findings.Finding) {
	pr := report.PluginResult{ID: m.ID, Family: m.Family, Tool: m.Tool.Name, Version: m.Tool.Version}
	fail := func(status report.Status, format string, a ...any) (report.PluginResult, []findings.Finding) {
		pr.Status = status
		pr.Reason = fmt.Sprintf(format, a...)
		return pr, nil
	}
	if m.Mode != "passive" {
		return fail(report.Skipped, "%s plugins are not supported yet", m.Mode)
	}
	if len(m.AppliesTo) > 0 {
		// A tree too large to search is scanned anyway.
		found, err := checks.HasFile(ctx, opt.TargetDir, m.AppliesTo)
		switch {
		case errors.Is(err, checks.ErrTooManyFiles):
		case err != nil:
			return fail(report.Failed, "look for files to scan: %v", err)
		case !found:
			return fail(report.Skipped, "no files matching %s", strings.Join(m.AppliesTo, ", "))
		}
	}
	image, ok := ImageFor(m)
	if !ok {
		return fail(report.Skipped, "no container image for linux/%s", runtime.GOARCH)
	}
	var dataDir, dataMount, warning string
	if m.Data != nil {
		var err error
		dataDir, warning, err = dataFor(opt.DataRoot, m, time.Now())
		if err != nil {
			return fail(report.Failed, "%v", err)
		}
		dataMount = m.Data.Mount
	}
	cpus := min(m.Resources.CPUs, runtime.NumCPU())
	args, err := substitute(m.Run.Args, cpus, dataMount)
	if err != nil {
		return fail(report.Failed, "%v", err)
	}
	out, err := os.MkdirTemp(work, m.ID+"-")
	if err != nil {
		return fail(report.Failed, "create output directory: %v", err)
	}
	res, err := ex.Run(ctx, sandbox.Spec{
		Image: image, Args: args, TargetDir: opt.TargetDir, OutDir: out, Network: m.Network,
		DataDir: dataDir, DataMount: dataMount,
		CPUs: cpus, MemoryMiB: m.Resources.MemoryMiB,
		Timeout: time.Duration(m.Resources.TimeoutSeconds) * time.Second,
	})
	switch {
	case err != nil:
		return fail(report.Failed, "%v", err)
	case res.Status == sandbox.TimedOut:
		return fail(report.TimedOut, "stopped after %d seconds", m.Resources.TimeoutSeconds)
	case res.Status == sandbox.Failed:
		return fail(report.Failed, "%s", lastLine(res.Stderr))
	case res.ExitCode != 0:
		// Built-in plugins are configured to exit 0 when they find issues, so
		// any other exit code means the tool itself failed.
		return fail(report.Failed, "tool exited with code %d: %s", res.ExitCode, lastLine(res.Stderr))
	}
	fs, err := readReport(filepath.Join(out, m.Output.File), m)
	if err != nil {
		return fail(report.Failed, "%v", err)
	}
	for i := range fs {
		fs[i].RedactCredentials()
	}
	pr.Status = report.Ran
	pr.Reason = warning
	pr.Findings = len(fs)
	return pr, fs
}

// ImageFor picks the plugin's OCI image. Containers run Linux on every host
// (macOS engines use a Linux VM), so the platform is linux/<arch> or "any".
func ImageFor(m *manifest.Manifest) (string, bool) {
	for _, a := range m.Tool.Artifacts {
		if a.Kind == "oci-image" && (a.Platform == "any" || a.Platform == "linux/"+runtime.GOARCH) {
			return a.Ref, true
		}
	}
	return "", false
}

// substitute replaces placeholders with their in-container values. The
// manifest validator already allows only known placeholders.
func substitute(args []string, cpus int, dataMount string) ([]string, error) {
	r := strings.NewReplacer(
		"{target}", sandbox.TargetMount,
		"{outdir}", sandbox.OutMount,
		"{workdir}", sandbox.WorkDir,
		"{threads}", strconv.Itoa(cpus),
		"{data}", dataMount,
	)
	out := make([]string, len(args))
	for i, a := range args {
		if strings.Contains(a, "{ratelimit}") {
			return nil, errors.New("{ratelimit} is only available to active plugins, which are not supported yet")
		}
		if strings.Contains(a, "{data}") && dataMount == "" {
			return nil, errors.New("{data} used without a data section")
		}
		out[i] = r.Replace(a)
	}
	return out, nil
}

// readReport opens the tool's report without following symlinks, because the
// output directory was writable by the tool (threat model T7).
func readReport(path string, m *manifest.Manifest) ([]findings.Finding, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0) // #nosec G304 -- the report the tool wrote in our private output directory; symlinks refused
	if errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("tool wrote no report %q", filepath.Base(path))
	}
	if err != nil {
		return nil, fmt.Errorf("open report: %w", err)
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, fmt.Errorf("report %q is not a regular file", filepath.Base(path))
	}
	if m.Output.Parser == "bandit-json" {
		return bandit.ToFindings(f, bandit.Options{Plugin: m.ID, Family: m.Family, MountPath: sandbox.TargetMount})
	}
	log, err := sarif.Read(f)
	if err != nil {
		return nil, err
	}
	return sarif.ToFindings(log, sarif.Options{
		Plugin: m.ID, Family: m.Family, Parser: m.Output.Parser, MountPath: sandbox.TargetMount,
	})
}

// lastLine returns the last non-empty line of a tool's output for the
// one-line reason shown in reports. Tool output is untrusted, so control
// characters (including terminal escape sequences) are removed and the line
// is cut to its last 300 characters.
func lastLine(s string) string {
	s = strings.Map(func(r rune) rune {
		if r == '\n' {
			return r
		}
		if r < 0x20 || (r >= 0x7f && r < 0xa0) || r == utf8.RuneError {
			return -1
		}
		return r
	}, strings.ToValidUTF8(s, ""))
	lines := strings.Split(strings.TrimSpace(s), "\n")
	l := []rune(strings.TrimSpace(lines[len(lines)-1]))
	if len(l) == 0 {
		return "no error output"
	}
	// Keep the end: tools put the root cause last ("...: no space left").
	if len(l) > 300 {
		l = append([]rune{'…'}, l[len(l)-300:]...)
	}
	return string(l)
}

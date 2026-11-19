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

// Select returns the plugins that scan targetKind, filtered by only (if not
// empty) and skip. Naming a plugin that does not exist, or one that cannot
// scan targetKind, is an error so a typo never silently drops a check.
func Select(all []*manifest.Manifest, targetKind string, only, skip []string) ([]*manifest.Manifest, error) {
	byID := map[string]*manifest.Manifest{}
	for _, m := range all {
		byID[m.ID] = m
	}
	for _, id := range slices.Concat(only, skip) {
		m, ok := byID[id]
		if !ok {
			return nil, fmt.Errorf("unknown plugin %q", id)
		}
		if !slices.Contains(m.Targets, targetKind) {
			return nil, fmt.Errorf("plugin %q cannot scan a %s target", id, targetKind)
		}
	}
	var out []*manifest.Manifest
	for _, m := range all {
		if !slices.Contains(m.Targets, targetKind) || slices.Contains(skip, m.ID) {
			continue
		}
		if len(only) > 0 && !slices.Contains(only, m.ID) {
			continue
		}
		out = append(out, m)
	}
	if len(out) == 0 {
		return nil, errors.New("no plugins selected")
	}
	return out, nil
}

// Options for one run.
type Options struct {
	Version   string // SiegeKit version recorded in the report
	TargetDir string // absolute path of the source directory to scan
	WorkDir   string // parent for the private temporary directory; "" means the OS default
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
	for _, m := range selected {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		pr, fs := runPlugin(ctx, ex, m, opt.TargetDir, work)
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

func runPlugin(ctx context.Context, ex Executor, m *manifest.Manifest, target, work string) (report.PluginResult, []findings.Finding) {
	pr := report.PluginResult{ID: m.ID, Family: m.Family, Tool: m.Tool.Name, Version: m.Tool.Version}
	fail := func(status report.Status, format string, a ...any) (report.PluginResult, []findings.Finding) {
		pr.Status = status
		pr.Reason = fmt.Sprintf(format, a...)
		return pr, nil
	}
	if m.Mode != "passive" {
		return fail(report.Skipped, "%s plugins are not supported yet", m.Mode)
	}
	image, ok := imageFor(m)
	if !ok {
		return fail(report.Skipped, "no container image for linux/%s", runtime.GOARCH)
	}
	cpus := min(m.Resources.CPUs, runtime.NumCPU())
	args, err := substitute(m.Run.Args, cpus)
	if err != nil {
		return fail(report.Failed, "%v", err)
	}
	out, err := os.MkdirTemp(work, m.ID+"-")
	if err != nil {
		return fail(report.Failed, "create output directory: %v", err)
	}
	res, err := ex.Run(ctx, sandbox.Spec{
		Image: image, Args: args, TargetDir: target, OutDir: out, Network: m.Network,
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
	log, err := readReport(filepath.Join(out, m.Output.File))
	if err != nil {
		return fail(report.Failed, "%v", err)
	}
	fs, err := sarif.ToFindings(log, sarif.Options{
		Plugin: m.ID, Family: m.Family, Parser: m.Output.Parser, MountPath: sandbox.TargetMount,
	})
	if err != nil {
		return fail(report.Failed, "%v", err)
	}
	pr.Status = report.Ran
	pr.Findings = len(fs)
	return pr, fs
}

// imageFor picks the plugin's OCI image. Containers run Linux on every host
// (macOS engines use a Linux VM), so the platform is linux/<arch> or "any".
func imageFor(m *manifest.Manifest) (string, bool) {
	for _, a := range m.Tool.Artifacts {
		if a.Kind == "oci-image" && (a.Platform == "any" || a.Platform == "linux/"+runtime.GOARCH) {
			return a.Ref, true
		}
	}
	return "", false
}

// substitute replaces placeholders with their in-container values. The
// manifest validator already allows only known placeholders.
func substitute(args []string, cpus int) ([]string, error) {
	r := strings.NewReplacer(
		"{target}", sandbox.TargetMount,
		"{outdir}", sandbox.OutMount,
		"{workdir}", sandbox.WorkDir,
		"{threads}", strconv.Itoa(cpus),
	)
	out := make([]string, len(args))
	for i, a := range args {
		if strings.Contains(a, "{ratelimit}") {
			return nil, errors.New("{ratelimit} is only available to active plugins, which are not supported yet")
		}
		out[i] = r.Replace(a)
	}
	return out, nil
}

// readReport opens the tool's report without following symlinks, because the
// output directory was writable by the tool (threat model T7).
func readReport(path string) (*sarif.Log, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
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
	return sarif.Read(f)
}

// lastLine returns the last non-empty line of a tool's output for the
// one-line reason shown in reports. Tool output is untrusted, so control
// characters (including terminal escape sequences) are removed and the line
// is cut to 300 characters.
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
	if len(l) > 300 {
		l = append(l[:300], '…')
	}
	return string(l)
}

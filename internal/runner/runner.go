// Package runner runs the selected plugins against one target and builds the
// run report. In M1 it runs passive plugins against a source directory.
package runner

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path"
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
	"github.com/Gobbuwu/SiegeKit/internal/files"
	"github.com/Gobbuwu/SiegeKit/internal/findings"
	"github.com/Gobbuwu/SiegeKit/internal/manifest"
	"github.com/Gobbuwu/SiegeKit/internal/nuclei"
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
	FilesRoot string         // where pinned files are kept (ADR 0024)
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

// getuid and getgid are replaced in tests.
var getuid, getgid = os.Getuid, os.Getgid

// unreadable records which target files a tool cannot read (see
// checks.Unreadable). It is only filled in when SiegeKit runs as root.
type unreadable struct {
	paths []string
	err   error // the list could not be made; every check is then incomplete
}

// findUnreadable lists target files the tools cannot read when SiegeKit runs
// as root (owner decision, 2026-11-19). It returns nil otherwise.
func findUnreadable(ctx context.Context, root string) *unreadable {
	if getuid() != 0 {
		return nil
	}
	uid, gid := sandbox.ToolIdentity(getuid(), getgid())
	paths, err := checks.Unreadable(ctx, root, uint32(uid), uint32(gid)) // #nosec G115 -- ToolIdentity returns a fixed non-root ID for root
	if errors.Is(err, checks.ErrTooManyFiles) {
		err = nil // the tree is too large to check fully; report what was found
	}
	return &unreadable{paths: paths, err: err}
}

// affects reports whether the unreadable paths matter to plugin m: every
// unreadable directory does, and a file does if m reads files like it.
func (u *unreadable) affects(m *manifest.Manifest) bool {
	if u == nil {
		return false
	}
	if u.err != nil || len(m.AppliesTo) == 0 {
		return u.err != nil || len(u.paths) > 0
	}
	for _, p := range u.paths {
		if strings.HasSuffix(p, "/") {
			return true
		}
		for _, pat := range m.AppliesTo {
			if ok, _ := path.Match(pat, path.Base(p)); ok {
				return true
			}
		}
	}
	return false
}

// reason explains the problem in the report.
func (u *unreadable) reason() string {
	if u.err != nil {
		return fmt.Sprintf("incomplete: SiegeKit runs as root, so the tool runs as user %d, and SiegeKit could not check which files that user can read (%v). Run SiegeKit as a normal user.", nonRootUser(), u.err)
	}
	const show = 5
	list := strings.Join(u.paths[:min(show, len(u.paths))], ", ")
	if len(u.paths) > show {
		list += fmt.Sprintf(" and %d more", len(u.paths)-show)
	}
	return fmt.Sprintf("incomplete: SiegeKit runs as root, so the tool runs as user %d and could not read %d path(s): %s. Run SiegeKit as a normal user, or make these readable (chmod o+r, and o+rx for directories).", nonRootUser(), len(u.paths), list)
}

func nonRootUser() int {
	uid, _ := sandbox.ToolIdentity(0, 0)
	return uid
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
		pr := report.PluginResult{ID: c.ID, Family: c.Family, Tool: "siegekit", Version: opt.Version}
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
	var unread *unreadable
	checked := false
	for _, m := range selected {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if _, ok := opt.Unavailable[m.ID]; !ok && !checked {
			unread, checked = findUnreadable(ctx, opt.TargetDir), true
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
		}
		if u, ok := opt.Unavailable[m.ID]; ok {
			run.Plugins = append(run.Plugins, report.PluginResult{
				ID: m.ID, Family: m.Family, Tool: m.Tool.Name, Version: m.Tool.Version,
				Status: u.Status, Reason: u.Reason,
			})
			continue
		}
		pr, fs := runPlugin(ctx, ex, m, opt, work)
		if pr.Status == report.Ran && unread.affects(m) {
			// Its findings are kept, but the run is incomplete (exit code 4).
			reason := unread.reason()
			if pr.Reason != "" {
				reason += " " + pr.Reason
			}
			pr.Status, pr.Reason = report.Failed, reason
		}
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
	if m.RequiresGit {
		// A .git file (worktree or submodule) points outside the target, so
		// only a .git directory counts.
		st, err := os.Lstat(filepath.Join(opt.TargetDir, ".git"))
		if err != nil || !st.IsDir() {
			return fail(report.Skipped, "not a git repository (no .git directory at the top level)")
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
	fileMounts, err := FileMounts(m, opt.FilesRoot)
	if err != nil {
		return fail(report.Failed, "%v", err)
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
		Image: image, Args: args, Env: m.Run.Env, TargetDir: opt.TargetDir, OutDir: out, Network: m.Network,
		DataDir: dataDir, DataMount: dataMount, Files: fileMounts,
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
	var suppressed int
	fs, err := readReport(filepath.Join(out, m.Output.File), m, &suppressed)
	if err != nil {
		return fail(report.Failed, "%v", err)
	}
	pr.Suppressed = suppressed
	if err := repoIgnores(ctx, &pr, m, opt.TargetDir); err != nil {
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

// repoIgnores records what the scanned repository told the tool to ignore:
// its settings files at the top level and the lines with the tool's ignore
// comment (owner decision, 2026-11-19).
func repoIgnores(ctx context.Context, pr *report.PluginResult, m *manifest.Manifest, root string) error {
	r := m.RepoIgnores
	if r == nil {
		return nil
	}
	for _, f := range r.Files {
		if st, err := os.Lstat(filepath.Join(root, f)); err == nil && st.Mode().IsRegular() {
			pr.RepoSettings = append(pr.RepoSettings, f)
		}
	}
	n, err := checks.CountMarker(ctx, root, r.Marker)
	if err != nil && !errors.Is(err, checks.ErrTooManyFiles) {
		return fmt.Errorf("count %q comments: %w", r.Marker, err)
	}
	pr.IgnoreMarkers = n
	return nil
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

// FilesFor returns the pinned archives and binaries m needs on this machine
// (ADR 0024). Containers run Linux, so the platform is linux/GOARCH.
func FilesFor(m *manifest.Manifest) []manifest.Artifact {
	var out []manifest.Artifact
	for _, a := range m.Tool.Artifacts {
		if (a.Kind == "archive" || a.Kind == "binary") && (a.Platform == "any" || a.Platform == "linux/"+runtime.GOARCH) {
			out = append(out, a)
		}
	}
	return out
}

// FileMounts returns the read-only mounts of m's pinned files under root.
// A file that is not installed is an error: the dependency step reports
// plugins whose files are missing, so this is only a safety net.
func FileMounts(m *manifest.Manifest, root string) ([]sandbox.FileMount, error) {
	var out []sandbox.FileMount
	for _, a := range FilesFor(m) {
		if root == "" || !files.Installed(root, a) {
			return nil, fmt.Errorf("pinned file %s is not installed", path.Base(a.Ref))
		}
		out = append(out, sandbox.FileMount{Host: files.Dir(root, a), Mount: a.Mount})
	}
	return out, nil
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
		if strings.Contains(a, "{target-base}") {
			return nil, errors.New("{target-base} is only available to plugins that scan URLs")
		}
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
func readReport(path string, m *manifest.Manifest, suppressed *int) ([]findings.Finding, error) {
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
	mount := sandbox.TargetMount
	if m.Network == "target-only" {
		mount = "" // locations are URLs; nothing is mounted at /target
	}
	if m.Output.Parser == "nuclei-jsonl" {
		return nuclei.ToFindings(f, nuclei.Options{Plugin: m.ID, Family: m.Family})
	}
	if m.Output.Parser == "bandit-json" {
		return bandit.ToFindings(f, bandit.Options{Plugin: m.ID, Family: m.Family, MountPath: mount, Suppressed: suppressed})
	}
	log, err := sarif.Read(f)
	if err != nil {
		return nil, err
	}
	return sarif.ToFindings(log, sarif.Options{
		Plugin: m.ID, Family: m.Family, Parser: m.Output.Parser, MountPath: mount,
		Suppressed: suppressed,
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

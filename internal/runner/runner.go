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
	"github.com/Gobbuwu/SiegeKit/internal/ffuf"
	"github.com/Gobbuwu/SiegeKit/internal/files"
	"github.com/Gobbuwu/SiegeKit/internal/findings"
	"github.com/Gobbuwu/SiegeKit/internal/gosec"
	"github.com/Gobbuwu/SiegeKit/internal/manifest"
	"github.com/Gobbuwu/SiegeKit/internal/nuclei"
	"github.com/Gobbuwu/SiegeKit/internal/report"
	"github.com/Gobbuwu/SiegeKit/internal/sandbox"
	"github.com/Gobbuwu/SiegeKit/internal/sarif"
	"github.com/Gobbuwu/SiegeKit/internal/schemathesis"
	"github.com/Gobbuwu/SiegeKit/internal/trivy"
)

// Executor runs one sandboxed tool. *sandbox.Engine implements it.
type Executor interface {
	Run(ctx context.Context, s sandbox.Spec) (*sandbox.Result, error)
}

// describer is an Executor that can say which engine it is.
type describer interface {
	Describe(ctx context.Context) (sandbox.Info, error)
}

// Environment names the machine and the engine behind ex (ADR 0038). The
// engine part is left out when ex is nil or does not answer.
func Environment(ctx context.Context, ex Executor) *report.Environment {
	env := &report.Environment{OS: runtime.GOOS, Arch: runtime.GOARCH, Go: runtime.Version()}
	if d, ok := ex.(describer); ok && ex != nil {
		if i, err := d.Describe(ctx); err == nil {
			env.Engine = &report.Engine{Name: i.Engine, Version: i.Version, Rootless: i.Rootless, Cgroup: i.Cgroup}
		}
	}
	return env
}

// Select returns the plugins and built-in checks that apply to targetKind,
// narrowed by --only and --skip. Each name is a plugin or check ID, or a
// family such as "secrets" or "dast" (ADR 0004), which stands for every
// plugin and check of that family. A name that is unknown, or that has
// nothing for this kind of target, is an error.
func Select(all []*manifest.Manifest, builtins []checks.Check, targetKind string, only, skip []string) ([]*manifest.Manifest, []checks.Check, error) {
	type entry struct {
		family  string
		targets []string
	}
	byID := map[string]entry{}
	for _, m := range all {
		byID[m.ID] = entry{m.Family, m.Targets}
	}
	for _, c := range builtins {
		byID[c.ID] = entry{c.Family, c.Targets}
	}
	for _, name := range slices.Concat(only, skip) {
		if e, ok := byID[name]; ok {
			if !slices.Contains(e.targets, targetKind) {
				return nil, nil, fmt.Errorf("plugin %q cannot scan a %s target", name, targetKind)
			}
			continue
		}
		if !slices.Contains(manifest.Families, name) {
			return nil, nil, fmt.Errorf("unknown plugin or family %q (families: %s)", name, strings.Join(manifest.Families, ", "))
		}
		found := false
		for _, e := range byID {
			found = found || e.family == name && slices.Contains(e.targets, targetKind)
		}
		if !found {
			return nil, nil, fmt.Errorf("no %s plugin can scan a %s target", name, targetKind)
		}
	}
	named := func(list []string, id, family string) bool {
		return slices.Contains(list, id) || slices.Contains(list, family)
	}
	want := func(id, family string, t []string) bool {
		return slices.Contains(t, targetKind) && !named(skip, id, family) && (len(only) == 0 || named(only, id, family))
	}
	var ms []*manifest.Manifest
	for _, m := range all {
		if want(m.ID, m.Family, m.Targets) {
			ms = append(ms, m)
		}
	}
	var cs []checks.Check
	for _, c := range builtins {
		if want(c.ID, c.Family, c.Targets) {
			cs = append(cs, c)
		}
	}
	if len(ms)+len(cs) == 0 {
		return nil, nil, errors.New("no plugins selected")
	}
	return ms, cs, nil
}

// Profiles are the values of --profile (owner decision 2026-11-20): full,
// the default, runs every selected check; quick leaves out the attack tests
// (destructive plugins), which only URL scans of local targets run.
var Profiles = []string{"full", "quick"}

// ProfileReason says why m does not run in profile, or "".
func ProfileReason(m *manifest.Manifest, profile string) string {
	return ProfileSkip(m.Destructive != nil && *m.Destructive, profile)
}

// ProfileSkip says why a check that is destructive or not does not run in
// profile, or "". SiegeKit's own login throttling check uses it too.
//
// Its cause is report.CauseProfile.
func ProfileSkip(destructive bool, profile string) string {
	if profile == "quick" && destructive {
		return "not run with --profile quick, which leaves out attack tests; use --profile full (the default) to run it"
	}
	return ""
}

// Options for one run.
type Options struct {
	Version string // SiegeKit version recorded in the report
	// Environment names the machine and engine for the report (ADR 0038);
	// nil means Run asks the engine itself.
	Environment *report.Environment
	TargetDir   string         // absolute path of the source directory to scan
	WorkDir     string         // parent for the private temporary directory; "" means the OS default
	DataRoot    string         // where 'siegekit update' keeps tool data (ADR 0014)
	FilesRoot   string         // where pinned files are kept (ADR 0024)
	Checks      []checks.Check // built-in checks to run (ADR 0015)
	// Unavailable records plugins that cannot run because a dependency is
	// missing (ADR 0016), keyed by plugin ID. They are reported, not run.
	Unavailable map[string]Unavailable
	// Notes say, by plugin ID, why an input a plugin can use is missing,
	// such as a declined Go module download (ADR 0066). A note is added to
	// the plugin's reason when the plugin reports work it could not do.
	Notes map[string]string
}

// Unavailable is the reported outcome of a plugin that was not run.
type Unavailable struct {
	Status report.Status // report.Skipped or report.Failed
	Cause  report.Cause  // required when skipped (ADR 0041)
	Reason string
}

// Skip is a plugin skipped for cause, explained by reason.
func Skip(cause report.Cause, reason string) Unavailable {
	return Unavailable{Status: report.Skipped, Cause: cause, Reason: reason}
}

// Fail is a plugin that failed before it started; cause may be "".
func Fail(cause report.Cause, reason string) Unavailable {
	return Unavailable{Status: report.Failed, Cause: cause, Reason: reason}
}

// Result is u as the report of plugin m.
func (u Unavailable) Result(m *manifest.Manifest) report.PluginResult {
	return report.PluginResult{
		ID: m.ID, Family: m.Family, Tool: m.Tool.Name, Version: m.Tool.Version,
		Status: u.Status, Cause: u.Cause, Reason: u.Reason,
	}
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
	// A tree too large to check fully leaves err set: files after the cap
	// may be unreadable too, so the run cannot be called complete (ADR 0067).
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
		Environment:     opt.Environment,
	}
	if run.Environment == nil {
		run.Environment = Environment(ctx, ex)
	}
	var all []findings.Finding
	for _, c := range opt.Checks {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		pr := report.PluginResult{ID: c.ID, Family: c.Family, Tool: "siegekit", Version: opt.Version}
		o, err := c.Run(ctx, opt.TargetDir)
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		var na checks.NotApplicable
		switch {
		case errors.As(err, &na):
			pr.Status, pr.Cause, pr.Reason = report.Skipped, report.CauseNoFiles, na.Reason
		case errors.Is(err, checks.ErrTooManyFiles):
			// A cap reached: a run cut short (ADR 0067).
			pr.Status, pr.Stop, pr.Reason = report.Failed, report.StopFileLimit, fmt.Sprintf("stopped at %d files and folders, the most SiegeKit's own checks read", checks.MaxFiles)
		case err != nil:
			pr.Status, pr.Reason = report.Failed, err.Error()
		default:
			pr.Status, pr.Findings, pr.Result = report.Ran, len(o.Findings), o.Result
			for _, g := range o.Gaps {
				pr.AddGap(g)
			}
			// SiegeKit's own checks read every file they want, within
			// limits that are named as gaps when reached.
			pr.Completeness = report.Complete
			all = append(all, o.Findings...)
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
			run.Plugins = append(run.Plugins, u.Result(m))
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

func runPlugin(ctx context.Context, ex Executor, m *manifest.Manifest, opt Options, work string) (result report.PluginResult, found []findings.Finding) {
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
	if m.Mode != "passive" {
		return skip(report.CauseUnsupported, "%s plugins are not supported yet", m.Mode)
	}
	if len(m.AppliesTo) > 0 {
		// A tree too large to search is scanned anyway.
		found, err := checks.HasFile(ctx, opt.TargetDir, m.AppliesTo)
		switch {
		case errors.Is(err, checks.ErrTooManyFiles):
		case err != nil:
			return fail(report.Failed, "look for files to scan: %v", err)
		case !found:
			return skip(report.CauseNoFiles, "no files matching %s", strings.Join(m.AppliesTo, ", "))
		}
	}
	if m.RequiresGit {
		// A .git file (worktree or submodule) points outside the target, so
		// only a .git directory counts.
		st, err := os.Lstat(filepath.Join(opt.TargetDir, ".git"))
		if err != nil || !st.IsDir() {
			return skip(report.CauseNoFiles, "not a git repository (no .git directory at the top level)")
		}
	}
	image, ok := ImageFor(m)
	if !ok {
		return skip(report.CausePlatform, "no container image for linux/%s", runtime.GOARCH)
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
	env, configFile := m.Run.Env, ""
	if m.Run.GitleaksRules != "" {
		env, configFile, pr.Input, err = gitleaksConfig(m, opt.TargetDir, work)
		if err != nil {
			return fail(report.Failed, "%v", err)
		}
	}
	var scratch string
	if m.Run.GoModules {
		var g goRun
		g, err = goSetup(m, opt.DataRoot, work)
		if err != nil {
			return fail(report.Failed, "%v", err)
		}
		scratch, env, pr.Input = g.scratch, g.env, g.input
		dataDir, dataMount = g.cache, g.cacheMount
		// The scratch can hold gigabytes; it is deleted whatever the
		// outcome, and a failure to delete it is reported.
		defer func() {
			if err := removeScratch(ex, image, scratch); err != nil {
				result.Reason = strings.TrimSpace(result.Reason + " " + err.Error())
			}
		}()
	}
	spec := sandbox.Spec{
		Image: image, Args: args, Env: env, TargetDir: opt.TargetDir, OutDir: out, Network: m.Network,
		DataDir: dataDir, DataMount: dataMount, Files: fileMounts, ConfigFile: configFile, ScratchDir: scratch,
		CPUs: cpus, MemoryMiB: m.Resources.MemoryMiB, InTarget: m.Run.InRepoRoot,
		Timeout:    time.Duration(m.Resources.TimeoutSeconds) * time.Second,
		StdoutFile: stdoutFile(m),
		StderrFile: stderrFile(m),
	}
	res, err := ex.Run(ctx, spec)
	if err == nil {
		pr.Usage = usage(res, spec)
	}
	switch {
	case err != nil:
		return fail(report.Failed, "%v", err)
	case res.Stop != "":
		return stopped(pr, res.Status, report.Stop(res.Stop), res.StopReason, func() ([]findings.Finding, error) {
			return readReport(filepath.Join(out, m.Output.File), m, nil, reportContext{})
		})
	case res.Status == sandbox.Failed:
		return fail(report.Failed, "%s", lastLine(res.Stderr))
	case res.ExitCode != 0 && !slices.Contains(m.Run.FindingsExitCodes, res.ExitCode):
		// Built-in plugins exit 0, or with a code their manifest lists, when
		// they find issues, so any other exit code means the tool failed.
		return fail(report.Failed, "tool exited with code %d: %s", res.ExitCode, lastLine(res.Stderr))
	}
	var suppressed int
	fs, err := readReport(filepath.Join(out, m.Output.File), m, &suppressed, reportContext{})
	if err != nil {
		return fail(report.Failed, "%v", err)
	}
	if m.Output.GitIgnoredNote {
		// Severity stays: an ignored file can still leave the machine, such
		// as in a container image built with COPY . (ADR 0068).
		g := checks.NewGitState(opt.TargetDir)
		for i := range fs {
			if g.IgnoredUntracked(fs[i].Location.URI) {
				fs[i].Message = strings.TrimSpace(fs[i].Message + " " + checks.GitIgnoredNote)
			}
		}
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
	if o := m.Output.Stdout; o != nil {
		// What the tool did not do (ADR 0040): its findings are kept, but
		// the run is incomplete (exit code 4), as for unreadable files.
		missed, err := notDone(filepath.Join(out, o.File), filepath.Join(out, o.StderrFile), o.Parser, opt.TargetDir)
		switch {
		case err != nil:
			pr.Status, pr.Reason = report.Failed, err.Error()
		case missed != "":
			pr.Status, pr.Reason = report.Failed, missed
		default:
			// The tool's own list of what it could not do was read and is
			// empty (ADR 0040).
			pr.Completeness = report.Complete
		}
		if note := opt.Notes[m.ID]; note != "" && pr.Status == report.Failed {
			pr.Reason += " " + note
		}
		if warning != "" && pr.Status == report.Failed {
			pr.Reason += " " + warning
		}
	}
	return pr, fs
}

// stopped reports a run cut short (ADR 0067): failed, or timed out, with
// its typed stop, keeping the findings the tool wrote before the stop.
func stopped(pr report.PluginResult, status sandbox.Status, stop report.Stop, reason string, read func() ([]findings.Finding, error)) (report.PluginResult, []findings.Finding) {
	pr.Status, pr.Stop, pr.Reason = report.Failed, stop, reason
	if status == sandbox.TimedOut {
		pr.Status = report.TimedOut
	}
	fs, err := read()
	if err != nil {
		pr.Reason += "; no findings kept: " + err.Error()
		return pr, nil
	}
	for i := range fs {
		fs[i].RedactCredentials()
	}
	pr.Findings = len(fs)
	if len(fs) > 0 {
		pr.Reason += fmt.Sprintf("; the %d finding(s) reported before the stop are kept", len(fs))
	}
	return pr, fs
}

// usage is what a run's container used against its limits, or nil when
// the waiter wrote no counters.
func usage(res *sandbox.Result, s sandbox.Spec) *report.Usage {
	if res.Usage == nil {
		return nil
	}
	return &report.Usage{
		MemoryPeak: res.Usage.MemoryPeak, MemoryLimit: int64(s.MemoryMiB) << 20,
		ProcessPeak: res.Usage.ProcessesPeak, ProcessLimit: int64(s.ProcessLimit()),
	}
}

// stderrFile is the file that also receives m's standard error, if any.
func stderrFile(m *manifest.Manifest) string {
	if m.Output == nil || m.Output.Stdout == nil {
		return ""
	}
	return m.Output.Stdout.StderrFile
}

// stdoutFile is the file that receives m's standard output, if any.
func stdoutFile(m *manifest.Manifest) string {
	if m.Output == nil || m.Output.Stdout == nil {
		return ""
	}
	return m.Output.Stdout.File
}

// notDone reads the saved standard output, and the saved standard error
// when the parser needs it, with parser and says what the tool did not do
// in target, "" if nothing. Unreadable output is an error: the run cannot
// be called complete without it.
func notDone(path, logPath, parser, target string) (string, error) {
	f, err := openOutput(path)
	if err != nil {
		return "", fmt.Errorf("could not read the tool's error list: %w", err)
	}
	defer f.Close()
	switch parser {
	case "gosec-errors":
		lf, err := openOutput(logPath)
		if err != nil {
			return "", fmt.Errorf("could not read the tool's log: %w", err)
		}
		defer lf.Close()
		why, err := gosec.Check(f, lf, target, sandbox.TargetMount)
		if err != nil {
			return "", fmt.Errorf("could not read the tool's error list: %w", err)
		}
		return why, nil
	}
	return "", fmt.Errorf("unknown stdout parser %q", parser)
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
	if errors.Is(err, checks.ErrTooManyFiles) {
		pr.AddGap(report.Gap{Cause: report.GapOverLimit, Path: ".", Detail: fmt.Sprintf("%q comments were counted in the first %d files and folders only, so ignoreMarkers may be low", r.Marker, checks.MaxFiles)})
	} else if err != nil {
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
		for _, p := range []string{"{target-base}", "{target-origin}", "{wordlist}", "{openapi}"} {
			if strings.Contains(a, p) {
				return nil, fmt.Errorf("%s is only available to plugins that scan URLs", p)
			}
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

// reportContext is what a URL plugin's parser needs to know about the run.
type reportContext struct {
	Origin    string // the target's scheme, host and port
	BasePath  string // the OpenAPI spec's base path, if BaseKnown
	BaseKnown bool
}

// readReport opens the tool's report without following symlinks, because the
// output directory was writable by the tool (threat model T7).
func readReport(path string, m *manifest.Manifest, suppressed *int, rc reportContext) ([]findings.Finding, error) {
	f, err := openOutput(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	mount := sandbox.TargetMount
	if m.Network == "target-only" {
		mount = "" // locations are URLs; nothing is mounted at /target
	}
	if m.Output.Parser == "nuclei-jsonl" {
		return nuclei.ToFindings(f, nuclei.Options{Plugin: m.ID, Family: m.Family})
	}
	if m.Output.Parser == "ffuf-json" {
		return ffuf.ToFindings(f, ffuf.Options{Plugin: m.ID, Family: m.Family})
	}
	if m.Output.Parser == "schemathesis-json" {
		return schemathesis.ToFindings(f, schemathesis.Options{Plugin: m.ID, Family: m.Family, Origin: rc.Origin, BasePath: rc.BasePath, BaseKnown: rc.BaseKnown})
	}
	if m.Output.Parser == "bandit-json" {
		return bandit.ToFindings(f, bandit.Options{Plugin: m.ID, Family: m.Family, MountPath: mount, Suppressed: suppressed})
	}
	if m.Output.Parser == "trivy-json" {
		return trivy.ToFindings(f, trivy.Options{Plugin: m.ID, Family: m.Family, MountPath: mount})
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

// openOutput opens a file the tool wrote in SiegeKit's private output
// directory: a regular file, not a link.
func openOutput(path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0) // #nosec G304 -- a file the tool wrote in our private output directory; symlinks refused
	if errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("tool wrote no report %q", filepath.Base(path))
	}
	if err != nil {
		return nil, fmt.Errorf("open report: %w", err)
	}
	st, err := f.Stat()
	if err != nil {
		_ = f.Close() // read-only; the Stat error is the one to report
		return nil, err
	}
	if !st.Mode().IsRegular() {
		_ = f.Close() // read-only; nothing was read
		return nil, fmt.Errorf("report %q is not a regular file", filepath.Base(path))
	}
	return f, nil
}

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"syscall"

	"github.com/Gobbuwu/SiegeKit/internal/checks"
	"github.com/Gobbuwu/SiegeKit/internal/deps"
	"github.com/Gobbuwu/SiegeKit/internal/findings"
	"github.com/Gobbuwu/SiegeKit/internal/manifest"
	"github.com/Gobbuwu/SiegeKit/internal/registry"
	"github.com/Gobbuwu/SiegeKit/internal/report"
	"github.com/Gobbuwu/SiegeKit/internal/runner"
	"github.com/Gobbuwu/SiegeKit/internal/sandbox"
	"github.com/Gobbuwu/SiegeKit/internal/store"
	"github.com/Gobbuwu/SiegeKit/plugins"
)

// engine runs sandboxed tools and manages their images. *sandbox.Engine
// implements it.
type engine interface {
	runner.Executor
	deps.Engine
}

// Replaced in tests.
var (
	newEngine            = func() (engine, error) { return sandbox.Detect() }
	sizer     deps.Sizer = &registry.Client{}
	stdin     io.Reader  = os.Stdin
	// stdinIsTerminal reports whether someone can answer a question.
	stdinIsTerminal = func() bool { return isTerminal(os.Stdin) }
)

const scanUsage = `Usage: siegekit scan [flags] DIR
       siegekit scan [--deployed] [--authorized-host HOST] URL

Scans a source directory with the passive checks (no network, nothing is
executed from DIR). Reports are written to --report-dir.

A URL target is checked against the target rules (ADR 0005) first: this
machine is allowed, a private network address needs you to type its host
name (or pass it with --authorized-host), and public systems need --deployed
and proof that you control them. Active web tests arrive later in M2.

With --deployed, SiegeKit gives you a token for the host the first time and
checks it at the start of every run: publish it at
/.well-known/siegekit-verify.txt on the target's origin, or as a DNS TXT
record on _siegekit-verify.HOST. There is no flag to skip this check, and
the host name must then be typed in a terminal (--authorized-host is only
for private addresses), so a script or AI assistant cannot confirm a live
system on its own.

Flags:
  --only a,b        run only these plugins
  --skip a,b        do not run these plugins
  --fail-on LEVEL   exit 3 if a finding is at or above LEVEL
                    (critical, high, medium, low, info; default high)
  --report-dir DIR  where to write report.html, report.json and report.sarif
                    (default ./siegekit-report)
  --no-save         do not keep a copy of the run for later comparison
  --update          refresh downloaded tool data first (network access)
  --yes             install missing dependencies without asking (for CI)
  --no-install      install nothing; tests that need a missing dependency
                    are skipped
  --deployed        test a public system you control (proof required)
  --authorized-host HOST
                    confirm without a terminal that you are authorized to
                    test HOST; must match the URL's host exactly
                    (private addresses only, not --deployed)
  --require-all     treat tests skipped for a missing dependency as an
                    incomplete run (exit code 4 unless there are findings)

Before installing a missing dependency (a tool's container image or its
data), SiegeKit lists it with its size and the tests that need it and asks.
Without a terminal and without --yes, nothing is installed. Declined
dependencies skip the tests that need them; the report lists them.
`

func scan(args []string, stdout, stderr io.Writer) int {
	fl := flag.NewFlagSet("scan", flag.ContinueOnError)
	fl.SetOutput(io.Discard)
	only := fl.String("only", "", "")
	skip := fl.String("skip", "", "")
	failOn := fl.String("fail-on", "high", "")
	reportDir := fl.String("report-dir", "siegekit-report", "")
	noSave := fl.Bool("no-save", false, "")
	deployed := fl.Bool("deployed", false, "")
	authorizedHost := fl.String("authorized-host", "", "")
	doUpdate := fl.Bool("update", false, "")
	yes := fl.Bool("yes", false, "")
	noInstall := fl.Bool("no-install", false, "")
	requireAll := fl.Bool("require-all", false, "")
	// Allow flags before and after DIR.
	var pos []string
	for {
		if err := fl.Parse(args); errors.Is(err, flag.ErrHelp) {
			fmt.Fprint(stdout, scanUsage)
			return exitOK
		} else if err != nil {
			fmt.Fprintf(stderr, "siegekit scan: %v\n\n%s", err, scanUsage)
			return exitUsage
		}
		if fl.NArg() == 0 {
			break
		}
		pos = append(pos, fl.Arg(0))
		args = fl.Args()[1:]
	}
	if len(pos) != 1 {
		fmt.Fprint(stderr, scanUsage)
		return exitUsage
	}
	if *yes && *noInstall {
		fmt.Fprint(stderr, "siegekit scan: --yes and --no-install cannot be used together\n")
		return exitUsage
	}
	threshold, err := findings.ParseSeverity(*failOn)
	if err != nil {
		fmt.Fprintf(stderr, "siegekit scan: --fail-on: %v\n", err)
		return exitUsage
	}
	fail := func(err error) int {
		fmt.Fprintf(stderr, "siegekit scan: %v\n", err)
		return exitInvalid
	}

	if isURL(pos[0]) {
		return scanURL(pos[0], *deployed, *authorizedHost, stdout, stderr)
	}
	if *deployed || *authorizedHost != "" {
		fmt.Fprint(stderr, "siegekit scan: --deployed and --authorized-host only apply to URL targets\n")
		return exitUsage
	}
	target, err := resolveDir(pos[0])
	if err != nil {
		return fail(err)
	}
	all, err := plugins.Builtin()
	if err != nil {
		return fail(err)
	}
	selected, builtins, err := runner.Select(all, checks.Builtin(), "repo", splitList(*only), splitList(*skip))
	if err != nil {
		return fail(err)
	}
	var st *store.Store
	dataRoot := ""
	if dir, err := dataDir(); err == nil {
		dataRoot = filepath.Join(dir, "data")
		if !*noSave {
			st = &store.Store{Dir: filepath.Join(dir, "runs")}
		}
	} else if !*noSave {
		return fail(fmt.Errorf("%w (or use --no-save)", err))
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ex, unavailable, fetched, err := prepare(ctx, selected, dataRoot, consent{yes: *yes, none: *noInstall}, stdout)
	if err != nil {
		return fail(err)
	}
	if *doUpdate && ex != nil {
		if dataRoot == "" {
			return fail(errors.New("cannot find a directory for downloaded data"))
		}
		var refresh []*manifest.Manifest
		for _, m := range selected {
			if _, ok := unavailable[m.ID]; !ok && m.Data != nil && !fetched[m.ID] {
				refresh = append(refresh, m)
			}
		}
		if len(refresh) > 0 {
			fmt.Fprintln(stdout, "Updating tool data (network access, none of your files).")
			results, err := runner.Update(ctx, ex, refresh, dataRoot, "")
			if err != nil {
				return fail(err)
			}
			for _, r := range results {
				if r.Err != nil {
					// Keep going: the scan uses the older data.
					fmt.Fprintf(stdout, "  %-18s update failed - %v\n", r.ID, r.Err)
				}
			}
		}
	}
	fmt.Fprintf(stdout, "Scanning %s with %d check(s).\n", target, len(selected)+len(builtins))
	run, err := runner.Run(ctx, ex, selected, runner.Options{Version: version, TargetDir: target, DataRoot: dataRoot, Checks: builtins, Unavailable: unavailable})
	if errors.Is(err, context.Canceled) {
		return fail(errors.New("interrupted; no report written"))
	}
	if err != nil {
		return fail(err)
	}

	paths, err := writeReports(*reportDir, run)
	if err != nil {
		return fail(err)
	}
	fmt.Fprintf(stdout, "\n%s\n", run.Headline())
	if !run.Complete() {
		fmt.Fprintln(stdout, "This run is incomplete: at least one check failed or timed out.")
	}
	fmt.Fprintln(stdout)
	for _, p := range run.Plugins {
		line := fmt.Sprintf("  %-18s %-10s %d finding(s)", p.ID, p.Status, p.Findings)
		if p.Reason != "" {
			line += " - " + p.Reason
		}
		fmt.Fprintln(stdout, line)
	}
	fmt.Fprintf(stdout, "\nReports: %s\n", strings.Join(paths, ", "))
	if st != nil {
		id, err := st.Save(run, filepath.Base(target))
		if err != nil {
			return fail(fmt.Errorf("save run: %w", err))
		}
		fmt.Fprintf(stdout, "Saved run %s\n", id)
	}
	fmt.Fprintln(stdout, "Automated checks do not cover everything; see \"Not tested by SiegeKit\" in the HTML report.")
	code := run.ExitCode(threshold)
	if *requireAll && code == report.ExitClean {
		for _, p := range run.Plugins {
			if u, ok := unavailable[p.ID]; ok && u.Status == report.Skipped {
				fmt.Fprintln(stdout, "Incomplete (--require-all): tests were skipped for missing dependencies.")
				return report.ExitIncomplete
			}
		}
	}
	return code
}

// consent is the user's standing answer, if any, from the command line.
// data means downloading tool data needs no question ('siegekit update').
type consent struct{ yes, none, data bool }

// prepare finds the container engine and each plugin's dependencies, asks
// before installing missing ones (ADR 0016), and returns the plugins that
// cannot run and those whose data was downloaded now. ex is nil when there
// is no working engine.
func prepare(ctx context.Context, selected []*manifest.Manifest, dataRoot string, c consent, out io.Writer) (ex engine, un map[string]runner.Unavailable, fetched map[string]bool, err error) {
	if len(selected) == 0 {
		return nil, nil, nil, nil
	}
	eng, err := newEngine()
	if err != nil {
		fmt.Fprintln(out, deps.EngineHelp(runtime.GOOS))
		return nil, deps.NoEngine(selected, "no container engine (Docker or Podman) found"), nil, nil
	}
	all, err := deps.Plan(ctx, eng, selected, dataRoot)
	if err != nil {
		if ctx.Err() != nil {
			return nil, nil, nil, ctx.Err()
		}
		fmt.Fprintf(out, "The container engine is not working, so only built-in checks run: %v\n", err)
		un := deps.NoEngine(selected, err.Error())
		for id, u := range un {
			u.Status = report.Failed
			un[id] = u
		}
		return nil, un, nil, nil
	}
	if c.data {
		// Asked for explicitly: data is downloaded without a question.
		for i := range all {
			if all[i].Kind == deps.Data {
				all[i].Installed = false
			}
		}
	}
	var auto []deps.Dep
	missing := deps.Missing(all)
	if len(missing) > 0 && !c.none {
		deps.AddSizes(ctx, sizer, all)
		missing = deps.Missing(all)
	}
	if c.data {
		var ask []deps.Dep
		for _, d := range missing {
			if d.Kind == deps.Data {
				auto = append(auto, d)
			} else {
				ask = append(ask, d)
			}
		}
		missing = ask
		deps.Describe(out, slices.DeleteFunc(slices.Clone(all), func(d deps.Dep) bool { return d.Kind == deps.Data }))
	} else {
		deps.Describe(out, all)
	}
	var chosen []deps.Dep
	notChosen := func(d deps.Dep) string { return "you declined " + d.Name() }
	switch {
	case len(missing) == 0:
	case c.yes:
		chosen = missing
	case c.none:
		fmt.Fprintln(out, "Not installing anything (--no-install).")
		notChosen = func(d deps.Dep) string { return d.Name() + " is not installed (--no-install)" }
	case !stdinIsTerminal():
		fmt.Fprintln(out, "Not installing anything: no terminal to ask in. Use --yes to install, or --no-install to silence this.")
		notChosen = func(d deps.Dep) string { return d.Name() + " is not installed (no terminal to ask; use --yes)" }
	default:
		chosen = deps.Ask(stdin, out, missing)
	}
	chosen = append(chosen, auto...)
	un, err = deps.Install(ctx, eng, eng, all, chosen, dataRoot, notChosen, out)
	if err != nil {
		return nil, nil, nil, err
	}
	fetched = map[string]bool{}
	for _, d := range chosen {
		if _, failed := un[d.Plugin.ID]; d.Kind == deps.Data && !failed {
			fetched[d.Plugin.ID] = true
		}
	}
	var skipped []string
	for _, m := range selected {
		if u, ok := un[m.ID]; ok && u.Status == report.Skipped {
			skipped = append(skipped, m.ID)
		}
	}
	if len(skipped) > 0 {
		fmt.Fprintf(out, "Skipped because a dependency is not installed: %s.\n", strings.Join(skipped, ", "))
	}
	return eng, un, fetched, nil
}

// resolveDir returns the absolute, symlink-free path of an existing directory,
// so the path mounted into the container is the one that was checked.
func resolveDir(p string) (string, error) {
	abs, err := filepath.Abs(p)
	if err != nil {
		return "", err
	}
	real, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return "", err
	}
	st, err := os.Stat(real)
	if err != nil {
		return "", err
	}
	if !st.IsDir() {
		return "", fmt.Errorf("%s is not a directory", p)
	}
	return real, nil
}

func splitList(s string) []string {
	var out []string
	for _, x := range strings.Split(s, ",") {
		if x = strings.TrimSpace(x); x != "" {
			out = append(out, x)
		}
	}
	return out
}

// dataDir is $XDG_DATA_HOME/siegekit, or ~/.local/share/siegekit.
func dataDir() (string, error) {
	if d := os.Getenv("XDG_DATA_HOME"); filepath.IsAbs(d) {
		return filepath.Join(d, "siegekit"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("cannot find a directory to save runs: %w", err)
	}
	return filepath.Join(home, ".local", "share", "siegekit"), nil
}

// writeReports writes the three report formats into dir (mode 0700, files
// 0600, because findings can point at secrets).
func writeReports(dir string, run *report.Run) ([]string, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	var paths []string
	for _, r := range []struct {
		name  string
		write func(io.Writer, *report.Run) error
	}{
		{"report.html", report.WriteHTML},
		{"report.json", report.WriteJSON},
		{"report.sarif", report.WriteSARIF},
	} {
		p := filepath.Join(dir, r.name)
		f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_TRUNC|syscall.O_NOFOLLOW, 0o600) // #nosec G304 -- the report directory the user chose; symlinks refused
		if err != nil {
			return nil, err
		}
		err = f.Chmod(0o600)
		if err == nil {
			err = r.write(f, run)
		}
		if cerr := f.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			return nil, fmt.Errorf("write %s: %w", p, err)
		}
		paths = append(paths, p)
	}
	return paths, nil
}

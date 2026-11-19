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
	"strings"
	"syscall"

	"github.com/Gobbuwu/SiegeKit/internal/checks"
	"github.com/Gobbuwu/SiegeKit/internal/findings"
	"github.com/Gobbuwu/SiegeKit/internal/report"
	"github.com/Gobbuwu/SiegeKit/internal/runner"
	"github.com/Gobbuwu/SiegeKit/internal/sandbox"
	"github.com/Gobbuwu/SiegeKit/internal/store"
	"github.com/Gobbuwu/SiegeKit/plugins"
)

// newExecutor finds the container engine. Tests replace it.
var newExecutor = func() (runner.Executor, error) { return sandbox.Detect() }

const scanUsage = `Usage: siegekit scan [flags] DIR

Scans a source directory with the passive checks (no network, nothing is
executed from DIR). Reports are written to --report-dir.

Flags:
  --only a,b        run only these plugins
  --skip a,b        do not run these plugins
  --fail-on LEVEL   exit 3 if a finding is at or above LEVEL
                    (critical, high, medium, low, info; default high)
  --report-dir DIR  where to write report.html, report.json and report.sarif
                    (default ./siegekit-report)
  --no-save         do not keep a copy of the run for later comparison
  --update          run 'siegekit update' first (downloads vulnerability data)
`

func scan(args []string, stdout, stderr io.Writer) int {
	fl := flag.NewFlagSet("scan", flag.ContinueOnError)
	fl.SetOutput(io.Discard)
	only := fl.String("only", "", "")
	skip := fl.String("skip", "", "")
	failOn := fl.String("fail-on", "high", "")
	reportDir := fl.String("report-dir", "siegekit-report", "")
	noSave := fl.Bool("no-save", false, "")
	doUpdate := fl.Bool("update", false, "")
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
	threshold, err := findings.ParseSeverity(*failOn)
	if err != nil {
		fmt.Fprintf(stderr, "siegekit scan: --fail-on: %v\n", err)
		return exitUsage
	}
	fail := func(err error) int {
		fmt.Fprintf(stderr, "siegekit scan: %v\n", err)
		return exitInvalid
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
	ex, err := newExecutor()
	if err != nil {
		return fail(err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if *doUpdate {
		if dataRoot == "" {
			return fail(errors.New("cannot find a directory for downloaded data"))
		}
		fmt.Fprintln(stdout, "Updating vulnerability data (network access, none of your files).")
		results, err := runner.Update(ctx, ex, selected, dataRoot, "")
		if err != nil {
			return fail(err)
		}
		for _, r := range results {
			if r.Err != nil {
				// Keep going: the scan uses older data if there is any and
				// otherwise reports the check as failed.
				fmt.Fprintf(stdout, "  %-10s update failed - %v\n", r.ID, r.Err)
			}
		}
	}
	fmt.Fprintf(stdout, "Scanning %s with %d check(s). Tool images are downloaded on first use.\n", target, len(selected)+len(builtins))
	run, err := runner.Run(ctx, ex, selected, runner.Options{Version: version, TargetDir: target, DataRoot: dataRoot, Checks: builtins})
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
		line := fmt.Sprintf("  %-10s %-10s %d finding(s)", p.ID, p.Status, p.Findings)
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
	return run.ExitCode(threshold)
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
		f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_TRUNC|syscall.O_NOFOLLOW, 0o600)
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

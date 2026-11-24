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
	"github.com/Gobbuwu/SiegeKit/internal/login"
	"github.com/Gobbuwu/SiegeKit/internal/manifest"
	"github.com/Gobbuwu/SiegeKit/internal/ratelimit"
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
and proof that you control them. SiegeKit then prints the plan, records the
run in its audit log, checks with one GET that the target answers, and runs
the web tests: ZAP's crawler and passive checks, and on local targets only,
ZAP's attack scan, which can change data. On this machine the attack scan
asks you to type yes first (or pass --authorized-host with the target's
host); --yes does not count. Every request goes through SiegeKit's egress
proxy, which reaches only the target's own address. Web tests run on Linux
only for now.

With --deployed, SiegeKit gives you a token for the host the first time and
checks it at the start of every run: publish it at
/.well-known/siegekit-verify.txt on the target's origin, or as a DNS TXT
record on _siegekit-verify.HOST. There is no flag to skip this check, and
the host name must then be typed in a terminal (--authorized-host is only
for private addresses), so a script or AI assistant cannot confirm a live
system on its own.

Flags:
  --only a,b        run only these plugins or families (sast, sca,
                    secrets, iac, dast), for example --only secrets,trivy
  --skip a,b        do not run these plugins or families
  --profile NAME    full (default) runs every check; quick leaves out the
                    attack tests of URL scans (zap-active, nuclei-intrusive,
                    nuclei-default-login, schemathesis, login-throttle,
                    login-spray, rate-limit, reset-limit, signup-limit,
                    code-limit);
                    ZAP's attack scan alone can take 30 minutes
  --fail-on LEVEL   exit 3 if a finding is at or above LEVEL
                    (critical, high, medium, low, info; default high)
  --report-dir DIR  where to write report.html, report.json and report.sarif
                    (default ./siegekit-report)
  --no-save         do not keep a copy of the run for later comparison
  --update          refresh downloaded tool data first (network access)
  --yes             install missing dependencies without asking (for CI)
  --no-install      install nothing; tests that need a missing dependency
                    are skipped. The install question also offers the
                    target's Go modules for gosec, downloaded from
                    proxy.golang.org (which sees their names and versions)
                    in a container that gets only copies of the go.mod,
                    go.sum, go.work and go.work.sum files; modules matching
                    GOPRIVATE or GONOPROXY are never requested
  --ca-file FILE    a PEM file of extra CA certificates for the containers
                    that download (tool data, Go modules), for networks
                    with TLS inspection; default $SIEGEKIT_CA_FILE
  --proxy URL       http(s)://host:port of a proxy for those containers,
                    with no password; default $SIEGEKIT_PROXY. It must be
                    reachable from a container: not 127.0.0.1 on Linux
                    (under Colima, host.docker.internal reaches the Mac)
  --deployed        test a public system you control (proof required)
  --authorized-host HOST
                    confirm without a terminal that you are authorized to
                    test HOST; must match the URL's host exactly
                    (private addresses only, not --deployed)
  --require-all     treat tests skipped for a missing or declined dependency
                    as an incomplete run (exit code 4 unless there are
                    findings); tests left out by the mode, the profile, a
                    missing input or the target's files do not count
  --openapi FILE_OR_URL
                    the API's OpenAPI or Swagger 2.0 spec (JSON or YAML) for
                    Schemathesis and access-control (on local targets every
                    GET route, filled with IDs from --har); a URL must be on
                    the target's origin. Without it, SiegeKit looks at
                    common spec paths on local targets (one GET each)
  --login-url URL   the app's login endpoint, on the target's origin, for
                    the login throttling check (local targets only)
  --login-user NAME a test account you own; the check may lock it
  --login-body TEMPLATE
                    the POST body, with {user} and {password}: JSON if it
                    starts with {, otherwise a form, for example
                    '{"email":"{user}","password":"{password}"}'
  --login-attempts N
                    logins to send with a random wrong password, one per
                    second (default 20, at most 50)
  --har FILE        a browser recording (HAR file) made while using the app
                    as test account A, for the access-control check: its
                    GET and HEAD requests are replayed as A, as account C
                    (an account outside every space A shares; session
                    headers in SIEGEKIT_SESSION_C), as account B (session
                    headers in SIEGEKIT_SESSION_B, one "Name: value" per
                    line) and with no login
  --har-user NAME   account A's login name, as it appears in the app's
                    answers; reports A's data readable with no login
  --replay-writes   also replay the HAR file's POST, PUT, PATCH and DELETE
                    requests as accounts C and B and with no login
                    (access-control-write, local targets only). It changes
                    data in the app: use a throwaway database or a
                    snapshot. A person types "change test data" first.
                    It also tries PUT, PATCH and DELETE on A's objects.
                    Record every kind of change the app has (create,
                    edit and delete each kind of object, send each form,
                    finish a purchase): what A never did is not tested
  --rate-limit-url URL
                    an expensive URL on the target's origin, such as a
                    search, for the rate-limit check (local targets only);
                    it may have a query
  --rate-limit-body BODY
                    send a POST with this body instead of a GET: JSON if it
                    starts with { or [, otherwise a form
  --rate-limit-requests N
                    requests to send, one per second, stopping at the first
                    sign of a limit (default 20, at most 50)
  --reset-url URL, --reset-body BODY
  --signup-url URL, --signup-body BODY
  --code-url URL, --code-body BODY
                    a password-reset, sign-up or verification-code (second
                    factor) page, for the reset-limit, signup-limit and
                    code-limit checks (local targets only): 20 POSTs, one
                    per second. In the body, {wrong} is filled with a new
                    wrong answer or code each time (required on a code
                    page), and {new} with a new user name (required on a
                    sign-up page: up to 20 accounts are made). Without
                    these flags, the pages are taken from --har when the
                    recording used them
  --mail-catcher URL
                    a local Mailpit (its web address, such as
                    http://127.0.0.1:8025/) that the app sends its mail
                    to: reset-limit and signup-limit count the emails that
                    arrive there for the addresses they sent, and a reset
                    that answers the same each time but sends fewer emails
                    than requests counts as limited. SiegeKit only reads
                    Mailpit's list of messages
  --backend-url URL the Supabase or Firebase Realtime Database URL the app
                    reads from the browser, for the backend-live check: one
                    GET per table or path with the app's own public key.
                    A backend that is not on this machine must appear in
                    the app's scripts, and you type its host name in a
                    terminal; no flag skips that. An app that calls
                    Supabase only from its server serves no key: set
                    SIEGEKIT_SUPABASE_KEY to the project's anon or
                    publishable key (never a secret or service_role key).
                    On a host not on this machine the project must accept
                    it (one GET of /auth/v1/settings first), and then the
                    scripts need not name the host
  --storage-url URL the app's file storage, for the storage-write test
                    (local targets only): the Supabase project URL, or
                    https://firebasestorage.googleapis.com or a local
                    emulator for Firebase. Uploads one 36-byte text file to
                    the root of each bucket named in the app's scripts and
                    to folders named there (at most 5 files), reads it back
                    and deletes it, with the app's public key. You type
                    "write test files" after reading the list, and the host
                    name (the bucket name for hosted Firebase) when the
                    storage is not on this machine; no flag skips that. A
                    file whose delete is refused stays and is listed.
                    SIEGEKIT_SUPABASE_KEY works as for --backend-url
  --source DIR      the app's repository: whether it uses Supabase (a
                    supabase/ directory) or Firebase (firebase.json or a
                    rules file) when the app's scripts do not say, table
                    names from its Supabase migrations, paths from
                    database.rules.json, and an
                    OpenAPI file for Schemathesis when the app serves none,
                    and on local targets the GET routes of its server code
                    (Go routers, Rocket.Chat REST API, Express) for the
                    access-control route sweep (read locally, nothing is
                    sent but the swept requests to the target)

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
	openAPI := fl.String("openapi", "", "")
	profile := fl.String("profile", "full", "")
	var lf loginFlags
	fl.StringVar(&lf.url, "login-url", "", "")
	fl.StringVar(&lf.user, "login-user", "", "")
	fl.StringVar(&lf.body, "login-body", "", "")
	fl.IntVar(&lf.attempts, "login-attempts", login.DefaultAttempts, "")
	var rl rateLimitFlags
	fl.StringVar(&rl.url, "rate-limit-url", "", "")
	fl.StringVar(&rl.body, "rate-limit-body", "", "")
	fl.IntVar(&rl.requests, "rate-limit-requests", ratelimit.DefaultRequests, "")
	pages := map[ratelimit.Page]*pageFlag{}
	for _, p := range ratelimit.Pages {
		f := &pageFlag{}
		fl.StringVar(&f.url, string(p)+"-url", "", "")
		fl.StringVar(&f.body, string(p)+"-body", "", "")
		pages[p] = f
	}
	mailCatcher := fl.String("mail-catcher", "", "")
	har := fl.String("har", "", "")
	harUser := fl.String("har-user", "", "")
	replayWrites := fl.Bool("replay-writes", false, "")
	backendURL := fl.String("backend-url", "", "")
	storageURL := fl.String("storage-url", "", "")
	source := fl.String("source", "", "")
	caFile := fl.String("ca-file", "", "")
	proxy := fl.String("proxy", "", "")
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
	if !slices.Contains(runner.Profiles, *profile) {
		fmt.Fprintf(stderr, "siegekit scan: --profile must be one of %s\n", strings.Join(runner.Profiles, ", "))
		return exitUsage
	}
	attemptsSet, requestsSet := false, false
	fl.Visit(func(f *flag.Flag) {
		attemptsSet = attemptsSet || f.Name == "login-attempts"
		requestsSet = requestsSet || f.Name == "rate-limit-requests"
	})
	if err := lf.check(attemptsSet); err != nil {
		fmt.Fprintf(stderr, "siegekit scan: %v\n", err)
		return exitUsage
	}
	if err := rl.check(requestsSet); err != nil {
		fmt.Fprintf(stderr, "siegekit scan: %v\n", err)
		return exitUsage
	}
	anyPage := false
	for _, p := range ratelimit.Pages {
		f := pages[p]
		if f.body != "" && f.url == "" {
			fmt.Fprintf(stderr, "siegekit scan: --%s-body needs --%s-url\n", p, p)
			return exitUsage
		}
		anyPage = anyPage || f.url != ""
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

	if *harUser != "" && *har == "" {
		fmt.Fprint(stderr, "siegekit scan: --har-user needs --har\n")
		return exitUsage
	}
	// Write replay changes data, so it is local only (ADR 0049 item 1).
	switch {
	case *replayWrites && *har == "":
		fmt.Fprint(stderr, "siegekit scan: --replay-writes needs --har\n")
		return exitUsage
	case *replayWrites && *deployed:
		fmt.Fprint(stderr, "siegekit scan: --replay-writes changes data, so it runs only on local targets, not with --deployed\n")
		return exitUsage
	}
	// So does the storage write test (ADR 0058 item 1).
	if *storageURL != "" && *deployed {
		fmt.Fprint(stderr, "siegekit scan: --storage-url uploads files to the app's storage, so it runs only on local targets, not with --deployed\n")
		return exitUsage
	}
	if sc := otherScheme(pos[0]); sc != "" {
		if _, err := os.Stat(pos[0]); err != nil {
			fmt.Fprintf(stderr, "siegekit scan: %s:// URLs cannot be scanned; give an http:// or https:// URL or a directory\n", sc)
			return exitUsage
		}
	}
	if isURL(pos[0]) {
		if *doUpdate {
			fmt.Fprint(stderr, "siegekit scan: --update only applies to directory scans\n")
			return exitUsage
		}
		if *caFile != "" || *proxy != "" {
			fmt.Fprint(stderr, "siegekit scan: --ca-file and --proxy only apply to directory scans and siegekit update\n")
			return exitUsage
		}
		return scanURL(pos[0], urlScan{
			deployed: *deployed, authorizedHost: *authorizedHost,
			only: splitList(*only), skip: splitList(*skip), threshold: threshold,
			reportDir: *reportDir, noSave: *noSave, consent: consent{yes: *yes, none: *noInstall},
			requireAll: *requireAll, openAPI: *openAPI, profile: *profile, login: lf,
			har: *har, harUser: *harUser, replayWrites: *replayWrites, rateLimit: rl, pageFlags: pages,
			mailCatcher: *mailCatcher, backendURL: *backendURL, storageURL: *storageURL, source: *source,
		}, stdout, stderr)
	}
	egress, err := egressFrom(*caFile, *proxy)
	if err != nil {
		fmt.Fprintf(stderr, "siegekit scan: %v\n", err)
		return exitUsage
	}
	if *deployed || *authorizedHost != "" || *openAPI != "" || lf.url != "" || attemptsSet || *har != "" || *replayWrites || rl.url != "" || anyPage || *mailCatcher != "" || *backendURL != "" || *storageURL != "" || *source != "" {
		fmt.Fprint(stderr, "siegekit scan: --deployed, --authorized-host, --openapi, --har, --replay-writes, --backend-url, --storage-url, --source, --mail-catcher, the --login flags, the --rate-limit flags and the --reset, --signup and --code flags only apply to URL targets\n")
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
	var roots deps.Roots
	if dir, err := dataDir(); err == nil {
		roots = rootsIn(dir)
	} else if !*noSave {
		return fail(fmt.Errorf("%w (or use --no-save)", err))
	}
	roots.Target, roots.Egress = target, egress
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	dataRoot := roots.Data
	ex, unavailable, fetched, notes, err := prepare(ctx, selected, roots, consent{yes: *yes, none: *noInstall}, stdout)
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
			results, err := runner.Update(ctx, ex, refresh, dataRoot, "", egress)
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
	env := runner.Environment(ctx, ex)
	fmt.Fprintf(stdout, "Environment: %s\n", env)
	fmt.Fprintf(stdout, "Scanning %s with %d check(s).\n", target, len(selected)+len(builtins))
	run, err := runner.Run(ctx, ex, selected, runner.Options{Version: version, TargetDir: target, DataRoot: dataRoot, FilesRoot: roots.Files, Checks: builtins, Unavailable: unavailable, Notes: notes, Environment: env})
	if errors.Is(err, context.Canceled) {
		return fail(errors.New("interrupted; no report written"))
	}
	if err != nil {
		return fail(err)
	}

	return finish(run, *reportDir, *noSave, filepath.Base(target), threshold, *requireAll, stdout, stderr)
}

// badCause is told which checks were skipped with no valid cause; the
// tests make it fail them, so every skip in every tested path has one.
var badCause = func([]string) {}

// finish writes the reports, prints the summary, saves the run unless
// noSave, and returns the exit code.
func finish(run *report.Run, reportDir string, noSave bool, name string, threshold findings.Severity, requireAll bool, stdout, stderr io.Writer) int {
	fail := func(err error) int {
		fmt.Fprintf(stderr, "siegekit scan: %v\n", err)
		return exitInvalid
	}
	if bad := run.CheckCauses(); len(bad) > 0 {
		badCause(bad)
		fmt.Fprintf(stderr, "siegekit scan: SiegeKit bug: %s skipped with no valid cause; reported as failed\n", strings.Join(bad, ", "))
	}
	var st *store.Store
	dir, dirErr := dataDir()
	if !noSave && dirErr != nil {
		return fail(fmt.Errorf("%w (or use --no-save)", dirErr))
	}
	if dirErr == nil {
		// Compare with the last saved run of this target (ADR 0013), also
		// with --no-save, which only stops this run from being saved.
		runs := &store.Store{Dir: filepath.Join(dir, "runs")}
		if id, prev, err := runs.Latest(run.Target); err != nil {
			fmt.Fprintf(stderr, "siegekit scan: cannot compare with earlier runs: %v\n", err)
		} else if prev != nil {
			run.Comparison = store.Comparison(id, prev, run)
		}
		if !noSave {
			st = runs
		}
	}
	paths, err := writeReports(reportDir, run)
	if err != nil {
		return fail(err)
	}

	fmt.Fprintf(stdout, "\n%s\n", run.Headline())
	if !run.Complete() {
		fmt.Fprintln(stdout, "This run is incomplete: at least one check failed or timed out.")
	}
	fmt.Fprintln(stdout)
	for _, p := range run.Plugins {
		line := fmt.Sprintf("  %-20s %-10s %d finding(s)", p.ID, p.Status, p.Findings)
		if p.Reason != "" {
			line += " - " + p.Reason
		}
		if n := p.IgnoreNote(); n != "" {
			line += " (repository ignores: " + n + ")"
		}
		if p.Input != "" {
			line += " (tested from " + p.Input + ")"
		}
		if p.Result != "" {
			line += " (result: " + p.Result + ")"
		}
		if p.Requests > 0 || p.Refused > 0 {
			line += fmt.Sprintf(" (%d request(s) answered by the target, %d refused by SiegeKit", p.Requests, p.Refused)
			if len(p.RefusedTo) > 0 {
				line += ": " + strings.Join(p.RefusedTo[:min(3, len(p.RefusedTo))], ", ")
				if len(p.RefusedTo) > 3 {
					line += ", ... (all in report.json)"
				}
			}
			line += ")"
		}
		fmt.Fprintln(stdout, line)
	}
	if c := run.Comparison; c != nil {
		fmt.Fprintf(stdout, "\n%s\n", c.Summary())
		if n := c.VersionNote(run.SiegeKitVersion); n != "" {
			fmt.Fprintln(stdout, n)
		}
	}
	fmt.Fprintf(stdout, "\nReports: %s\n", strings.Join(paths, ", "))
	if st != nil {
		id, err := st.Save(run, name)
		if err != nil {
			return fail(fmt.Errorf("save run: %w", err))
		}
		fmt.Fprintf(stdout, "Saved run %s\n", id)
	}
	fmt.Fprintln(stdout, "Automated checks do not cover everything; see \"Not tested by SiegeKit\" in the HTML report.")
	code := run.ExitCode(threshold)
	if requireAll && code == report.ExitClean {
		// Only a missing or declined dependency counts (ADR 0016, ADR 0041):
		// a check left out by the target mode, the profile, a missing input
		// or the target's files is not a missing dependency.
		for _, p := range run.Plugins {
			if p.Status == report.Skipped && p.Cause.MissingDependency() {
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
func prepare(ctx context.Context, selected []*manifest.Manifest, roots deps.Roots, c consent, out io.Writer) (ex engine, un map[string]runner.Unavailable, fetched map[string]bool, notes map[string]string, err error) {
	if len(selected) == 0 {
		return nil, nil, nil, nil, nil
	}
	eng, err := newEngine()
	if err != nil {
		fmt.Fprintln(out, deps.EngineHelp(runtime.GOOS))
		return nil, deps.NoEngine(selected, "no container engine (Docker or Podman) found"), nil, nil, nil
	}
	all, err := deps.Plan(ctx, eng, selected, roots)
	if err == nil {
		all, err = deps.PlanGo(ctx, eng, all, selected, roots)
	}
	if err != nil {
		if ctx.Err() != nil {
			return nil, nil, nil, nil, ctx.Err()
		}
		fmt.Fprintf(out, "The container engine is not working, so only built-in checks run: %v\n", err)
		un := deps.NoEngine(selected, err.Error())
		for id, u := range un {
			u.Status = report.Failed
			un[id] = u
		}
		return nil, un, nil, nil, nil
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
	notChosen := func(d deps.Dep) runner.Unavailable {
		return runner.Skip(report.CauseDeclined, "you declined "+d.Name())
	}
	switch {
	case len(missing) == 0:
	case c.yes:
		chosen = missing
	case c.none:
		fmt.Fprintln(out, "Not installing anything (--no-install).")
		notChosen = func(d deps.Dep) runner.Unavailable {
			return runner.Skip(report.CauseMissingDependency, d.Name()+" is not installed (--no-install)")
		}
	case !stdinIsTerminal():
		fmt.Fprintln(out, "Not installing anything: no terminal to ask in. Use --yes to install, or --no-install to silence this.")
		notChosen = func(d deps.Dep) runner.Unavailable {
			return runner.Skip(report.CauseMissingDependency, d.Name()+" is not installed (no terminal to ask; use --yes)")
		}
	default:
		chosen = deps.Ask(stdin, out, missing)
	}
	chosen = append(chosen, auto...)
	un, notes, err = deps.Install(ctx, eng, eng, all, chosen, roots, notChosen, out)
	if err != nil {
		return nil, nil, nil, nil, err
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
	return eng, un, fetched, notes, nil
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

// rootsIn returns where downloaded data and pinned files are kept under
// SiegeKit's data directory dir.
func rootsIn(dir string) deps.Roots {
	return deps.Roots{Data: filepath.Join(dir, "data"), Files: filepath.Join(dir, "files")}
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

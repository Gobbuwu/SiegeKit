package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/Gobbuwu/SiegeKit/internal/audit"
	"github.com/Gobbuwu/SiegeKit/internal/egress"
	"github.com/Gobbuwu/SiegeKit/internal/findings"
	"github.com/Gobbuwu/SiegeKit/internal/manifest"
	"github.com/Gobbuwu/SiegeKit/internal/report"
	"github.com/Gobbuwu/SiegeKit/internal/runner"
	"github.com/Gobbuwu/SiegeKit/internal/sandbox"
	"github.com/Gobbuwu/SiegeKit/internal/target"
	"github.com/Gobbuwu/SiegeKit/internal/verify"
	"github.com/Gobbuwu/SiegeKit/plugins"
)

// resolver looks up target host names; tests replace it.
var resolver target.Resolver

// hostOS is runtime.GOOS; tests replace it.
var hostOS = runtime.GOOS

// activeRunner runs active plugins when the engine is not a
// *sandbox.Engine; tests set it.
var activeRunner runner.ActiveRunner

// prover checks deployed-mode proof of control; tests replace it.
var prover interface {
	Check(ctx context.Context, u *target.URL, addrs []netip.Addr, token string) (string, error)
} = &verify.Checker{}

func isURL(s string) bool {
	l := strings.ToLower(s)
	return strings.HasPrefix(l, "http://") || strings.HasPrefix(l, "https://")
}

// urlScan holds the scan flags that apply to a URL target.
type urlScan struct {
	deployed       bool
	authorizedHost string
	only, skip     []string
	threshold      findings.Severity
	reportDir      string
	noSave         bool
	consent        consent
	requireAll     bool
}

// scanURL applies the target rules of ADR 0005, then runs the active
// plugins (ADR 0023). Deployed mode checks proof of control (a GET of the
// well-known file from the pinned addresses, or a DNS TXT lookup) before
// asking for confirmation. No test traffic is sent before the target is
// allowed, the plan is printed and the run is in the audit log.
func scanURL(raw string, o urlScan, stdout, stderr io.Writer) int {
	deployed, authorizedHost := o.deployed, o.authorizedHost
	refuse := func(format string, a ...any) int {
		fmt.Fprintf(stderr, "siegekit scan: refused: "+format+"\n", a...)
		return exitInvalid
	}
	// Refused before any DNS lookup or request: --deployed only ever accepts
	// a host name typed by the person (ADR 0005, owner decision 2026-11-19).
	if deployed && authorizedHost != "" {
		return refuse("--authorized-host is not accepted for deployed targets; the person running SiegeKit types the host name in a terminal")
	}
	u, err := target.Parse(raw)
	if err != nil {
		return refuse("%v", err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	rctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	addrs, err := target.Resolve(rctx, resolver, u)
	if err != nil {
		return refuse("%v", err)
	}
	mode := target.Local
	if deployed {
		mode = target.Deployed
	}
	d := target.Authorize(mode, addrs)
	fmt.Fprintf(stdout, "Target %s resolves to %s (%s mode).\n", u, joinAddrs(d), mode)
	if !d.Allowed {
		return refuse("%s", d.Reason)
	}
	verification := "loopback"
	proof := ""
	if d.NeedsProof {
		// ADR 0005: a person types the host name. A flag would let a script
		// or an AI assistant confirm a live system on its own.
		if authorizedHost != "" {
			return refuse("--authorized-host is not accepted for deployed targets; the person running SiegeKit types the host name in a terminal")
		}
		if !stdinIsTerminal() {
			return refuse("deployed targets need the host name typed in a terminal; run this command yourself in a terminal (an AI assistant should ask you to)")
		}
		dir, err := dataDir()
		if err != nil {
			return refuse("%v", err)
		}
		token, err := verify.Token(filepath.Join(dir, "verify"), u.Host)
		if err != nil {
			return refuse("%v", err)
		}
		method, err := prover.Check(ctx, u, d.Addrs, token)
		if err != nil {
			fmt.Fprintf(stdout, "\n%s\n\n", verify.Instructions(u, token))
			return refuse("%v", err)
		}
		fmt.Fprintf(stdout, "Proof of control found: %s.\n", method)
		fmt.Fprint(stdout, "Before testing a deployed system, check your hosting provider's penetration-testing policy (some require notice or forbid some tests), and prefer a staging copy over production.\n")
		proof = method + " + "
	}
	if d.NeedsConfirmation {
		fmt.Fprintf(stdout, "%s. Only continue if you are authorized to test it.\n", d.Reason)
		verification = "typed confirmation"
		switch {
		case authorizedHost != "":
			if !target.Confirmed(u, authorizedHost) {
				return refuse("--authorized-host %q does not match the target host %q", authorizedHost, u.Host)
			}
			verification = "--authorized-host"
		case stdinIsTerminal():
			fmt.Fprintf(stdout, "Type the host name (%s) to confirm: ", u.Host)
			line, _ := bufio.NewReader(stdin).ReadString('\n')
			if !target.Confirmed(u, line) {
				return refuse("the typed host name did not match %q", u.Host)
			}
		default:
			return refuse("confirmation needed and there is no terminal to ask in; run this command yourself in a terminal, or pass --authorized-host %s if you (the person, not an AI assistant on its own) authorize this host", u.Host)
		}
	} else if authorizedHost != "" && !target.Confirmed(u, authorizedHost) {
		return refuse("--authorized-host %q does not match the target host %q", authorizedHost, u.Host)
	}
	verification = proof + verification
	fmt.Fprintf(stdout, "Target allowed (%s).\n", verification)
	confirmed := ""
	if verification != "loopback" {
		confirmed = u.Host
	}
	return runURL(ctx, u, d.Addrs, mode, verification, confirmed, o, stdout, stderr)
}

// runURL selects the active plugins, asks before installing their images
// (ADR 0016), prints the plan (ADR 0022), records the run in the audit log
// (ADR 0005) and runs it.
func runURL(ctx context.Context, u *target.URL, addrs []netip.Addr, mode target.Mode, verification, confirmed string, o urlScan, stdout, stderr io.Writer) int {
	fail := func(err error) int {
		fmt.Fprintf(stderr, "siegekit scan: %v\n", err)
		return exitInvalid
	}
	all, err := plugins.Builtin()
	if err != nil {
		return fail(err)
	}
	selected, _, err := runner.Select(all, nil, "url", o.only, o.skip)
	if err != nil {
		return fail(err)
	}
	dir, err := dataDir()
	if err != nil {
		// The audit log is required for every active run (ADR 0005).
		return fail(fmt.Errorf("%w; it holds the audit log of active runs", err))
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fail(err)
	}
	// Plugins that do not run in this mode or on this system are reported,
	// and their images are not offered for download.
	unavailable := map[string]runner.Unavailable{}
	var runnable []*manifest.Manifest
	for _, m := range selected {
		switch r := runner.SkipReason(m, o.deployed); {
		case r != "":
			unavailable[m.ID] = runner.Unavailable{Status: report.Skipped, Reason: r}
		case hostOS != "linux":
			unavailable[m.ID] = runner.Unavailable{Status: report.Failed, Reason: "active tests run only on Linux for now (ADR 0018)"}
		default:
			runnable = append(runnable, m)
		}
	}
	ex, un, _, err := prepare(ctx, runnable, "", o.consent, stdout)
	if err != nil {
		return fail(err)
	}
	maps.Copy(unavailable, un)
	limits := runner.LocalLimits
	if o.deployed {
		limits = runner.DeployedLimits
	}
	var planned []string
	fmt.Fprintf(stdout, "\nPlan: %s, %s mode, addresses %s.\n", u, mode, joinList(addrs))
	for _, m := range selected {
		if r, ok := unavailable[m.ID]; ok {
			fmt.Fprintf(stdout, "  %-12s not run - %s\n", m.ID, r.Reason)
			continue
		}
		planned = append(planned, m.ID)
		fmt.Fprintf(stdout, "  %-12s %s %s: %s\n", m.ID, m.Tool.Name, m.Tool.Version, m.Name)
	}
	fmt.Fprintf(stdout, "Limits: at most %.0f requests per second, stop after %d server errors in a row; only %s is reachable, and every request is labeled \"SiegeKit/%s\".\n",
		limits.Rate, limits.MaxServerErrors, strings.TrimSuffix(u.String(), u.Path), version)
	if len(planned) > 0 {
		if err := audit.Append(filepath.Join(dir, "audit.log"), audit.Entry{
			Time: time.Now().UTC(), Version: version, Target: u.String(), Addresses: addrStrings(addrs),
			Mode: string(mode), Verification: verification, Confirmed: confirmed, Plugins: planned,
		}); err != nil {
			return fail(fmt.Errorf("no test was sent: %w", err))
		}
	}
	var active runner.ActiveRunner
	if e, ok := ex.(*sandbox.Engine); ok {
		bin, err := os.Executable()
		if err != nil {
			return fail(err)
		}
		active = func(ctx context.Context, s sandbox.Spec, c egress.Config) (*runner.ActiveResult, error) {
			return runner.RunTargetOnly(ctx, e, s, c, "", bin)
		}
	} else if ex != nil {
		active = activeRunner // tests
	}
	run, err := runner.RunURL(ctx, active, selected, runner.URLOptions{
		Version: version, Target: u, Addrs: addrs, Deployed: o.deployed, Limits: limits, Unavailable: unavailable,
	})
	if errors.Is(err, context.Canceled) {
		return fail(errors.New("interrupted; no report written"))
	}
	if err != nil {
		return fail(err)
	}
	return finish(run, o.reportDir, o.noSave, u.Host, o.threshold, o.requireAll, unavailable, stdout, stderr)
}

func joinList[T fmt.Stringer](xs []T) string {
	s := make([]string, len(xs))
	for i, x := range xs {
		s[i] = x.String()
	}
	return strings.Join(s, ", ")
}

func addrStrings(addrs []netip.Addr) []string {
	s := make([]string, len(addrs))
	for i, a := range addrs {
		s[i] = a.String()
	}
	return s
}

func joinAddrs(d target.Decision) string {
	s := make([]string, len(d.Addrs))
	for i, a := range d.Addrs {
		s[i] = a.String()
	}
	return strings.Join(s, ", ")
}

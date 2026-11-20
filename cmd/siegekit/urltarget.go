package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/Gobbuwu/SiegeKit/internal/audit"
	"github.com/Gobbuwu/SiegeKit/internal/authz"
	"github.com/Gobbuwu/SiegeKit/internal/checks"
	"github.com/Gobbuwu/SiegeKit/internal/deps"
	"github.com/Gobbuwu/SiegeKit/internal/egress"
	"github.com/Gobbuwu/SiegeKit/internal/findings"
	"github.com/Gobbuwu/SiegeKit/internal/login"
	"github.com/Gobbuwu/SiegeKit/internal/manifest"
	"github.com/Gobbuwu/SiegeKit/internal/openapi"
	"github.com/Gobbuwu/SiegeKit/internal/report"
	"github.com/Gobbuwu/SiegeKit/internal/runner"
	"github.com/Gobbuwu/SiegeKit/internal/sandbox"
	"github.com/Gobbuwu/SiegeKit/internal/served"
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

// reachable checks that the target answers before the first plugin runs;
// tests replace it.
var reachable = egress.Reachable

// specGet fetches an OpenAPI spec from the target; tests replace it.
var specGet = egress.Get

// prover checks deployed-mode proof of control; tests replace it.
var prover interface {
	Check(ctx context.Context, u *target.URL, addrs []netip.Addr, token string) (string, error)
} = &verify.Checker{}

func isURL(s string) bool {
	l := strings.ToLower(s)
	return strings.HasPrefix(l, "http://") || strings.HasPrefix(l, "https://")
}

// otherScheme returns the scheme of a URL that SiegeKit cannot scan, such
// as ftp://, or "" if s does not start with "scheme://".
func otherScheme(s string) string {
	scheme, _, ok := strings.Cut(s, "://")
	if !ok || scheme == "" || isURL(s) {
		return ""
	}
	for i, c := range scheme {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || i > 0 && (c >= '0' && c <= '9' || c == '+' || c == '-' || c == '.')) {
			return ""
		}
	}
	return scheme
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
	openAPI        string // --openapi: a file or a URL on the target's origin
	profile        string // --profile: full or quick
	login          loginFlags
	har, harUser   string // --har and --har-user (ADR 0035)

	// Read from --har and SIEGEKIT_SESSION_B before any request.
	harRequests *authz.HAR
	sessionB    http.Header
}

// loginFlags are the --login flags of the login throttling check
// (ADR 0030).
type loginFlags struct {
	url, user, body string
	attempts        int
}

// check accepts all three of --login-url, --login-user and --login-body or
// none, and --login-attempts only with them.
func (f loginFlags) check(attemptsSet bool) error {
	n := 0
	for _, v := range []string{f.url, f.user, f.body} {
		if v != "" {
			n++
		}
	}
	switch {
	case n != 0 && n != 3:
		return errors.New("--login-url, --login-user and --login-body are needed together")
	case attemptsSet && n == 0:
		return errors.New("--login-attempts needs --login-url, --login-user and --login-body")
	case f.attempts < login.MinAttempts || f.attempts > login.MaxAttempts:
		return fmt.Errorf("--login-attempts must be from %d to %d", login.MinAttempts, login.MaxAttempts)
	}
	return nil
}

// loginCheck runs the login throttling check; tests replace it.
var loginCheck = login.Check

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
	// A spec file is read now, so a wrong path is reported before any
	// request; a spec URL is fetched after the run is allowed.
	var spec specSource
	if o.openAPI != "" {
		if spec, err = openAPISource(o.openAPI, u); err != nil {
			return refuse("--openapi: %v", err)
		}
	}
	// The login is checked now too, so a mistake is reported before any
	// request.
	var lg *login.Login
	if o.login.url != "" {
		if lg, err = login.Parse(o.login.url, o.login.user, o.login.body, u); err != nil {
			return refuse("%v", err)
		}
	}
	// So are the HAR file and account B's session (ADR 0035).
	if o.har != "" {
		data, err := readHAR(o.har)
		if err != nil {
			return refuse("--har: %v", err)
		}
		if o.harRequests, err = authz.ParseHAR(data, u); err != nil {
			return refuse("--har: %v", err)
		}
		if s, ok := os.LookupEnv(authz.SessionEnv); ok {
			if o.sessionB, err = authz.ParseSession(s); err != nil {
				return refuse("%v", err)
			}
		}
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
	return runURL(ctx, u, d.Addrs, mode, verification, confirmed, o, spec, lg, stdout, stderr)
}

// specSource is what --openapi named: a spec read from a file, or a path
// on the target's origin.
type specSource struct {
	spec *openapi.Spec
	path string
}

// openAPISource reads a spec file, or checks that a spec URL is on the
// target's origin: SiegeKit sends requests only to the target (ADR 0005).
func openAPISource(arg string, u *target.URL) (specSource, error) {
	if isURL(arg) {
		su, err := target.Parse(arg)
		if err != nil {
			return specSource{}, err
		}
		if su.Origin() != u.Origin() {
			return specSource{}, fmt.Errorf("%s is not on the target's origin %s; SiegeKit sends requests only to the target, so download the spec and pass the file", su, u.Origin())
		}
		return specSource{path: su.Path}, nil
	}
	f, err := os.Open(arg) // #nosec G304 -- the spec file the user named
	if err != nil {
		return specSource{}, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, openapi.MaxSize+1))
	if err != nil {
		return specSource{}, err
	}
	format, err := openapi.Check(b)
	if err != nil {
		return specSource{}, fmt.Errorf("%s: %w", arg, err)
	}
	return specSource{spec: &openapi.Spec{Data: b, Format: format, Source: arg}}, nil
}

// findSpec returns the spec for plugins that use one (ADR 0025 item 4,
// ADR 0028): the --openapi file, the --openapi URL, or on local targets the
// first valid spec at openapi.DefaultPaths. It returns nil and the reason
// when there is none; failed is true when the spec the user named could
// not be used.
func findSpec(ctx context.Context, cfg egress.Config, src specSource, deployed bool) (spec *openapi.Spec, reason string, failed bool) {
	if src.spec != nil {
		return src.spec, "", false
	}
	fetch := func(p string) (*openapi.Spec, error) {
		status, b, err := specGet(ctx, cfg, p, openapi.MaxSize)
		if err != nil {
			return nil, err
		}
		if status != 200 {
			return nil, fmt.Errorf("answered %d", status)
		}
		format, err := openapi.Check(b)
		if err != nil {
			return nil, err
		}
		return &openapi.Spec{Data: b, Format: format, Source: cfg.Target.Origin() + p}, nil
	}
	if src.path != "" {
		s, err := fetch(src.path)
		if err != nil {
			return nil, fmt.Sprintf("the OpenAPI spec at %s could not be used: %v", cfg.Target.Origin()+src.path, err), true
		}
		return s, "", false
	}
	if deployed {
		return nil, "no OpenAPI spec was given with --openapi (SiegeKit looks for one only on local targets)", false
	}
	for _, p := range openapi.DefaultPaths {
		if err := ctx.Err(); err != nil {
			return nil, err.Error(), true
		}
		if s, err := fetch(p); err == nil {
			return s, "", false
		}
	}
	return nil, fmt.Sprintf("no OpenAPI spec was given with --openapi and none was found at %s", strings.Join(openapi.DefaultPaths, ", ")), false
}

// runURL selects the active plugins, asks before installing their images
// (ADR 0016), prints the plan (ADR 0022), records the run in the audit log
// (ADR 0005) and runs it.
func runURL(ctx context.Context, u *target.URL, addrs []netip.Addr, mode target.Mode, verification, confirmed string, o urlScan, src specSource, lg *login.Login, stdout, stderr io.Writer) int {
	fail := func(err error) int {
		fmt.Fprintf(stderr, "siegekit scan: %v\n", err)
		return exitInvalid
	}
	all, err := plugins.Builtin()
	if err != nil {
		return fail(err)
	}
	// SiegeKit's own login throttling and served-secrets checks are
	// selected like plugins.
	selected, own, err := runner.Select(all, []checks.Check{
		{ID: login.ID, Name: login.Name, Family: login.Family, Targets: []string{"url"}},
		{ID: served.ID, Name: served.Name, Family: served.Family, Targets: []string{"url"}},
		{ID: authz.ID, Name: authz.Name, Family: authz.Family, Targets: []string{"url"}},
	}, "url", o.only, o.skip)
	if err != nil {
		return fail(err)
	}
	ownSelected := func(id string) bool {
		return slices.ContainsFunc(own, func(c checks.Check) bool { return c.ID == id })
	}
	loginSelected, servedSelected, authzSelected := ownSelected(login.ID), ownSelected(served.ID), ownSelected(authz.ID)
	// The served-secrets check runs Gitleaks over the files it fetched
	// (ADR 0032).
	var gitleaks *manifest.Manifest
	if servedSelected {
		i := slices.IndexFunc(all, func(m *manifest.Manifest) bool { return m.ID == servedTool })
		if i < 0 {
			return fail(fmt.Errorf("built-in plugin %s is missing", servedTool))
		}
		gitleaks = all[i]
	}
	if loginSelected && runner.ProfileSkip(true, o.profile) != "" && slices.Contains(o.only, login.ID) {
		return fail(fmt.Errorf("--only names %s, which --profile %s does not run", login.ID, o.profile))
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
		if r := runner.ProfileReason(m, o.profile); r != "" && slices.Contains(o.only, m.ID) {
			return fail(fmt.Errorf("--only names %s, which --profile %s does not run", m.ID, o.profile))
		}
		switch r := runner.SkipReason(m, o.deployed); {
		case r != "":
			unavailable[m.ID] = runner.Unavailable{Status: report.Skipped, Reason: r}
		case runner.ProfileReason(m, o.profile) != "":
			unavailable[m.ID] = runner.Unavailable{Status: report.Skipped, Reason: runner.ProfileReason(m, o.profile)}
		case hostOS != "linux":
			unavailable[m.ID] = runner.Unavailable{Status: report.Failed, Reason: "active tests run only on Linux for now (ADR 0018)"}
		default:
			runnable = append(runnable, m)
		}
	}
	if servedSelected && hostOS != "linux" {
		unavailable[served.ID] = runner.Unavailable{Status: report.Failed, Reason: "active tests run only on Linux for now (ADR 0018)"}
	}
	// Active plugins need no tool data, but some need pinned files. The
	// served-secrets check needs the Gitleaks image.
	toPrepare := runnable
	if servedSelected && hostOS == "linux" {
		toPrepare = append(slices.Clip(runnable), gitleaks)
	}
	ex, un, _, err := prepare(ctx, toPrepare, deps.Roots{Files: rootsIn(dir).Files}, o.consent, stdout)
	if err != nil {
		return fail(err)
	}
	if u, ok := un[servedTool]; ok {
		unavailable[served.ID] = u
		delete(un, servedTool)
	}
	maps.Copy(unavailable, un)
	if loginSelected {
		switch {
		case o.deployed:
			unavailable[login.ID] = runner.Unavailable{Status: report.Skipped, Reason: "runs only on local targets: deployed targets get only GET and HEAD requests until request limits are measured (M2.10)"}
		case runner.ProfileSkip(true, o.profile) != "":
			unavailable[login.ID] = runner.Unavailable{Status: report.Skipped, Reason: runner.ProfileSkip(true, o.profile)}
		case lg == nil:
			unavailable[login.ID] = runner.Unavailable{Status: report.Skipped, Reason: "no login was given: pass --login-url, --login-user and --login-body to test whether failed logins are limited"}
		case hostOS != "linux":
			unavailable[login.ID] = runner.Unavailable{Status: report.Failed, Reason: "active tests run only on Linux for now (ADR 0018)"}
		}
	}
	if authzSelected {
		switch {
		case o.harRequests == nil:
			unavailable[authz.ID] = runner.Unavailable{Status: report.Skipped, Reason: "no HAR file was given: pass --har (a browser recording made as test account A) and set " + authz.SessionEnv + " to account B's session headers to test access between accounts"}
		case hostOS != "linux":
			unavailable[authz.ID] = runner.Unavailable{Status: report.Failed, Reason: "active tests run only on Linux for now (ADR 0018)"}
		}
	}
	limits := runner.LocalLimits
	if o.deployed {
		limits = runner.DeployedLimits
	}
	var planned []string
	var spec *openapi.Spec
	noSpec := ""
	fmt.Fprintf(stdout, "\nPlan: %s, %s mode, addresses %s.\n", u, mode, joinList(addrs))
	for _, m := range selected {
		if r, ok := unavailable[m.ID]; ok {
			fmt.Fprintf(stdout, "  %-20s not run - %s\n", m.ID, r.Reason)
			continue
		}
		planned = append(planned, m.ID)
		fmt.Fprintf(stdout, "  %-20s %s %s: %s\n", m.ID, m.Tool.Name, m.Tool.Version, m.Name)
	}
	if loginSelected {
		if r, ok := unavailable[login.ID]; ok {
			fmt.Fprintf(stdout, "  %-20s not run - %s\n", login.ID, r.Reason)
		} else {
			planned = append(planned, login.ID)
			fmt.Fprintf(stdout, "  %-20s siegekit %s: %d logins for %q with a random wrong password, POST %s, one per second; the account may be locked\n",
				login.ID, version, o.login.attempts, lg.User, lg.URL)
		}
	}
	if servedSelected {
		if r, ok := unavailable[served.ID]; ok {
			fmt.Fprintf(stdout, "  %-20s not run - %s\n", served.ID, r.Reason)
		} else {
			planned = append(planned, served.ID)
			fmt.Fprintf(stdout, "  %-20s %s %s: GET the start page and up to %d same-origin scripts, styles, JSON files and source maps it links, then scan them for secrets\n",
				served.ID, gitleaks.Tool.Name, gitleaks.Tool.Version, served.MaxRequests-1)
		}
	}
	if authzSelected {
		if r, ok := unavailable[authz.ID]; ok {
			fmt.Fprintf(stdout, "  %-20s not run - %s\n", authz.ID, r.Reason)
		} else {
			planned = append(planned, authz.ID)
			who := "as account A, as account B and with no login"
			if o.sessionB == nil {
				who = "as account A and with no login (" + authz.SessionEnv + " not set: account B is not tested)"
			}
			fmt.Fprintf(stdout, "  %-20s siegekit %s: replay %d GET and HEAD request(s) from %s %s\n",
				authz.ID, version, len(o.harRequests.Requests), filepath.Base(o.har), who)
		}
	}
	fmt.Fprintf(stdout, "Limits: at most %.0f requests per second, stop after %d server errors in a row; only %s is reachable, and every request is labeled \"SiegeKit/%s\".\n",
		limits.Rate, limits.MaxServerErrors, strings.TrimSuffix(u.String(), u.Path), version)
	if mode == "deployed" {
		fmt.Fprintln(stdout, "Only GET and HEAD requests are allowed: no check may change data on a deployed target.")
	}
	// ADR 0005: destructive checks run only after a person confirmed the
	// run. Private and deployed targets were confirmed above; a loopback
	// target was not, so ask now (owner decision, 2026-11-19). --yes does
	// not count.
	if verification == "loopback" {
		var destructive []string
		for _, m := range selected {
			if slices.Contains(planned, m.ID) && *m.Destructive {
				destructive = append(destructive, m.ID)
			}
		}
		var warn []string
		if len(destructive) > 0 {
			warn = append(warn, fmt.Sprintf("%s send(s) attack payloads that can change or delete data in the app at %s.", strings.Join(destructive, ", "), u))
		}
		// The login check can lock the test account (ADR 0010).
		if slices.Contains(planned, login.ID) {
			destructive = append(destructive, login.ID)
			warn = append(warn, fmt.Sprintf("%s can lock the test account %q.", login.ID, lg.User))
		}
		reason := ""
		switch {
		case len(destructive) == 0:
		case o.authorizedHost != "": // matched the target above
			verification, confirmed = "loopback + --authorized-host", u.Host
		case stdinIsTerminal():
			fmt.Fprintf(stdout, "%s Type yes to run them: ", strings.Join(warn, " "))
			line, _ := bufio.NewReader(stdin).ReadString('\n')
			if strings.TrimSpace(line) == "yes" {
				verification, confirmed = "loopback + typed yes", u.Host
			} else {
				reason = "not confirmed: \"yes\" was not typed"
			}
		default:
			reason = fmt.Sprintf("can change data, so it needs a person's confirmation: run this command in a terminal and type yes, or pass --authorized-host %s if you (the person, not an AI assistant on its own) authorize it", u.Host)
		}
		if reason != "" {
			for _, id := range destructive {
				unavailable[id] = runner.Unavailable{Status: report.Skipped, Reason: reason}
				planned = slices.DeleteFunc(planned, func(p string) bool { return p == id })
				fmt.Fprintf(stdout, "  %-20s not run - %s\n", id, reason)
			}
		}
	}
	if len(planned) > 0 {
		if err := audit.Append(filepath.Join(dir, "audit.log"), audit.Entry{
			Time: time.Now().UTC(), Version: version, Target: u.String(), Addresses: addrStrings(addrs),
			Mode: string(mode), Verification: verification, Confirmed: confirmed, Plugins: planned,
		}); err != nil {
			return fail(fmt.Errorf("no test was sent: %w", err))
		}
		// One GET first, so a target that is down is not sent a full scan.
		cfg := egress.Config{Target: u, Addrs: addrs, VerifyTLS: o.deployed, Version: version}
		if err := reachable(ctx, cfg); err != nil {
			return fail(fmt.Errorf("%s: %w; no test was sent. Check that the app is running at this address", u, err))
		}
		needSpec := slices.ContainsFunc(selected, func(m *manifest.Manifest) bool {
			return slices.Contains(planned, m.ID) && runner.UsesOpenAPI(m)
		})
		// The access-control check adds the spec's routes when there is
		// one (ADR 0035), but runs without.
		if needSpec || slices.Contains(planned, authz.ID) {
			s, reason, failed := findSpec(ctx, cfg, src, o.deployed)
			switch {
			case s != nil:
				spec = s
				fmt.Fprintf(stdout, "OpenAPI spec: %s.\n", s.Source)
			case failed:
				fmt.Fprintf(stdout, "OpenAPI spec: %s.\n", reason)
				for _, m := range selected {
					if runner.UsesOpenAPI(m) {
						unavailable[m.ID] = runner.Unavailable{Status: report.Failed, Reason: reason}
					}
				}
			case needSpec:
				noSpec = reason
				fmt.Fprintf(stdout, "OpenAPI spec: %s; tests that need one do not run.\n", reason)
			default:
				fmt.Fprintf(stdout, "OpenAPI spec: %s.\n", reason)
			}
		}
	}
	// The login check runs first, so other tests' traffic cannot trip a
	// limit it would then report (ADR 0030).
	started := time.Now().UTC()
	var loginResult *report.PluginResult
	var loginFindings []findings.Finding
	if loginSelected {
		pr := report.PluginResult{ID: login.ID, Family: login.Family, Tool: "siegekit", Version: version}
		if r, ok := unavailable[login.ID]; ok {
			pr.Status, pr.Reason = r.Status, r.Reason
		} else {
			pr.Input = fmt.Sprintf("POST %s as %q", lg.URL, lg.User)
			fmt.Fprintf(stdout, "%s: sending %d logins, one per second.\n", login.ID, o.login.attempts)
			res, err := loginCheck(ctx, egress.Config{Target: u, Addrs: addrs, VerifyTLS: o.deployed, Version: version, ReadOnly: o.deployed}, lg, o.login.attempts)
			if ctx.Err() != nil {
				return fail(errors.New("interrupted; no report written"))
			}
			pr.Requests = res.Attempts
			if err != nil {
				pr.Status, pr.Reason = report.Failed, err.Error()
			} else {
				loginFindings = login.Findings(lg, res, o.login.attempts)
				pr.Status, pr.Result, pr.Findings = report.Ran, res.Summary(o.login.attempts), len(loginFindings)
			}
		}
		loginResult = &pr
	}
	var servedResult *report.PluginResult
	var servedFindings []findings.Finding
	if servedSelected {
		pr := report.PluginResult{ID: served.ID, Family: served.Family, Tool: gitleaks.Tool.Name, Version: gitleaks.Tool.Version}
		if r, ok := unavailable[served.ID]; ok {
			pr.Status, pr.Reason = r.Status, r.Reason
		} else {
			fmt.Fprintf(stdout, "%s: fetching the start page and the files it links.\n", served.ID)
			pr, servedFindings = runServed(ctx, ex, gitleaks, egress.Config{Target: u, Addrs: addrs, VerifyTLS: o.deployed, Version: version, ReadOnly: true}, limits.Rate, rootsIn(dir).Files, pr)
			if ctx.Err() != nil {
				return fail(errors.New("interrupted; no report written"))
			}
		}
		servedResult = &pr
	}
	var authzResult *report.PluginResult
	var authzFindings []findings.Finding
	if authzSelected {
		pr := report.PluginResult{ID: authz.ID, Family: authz.Family, Tool: "siegekit", Version: version}
		if r, ok := unavailable[authz.ID]; ok {
			pr.Status, pr.Reason = r.Status, r.Reason
		} else {
			if spec != nil {
				base, _ := openapi.BasePath(spec.Data, spec.Format)
				o.harRequests.AddSpecRoutes(authz.SpecRoutes(spec.Data, spec.Format), base)
			}
			pr.Input = fmt.Sprintf("%s, %d request(s) recorded as account A", filepath.Base(o.har), len(o.harRequests.Requests)-o.harRequests.FromSpec)
			if o.harRequests.FromSpec > 0 {
				pr.Input += fmt.Sprintf("; %d route(s) from the OpenAPI spec %s", o.harRequests.FromSpec, spec.Source)
			}
			if o.sessionB != nil {
				pr.Input += "; account B from " + authz.SessionEnv
			}
			fmt.Fprintf(stdout, "%s: replaying %d request(s).\n", authz.ID, len(o.harRequests.Requests))
			res, err := authzCheck(ctx, egress.Config{Target: u, Addrs: addrs, VerifyTLS: o.deployed, Version: version, ReadOnly: true}, o.harRequests.Requests, o.sessionB, limits.Rate)
			if ctx.Err() != nil {
				return fail(errors.New("interrupted; no report written"))
			}
			pr.Requests = res.Requests
			if err != nil {
				pr.Status, pr.Reason = report.Failed, err.Error()
			} else {
				authzFindings = authz.Findings(u.Origin(), res, o.harUser)
				pr.Status, pr.Result, pr.Findings = report.Ran, res.Summary(o.harRequests, o.harUser, authz.Count(res, o.harUser)), len(authzFindings)
			}
		}
		authzResult = &pr
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
		FilesRoot: rootsIn(dir).Files, OpenAPI: spec, NoOpenAPI: noSpec,
	})
	if errors.Is(err, context.Canceled) {
		return fail(errors.New("interrupted; no report written"))
	}
	if err != nil {
		return fail(err)
	}
	var first []report.PluginResult
	for _, pr := range []*report.PluginResult{loginResult, servedResult, authzResult} {
		if pr != nil {
			first = append(first, *pr)
		}
	}
	if len(first) > 0 {
		run.Started = started
		run.Plugins = append(first, run.Plugins...)
		if run.Findings = findings.Dedupe(slices.Concat(loginFindings, servedFindings, authzFindings, run.Findings)); run.Findings == nil {
			run.Findings = []findings.Finding{}
		}
	}
	return finish(run, o.reportDir, o.noSave, u.Host, o.threshold, o.requireAll, unavailable, stdout, stderr)
}

// servedTool is the plugin that reads the served files (ADR 0032).
const servedTool = "gitleaks"

// runServed fetches the served files into a private directory and runs
// Gitleaks over them like a source directory, then places the findings at
// the URLs the files came from (ADR 0032). cfg allows only GET and HEAD.
func runServed(ctx context.Context, ex runner.Executor, gl *manifest.Manifest, cfg egress.Config, rate float64, filesRoot string, pr report.PluginResult) (report.PluginResult, []findings.Finding) {
	failed := func(format string, a ...any) (report.PluginResult, []findings.Finding) {
		pr.Status, pr.Reason = report.Failed, fmt.Sprintf(format, a...)
		return pr, nil
	}
	pr.Input = "the start page " + cfg.Target.String() + " and the files it links"
	work, err := os.MkdirTemp("", "siegekit-served-")
	if err != nil {
		return failed("%v", err)
	}
	defer os.RemoveAll(work)
	// The tool runs as another user when SiegeKit runs as root (ADR 0021),
	// so the directory it reads must be readable by others.
	files := filepath.Join(work, "files")
	if err := os.Mkdir(files, 0o700); err != nil {
		return failed("%v", err)
	}
	if err := os.Chmod(files, 0o755); err != nil { // #nosec G302 -- read by the tool's user; the parent is private
		return failed("%v", err)
	}
	res, err := servedCollect(ctx, cfg, rate, files)
	pr.Requests = res.Requests
	if err != nil {
		return failed("%v", err)
	}
	pr.Result = res.Summary()
	run, err := runner.Run(ctx, ex, []*manifest.Manifest{gl}, runner.Options{Version: version, TargetDir: files, WorkDir: work, FilesRoot: filesRoot})
	if err != nil {
		return failed("%v", err)
	}
	tool := run.Plugins[0]
	pr.Status, pr.Reason, pr.Suppressed = tool.Status, tool.Reason, tool.Suppressed
	if tool.Status != report.Ran {
		return pr, nil
	}
	fs := served.Findings(run.Findings, res)
	pr.Findings = len(fs)
	return pr, fs
}

// authzCheck replays the HAR's requests; tests replace it.
var authzCheck = authz.Check

// readHAR reads the HAR file, refusing anything but a regular file of at
// most authz.MaxHARSize bytes.
func readHAR(name string) ([]byte, error) {
	f, err := os.Open(name) // #nosec G304 -- a file the person names on the command line
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", name)
	}
	return io.ReadAll(io.LimitReader(f, authz.MaxHARSize+1))
}

// servedCollect fetches the served files; tests replace it.
var servedCollect = served.Collect

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

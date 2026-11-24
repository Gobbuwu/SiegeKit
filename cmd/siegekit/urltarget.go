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
	"regexp"
	"runtime"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/Gobbuwu/SiegeKit/internal/audit"
	"github.com/Gobbuwu/SiegeKit/internal/authz"
	"github.com/Gobbuwu/SiegeKit/internal/backend"
	"github.com/Gobbuwu/SiegeKit/internal/checks"
	"github.com/Gobbuwu/SiegeKit/internal/coderoutes"
	"github.com/Gobbuwu/SiegeKit/internal/deps"
	"github.com/Gobbuwu/SiegeKit/internal/egress"
	"github.com/Gobbuwu/SiegeKit/internal/findings"
	"github.com/Gobbuwu/SiegeKit/internal/login"
	"github.com/Gobbuwu/SiegeKit/internal/mailcatcher"
	"github.com/Gobbuwu/SiegeKit/internal/manifest"
	"github.com/Gobbuwu/SiegeKit/internal/openapi"
	"github.com/Gobbuwu/SiegeKit/internal/publicmaps"
	"github.com/Gobbuwu/SiegeKit/internal/ratelimit"
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
	deployed        bool
	authorizedHost  string
	only, skip      []string
	threshold       findings.Severity
	reportDir       string
	noSave          bool
	consent         consent
	requireAll      bool
	requireComplete bool
	openAPI         string // --openapi: a file or a URL on the target's origin
	profile         string // --profile: full or quick
	login           loginFlags
	har, harUser    string // --har and --har-user (ADR 0035)
	replayWrites    bool   // --replay-writes (ADR 0049)
	rateLimit       rateLimitFlags
	pageFlags       map[ratelimit.Page]*pageFlag // --reset-url and the like (ADR 0055)
	mailCatcher     string                       // --mail-catcher (ADR 0056)
	backendURL      string                       // --backend-url (ADR 0037)
	storageURL      string                       // --storage-url (ADR 0058)
	source          string                       // --source: the app's repository (ADR 0037)

	// Read from --har, SIEGEKIT_SESSION_B and SIEGEKIT_SESSION_C before
	// any request.
	harRequests *authz.HAR
	sessionB    http.Header
	sessionC    http.Header   // an account outside A's shared spaces (ADR 0051)
	writes      *authz.Writes // read only with --replay-writes
	// Read from --rate-limit-url and --rate-limit-body before any request.
	rateEndpoint *ratelimit.Endpoint
	// Read from the page flags, else from --har, before any request.
	pageEndpoints map[ratelimit.Page]*ratelimit.Endpoint
	harPages      ratelimit.HARPages
	// Read from --mail-catcher before any request; opened when a reset or
	// sign-up check will run.
	catcherURL *target.URL
	catcher    *mailcatcher.Catcher
	// Read from --backend-url and --source before any request.
	backend *backend.Backend
	storage *backend.Storage
	repo    *checks.Source
	// Read from --source on local targets: the routes of the app's
	// server code, for the route sweep (ADR 0053).
	code    *coderoutes.Result
	codeErr error
	// in reads every typed answer, so one prompt cannot swallow the next.
	in *bufio.Reader
}

// rateLimitFlags are the --rate-limit flags of the rate-limit check
// (ADR 0036).
type rateLimitFlags struct {
	url, body string
	requests  int
}

// check accepts --rate-limit-body and --rate-limit-requests only with
// --rate-limit-url.
func (f rateLimitFlags) check(requestsSet bool) error {
	switch {
	case f.url == "" && (f.body != "" || requestsSet):
		return errors.New("--rate-limit-body and --rate-limit-requests need --rate-limit-url")
	case f.requests < ratelimit.MinRequests || f.requests > ratelimit.MaxRequests:
		return fmt.Errorf("--rate-limit-requests must be from %d to %d", ratelimit.MinRequests, ratelimit.MaxRequests)
	}
	return nil
}

// rateLimitCheck runs the rate-limit check and the page checks; tests
// replace it.
var rateLimitCheck = ratelimit.Check

// pageFlag is a page's URL and body flags, such as --reset-url and
// --reset-body (ADR 0055).
type pageFlag struct{ url, body string }

// pageReason says why a page check has no page to test.
func (o urlScan) pageReason(p ratelimit.Page) string {
	flags := fmt.Sprintf("pass %s and --%s-body", p.Flag(), p)
	switch {
	case o.harPages.Unusable[p] != "":
		return fmt.Sprintf("the %s recorded in %s cannot be tested (%s); %s", p.What(), filepath.Base(o.har), o.harPages.Unusable[p], flags)
	case o.har != "":
		return fmt.Sprintf("no %s was given or found in %s: %s, or use that page while recording", p.What(), filepath.Base(o.har), flags)
	}
	return fmt.Sprintf("no %s was given: %s, or --har with a recording that uses it", p.What(), flags)
}

// pageInput says which page a check tested and where it came from.
func pageInput(e *ratelimit.Endpoint) string {
	if strings.HasPrefix(e.From, "--") {
		return fmt.Sprintf("POST %s (from %s)", e.URL, e.From)
	}
	return fmt.Sprintf("POST %s (recorded in %s)", e.URL, e.From)
}

// pageMade says what a page check's requests may have made, so the person
// knows what to clean up (design safety rule 6).
func pageMade(p ratelimit.Page, r ratelimit.Result) string {
	switch {
	case r.Accepted == 0:
		return ""
	case p == ratelimit.SignUp:
		return fmt.Sprintf("; %d answered below 400, so up to %d accounts were made, named siegekit-new-...", r.Accepted, r.Accepted)
	case p == ratelimit.Reset && r.Mail == nil:
		return fmt.Sprintf("; %d answered below 400, so the app may have sent up to %d emails or texts", r.Accepted, r.Accepted)
	}
	return ""
}

// openCatcher opens the mail catcher; tests replace it.
var openCatcher = mailcatcher.Open

// sprayCheck runs the spraying check; tests replace it.
var sprayCheck = login.Spray

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
	o.in = bufio.NewReader(stdin)
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
	// So is the rate-limit URL (ADR 0036).
	if o.rateLimit.url != "" {
		if o.rateEndpoint, err = ratelimit.Parse(o.rateLimit.url, o.rateLimit.body, u); err != nil {
			return refuse("%v", err)
		}
	}
	// So are the reset, sign-up and code pages (ADR 0055).
	o.pageEndpoints = map[ratelimit.Page]*ratelimit.Endpoint{}
	for _, p := range ratelimit.Pages {
		if f := o.pageFlags[p]; f != nil && f.url != "" {
			if o.pageEndpoints[p], err = ratelimit.ParsePage(p, f.url, f.body, u); err != nil {
				return refuse("%v", err)
			}
		}
	}
	// So is the mail catcher (ADR 0056).
	if o.mailCatcher != "" {
		if o.catcherURL, err = mailcatcher.Parse(o.mailCatcher); err != nil {
			return refuse("%v", err)
		}
	}
	// So are the backend URL and the repository (ADR 0037).
	if o.backendURL != "" {
		if o.backend, err = backend.Parse(o.backendURL); err != nil {
			return refuse("%v", err)
		}
	}
	if o.storageURL != "" {
		if o.storage, err = backend.ParseStorage(o.storageURL); err != nil {
			return refuse("%v", err)
		}
	}
	if o.source != "" {
		var repoSpec *openapi.Spec
		if o.repo, repoSpec, err = readSource(o.source); err != nil {
			return refuse("--source: %v", err)
		}
		spec.repo = repoSpec
		if !o.deployed {
			r, err := coderoutes.FromPath(o.source)
			o.code, o.codeErr = &r, err
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
		// A page given by its flags wins over the recorded one.
		if o.harPages, err = ratelimit.PagesFromHAR(data, u, filepath.Base(o.har)); err != nil {
			return refuse("--har: %v", err)
		}
		for p, e := range o.harPages.Pages {
			if o.pageEndpoints[p] == nil {
				o.pageEndpoints[p] = e
			}
		}
		if o.replayWrites {
			if o.writes, err = authz.ParseWrites(data, u); err != nil {
				return refuse("--har: %v", err)
			}
		}
		if s, ok := os.LookupEnv(authz.SessionEnv); ok {
			if o.sessionB, err = authz.ParseSession(s); err != nil {
				return refuse("%v", err)
			}
		}
		if s, ok := os.LookupEnv(authz.SessionEnvC); ok {
			if o.sessionC, err = authz.ParseSessionFrom(authz.SessionEnvC, s); err != nil {
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
			line, _ := o.in.ReadString('\n')
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
	repo *openapi.Spec // the first spec in --source (ADR 0037)
}

// openAPISource reads a spec file, or checks that a spec URL is on the
// target's origin: SiegeKit sends requests only to the target (ADR 0005).
func openAPISource(arg string, u *target.URL) (specSource, error) {
	if isURL(arg) {
		su, _, err := target.OnOrigin(u, arg, "--openapi", false)
		if err != nil {
			return specSource{}, fmt.Errorf("%w; to use another spec, download it and pass the file", err)
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
// ADR 0028): the --openapi file, the --openapi URL, the first spec in
// --source (ADR 0037), or on local targets the first valid spec that probe
// finds at publicmaps.Paths (ADR 0046). It returns nil and the reason
// when there is none; failed is true when the spec the user named could
// not be used.
func findSpec(ctx context.Context, cfg egress.Config, src specSource, deployed bool, probe func() (publicmaps.Probe, error)) (spec *openapi.Spec, reason string, failed bool) {
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
	if src.repo != nil {
		return src.repo, "", false
	}
	if deployed {
		return nil, "no OpenAPI spec was given with --openapi (SiegeKit looks for one only on local targets)", false
	}
	p, err := probe()
	if err != nil {
		return nil, err.Error(), true
	}
	if s := p.First(); s != nil {
		return s, "", false
	}
	return nil, fmt.Sprintf("no OpenAPI spec was given with --openapi and none was found at %s", strings.Join(publicmaps.Paths(), ", ")), false
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
		{ID: login.SprayID, Name: login.SprayName, Family: login.Family, Targets: []string{"url"}},
		{ID: ratelimit.ID, Name: ratelimit.Name, Family: ratelimit.Family, Targets: []string{"url"}},
		{ID: ratelimit.ResetID, Name: ratelimit.Reset.Name(), Family: ratelimit.Family, Targets: []string{"url"}},
		{ID: ratelimit.SignUpID, Name: ratelimit.SignUp.Name(), Family: ratelimit.Family, Targets: []string{"url"}},
		{ID: ratelimit.CodeID, Name: ratelimit.Code.Name(), Family: ratelimit.Family, Targets: []string{"url"}},
		{ID: served.ID, Name: served.Name, Family: served.Family, Targets: []string{"url"}},
		{ID: publicmaps.ID, Name: publicmaps.Name, Family: publicmaps.Family, Targets: []string{"url"}},
		{ID: backend.ID, Name: backend.Name, Family: backend.Family, Targets: []string{"url"}},
		{ID: backend.StorageID, Name: backend.StorageName, Family: backend.StorageFamily, Targets: []string{"url"}},
		{ID: authz.ID, Name: authz.Name, Family: authz.Family, Targets: []string{"url"}},
		{ID: authz.WriteID, Name: authz.WriteName, Family: authz.Family, Targets: []string{"url"}},
	}, "url", o.only, o.skip)
	if err != nil {
		return fail(err)
	}
	ownSelected := func(id string) bool {
		return slices.ContainsFunc(own, func(c checks.Check) bool { return c.ID == id })
	}
	loginSelected, servedSelected, authzSelected := ownSelected(login.ID), ownSelected(served.ID), ownSelected(authz.ID)
	writeSelected := ownSelected(authz.WriteID)
	rateSelected, backendSelected, mapsSelected := ownSelected(ratelimit.ID), ownSelected(backend.ID), ownSelected(publicmaps.ID)
	spraySelected, storageSelected := ownSelected(login.SprayID), ownSelected(backend.StorageID)
	pageSelected := map[ratelimit.Page]bool{}
	for _, p := range ratelimit.Pages {
		pageSelected[p] = ownSelected(p.ID())
	}
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
	for _, id := range []string{login.ID, login.SprayID, ratelimit.ID, ratelimit.ResetID, ratelimit.SignUpID, ratelimit.CodeID, authz.WriteID, backend.StorageID} {
		if ownSelected(id) && runner.ProfileSkip(true, o.profile) != "" && slices.Contains(o.only, id) {
			return fail(fmt.Errorf("--only names %s, which --profile %s does not run", id, o.profile))
		}
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
			unavailable[m.ID] = runner.Skip(runner.SkipCause(m), r)
		case runner.ProfileReason(m, o.profile) != "":
			unavailable[m.ID] = runner.Skip(report.CauseProfile, runner.ProfileReason(m, o.profile))
		case hostOS != "linux":
			unavailable[m.ID] = runner.Fail(report.CausePlatform, "active tests run only on Linux for now (ADR 0018)")
		default:
			runnable = append(runnable, m)
		}
	}
	if servedSelected && hostOS != "linux" {
		unavailable[served.ID] = runner.Fail(report.CausePlatform, "active tests run only on Linux for now (ADR 0018)")
	}
	if mapsSelected && hostOS != "linux" {
		unavailable[publicmaps.ID] = runner.Fail(report.CausePlatform, "active tests run only on Linux for now (ADR 0018)")
	}
	// Active plugins need no tool data, but some need pinned files. The
	// served-secrets check needs the Gitleaks image.
	toPrepare := runnable
	if servedSelected && hostOS == "linux" {
		toPrepare = append(slices.Clip(runnable), gitleaks)
	}
	ex, un, _, _, err := prepare(ctx, toPrepare, deps.Roots{Files: rootsIn(dir).Files}, o.consent, stdout)
	if err != nil {
		return fail(err)
	}
	env := runner.Environment(ctx, ex)
	fmt.Fprintf(stdout, "Environment: %s\n", env)
	if u, ok := un[servedTool]; ok {
		unavailable[served.ID] = u
		delete(un, servedTool)
	}
	maps.Copy(unavailable, un)
	if loginSelected {
		switch {
		case o.deployed:
			unavailable[login.ID] = runner.Skip(report.CauseTargetMode, "runs only on local targets: deployed targets get only GET and HEAD requests until request limits are measured (M2.10)")
		case runner.ProfileSkip(true, o.profile) != "":
			unavailable[login.ID] = runner.Skip(report.CauseProfile, runner.ProfileSkip(true, o.profile))
		case lg == nil:
			unavailable[login.ID] = runner.Skip(report.CauseNoInput, "no login was given: pass --login-url, --login-user and --login-body to test whether failed logins are limited")
		case hostOS != "linux":
			unavailable[login.ID] = runner.Fail(report.CausePlatform, "active tests run only on Linux for now (ADR 0018)")
		}
	}
	if rateSelected {
		switch {
		case o.deployed:
			unavailable[ratelimit.ID] = runner.Skip(report.CauseTargetMode, "runs only on local targets until request limits are measured (M2.10)")
		case runner.ProfileSkip(true, o.profile) != "":
			unavailable[ratelimit.ID] = runner.Skip(report.CauseProfile, runner.ProfileSkip(true, o.profile))
		case o.rateEndpoint == nil:
			unavailable[ratelimit.ID] = runner.Skip(report.CauseNoInput, "no URL was given: pass --rate-limit-url (an expensive URL such as a search) to test whether its requests are limited")
		case hostOS != "linux":
			unavailable[ratelimit.ID] = runner.Fail(report.CausePlatform, "active tests run only on Linux for now (ADR 0018)")
		}
	}
	// Spraying runs only after login-throttle, on the same login
	// (ADR 0055 item 6).
	if spraySelected {
		_, loginOff := unavailable[login.ID]
		switch {
		case o.deployed:
			unavailable[login.SprayID] = runner.Skip(report.CauseTargetMode, "runs only on local targets: deployed targets get only GET and HEAD requests until request limits are measured (M2.10)")
		case runner.ProfileSkip(true, o.profile) != "":
			unavailable[login.SprayID] = runner.Skip(report.CauseProfile, runner.ProfileSkip(true, o.profile))
		case lg == nil:
			unavailable[login.SprayID] = runner.Skip(report.CauseNoInput, "no login was given: pass --login-url, --login-user and --login-body; spraying runs when login-throttle sees a limit on that account")
		case !loginSelected || loginOff:
			unavailable[login.SprayID] = runner.Skip(report.CauseNoInput, "runs only after login-throttle sees a limit on one account, and login-throttle does not run")
		case hostOS != "linux":
			unavailable[login.SprayID] = runner.Fail(report.CausePlatform, "active tests run only on Linux for now (ADR 0018)")
		}
	}
	for _, p := range ratelimit.Pages {
		if !pageSelected[p] {
			continue
		}
		switch {
		case o.deployed:
			unavailable[p.ID()] = runner.Skip(report.CauseTargetMode, "runs only on local targets until request limits are measured (M2.10)")
		case runner.ProfileSkip(true, o.profile) != "":
			unavailable[p.ID()] = runner.Skip(report.CauseProfile, runner.ProfileSkip(true, o.profile))
		case o.pageEndpoints[p] == nil:
			unavailable[p.ID()] = runner.Skip(report.CauseNoInput, o.pageReason(p))
		case hostOS != "linux":
			unavailable[p.ID()] = runner.Fail(report.CausePlatform, "active tests run only on Linux for now (ADR 0018)")
		}
	}
	// The mail catcher is opened (one GET of Mailpit's version) only when
	// a reset or sign-up check will run; one that does not answer fails
	// them before they send anything (ADR 0056 item 2).
	if o.catcherURL != nil {
		var mailPages []ratelimit.Page
		for _, p := range []ratelimit.Page{ratelimit.Reset, ratelimit.SignUp} {
			if _, off := unavailable[p.ID()]; pageSelected[p] && !off {
				mailPages = append(mailPages, p)
			}
		}
		if len(mailPages) > 0 {
			rctx, cancel := context.WithTimeout(ctx, 15*time.Second)
			c, err := openCatcher(rctx, resolver, o.catcherURL, version)
			cancel()
			if err != nil {
				for _, p := range mailPages {
					unavailable[p.ID()] = runner.Fail("", fmt.Sprintf("%v; no request was sent to the %s", err, p.What()))
				}
			}
			o.catcher = c
		}
	}
	var bp *backendPlan
	if backendSelected {
		switch {
		case o.backend == nil:
			unavailable[backend.ID] = runner.Skip(report.CauseNoInput, "no backend URL was given: pass --backend-url (the Supabase or Firebase Realtime Database URL the app reads from the browser) to test whether its data can be read with the app's public key")
		case hostOS != "linux":
			unavailable[backend.ID] = runner.Fail(report.CausePlatform, "active tests run only on Linux for now (ADR 0018)")
		default:
			rctx, cancel := context.WithTimeout(ctx, 15*time.Second)
			p, reason := planBackend(rctx, o.backend, mode)
			cancel()
			if reason != "" {
				unavailable[backend.ID] = runner.Fail("", reason)
			}
			bp = p
		}
	}
	// The storage write test uploads files: local targets only (the
	// --deployed refusal is in scan.go), off unless asked for, and left out
	// of --profile quick (ADR 0058 items 1 and 2).
	var sp *storagePlan
	if storageSelected {
		switch {
		case runner.ProfileSkip(true, o.profile) != "":
			unavailable[backend.StorageID] = runner.Skip(report.CauseProfile, runner.ProfileSkip(true, o.profile))
		case o.storage == nil:
			unavailable[backend.StorageID] = runner.Skip(report.CauseNoInput, "off unless asked for, because it uploads files: pass --storage-url (the Supabase project URL, or https://firebasestorage.googleapis.com or a local emulator for Firebase) to test whether anyone can upload to the app's storage buckets")
		case hostOS != "linux":
			unavailable[backend.StorageID] = runner.Fail(report.CausePlatform, "active tests run only on Linux for now (ADR 0018)")
		default:
			rctx, cancel := context.WithTimeout(ctx, 15*time.Second)
			h, reason := planHost(rctx, o.storage.URL, o.storage.URL.Origin(), "storage", mode)
			cancel()
			if reason != "" {
				unavailable[backend.StorageID] = runner.Fail("", reason)
			} else {
				sp = &storagePlan{s: o.storage, host: h}
			}
		}
	}
	if authzSelected {
		switch {
		case o.harRequests == nil:
			unavailable[authz.ID] = runner.Skip(report.CauseNoInput, "no HAR file was given: pass --har (a browser recording made as test account A) and set "+authz.SessionEnv+" and "+authz.SessionEnvC+" to accounts B's and C's session headers to test access between accounts")
		case len(o.harRequests.Requests) == 0:
			unavailable[authz.ID] = runner.Skip(report.CauseNoInput, fmt.Sprintf("%s has no GET or HEAD request to replay (%d naming an action left out, ADR 0048); its %d request(s) go to zap-active (ADR 0047)", filepath.Base(o.har), o.harRequests.Action, len(o.harRequests.Recorded)))
		case hostOS != "linux":
			unavailable[authz.ID] = runner.Fail(report.CausePlatform, "active tests run only on Linux for now (ADR 0018)")
		}
	}
	// Write replay changes data: local only, off unless asked for, and
	// left out of --profile quick (ADR 0049 items 1 and 2).
	if writeSelected {
		switch {
		case o.deployed:
			unavailable[authz.WriteID] = runner.Skip(report.CauseTargetMode, "changes data, so it runs only on local targets")
		case runner.ProfileSkip(true, o.profile) != "":
			unavailable[authz.WriteID] = runner.Skip(report.CauseProfile, runner.ProfileSkip(true, o.profile))
		case !o.replayWrites:
			unavailable[authz.WriteID] = runner.Skip(report.CauseNoInput, "off unless asked for, because it changes data: pass --replay-writes with --har (recorded as test account A) to replay its POST, PUT, PATCH and DELETE requests as account B and with no login")
		case len(o.writes.Writes) == 0:
			unavailable[authz.WriteID] = runner.Skip(report.CauseNoInput, fmt.Sprintf("%s has no POST, PUT, PATCH or DELETE request to replay (%d could log in, log out or lock an account out and are never replayed)", filepath.Base(o.har), o.writes.Lockout))
		case hostOS != "linux":
			unavailable[authz.WriteID] = runner.Fail(report.CausePlatform, "active tests run only on Linux for now (ADR 0018)")
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
	if rateSelected {
		if r, ok := unavailable[ratelimit.ID]; ok {
			fmt.Fprintf(stdout, "  %-20s not run - %s\n", ratelimit.ID, r.Reason)
		} else {
			planned = append(planned, ratelimit.ID)
			fmt.Fprintf(stdout, "  %-20s siegekit %s: up to %d requests %s %s, one per second, stopping at the first sign of a limit\n",
				ratelimit.ID, version, o.rateLimit.requests, o.rateEndpoint.Method, o.rateEndpoint.URL)
		}
	}
	if spraySelected {
		if r, ok := unavailable[login.SprayID]; ok {
			fmt.Fprintf(stdout, "  %-20s not run - %s\n", login.SprayID, r.Reason)
		} else {
			planned = append(planned, login.SprayID)
			fmt.Fprintf(stdout, "  %-20s siegekit %s: only if login-throttle sees a limit, %d logins for invented user names (%s and on) with one wrong password, POST %s, one per second\n",
				login.SprayID, version, o.login.attempts, login.SprayUser(lg, 1), lg.URL)
		}
	}
	for _, p := range ratelimit.Pages {
		if !pageSelected[p] {
			continue
		}
		if r, ok := unavailable[p.ID()]; ok {
			fmt.Fprintf(stdout, "  %-20s not run - %s\n", p.ID(), r.Reason)
			continue
		}
		planned = append(planned, p.ID())
		e := o.pageEndpoints[p]
		what := map[ratelimit.Page]string{ratelimit.Reset: "with wrong answers", ratelimit.SignUp: "each with a new user name (siegekit-new-...)", ratelimit.Code: "with wrong codes"}[p]
		fmt.Fprintf(stdout, "  %-20s siegekit %s: up to %d requests %s, %s, one per second, stopping at the first sign of a limit\n",
			p.ID(), version, ratelimit.DefaultRequests, pageInput(e), what)
		if o.catcher != nil && p != ratelimit.Code {
			fmt.Fprintf(stdout, "  %-20s then counts the emails that arrive at %s, waiting up to %s\n", "", o.catcher, mailcatcher.Max)
		}
		if n := o.harPages.More[p]; n > 0 && !strings.HasPrefix(e.From, "--") {
			fmt.Fprintf(stdout, "  %-20s only the first of the %d %ss recorded is tested\n", "", n+1, p.What())
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
	if mapsSelected {
		if r, ok := unavailable[publicmaps.ID]; ok {
			fmt.Fprintf(stdout, "  %-20s not run - %s\n", publicmaps.ID, r.Reason)
		} else {
			planned = append(planned, publicmaps.ID)
			fmt.Fprintf(stdout, "  %-20s siegekit %s: GET %d paths where API specs are often served, and the source maps of the start page's scripts and styles; report each one served\n",
				publicmaps.ID, version, len(publicmaps.Paths()))
		}
	}
	if backendSelected {
		if r, ok := unavailable[backend.ID]; ok {
			fmt.Fprintf(stdout, "  %-20s not run - %s\n", backend.ID, r.Reason)
		} else {
			planned = append(planned, backend.ID)
			from := "table or path names from the app's scripts"
			if o.repo != nil {
				from += " and " + o.source
			}
			how := "with the app's own public key for Supabase, with no login for Firebase"
			switch o.backend.Kind {
			case backend.Supabase:
				how = "with the app's own public key"
			case backend.Firebase:
				how = "with no login"
			}
			fmt.Fprintf(stdout, "  %-20s siegekit %s: one GET (at most one row) per table or path at %s (%s), %s; %s\n",
				backend.ID, version, o.backend, joinList(bp.addrs), how, from)
		}
	}
	if storageSelected {
		if r, ok := unavailable[backend.StorageID]; ok {
			fmt.Fprintf(stdout, "  %-20s not run - %s\n", backend.StorageID, r.Reason)
		} else {
			planned = append(planned, backend.StorageID)
			fmt.Fprintf(stdout, "  %-20s siegekit %s: upload one %d-byte text file to the root of each bucket and to folders named in the app's scripts at %s (%s), read it back and delete it, at most %d files; lists them and asks before the first upload\n",
				backend.StorageID, version, len(backend.TestContent), o.storage.URL.Origin(), joinList(sp.host.addrs), backend.MaxFiles)
		}
	}
	if authzSelected {
		if r, ok := unavailable[authz.ID]; ok {
			fmt.Fprintf(stdout, "  %-20s not run - %s\n", authz.ID, r.Reason)
		} else {
			planned = append(planned, authz.ID)
			who := "as account A, " + o.otherAccounts() + "with no login"
			if o.otherAccounts() == "" {
				who = "as account A and with no login"
			}
			if note := o.accountsNotTested(); note != "" {
				who += " (" + note + ")"
			}
			fmt.Fprintf(stdout, "  %-20s siegekit %s: replay %d GET and HEAD request(s) from %s %s\n",
				authz.ID, version, len(o.harRequests.Requests), filepath.Base(o.har), who)
			if !o.deployed {
				fmt.Fprintf(stdout, "  %-20s and every GET route of the OpenAPI spec, if one is given or found, filled with IDs from %s (at most %d, ADR 0052)\n",
					"", filepath.Base(o.har), authz.MaxSweep)
				if routes := o.codeRoutes(); len(routes) > 0 {
					fmt.Fprintf(stdout, "  %-20s and the %d GET route(s) found in the server code in %s, filled the same way (ADR 0053)\n",
						"", len(routes), o.source)
				}
			}
		}
	}
	if writeSelected {
		if r, ok := unavailable[authz.WriteID]; ok {
			fmt.Fprintf(stdout, "  %-20s not run - %s\n", authz.WriteID, r.Reason)
		} else {
			planned = append(planned, authz.WriteID)
			who := o.writeSenders()
			if note := o.accountsNotTested(); note != "" {
				who += " (" + note + ")"
			}
			recorded, tried := o.writes.Recorded()
			fmt.Fprintf(stdout, "  %-20s siegekit %s: replay %d POST, PUT, PATCH and DELETE request(s) from %s, and try %d PUT, PATCH or DELETE request(s) it did not make on account A's objects, %s, each on a copy of account A's object where the recording shows how A made it; this changes data\n",
				authz.WriteID, version, recorded, filepath.Base(o.har), tried, who)
		}
	}
	reach := strings.TrimSuffix(u.String(), u.Path)
	if slices.Contains(planned, backend.ID) {
		reach += " (and " + o.backend.URL.Origin() + " for backend-live)"
	}
	if slices.Contains(planned, backend.StorageID) {
		reach += " (and " + o.storage.URL.Origin() + " for storage-write)"
	}
	fmt.Fprintf(stdout, "Limits: at most %.0f requests per second, stop after %d server errors in a row; only %s is reachable, and every request is labeled \"SiegeKit/%s\".\n",
		limits.Rate, limits.MaxServerErrors, reach, version)
	if mode == "deployed" {
		fmt.Fprintln(stdout, "Only GET and HEAD requests are allowed. Some apps change data on a GET, so prefer a staging copy (ADR 0048).")
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
		// A POST can create data each time it is sent (ADR 0036).
		if slices.Contains(planned, ratelimit.ID) && o.rateEndpoint.Method != http.MethodGet {
			destructive = append(destructive, ratelimit.ID)
			warn = append(warn, fmt.Sprintf("%s sends up to %d POST requests to %s, which can change data.", ratelimit.ID, o.rateLimit.requests, o.rateEndpoint.URL))
		}
		// The page checks make accounts and can send real emails or
		// texts, and spraying sends logins (ADR 0055 item 8).
		if slices.Contains(planned, login.SprayID) {
			destructive = append(destructive, login.SprayID)
			warn = append(warn, fmt.Sprintf("%s may send up to %d logins for invented user names.", login.SprayID, o.login.attempts))
		}
		for _, p := range ratelimit.Pages {
			if !slices.Contains(planned, p.ID()) {
				continue
			}
			destructive = append(destructive, p.ID())
			n, to := ratelimit.DefaultRequests, o.pageEndpoints[p].URL
			switch p {
			case ratelimit.Reset:
				warn = append(warn, fmt.Sprintf("%s sends up to %d password-reset requests to %s, so the app may send up to %d emails or texts to the address in them.", p.ID(), n, to, n))
			case ratelimit.SignUp:
				warn = append(warn, fmt.Sprintf("%s creates up to %d accounts at %s and may send up to %d emails or texts.", p.ID(), n, to, n))
			case ratelimit.Code:
				warn = append(warn, fmt.Sprintf("%s sends up to %d wrong codes to %s.", p.ID(), n, to))
			}
		}
		reason := ""
		switch {
		case len(destructive) == 0:
		case o.authorizedHost != "": // matched the target above
			verification, confirmed = "loopback + --authorized-host", u.Host
		case stdinIsTerminal():
			fmt.Fprintf(stdout, "%s Type yes to run them: ", strings.Join(warn, " "))
			line, _ := o.in.ReadString('\n')
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
				unavailable[id] = runner.Skip(report.CauseNotConfirmed, reason)
				planned = slices.DeleteFunc(planned, func(p string) bool { return p == id })
				fmt.Fprintf(stdout, "  %-20s not run - %s\n", id, reason)
			}
		}
	}
	// A backend that is not on this machine is someone's hosted service:
	// the person types its host name, and no flag skips that (answer 2a).
	backendVerification, backendConfirmed := "loopback", ""
	if slices.Contains(planned, backend.ID) && bp.remote {
		reason := ""
		switch {
		case stdinIsTerminal():
			fmt.Fprintf(stdout, "%s reads data from %s, which is not on this machine. Type its host name (%s) to confirm it is this app's backend and you may test it: ", backend.ID, o.backend, o.backend.URL.Host)
			line, _ := o.in.ReadString('\n')
			if target.Confirmed(o.backend.URL, line) {
				backendVerification, backendConfirmed = "typed backend host", o.backend.URL.Host
			} else {
				reason = fmt.Sprintf("the typed host name did not match %q", o.backend.URL.Host)
			}
		default:
			reason = fmt.Sprintf("the backend %s is not on this machine, so a person must type its host name in a terminal; run this command yourself (an AI assistant should ask you to). No flag skips this", o.backend.URL.Host)
		}
		if reason != "" {
			unavailable[backend.ID] = runner.Skip(report.CauseNotConfirmed, reason)
			planned = slices.DeleteFunc(planned, func(p string) bool { return p == backend.ID })
			fmt.Fprintf(stdout, "  %-20s not run - %s\n", backend.ID, reason)
		}
	}
	// The access-control check replays account A's session and uses account
	// B's, and zap-active attacks the HAR file's requests with A's
	// session (ADR 0047), so a person types that they are test accounts
	// (owner Q5, 2026-11-21, ADR 0035). No flag or environment variable
	// skips this: an AI assistant cannot confirm it for the person.
	authzPlanned := slices.Contains(planned, authz.ID)
	writePlanned := slices.Contains(planned, authz.WriteID)
	recordedPlanned := slices.Contains(planned, zapActive) && o.harRequests != nil && len(o.harRequests.Recorded) > 0
	var recordedRequests []authz.RecordedRequest
	if authzPlanned || writePlanned || recordedPlanned {
		accounts := "account A (the HAR file's session)"
		if authzPlanned || writePlanned {
			switch {
			case o.sessionB != nil && o.sessionC != nil:
				accounts = "accounts A (the HAR file's session), B (" + authz.SessionEnv + ") and C (" + authz.SessionEnvC + ")"
			case o.sessionB != nil:
				accounts = "accounts A (the HAR file's session) and B (" + authz.SessionEnv + ")"
			case o.sessionC != nil:
				accounts = "accounts A (the HAR file's session) and C (" + authz.SessionEnvC + ")"
			}
		}
		var who []string
		if authzPlanned {
			who = append(who, authz.ID+" replays requests")
		}
		if writePlanned {
			who = append(who, authz.WriteID+" replays writes")
		}
		if recordedPlanned {
			who = append(who, fmt.Sprintf("%s attacks %d recorded request(s)", zapActive, len(o.harRequests.Recorded)))
		}
		reason := ""
		switch {
		case stdinIsTerminal():
			fmt.Fprintf(stdout, "%s with the sessions of %s. Type %q to confirm they are test accounts you own, not a real person's: ", strings.Join(who, ", and "), accounts, testAccounts)
			line, _ := o.in.ReadString('\n')
			if strings.TrimSpace(line) != testAccounts {
				reason = fmt.Sprintf("not confirmed: %q was not typed", testAccounts)
			}
		default:
			reason = "it replays account sessions, so a person must type in a terminal that they are test accounts; run this command yourself (an AI assistant should ask you to). No flag skips this"
		}
		switch {
		case reason == "" && recordedPlanned:
			recordedRequests = o.harRequests.Recorded
		case reason != "" && recordedPlanned:
			fmt.Fprintf(stdout, "  %-20s runs without the recorded requests - %s\n", zapActive, reason)
		}
		if reason != "" {
			for _, id := range []string{authz.ID, authz.WriteID} {
				if slices.Contains(planned, id) {
					unavailable[id] = runner.Skip(report.CauseNotConfirmed, reason)
					planned = slices.DeleteFunc(planned, func(p string) bool { return p == id })
					fmt.Fprintf(stdout, "  %-20s not run - %s\n", id, reason)
				}
			}
		}
	}
	// Write replay changes data, so after "test accounts" the person reads
	// the writes and types a second phrase (ADR 0049 item 3). No flag or
	// environment variable skips it; a program that drives a
	// pseudo-terminal can type it (ADR 0044).
	if slices.Contains(planned, authz.WriteID) {
		reason := ""
		switch {
		case stdinIsTerminal():
			fmt.Fprintf(stdout, "%s will send these %d request(s) to %s:\n", authz.WriteID, len(o.writes.Writes), u)
			for _, w := range o.writes.Writes {
				note := ""
				if w.Tried {
					note = " (not in the recording)"
				}
				if len(w.Steps) > 0 {
					note += fmt.Sprintf(" (account A first sends %d of its earlier writes again)", len(w.Steps))
				}
				fmt.Fprintf(stdout, "  %s%s\n", w.Label(), note)
			}
			fmt.Fprintf(stdout, "Each is sent %s; where the recording shows how account A made the object, SiegeKit first makes a copy with A's request. Only what the recording did is tested, plus PUT, PATCH and DELETE on A's objects: record every kind of change the app has (create, edit and delete each kind of object, send each form, finish a purchase). This changes data in the app: use a throwaway database or a snapshot. Type %q to run them: ", o.writeSenders(), changeTestData)
			line, _ := o.in.ReadString('\n')
			if strings.TrimSpace(line) != changeTestData {
				reason = fmt.Sprintf("not confirmed: %q was not typed", changeTestData)
			}
		default:
			reason = fmt.Sprintf("it changes data in the app, so a person must type %q in a terminal; run this command yourself (an AI assistant should ask you to). No flag skips this", changeTestData)
		}
		if reason != "" {
			unavailable[authz.WriteID] = runner.Skip(report.CauseNotConfirmed, reason)
			planned = slices.DeleteFunc(planned, func(p string) bool { return p == authz.WriteID })
			fmt.Fprintf(stdout, "  %-20s not run - %s\n", authz.WriteID, reason)
		}
	}
	// The spec paths are probed once, for the checks that use a spec
	// and for public-maps (ADR 0046).
	var probe *publicmaps.Probe
	var probeErr error
	probeSpecs := func() (publicmaps.Probe, error) {
		if probe == nil {
			p, err := publicmaps.ProbeSpecs(ctx, specGet, egress.Config{Target: u, Addrs: addrs, VerifyTLS: o.deployed, Version: version, ReadOnly: true}, limits.Rate)
			probe, probeErr = &p, err
		}
		return *probe, probeErr
	}
	if len(planned) > 0 {
		if err := audit.Append(filepath.Join(dir, "audit.log"), audit.Entry{
			Time: time.Now().UTC(), Version: version, Target: u.String(), Addresses: addrStrings(addrs),
			Mode: string(mode), Verification: verification, Confirmed: confirmed, Plugins: planned, Environment: env.String(),
		}); err != nil {
			return fail(fmt.Errorf("no test was sent: %w", err))
		}
		// The backend is another host, so it gets its own entry (ADR 0037).
		if slices.Contains(planned, backend.ID) {
			if err := audit.Append(filepath.Join(dir, "audit.log"), audit.Entry{
				Time: time.Now().UTC(), Version: version, Target: o.backend.String(), Addresses: addrStrings(bp.addrs),
				Mode: string(mode), Verification: backendVerification, Confirmed: backendConfirmed, Plugins: []string{backend.ID}, Environment: env.String(),
			}); err != nil {
				return fail(fmt.Errorf("no test was sent: %w", err))
			}
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
			s, reason, failed := findSpec(ctx, cfg, src, o.deployed, probeSpecs)
			switch {
			case s != nil:
				spec = s
				fmt.Fprintf(stdout, "OpenAPI spec: %s.\n", s.Source)
			case failed:
				fmt.Fprintf(stdout, "OpenAPI spec: %s.\n", reason)
				for _, m := range selected {
					if runner.UsesOpenAPI(m) {
						unavailable[m.ID] = runner.Fail("", reason)
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
	loginLimited := false
	if loginSelected {
		pr := report.PluginResult{ID: login.ID, Family: login.Family, Tool: "siegekit", Version: version}
		if r, ok := unavailable[login.ID]; ok {
			pr.Status, pr.Cause, pr.Reason = r.Status, r.Cause, r.Reason
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
				loginLimited = res.Limited
				pr.Status, pr.Result, pr.Findings = report.Ran, res.Summary(o.login.attempts), len(loginFindings)
			}
		}
		loginResult = &pr
	}
	// Spraying runs right after, and only when login-throttle saw a
	// limit on one account (ADR 0055 item 6).
	var sprayResult *report.PluginResult
	var sprayFindings []findings.Finding
	if spraySelected {
		pr := report.PluginResult{ID: login.SprayID, Family: login.Family, Tool: "siegekit", Version: version}
		r, off := unavailable[login.SprayID]
		switch {
		case off:
			pr.Status, pr.Cause, pr.Reason = r.Status, r.Cause, r.Reason
		case loginResult.Status != report.Ran:
			pr.Status, pr.Cause, pr.Reason = report.Skipped, report.CauseNoInput, "runs only after login-throttle sees a limit on one account, and login-throttle did not finish"
		case !loginLimited:
			pr.Status, pr.Cause, pr.Reason = report.Skipped, report.CauseNoInput, "login-throttle saw no limit on one account, so many accounts from the same address cannot be limited either; nothing to add"
		default:
			pr.Input = fmt.Sprintf("POST %s as %s and on", lg.URL, login.SprayUser(lg, 1))
			fmt.Fprintf(stdout, "%s: sending %d logins for invented user names, one per second.\n", login.SprayID, o.login.attempts)
			res, err := sprayCheck(ctx, egress.Config{Target: u, Addrs: addrs, VerifyTLS: o.deployed, Version: version, ReadOnly: o.deployed}, lg, o.login.attempts)
			if ctx.Err() != nil {
				return fail(errors.New("interrupted; no report written"))
			}
			pr.Requests = res.Attempts
			if err != nil {
				pr.Status, pr.Reason = report.Failed, err.Error()
			} else {
				sprayFindings = login.SprayFindings(lg, res, o.login.attempts)
				pr.Status, pr.Result, pr.Findings = report.Ran, res.Summary(o.login.attempts), len(sprayFindings)
			}
		}
		sprayResult = &pr
	}
	// The rate-limit check runs next, before the other checks' traffic.
	var rateResult *report.PluginResult
	var rateFindings []findings.Finding
	if rateSelected {
		pr := report.PluginResult{ID: ratelimit.ID, Family: ratelimit.Family, Tool: "siegekit", Version: version}
		if r, ok := unavailable[ratelimit.ID]; ok {
			pr.Status, pr.Cause, pr.Reason = r.Status, r.Cause, r.Reason
		} else {
			e := o.rateEndpoint
			pr.Input = e.Method + " " + e.URL
			fmt.Fprintf(stdout, "%s: sending up to %d requests, one per second.\n", ratelimit.ID, o.rateLimit.requests)
			res, err := rateLimitCheck(ctx, egress.Config{Target: u, Addrs: addrs, VerifyTLS: o.deployed, Version: version, ReadOnly: o.deployed}, e, o.rateLimit.requests)
			if ctx.Err() != nil {
				return fail(errors.New("interrupted; no report written"))
			}
			pr.Requests = res.Requests
			if err != nil {
				pr.Status, pr.Reason = report.Failed, err.Error()
			} else {
				rateFindings = ratelimit.Findings(e, res, o.rateLimit.requests)
				pr.Status, pr.Result, pr.Findings = report.Ran, res.Summary(o.rateLimit.requests), len(rateFindings)
			}
		}
		rateResult = &pr
	}
	// Then the reset, sign-up and code pages (ADR 0055).
	var pageResults []*report.PluginResult
	var pageFindings []findings.Finding
	for _, p := range ratelimit.Pages {
		if !pageSelected[p] {
			continue
		}
		pr := report.PluginResult{ID: p.ID(), Family: ratelimit.Family, Tool: "siegekit", Version: version}
		if r, ok := unavailable[p.ID()]; ok {
			pr.Status, pr.Cause, pr.Reason = r.Status, r.Cause, r.Reason
		} else {
			e, n := o.pageEndpoints[p], ratelimit.DefaultRequests
			pr.Input = pageInput(e)
			fmt.Fprintf(stdout, "%s: sending up to %d requests to the %s, one per second.\n", p.ID(), n, p.What())
			counted := o.catcher != nil && p != ratelimit.Code
			var mark mailcatcher.Mark
			var markErr error
			if counted {
				pr.Input += "; emails counted at " + o.catcher.String()
				mark, markErr = o.catcher.Mark(ctx)
			}
			var res ratelimit.Result
			var err error
			if markErr != nil {
				err = fmt.Errorf("%v; no request was sent to the %s", markErr, p.What())
			} else {
				res, err = rateLimitCheck(ctx, egress.Config{Target: u, Addrs: addrs, VerifyTLS: o.deployed, Version: version, ReadOnly: o.deployed}, e, n)
			}
			if err == nil && counted && res.Accepted > 0 {
				fmt.Fprintf(stdout, "%s: counting the emails at %s.\n", p.ID(), o.catcher)
				t, cerr := o.catcher.Settle(ctx, mark, res.To)
				if cerr != nil {
					err = fmt.Errorf("the requests were sent, but %v", cerr)
				} else {
					res.Mail = &ratelimit.Mail{Catcher: o.catcher.URL.String(), Emails: t.Emails, Settled: t.Settled, Any: len(res.To) == 0}
				}
			}
			if ctx.Err() != nil {
				return fail(errors.New("interrupted; no report written"))
			}
			pr.Requests = res.Requests
			if err != nil {
				pr.Status, pr.Reason = report.Failed, err.Error()+pageMade(p, res)
			} else {
				fs := ratelimit.Findings(e, res, n)
				pageFindings = append(pageFindings, fs...)
				pr.Status, pr.Result, pr.Findings = report.Ran, res.Summary(n)+pageMade(p, res), len(fs)
			}
		}
		pageResults = append(pageResults, &pr)
	}
	// The start page and the files it links are fetched once, for the
	// served-secrets, backend-live and public-maps checks.
	_, servedOff := unavailable[served.ID]
	_, backendOff := unavailable[backend.ID]
	_, mapsOff := unavailable[publicmaps.ID]
	_, storageOff := unavailable[backend.StorageID]
	servedRuns, backendRuns, mapsRuns := servedSelected && !servedOff, backendSelected && !backendOff, mapsSelected && !mapsOff
	storageRuns := storageSelected && !storageOff
	var col *collected
	if servedRuns || backendRuns || mapsRuns || storageRuns {
		col = collect(ctx, egress.Config{Target: u, Addrs: addrs, VerifyTLS: o.deployed, Version: version, ReadOnly: true}, limits.Rate)
		defer col.cleanup()
		if ctx.Err() != nil {
			return fail(errors.New("interrupted; no report written"))
		}
	}
	var servedResult *report.PluginResult
	var servedFindings []findings.Finding
	if servedSelected {
		pr := report.PluginResult{ID: served.ID, Family: served.Family, Tool: gitleaks.Tool.Name, Version: gitleaks.Tool.Version}
		if r, ok := unavailable[served.ID]; ok {
			pr.Status, pr.Cause, pr.Reason = r.Status, r.Cause, r.Reason
		} else {
			fmt.Fprintf(stdout, "%s: scanning the start page and the files it links.\n", served.ID)
			pr, servedFindings = runServed(ctx, ex, gitleaks, u.String(), col, rootsIn(dir).Files, pr)
			if ctx.Err() != nil {
				return fail(errors.New("interrupted; no report written"))
			}
		}
		servedResult = &pr
	}
	// The fetches count once, as requests of the first check that ran
	// that used them.
	collectCounted := servedRuns
	var backendResult *report.PluginResult
	var backendFindings []findings.Finding
	if backendSelected {
		pr := report.PluginResult{ID: backend.ID, Family: backend.Family, Tool: "siegekit", Version: version}
		if r, ok := unavailable[backend.ID]; ok {
			pr.Status, pr.Cause, pr.Reason = r.Status, r.Cause, r.Reason
		} else {
			// Fetches made only for this check count as its requests.
			extra := 0
			if !servedRuns {
				extra = col.res.Requests
			}
			collectCounted = true
			fmt.Fprintf(stdout, "%s: reading %s.\n", backend.ID, o.backend)
			pr, backendFindings = runBackend(ctx, bp, col, o.repo, extra, pr)
			if ctx.Err() != nil {
				return fail(errors.New("interrupted; no report written"))
			}
		}
		backendResult = &pr
	}
	// After backend-live, so a Supabase host typed there is not asked again.
	var storageResult *report.PluginResult
	var storageFindings []findings.Finding
	if storageSelected {
		pr := report.PluginResult{ID: backend.StorageID, Family: backend.StorageFamily, Tool: "siegekit", Version: version}
		if r, ok := unavailable[backend.StorageID]; ok {
			pr.Status, pr.Cause, pr.Reason = r.Status, r.Cause, r.Reason
		} else {
			extra := 0
			if !collectCounted {
				extra = col.res.Requests
			}
			collectCounted = true
			var interrupted bool
			pr, storageFindings, interrupted = o.runStorage(ctx, storageRun{
				plan: sp, col: col, repo: o.repo, backendConfirmed: backendConfirmed,
				auditLog: filepath.Join(dir, "audit.log"), mode: string(mode), env: env.String(), extraRequests: extra,
			}, stdout)
			if interrupted || ctx.Err() != nil {
				return fail(errors.New("interrupted; no report written"))
			}
		}
		storageResult = &pr
	}
	var mapsResult *report.PluginResult
	var mapsFindings []findings.Finding
	if mapsSelected {
		pr := report.PluginResult{ID: publicmaps.ID, Family: publicmaps.Family, Tool: "siegekit", Version: version}
		if r, ok := unavailable[publicmaps.ID]; ok {
			pr.Status, pr.Cause, pr.Reason = r.Status, r.Cause, r.Reason
		} else {
			fmt.Fprintf(stdout, "%s: looking for served API specs and source maps.\n", publicmaps.ID)
			p, err := probeSpecs()
			if ctx.Err() != nil {
				return fail(errors.New("interrupted; no report written"))
			}
			pr.Input = fmt.Sprintf("%d spec path(s) on %s, and the source maps of the files the start page %s links", len(publicmaps.Paths()), u.Origin(), u)
			pr.Requests = p.Requests
			if !collectCounted {
				pr.Requests += col.res.Requests
				collectCounted = true
			}
			switch {
			case err != nil:
				pr.Status, pr.Reason = report.Failed, err.Error()
			case col.err != nil:
				pr.Status, pr.Reason = report.Failed, "source maps not checked: "+col.err.Error()
			default:
				mapsFindings = publicmaps.Findings(p, col.res)
				pr.Status, pr.Result, pr.Findings = report.Ran, publicmaps.Summary(p, col.res), len(mapsFindings)
			}
		}
		mapsResult = &pr
	}
	var authzResult *report.PluginResult
	var authzFindings []findings.Finding
	if authzSelected {
		pr := report.PluginResult{ID: authz.ID, Family: authz.Family, Tool: "siegekit", Version: version}
		if r, ok := unavailable[authz.ID]; ok {
			pr.Status, pr.Cause, pr.Reason = r.Status, r.Cause, r.Reason
		} else {
			o.harRequests.Sessions = []http.Header{o.sessionB, o.sessionC}
			inSpec := addSpecRequests(o.harRequests, spec, o.codeRoutes(), o.deployed)
			pr.Input = fmt.Sprintf("%s, %d request(s) recorded as account A", filepath.Base(o.har), len(o.harRequests.Requests)-o.harRequests.FromSpec-o.harRequests.FromSweep)
			if o.harRequests.FromSpec > 0 {
				pr.Input += fmt.Sprintf("; %d route(s) from the OpenAPI spec %s", o.harRequests.FromSpec, spec.Source)
			}
			if n := o.harRequests.FromSweep - o.harRequests.FromCodeSweep; n > 0 {
				pr.Input += fmt.Sprintf("; %d route(s) swept from the OpenAPI spec %s with IDs from the HAR file", n, spec.Source)
			}
			pr.Input += o.codeInput(inSpec)
			pr.Input += o.accountsInput()
			fmt.Fprintf(stdout, "%s: replaying %d request(s).\n", authz.ID, len(o.harRequests.Requests))
			res, err := authzCheck(ctx, egress.Config{Target: u, Addrs: addrs, VerifyTLS: o.deployed, Version: version, ReadOnly: true}, o.harRequests.Requests, authz.Accounts{B: o.sessionB, C: o.sessionC}, limits.Rate)
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
	// After the read replay, so its answers are those A recorded (ADR 0049).
	var writeResult *report.PluginResult
	var writeFindings []findings.Finding
	if writeSelected {
		pr := report.PluginResult{ID: authz.WriteID, Family: authz.Family, Tool: "siegekit", Version: version}
		if r, ok := unavailable[authz.WriteID]; ok {
			pr.Status, pr.Cause, pr.Reason = r.Status, r.Cause, r.Reason
		} else {
			recorded, tried := o.writes.Recorded()
			pr.Input = fmt.Sprintf("%s, %d write(s) recorded as account A, %d tried on A's objects", filepath.Base(o.har), recorded, tried)
			pr.Input += o.accountsInput()
			fmt.Fprintf(stdout, "%s: replaying %d write(s).\n", authz.WriteID, len(o.writes.Writes))
			res, err := writeCheck(ctx, egress.Config{Target: u, Addrs: addrs, Version: version}, o.writes.Writes, authz.Accounts{B: o.sessionB, C: o.sessionC}, o.harUser, limits.Rate, mode)
			if ctx.Err() != nil {
				return fail(errors.New("interrupted; no report written"))
			}
			pr.Requests = res.Requests
			if err != nil {
				pr.Status, pr.Reason = report.Failed, err.Error()
			} else {
				writeFindings = authz.WriteFindings(u.Origin(), res)
				pr.Status, pr.Result, pr.Findings = report.Ran, res.WriteSummary(o.writes), len(writeFindings)
			}
		}
		writeResult = &pr
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
		FilesRoot: rootsIn(dir).Files, OpenAPI: spec, NoOpenAPI: noSpec, Environment: env,
		Recorded: recordedRequests, RecordedFrom: filepath.Base(o.har),
	})
	if errors.Is(err, context.Canceled) {
		return fail(errors.New("interrupted; no report written"))
	}
	if err != nil {
		return fail(err)
	}
	var first []report.PluginResult
	for _, pr := range slices.Concat([]*report.PluginResult{loginResult, sprayResult, rateResult}, pageResults, []*report.PluginResult{servedResult, backendResult, storageResult, mapsResult, authzResult, writeResult}) {
		if pr != nil {
			first = append(first, *pr)
		}
	}
	if len(first) > 0 {
		run.Started = started
		run.Plugins = append(first, run.Plugins...)
		if run.Findings = findings.Dedupe(slices.Concat(loginFindings, sprayFindings, rateFindings, pageFindings, servedFindings, backendFindings, storageFindings, mapsFindings, authzFindings, writeFindings, run.Findings)); run.Findings == nil {
			run.Findings = []findings.Finding{}
		}
	}
	return finish(run, o.reportDir, o.noSave, u.Host, o.threshold, o.requireAll, o.requireComplete, stdout, stderr)
}

// zapActive is the plugin that attacks the HAR file's requests (ADR 0047).
const zapActive = "zap-active"

// servedTool is the plugin that reads the served files (ADR 0032).
const servedTool = "gitleaks"

// runServed runs Gitleaks over the fetched files like a source directory,
// then places the findings at the URLs the files came from (ADR 0032).
func runServed(ctx context.Context, ex runner.Executor, gl *manifest.Manifest, start string, c *collected, filesRoot string, pr report.PluginResult) (report.PluginResult, []findings.Finding) {
	pr.Input = "the start page " + start + " and the files it links"
	pr.Requests = c.res.Requests
	if c.err != nil {
		pr.Status, pr.Reason = report.Failed, c.err.Error()
		return pr, nil
	}
	pr.Result = c.res.Summary()
	run, err := runner.Run(ctx, ex, []*manifest.Manifest{gl}, runner.Options{Version: version, TargetDir: c.files, WorkDir: c.work, FilesRoot: filesRoot})
	if err != nil {
		pr.Status, pr.Reason = report.Failed, err.Error()
		return pr, nil
	}
	tool := run.Plugins[0]
	pr.Status, pr.Reason, pr.Suppressed = tool.Status, tool.Reason, tool.Suppressed
	if tool.Status != report.Ran {
		return pr, nil
	}
	fs := served.Findings(run.Findings, c.res)
	pr.Findings = len(fs)
	return pr, fs
}

// testAccounts is what a person types to confirm that the access-control
// check's accounts are test accounts.
const testAccounts = "test accounts"

// changeTestData is what a person types before access-control-write
// changes data (ADR 0049 item 3).
const changeTestData = "change test data"

// otherAccounts names the accounts besides A that the replays use, as
// "as account C, as account B and " (C first, ADR 0051), or "".
func (o *urlScan) otherAccounts() string {
	s := ""
	if o.sessionC != nil {
		s += "as account C, "
	}
	if o.sessionB != nil {
		s += "as account B, "
	}
	if s != "" {
		s = strings.TrimSuffix(s, ", ") + " and "
	}
	return s
}

// writeSenders names the write replay's senders in the order they send
// (ADR 0051 item 2).
func (o *urlScan) writeSenders() string {
	switch {
	case o.sessionC != nil && o.sessionB != nil:
		return "as account C, with no login and as account B"
	case o.sessionC != nil:
		return "as account C and with no login"
	case o.sessionB != nil:
		return "as account B and with no login"
	}
	return "with no login"
}

// accountsNotTested says which session variables are not set, or "".
func (o *urlScan) accountsNotTested() string {
	switch {
	case o.sessionB == nil && o.sessionC == nil:
		return authz.SessionEnv + " and " + authz.SessionEnvC + " not set: accounts B and C are not tested"
	case o.sessionB == nil:
		return authz.SessionEnv + " not set: account B is not tested"
	case o.sessionC == nil:
		return authz.SessionEnvC + " not set: account C, an account outside A's shared spaces, is not tested"
	}
	return ""
}

// accountsInput names the session variables given, for the report.
func (o *urlScan) accountsInput() string {
	s := ""
	if o.sessionB != nil {
		s += "; account B from " + authz.SessionEnv
	}
	if o.sessionC != nil {
		s += "; account C from " + authz.SessionEnvC
	}
	return s
}

// authzCheck replays the HAR's requests; tests replace it.
var authzCheck = authz.Check

// writeCheck is authz.WriteCheck; tests replace it.
var writeCheck = authz.WriteCheck

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

// addSpecRequests adds the spec's routes to the requests access-control
// replays: its GET routes without parameters on every target (ADR 0035),
// and on local targets the route sweep, every GET route filled from the
// IDs A's recording showed (ADR 0052).
//
// On local targets it then sweeps the routes read from the server code
// (ADR 0053), filled the same way, leaving out those the spec already
// has: the spec says which parameters are required, the code does not.
// It returns how many code routes the spec already had.
func addSpecRequests(h *authz.HAR, spec *openapi.Spec, code []authz.SpecRoute, deployed bool) (inSpec int) {
	specPaths := map[string]bool{}
	if spec != nil {
		base, _ := openapi.BasePath(spec.Data, spec.Format)
		h.AddSpecRoutes(authz.SpecRoutes(spec.Data, spec.Format), base)
		if !deployed {
			sw := authz.SweepRoutes(spec.Data, spec.Format)
			for _, rt := range sw {
				specPaths[routeShape(base+rt.Path)] = true
			}
			h.AddSweepRoutes(sw, base)
		}
	}
	if deployed || len(code) == 0 {
		return 0
	}
	var rest []authz.SpecRoute
	for _, rt := range code {
		if specPaths[routeShape(rt.Path)] {
			inSpec++
			continue
		}
		rest = append(rest, rt)
	}
	h.AddSweepRoutes(rest, "")
	return inSpec
}

var rePathName = regexp.MustCompile(`\{[^{}/]*\}`)

// routeShape is a route path with its parameter names left out and no
// trailing slash, so /rooms/{rid} in the code and /rooms/{roomId} in the
// spec are the same route.
func routeShape(p string) string {
	p = rePathName.ReplaceAllString(p, "{}")
	if len(p) > 1 {
		p = strings.TrimSuffix(p, "/")
	}
	return p
}

// codeRoutes returns the routes read from --source, or nil.
func (o *urlScan) codeRoutes() []authz.SpecRoute {
	if o.code == nil || o.codeErr != nil {
		return nil
	}
	return o.code.Routes
}

// codeInput describes what was read from the server code, for the
// report's input line.
func (o *urlScan) codeInput(inSpec int) string {
	if o.code == nil {
		return ""
	}
	if o.codeErr != nil {
		return fmt.Sprintf("; no routes read from the server code in %s (%v)", o.source, o.codeErr)
	}
	c := o.code
	var kinds []string
	for _, k := range []string{coderoutes.KindGo, coderoutes.KindRocketChat, coderoutes.KindExpress} {
		if c.Found[k] > 0 {
			kinds = append(kinds, fmt.Sprintf("%s %d", k, c.Found[k]))
		}
	}
	s := fmt.Sprintf("; server code in %s: %d file(s) read, %d GET route(s) found", o.source, c.Files, len(c.Routes))
	if len(kinds) > 0 {
		s += " (" + strings.Join(kinds, ", ") + ")"
	}
	if inSpec > 0 {
		s += fmt.Sprintf(", %d of them also in the OpenAPI spec and swept from it", inSpec)
	}
	s += fmt.Sprintf(", %d request(s) swept from them with IDs from the HAR file", o.harRequests.FromCodeSweep)
	var left []string
	if c.Unresolved > 0 {
		left = append(left, fmt.Sprintf("%d route(s) whose path the code builds at run time, as a wildcard or by mounting a router (not swept)", c.Unresolved))
	}
	if c.TooBig > 0 {
		left = append(left, fmt.Sprintf("%d file(s) over the size or count limits (not read)", c.TooBig))
	}
	if c.Unparsed > 0 {
		left = append(left, fmt.Sprintf("%d Go file(s) that did not parse", c.Unparsed))
	}
	if c.Truncated {
		left = append(left, "the Go code was too large to follow to the end, so routes may be missing")
	}
	if len(left) > 0 {
		s += "; " + strings.Join(left, "; ")
	}
	return s
}

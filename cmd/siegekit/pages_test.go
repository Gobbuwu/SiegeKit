package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/Gobbuwu/SiegeKit/internal/audit"
	"github.com/Gobbuwu/SiegeKit/internal/egress"
	"github.com/Gobbuwu/SiegeKit/internal/findings"
	"github.com/Gobbuwu/SiegeKit/internal/login"
	"github.com/Gobbuwu/SiegeKit/internal/ratelimit"
	"github.com/Gobbuwu/SiegeKit/internal/report"
	"github.com/Gobbuwu/SiegeKit/internal/verify"
)

var pageArgs = []string{
	"--reset-url", "http://localhost:3000/rest/user/reset-password", "--reset-body", `{"email":"tester@shop.test","answer":"{wrong}"}`,
	"--signup-url", "http://localhost:3000/api/Users", "--signup-body", `{"email":"{new}@example.com","password":"p"}`,
	"--code-url", "http://localhost:3000/rest/2fa/verify", "--code-body", `{"tmpToken":"t","totpToken":"{wrong}"}`,
	"--only", "reset-limit,signup-limit,code-limit",
}

// useSpray replaces the spraying check and counts its calls.
func useSpray(t *testing.T, res login.Result) *int {
	t.Helper()
	n := 0
	old := sprayCheck
	sprayCheck = func(_ context.Context, cfg egress.Config, l *login.Login, attempts int, _ login.Result) (login.Result, error) {
		n++
		if cfg.ReadOnly || l.Path != "/rest/user/login" || attempts != 20 {
			t.Errorf("spray %+v %+v %d", cfg, l, attempts)
		}
		return res, nil
	}
	t.Cleanup(func() { sprayCheck = old })
	return &n
}

func TestScanURLPages(t *testing.T) {
	old := resolver
	resolver = fakeResolver{"localhost": "127.0.0.1", "shop.example": "93.184.215.14"}
	t.Cleanup(func() { resolver = old })
	scan := func(tty bool, input string, args ...string) (int, string) {
		t.Helper()
		stdinIsTerminal = func() bool { return tty }
		stdin = strings.NewReader(input)
		t.Cleanup(func() { stdinIsTerminal = func() bool { return false } })
		var out, errb bytes.Buffer
		code := run(append([]string{"scan", "--no-save"}, args...), &out, &errb)
		return code, out.String() + errb.String()
	}
	readReport := func() report.Run {
		t.Helper()
		b, err := os.ReadFile(filepath.Join("siegekit-report", "report.json"))
		var r report.Run
		if err != nil || json.Unmarshal(b, &r) != nil {
			t.Fatalf("report %v", err)
		}
		return r
	}
	plugin := func(r report.Run, id string) report.PluginResult {
		t.Helper()
		for _, p := range r.Plugins {
			if p.ID == id {
				return p
			}
		}
		t.Fatalf("no %s in %+v", id, r.Plugins)
		return report.PluginResult{}
	}

	// Mistakes are refused before any lookup, request or audit entry.
	for _, c := range []struct {
		args []string
		code int
		want string
	}{
		{[]string{"--reset-body", "email=a", "http://localhost:3000/"}, exitUsage, "--reset-body needs --reset-url"},
		{[]string{"--code-url", "http://localhost:3000/c", "--code-body", "c={wrong}", t.TempDir()}, exitUsage, "only apply to URL targets"},
		{[]string{"--code-url", "http://localhost:3000/c", "http://localhost:3000/"}, exitInvalid, "--code-url needs --code-body"},
		{[]string{"--signup-url", "http://localhost:3001/s", "--signup-body", "u={new}", "http://localhost:3000/"}, exitInvalid, "not on the target's origin"},
		{[]string{"--signup-url", "http://localhost:3000/s", "--signup-body", "u=me", "http://localhost:3000/"}, exitInvalid, "must contain {new}"},
		// The page flags (ADR 0069).
		{[]string{"--signup-url", "http://localhost:3000/s", "--signup-page", "http://localhost:3000/s", "--signup-body", "u={new}", "http://localhost:3000/"}, exitUsage, "--signup-url and --signup-page cannot be used together"},
		{[]string{"--signup-body", "u={new}", "http://localhost:3000/"}, exitUsage, "--signup-body needs --signup-url or --signup-page"},
		{[]string{"--code-body", "c={wrong}", "http://localhost:3000/"}, exitUsage, "--code-body needs --code-url\n"},
		{[]string{"--code-page", "http://localhost:3000/c", "http://localhost:3000/"}, exitUsage, "flag provided but not defined: -code-page"},
		{[]string{"--signup-page", "http://localhost:3000/s", "--signup-body", `{"u":"{new}"}`, "http://localhost:3000/"}, exitInvalid, "with --signup-page, --signup-body names the form's fields as a form body"},
		{[]string{"--reset-page", "http://localhost:3001/f", "--reset-body", "email=a", "http://localhost:3000/"}, exitInvalid, "--reset-page http://localhost:3001/f is not on the target's origin"},
	} {
		f := useActive(t)
		data := useData(t)
		calls := useRateLimit(t, ratelimit.Result{}, nil)
		code, out := scan(false, "", c.args...)
		if code != c.code || !strings.Contains(out, c.want) || len(f.specs)+len(*calls) != 0 {
			t.Errorf("%v: exit %d, %d runs, %d checks\n%s", c.args, code, len(f.specs), len(*calls), out)
		}
		if _, err := os.Stat(filepath.Join(data, "siegekit", "audit.log")); err == nil {
			t.Errorf("%v: audit entry written", c.args)
		}
	}

	// Pages from flags; the side effects are named before the typed yes.
	useActive(t)
	data := useData(t)
	calls := useRateLimit(t, ratelimit.Result{Requests: 20, Baseline: 201, Accepted: 20, Reached: "an answer (answered 201) differed from the page's own answer to a GET (answered 401)"}, nil)
	code, out := scan(true, "yes\n", append(slices.Clone(pageArgs), "--fail-on", "low", "http://localhost:3000/")...)
	for _, want := range []string{
		"reset-limit          siegekit 0.0.0-dev: up to 20 requests POST http://localhost:3000/rest/user/reset-password (from --reset-url), with wrong answers, one per second",
		"signup-limit         siegekit 0.0.0-dev: up to 20 requests POST http://localhost:3000/api/Users (from --signup-url), each with a new user name (siegekit-new-...)",
		"code-limit           siegekit 0.0.0-dev: up to 20 requests POST http://localhost:3000/rest/2fa/verify (from --code-url), with wrong codes",
		"reset-limit sends up to 20 password-reset requests to http://localhost:3000/rest/user/reset-password, so the app may send up to 20 emails or texts to the address in them.",
		"signup-limit creates up to 20 accounts at http://localhost:3000/api/Users and may send up to 20 emails or texts.",
		"code-limit sends up to 20 wrong codes to http://localhost:3000/rest/2fa/verify. Type yes",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q", want)
		}
	}
	if code != report.ExitFindings || len(*calls) != 3 {
		t.Fatalf("exit %d, %d checks\n%s", code, len(*calls), out)
	}
	for i, p := range ratelimit.Pages {
		if c := (*calls)[i]; c.e.Page != p || c.n != ratelimit.DefaultRequests || c.cfg.ReadOnly || c.e.From != p.Flag() {
			t.Errorf("call %d %+v", i, c)
		}
	}
	b, err := os.ReadFile(filepath.Join(data, "siegekit", "audit.log"))
	var e audit.Entry
	if err != nil || json.Unmarshal(b, &e) != nil || !slices.Equal(e.Plugins, []string{"reset-limit", "signup-limit", "code-limit"}) || e.Verification != "loopback + typed yes" {
		t.Errorf("audit entry %+v %v", e, err)
	}
	r := readReport()
	if p := plugin(r, "signup-limit"); p.Status != report.Ran || p.Input != "POST http://localhost:3000/api/Users (from --signup-url)" ||
		p.Result != "no limit seen in 20 requests, all answered 201 with no rate-limit header; 20 answered below 400, so up to 20 accounts may have been made, named siegekit-new-..." {
		t.Errorf("sign-up %+v", p)
	}
	if p := plugin(r, "reset-limit"); !strings.HasSuffix(p.Result, "so the app may have sent up to 20 emails or texts") {
		t.Errorf("reset %+v", p)
	}
	rules := map[string]findings.Severity{}
	for _, f := range r.Findings {
		rules[f.RuleID] = f.Severity
	}
	if rules["reset-not-limited"] != findings.Low || rules["signup-not-limited"] != findings.Low || rules["code-not-limited"] != findings.Medium {
		t.Errorf("findings %v", rules)
	}

	// Not confirmed: skipped with that cause, nothing sent.
	for _, c := range []struct {
		tty   bool
		input string
		want  string
	}{
		{true, "no\n", `not confirmed: "yes" was not typed`},
		{false, "", "needs a person's confirmation"},
	} {
		useActive(t)
		useData(t)
		calls := useRateLimit(t, ratelimit.Result{}, nil)
		scan(c.tty, c.input, append(slices.Clone(pageArgs), "http://localhost:3000/")...)
		if p := plugin(readReport(), "code-limit"); len(*calls) != 0 || p.Status != report.Skipped || p.Cause != report.CauseNotConfirmed || !strings.Contains(p.Reason, c.want) {
			t.Errorf("%q: %d checks %+v", c.input, len(*calls), p)
		}
	}

	// Pages from the HAR file; a flag wins over the recording, and a
	// recorded page that cannot be tested says why.
	dir := t.TempDir()
	harFile := filepath.Join(dir, "a.har")
	if err := os.WriteFile(harFile, []byte(`{"log":{"entries":[
		{"request":{"method":"POST","url":"http://localhost:3000/rest/user/reset-password","headers":[],"postData":{"mimeType":"application/json","text":"{\"email\":\"a@shop.test\",\"answer\":\"blue\"}"}}},
		{"request":{"method":"POST","url":"http://localhost:3000/rest/2fa/verify","headers":[],"postData":{"mimeType":"application/json","text":"{\"tmpToken\":\"t\",\"totpToken\":\"123456\"}"}}},
		{"request":{"method":"POST","url":"http://localhost:3000/register","headers":[],"postData":{"mimeType":"application/json","text":"{\"password\":\"p\"}"}}}
	]}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	useActive(t)
	useData(t)
	calls = useRateLimit(t, ratelimit.Result{Requests: 1, Limited: true, Signal: "answered 429, already at the first request"}, nil)
	code, out = scan(false, "", "--har", harFile, "--authorized-host", "localhost", "--code-url", "http://localhost:3000/api/mfa", "--code-body", "code={wrong}",
		"--only", "reset-limit,signup-limit,code-limit", "http://localhost:3000/")
	if code != exitOK || len(*calls) != 2 || (*calls)[0].e.From != "a.har" || (*calls)[1].e.From != "--code-url" {
		t.Fatalf("exit %d, %d checks\n%s", code, len(*calls), out)
	}
	r = readReport()
	if p := plugin(r, "reset-limit"); p.Input != "POST http://localhost:3000/rest/user/reset-password (recorded in a.har)" || p.Findings != 0 {
		t.Errorf("reset %+v", p)
	}
	if p := plugin(r, "signup-limit"); p.Status != report.Skipped || p.Cause != report.CauseNoInput ||
		!strings.Contains(p.Reason, "the sign-up page recorded in a.har cannot be tested (POST http://localhost:3000/register: no field of its body holds a user name or an email address") {
		t.Errorf("sign-up %+v", p)
	}
	useActive(t)
	useData(t)
	useRateLimit(t, ratelimit.Result{}, nil)
	scan(false, "", "--har", harFile, "--authorized-host", "localhost", "--only", "signup-limit", "http://localhost:3000/")
	if p := plugin(readReport(), "signup-limit"); !strings.Contains(p.Reason, "cannot be tested") {
		t.Errorf("sign-up %+v", p)
	}

	// Pages given as their forms (ADR 0069): the plan and the report name
	// the form, and the report counts the page reads.
	useActive(t)
	useData(t)
	calls = useRateLimit(t, ratelimit.Result{Requests: 11, Reads: 22, Accepted: 11, Limited: true, Signal: "redirected to /signup?error=too-many-attempts instead of /signup?notice=check-email",
		Form: `sent to http://localhost:3000/signup as multipart/form-data, button "Sign up"`}, nil)
	code, out = scan(true, "yes\n", "--signup-page", "http://localhost:3000/signup", "--signup-body", "email={new}@example.com&password=p",
		"--reset-page", "http://localhost:3000/forgot", "--reset-body", "email=tester@shop.test", "--only", "reset-limit,signup-limit", "http://localhost:3000/")
	if code != exitOK || len(*calls) != 2 || !(*calls)[0].e.Form || (*calls)[0].e.From != "--reset-page" || (*calls)[1].e.From != "--signup-page" ||
		!strings.Contains(out, "signup-limit         siegekit 0.0.0-dev: up to 20 requests POST of the form on http://localhost:3000/signup (from --signup-page), each with a new user name") {
		t.Fatalf("pages: exit %d, %d checks\n%s", code, len(*calls), out)
	}
	if p := plugin(readReport(), "signup-limit"); p.Requests != 33 || p.Findings != 0 ||
		p.Input != `POST of the form on http://localhost:3000/signup (from --signup-page), sent to http://localhost:3000/signup as multipart/form-data, button "Sign up"` {
		t.Errorf("pages: %+v", p)
	}

	// A failed page check makes the run incomplete and still says what
	// it may have made.
	useActive(t)
	useData(t)
	useRateLimit(t, ratelimit.Result{Requests: 3, Accepted: 3}, errors.New("the URL answered 500 (a server error) after 2 request(s)"))
	if code, _ := scan(false, "", append(slices.Clone(pageArgs), "--authorized-host", "localhost", "http://localhost:3000/")...); code != report.ExitIncomplete {
		t.Errorf("failed: exit %d", code)
	}
	if p := plugin(readReport(), "signup-limit"); p.Status != report.Failed || !strings.HasSuffix(p.Reason, "so up to 3 accounts may have been made, named siegekit-new-...") {
		t.Errorf("failed: %+v", p)
	}

	// --profile quick leaves them out; deployed targets never run them.
	useActive(t)
	useData(t)
	calls = useRateLimit(t, ratelimit.Result{}, nil)
	if code, out := scan(false, "", append(slices.Clone(pageArgs[:len(pageArgs)-2]), "--profile", "quick", "--only", "dast", "http://localhost:3000/")...); len(*calls) != 0 || !strings.Contains(out, "code-limit           not run - not run with --profile quick") {
		t.Errorf("quick: exit %d\n%s", code, out)
	}
	if code, out := scan(false, "", append(slices.Clone(pageArgs[:len(pageArgs)-2]), "--profile", "quick", "--only", "zap,code-limit", "http://localhost:3000/")...); code != exitInvalid || !strings.Contains(out, "--only names code-limit, which --profile quick does not run") {
		t.Errorf("--only with quick: exit %d\n%s", code, out)
	}
	useActive(t)
	data = useData(t)
	calls = useRateLimit(t, ratelimit.Result{}, nil)
	tok, err := verify.Token(filepath.Join(data, "siegekit", "verify"), "shop.example")
	if err != nil {
		t.Fatal(err)
	}
	useProver(t, &fakeProver{published: map[string]string{"shop.example": verify.Value(tok)}})
	code, out = scan(true, "shop.example\n", "--deployed", "--reset-url", "https://shop.example/reset", "--reset-body", "email=a", "--only", "reset-limit,zap", "https://shop.example/")
	if code != exitOK || len(*calls) != 0 || !strings.Contains(out, "reset-limit          not run - runs only on local targets") {
		t.Errorf("deployed: exit %d, %d checks\n%s", code, len(*calls), out)
	}
}

func TestScanURLSpray(t *testing.T) {
	old := resolver
	resolver = fakeResolver{"localhost": "127.0.0.1"}
	t.Cleanup(func() { resolver = old })
	scan := func(args ...string) (int, string, report.Run) {
		t.Helper()
		var out, errb bytes.Buffer
		code := run(append([]string{"scan", "--no-save", "--authorized-host", "localhost", "--only", "login-throttle,login-spray"}, append(args, "http://localhost:3000/")...), &out, &errb)
		b, _ := os.ReadFile(filepath.Join("siegekit-report", "report.json"))
		var r report.Run
		json.Unmarshal(b, &r)
		return code, out.String() + errb.String(), r
	}
	// After a limit on one account: spraying runs, and no limit across
	// invented names is a medium finding.
	useActive(t)
	useData(t)
	useLogin(t, login.Result{Attempts: 3, Limited: true, Signal: "answered 423"}, nil)
	n := useSpray(t, login.Result{Attempts: 20, Baseline: 401})
	code, out, r := scan(loginArgs...)
	if code != exitOK || *n != 1 || len(r.Plugins) != 2 || r.Plugins[1].ID != login.SprayID || r.Plugins[1].Status != report.Ran ||
		r.Plugins[1].Input != "POST http://localhost:3000/rest/user/login as siegekit-nobody-1 and on" ||
		!strings.Contains(out, "login-spray          siegekit 0.0.0-dev: only if login-throttle sees a limit, 20 logins for invented user names (siegekit-nobody-1 and on)") {
		t.Fatalf("exit %d, %d sprays %+v\n%s", code, *n, r.Plugins, out)
	}
	if len(r.Findings) != 1 || r.Findings[0].RuleID != "spray-not-limited" || r.Findings[0].Severity != findings.Medium {
		t.Errorf("findings %+v", r.Findings)
	}
	// No limit on one account: nothing to add, skipped with the reason.
	useActive(t)
	useData(t)
	useLogin(t, login.Result{Attempts: 20, Baseline: 401}, nil)
	n = useSpray(t, login.Result{})
	_, _, r = scan(loginArgs...)
	if *n != 0 || r.Plugins[1].Status != report.Skipped || r.Plugins[1].Cause != report.CauseNoInput || !strings.Contains(r.Plugins[1].Reason, "login-throttle saw no limit on one account") {
		t.Errorf("no limit: %d %+v", *n, r.Plugins[1])
	}
	// login-throttle failed: not known, skipped.
	useActive(t)
	useData(t)
	useLogin(t, login.Result{}, errors.New("the login URL answered 404 to a POST"))
	n = useSpray(t, login.Result{})
	_, _, r = scan(loginArgs...)
	if *n != 0 || r.Plugins[1].Status != report.Skipped || !strings.Contains(r.Plugins[1].Reason, "login-throttle did not finish") {
		t.Errorf("login failed: %d %+v", *n, r.Plugins[1])
	}
	// Without a login, or without login-throttle, it cannot run.
	useActive(t)
	useData(t)
	_, _, r = scan()
	if r.Plugins[1].Status != report.Skipped || !strings.Contains(r.Plugins[1].Reason, "no login was given") {
		t.Errorf("no login: %+v", r.Plugins[1])
	}
	useActive(t)
	useData(t)
	var stdout, stderr bytes.Buffer
	run(append([]string{"scan", "--no-save", "--authorized-host", "localhost", "--only", "login-spray"}, append(slices.Clone(loginArgs), "http://localhost:3000/")...), &stdout, &stderr)
	b, _ := os.ReadFile(filepath.Join("siegekit-report", "report.json"))
	r = report.Run{}
	json.Unmarshal(b, &r)
	if len(r.Plugins) != 1 || r.Plugins[0].Status != report.Skipped || !strings.Contains(r.Plugins[0].Reason, "login-throttle does not run") {
		t.Errorf("without login-throttle: %+v", r.Plugins)
	}
}

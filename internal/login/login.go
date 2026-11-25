// Package login is SiegeKit's login throttling check (ADR 0010, ADR 0030,
// ADR 0062). It sends one login with the test account's right password,
// which the user gives, then a few logins for that account, each with a
// new randomly generated wrong password, at most one per second, and
// reports whether the app slows down, blocks, asks for a CAPTCHA or locks
// the account. It never guesses a password and never uses a password list.
package login

import (
	"cmp"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/Gobbuwu/SiegeKit/internal/egress"
	"github.com/Gobbuwu/SiegeKit/internal/findings"
	"github.com/Gobbuwu/SiegeKit/internal/ratelimit"
	"github.com/Gobbuwu/SiegeKit/internal/target"
	"github.com/Gobbuwu/SiegeKit/internal/webform"
)

// ID, Name and Family describe the check in plans and reports.
const (
	ID     = "login-throttle"
	Name   = "Login throttling check"
	Family = "dast"
)

// Limits of ADR 0010: 20 attempts by default, never more than 50, at most
// one per second.
const (
	DefaultAttempts = 20
	MaxAttempts     = 50
	MinAttempts     = 2 // the first answer is the baseline
	Interval        = time.Second
)

// MaxAnswer caps the body read from each answer.
const MaxAnswer = 2 << 20

// Limits on what the user passes, so a mistake is caught before any request.
const (
	maxUser = 256
	maxBody = 8 << 10
)

// Login is a login request with {user} and {password} placeholders: a
// body sent to a URL (--login-url), or the form on a page (--login-page,
// ADR 0062).
type Login struct {
	URL  string // origin and path, for plans and reports: the login URL or page
	Path string // path on the target's origin, with the page's query
	User string
	Page bool // the login is the form on the page at URL
	body string
	json bool
	// The page's form: the template's fields, the page's URL and the
	// target the form's action and a login's redirect must be on.
	fields  []webform.Field
	pageURL *url.URL
	target  *target.URL
}

// Parse checks the --login-url, --login-user and --login-body values. The
// URL must be on the target's origin (ADR 0005). A body that starts with
// "{" is sent as JSON, anything else as a form.
func Parse(rawURL, user, body string, t *target.URL) (*Login, error) {
	u, _, err := target.OnOrigin(t, rawURL, "--login-url", false)
	if err != nil {
		return nil, err
	}
	if err := checkUserBody(user, body); err != nil {
		return nil, err
	}
	l := &Login{URL: u.String(), Path: u.Path, User: user, body: body, json: strings.HasPrefix(strings.TrimLeft(body, " \t\r\n"), "{"), target: t}
	b := l.render("x")
	if l.json && !json.Valid(b) {
		return nil, errors.New("--login-body is not valid JSON once {user} and {password} are filled in; put them inside quotes")
	}
	if !l.json {
		if _, err := url.ParseQuery(string(b)); err != nil {
			return nil, fmt.Errorf("--login-body is not a valid form body: %v", err)
		}
	}
	return l, nil
}

// ParsePage checks the --login-page, --login-user and --login-body values
// (ADR 0062). The page must be on the target's origin and may have a
// query. The body names the form's fields, such as
// "email={user}&password={password}": SiegeKit fills them in and sends the
// page's form as a browser does, with its other fields as the page has
// them.
func ParsePage(rawPage, user, body string, t *target.URL) (*Login, error) {
	u, query, err := target.OnOrigin(t, rawPage, "--login-page", true)
	if err != nil {
		return nil, err
	}
	if err := checkUserBody(user, body); err != nil {
		return nil, err
	}
	if strings.HasPrefix(strings.TrimLeft(body, " \t\r\n"), "{") {
		return nil, errors.New("with --login-page, --login-body names the form's fields as a form body, such as 'email={user}&password={password}'")
	}
	l := &Login{URL: u.String(), Path: u.Path, User: user, Page: true, body: body, target: t}
	if query != "" {
		l.URL += "?" + query
		l.Path += "?" + query
	}
	if l.pageURL, err = url.Parse(l.URL); err != nil {
		return nil, fmt.Errorf("--login-page: %v", err)
	}
	if l.fields, err = webform.ParseFields(body, "--login-body", "{user}", "{password}"); err != nil {
		return nil, err
	}
	return l, nil
}

// checkUserBody checks the user name and the body template.
func checkUserBody(user, body string) error {
	switch {
	case user == "":
		return errors.New("--login-user is empty")
	case len(user) > maxUser:
		return fmt.Errorf("--login-user is longer than %d bytes", maxUser)
	case !utf8.ValidString(user) || strings.ContainsFunc(user, unicode.IsControl):
		return errors.New("--login-user contains control characters or invalid UTF-8")
	}
	if len(body) > maxBody {
		return fmt.Errorf("--login-body is longer than %d bytes", maxBody)
	}
	if !strings.Contains(body, "{user}") || !strings.Contains(body, "{password}") {
		return errors.New(`--login-body must contain {user} and {password}, for example '{"email":"{user}","password":"{password}"}' or 'username={user}&password={password}'`)
	}
	return nil
}

// PasswordEnv holds the test account's right password: one login with it
// shows that the check's logins reach the app's login code (ADR 0062).
const PasswordEnv = "SIEGEKIT_LOGIN_PASSWORD" // #nosec G101 -- the name of an environment variable, not a password

// maxPassword caps PasswordEnv.
const maxPassword = 1024

// CheckPassword checks the value of PasswordEnv. The value is never
// written anywhere, errors included.
func CheckPassword(p string) error {
	switch {
	case p == "":
		return fmt.Errorf("%s is empty", PasswordEnv)
	case len(p) > maxPassword:
		return fmt.Errorf("%s is longer than %d bytes", PasswordEnv, maxPassword)
	case !utf8.ValidString(p) || strings.ContainsFunc(p, unicode.IsControl):
		return fmt.Errorf("%s contains control characters or invalid UTF-8", PasswordEnv)
	}
	return nil
}

// ContentType is the request's content type in --login-url mode.
func (l *Login) ContentType() string {
	if l.json {
		return "application/json"
	}
	return "application/x-www-form-urlencoded"
}

// render fills in the placeholders, escaped for JSON strings or forms.
func (l *Login) render(password string) []byte { return l.renderFor(l.User, password) }

// renderFor fills in the placeholders with user and password.
func (l *Login) renderFor(user, password string) []byte {
	esc := url.QueryEscape
	if l.json {
		esc = func(s string) string {
			b, _ := json.Marshal(s) // a string always marshals
			return string(b[1 : len(b)-1])
		}
	}
	return []byte(strings.NewReplacer("{user}", esc(user), "{password}", esc(password)).Replace(l.body))
}

// wrongPassword returns a new random password that cannot be the account's
// real one. The prefix shows where it came from in the app's logs.
func wrongPassword() string {
	return "siegekit-wrong-" + strings.ToLower(rand.Text()[:20])
}

// Result is what the check saw.
type Result struct {
	Attempts int    // logins with a wrong password answered by the target
	Requests int    // requests sent, with the right-password login and page reads
	Limited  bool   // a limit was seen
	Signal   string // what showed the limit
	Baseline int    // the status of the first wrong-password answer
	Redirect string // the first wrong-password answer's redirect, "" for none
	Right    string // how the right-password login was answered, "" if none was sent
	URL      string // where the logins were posted
	Form     string // the page's form, as sent: "multipart/form-data, button \"Log in\""
	// limit is the answer that showed the limit, and normal the baseline's
	// (Spray reads them, ADR 0062).
	limit, normal *answerKind
}

// answerKind is what tells a limited answer from a normal one without a
// fixed sign: the status, the redirect and the limit words in the body.
type answerKind struct {
	status   int
	location string
	words    string
	next     string // the limit words of the page the answer redirected to
}

func kindOf(at *attempt) *answerKind {
	return &answerKind{at.a.Status, webform.Redirect(at.a), strings.Join(ratelimit.LimitWords(at.a.Body), ","), strings.Join(at.nextWords, ",")}
}

// answer is the wrong-password answer, such as "303 to /error".
func (r Result) answer() string {
	if r.Redirect != "" {
		return fmt.Sprintf("%d to %s", r.Baseline, r.Redirect)
	}
	return fmt.Sprint(r.Baseline)
}

// Summary says the result in one line, for reports.
func (r Result) Summary(planned int) string {
	if r.Limited {
		return fmt.Sprintf("limited after %d of %d attempts: %s", r.Attempts, planned, r.Signal)
	}
	s := fmt.Sprintf("no limit seen in %d attempts, all answered %s", r.Attempts, r.answer())
	if r.Right != "" {
		s += "; the right password " + r.Right
	}
	if planned < DefaultAttempts {
		s += fmt.Sprintf("; too few attempts to report a finding, since many apps limit failed logins at 5 to 30: run again with --login-attempts %d or more", DefaultAttempts)
	}
	return s
}

// send and sleep are replaced in tests.
var (
	send  = egress.SendHeader
	sleep = func(ctx context.Context, d time.Duration) error {
		t := time.NewTimer(d)
		defer t.Stop()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
			return nil
		}
	}
	// now is the clock the request pacing reads; tests fix it, so the
	// waits they check do not depend on how fast the machine is.
	now = time.Now
)

// SprayID and SprayName describe the spraying check (ADR 0055 item 6).
const (
	SprayID   = "login-spray"
	SprayName = "Password spraying check"
)

// SprayUser is the i-th user name the spraying check invents (from 1): an
// email address at example.com, which is reserved and accepts no mail
// (RFC 2606, RFC 7505), when the test account's name is an email address,
// so the app's format checks pass, and a plain name otherwise. No real
// account has such a name, so none is locked.
func SprayUser(l *Login, i int) string {
	if strings.Contains(l.User, "@") {
		return fmt.Sprintf("siegekit-nobody-%d@example.com", i)
	}
	return fmt.Sprintf("siegekit-nobody-%d", i)
}

// Spray sends attempts logins like Check, but each for a new invented user
// name and all with one wrong password, as an attacker spraying one
// password across many accounts does (design Q5). It runs only after
// Check saw a limit on one account: if one account is never limited from
// one address, many accounts from that address cannot be limited either.
// Check's right-password login already showed that these logins reach the
// login code, so Spray sends none. after is Check's result: a limit for
// the whole address can still hold when Spray starts, and its first
// answer is then the limited one Check saw, not a normal one (measured
// with Supabase Auth, 2026-11-23), so that answer counts as a limit.
func Spray(ctx context.Context, cfg egress.Config, l *Login, attempts int, after Result) (Result, error) {
	password := wrongPassword()
	return run(ctx, cfg, l, attempts, "", func(i int) (string, string) { return SprayUser(l, i+1), password }, after.limit, after.normal)
}

// Check sends one login with the account's right password, then attempts
// logins with a wrong one, at most one per Interval, and stops at the
// first sign of a limit. The first wrong-password answer is the baseline:
// a 429, 423 or 503 status or a Retry-After header in a later answer, a
// status or redirect other than the baseline's, words about a lockout,
// CAPTCHA or too many attempts that the baseline did not have, or an
// answer at least 3 times slower than the baseline and at least 1 second
// long count as a limit (owner decision 2026-11-20, ADR 0030, ADR 0062).
// When the right password is answered like a wrong one, the check fails:
// its logins may never reach the login code (ADR 0062). cfg must not be
// for a deployed target.
func Check(ctx context.Context, cfg egress.Config, l *Login, attempts int, right string) (Result, error) {
	if err := CheckPassword(right); err != nil {
		return Result{}, err
	}
	return run(ctx, cfg, l, attempts, right, func(int) (string, string) { return l.User, wrongPassword() }, nil, nil)
}

// attempt is what one login got.
type attempt struct {
	a       *egress.Answer // the login's answer; nil when the form was not sent
	page    *egress.Answer // --login-page: the page's answer
	words   []string       // the page's limit words
	formErr error          // why the page's form could not be sent
	form    *webform.Submission
	// The page a wrong login's redirect named, read as a browser does, and
	// its limit words; nil when the answer was not such a redirect.
	next      *egress.Answer
	nextWords []string
}

// try sends one login for user and password. With --login-page it first
// reads the page, with no cookie, then sends its form with the cookies the
// page set, as a browser with no JavaScript does (ADR 0062). Each login
// starts with no cookie, so a limit kept only in a cookie is not counted.
func (l *Login) try(ctx context.Context, cfg egress.Config, user, password string, wrong bool, r *Result) (*attempt, error) {
	if !l.Page {
		r.Requests++
		a, err := send(ctx, cfg, http.MethodPost, l.Path, http.Header{"Content-Type": {l.ContentType()}}, l.renderFor(user, password), MaxAnswer)
		at := &attempt{a: a}
		if err == nil && wrong {
			err = l.follow(ctx, cfg, at, l.URL, l.Path, "", r)
		}
		return at, err
	}
	r.Requests++
	pa, err := send(ctx, cfg, http.MethodGet, l.Path, http.Header{"Accept": {"text/html,application/xhtml+xml"}}, nil, MaxAnswer)
	if err != nil {
		return nil, err
	}
	at := &attempt{page: pa}
	if pa.Status != http.StatusOK {
		return at, nil
	}
	at.words = ratelimit.LimitWords(pa.Body)
	if at.form, at.formErr = webform.Read(pa.Body).Build(l.pageURL, l.target, l.fields, strings.NewReplacer("{user}", user, "{password}", password)); at.formErr != nil {
		return at, nil
	}
	h := http.Header{"Content-Type": {at.form.ContentType}, "Origin": {l.target.Origin()}, "Accept": {"text/html,application/xhtml+xml"}}
	if c := webform.Cookies(pa.Header, l.target.Host, l.pageURL.Path, at.form.Path, now()); c != "" {
		h.Set("Cookie", c)
	}
	r.Requests++
	if at.a, err = send(ctx, cfg, http.MethodPost, at.form.Path, h, at.form.Body, MaxAnswer); err == nil && wrong {
		err = l.follow(ctx, cfg, at, at.form.URL, at.form.Path, h.Get("Cookie"), r)
	}
	return at, err
}

// follow reads the page that a wrong login's 301, 302 or 303 names, on the
// target's origin, with the cookies the login sent and the cookies its
// answer set, as a browser does. Some apps show their limit only there, in
// a message carried by the session cookie, behind the same redirect as a
// wrong password: Rails 8's generated login and Laravel Breeze's (measured,
// ADR 0062 item 4). A 307 or 308 is not followed: a browser would send the
// login again.
func (l *Login) follow(ctx context.Context, cfg egress.Config, at *attempt, from, fromPath, sent string, r *Result) error {
	path, cookie, ok := webform.Next(l.target, at.a, from, fromPath, sent, now())
	if !ok {
		return nil // not a redirect a browser follows with a GET, or not to the target
	}
	h := http.Header{"Accept": {"text/html,application/xhtml+xml"}}
	if cookie != "" {
		h.Set("Cookie", cookie)
	}
	r.Requests++
	var err error
	if at.next, err = send(ctx, cfg, http.MethodGet, path, h, nil, MaxAnswer); err == nil {
		at.nextWords = ratelimit.LimitWords(at.next.Body)
	}
	return err
}

// run sends the right-password login when right is set, then attempts
// logins with the user and password next gives (i from 0); Check and
// Spray share it, so both read a limit the same way. When the first
// wrong-password answer is of the kind limited, not normal, the limit
// already holds.
func run(ctx context.Context, cfg egress.Config, l *Login, attempts int, right string, next func(i int) (string, string), limited, normal *answerKind) (Result, error) {
	if attempts < MinAttempts || attempts > MaxAttempts {
		return Result{}, fmt.Errorf("attempts must be from %d to %d", MinAttempts, MaxAttempts)
	}
	if cfg.ReadOnly {
		return Result{}, errors.New("the login throttling check sends POST requests, which this target does not allow")
	}
	r := Result{URL: l.URL}
	var last time.Time
	pace := func() error {
		if !last.IsZero() {
			if err := sleep(ctx, Interval-now().Sub(last)); err != nil {
				return err
			}
		}
		last = now()
		return nil
	}
	var base *egress.Answer
	var baseWords, nextWords, pageWords []string
	var rightShape webform.Shape
	total := attempts
	if right != "" {
		total++
	}
	for k := range total {
		guard := right != "" && k == 0 // the right-password login
		first := k == 0
		if err := pace(); err != nil {
			return r, err
		}
		user, password := l.User, right
		if !guard {
			user, password = next(r.Attempts)
		}
		at, err := l.try(ctx, cfg, user, password, !guard, &r)
		if err != nil {
			if first {
				return r, fmt.Errorf("the login %s did not answer: %w", l.noun(), err)
			}
			if ctx.Err() != nil {
				return r, ctx.Err()
			}
			return r, fmt.Errorf("the target stopped answering after %d login(s): %v. A block of SiegeKit's address and a crash look the same from here, so this check cannot tell which it was", k, err)
		}
		// The page, read before each login with --login-page.
		if p := at.page; p != nil {
			if s := limitStatus(p); s != "" {
				r.Limited, r.Signal = true, "the login page "+s
				if first {
					r.Signal += ", already at the first login (perhaps from an earlier run)"
				}
				return r, nil
			}
			switch {
			case first && p.Status != http.StatusOK:
				return r, fmt.Errorf("the login page answered %d; --login-page must be the page with the login form itself (SiegeKit does not follow redirects)", p.Status)
			case first && at.formErr != nil:
				return r, fmt.Errorf("--login-page: %v", at.formErr)
			case first:
				pageWords = at.words
				r.URL, r.Form = at.form.URL, at.form.Describe()
			case p.Status >= 500:
				return r, fmt.Errorf("the login page answered %d (a server error) after %d login(s); a crash is not a limit, so this check cannot tell whether logins are limited", p.Status, k)
			case p.Status != http.StatusOK:
				r.Limited, r.Signal = true, fmt.Sprintf("the login page answered %d instead of 200", p.Status)
			case ratelimit.NewWord(at.words, pageWords) != "":
				r.Limited, r.Signal = true, "the login page has "+ratelimit.Said(ratelimit.NewWord(at.words, pageWords))
			case at.formErr != nil:
				return r, fmt.Errorf("after %d login(s) the login page's form could not be sent: %v", k, at.formErr)
			}
			if r.Limited {
				return r, nil
			}
		}
		a := at.a
		if !guard {
			r.Attempts++
		}
		if s := limitStatus(a); s != "" {
			r.Limited, r.Signal = true, s
			if first {
				r.Signal += ", already at the first login (perhaps from an earlier run)"
			}
			return r, nil
		}
		what := "a login with a wrong password"
		if guard {
			what = "a login with the right password"
		}
		if guard || base == nil {
			switch {
			case a.Status == http.StatusNotFound || a.Status == http.StatusMethodNotAllowed || a.Status == http.StatusNotImplemented:
				return r, fmt.Errorf("the login %s answered %d to a POST; check %s", l.noun(), a.Status, l.flags())
			case a.Status >= 500:
				return r, fmt.Errorf("the login %s answered %d (a server error) to %s; check --login-body", l.noun(), a.Status, what)
			}
		}
		if guard {
			rightShape = shapeOf(a)
			r.Right = rightShape.String()
			continue
		}
		if base == nil {
			base, baseWords, nextWords, r.Baseline, r.Redirect = a, ratelimit.LimitWords(a.Body), at.nextWords, a.Status, webform.Redirect(a)
			r.normal = kindOf(at)
			if limited != nil && *r.normal == *limited && (normal == nil || *normal != *limited) {
				said := ""
				if len(at.nextWords) > 0 {
					said = ", and the page it redirected to has " + ratelimit.Said(at.nextWords...)
				}
				r.Limited, r.Signal = true, fmt.Sprintf("the first login got the answer that showed login-throttle's limit (%s%s), so the limit holds for other names too", shapeOf(a), said)
				r.limit = r.normal
				return r, nil
			}
			// The page the first wrong login redirected to says what the
			// login page does not: a limit already holding (perhaps from an
			// earlier run), or a warning, either way no report of no limit.
			if w := ratelimit.NewWord(at.nextWords, pageWords); at.next != nil && w != "" {
				r.Limited, r.Signal = true, "the page the first wrong login redirected to has "+ratelimit.Said(w)+", already at the first login (perhaps from an earlier run)"
				r.limit = r.normal
				return r, nil
			}
			if right != "" && shapeOf(a) == rightShape {
				return r, fmt.Errorf("a login with the right password (%s) and one with a wrong password were both %s, so SiegeKit cannot tell that its logins reach the app's login code, and a report of no limit could be false. Check %s and that %s is the account's password; a login form that needs JavaScript or a CSRF token needs --login-page", PasswordEnv, rightShape, l.flags(), PasswordEnv)
			}
			continue
		}
		if a.Status >= 500 {
			return r, fmt.Errorf("the login %s answered %d (a server error) after %d login(s); a crash is not a limit, so this check cannot tell whether logins are limited", l.noun(), a.Status, k)
		}
		switch {
		case a.Status != base.Status:
			r.Limited, r.Signal = true, fmt.Sprintf("answered %d instead of %d", a.Status, base.Status)
		case webform.Redirect(a) != r.Redirect:
			r.Limited, r.Signal = true, fmt.Sprintf("redirected to %s instead of %s", orNone(webform.Redirect(a)), orNone(r.Redirect))
		case ratelimit.NewWord(ratelimit.LimitWords(a.Body), baseWords) != "":
			r.Limited, r.Signal = true, "the answer has "+ratelimit.Said(ratelimit.NewWord(ratelimit.LimitWords(a.Body), baseWords))
		case ratelimit.NewWord(at.nextWords, nextWords) != "":
			r.Limited, r.Signal = true, "the page it redirected to has "+ratelimit.Said(ratelimit.NewWord(at.nextWords, nextWords))
		case a.Took >= 3*base.Took && a.Took >= time.Second:
			r.Limited, r.Signal = true, fmt.Sprintf("answered in %s instead of %s", a.Took.Round(time.Millisecond), base.Took.Round(time.Millisecond))
		}
		if r.Limited {
			r.limit = kindOf(at)
			return r, nil
		}
	}
	return r, nil
}

// noun is "URL" or "page", for messages.
func (l *Login) noun() string {
	if l.Page {
		return "page's form"
	}
	return "URL"
}

// flags names the flags that give the login, for messages.
func (l *Login) flags() string {
	if l.Page {
		return "--login-page and --login-body"
	}
	return "--login-url and --login-body"
}

func orNone(s string) string {
	if s == "" {
		return "no redirect"
	}
	return s
}

// shapeOf is what tells a login's answers apart for the right-password
// guard (ADR 0062): webform.Shape with the redirect's random values left
// out.
func shapeOf(a *egress.Answer) webform.Shape { return webform.ShapeOf(a, webform.Redirect(a)) }

// limitStatus names a status or header that always means a limit.
func limitStatus(a *egress.Answer) string {
	switch {
	case a.Status == http.StatusTooManyRequests || a.Status == http.StatusLocked || a.Status == http.StatusServiceUnavailable:
		return fmt.Sprintf("answered %d", a.Status)
	case a.Header.Get("Retry-After") != "":
		return "answered with a Retry-After header"
	}
	return ""
}

// Findings turns a result into findings: one when no limit was seen in
// at least DefaultAttempts attempts (issue #79). A run shows only that the
// app allowed that many guesses, never that it has no limit, so the
// finding says so. Fewer attempts give no finding: many apps limit at 5 to
// 30, so a limit just past a small N would be reported as none.
func Findings(l *Login, r Result, planned int) []findings.Finding {
	if r.Limited || r.Attempts < planned || planned < DefaultAttempts {
		return nil
	}
	f := findings.Finding{
		RuleID: "login-not-limited",
		Title:  fmt.Sprintf("No limit seen in %d failed logins", r.Attempts),
		Message: fmt.Sprintf("%d logins for the test account %q with a wrong password, one per second, all got the same answer (%s) with no slowdown, block, lockout or CAPTCHA, so an attacker can make at least %d guesses at this account's password. A login with the right password first %s, so these logins reached the app's login code. %s If the app has no limit, add one, for example a growing delay, a temporary lock or a CAPTCHA. SiegeKit does not see a limit per IP address or one across many accounts.",
			r.Attempts, l.User, r.answer(), r.Attempts, r.Right, aboveN(r.Attempts)),
		Severity: findings.Medium,
		CWEs:     []string{"CWE-307"},
		Location: findings.Location{URI: cmp.Or(r.URL, l.URL)},
		Family:   Family,
	}
	f.Sources = []findings.Source{{Plugin: ID, RuleID: f.RuleID}}
	f.ComputeFingerprint()
	return []findings.Finding{f}
}

// aboveN says what a run of n attempts cannot show (issue #79).
func aboveN(n int) string {
	return fmt.Sprintf("Many apps limit failed logins at 5 to 30, and NIST SP 800-63B allows at most 100 in a row for one account; SiegeKit does not see a limit set above %d attempts.", n)
}

// SprayFindings turns a spraying result into findings: one when no limit
// was seen in at least DefaultAttempts logins, medium like a login with no
// limit (owner 2026-11-22), and worded like it (issue #79).
func SprayFindings(l *Login, r Result, planned int) []findings.Finding {
	if r.Limited || r.Attempts < planned || planned < DefaultAttempts {
		return nil
	}
	f := findings.Finding{
		RuleID: "spray-not-limited",
		Title:  fmt.Sprintf("No limit seen in %d failed logins across accounts", r.Attempts),
		Message: fmt.Sprintf("The app limited failed logins for the one test account, but %d logins for %d different invented user names (siegekit-nobody-1 and on), one per second and all with the same wrong password, all got the same answer (%s) with no slowdown, block or CAPTCHA. So the limit seen is per account: an attacker who tries one common password on many accounts (password spraying) can make at least %d such guesses from one address. %s If the app has no such limit, also limit failed logins per client address, or across accounts.",
			r.Attempts, r.Attempts, r.answer(), r.Attempts, aboveN(r.Attempts)),
		Severity: findings.Medium,
		CWEs:     []string{"CWE-307"},
		Location: findings.Location{URI: cmp.Or(r.URL, l.URL)},
		Family:   Family,
	}
	f.Sources = []findings.Source{{Plugin: SprayID, RuleID: f.RuleID}}
	f.ComputeFingerprint()
	return []findings.Finding{f}
}

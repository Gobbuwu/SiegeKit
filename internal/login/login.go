// Package login is SiegeKit's login throttling check (ADR 0010, ADR 0030).
// It sends a few logins for a test account the user owns, each with a new
// randomly generated wrong password, at most one per second, and reports
// whether the app slows down, blocks, asks for a CAPTCHA or locks the
// account. It never tries a real password and never uses a password list.
package login

import (
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

// Login is a login request with {user} and {password} placeholders.
type Login struct {
	URL  string // origin and path, for plans and reports
	Path string // path on the target's origin
	User string
	body string
	json bool
}

// Parse checks the --login-url, --login-user and --login-body values. The
// URL must be on the target's origin (ADR 0005). A body that starts with
// "{" is sent as JSON, anything else as a form.
func Parse(rawURL, user, body string, t *target.URL) (*Login, error) {
	u, _, err := target.OnOrigin(t, rawURL, "--login-url", false)
	if err != nil {
		return nil, err
	}
	switch {
	case user == "":
		return nil, errors.New("--login-user is empty")
	case len(user) > maxUser:
		return nil, fmt.Errorf("--login-user is longer than %d bytes", maxUser)
	case !utf8.ValidString(user) || strings.ContainsFunc(user, unicode.IsControl):
		return nil, errors.New("--login-user contains control characters or invalid UTF-8")
	}
	if len(body) > maxBody {
		return nil, fmt.Errorf("--login-body is longer than %d bytes", maxBody)
	}
	if !strings.Contains(body, "{user}") || !strings.Contains(body, "{password}") {
		return nil, errors.New(`--login-body must contain {user} and {password}, for example '{"email":"{user}","password":"{password}"}' or 'username={user}&password={password}'`)
	}
	l := &Login{URL: u.String(), Path: u.Path, User: user, body: body, json: strings.HasPrefix(strings.TrimLeft(body, " \t\r\n"), "{")}
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

// ContentType is the request's content type.
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
	Attempts int    // logins answered by the target
	Limited  bool   // a limit was seen
	Signal   string // what showed the limit
	Baseline int    // the status of the first answer
}

// Summary says the result in one line, for reports.
func (r Result) Summary(planned int) string {
	if r.Limited {
		return fmt.Sprintf("limited after %d of %d attempts: %s", r.Attempts, planned, r.Signal)
	}
	return fmt.Sprintf("no limit seen in %d attempts, all answered %d", r.Attempts, r.Baseline)
}

// send and sleep are replaced in tests.
var (
	send  = egress.Send
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
func Spray(ctx context.Context, cfg egress.Config, l *Login, attempts int) (Result, error) {
	password := wrongPassword()
	i := 0
	return run(ctx, cfg, l, attempts, func() []byte {
		i++
		return l.renderFor(SprayUser(l, i), password)
	})
}

// Check sends attempts logins, at most one per Interval, and stops at the
// first sign of a limit. The first answer is the baseline: a 429, 423 or
// 503 status or a Retry-After header in a later answer, a status other than
// the baseline's, words about a lockout, CAPTCHA or too many attempts that
// the baseline did not have, or an answer at least 3 times slower than the
// baseline and at least 1 second long count as a limit (owner decision
// 2026-11-20, ADR 0030). cfg must not be for a deployed target.
func Check(ctx context.Context, cfg egress.Config, l *Login, attempts int) (Result, error) {
	return run(ctx, cfg, l, attempts, func() []byte { return l.render(wrongPassword()) })
}

// run sends attempts logins with the bodies body gives; Check and Spray
// share it, so both read a limit the same way.
func run(ctx context.Context, cfg egress.Config, l *Login, attempts int, body func() []byte) (Result, error) {
	if attempts < MinAttempts || attempts > MaxAttempts {
		return Result{}, fmt.Errorf("attempts must be from %d to %d", MinAttempts, MaxAttempts)
	}
	if cfg.ReadOnly {
		return Result{}, errors.New("the login throttling check sends POST requests, which this target does not allow")
	}
	var r Result
	var base *egress.Answer
	var baseWords []string
	var last time.Time
	for i := range attempts {
		if i > 0 {
			if err := sleep(ctx, Interval-now().Sub(last)); err != nil {
				return r, err
			}
		}
		last = now()
		a, err := send(ctx, cfg, http.MethodPost, l.Path, l.ContentType(), body(), MaxAnswer)
		if err != nil {
			if i == 0 {
				return r, fmt.Errorf("the login URL did not answer: %w", err)
			}
			if ctx.Err() != nil {
				return r, ctx.Err()
			}
			return r, fmt.Errorf("the target stopped answering after %d login(s): %v. A block of SiegeKit's address and a crash look the same from here, so this check cannot tell which it was", r.Attempts, err)
		}
		r.Attempts++
		if s := limitStatus(a); s != "" {
			r.Limited, r.Signal = true, s
			if i == 0 {
				r.Signal += ", already at the first attempt (perhaps from an earlier run)"
			}
			return r, nil
		}
		if i == 0 {
			switch {
			case a.Status == http.StatusNotFound || a.Status == http.StatusMethodNotAllowed || a.Status == http.StatusNotImplemented:
				return r, fmt.Errorf("the login URL answered %d to a POST; check --login-url", a.Status)
			case a.Status >= 500:
				return r, fmt.Errorf("the login URL answered %d (a server error) to a login with a wrong password; check --login-body", a.Status)
			}
			base, baseWords, r.Baseline = a, ratelimit.LimitWords(a.Body), a.Status
			continue
		}
		if a.Status >= 500 {
			return r, fmt.Errorf("the login URL answered %d (a server error) after %d login(s); a crash is not a limit, so this check cannot tell whether logins are limited", a.Status, r.Attempts-1)
		}
		switch {
		case a.Status != base.Status:
			r.Limited, r.Signal = true, fmt.Sprintf("answered %d instead of %d", a.Status, base.Status)
		case ratelimit.NewWord(ratelimit.LimitWords(a.Body), baseWords) != "":
			r.Limited, r.Signal = true, fmt.Sprintf("the answer says %q", ratelimit.NewWord(ratelimit.LimitWords(a.Body), baseWords))
		case a.Took >= 3*base.Took && a.Took >= time.Second:
			r.Limited, r.Signal = true, fmt.Sprintf("answered in %s instead of %s", a.Took.Round(time.Millisecond), base.Took.Round(time.Millisecond))
		}
		if r.Limited {
			return r, nil
		}
	}
	return r, nil
}

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

// Findings turns a result into findings: one when no limit was seen.
func Findings(l *Login, r Result, planned int) []findings.Finding {
	if r.Limited || r.Attempts < planned {
		return nil
	}
	f := findings.Finding{
		RuleID: "login-not-limited",
		Title:  "Failed logins are not limited",
		Message: fmt.Sprintf("%d logins for the test account %q with a wrong password, one per second, all got the same answer (%d) with no slowdown, block, lockout or CAPTCHA, so an attacker can keep guessing this account's password. Limit failed logins, for example with a growing delay, a temporary lock or a CAPTCHA. SiegeKit does not see a limit set above %d attempts, one per IP address, or one across many accounts.",
			r.Attempts, l.User, r.Baseline, planned),
		Severity: findings.Medium,
		CWEs:     []string{"CWE-307"},
		Location: findings.Location{URI: l.URL},
		Family:   Family,
	}
	f.Sources = []findings.Source{{Plugin: ID, RuleID: f.RuleID}}
	f.ComputeFingerprint()
	return []findings.Finding{f}
}

// SprayFindings turns a spraying result into findings: one when no limit
// was seen, medium like a login with no limit (owner 2026-11-22).
func SprayFindings(l *Login, r Result, planned int) []findings.Finding {
	if r.Limited || r.Attempts < planned {
		return nil
	}
	f := findings.Finding{
		RuleID: "spray-not-limited",
		Title:  "Logins across many accounts are not limited",
		Message: fmt.Sprintf("The app limited failed logins for the one test account, but %d logins for %d different invented user names (siegekit-nobody-1 and on), one per second and all with the same wrong password, all got the same answer (%d) with no slowdown, block or CAPTCHA. So the limit is per account only: an attacker who tries one common password on many accounts (password spraying) is never stopped. Also limit failed logins per client address, or across accounts. SiegeKit does not see a limit set above %d attempts.",
			r.Attempts, r.Attempts, r.Baseline, planned),
		Severity: findings.Medium,
		CWEs:     []string{"CWE-307"},
		Location: findings.Location{URI: l.URL},
		Family:   Family,
	}
	f.Sources = []findings.Source{{Plugin: SprayID, RuleID: f.RuleID}}
	f.ComputeFingerprint()
	return []findings.Finding{f}
}

// Package ratelimit is SiegeKit's rate-limit check (ADR 0011 item 2,
// ADR 0036). It sends a short burst of requests to one URL the user names,
// at most one per second, and reports whether the app shows a limit: a 429
// or 503 answer, or a rate-limit header. It never sends more than 50.
package ratelimit

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/Gobbuwu/SiegeKit/internal/egress"
	"github.com/Gobbuwu/SiegeKit/internal/findings"
	"github.com/Gobbuwu/SiegeKit/internal/mailcatcher"
	"github.com/Gobbuwu/SiegeKit/internal/target"
)

// ID, Name and Family describe the check in plans and reports.
const (
	ID     = "rate-limit"
	Name   = "Rate-limit check"
	Family = "dast"
)

// Limits of ADR 0011 and answer 7a: 20 requests by default, never more
// than 50, at most one per second.
const (
	DefaultRequests = 20
	MaxRequests     = 50
	MinRequests     = 2
	Interval        = time.Second
)

// MaxAnswer caps the body read from each answer.
const MaxAnswer = 2 << 20

const maxBody = 8 << 10

// Endpoint is the request the check repeats.
type Endpoint struct {
	URL    string // the URL as given, for plans and reports
	Path   string // path and query on the target's origin
	Method string // GET, or POST when a body is given
	// Page is the kind of page for the reset, sign-up and code checks
	// (ADR 0055), "" for --rate-limit-url. Its body is a template whose
	// {wrong} and {new} are filled in anew for each request.
	Page Page
	From string // where the page came from: its flag or the HAR file
	body []byte
	json bool
}

// Parse checks the --rate-limit-url and --rate-limit-body values. The URL
// must be on the target's origin (ADR 0005); it may have a query, such as
// a search term. With a body the request is a POST: JSON when the body
// starts with "{" or "[", a form otherwise.
func Parse(rawURL, body string, t *target.URL) (*Endpoint, error) {
	u, query, err := target.OnOrigin(t, rawURL, "--rate-limit-url", true)
	if err != nil {
		return nil, err
	}
	e := &Endpoint{URL: u.String(), Path: u.Path, Method: http.MethodGet}
	if query != "" {
		e.URL += "?" + query
		e.Path += "?" + query
	}
	if body != "" {
		if len(body) > maxBody {
			return nil, fmt.Errorf("--rate-limit-body is longer than %d bytes", maxBody)
		}
		trimmed := strings.TrimLeft(body, " \t\r\n")
		e.Method, e.body = http.MethodPost, []byte(body)
		e.json = strings.HasPrefix(trimmed, "{") || strings.HasPrefix(trimmed, "[")
		if e.json && !json.Valid(e.body) {
			return nil, errors.New("--rate-limit-body starts like JSON but is not valid JSON")
		}
		if !e.json {
			if _, err := url.ParseQuery(body); err != nil {
				return nil, fmt.Errorf("--rate-limit-body is not valid JSON or a valid form body: %v", err)
			}
		}
	}
	return e, nil
}

// ContentType is the request's content type, "" for a GET.
func (e *Endpoint) ContentType() string {
	switch {
	case e.Method == http.MethodGet:
		return ""
	case e.json:
		return "application/json"
	}
	return "application/x-www-form-urlencoded"
}

// Result is what the check saw.
type Result struct {
	Requests int    // requests the target answered
	Limited  bool   // a limit was seen
	Signal   string // what showed the limit
	Baseline int    // the status of the first answer
	// Changed counts answers whose status differs from the first one's.
	// Such a run is not reported as "not limited": a changed status may
	// be a limit that shows no 429, 503 or header (ADR 0055 item 7).
	Changed int
	// Limit is the number a RateLimit-Limit or X-RateLimit-Limit header
	// gave, 0 when none did (ADR 0055 item 5).
	Limit int
	// Window is how long the limit lasts by the limit answer's headers
	// (RateLimit-Policy's w, a reset time or Retry-After), 0 when they do
	// not say.
	Window time.Duration
	// Accepted counts answers below 400: on a sign-up page each may have
	// made an account, on a reset page each may have sent an email.
	Accepted int
	// To lists the email addresses the requests of a reset or sign-up page
	// held, once each, for counting their emails (ADR 0056).
	To []string
	// Mail is the count at the mail catcher, nil when none was given.
	Mail *Mail
}

// Mail is what a mail catcher received during a reset or sign-up page
// check (ADR 0056).
type Mail struct {
	Catcher string // the catcher, as the report names it
	Emails  int    // emails that arrived for the addresses in To
	// Settled is false when emails were still arriving when SiegeKit
	// stopped waiting, so Emails is the count so far.
	Settled bool
	// Any is set when the requests held no address, so every email that
	// arrived was counted.
	Any bool
}

// MailLimited reports whether the answers showed no limit but fewer emails
// arrived than requests were accepted: the app limits its emails, which
// is what a reset page's limit protects (design Q2 B, ADR 0056 item 4).
func (r Result) MailLimited() bool {
	m := r.Mail
	return m != nil && !r.Limited && m.Settled && m.Emails > 0 && m.Emails < r.Accepted
}

// said describes the count in a phrase.
func (m *Mail) said(r Result) string {
	to := " to the addresses sent"
	if m.Any {
		to = " to any address (the requests held none)"
	}
	es := func(n int) string {
		if n == 1 {
			return "1 email"
		}
		return fmt.Sprintf("%d emails", n)
	}
	switch {
	case !m.Settled:
		return fmt.Sprintf("%s had arrived at the mail catcher %s%s when SiegeKit stopped waiting after %s, and more were still arriving", es(m.Emails), m.Catcher, to, mailcatcher.Max)
	case r.MailLimited():
		return fmt.Sprintf("but only %s arrived at the mail catcher %s%s for the %d requests answered below 400: the app limits these emails", es(m.Emails), m.Catcher, to, r.Accepted)
	case m.Emails == 0:
		return fmt.Sprintf("no email arrived at the mail catcher %s%s: the app sent none for these requests, or does not send its mail there", m.Catcher, to)
	}
	return fmt.Sprintf("%s arrived at the mail catcher %s%s for %d requests answered below 400", es(m.Emails), m.Catcher, to, r.Accepted)
}

// Summary says the result in one line, for reports.
func (r Result) Summary(planned int) string {
	if r.Mail == nil {
		return r.summary(planned)
	}
	if r.MailLimited() {
		return fmt.Sprintf("no 429, 503 or rate-limit header in %d requests, all answered %d, %s", r.Requests, r.Baseline, r.Mail.said(r))
	}
	return r.summary(planned) + "; " + r.Mail.said(r)
}

func (r Result) summary(planned int) string {
	if r.Limited {
		s := fmt.Sprintf("limit seen after %d of %d requests: %s", r.Requests, planned, r.Signal)
		switch {
		case r.Limit > 0 && r.Window > 0:
			s += fmt.Sprintf(" (limit %d per %s)", r.Limit, r.Window)
		case r.Limit > 0:
			s += fmt.Sprintf(" (limit %d)", r.Limit)
		case r.Window > 0:
			s += fmt.Sprintf(" (for %s)", r.Window)
		}
		return s
	}
	if r.Changed > 0 {
		return fmt.Sprintf("no 429, 503 or rate-limit header in %d requests, but %d answered a status other than the first answer's %d, which may be a limit: not reported", r.Requests, r.Changed, r.Baseline)
	}
	s := fmt.Sprintf("no limit seen in %d requests, all answered %d with no rate-limit header", r.Requests, r.Baseline)
	if planned < DefaultRequests {
		s += fmt.Sprintf("; too few requests to report a finding: run again with --rate-limit-requests %d or more", DefaultRequests)
	}
	return s
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

// Check sends n requests, at most one per Interval, and stops at the first
// sign of a limit: a 429 or 503 answer, or a RateLimit-*, X-RateLimit-* or
// Retry-After header (answer 7a). The first answer must be a success or a
// client error other than 401, 403, 404, 405 and 501, so a wrong URL or a
// URL behind a login is reported as such rather than as "not limited". On
// a reset or code page a 401 or 403 is the answer to a wrong guess, so it
// is a valid first answer there; a sign-up's first answer must be below
// 400, or no account was made (ADR 0055 item 4). Data-changing requests
// (POST) need a configuration that allows them.
func Check(ctx context.Context, cfg egress.Config, e *Endpoint, n int) (Result, error) {
	if n < MinRequests || n > MaxRequests {
		return Result{}, fmt.Errorf("requests must be from %d to %d", MinRequests, MaxRequests)
	}
	if cfg.ReadOnly && e.Method != http.MethodGet {
		return Result{}, errors.New("the rate-limit check would send POST requests, which this target does not allow")
	}
	var r Result
	var last time.Time
	var baseWords []string // limit words the first answer already had
	for i := range n {
		if i > 0 {
			if err := sleep(ctx, Interval-now().Sub(last)); err != nil {
				return r, err
			}
		}
		last = now()
		body := e.next()
		if e.Page == Reset || e.Page == SignUp {
			for _, to := range mailcatcher.Addresses(body, e.Method == http.MethodPost && !e.json) {
				if !slices.Contains(r.To, to) && len(r.To) < MaxRequests {
					r.To = append(r.To, to)
				}
			}
		}
		a, err := send(ctx, cfg, e.Method, e.Path, e.ContentType(), body, MaxAnswer)
		if a == nil || err != nil && !errors.Is(err, egress.ErrTooLarge) {
			if ctx.Err() != nil {
				return r, ctx.Err()
			}
			if i == 0 {
				return r, fmt.Errorf("the URL did not answer: %v", err)
			}
			return r, fmt.Errorf("the target stopped answering after %d request(s): %v. A block of SiegeKit's address and a crash look the same from here, so this check cannot tell which it was", r.Requests, err)
		}
		r.Requests++
		if a.Status < 400 {
			r.Accepted++
		}
		if s := Signal(a.Status, a.Header); s != "" {
			r.Limited, r.Signal, r.Limit, r.Window = true, s, LimitNumber(a.Header), Window(a.Header, now())
			if i == 0 {
				r.Signal += ", already at the first request"
			}
			return r, nil
		}
		if i > 0 {
			// Many apps say so in words with the same status (Ory
			// Kratos: 400 "The request was submitted too often" after 5
			// wrong codes), as login-throttle reads them.
			if w := NewWord(LimitWords(a.Body), baseWords); w != "" {
				r.Limited, r.Signal, r.Window = true, fmt.Sprintf("the answer says %q", w), Window(a.Header, now())
				return r, nil
			}
		}
		if i == 0 {
			guess := e.Page == Reset || e.Page == Code
			switch {
			case (a.Status == http.StatusUnauthorized || a.Status == http.StatusForbidden) && !guess:
				return r, fmt.Errorf("the URL answered %d: it needs a login, which this check does not send; name a URL that answers without one", a.Status)
			case a.Status == http.StatusNotFound || a.Status == http.StatusMethodNotAllowed || a.Status == http.StatusNotImplemented:
				return r, fmt.Errorf("the URL answered %d to a %s; check %s", a.Status, e.Method, e.source())
			case a.Status >= 500:
				return r, fmt.Errorf("the URL answered %d (a server error); check %s", a.Status, e.source())
			case e.Page == SignUp && a.Status >= 400:
				return r, fmt.Errorf("the sign-up answered %d, so it made no account and its limit cannot be tested; check %s", a.Status, e.source())
			}
			r.Baseline, baseWords = a.Status, LimitWords(a.Body)
			continue
		}
		if a.Status != r.Baseline {
			r.Changed++
		}
		if a.Status >= 500 {
			return r, fmt.Errorf("the URL answered %d (a server error) after %d request(s); a crash is not a limit, so this check cannot tell whether requests are limited", a.Status, r.Requests-1)
		}
	}
	return r, nil
}

// limitWords are words that an answer about a limit uses, in lower case.
// "too often" is Ory Kratos's (1.3.1, measured 2026-11-23).
var limitWords = []string{"captcha", "too many", "too often", "locked", "lockout", "try again later", "rate limit", "rate-limit", "throttl"}

// LimitWords lists the limit words that body holds.
func LimitWords(body []byte) []string {
	lower := bytes.ToLower(body)
	var out []string
	for _, w := range limitWords {
		if bytes.Contains(lower, []byte(w)) {
			out = append(out, w)
		}
	}
	return out
}

// NewWord returns a word of now that base does not hold, or "".
func NewWord(now, base []string) string {
	for _, w := range now {
		found := false
		for _, b := range base {
			found = found || b == w
		}
		if !found {
			return w
		}
	}
	return ""
}

// Signal names a status or header that shows a rate limit (answer 7a): a
// 429 or 503 answer, a Retry-After header, or a header named RateLimit,
// RateLimit-* or X-RateLimit-* (the IETF draft's names and the common older
// ones, such as express-rate-limit's).
func Signal(status int, h http.Header) string {
	switch status {
	case http.StatusTooManyRequests, http.StatusServiceUnavailable:
		return fmt.Sprintf("answered %d", status)
	}
	if h.Get("Retry-After") != "" {
		return "answered with a Retry-After header"
	}
	// In name order: ranging over the map would name a different header
	// on each run when an answer has several (Juice Shop sends
	// X-RateLimit-Limit, -Remaining and -Reset).
	for _, k := range slices.Sorted(maps.Keys(h)) {
		c := http.CanonicalHeaderKey(k)
		if c == "Ratelimit" || strings.HasPrefix(c, "Ratelimit-") || strings.HasPrefix(c, "X-Ratelimit-") {
			return fmt.Sprintf("answered with a %s header", c)
		}
	}
	return ""
}

// Findings turns a result into findings: one when no limit was seen in
// all planned requests, at least DefaultRequests, and every answer had the
// first one's status. A run shows only that the app allowed that many, so
// the finding says so, and fewer give none (ADR 0062 item 7, issue #79).
// The reset, sign-up and code pages have their own (ADR 0055).
func Findings(e *Endpoint, r Result, planned int) []findings.Finding {
	if e.Page != "" {
		return pageFindings(e, r, planned)
	}
	if r.Limited || r.Requests < planned || r.Changed > 0 || planned < DefaultRequests {
		return nil
	}
	f := findings.Finding{
		RuleID: "rate-not-limited",
		Title:  fmt.Sprintf("No rate limit seen in %d requests", r.Requests),
		Message: fmt.Sprintf("%d %s requests to this URL, one per second, all answered %d, with no 429 or 503 answer and no rate-limit header (RateLimit-*, X-RateLimit-*, Retry-After), so anyone can call it at least %d times in a row. If this URL is expensive (a search, a report, an AI call) and has no limit, anyone can run up load or cost: limit it per client. SiegeKit does not see a limit set above %d requests, one that only slows answers, or one that shows no header and no 429 or 503. Check that this is the URL you meant: an app that answers every unknown page (a single-page app) shows no limit there either.",
			r.Requests, e.Method, r.Baseline, r.Requests, planned),
		Severity: findings.Low,
		CWEs:     []string{"CWE-770"},
		Location: findings.Location{URI: strings.SplitN(e.URL, "?", 2)[0]},
		Family:   Family,
	}
	f.Sources = []findings.Source{{Plugin: ID, RuleID: f.RuleID}}
	f.ComputeFingerprint()
	return []findings.Finding{f}
}

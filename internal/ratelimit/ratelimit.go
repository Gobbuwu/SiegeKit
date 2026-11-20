// Package ratelimit is SiegeKit's rate-limit check (ADR 0011 item 2,
// ADR 0036). It sends a short burst of requests to one URL the user names,
// at most one per second, and reports whether the app shows a limit: a 429
// or 503 answer, or a rate-limit header. It never sends more than 50.
package ratelimit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Gobbuwu/SiegeKit/internal/egress"
	"github.com/Gobbuwu/SiegeKit/internal/findings"
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
	body   []byte
	json   bool
}

// Parse checks the --rate-limit-url and --rate-limit-body values. The URL
// must be on the target's origin (ADR 0005); it may have a query, such as
// a search term. With a body the request is a POST: JSON when the body
// starts with "{" or "[", a form otherwise.
func Parse(rawURL, body string, t *target.URL) (*Endpoint, error) {
	if strings.Contains(rawURL, "#") {
		return nil, errors.New("--rate-limit-url must not have a fragment")
	}
	pathURL, query, _ := strings.Cut(rawURL, "?")
	u, err := target.Parse(pathURL)
	if err != nil {
		return nil, fmt.Errorf("--rate-limit-url: %w", err)
	}
	if u.Origin() != t.Origin() {
		return nil, fmt.Errorf("--rate-limit-url %s is not on the target's origin %s; SiegeKit sends requests only to the target", u, t.Origin())
	}
	if !strings.HasPrefix(u.Path, "/") || strings.HasPrefix(u.Path, "//") {
		return nil, errors.New("--rate-limit-url must have a path that starts with a single /")
	}
	if _, err := url.ParseQuery(query); err != nil {
		return nil, fmt.Errorf("--rate-limit-url has an invalid query: %v", err)
	}
	if strings.ContainsAny(query, " \t\r\n") {
		return nil, errors.New("--rate-limit-url has spaces in its query; encode them as %20")
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
}

// Summary says the result in one line, for reports.
func (r Result) Summary(planned int) string {
	if r.Limited {
		return fmt.Sprintf("limit seen after %d of %d requests: %s", r.Requests, planned, r.Signal)
	}
	return fmt.Sprintf("no limit seen in %d requests, all answered %d with no rate-limit header", r.Requests, r.Baseline)
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
)

// Check sends n requests, at most one per Interval, and stops at the first
// sign of a limit: a 429 or 503 answer, or a RateLimit-*, X-RateLimit-* or
// Retry-After header (answer 7a). The first answer must be a success or a
// client error other than 401, 403, 404, 405 and 501, so a wrong URL or a
// URL behind a login is reported as such rather than as "not limited".
// Data-changing requests (POST) need a configuration that allows them.
func Check(ctx context.Context, cfg egress.Config, e *Endpoint, n int) (Result, error) {
	if n < MinRequests || n > MaxRequests {
		return Result{}, fmt.Errorf("requests must be from %d to %d", MinRequests, MaxRequests)
	}
	if cfg.ReadOnly && e.Method != http.MethodGet {
		return Result{}, errors.New("the rate-limit check would send POST requests, which this target does not allow")
	}
	var r Result
	var last time.Time
	for i := range n {
		if i > 0 {
			if err := sleep(ctx, Interval-time.Since(last)); err != nil {
				return r, err
			}
		}
		last = time.Now()
		a, err := send(ctx, cfg, e.Method, e.Path, e.ContentType(), e.body, MaxAnswer)
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
		if s := Signal(a.Status, a.Header); s != "" {
			r.Limited, r.Signal = true, s
			if i == 0 {
				r.Signal += ", already at the first request"
			}
			return r, nil
		}
		if i == 0 {
			switch {
			case a.Status == http.StatusUnauthorized || a.Status == http.StatusForbidden:
				return r, fmt.Errorf("the URL answered %d: it needs a login, which this check does not send; name a URL that answers without one", a.Status)
			case a.Status == http.StatusNotFound || a.Status == http.StatusMethodNotAllowed || a.Status == http.StatusNotImplemented:
				return r, fmt.Errorf("the URL answered %d to a %s; check --rate-limit-url and --rate-limit-body", a.Status, e.Method)
			case a.Status >= 500:
				return r, fmt.Errorf("the URL answered %d (a server error); check --rate-limit-url and --rate-limit-body", a.Status)
			}
			r.Baseline = a.Status
			continue
		}
		if a.Status >= 500 {
			return r, fmt.Errorf("the URL answered %d (a server error) after %d request(s); a crash is not a limit, so this check cannot tell whether requests are limited", a.Status, r.Requests-1)
		}
	}
	return r, nil
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
	for k := range h {
		c := http.CanonicalHeaderKey(k)
		if c == "Ratelimit" || strings.HasPrefix(c, "Ratelimit-") || strings.HasPrefix(c, "X-Ratelimit-") {
			return fmt.Sprintf("answered with a %s header", c)
		}
	}
	return ""
}

// Findings turns a result into findings: one when no limit was seen in
// all planned requests.
func Findings(e *Endpoint, r Result, planned int) []findings.Finding {
	if r.Limited || r.Requests < planned {
		return nil
	}
	f := findings.Finding{
		RuleID: "rate-not-limited",
		Title:  "Requests are not rate limited",
		Message: fmt.Sprintf("%d %s requests to this URL, one per second, all answered %d, with no 429 or 503 answer and no rate-limit header (RateLimit-*, X-RateLimit-*, Retry-After). If this URL is expensive (a search, a report, an AI call), anyone can call it as often as they like and run up load or cost: limit it per client. SiegeKit does not see a limit set above %d requests, one that only slows answers, or one that shows no header and no 429 or 503. Check that this is the URL you meant: an app that answers every unknown page (a single-page app) shows no limit there either.",
			r.Requests, e.Method, r.Baseline, planned),
		Severity: findings.Low,
		CWEs:     []string{"CWE-770"},
		Location: findings.Location{URI: strings.SplitN(e.URL, "?", 2)[0]},
		Family:   Family,
	}
	f.Sources = []findings.Source{{Plugin: ID, RuleID: f.RuleID}}
	f.ComputeFingerprint()
	return []findings.Finding{f}
}

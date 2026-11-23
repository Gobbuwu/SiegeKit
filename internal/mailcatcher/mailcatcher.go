// Package mailcatcher counts the emails an app sends while SiegeKit's
// password-reset and sign-up checks run, at a local Mailpit the person
// points the app's mail setting at (ADR 0056). It only reads: it sends GET
// requests to Mailpit's API and never deletes or changes a message.
package mailcatcher

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"github.com/Gobbuwu/SiegeKit/internal/egress"
	"github.com/Gobbuwu/SiegeKit/internal/target"
)

// Flag is the command-line flag that names the mail catcher.
const Flag = "--mail-catcher"

// Limits of one count. Mailpit keeps 500 messages by default, so a count
// never reads more than that many.
const (
	pageSize    = 50
	maxMessages = 500
	maxAnswer   = 4 << 20
)

// Wait times after a check's last request (ADR 0056 item 3): the count
// stops when no new email arrived for Quiet, or after Max. Gitea 1.24.6
// delivered a reset email 1.7 s after the request (measured 2026-11-23).
// They are variables only so tests can shorten them.
var (
	Quiet = 5 * time.Second
	Max   = 30 * time.Second
	Poll  = time.Second
)

// Parse checks the --mail-catcher value before anything is sent: an http
// or https URL of Mailpit's web interface (its base, such as
// http://127.0.0.1:8025/, or the --webroot it runs under), with no query,
// fragment, user name or password.
func Parse(raw string) (*target.URL, error) {
	if strings.ContainsAny(raw, "?#") {
		return nil, fmt.Errorf("%s must not have a query or fragment: give Mailpit's address, such as http://127.0.0.1:8025/", Flag)
	}
	u, err := target.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", Flag, err)
	}
	if !target.SendablePath(u.Path) {
		return nil, fmt.Errorf("%s must have a path that starts with a single /", Flag)
	}
	return u, nil
}

// Catcher is a Mailpit that answered.
type Catcher struct {
	URL     *target.URL
	Addrs   []netip.Addr
	Version string // Mailpit's version, from its API
	cfg     egress.Config
}

// String names the catcher in plans and reports.
func (c *Catcher) String() string { return fmt.Sprintf("%s (Mailpit %s)", c.URL, c.Version) }

// get is replaced in tests.
var get = egress.SendHeader

// Open resolves the catcher once and asks Mailpit for its version. It must
// be on this machine or the local network, as a local target is (ADR
// 0005): the counts are of a test app's mail, never of a hosted mailbox.
func Open(ctx context.Context, r target.Resolver, u *target.URL, version string) (*Catcher, error) {
	addrs, err := target.Resolve(ctx, r, u)
	if err != nil {
		return nil, fmt.Errorf("the mail catcher %s could not be looked up: %v", u, err)
	}
	for _, a := range addrs {
		if c := target.Classify(a); c != target.Loopback && c != target.Private {
			return nil, fmt.Errorf("the mail catcher %s resolves to %s, which is not on this machine or a private network; SiegeKit counts emails only at a local Mailpit", u, a)
		}
	}
	c := &Catcher{URL: u, Addrs: addrs, cfg: egress.Config{Target: u, Addrs: addrs, Version: version, ReadOnly: true}}
	var info struct {
		Version  string
		Messages *int
	}
	if err := c.getJSON(ctx, "info", &info); err != nil {
		return nil, err
	}
	if info.Version == "" || info.Messages == nil {
		return nil, fmt.Errorf("%s answered %s without Mailpit's version and message count: is this Mailpit's address?", u, c.path("info"))
	}
	c.Version = info.Version
	return c, nil
}

// path is an API path under the catcher's base path.
func (c *Catcher) path(p string) string {
	return strings.TrimSuffix(c.URL.Path, "/") + "/api/v1/" + p
}

func (c *Catcher) getJSON(ctx context.Context, p string, v any) error {
	a, err := get(ctx, c.cfg, http.MethodGet, c.path(p), http.Header{"Accept": {"application/json"}}, nil, maxAnswer)
	if err != nil {
		return fmt.Errorf("the mail catcher %s did not answer: %v", c.URL, err)
	}
	if a.Status != http.StatusOK {
		return fmt.Errorf("the mail catcher answered %d to GET %s: is this Mailpit's address, and is its API open without a password?", a.Status, strings.SplitN(c.path(p), "?", 2)[0])
	}
	if err := json.Unmarshal(a.Body, v); err != nil {
		return fmt.Errorf("the mail catcher's answer to GET %s is not Mailpit's JSON: %v", strings.SplitN(c.path(p), "?", 2)[0], err)
	}
	return nil
}

type address struct{ Address string }

type message struct {
	ID          string
	To, Cc, Bcc []address
}

type list struct {
	Total    *int `json:"total"`
	Messages []message
}

// Mark is the newest message before a check, so the count after it reads
// only the messages that came later.
type Mark struct{ newest string }

// Mark reads the newest message now.
func (c *Catcher) Mark(ctx context.Context) (Mark, error) {
	var l list
	if err := c.getJSON(ctx, "messages?limit=1", &l); err != nil {
		return Mark{}, err
	}
	if l.Total == nil {
		return Mark{}, errors.New("the mail catcher's message list has no total: is this Mailpit?")
	}
	if len(l.Messages) == 0 {
		return Mark{}, nil
	}
	return Mark{newest: l.Messages[0].ID}, nil
}

// Count counts the messages that arrived after m and were sent to one of
// to (To, Cc or Bcc; any address when to is empty). Mailpit lists the
// newest first, so it reads until it reaches m's message.
func (c *Catcher) Count(ctx context.Context, m Mark, to []string) (int, error) {
	want := map[string]bool{}
	for _, a := range to {
		want[strings.ToLower(a)] = true
	}
	seen := map[string]bool{}
	n := 0
	for start := 0; start < maxMessages; start += pageSize {
		var l list
		if err := c.getJSON(ctx, fmt.Sprintf("messages?start=%d&limit=%d", start, pageSize), &l); err != nil {
			return 0, err
		}
		for _, msg := range l.Messages {
			if m.newest != "" && msg.ID == m.newest {
				return n, nil
			}
			if seen[msg.ID] { // a message that arrived during the read moves the pages
				continue
			}
			seen[msg.ID] = true
			if sentTo(msg, want) {
				n++
			}
		}
		if len(l.Messages) < pageSize {
			if m.newest != "" {
				return 0, errors.New("the message that was newest before the check is gone from the mail catcher (deleted, or pushed out by its message limit), so the emails cannot be counted")
			}
			return n, nil
		}
	}
	return 0, fmt.Errorf("more than %d messages arrived at the mail catcher during the check, so they were not counted", maxMessages)
}

func sentTo(m message, want map[string]bool) bool {
	if len(want) == 0 {
		return true
	}
	for _, as := range [][]address{m.To, m.Cc, m.Bcc} {
		for _, a := range as {
			if want[strings.ToLower(a.Address)] {
				return true
			}
		}
	}
	return false
}

// Tally is a count after a check.
type Tally struct {
	Emails int
	// Settled is false when emails were still arriving at Max, so Emails
	// is only the count so far.
	Settled bool
	Waited  time.Duration
}

// sleep and now are replaced in tests.
var (
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
	now = time.Now
)

// Settle counts after a check's last request, once per Poll, until no new
// email arrived for Quiet or Max has passed: apps send mail from a queue,
// a little after they answer.
func (c *Catcher) Settle(ctx context.Context, m Mark, to []string) (Tally, error) {
	start := now()
	last, changed := -1, start
	for {
		n, err := c.Count(ctx, m, to)
		if err != nil {
			return Tally{}, err
		}
		t := now()
		if n != last {
			last, changed = n, t
		}
		if t.Sub(changed) >= Quiet {
			return Tally{Emails: n, Settled: true, Waited: t.Sub(start)}, nil
		}
		if t.Sub(start) >= Max {
			return Tally{Emails: n, Waited: t.Sub(start)}, nil
		}
		if err := sleep(ctx, Poll); err != nil {
			return Tally{}, err
		}
	}
}

// Addresses lists the email addresses in a request body, as sent: in a
// form, after decoding it. A reset body holds the test account's address;
// a sign-up's holds a new one each time.
func Addresses(body []byte, form bool) []string {
	s := string(body)
	if form {
		if d, err := url.QueryUnescape(strings.ReplaceAll(s, "+", " ")); err == nil {
			s = d
		}
	}
	var out []string
	for _, tok := range strings.FieldsFunc(s, func(r rune) bool {
		return !(r == '@' || r == '.' || r == '-' || r == '_' || r == '+' ||
			r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9')
	}) {
		tok = strings.Trim(tok, ".")
		at := strings.IndexByte(tok, '@')
		if at > 0 && at == strings.LastIndexByte(tok, '@') && strings.Contains(tok[at+1:], ".") && !strings.HasSuffix(tok, ".") {
			out = append(out, strings.ToLower(tok))
		}
	}
	return out
}

// Package served fetches the files a web app serves, for the secrets check
// of ADR 0010 and ADR 0032: the start page and the same-origin scripts,
// styles, JSON files and source maps it links, one level deep. Gitleaks
// then reads them like a source directory.
package served

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Gobbuwu/SiegeKit/internal/egress"
	"github.com/Gobbuwu/SiegeKit/internal/findings"
	"github.com/Gobbuwu/SiegeKit/internal/target"
)

// ID, Name and Family describe the check in plans and reports.
const (
	ID     = "served-secrets"
	Name   = "Secrets in served files"
	Family = "secrets"
)

// Limits of ADR 0032 (owner decision 2026-11-20): at most 200 GET requests
// sent, redirects included, and at most 10 MiB per answer.
const (
	MaxRequests  = 200
	MaxFileSize  = 10 << 20
	maxRedirects = 5
)

// Kind is what a fetched file is.
type Kind string

// The kinds of fetched files.
const (
	Page      Kind = "page"
	Script    Kind = "script"
	Style     Kind = "style"
	JSON      Kind = "JSON"
	SourceMap Kind = "source map"
)

var ext = map[Kind]string{Page: ".html", Script: ".js", Style: ".css", JSON: ".json", SourceMap: ".map"}

// File is one fetched file.
type File struct {
	Name string // file name in the scanned directory
	URL  string // origin and path, without the query
	Kind Kind
}

// Result is what Collect fetched and left out.
type Result struct {
	Files       []File
	Requests    int // GET requests the target answered, redirects included
	OtherOrigin int // links to another origin, not fetched (ADR 0005)
	BadPath     int // links whose path does not start with a single /, not fetched (ADR 0042)
	Failed      int // answered with a status other than 200, did not answer, or redirected elsewhere
	TooLarge    int // answers larger than MaxFileSize
	OverLimit   int // links not fetched because MaxRequests was reached
}

// Summary says what was scanned in one line, for reports.
func (r Result) Summary() string {
	n := map[Kind]int{}
	for _, f := range r.Files {
		n[f.Kind]++
	}
	var parts []string
	for _, k := range []Kind{Page, Script, Style, JSON, SourceMap} {
		if n[k] > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n[k], plural(k, n[k])))
		}
	}
	s := fmt.Sprintf("scanned %d file(s): %s", len(r.Files), strings.Join(parts, ", "))
	var left []string
	for _, x := range []struct {
		n    int
		what string
	}{
		{r.OtherOrigin, "on another origin"},
		{r.BadPath, "with a path that does not start with a single /"},
		{r.Failed, "not answered with 200"},
		{r.TooLarge, "larger than 10 MiB"},
		{r.OverLimit, fmt.Sprintf("over the %d-request limit", MaxRequests)},
	} {
		if x.n > 0 {
			left = append(left, fmt.Sprintf("%d %s", x.n, x.what))
		}
	}
	if len(left) > 0 {
		s += "; not scanned: " + strings.Join(left, ", ")
	}
	return s
}

func plural(k Kind, n int) string {
	if n == 1 || k == JSON {
		return string(k)
	}
	return string(k) + "s"
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

type collector struct {
	ctx      context.Context
	cfg      egress.Config
	interval time.Duration
	dir      string
	last     time.Time
	sent     int // requests sent, answered or not: at most MaxRequests
	res      Result
	seen     map[string]bool
}

var errLimit = errors.New("request limit reached")

// Collect fetches the start page of cfg.Target and the files it links into
// dir, which must exist, with GET requests only, at most rate per second.
// It fails only when the start page cannot be fetched or a file cannot be
// written.
func Collect(ctx context.Context, cfg egress.Config, rate float64, dir string) (Result, error) {
	c := &collector{ctx: ctx, cfg: cfg, dir: dir, seen: map[string]bool{}}
	if rate > 0 {
		c.interval = time.Duration(float64(time.Second) / rate)
	}
	start, err := url.Parse(cfg.Target.Origin() + cfg.Target.Path)
	if err != nil {
		return c.res, err
	}
	a, page, err := c.get(start)
	switch {
	case ctx.Err() != nil:
		return c.res, ctx.Err()
	case err != nil:
		return c.res, fmt.Errorf("the start page could not be fetched: %w", err)
	case a.Status != http.StatusOK:
		return c.res, fmt.Errorf("the start page answered %d, not 200", a.Status)
	}
	if err := c.save(page, Page, a.Body); err != nil {
		return c.res, err
	}
	type item struct {
		u    *url.URL
		kind Kind
	}
	var queue []item
	add := func(base *url.URL, ref string, kind Kind) {
		u, ok := c.resolve(base, ref)
		if !ok {
			return
		}
		key := requestPath(u)
		if !c.seen[key] {
			c.seen[key] = true
			queue = append(queue, item{u, kind})
		}
	}
	c.seen[requestPath(page)] = true
	for _, l := range Links(a.Body) {
		add(page, l.Ref, l.Kind)
	}
	for i := 0; i < len(queue); i++ {
		it := queue[i]
		a, u, err := c.get(it.u)
		switch {
		case ctx.Err() != nil:
			return c.res, ctx.Err()
		case errors.Is(err, errLimit):
			c.res.OverLimit += len(queue) - i
			return c.res, nil
		case errors.Is(err, egress.ErrTooLarge):
			c.res.TooLarge++
			continue
		case err != nil || a.Status != http.StatusOK:
			c.res.Failed++
			continue
		}
		if err := c.save(u, it.kind, a.Body); err != nil {
			return c.res, err
		}
		// A script's or style's source map counts as part of it.
		if it.kind == Script || it.kind == Style {
			ref := a.Header.Get("SourceMap")
			if ref == "" {
				ref = a.Header.Get("X-SourceMap")
			}
			if ref == "" {
				ref = SourceMapRef(a.Body)
			}
			if ref != "" {
				add(u, ref, SourceMap)
			}
		}
	}
	return c.res, nil
}

// resolve resolves ref against base and keeps it only on the target's
// origin. A link elsewhere is counted, not fetched (ADR 0005); data:,
// javascript: and similar are ignored.
func (c *collector) resolve(base *url.URL, ref string) (*url.URL, bool) {
	r, err := url.Parse(ref)
	if err != nil || len(ref) > maxRef {
		return nil, false
	}
	u := base.ResolveReference(r)
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, false
	}
	if u.User != nil || !c.sameOrigin(u) {
		c.res.OtherOrigin++
		return nil, false
	}
	u.Fragment, u.RawFragment = "", ""
	if !target.SendablePath(requestPath(u)) {
		c.res.BadPath++
		return nil, false
	}
	return u, true
}

func (c *collector) sameOrigin(u *url.URL) bool {
	t, err := target.Parse(u.Scheme + "://" + u.Host + "/")
	return err == nil && t.Origin() == c.cfg.Target.Origin()
}

func requestPath(u *url.URL) string {
	p := u.EscapedPath()
	if p == "" {
		p = "/"
	}
	if u.RawQuery != "" {
		p += "?" + u.RawQuery
	}
	return p
}

// get fetches u, following same-origin redirects, and returns the answer
// and the final URL.
func (c *collector) get(u *url.URL) (*egress.Answer, *url.URL, error) {
	for hops := 0; ; hops++ {
		if c.sent >= MaxRequests {
			return nil, u, errLimit
		}
		if !c.last.IsZero() {
			if err := sleep(c.ctx, c.interval-time.Since(c.last)); err != nil {
				return nil, u, err
			}
		}
		c.last = time.Now()
		c.sent++
		a, err := send(c.ctx, c.cfg, http.MethodGet, requestPath(u), "", nil, MaxFileSize)
		if a != nil {
			c.res.Requests++
		}
		if err != nil {
			return a, u, err
		}
		switch a.Status {
		case http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther, http.StatusTemporaryRedirect, http.StatusPermanentRedirect:
		default:
			return a, u, nil
		}
		if hops == maxRedirects {
			return a, u, nil
		}
		loc, err := url.Parse(a.Header.Get("Location"))
		if err != nil || a.Header.Get("Location") == "" {
			return a, u, nil
		}
		next := u.ResolveReference(loc)
		if (next.Scheme != "http" && next.Scheme != "https") || next.User != nil || !c.sameOrigin(next) {
			return a, u, nil // not followed: another origin
		}
		u = next
	}
}

// save writes one fetched file, readable by the tool's user (ADR 0021).
func (c *collector) save(u *url.URL, k Kind, body []byte) error {
	name := fmt.Sprintf("%03d-%s%s", len(c.res.Files)+1, strings.ReplaceAll(string(k), " ", "-"), ext[k])
	// #nosec G306 -- the tool runs as another user and must read the file
	if err := os.WriteFile(filepath.Join(c.dir, name), body, 0o644); err != nil {
		return err
	}
	c.res.Files = append(c.res.Files, File{Name: name, URL: c.cfg.Target.Origin() + u.EscapedPath(), Kind: k})
	return nil
}

// Findings places the tool's findings at the URL each file came from, and
// names this check as their source.
func Findings(fs []findings.Finding, r Result) []findings.Finding {
	byName := map[string]File{}
	for _, f := range r.Files {
		byName[f.Name] = f
	}
	out := make([]findings.Finding, 0, len(fs))
	for _, f := range fs {
		file, ok := byName[f.Location.URI]
		if !ok {
			continue // not one of the fetched files; cannot happen with Gitleaks
		}
		f.Location.URI = file.URL
		f.Message = strings.TrimSpace(f.Message) + fmt.Sprintf(" Found in the %s served at %s: anyone who opens the site can read it.", file.Kind, file.URL)
		f.Sources = append([]findings.Source(nil), f.Sources...)
		for i := range f.Sources {
			f.Sources[i].Plugin = ID
		}
		f.ComputeFingerprint()
		out = append(out, f)
	}
	return out
}

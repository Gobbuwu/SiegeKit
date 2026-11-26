package egress

import (
	"context"
	"fmt"
	"io"
	"mime"
	"net/http"
	"sync"
	"time"
)

// A host can stop serving the app partway through a run and answer every
// request with one page of its own: Vercel's Security Checkpoint (a 403 of
// about 25 KB) did on Porchlet's R1p run. Every answer then still looks
// healthy to the proxy's server-error rule, so tools and SiegeKit's own
// checks went on and reported the block page as findings (issue #86). The
// watch notices that change and stops the check (ADR 0071):
//
//   - D1: the start page is fetched before each check and, when the check
//     did not stop earlier, after it. Its status is compared with the
//     status the start page had at the run's first check.
//   - D3: when StreakAnswers answers in a row share a shape (status, media
//     type, length within 5%), the start page is fetched once for that
//     shape; if it now has the same shape and did not at the run's first
//     check, the check stops.
//
// Both were measured through SiegeKit with a block page that starts partway
// through ffuf, Nuclei, ZAP and access-control (CI runs 45529252929,
// 45537954705, 45544252358): D3 stops a check within 10 to 19 blocked
// answers, and D1 catches a block in a check's last answers, which D3 has
// too few of.

// StreakAnswers is how many answers in a row of one shape make the watch
// fetch the start page (D3). Measured with 10: no false stop on full scans
// of Juice Shop, Gitea and a Next.js-like app.
const StreakAnswers = 10

// maxShapeBody is the longest body whose length a shape records; a longer
// one has an unknown length and is never like another.
const maxShapeBody = 2 << 20

// StartPageAgent is the User-Agent of the watch's start-page fetches, so a
// server log can tell them from the checks' requests.
const startPageAgent = " (start page check)"

// Shape is what the watch compares answers by.
type Shape struct {
	Status int
	Type   string // media type, without parameters
	Len    int64  // body length; -1 when unknown or over 2 MiB
}

// Like reports whether a and b have the same status and media type and
// lengths within 5% of the longer one. The margin covers pages that differ
// by a few bytes per answer, such as Vercel's checkpoint (10 bytes apart in
// two fetches, measured 2026-11-25).
func (a Shape) Like(b Shape) bool {
	if a.Status != b.Status || a.Type != b.Type {
		return false
	}
	return near(a.Len, b.Len)
}

func near(a, b int64) bool {
	if a < 0 || b < 0 {
		return false
	}
	d := a - b
	if d < 0 {
		d = -d
	}
	return d <= max(a, b)/20
}

func (a Shape) String() string {
	t := a.Type
	if t == "" {
		t = "no type"
	}
	if a.Len < 0 {
		return fmt.Sprintf("%d (%s, over %d bytes)", a.Status, t, maxShapeBody)
	}
	return fmt.Sprintf("%d (%s, %d bytes)", a.Status, t, a.Len)
}

func mediaType(h http.Header) string {
	t, _, _ := mime.ParseMediaType(h.Get("Content-Type"))
	return t
}

// Block is what the watch saw when the host stopped serving the app.
type Block struct {
	// Page is the shape of the page the host answered with; Status is 0
	// when the start page could not be fetched.
	Page Shape
	// Reason says what was seen, for the report.
	Reason string
}

// Matches reports whether an answer with this status and body length was
// the block page: the same status and a length within 5% (F2, ADR 0071).
func (b *Block) Matches(status int, length int64) bool {
	return b != nil && b.Page.Status != 0 && status == b.Page.Status && near(length, b.Page.Len)
}

// Watch is one run's watch on the target's start page. It is safe for use
// by one check at a time.
type Watch struct {
	cfg Config

	mu      sync.Mutex
	base    Shape
	hasBase bool
}

// NewWatch watches the start page of cfg's target, fetched with cfg's
// pinned addresses, TLS setting and extra headers. A nil *Watch watches
// nothing.
func NewWatch(cfg Config) *Watch {
	cfg.Watch = nil
	return &Watch{cfg: cfg}
}

// Begin starts watching one check: it fetches the start page (D1). The
// run's first Begin records the start page; a later one whose start page
// has another status, or cannot be fetched, returns a Unit that is already
// blocked, and the check must not send its requests. Begin on a nil Watch
// returns nil, which watches nothing.
func (w *Watch) Begin(ctx context.Context) *Unit {
	if w == nil {
		return nil
	}
	u := &Unit{w: w}
	s, err := w.startPage(ctx)
	if ctx.Err() != nil {
		return u // interrupted: the run ends without a report
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	switch {
	case err != nil:
		u.block = &Block{Reason: fmt.Sprintf("the host stopped serving the app before this check: the start page could not be fetched (%v)", err)}
	case !w.hasBase:
		w.base, w.hasBase = s, true
	case s.Status != w.base.Status:
		u.block = &Block{Page: s, Reason: fmt.Sprintf("the host stopped serving the app before this check: the start page answered %s; at the run's first check it answered %d", s, w.base.Status)}
	}
	return u
}

// startPage fetches the target URL once, without following redirects.
func (w *Watch) startPage(ctx context.Context) (Shape, error) {
	tr := newTransport(w.cfg)
	defer tr.CloseIdleConnections()
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, w.cfg.Target.String(), nil)
	if err != nil {
		return Shape{}, err
	}
	req.Header.Set("User-Agent", "SiegeKit/"+w.cfg.Version+startPageAgent)
	addExtra(req.Header, w.cfg.Header)
	resp, err := tr.RoundTrip(req)
	if err != nil {
		return Shape{}, err
	}
	defer resp.Body.Close()
	n, err := io.Copy(io.Discard, io.LimitReader(resp.Body, maxShapeBody+1))
	if err != nil {
		return Shape{}, err
	}
	if n > maxShapeBody {
		n = -1
	}
	return Shape{Status: resp.StatusCode, Type: mediaType(resp.Header), Len: n}, nil
}

// Unit watches one check. Its methods may be called from several
// goroutines; all of them do nothing on a nil *Unit.
type Unit struct {
	w *Watch

	mu       sync.Mutex
	block    *Block
	ended    bool
	streak   Shape
	streakN  int
	checking bool
	cleared  []Shape
}

// Block returns what stopped the check, or nil.
func (u *Unit) Block() *Block {
	if u == nil {
		return nil
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.block
}

// answer records one answer the check got (D3) and returns the block once
// the watch has seen one. It may fetch the start page, so it is called
// after the answer's body was read and outside any lock of the caller.
func (u *Unit) answer(ctx context.Context, s Shape) *Block {
	if u == nil {
		return nil
	}
	u.mu.Lock()
	if u.block != nil {
		defer u.mu.Unlock()
		return u.block
	}
	if s.Like(u.streak) {
		u.streakN++
	} else {
		u.streak, u.streakN = s, 1
	}
	if u.streakN < StreakAnswers || u.checking || u.known(u.streak) {
		u.mu.Unlock()
		return nil
	}
	// Each shape is checked once: a page every guessed path gets, such as
	// an app's not-found page, costs one start-page fetch per check.
	streak := u.streak
	u.checking = true
	u.mu.Unlock()

	page, err := u.w.startPage(ctx)
	base, _ := u.w.baseline()

	u.mu.Lock()
	defer u.mu.Unlock()
	u.checking = false
	u.cleared = append(u.cleared, streak)
	if err == nil && page.Like(streak) && !base.Like(streak) && u.block == nil {
		u.block = &Block{Page: page, Reason: fmt.Sprintf("the host stopped serving the app: %d answers in a row and the start page were the same page, %s; at the run's first check the start page answered %d", StreakAnswers, page, base.Status)}
	}
	return u.block
}

// known reports whether shape s was already checked. The caller holds u.mu.
func (u *Unit) known(s Shape) bool {
	for _, c := range u.cleared {
		if c.Like(s) {
			return true
		}
	}
	return false
}

// End finishes watching the check: unless it already stopped, it fetches
// the start page again (D1) and returns a block when its status changed or
// it could not be fetched. End is called once, after the check's last
// request.
func (u *Unit) End(ctx context.Context) *Block {
	if u == nil {
		return nil
	}
	u.mu.Lock()
	if u.block != nil || u.ended {
		defer u.mu.Unlock()
		return u.block
	}
	u.ended = true
	u.mu.Unlock()
	page, err := u.w.startPage(ctx)
	if ctx.Err() != nil {
		return nil
	}
	base, _ := u.w.baseline()
	u.mu.Lock()
	defer u.mu.Unlock()
	switch {
	case err != nil:
		u.block = &Block{Reason: fmt.Sprintf("the host stopped serving the app during this check: after it, the start page could not be fetched (%v)", err)}
	case page.Status != base.Status:
		u.block = &Block{Page: page, Reason: fmt.Sprintf("the host stopped serving the app during this check: after it, the start page answered %s; at the run's first check it answered %d", page, base.Status)}
	}
	return u.block
}

func (w *Watch) baseline() (Shape, bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.base, w.hasBase
}

// countingBody counts a forwarded answer's body as the proxy copies it to
// the tool and reports its shape when the body is closed, so nothing is
// buffered and a streamed answer is not held back.
type countingBody struct {
	io.ReadCloser
	n    int64
	eof  bool
	done func(n int64, complete bool)
	once sync.Once
}

func (b *countingBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	b.n += int64(n)
	if err == io.EOF {
		b.eof = true
	}
	return n, err
}

func (b *countingBody) Close() error {
	err := b.ReadCloser.Close()
	b.once.Do(func() { b.done(b.n, b.eof) })
	return err
}

// MEASUREMENT PROTOTYPE, NOT FOR MERGE (from-porchlet #86, #87).
//
// Four detectors for "the host stopped serving the app" run in shadow mode
// on the same traffic and log when each would stop (SIEGEKIT_ZZ_LOG, one
// JSON line per event). SIEGEKIT_ZZ_ENFORCE=d1|d2|d3|d4 makes that one
// stop the run. SIEGEKIT_ZZ_HEADERS (H1, "Name: value" lines) or
// SIEGEKIT_ZZ_VERCEL (H2, the bypass secret) add headers to every request.
package egress

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

type zzShape struct {
	Status int    `json:"status"`
	Type   string `json:"type"`
	Len    int64  `json:"len"` // -1: longer than zzMaxBody
}

const zzMaxBody = 2 << 20

func (a zzShape) like(b zzShape) bool {
	if a.Status != b.Status || a.Type != b.Type || a.Len < 0 || b.Len < 0 {
		return false
	}
	d := a.Len - b.Len
	if d < 0 {
		d = -d
	}
	m := max(a.Len, b.Len) / 20 // 5%
	return d <= m
}

func zzEnv(name string, def int) int {
	if v, err := strconv.Atoi(os.Getenv(name)); err == nil && v > 0 {
		return v
	}
	return def
}

type zzDetector struct {
	p       *Proxy
	enforce string
	n, r, k int

	once     sync.Once
	base     zzShape
	baseErr  error
	mu       sync.Mutex
	fwd      int
	streak   zzShape
	streakN  int
	cleared  []zzShape
	checking bool
	k403     int
	fired    map[string]bool
	canaries map[string]int
	own      bool // the detector of SiegeKit's own checks
}

func newZZ(p *Proxy) *zzDetector {
	return &zzDetector{
		p: p, enforce: os.Getenv("SIEGEKIT_ZZ_ENFORCE"),
		n: zzEnv("SIEGEKIT_ZZ_N", 50), r: zzEnv("SIEGEKIT_ZZ_R", 10), k: zzEnv("SIEGEKIT_ZZ_K", 50),
		fired: map[string]bool{}, canaries: map[string]int{},
	}
}

var zzLogMu sync.Mutex

func zzLog(ev map[string]any) {
	name := os.Getenv("SIEGEKIT_ZZ_LOG")
	if name == "" {
		return
	}
	ev["t"] = time.Now().UTC().Format(time.RFC3339Nano)
	b, _ := json.Marshal(ev)
	zzLogMu.Lock()
	defer zzLogMu.Unlock()
	f, err := os.OpenFile(name, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	defer f.Close()
	_, _ = f.Write(append(b, '\n'))
}

// canary fetches the start page through the proxy's pinned transport.
func (z *zzDetector) canary(who string) (zzShape, error) {
	z.mu.Lock()
	z.canaries[who]++
	z.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, z.p.cfg.Target.String(), nil)
	if err != nil {
		return zzShape{}, err
	}
	req.Header.Set("User-Agent", "SiegeKit/"+z.p.cfg.Version+" canary")
	zzAddHeaders(req.Header)
	resp, err := z.p.transport.RoundTrip(req)
	if err != nil {
		return zzShape{}, err
	}
	defer resp.Body.Close()
	n, _ := io.Copy(io.Discard, io.LimitReader(resp.Body, zzMaxBody+1))
	if n > zzMaxBody {
		n = -1
	}
	return zzShape{resp.StatusCode, zzType(resp.Header), n}, nil
}

func zzType(h http.Header) string {
	t, _, _ := mime.ParseMediaType(h.Get("Content-Type"))
	return t
}

func (z *zzDetector) baseline() {
	z.once.Do(func() {
		z.base, z.baseErr = z.canary("baseline")
		zzLog(map[string]any{"ev": "baseline", "shape": z.base, "err": fmt.Sprint(z.baseErr)})
	})
}

func (z *zzDetector) fire(d, why string) {
	key := d
	if z.own {
		zzSendMu.Lock()
		key = d + "@" + zzPhase
		zzSendMu.Unlock()
	}
	z.mu.Lock()
	if z.fired[key] {
		z.mu.Unlock()
		return
	}
	z.fired[key] = true
	fwd := z.fwd
	z.mu.Unlock()
	zzLog(map[string]any{"ev": "would-stop", "detector": d, "own": key, "forwarded": fwd, "why": why})
	if z.enforce == d && z.own {
		zzRecordOwnStop("the host stopped serving the app (" + d + "): " + why)
	}
	if z.enforce == d {
		z.p.mu.Lock()
		if z.p.stopReason == "" {
			z.p.stopReason = "the host stopped serving the app (" + d + "): " + why
			close(z.p.stop)
		}
		z.p.mu.Unlock()
	}
}

// answer is called for every forwarded answer, with its shape.
func (z *zzDetector) answer(s zzShape) {
	z.baseline()
	z.mu.Lock()
	z.fwd++
	fwd := z.fwd
	// D4: K answers in a row of 403 or 429.
	if s.Status == 403 || s.Status == 429 {
		z.k403++
	} else {
		z.k403 = 0
	}
	d4 := z.k403 >= z.k
	// D3: R answers in a row of one shape not yet cleared.
	if s.like(z.streak) {
		z.streakN++
	} else {
		z.streak, z.streakN = s, 1
	}
	d3 := false
	if z.streakN >= z.r && !z.checking {
		known := false
		for _, c := range z.cleared {
			if c.like(z.streak) {
				known = true
				break
			}
		}
		if !known {
			z.checking, d3 = true, true
		}
	}
	streak := z.streak
	z.mu.Unlock()
	if d4 {
		z.fire("d4", fmt.Sprintf("%d answers in a row were %d", z.k, s.Status))
	}
	if fwd%z.n == 0 {
		go z.d2()
	}
	if d3 {
		go z.d3(streak)
	}
}

func (z *zzDetector) d2() {
	c, err := z.canary("d2")
	if z.baseErr != nil {
		return
	}
	if err != nil || c.Status != z.base.Status {
		z.fire("d2", fmt.Sprintf("the start page answered %d (%s, %d bytes), at the start %d; err=%v", c.Status, c.Type, c.Len, z.base.Status, err))
	}
}

func (z *zzDetector) d3(streak zzShape) {
	c, err := z.canary("d3")
	zzLog(map[string]any{"ev": "d3-check", "streak": streak, "canary": c, "err": fmt.Sprint(err)})
	// Each shape is checked once (a confirmed block shape is not checked again).
	z.mu.Lock()
	z.checking = false
	z.cleared = append(z.cleared, streak)
	z.mu.Unlock()
	if err == nil && z.baseErr == nil && c.like(streak) && !z.base.like(streak) {
		z.fire("d3", fmt.Sprintf("%d answers in a row and the start page were the same %d page (%s, %d bytes); at the start it was %d", z.r, c.Status, c.Type, c.Len, z.base.Status))
	}
}

// final runs D1 after the tool exits and logs the counters.
func (z *zzDetector) final() {
	z.mu.Lock()
	fwd := z.fwd
	z.mu.Unlock()
	if fwd == 0 {
		return
	}
	c, err := z.canary("d1")
	if z.baseErr == nil && (err != nil || c.Status != z.base.Status) {
		z.fire("d1", fmt.Sprintf("the start page answered %d after the check, %d before; err=%v", c.Status, z.base.Status, err))
	}
	z.mu.Lock()
	defer z.mu.Unlock()
	zzLog(map[string]any{"ev": "final", "forwarded": z.fwd, "canaries": z.canaries, "fired": z.fired, "end": c})
}

// ZZFinal is called by the runner after the tool exits.
func (p *Proxy) ZZFinal() {
	if p.zz != nil {
		p.zz.final()
	}
}

// zzShapeOf reads at most zzMaxBody of resp's body to measure it and puts
// the bytes back.
func zzShapeOf(resp *http.Response) zzShape {
	buf, err := io.ReadAll(io.LimitReader(resp.Body, zzMaxBody+1))
	n := int64(len(buf))
	resp.Body = struct {
		io.Reader
		io.Closer
	}{io.MultiReader(bytes.NewReader(buf), resp.Body), resp.Body}
	if err != nil || n > zzMaxBody {
		n = -1
	}
	return zzShape{resp.StatusCode, zzType(resp.Header), n}
}

var (
	zzHdrOnce sync.Once
	zzHdr     http.Header
)

// zzHeaders reads H1 or H2 from the environment once.
func zzHeaders() http.Header {
	zzHdrOnce.Do(func() {
		zzHdr = http.Header{}
		if v := os.Getenv("SIEGEKIT_ZZ_VERCEL"); v != "" {
			zzHdr.Set("X-Vercel-Protection-Bypass", v)
		}
		sc := bufio.NewScanner(strings.NewReader(os.Getenv("SIEGEKIT_ZZ_HEADERS")))
		for sc.Scan() {
			k, v, ok := strings.Cut(sc.Text(), ":")
			k = http.CanonicalHeaderKey(strings.TrimSpace(k))
			if !ok || k == "" || fixedHeader[k] || k == "Cookie" || k == "Authorization" || strings.HasPrefix(k, "Proxy-") {
				continue
			}
			zzHdr.Add(k, strings.TrimSpace(v))
		}
	})
	return zzHdr
}

func zzAddHeaders(h http.Header) {
	for k, vs := range zzHeaders() {
		h.Del(k)
		for _, v := range vs {
			h.Add(k, v)
		}
	}
}

// ZZAddHeaders is used by the proof fetch.
func ZZAddHeaders(h http.Header) { zzAddHeaders(h) }

// ---- SiegeKit's own checks (egress.Send), one detector per run ----

var (
	zzSendMu    sync.Mutex
	zzSendDet   *zzDetector
	zzPhase     string
	zzSendStops = map[string]string{} // phase -> stop reason
)

func zzSendFor(cfg Config) *zzDetector {
	zzSendMu.Lock()
	defer zzSendMu.Unlock()
	if zzSendDet == nil {
		p := &Proxy{cfg: cfg, transport: newTransport(cfg), stop: make(chan struct{})}
		zzSendDet = newZZ(p)
		zzSendDet.own = true
	}
	return zzSendDet
}

// zzSendBlocked returns the stop reason once the enforced detector fired.
func zzSendBlocked(cfg Config) string {
	d := zzSendFor(cfg)
	d.p.mu.Lock()
	defer d.p.mu.Unlock()
	return d.p.stopReason
}

func zzSendAnswer(cfg Config, status int, h http.Header, n int64) {
	zzSendFor(cfg).answer(zzShape{status, zzType(h), n})
}

// ZZSendPhase names the own check whose requests follow; ending a phase
// runs D1 for it.
func ZZSendPhase(name string) {
	zzSendMu.Lock()
	d, prev := zzSendDet, zzPhase
	zzSendMu.Unlock()
	if d != nil && prev != "" {
		d.final() // D1 for the phase that ends, recorded under its name
		d.mu.Lock()
		d.fwd = 0
		d.mu.Unlock()
	}
	zzSendMu.Lock()
	zzPhase = name
	zzSendMu.Unlock()
	if d != nil {
		// A run already stopped refuses this phase's requests too.
		if r := zzSendBlocked(d.p.cfg); r != "" && d.enforce != "" {
			zzRecordOwnStop(r)
		}
	}
	zzLog(map[string]any{"ev": "phase", "from": prev, "to": name})
}

// ZZSendStop says why the enforced detector stopped the given phase, or "".
func ZZSendStop(phase string) string {
	zzSendMu.Lock()
	defer zzSendMu.Unlock()
	return zzSendStops[phase]
}

func zzRecordOwnStop(reason string) {
	zzSendMu.Lock()
	defer zzSendMu.Unlock()
	if _, ok := zzSendStops[zzPhase]; !ok {
		zzSendStops[zzPhase] = reason
	}
}

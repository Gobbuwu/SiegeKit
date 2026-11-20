// Package egress is the proxy that active tests reach the target through
// (ADR 0006, ADR 0018). It accepts requests only for the target origin,
// connects only to the pinned addresses, caps the request rate, labels the
// traffic, inspects HTTPS with a per-run certificate authority, and stops
// after repeated server errors.
package egress

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Gobbuwu/SiegeKit/internal/target"
)

// Config describes one run's proxy.
type Config struct {
	Target *target.URL
	Addrs  []netip.Addr // pinned under ADR 0005
	// Client is the only network TCP connections are accepted from. Unix
	// socket connections (the relay, ADR 0019) are accepted without it.
	Client netip.Prefix
	// VerifyTLS checks the target's certificate (deployed mode). Local mode
	// accepts self-signed development certificates.
	VerifyTLS bool
	Rate      float64 // requests per second
	Burst     int
	// MaxConns limits connections to the target, so at most that many
	// requests are in flight. Idle connections from the tool hold no slot:
	// a tool keeps idle keep-alive connections open, and while the proxy
	// counted them, new requests waited up to 27 s, past the tool's own
	// timeout, and were lost without an error (measured with Nuclei,
	// ADR 0026). The relay bounds the tool's open connections.
	MaxConns        int
	MaxServerErrors int // consecutive 5xx or upstream failures before stopping
	Version         string
	// ReadOnly allows only GET and HEAD requests. Non-destructive plugins
	// get it on deployed targets, so a tool default that submits forms
	// cannot change data there (owner decision 2026-11-19, ADR 0023).
	ReadOnly bool

	// Dial and RootCAs replace the network and system roots in tests.
	Dial    func(ctx context.Context, network, addr string) (net.Conn, error)
	RootCAs *x509.CertPool
}

// Stats counts what the proxy did.
type Stats struct {
	Requests     int // answered by the target
	Refused      int // refused requests and connections
	ServerErrors int // 5xx answers and failed upstream connections
	// RefusedTo lists what was refused, such as "CONNECT other.test:443"
	// or "POST app.test:8080 (only GET and HEAD)", each once, at most
	// MaxRefusedTo entries.
	RefusedTo []string
}

// MaxRefusedTo caps Stats.RefusedTo.
const MaxRefusedTo = 20

// Proxy is a running egress proxy.
type Proxy struct {
	cfg       Config
	authority string // host[:port] as sent upstream
	ca        *authority
	leaf      tls.Certificate
	transport *http.Transport
	bucket    *bucket

	mu          sync.Mutex
	stats       Stats
	consecutive int
	stopReason  string
	stop        chan struct{}
	hijacked    map[net.Conn]struct{}
	closed      bool
	listener    net.Listener
	srv         *http.Server
}

// New checks cfg and prepares the proxy and its certificate authority.
func New(cfg Config) (*Proxy, error) {
	switch {
	case cfg.Target == nil:
		return nil, errors.New("no target")
	case len(cfg.Addrs) == 0:
		return nil, errors.New("no pinned addresses")
	case cfg.Rate <= 0 || cfg.Burst < 1 || cfg.MaxConns < 1 || cfg.MaxServerErrors < 1:
		return nil, errors.New("rate, burst, connection and server-error limits must be positive")
	}
	for _, a := range cfg.Addrs {
		if target.Classify(a) == target.Blocked {
			return nil, fmt.Errorf("%s is in a range SiegeKit never tests", a)
		}
	}
	p := &Proxy{
		cfg:       cfg,
		authority: authorityOf(cfg.Target),
		bucket:    newBucket(cfg.Rate, cfg.Burst),
		stop:      make(chan struct{}),
		hijacked:  map[net.Conn]struct{}{},
	}
	if cfg.Target.Scheme == "https" {
		ca, err := newAuthority(cfg.Target)
		if err != nil {
			return nil, err
		}
		leaf, err := ca.leaf(cfg.Target)
		if err != nil {
			return nil, err
		}
		p.ca, p.leaf = ca, leaf
	}
	p.transport = newTransport(cfg)
	return p, nil
}

// CACertPEM is the certificate the tool container trusts; nil for an http
// target. The private key never leaves this process.
func (p *Proxy) CACertPEM() []byte {
	if p.ca == nil {
		return nil
	}
	return p.ca.certPEM
}

// Stopped is closed when the proxy stops forwarding after repeated errors.
func (p *Proxy) Stopped() <-chan struct{} { return p.stop }

// StopReason says why the proxy stopped, or "".
func (p *Proxy) StopReason() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.stopReason
}

// newTransport sends every upstream request to a pinned address of the
// target, whatever the request named.
func newTransport(cfg Config) *http.Transport {
	dial := cfg.Dial
	if dial == nil {
		dial = (&net.Dialer{Timeout: 10 * time.Second}).DialContext
	}
	port := strconv.Itoa(cfg.Target.Port)
	return &http.Transport{
		Proxy: nil,
		// Every upstream connection goes to a pinned address, whatever the
		// request named.
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var last error
			for _, a := range cfg.Addrs {
				c, err := dial(ctx, "tcp", net.JoinHostPort(a.String(), port))
				if err == nil {
					return c, nil
				}
				last = err
			}
			return nil, last
		},
		TLSClientConfig: &tls.Config{
			ServerName: cfg.Target.Host,
			RootCAs:    cfg.RootCAs,
			MinVersion: tls.VersionTLS12,
			// Local mode only: development servers often use self-signed
			// certificates (ADR 0018 item 4).
			InsecureSkipVerify: !cfg.VerifyTLS, // #nosec G402 -- local mode only, see ADR 0018
		},
		ForceAttemptHTTP2:     false,
		DisableCompression:    true,
		MaxIdleConns:          cfg.MaxConns,
		MaxConnsPerHost:       cfg.MaxConns,
		IdleConnTimeout:       30 * time.Second,
		ResponseHeaderTimeout: 60 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
	}
}

// Reachable sends one GET for the target URL from the host, through the
// same pinned transport as the proxy, and returns nil if the target
// answered with any HTTP status. It is the check before the first plugin
// of a run, so that a target that is down is not sent a full scan.
func Reachable(ctx context.Context, cfg Config) error {
	tr := newTransport(cfg)
	defer tr.CloseIdleConnections()
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, cfg.Target.String(), nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "SiegeKit/"+cfg.Version)
	resp, err := tr.RoundTrip(req)
	if err != nil {
		return fmt.Errorf("the target did not answer: %w", err)
	}
	return resp.Body.Close()
}

// Stats returns a copy of the counters.
func (p *Proxy) Stats() Stats {
	p.mu.Lock()
	defer p.mu.Unlock()
	s := p.stats
	s.RefusedTo = append([]string(nil), p.stats.RefusedTo...)
	return s
}

// Serve accepts client connections on l until Close.
func (p *Proxy) Serve(l net.Listener) error {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return http.ErrServerClosed
	}
	p.listener = &filterListener{Listener: l, p: p}
	p.srv = &http.Server{
		Handler:           http.HandlerFunc(p.serveClient),
		ReadHeaderTimeout: 30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    64 << 10,
		ErrorLog:          log.New(io.Discard, "", 0),
	}
	srv, fl := p.srv, p.listener
	p.mu.Unlock()
	return srv.Serve(fl)
}

// Close stops the proxy and closes every connection.
func (p *Proxy) Close() error {
	p.mu.Lock()
	p.closed = true
	srv := p.srv
	conns := make([]net.Conn, 0, len(p.hijacked))
	for c := range p.hijacked {
		conns = append(conns, c)
	}
	p.mu.Unlock()
	for _, c := range conns {
		_ = c.Close()
	}
	p.transport.CloseIdleConnections()
	if srv != nil {
		return srv.Close()
	}
	return nil
}

// refuse answers 403 and records what was refused: the method and
// destination, plus a note when the destination itself was allowed.
func (p *Proxy) refuse(w http.ResponseWriter, what, format string, a ...any) {
	p.mu.Lock()
	p.countRefused(what)
	p.mu.Unlock()
	http.Error(w, "SiegeKit egress proxy: "+fmt.Sprintf(format, a...), http.StatusForbidden)
}

// countRefused counts one refusal. The caller holds p.mu.
func (p *Proxy) countRefused(what string) {
	p.stats.Refused++
	if len(p.stats.RefusedTo) < MaxRefusedTo && !slices.Contains(p.stats.RefusedTo, what) {
		p.stats.RefusedTo = append(p.stats.RefusedTo, what)
	}
}

// destination names where a request was going, for Stats.RefusedTo. The
// host comes from the client and is cut to keep reports readable.
func destination(r *http.Request) string {
	host := r.Host
	if r.URL.IsAbs() {
		host = r.URL.Scheme + "://" + r.URL.Host
	}
	return named(r.Method, host)
}

func named(method, host string) string {
	if len(host) > 100 {
		host = host[:100] + "..."
	}
	return strings.ToValidUTF8(method, "?") + " " + strings.ToValidUTF8(host, "?")
}

// serveClient handles requests on a client connection: CONNECT tunnels for
// an https target, absolute-form requests for an http target.
func (p *Proxy) serveClient(w http.ResponseWriter, r *http.Request) {
	t := p.cfg.Target
	if r.Method == http.MethodConnect {
		if t.Scheme != "https" || !p.sameOrigin(r.Host) {
			p.refuse(w, destination(r), "only %s is allowed", t)
			return
		}
		p.tunnel(w)
		return
	}
	if !r.URL.IsAbs() || r.URL.Scheme != t.Scheme || !p.sameOrigin(r.URL.Host) {
		p.refuse(w, destination(r), "only %s is allowed", t)
		return
	}
	p.forward(w, r)
}

// tunnel answers CONNECT and serves the decrypted requests inside it.
func (p *Proxy) tunnel(w http.ResponseWriter) {
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "cannot tunnel", http.StatusInternalServerError)
		return
	}
	conn, buf, err := hj.Hijack()
	if err != nil {
		return
	}
	if !p.track(conn) {
		_ = conn.Close()
		return
	}
	defer p.untrack(conn)
	defer conn.Close()
	if buf.Reader.Buffered() > 0 {
		return // the client sent data before the tunnel was established
	}
	if _, err := conn.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n")); err != nil {
		return
	}
	tc := tls.Server(conn, &tls.Config{
		Certificates: []tls.Certificate{p.leaf},
		MinVersion:   tls.VersionTLS12,
		NextProtos:   []string{"http/1.1"},
	})
	inner := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.IsAbs() && (r.URL.Scheme != "https" || !p.sameOrigin(r.URL.Host)) {
				p.refuse(w, destination(r), "only %s is allowed", p.cfg.Target)
				return
			}
			p.forward(w, r)
		}),
		ReadHeaderTimeout: 30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    64 << 10,
		ErrorLog:          log.New(io.Discard, "", 0),
	}
	_ = inner.Serve(newOneConnListener(tc))
}

// forward sends one request to the target and copies the answer back.
func (p *Proxy) forward(w http.ResponseWriter, r *http.Request) {
	if !p.sameOrigin(r.Host) {
		p.refuse(w, named(r.Method, "Host: "+r.Host), "the Host header must name %s", p.authority)
		return
	}
	if p.cfg.ReadOnly && r.Method != http.MethodGet && r.Method != http.MethodHead {
		p.refuse(w, destination(r)+" (only GET and HEAD)", "only GET and HEAD requests are allowed for this check on a deployed target")
		return
	}
	select {
	case <-p.stop:
		http.Error(w, "SiegeKit egress proxy: the run was stopped: "+p.StopReason(), http.StatusServiceUnavailable)
		return
	default:
	}
	if err := p.bucket.wait(r.Context()); err != nil {
		return
	}
	t := p.cfg.Target
	rp := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.Out.URL.Scheme = t.Scheme
			pr.Out.URL.Host = p.authority
			pr.Out.Host = p.authority
			ua := strings.TrimSpace(pr.In.Header.Get("User-Agent") + " SiegeKit/" + p.cfg.Version)
			pr.Out.Header.Set("User-Agent", ua)
		},
		Transport: p.transport,
		ModifyResponse: func(resp *http.Response) error {
			// Count only requests the target answered (an unreachable
			// target counts none, so the plugin is reported as failed).
			p.mu.Lock()
			p.stats.Requests++
			p.mu.Unlock()
			p.result(resp.StatusCode >= 500, fmt.Sprintf("the target answered %s", resp.Status))
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, err error) {
			p.result(true, "the target could not be reached: "+err.Error())
			http.Error(w, "SiegeKit egress proxy: the target could not be reached", http.StatusBadGateway)
		},
		ErrorLog: log.New(io.Discard, "", 0),
	}
	rp.ServeHTTP(w, r)
}

// result records one upstream outcome and stops the proxy after
// MaxServerErrors failures in a row.
func (p *Proxy) result(failed bool, what string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !failed {
		p.consecutive = 0
		return
	}
	p.stats.ServerErrors++
	p.consecutive++
	if p.consecutive >= p.cfg.MaxServerErrors && p.stopReason == "" {
		p.stopReason = fmt.Sprintf("%d server errors in a row (last: %s)", p.consecutive, what)
		close(p.stop)
	}
}

// sameOrigin reports whether hostport names the target host and port. A
// missing port means the scheme's default.
func (p *Proxy) sameOrigin(hostport string) bool {
	t := p.cfg.Target
	host, port := hostport, ""
	if h, pt, err := net.SplitHostPort(hostport); err == nil {
		host, port = h, pt
	} else if strings.HasPrefix(hostport, "[") && strings.HasSuffix(hostport, "]") {
		host = hostport[1 : len(hostport)-1]
	}
	n := map[string]int{"http": 80, "https": 443}[t.Scheme]
	if port != "" {
		v, err := strconv.Atoi(port)
		if err != nil || strconv.Itoa(v) != port {
			return false
		}
		n = v
	}
	if n != t.Port {
		return false
	}
	if t.IP.IsValid() {
		a, err := netip.ParseAddr(host)
		return err == nil && a == t.IP
	}
	return strings.TrimSuffix(strings.ToLower(host), ".") == t.Host
}

func authorityOf(t *target.URL) string {
	h := t.Host
	if t.IP.Is6() {
		h = "[" + h + "]"
	}
	if t.Port != map[string]int{"http": 80, "https": 443}[t.Scheme] {
		h += ":" + strconv.Itoa(t.Port)
	}
	return h
}

func (p *Proxy) track(c net.Conn) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return false
	}
	p.hijacked[c] = struct{}{}
	return true
}

func (p *Proxy) untrack(c net.Conn) {
	p.mu.Lock()
	delete(p.hijacked, c)
	p.mu.Unlock()
}

// filterListener accepts connections only from the client network.
type filterListener struct {
	net.Listener
	p *Proxy
}

func (l *filterListener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		allowed := l.Listener.Addr().Network() == "unix"
		if !allowed {
			ap, err := netip.ParseAddrPort(c.RemoteAddr().String())
			allowed = err == nil && l.p.cfg.Client.IsValid() && l.p.cfg.Client.Contains(ap.Addr().Unmap())
		}
		if !allowed {
			l.p.mu.Lock()
			l.p.countRefused("connection from outside the tool's network")
			l.p.mu.Unlock()
			_ = c.Close()
			continue
		}
		return c, nil
	}
}

// oneConnListener hands out one connection, then blocks until it is closed,
// so http.Server.Serve returns when the tunnel ends.
type oneConnListener struct {
	conn net.Conn
	done chan struct{}
	once sync.Once
	used bool
	mu   sync.Mutex
}

func newOneConnListener(c net.Conn) *oneConnListener {
	l := &oneConnListener{done: make(chan struct{})}
	l.conn = &notifyConn{Conn: c, closed: func() { l.once.Do(func() { close(l.done) }) }}
	return l
}

func (l *oneConnListener) Accept() (net.Conn, error) {
	l.mu.Lock()
	if !l.used {
		l.used = true
		l.mu.Unlock()
		return l.conn, nil
	}
	l.mu.Unlock()
	<-l.done
	return nil, net.ErrClosed
}

func (l *oneConnListener) Close() error   { return nil }
func (l *oneConnListener) Addr() net.Addr { return l.conn.LocalAddr() }

type notifyConn struct {
	net.Conn
	once   sync.Once
	closed func()
}

func (c *notifyConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(c.closed)
	return err
}

// bucket is a token bucket: requests wait for a token.
type bucket struct {
	mu     sync.Mutex
	rate   float64
	burst  float64
	tokens float64
	last   time.Time
}

func newBucket(rate float64, burst int) *bucket {
	return &bucket{rate: rate, burst: float64(burst), tokens: float64(burst), last: time.Now()}
}

func (b *bucket) wait(ctx context.Context) error {
	for {
		b.mu.Lock()
		now := time.Now()
		b.tokens = min(b.burst, b.tokens+now.Sub(b.last).Seconds()*b.rate)
		b.last = now
		if b.tokens >= 1 {
			b.tokens--
			b.mu.Unlock()
			return nil
		}
		d := time.Duration((1 - b.tokens) / b.rate * float64(time.Second))
		b.mu.Unlock()
		t := time.NewTimer(d)
		select {
		case <-t.C:
		case <-ctx.Done():
			t.Stop()
			return ctx.Err()
		}
	}
}

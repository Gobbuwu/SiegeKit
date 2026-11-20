package egress

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Gobbuwu/SiegeKit/internal/target"
)

type upstream struct {
	srv  *httptest.Server
	hits atomic.Int32
	last atomic.Value // *http.Request
}

func newUpstream(t *testing.T, tlsOn bool, status func() int) *upstream {
	t.Helper()
	u := &upstream{}
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u.hits.Add(1)
		u.last.Store(r.Clone(r.Context()))
		code := http.StatusOK
		if status != nil {
			code = status()
		}
		w.WriteHeader(code)
		fmt.Fprint(w, "hello from target")
	})
	if tlsOn {
		u.srv = httptest.NewTLSServer(h)
	} else {
		u.srv = httptest.NewServer(h)
	}
	t.Cleanup(u.srv.Close)
	return u
}

func (u *upstream) port() int {
	su, _ := url.Parse(u.srv.URL)
	p, _ := strconv.Atoi(su.Port())
	return p
}

// start runs a proxy for scheme://host:<upstream port> pinned to 127.0.0.1.
func start(t *testing.T, u *upstream, scheme, host string, edit func(*Config)) (*Proxy, *http.Client, string) {
	t.Helper()
	tu, err := target.Parse(fmt.Sprintf("%s://%s:%d/", scheme, host, u.port()))
	if err != nil {
		t.Fatal(err)
	}
	cfg := Config{
		Target: tu, Addrs: []netip.Addr{netip.MustParseAddr("127.0.0.1")},
		Client: netip.MustParsePrefix("127.0.0.0/8"), VerifyTLS: true,
		Rate: 1000, Burst: 100, MaxConns: 8, MaxServerErrors: 5, Version: "test",
	}
	if u.srv.TLS != nil {
		cfg.RootCAs = u.srv.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs
	}
	if edit != nil {
		edit(&cfg)
	}
	p, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go p.Serve(l)
	t.Cleanup(func() { p.Close() })
	pool := x509.NewCertPool()
	if pem := p.CACertPEM(); pem != nil && !pool.AppendCertsFromPEM(pem) {
		t.Fatal("bad CA PEM")
	}
	proxyURL, _ := url.Parse("http://" + l.Addr().String())
	c := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			Proxy:           http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{RootCAs: pool},
		},
	}
	return p, c, fmt.Sprintf("%s://%s:%d", scheme, host, u.port())
}

func get(t *testing.T, c *http.Client, rawURL string, edit func(*http.Request)) (int, string, error) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, rawURL, nil)
	req.Header.Set("User-Agent", "tool/1.0")
	if edit != nil {
		edit(req)
	}
	resp, err := c.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b), nil
}

func TestHTTPTarget(t *testing.T) {
	u := newUpstream(t, false, nil)
	p, c, origin := start(t, u, "http", "app.test", nil)

	code, body, err := get(t, c, origin+"/x?q=1", nil)
	if err != nil || code != 200 || body != "hello from target" {
		t.Fatalf("allowed request: %d %q %v", code, body, err)
	}
	r := u.last.Load().(*http.Request)
	if r.URL.RequestURI() != "/x?q=1" || r.Host != fmt.Sprintf("app.test:%d", u.port()) || r.Header.Get("User-Agent") != "tool/1.0 SiegeKit/test" {
		t.Errorf("upstream saw %s %s UA %q", r.Host, r.URL, r.Header.Get("User-Agent"))
	}
	if r.Header.Get("Proxy-Connection") != "" || r.Header.Get("X-Forwarded-For") != "" {
		t.Errorf("proxy headers leaked upstream: %v", r.Header)
	}

	for name, tc := range map[string]struct {
		url  string
		edit func(*http.Request)
	}{
		"other host":          {fmt.Sprintf("http://other.test:%d/", u.port()), nil},
		"subdomain":           {fmt.Sprintf("http://api.app.test:%d/", u.port()), nil},
		"other port":          {"http://app.test:1/", nil},
		"metadata address":    {"http://169.254.169.254/latest/meta-data/", nil},
		"loopback by address": {fmt.Sprintf("http://127.0.0.1:%d/", u.port()), nil},
		"https scheme":        {fmt.Sprintf("https://app.test:%d/", u.port()), nil},
		"other Host header":   {origin + "/", func(r *http.Request) { r.Host = "victim.test" }},
		"Host header port":    {origin + "/", func(r *http.Request) { r.Host = "app.test:1" }},
	} {
		before := u.hits.Load()
		code, _, err := get(t, c, tc.url, tc.edit)
		if err == nil && code != http.StatusForbidden {
			t.Errorf("%s: answered %d, want 403", name, code)
		}
		if u.hits.Load() != before {
			t.Errorf("%s: reached the target", name)
		}
	}
	s := p.Stats()
	if s.Requests != 1 || s.Refused < 7 {
		t.Errorf("stats %+v", s)
	}
	for _, want := range []string{
		fmt.Sprintf("GET http://other.test:%d", u.port()),
		"GET http://169.254.169.254",
		fmt.Sprintf("CONNECT app.test:%d", u.port()),
		"GET http://victim.test",
	} {
		if !slices.Contains(s.RefusedTo, want) {
			t.Errorf("RefusedTo %q lacks %q", s.RefusedTo, want)
		}
	}
}

// TestUnreachableTargetCountsNoRequest checks that a request counts only
// when the target answered: a plugin whose requests all failed is reported
// as having sent none.
func TestUnreachableTargetCountsNoRequest(t *testing.T) {
	u := newUpstream(t, false, nil)
	p, c, origin := start(t, u, "http", "app.test", nil)
	u.srv.Close()
	if code, _, err := get(t, c, origin+"/", nil); err != nil || code != http.StatusBadGateway {
		t.Errorf("answered %d %v, want 502", code, err)
	}
	if s := p.Stats(); s.Requests != 0 || s.ServerErrors != 1 {
		t.Errorf("stats %+v", s)
	}
}

func TestRefusedToIsCapped(t *testing.T) {
	u := newUpstream(t, false, nil)
	p, c, _ := start(t, u, "http", "app.test", nil)
	for i := range MaxRefusedTo + 5 {
		get(t, c, fmt.Sprintf("http://h%d.test/", i), nil)
	}
	get(t, c, "http://h0.test/", nil)
	if s := p.Stats(); len(s.RefusedTo) != MaxRefusedTo || s.Refused != MaxRefusedTo+6 {
		t.Errorf("%d entries, %d refused", len(s.RefusedTo), s.Refused)
	}
}

func TestHTTPSTarget(t *testing.T) {
	// httptest's certificate is valid for example.com; the name never
	// resolves here, so success shows that the pinned address was used.
	u := newUpstream(t, true, nil)
	_, c, origin := start(t, u, "https", "example.com", nil)
	code, body, err := get(t, c, origin+"/secure", nil)
	if err != nil || code != 200 || body != "hello from target" {
		t.Fatalf("allowed request: %d %q %v", code, body, err)
	}
	r := u.last.Load().(*http.Request)
	if r.URL.Path != "/secure" || r.Header.Get("User-Agent") != "tool/1.0 SiegeKit/test" {
		t.Errorf("upstream saw %s UA %q", r.URL, r.Header.Get("User-Agent"))
	}
	// CONNECT to anything else is refused before any TLS.
	if _, _, err := get(t, c, fmt.Sprintf("https://www.example.com:%d/", u.port()), nil); err == nil || !strings.Contains(err.Error(), "Forbidden") {
		t.Errorf("CONNECT to another host: %v", err)
	}
	if _, _, err := get(t, c, "https://example.com:1/", nil); err == nil {
		t.Error("CONNECT to another port succeeded")
	}
	// Plain http to the https origin is refused.
	if code, _, _ := get(t, c, fmt.Sprintf("http://example.com:%d/", u.port()), nil); code != http.StatusForbidden {
		t.Errorf("plain http to https target: %d", code)
	}
	// Inside the tunnel the Host header must still name the target.
	before := u.hits.Load()
	if code, _, _ := get(t, c, origin+"/", func(r *http.Request) { r.Host = "victim.test" }); code != http.StatusForbidden || u.hits.Load() != before {
		t.Errorf("other Host header inside the tunnel: %d", code)
	}
}

func TestUpstreamCertificate(t *testing.T) {
	u := newUpstream(t, true, nil)
	// Deployed mode with a certificate the proxy does not trust: refused.
	p, c, origin := start(t, u, "https", "example.com", func(c *Config) { c.RootCAs = x509.NewCertPool() })
	if code, _, err := get(t, c, origin+"/", nil); err != nil || code != http.StatusBadGateway {
		t.Errorf("untrusted target certificate: %d %v", code, err)
	}
	if p.Stats().ServerErrors != 1 {
		t.Errorf("stats %+v", p.Stats())
	}
	// Local mode accepts it (self-signed development servers).
	_, c, origin = start(t, u, "https", "example.com", func(c *Config) { c.RootCAs = x509.NewCertPool(); c.VerifyTLS = false })
	if code, _, err := get(t, c, origin+"/", nil); err != nil || code != 200 {
		t.Errorf("local mode: %d %v", code, err)
	}
}

func TestCertificateAuthorityOnlyCoversTarget(t *testing.T) {
	for _, host := range []string{"shop.example", "93.184.215.14", "2001:db8::1"} {
		raw := "https://" + host + "/"
		if strings.Contains(host, ":") {
			raw = "https://[" + host + "]/"
		}
		tu, _ := target.Parse(raw)
		ca, err := newAuthority(tu)
		if err != nil {
			t.Fatal(err)
		}
		pool := x509.NewCertPool()
		pool.AddCert(ca.cert)
		verify := func(other string) error {
			ou, _ := target.Parse(other)
			l, err := ca.leaf(ou)
			if err != nil {
				return err
			}
			c, _ := x509.ParseCertificate(l.Certificate[0])
			_, err = c.Verify(x509.VerifyOptions{Roots: pool, DNSName: ou.Host})
			return err
		}
		if err := verify(raw); err != nil {
			t.Errorf("%s: own certificate rejected: %v", host, err)
		}
		for _, other := range []string{"https://bank.example/", "https://api.shop.example/", "https://93.184.215.15/", "https://[2001:db8::2]/"} {
			if err := verify(other); err == nil {
				t.Errorf("CA for %s vouches for %s", host, other)
			}
		}
	}
}

func TestStopsAfterServerErrors(t *testing.T) {
	var code atomic.Int32
	code.Store(500)
	u := newUpstream(t, false, func() int { return int(code.Load()) })
	p, c, origin := start(t, u, "http", "app.test", func(c *Config) { c.MaxServerErrors = 3 })
	get(t, c, origin+"/", nil)
	get(t, c, origin+"/", nil)
	code.Store(200) // a success resets the count
	get(t, c, origin+"/", nil)
	code.Store(503)
	for range 3 {
		get(t, c, origin+"/", nil)
	}
	select {
	case <-p.Stopped():
	default:
		t.Fatalf("not stopped; stats %+v", p.Stats())
	}
	before := u.hits.Load()
	if code, body, _ := get(t, c, origin+"/", nil); code != http.StatusServiceUnavailable || !strings.Contains(body, "3 server errors in a row") {
		t.Errorf("after stop: %d %q", code, body)
	}
	if u.hits.Load() != before {
		t.Error("request forwarded after stop")
	}
	if s := p.Stats(); s.Requests != 6 || s.ServerErrors != 5 {
		t.Errorf("stats %+v", s)
	}
}

func TestRateCap(t *testing.T) {
	u := newUpstream(t, false, nil)
	_, c, origin := start(t, u, "http", "app.test", func(c *Config) { c.Rate, c.Burst = 20, 1 })
	t0 := time.Now()
	for range 5 {
		if code, _, err := get(t, c, origin+"/", nil); err != nil || code != 200 {
			t.Fatal(code, err)
		}
	}
	// One token at the start, then one every 50 ms.
	if d := time.Since(t0); d < 190*time.Millisecond {
		t.Errorf("5 requests at 20/s took %v", d)
	}
}

func TestRefusesOtherClients(t *testing.T) {
	u := newUpstream(t, false, nil)
	p, c, origin := start(t, u, "http", "app.test", func(c *Config) { c.Client = netip.MustParsePrefix("10.0.0.0/8") })
	if _, _, err := get(t, c, origin+"/", nil); err == nil {
		t.Error("connection from outside the client network accepted")
	}
	if u.hits.Load() != 0 || p.Stats().Refused == 0 {
		t.Errorf("hits %d stats %+v", u.hits.Load(), p.Stats())
	}
}

func TestNewRefusesBadConfig(t *testing.T) {
	tu, _ := target.Parse("http://app.test/")
	ok := Config{Target: tu, Addrs: []netip.Addr{netip.MustParseAddr("127.0.0.1")}, Client: netip.MustParsePrefix("127.0.0.0/8"), Rate: 1, Burst: 1, MaxConns: 1, MaxServerErrors: 1}
	for name, edit := range map[string]func(*Config){
		"metadata":  func(c *Config) { c.Addrs = []netip.Addr{netip.MustParseAddr("169.254.169.254")} },
		"no addrs":  func(c *Config) { c.Addrs = nil },
		"zero rate": func(c *Config) { c.Rate = 0 },
		"no target": func(c *Config) { c.Target = nil },
		"no errors": func(c *Config) { c.MaxServerErrors = 0 },
	} {
		c := ok
		edit(&c)
		if _, err := New(c); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := New(ok); err != nil {
		t.Errorf("valid config refused: %v", err)
	}
}

func TestSameOrigin(t *testing.T) {
	name, _ := target.Parse("https://Shop.Example/")
	v6, _ := target.Parse("http://[2001:db8::1]:8080/")
	pn := &Proxy{cfg: Config{Target: name}}
	p6 := &Proxy{cfg: Config{Target: v6}}
	for _, tc := range []struct {
		p    *Proxy
		in   string
		want bool
	}{
		{pn, "shop.example", true},
		{pn, "SHOP.example.:443", true},
		{pn, "shop.example:0443", false},
		{pn, "shop.example:80", false},
		{pn, "api.shop.example", false},
		{pn, "shop.example@evil.test", false},
		{pn, "", false},
		{p6, "[2001:db8::1]:8080", true},
		{p6, "[2001:db8:0::1]:8080", true},
		{p6, "[2001:db8::1]", false},
		{p6, "[2001:db8::2]:8080", false},
	} {
		if got := tc.p.sameOrigin(tc.in); got != tc.want {
			t.Errorf("sameOrigin(%q) = %v", tc.in, got)
		}
	}
}

func TestCloseEndsTunnels(t *testing.T) {
	u := newUpstream(t, true, nil)
	p, c, origin := start(t, u, "https", "example.com", nil)
	if code, _, err := get(t, c, origin+"/", nil); err != nil || code != 200 {
		t.Fatal(code, err)
	}
	p.Close()
	if _, _, err := get(t, c, origin+"/", nil); err == nil {
		t.Error("request succeeded after Close")
	}
}

func TestReadOnly(t *testing.T) {
	for _, scheme := range []string{"http", "https"} {
		u := newUpstream(t, scheme == "https", nil)
		host := "app.test"
		if scheme == "https" {
			host = "example.com" // httptest's certificate name
		}
		p, c, origin := start(t, u, scheme, host, func(c *Config) { c.ReadOnly = true })
		for _, m := range []string{http.MethodGet, http.MethodHead} {
			if code, _, err := get(t, c, origin+"/", func(r *http.Request) { r.Method = m }); err != nil || code != 200 {
				t.Errorf("%s %s: %d %v", scheme, m, code, err)
			}
		}
		for _, m := range []string{http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch, http.MethodOptions, "PROPFIND"} {
			before := u.hits.Load()
			code, _, err := get(t, c, origin+"/", func(r *http.Request) { r.Method = m })
			if err != nil || code != http.StatusForbidden || u.hits.Load() != before {
				t.Errorf("%s %s: answered %d (%v), target hit %v", scheme, m, code, err, u.hits.Load() != before)
			}
		}
		s := p.Stats()
		if s.Requests != 2 || s.Refused != 6 {
			t.Errorf("%s stats %+v", scheme, s)
		}
		if len(s.RefusedTo) != 6 || !strings.HasPrefix(s.RefusedTo[0], "POST ") || !strings.HasSuffix(s.RefusedTo[0], " (only GET and HEAD)") {
			t.Errorf("%s RefusedTo %q", scheme, s.RefusedTo)
		}
	}
}

func TestReachable(t *testing.T) {
	for _, scheme := range []string{"http", "https"} {
		u := newUpstream(t, scheme == "https", func() int { return http.StatusInternalServerError })
		host := "app.test"
		if scheme == "https" {
			host = "example.com" // httptest's certificate name
		}
		tu, err := target.Parse(fmt.Sprintf("%s://%s:%d/start", scheme, host, u.port()))
		if err != nil {
			t.Fatal(err)
		}
		cfg := Config{Target: tu, Addrs: []netip.Addr{netip.MustParseAddr("127.0.0.1")}, VerifyTLS: true, Version: "test"}
		if u.srv.TLS != nil {
			cfg.RootCAs = u.srv.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs
		}
		// Any HTTP answer counts, even a server error.
		if err := Reachable(context.Background(), cfg); err != nil {
			t.Errorf("%s: %v", scheme, err)
		}
		r := u.last.Load().(*http.Request)
		if u.hits.Load() != 1 || r.Method != http.MethodGet || r.URL.Path != "/start" || r.Header.Get("User-Agent") != "SiegeKit/test" {
			t.Errorf("%s: %d hits, %s %s %q", scheme, u.hits.Load(), r.Method, r.URL, r.Header.Get("User-Agent"))
		}
		u.srv.Close()
		if err := Reachable(context.Background(), cfg); err == nil || !strings.Contains(err.Error(), "the target did not answer") {
			t.Errorf("%s closed: %v", scheme, err)
		}
	}
}

// TestConnectionLimit checks that MaxConns limits requests in flight to the
// target, and that idle connections the tool keeps open do not make new
// requests wait (ADR 0026).
func TestConnectionLimit(t *testing.T) {
	var inFlight, peak atomic.Int32
	u := newUpstream(t, false, func() int {
		n := inFlight.Add(1)
		defer inFlight.Add(-1)
		for {
			p := peak.Load()
			if n <= p || peak.CompareAndSwap(p, n) {
				break
			}
		}
		time.Sleep(50 * time.Millisecond)
		return http.StatusOK
	})
	_, c, base := start(t, u, "http", "app.test", func(c *Config) { c.MaxConns = 2 })
	client := func() *http.Client {
		return &http.Client{Timeout: 5 * time.Second, Transport: c.Transport.(*http.Transport).Clone()}
	}
	// Four tools' clients each leave an idle keep-alive connection open.
	for i := 0; i < 4; i++ {
		if code, _, err := get(t, client(), base+"/", nil); err != nil || code != http.StatusOK {
			t.Fatalf("client %d: %d %v", i, code, err)
		}
	}
	start := time.Now()
	if code, _, err := get(t, client(), base+"/", nil); err != nil || code != http.StatusOK {
		t.Fatalf("new client behind idle connections: %d %v", code, err)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Errorf("new request waited %v behind idle connections", d)
	}
	// Many requests at once reach the target at most MaxConns at a time.
	peak.Store(0)
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if code, _, err := get(t, client(), base+"/", nil); err != nil || code != http.StatusOK {
				t.Errorf("concurrent request: %d %v", code, err)
			}
		}()
	}
	wg.Wait()
	if p := peak.Load(); p < 1 || p > 2 {
		t.Errorf("peak requests in flight at the target: %d, want at most 2", p)
	}
}

func TestGet(t *testing.T) {
	u := newUpstream(t, false, func() int { return http.StatusNotFound })
	tu, err := target.Parse(fmt.Sprintf("http://app.test:%d/start/", u.port()))
	if err != nil {
		t.Fatal(err)
	}
	cfg := Config{Target: tu, Addrs: []netip.Addr{netip.MustParseAddr("127.0.0.1")}, Version: "test"}
	status, b, err := Get(context.Background(), cfg, "/openapi.json", 100)
	if err != nil || status != http.StatusNotFound || string(b) != "hello from target" {
		t.Fatalf("%d %q %v", status, b, err)
	}
	// The path is on the origin, not under the target's path, and the
	// request goes to the pinned address with the target's host name.
	r := u.last.Load().(*http.Request)
	if r.URL.Path != "/openapi.json" || r.Host != fmt.Sprintf("app.test:%d", u.port()) || r.Header.Get("User-Agent") != "SiegeKit/test" {
		t.Errorf("%s %s %q", r.Host, r.URL, r.Header.Get("User-Agent"))
	}
	if _, _, err := Get(context.Background(), cfg, "/openapi.json", 5); err == nil || !strings.Contains(err.Error(), "larger than 5 bytes") {
		t.Errorf("size limit: %v", err)
	}
	for _, p := range []string{"openapi.json", "//evil.test/x", ""} {
		if _, _, err := Get(context.Background(), cfg, p, 100); err == nil {
			t.Errorf("path %q accepted", p)
		}
	}
	if u.hits.Load() != 2 {
		t.Errorf("%d hits, want 2", u.hits.Load())
	}
}

func TestSend(t *testing.T) {
	var got struct {
		method, ctype, body string
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got.method, got.ctype, got.body = r.Method, r.Header.Get("Content-Type"), string(b)
		w.Header().Set("Retry-After", "5")
		w.WriteHeader(http.StatusTooManyRequests)
		io.WriteString(w, "slow down")
	}))
	defer srv.Close()
	tu, err := target.Parse(srv.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	cfg := Config{Target: tu, Addrs: []netip.Addr{netip.MustParseAddr("127.0.0.1")}, Version: "test"}
	a, err := Send(context.Background(), cfg, http.MethodPost, "/login", "application/json", []byte(`{"a":1}`), 100)
	if err != nil || a.Status != http.StatusTooManyRequests || string(a.Body) != "slow down" || a.Header.Get("Retry-After") != "5" || a.Took <= 0 {
		t.Fatalf("%+v %v", a, err)
	}
	if got.method != http.MethodPost || got.ctype != "application/json" || got.body != `{"a":1}` {
		t.Errorf("sent %+v", got)
	}
	// Deployed targets are read-only: no POST leaves SiegeKit.
	got.method = ""
	cfg.ReadOnly = true
	if _, err := Send(context.Background(), cfg, http.MethodPost, "/login", "", nil, 100); err == nil || got.method != "" {
		t.Errorf("POST on a read-only target: %v, server saw %q", err, got.method)
	}
	if _, err := Send(context.Background(), cfg, http.MethodGet, "/login", "", nil, 100); err != nil || got.method != http.MethodGet {
		t.Errorf("GET on a read-only target: %v, server saw %q", err, got.method)
	}
}

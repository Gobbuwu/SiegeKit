package egress

import (
	"context"
	"fmt"
	"net/http"
	"net/netip"
	"strings"
	"testing"

	"github.com/Gobbuwu/SiegeKit/internal/target"
)

const bypass = "s3cr3t-bypass-0123456789abcdefXY"

func TestParseExtraHeaders(t *testing.T) {
	h, err := ParseExtraHeaders("x-vercel-protection-bypass: " + bypass + "\r\n\n  CF-Access-Client-Id :  id-0123456789  \n") // gitleaks:allow (fake test value)
	if err != nil {
		t.Fatal(err)
	}
	want := http.Header{"X-Vercel-Protection-Bypass": {bypass}, "Cf-Access-Client-Id": {"id-0123456789"}}
	if fmt.Sprint(h) != fmt.Sprint(want) {
		t.Errorf("got %v", h)
	}
	for name, s := range map[string]string{
		"empty":                "",
		"blank lines":          " \n\t\n",
		"no colon":             bypass,
		"bad name":             "x bypass: " + bypass,
		"empty name":           ": " + bypass,
		"empty value":          "X-Vercel-Protection-Bypass:",
		"blank value":          "X-Vercel-Protection-Bypass:   ",
		"short value":          "X-Debug: 1",
		"control character":    "X-A: " + bypass + "\x00",
		"Host":                 "host: " + bypass,
		"User-Agent":           "User-Agent: " + bypass,
		"Connection":           "Connection: " + bypass,
		"Keep-Alive":           "Keep-Alive: " + bypass,
		"Transfer-Encoding":    "Transfer-Encoding: " + bypass,
		"TE":                   "TE: " + bypass,
		"Trailer":              "Trailer: " + bypass,
		"Upgrade":              "Upgrade: " + bypass,
		"Content-Length":       "Content-Length: 123456789",
		"Content-Type":         "Content-Type: " + bypass,
		"Proxy-Authorization":  "Proxy-Authorization: " + bypass,
		"Proxy-Connection":     "proxy-connection: " + bypass,
		"name given twice":     "X-A: " + bypass + "\nx-a: " + bypass,
		"longer than the size": "X-A: " + strings.Repeat("a", maxExtraHeaders),
	} {
		_, err := ParseExtraHeaders(s)
		if err == nil {
			t.Errorf("%s: accepted", name)
			continue
		}
		if !strings.Contains(err.Error(), ExtraHeadersEnv) {
			t.Errorf("%s: error does not name the variable: %v", name, err)
		}
		if strings.Contains(err.Error(), bypass) {
			t.Errorf("%s: error quotes the value: %v", name, err)
		}
	}
}

// The extra headers reach the target on every path: the proxy (tools),
// Send and SendHeader (SiegeKit's own checks) and Reachable. They replace
// a header of the same name, and a config without them sends none.
func TestExtraHeadersSent(t *testing.T) {
	extra := http.Header{"X-Vercel-Protection-Bypass": {bypass}}
	for _, scheme := range []string{"http", "https"} {
		up := newUpstream(t, scheme == "https", nil)
		host := "app.test"
		if scheme == "https" {
			host = "example.com" // httptest's certificate name
		}
		_, c, origin := start(t, up, scheme, host, func(cfg *Config) { cfg.Header = extra })
		if _, _, err := get(t, c, origin+"/p", func(r *http.Request) { r.Header.Set("X-Vercel-Protection-Bypass", "from-the-tool") }); err != nil {
			t.Fatal(err)
		}
		r := up.last.Load().(*http.Request)
		if got := r.Header.Values("X-Vercel-Protection-Bypass"); len(got) != 1 || got[0] != bypass {
			t.Errorf("%s proxy: target got %q", scheme, got)
		}
		if r.Header.Get("User-Agent") != "tool/1.0 SiegeKit/test" {
			t.Errorf("%s proxy: User-Agent %q", scheme, r.Header.Get("User-Agent"))
		}

		tu, err := target.Parse(origin + "/")
		if err != nil {
			t.Fatal(err)
		}
		cfg := Config{Target: tu, Addrs: []netip.Addr{netip.MustParseAddr("127.0.0.1")}, VerifyTLS: true, Version: "test", Header: extra}
		if up.srv.TLS != nil {
			cfg.RootCAs = up.srv.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs
		}
		check := func(what string, want bool) {
			t.Helper()
			r := up.last.Load().(*http.Request)
			if got := r.Header.Get("X-Vercel-Protection-Bypass"); (got == bypass) != want || !want && got != "" {
				t.Errorf("%s %s: target got %q", scheme, what, got)
			}
		}
		if err := Reachable(context.Background(), cfg); err != nil {
			t.Fatal(err)
		}
		check("Reachable", true)
		if _, err := Send(context.Background(), cfg, http.MethodGet, "/s", "", nil, 100); err != nil {
			t.Fatal(err)
		}
		check("Send", true)
		if _, err := SendHeader(context.Background(), cfg, http.MethodGet, "/s", http.Header{"Cookie": {"a=b"}, "X-Vercel-Protection-Bypass": {"from-a-check"}}, nil, 100); err != nil {
			t.Fatal(err)
		}
		check("SendHeader", true)
		if r := up.last.Load().(*http.Request); r.Header.Get("Cookie") != "a=b" {
			t.Errorf("%s SendHeader: check's own header lost: %v", scheme, r.Header)
		}
		cfg.Header = nil
		if _, err := Send(context.Background(), cfg, http.MethodGet, "/s", "", nil, 100); err != nil {
			t.Fatal(err)
		}
		check("Send without extra headers", false)
	}
}

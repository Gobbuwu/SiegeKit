package target

import (
	"context"
	"errors"
	"net/netip"
	"net/url"
	"strings"
	"testing"
)

// String names a class in test messages; SiegeKit itself never prints one.
func (c Class) String() string {
	return [...]string{"public", "loopback", "private", "always blocked"}[c]
}

func TestClassify(t *testing.T) {
	cases := map[string]Class{
		"127.0.0.1": Loopback, "127.255.255.254": Loopback, "::1": Loopback, "::ffff:127.0.0.1": Loopback,
		"10.1.2.3": Private, "172.16.0.1": Private, "172.31.255.255": Private, "192.168.1.20": Private,
		"fd00::1": Private, "100.64.0.1": Private, "100.127.255.255": Private, "198.18.0.1": Private,
		"192.0.0.8": Private, "240.0.0.1": Private, "::ffff:10.0.0.1": Private,
		"169.254.169.254": Blocked, "fe80::1": Blocked, "0.0.0.0": Blocked, "0.1.2.3": Blocked,
		"255.255.255.255": Blocked, "::": Blocked, "224.0.0.1": Blocked, "239.255.255.250": Blocked,
		"ff02::1": Blocked, "::ffff:169.254.169.254": Blocked, "fe80::1%eth0": Blocked,
		"8.8.8.8": Public, "172.32.0.1": Public, "100.128.0.1": Public, "2606:4700::1111": Public,
		// IPv6 forms that carry an IPv4 address take its class; loopback
		// inside a wrapper is not this machine, so it counts as private.
		"64:ff9b::a9fe:a9fe": Blocked, "64:ff9b::7f00:1": Private, "64:ff9b::a00:1": Private,
		"64:ff9b::808:808": Public, "64:ff9b:1::1": Private,
		"2002:a9fe:a9fe::1": Blocked, "2002:c0a8:0101::1": Private, "2002:0808:0808::1": Public,
		"::a9fe:a9fe": Blocked, "::10.0.0.1": Private,
	}
	for s, want := range cases {
		a, err := netip.ParseAddr(s)
		if err != nil {
			t.Fatalf("%s: %v", s, err)
		}
		if got := Classify(a); got != want {
			t.Errorf("%s: %s, want %s", s, got, want)
		}
	}
	if Classify(netip.Addr{}) != Blocked {
		t.Error("invalid address must be blocked")
	}
}

func TestParse(t *testing.T) {
	ok := map[string]string{
		"http://localhost:3000":              "http://localhost:3000/",
		"https://Example.COM./app?token=x#y": "https://example.com/app",
		"http://127.0.0.1":                   "http://127.0.0.1/",
		"http://[::1]:8080/a":                "http://[::1]:8080/a",
		"https://[::ffff:7f00:1]/":           "https://[::ffff:127.0.0.1]/",
		"https://example.com:443/":           "https://example.com/",
	}
	for in, want := range ok {
		u, err := Parse(in)
		if err != nil {
			t.Errorf("%s: %v", in, err)
			continue
		}
		if u.String() != want {
			t.Errorf("%s: %s, want %s", in, u, want)
		}
	}
	bad := map[string]string{
		"ftp://example.com":          "http:// or https://",
		"example.com":                "http:// or https://",
		"http://user:pw@example.com": "user name or password",
		"http://":                    "no host",
		"http://2130706433/":         "ambiguous",
		"http://0x7f000001/":         "ambiguous",
		"http://0177.0.0.1/":         "ambiguous",
		"http://127.1/":              "ambiguous",
		"http://127.0.0.01/":         "ambiguous",
		"http://[fe80::1%25eth0]/":   "zone",
		"http://exa_mple.com/":       "invalid host name",
		"http://example.com:0/":      "invalid port",
		"http://example.com:99999/":  "invalid port",
		"http://exa mple.com/":       "spaces",
		"http://example.com\\@evil/": "backslashes",
	}
	for in, want := range bad {
		if _, err := Parse(in); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: got %v, want error with %q", in, err, want)
		}
	}
}

type fakeResolver map[string][]string

func (f fakeResolver) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	ss, ok := f[host]
	if !ok {
		return nil, errors.New("no such host")
	}
	var out []netip.Addr
	for _, s := range ss {
		out = append(out, netip.MustParseAddr(s))
	}
	return out, nil
}

func TestAuthorize(t *testing.T) {
	r := fakeResolver{
		"localhost":    {"127.0.0.1", "::1"},
		"nas.lan":      {"192.168.1.20"},
		"example.com":  {"93.184.215.14", "2606:2800:21f:cb07:6820:80da:af6b:8b2c"},
		"mixed.test":   {"93.184.215.14", "10.0.0.5"},
		"metadata.bad": {"169.254.169.254"},
		"mapped.test":  {"::ffff:127.0.0.1"},
	}
	cases := []struct {
		url     string
		mode    Mode
		allowed bool
		confirm bool
		proof   bool
		reason  string
	}{
		{"http://localhost:3000", Local, true, false, false, ""},
		{"http://mapped.test", Local, true, false, false, ""},
		{"http://nas.lan", Local, true, true, false, "private network address"},
		{"http://example.com", Local, false, false, false, "with --deployed"},
		{"http://mixed.test", Local, false, false, false, "public address"},
		{"http://metadata.bad", Local, false, false, false, "never tests"},
		{"http://169.254.169.254/latest/meta-data", Local, false, false, false, "never tests"},
		{"https://example.com", Deployed, true, true, true, ""},
		{"https://mixed.test", Deployed, false, false, false, "not a public address"},
		{"http://localhost", Deployed, false, false, false, "not a public address"},
		{"http://metadata.bad", Deployed, false, false, false, "never tests"},
	}
	for _, tc := range cases {
		u, err := Parse(tc.url)
		if err != nil {
			t.Fatal(err)
		}
		addrs, err := Resolve(context.Background(), r, u)
		if err != nil {
			t.Fatal(err)
		}
		d := Authorize(tc.mode, addrs)
		if d.Allowed != tc.allowed || d.NeedsConfirmation != tc.confirm || d.NeedsProof != tc.proof || !strings.Contains(d.Reason, tc.reason) {
			t.Errorf("%s %s: %+v", tc.mode, tc.url, d)
		}
	}
	if d := Authorize(Local, nil); d.Allowed {
		t.Error("no addresses allowed")
	}
	if d := Authorize("other", []netip.Addr{netip.MustParseAddr("127.0.0.1")}); d.Allowed {
		t.Error("unknown mode allowed")
	}
	u, _ := Parse("http://nowhere.test")
	if _, err := Resolve(context.Background(), r, u); err == nil {
		t.Error("unresolvable host accepted")
	}
}

func TestConfirmed(t *testing.T) {
	name, _ := Parse("http://nas.lan:8080/")
	ip, _ := Parse("http://[::1]/")
	for typed, want := range map[string]bool{"nas.lan": true, " NAS.lan. \n": true, "nas.lan:8080": false, "lan": false, "": false} {
		if Confirmed(name, typed) != want {
			t.Errorf("name %q: want %v", typed, want)
		}
	}
	for typed, want := range map[string]bool{"::1": true, "[::1]": true, "0:0::1": true, "127.0.0.1": false} {
		if Confirmed(ip, typed) != want {
			t.Errorf("ip %q: want %v", typed, want)
		}
	}
}

func FuzzParse(f *testing.F) {
	for _, s := range []string{"http://localhost:3000", "https://[::1]/", "http://0x7f.1/", "http://a@b/", "https://example.com/a?b#c"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		u, err := Parse(s)
		if err != nil {
			return
		}
		// A parsed target round-trips and never keeps a query, fragment or
		// credentials.
		again, err := Parse(u.String())
		if err != nil || again.String() != u.String() {
			t.Fatalf("%q -> %q does not round-trip: %v", s, u, err)
		}
		p, err := url.Parse(u.String())
		if err != nil || p.User != nil || p.RawQuery != "" || p.Fragment != "" || p.Hostname() != strings.Trim(u.Host, "[]") {
			t.Fatalf("%q kept a query, fragment or user, or changed host: %q", s, u)
		}
	})
}

func TestOrigin(t *testing.T) {
	for in, want := range map[string]string{
		"http://localhost:3000/app/":  "http://localhost:3000",
		"https://example.com/":        "https://example.com",
		"https://example.com:8443/a/": "https://example.com:8443",
		"http://[::1]:8080/":          "http://[::1]:8080",
	} {
		u, err := Parse(in)
		if err != nil {
			t.Fatal(err)
		}
		if got := u.Origin(); got != want {
			t.Errorf("%s: %q, want %q", in, got, want)
		}
	}
}

// TestOnOrigin checks the one origin check that every URL flag uses
// (ADR 0042), including the "//" paths found by the full project check
// (F6, F7).
func TestOnOrigin(t *testing.T) {
	tu, err := Parse("http://localhost:3000/app/")
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		raw        string
		allowQuery bool
		path, q    string
		err        string
	}{
		{"http://localhost:3000/login", false, "/login", "", ""},
		{"http://localhost:3000", false, "/", "", ""},
		{"http://LOCALHOST:3000/a/b", false, "/a/b", "", ""},
		{"http://localhost:3000/s?q=apple&x=1", true, "/s", "q=apple&x=1", ""},
		{"http://localhost:3000/s?q=apple", false, "", "", "--x must not have a query"},
		{"http://localhost:3000/s#f", true, "", "", "--x must not have a fragment"},
		{"http://localhost:3000//x", false, "", "", "single /"},
		{"http://localhost:3000//evil.test/a", true, "", "", "single /"},
		{"http://localhost:3000///x", false, "", "", "single /"},
		{"http://localhost:3001/x", false, "", "", "not on the target's origin"},
		{"https://localhost:3000/x", false, "", "", "not on the target's origin"},
		{"http://evil.test/x", false, "", "", "not on the target's origin"},
		{"http://u:p@localhost:3000/x", false, "", "", "--x: "},
		{"/relative", false, "", "", "--x: "},
		{"ftp://localhost:3000/x", false, "", "", "--x: "},
		{"http://localhost:3000/s?q=a b", true, "", "", "spaces or control characters"},
		{"http://localhost:3000/s?q=\x00", true, "", "", "spaces or control characters"},
		{"http://localhost:3000/s?q=%zz", true, "", "", "invalid query"},
	} {
		u, q, err := OnOrigin(tu, c.raw, "--x", c.allowQuery)
		switch {
		case c.err != "" && (err == nil || !strings.Contains(err.Error(), c.err)):
			t.Errorf("%q: err %v, want %q", c.raw, err, c.err)
		case c.err == "" && (err != nil || u.Path != c.path || q != c.q):
			t.Errorf("%q: %v %q %v, want %q %q", c.raw, u, q, err, c.path, c.q)
		}
	}
}

func FuzzOnOrigin(f *testing.F) {
	for _, s := range []string{"http://localhost:3000/a", "http://localhost:3000//x", "http://localhost:3000/a?b=c", "http://localhost:3000/%2F%2Fx", "http://localhost:3000/a/..//b#c"} {
		f.Add(s, true)
	}
	tu, err := Parse("http://localhost:3000/")
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, s string, allowQuery bool) {
		u, q, err := OnOrigin(tu, s, "--x", allowQuery)
		if err != nil {
			return
		}
		// What passes is sendable: on the origin, a single leading "/", and
		// the request URL SiegeKit builds names the target's host only.
		if u.Origin() != tu.Origin() || !SendablePath(u.Path) || strings.Contains(s, "#") || (!allowQuery && q != "") {
			t.Fatalf("%q passed: %v %q", s, u, q)
		}
		req := u.Origin() + u.Path
		if q != "" {
			req += "?" + q
		}
		p, err := url.Parse(req)
		if err != nil || p.Host != "localhost:3000" || p.User != nil {
			t.Fatalf("%q gives request URL %q (%v)", s, req, err)
		}
	})
}

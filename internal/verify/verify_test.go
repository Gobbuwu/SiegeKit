package verify

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Gobbuwu/SiegeKit/internal/target"
)

func TestToken(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "verify")
	a, err := Token(dir, "shop.example")
	if err != nil || !reToken.MatchString(a) {
		t.Fatalf("token %q %v", a, err)
	}
	again, _ := Token(dir, "shop.example")
	if again != a {
		t.Error("token not kept between runs")
	}
	sub, _ := Token(dir, "api.shop.example")
	v6, err := Token(dir, "2001:db8::1")
	if sub == a || v6 == a || err != nil {
		t.Error("hosts share a token")
	}
	if st, _ := os.Stat(filepath.Join(dir, "shop.example.token")); st.Mode().Perm() != 0o600 {
		t.Errorf("token file mode %v", st.Mode().Perm())
	}
	os.WriteFile(filepath.Join(dir, "bad.example.token"), []byte("nope"), 0o600)
	if _, err := Token(dir, "bad.example"); err == nil || !strings.Contains(err.Error(), "damaged") {
		t.Errorf("damaged token accepted: %v", err)
	}
}

type txt map[string][]string

func (f txt) LookupTXT(_ context.Context, name string) ([]string, error) {
	if r, ok := f[name]; ok {
		return r, nil
	}
	return nil, errors.New("no such host")
}

// server serves the well-known path with handler and returns a target URL
// for host on the server's port, pinned to the server's address.
func server(t *testing.T, host string, handler http.HandlerFunc) (*Checker, *target.URL, []netip.Addr) {
	t.Helper()
	srv := httptest.NewTLSServer(handler)
	t.Cleanup(srv.Close)
	su, _ := url.Parse(srv.URL)
	port, _ := strconv.Atoi(su.Port())
	u, err := target.Parse(fmt.Sprintf("https://%s:%d/app", host, port))
	if err != nil {
		t.Fatal(err)
	}
	c := &Checker{
		TXT:     txt{},
		Timeout: 5 * time.Second,
		TLS:     &tls.Config{RootCAs: srv.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs},
	}
	return c, u, []netip.Addr{netip.MustParseAddr(su.Hostname())}
}

const tok = "0123456789abcdef0123456789abcdef"

func TestWellKnown(t *testing.T) {
	ok := func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != WellKnownPath || r.Host == "" {
			http.NotFound(w, r)
			return
		}
		fmt.Fprintf(w, "# comment\n  %s  \n", Value(tok))
	}
	// httptest's certificate is valid for example.com; the name never
	// resolves here, so success proves the pinned address was used.
	c, u, addrs := server(t, "example.com", ok)
	if m, err := c.Check(context.Background(), u, addrs, tok, nil); err != nil || m != "well-known file" {
		t.Fatalf("%q %v", m, err)
	}
	if _, err := c.Check(context.Background(), u, addrs, strings.Repeat("f", 32), nil); err == nil {
		t.Error("wrong token accepted")
	}

	for name, h := range map[string]http.HandlerFunc{
		"redirect": func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "https://elsewhere.example"+WellKnownPath, http.StatusFound)
		},
		"not found": http.NotFound,
		"token past the read limit": func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintf(w, "%s\n%s\n", strings.Repeat("x", MaxBody), Value(tok))
		},
		"token inside a line": func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintf(w, "<p>%s</p>\n", Value(tok))
		},
	} {
		c, u, addrs := server(t, "example.com", h)
		if _, err := c.Check(context.Background(), u, addrs, tok, nil); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}

	// A certificate for another name fails, even with the right file.
	c, u, addrs = server(t, "other.example", ok)
	if _, err := c.Check(context.Background(), u, addrs, tok, nil); err == nil || !strings.Contains(err.Error(), "certificate") {
		t.Errorf("certificate for another host accepted: %v", err)
	}
}

// A preview behind its host's login serves the file only with the bypass
// header (ADR 0070): the header reaches the proof fetch, and without it the
// login redirect is refused.
func TestWellKnownExtraHeader(t *testing.T) {
	const secret = "s3cr3t-bypass-value-0123456789ab"
	c, u, addrs := server(t, "example.com", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Vercel-Protection-Bypass") != secret || r.Header.Get("User-Agent") != "SiegeKit-verify" {
			http.Redirect(w, r, "https://vercel.com/sso-api", http.StatusFound)
			return
		}
		fmt.Fprintf(w, "%s\n", Value(tok))
	})
	if _, err := c.Check(context.Background(), u, addrs, tok, nil); err == nil || !strings.Contains(err.Error(), "302") {
		t.Errorf("no header: %v", err)
	}
	h := http.Header{"X-Vercel-Protection-Bypass": {secret}}
	m, err := c.Check(context.Background(), u, addrs, tok, h)
	if err != nil || m != "well-known file" {
		t.Fatalf("with header: %q %v", m, err)
	}
	if strings.Contains(fmt.Sprint(err), secret) {
		t.Error("secret in the error")
	}
}

func TestTXT(t *testing.T) {
	c, u, _ := server(t, "example.com", http.NotFound)
	c.TXT = txt{"_siegekit-verify.example.com": {"v=spf1 -all", Value(tok)}}
	if m, err := c.Check(context.Background(), u, nil, tok, nil); err != nil || m != "DNS TXT record" {
		t.Fatalf("%q %v", m, err)
	}
	// A record on a parent or sibling name does not count.
	c.TXT = txt{"_siegekit-verify.com": {Value(tok)}, "_siegekit-verify.www.example.com": {Value(tok)}}
	if _, err := c.Check(context.Background(), u, nil, tok, nil); err == nil {
		t.Error("record on another name accepted")
	}
	ip, _ := target.Parse("https://93.184.215.14/")
	if err := c.checkTXT(context.Background(), ip, Value(tok)); err == nil {
		t.Error("TXT check on an IP address")
	}
}

func TestInstructions(t *testing.T) {
	u, _ := target.Parse("https://shop.example:8443/app")
	s := Instructions(u, tok)
	for _, want := range []string{"siegekit-verify=" + tok, "https://shop.example:8443/.well-known/siegekit-verify.txt", "_siegekit-verify.shop.example"} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %q in:\n%s", want, s)
		}
	}
}

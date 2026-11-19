// Package verify checks that the user controls a deployed target before it
// is tested (ADR 0005 deployed mode): a random token, tied to the exact host
// name, published at /.well-known/siegekit-verify.txt on the target's own
// origin or as a DNS TXT record at _siegekit-verify.<host>.
package verify

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/Gobbuwu/SiegeKit/internal/target"
)

// WellKnownPath is where the token file is published on the target origin.
const WellKnownPath = "/.well-known/siegekit-verify.txt"

// Prefix starts the published value: "siegekit-verify=<token>".
const Prefix = "siegekit-verify="

// MaxBody is the most of the well-known file that is read.
const MaxBody = 4 << 10

var reToken = regexp.MustCompile(`^[0-9a-f]{32}$`)

// Token returns the token for host, creating it the first time. Tokens are
// kept in dir, one file per host, so the user publishes it once and each run
// checks it again. A token for one host never matches another, including a
// subdomain, because each host has its own random token.
func Token(dir, host string) (string, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	p := filepath.Join(dir, tokenFile(host))
	b, err := os.ReadFile(p) // #nosec G304 -- file name derived from a validated host name
	if err == nil {
		t := strings.TrimSpace(string(b))
		if reToken.MatchString(t) {
			return t, nil
		}
		return "", fmt.Errorf("token file %s is damaged; delete it to create a new token", p)
	}
	if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	raw := make([]byte, 16) // 128 bits
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	t := hex.EncodeToString(raw)
	f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600) // #nosec G304 -- see above
	if err != nil {
		return "", err
	}
	_, err = f.WriteString(t + "\n")
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		// Do not leave a partial token behind: the next run would call it damaged.
		return "", errors.Join(err, os.Remove(p))
	}
	return t, nil
}

// tokenFile maps a host (a validated lower-case name or IP address) to a
// file name. IPv6 colons are replaced, since they are not portable in names.
func tokenFile(host string) string {
	return strings.ReplaceAll(host, ":", "_") + ".token"
}

// Value is what the user publishes.
func Value(token string) string { return Prefix + token }

// Instructions tells the user how to publish the token for u.
func Instructions(u *target.URL, token string) string {
	origin := strings.TrimSuffix(u.String(), u.Path)
	return fmt.Sprintf(`Prove that you control %[1]s by publishing this line in one of two places:

  %[2]s

  1. As the content of %[3]s%[4]s (served directly, no redirect), or
  2. As a DNS TXT record on _siegekit-verify.%[1]s

Then run the same command again. SiegeKit checks it at the start of every run.`, u.Host, Value(token), origin, WellKnownPath)
}

// TXTResolver looks up TXT records. *net.Resolver implements it.
type TXTResolver interface {
	LookupTXT(ctx context.Context, name string) ([]string, error)
}

// Checker verifies tokens. Its zero value uses the system resolver and real
// network connections.
type Checker struct {
	TXT     TXTResolver
	Timeout time.Duration // per method; default 10 s
	// Dial connects to a pinned address; for tests.
	Dial func(ctx context.Context, network, addr string) (net.Conn, error)
	// TLS is the base TLS configuration (tests set RootCAs); ServerName is
	// always the target host. nil uses the system roots.
	TLS *tls.Config
}

// Check returns the method that proved control ("well-known file" or
// "DNS TXT record"), or an error saying what was found. The well-known file
// is fetched only from the pinned addresses, without following redirects or
// using any proxy.
func (c *Checker) Check(ctx context.Context, u *target.URL, addrs []netip.Addr, token string) (string, error) {
	want := Value(token)
	webErr := c.checkWellKnown(ctx, u, addrs, want)
	if webErr == nil {
		return "well-known file", nil
	}
	dnsErr := c.checkTXT(ctx, u, want)
	if dnsErr == nil {
		return "DNS TXT record", nil
	}
	return "", fmt.Errorf("no proof of control found: %s: %v; _siegekit-verify.%s: %v", WellKnownPath, webErr, u.Host, dnsErr)
}

func (c *Checker) timeout() time.Duration {
	if c.Timeout > 0 {
		return c.Timeout
	}
	return 10 * time.Second
}

func (c *Checker) checkWellKnown(ctx context.Context, u *target.URL, addrs []netip.Addr, want string) error {
	ctx, cancel := context.WithTimeout(ctx, c.timeout())
	defer cancel()
	dial := c.Dial
	if dial == nil {
		dial = (&net.Dialer{}).DialContext
	}
	port := strconv.Itoa(u.Port)
	tr := &http.Transport{
		Proxy: nil, // never through a proxy: the pinned address must be the one reached
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var last error
			for _, a := range addrs {
				conn, err := dial(ctx, "tcp", net.JoinHostPort(a.String(), port))
				if err == nil {
					return conn, nil
				}
				last = err
			}
			if last == nil {
				last = errors.New("no addresses")
			}
			return nil, last
		},
		TLSClientConfig:       c.tlsConfig(u.Host),
		ForceAttemptHTTP2:     false,
		DisableKeepAlives:     true,
		ResponseHeaderTimeout: c.timeout(),
	}
	defer tr.CloseIdleConnections()
	client := &http.Client{
		Transport:     tr,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.Scheme+"://"+net.JoinHostPort(u.Host, port)+WellKnownPath, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "SiegeKit-verify")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("answered %s (redirects are not followed)", resp.Status)
	}
	sc := bufio.NewScanner(io.LimitReader(resp.Body, MaxBody))
	for sc.Scan() {
		if strings.TrimSpace(sc.Text()) == want {
			return nil
		}
	}
	return errors.New("the file does not contain the expected line")
}

func (c *Checker) tlsConfig(host string) *tls.Config {
	cfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if c.TLS != nil {
		cfg = c.TLS.Clone()
	}
	cfg.ServerName = host
	return cfg
}

func (c *Checker) checkTXT(ctx context.Context, u *target.URL, want string) error {
	if u.IP.IsValid() {
		return errors.New("an IP address has no DNS name to hold a TXT record")
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout())
	defer cancel()
	r := c.TXT
	if r == nil {
		r = net.DefaultResolver
	}
	recs, err := r.LookupTXT(ctx, "_siegekit-verify."+u.Host)
	if err != nil {
		return err
	}
	for _, rec := range recs {
		if strings.TrimSpace(rec) == want {
			return nil
		}
	}
	return errors.New("no TXT record with the expected value")
}

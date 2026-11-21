package target

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode"
)

// URL is a parsed web target.
type URL struct {
	Scheme string     // http or https
	Host   string     // lower-case host name, or an IP address without brackets
	Port   int        // explicit or the scheme's default
	Path   string     // path to start from; "/" if empty
	IP     netip.Addr // set when Host is an IP address literal
}

// Origin returns scheme, host and port, without the path.
func (u *URL) Origin() string {
	return strings.TrimSuffix(u.String(), u.Path)
}

// String returns the target without query or fragment, safe to log.
func (u *URL) String() string {
	h := u.Host
	if u.IP.Is6() {
		h = "[" + h + "]"
	}
	def := map[string]int{"http": 80, "https": 443}[u.Scheme]
	if u.Port != def {
		h += ":" + strconv.Itoa(u.Port)
	}
	return u.Scheme + "://" + h + u.Path
}

var (
	reHostName = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*\.?$`)
	// Spellings that some tools read as an IPv4 address although they are
	// not in dotted-decimal form: 2130706433, 0x7f000001, 0177.0.0.1, 127.1.
	reNumeric = regexp.MustCompile(`^(0x[0-9a-f]+|[0-9]+)(\.(0x[0-9a-f]+|[0-9]+))*\.?$`)
)

// Parse checks a target URL. It accepts http and https URLs with a host and
// no user name or password. Query strings and fragments are dropped: they
// often carry secrets and SiegeKit's tools find their own paths.
func Parse(raw string) (*URL, error) {
	if strings.ContainsAny(raw, " \t\r\n\\") {
		return nil, errors.New("the URL contains spaces, control characters or backslashes")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("not a valid URL: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("the URL must start with http:// or https://")
	}
	if u.User != nil {
		return nil, errors.New("the URL must not contain a user name or password; SiegeKit asks for test accounts separately")
	}
	if u.Opaque != "" || u.Host == "" {
		return nil, errors.New("the URL has no host")
	}
	t := &URL{Scheme: u.Scheme, Path: u.EscapedPath()}
	if t.Path == "" {
		t.Path = "/"
	}
	host := strings.ToLower(u.Hostname())
	switch p := u.Port(); p {
	case "":
		t.Port = map[string]int{"http": 80, "https": 443}[u.Scheme]
	default:
		n, err := strconv.Atoi(p)
		if err != nil || n < 1 || n > 65535 {
			return nil, fmt.Errorf("invalid port %q", p)
		}
		t.Port = n
	}
	if strings.HasPrefix(u.Host, "[") {
		a, err := netip.ParseAddr(host)
		if err != nil || !a.Is6() {
			return nil, fmt.Errorf("invalid IPv6 address %q", host)
		}
		if a.Zone() != "" {
			return nil, errors.New("IPv6 addresses with a zone are link-local and never allowed")
		}
		t.Host, t.IP = a.String(), a
		return t, nil
	}
	if reNumeric.MatchString(host) {
		a, err := netip.ParseAddr(host)
		if err != nil || !a.Is4() || a.String() != host {
			return nil, fmt.Errorf("%q is an ambiguous way to write an IP address; write it as four decimal numbers without leading zeros", host)
		}
		t.Host, t.IP = host, a
		return t, nil
	}
	if !reHostName.MatchString(host) || len(host) > 253 {
		return nil, fmt.Errorf("invalid host name %q", host)
	}
	t.Host = strings.TrimSuffix(host, ".")
	return t, nil
}

// Resolver looks up host addresses. *net.Resolver implements it.
type Resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// Resolve returns the addresses of the target, once (ADR 0005 address
// pinning). An IP literal resolves to itself.
func Resolve(ctx context.Context, r Resolver, t *URL) ([]netip.Addr, error) {
	if t.IP.IsValid() {
		return []netip.Addr{t.IP}, nil
	}
	if r == nil {
		r = net.DefaultResolver
	}
	addrs, err := r.LookupNetIP(ctx, "ip", t.Host)
	if err != nil {
		return nil, fmt.Errorf("resolve %s: %w", t.Host, err)
	}
	if len(addrs) == 0 {
		return nil, fmt.Errorf("%s has no addresses", t.Host)
	}
	for i := range addrs {
		addrs[i] = addrs[i].Unmap()
	}
	slices.SortFunc(addrs, func(a, b netip.Addr) int { return a.Compare(b) })
	return slices.Compact(addrs), nil
}

// SendablePath reports whether p, a request path with any query, starts
// with a single "/". "//x" names another host to some servers and proxies
// (a network-path reference), so SiegeKit never sends it (ADR 0042).
func SendablePath(p string) bool {
	return strings.HasPrefix(p, "/") && !strings.HasPrefix(p, "//")
}

// OnOrigin checks a URL named by flag, such as --login-url, before SiegeKit
// sends anything to it: a valid URL (see Parse) on t's origin, with a path
// that starts with a single "/", no fragment, no spaces or control
// characters anywhere, and a valid query only when allowQuery (ADR 0005,
// ADR 0042). Every flag that names a URL on the
// target uses it, so they all refuse the same URLs. It returns the URL
// without its query, and the query.
func OnOrigin(t *URL, raw, flag string, allowQuery bool) (*URL, string, error) {
	if strings.ContainsFunc(raw, func(r rune) bool { return r == ' ' || unicode.IsControl(r) }) {
		return nil, "", fmt.Errorf("%s has spaces or control characters; encode them, such as a space as %%20", flag)
	}
	if strings.Contains(raw, "#") {
		return nil, "", fmt.Errorf("%s must not have a fragment", flag)
	}
	pathURL, query, hasQuery := strings.Cut(raw, "?")
	if hasQuery && !allowQuery {
		return nil, "", fmt.Errorf("%s must not have a query", flag)
	}
	if _, err := url.ParseQuery(query); err != nil {
		return nil, "", fmt.Errorf("%s has an invalid query: %v", flag, err)
	}
	u, err := Parse(pathURL)
	if err != nil {
		return nil, "", fmt.Errorf("%s: %w", flag, err)
	}
	if u.Origin() != t.Origin() {
		return nil, "", fmt.Errorf("%s %s is not on the target's origin %s; SiegeKit sends requests only to the target", flag, u, t.Origin())
	}
	if !SendablePath(u.Path) {
		return nil, "", fmt.Errorf("%s must have a path that starts with a single /", flag)
	}
	return u, query, nil
}

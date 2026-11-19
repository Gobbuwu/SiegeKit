package main

import (
	"bytes"
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/Gobbuwu/SiegeKit/internal/target"
	"github.com/Gobbuwu/SiegeKit/internal/verify"
)

// fakeProver accepts a token when published[host] holds its value, the
// way a well-known file would.
type fakeProver struct {
	published map[string]string
	calls     [][]netip.Addr
}

func (f *fakeProver) Check(_ context.Context, u *target.URL, addrs []netip.Addr, token string) (string, error) {
	f.calls = append(f.calls, addrs)
	if f.published[u.Host] == verify.Value(token) {
		return "well-known file", nil
	}
	return "", errors.New("no proof of control found")
}

func useProver(t *testing.T, p *fakeProver) {
	old := prover
	prover = p
	t.Cleanup(func() { prover = old })
}

type fakeResolver map[string]string

func (f fakeResolver) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	if a, ok := f[host]; ok {
		return []netip.Addr{netip.MustParseAddr(a)}, nil
	}
	return nil, errors.New("no such host")
}

func TestScanURL(t *testing.T) {
	old := resolver
	resolver = fakeResolver{"localhost": "127.0.0.1", "nas.lan": "192.168.1.20", "shop.example": "93.184.215.14", "meta.example": "169.254.169.254"}
	t.Cleanup(func() { resolver = old })
	useEngine(t, nil, nil)
	useProver(t, &fakeProver{})
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	for _, tc := range []struct {
		name  string
		args  []string
		tty   bool
		input string
		code  int
		want  string
	}{
		{"loopback", []string{"http://localhost:3000"}, false, "", exitOK, "Target allowed (loopback)"},
		{"private with flag", []string{"--authorized-host", "NAS.lan", "http://nas.lan"}, false, "", exitOK, "Target allowed (--authorized-host)"},
		{"private flag mismatch", []string{"--authorized-host", "other.lan", "http://nas.lan"}, false, "", exitInvalid, "does not match"},
		{"private no terminal", []string{"http://nas.lan"}, false, "", exitInvalid, "pass --authorized-host nas.lan"},
		{"private typed", []string{"http://nas.lan"}, true, "nas.lan\n", exitOK, "Target allowed (typed confirmation)"},
		{"private typed wrong", []string{"http://nas.lan"}, true, "nas\n", exitInvalid, "did not match"},
		{"loopback flag mismatch", []string{"--authorized-host", "x", "http://localhost"}, false, "", exitInvalid, "does not match"},
		{"public in local mode", []string{"https://shop.example"}, false, "", exitInvalid, "--deployed"},
		{"public deployed", []string{"--deployed", "https://shop.example"}, true, "", exitInvalid, "siegekit-verify="},
		{"metadata", []string{"http://meta.example"}, false, "", exitInvalid, "never tests"},
		{"bad url", []string{"http://user:pw@localhost"}, false, "", exitInvalid, "user name or password"},
		{"unresolvable", []string{"http://nowhere.example"}, false, "", exitInvalid, "no such host"},
		{"flag on directory", []string{"--deployed", "."}, false, "", exitUsage, "only apply to URL targets"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stdinIsTerminal = func() bool { return tc.tty }
			stdin = strings.NewReader(tc.input)
			var out, errb bytes.Buffer
			code := run(append([]string{"scan"}, tc.args...), &out, &errb)
			if code != tc.code || !strings.Contains(out.String()+errb.String(), tc.want) {
				t.Errorf("exit %d (want %d), output %q (want %q)", code, tc.code, out.String()+errb.String(), tc.want)
			}
		})
	}
}

func TestScanURLDeployed(t *testing.T) {
	old := resolver
	resolver = fakeResolver{"shop.example": "93.184.215.14", "api.shop.example": "93.184.215.15", "rebind.example": "10.0.0.5"}
	t.Cleanup(func() { resolver = old })
	useEngine(t, nil, nil)
	data := t.TempDir()
	t.Setenv("XDG_DATA_HOME", data)
	tokenOf := func(host string) string {
		tok, err := verify.Token(filepath.Join(data, "siegekit", "verify"), host)
		if err != nil {
			t.Fatal(err)
		}
		return tok
	}
	scan := func(tty bool, input string, args ...string) (int, string) {
		stdinIsTerminal = func() bool { return tty }
		stdin = strings.NewReader(input)
		var out, errb bytes.Buffer
		code := run(append([]string{"scan", "--deployed"}, args...), &out, &errb)
		return code, out.String() + errb.String()
	}
	p := &fakeProver{published: map[string]string{}}
	useProver(t, p)

	// No proof yet: refused, with instructions naming this host's token.
	code, out := scan(true, "shop.example\n", "https://shop.example")
	if code != exitInvalid || !strings.Contains(out, verify.Value(tokenOf("shop.example"))) || !strings.Contains(out, "_siegekit-verify.shop.example") {
		t.Fatalf("no proof: exit %d\n%s", code, out)
	}
	if !slices.Equal(p.calls[0], []netip.Addr{netip.MustParseAddr("93.184.215.14")}) {
		t.Errorf("checked addresses %v, want the pinned one", p.calls[0])
	}

	p.published["shop.example"] = verify.Value(tokenOf("shop.example"))
	for _, tc := range []struct {
		name  string
		tty   bool
		input string
		args  []string
		code  int
		want  string
	}{
		{"typed", true, "Shop.Example.\n", []string{"https://shop.example/app"}, exitOK, "Target allowed (well-known file + typed confirmation)"},
		{"typed wrong", true, "api.shop.example\n", []string{"https://shop.example"}, exitInvalid, "did not match"},
		{"no terminal", false, "", []string{"https://shop.example"}, exitInvalid, "typed in a terminal"},
		{"flag refused", true, "shop.example\n", []string{"--authorized-host", "shop.example", "https://shop.example"}, exitInvalid, "not accepted for deployed targets"},
		{"flag refused before lookup", true, "", []string{"--authorized-host", "nowhere.example", "https://nowhere.example"}, exitInvalid, "not accepted for deployed targets"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, out := scan(tc.tty, tc.input, tc.args...)
			if code != tc.code || !strings.Contains(out, tc.want) {
				t.Errorf("exit %d (want %d)\n%s", code, tc.code, out)
			}
			if tc.code == exitOK && !strings.Contains(out, "penetration-testing policy") {
				t.Errorf("no hosting-policy reminder:\n%s", out)
			}
		})
	}

	// Without a terminal, or with the flag, nothing is sent to the target.
	n0 := len(p.calls)
	scan(false, "", "https://shop.example")
	scan(true, "shop.example\n", "--authorized-host", "shop.example", "https://shop.example")
	if len(p.calls) != n0 {
		t.Errorf("proof checked although confirmation cannot be given")
	}

	// A subdomain has its own token: the parent's value does not prove it.
	p.published["api.shop.example"] = p.published["shop.example"]
	if code, out := scan(true, "api.shop.example\n", "https://api.shop.example"); code != exitInvalid {
		t.Errorf("parent's token accepted for a subdomain: %s", out)
	}

	// A stale token (the token file was replaced) no longer proves control.
	if err := os.Remove(filepath.Join(data, "siegekit", "verify", "shop.example.token")); err != nil {
		t.Fatal(err)
	}
	if code, out := scan(true, "shop.example\n", "https://shop.example"); code != exitInvalid || !strings.Contains(out, verify.Value(tokenOf("shop.example"))) {
		t.Errorf("stale token accepted: exit %d\n%s", code, out)
	}

	// A name that now resolves to a private address is refused before any
	// request, even with a valid-looking proof.
	p.published["rebind.example"] = verify.Value(tokenOf("rebind.example"))
	n := len(p.calls)
	if code, out := scan(true, "rebind.example\n", "https://rebind.example"); code != exitInvalid || !strings.Contains(out, "not a public address") || len(p.calls) != n {
		t.Errorf("private address in deployed mode: exit %d, %d checks\n%s", code, len(p.calls)-n, out)
	}
}

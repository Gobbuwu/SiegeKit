package main

import (
	"bytes"
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"
)

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
		{"public deployed", []string{"--deployed", "https://shop.example"}, false, "", exitInvalid, "M2.2"},
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

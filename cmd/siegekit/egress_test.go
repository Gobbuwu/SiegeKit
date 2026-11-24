package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Gobbuwu/SiegeKit/internal/sandbox"
)

// caFile writes a throwaway self-signed CA certificate.
func caFile(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test CA"}, NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(p, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestEgressFrom(t *testing.T) {
	ca := caFile(t)
	t.Setenv(caFileEnv, "")
	t.Setenv(proxyEnv, "")
	e, err := egressFrom(ca, "http://proxy.example:3128")
	if err != nil || e.CAFile != ca || e.Proxy != "http://proxy.example:3128" {
		t.Fatalf("%+v %v", e, err)
	}
	// The environment stands in for missing flags; a flag wins.
	t.Setenv(caFileEnv, ca)
	t.Setenv(proxyEnv, "http://env.example:1")
	if e, err := egressFrom("", ""); err != nil || e.CAFile != ca || e.Proxy != "http://env.example:1" {
		t.Errorf("environment: %+v %v", e, err)
	}
	if e, err := egressFrom("", "http://flag.example:2"); err != nil || e.Proxy != "http://flag.example:2" {
		t.Errorf("flag first: %+v %v", e, err)
	}
	t.Setenv(caFileEnv, "")
	t.Setenv(proxyEnv, "")
	key := filepath.Join(t.TempDir(), "key.pem")
	os.WriteFile(key, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("x")}), 0o600)
	text := filepath.Join(t.TempDir(), "x.txt")
	os.WriteFile(text, []byte("not a certificate"), 0o600)
	for _, c := range []struct{ ca, proxy, want string }{
		{"", "http://user:secret@p:1", "user name or password"},
		{"", "p:3128", "http:// or https://"},
		{key, "", "only certificates"},
		{text, "", "no PEM certificate"},
		{filepath.Join(t.TempDir(), "missing.pem"), "", "missing.pem"},
		{t.TempDir(), "", "PEM file"},
	} {
		_, err := egressFrom(c.ca, c.proxy)
		if err == nil || !strings.Contains(err.Error(), c.want) || strings.Contains(err.Error(), "secret") {
			t.Errorf("%q %q: %v", c.ca, c.proxy, err)
		}
	}
}

// TestEgressReachesOnlyNetworkContainers runs update and a scan with
// --ca-file and --proxy: the data update and the Go module download get
// them, the scan containers do not.
func TestEgressReachesOnlyNetworkContainers(t *testing.T) {
	ca := caFile(t)
	t.Setenv(caFileEnv, "")
	t.Setenv(proxyEnv, "")
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	var mu sync.Mutex
	var specs []sandbox.Spec
	useExecutor(t, fakeExec(func(s sandbox.Spec) (*sandbox.Result, error) {
		mu.Lock()
		specs = append(specs, s)
		mu.Unlock()
		if s.Entrypoint == "go" {
			if s.Network == "none" { // the presence check: nothing cached yet
				return &sandbox.Result{Status: sandbox.Completed, ExitCode: 1}, nil
			}
			return &sandbox.Result{Status: sandbox.Completed}, nil
		}
		return emptySARIF(s)
	}), nil)
	var out, errb bytes.Buffer
	if code := run([]string{"update", "--ca-file", ca, "--proxy", "http://proxy.example:3128"}, &out, &errb); code != exitOK {
		t.Fatalf("update: exit %d %s %s", code, out.String(), errb.String())
	}
	want := sandbox.Egress{CAFile: ca, Proxy: "http://proxy.example:3128"}
	if len(specs) != 1 || specs[0].Network != "egress" || specs[0].Egress != want {
		t.Fatalf("update specs %+v", specs)
	}

	target := t.TempDir()
	os.WriteFile(filepath.Join(target, "main.go"), []byte("package main\n"), 0o644)
	os.WriteFile(filepath.Join(target, "go.mod"), []byte("module x\nrequire example.com/a v1.0.0\n"), 0o644)
	specs = nil
	out.Reset()
	t.Setenv(caFileEnv, ca)
	t.Setenv(proxyEnv, "http://proxy.example:3128")
	if code := run([]string{"scan", "--yes", "--no-save", "--only", "gosec", "--report-dir", filepath.Join(t.TempDir(), "r"), target}, &out, &errb); code != exitOK {
		t.Fatalf("scan: exit %d %s %s", code, out.String(), errb.String())
	}
	var download, scans int
	for _, s := range specs {
		switch {
		case s.Network == "egress":
			download++
			if s.Egress != want || s.Entrypoint != "go" || s.TargetDir != "" {
				t.Errorf("download spec %+v", s)
			}
		case s.Egress != (sandbox.Egress{}):
			t.Errorf("a container without network got the proxy or CA: %+v", s)
		case s.Entrypoint == "":
			scans++
			if s.ScratchDir == "" || s.DataDir == "" || s.Env["GOPROXY"] != "off" {
				t.Errorf("gosec spec %+v", s)
			}
		}
	}
	if download != 1 || scans != 1 {
		t.Errorf("%d downloads, %d scans: %+v", download, scans, specs)
	}
	if !strings.Contains(out.String(), "Go modules for gosec: 1 module named in your go.mod files") {
		t.Errorf("output: %s", out.String())
	}

	// Only directory scans and update use them.
	if code := run([]string{"scan", "--ca-file", ca, "http://localhost:3000/"}, &out, &errb); code != exitUsage || !strings.Contains(errb.String(), "only apply to directory scans") {
		t.Errorf("URL scan: exit %d %s", code, errb.String())
	}
	errb.Reset()
	if code := run([]string{"update", "--proxy", "http://u:pw@p:1"}, &out, &errb); code != exitUsage || strings.Contains(errb.String(), "pw") {
		t.Errorf("password: exit %d %s", code, errb.String())
	}
}

package main

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/Gobbuwu/SiegeKit/internal/sandbox"
)

// Environment variables that stand in for --ca-file and --proxy when the
// flags are not given (ADR 0066; owner 2026-11-24: SiegeKit has no
// configuration file, so these SiegeKit-only variables keep the setting).
const (
	caFileEnv = "SIEGEKIT_CA_FILE"
	proxyEnv  = "SIEGEKIT_PROXY"
)

// maxCAFile is the largest CA file accepted.
const maxCAFile = 4 << 20

// egressFrom checks --ca-file and --proxy, or their environment variables
// when the flags are empty, for the containers that use the network: data
// updates and the Go module download (ADR 0066). Scan containers never get
// them.
func egressFrom(caFile, proxy string) (sandbox.Egress, error) {
	if caFile == "" {
		caFile = os.Getenv(caFileEnv)
	}
	if proxy == "" {
		proxy = os.Getenv(proxyEnv)
	}
	var e sandbox.Egress
	if proxy != "" {
		if err := sandbox.CheckProxy(proxy); err != nil {
			return e, fmt.Errorf("--proxy (or %s): %w", proxyEnv, err)
		}
		e.Proxy = proxy
	}
	if caFile != "" {
		p, err := checkCAFile(caFile)
		if err != nil {
			return e, fmt.Errorf("--ca-file (or %s): %w", caFileEnv, err)
		}
		e.CAFile = p
	}
	return e, nil
}

// checkCAFile returns the absolute, symlink-free path of a PEM file that
// holds at least one certificate, and only certificates.
func checkCAFile(p string) (string, error) {
	abs, err := filepath.Abs(p)
	if err != nil {
		return "", err
	}
	real, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return "", err
	}
	st, err := os.Stat(real) // #nosec G703 -- the CA file the person named
	if err != nil {
		return "", err
	}
	if !st.Mode().IsRegular() || st.Size() > maxCAFile {
		return "", fmt.Errorf("%s must be a PEM file of at most %d bytes", p, maxCAFile)
	}
	b, err := os.ReadFile(real) // #nosec G304 G703 -- the CA file the person named
	if err != nil {
		return "", err
	}
	n := 0
	for {
		var blk *pem.Block
		blk, b = pem.Decode(b)
		if blk == nil {
			break
		}
		if blk.Type != "CERTIFICATE" {
			return "", fmt.Errorf("%s holds a %q block; only certificates are accepted", p, blk.Type)
		}
		if _, err := x509.ParseCertificate(blk.Bytes); err != nil {
			return "", fmt.Errorf("%s: %w", p, err)
		}
		n++
	}
	if n == 0 {
		return "", errors.New(p + " holds no PEM certificate")
	}
	return real, nil
}

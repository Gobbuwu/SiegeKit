package egress

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"time"

	"github.com/Gobbuwu/SiegeKit/internal/target"
)

// authority is a per-run certificate authority. Its key lives only in
// memory, and its name constraints allow only the target host, so the
// certificate cannot vouch for any other site (ADR 0018 item 4).
type authority struct {
	cert    *x509.Certificate
	key     *ecdsa.PrivateKey
	certPEM []byte
}

const certLifetime = 24 * time.Hour

func serial() (*big.Int, error) {
	return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
}

func newAuthority(t *target.URL) (*authority, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	sn, err := serial()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:                sn,
		Subject:                     pkix.Name{CommonName: "SiegeKit run CA for " + t.Host, Organization: []string{"SiegeKit (one run only)"}},
		NotBefore:                   now.Add(-time.Minute),
		NotAfter:                    now.Add(certLifetime),
		KeyUsage:                    x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid:       true,
		IsCA:                        true,
		MaxPathLenZero:              true,
		PermittedDNSDomainsCritical: true,
	}
	// Constraints only limit names of their own type, so the other type is
	// excluded entirely.
	if t.IP.IsValid() {
		bits := 32
		if t.IP.Is6() {
			bits = 128
		}
		tmpl.PermittedIPRanges = []*net.IPNet{{IP: t.IP.AsSlice(), Mask: net.CIDRMask(bits, bits)}}
		tmpl.ExcludedDNSDomains = []string{""} // an empty constraint matches every name
	} else {
		// The permitted name also covers subdomains, so exclude them.
		tmpl.PermittedDNSDomains = []string{t.Host}
		tmpl.ExcludedDNSDomains = []string{"." + t.Host}
		tmpl.ExcludedIPRanges = []*net.IPNet{
			{IP: net.IPv4zero.To4(), Mask: net.CIDRMask(0, 32)},
			{IP: net.IPv6zero, Mask: net.CIDRMask(0, 128)},
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &authority{cert: cert, key: key, certPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}, nil
}

// leaf issues the certificate the proxy shows to the tool for the target.
func (a *authority) leaf(t *target.URL) (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	sn, err := serial()
	if err != nil {
		return tls.Certificate{}, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: sn,
		Subject:      pkix.Name{CommonName: t.Host},
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(certLifetime),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if t.IP.IsValid() {
		tmpl.IPAddresses = []net.IP{t.IP.AsSlice()}
	} else {
		tmpl.DNSNames = []string{t.Host}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, a.cert, &key.PublicKey, a.key)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der, a.cert.Raw}, PrivateKey: key}, nil
}

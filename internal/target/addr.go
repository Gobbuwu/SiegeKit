// Package target parses URL targets and decides, from the addresses a host
// resolves to, whether SiegeKit may test it (ADR 0005). It sends no traffic.
package target

import (
	"net/netip"
)

// Class is what an address is, for authorization.
type Class int

const (
	// Public addresses can only be tested in deployed mode, after proof of
	// control.
	Public Class = iota
	// Loopback addresses are always allowed in local mode.
	Loopback
	// Private addresses are allowed in local mode after a typed confirmation.
	Private
	// Blocked addresses are never allowed.
	Blocked
)

func (c Class) String() string {
	return [...]string{"public", "loopback", "private", "always blocked"}[c]
}

func prefixes(ss ...string) []netip.Prefix {
	out := make([]netip.Prefix, len(ss))
	for i, s := range ss {
		out[i] = netip.MustParsePrefix(s)
	}
	return out
}

var (
	// ADR 0005 "Always blocked": link-local (including cloud metadata),
	// unspecified, broadcast and multicast.
	blocked = prefixes(
		"169.254.0.0/16", "fe80::/10",
		"0.0.0.0/8", "255.255.255.255/32", "::/128",
		"224.0.0.0/4", "ff00::/8",
	)
	loopback = prefixes("127.0.0.0/8", "::1/128")
	// ADR 0005 private ranges, plus ranges that are internal in practice and
	// must not count as public: shared address space used by carrier NAT and
	// VPN overlays (100.64.0.0/10), benchmarking (198.18.0.0/15), the IETF
	// protocol block (192.0.0.0/24) and the reserved 240.0.0.0/4.
	private = prefixes(
		"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7",
		"100.64.0.0/10", "198.18.0.0/15", "192.0.0.0/24", "240.0.0.0/4",
	)
	// IPv6 forms that carry an IPv4 address: NAT64 (64:ff9b::/96 and the
	// local-use 64:ff9b:1::/48), 6to4 (2002::/16) and the deprecated
	// IPv4-compatible form (::/96). The IPv4 address inside is classified.
	nat64      = netip.MustParsePrefix("64:ff9b::/96")
	nat64Local = netip.MustParsePrefix("64:ff9b:1::/48")
	sixToFour  = netip.MustParsePrefix("2002::/16")
	v4Compat   = netip.MustParsePrefix("::/96")
)

// Classify returns the class of a. Addresses that embed an IPv4 address are
// classified by that address; an address with a zone (fe80::1%eth0) is
// blocked.
func Classify(a netip.Addr) Class {
	if !a.IsValid() || a.Zone() != "" {
		return Blocked
	}
	a = a.Unmap() // ::ffff:a.b.c.d
	if a.Is6() {
		b := a.As16()
		switch {
		case nat64.Contains(a) || v4Compat.Contains(a) && a != netip.IPv6Unspecified() && a != netip.IPv6Loopback():
			return worst(Public, Classify(netip.AddrFrom4([4]byte{b[12], b[13], b[14], b[15]})))
		case nat64Local.Contains(a):
			// The IPv4 address may sit anywhere in the suffix; treat it as
			// internal.
			return Private
		case sixToFour.Contains(a):
			return worst(Public, Classify(netip.AddrFrom4([4]byte{b[2], b[3], b[4], b[5]})))
		}
	}
	for _, p := range blocked {
		if p.Contains(a) {
			return Blocked
		}
	}
	for _, p := range loopback {
		if p.Contains(a) {
			return Loopback
		}
	}
	for _, p := range private {
		if p.Contains(a) {
			return Private
		}
	}
	return Public
}

// worst returns the more restricted class. For an IPv6 address that wraps a
// loopback IPv4 address, the wrapper is not the same machine, so loopback
// counts as private.
func worst(a, b Class) Class {
	if b == Loopback {
		b = Private
	}
	if b > a {
		return b
	}
	return a
}

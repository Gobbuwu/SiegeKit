package target

import (
	"fmt"
	"net/netip"
	"strings"
)

// Mode is how a target is tested (ADR 0005).
type Mode string

const (
	Local    Mode = "local"
	Deployed Mode = "deployed"
)

// Decision says whether a run may go ahead and what it still needs.
type Decision struct {
	Allowed bool
	// NeedsConfirmation is set when the user must type the host name to
	// confirm they are authorized (private addresses in local mode, every
	// deployed-mode target).
	NeedsConfirmation bool
	// NeedsProof is set in deployed mode: proof of control (M2.2).
	NeedsProof bool
	Reason     string // why the run is refused, or what it needs
	Addrs      []netip.Addr
}

// Authorize applies the ADR 0005 rules to the addresses the target resolved
// to. Every address must be allowed: a name that resolves to both a public
// and a private address is refused in both modes.
func Authorize(mode Mode, addrs []netip.Addr) Decision {
	d := Decision{Addrs: addrs}
	if len(addrs) == 0 {
		d.Reason = "the target has no addresses"
		return d
	}
	byClass := map[Class][]string{}
	for _, a := range addrs {
		c := Classify(a)
		byClass[c] = append(byClass[c], a.String())
	}
	list := func(c Class) string { return strings.Join(byClass[c], ", ") }
	if len(byClass[Blocked]) > 0 {
		d.Reason = fmt.Sprintf("%s is in a range SiegeKit never tests (link-local, cloud metadata, broadcast, multicast or unspecified)", list(Blocked))
		return d
	}
	switch mode {
	case Local:
		if len(byClass[Public]) > 0 {
			d.Reason = fmt.Sprintf("%s is a public address; test deployed systems with --deployed, which asks for proof that you control them", list(Public))
			return d
		}
		d.Allowed = true
		if len(byClass[Private]) > 0 {
			d.NeedsConfirmation = true
			d.Reason = fmt.Sprintf("%s is a private network address and may belong to someone else on your network", list(Private))
		}
	case Deployed:
		if n := len(byClass[Loopback]) + len(byClass[Private]); n > 0 {
			d.Reason = fmt.Sprintf("%s is not a public address; deployed mode only tests public systems (use local mode for this machine and your own network)", strings.Join(append(byClass[Loopback], byClass[Private]...), ", "))
			return d
		}
		d.Allowed, d.NeedsConfirmation, d.NeedsProof = true, true, true
		d.Reason = "deployed systems need proof of control and a typed confirmation"
	default:
		d.Reason = fmt.Sprintf("unknown mode %q", mode)
	}
	return d
}

// Confirmed reports whether typed matches the target host exactly (after
// trimming surrounding space). Case and a trailing dot are ignored for names.
func Confirmed(t *URL, typed string) bool {
	typed = strings.TrimSpace(typed)
	if t.IP.IsValid() {
		a, err := netip.ParseAddr(strings.Trim(typed, "[]"))
		return err == nil && a == t.IP
	}
	return strings.TrimSuffix(strings.ToLower(typed), ".") == t.Host
}

package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/Gobbuwu/SiegeKit/internal/target"
	"github.com/Gobbuwu/SiegeKit/internal/verify"
)

// resolver looks up target host names; tests replace it.
var resolver target.Resolver

// prover checks deployed-mode proof of control; tests replace it.
var prover interface {
	Check(ctx context.Context, u *target.URL, addrs []netip.Addr, token string) (string, error)
} = &verify.Checker{}

func isURL(s string) bool {
	l := strings.ToLower(s)
	return strings.HasPrefix(l, "http://") || strings.HasPrefix(l, "https://")
}

// scanURL applies the target rules of ADR 0005. Deployed mode checks proof
// of control (a GET of the well-known file from the pinned addresses, or a
// DNS TXT lookup) before asking for confirmation. No active plugin exists
// yet, so an allowed target ends with that message; no test traffic is sent.
func scanURL(raw string, deployed bool, authorizedHost string, stdout, stderr io.Writer) int {
	refuse := func(format string, a ...any) int {
		fmt.Fprintf(stderr, "siegekit scan: refused: "+format+"\n", a...)
		return exitInvalid
	}
	u, err := target.Parse(raw)
	if err != nil {
		return refuse("%v", err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	rctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	addrs, err := target.Resolve(rctx, resolver, u)
	if err != nil {
		return refuse("%v", err)
	}
	mode := target.Local
	if deployed {
		mode = target.Deployed
	}
	d := target.Authorize(mode, addrs)
	fmt.Fprintf(stdout, "Target %s resolves to %s (%s mode).\n", u, joinAddrs(d), mode)
	if !d.Allowed {
		return refuse("%s", d.Reason)
	}
	verification := "loopback"
	proof := ""
	if d.NeedsProof {
		dir, err := dataDir()
		if err != nil {
			return refuse("%v", err)
		}
		token, err := verify.Token(filepath.Join(dir, "verify"), u.Host)
		if err != nil {
			return refuse("%v", err)
		}
		method, err := prover.Check(ctx, u, d.Addrs, token)
		if err != nil {
			fmt.Fprintf(stdout, "\n%s\n\n", verify.Instructions(u, token))
			return refuse("%v", err)
		}
		fmt.Fprintf(stdout, "Proof of control found: %s.\n", method)
		fmt.Fprint(stdout, "Before testing a deployed system, check your hosting provider's penetration-testing policy (some require notice or forbid some tests), and prefer a staging copy over production.\n")
		proof = method + " + "
	}
	if d.NeedsConfirmation {
		fmt.Fprintf(stdout, "%s. Only continue if you are authorized to test it.\n", d.Reason)
		verification = "typed confirmation"
		switch {
		case authorizedHost != "":
			if !target.Confirmed(u, authorizedHost) {
				return refuse("--authorized-host %q does not match the target host %q", authorizedHost, u.Host)
			}
			verification = "--authorized-host"
		case stdinIsTerminal():
			fmt.Fprintf(stdout, "Type the host name (%s) to confirm: ", u.Host)
			line, _ := bufio.NewReader(stdin).ReadString('\n')
			if !target.Confirmed(u, line) {
				return refuse("the typed host name did not match %q", u.Host)
			}
		default:
			return refuse("confirmation needed and there is no terminal to ask in; pass --authorized-host %s", u.Host)
		}
	} else if authorizedHost != "" && !target.Confirmed(u, authorizedHost) {
		return refuse("--authorized-host %q does not match the target host %q", authorizedHost, u.Host)
	}
	verification = proof + verification
	fmt.Fprintf(stdout, "Target allowed (%s). No active web test is available yet: they arrive in M2.4, after the egress proxy. No test traffic was sent to the target.\n", verification)
	return exitOK
}

func joinAddrs(d target.Decision) string {
	s := make([]string, len(d.Addrs))
	for i, a := range d.Addrs {
		s[i] = a.String()
	}
	return strings.Join(s, ", ")
}

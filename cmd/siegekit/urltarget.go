package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/Gobbuwu/SiegeKit/internal/target"
)

// resolver looks up target host names; tests replace it.
var resolver target.Resolver

func isURL(s string) bool {
	l := strings.ToLower(s)
	return strings.HasPrefix(l, "http://") || strings.HasPrefix(l, "https://")
}

// scanURL applies the target rules of ADR 0005. In M2.1 no active plugin
// exists yet, so an allowed target ends with that message; nothing is sent
// to the target.
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
	if d.NeedsProof {
		return refuse("deployed mode needs proof of control, which arrives in the next release step (M2.2)")
	}
	verification := "loopback"
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
	fmt.Fprintf(stdout, "Target allowed (%s). No active web test is available yet: they arrive in M2.4, after the egress proxy. Nothing was sent to the target.\n", verification)
	return exitOK
}

func joinAddrs(d target.Decision) string {
	s := make([]string, len(d.Addrs))
	for i, a := range d.Addrs {
		s[i] = a.String()
	}
	return strings.Join(s, ", ")
}

// Package relay is the forwarder that runs inside the relay container of an
// active test (ADR 0019, ADR 0021): it accepts TCP connections on loopback in
// the container's network namespace, which the tool container shares, and
// forwards each one to the egress proxy's Unix socket on the host. It is
// part of SiegeKit's own binary, so no third-party image is needed.
package relay

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
)

// Command is the hidden subcommand that runs the relay. It is not listed in
// the help, because only SiegeKit starts it, inside the relay container.
const Command = "internal-relay"

// MaxConns limits the tool's open connections; a connection beyond it is
// closed at once. Tools keep idle keep-alive connections open: Nuclei had up
// to 299 open in one local scan, and the earlier limit of 64 lost requests
// (ADR 0026). The proxy limits connections to the target separately.
const MaxConns = 1024

// Serve accepts connections on l and forwards each to the Unix socket at
// socket until ctx ends or l is closed.
func Serve(ctx context.Context, l net.Listener, socket string) error {
	var wg sync.WaitGroup
	defer wg.Wait()
	slots := make(chan struct{}, MaxConns)
	stop := context.AfterFunc(ctx, func() { _ = l.Close() })
	defer stop()
	for {
		c, err := l.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		select {
		case slots <- struct{}{}:
		default:
			_ = c.Close() // too many connections
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-slots }()
			forward(ctx, c, socket)
		}()
	}
}

func forward(ctx context.Context, c net.Conn, socket string) {
	defer c.Close()
	var d net.Dialer
	up, err := d.DialContext(ctx, "unix", socket)
	if err != nil {
		return
	}
	defer up.Close()
	done := make(chan struct{}, 2)
	pipe := func(dst, src net.Conn) {
		_, _ = io.Copy(dst, src)
		// Pass the end of one direction on, so the other side sees EOF.
		if cw, ok := dst.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
		done <- struct{}{}
	}
	go pipe(up, c)
	go pipe(c, up)
	select {
	case <-done:
		<-done
	case <-ctx.Done():
	}
}

// Main runs the relay: args are the listen address (loopback only) and the
// socket path. It prints "listening on ADDR" once it accepts connections,
// which SiegeKit waits for.
func Main(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) != 2 {
		fmt.Fprintln(stderr, "usage: siegekit "+Command+" 127.0.0.1:PORT SOCKET")
		return 2
	}
	host, _, err := net.SplitHostPort(args[0])
	if err != nil || host != "127.0.0.1" {
		fmt.Fprintln(stderr, "relay: the listen address must be 127.0.0.1:PORT")
		return 2
	}
	l, err := net.Listen("tcp", args[0])
	if err != nil {
		fmt.Fprintln(stderr, "relay:", err)
		return 1
	}
	fmt.Fprintln(stdout, "listening on", l.Addr())
	if err := Serve(ctx, l, args[1]); err != nil {
		fmt.Fprintln(stderr, "relay:", err)
		return 1
	}
	return 0
}

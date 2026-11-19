package runner

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"

	"github.com/Gobbuwu/SiegeKit/internal/egress"
	"github.com/Gobbuwu/SiegeKit/internal/sandbox"
)

// ActiveResult is the outcome of one run behind the egress proxy.
type ActiveResult struct {
	*sandbox.Result
	Stats egress.Stats
	// Stopped is why the proxy stopped the run, or "" (ADR 0005 item 3).
	Stopped string
}

// RunTargetOnly runs s with no network except the egress proxy for cfg's
// target (ADR 0018, ADR 0019). parent is a private directory for the
// proxy's socket; it must be short enough for a Unix socket path. relayBin
// is a static SiegeKit binary that runs the relay (ADR 0021), normally the
// running one (os.Executable).
func RunTargetOnly(ctx context.Context, e *sandbox.Engine, s sandbox.Spec, cfg egress.Config, parent, relayBin string) (*ActiveResult, error) {
	dir, err := os.MkdirTemp(parent, "egress-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)
	// The relay container's user must reach the socket; nothing else in dir
	// is secret (the CA key never leaves this process).
	if err := os.Chmod(dir, 0o711); err != nil { // #nosec G302 -- traverse only, for the relay's user
		return nil, err
	}
	sock := filepath.Join(dir, sandbox.RelaySocket)
	if len(sock) > 100 {
		return nil, fmt.Errorf("socket path %s is too long", sock)
	}
	l, err := net.Listen("unix", sock)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(sock, 0o666); err != nil { // #nosec G302 -- the relay runs as another user; the directory admits no listing
		_ = l.Close()
		return nil, err
	}
	p, err := egress.New(cfg)
	if err != nil {
		_ = l.Close()
		return nil, err
	}
	served := make(chan struct{})
	go func() {
		defer close(served)
		_ = p.Serve(l)
	}()
	defer func() {
		_ = p.Close()
		<-served
	}()
	s.Network, s.CAFile = "target-only", ""
	if pem := p.CACertPEM(); pem != nil {
		s.CAFile = filepath.Join(dir, "ca.pem")
		if err := os.WriteFile(s.CAFile, pem, 0o644); err != nil { // #nosec G306 -- a public certificate the tool must read
			return nil, err
		}
	}
	relay, err := e.StartRelay(ctx, dir, relayBin)
	if err != nil {
		return nil, err
	}
	defer e.StopRelay(relay)
	s.Relay = relay

	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		select {
		case <-p.Stopped():
			cancel()
		case <-runCtx.Done():
		}
	}()
	res, err := e.Run(runCtx, s)
	out := &ActiveResult{Result: res, Stats: p.Stats(), Stopped: p.StopReason()}
	if out.Stopped != "" && errors.Is(err, context.Canceled) && ctx.Err() == nil {
		// The proxy stopped the run: report it as a result, not an error.
		out.Result = &sandbox.Result{Status: sandbox.Failed, ExitCode: -1}
		return out, nil
	}
	if err != nil {
		return nil, err
	}
	return out, nil
}

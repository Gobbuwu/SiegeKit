package relay

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// echoSocket serves a Unix socket that answers each line with "echo: " and
// the line, standing in for the egress proxy.
func echoSocket(t *testing.T) string {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "p.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				sc := bufio.NewScanner(c)
				for sc.Scan() {
					if _, err := io.WriteString(c, "echo: "+sc.Text()+"\n"); err != nil {
						return
					}
				}
			}()
		}
	}()
	return sock
}

func TestServeForwards(t *testing.T) {
	sock := echoSocket(t)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Serve(ctx, l, sock) }()

	for i := 0; i < 3; i++ { // several connections, one after another
		c, err := net.Dial("tcp", l.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
		if _, err := io.WriteString(c, "hello\n"); err != nil {
			t.Fatal(err)
		}
		line, err := bufio.NewReader(c).ReadString('\n')
		if err != nil || line != "echo: hello\n" {
			t.Fatalf("got %q, %v", line, err)
		}
		c.Close()
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Serve after cancel: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not stop")
	}
}

func TestServeNoUpstream(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go Serve(ctx, l, filepath.Join(t.TempDir(), "missing.sock"))
	c, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	if n, err := c.Read(make([]byte, 1)); n != 0 || err == nil {
		t.Errorf("connection not closed when the socket is missing: %d %v", n, err)
	}
}

func TestMainArgs(t *testing.T) {
	for _, args := range [][]string{nil, {"0.0.0.0:8080", "/s"}, {"10.0.0.1:8080", "/s"}, {"x", "/s"}, {"127.0.0.1:1", "/s", "extra"}} {
		var out, errb bytes.Buffer
		if code := Main(context.Background(), args, &out, &errb); code != 2 {
			t.Errorf("Main(%q) = %d, want 2 (%s)", args, code, errb.String())
		}
	}
	// A valid call prints the readiness line and stops with the context.
	ctx, cancel := context.WithCancel(context.Background())
	pr, pw := io.Pipe()
	var errb bytes.Buffer
	done := make(chan int, 1)
	go func() {
		done <- Main(ctx, []string{"127.0.0.1:0", "/nonexistent.sock"}, pw, &errb)
		pw.Close()
	}()
	line, err := bufio.NewReader(pr).ReadString('\n')
	cancel()
	go io.Copy(io.Discard, pr)
	if code := <-done; code != 0 || err != nil || !strings.HasPrefix(line, "listening on 127.0.0.1:") {
		t.Errorf("Main exit %d, first line %q (%v), stderr %q", code, line, err, errb.String())
	}
}

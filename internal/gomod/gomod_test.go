package gomod

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Gobbuwu/SiegeKit/internal/sandbox"
)

func put(t *testing.T, root, rel, body string) {
	t.Helper()
	p := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

const rootMod = `module example.com/app // the app

go 1.27

require example.com/a v1.0.0

require (
	example.com/b v1.2.0 // indirect
	"example.com/c" v0.1.0
	// example.com/commented v1.0.0
)

replace example.com/d => ./d
exclude example.com/e v1.0.0
`

func TestRequires(t *testing.T) {
	got := Requires([]byte(rootMod))
	want := []string{"example.com/a", "example.com/b", "example.com/c"}
	if !slices.Equal(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestFind(t *testing.T) {
	root := t.TempDir()
	put(t, root, "go.mod", rootMod)
	put(t, root, "go.sum", "example.com/a v1.0.0 h1:x\n")
	put(t, root, "go.work", "go 1.27\nuse (\n\t.\n\t./tools\n)\n")
	put(t, root, "tools/go.mod", "module example.com/tools\nrequire example.com/a v1.1.0\nrequire example.com/z v1.0.0\n")
	put(t, root, "vendor/example.com/a/go.mod", "module example.com/a\nrequire example.com/v v1.0.0\n")
	put(t, root, ".git/go.mod", "module x\nrequire example.com/g v1.0.0\n")
	put(t, root, "main.go", "package main\n")
	// A symlinked go.mod is not read: it could point outside the target.
	if err := os.MkdirAll(filepath.Join(root, "linked"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/etc/hostname", filepath.Join(root, "linked", "go.mod")); err != nil {
		t.Fatal(err)
	}
	tr, err := Find(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(tr.Dirs, []string{".", "tools"}) {
		t.Errorf("dirs %v", tr.Dirs)
	}
	if tr.Required != 4 { // a, b, c, z
		t.Errorf("required %d", tr.Required)
	}
	got := slices.Sorted(func(yield func(string) bool) {
		for k := range tr.files {
			if !yield(k) {
				return
			}
		}
	})
	if !slices.Equal(got, []string{"go.mod", "go.sum", "go.work", "tools/go.mod"}) {
		t.Errorf("files %v", got)
	}
	empty, err := Find(context.Background(), t.TempDir())
	if err != nil || len(empty.Dirs) != 0 {
		t.Errorf("empty tree: %+v %v", empty, err)
	}
}

func TestFindLimits(t *testing.T) {
	root := t.TempDir()
	put(t, root, "go.sum", strings.Repeat("x", MaxFileSize+1))
	if _, err := Find(context.Background(), root); err == nil {
		t.Error("a file over the size limit must be refused")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Find(ctx, t.TempDir()); !errors.Is(err, context.Canceled) {
		t.Errorf("cancelled: %v", err)
	}
}

func TestStage(t *testing.T) {
	root := t.TempDir()
	put(t, root, "go.mod", rootMod)
	put(t, root, "a/b/go.mod", "module x\n")
	tr, err := Find(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	dst := t.TempDir()
	if err := tr.Stage(dst); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(dst, "a", "b", "go.mod"))
	if err != nil || string(b) != "module x\n" {
		t.Fatalf("%q %v", b, err)
	}
	for p, want := range map[string]os.FileMode{"a": 0o755, "a/b": 0o755, "a/b/go.mod": 0o644, "go.mod": 0o644} {
		st, err := os.Stat(filepath.Join(dst, p))
		if err != nil || st.Mode().Perm() != want {
			t.Errorf("%s: %v %v", p, st.Mode().Perm(), err)
		}
	}
}

// exec records specs and answers with exit codes in order.
type exec struct {
	specs []sandbox.Spec
	codes []int
	err   error
}

func (e *exec) Run(_ context.Context, s sandbox.Spec) (*sandbox.Result, error) {
	// The module files are staged before each run.
	if _, err := os.Stat(filepath.Join(s.InputDir, "go.mod")); err != nil {
		return nil, err
	}
	e.specs = append(e.specs, s)
	if e.err != nil {
		return nil, e.err
	}
	code := 0
	if len(e.codes) > 0 {
		code, e.codes = e.codes[0], e.codes[1:]
	}
	return &sandbox.Result{Status: sandbox.Completed, ExitCode: code, Stderr: "go: example.com/a@v1.0.0: reading https://proxy.golang.org/...: 404 Not Found\n"}, nil
}

func tree(t *testing.T) *Tree {
	root := t.TempDir()
	put(t, root, "go.mod", rootMod)
	put(t, root, "tools/go.mod", "module example.com/tools\n")
	tr, err := Find(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	return tr
}

func job(t *testing.T) Job {
	return Job{Image: "ghcr.io/x/gosec@sha256:" + strings.Repeat("a", 64), CPUs: 2, MemoryMiB: 2048, Timeout: time.Minute, DataRoot: t.TempDir(),
		Egress: sandbox.Egress{Proxy: "http://proxy.example:3128"}, Private: map[string]string{"GOPRIVATE": "corp.example/*"}}
}

func TestDownload(t *testing.T) {
	tr, j, e := tree(t), job(t), &exec{}
	if err := Download(context.Background(), e, tr, j); err != nil {
		t.Fatal(err)
	}
	if len(e.specs) != 2 {
		t.Fatalf("%d runs", len(e.specs))
	}
	for i, s := range e.specs {
		wantArgs := []string{"-C", []string{"/siegekit/input", "/siegekit/input/tools"}[i], "mod", "download"}
		if !slices.Equal(s.Args, wantArgs) || s.Entrypoint != "go" || s.Image != j.Image {
			t.Errorf("run %d: %s %v", i, s.Entrypoint, s.Args)
		}
		if s.Network != "egress" || !s.DataWritable || s.DataDir != CacheDir(j.DataRoot) || s.DataMount != CacheMount || s.TargetDir != "" || s.Egress != j.Egress {
			t.Errorf("run %d: %+v", i, s)
		}
		want := map[string]string{"GOMODCACHE": CacheMount, "GOPATH": "/tmp/go", "GOTOOLCHAIN": "local", "GOPROXY": sandbox.GoProxy,
			"GOFLAGS": "-mod=mod", "GOVCS": "*:off", "GOPRIVATE": "corp.example/*"}
		for k, v := range want {
			if s.Env[k] != v {
				t.Errorf("run %d: %s=%q, want %q", i, k, s.Env[k], v)
			}
		}
		if len(s.Env) != len(want) {
			t.Errorf("run %d env %v", i, s.Env)
		}
		if err := sandbox.CheckEnv(s.Env); err != nil {
			t.Error(err)
		}
	}
	if st, err := os.Stat(CacheDir(j.DataRoot)); err != nil || !st.IsDir() {
		t.Errorf("cache folder: %v", err)
	}

	// A failed folder is named; the others are still downloaded.
	e = &exec{codes: []int{1, 0}}
	err := Download(context.Background(), e, tr, j)
	if len(e.specs) != 2 || err == nil || !strings.Contains(err.Error(), "1 of 2 module folders: . (go: example.com/a@v1.0.0") {
		t.Errorf("%d runs, %v", len(e.specs), err)
	}
	// An engine error stops the download.
	e = &exec{err: errors.New("engine gone")}
	if err := Download(context.Background(), e, tr, j); err == nil || len(e.specs) != 1 {
		t.Errorf("engine error: %v", err)
	}
}

func TestPresent(t *testing.T) {
	tr, j := tree(t), job(t)
	e := &exec{}
	// No cache yet: nothing to check, nothing run.
	if ok, err := Present(context.Background(), e, tr, j); ok || err != nil || len(e.specs) != 0 {
		t.Fatalf("no cache: %v %v %d", ok, err, len(e.specs))
	}
	if err := os.MkdirAll(CacheDir(j.DataRoot), 0o755); err != nil {
		t.Fatal(err)
	}
	if ok, err := Present(context.Background(), e, tr, j); !ok || err != nil || len(e.specs) != 2 {
		t.Fatalf("complete: %v %v %d", ok, err, len(e.specs))
	}
	s := e.specs[0]
	if s.Network != "none" || s.DataWritable || s.Egress != (sandbox.Egress{}) || s.Env["GOPROXY"] != "off" || s.DataDir != CacheDir(j.DataRoot) {
		t.Errorf("check spec %+v", s)
	}
	// The first incomplete folder ends the check.
	e = &exec{codes: []int{1}}
	if ok, err := Present(context.Background(), e, tr, j); ok || err != nil || len(e.specs) != 1 {
		t.Errorf("incomplete: %v %v %d", ok, err, len(e.specs))
	}
	e = &exec{err: errors.New("engine gone")}
	if _, err := Present(context.Background(), e, tr, j); err == nil {
		t.Error("engine error must be returned")
	}
}

func TestPrivateEnv(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "env")
	put(t, dir, "env", "# comment\nGOPRIVATE=file.example/*\nGONOPROXY = nop.example\nGOFLAGS=-x\n")
	env := map[string]string{"GOENV": file}
	get := func(k string) string { return env[k] }
	if got := PrivateEnv(get); got["GOPRIVATE"] != "file.example/*" || got["GONOPROXY"] != "nop.example" || len(got) != 2 {
		t.Errorf("from file: %v", got)
	}
	env["GOPRIVATE"] = "env.example"
	if got := PrivateEnv(get); got["GOPRIVATE"] != "env.example" || got["GONOPROXY"] != "nop.example" {
		t.Errorf("environment first: %v", got)
	}
	env = map[string]string{"GOENV": "off"}
	if got := PrivateEnv(get); len(got) != 0 {
		t.Errorf("GOENV=off: %v", got)
	}
}

func TestLastLine(t *testing.T) {
	if got := LastLine("a\nb \x1b[31mred\n\n"); got != "b [31mred" {
		t.Errorf("%q", got)
	}
	if got := LastLine(""); got != "no error output" {
		t.Errorf("%q", got)
	}
	if got := []rune(LastLine(strings.Repeat("é", 400))); len(got) != 301 {
		t.Errorf("%d runes", len(got))
	}
}

func TestLockWaits(t *testing.T) {
	p := filepath.Join(t.TempDir(), "x.lock")
	unlock, err := lock(p)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		u, err := lock(p)
		if err == nil {
			u()
		}
		close(done)
	}()
	select {
	case <-done:
		t.Fatal("second lock did not wait")
	case <-time.After(100 * time.Millisecond):
	}
	unlock()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("second lock never got the lock")
	}
}

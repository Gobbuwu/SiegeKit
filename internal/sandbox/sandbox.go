// Package sandbox runs one plugin's tool inside a locked-down container
// (ADR 0006). It builds the container engine's command line directly; no shell
// is involved at any point (threat model T1).
package sandbox

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Paths inside the container.
const (
	TargetMount = "/target"
	OutMount    = "/out"
	WorkDir     = "/tmp/work"
)

// DefaultOutputLimit caps what a tool may write to its output directory
// (threat model T6).
const DefaultOutputLimit = 512 << 20

// Fallback identity used when SiegeKit itself runs as root, so tools never
// run as root inside the container.
const nonRootUID, nonRootGID = 65532, 65532

var reDataMount = regexp.MustCompile(`^/(tmp|data)(/[a-z0-9_-][a-z0-9._-]*)+$`)

var reImage = regexp.MustCompile(`^[a-z0-9.-]+(:[0-9]+)?/[^@\s]+@sha256:[a-f0-9]{64}$`)

// Spec describes one sandboxed run.
type Spec struct {
	Image     string   // must be pinned by digest
	Args      []string // arguments for the image's entrypoint, placeholders already substituted
	TargetDir string   // mounted read-only at /target; empty for none
	OutDir    string   // mounted read-write at /out; must exist and be empty
	// Network is "none" for scans. "egress" (the engine's default network) is
	// only for data updates (ADR 0014) and is refused when a target is mounted.
	// "target-only" arrives with the egress proxy in M2.
	Network      string
	DataDir      string // host directory with the tool's data; empty for none
	DataMount    string // where DataDir is mounted; read-only unless DataWritable
	DataWritable bool   // only for update runs
	CPUs         int
	MemoryMiB    int
	PidsLimit    int // 0 means 256
	Timeout      time.Duration
	OutputLimit  int64 // bytes; 0 means DefaultOutputLimit
}

// Status of a finished run.
type Status string

// Run outcomes.
const (
	Completed Status = "completed"
	TimedOut  Status = "timed-out"
	Failed    Status = "failed"
)

// Result of a sandboxed run.
type Result struct {
	Status   Status
	ExitCode int
	Stderr   string // last 64 KiB
	Duration time.Duration
}

// Engine is a container engine CLI (Docker or Podman).
type Engine struct {
	Bin string // absolute path to docker or podman
}

// Detect finds docker or podman on PATH, preferring Podman (rootless by default).
func Detect() (*Engine, error) {
	for _, name := range []string{"podman", "docker"} {
		if p, err := exec.LookPath(name); err == nil {
			return &Engine{Bin: p}, nil
		}
	}
	return nil, errors.New("no container engine found: install Docker or Podman (see README)")
}

// validate rejects specs that would weaken the sandbox.
func (s *Spec) validate() error {
	if !reImage.MatchString(s.Image) {
		return fmt.Errorf("image %q is not pinned by @sha256 digest", s.Image)
	}
	if len(s.Args) == 0 {
		return errors.New("no arguments")
	}
	switch s.Network {
	case "none":
	case "egress":
		if s.TargetDir != "" || !s.DataWritable {
			return errors.New("network \"egress\" is only allowed for data updates, with no target mounted")
		}
	default:
		return fmt.Errorf("network %q is not supported", s.Network)
	}
	if s.DataWritable && s.TargetDir != "" {
		return errors.New("data can only be writable when no target is mounted")
	}
	if (s.DataDir == "") != (s.DataMount == "") {
		return errors.New("data directory and data mount must be set together")
	}
	if s.DataMount != "" {
		if !reDataMount.MatchString(s.DataMount) || s.DataMount == WorkDir || strings.HasPrefix(s.DataMount, WorkDir+"/") {
			return fmt.Errorf("data mount %q must be a path under /tmp or /data", s.DataMount)
		}
	}
	if s.CPUs < 1 || s.MemoryMiB < 64 || s.Timeout <= 0 {
		return errors.New("cpus, memory and timeout must be set")
	}
	for _, d := range []struct {
		name, path string
		required   bool
	}{{"target", s.TargetDir, false}, {"output", s.OutDir, true}, {"data", s.DataDir, false}} {
		if d.path == "" {
			if d.required {
				return fmt.Errorf("%s directory is required", d.name)
			}
			continue
		}
		if err := checkMountPath(d.path); err != nil {
			return fmt.Errorf("%s directory: %w", d.name, err)
		}
	}
	entries, err := os.ReadDir(s.OutDir)
	if err != nil {
		return fmt.Errorf("output directory: %w", err)
	}
	if len(entries) > 0 {
		return errors.New("output directory must be empty")
	}
	return nil
}

// checkMountPath accepts only absolute, clean directory paths without
// characters that the engine's --mount option parser treats specially, so a
// path can never inject extra mount options (for example ",readonly=false").
func checkMountPath(p string) error {
	if !filepath.IsAbs(p) || filepath.Clean(p) != p {
		return fmt.Errorf("%q must be an absolute, clean path", p)
	}
	if strings.ContainsAny(p, ",\"'\n\r\x00") {
		return fmt.Errorf("%q contains a character that is not allowed in a mount path", p)
	}
	st, err := os.Stat(p)
	if err != nil {
		return err
	}
	if !st.IsDir() {
		return fmt.Errorf("%q is not a directory", p)
	}
	return nil
}

// EngineArgs returns the engine command line for s, after validation. It is
// exported so tests and a future --dry-run can show exactly what will run.
// Args are passed to the image's own entrypoint.
func (s *Spec) EngineArgs(name string, uid, gid int) ([]string, error) {
	if err := s.validate(); err != nil {
		return nil, err
	}
	if uid == 0 {
		uid, gid = nonRootUID, nonRootGID
	}
	pids := s.PidsLimit
	if pids == 0 {
		pids = 256
	}
	args := []string{
		"run", "--rm",
		"--name", name,
		"--pull", "missing",
	}
	// "egress" uses the engine's default network, so no flag is passed.
	if s.Network == "none" {
		args = append(args, "--network", "none")
	}
	args = append(args,
		"--user", fmt.Sprintf("%d:%d", uid, gid),
		"--cap-drop", "ALL",
		"--security-opt", "no-new-privileges",
		"--read-only",
		"--tmpfs", "/tmp:rw,nosuid,nodev,size=256m",
		"--pids-limit", strconv.Itoa(pids),
		"--memory", fmt.Sprintf("%dm", s.MemoryMiB),
		"--memory-swap", fmt.Sprintf("%dm", s.MemoryMiB),
		"--cpus", strconv.Itoa(s.CPUs),
		"--env", "HOME=/tmp",
		"--workdir", "/tmp",
		"--mount", "type=bind,source="+s.OutDir+",target="+OutMount,
	)
	if s.TargetDir != "" {
		args = append(args, "--mount", "type=bind,source="+s.TargetDir+",target="+TargetMount+",readonly")
	}
	if s.DataDir != "" {
		m := "type=bind,source=" + s.DataDir + ",target=" + s.DataMount
		if !s.DataWritable {
			m += ",readonly"
		}
		args = append(args, "--mount", m)
	}
	args = append(args, s.Image)
	args = append(args, s.Args...)
	return args, nil
}

// Run executes the spec and waits for it, killing the container on timeout.
func (e *Engine) Run(ctx context.Context, s Spec) (*Result, error) {
	name, err := containerName()
	if err != nil {
		return nil, err
	}
	uid, gid := os.Getuid(), os.Getgid()
	args, err := s.EngineArgs(name, uid, gid)
	if err != nil {
		return nil, err
	}
	// The container user may not map to the caller's UID (SiegeKit running as
	// root, user-namespace remapping, rootless engines), so the output
	// directory is opened up for the run. This is only safe because its
	// parent must be private to the caller, which is checked first.
	if err := requirePrivateParent(s.OutDir); err != nil {
		return nil, err
	}
	if err := os.Chmod(s.OutDir, 0o777); err != nil {
		return nil, err
	}
	defer os.Chmod(s.OutDir, 0o700)
	if s.DataWritable {
		// Same reasoning for a data update; afterwards the data stays
		// readable (not writable) so scans can use it as any container user.
		if err := requirePrivateParent(s.DataDir); err != nil {
			return nil, err
		}
		if err := os.Chmod(s.DataDir, 0o777); err != nil {
			return nil, err
		}
		defer os.Chmod(s.DataDir, 0o755)
	}
	runCtx, cancel := context.WithTimeout(ctx, s.Timeout)
	defer cancel()
	cmd := exec.CommandContext(runCtx, e.Bin, args...)
	var stderr tailBuffer
	cmd.Stdout = &stderr // tools that log to stdout are captured with stderr
	cmd.Stderr = &stderr
	cmd.Env = minimalEnv()
	start := time.Now()
	runErr := cmd.Run()
	res := &Result{Duration: time.Since(start), Stderr: stderr.String()}

	if runCtx.Err() == context.DeadlineExceeded {
		// Killing the CLI process does not stop the container; remove it explicitly.
		e.forceRemove(name)
		res.Status = TimedOut
		res.ExitCode = -1
		return res, nil
	}
	if ctx.Err() != nil {
		e.forceRemove(name)
		return nil, ctx.Err()
	}
	var exitErr *exec.ExitError
	switch {
	case runErr == nil:
		res.Status = Completed
	case errors.As(runErr, &exitErr):
		res.ExitCode = exitErr.ExitCode()
		// Exit codes 125 to 127 come from the engine itself (bad image, missing
		// command), not from the tool.
		if res.ExitCode >= 125 && res.ExitCode <= 127 {
			res.Status = Failed
		} else {
			res.Status = Completed
		}
	default:
		return nil, runErr
	}

	limit := s.OutputLimit
	if limit == 0 {
		limit = DefaultOutputLimit
	}
	size, err := dirSize(s.OutDir)
	if err != nil {
		return nil, err
	}
	if size > limit {
		res.Status = Failed
		res.Stderr = fmt.Sprintf("output exceeded %d bytes (%d written)\n", limit, size) + res.Stderr
	}
	return res, nil
}

// requirePrivateParent fails unless dir's parent grants no access to group or
// others, so nobody else can reach the output directory while it is open.
func requirePrivateParent(dir string) error {
	st, err := os.Stat(filepath.Dir(dir))
	if err != nil {
		return err
	}
	if st.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("parent of output directory %q must be accessible only by its owner (mode 0700), has %v", dir, st.Mode().Perm())
	}
	return nil
}

func (e *Engine) forceRemove(name string) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	_ = exec.CommandContext(ctx, e.Bin, "rm", "--force", name).Run()
}

func containerName() (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "siegekit-" + hex.EncodeToString(b), nil
}

// minimalEnv passes only what the engine CLI needs to find its daemon, so the
// user's other environment variables (tokens, keys) are never exposed.
func minimalEnv() []string {
	var env []string
	for _, k := range []string{"PATH", "HOME", "DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_CONFIG", "XDG_RUNTIME_DIR", "CONTAINER_HOST", "CONTAINERS_CONF"} {
		if v, ok := os.LookupEnv(k); ok {
			env = append(env, k+"="+v)
		}
	}
	return env
}

func dirSize(root string) (int64, error) {
	var n int64
	err := filepath.WalkDir(root, func(_ string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.Type().IsRegular() {
			info, err := d.Info()
			if err != nil {
				return err
			}
			n += info.Size()
		}
		return nil
	})
	return n, err
}

// tailBuffer keeps the last 64 KiB written to it.
type tailBuffer struct{ b bytes.Buffer }

const tailMax = 64 << 10

func (t *tailBuffer) Write(p []byte) (int, error) {
	t.b.Write(p)
	if t.b.Len() > tailMax {
		keep := t.b.Bytes()[t.b.Len()-tailMax:]
		t.b = *bytes.NewBuffer(append([]byte(nil), keep...))
	}
	return len(p), nil
}

func (t *tailBuffer) String() string { return t.b.String() }

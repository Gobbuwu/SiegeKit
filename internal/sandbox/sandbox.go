// Package sandbox runs one plugin's tool inside a locked-down container
// (ADR 0006). It builds the container engine's command line directly; no shell
// is involved at any point (threat model T1).
package sandbox

import (
	"bytes"
	"context"
	"crypto/rand"
	"debug/elf"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/Gobbuwu/SiegeKit/internal/relay"
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

// ToolIdentity returns the user and group a tool runs as when SiegeKit runs
// as uid:gid: the same user, or a fixed non-root user when SiegeKit runs as
// root.
func ToolIdentity(uid, gid int) (int, int) {
	if uid == 0 {
		return nonRootUID, nonRootGID
	}
	return uid, gid
}

var reFilesMount = regexp.MustCompile(`^/siegekit/files/[a-z0-9][a-z0-9._-]*$`)

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
	// "target-only" joins the network namespace of Relay, whose only way
	// out is the egress proxy (ADR 0018, ADR 0019).
	Network string
	Relay   string // relay container name, for "target-only"
	CAFile  string // per-run CA certificate to trust (https targets), for "target-only"
	// ConfigFile is a configuration file SiegeKit wrote for the tool (ADR
	// 0023), mounted read-only at ConfigMount; empty for none.
	ConfigFile   string
	DataDir      string // host directory with the tool's data; empty for none
	DataMount    string // where DataDir is mounted; read-only unless DataWritable
	DataWritable bool   // only for update runs
	// Files are pinned downloads (ADR 0024), each a host directory mounted
	// read-only under FilesMount.
	Files       []FileMount
	CPUs        int
	MemoryMiB   int
	PidsLimit   int // 0 means 256
	Timeout     time.Duration
	OutputLimit int64 // bytes; 0 means DefaultOutputLimit
	// Env is extra environment for the tool; see CheckEnv.
	Env map[string]string
	// TmpMiB is the size of the in-memory /tmp; 0 means 256. Its pages count
	// against MemoryMiB, so it cannot exceed the memory limit.
	TmpMiB int
}

// FileMount is a host directory mounted read-only at Mount, which must be
// FilesMount + "/" + a name.
type FileMount struct {
	Host  string
	Mount string
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
	Bin    string // absolute path to docker or podman
	Podman bool   // the CLI is Podman, even when it is installed as "docker"
}

// EngineEnv names the environment variable that picks the engine when both
// are installed: "podman" or "docker" (ADR 0039).
const EngineEnv = "SIEGEKIT_ENGINE"

// Detect finds docker or podman on PATH, preferring Podman (rootless by
// default), or the one named by SIEGEKIT_ENGINE.
func Detect() (*Engine, error) {
	names := []string{"podman", "docker"}
	if v, ok := os.LookupEnv(EngineEnv); ok && v != "" {
		if v != "podman" && v != "docker" {
			return nil, fmt.Errorf("%s must be \"podman\" or \"docker\", not %q", EngineEnv, v)
		}
		names = []string{v}
	}
	for _, name := range names {
		if p, err := exec.LookPath(name); err == nil {
			return &Engine{Bin: p, Podman: isPodman(p)}, nil
		}
	}
	if len(names) == 1 {
		return nil, fmt.Errorf("%s=%s, but %s is not installed", EngineEnv, names[0], names[0])
	}
	return nil, errors.New("no container engine found: install Docker or Podman (see README)")
}

// isPodman reports whether the engine CLI at bin is Podman. "podman
// --version" prints "podman version X"; Docker prints "Docker version X".
func isPodman(bin string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, "--version") // #nosec G204 -- bin is the engine found on PATH; the argument is fixed
	cmd.Env = minimalEnv()
	out, err := cmd.Output()
	return err == nil && strings.HasPrefix(strings.ToLower(strings.TrimSpace(string(out))), "podman")
}

// sameOnEveryEngine adds the flags that make Podman's sandbox match
// Docker's (ADR 0039): with --read-only, Podman also mounts writable tmpfs
// on /run and /var/tmp unless --read-only-tmpfs=false is given. /tmp is
// mounted by SiegeKit itself, with noexec spelled out.
func (e *Engine) sameOnEveryEngine(args []string) []string {
	if !e.Podman {
		return args
	}
	i := slices.Index(args, "--read-only")
	if i < 0 {
		return args
	}
	return slices.Insert(args, i+1, "--read-only-tmpfs=false")
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
	case "target-only":
		if goos != "linux" {
			return errors.New("active tests run only on Linux for now (ADR 0018)")
		}
		if !reRelay.MatchString(s.Relay) {
			return fmt.Errorf("relay %q is not a SiegeKit relay container", s.Relay)
		}
		if s.DataWritable {
			return errors.New("data cannot be writable in an active test")
		}
		if s.CAFile != "" {
			if err := checkMountFile("CA file", s.CAFile); err != nil {
				return err
			}
		}
	default:
		return fmt.Errorf("network %q is not supported", s.Network)
	}
	if s.Network != "target-only" && (s.Relay != "" || s.CAFile != "") {
		return errors.New("relay and CA file are only for target-only runs")
	}
	if s.ConfigFile != "" {
		if err := checkMountFile("config file", s.ConfigFile); err != nil {
			return err
		}
	}
	if err := CheckEnv(s.Env); err != nil {
		return err
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
	seen := map[string]bool{}
	for _, f := range s.Files {
		if !reFilesMount.MatchString(f.Mount) || seen[f.Mount] {
			return fmt.Errorf("file mount %q must be a distinct path %s/NAME", f.Mount, FilesMount)
		}
		seen[f.Mount] = true
		if err := checkMountPath(f.Host); err != nil {
			return fmt.Errorf("file directory: %w", err)
		}
	}
	if s.CPUs < 1 || s.MemoryMiB < 64 || s.Timeout <= 0 {
		return errors.New("cpus, memory and timeout must be set")
	}
	if s.TmpMiB < 0 || s.TmpMiB > s.MemoryMiB {
		return errors.New("tmp size must be between 0 and the memory limit")
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
	uid, gid = ToolIdentity(uid, gid)
	pids := s.PidsLimit
	if pids == 0 {
		pids = 256
	}
	tmp := s.TmpMiB
	if tmp == 0 {
		tmp = 256
	}
	args := []string{
		"run", "--rm",
		"--name", name,
		// Images are pulled only after the user agrees (ADR 0016).
		"--pull", "never",
	}
	// "egress" uses the engine's default network, so no flag is passed.
	switch s.Network {
	case "none":
		args = append(args, "--network", "none")
	case "target-only":
		proxy := "http://127.0.0.1:" + strconv.Itoa(RelayPort)
		args = append(args, "--network", "container:"+s.Relay)
		for _, k := range []string{"HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"} {
			args = append(args, "--env", k+"="+proxy)
		}
		args = append(args, "--env", "NO_PROXY=", "--env", "no_proxy=")
		if s.CAFile != "" {
			args = append(args, "--mount", "type=bind,source="+s.CAFile+",target="+CAMount+",readonly")
			for _, k := range []string{"SSL_CERT_FILE", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE", "NODE_EXTRA_CA_CERTS"} {
				args = append(args, "--env", k+"="+CAMount)
			}
		}
	}
	args = append(args,
		"--user", fmt.Sprintf("%d:%d", uid, gid),
		"--cap-drop", "ALL",
		"--security-opt", "no-new-privileges",
		"--read-only",
		// noexec is spelled out: Docker adds it to --tmpfs and Podman does
		// not, so without it the sandbox differs by engine (ADR 0039).
		"--tmpfs", fmt.Sprintf("/tmp:rw,nosuid,nodev,noexec,size=%dm", tmp),
		"--pids-limit", strconv.Itoa(pids),
		"--memory", fmt.Sprintf("%dm", s.MemoryMiB),
		"--memory-swap", fmt.Sprintf("%dm", s.MemoryMiB),
		"--cpus", strconv.Itoa(s.CPUs),
		"--env", "HOME=/tmp",
		"--workdir", "/tmp",
	)
	keys := make([]string, 0, len(s.Env))
	for k := range s.Env {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		args = append(args, "--env", k+"="+s.Env[k])
	}
	args = append(args,
		"--mount", "type=bind,source="+s.OutDir+",target="+OutMount,
	)
	if s.TargetDir != "" {
		args = append(args, "--mount", "type=bind,source="+s.TargetDir+",target="+TargetMount+",readonly")
	}
	if s.ConfigFile != "" {
		args = append(args, "--mount", "type=bind,source="+s.ConfigFile+",target="+ConfigMount+",readonly")
	}
	if s.DataDir != "" {
		m := "type=bind,source=" + s.DataDir + ",target=" + s.DataMount
		if !s.DataWritable {
			m += ",readonly"
		}
		args = append(args, "--mount", m)
	}
	for _, f := range s.Files {
		args = append(args, "--mount", "type=bind,source="+f.Host+",target="+f.Mount+",readonly")
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
	args = e.sameOnEveryEngine(args)
	// The container user may not map to the caller's UID (SiegeKit running as
	// root, user-namespace remapping, rootless engines), so the output
	// directory is opened up for the run. This is only safe because its
	// parent must be private to the caller, which is checked first.
	if err := requirePrivateParent(s.OutDir); err != nil {
		return nil, err
	}
	if err := os.Chmod(s.OutDir, 0o777); err != nil { // #nosec G302 -- the container user may differ from the caller; the parent is checked to be private (0700) first
		return nil, err
	}
	defer os.Chmod(s.OutDir, 0o700) // #nosec G302 -- a directory, restored to owner-only after the run
	if s.DataWritable {
		// Same reasoning for a data update; afterwards the data stays
		// readable (not writable) so scans can use it as any container user.
		if err := requirePrivateParent(s.DataDir); err != nil {
			return nil, err
		}
		if err := os.Chmod(s.DataDir, 0o777); err != nil { // #nosec G302 -- as for the output directory: the parent is checked to be private first
			return nil, err
		}
		defer os.Chmod(s.DataDir, 0o755) // #nosec G302 -- data must stay readable by any container user; the private parent keeps others out
	}
	runCtx, cancel := context.WithTimeout(ctx, s.Timeout)
	defer cancel()
	cmd := exec.CommandContext(runCtx, e.Bin, args...) // #nosec G204 -- e.Bin is the engine found on PATH; args come from a validated Spec
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

// HasImage reports whether the engine already holds image, a reference
// pinned by digest. It never downloads anything.
func (e *Engine) HasImage(ctx context.Context, image string) (bool, error) {
	if !reImage.MatchString(image) {
		return false, fmt.Errorf("image %q must be pinned by digest", image)
	}
	cmd := exec.CommandContext(ctx, e.Bin, "image", "inspect", "--format", "{{.Id}}", image) // #nosec G204 -- image is checked against reImage above
	cmd.Env = minimalEnv()
	var out tailBuffer
	cmd.Stdout, cmd.Stderr = io.Discard, &out
	err := cmd.Run()
	if err == nil {
		return true, nil
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) && isNoSuchImage(out.String()) {
		return false, nil
	}
	return false, fmt.Errorf("container engine is not working: %s", lastLine(out.String(), err))
}

// isNoSuchImage recognizes the "image not found" messages of Docker and
// Podman, so any other failure (daemon not running) is reported as such.
func isNoSuchImage(msg string) bool {
	m := strings.ToLower(msg)
	return strings.Contains(m, "no such image") || strings.Contains(m, "image not known") || strings.Contains(m, "no such object")
}

// Info names the container engine a run used. Results measured with one
// engine, mode or cgroup version do not carry over to another (Docker adds
// noexec to /tmp, Podman does not), so every report and measurement names it
// (ADR 0038).
type Info struct {
	Engine   string // "docker" or "podman"
	Version  string
	Rootless bool
	Cgroup   string // "v1" or "v2"; empty when the engine does not say
}

// Describe asks the engine what it is. Podman's format is tried first, so a
// "docker" command that is really Podman (podman-docker) is named as Podman.
func (e *Engine) Describe(ctx context.Context) (Info, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	info := func(format string) (string, error) {
		cmd := exec.CommandContext(ctx, e.Bin, "info", "--format", format) // #nosec G204 -- e.Bin is the engine found on PATH; the format is fixed
		cmd.Env = minimalEnv()
		var out, errOut tailBuffer
		cmd.Stdout, cmd.Stderr = &out, &errOut
		if err := cmd.Run(); err != nil {
			return "", errors.New(lastLine(errOut.String(), err))
		}
		return strings.TrimSpace(out.String()), nil
	}
	if out, err := info("{{.Version.Version}}\t{{.Host.CgroupsVersion}}\t{{.Host.Security.Rootless}}"); err == nil {
		return parseInfo("podman", out)
	}
	out, err := info("{{.ServerVersion}}\t{{.CgroupVersion}}\t{{range .SecurityOptions}}{{.}},{{end}}")
	if err != nil {
		return Info{}, fmt.Errorf("container engine is not working: %v", err)
	}
	return parseInfo("docker", out)
}

// parseInfo reads the tab-separated answer of Describe's formats.
func parseInfo(engine, out string) (Info, error) {
	f := strings.Split(out, "\t")
	if len(f) != 3 || f[0] == "" || len(f[0]) > 64 || strings.ContainsAny(out, "\n\r") {
		return Info{}, fmt.Errorf("unexpected %s info: %q", engine, out)
	}
	i := Info{Engine: engine, Version: f[0]}
	switch strings.TrimPrefix(f[1], "v") {
	case "1":
		i.Cgroup = "v1"
	case "2":
		i.Cgroup = "v2"
	}
	if engine == "podman" {
		i.Rootless = f[2] == "true"
	} else {
		i.Rootless = slices.Contains(strings.Split(f[2], ","), "name=rootless")
	}
	return i, nil
}

// Pull downloads image, a reference pinned by digest.
func (e *Engine) Pull(ctx context.Context, image string) error {
	if !reImage.MatchString(image) {
		return fmt.Errorf("image %q must be pinned by digest", image)
	}
	cmd := exec.CommandContext(ctx, e.Bin, "pull", "--quiet", image) // #nosec G204 -- image is checked against reImage above
	cmd.Env = minimalEnv()
	var out tailBuffer
	cmd.Stdout, cmd.Stderr = io.Discard, &out
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("download failed: %s", lastLine(out.String(), err))
	}
	return nil
}

// lastLine returns the last non-empty line of engine output, or err, without
// control characters and cut to 300 bytes.
func lastLine(s string, err error) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	l := strings.TrimSpace(lines[len(lines)-1])
	if l == "" {
		l = err.Error()
	}
	l = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, strings.ToValidUTF8(l, ""))
	if len(l) > 300 {
		l = l[:300]
	}
	return l
}

// forceRemove removes a container and waits, up to 30 seconds, until the
// engine no longer lists it. "rm --force" can return while the container is
// still listed, for example when the engine's own --rm cleanup is removing
// it at the same moment, so removal is confirmed rather than assumed.
func (e *Engine) forceRemove(name string) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	for {
		_ = exec.CommandContext(ctx, e.Bin, "rm", "--force", name).Run() // #nosec G204 -- name is generated by containerName
		if !e.listed(ctx, name) {
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(200 * time.Millisecond):
		}
	}
}

// listed reports whether the engine still lists the container name. An
// engine error counts as not listed: nothing more can be done about it.
func (e *Engine) listed(ctx context.Context, name string) bool {
	out, err := exec.CommandContext(ctx, e.Bin, "ps", "--all", "--quiet", "--filter", "name=^"+name+"$").Output() // #nosec G204 -- name is generated by SiegeKit
	return err == nil && len(bytes.TrimSpace(out)) > 0
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

// Relay settings (ADR 0019, ADR 0021).
const (
	// RelayImage is the Docker Official Image alpine:3.24.4, published
	// 2026-11-08, pinned by index digest. It only provides a root file
	// system: the relay itself is SiegeKit's own static binary.
	RelayImage = "docker.io/library/alpine@sha256:f59abe656b692d901e184be3445e084786602108599d2a51d229c0f5a48c71bf"
	// RelayImageVersion is RelayImage's Alpine release, for consent prompts.
	RelayImageVersion = "3.24.4"
	RelayPort         = 8080
	// relayBinary is the copy of SiegeKit's binary in the relay directory.
	relayBinary = "siegekit-relay"
	// RelaySocket is the proxy's socket file name in the relay directory.
	RelaySocket = "proxy.sock"
	relayMount  = "/run/siegekit"
	CAMount     = "/siegekit/ca.pem"
	// ConfigMount is where Spec.ConfigFile is mounted (ADR 0023).
	ConfigMount = "/siegekit/config.json"
	// FilesMount holds the pinned downloads of a plugin (ADR 0024).
	FilesMount = "/siegekit/files"
)

var (
	reRelay = regexp.MustCompile(`^siegekit-relay-[0-9a-f]{16}$`)
	goos    = runtime.GOOS
)

// StartRelay starts the relay container for one active run: no network,
// forwarding 127.0.0.1:RelayPort in its namespace to the Unix socket
// RelaySocket in dir. The relay is bin, a statically linked SiegeKit binary
// for this machine (normally the running one), copied into dir and run with
// its hidden relay command (ADR 0021). It returns once the relay listens.
func (e *Engine) StartRelay(ctx context.Context, dir, bin string) (string, error) {
	if goos != "linux" {
		return "", errors.New("active tests run only on Linux for now (ADR 0018)")
	}
	if err := checkMountPath(dir); err != nil {
		return "", fmt.Errorf("relay directory: %w", err)
	}
	if err := CheckStatic(bin); err != nil {
		return "", err
	}
	if err := copyExecutable(bin, filepath.Join(dir, relayBinary)); err != nil {
		return "", fmt.Errorf("copy relay binary: %w", err)
	}
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	name := "siegekit-relay-" + hex.EncodeToString(b)
	uid, gid := os.Getuid(), os.Getgid()
	if uid == 0 {
		uid, gid = nonRootUID, nonRootGID
	}
	args := []string{
		"run", "-d", "--rm", "--name", name, "--pull", "never",
		"--network", "none",
		"--user", fmt.Sprintf("%d:%d", uid, gid),
		"--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--read-only",
		"--pids-limit", "64", "--memory", "64m", "--memory-swap", "64m", "--cpus", "1",
		"--mount", "type=bind,source=" + dir + ",target=" + relayMount + ",readonly",
		"--entrypoint", relayMount + "/" + relayBinary,
		RelayImage,
		relay.Command, fmt.Sprintf("127.0.0.1:%d", RelayPort), relayMount + "/" + RelaySocket,
	}
	args = e.sameOnEveryEngine(args)
	cmd := exec.CommandContext(ctx, e.Bin, args...) // #nosec G204 -- fixed arguments; dir is checked above
	cmd.Env = minimalEnv()
	if out, err := cmd.CombinedOutput(); err != nil {
		return "", fmt.Errorf("start relay: %s", lastLine(string(out), err))
	}
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		logs := exec.CommandContext(ctx, e.Bin, "logs", name) // #nosec G204 -- name is generated above
		logs.Env = minimalEnv()
		out, err := logs.CombinedOutput()
		if err == nil && strings.Contains(string(out), "listening on") {
			return name, nil
		}
		if ctx.Err() != nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	e.forceRemove(name)
	if ctx.Err() != nil {
		return "", ctx.Err()
	}
	return "", errors.New("the relay container did not start listening")
}

// checkMountFile checks a file that is bind-mounted into the container: an
// absolute, clean path to a regular file, with no character that could add
// options to a --mount argument.
func checkMountFile(what, p string) error {
	if !filepath.IsAbs(p) || filepath.Clean(p) != p || strings.ContainsAny(p, ",\"'\n\r\x00") {
		return fmt.Errorf("%s %q must be an absolute, clean path", what, p)
	}
	if st, err := os.Lstat(p); err != nil || !st.Mode().IsRegular() {
		return fmt.Errorf("%s %q is not a regular file", what, p)
	}
	return nil
}

// StopRelay removes the relay container.
func (e *Engine) StopRelay(name string) {
	if reRelay.MatchString(name) {
		e.forceRemove(name)
	}
}

var reEnvKey = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,63}$`)

// CheckEnv checks tool environment variables. Names that change how
// programs load code or reach the network, or that SiegeKit sets itself,
// are refused.
func CheckEnv(env map[string]string) error {
	if len(env) > 16 {
		return errors.New("more than 16 environment variables")
	}
	for k, v := range env {
		switch {
		case !reEnvKey.MatchString(k):
			return fmt.Errorf("environment variable name %q must match %s", k, reEnvKey)
		case k == "PATH" || k == "HOME" || strings.HasPrefix(k, "LD_") || strings.HasPrefix(k, "DYLD_") ||
			strings.Contains(k, "PROXY") || strings.HasPrefix(k, "SSL_") || strings.HasPrefix(k, "SIEGEKIT_") ||
			k == "REQUESTS_CA_BUNDLE" || k == "CURL_CA_BUNDLE" || k == "NODE_EXTRA_CA_CERTS":
			return fmt.Errorf("environment variable %s is not allowed", k)
		case len(v) > 16<<10 || strings.ContainsRune(v, 0) || !utf8.ValidString(v):
			return fmt.Errorf("environment variable %s: value must be UTF-8 text up to 16 KiB", k)
		}
	}
	return nil
}

// CheckStatic checks that bin is a statically linked Linux executable for
// this machine's architecture, so it runs in any Linux container image.
// SiegeKit's release binaries are static; a local build must use
// CGO_ENABLED=0 (README).
func CheckStatic(bin string) error {
	f, err := elf.Open(bin)
	if err != nil {
		return fmt.Errorf("relay binary %s is not a Linux executable: %w", bin, err)
	}
	defer f.Close()
	want := map[string]elf.Machine{"amd64": elf.EM_X86_64, "arm64": elf.EM_AARCH64}[runtime.GOARCH]
	if f.Machine != want || f.Type != elf.ET_EXEC {
		return fmt.Errorf("relay binary %s is not a Linux %s executable", bin, runtime.GOARCH)
	}
	for _, p := range f.Progs {
		if p.Type == elf.PT_INTERP || p.Type == elf.PT_DYNAMIC {
			return fmt.Errorf("SiegeKit was built with dynamic linking, so it cannot run its relay inside a container; build it with CGO_ENABLED=0 (see the README)")
		}
	}
	return nil
}

// copyExecutable copies a regular file to dst with mode 0755, refusing
// symlinks at either end.
func copyExecutable(src, dst string) error {
	in, err := os.OpenFile(src, os.O_RDONLY|syscall.O_NOFOLLOW, 0) // #nosec G304 -- SiegeKit's own binary, checked by CheckStatic
	if err != nil {
		return err
	}
	defer in.Close()
	st, err := in.Stat()
	if err != nil {
		return err
	}
	if !st.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular file", src)
	}
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o755) // #nosec G302 G304 -- the relay's user (another UID) must run it; dst is in SiegeKit's private run directory
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return err
	}
	if err := out.Chmod(0o755); err != nil { // umask aside
		_ = out.Close()
		return err
	}
	return out.Close()
}

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
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"net/url"
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
	"github.com/Gobbuwu/SiegeKit/internal/waiter"
	"github.com/Gobbuwu/SiegeKit/internal/waiterbin"
)

// Paths inside the container.
const (
	TargetMount = "/target"
	OutMount    = "/out"
	WorkDir     = "/tmp/work"
	// InputMount is where Spec.InputDir is mounted, read-only.
	InputMount = "/siegekit/input"
	// ScratchMount is where Spec.ScratchDir is mounted, read-write.
	ScratchMount = "/siegekit/scratch"
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
	// 0023), mounted read-only at ConfigMount, or at ConfigMountTOML when
	// its name ends in ".toml" (ADR 0063); empty for none.
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
	// StdoutFile, if set, is a plain file name inside OutDir that receives
	// the tool's standard output, which is then not mixed into Stderr
	// (ADR 0040). It counts against OutputLimit.
	StdoutFile string
	// StderrFile, if set, is a plain file name inside OutDir that also
	// receives the tool's standard error in full, for a parser that reads
	// the tool's log (ADR 0066); Stderr still keeps its tail. It counts
	// against OutputLimit.
	StderrFile string
	// Entrypoint, if set, replaces the image's entrypoint with a program
	// on the image's PATH, such as "go" for the Go module download
	// (ADR 0066).
	Entrypoint string
	// InputDir is a directory SiegeKit prepared for the tool, such as
	// copies of a repository's go.mod files, mounted read-only at
	// InputMount; empty for none.
	InputDir string
	// ScratchDir is an empty directory in SiegeKit's private run
	// directory, mounted read-write at ScratchMount, for a scan's build
	// cache and compile scratch (ADR 0066); empty for none. Only for runs
	// without network. The caller deletes it afterwards.
	ScratchDir string
	// Egress is how an "egress" run reaches the internet through a proxy
	// or TLS inspection (ADR 0066).
	Egress Egress
}

// Egress is the person's proxy and extra CA certificate for the containers
// that use the network: data updates and the Go module download (ADR 0066,
// Porchlet finding SK-8). Scan containers never get them.
type Egress struct {
	// CAFile is a PEM file of extra CA certificates, mounted read-only at
	// CAMount and named by SSL_CERT_FILE. Go programs then still read the
	// image's /etc/ssl/certs, so it adds to the image's roots (measured,
	// ADR 0066).
	CAFile string
	// Proxy is an http or https URL with no user name or password, passed
	// as HTTPS_PROXY and HTTP_PROXY.
	Proxy string
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

// Stop says, as a fixed word, why a run was cut short (ADR 0067, decision
// 1). A stopped run is Failed (TimedOut for StopTimeLimit), so every caller
// that does not look at Stop still treats it as failed; the output the tool
// wrote before the stop is left in place.
type Stop string

// Run stops.
const (
	// The run reached its time limit.
	StopTimeLimit Stop = "time-limit"
	// The kernel killed a process of the tool for memory.
	StopMemoryKill Stop = "memory-kill"
	// The kernel refused to start a process at the process limit.
	StopProcessLimit Stop = "process-limit"
	// The container's first process was killed (exit 137) before it could
	// report; the kernel's reason is not known (ADR 0067, decision 2).
	StopKilled Stop = "killed"
	// The tool wrote more than its output limit.
	StopOutputLimit Stop = "output-limit"
	// The kernel's counters could not be read, so a stop cannot be ruled
	// out.
	StopCountersUnread Stop = "counters-unread"
)

// Result of a sandboxed run.
type Result struct {
	Status   Status
	ExitCode int
	// Stderr is the last 64 KiB of the tool's output. When the run was
	// stopped, its last line is StopReason, so a caller that shows only the
	// last line shows why.
	Stderr   string
	Duration time.Duration
	// Stop and StopReason say why the run was cut short; "" when it was not.
	Stop       Stop
	StopReason string
	// Usage is what the waiter measured; nil when it wrote no counters.
	Usage *waiter.Status
}

// stopped marks r as cut short for why.
func (r *Result) stopped(stop Stop, why string) {
	if r.Stop == "" {
		r.Stop, r.StopReason = stop, why
		r.Stderr = strings.TrimRight(r.Stderr, "\n") + "\n" + why
	} else {
		r.StopReason += "; " + why
		r.Stderr += "; " + why
	}
	if r.Status != TimedOut {
		r.Status = Failed
	}
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
// on /run and /var/tmp unless --read-only-tmpfs=false is given. /tmp and
// /dev/shm are mounted by SiegeKit itself, with noexec spelled out.
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
	if s.StdoutFile != "" && !reStdoutFile.MatchString(s.StdoutFile) {
		return fmt.Errorf("stdout file %q is not a plain file name", s.StdoutFile)
	}
	if s.StderrFile != "" && (!reStdoutFile.MatchString(s.StderrFile) || s.StderrFile == s.StdoutFile) {
		return fmt.Errorf("stderr file %q is not a plain file name other than the stdout file", s.StderrFile)
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
	if s.Egress != (Egress{}) && s.Network != "egress" {
		return errors.New("a proxy or extra CA file is only for egress runs")
	}
	if s.Egress.CAFile != "" {
		if err := checkMountFile("CA file", s.Egress.CAFile); err != nil {
			return err
		}
	}
	if s.Egress.Proxy != "" {
		if err := CheckProxy(s.Egress.Proxy); err != nil {
			return err
		}
	}
	if s.Entrypoint != "" && !reEntrypoint.MatchString(s.Entrypoint) {
		return fmt.Errorf("entrypoint %q must be a program name matching %s", s.Entrypoint, reEntrypoint)
	}
	if s.ScratchDir != "" && s.Network != "none" {
		return errors.New("a scratch directory is only for runs without network")
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
	}{{"target", s.TargetDir, false}, {"output", s.OutDir, true}, {"data", s.DataDir, false}, {"input", s.InputDir, false}, {"scratch", s.ScratchDir, false}} {
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
	pids := s.ProcessLimit()
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
	case "egress":
		if p := s.Egress.Proxy; p != "" {
			for _, k := range []string{"HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"} {
				args = append(args, "--env", k+"="+p)
			}
		}
		if s.Egress.CAFile != "" {
			args = append(args, "--mount", "type=bind,source="+s.Egress.CAFile+",target="+CAMount+",readonly",
				"--env", "SSL_CERT_FILE="+CAMount)
		}
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
		// /dev/shm as Docker mounts it by default; Podman's is read-only
		// with --read-only-tmpfs=false (measured, ADR 0039).
		"--tmpfs", "/dev/shm:rw,nosuid,nodev,noexec,size=64m",
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
		target := ConfigMount
		if strings.HasSuffix(s.ConfigFile, ".toml") {
			target = ConfigMountTOML
		}
		args = append(args, "--mount", "type=bind,source="+s.ConfigFile+",target="+target+",readonly")
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
	if s.InputDir != "" {
		args = append(args, "--mount", "type=bind,source="+s.InputDir+",target="+InputMount+",readonly")
	}
	if s.ScratchDir != "" {
		args = append(args, "--mount", "type=bind,source="+s.ScratchDir+",target="+ScratchMount)
	}
	if s.Entrypoint != "" {
		args = append(args, "--entrypoint", s.Entrypoint)
	}
	args = append(args, s.Image)
	args = append(args, s.Args...)
	return args, nil
}

// Run executes the spec and waits for it, killing the container on timeout.
// The tool runs under the waiter (ADR 0067), whose counters decide whether
// the run was cut short.
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
	entry := []string{s.Entrypoint}
	if s.Entrypoint == "" {
		if entry, err = e.entrypoint(ctx, s.Image); err != nil {
			return nil, err
		}
	}
	wdir, err := installWaiter(filepath.Dir(s.OutDir))
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(wdir)
	if args, err = withWaiter(args, s, entry, wdir); err != nil {
		return nil, err
	}
	args = e.sameOnEveryEngine(args)
	if err := os.Chmod(s.OutDir, 0o777); err != nil { // #nosec G302 -- the container user may differ from the caller; the parent is checked to be private (0700) first
		return nil, err
	}
	defer os.Chmod(s.OutDir, 0o700) // #nosec G302 -- a directory, restored to owner-only after the run
	if s.ScratchDir != "" {
		// As for the output directory; the caller deletes it afterwards.
		if err := requirePrivateParent(s.ScratchDir); err != nil {
			return nil, err
		}
		if err := os.Chmod(s.ScratchDir, 0o777); err != nil { // #nosec G302 -- the container user may differ from the caller; the parent is checked to be private (0700) first
			return nil, err
		}
	}
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
	cmd := e.command(runCtx, args...) // args come from a validated Spec
	var stderr tailBuffer
	cmd.Stdout = &stderr // tools that log to stdout are captured with stderr
	cmd.Stderr = &stderr
	if s.StdoutFile != "" {
		w, closeFile, err := captureFile(s, s.StdoutFile)
		if err != nil {
			return nil, fmt.Errorf("create stdout file: %w", err)
		}
		defer closeFile()
		cmd.Stdout = w
	}
	if s.StderrFile != "" {
		w, closeFile, err := captureFile(s, s.StderrFile)
		if err != nil {
			return nil, fmt.Errorf("create stderr file: %w", err)
		}
		defer closeFile()
		cmd.Stderr = io.MultiWriter(&stderr, w)
	}
	start := time.Now()
	runErr := cmd.Run()
	res := &Result{Duration: time.Since(start), Stderr: stderr.String()}

	if runCtx.Err() == context.DeadlineExceeded {
		// Killing the CLI process does not stop the container; remove it explicitly.
		if err := e.forceRemove(name); err != nil {
			return nil, fmt.Errorf("stopped after %v, but %w", s.Timeout, err)
		}
		res.Status = TimedOut
		res.ExitCode = -1
		_ = os.Remove(filepath.Join(s.OutDir, StatusFile)) // not read: the run is stopped already
		res.stopped(StopTimeLimit, fmt.Sprintf("stopped after %d seconds, its time limit", int(s.Timeout.Seconds())))
		return res, nil
	}
	if ctx.Err() != nil {
		return nil, errors.Join(ctx.Err(), e.forceRemove(name))
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
	usage, uerr := readStatus(s.OutDir)
	res.Usage = usage
	switch {
	case res.Status == Failed:
		// The engine or the waiter could not start the tool; the reason is
		// its last line.
	case uerr != nil && res.ExitCode == 137:
		res.stopped(StopKilled, "the container was killed (exit 137) before SiegeKit's waiter could read the kernel's counters; the most common cause is running out of memory")
	case uerr != nil:
		res.stopped(StopCountersUnread, "SiegeKit could not read the kernel's counters for this run, so it cannot tell whether the run was cut short: "+uerr.Error())
	default:
		if usage.MemoryKills > 0 {
			res.stopped(StopMemoryKill, fmt.Sprintf("the kernel killed %d process(es) of the tool for using more than the %d MiB memory limit", usage.MemoryKills, s.MemoryMiB))
		}
		if usage.ProcessesRefused > 0 {
			res.stopped(StopProcessLimit, fmt.Sprintf("the kernel refused %d new process(es) at the limit of %d processes and threads", usage.ProcessesRefused, s.ProcessLimit()))
		}
		if len(usage.Errors) > 0 {
			res.stopped(StopCountersUnread, "SiegeKit could not read the kernel's counters for this run, so it cannot tell whether the run was cut short: "+strings.Join(usage.Errors, "; "))
		}
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
		res.stopped(StopOutputLimit, fmt.Sprintf("the tool's output exceeded the limit of %d bytes (%d written)", limit, size))
	}
	return res, nil
}

// ProcessLimit is the limit of processes and threads the run gets.
func (s *Spec) ProcessLimit() int {
	if s.PidsLimit == 0 {
		return 256
	}
	return s.PidsLimit
}

// Waiter settings (ADR 0067).
const (
	// WaiterMount is where the waiter's directory is mounted, read-only.
	WaiterMount = "/siegekit/waiter"
	waiterFile  = "wait"
	// StatusFile is the waiter's status file in the output directory. It
	// is written after the tool exits and removed by SiegeKit before the
	// output is read or measured.
	StatusFile = ".siegekit-waiter.json"
)

// installWaiter writes the waiter for this machine's CPU type into a new
// directory in parent, which must be private (checked by the caller).
func installWaiter(parent string) (string, error) {
	bin, err := waiterbin.Binary(runtime.GOARCH)
	if err != nil {
		return "", err
	}
	dir, err := os.MkdirTemp(parent, "waiter-")
	if err != nil {
		return "", err
	}
	// The container user may be any user: traverse only, as for the relay.
	if err := os.Chmod(dir, 0o711); err != nil { // #nosec G302 -- traverse only; the parent is private
		_ = os.RemoveAll(dir)
		return "", err
	}
	f, err := os.OpenFile(filepath.Join(dir, waiterFile), os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o755) // #nosec G302 G304 -- the tool's user (another UID) must run it; dir is new and private to SiegeKit
	if err == nil {
		_, err = f.Write(bin)
		err = errors.Join(err, f.Chmod(0o755), f.Close())
	}
	if err != nil {
		_ = os.RemoveAll(dir)
		return "", fmt.Errorf("install waiter: %w", err)
	}
	return dir, nil
}

// withWaiter changes engine arguments made by EngineArgs so the waiter in
// dir runs first and starts entry (the image's entrypoint, or the spec's)
// with the spec's arguments, as the engine itself would have.
func withWaiter(args []string, s Spec, entry []string, dir string) ([]string, error) {
	if err := checkMountPath(dir); err != nil {
		return nil, fmt.Errorf("waiter directory: %w", err)
	}
	img := len(args) - len(s.Args) - 1
	if img < 0 || args[img] != s.Image {
		return nil, errors.New("waiter: image not where expected in the engine arguments")
	}
	var out []string
	for i := 0; i < img; i++ {
		if args[i] == "--entrypoint" {
			i++ // replaced below
			continue
		}
		out = append(out, args[i])
	}
	out = append(out,
		"--mount", "type=bind,source="+dir+",target="+WaiterMount+",readonly",
		"--entrypoint", WaiterMount+"/"+waiterFile,
		s.Image, OutMount+"/"+StatusFile)
	for _, e := range entry {
		if e != "" {
			out = append(out, e)
		}
	}
	return append(out, s.Args...), nil
}

// entrypoint reads image's entrypoint, which the waiter starts.
func (e *Engine) entrypoint(ctx context.Context, image string) ([]string, error) {
	if !reImage.MatchString(image) {
		return nil, fmt.Errorf("image %q must be pinned by digest", image)
	}
	cmd := e.command(ctx, "image", "inspect", "--format", "{{json .Config.Entrypoint}}", image) // image is checked against reImage above
	var out, errOut tailBuffer
	cmd.Stdout, cmd.Stderr = &out, &errOut
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("read the image's entrypoint: %s", lastLine(errOut.String(), err))
	}
	var entry []string
	if err := json.Unmarshal([]byte(strings.TrimSpace(out.String())), &entry); err != nil {
		return nil, fmt.Errorf("read the image's entrypoint: %v", err)
	}
	if len(entry) > 32 {
		return nil, errors.New("read the image's entrypoint: more than 32 parts")
	}
	return entry, nil
}

// readStatus reads and removes the waiter's status file in dir.
func readStatus(dir string) (*waiter.Status, error) {
	p := filepath.Join(dir, StatusFile)
	defer os.Remove(p)
	f, err := os.OpenFile(p, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0) // #nosec G304 -- fixed name in SiegeKit's private output directory; links refused
	if errors.Is(err, os.ErrNotExist) {
		return nil, errors.New("the waiter wrote no counters")
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if st, err := f.Stat(); err != nil || !st.Mode().IsRegular() {
		return nil, errors.New("the waiter's status is not a regular file")
	}
	b, err := io.ReadAll(io.LimitReader(f, waiter.MaxStatusSize+1))
	if err != nil {
		return nil, err
	}
	st, err := waiter.ParseStatus(b)
	if err != nil {
		return nil, err
	}
	return &st, nil
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
	cmd := e.command(ctx, "image", "inspect", "--format", "{{.Id}}", image) // image is checked against reImage above
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
		cmd := e.command(ctx, "info", "--format", format)
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
	cmd := e.command(ctx, "pull", "--quiet", image) // image is checked against reImage above
	var out tailBuffer
	cmd.Stdout, cmd.Stderr = io.Discard, &out
	if err := cmd.Run(); err != nil {
		msg := lastLine(out.String(), err)
		return fmt.Errorf("download failed: %s%s", msg, TooManyPullsHint(image, out.String()))
	}
	return nil
}

// TooManyPullsHint explains a registry's pull limit when engine output
// says the registry refused with 429 Too Many Requests, and is "" otherwise
// (ADR 0066, 7A). SiegeKit's pull already uses a sign-in stored with
// "docker login" or "podman login" (measured on both engines).
func TooManyPullsHint(image, output string) string {
	o := strings.ToLower(output)
	if !strings.Contains(o, "toomanyrequests") && !strings.Contains(o, "429 too many requests") && !strings.Contains(o, "pull rate limit") {
		return ""
	}
	if strings.HasPrefix(image, "docker.io/") {
		return ". Docker Hub limits downloads per IP address (100 per hour without signing in, measured 2026-11-24), and a shared address (CI, a cloud machine) may have used them up. Sign in with 'docker login' or 'podman login' (200 per hour per account), or set a registry mirror for docker.io in your engine, such as https://mirror.gcr.io: Docker's registry-mirrors in daemon.json, Podman's registries.conf, or Colima's colima.yaml (see docs/network.md), then run SiegeKit again"
	}
	return ". The registry limits downloads: wait and run SiegeKit again, or set a mirror for it in your engine (see docs/network.md)"
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
// it at the same moment, so removal is confirmed rather than assumed. A
// container that may still run is an error: it can keep writing to the
// folders mounted into it.
func (e *Engine) forceRemove(name string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	for {
		_ = e.command(ctx, "rm", "--force", name).Run() // name is generated by SiegeKit; listed confirms the result
		listed, err := e.listed(ctx, name)
		if err == nil && !listed {
			return nil
		}
		select {
		case <-ctx.Done():
			if err == nil {
				err = errors.New("still listed after 30 seconds")
			}
			return fmt.Errorf("SiegeKit could not remove container %s: %v", name, err)
		case <-time.After(200 * time.Millisecond):
		}
	}
}

// listed reports whether the engine still lists the container name.
func (e *Engine) listed(ctx context.Context, name string) (bool, error) {
	var errOut tailBuffer
	cmd := e.command(ctx, "ps", "--all", "--quiet", "--filter", "name=^"+name+"$")
	cmd.Stderr = &errOut
	out, err := cmd.Output()
	if err != nil {
		return false, errors.New(lastLine(errOut.String(), err))
	}
	return len(bytes.TrimSpace(out)) > 0, nil
}

// command is an engine command. Every engine command gets the same
// environment: when "rm" and "ps" saw an XDG_DATA_HOME that "run" did not,
// rootless Podman looked for the container in another store, did not find
// it, and a timed-out container kept running (ADR 0066 build).
func (e *Engine) command(ctx context.Context, args ...string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, e.Bin, args...) // #nosec G204 -- e.Bin is the engine found on PATH; callers validate args
	cmd.Env = minimalEnv()
	return cmd
}

func containerName() (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "siegekit-" + hex.EncodeToString(b), nil
}

// minimalEnv passes only what the engine CLI needs to find its daemon and,
// for Podman, its image store and settings (registries.conf, where a mirror
// is set), so the user's other environment variables (tokens, keys) are
// never exposed.
func minimalEnv() []string {
	var env []string
	for _, k := range []string{"PATH", "HOME", "DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_CONFIG", "XDG_RUNTIME_DIR", "XDG_DATA_HOME", "XDG_CONFIG_HOME",
		"CONTAINER_HOST", "CONTAINERS_CONF", "CONTAINERS_REGISTRIES_CONF", "CONTAINERS_STORAGE_CONF"} {
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
// cappedWriter writes at most left bytes and drops the rest, so a tool
// cannot fill the disk through its standard output. Writing one byte more
// than the output limit is enough for the size check after the run to fail.
// captureFile creates name in s.OutDir for one of the tool's output
// streams. It is created by SiegeKit before the tool starts, so the tool
// cannot make it a link, and written only by this process, up to one byte
// past the output limit so that going over it is seen.
func captureFile(s Spec, name string) (io.Writer, func() error, error) {
	f, err := os.OpenFile(filepath.Join(s.OutDir, name), os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600) // #nosec G304 -- a plain file name (checked in validate) in the private output directory
	if err != nil {
		return nil, nil, err
	}
	limit := s.OutputLimit
	if limit == 0 {
		limit = DefaultOutputLimit
	}
	return &cappedWriter{w: f, left: limit + 1}, f.Close, nil
}

type cappedWriter struct {
	w    io.Writer
	left int64
}

func (c *cappedWriter) Write(p []byte) (int, error) {
	n := len(p)
	if int64(len(p)) > c.left {
		p = p[:c.left]
	}
	if len(p) > 0 {
		if _, err := c.w.Write(p); err != nil {
			return 0, err
		}
		c.left -= int64(len(p))
	}
	return n, nil
}

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
	// ConfigMountTOML is where a TOML Spec.ConfigFile is mounted, such as
	// the Gitleaks configuration SiegeKit builds (ADR 0063).
	ConfigMountTOML = "/siegekit/config.toml"
	// FilesMount holds the pinned downloads of a plugin (ADR 0024).
	FilesMount = "/siegekit/files"
)

var (
	reRelay = regexp.MustCompile(`^siegekit-relay-[0-9a-f]{16}$`)
	// reStdoutFile is a plain file name, as for a manifest's output.file.
	reStdoutFile = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$`)
	goos         = runtime.GOOS
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
	cmd := e.command(ctx, args...) // fixed arguments; dir is checked above
	if out, err := cmd.CombinedOutput(); err != nil {
		return "", fmt.Errorf("start relay: %s", lastLine(string(out), err))
	}
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		logs := e.command(ctx, "logs", name)
		out, err := logs.CombinedOutput()
		if err == nil && strings.Contains(string(out), "listening on") {
			return name, nil
		}
		if ctx.Err() != nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if err := e.forceRemove(name); err != nil {
		return "", err
	}
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
		_ = e.forceRemove(name) // runs deferred, after the active checks; nothing to report it to
	}
}

var reEnvKey = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,63}$`)

// reEntrypoint is a program name looked up on the image's PATH.
var reEntrypoint = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,31}$`)

// GoProxy is the only module proxy a tool may be pointed at: Go's own
// (ADR 0066). GOPROXY=off is allowed too.
const GoProxy = "https://proxy.golang.org"

// CheckProxy checks a proxy URL for Egress: http or https, a host, no user
// name or password (it would sit in the container's environment, ADR
// 0066), and nothing after the host and port.
func CheckProxy(p string) error {
	u, err := url.Parse(p)
	switch {
	case err != nil:
		return fmt.Errorf("proxy %q is not a URL", p)
	case u.Scheme != "http" && u.Scheme != "https":
		return fmt.Errorf("proxy %q must start with http:// or https://", p)
	case u.User != nil:
		return errors.New("a proxy URL with a user name or password is not supported: it would be visible in the container's environment")
	case u.Hostname() == "" || u.Opaque != "" || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" || strings.ContainsAny(p, " \n\r\t\x00"):
		return fmt.Errorf("proxy %q must be scheme://host[:port] and nothing more", p)
	}
	return nil
}

// CheckEnv checks tool environment variables. Names that change how
// programs load code or reach the network, or that SiegeKit sets itself,
// are refused.
func CheckEnv(env map[string]string) error {
	if len(env) > 16 {
		return errors.New("more than 16 environment variables")
	}
	for _, k := range slices.Sorted(maps.Keys(env)) { // the same error each run
		v := env[k]
		switch {
		case !reEnvKey.MatchString(k):
			return fmt.Errorf("environment variable name %q must match %s", k, reEnvKey)
		case k == "GOPROXY" && v != "off" && v != GoProxy:
			return fmt.Errorf("environment variable GOPROXY must be off or %s", GoProxy)
		case k == "PATH" || k == "HOME" || strings.HasPrefix(k, "LD_") || strings.HasPrefix(k, "DYLD_") ||
			strings.Contains(k, "PROXY") && k != "GOPROXY" && k != "GONOPROXY" || strings.HasPrefix(k, "SSL_") || strings.HasPrefix(k, "SIEGEKIT_") ||
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

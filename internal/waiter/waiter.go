// Package waiter is the program SiegeKit starts as the first process of
// every tool container (ADR 0067, decision 2). It runs the tool, reaps every
// process, samples the container's program memory and process count, and,
// after the tool exits, reads the kernel's counters of refused processes and
// memory kills from the container's own cgroup. It writes them to a status
// file that SiegeKit reads after the container stops.
//
// Only a process inside the container sees every refused process and memory
// kill: polling from the host every 2 s caught 0 of 18 events, and the
// engine's inspect missed a memory kill on Podman 4.9.3 and never reports
// refused processes (measured, ADR 0067).
//
// The waiter is built on its own (cmd/siegekit-waiter) as a static Linux
// program and embedded in SiegeKit (internal/waiterbin), so it runs in any
// image on any host, macOS included.
package waiter

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// StatusVersion is the version of the status file's format.
const StatusVersion = 1

// MaxStatusSize is the largest status file SiegeKit reads.
const MaxStatusSize = 64 << 10

// Status is what the waiter writes after the tool exits.
type Status struct {
	Version int `json:"version"`
	// Exit is the tool's exit code, or 128 plus the signal that ended it.
	Exit int `json:"exit"`
	// Signal names the signal that ended the tool, if one did.
	Signal string `json:"signal,omitempty"`
	// Cgroup is "v1" or "v2".
	Cgroup string `json:"cgroup,omitempty"`
	// MemoryKills counts processes the kernel killed for memory in the
	// container (v2 memory.events oom_kill, v1 memory.oom_control oom_kill).
	MemoryKills int64 `json:"memoryKills"`
	// ProcessesRefused counts process creations refused at the process
	// limit (pids.events max).
	ProcessesRefused int64 `json:"processesRefused"`
	// MemoryPeak is the highest program memory sampled, in bytes: anon in
	// memory.stat (v2), total_rss (v1). File cache is left out: the
	// kernel's own peak counts it (ADR 0067, Context 5).
	MemoryPeak int64 `json:"memoryPeak"`
	// ProcessesPeak is the highest process count seen (sampled, and
	// pids.peak where the kernel has it).
	ProcessesPeak int64 `json:"processesPeak"`
	// Samples counts memory samples taken.
	Samples int `json:"samples"`
	// Errors lists counters that could not be read. Any error means the
	// counters cannot prove the run was not cut short.
	Errors []string `json:"errors,omitempty"`
}

// Command-line protocol: waiter STATUS-FILE PROGRAM [ARG...]. The waiter
// re-runs itself with ShimArg first to start the tool (see shim).
const ShimArg = "--siegekit-shim"

// SampleEvery is how often memory and processes are sampled.
const SampleEvery = 200 * time.Millisecond

// oomScore is the tool's OOM score: the highest, so the kernel kills the
// tool before the waiter. Rootless Podman gives every container process 500;
// without raising the tool's, the waiter was killed in 6 of 7 runs where a
// child ran out of memory (ADR 0067). Raising needs no privilege.
const oomScore = "1000"

// forwarded are the signals passed on to the tool.
var forwarded = []os.Signal{syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP, syscall.SIGQUIT, syscall.SIGUSR1, syscall.SIGUSR2}

// Main runs the waiter and returns its exit code.
func Main(args []string) int {
	if len(args) >= 1 && args[0] == ShimArg {
		return shim(args[1:])
	}
	if len(args) < 2 || args[0] == "" || args[1] == "" {
		fmt.Fprintln(os.Stderr, "siegekit-waiter: usage: siegekit-waiter STATUS-FILE PROGRAM [ARG...]")
		return 127
	}
	statusPath, argv := args[0], args[1:]
	cg := findCgroup()
	st := Status{Version: StatusVersion, Cgroup: cg.version}
	if cg.err != nil {
		st.Errors = append(st.Errors, cg.err.Error())
	}
	self, err := os.Executable()
	if err != nil {
		fmt.Fprintf(os.Stderr, "siegekit-waiter: %v\n", err)
		return 127
	}
	// The status file is created before the tool starts, so the tool can
	// never put one there first; it is written through this handle at the end.
	out, err := os.OpenFile(statusPath, os.O_RDWR|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o644) // #nosec G302 G304 -- SiegeKit reads it as another user; the path is SiegeKit's own
	if err != nil {
		fmt.Fprintf(os.Stderr, "siegekit-waiter: create status file: %v\n", err)
		return 127
	}
	defer out.Close()
	sigs := make(chan os.Signal, 8)
	signal.Notify(sigs, forwarded...)
	// The shim raises its own OOM score, then becomes the tool, so every
	// process the tool starts inherits the score with no window in between.
	proc, err := os.StartProcess(self, append([]string{self, ShimArg}, argv...), &os.ProcAttr{
		Files: []*os.File{os.Stdin, os.Stdout, os.Stderr},
		Env:   os.Environ(),
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "siegekit-waiter: start %s: %v\n", argv[0], err)
		return 127
	}
	go func() {
		for s := range sigs {
			_ = proc.Signal(s) // the tool may have exited already
		}
	}()
	stop := make(chan struct{})
	var wg sync.WaitGroup
	if cg.err == nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			cg.sample(&st, stop)
		}()
	}
	st.Exit, st.Signal = reap(proc.Pid)
	close(stop)
	wg.Wait()
	if cg.err == nil {
		cg.final(&st)
	}
	if err := writeStatus(out, st); err != nil {
		// SiegeKit treats a missing status as counters not read.
		fmt.Fprintf(os.Stderr, "siegekit-waiter: write status: %v\n", err)
	}
	return st.Exit
}

// reap waits for every child (as the container's first process the waiter
// adopts orphans) until pid exits, and returns pid's exit code and signal.
func reap(pid int) (int, string) {
	for {
		var ws syscall.WaitStatus
		got, err := syscall.Wait4(-1, &ws, 0, nil)
		if errors.Is(err, syscall.EINTR) {
			continue
		}
		if err != nil {
			// ECHILD: the tool is gone and was reaped elsewhere; cannot happen
			// as the only waiter, so it is reported as an engine-level failure.
			return 127, ""
		}
		if got != pid {
			continue
		}
		switch {
		case ws.Exited():
			return ws.ExitStatus(), ""
		case ws.Signaled():
			return 128 + int(ws.Signal()), unix(ws.Signal())
		}
	}
}

// unix names a signal as the kernel does, such as "SIGKILL".
func unix(s syscall.Signal) string {
	switch s {
	case syscall.SIGKILL:
		return "SIGKILL"
	case syscall.SIGTERM:
		return "SIGTERM"
	case syscall.SIGSEGV:
		return "SIGSEGV"
	case syscall.SIGABRT:
		return "SIGABRT"
	case syscall.SIGINT:
		return "SIGINT"
	}
	return "signal " + strconv.Itoa(int(s))
}

// shim raises its own OOM score and replaces itself with the tool, looked up
// on the container's PATH as the engine would.
func shim(argv []string) int {
	if len(argv) == 0 {
		return 127
	}
	if err := os.WriteFile("/proc/self/oom_score_adj", []byte(oomScore), 0); err != nil {
		// Not fatal: the counters still show kills; the waiter may be the
		// one killed, which SiegeKit reports as exit 137.
		fmt.Fprintf(os.Stderr, "siegekit-waiter: raise OOM score: %v\n", err)
	}
	bin := argv[0]
	if !strings.Contains(bin, "/") {
		p, err := exec.LookPath(bin)
		if err != nil {
			fmt.Fprintf(os.Stderr, "siegekit-waiter: %s: not found on PATH\n", bin)
			return 127
		}
		bin = p
	}
	err := syscall.Exec(bin, argv, os.Environ()) // #nosec G204 -- runs the tool SiegeKit named, inside its sandbox, by design
	fmt.Fprintf(os.Stderr, "siegekit-waiter: run %s: %v\n", argv[0], err)
	if errors.Is(err, syscall.ENOENT) {
		return 127
	}
	return 126
}

// writeStatus replaces the status file's contents with st, whatever the
// tool wrote to it.
func writeStatus(f *os.File, st Status) error {
	b, err := json.Marshal(st)
	if err != nil {
		return err
	}
	if err := f.Truncate(0); err != nil {
		return err
	}
	if _, err := f.WriteAt(b, 0); err != nil {
		return err
	}
	return f.Sync()
}

// ParseStatus reads a status file's contents.
func ParseStatus(b []byte) (Status, error) {
	var st Status
	if len(b) > MaxStatusSize {
		return st, errors.New("status file too large")
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&st); err != nil {
		return st, fmt.Errorf("status file: %w", err)
	}
	if st.Version != StatusVersion {
		return st, fmt.Errorf("status file version %d, want %d", st.Version, StatusVersion)
	}
	if st.MemoryKills < 0 || st.ProcessesRefused < 0 || st.MemoryPeak < 0 || st.ProcessesPeak < 0 || st.Exit < 0 || st.Exit > 255 || len(st.Errors) > 32 {
		return st, errors.New("status file: value out of range")
	}
	return st, nil
}

// cgroup is the container's own cgroup, as the waiter sees it.
type cgroup struct {
	version string
	memory  string // directory with memory.stat
	pids    string // directory with pids.current and pids.events
	err     error
}

// findCgroup finds the waiter's own cgroup and checks it is the one the
// counters are read from: its cgroup.procs must list the waiter, so a host
// or parent cgroup is never read by mistake.
func findCgroup() cgroup {
	if _, err := os.Stat("/sys/fs/cgroup/cgroup.controllers"); err == nil {
		rel, err := selfCgroup()
		if err != nil {
			return cgroup{version: "v2", err: err}
		}
		d := filepath.Join("/sys/fs/cgroup", rel)
		return checkOwn(cgroup{version: "v2", memory: d, pids: d})
	}
	return checkOwn(cgroup{version: "v1", memory: "/sys/fs/cgroup/memory", pids: "/sys/fs/cgroup/pids"})
}

// selfCgroup returns the waiter's cgroup v2 path from /proc/self/cgroup.
func selfCgroup() (string, error) {
	b, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		return "", err
	}
	for _, l := range strings.Split(string(b), "\n") {
		f := strings.SplitN(l, ":", 3)
		if len(f) == 3 && f[0] == "0" && f[1] == "" {
			return f[2], nil
		}
	}
	return "", errors.New("own cgroup not found in /proc/self/cgroup")
}

func checkOwn(c cgroup) cgroup {
	self := strconv.Itoa(os.Getpid())
	for _, d := range []string{c.memory, c.pids} {
		b, err := os.ReadFile(filepath.Join(d, "cgroup.procs"))
		if err != nil {
			c.err = fmt.Errorf("read %s: %w", filepath.Join(d, "cgroup.procs"), err)
			return c
		}
		if !containsLine(string(b), self) {
			c.err = fmt.Errorf("%s does not hold the waiter (pid %s), so it is not the container's own cgroup", d, self)
			return c
		}
	}
	return c
}

func containsLine(s, want string) bool {
	for _, l := range strings.Split(s, "\n") {
		if strings.TrimSpace(l) == want {
			return true
		}
	}
	return false
}

// sample records program memory and processes until stop is closed.
func (c cgroup) sample(st *Status, stop <-chan struct{}) {
	t := time.NewTicker(SampleEvery)
	defer t.Stop()
	memKey := "anon"
	if c.version == "v1" {
		memKey = "total_rss"
	}
	for {
		if v, err := statValue(filepath.Join(c.memory, "memory.stat"), memKey); err == nil {
			st.MemoryPeak = max(st.MemoryPeak, v)
			st.Samples++
		}
		if v, err := readInt(filepath.Join(c.pids, "pids.current")); err == nil {
			st.ProcessesPeak = max(st.ProcessesPeak, v)
		}
		select {
		case <-stop:
			return
		case <-t.C:
		}
	}
}

// final reads the event counters after the tool exited. Each counter that
// cannot be read is an error in the status.
func (c cgroup) final(st *Status) {
	fail := func(what string, err error) { st.Errors = append(st.Errors, what+": "+err.Error()) }
	if st.Samples == 0 {
		fail("memory.stat", errors.New("no sample read"))
	}
	if v, err := readInt(filepath.Join(c.pids, "pids.peak")); err == nil {
		st.ProcessesPeak = max(st.ProcessesPeak, v)
	}
	if v, err := statValue(filepath.Join(c.pids, "pids.events"), "max"); err == nil {
		st.ProcessesRefused = v
	} else {
		fail("pids.events", err)
	}
	if c.version == "v2" {
		if v, err := statValue(filepath.Join(c.memory, "memory.events"), "oom_kill"); err == nil {
			st.MemoryKills = v
		} else {
			fail("memory.events", err)
		}
		return
	}
	if v, err := statValue(filepath.Join(c.memory, "memory.oom_control"), "oom_kill"); err == nil {
		st.MemoryKills = v
	} else {
		fail("memory.oom_control", err)
	}
}

// statValue reads the value of key from a "key value" per line file.
func statValue(path, key string) (int64, error) {
	f, err := os.Open(path) // #nosec G304 -- fixed cgroup files
	if err != nil {
		return 0, err
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	for s.Scan() {
		k, v, ok := strings.Cut(s.Text(), " ")
		if ok && k == key {
			return strconv.ParseInt(strings.TrimSpace(v), 10, 64)
		}
	}
	if err := s.Err(); err != nil {
		return 0, err
	}
	return 0, fmt.Errorf("no %q line", key)
}

// readInt reads a file holding one number.
func readInt(path string) (int64, error) {
	b, err := os.ReadFile(path) // #nosec G304 -- fixed cgroup files
	if err != nil {
		return 0, err
	}
	return strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64)
}

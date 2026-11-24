// Measurement waiter: runs argv[1:] as a child, waits, then reads the
// container's own cgroup counters and writes them to $COUNTERS_OUT.
package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"strings"
	"syscall"
)

func read(p string) string {
	b, err := os.ReadFile(p)
	if err != nil {
		return "ERR " + err.Error()
	}
	return strings.TrimSpace(string(b))
}

func main() {
	cmd := exec.Command(os.Args[1], os.Args[2:]...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	code := 0
	if err := cmd.Start(); err != nil {
		os.Exit(127)
	}
	// Make the tool, not the waiter, the OOM killer's choice (raising is
	// allowed without privileges). OOM_ADJ=0 skips it for comparison.
	adj := "skipped"
	if os.Getenv("OOM_ADJ") != "0" {
		if err := os.WriteFile("/proc/"+itoa(cmd.Process.Pid)+"/oom_score_adj", []byte("1000"), 0); err != nil {
			adj = "ERR " + err.Error()
		} else {
			adj = "1000"
		}
	}
	// reap everything until our child has exited
	for {
		var ws syscall.WaitStatus
		pid, err := syscall.Wait4(-1, &ws, 0, nil)
		if err != nil {
			break
		}
		if pid == cmd.Process.Pid {
			code = ws.ExitStatus()
			if ws.Signaled() {
				code = 128 + int(ws.Signal())
			}
			break
		}
	}
	files := []string{
		"/proc/self/cgroup",
		"/sys/fs/cgroup/pids.events", "/sys/fs/cgroup/pids.peak", "/sys/fs/cgroup/pids.max",
		"/sys/fs/cgroup/memory.events", "/sys/fs/cgroup/memory.events.local", "/sys/fs/cgroup/memory.peak", "/sys/fs/cgroup/memory.max", "/sys/fs/cgroup/memory.oom.group",
		"/sys/fs/cgroup/pids/pids.events", "/sys/fs/cgroup/pids/pids.max",
		"/sys/fs/cgroup/memory/memory.oom_control", "/sys/fs/cgroup/memory/memory.max_usage_in_bytes", "/sys/fs/cgroup/memory/memory.failcnt", "/sys/fs/cgroup/memory/memory.limit_in_bytes",
	}
	m := map[string]string{"child oom_score_adj set": adj, "waiter oom_score_adj": read("/proc/self/oom_score_adj")}
	m["exit"] = func() string { b, _ := json.Marshal(code); return string(b) }()
	for _, f := range files {
		m[f] = read(f)
	}
	b, _ := json.MarshalIndent(m, "", " ")
	if p := os.Getenv("COUNTERS_OUT"); p != "" {
		_ = os.WriteFile(p, b, 0o644)
	} else {
		os.Stdout.Write(b)
	}
	os.Exit(code)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	b := []byte{}
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

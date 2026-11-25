// Package audit appends one line per active run to a local log (ADR 0005):
// when, which target and addresses, which mode and verification, and which
// plugins. Lines are only ever appended.
package audit

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"syscall"
	"time"
)

// Entry is one active run.
type Entry struct {
	Time         time.Time `json:"time"`
	Version      string    `json:"siegekitVersion"`
	Target       string    `json:"target"` // without query, fragment or credentials
	Addresses    []string  `json:"addresses"`
	Mode         string    `json:"mode"`
	Verification string    `json:"verification"` // e.g. "loopback", "typed confirmation", "well-known file"
	Confirmed    string    `json:"confirmedHost,omitempty"`
	Plugins      []string  `json:"plugins"`
	// Environment names the machine and container engine (ADR 0038).
	Environment string `json:"environment,omitempty"`
	// ExtraHeaders names the headers from SIEGEKIT_EXTRA_HEADERS sent on
	// every request (ADR 0070); their values are never logged.
	ExtraHeaders []string `json:"extraHeaders,omitempty"`
}

// MaxSize is the largest log Append writes to; past it, Append fails rather
// than truncate, so the history is never lost silently.
const MaxSize = 64 << 20

// Append writes e as one JSON line to path, creating it with mode 0600. It
// refuses to follow a symlink or to write to anything but a regular file.
func Append(path string, e Entry) error {
	if e.Time.IsZero() {
		return errors.New("audit entry has no time")
	}
	line, err := json.Marshal(e)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE|syscall.O_NOFOLLOW, 0o600) // #nosec G304 -- the log path is SiegeKit's own data directory
	if err != nil {
		return fmt.Errorf("open audit log: %w", err)
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return err
	}
	if !st.Mode().IsRegular() {
		return fmt.Errorf("audit log %s is not a regular file", path)
	}
	if st.Size()+int64(len(line))+1 > MaxSize {
		return fmt.Errorf("audit log %s is larger than %d bytes; move it aside to keep it", path, MaxSize)
	}
	if _, err := f.Write(append(line, '\n')); err != nil {
		return fmt.Errorf("write audit log: %w", err)
	}
	return f.Sync()
}

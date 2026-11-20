package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/Gobbuwu/SiegeKit/docs"
)

func TestRun(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		code int
		out  string
	}{
		{"no args", nil, exitUsage, "Usage"},
		{"version", []string{"version"}, exitOK, "siegekit 0.0.0-dev"},
		{"unknown", []string{"attack"}, exitUsage, "Usage"},
		{"valid plugin", []string{"plugins", "validate", "../../schemas/testdata/valid/passive.json"}, exitOK, "ok"},
		{"invalid plugin", []string{"plugins", "validate", "../../schemas/testdata/invalid/unpinned-image.json"}, exitInvalid, "FAIL"},
		{"missing file", []string{"plugins", "validate", "does-not-exist.json"}, exitInvalid, "FAIL"},
		{"list", []string{"plugins", "list"}, exitOK, "login-throttle       dast     active   built into SiegeKit"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var out, errb bytes.Buffer
			if got := run(tc.args, &out, &errb); got != tc.code {
				t.Fatalf("exit %d, want %d (stderr: %s)", got, tc.code, errb.String())
			}
			if !strings.Contains(out.String()+errb.String(), tc.out) {
				t.Fatalf("output %q does not contain %q", out.String()+errb.String(), tc.out)
			}
		})
	}
}

func TestAgentsCommand(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run([]string{"agents"}, &out, &errb); code != exitOK || out.String() != docs.Agents || !strings.Contains(out.String(), "Never confirm a target for the person") {
		t.Fatalf("exit %d, %d bytes", code, out.Len())
	}
}

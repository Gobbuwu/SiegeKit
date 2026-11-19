package runner

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"testing"
)

var update = flag.Bool("update", false, "rewrite the golden files in testdata/recorded")

// TestRecordedToolOutput converts real reports recorded from the pinned tool
// versions (see testdata/recorded/README.md) and compares the findings with
// golden files. Run with -update after re-recording.
func TestRecordedToolOutput(t *testing.T) {
	for id, file := range map[string]string{
		"bandit":           "bandit.json",
		"checkov":          "results_sarif.sarif",
		"gitleaks":         "gitleaks.sarif",
		"gitleaks-history": "gitleaks-history.sarif",
		"gosec":            "gosec.sarif",
		"trivy":            "trivy.sarif",
	} {
		t.Run(id, func(t *testing.T) {
			m := builtin(t, id)
			if m.Output.File != file {
				t.Fatalf("manifest writes %s, recording is %s", m.Output.File, file)
			}
			fs, err := readReport(filepath.Join("testdata", "recorded", file), m, new(int))
			if err != nil {
				t.Fatal(err)
			}
			if len(fs) == 0 {
				t.Fatal("no findings")
			}
			for i := range fs {
				fs[i].RedactCredentials()
			}
			got, err := json.MarshalIndent(fs, "", "  ")
			if err != nil {
				t.Fatal(err)
			}
			got = append(got, '\n')
			golden := filepath.Join("testdata", "recorded", id+".golden.json")
			if *update {
				if err := os.WriteFile(golden, got, 0o644); err != nil {
					t.Fatal(err)
				}
			}
			want, err := os.ReadFile(golden)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, want) {
				t.Errorf("findings differ from %s; run with -update if the change is intended", golden)
			}
		})
	}
}

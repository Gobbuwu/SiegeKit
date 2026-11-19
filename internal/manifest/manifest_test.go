package manifest

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

const schemaDir = "../../schemas"

func readFixture(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestSchemaFixtures keeps the Go validator and the JSON Schema fixtures in step (ADR 0012).
func TestSchemaFixtures(t *testing.T) {
	for _, tc := range []struct {
		dir   string
		valid bool
	}{{"valid", true}, {"invalid", false}} {
		files, err := filepath.Glob(filepath.Join(schemaDir, "testdata", tc.dir, "*.json"))
		if err != nil {
			t.Fatal(err)
		}
		if len(files) == 0 {
			t.Fatalf("no fixtures in %s", tc.dir)
		}
		for _, f := range files {
			t.Run(tc.dir+"/"+filepath.Base(f), func(t *testing.T) {
				_, err := Parse(readFixture(t, f))
				if tc.valid && err != nil {
					t.Errorf("expected valid, got %v", err)
				}
				if !tc.valid && err == nil {
					t.Errorf("expected rejection, got none")
				}
			})
		}
	}
}

// TestSchemaEnumsMatch fails if the JSON Schema and the Go validator allow different values.
func TestSchemaEnumsMatch(t *testing.T) {
	var s map[string]any
	if err := json.Unmarshal(readFixture(t, filepath.Join(schemaDir, "plugin-manifest.schema.json")), &s); err != nil {
		t.Fatal(err)
	}
	get := func(path ...string) []string {
		var cur any = s
		for _, k := range path {
			m, ok := cur.(map[string]any)
			if !ok {
				t.Fatalf("schema path %v not found", path)
			}
			cur = m[k]
		}
		var out []string
		for _, v := range cur.([]any) {
			out = append(out, v.(string))
		}
		return out
	}
	art := []string{"properties", "tool", "properties", "artifacts", "items", "properties"}
	for _, c := range []struct {
		name   string
		schema []string
		goVals []string
	}{
		{"family", get("properties", "family", "enum"), Families},
		{"mode", get("properties", "mode", "enum"), Modes},
		{"targets", get("properties", "targets", "items", "enum"), Targets},
		{"platform", get(append(slices.Clone(art), "platform", "enum")...), Platforms},
		{"kind", get(append(slices.Clone(art), "kind", "enum")...), Kinds},
		{"gpu", get("properties", "resources", "properties", "gpu", "enum"), GPUModes},
		{"network", get("properties", "network", "enum"), Networks},
		{"format", get("properties", "output", "properties", "format", "enum"), Formats},
		{"parser", get("properties", "output", "properties", "parser", "enum"), Parsers},
	} {
		if !slices.Equal(c.schema, c.goVals) {
			t.Errorf("%s: schema %v != Go %v", c.name, c.schema, c.goVals)
		}
	}
}

func validJSON(t *testing.T) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(readFixture(t, filepath.Join(schemaDir, "testdata", "valid", "passive.json")), &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func mustMarshal(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestRejections(t *testing.T) {
	cases := map[string]func(m map[string]any){
		"timeout above max": func(m map[string]any) {
			m["resources"].(map[string]any)["timeoutSeconds"] = 7200
		},
		"missing destructive":   func(m map[string]any) { delete(m, "destructive") },
		"missing schemaVersion": func(m map[string]any) { delete(m, "schemaVersion") },
		"duplicate target":      func(m map[string]any) { m["targets"] = []string{"repo", "repo"} },
		"empty license": func(m map[string]any) {
			m["tool"].(map[string]any)["license"] = ""
		},
		"uppercase sha": func(m map[string]any) {
			a := m["tool"].(map[string]any)["artifacts"].([]any)[0].(map[string]any)
			a["sha256"] = strings.Repeat("A", 64)
		},
		"image digest differs from sha256": func(m map[string]any) {
			a := m["tool"].(map[string]any)["artifacts"].([]any)[0].(map[string]any)
			a["sha256"] = strings.Repeat("1", 64)
		},
		"output file traversal": func(m map[string]any) { m["output"].(map[string]any)["file"] = "../x" },
		"output file dotdot":    func(m map[string]any) { m["output"].(map[string]any)["file"] = ".." },
		"output file missing":   func(m map[string]any) { delete(m["output"].(map[string]any), "file") },
		"unknown parser":        func(m map[string]any) { m["output"].(map[string]any)["parser"] = "custom" },
		"sarif parser on json":  func(m map[string]any) { m["output"].(map[string]any)["format"] = "json" },
		"data without section": func(m map[string]any) {
			m["run"].(map[string]any)["args"] = []string{"--db", "{data}"}
		},
		"data mount traversal":  func(m map[string]any) { m["data"] = dataSection("/tmp/../etc") },
		"data mount on target":  func(m map[string]any) { m["data"] = dataSection("/target/db") },
		"data mount in workdir": func(m map[string]any) { m["data"] = dataSection("/tmp/work/db") },
		"data update uses target": func(m map[string]any) {
			d := dataSection("/tmp/db")
			d["updateArgs"] = []string{"{target}"}
			m["data"] = d
		},
		"data max age zero": func(m map[string]any) {
			d := dataSection("/tmp/db")
			d["maxAgeDays"] = 0
			m["data"] = d
		},
		"unknown nested field": func(m map[string]any) {
			m["run"].(map[string]any)["shell"] = "/bin/sh"
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			m := validJSON(t)
			mutate(m)
			if _, err := Parse(mustMarshal(t, m)); err == nil {
				t.Fatal("expected rejection")
			}
		})
	}
}

func TestRejectsDuplicateKeys(t *testing.T) {
	b := readFixture(t, filepath.Join(schemaDir, "testdata", "valid", "passive.json"))
	dup := strings.Replace(string(b), `"network": "none"`, `"network": "none", "network": "none"`, 1)
	if dup == string(b) {
		t.Fatal("fixture layout changed; update test")
	}
	_, err := Parse([]byte(dup))
	if err == nil || !strings.Contains(err.Error(), "duplicate key") {
		t.Fatalf("expected duplicate key error, got %v", err)
	}
}

func TestRejectsTrailingData(t *testing.T) {
	b := readFixture(t, filepath.Join(schemaDir, "testdata", "valid", "passive.json"))
	if _, err := Parse(append(b, []byte(` {}`)...)); err == nil {
		t.Fatal("expected rejection of trailing data")
	}
}

func TestRejectsOversize(t *testing.T) {
	big := make([]byte, MaxFileSize+1)
	if _, err := Parse(big); err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Fatalf("expected size error, got %v", err)
	}
}

func TestReportsAllProblems(t *testing.T) {
	_, err := Parse([]byte(`{"schemaVersion":2,"id":"X"}`))
	ve, ok := err.(*ValidationError)
	if !ok {
		t.Fatalf("expected *ValidationError, got %T: %v", err, err)
	}
	if len(ve.Problems) < 5 {
		t.Fatalf("expected many problems, got %v", ve.Problems)
	}
}

func FuzzParse(f *testing.F) {
	for _, dir := range []string{"valid", "invalid"} {
		files, _ := filepath.Glob(filepath.Join(schemaDir, "testdata", dir, "*.json"))
		for _, p := range files {
			if b, err := os.ReadFile(p); err == nil {
				f.Add(b)
			}
		}
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		m, err := Parse(data)
		if err == nil {
			// Anything accepted must still pass validation when re-encoded.
			if _, err := Parse(mustMarshal(t, m)); err != nil {
				t.Fatalf("accepted manifest fails after round trip: %v", err)
			}
		}
	})
}

func dataSection(mount string) map[string]any {
	return map[string]any{"mount": mount, "updateArgs": []string{"update", "--dir", "{data}"}, "maxAgeDays": 7}
}

func TestAcceptsDataSection(t *testing.T) {
	m := validJSON(t)
	m["data"] = dataSection("/tmp/tool/db")
	m["run"].(map[string]any)["args"] = []string{"scan", "--db", "{data}", "{target}"}
	if _, err := Parse(mustMarshal(t, m)); err != nil {
		t.Fatal(err)
	}
}

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
		{"stdout parser", get("properties", "output", "properties", "stdout", "properties", "parser", "enum"), StdoutParsers},
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
		"output file traversal":  func(m map[string]any) { m["output"].(map[string]any)["file"] = "../x" },
		"output file dotdot":     func(m map[string]any) { m["output"].(map[string]any)["file"] = ".." },
		"output file missing":    func(m map[string]any) { delete(m["output"].(map[string]any), "file") },
		"unknown parser":         func(m map[string]any) { m["output"].(map[string]any)["parser"] = "custom" },
		"sarif parser on json":   func(m map[string]any) { m["output"].(map[string]any)["format"] = "json" },
		"nuclei parser on sarif": func(m map[string]any) { m["output"].(map[string]any)["parser"] = "nuclei-jsonl" },
		"ffuf parser on sarif":   func(m map[string]any) { m["output"].(map[string]any)["parser"] = "ffuf-json" },
		"wordlist placeholder without wordlist": func(m map[string]any) {
			m["run"].(map[string]any)["args"] = []string{"-w", "{wordlist}"}
		},
		"wordlist not used": func(m map[string]any) {
			m["run"].(map[string]any)["wordlist"] = map[string]any{"local": "deployed.txt", "deployed": "deployed.txt"}
		},
		"wordlist on repo target": func(m map[string]any) {
			m["run"].(map[string]any)["args"] = []string{"-w", "{wordlist}"}
			m["run"].(map[string]any)["wordlist"] = map[string]any{"local": "deployed.txt", "deployed": "deployed.txt"}
		},
		"unknown wordlist": func(m map[string]any) {
			m["targets"] = []string{"url"}
			m["run"].(map[string]any)["args"] = []string{"-w", "{wordlist}"}
			m["run"].(map[string]any)["wordlist"] = map[string]any{"local": "big.txt", "deployed": "deployed.txt"}
		},
		"schemathesis parser on sarif": func(m map[string]any) { m["output"].(map[string]any)["parser"] = "schemathesis-json" },
		"schemathesis parser without spec": func(m map[string]any) {
			m["output"].(map[string]any)["format"] = "json"
			m["output"].(map[string]any)["parser"] = "schemathesis-json"
		},
		"openapi on repo target": func(m map[string]any) {
			m["run"].(map[string]any)["args"] = []string{"run", "{openapi}"}
		},
		"findings exit code 0": func(m map[string]any) {
			m["run"].(map[string]any)["findingsExitCodes"] = []int{0}
		},
		"findings exit code repeated": func(m map[string]any) {
			m["run"].(map[string]any)["findingsExitCodes"] = []int{1, 1}
		},
		"findings exit code 126": func(m map[string]any) {
			m["run"].(map[string]any)["findingsExitCodes"] = []int{126}
		},
		"too many findings exit codes": func(m map[string]any) {
			m["run"].(map[string]any)["findingsExitCodes"] = []int{1, 2, 3, 4, 5}
		},
		"data without section": func(m map[string]any) {
			m["run"].(map[string]any)["args"] = []string{"--db", "{data}"}
		},
		"config placeholder without config": func(m map[string]any) {
			m["run"].(map[string]any)["args"] = []string{"-autorun", "{config}"}
		},
		"config without placeholder": func(m map[string]any) {
			m["run"].(map[string]any)["config"] = map[string]any{"a": "b"}
		},
		"config not an object": func(m map[string]any) {
			m["run"].(map[string]any)["args"] = []string{"{config}"}
			m["run"].(map[string]any)["config"] = []any{"x"}
		},
		"config unknown placeholder": func(m map[string]any) {
			m["run"].(map[string]any)["args"] = []string{"{config}"}
			m["run"].(map[string]any)["config"] = map[string]any{"a": []any{map[string]any{"b": "{outdir}"}}}
		},
		"config too deep": func(m map[string]any) {
			var v any = "x"
			for range 18 {
				v = map[string]any{"a": v}
			}
			m["run"].(map[string]any)["args"] = []string{"{config}"}
			m["run"].(map[string]any)["config"] = v
		},
		"localOnly passive":     func(m map[string]any) { m["localOnly"] = true },
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

// TestRecordedRequestsRules checks where run.recordedRequests is allowed (ADR 0047).
func TestRecordedRequestsRules(t *testing.T) {
	for _, c := range []struct {
		name   string
		mutate func(m map[string]any)
		want   string
	}{
		{"not ZAP", func(m map[string]any) { m["run"].(map[string]any)["recordedRequests"] = true }, "only for ZAP plugins"},
		{"not local-only", func(m map[string]any) {
			m["tool"].(map[string]any)["name"] = "zap"
			m["run"].(map[string]any)["recordedRequests"] = true
		}, "only for destructive plugins that run on local targets only"},
	} {
		m := validJSON(t)
		c.mutate(m)
		if _, err := Parse(mustMarshal(t, m)); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want %q", c.name, err, c.want)
		}
	}
	// The ZAP attack scan's manifest without its spider job.
	b, err := os.ReadFile("../../plugins/zap-active/plugin.json")
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	if _, err := Parse(mustMarshal(t, m)); err != nil {
		t.Fatalf("zap-active: %v", err)
	}
	c := m["run"].(map[string]any)["config"].(map[string]any)
	c["jobs"] = slices.DeleteFunc(c["jobs"].([]any), func(j any) bool { return j.(map[string]any)["type"] == "spider" })
	if _, err := Parse(mustMarshal(t, m)); err == nil || !strings.Contains(err.Error(), "needs a spider job") {
		t.Errorf("no spider: %v", err)
	}
}

// TestGitleaksRulesRules checks where run.gitleaksRules is allowed and how
// it must be written (ADR 0063), starting from the built-in history scan.
func TestGitleaksRulesRules(t *testing.T) {
	b, err := os.ReadFile("../../plugins/gitleaks-history/plugin.json")
	if err != nil {
		t.Fatal(err)
	}
	load := func() map[string]any {
		var m map[string]any
		if err := json.Unmarshal(b, &m); err != nil {
			t.Fatal(err)
		}
		return m
	}
	parsed, err := Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	if ids := parsed.Run.GitleaksRuleIDs(); !slices.Equal(ids, []string{"env-file-committed", "siegekit-supabase-secret-key", "siegekit-supabase-publishable-key"}) {
		t.Errorf("rule ids %v", ids)
	}
	run := func(m map[string]any) map[string]any { return m["run"].(map[string]any) }
	for _, c := range []struct {
		name   string
		mutate func(m map[string]any)
		want   string
	}{
		{"not gitleaks", func(m map[string]any) { m["tool"].(map[string]any)["name"] = "trufflehog" }, "only for Gitleaks plugins whose only target is repo"},
		{"url target", func(m map[string]any) { m["targets"] = []string{"repo", "url"} }, "only for Gitleaks plugins whose only target is repo"},
		{"id not on its own line", func(m map[string]any) {
			run(m)["gitleaksRules"] = "[[rules]]\nid=\"x-y\"\nregex = '''x'''\n"
		}, "must write each rule's id"},
		{"a rule without a readable id", func(m map[string]any) {
			run(m)["gitleaksRules"] = run(m)["gitleaksRules"].(string) + "\n[[rules]]\nregex = '''x'''\n"
		}, "must write each rule's id"},
		{"duplicate id", func(m map[string]any) {
			run(m)["gitleaksRules"] = "[[rules]]\nid = \"a-b\"\nregex = '''x'''\n[[rules]]\nid = \"a-b\"\nregex = '''y'''\n"
		}, "defines rule \"a-b\" twice"},
		{"too large", func(m map[string]any) {
			run(m)["gitleaksRules"] = "[[rules]]\nid = \"a-b\"\nregex = '''x'''\n#" + strings.Repeat("x", 16<<10)
		}, "UTF-8 text up to 16 KiB"},
		{"env sets the config", func(m map[string]any) {
			run(m)["env"].(map[string]any)["GITLEAKS_CONFIG_TOML"] = "x"
		}, "must not set GITLEAKS_CONFIG"},
		{"repository config not listed", func(m map[string]any) {
			m["repoIgnores"].(map[string]any)["files"] = []string{".gitleaksignore"}
		}, "needs .gitleaks.toml in repoIgnores.files"},
	} {
		m := load()
		c.mutate(m)
		if _, err := Parse(mustMarshal(t, m)); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want %q", c.name, err, c.want)
		}
	}
}

// TestRepoRootRules checks where run.inRepoRoot and output.gitIgnoredNote
// are allowed (ADR 0068), starting from the built-in Gitleaks plugin.
func TestRepoRootRules(t *testing.T) {
	b, err := os.ReadFile("../../plugins/gitleaks/plugin.json")
	if err != nil {
		t.Fatal(err)
	}
	if m, err := Parse(b); err != nil || !m.Run.InRepoRoot || !m.Output.GitIgnoredNote {
		t.Fatalf("gitleaks: %v", err)
	}
	for _, c := range []struct {
		name   string
		mutate func(m map[string]any)
		want   string
	}{
		{"url target", func(m map[string]any) { m["targets"] = []string{"repo", "url"} }, "run.inRepoRoot is only for plugins whose only target is repo"},
		{"{target} in args", func(m map[string]any) { m["run"].(map[string]any)["args"] = []string{"dir", "{target}"} }, "must name the repository as \".\", not {target}"},
		{"{target} inside an arg", func(m map[string]any) { m["run"].(map[string]any)["args"] = []string{"--source={target}"} }, "not {target}"},
		{"note on a history scan", func(m map[string]any) { m["requiresGit"] = true }, "output.gitIgnoredNote is only for secrets plugins"},
		{"note on another family", func(m map[string]any) { m["family"] = "sast" }, "output.gitIgnoredNote is only for secrets plugins"},
	} {
		var m map[string]any
		if err := json.Unmarshal(b, &m); err != nil {
			t.Fatal(err)
		}
		c.mutate(m)
		if _, err := Parse(mustMarshal(t, m)); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want %q", c.name, err, c.want)
		}
	}
}

// TestGoModulesRules checks where run.goModules is allowed (ADR 0066),
// starting from the built-in gosec plugin.
func TestGoModulesRules(t *testing.T) {
	b, err := os.ReadFile("../../plugins/gosec/plugin.json")
	if err != nil {
		t.Fatal(err)
	}
	if m, err := Parse(b); err != nil || !m.Run.GoModules {
		t.Fatalf("gosec: %v", err)
	}
	for _, c := range []struct {
		name   string
		mutate func(m map[string]any)
		want   string
	}{
		{"url target", func(m map[string]any) { m["targets"] = []string{"repo", "url"} }, "run.goModules is only for passive plugins whose only target is repo"},
		{"data section", func(m map[string]any) {
			m["data"] = map[string]any{"mount": "/tmp/x", "updateArgs": []string{"u"}, "maxAgeDays": 7}
		}, "run.goModules is only for passive plugins whose only target is repo, with no data section"},
		{"env sets GOCACHE", func(m map[string]any) { m["run"].(map[string]any)["env"].(map[string]any)["GOCACHE"] = "/tmp/c" }, "must not set GOCACHE"},
		{"env sets GOFLAGS", func(m map[string]any) { m["run"].(map[string]any)["env"].(map[string]any)["GOFLAGS"] = "-mod=mod" }, "must not set GOFLAGS"},
	} {
		var m map[string]any
		if err := json.Unmarshal(b, &m); err != nil {
			t.Fatal(err)
		}
		c.mutate(m)
		if _, err := Parse(mustMarshal(t, m)); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want %q", c.name, err, c.want)
		}
	}
}

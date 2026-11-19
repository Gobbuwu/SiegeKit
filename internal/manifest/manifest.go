// Package manifest loads and validates SiegeKit plugin manifests.
//
// The rules implemented here are the authority (ADR 0012). They mirror
// schemas/plugin-manifest.schema.json and add checks JSON Schema cannot express.
package manifest

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
)

// MaxFileSize is the largest manifest accepted, in bytes.
const MaxFileSize = 64 * 1024

// Allowed enum values. Tests check these against the JSON Schema.
var (
	Families   = []string{"sast", "sca", "secrets", "iac", "dast", "fuzz", "credential-audit"}
	Modes      = []string{"passive", "active", "offline"}
	Targets    = []string{"repo", "url", "openapi", "image", "binary", "hashfile"}
	Platforms  = []string{"linux/amd64", "linux/arm64", "darwin/amd64", "darwin/arm64", "any"}
	Kinds      = []string{"oci-image", "archive", "binary"}
	GPUModes   = []string{"none", "optional", "required"}
	Networks   = []string{"none", "target-only"}
	Formats    = []string{"sarif", "json", "jsonl", "xml", "text"}
	Placeholds = []string{"target", "outdir", "workdir", "threads", "ratelimit"}
)

var (
	reID      = regexp.MustCompile(`^[a-z][a-z0-9-]{1,39}$`)
	reSemver  = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+$`)
	reHTTPS   = regexp.MustCompile(`^https://[^\s]+$`)
	reOCI     = regexp.MustCompile(`^[a-z0-9.-]+(:[0-9]+)?/[^@\s]+@sha256:[a-f0-9]{64}$`)
	reSHA256  = regexp.MustCompile(`^[a-f0-9]{64}$`)
	reArg     = regexp.MustCompile(`^([^{}]|\{(` + strings.Join(Placeholds, "|") + `)\})*$`)
	reHomeURL = regexp.MustCompile(`^https://`)
)

// Manifest describes one plugin. Pointer fields are required fields whose
// zero value would otherwise be indistinguishable from "missing".
type Manifest struct {
	SchemaVersion *int       `json:"schemaVersion"`
	ID            string     `json:"id"`
	Name          string     `json:"name"`
	Version       string     `json:"version"`
	Description   string     `json:"description,omitempty"`
	Family        string     `json:"family"`
	Mode          string     `json:"mode"`
	Destructive   *bool      `json:"destructive"`
	Targets       []string   `json:"targets"`
	Tool          *Tool      `json:"tool"`
	Resources     *Resources `json:"resources"`
	Network       string     `json:"network"`
	Run           *Run       `json:"run"`
	Output        *Output    `json:"output"`
}

// Tool is the upstream tool a plugin runs.
type Tool struct {
	Name      string     `json:"name"`
	Version   string     `json:"version"`
	License   string     `json:"license"`
	Homepage  string     `json:"homepage"`
	Artifacts []Artifact `json:"artifacts"`
}

// Artifact is one pinned download or image of the tool.
type Artifact struct {
	Platform string `json:"platform"`
	Kind     string `json:"kind"`
	Ref      string `json:"ref"`
	SHA256   string `json:"sha256"`
}

// Resources are the limits a plugin runs under.
type Resources struct {
	CPUs              int    `json:"cpus"`
	MemoryMiB         int    `json:"memoryMiB"`
	GPU               string `json:"gpu"`
	TimeoutSeconds    int    `json:"timeoutSeconds"`
	MaxTimeoutSeconds int    `json:"maxTimeoutSeconds"`
}

// Run is how the tool is invoked. Args are passed as a vector, never to a shell.
type Run struct {
	Args []string `json:"args"`
}

// Output is what the tool produces and which parser reads it.
type Output struct {
	Format string `json:"format"`
	Parser string `json:"parser"`
}

// ValidationError lists every rule a manifest breaks.
type ValidationError struct {
	Problems []string
}

func (e *ValidationError) Error() string {
	return "invalid manifest: " + strings.Join(e.Problems, "; ")
}

// Load reads and validates a manifest file.
func Load(path string) (*Manifest, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, MaxFileSize+1))
	if err != nil {
		return nil, err
	}
	return Parse(data)
}

// Parse decodes and validates manifest JSON.
func Parse(data []byte) (*Manifest, error) {
	if len(data) > MaxFileSize {
		return nil, fmt.Errorf("manifest larger than %d bytes", MaxFileSize)
	}
	if err := rejectDuplicateKeys(data); err != nil {
		return nil, fmt.Errorf("decode manifest: %w", err)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var m Manifest
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("decode manifest: %w", err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("decode manifest: unexpected data after the JSON object")
	}
	if err := m.Validate(); err != nil {
		return nil, err
	}
	return &m, nil
}

// Validate checks every rule and returns a *ValidationError listing all problems.
func (m *Manifest) Validate() error {
	var p []string
	add := func(format string, a ...any) { p = append(p, fmt.Sprintf(format, a...)) }

	if m.SchemaVersion == nil || *m.SchemaVersion != 1 {
		add("schemaVersion must be 1")
	}
	if !reID.MatchString(m.ID) {
		add("id %q must match %s", m.ID, reID)
	}
	if n := len([]rune(m.Name)); n < 1 || n > 80 {
		add("name must be 1 to 80 characters")
	}
	if !reSemver.MatchString(m.Version) {
		add("version %q must be MAJOR.MINOR.PATCH", m.Version)
	}
	if len([]rune(m.Description)) > 500 {
		add("description must be at most 500 characters")
	}
	checkEnum(&p, "family", m.Family, Families)
	checkEnum(&p, "mode", m.Mode, Modes)
	if m.Destructive == nil {
		add("destructive is required")
	}
	if len(m.Targets) == 0 {
		add("targets must list at least one target kind")
	}
	seen := map[string]bool{}
	for i, t := range m.Targets {
		checkEnum(&p, fmt.Sprintf("targets[%d]", i), t, Targets)
		if seen[t] {
			add("targets[%d] %q is duplicated", i, t)
		}
		seen[t] = true
	}
	m.validateTool(&p)
	m.validateResources(&p)
	checkEnum(&p, "network", m.Network, Networks)
	if m.Run == nil || len(m.Run.Args) == 0 {
		add("run.args must have at least one argument")
	} else {
		for i, a := range m.Run.Args {
			if !reArg.MatchString(a) {
				add("run.args[%d] %q uses braces other than an allowed placeholder {%s}", i, a, strings.Join(Placeholds, "}, {"))
			}
		}
	}
	if m.Output == nil {
		add("output is required")
	} else {
		checkEnum(&p, "output.format", m.Output.Format, Formats)
		if !reID.MatchString(m.Output.Parser) {
			add("output.parser %q must match %s", m.Output.Parser, reID)
		}
	}

	// Cross-field safety rules (ADR 0004, 0005).
	if (m.Mode == "passive" || m.Mode == "offline") && m.Network != "none" {
		add("%s plugins must use network \"none\"", m.Mode)
	}
	if m.Network == "target-only" && m.Mode != "active" {
		add("network \"target-only\" is only allowed for active plugins")
	}
	if m.Destructive != nil && *m.Destructive && m.Mode != "active" {
		add("only active plugins can be destructive")
	}

	if len(p) > 0 {
		return &ValidationError{Problems: p}
	}
	return nil
}

func (m *Manifest) validateTool(p *[]string) {
	t := m.Tool
	if t == nil {
		*p = append(*p, "tool is required")
		return
	}
	if t.Name == "" {
		*p = append(*p, "tool.name is required")
	}
	if t.Version == "" {
		*p = append(*p, "tool.version is required")
	}
	if t.License == "" {
		*p = append(*p, "tool.license is required")
	}
	if !reHomeURL.MatchString(t.Homepage) {
		*p = append(*p, "tool.homepage must start with https://")
	}
	if len(t.Artifacts) == 0 {
		*p = append(*p, "tool.artifacts must list at least one artifact")
	}
	for i, a := range t.Artifacts {
		f := fmt.Sprintf("tool.artifacts[%d]", i)
		checkEnum(p, f+".platform", a.Platform, Platforms)
		checkEnum(p, f+".kind", a.Kind, Kinds)
		switch a.Kind {
		case "oci-image":
			if !reOCI.MatchString(a.Ref) {
				*p = append(*p, fmt.Sprintf("%s.ref must be an image reference pinned by @sha256 digest", f))
			}
		case "archive", "binary":
			if !reHTTPS.MatchString(a.Ref) {
				*p = append(*p, fmt.Sprintf("%s.ref must be an https:// URL", f))
			}
		}
		if !reSHA256.MatchString(a.SHA256) {
			*p = append(*p, fmt.Sprintf("%s.sha256 must be 64 lowercase hex characters", f))
		}
	}
}

func (m *Manifest) validateResources(p *[]string) {
	r := m.Resources
	if r == nil {
		*p = append(*p, "resources is required")
		return
	}
	if r.CPUs < 1 || r.CPUs > 256 {
		*p = append(*p, "resources.cpus must be 1 to 256")
	}
	if r.MemoryMiB < 64 || r.MemoryMiB > 262144 {
		*p = append(*p, "resources.memoryMiB must be 64 to 262144")
	}
	checkEnum(p, "resources.gpu", r.GPU, GPUModes)
	if r.TimeoutSeconds < 1 {
		*p = append(*p, "resources.timeoutSeconds must be at least 1")
	}
	if r.MaxTimeoutSeconds < 1 {
		*p = append(*p, "resources.maxTimeoutSeconds must be at least 1")
	}
	if r.TimeoutSeconds > r.MaxTimeoutSeconds {
		*p = append(*p, "resources.timeoutSeconds must not exceed maxTimeoutSeconds")
	}
}

func checkEnum(p *[]string, field, v string, allowed []string) {
	for _, a := range allowed {
		if v == a {
			return
		}
	}
	*p = append(*p, fmt.Sprintf("%s %q must be one of: %s", field, v, strings.Join(allowed, ", ")))
}

// rejectDuplicateKeys fails if any JSON object repeats a key. encoding/json
// silently keeps the last value, which would let a manifest show one value to
// a reviewer and use another.
func rejectDuplicateKeys(data []byte) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var walk func(depth int) error
	walk = func(depth int) error {
		if depth > 32 {
			return errors.New("JSON nested too deeply")
		}
		tok, err := dec.Token()
		if err != nil {
			return err
		}
		d, ok := tok.(json.Delim)
		if !ok {
			return nil
		}
		switch d {
		case '{':
			keys := map[string]bool{}
			for dec.More() {
				kt, err := dec.Token()
				if err != nil {
					return err
				}
				k, _ := kt.(string)
				if keys[k] {
					return fmt.Errorf("duplicate key %q", k)
				}
				keys[k] = true
				if err := walk(depth + 1); err != nil {
					return err
				}
			}
		case '[':
			for dec.More() {
				if err := walk(depth + 1); err != nil {
					return err
				}
			}
		}
		_, err = dec.Token() // closing delimiter
		return err
	}
	return walk(0)
}

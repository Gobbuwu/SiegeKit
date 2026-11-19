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
	"slices"
	"sort"
	"strings"

	"github.com/Gobbuwu/SiegeKit/internal/sandbox"
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
	Placeholds = []string{"target", "outdir", "workdir", "threads", "ratelimit", "data", "config"}
	// ConfigPlaceholds are the placeholders allowed in run.config strings.
	ConfigPlaceholds = []string{"target", "target-regex"}
	Parsers          = []string{"sarif", "sarif-gitleaks", "sarif-checkov", "sarif-zap", "bandit-json"}
)

var (
	reID           = regexp.MustCompile(`^[a-z][a-z0-9-]{1,39}$`)
	reSemver       = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+$`)
	reHTTPS        = regexp.MustCompile(`^https://[^\s]+$`)
	reOCI          = regexp.MustCompile(`^[a-z0-9.-]+(:[0-9]+)?/[^@\s]+@sha256:[a-f0-9]{64}$`)
	reSHA256       = regexp.MustCompile(`^[a-f0-9]{64}$`)
	reArg          = regexp.MustCompile(`^([^{}]|\{(` + strings.Join(Placeholds, "|") + `)\})*$`)
	reHomeURL      = regexp.MustCompile(`^https://`)
	reOutFile      = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$`)
	reApplies      = regexp.MustCompile(`^[A-Za-z0-9*?._-]{1,64}$`)
	reIgnoreFile   = regexp.MustCompile(`^\.?[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
	reIgnoreMarker = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9:_.-]{2,63}$`)
	reMount        = regexp.MustCompile(`^/(tmp|data)(/[a-z0-9_-][a-z0-9._-]*)+$`)
	reUpdArg       = regexp.MustCompile(`^([^{}]|\{(data|threads)\})*$`)
	reConfigStr    = regexp.MustCompile(`^([^{}]|\{(` + strings.Join(ConfigPlaceholds, "|") + `)\})*$`)
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
	Data          *Data      `json:"data,omitempty"`
	// AppliesTo lists file name patterns (path.Match syntax, matched against
	// base names). If set, the plugin is skipped when the target has no
	// matching file, so "0 findings" never stands for "nothing was scanned".
	AppliesTo []string `json:"appliesTo,omitempty"`
	// RequiresGit skips the plugin, saying so, when the target is not a git
	// repository (no .git at its top level).
	RequiresGit bool `json:"requiresGit,omitempty"`
	// RepoIgnores names what in the scanned repository can make the tool
	// leave out findings, so reports can say so (owner decision 2026-11-19:
	// obey such settings, but make them visible).
	RepoIgnores *RepoIgnores `json:"repoIgnores,omitempty"`
	// LocalOnly limits an active plugin to local-mode targets (ADR 0023):
	// deployed runs skip it, saying so.
	LocalOnly bool `json:"localOnly,omitempty"`
}

// RepoIgnores describes the scanned repository's own ways of hiding
// findings from the tool.
type RepoIgnores struct {
	// Files are settings files at the target's top level that the tool
	// reads, such as ".gitleaksignore".
	Files []string `json:"files,omitempty"`
	// Marker is an inline comment that hides a finding, such as
	// "gitleaks:allow". SiegeKit counts the lines that carry it. Set it only
	// for tools that do not report what they suppressed.
	Marker string `json:"marker,omitempty"`
}

// Data is downloadable data the tool needs, such as a vulnerability
// database (ADR 0014).
type Data struct {
	Mount      string   `json:"mount"`      // path inside the container
	UpdateArgs []string `json:"updateArgs"` // arguments for the update run
	MaxAgeDays int      `json:"maxAgeDays"` // warn when older
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
	// Env is extra environment for the tool (sandbox.CheckEnv rules).
	// Values are passed as written; placeholders are not substituted.
	Env map[string]string `json:"env,omitempty"`
	// Config is a JSON object that SiegeKit writes to a file for the tool and
	// mounts read-only; {config} in Args is its path (ADR 0023). String
	// values may use {target} and {target-regex}, which are substituted as
	// JSON strings, so a target cannot change the file's structure.
	Config map[string]any `json:"config,omitempty"`
}

// Output is what the tool produces and which parser reads it.
type Output struct {
	Format string `json:"format"`
	Parser string `json:"parser"`
	File   string `json:"file"` // report file name inside {outdir}
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
	f, err := os.Open(path) // #nosec G304 -- the manifest file the user named
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
	if m.Data != nil {
		if !reMount.MatchString(m.Data.Mount) || m.Data.Mount == "/tmp/work" || strings.HasPrefix(m.Data.Mount, "/tmp/work/") {
			add("data.mount %q must be a path under /tmp or /data (not /tmp/work) matching %s", m.Data.Mount, reMount)
		}
		if len(m.Data.UpdateArgs) == 0 {
			add("data.updateArgs must have at least one argument")
		}
		for i, a := range m.Data.UpdateArgs {
			if !reUpdArg.MatchString(a) {
				add("data.updateArgs[%d] %q may only use the placeholders {data} and {threads}", i, a)
			}
		}
		if m.Data.MaxAgeDays < 1 || m.Data.MaxAgeDays > 90 {
			add("data.maxAgeDays must be 1 to 90")
		}
	} else if m.Run != nil {
		for i, a := range m.Run.Args {
			if strings.Contains(a, "{data}") {
				add("run.args[%d] uses {data} but the manifest has no data section", i)
			}
		}
	}
	if m.Run != nil {
		if err := sandbox.CheckEnv(m.Run.Env); err != nil {
			add("run.env: %v", err)
		}
		uses := slices.ContainsFunc(m.Run.Args, func(a string) bool { return strings.Contains(a, "{config}") })
		switch {
		case m.Run.Config != nil && len(m.Run.Config) == 0:
			// An empty object would be dropped when the manifest is
			// written again (found by FuzzParse in CI, 2026-11-19).
			add("run.config is empty")
		case m.Run.Config == nil && uses:
			add("run.args uses {config} but the manifest has no run.config")
		case m.Run.Config != nil && !uses:
			add("run.config is set but no run.args entry uses {config}")
		}
		if m.Run.Config != nil {
			checkConfig(&p, "run.config", m.Run.Config, 0)
		}
	}
	if m.LocalOnly && m.Mode != "active" {
		add("localOnly is only allowed for active plugins")
	}
	if m.AppliesTo != nil && len(m.AppliesTo) == 0 {
		add("appliesTo must not be empty when present")
	}
	for i, pat := range m.AppliesTo {
		if !reApplies.MatchString(pat) {
			add("appliesTo[%d] %q must be a file name pattern matching %s", i, pat, reApplies)
		}
	}
	if r := m.RepoIgnores; r != nil {
		if len(r.Files) == 0 && r.Marker == "" {
			add("repoIgnores must name files or a marker")
		}
		if len(r.Files) > 8 {
			add("repoIgnores.files has more than 8 entries")
		}
		for i, f := range r.Files {
			if !reIgnoreFile.MatchString(f) {
				add("repoIgnores.files[%d] %q must be a plain file name matching %s", i, f, reIgnoreFile)
			}
		}
		if r.Marker != "" && !reIgnoreMarker.MatchString(r.Marker) {
			add("repoIgnores.marker %q must match %s", r.Marker, reIgnoreMarker)
		}
	}
	if m.Output == nil {
		add("output is required")
	} else {
		checkEnum(&p, "output.format", m.Output.Format, Formats)
		checkEnum(&p, "output.parser", m.Output.Parser, Parsers)
		if !reOutFile.MatchString(m.Output.File) {
			add("output.file %q must be a plain file name matching %s", m.Output.File, reOutFile)
		}
		if strings.HasPrefix(m.Output.Parser, "sarif") && m.Output.Format != "sarif" {
			add("output.parser %q needs output.format \"sarif\"", m.Output.Parser)
		}
		if m.Output.Parser == "bandit-json" && m.Output.Format != "json" {
			add("output.parser \"bandit-json\" needs output.format \"json\"")
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

// checkConfig checks that every string in a run.config value uses only the
// allowed placeholders, and limits nesting.
func checkConfig(p *[]string, path string, v any, depth int) {
	if depth > 16 {
		*p = append(*p, fmt.Sprintf("%s is nested more than 16 levels", path))
		return
	}
	switch t := v.(type) {
	case string:
		if !reConfigStr.MatchString(t) {
			*p = append(*p, fmt.Sprintf("%s %q uses braces other than an allowed placeholder {%s}", path, t, strings.Join(ConfigPlaceholds, "}, {")))
		}
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			checkConfig(p, path+"."+k, t[k], depth+1)
		}
	case []any:
		for i, x := range t {
			checkConfig(p, fmt.Sprintf("%s[%d]", path, i), x, depth+1)
		}
	}
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
			} else if !strings.HasSuffix(a.Ref, "@sha256:"+a.SHA256) {
				*p = append(*p, fmt.Sprintf("%s.sha256 must equal the image digest in ref", f))
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

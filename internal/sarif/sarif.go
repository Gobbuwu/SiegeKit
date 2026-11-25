// Package sarif reads the subset of SARIF 2.1.0 that SiegeKit needs and
// converts results to findings. Tool output is untrusted input (threat model T7):
// size is limited and nothing in it is executed or interpreted beyond decoding.
package sarif

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/Gobbuwu/SiegeKit/internal/findings"
)

// MaxSize is the largest SARIF document accepted, in bytes.
const MaxSize = 256 << 20

// Log is a SARIF log (subset).
type Log struct {
	Version string `json:"version"`
	Runs    []Run  `json:"runs"`
}

// Run is one tool run.
type Run struct {
	Tool    Tool     `json:"tool"`
	Results []Result `json:"results"`
}

// Tool describes the analysis tool.
type Tool struct {
	Driver Driver `json:"driver"`
}

// Driver is the tool component that produced results.
type Driver struct {
	Name  string `json:"name"`
	Rules []Rule `json:"rules"`
}

// Rule is a reporting descriptor.
type Rule struct {
	ID               string         `json:"id"`
	Name             string         `json:"name"`
	ShortDescription *Message       `json:"shortDescription"`
	HelpURI          string         `json:"helpUri"`
	Properties       map[string]any `json:"properties"`
	// Relationships link a rule to taxonomies such as CWE (SARIF 3.49.15).
	Relationships []Relationship `json:"relationships"`
}

// Relationship links a rule to a taxonomy entry.
type Relationship struct {
	Target struct {
		ID            string `json:"id"`
		ToolComponent struct {
			Name string `json:"name"`
		} `json:"toolComponent"`
	} `json:"target"`
}

// Message is a SARIF message.
type Message struct {
	Text string `json:"text"`
}

// Result is one SARIF result.
type Result struct {
	RuleID     string         `json:"ruleId"`
	RuleIndex  *int           `json:"ruleIndex"`
	Level      string         `json:"level"`
	Message    Message        `json:"message"`
	Locations  []Location     `json:"locations"`
	Properties map[string]any `json:"properties"`
	// Suppressions are set when the scanned code asked the tool to ignore
	// this result (for example a "#nosec" or "checkov:skip" comment).
	Suppressions []Suppression `json:"suppressions"`
}

// Suppression is a SARIF suppression object.
type Suppression struct {
	Kind   string `json:"kind"`
	Status string `json:"status"`
}

// suppressed reports whether a result is suppressed: it has a suppression
// that is accepted (no status means accepted). One under review or rejected
// does not hide the result.
func (r *Result) suppressed() bool {
	for _, s := range r.Suppressions {
		if s.Status == "" || s.Status == "accepted" {
			return true
		}
	}
	return false
}

// Location is a SARIF location (physical only).
type Location struct {
	PhysicalLocation struct {
		ArtifactLocation struct {
			URI string `json:"uri"`
		} `json:"artifactLocation"`
		Region struct {
			StartLine int `json:"startLine"`
			Snippet   *struct {
				Text string `json:"text"`
			} `json:"snippet"`
		} `json:"region"`
	} `json:"physicalLocation"`
}

// Read decodes a SARIF log, enforcing the size limit and version.
func Read(r io.Reader) (*Log, error) {
	data, err := io.ReadAll(io.LimitReader(r, MaxSize+1))
	if err != nil {
		return nil, err
	}
	if len(data) > MaxSize {
		return nil, fmt.Errorf("SARIF larger than %d bytes", MaxSize)
	}
	var l Log
	if err := json.Unmarshal(data, &l); err != nil {
		return nil, fmt.Errorf("decode SARIF: %w", err)
	}
	if l.Version != "2.1.0" {
		return nil, fmt.Errorf("unsupported SARIF version %q (want 2.1.0)", l.Version)
	}
	return &l, nil
}

// Options control conversion.
type Options struct {
	Plugin string // plugin id recorded as the source
	Family string // test family, e.g. "secrets"
	// Parser selects tool-specific severity rules: "sarif" (or empty) for
	// plain SARIF, "sarif-gitleaks" or "sarif-checkov".
	Parser string
	// MountPath is where the target was mounted in the container (for example
	// "/target"). It is removed from the start of URIs so locations are
	// relative to the target directory.
	MountPath string
	// Suppressed, if set, is increased by one for each result the scanned
	// code suppressed. Such results are not returned as findings.
	Suppressed *int
}

// Parsers lists the accepted Options.Parser values.
var Parsers = []string{"sarif", "sarif-gitleaks", "sarif-checkov", "sarif-zap"}

var reCWE = regexp.MustCompile(`(?i)\bCWE-([0-9]{1,5})\b`)

// ToFindings converts every result in the log.
func ToFindings(l *Log, opt Options) ([]findings.Finding, error) {
	if opt.Plugin == "" || opt.Family == "" {
		return nil, errors.New("plugin and family are required")
	}
	if opt.Parser == "" {
		opt.Parser = "sarif"
	}
	if !slices.Contains(Parsers, opt.Parser) {
		return nil, fmt.Errorf("unknown parser %q", opt.Parser)
	}
	var out []findings.Finding
	for _, run := range l.Runs {
		rules := map[string]Rule{}
		for _, r := range run.Tool.Driver.Rules {
			rules[r.ID] = r
		}
		for _, res := range run.Results {
			if res.suppressed() {
				if opt.Suppressed != nil {
					*opt.Suppressed++
				}
				continue
			}
			rule, ok := rules[res.RuleID]
			if !ok && res.RuleIndex != nil && *res.RuleIndex >= 0 && *res.RuleIndex < len(run.Tool.Driver.Rules) {
				rule = run.Tool.Driver.Rules[*res.RuleIndex]
			}
			ruleID := res.RuleID
			if ruleID == "" {
				ruleID = rule.ID
			}
			f := findings.Finding{
				RuleID:   ruleID,
				Title:    title(rule, ruleID),
				Message:  stripMount(res.Message.Text, opt.MountPath),
				Severity: adjust(opt.Parser, ruleID, severity(res, rule)),
				CWEs:     cwes(rule),
				HelpURI:  findings.SafeHelpURI(helpURI(opt.Parser, rule)),
				Family:   opt.Family,
				Sources:  []findings.Source{{Plugin: opt.Plugin, RuleID: ruleID}},
			}
			if len(res.Locations) > 0 {
				pl := res.Locations[0].PhysicalLocation
				f.Location = findings.Location{URI: RelURI(pl.ArtifactLocation.URI, opt.MountPath), StartLine: pl.Region.StartLine}
				if pl.Region.Snippet != nil {
					f.Snippet = pl.Region.Snippet.Text
				}
			}
			if opt.Parser == "sarif-gitleaks" && ruleID == PublishableKeyRule {
				f.Message = publishableKeyMessage
			}
			if opt.Family == "secrets" {
				// Never carry a secret value forward (ADR 0007, threat model T9).
				f.Snippet = findings.MaskSecret(strings.TrimSpace(f.Snippet))
			}
			f.ComputeFingerprint()
			out = append(out, f)
		}
	}
	return out, nil
}

// helpURI is the rule's help link. ZAP leaves helpUri empty and lists
// reference links in its "references" property; the first safe one is used.
func helpURI(parser string, r Rule) string {
	if r.HelpURI != "" || parser != "sarif-zap" {
		return r.HelpURI
	}
	refs, _ := r.Properties["references"].([]any)
	for _, x := range refs {
		if s, ok := x.(string); ok && findings.SafeHelpURI(s) != "" {
			return s
		}
	}
	return ""
}

// PublishableKeyRule is SiegeKit's Gitleaks rule for Supabase publishable
// keys (ADR 0063), which are public by design.
const PublishableKeyRule = "siegekit-supabase-publishable-key"

const publishableKeyMessage = "A Supabase publishable key (sb_publishable_). It is meant to be public, so this is not a leak: anyone can use it to call the project's API, and only Row Level Security keeps each table's rows private. Check that every table the key can reach has Row Level Security enabled with policies that limit rows to their owners."

// adjust applies tool-specific severity rules.
//
// Gitleaks results carry no level or score, but every one is a credential in
// the code, so they are high, except SiegeKit's own rule for Supabase
// publishable keys, which are public by design and info (ADR 0063).
// Checkov's open-source edition marks every failed check "error" and has no
// severity data, so its results are capped at medium rather than all being
// reported as high.
func adjust(parser, ruleID string, s findings.Severity) findings.Severity {
	switch parser {
	case "sarif-gitleaks":
		if ruleID == PublishableKeyRule {
			return findings.Info
		}
		return findings.High
	case "sarif-checkov":
		return min(s, findings.Medium)
	}
	return s
}

// RelURI removes the container mount path from the start of a URI. Tools
// report it as "/target/x", "file:///target/x" or "target/x", or, run from
// the repository's top level (run.inRepoRoot, ADR 0068), as "./x" or "x".
func RelURI(uri, mount string) string {
	mount = strings.Trim(mount, "/")
	if mount == "" {
		return uri
	}
	if rest, ok := strings.CutPrefix(uri, "./"); ok && rest != "" {
		return rest
	}
	for _, p := range []string{"file:///" + mount + "/", "/" + mount + "/", mount + "/"} {
		if rest, ok := strings.CutPrefix(uri, p); ok && rest != "" {
			return rest
		}
	}
	return uri
}

// stripMount removes the container mount path from paths in a message, so
// "/target/app/x.py" reads "app/x.py" as in the finding's location. Only a
// path at the start of the message or after a space, quote or bracket is
// changed, so "src/target/x" stays as it is.
func stripMount(msg, mount string) string {
	mount = strings.Trim(mount, "/")
	if mount == "" {
		return msg
	}
	re := regexp.MustCompile(`(^|[\s'"(\[])(?:file://)?/` + regexp.QuoteMeta(mount) + `/`)
	return re.ReplaceAllString(msg, "$1")
}

func title(r Rule, id string) string {
	if r.ShortDescription != nil && r.ShortDescription.Text != "" {
		return r.ShortDescription.Text
	}
	if r.Name != "" {
		return r.Name
	}
	return id
}

// severity uses the rule's numeric "security-severity" property when present
// (the convention used by GitHub code scanning: 9.0+ critical, 7.0+ high,
// 4.0+ medium, above 0 low), otherwise the result level.
func severity(res Result, r Rule) findings.Severity {
	for _, props := range []map[string]any{res.Properties, r.Properties} {
		if v, ok := props["security-severity"]; ok {
			var score float64
			switch t := v.(type) {
			case string:
				s, err := strconv.ParseFloat(t, 64)
				if err != nil {
					continue
				}
				score = s
			case float64:
				score = t
			default:
				continue
			}
			switch {
			case score >= 9:
				return findings.Critical
			case score >= 7:
				return findings.High
			case score >= 4:
				return findings.Medium
			case score > 0:
				return findings.Low
			default:
				return findings.Info
			}
		}
	}
	switch res.Level {
	case "error":
		return findings.High
	case "warning", "": // SARIF's default level is "warning".
		return findings.Medium
	case "note":
		return findings.Low
	default:
		return findings.Info
	}
}

func cwes(r Rule) []string {
	seen := map[string]bool{}
	var out []string
	var visit func(v any)
	visit = func(v any) {
		switch t := v.(type) {
		case string:
			for _, m := range reCWE.FindAllStringSubmatch(t, -1) {
				num := strings.TrimLeft(m[1], "0")
				if num == "" {
					continue
				}
				id := "CWE-" + num
				if !seen[id] {
					seen[id] = true
					out = append(out, id)
				}
			}
		case []any:
			for _, x := range t {
				visit(x)
			}
		}
	}
	for _, k := range []string{"tags", "cwe"} {
		visit(r.Properties[k])
	}
	for _, rel := range r.Relationships {
		if strings.EqualFold(rel.Target.ToolComponent.Name, "CWE") {
			visit("CWE-" + rel.Target.ID)
		}
	}
	return out
}

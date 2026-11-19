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
	Properties       map[string]any `json:"properties"`
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
}

var reCWE = regexp.MustCompile(`(?i)\bCWE-([0-9]{1,5})\b`)

// ToFindings converts every result in the log.
func ToFindings(l *Log, opt Options) ([]findings.Finding, error) {
	if opt.Plugin == "" || opt.Family == "" {
		return nil, errors.New("plugin and family are required")
	}
	var out []findings.Finding
	for _, run := range l.Runs {
		rules := map[string]Rule{}
		for _, r := range run.Tool.Driver.Rules {
			rules[r.ID] = r
		}
		for _, res := range run.Results {
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
				Message:  res.Message.Text,
				Severity: severity(res, rule),
				CWEs:     cwes(rule),
				Family:   opt.Family,
				Sources:  []findings.Source{{Plugin: opt.Plugin, RuleID: ruleID}},
			}
			if len(res.Locations) > 0 {
				pl := res.Locations[0].PhysicalLocation
				f.Location = findings.Location{URI: pl.ArtifactLocation.URI, StartLine: pl.Region.StartLine}
				if pl.Region.Snippet != nil {
					f.Snippet = pl.Region.Snippet.Text
				}
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
	return out
}

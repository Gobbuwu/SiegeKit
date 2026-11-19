// Package findings is SiegeKit's tool-independent model of a security finding
// (ADR 0007).
package findings

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"
)

// Severity is SiegeKit's single severity scale.
type Severity int

// Severities from least to most severe.
const (
	Info Severity = iota
	Low
	Medium
	High
	Critical
)

var severityNames = []string{"info", "low", "medium", "high", "critical"}

func (s Severity) String() string {
	if s < Info || s > Critical {
		return "unknown"
	}
	return severityNames[s]
}

// ParseSeverity converts a name such as "high" to a Severity.
func ParseSeverity(name string) (Severity, error) {
	for i, n := range severityNames {
		if strings.EqualFold(name, n) {
			return Severity(i), nil
		}
	}
	return Info, fmt.Errorf("unknown severity %q (want one of %s)", name, strings.Join(severityNames, ", "))
}

// MarshalText encodes the severity as its name.
func (s Severity) MarshalText() ([]byte, error) { return []byte(s.String()), nil }

// UnmarshalText decodes a severity name.
func (s *Severity) UnmarshalText(b []byte) error {
	v, err := ParseSeverity(string(b))
	if err != nil {
		return err
	}
	*s = v
	return nil
}

// Location is where a finding was observed: a file and line, or a URL.
type Location struct {
	URI       string `json:"uri"`
	StartLine int    `json:"startLine,omitempty"`
}

// Source records which plugin and rule reported a finding.
type Source struct {
	Plugin string `json:"plugin"`
	RuleID string `json:"ruleId"`
}

// Finding is one normalized result.
type Finding struct {
	RuleID     string   `json:"ruleId"`
	Title      string   `json:"title"`
	Message    string   `json:"message"`
	Severity   Severity `json:"severity"`
	CWEs       []string `json:"cwes,omitempty"`
	Location   Location `json:"location"`
	Snippet    string   `json:"snippet,omitempty"`
	Family     string   `json:"family"`
	Sources    []Source `json:"sources"`
	Confidence string   `json:"confidence,omitempty"`
	// HelpURI is the tool's page about the rule (https only), for fixing it.
	HelpURI string `json:"helpUri,omitempty"`
	// Fingerprint identifies the same issue across runs and tools.
	Fingerprint string `json:"fingerprint"`
}

// key is what makes two findings "the same issue": the location plus the
// weakness. When CWEs are known, different tools agree on them even though
// their rule IDs differ, so they deduplicate across tools. Dependency
// findings are keyed by advisory ID instead: one manifest line can carry many
// different vulnerabilities that share a CWE.
func (f *Finding) key() string {
	what := "rule:" + f.RuleID
	if f.Family == "sca" {
		what = "advisory:" + f.RuleID
	} else if len(f.CWEs) > 0 {
		c := append([]string(nil), f.CWEs...)
		sort.Strings(c)
		what = "cwe:" + strings.Join(c, ",")
	}
	return fmt.Sprintf("%s|%d|%s", f.Location.URI, f.Location.StartLine, what)
}

// ComputeFingerprint sets f.Fingerprint from its key.
func (f *Finding) ComputeFingerprint() {
	sum := sha256.Sum256([]byte(f.key()))
	f.Fingerprint = hex.EncodeToString(sum[:16])
}

// Dedupe merges findings with the same fingerprint, keeping the highest
// severity and listing every source. The result is sorted most severe first,
// then by location, so output is stable.
func Dedupe(in []Finding) []Finding {
	byFP := map[string]int{}
	var out []Finding
	for _, f := range in {
		if f.Fingerprint == "" {
			f.ComputeFingerprint()
		}
		i, ok := byFP[f.Fingerprint]
		if !ok {
			byFP[f.Fingerprint] = len(out)
			f.Sources = append([]Source(nil), f.Sources...)
			out = append(out, f)
			continue
		}
		existing := &out[i]
		if existing.HelpURI == "" {
			existing.HelpURI = f.HelpURI
		}
		if f.Severity > existing.Severity {
			existing.Severity = f.Severity
		}
		for _, s := range f.Sources {
			if !containsSource(existing.Sources, s) {
				existing.Sources = append(existing.Sources, s)
			}
		}
	}
	Sort(out)
	return out
}

// Sort orders findings most severe first, then by URI, line and rule.
func Sort(fs []Finding) {
	sort.SliceStable(fs, func(i, j int) bool {
		a, b := fs[i], fs[j]
		if a.Severity != b.Severity {
			return a.Severity > b.Severity
		}
		if a.Location.URI != b.Location.URI {
			return a.Location.URI < b.Location.URI
		}
		if a.Location.StartLine != b.Location.StartLine {
			return a.Location.StartLine < b.Location.StartLine
		}
		return a.RuleID < b.RuleID
	})
}

func containsSource(list []Source, s Source) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// MaskSecret hides all but the first four characters of a secret value
// (ADR 0007: secrets are masked in every output by default).
func MaskSecret(s string) string {
	r := []rune(s)
	if len(r) <= 4 {
		return strings.Repeat("*", len(r))
	}
	return string(r[:4]) + strings.Repeat("*", min(len(r)-4, 16))
}

// credentialCWEs are weaknesses whose findings quote a credential: hard-coded
// passwords and keys, and plaintext storage of passwords.
var credentialCWEs = map[string]bool{"CWE-259": true, "CWE-321": true, "CWE-798": true, "CWE-256": true}

var reQuoted = regexp.MustCompile(`'[^'\n]*'|"[^"\n]*"|` + "`[^`\\n]*`")

// RedactCredentials removes credential values from findings about
// credentials, whichever tool reported them (ADR 0007, threat model T9).
// Code scanners quote the value they flag, for example Bandit's "Possible
// hardcoded password: '<value>'". The snippet is replaced and every quoted
// string in the message is masked. Secret-scanner findings are masked when
// they are converted; this is the second line of defence for the others.
func (f *Finding) RedactCredentials() {
	match := f.Family == "secrets"
	for _, c := range f.CWEs {
		match = match || credentialCWEs[c]
	}
	if !match {
		return
	}
	if f.Family != "secrets" && f.Snippet != "" {
		f.Snippet = "[snippet removed: it may contain a credential]"
	}
	f.Message = reQuoted.ReplaceAllStringFunc(f.Message, func(q string) string {
		r := []rune(q)
		return string(r[0]) + MaskSecret(string(r[1:len(r)-1])) + string(r[len(r)-1])
	})
}

// SafeHelpURI returns u if it is an absolute https URL without user
// information and at most 2048 bytes long, and "" otherwise. Tool output is
// untrusted, and the link ends up in reports.
func SafeHelpURI(u string) string {
	if len(u) > 2048 {
		return ""
	}
	p, err := url.Parse(u)
	if err != nil || p.Scheme != "https" || p.Host == "" || p.User != nil || p.Opaque != "" {
		return ""
	}
	return u
}

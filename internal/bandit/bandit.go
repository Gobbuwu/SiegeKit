// Package bandit converts Bandit's JSON report to findings. The published
// Bandit image does not include Bandit's optional SARIF formatter, so its
// JSON format is read instead. The report is untrusted input (threat model
// T7): size is limited and values are only decoded.
package bandit

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/Gobbuwu/SiegeKit/internal/findings"
	"github.com/Gobbuwu/SiegeKit/internal/sarif"
)

// MaxSize is the largest report accepted, in bytes.
const MaxSize = sarif.MaxSize

type report struct {
	Results *[]result `json:"results"`
	Metrics struct {
		Totals struct {
			// Nosec counts results hidden by a bare "# nosec" comment,
			// SkippedTests those hidden by "# nosec <test id>" (checked with
			// Bandit 1.9.4).
			Nosec        int `json:"nosec"`
			SkippedTests int `json:"skipped_tests"`
		} `json:"_totals"`
	} `json:"metrics"`
}

type result struct {
	Filename   string `json:"filename"`
	LineNumber int    `json:"line_number"`
	TestID     string `json:"test_id"`
	TestName   string `json:"test_name"`
	IssueText  string `json:"issue_text"`
	Severity   string `json:"issue_severity"`
	Confidence string `json:"issue_confidence"`
	Code       string `json:"code"`
	MoreInfo   string `json:"more_info"`
	CWE        *struct {
		ID int `json:"id"`
	} `json:"issue_cwe"`
}

// Options control conversion.
type Options struct {
	Plugin    string // plugin id recorded as the source
	Family    string // test family
	MountPath string // container path of the target, removed from file names
	// Suppressed, if set, receives the number of results the scanned code
	// hid with "# nosec" comments.
	Suppressed *int
}

// ToFindings reads a Bandit JSON report and converts every result.
func ToFindings(r io.Reader, opt Options) ([]findings.Finding, error) {
	if opt.Plugin == "" || opt.Family == "" {
		return nil, errors.New("plugin and family are required")
	}
	data, err := io.ReadAll(io.LimitReader(r, MaxSize+1))
	if err != nil {
		return nil, err
	}
	if len(data) > MaxSize {
		return nil, fmt.Errorf("Bandit report larger than %d bytes", MaxSize)
	}
	var rep report
	if err := json.Unmarshal(data, &rep); err != nil {
		return nil, fmt.Errorf("decode Bandit report: %w", err)
	}
	if rep.Results == nil {
		return nil, errors.New("decode Bandit report: no results list")
	}
	if opt.Suppressed != nil {
		// Clamped: the report is untrusted and the sum must not overflow.
		*opt.Suppressed = min(max(0, rep.Metrics.Totals.Nosec), 1<<30) + min(max(0, rep.Metrics.Totals.SkippedTests), 1<<30)
	}
	var out []findings.Finding
	for _, res := range *rep.Results {
		if res.TestID == "" {
			return nil, errors.New("decode Bandit report: result without test_id")
		}
		f := findings.Finding{
			RuleID:     res.TestID,
			Title:      res.TestName,
			Message:    res.IssueText,
			Severity:   severity(res.Severity),
			Confidence: strings.ToLower(res.Confidence),
			Location:   findings.Location{URI: sarif.RelURI(res.Filename, opt.MountPath), StartLine: res.LineNumber},
			Snippet:    res.Code,
			HelpURI:    findings.SafeHelpURI(res.MoreInfo),
			Family:     opt.Family,
			Sources:    []findings.Source{{Plugin: opt.Plugin, RuleID: res.TestID}},
		}
		if f.Title == "" {
			f.Title = res.TestID
		}
		if res.CWE != nil && res.CWE.ID > 0 {
			f.CWEs = []string{"CWE-" + strconv.Itoa(res.CWE.ID)}
		}
		f.ComputeFingerprint()
		out = append(out, f)
	}
	return out, nil
}

func severity(s string) findings.Severity {
	switch strings.ToUpper(s) {
	case "HIGH":
		return findings.High
	case "MEDIUM":
		return findings.Medium
	case "LOW":
		return findings.Low
	}
	return findings.Info
}

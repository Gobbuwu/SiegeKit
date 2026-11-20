// Package ffuf converts ffuf's JSON report (-of json) to findings. Each
// result is a guessed path that the target answered with a status ffuf
// matches (its default set: 200-299, 301, 302, 307, 401, 403, 405, 500),
// after auto-calibration dropped answers that look like the app's answer to
// any path (ADR 0027). The report is untrusted input (threat model T7):
// size is limited and values are only decoded.
package ffuf

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"

	"github.com/Gobbuwu/SiegeKit/internal/findings"
	"github.com/Gobbuwu/SiegeKit/internal/sarif"
)

// MaxSize is the largest report accepted, in bytes.
const MaxSize = sarif.MaxSize

// RuleID is the rule of every ffuf finding.
const RuleID = "path-found"

type report struct {
	Results *[]result `json:"results"`
}

type result struct {
	Status      int    `json:"status"`
	Length      int64  `json:"length"`
	ContentType string `json:"content-type"`
	Redirect    string `json:"redirectlocation"`
	URL         string `json:"url"`
}

// Options control conversion.
type Options struct {
	Plugin string // plugin id recorded as the source
	Family string // test family
}

// ToFindings reads ffuf's JSON report and converts each result to an
// informational finding: a guessed path is worth a look, not a flaw by
// itself. The request's headers and ffuf's settings are not copied.
func ToFindings(r io.Reader, opt Options) ([]findings.Finding, error) {
	if opt.Plugin == "" || opt.Family == "" {
		return nil, errors.New("plugin and family are required")
	}
	data, err := io.ReadAll(io.LimitReader(r, MaxSize+1))
	if err != nil {
		return nil, err
	}
	if len(data) > MaxSize {
		return nil, fmt.Errorf("ffuf report larger than %d bytes", MaxSize)
	}
	var rep report
	if err := json.NewDecoder(bytes.NewReader(data)).Decode(&rep); err != nil {
		return nil, fmt.Errorf("decode ffuf report: %w", err)
	}
	if rep.Results == nil {
		return nil, errors.New("decode ffuf report: no results list")
	}
	out := []findings.Finding{}
	seen := map[string]bool{}
	for i, res := range *rep.Results {
		u, err := url.Parse(res.URL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || res.Status < 100 || res.Status > 599 || res.Length < 0 {
			return nil, fmt.Errorf("decode ffuf report: result %d has no valid URL or status", i+1)
		}
		if seen[res.URL] {
			continue
		}
		seen[res.URL] = true
		msg := fmt.Sprintf("%s answered %d (%d bytes", res.URL, res.Status, res.Length)
		if res.ContentType != "" {
			msg += ", " + res.ContentType
		}
		msg += ")"
		if res.Redirect != "" {
			msg += ", redirecting to " + res.Redirect
		}
		f := findings.Finding{
			RuleID:   RuleID,
			Title:    "Path found by guessing",
			Message:  msg,
			Severity: findings.Info,
			Location: findings.Location{URI: res.URL},
			Family:   opt.Family,
			Sources:  []findings.Source{{Plugin: opt.Plugin, RuleID: RuleID}},
		}
		f.ComputeFingerprint()
		out = append(out, f)
	}
	return out, nil
}

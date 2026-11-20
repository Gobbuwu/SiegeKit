// Package schemathesis converts Schemathesis's JSON run report
// (--report json) to findings (ADR 0028). The report lists each failed
// check once, with the operations it failed on, such as "GET /items/{id}".
// The report is untrusted input (threat model T7): size is limited, values
// are checked and only decoded, and request data is not copied.
package schemathesis

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"slices"
	"strings"

	"github.com/Gobbuwu/SiegeKit/internal/findings"
	"github.com/Gobbuwu/SiegeKit/internal/sarif"
)

// MaxSize is the largest report accepted, in bytes.
const MaxSize = sarif.MaxSize

type report struct {
	Complete   *bool  `json:"complete"`
	StopReason string `json:"stop_reason"`
	Operations *struct {
		Selected int `json:"selected"`
		Tested   int `json:"tested"`
		Skipped  int `json:"skipped"`
	} `json:"operations"`
	Failures *[]failure `json:"failures"`
	Errors   []struct {
		Title string `json:"title"`
		Count int    `json:"count"`
	} `json:"errors"`
}

type failure struct {
	Code       string   `json:"code"`
	Title      string   `json:"title"`
	Operations []string `json:"operations"`
}

// Options control conversion.
type Options struct {
	Plugin string // plugin id recorded as the source
	Family string // test family
	// Origin is the target's scheme, host and port; BasePath is the path
	// the spec's operations are relative to, if BaseKnown.
	Origin    string
	BasePath  string
	BaseKnown bool
}

var (
	reCode = regexp.MustCompile(`^ST[0-9]{3}$`)
	// An operation label: an HTTP method and the spec's path template.
	reOperation = regexp.MustCompile(`^([A-Z]{3,7}) (/[!-~]*)$`)
)

// Severity is SiegeKit's rating of a failed check: a server error (the API
// crashed on generated input) is medium, every other check (status codes,
// headers and bodies that differ from the spec) is low. Neither proves a
// vulnerability, so both rank below confirmed flaws (ADR 0028).
func Severity(code string) findings.Severity {
	if code == "ST101" {
		return findings.Medium
	}
	return findings.Low
}

// ToFindings reads the report and returns one finding per failed check and
// path, naming the methods it failed for. A report with errors (such as a
// network error or an operation Schemathesis could not test), or that
// tested no operation, is an error: the run did not check what it should
// have.
func ToFindings(r io.Reader, opt Options) ([]findings.Finding, error) {
	if opt.Plugin == "" || opt.Family == "" || opt.Origin == "" {
		return nil, errors.New("plugin, family and origin are required")
	}
	data, err := io.ReadAll(io.LimitReader(r, MaxSize+1))
	if err != nil {
		return nil, err
	}
	if len(data) > MaxSize {
		return nil, fmt.Errorf("Schemathesis report larger than %d bytes", MaxSize)
	}
	var rep report
	if err := json.NewDecoder(bytes.NewReader(data)).Decode(&rep); err != nil {
		return nil, fmt.Errorf("decode Schemathesis report: %w", err)
	}
	switch {
	case rep.Complete == nil || rep.Operations == nil || rep.Failures == nil:
		return nil, errors.New("decode Schemathesis report: no complete, operations or failures field")
	case len(rep.Errors) > 0:
		var titles []string
		for _, e := range rep.Errors[:min(3, len(rep.Errors))] {
			titles = append(titles, fmt.Sprintf("%s (%d)", clean(e.Title), e.Count))
		}
		return nil, fmt.Errorf("Schemathesis reported %d error(s), so some operations were not tested: %s", len(rep.Errors), strings.Join(titles, ", "))
	case !*rep.Complete:
		return nil, fmt.Errorf("Schemathesis did not finish (stop reason %q)", clean(rep.StopReason))
	case rep.Operations.Tested == 0:
		return nil, fmt.Errorf("Schemathesis tested no operation (%d selected, %d skipped)", rep.Operations.Selected, rep.Operations.Skipped)
	}
	type key struct{ code, path string }
	methods := map[key][]string{}
	titles := map[string]string{}
	var order []key
	for i, f := range *rep.Failures {
		if !reCode.MatchString(f.Code) || len(f.Operations) == 0 {
			return nil, fmt.Errorf("decode Schemathesis report: failure %d has no valid code or operations", i+1)
		}
		titles[f.Code] = clean(f.Title)
		for _, op := range f.Operations {
			m := reOperation.FindStringSubmatch(op)
			if m == nil || len(op) > 2048 {
				return nil, fmt.Errorf("decode Schemathesis report: failure %d has an invalid operation", i+1)
			}
			k := key{f.Code, m[2]}
			if _, ok := methods[k]; !ok {
				order = append(order, k)
			}
			if !slices.Contains(methods[k], m[1]) {
				methods[k] = append(methods[k], m[1])
			}
		}
	}
	out := []findings.Finding{}
	for _, k := range order {
		ms := methods[k]
		slices.Sort(ms)
		title := titles[k.code]
		if title == "" {
			title = "Schemathesis check failed"
		}
		uri := opt.Origin + opt.BasePath + k.path
		msg := fmt.Sprintf("%s (Schemathesis check %s) for %s requests to %s generated from the OpenAPI spec.", title, k.code, strings.Join(ms, ", "), opt.BasePath+k.path)
		if !opt.BaseKnown {
			uri = opt.Origin + k.path
			msg += " The path is as written in the spec: SiegeKit could not read the API's base path from it."
		}
		f := findings.Finding{
			RuleID:   k.code,
			Title:    title,
			Message:  msg,
			Severity: Severity(k.code),
			Location: findings.Location{URI: uri},
			Family:   opt.Family,
			Sources:  []findings.Source{{Plugin: opt.Plugin, RuleID: k.code}},
		}
		f.ComputeFingerprint()
		out = append(out, f)
	}
	return out, nil
}

// clean removes control characters and cuts s to 200 characters, as titles
// and reasons are shown in reports and terminals.
func clean(s string) string {
	s = strings.Map(func(r rune) rune {
		if r < ' ' || r == 0x7f || (r >= 0x80 && r < 0xa0) {
			return -1
		}
		return r
	}, s)
	if r := []rune(s); len(r) > 200 {
		s = string(r[:200])
	}
	return s
}

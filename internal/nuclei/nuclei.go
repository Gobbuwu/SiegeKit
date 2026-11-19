// Package nuclei converts Nuclei's JSON Lines output (-jsonl) to findings.
// Nuclei's SARIF export drops the matcher name, so the ten missing-header
// results of one template read the same, and gives no location; its JSON
// Lines keep both (checked with Nuclei 3.11.1). The report is untrusted
// input (threat model T7): size is limited and values are only decoded.
package nuclei

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"regexp"
	"slices"
	"strings"

	"github.com/Gobbuwu/SiegeKit/internal/findings"
	"github.com/Gobbuwu/SiegeKit/internal/sarif"
)

// MaxSize is the largest report accepted, in bytes.
const MaxSize = sarif.MaxSize

// MaxLine is the longest line accepted, in bytes.
const MaxLine = 1 << 20

type result struct {
	TemplateID  string `json:"template-id"`
	TemplateURL string `json:"template-url"`
	Info        struct {
		Name           string `json:"name"`
		Description    string `json:"description"`
		Severity       string `json:"severity"`
		Classification *struct {
			CWEs []string `json:"cwe-id"`
		} `json:"classification"`
	} `json:"info"`
	MatcherName string `json:"matcher-name"`
	MatchedAt   string `json:"matched-at"`
	URL         string `json:"url"`
}

// Options control conversion.
type Options struct {
	Plugin string // plugin id recorded as the source
	Family string // test family
}

var reCWE = regexp.MustCompile(`^(?i:cwe)-[0-9]{1,6}$`)

// ToFindings reads Nuclei's JSON Lines and converts the results. Results of
// one template at one address are merged into one finding that names every
// matcher, such as each missing security header. Extracted values are never
// copied: they can be secrets the template found.
func ToFindings(r io.Reader, opt Options) ([]findings.Finding, error) {
	if opt.Plugin == "" || opt.Family == "" {
		return nil, errors.New("plugin and family are required")
	}
	data, err := io.ReadAll(io.LimitReader(r, MaxSize+1))
	if err != nil {
		return nil, err
	}
	if len(data) > MaxSize {
		return nil, fmt.Errorf("Nuclei report larger than %d bytes", MaxSize)
	}
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), MaxLine)
	var out []findings.Finding
	matchers := map[int][]string{}
	index := map[string]int{}
	for n := 1; sc.Scan(); n++ {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var res result
		if err := json.Unmarshal(line, &res); err != nil {
			return nil, fmt.Errorf("decode Nuclei report line %d: %w", n, err)
		}
		if res.TemplateID == "" || res.MatchedAt == "" {
			return nil, fmt.Errorf("decode Nuclei report line %d: result without template-id or matched-at", n)
		}
		res.MatchedAt = location(res)
		k := res.TemplateID + "\x00" + res.MatchedAt
		i, seen := index[k]
		if !seen {
			i = len(out)
			index[k] = i
			out = append(out, finding(res, opt))
		}
		if m := res.MatcherName; m != "" && !slices.Contains(matchers[i], m) {
			matchers[i] = append(matchers[i], m)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("read Nuclei report: %w", err)
	}
	for i := range out {
		if ms := matchers[i]; len(ms) > 0 {
			slices.Sort(ms)
			out[i].Message += ": " + strings.Join(ms, ", ")
		}
		out[i].ComputeFingerprint()
	}
	return out, nil
}

func finding(res result, opt Options) findings.Finding {
	f := findings.Finding{
		RuleID:   res.TemplateID,
		Title:    res.Info.Name,
		Message:  fmt.Sprintf("%s at %s", firstNonEmpty(res.Info.Name, res.TemplateID), res.MatchedAt),
		Severity: severity(res.Info.Severity),
		Location: findings.Location{URI: res.MatchedAt},
		HelpURI:  findings.SafeHelpURI(res.TemplateURL),
		Family:   opt.Family,
		Sources:  []findings.Source{{Plugin: opt.Plugin, RuleID: res.TemplateID}},
	}
	if f.Title == "" {
		f.Title = res.TemplateID
	}
	if res.Info.Classification != nil {
		for _, c := range res.Info.Classification.CWEs {
			if c = strings.TrimSpace(c); reCWE.MatchString(c) {
				if c = strings.ToUpper(c); !slices.Contains(f.CWEs, c) {
					f.CWEs = append(f.CWEs, c)
				}
			}
		}
	}
	return f
}

// location is where the result was found, as a URL. Some templates give
// matched-at as host:port only (the cookie checks, for example); the
// request's URL is used for those.
func location(res result) string {
	if isWebURL(res.MatchedAt) || !isWebURL(res.URL) {
		return res.MatchedAt
	}
	return res.URL
}

func isWebURL(s string) bool {
	u, err := url.Parse(s)
	return err == nil && (u.Scheme == "http" || u.Scheme == "https") && u.Host != ""
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func severity(s string) findings.Severity {
	switch strings.ToLower(s) {
	case "critical":
		return findings.Critical
	case "high":
		return findings.High
	case "medium":
		return findings.Medium
	case "low":
		return findings.Low
	}
	return findings.Info // "info", "unknown" or missing
}

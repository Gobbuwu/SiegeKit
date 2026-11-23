// Package knownanswers compares a scan report with what each check is
// known to find on a fixture, and with the least work a complete run does
// (ADR 0039). A check that finds less, or does less, than its known answer
// fails, whatever the cause.
package knownanswers

import (
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/url"
	"os"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/Gobbuwu/SiegeKit/internal/report"
)

// Match says how a check's findings are compared with its answer.
const (
	// Exact: the same findings, no more and no fewer. For checks whose tool,
	// rules and data are all pinned, so any difference has a cause to find.
	Exact = "exact"
	// Includes: at least these findings. For checks whose data is updated
	// at run time (trivy's advisories) or whose crawl varies (ZAP).
	Includes = "includes"
)

// Answers is the known answer of one fixture.
type Answers struct {
	Fixture  string           `json:"fixture"`
	Measured string           `json:"measured"` // where the answer was measured: runs, engines, date
	Checks   map[string]Check `json:"checks"`
	// NotMetYet lists issues the fixture really has that SiegeKit does not
	// find yet, each with the change that must find it. A run that finds
	// one fails until it is moved into its check's findings.
	NotMetYet []Gap `json:"notMetYet,omitempty"`
}

// Check is the known answer of one check on one fixture.
type Check struct {
	Status      string   `json:"status"`                // "ran", "skipped", or "failed" for a known incomplete run (ADR 0040)
	Reason      string   `json:"reason,omitempty"`      // text the plugin's reason must contain
	Cause       string   `json:"cause,omitempty"`       // a skipped check's cause, compared exactly (ADR 0041)
	Match       string   `json:"match,omitempty"`       // Exact or Includes; "" when the check finds nothing to compare
	Findings    []string `json:"findings,omitempty"`    // keys, see Key
	Count       int      `json:"count,omitempty"`       // Exact: the plugin's own finding count (two findings can share a key)
	MinRequests int      `json:"minRequests,omitempty"` // URL checks: requests a complete run sends at least
	Why         string   `json:"why,omitempty"`         // how the answer was set, when not obvious
	// ByRule compares rule IDs instead of keys: Findings lists the rules
	// that must be reported at least once. For crawlers, whose pages vary
	// from run to run while the rules they report do not.
	ByRule bool `json:"byRule,omitempty"`
	// Unstable lists findings that came and went between identical runs,
	// with the cause in Why. They are neither required nor new, and each
	// run prints them: an unexplained difference is a finding to fix
	// (ADR 0038), not a pass.
	Unstable []string `json:"unstable,omitempty"`
	// ByEngine replaces this answer on one engine, for a difference between
	// engines that is explained in Why. An unexplained one is a finding
	// (ADR 0038), not an override.
	ByEngine map[string]Check `json:"byEngine,omitempty"`
}

// Gap is an issue the fixture has and SiegeKit does not find yet.
type Gap struct {
	Check     string `json:"check"`
	Finding   string `json:"finding"`   // key, see Key
	Needs     string `json:"needs"`     // the change that must find it
	Confirmed string `json:"confirmed"` // how the issue was confirmed to be real
}

// Load reads and checks an answer file.
func Load(path string) (*Answers, error) {
	b, err := os.ReadFile(path) // #nosec G304 -- a path from CI's own workflow
	if err != nil {
		return nil, err
	}
	var a Answers
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&a); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if err := a.validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &a, nil
}

func (a *Answers) validate() error {
	if a.Fixture == "" || a.Measured == "" || len(a.Checks) == 0 {
		return fmt.Errorf("fixture, measured and checks are required")
	}
	for _, id := range slices.Sorted(maps.Keys(a.Checks)) { // the same error each run
		c := a.Checks[id]
		if err := c.validate(); err != nil {
			return fmt.Errorf("check %s: %w", id, err)
		}
		for _, eng := range slices.Sorted(maps.Keys(c.ByEngine)) {
			o := c.ByEngine[eng]
			if eng != "podman" && eng != "docker" {
				return fmt.Errorf("check %s: unknown engine %q", id, eng)
			}
			if c.Why == "" {
				return fmt.Errorf("check %s: byEngine needs a why", id)
			}
			if len(o.ByEngine) > 0 {
				return fmt.Errorf("check %s: nested byEngine", id)
			}
			if err := o.validate(); err != nil {
				return fmt.Errorf("check %s on %s: %w", id, eng, err)
			}
		}
	}
	for _, g := range a.NotMetYet {
		if _, ok := a.Checks[g.Check]; !ok || g.Finding == "" || g.Needs == "" || g.Confirmed == "" {
			return fmt.Errorf("not-met-yet entry %+v: needs a known check, a finding, what it needs and how it was confirmed", g)
		}
	}
	return nil
}

func (c Check) validate() error {
	switch c.Status {
	case string(report.Ran), string(report.Skipped):
	case string(report.Failed):
		// A check that did part of its work and says what it left out
		// (ADR 0040): its findings are still compared, and the reason must
		// name what was left out.
		if c.Reason == "" || c.Why == "" {
			return fmt.Errorf("a failed check needs the reason it gives and a why")
		}
	default:
		return fmt.Errorf("status %q", c.Status)
	}
	switch c.Match {
	case Exact, Includes:
	case "":
		if len(c.Findings) > 0 {
			return fmt.Errorf("findings need a match")
		}
	default:
		return fmt.Errorf("match %q", c.Match)
	}
	if c.Count > 0 && (c.Match != Exact || len(c.Unstable) > 0 || c.ByRule) {
		return fmt.Errorf("count needs match exact, by key, with no unstable findings")
	}
	if (c.ByRule || len(c.Unstable) > 0) && c.Why == "" {
		return fmt.Errorf("byRule and unstable need a why")
	}
	for _, k := range c.Unstable {
		if slices.Contains(c.Findings, k) {
			return fmt.Errorf("%q is both required and unstable", k)
		}
	}
	if c.Status == string(report.Skipped) && (c.Match != "" || c.MinRequests > 0 || c.Reason == "" || !report.Cause(c.Cause).Valid()) {
		return fmt.Errorf("a skipped check has a reason, a valid cause and no findings or requests")
	}
	if c.Status != string(report.Skipped) && c.Cause != "" {
		return fmt.Errorf("only a skipped check has a cause in its answer")
	}
	return nil
}

// Key names a finding for comparison: "RULE URI:LINE" for a file, or
// "RULE PATH" for a URL (the host and port belong to the run, and query
// values can vary).
func Key(rule, uri string, line int) string {
	if u, err := url.Parse(uri); err == nil && (u.Scheme == "http" || u.Scheme == "https") {
		p := u.EscapedPath()
		if p == "" {
			p = "/"
		}
		return rule + " " + p
	}
	if line > 0 {
		return rule + " " + uri + ":" + strconv.Itoa(line)
	}
	return rule + " " + uri
}

// Observed is what a report shows for one check.
type Observed struct {
	Status   string
	Reason   string
	Cause    string
	Requests int
	Count    int      // the plugin's own finding count
	Findings []string // sorted, unique keys
}

// Observe collects each check's results from r.
func Observe(r *report.Run) map[string]Observed {
	keys := map[string]map[string]bool{}
	for _, f := range r.Findings {
		for _, s := range f.Sources {
			if keys[s.Plugin] == nil {
				keys[s.Plugin] = map[string]bool{}
			}
			keys[s.Plugin][Key(s.RuleID, f.Location.URI, f.Location.StartLine)] = true
		}
	}
	out := map[string]Observed{}
	for _, p := range r.Plugins {
		o := Observed{Status: string(p.Status), Reason: p.Reason, Cause: string(p.Cause), Requests: p.Requests, Count: p.Findings}
		for k := range keys[p.ID] {
			o.Findings = append(o.Findings, k)
		}
		sort.Strings(o.Findings)
		out[p.ID] = o
	}
	return out
}

// Result of comparing a report with its answers.
type Result struct {
	Failures  []string // each fails the run
	NotMetYet []string // printed every run
	Unstable  []string // printed every run
}

// Compare checks the report r, from a run on engine, against a.
func Compare(a *Answers, r *report.Run, engine string) Result {
	var res Result
	obs := Observe(r)
	ids := make([]string, 0, len(obs))
	for id := range obs {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		if _, ok := a.Checks[id]; !ok {
			res.Failures = append(res.Failures, fmt.Sprintf("%s: no known answer for this check on %s", id, a.Fixture))
		}
	}
	ids = ids[:0]
	for id := range a.Checks {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		want := a.Checks[id]
		if o, ok := want.ByEngine[engine]; ok {
			want = o
		}
		got, ok := obs[id]
		if !ok {
			res.Failures = append(res.Failures, fmt.Sprintf("%s: not in the report", id))
			continue
		}
		res.Failures = append(res.Failures, compareCheck(id, want, got)...)
		if len(want.Unstable) > 0 {
			res.Unstable = append(res.Unstable, fmt.Sprintf("%s: %d findings vary between identical runs, not compared (%s): %s", id, len(want.Unstable), want.Why, strings.Join(want.Unstable, ", ")))
		}
	}
	for _, g := range a.NotMetYet {
		if slices.Contains(obs[g.Check].Findings, g.Finding) {
			res.Failures = append(res.Failures, fmt.Sprintf("%s: now finds %q, listed as not met yet (%s): move it into the check's findings", g.Check, g.Finding, g.Needs))
			continue
		}
		res.NotMetYet = append(res.NotMetYet, fmt.Sprintf("%s: %s (needs %s)", g.Check, g.Finding, g.Needs))
	}
	return res
}

func compareCheck(id string, want Check, got Observed) []string {
	var fails []string
	if got.Status != want.Status {
		fails = append(fails, fmt.Sprintf("%s: %s %s, known answer is %s", id, got.Status, got.Reason, want.Status))
		return fails
	}
	if !strings.Contains(got.Reason, want.Reason) {
		fails = append(fails, fmt.Sprintf("%s: reason %q, known answer contains %q", id, got.Reason, want.Reason))
	}
	if want.Status == string(report.Skipped) && got.Cause != want.Cause {
		fails = append(fails, fmt.Sprintf("%s: cause %q, known answer is %q", id, got.Cause, want.Cause))
	}
	if got.Requests < want.MinRequests {
		fails = append(fails, fmt.Sprintf("%s: sent %d requests, a complete run sends at least %d", id, got.Requests, want.MinRequests))
	}
	have := got.Findings
	if want.ByRule {
		have = rules(have)
	}
	var missing, extra []string
	for _, k := range want.Findings {
		if !slices.Contains(have, k) {
			missing = append(missing, k)
		}
	}
	if want.Match == Exact || want.Match == "" {
		for _, k := range have {
			if !slices.Contains(want.Findings, k) && !slices.Contains(want.Unstable, k) {
				extra = append(extra, k)
			}
		}
	}
	if want.Count > 0 && got.Count != want.Count {
		fails = append(fails, fmt.Sprintf("%s: %d findings, known answer is %d", id, got.Count, want.Count))
	}
	for _, k := range missing {
		fails = append(fails, fmt.Sprintf("%s: missed %s", id, k))
	}
	for _, k := range extra {
		fails = append(fails, fmt.Sprintf("%s: new finding %s, not in the known answer", id, k))
	}
	return fails
}

// rules returns the sorted, unique rule IDs of keys.
func rules(keys []string) []string {
	var out []string
	for _, k := range keys {
		r, _, _ := strings.Cut(k, " ")
		if !slices.Contains(out, r) {
			out = append(out, r)
		}
	}
	sort.Strings(out)
	return out
}

// AnswerFrom writes what r shows as an answer file, for a person to review
// when a pin changes and the answer must be measured again.
func AnswerFrom(fixture, measured string, r *report.Run, old *Answers) *Answers {
	a := &Answers{Fixture: fixture, Measured: measured, Checks: map[string]Check{}}
	if old != nil {
		a.NotMetYet = old.NotMetYet
	}
	for id, o := range Observe(r) {
		c := Check{Status: o.Status, Findings: o.Findings}
		if o.Status == string(report.Skipped) || o.Status == string(report.Failed) {
			c.Reason = o.Reason
		}
		if o.Status == string(report.Failed) {
			// To be reviewed: a failed check is only a known answer with
			// a why (ADR 0040), which Load requires.
			c.Why = "failed in the measured runs: " + o.Reason
		}
		if len(o.Findings) > 0 {
			c.Match, c.Count = Exact, o.Count
		}
		if old != nil {
			if prev, ok := old.Checks[id]; ok {
				if prev.Why != "" {
					c.Why = prev.Why
				}
				c.ByEngine, c.ByRule, c.Unstable = prev.ByEngine, prev.ByRule, prev.Unstable
				if c.ByRule {
					c.Findings = rules(c.Findings)
				}
				c.Findings = slices.DeleteFunc(c.Findings, func(k string) bool { return slices.Contains(c.Unstable, k) })
				if prev.Reason != "" && strings.Contains(o.Reason, prev.Reason) {
					c.Reason = prev.Reason
				}
				if prev.Match != "" && len(o.Findings) > 0 {
					c.Match = prev.Match
				}
				if c.Match != Exact || c.ByRule || len(c.Unstable) > 0 {
					c.Count = 0
				}
				c.MinRequests = prev.MinRequests
			}
		}
		if c.Status == string(report.Skipped) {
			c.Match, c.Findings, c.MinRequests, c.Cause = "", nil, 0, o.Cause
		}
		a.Checks[id] = c
	}
	return a
}

// EngineOf names the container engine a report's answers hold for (ADR
// 0038). A run whose checks were all SiegeKit's own, in-process checks
// started no container, so it has no engine and holds for every engine:
// "" (a byEngine answer never applies). Any other run without an engine
// is refused, since its answers cannot be compared (ADR 0054).
func EngineOf(r *report.Run) (string, error) {
	if r.Environment != nil && r.Environment.Engine != nil {
		return r.Environment.Engine.Name, nil
	}
	if len(r.Plugins) == 0 {
		return "", errors.New("the report names no container engine and no check, so its answers cannot be compared (ADR 0038)")
	}
	for _, p := range r.Plugins {
		if p.Tool != "siegekit" {
			return "", fmt.Errorf("the report names no container engine but %s ran with %s, so its answers cannot be compared (ADR 0038)", p.ID, p.Tool)
		}
	}
	return "", nil
}

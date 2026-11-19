// Package report builds SiegeKit's run reports (ADR 0007, ADR 0009).
//
// Wording rule (ADR 0009): a report never says "secure", "safe" or "passed".
// The strongest summary is "No issues found by the N checks that ran."
package report

import (
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/Gobbuwu/SiegeKit/internal/findings"
)

// Status of one plugin in a run.
type Status string

// Plugin statuses.
const (
	Ran      Status = "ran"
	Skipped  Status = "skipped"
	Failed   Status = "failed"
	TimedOut Status = "timed-out"
)

// PluginResult is the coverage record for one plugin (ADR 0009 item 2).
type PluginResult struct {
	ID       string `json:"id"`
	Family   string `json:"family"`
	Tool     string `json:"tool"`
	Version  string `json:"version"`
	Status   Status `json:"status"`
	Reason   string `json:"reason,omitempty"`
	Findings int    `json:"findings"`
	// What the scanned repository told the tool to ignore (owner decision,
	// 2026-11-19: obey it, but show it). Suppressed counts findings the tool
	// reported as suppressed by comments in the code; RepoSettings lists the
	// repository's own settings files the tool read; IgnoreMarkers counts
	// lines carrying the tool's ignore comment, for tools that do not report
	// what they suppressed.
	Suppressed    int      `json:"suppressed,omitempty"`
	RepoSettings  []string `json:"repoSettings,omitempty"`
	IgnoreMarkers int      `json:"ignoreMarkers,omitempty"`
	// Requests counts requests the target answered through the egress proxy
	// in an active run; Refused counts requests and connections the proxy
	// refused, and RefusedTo names them, each once and at most 20 (ADR 0018,
	// ADR 0023).
	Requests  int      `json:"requests,omitempty"`
	Refused   int      `json:"refused,omitempty"`
	RefusedTo []string `json:"refusedTo,omitempty"`
}

// IgnoreNote says in one line what the repository told the tool to ignore,
// or "" if nothing.
func (p PluginResult) IgnoreNote() string {
	var parts []string
	if p.Suppressed > 0 {
		parts = append(parts, fmt.Sprintf("%d finding(s) suppressed by comments in the code", p.Suppressed))
	}
	if len(p.RepoSettings) > 0 {
		parts = append(parts, "obeys the repository's "+strings.Join(p.RepoSettings, ", ")+", which can hide findings")
	}
	if p.IgnoreMarkers > 0 {
		parts = append(parts, fmt.Sprintf("%d line(s) carry an ignore comment", p.IgnoreMarkers))
	}
	return strings.Join(parts, "; ")
}

// Run is everything a report shows.
type Run struct {
	SiegeKitVersion string             `json:"siegekitVersion"`
	Target          string             `json:"target"`
	Mode            string             `json:"mode"`
	Started         time.Time          `json:"started"`
	Finished        time.Time          `json:"finished"`
	Plugins         []PluginResult     `json:"plugins"`
	Findings        []findings.Finding `json:"findings"`
	// Comparison is set when a saved run of the same target exists.
	Comparison *Comparison `json:"comparison,omitempty"`
}

// Comparison says what changed since the last saved run of the same target
// (ADR 0013). A finding that disappeared counts as fixed only if a plugin
// that reported it ran to completion in this run; otherwise it is listed as
// not checked again, so a failed check cannot make problems look fixed.
type Comparison struct {
	PreviousRun     string             `json:"previousRun"`
	PreviousStarted time.Time          `json:"previousStarted"`
	PreviousVersion string             `json:"previousVersion"`
	New             []string           `json:"new"` // fingerprints of findings the previous run did not report
	Fixed           []findings.Finding `json:"fixed"`
	NotRechecked    []findings.Finding `json:"notRechecked"` // gone from this run, but no plugin that reported them completed
	StillPresent    int                `json:"stillPresent"` // reported by both runs
}

// Summary is one line for the terminal and the HTML report.
func (c *Comparison) Summary() string {
	s := fmt.Sprintf("Since the last scan of this target (%s): %d new, %d fixed, %d still present",
		c.PreviousStarted.UTC().Format("2006-01-02 15:04 UTC"), len(c.New), len(c.Fixed), c.StillPresent)
	if n := len(c.NotRechecked); n > 0 {
		s += fmt.Sprintf(", %d not checked again because their check did not run to completion", n)
	}
	return s + "."
}

// VersionNote warns when the previous run used another SiegeKit version:
// tool and parser changes can make findings look new or fixed.
func (c *Comparison) VersionNote(current string) string {
	if c.PreviousVersion == current {
		return ""
	}
	prev := c.PreviousVersion
	if prev == "" {
		prev = "an unknown version"
	}
	return fmt.Sprintf("The previous run used SiegeKit %s, this one %s: some changes may come from the upgrade, not from the target.", prev, current)
}

// NotTested lists what automated checks cannot cover (ADR 0009 item 3).
// Every report shows it.
var NotTested = []string{
	// Keep this list true for the current version. Update the web, language
	// and access-control lines when more web tools (M2.5), Opengrep (M2.9)
	// and the two-account test (M2.7) land.
	"The running application, unless you scanned its URL: a directory scan only reads files. A URL scan crawls the app with ZAP and runs ZAP's passive checks; ZAP's attack scan runs only on local targets, and deployed targets get passive checks until request limits are measured. ZAP's crawler follows HTML links, so pages that a single-page app builds in JavaScript are mostly not reached. API specifications, other web tools (Nuclei, ffuf, sqlmap, Nikto) and login checks are planned for M2.",
	"The source code, unless you scanned its directory: a URL scan only sends requests to the running app.",
	"Code in languages without an analyzer: Python (bandit) and Go (gosec) code is analyzed; JavaScript, TypeScript and other languages are not yet (planned for M2). Secrets, dependencies and configuration files are checked in any language.",
	"Access control: whether every request checks that this user may access this record. SiegeKit has no access-control test yet; a partial two-account test is planned for M2.",
	"Business logic: skipping steps, replaying actions, tampering with prices or limits.",
	"Authentication and session design decisions that need human judgement.",
	"Code paths the tools did not reach: pages behind logins that were not configured, endpoints missing from specs, code without fuzz harnesses.",
	"Systems that were not scanned: cloud accounts, third-party services, infrastructure outside the target.",
}

// Complete reports whether every selected plugin ran to completion.
func (r *Run) Complete() bool {
	for _, p := range r.Plugins {
		if p.Status == Failed || p.Status == TimedOut {
			return false
		}
	}
	return true
}

// RanCount returns how many plugins ran to completion.
func (r *Run) RanCount() int {
	n := 0
	for _, p := range r.Plugins {
		if p.Status == Ran {
			n++
		}
	}
	return n
}

// Counts returns the number of findings per severity.
func (r *Run) Counts() map[findings.Severity]int {
	c := map[findings.Severity]int{}
	for _, f := range r.Findings {
		c[f.Severity]++
	}
	return c
}

// Headline is the one-sentence summary at the top of every report.
func (r *Run) Headline() string {
	switch {
	case r.RanCount() == 0:
		return "No checks completed. Nothing was tested."
	case len(r.Findings) > 0:
		return fmt.Sprintf("%d issue(s) found by the %d check(s) that ran.", len(r.Findings), r.RanCount())
	default:
		return fmt.Sprintf("No issues found by the %d check(s) that ran. This does not mean the application is secure.", r.RanCount())
	}
}

// Exit codes for CI use (ADR 0009 item 4). 1 and 2 are used by the CLI for
// invalid input and usage errors.
const (
	ExitClean      = 0
	ExitFindings   = 3
	ExitIncomplete = 4
)

// ExitCode returns ExitFindings if any finding is at or above threshold,
// otherwise ExitIncomplete if any plugin failed or timed out, otherwise
// ExitClean. An incomplete run is never reported as clean.
func (r *Run) ExitCode(threshold findings.Severity) int {
	for _, f := range r.Findings {
		if f.Severity >= threshold {
			return ExitFindings
		}
	}
	if !r.Complete() || r.RanCount() == 0 {
		return ExitIncomplete
	}
	return ExitClean
}

// WriteJSON writes the run as indented JSON.
func WriteJSON(w io.Writer, r *Run) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(struct {
		SchemaVersion int `json:"schemaVersion"`
		*Run
	}{SchemaVersion, r})
}

// SchemaVersion is the report.json format version. It changes only when a
// field is removed or changes meaning; new fields keep the version.
const SchemaVersion = 1

// WriteSARIF writes the deduplicated findings as one SARIF 2.1.0 log with a
// single "SiegeKit" run, so code hosts and IDEs can read them.
func WriteSARIF(w io.Writer, r *Run) error {
	type msg struct {
		Text string `json:"text"`
	}
	type rule struct {
		ID               string         `json:"id"`
		ShortDescription msg            `json:"shortDescription"`
		HelpURI          string         `json:"helpUri,omitempty"`
		Properties       map[string]any `json:"properties,omitempty"`
	}
	type region struct {
		StartLine int `json:"startLine,omitempty"`
	}
	type loc struct {
		PhysicalLocation struct {
			ArtifactLocation struct {
				URI string `json:"uri"`
			} `json:"artifactLocation"`
			Region *region `json:"region,omitempty"`
		} `json:"physicalLocation"`
	}
	type result struct {
		RuleID              string            `json:"ruleId"`
		Level               string            `json:"level"`
		Message             msg               `json:"message"`
		Locations           []loc             `json:"locations,omitempty"`
		PartialFingerprints map[string]string `json:"partialFingerprints"`
		Properties          map[string]any    `json:"properties"`
	}
	levels := map[findings.Severity]string{
		findings.Critical: "error", findings.High: "error",
		findings.Medium: "warning", findings.Low: "note", findings.Info: "none",
	}
	var rules []rule
	seenRule := map[string]bool{}
	var results []result
	for _, f := range r.Findings {
		if !seenRule[f.RuleID] {
			seenRule[f.RuleID] = true
			var props map[string]any
			if len(f.CWEs) > 0 {
				props = map[string]any{"tags": f.CWEs}
			}
			rules = append(rules, rule{ID: f.RuleID, ShortDescription: msg{f.Title}, HelpURI: f.HelpURI, Properties: props})
		}
		res := result{
			RuleID:              f.RuleID,
			Level:               levels[f.Severity],
			Message:             msg{f.Message},
			PartialFingerprints: map[string]string{"siegekit/v1": f.Fingerprint},
			Properties:          map[string]any{"siegekit-severity": f.Severity.String(), "sources": f.Sources},
		}
		if f.Location.URI != "" {
			var l loc
			l.PhysicalLocation.ArtifactLocation.URI = f.Location.URI
			if f.Location.StartLine > 0 {
				l.PhysicalLocation.Region = &region{StartLine: f.Location.StartLine}
			}
			res.Locations = []loc{l}
		}
		results = append(results, res)
	}
	if results == nil {
		results = []result{}
	}
	out := map[string]any{
		"$schema": "https://json.schemastore.org/sarif-2.1.0.json",
		"version": "2.1.0",
		"runs": []any{map[string]any{
			"tool": map[string]any{"driver": map[string]any{
				"name": "SiegeKit", "version": r.SiegeKitVersion,
				"informationUri": "https://github.com/Gobbuwu/SiegeKit", "rules": rules,
			}},
			"results": results,
		}},
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

// WriteHTML writes a self-contained HTML report: no scripts, no external
// resources, every value escaped by html/template (threat model T8).
func WriteHTML(w io.Writer, r *Run) error {
	plugins := append([]PluginResult(nil), r.Plugins...)
	sort.SliceStable(plugins, func(i, j int) bool { return plugins[i].Family < plugins[j].Family })
	counts := r.Counts()
	isNew := map[string]bool{}
	versionNote := ""
	if r.Comparison != nil {
		for _, fp := range r.Comparison.New {
			isNew[fp] = true
		}
		versionNote = r.Comparison.VersionNote(r.SiegeKitVersion)
	}
	return page.Execute(w, map[string]any{
		"Run":         r,
		"New":         isNew,
		"VersionNote": versionNote,
		"Headline":    r.Headline(),
		"Complete":    r.Complete(),
		"Plugins":     plugins,
		"NotTested":   NotTested,
		"Counts": []struct {
			Name string
			N    int
		}{
			{"critical", counts[findings.Critical]},
			{"high", counts[findings.High]},
			{"medium", counts[findings.Medium]},
			{"low", counts[findings.Low]},
			{"info", counts[findings.Info]},
		},
	})
}

var page = template.Must(template.New("report").Parse(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SiegeKit report</title>
<style>
body{font:15px/1.5 system-ui,sans-serif;margin:0 auto;max-width:960px;padding:16px;color:#1b1b1b;background:#fff}
h1{font-size:22px}h2{font-size:18px;margin-top:32px}
table{border-collapse:collapse;width:100%}th,td{border-bottom:1px solid #ddd;padding:6px 8px;text-align:left;vertical-align:top}
.warn{background:#fff4e5;border:1px solid #f0b46b;padding:8px 12px;border-radius:6px}
.sev-critical,.sev-high{font-weight:600}
code,pre{font:13px ui-monospace,monospace;white-space:pre-wrap;word-break:break-word}
@media (prefers-color-scheme:dark){body{background:#151515;color:#e8e8e8}th,td{border-color:#333}.warn{background:#3a2a12;border-color:#8a5a1a}}
</style>
</head>
<body>
<h1>SiegeKit report</h1>
<p><strong>{{.Headline}}</strong></p>
{{if not .Complete}}<p class="warn">This run is incomplete: at least one check failed or timed out. Missing checks may hide issues.</p>{{end}}
<p>Target: <code>{{.Run.Target}}</code> · Mode: {{.Run.Mode}} · SiegeKit {{.Run.SiegeKitVersion}} · {{.Run.Started.Format "2006-01-02 15:04 MST"}}</p>

{{with .Run.Comparison}}<h2>Since the last scan</h2>
<p>{{.Summary}} Previous run: <code>{{.PreviousRun}}</code>.</p>
{{with $.VersionNote}}<p class="warn">{{.}}</p>{{end}}
{{if .Fixed}}<p>Fixed: the check that reported each one ran to completion and did not report it again. An ignore setting added to the repository also hides a finding; each check's ignore counts are under "What was tested".</p>
<ul>{{range .Fixed}}<li>[{{.Severity}}] {{.Title}} · <code>{{.Location.URI}}{{if .Location.StartLine}}:{{.Location.StartLine}}{{end}}</code></li>{{end}}</ul>{{end}}
{{if .NotRechecked}}<p class="warn">Not checked again, because their check did not complete in this run:</p>
<ul>{{range .NotRechecked}}<li>[{{.Severity}}] {{.Title}} · <code>{{.Location.URI}}{{if .Location.StartLine}}:{{.Location.StartLine}}{{end}}</code></li>{{end}}</ul>{{end}}
{{end}}
<h2>What was tested</h2>
<table>
<tr><th>Check</th><th>Family</th><th>Tool</th><th>Status</th><th>Findings</th></tr>
{{range .Plugins}}<tr><td>{{.ID}}</td><td>{{.Family}}</td><td>{{.Tool}} {{.Version}}</td><td>{{.Status}}{{if .Reason}}: {{.Reason}}{{end}}{{with .IgnoreNote}}<br>Repository ignores: {{.}}{{end}}{{if or .Requests .Refused}}<br>Requests answered by the target: {{.Requests}}. Refused by SiegeKit: {{.Refused}}{{if .RefusedTo}} ({{range $i, $d := .RefusedTo}}{{if $i}}, {{end}}<code>{{$d}}</code>{{end}}){{end}}.{{end}}</td><td>{{.Findings}}</td></tr>
{{else}}<tr><td colspan="5">No checks were selected.</td></tr>{{end}}
</table>

<h2>Not tested by SiegeKit</h2>
<p>Automated tools cannot check these. Review them yourself before deploying; see the pre-deploy checklist in the SiegeKit documentation.</p>
<ul>{{range .NotTested}}<li>{{.}}</li>{{end}}</ul>

<h2>Findings</h2>
<p>{{range $i, $c := .Counts}}{{if $i}} · {{end}}{{$c.Name}}: {{$c.N}}{{end}}</p>
{{range .Run.Findings}}
<h3 class="sev-{{.Severity}}">{{if index $.New .Fingerprint}}New: {{end}}[{{.Severity}}] {{.Title}}</h3>
<p>{{.Message}}</p>
<p><code>{{.Location.URI}}{{if .Location.StartLine}}:{{.Location.StartLine}}{{end}}</code>{{if .CWEs}} · {{range $i, $c := .CWEs}}{{if $i}}, {{end}}{{$c}}{{end}}{{end}}</p>
{{if .Snippet}}<pre>{{.Snippet}}</pre>{{end}}
<p>Reported by: {{range $i, $s := .Sources}}{{if $i}}, {{end}}{{$s.Plugin}} ({{$s.RuleID}}){{end}}{{if .HelpURI}} · <a href="{{.HelpURI}}" rel="noreferrer">About this rule</a>{{end}}</p>
{{else}}<p>None reported by the checks that ran.</p>{{end}}
</body>
</html>
`))

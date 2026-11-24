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

// Cause says, as a fixed word, why a check did not run (ADR 0041). Code,
// CI and AI agents decide on the cause; Reason is the explanation for
// people and can be reworded.
type Cause string

// Causes of a check that did not run. Every skipped check has one; a check
// that failed before it started can have one too.
const (
	// The container engine, an image, a file or data is not installed, or
	// could not be installed.
	CauseMissingDependency Cause = "missing-dependency"
	// The person said no to installing a dependency.
	CauseDeclined Cause = "declined"
	// The target has nothing the check reads: no files of its kind, or no
	// git history.
	CauseNoFiles Cause = "no-files"
	// The check does not run in this target mode: local-only checks on
	// deployed targets, or checks that can change data.
	CauseTargetMode Cause = "deployed-or-local-only"
	// The chosen --profile leaves the check out.
	CauseProfile Cause = "profile"
	// The check needs an input that was not given or not found: a login,
	// a URL, a HAR file, a backend URL, an OpenAPI spec.
	CauseNoInput Cause = "no-input"
	// The check needs a person's confirmation, which was not given.
	CauseNotConfirmed Cause = "not-confirmed"
	// The check does not run on this operating system or architecture.
	CausePlatform Cause = "platform"
	// The plugin's kind does not fit this kind of target (a passive plugin
	// on a URL); a bug in how plugins were selected.
	CauseUnsupported Cause = "unsupported"
)

// Causes lists every cause, in the order documented in docs/agents.md.
var Causes = []Cause{CauseMissingDependency, CauseDeclined, CauseNoFiles, CauseTargetMode, CauseProfile, CauseNoInput, CauseNotConfirmed, CausePlatform, CauseUnsupported}

// Valid reports whether c is one of Causes.
func (c Cause) Valid() bool {
	for _, k := range Causes {
		if c == k {
			return true
		}
	}
	return false
}

// MissingDependency reports whether c means a dependency is missing or was
// declined: the skips --require-all counts (ADR 0016, ADR 0041).
func (c Cause) MissingDependency() bool {
	return c == CauseMissingDependency || c == CauseDeclined
}

// PluginResult is the coverage record for one plugin (ADR 0009 item 2).
type PluginResult struct {
	ID      string `json:"id"`
	Family  string `json:"family"`
	Tool    string `json:"tool"`
	Version string `json:"version"`
	Status  Status `json:"status"`
	Reason  string `json:"reason,omitempty"`
	// Cause is set on every skipped check, and on a check that failed
	// before it started when the cause is known (ADR 0041).
	Cause    Cause `json:"cause,omitempty"`
	Findings int   `json:"findings"`
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
	// Input names what the plugin tested from besides the target, such as
	// the OpenAPI spec Schemathesis used (ADR 0028).
	Input string `json:"input,omitempty"`
	// Result says what a check saw when that is not a finding, such as
	// "limited after 6 of 20 attempts" for the login throttling check
	// (ADR 0030).
	Result string `json:"result,omitempty"`
	// Stop says, as a fixed word, why the check was cut short (ADR 0067,
	// decision 1). The check is failed (timed-out for StopTimeLimit) and
	// its findings up to the stop are kept.
	Stop Stop `json:"stop,omitempty"`
	// Gaps names what the check could not read, each with a typed cause
	// (ADR 0067, decision 1); at most MaxGaps are listed and GapCount
	// counts them all. Gaps do not change the exit code unless
	// --require-complete is given.
	Gaps     []Gap `json:"gaps,omitempty"`
	GapCount int   `json:"gapCount,omitempty"`
	// Completeness is set on every check that ran: whether it compared what
	// it was given with what it checked (ADR 0067).
	Completeness Completeness `json:"completeness,omitempty"`
	// Usage is what the check's container used, as the waiter measured it.
	Usage *Usage `json:"usage,omitempty"`
}

// Stop is why a check was cut short (ADR 0067).
type Stop string

// Run stops. A stopped check fails the run with exit code 4.
const (
	StopTimeLimit       Stop = "time-limit"
	StopMemoryKill      Stop = "memory-kill"
	StopProcessLimit    Stop = "process-limit"
	StopKilled          Stop = "killed"
	StopOutputLimit     Stop = "output-limit"
	StopCountersUnread  Stop = "counters-unread"
	StopTargetStopped   Stop = "target-stopped"   // SiegeKit's proxy stopped the run: the target kept failing
	StopFileLimit       Stop = "file-limit"       // the tree has more files than a check reads
	StopRequestLimit    Stop = "request-limit"    // a check reached its own request cap
	StopAnswerTooLarge  Stop = "answer-too-large" // an answer the check compares was cut at its size limit
	StopTargetUnreached Stop = "target-unreached" // a request the check needs got no answer
)

// Completeness says whether a check that ran showed it checked everything
// it was given (ADR 0067, decision 1).
type Completeness string

const (
	// Complete: the check compared what it was given with what it checked
	// and found nothing left out.
	Complete Completeness = "complete"
	// WithGaps: the check named what it could not read in Gaps.
	WithGaps Completeness = "gaps"
	// NotProven: the tool leaves no signal to compare, so the check cannot
	// show it read everything.
	NotProven Completeness = "not-proven"
)

// GapCause says, as a fixed word, why something was not checked.
type GapCause string

// Gap causes.
const (
	GapTooLarge  GapCause = "too-large"  // a file over the size a check reads
	GapTooDeep   GapCause = "too-deep"   // a folder deeper than a check descends
	GapNotParsed GapCause = "not-parsed" // the tool could not parse the file
	GapOverLimit GapCause = "over-limit" // more items than the check takes
	GapNoAnswer  GapCause = "no-answer"  // a request for it got no usable answer
)

// Gap is one thing a check could not read.
type Gap struct {
	Cause GapCause `json:"cause"`
	// Path is a slash-separated path in the target, or a URL path.
	Path   string `json:"path"`
	Detail string `json:"detail,omitempty"`
}

// MaxGaps is how many gaps a check lists; GapCount counts the rest.
const MaxGaps = 200

// AddGap records g, listing it while fewer than MaxGaps are listed.
func (p *PluginResult) AddGap(g Gap) {
	p.GapCount++
	if len(p.Gaps) < MaxGaps {
		p.Gaps = append(p.Gaps, g)
	}
}

// Usage is the program memory and processes a check's container used.
type Usage struct {
	// MemoryPeak is the highest program memory sampled every 0.2 s, in
	// bytes (anon memory; file cache left out).
	MemoryPeak   int64 `json:"memoryPeak"`
	MemoryLimit  int64 `json:"memoryLimit"`
	ProcessPeak  int64 `json:"processPeak"`
	ProcessLimit int64 `json:"processLimit"`
}

// GapNote says in one line what the check could not read, or "".
func (p PluginResult) GapNote() string {
	if p.GapCount == 0 {
		return ""
	}
	const show = 5
	var names []string
	for _, g := range p.Gaps[:min(show, len(p.Gaps))] {
		n := g.Path + " (" + string(g.Cause)
		if g.Detail != "" {
			n += ": " + g.Detail
		}
		names = append(names, n+")")
	}
	s := fmt.Sprintf("%d not checked: %s", p.GapCount, strings.Join(names, ", "))
	if p.GapCount > len(names) {
		s += fmt.Sprintf(" and %d more (all listed in report.json, up to %d)", p.GapCount-len(names), MaxGaps)
	}
	return s
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
	// Environment names where the run happened (ADR 0038): results from one
	// container engine, mode or cgroup version do not carry over to another.
	Environment *Environment `json:"environment,omitempty"`
}

// Environment is the machine and container engine of a run.
type Environment struct {
	OS   string `json:"os"`
	Arch string `json:"arch"`
	// Go is the Go release SiegeKit was built with, such as "go1.27.4"; it
	// decides the built-in checks' and the relay's behavior (full project
	// check F11). Tools in images bring their own.
	Go     string  `json:"go,omitempty"`
	Engine *Engine `json:"engine,omitempty"` // nil when no engine was found or it did not answer
}

// Engine is the container engine that ran the tools.
type Engine struct {
	Name     string `json:"name"` // "docker" or "podman"
	Version  string `json:"version"`
	Rootless bool   `json:"rootless"`
	Cgroup   string `json:"cgroup,omitempty"` // "v1" or "v2"
}

// String is the form shown in the terminal and the HTML report.
func (e *Environment) String() string {
	s := e.OS + "/" + e.Arch
	if e.Go != "" {
		s += ", SiegeKit built with " + e.Go
	}
	if e.Engine == nil {
		return s + ", no container engine"
	}
	s += ", " + e.Engine.Name + " " + e.Engine.Version
	if e.Engine.Rootless {
		s += " rootless"
	} else {
		s += " rootful"
	}
	if e.Engine.Cgroup != "" {
		s += ", cgroup " + e.Engine.Cgroup
	}
	return s
}

// Comparison says what changed since the last saved run of the same target
// (ADR 0013). A finding that disappeared counts as fixed only if a plugin
// that reported it ran to completion in this run. Otherwise it is listed as
// not run, when the person left every such check out of this run (ADR
// 0063), or as not checked again, when a check could not run or did not
// complete, so a failed check cannot make problems look fixed.
type Comparison struct {
	PreviousRun     string             `json:"previousRun"`
	PreviousStarted time.Time          `json:"previousStarted"`
	PreviousVersion string             `json:"previousVersion"`
	New             []string           `json:"new"` // fingerprints of findings the previous run did not report
	Fixed           []findings.Finding `json:"fixed"`
	NotRechecked    []findings.Finding `json:"notRechecked"` // gone from this run, but a check that reported them could not run or did not complete
	NotRun          []findings.Finding `json:"notRun"`       // gone from this run, but every check that reported them was left out by --only, --skip or --profile
	StillPresent    int                `json:"stillPresent"` // reported by both runs
}

// Summary is one line for the terminal and the HTML report.
func (c *Comparison) Summary() string {
	s := fmt.Sprintf("Since the last scan of this target (%s): %d new, %d fixed, %d still present",
		c.PreviousStarted.UTC().Format("2006-01-02 15:04 UTC"), len(c.New), len(c.Fixed), c.StillPresent)
	if n := len(c.NotRun); n > 0 {
		s += fmt.Sprintf(", %d not run this time because their check was left out (--only, --skip or --profile)", n)
	}
	if n := len(c.NotRechecked); n > 0 {
		s += fmt.Sprintf(", %d not checked again because their check could not run or did not complete", n)
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
	// Keep this list true for the current version. Update the web and
	// language lines when Opengrep (M2.9) lands.
	"The running application, unless you scanned its URL: a directory scan only reads files. A URL scan crawls the app with ZAP and runs ZAP's passive checks, runs Nuclei's templates for known issues, exposed files and misconfigurations, and asks for common paths with ffuf. Attack tests (ZAP's attack scan, Nuclei's intrusive and default-login templates, Schemathesis's API tests) run only on local targets; deployed targets get only GET and HEAD requests until request limits are measured. ZAP's crawler follows HTML links, so pages that a single-page app builds in JavaScript are mostly not reached. Nuclei runs only its HTTP templates (its TCP, DNS, SSL and JavaScript templates cannot pass SiegeKit's proxy), without out-of-band callbacks (so blind flaws such as blind SSRF are not found), and without its denial-of-service, fuzzing and brute-force templates; its default-login templates, which try each vendor's documented factory logins once, run only on local targets. ffuf guesses 4,751 common paths on local targets but only 210 on deployed targets, so exposed files with other names are missed there. Schemathesis tests an API only with an OpenAPI or Swagger 2.0 spec, given with --openapi or found at one of 11 common paths; APIs without one are not tested by it, and its random inputs can miss bugs. The login throttling check runs only on local targets and only with a login given by --login-url, --login-user and --login-body; it does not see a limit set above the number of attempts it sends (20 by default), one per IP address, or one across many accounts. The rate-limit check runs only on local targets, on one URL given by --rate-limit-url that answers without a login; it does not see a limit set above the number of requests it sends (20 by default), one per IP address, one that only slows answers, or one that shows no 429 or 503 and no rate-limit header. ZAP's attack scan sends request bodies (XML, JSON, forms) only for the requests of a --har recording, so XML external entities (XXE) and flaws in writes the recording does not hold are not tested, and SAML is not tested. The public-maps check looks for an API spec only at 11 common paths (a spec elsewhere, Swagger UI mounted elsewhere than /api-docs and GraphQL schemas are not found) and for the source maps of the files the start page links. The served-secrets check scans for keys only the start page and the same-origin scripts, styles, JSON files and source maps it links (at most 200 requests, 10 MiB each), with Gitleaks' rules: scripts loaded later by other scripts, other pages, files on other origins such as CDNs, inline source maps and files behind a login are not scanned. sqlmap and Nikto are planned for M2.",
	"The source code, unless you scanned its directory: a URL scan only sends requests to the running app.",
	"Code in languages without an analyzer: Python (bandit) and Go (gosec) code is analyzed; JavaScript, TypeScript and other languages are not yet (planned for M2). Secrets, dependencies and configuration files are checked in any language.",
	"Development dependencies in pnpm lockfiles older than version 9: Trivy leaves them out of its results, so their vulnerabilities are not reported. In npm, Yarn, Bun and uv lockfiles development dependencies are scanned and a finding says when the package is one (measured); other lockfile formats were not measured.",
	"Access control: whether every request checks that this user may access this record. The access-control check (URL scans with --har) replays only the GET and HEAD requests of a browser recording made as one test account, plus OpenAPI routes without path parameters, as a second account and with no login; it reports an answer only when the second account gets exactly the first account's answer while a request with no login is refused, or when a request with no login gets the first account's answer with its login name in it, or a JSON answer with a field named like a password, hash, secret, key or token that holds a value. It does not test pages the recording did not reach, other IDs than the recorded ones, changes (POST, PUT, PATCH, DELETE), answers that differ on every request, secrets given only to logged-in accounts, or data readable with no login that neither names the first account nor has a field named like a secret. Without --har, access control is not tested.",
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

// GapCount counts what the checks that ran could not read.
func (r *Run) GapCount() int {
	n := 0
	for _, p := range r.Plugins {
		if p.Status == Ran {
			n += p.GapCount
		}
	}
	return n
}

// MarkCompleteness sets each ran check's completeness that its runner left
// unset: with gaps when it named any, otherwise not proven, so no check
// is called complete without a signal (ADR 0067).
func (r *Run) MarkCompleteness() {
	for i, p := range r.Plugins {
		switch {
		case p.Status != Ran:
			r.Plugins[i].Completeness = ""
		case p.GapCount > 0:
			r.Plugins[i].Completeness = WithGaps
		case p.Completeness == "":
			r.Plugins[i].Completeness = NotProven
		}
	}
}

// CheckCauses makes every skipped check without a valid cause failed, so a
// missing cause is never read as an acceptable skip (ADR 0041). It returns
// the IDs it changed; any is a bug in SiegeKit.
func (r *Run) CheckCauses() []string {
	var bad []string
	for i, p := range r.Plugins {
		if p.Status == Skipped && !p.Cause.Valid() {
			r.Plugins[i].Status = Failed
			r.Plugins[i].Reason = fmt.Sprintf("SiegeKit bug: skipped with no valid cause (%q): %s", p.Cause, p.Reason)
			bad = append(bad, p.ID)
		}
	}
	return bad
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
// otherwise ExitIncomplete if any plugin failed or timed out, or, with
// requireComplete, if a check that ran named gaps (ADR 0067), otherwise
// ExitClean. An incomplete run is never reported as clean.
func (r *Run) ExitCode(threshold findings.Severity, requireComplete bool) int {
	for _, f := range r.Findings {
		if f.Severity >= threshold {
			return ExitFindings
		}
	}
	if !r.Complete() || r.RanCount() == 0 || requireComplete && r.GapCount() > 0 {
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
		"Gaps":        r.GapCount(),
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
{{if not .Complete}}<p class="warn">This run is incomplete: at least one check failed, timed out or was cut short. Missing checks may hide issues.</p>{{end}}
{{with .Gaps}}<p class="warn">{{.}} file(s) or item(s) could not be checked; each check below names them.</p>{{end}}
<p>Target: <code>{{.Run.Target}}</code> · Mode: {{.Run.Mode}} · SiegeKit {{.Run.SiegeKitVersion}} · {{.Run.Started.Format "2006-01-02 15:04 MST"}}{{with .Run.Environment}} · {{.String}}{{end}}</p>

{{with .Run.Comparison}}<h2>Since the last scan</h2>
<p>{{.Summary}} Previous run: <code>{{.PreviousRun}}</code>.</p>
{{with $.VersionNote}}<p class="warn">{{.}}</p>{{end}}
{{if .Fixed}}<p>Fixed: the check that reported each one ran to completion and did not report it again. An ignore setting added to the repository also hides a finding; each check's ignore counts are under "What was tested".</p>
<ul>{{range .Fixed}}<li>[{{.Severity}}] {{.Title}} · <code>{{.Location.URI}}{{if .Location.StartLine}}:{{.Location.StartLine}}{{end}}</code></li>{{end}}</ul>{{end}}
{{if .NotRechecked}}<p class="warn">Not checked again, because their check could not run or did not complete in this run:</p>
<ul>{{range .NotRechecked}}<li>[{{.Severity}}] {{.Title}} · <code>{{.Location.URI}}{{if .Location.StartLine}}:{{.Location.StartLine}}{{end}}</code></li>{{end}}</ul>{{end}}
{{if .NotRun}}<p>Not run this time, because their check was left out with --only, --skip or --profile. They are still open from the last scan:</p>
<ul>{{range .NotRun}}<li>[{{.Severity}}] {{.Title}} · <code>{{.Location.URI}}{{if .Location.StartLine}}:{{.Location.StartLine}}{{end}}</code></li>{{end}}</ul>{{end}}
{{end}}
<h2>What was tested</h2>
<table>
<tr><th>Check</th><th>Family</th><th>Tool</th><th>Status</th><th>Findings</th></tr>
{{range .Plugins}}<tr><td>{{.ID}}</td><td>{{.Family}}</td><td>{{.Tool}} {{.Version}}</td><td>{{.Status}}{{if .Reason}}: {{.Reason}}{{end}}{{with .IgnoreNote}}<br>Repository ignores: {{.}}{{end}}{{with .Input}}<br>Tested from: {{.}}{{end}}{{with .Result}}<br>Result: {{.}}{{end}}{{with .Stop}}<br>Cut short: {{.}}{{end}}{{with .GapNote}}<br>Gaps: {{.}}{{end}}{{if eq .Completeness "not-proven"}}<br>Not proven complete: the tool gives no count of what it read.{{end}}{{if or .Requests .Refused}}<br>Requests answered by the target: {{.Requests}}. Refused by SiegeKit: {{.Refused}}{{if .RefusedTo}} ({{range $i, $d := .RefusedTo}}{{if $i}}, {{end}}<code>{{$d}}</code>{{end}}){{end}}.{{end}}</td><td>{{.Findings}}</td></tr>
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

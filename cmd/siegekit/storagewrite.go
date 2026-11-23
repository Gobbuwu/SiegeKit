package main

import (
	"context"
	"fmt"
	"io"
	"slices"
	"strings"
	"time"

	"github.com/Gobbuwu/SiegeKit/internal/audit"
	"github.com/Gobbuwu/SiegeKit/internal/backend"
	"github.com/Gobbuwu/SiegeKit/internal/checks"
	"github.com/Gobbuwu/SiegeKit/internal/egress"
	"github.com/Gobbuwu/SiegeKit/internal/findings"
	"github.com/Gobbuwu/SiegeKit/internal/report"
	"github.com/Gobbuwu/SiegeKit/internal/target"
)

// storageWrite runs the storage write test; tests replace it.
var storageWrite = backend.WriteStorage

// writeTestFiles is the phrase a person types before the first upload
// (ADR 0058 item 4).
const writeTestFiles = "write test files"

// storagePlan is a --storage-url host that passed the address rules.
type storagePlan struct {
	s    *backend.Storage
	host *hostPlan
}

// storageRun is what runStorage needs from the scan.
type storageRun struct {
	plan *storagePlan
	col  *collected
	repo *checks.Source
	// backendConfirmed is the host typed for backend-live in this run; the
	// same Supabase host is not asked twice.
	backendConfirmed string
	auditLog, mode   string
	env              string
	extraRequests    int
}

// runStorage reads the bucket names, folders and public key from the
// app's scripts (and --source), shows the person every file it will
// upload, asks for the typed confirmations, writes the audit entry, and
// then tests each location (ADR 0058). Nothing is sent to the storage
// before the person typed the phrase. It returns interrupted when ctx
// ended during the writes; the leftovers are printed first.
func (o *urlScan) runStorage(ctx context.Context, r storageRun, stdout io.Writer) (pr report.PluginResult, fs []findings.Finding, interrupted bool) {
	pr = report.PluginResult{ID: backend.StorageID, Family: backend.StorageFamily, Tool: "siegekit", Version: version, Requests: r.extraRequests}
	failed := func(format string, a ...any) (report.PluginResult, []findings.Finding, bool) {
		pr.Status, pr.Reason = report.Failed, fmt.Sprintf(format, a...)
		return pr, nil, false
	}
	p := r.plan
	pr.Input = p.s.URL.Origin()
	if r.col.err != nil {
		return failed("the app's start page and scripts could not be fetched: %v", r.col.err)
	}
	files, err := r.col.read()
	if err != nil {
		return failed("%v", err)
	}
	sc := backend.ReadStorageScripts(p.s, files)
	if sc.Kind == "" {
		return failed("cannot tell whether %s is Supabase or Firebase Storage: the app's scripts name neither", p.s.URL.Origin())
	}
	// A storage host not on this machine must be the app's: hosted Firebase
	// Storage is shared by every project, so there the bucket named in the
	// app's config is what ties it to the app.
	if p.host.remote && !p.s.Hosted() && !sc.HostSeen {
		return failed("%s does not appear in the app's start page or scripts (%d file(s) fetched), so SiegeKit cannot tell it is this app's storage; nothing was sent to it", p.s.URL.Host, len(files))
	}
	buckets, folders := sc.Buckets, sc.Folders
	fromSource := 0
	if r.repo != nil {
		switch sc.Kind {
		case backend.FirebaseStorage:
			// Buckets come only from the app's own config.
			folders = merge(folders, r.repo.FirebaseFolders)
			fromSource = len(r.repo.FirebaseFolders)
		case backend.SupabaseStorage:
			buckets = merge(buckets, r.repo.SupabaseBuckets)
			folders = merge(folders, r.repo.SupabaseFolders)
			fromSource = len(r.repo.SupabaseBuckets) + len(r.repo.SupabaseFolders)
		}
	}
	pr.Input = fmt.Sprintf("%s %s; %d bucket(s) and %d folder(s) from the app's scripts", sc.Kind, p.s.URL.Origin(), len(sc.Buckets), len(sc.Folders))
	if r.repo != nil {
		pr.Input += fmt.Sprintf(", %d name(s) from --source", fromSource)
	}
	if len(buckets) == 0 {
		return failed("no bucket name was found in the app's scripts (storageBucket in the Firebase config, or .storage.from(\"NAME\") for Supabase); nothing was sent")
	}
	if sc.Kind == backend.SupabaseStorage {
		if sc.Key == "" {
			return failed("no Supabase public key was found in the app's scripts; nothing was sent")
		}
		pr.Input += "; public key from " + sc.KeyFile
	}
	locs, left, err := backend.PlanFiles(buckets, sc.Pairs, folders)
	if err != nil {
		return failed("%v", err)
	}
	verification, confirmed, reason := o.confirmStorage(p, sc.Kind, locs, left, r.backendConfirmed, stdout)
	if reason != "" {
		pr.Status, pr.Cause, pr.Reason = report.Skipped, report.CauseNotConfirmed, reason
		fmt.Fprintf(stdout, "  %-20s not run - %s\n", backend.StorageID, reason)
		return pr, nil, false
	}
	// The storage is another host, so it gets its own entry (ADR 0037).
	if err := audit.Append(r.auditLog, audit.Entry{
		Time: time.Now().UTC(), Version: version, Target: p.s.URL.String(), Addresses: addrStrings(p.host.addrs),
		Mode: r.mode, Verification: verification, Confirmed: confirmed, Plugins: []string{backend.StorageID}, Environment: r.env,
	}); err != nil {
		return failed("nothing was uploaded: %v", err)
	}
	fmt.Fprintf(stdout, "%s: uploading %d test file(s) to %s.\n", backend.StorageID, len(locs), p.s.URL.Origin())
	cfg := egress.Config{Target: p.s.URL, Addrs: p.host.addrs, VerifyTLS: p.host.public, Version: version}
	res, err := storageWrite(ctx, cfg, sc.Kind, sc.Key, locs, left)
	pr.Requests += res.Requests
	if lo := res.Leftovers(); len(lo) > 0 {
		fmt.Fprintf(stdout, "%s: %d test file(s) may still be there; delete them:\n", backend.StorageID, len(lo))
		for _, l := range lo {
			fmt.Fprintf(stdout, "  %s\n", l.Where(sc.Kind))
		}
	}
	if ctx.Err() != nil {
		return pr, nil, true
	}
	if err != nil {
		pr.Status, pr.Reason = report.Failed, err.Error()
		if len(res.Outcomes) > 0 {
			pr.Reason += "; " + res.Summary()
		}
		return pr, nil, false
	}
	fs = backend.StorageFindings(p.s, res)
	pr.Status, pr.Result, pr.Findings = report.Ran, res.Summary(), len(fs)
	return pr, fs, false
}

// confirmStorage shows the files and asks, in a terminal only: the host
// name (or, for hosted Firebase Storage, each bucket name) when the
// storage is not on this machine, then the phrase. No flag skips either;
// a program that drives a pseudo-terminal can type them (ADR 0044). It
// returns the audit entry's verification and confirmed values, or the
// reason the test does not run.
func (o *urlScan) confirmStorage(p *storagePlan, kind backend.StorageKind, locs []backend.Location, left int, backendConfirmed string, stdout io.Writer) (verification, confirmed, reason string) {
	if !stdinIsTerminal() {
		return "", "", fmt.Sprintf("it uploads files to the app's storage, so a person must type %q in a terminal; run this command yourself (an AI assistant should ask you to). No flag skips this", writeTestFiles)
	}
	verification = "loopback"
	switch {
	case !p.host.remote:
	case p.s.Hosted():
		var typed []string
		for _, b := range bucketsOf(locs) {
			fmt.Fprintf(stdout, "%s writes to the bucket %s on %s, which every Firebase project shares. Type the bucket name (%s) to confirm it is this app's and you may write to it: ", backend.StorageID, b, p.s.URL.Host, b)
			line, _ := o.in.ReadString('\n')
			if strings.TrimSuffix(strings.ToLower(strings.TrimSpace(line)), "/") != strings.ToLower(b) && strings.TrimSpace(line) != "gs://"+b {
				return "", "", fmt.Sprintf("the typed bucket name did not match %q", b)
			}
			typed = append(typed, b)
		}
		verification, confirmed = "typed bucket name", strings.Join(typed, " ")
	case backendConfirmed != "" && backendConfirmed == p.s.URL.Host:
		verification, confirmed = "typed storage host (for backend-live)", p.s.URL.Host
	default:
		fmt.Fprintf(stdout, "%s writes to %s, which is not on this machine. Type its host name (%s) to confirm it is this app's storage and you may write to it: ", backend.StorageID, p.s.URL.Origin(), p.s.URL.Host)
		line, _ := o.in.ReadString('\n')
		if !target.Confirmed(p.s.URL, line) {
			return "", "", fmt.Sprintf("the typed host name did not match %q", p.s.URL.Host)
		}
		verification, confirmed = "typed storage host", p.s.URL.Host
	}
	fmt.Fprintf(stdout, "%s will upload one %d-byte text file (%q) to each of these %d location(s) in %s, read it back, and delete it:\n", backend.StorageID, len(backend.TestContent), backend.TestContent, len(locs), kind)
	for _, l := range locs {
		fmt.Fprintf(stdout, "  %s\n", l.Where(kind))
	}
	if left > 0 {
		fmt.Fprintf(stdout, "  (%d more location(s) over the %d-file limit are not tested)\n", left, backend.MaxFiles)
	}
	fmt.Fprintf(stdout, "Where the rules allow the upload but refuse the delete, the file stays, and SiegeKit lists it for you to delete. An upload can also start the app's own storage triggers, such as functions that resize images or send messages. Type %q to upload them: ", writeTestFiles)
	line, _ := o.in.ReadString('\n')
	if strings.TrimSpace(line) != writeTestFiles {
		return "", "", fmt.Sprintf("not confirmed: %q was not typed", writeTestFiles)
	}
	return verification + " + typed phrase", confirmed, ""
}

func bucketsOf(locs []backend.Location) []string {
	var out []string
	for _, l := range locs {
		if !slices.Contains(out, l.Bucket) {
			out = append(out, l.Bucket)
		}
	}
	return out
}

// merge joins two name lists, sorted and without duplicates.
func merge(a, b []string) []string {
	out := slices.Concat(a, b)
	slices.Sort(out)
	return slices.Compact(out)
}

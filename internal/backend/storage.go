package backend

// The storage write test (ADR 0058, amending ADR 0037). A Firebase Storage
// or Supabase Storage bucket whose rules let anyone write takes uploads
// from anyone who loads the app. The rules file does not show every such
// bucket (measured: 4 of 5 open Firebase rule sets, 0 of 5 Supabase policy
// sets), so this check uploads one small text file with the app's public
// key, reads it back, deletes it, and checks that it is gone.

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"slices"
	"strings"

	"github.com/Gobbuwu/SiegeKit/internal/egress"
	"github.com/Gobbuwu/SiegeKit/internal/findings"
	"github.com/Gobbuwu/SiegeKit/internal/target"
)

// StorageID, StorageName and StorageFamily describe the check.
const (
	StorageID     = "storage-write"
	StorageName   = "Storage write test"
	StorageFamily = "dast"
)

// MaxFiles is the most test files one run uploads, bucket roots included
// (design safety rule 4).
const MaxFiles = 5

// TestContent is the test file: 36 bytes of plain text that say what it is.
const TestContent = "SiegeKit write test. Safe to delete."

// StorageKind is the storage product.
type StorageKind string

// The storage services SiegeKit can test.
const (
	SupabaseStorage StorageKind = "Supabase Storage"
	FirebaseStorage StorageKind = "Firebase Storage"
)

// firebaseStorageHost is hosted Firebase Storage, shared by every project:
// the bucket, not the host, names the project.
const firebaseStorageHost = "firebasestorage.googleapis.com"

// Storage is the --storage-url value.
type Storage struct {
	URL  *target.URL
	Kind StorageKind // "" when the host name does not tell; the app's scripts then do
}

// Hosted reports whether the URL is hosted Firebase Storage, where the
// bucket names the project and is what a person confirms.
func (s *Storage) Hosted() bool { return s.URL.Host == firebaseStorageHost }

// ParseStorage checks --storage-url: an http or https URL with no path,
// query, fragment or user name. Hosted Supabase (*.supabase.co) and hosted
// Firebase Storage (firebasestorage.googleapis.com) are known by their
// host name and must use https; any other host (a local stack or emulator)
// is told apart by the app's scripts.
func ParseStorage(raw string) (*Storage, error) {
	pu, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("--storage-url: not a valid URL: %w", err)
	}
	if pu.RawQuery != "" || pu.ForceQuery || pu.Fragment != "" || strings.ContainsAny(raw, "?#") {
		return nil, errors.New("--storage-url must not have a query or fragment")
	}
	s := &Storage{}
	if s.URL, err = target.Parse(raw); err != nil {
		return nil, fmt.Errorf("--storage-url: %w", err)
	}
	if s.URL.Path != "/" {
		return nil, errors.New("--storage-url must be the storage service's address with no path, such as https://PROJECT.supabase.co or https://" + firebaseStorageHost)
	}
	switch h := s.URL.Host; {
	case strings.HasSuffix(h, ".supabase.co"):
		s.Kind = SupabaseStorage
	case h == firebaseStorageHost:
		s.Kind = FirebaseStorage
	}
	if s.Kind != "" && s.URL.Scheme != "https" {
		return nil, errors.New("--storage-url: hosted Supabase and Firebase Storage use https")
	}
	return s, nil
}

// StorageScripts is what the app's served files say about its storage.
type StorageScripts struct {
	HostSeen bool // the storage host appears in a served file (not used for hosted Firebase)
	Kind     StorageKind
	Key      string // Supabase public key, as backend-live reads it
	KeyFile  string
	Buckets  []string
	Folders  []string // "uploads/", always ending in "/"
	// Pairs are folders the scripts upload to in a named bucket, from
	// .storage.from("B").upload("F..."): they are tested before the
	// folders that could be in any bucket.
	Pairs []Location
}

var (
	// Firebase: storageBucket: "NAME" in the app's config (minifiers keep
	// object keys), and gs://NAME literals.
	reStorageBucket = regexp.MustCompile(`\bstorageBucket["']?\s*:\s*["'\x60]([a-z0-9][a-z0-9._-]{1,220}[a-z0-9])["'\x60]`)
	reGS            = regexp.MustCompile(`["'\x60]gs://([a-z0-9][a-z0-9._-]{1,220}[a-z0-9])/?["'\x60]`)
	// Supabase: .storage.from("NAME"); minifiers keep property names.
	reSupabaseBucket = regexp.MustCompile(`\.\s*storage\s*\.\s*from\s*\(\s*["'\x60]([^"'\x60\\$/]{1,100})["'\x60]\s*\)`)
	// Supabase: .upload("PATH" or .upload(`PATH${...}`, the first argument
	// up to its first ${ or its end, and the same chained to its bucket.
	reUpload       = regexp.MustCompile(`\.\s*upload\s*\(\s*["'\x60]([^"'\x60\\$]{1,200})`)
	reBucketUpload = regexp.MustCompile(`\.\s*storage\s*\.\s*from\s*\(\s*["'\x60]([^"'\x60\\$/]{1,100})["'\x60]\s*\)\s*\.\s*upload\s*\(\s*["'\x60]([^"'\x60\\$]{1,200})`)
	// Firebase: ref(storage, "PATH") and .child("PATH") as written; a
	// minified bundle renames ref() (measured with esbuild 0.25.0), so
	// there folders come only from storage.rules (--source).
	reStorageRef = regexp.MustCompile(`(?:\bref|\.child)\s*\(\s*(?:[A-Za-z_$][\w$.]*\s*,\s*)?["'\x60]([^"'\x60\\$]{1,200})`)
)

// ReadStorageScripts reads the fetched files (name to content). The key
// and kind come from ReadScripts, so the same rules apply: only keys meant
// to be public are ever returned.
func ReadStorageScripts(s *Storage, files map[string][]byte) StorageScripts {
	hint := Kind("")
	if s.Kind == SupabaseStorage {
		hint = Supabase
	}
	sc := ReadScripts(&Backend{URL: s.URL, Kind: hint}, files)
	out := StorageScripts{HostSeen: sc.HostSeen, Kind: s.Kind}
	if out.Kind == "" {
		switch sc.Kind {
		case Supabase:
			out.Kind = SupabaseStorage
		case Firebase:
			out.Kind = FirebaseStorage
		}
	}
	if out.Kind == SupabaseStorage {
		out.Key, out.KeyFile = sc.Key, sc.KeyFile
	}
	buckets, folders, pairs := map[string]bool{}, map[string]bool{}, map[Location]bool{}
	for _, n := range sortedFileNames(files) {
		data := string(files[n])
		switch out.Kind {
		case FirebaseStorage:
			for _, re := range []*regexp.Regexp{reStorageBucket, reGS} {
				for _, m := range re.FindAllStringSubmatch(data, -1) {
					buckets[m[1]] = true
				}
			}
			for _, m := range reStorageRef.FindAllStringSubmatch(data, -1) {
				if f := Folder(m[1]); f != "" {
					folders[f] = true
				}
			}
		case SupabaseStorage:
			for _, m := range reSupabaseBucket.FindAllStringSubmatch(data, -1) {
				buckets[m[1]] = true
			}
			for _, m := range reUpload.FindAllStringSubmatch(data, -1) {
				if f := Folder(m[1]); f != "" {
					folders[f] = true
				}
			}
			for _, m := range reBucketUpload.FindAllStringSubmatch(data, -1) {
				if f := Folder(m[2]); f != "" {
					pairs[Location{Bucket: m[1], Folder: f}] = true
				}
			}
		}
	}
	out.Buckets, out.Folders = sortedKeys(buckets), sortedKeys(folders)
	for l := range pairs {
		out.Pairs = append(out.Pairs, l)
	}
	slices.SortFunc(out.Pairs, func(a, b Location) int { return strings.Compare(a.Bucket+"/"+a.Folder, b.Bucket+"/"+b.Folder) })
	return out
}

func sortedFileNames(files map[string][]byte) []string {
	m := make(map[string]bool, len(files))
	for n := range files {
		m[n] = true
	}
	return sortedKeys(m)
}

var reFolderSeg = regexp.MustCompile(`^[A-Za-z0-9._-]{1,100}$`)

// Folder is the folder part of an object path written in code or rules
// ("uploads/" from "uploads/" + name or uploads/${uid}/x), at most three
// plain segments, or "" for the bucket root or a path that is not plain.
func Folder(p string) string {
	p = strings.TrimPrefix(p, "/")
	i := strings.LastIndex(p, "/")
	if i <= 0 {
		return ""
	}
	segs := strings.Split(p[:i], "/")
	if len(segs) > 3 {
		segs = segs[:3]
	}
	for _, s := range segs {
		if !reFolderSeg.MatchString(s) || s == "." || s == ".." {
			return ""
		}
	}
	return strings.Join(segs, "/") + "/"
}

// Location is one test file: a bucket, a folder ("" is the root) and a
// name chosen at random for this run.
type Location struct {
	Bucket, Folder, Name string
}

// Path is the object path inside the bucket.
func (l Location) Path() string { return l.Folder + l.Name }

// Where names the location for people: gs://BUCKET/PATH for Firebase, and
// BUCKET/PATH for Supabase.
func (l Location) Where(kind StorageKind) string {
	if kind == FirebaseStorage {
		return "gs://" + l.Bucket + "/" + l.Path()
	}
	return l.Bucket + "/" + l.Path()
}

// randomName is replaced in tests.
var randomName = func() (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "siegekit-write-test-" + hex.EncodeToString(b) + ".txt", nil
}

// reBucket is a bucket name SiegeKit sends: Firebase (Cloud Storage) and
// Supabase bucket names fit it; anything else, such as "..", is dropped.
var reBucket = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9._-]{0,221}$`)

// PlanFiles picks at most MaxFiles locations: each bucket's root first,
// then the folders the scripts upload to in a named bucket (pairs), then
// each other folder in each bucket. It returns them and how many were
// left out.
func PlanFiles(buckets []string, pairs []Location, folders []string) ([]Location, int, error) {
	var all []Location
	seen := map[Location]bool{}
	add := func(l Location) {
		if !reBucket.MatchString(l.Bucket) || (l.Folder != "" && Folder(l.Folder) != l.Folder) {
			return
		}
		if !seen[l] {
			seen[l] = true
			all = append(all, l)
		}
	}
	for _, b := range buckets {
		add(Location{Bucket: b})
	}
	for _, p := range pairs {
		add(Location{Bucket: p.Bucket, Folder: p.Folder})
	}
	for _, b := range buckets {
		for _, f := range folders {
			add(Location{Bucket: b, Folder: f})
		}
	}
	left := 0
	if len(all) > MaxFiles {
		left, all = len(all)-MaxFiles, all[:MaxFiles]
	}
	for i := range all {
		n, err := randomName()
		if err != nil {
			return nil, 0, err
		}
		all[i].Name = n
	}
	return all, left, nil
}

// Outcome is what happened at one location.
type Outcome struct {
	Location
	Written  bool // the upload was accepted
	Refused  bool // the upload was refused by the rules
	Missing  bool // no such bucket
	Readable bool // the file read back with the same content
	Deleted  bool // the delete was confirmed
	Gone     bool // a read after the delete found no file
	Left     bool // the file is, or may be, still there
	Error    string
}

// StorageResult is what the check saw.
type StorageResult struct {
	Kind     StorageKind
	Outcomes []Outcome
	LeftOut  int // locations over MaxFiles, not tested
	Requests int
}

// Written is the outcomes whose upload was accepted.
func (r StorageResult) Written() []Outcome {
	var out []Outcome
	for _, o := range r.Outcomes {
		if o.Written {
			out = append(out, o)
		}
	}
	return out
}

// Leftovers is every test file that is, or may be, still there.
func (r StorageResult) Leftovers() []Outcome {
	var out []Outcome
	for _, o := range r.Outcomes {
		if o.Left {
			out = append(out, o)
		}
	}
	return out
}

// Summary says the result in one line, for reports. Leftover files are
// named with their full path.
func (r StorageResult) Summary() string {
	var refused, missing, errs, readable int
	for _, o := range r.Outcomes {
		switch {
		case o.Refused:
			refused++
		case o.Missing:
			missing++
		case o.Error != "" && !o.Written:
			errs++
		}
		if o.Readable {
			readable++
		}
	}
	parts := []string{fmt.Sprintf("%d accepted an upload with no login", len(r.Written()))}
	for _, c := range []struct {
		n    int
		text string
	}{{readable, "read back"}, {refused, "refused"}, {missing, "bucket not found"}, {errs, "other answers"}, {r.LeftOut, fmt.Sprintf("over the %d-file limit, not tested", MaxFiles)}} {
		if c.n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", c.n, c.text))
		}
	}
	s := fmt.Sprintf("%d location(s) tested: %s", len(r.Outcomes), strings.Join(parts, ", "))
	if left := r.Leftovers(); len(left) > 0 {
		names := make([]string, len(left))
		for i, o := range left {
			names[i] = o.Where(r.Kind)
		}
		s += fmt.Sprintf("; %d test file(s) may still be there, delete them: %s", len(left), strings.Join(names, ", "))
	} else if len(r.Written()) > 0 {
		s += "; every test file was deleted"
	}
	return s
}

// The largest answer read: an upload's metadata, or the 36-byte file.
const maxStorageAnswer = 64 << 10

// WriteStorage tests each location in turn, one request per Interval:
// upload the test file with the app's public key (Supabase) or no login
// (Firebase), read it back, delete it, and read it again. A delete is sent
// for every accepted upload even when ctx is cancelled, so an interrupted
// run still cleans up. It fails when the storage answers nothing it can
// read.
func WriteStorage(ctx context.Context, cfg egress.Config, kind StorageKind, key string, locs []Location, leftOut int) (StorageResult, error) {
	if cfg.ReadOnly {
		return StorageResult{}, errors.New("the storage write test needs a configuration that allows POST and DELETE")
	}
	r := StorageResult{Kind: kind, LeftOut: leftOut}
	var header http.Header
	switch kind {
	case SupabaseStorage:
		if key == "" {
			return r, ErrNoKey
		}
		header = supabaseHeader(key)
	case FirebaseStorage:
	default:
		return r, errors.New("cannot tell whether the storage is Supabase or Firebase")
	}
	if len(locs) == 0 {
		return r, errors.New("no bucket name was found in the app's scripts")
	}
	first := true
	do := func(ctx context.Context, method, p string, h http.Header, body []byte) (*egress.Answer, error) {
		if !first {
			if err := sleep(ctx, Interval); err != nil {
				return nil, err
			}
		}
		first = false
		hh := header.Clone()
		if hh == nil {
			hh = http.Header{}
		}
		for k, v := range h {
			hh[k] = v
		}
		a, err := send(ctx, cfg, method, p, hh, body, maxStorageAnswer)
		if a != nil {
			r.Requests++
		}
		return a, err
	}
	for _, l := range locs {
		if ctx.Err() != nil {
			return r, ctx.Err()
		}
		o := testLocation(ctx, do, kind, l)
		r.Outcomes = append(r.Outcomes, o)
	}
	answered := 0
	for _, o := range r.Outcomes {
		if o.Written || o.Refused || o.Missing {
			answered++
		}
	}
	if answered == 0 {
		return r, fmt.Errorf("the storage gave no answer this check can read in %d upload(s); check --storage-url (first: %s)", len(r.Outcomes), r.Outcomes[0].Error)
	}
	return r, nil
}

type sender func(ctx context.Context, method, p string, h http.Header, body []byte) (*egress.Answer, error)

// testLocation runs upload, read, delete and check at one location.
func testLocation(ctx context.Context, do sender, kind StorageKind, l Location) Outcome {
	o := Outcome{Location: l}
	method, p, h, body := uploadRequest(kind, l)
	a, err := do(ctx, method, p, h, body)
	switch {
	case a == nil:
		// No answer: the upload may still have landed.
		o.Error, o.Left = fmt.Sprintf("upload: %v", err), true
		cleanup(ctx, do, kind, &o)
		return o
	case uploadAccepted(kind, a):
		o.Written = true
	case refusedAnswer(kind, a):
		o.Refused = true
		return o
	case missingBucket(kind, a):
		o.Missing = true
		return o
	default:
		o.Error = fmt.Sprintf("upload answered %d", a.Status)
		if a.Status >= 200 && a.Status < 300 {
			o.Written = true // accepted in a form this check does not know
		} else {
			return o
		}
	}
	if a, err := do(ctx, http.MethodGet, readPath(kind, l), nil, nil); err == nil && a.Status == http.StatusOK && string(a.Body) == TestContent {
		o.Readable = true
	}
	cleanup(ctx, do, kind, &o)
	return o
}

// cleanup deletes the test file and reads it again. It runs even when
// ctx is cancelled, so a file uploaded just before an interrupt is still
// deleted.
func cleanup(ctx context.Context, do sender, kind StorageKind, o *Outcome) {
	ctx = context.WithoutCancel(ctx)
	method, p, h, body := deleteRequest(kind, o.Location)
	a, err := do(ctx, method, p, h, body)
	if err == nil {
		o.Deleted = deleteConfirmed(kind, o.Location, a)
	}
	if a, err := do(ctx, http.MethodGet, checkPath(kind, o.Location), nil, nil); err == nil {
		switch {
		case a.Status == http.StatusOK:
			o.Deleted, o.Gone = false, false // still served
		case kind == FirebaseStorage && a.Status == http.StatusNotFound:
			o.Gone = true
		case kind == SupabaseStorage && supabaseCode(a) == "404":
			// Gone, or hidden from the public key: only a confirmed
			// delete counts (measured: storage-api answers this for both).
			o.Gone = o.Deleted
		}
	}
	o.Left = !o.Deleted && !o.Gone
}

// The REST calls the web SDKs make (firebase 12 uploadBytes, supabase-js
// 2.49 upload and remove).
func uploadRequest(kind StorageKind, l Location) (string, string, http.Header, []byte) {
	if kind == FirebaseStorage {
		boundary := "siegekit" + strings.TrimSuffix(strings.TrimPrefix(l.Name, "siegekit-write-test-"), ".txt")
		meta, _ := json.Marshal(map[string]string{"name": l.Path(), "contentType": "text/plain"})
		var b bytes.Buffer
		fmt.Fprintf(&b, "--%s\r\nContent-Type: application/json; charset=utf-8\r\n\r\n%s\r\n--%s\r\nContent-Type: text/plain\r\n\r\n%s\r\n--%s--", boundary, meta, boundary, TestContent, boundary)
		h := http.Header{"X-Goog-Upload-Protocol": {"multipart"}, "Content-Type": {"multipart/related; boundary=" + boundary}}
		return http.MethodPost, "/v0/b/" + url.PathEscape(l.Bucket) + "/o?name=" + url.QueryEscape(l.Path()), h, b.Bytes()
	}
	h := http.Header{"Content-Type": {"text/plain;charset=UTF-8"}, "X-Upsert": {"false"}}
	return http.MethodPost, "/storage/v1/object/" + supabaseObject(l), h, []byte(TestContent)
}

func readPath(kind StorageKind, l Location) string {
	if kind == FirebaseStorage {
		return firebaseObject(l) + "?alt=media"
	}
	return "/storage/v1/object/" + supabaseObject(l)
}

func checkPath(kind StorageKind, l Location) string {
	if kind == FirebaseStorage {
		return firebaseObject(l)
	}
	return "/storage/v1/object/" + supabaseObject(l)
}

func deleteRequest(kind StorageKind, l Location) (string, string, http.Header, []byte) {
	if kind == FirebaseStorage {
		return http.MethodDelete, firebaseObject(l), nil, nil
	}
	body, _ := json.Marshal(map[string][]string{"prefixes": {l.Path()}})
	return http.MethodDelete, "/storage/v1/object/" + url.PathEscape(l.Bucket), http.Header{"Content-Type": {"application/json"}}, body
}

func firebaseObject(l Location) string {
	return "/v0/b/" + url.PathEscape(l.Bucket) + "/o/" + url.PathEscape(l.Path())
}

func supabaseObject(l Location) string {
	segs := []string{url.PathEscape(l.Bucket)}
	for _, s := range strings.Split(l.Path(), "/") {
		segs = append(segs, url.PathEscape(s))
	}
	return strings.Join(segs, "/")
}

// supabaseCode is the statusCode inside a storage-api error body: it
// answers 400 and puts the real code ("403", "404") in the body.
func supabaseCode(a *egress.Answer) string {
	var e struct {
		StatusCode json.RawMessage `json:"statusCode"`
	}
	if json.Unmarshal(a.Body, &e) != nil {
		return ""
	}
	return strings.Trim(string(e.StatusCode), `"`)
}

func uploadAccepted(kind StorageKind, a *egress.Answer) bool {
	if a.Status != http.StatusOK {
		return false
	}
	var v map[string]any
	if json.Unmarshal(a.Body, &v) != nil {
		return false
	}
	if kind == FirebaseStorage {
		_, ok := v["name"]
		return ok
	}
	_, ok := v["Key"]
	return ok
}

func refusedAnswer(kind StorageKind, a *egress.Answer) bool {
	if a.Status == http.StatusUnauthorized || a.Status == http.StatusForbidden {
		return true
	}
	if kind == SupabaseStorage && a.Status == http.StatusBadRequest {
		c := supabaseCode(a)
		return c == "401" || c == "403"
	}
	return false
}

func missingBucket(kind StorageKind, a *egress.Answer) bool {
	if kind == SupabaseStorage {
		return (a.Status == http.StatusBadRequest || a.Status == http.StatusNotFound) && supabaseCode(a) == "404"
	}
	return a.Status == http.StatusNotFound
}

// deleteConfirmed reads the delete's answer: Firebase answers 204 (or 200)
// when it deleted and 403 when the rules refuse; Supabase's bulk delete
// answers 200 with the objects it deleted, and [] when it deleted none
// (measured on storage-api v1.94.2).
func deleteConfirmed(kind StorageKind, l Location, a *egress.Answer) bool {
	if kind == FirebaseStorage {
		return a.Status == http.StatusNoContent || a.Status == http.StatusOK
	}
	if a.Status != http.StatusOK {
		return false
	}
	var objs []struct {
		Name string `json:"name"`
	}
	if json.Unmarshal(a.Body, &objs) != nil {
		return false
	}
	for _, ob := range objs {
		if ob.Name == l.Path() {
			return true
		}
	}
	return false
}

// StorageFindings turns each accepted upload into a finding: critical,
// like an open write in backend-rules, with CWE-284 and CWE-862. The
// location is the bucket and folder, so the finding is the same on every
// run whatever the file's random name.
func StorageFindings(s *Storage, r StorageResult) []findings.Finding {
	var out []findings.Finding
	for _, o := range r.Written() {
		where := (Location{Bucket: o.Bucket, Folder: o.Folder}).Where(r.Kind)
		uri := where
		if r.Kind == SupabaseStorage {
			uri = strings.TrimSuffix(s.URL.Origin(), "/") + "/storage/v1/object/" + path.Clean(o.Bucket+"/"+o.Folder) + "/"
		}
		f := findings.Finding{
			Severity: findings.Critical,
			CWEs:     []string{"CWE-284", "CWE-862"},
			Location: findings.Location{URI: uri},
			Family:   StorageFamily,
			RuleID:   "storage-public-write",
			Title:    "Anyone can upload files to this storage bucket",
		}
		who := "with no login"
		fix := "Add a write rule with a condition, such as \"allow write: if request.auth != null && request.auth.uid == userId\" under a path that holds the user's ID."
		if r.Kind == SupabaseStorage {
			who = "with the public key from the app's scripts"
			fix = "Limit the insert policy on storage.objects to signed-in users and their own folder, for example \"to authenticated with check (bucket_id = '" + o.Bucket + "' and (storage.foldername(name))[1] = auth.uid()::text)\"."
		}
		msg := fmt.Sprintf("SiegeKit uploaded a %d-byte text file to %s %s, so anyone who loads the app can store files here: they can fill the bucket, run up its bill, or host files under the app's name.", len(TestContent), o.Where(r.Kind), who)
		if o.Readable {
			msg += " The file could also be read back without signing in."
		}
		if o.Left {
			msg += fmt.Sprintf(" SiegeKit could not confirm that its test file was deleted; delete %s yourself.", o.Where(r.Kind))
		}
		f.Message = msg + " " + fix
		f.Sources = []findings.Source{{Plugin: StorageID, RuleID: f.RuleID}}
		f.ComputeFingerprint()
		out = append(out, f)
	}
	return out
}

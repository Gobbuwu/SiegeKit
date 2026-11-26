package authz

// PROTOTYPE (issue #96, card 2): the rules measured for what proves that
// C read A's data. Removed before merge; the measured pick stays.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"mime"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
)

const (
	dataAny     = "R0"  // today: any non-blank body
	dataRSC     = "R1"  // an RSC answer counts only with non-structural content
	dataMarker  = "R2"  // a no-ID, no-login-name answer needs a value of A's recording
	dataMarkAll = "R2b" // every answer needs a value of A's recording not in its URL
	dataSkip    = "R3"  // prefetch requests are not compared
)

var dataRule = func() string {
	if v := os.Getenv("SIEGEKIT_PROTO_DATA"); v != "" {
		return v
	}
	return dataAny
}()

// readMarkers are values of A's recording (R2): long IDs and the values A
// wrote. Set by ParseHAR.
var readMarkers []string

// holds is HoldsData under the active rule.
func (r Replay) holds() bool {
	if !HoldsData(r.A.Body) {
		return false
	}
	switch dataRule {
	case dataRSC:
		if isRSC(r.Header) {
			return rscHoldsData(r.A.Body, r.Path)
		}
	case dataMarker:
		return hasID(r.Path) || hasMarker(r.A.Body, r.Path)
	case dataMarkAll:
		return hasMarker(r.A.Body, r.Path)
	case dataSkip:
		return !isPrefetch(r.Header)
	}
	return true
}

func isRSC(h http.Header) bool      { return h.Get("Rsc") == "1" }
func isPrefetch(h http.Header) bool { return h.Get("Next-Router-Prefetch") != "" }

// markerOK: a marker is at least 6 bytes and not only digits.
func markerOK(s string) bool {
	if len(s) < 6 || len(s) > 200 {
		return false
	}
	return strings.Trim(s, "0123456789") != ""
}

var reLongID = regexp.MustCompile(`^(?:[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}|[0-9a-fA-F]{16,})$`)

// addMarkers keeps the values a recorded write sent and the long IDs the
// recording showed.
func addMarkers(ids *idSet, method string, pd *harPostData) {
	if ids != nil && readMarkers == nil {
		for _, v := range ids.all {
			if reLongID.MatchString(v) {
				readMarkers = appendOnce(readMarkers, v)
			}
		}
	}
	if pd == nil || method == http.MethodGet || method == http.MethodHead {
		return
	}
	add := func(v string) {
		v = strings.TrimSpace(v)
		if markerOK(v) && !strings.HasPrefix(v, "$") && !strings.HasPrefix(v, "[") {
			readMarkers = appendOnce(readMarkers, v)
		}
	}
	mt, params, _ := mime.ParseMediaType(pd.MimeType)
	switch {
	case mt == "multipart/form-data" && params["boundary"] != "":
		mr := multipart.NewReader(strings.NewReader(pd.Text), params["boundary"])
		for {
			p, err := mr.NextPart()
			if err != nil {
				break
			}
			var b bytes.Buffer
			_, _ = b.ReadFrom(p)
			add(b.String())
		}
	case mt == "application/x-www-form-urlencoded":
		if q, err := url.ParseQuery(pd.Text); err == nil {
			for _, vs := range q {
				for _, v := range vs {
					add(v)
				}
			}
		}
	default:
		var v any
		if json.Unmarshal([]byte(pd.Text), &v) == nil {
			walkStrings(v, 0, add)
		}
	}
}

func walkStrings(v any, depth int, fn func(string)) {
	if depth > 32 {
		return
	}
	switch x := v.(type) {
	case string:
		fn(x)
	case []any:
		for _, e := range x {
			walkStrings(e, depth+1, fn)
		}
	case map[string]any:
		for _, e := range x {
			walkStrings(e, depth+1, fn)
		}
	}
}

// hasMarker reports whether body holds a marker that its own URL does not.
func hasMarker(body []byte, p string) bool {
	u, _ := url.PathUnescape(p)
	for _, m := range readMarkers {
		if !strings.Contains(u, m) && bytes.Contains(body, []byte(m)) {
			return true
		}
	}
	return false
}

// rscStructural are the router keys of an RSC answer's tree lines.
var rscStructural = map[string]bool{"s": true, "n": true, "t": true, "k": true, "b": true, "q": true, "c": true}

// rscHoldsData (R1) parses an RSC answer line by line: imports, hints,
// references ($...), chunk paths, the router tree's keys and the URL's own
// segments are structure; any other string is content.
func rscHoldsData(body []byte, p string) bool {
	parts := map[string]bool{"": true, "children": true, "__PAGE__": true, "__DEFAULT__": true}
	pathOnly, q, _ := strings.Cut(p, "?")
	for _, s := range strings.Split(pathOnly, "/") {
		if u, err := url.PathUnescape(s); err == nil {
			parts[u] = true
		}
	}
	if v, err := url.ParseQuery(q); err == nil {
		for _, vs := range v {
			for _, x := range vs {
				parts[x] = true
			}
		}
	}
	found := false
	var walk func(v any, key string, depth int)
	walk = func(v any, key string, depth int) {
		if found || depth > 64 {
			return
		}
		switch x := v.(type) {
		case string:
			if !rscStructural[key] && !parts[x] && !strings.HasPrefix(x, "$") && !strings.HasPrefix(x, "/_next/") {
				found = true
			}
		case []any:
			if len(x) >= 4 && x[0] == "$" {
				walk(x[3], "", depth+1) // an element: its type and key are structure
				return
			}
			for _, e := range x {
				walk(e, "", depth+1)
			}
		case map[string]any:
			for k, e := range x {
				walk(e, k, depth+1)
			}
		}
	}
	for _, line := range strings.Split(string(body), "\n") {
		_, payload, ok := strings.Cut(line, ":")
		if !ok || payload == "" {
			continue
		}
		if strings.HasPrefix(payload, "I[") || strings.HasPrefix(payload, "HL[") || strings.HasPrefix(payload, ":HL[") || len(payload) == 1 {
			continue
		}
		var v any
		if json.Unmarshal([]byte(payload), &v) != nil {
			return true // a text chunk or something unknown: content
		}
		walk(v, "", 0)
		if found {
			return true
		}
	}
	return false
}

var measureMu sync.Mutex

// measureReads writes each replay's outcome under every rule to the file
// in SIEGEKIT_PROTO_MEASURE.
func measureReads(res Result, loginName string) {
	f := os.Getenv("SIEGEKIT_PROTO_MEASURE")
	if f == "" {
		return
	}
	measureMu.Lock()
	defer measureMu.Unlock()
	out, err := os.OpenFile(f, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600) // #nosec G703 -- PROTOTYPE: the gate's measure file, removed before merge
	if err != nil {
		return
	}
	defer out.Close()
	saved := dataRule
	defer func() { dataRule = saved }()
	cWorks := res.CWorks()
	fmt.Fprintf(out, "MEASURE read markers=%d active=%s\n", len(readMarkers), saved)
	for _, r := range res.Replays {
		line := fmt.Sprintf("MEASURE read %s %s rsc=%v prefetch=%v id=%v a=%d/%d c=%d/%d none=%d", r.Method, r.Path, isRSC(r.Header), isPrefetch(r.Header), hasID(r.Path), r.A.Status, len(r.A.Body), r.C.Status, len(r.C.Body), r.None.Status)
		for _, rule := range []string{dataAny, dataRSC, dataMarker, dataMarkAll, dataSkip} {
			dataRule = rule
			v := "-"
			switch {
			case r.Outsider():
				v = "cross"
			case r.BOnly(cWorks):
				v = "bonly"
			case r.CrossAccount():
				v = "crossB"
			case r.NoLogin(loginName):
				v = "nologin"
			}
			line += " " + rule + "=" + v
		}
		fmt.Fprintln(out, line)
	}
}

// measureWrites writes each write replay's acceptance under every rule of
// card 1 to the file in SIEGEKIT_PROTO_MEASURE (PROTOTYPE).
func measureWrites(res WriteResult) {
	f := os.Getenv("SIEGEKIT_PROTO_MEASURE")
	if f == "" {
		return
	}
	measureMu.Lock()
	defer measureMu.Unlock()
	out, err := os.OpenFile(f, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600) // #nosec G703 -- PROTOTYPE: the gate's measure file, removed before merge
	if err != nil {
		return
	}
	defer out.Close()
	fmt.Fprintf(out, "MEASURE write active=%s requests=%d\n", acceptRule, res.Requests)
	for _, r := range res.Replays {
		line := fmt.Sprintf("MEASURE write %s who=%s notsent=%v status=%d sig=%v rec=%v read=%v noisy=%v once=%v changed=%v ignored=%v", r.Label(), whoName(r.Who), r.NotSent != "", r.Answer.Status, r.Signals, r.RecordedSignals, r.Read, r.Noisy, r.changedOnce(), r.readChanged(), r.MethodIgnored)
		for _, rule := range []string{acceptAny, acceptNext, acceptSignal, acceptState, acceptHybrid, acceptAction} {
			line += fmt.Sprintf(" %s=%v", rule, r.NotSent == "" && r.acceptedBy(rule))
		}
		fmt.Fprintln(out, line)
		if os.Getenv("SIEGEKIT_PROTO_DIFF") != "" && r.changedOnce() {
			r1, w1 := pageWords(r.Before.Body)
			r2, w2 := pageWords(r.After.Body)
			fmt.Fprintf(out, "DIFF rest-equal=%v words=%d/%d\n", bytes.Equal(r1, r2), len(w1), len(w2))
			if len(w1) == len(w2) {
				for i := range w1 {
					if !bytes.Equal(w1[i], w2[i]) {
						fmt.Fprintf(out, "DIFF word %d: %q -> %q\n", i, w1[i], w2[i])
					}
				}
			}
			if _, w3 := pageWords(r.Settle.Body); len(w3) == len(w2) {
				for i := range w2 {
					if !bytes.Equal(w2[i], w3[i]) {
						fmt.Fprintf(out, "DIFF settle word %d: %q -> %q\n", i, w2[i], w3[i])
					}
				}
			} else {
				fmt.Fprintf(out, "DIFF settle words=%d unsettled=%v\n", len(w3), r.unsettled)
			}
			_ = os.WriteFile(f+"."+r.Method+".before", r.Before.Body, 0o600)
			_ = os.WriteFile(f+"."+r.Method+".after", r.After.Body, 0o600)
		}
	}
}

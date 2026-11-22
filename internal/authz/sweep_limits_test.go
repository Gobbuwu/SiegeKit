package authz

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"

	"github.com/Gobbuwu/SiegeKit/internal/egress"
)

// A 429 says nothing about access: it is counted, the route is not
// compared, and the summary says coverage may be incomplete. The
// summary also names every reason a swept route was not sent (ADR 0052).
func TestSweepRateLimitAndNotes(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Header.Get("Authorization") {
		case "Bearer A":
			w.Write([]byte(`{"messages":[{"_id":"m1"}]}`))
		case "Bearer C":
			w.WriteHeader(http.StatusTooManyRequests)
		default:
			w.WriteHeader(http.StatusUnauthorized)
		}
	}))
	defer srv.Close()
	noSleep(t)
	tu := mustTarget(t, srv.URL+"/")
	cfg := egress.Config{Target: tu, Addrs: []netip.Addr{netip.MustParseAddr("127.0.0.1")}, Version: "test", ReadOnly: true}
	reqs := []Request{{Method: "GET", Path: "/api/v1/chat.getDeletedMessages?roomId=r1", Header: http.Header{"Authorization": {"Bearer A"}}}}
	res, err := Check(context.Background(), cfg, reqs, Accounts{C: http.Header{"Authorization": {"Bearer C"}}}, 10)
	if err != nil {
		t.Fatal(err)
	}
	if res.Rate429 != 1 {
		t.Errorf("Rate429 = %d, want 1", res.Rate429)
	}
	if fs := Findings(srv.URL, res, ""); len(fs) != 0 {
		t.Errorf("a 429 for C was reported: %+v", fs)
	}
	h := &HAR{FromSweep: 1, SweepNoID: 2, SweepURL: 3, SweepOverLimit: 4, SweepUnreadable: 5}
	s := res.Summary(h, "", Count(res, ""))
	for _, want := range []string{
		"1 from the route sweep",
		"1 answer(s) were 429 (rate limited)",
		"2 spec routes needing an object ID",
		"3 spec routes needing an address the app would fetch",
		"4 spec routes over the route sweep's 500-request limit",
		"5 spec routes with a parameter the spec does not describe",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("summary lacks %q: %s", want, s)
		}
	}
}

// YAML specs (Rocket.Chat and Mattermost publish only YAML): $ref
// parameters resolve, and a date example stays a string.
func TestSweepRoutesYAML(t *testing.T) {
	spec := `openapi: 3.0.0
paths:
  /api/v1/chat.getDeletedMessages:
    get:
      parameters:
        - $ref: '#/components/parameters/RoomId'
        - name: since
          in: query
          required: true
          schema: {type: string}
          example: 2018-12-12T00:11:22.345Z
components:
  parameters:
    RoomId: {name: roomId, in: query, required: true, schema: {type: string}}
`
	routes := SweepRoutes([]byte(spec), "yaml")
	if len(routes) != 1 || len(routes[0].Params) != 2 {
		t.Fatalf("%+v", routes)
	}
	for _, p := range routes[0].Params {
		if p.Name == "since" && p.Example != "2018-12-12T00:11:22.345Z" {
			t.Errorf("date example became %q", p.Example)
		}
		if p.Name == "roomId" && !p.Required {
			t.Error("$ref parameter not resolved")
		}
	}
}

// YAML merge keys ("<<: *base") are followed, as yaml.v3 decodes them:
// a route or parameter written through one is not lost, and keys written
// in the mapping win over merged ones.
func TestSweepRoutesYAMLMergeKey(t *testing.T) {
	spec := `openapi: 3.0.0
x-base: &room
  name: roomId
  in: query
  required: false
x-op: &op
  parameters:
    - <<: *room
      required: true
paths:
  /api/v1/chat.getDeletedMessages:
    get:
      <<: *op
  /api/v1/rooms.info:
    <<: {get: {parameters: [{name: roomId, in: query, required: true}]}}
`
	routes := SweepRoutes([]byte(spec), "yaml")
	if len(routes) != 2 {
		t.Fatalf("routes %+v, want 2", routes)
	}
	for _, r := range routes {
		if len(r.Params) != 1 || r.Params[0].Name != "roomId" || r.Params[0].In != "query" || !r.Params[0].Required {
			t.Errorf("%s: params %+v, want required query roomId", r.Path, r.Params)
		}
	}
	// A quoted "<<" is an ordinary key, not a merge.
	j, err := yamlToJSON([]byte("a: {\"<<\": {b: 1}}\n"))
	if err != nil || string(j) != `{"a":{"\u003c\u003c":{"b":1}}}` {
		t.Errorf("quoted <<: %s %v", j, err)
	}
}

// A route whose parameter the spec does not describe (a $ref to another
// file or to a name the document lacks, or a {name} in the path no
// parameter declares) is counted and not sent, rather than sent half
// filled or with literal braces (ADR 0052).
func TestAddSweepRoutesUnreadable(t *testing.T) {
	tu := mustTarget(t, "http://localhost:3000/")
	har := []byte(`{"log":{"entries":[{"request":{"method":"GET","url":"http://localhost:3000/api/x","headers":[{"name":"Cookie","value":"s=A"}]},"response":{"content":{"text":"{\"rid\":\"6b0281133568ca9b5b817585\"}"}}}]}}`)
	h, err := ParseHAR(har, tu)
	if err != nil {
		t.Fatal(err)
	}
	spec := `{"openapi":"3.0.0","paths":{
	 "/ext":{"get":{"parameters":[{"$ref":"params.yaml#/RoomId"}]}},
	 "/missing":{"get":{"parameters":[{"$ref":"#/components/parameters/Nope"}]}},
	 "/undeclared/{rid}":{"get":{}},
	 "/ok/{rid}":{"get":{"parameters":[{"name":"rid","in":"path","required":true}]}}}}`
	h.AddSweepRoutes(SweepRoutes([]byte(spec), "json"), "")
	var paths []string
	for _, r := range h.Requests[1:] {
		paths = append(paths, r.Path)
	}
	if len(paths) != 1 || paths[0] != "/ok/6b0281133568ca9b5b817585" {
		t.Errorf("swept %v, want only /ok/<A's ID>", paths)
	}
	if h.SweepUnreadable != 3 {
		t.Errorf("SweepUnreadable = %d, want 3", h.SweepUnreadable)
	}
}

// A YAML spec built to expand through aliases is refused, not expanded.
func TestSweepRoutesYAMLAliasBomb(t *testing.T) {
	var b strings.Builder
	b.WriteString("a0: &a0 [x, x, x, x, x, x, x, x, x, x]\n")
	for i := 1; i < 9; i++ {
		b.WriteString("a" + string(rune('0'+i)) + ": &a" + string(rune('0'+i)) + " [")
		for j := 0; j < 10; j++ {
			if j > 0 {
				b.WriteString(", ")
			}
			b.WriteString("*a" + string(rune('0'+i-1)))
		}
		b.WriteString("]\n")
	}
	b.WriteString("paths: {/x: {get: {}}}\n") // 10^9 nodes if expanded
	if _, err := yamlToJSON([]byte(b.String())); err != errYAMLTooBig {
		t.Errorf("alias bomb: err %v, want errYAMLTooBig", err)
	}
	if r := SweepRoutes([]byte(b.String()), "yaml"); r != nil {
		t.Errorf("alias bomb gave routes: %v", r)
	}
}

func FuzzSweepRoutes(f *testing.F) {
	f.Add([]byte("openapi: 3.0.0\npaths: {/a/{id}: {get: {parameters: [{name: id, in: path, required: true}]}}}\n"), true)
	f.Add([]byte(`{"swagger":"2.0","paths":{"/a":{"get":{"parameters":[{"$ref":"#/parameters/x"}]}}},"parameters":{"x":{"name":"q","in":"query","required":true}}}`), false)
	f.Fuzz(func(t *testing.T, data []byte, yamlFormat bool) {
		format := "json"
		if yamlFormat {
			format = "yaml"
		}
		for _, r := range SweepRoutes(data, format) {
			if !strings.HasPrefix(r.Path, "/") || strings.HasPrefix(r.Path, "//") {
				t.Fatalf("route %q", r.Path)
			}
		}
	})
}

// IDs are harvested in a fixed order, so the same recording always fills
// the same routes; times are not taken as IDs (ADR 0052).
func TestHarvestOrderAndTimes(t *testing.T) {
	tu := mustTarget(t, "http://localhost:3000/")
	ans := `{"z_id":"zzzzzzzzzz1","create_at":1795344345615,"ts":"1795344345616","_updatedAt":"1795344345617","created_unix":1795344345618,"lastMessageDate":"1795344345619","chat":"cccccccccc1","a_id":"aaaaaaaaaa1","m_id":"mmmmmmmmmm1","id":42}`
	har := []byte(`{"log":{"entries":[{"request":{"method":"GET","url":"http://localhost:3000/x?q2=qqqqqqqqqq2&q1=qqqqqqqqqq1","headers":[]},"response":{"content":{"text":` + strconvQuote(ans) + `}}}]}}`)
	var first []string
	for i := 0; i < 50; i++ {
		h, err := ParseHAR(har, tu)
		if err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			first = h.ids.all
			continue
		}
		if strings.Join(h.ids.all, ",") != strings.Join(first, ",") {
			t.Fatalf("run %d harvested %v, run 0 %v", i, h.ids.all, first)
		}
	}
	want := "qqqqqqqqqq1,qqqqqqqqqq2,aaaaaaaaaa1,cccccccccc1,42,mmmmmmmmmm1,zzzzzzzzzz1"
	if got := strings.Join(first, ","); got != want {
		t.Errorf("harvested %s, want %s", got, want)
	}
}

func strconvQuote(s string) string { b, _ := json.Marshal(s); return string(b) }

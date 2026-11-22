package main

import (
	"strings"
	"testing"

	"github.com/Gobbuwu/SiegeKit/internal/authz"
	"github.com/Gobbuwu/SiegeKit/internal/openapi"
	"github.com/Gobbuwu/SiegeKit/internal/target"
)

// sweepSpec is a YAML spec shaped like Rocket.Chat's: a route that needs
// a room ID and a date, and one with no parameter.
const sweepSpec = `openapi: 3.0.0
info: {title: t, version: "1"}
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
  /api/v1/me:
    get: {}
components:
  parameters:
    RoomId:
      name: roomId
      in: query
      required: true
      schema: {type: string}
`

func sweepHAR(t *testing.T) *authz.HAR {
	t.Helper()
	u, _ := target.Parse("http://localhost:3000/")
	h, err := authz.ParseHAR([]byte(`{"log":{"entries":[{"request":{"method":"GET","url":"http://localhost:3000/api/v1/rooms.get","headers":[{"name":"X-Auth-Token","value":"tok"}]},"response":{"content":{"text":"{\"update\":[{\"rid\":\"6b0281133568ca9b5b817585\"}]}"}}}]}}`), u)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func TestAddSpecRequestsSweepsLocalOnly(t *testing.T) {
	format, err := openapi.Check([]byte(sweepSpec))
	if err != nil || format != "yaml" {
		t.Fatalf("spec check: %q %v", format, err)
	}
	spec := &openapi.Spec{Data: []byte(sweepSpec), Format: format, Source: "rc.yaml"}

	h := sweepHAR(t)
	addSpecRequests(h, spec, nil, false)
	var got string
	for _, r := range h.Requests {
		if strings.HasPrefix(r.Path, "/api/v1/chat.getDeletedMessages?") {
			got = r.Path
		}
	}
	if got != "/api/v1/chat.getDeletedMessages?roomId=6b0281133568ca9b5b817585&since=2018-12-12T00%3A11%3A22.345Z" || h.FromSweep != 2 { // the route above and /api/v1/me
		t.Errorf("local: swept %d, route %q", h.FromSweep, got)
	}

	// Deployed targets get no sweep: only the parameterless route, which a
	// YAML spec does not give to AddSpecRoutes (ADR 0035).
	h = sweepHAR(t)
	addSpecRequests(h, spec, nil, true)
	if h.FromSweep != 0 || len(h.Requests) != 1 {
		t.Errorf("deployed: swept %d, %d requests", h.FromSweep, len(h.Requests))
	}
	addSpecRequests(h, nil, nil, false) // no spec: nothing added
	if len(h.Requests) != 1 {
		t.Errorf("nil spec added requests")
	}
}

// Routes read from the server code (ADR 0053) are swept on local targets
// after the spec's, without those the spec already has, and never on
// deployed targets. The code route is filled from A's IDs with the
// earliest date, and an ID filter the recording has no ID for is left
// out rather than dropping the route.
func TestAddSpecRequestsCodeRoutes(t *testing.T) {
	code := []authz.SpecRoute{
		{Path: "/api/v1/chat.getDeletedMessages", FromCode: true, Params: []authz.SpecParam{
			{Name: "roomId", In: "query", Fill: true}, {Name: "since", In: "query", Required: true}}},
		{Path: "/api/v1/rooms.media/{rid}", FromCode: true, Params: []authz.SpecParam{
			{Name: "rid", In: "path", Required: true}, {Name: "fileId", In: "query", Fill: true}}},
		{Path: "/api/v1/info", FromCode: true},
	}

	// No spec: every code route is swept.
	h := sweepHAR(t)
	if n := addSpecRequests(h, nil, code, false); n != 0 {
		t.Errorf("in spec %d", n)
	}
	var got []string
	for _, r := range h.Requests[1:] {
		got = append(got, r.Path)
	}
	want := []string{
		"/api/v1/chat.getDeletedMessages?roomId=6b0281133568ca9b5b817585&since=1970-01-01T00%3A00%3A00.000Z",
		"/api/v1/rooms.media/6b0281133568ca9b5b817585",
		"/api/v1/info",
	}
	if strings.Join(got, " ") != strings.Join(want, " ") || h.FromSweep != 3 || h.FromCodeSweep != 3 {
		t.Errorf("no spec: swept %d (%d from code):\n got  %q\n want %q", h.FromSweep, h.FromCodeSweep, got, want)
	}
	if h.Requests[1].Header.Get("X-Auth-Token") != "tok" {
		t.Errorf("code route without A's session headers: %v", h.Requests[1].Header)
	}

	// With the spec: its getDeletedMessages wins (its example date), the
	// code's copy is left out and counted.
	spec := &openapi.Spec{Data: []byte(sweepSpec), Format: "yaml", Source: "rc.yaml"}
	h = sweepHAR(t)
	if n := addSpecRequests(h, spec, code, false); n != 1 {
		t.Errorf("in spec %d, want 1", n)
	}
	got = nil
	for _, r := range h.Requests {
		if strings.HasPrefix(r.Path, "/api/v1/chat.getDeletedMessages") {
			got = append(got, r.Path)
		}
	}
	if len(got) != 1 || !strings.Contains(got[0], "since=2018-12-12") || h.FromCodeSweep != 2 || h.FromSweep != 4 {
		t.Errorf("with spec: %q, swept %d (%d from code)", got, h.FromSweep, h.FromCodeSweep)
	}

	// Deployed: nothing from the code.
	h = sweepHAR(t)
	addSpecRequests(h, nil, code, true)
	if h.FromSweep != 0 || len(h.Requests) != 1 {
		t.Errorf("deployed: swept %d, %d requests", h.FromSweep, len(h.Requests))
	}
}

func TestRouteShape(t *testing.T) {
	for in, want := range map[string]string{"/rooms/{rid}/": "/rooms/{}", "/a/{roomId}/b": "/a/{}/b", "/": "/"} {
		if got := routeShape(in); got != want {
			t.Errorf("routeShape(%q) = %q, want %q", in, got, want)
		}
	}
}

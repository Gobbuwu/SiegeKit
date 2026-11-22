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
	addSpecRequests(h, spec, false)
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
	addSpecRequests(h, spec, true)
	if h.FromSweep != 0 || len(h.Requests) != 1 {
		t.Errorf("deployed: swept %d, %d requests", h.FromSweep, len(h.Requests))
	}
	addSpecRequests(h, nil, false) // no spec: nothing added
	if len(h.Requests) != 1 {
		t.Errorf("nil spec added requests")
	}
}

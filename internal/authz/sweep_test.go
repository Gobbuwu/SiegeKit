package authz

import (
	"strings"
	"testing"

	"github.com/Gobbuwu/SiegeKit/internal/target"
)

func TestIsID(t *testing.T) {
	for _, s := range []string{"26", "wKBW2YwrPahpag4zA", "6b0281133568ca9b5b817585", "550e8400-e29b-41d4-a716-446655440000", "0123456789abcdef"} {
		if !isID(s) {
			t.Errorf("isID(%q) = false, want true", s)
		}
	}
	for _, s := range []string{"", "bob", "secret-ab", "hello", "abcdefghij", "a", "name with space"} {
		if isID(s) {
			t.Errorf("isID(%q) = true, want false", s)
		}
	}
}

func TestNormKey(t *testing.T) {
	for in, want := range map[string]string{"room_id": "roomid", "roomId": "roomid", "Room-ID": "roomid", "rid": "rid"} {
		if got := normKey(in); got != want {
			t.Errorf("normKey(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestHarvestAndCandidates(t *testing.T) {
	s := newIDSet()
	s.harvest("roomId=6b0281133568ca9b5b817585&page=1", &harPostData{Text: `{"rid":"wKBW2YwrPahpag4zA","msg":"hi"}`}, `{"update":[{"_id":"6b0281133568ca9b5b817585","u":{"_id":"alice123xyz"}}]}`)
	// roomId candidates come from roomId and its alias rid.
	c := s.candidates("roomId")
	if !containsStr(c, "6b0281133568ca9b5b817585") || !containsStr(c, "wKBW2YwrPahpag4zA") {
		t.Errorf("roomId candidates = %v, want both the roomId and the rid value", c)
	}
	// "page=1" is numeric and short; 1 is an ID by the numeric rule, but
	// it is not offered for roomId (different alias group).
	if containsStr(c, "1") {
		t.Errorf("roomId candidates include the page number: %v", c)
	}
	// "msg" is message text, not an ID, so it is not harvested.
	if containsStr(s.all, "hi") {
		t.Error("message text was harvested as an ID")
	}
}

func TestHarvestCaps(t *testing.T) {
	s := newIDSet()
	var b strings.Builder
	b.WriteString(`{"items":[`)
	for i := 0; i < 100; i++ {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(`{"rid":"` + "aaaaaaaa" + pad(i) + `"}`)
	}
	b.WriteString(`]}`)
	s.harvestJSON(b.String())
	if len(s.byKey["rid"]) > maxIDsPerKey {
		t.Errorf("rid kept %d values, cap is %d", len(s.byKey["rid"]), maxIDsPerKey)
	}
	if len(s.all) > maxIDsTotal {
		t.Errorf("all kept %d values, cap is %d", len(s.all), maxIDsTotal)
	}
}

func pad(i int) string {
	s := "00" + itoa(i)
	return s[len(s)-3:]
}
func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}

func TestFillValue(t *testing.T) {
	cases := []struct {
		p    SpecParam
		want string
	}{
		{SpecParam{Name: "since", Required: true, Type: "string", Example: "2018-12-12T00:11:22.345Z"}, "2018-12-12T00:11:22.345Z"},
		{SpecParam{Name: "since", Required: true, Type: "string"}, epochDate},
		{SpecParam{Name: "updatedSince", Type: "string", Format: "date-time"}, epochDate},
		{SpecParam{Name: "count", Type: "integer"}, "0"},
		{SpecParam{Name: "active", Type: "boolean"}, "false"},
		{SpecParam{Name: "q", Type: "string"}, ""},
	}
	for _, c := range cases {
		if got := c.p.fillValue(); got != c.want {
			t.Errorf("fillValue(%+v) = %q, want %q", c.p, got, c.want)
		}
	}
}

func TestIsIDParam(t *testing.T) {
	for _, n := range []string{"roomId", "rid", "userId", "fileId", "id", "messageId"} {
		if !(SpecParam{Name: n}).isIDParam() {
			t.Errorf("isIDParam(%q) = false, want true", n)
		}
	}
	for _, n := range []string{"since", "count", "query", "searchText", "offset"} {
		if (SpecParam{Name: n}).isIDParam() {
			t.Errorf("isIDParam(%q) = true, want false", n)
		}
	}
}

// openapiLeak is a small OpenAPI 3 spec shaped like Rocket.Chat's
// getDeletedMessages: a $ref parameter for the room ID, a required query
// date typed only as a string with an example, and a route with no ID.
const openapiLeak = `{
 "openapi":"3.0.0",
 "paths":{
  "/api/v1/chat.getDeletedMessages":{"get":{"parameters":[
    {"$ref":"#/components/parameters/RoomId"},
    {"name":"since","in":"query","required":true,"schema":{"type":"string"},"example":"2018-12-12T00:11:22.345Z"}
  ]}},
  "/api/v1/rooms.get":{"get":{"parameters":[]}},
  "/api/v1/users/{userId}/profile":{"get":{"parameters":[{"name":"userId","in":"path","required":true,"schema":{"type":"string"}}]}}
 },
 "components":{"parameters":{
   "RoomId":{"name":"roomId","in":"query","required":true,"schema":{"type":"string"}}
 }}
}`

func TestSweepRoutesJSON(t *testing.T) {
	routes := SweepRoutes([]byte(openapiLeak), "json")
	if len(routes) != 3 {
		t.Fatalf("got %d routes, want 3", len(routes))
	}
	byPath := map[string]SpecRoute{}
	for _, r := range routes {
		byPath[r.Path] = r
	}
	leak := byPath["/api/v1/chat.getDeletedMessages"]
	var room, since bool
	for _, p := range leak.Params {
		if p.Name == "roomId" && p.In == "query" && p.Required { // resolved from $ref
			room = true
		}
		if p.Name == "since" && p.Required && p.Example == "2018-12-12T00:11:22.345Z" {
			since = true
		}
	}
	if !room {
		t.Error("roomId not resolved from $ref")
	}
	if !since {
		t.Error("since example not read")
	}
	// A YAML spec gives no routes here.
	if r := SweepRoutes([]byte("openapi: 3.0.0\npaths: {}\n"), "yaml"); r != nil {
		t.Errorf("YAML gave %d routes, want 0", len(r))
	}
}

func TestAddSweepRoutesFindsLeakRoute(t *testing.T) {
	tu, _ := target.Parse("http://localhost:3000/")
	// A loads the room; the answer carries the room id under "rid".
	har := []byte(`{"log":{"entries":[{"request":{"method":"GET","url":"http://localhost:3000/api/v1/rooms.get","headers":[{"name":"X-Auth-Token","value":"tok"},{"name":"X-User-Id","value":"alice"}]},"response":{"content":{"text":"{\"update\":[{\"_id\":\"6b0281133568ca9b5b817585\",\"rid\":\"6b0281133568ca9b5b817585\"}]}"}}}]}}`)
	h, err := ParseHAR(har, tu)
	if err != nil {
		t.Fatal(err)
	}
	h.AddSweepRoutes(SweepRoutes([]byte(openapiLeak), "json"), "")
	var leak string
	for _, r := range h.Requests {
		if strings.Contains(r.Path, "chat.getDeletedMessages") {
			leak = r.Path
		}
	}
	if leak == "" {
		t.Fatal("the sweep did not produce the getDeletedMessages route")
	}
	if !strings.Contains(leak, "roomId=6b0281133568ca9b5b817585") || !strings.Contains(leak, "since=") {
		t.Errorf("leak route missing filled params: %s", leak)
	}
	// It carries every header of A's session request, like AddSpecRoutes:
	// Rocket.Chat refuses X-Auth-Token without X-User-Id (ADR 0052).
	for _, r := range h.Requests {
		if strings.Contains(r.Path, "getDeletedMessages") && (r.Header.Get("X-Auth-Token") != "tok" || r.Header.Get("X-User-Id") != "alice") {
			t.Errorf("swept route did not carry A's headers: %v", r.Header)
		}
	}
	if h.FromSweep == 0 {
		t.Error("FromSweep not counted")
	}
}

func TestAddSweepRoutesDropsWhenNoID(t *testing.T) {
	tu, _ := target.Parse("http://localhost:3000/")
	// A's recording holds no room ID, so the room-scoped route is dropped
	// and the no-parameter route is not.
	har := []byte(`{"log":{"entries":[{"request":{"method":"GET","url":"http://localhost:3000/api/v1/rooms.get","headers":[{"name":"X-Auth-Token","value":"tok"}]},"response":{"content":{"text":"{\"ok\":true}"}}}]}}`)
	h, err := ParseHAR(har, tu)
	if err != nil {
		t.Fatal(err)
	}
	h.AddSweepRoutes(SweepRoutes([]byte(openapiLeak), "json"), "")
	for _, r := range h.Requests {
		if strings.Contains(r.Path, "getDeletedMessages") {
			t.Error("getDeletedMessages route sent with no room ID to fill it")
		}
	}
	if h.SweepNoID == 0 {
		t.Error("SweepNoID not counted when an ID-named parameter has no value")
	}
	// rooms.get (no parameters) is still swept.
	var hasRoomsGet bool
	for _, r := range h.Requests {
		if r.Path == "/api/v1/rooms.get" {
			hasRoomsGet = true
		}
	}
	if !hasRoomsGet {
		t.Error("parameterless route not swept")
	}
}

func TestAddSweepRoutesNoSessionNoSweep(t *testing.T) {
	tu, _ := target.Parse("http://localhost:3000/")
	// No session header anywhere: nothing is swept (A would equal no login).
	har := []byte(`{"log":{"entries":[{"request":{"method":"GET","url":"http://localhost:3000/api/v1/rooms.get","headers":[]},"response":{"content":{"text":"{\"rid\":\"6b0281133568ca9b5b817585\"}"}}}]}}`)
	h, err := ParseHAR(har, tu)
	if err != nil {
		t.Fatal(err)
	}
	h.AddSweepRoutes(SweepRoutes([]byte(openapiLeak), "json"), "")
	if h.FromSweep != 0 {
		t.Errorf("swept %d routes with no session header, want 0", h.FromSweep)
	}
}

func TestAddSweepRoutesSkipsActionNames(t *testing.T) {
	tu, _ := target.Parse("http://localhost:3000/")
	har := []byte(`{"log":{"entries":[{"request":{"method":"GET","url":"http://localhost:3000/a","headers":[{"name":"Authorization","value":"Bearer t"}]},"response":{"content":{"text":"{\"rid\":\"6b0281133568ca9b5b817585\"}"}}}]}}`)
	h, err := ParseHAR(har, tu)
	if err != nil {
		t.Fatal(err)
	}
	spec := `{"openapi":"3.0.0","paths":{"/api/v1/rooms.delete":{"get":{"parameters":[{"name":"roomId","in":"query","required":true,"schema":{"type":"string"}}]}}}}`
	h.AddSweepRoutes(SweepRoutes([]byte(spec), "json"), "")
	for _, r := range h.Requests {
		if strings.Contains(r.Path, "rooms.delete") {
			t.Error("a route whose path names an action was swept")
		}
	}
	if h.Action == 0 {
		t.Error("the action route was not counted as skipped")
	}
}

func TestSweepRoutesSwagger2Ref(t *testing.T) {
	// Swagger 2.0: parameters live at the top level and type is on the
	// parameter itself.
	spec := `{"swagger":"2.0","parameters":{"Rid":{"name":"roomId","in":"query","required":true,"type":"string"}},"paths":{"/x":{"get":{"parameters":[{"$ref":"#/parameters/Rid"}]}}}}`
	routes := SweepRoutes([]byte(spec), "json")
	if len(routes) != 1 || len(routes[0].Params) != 1 || routes[0].Params[0].Name != "roomId" {
		t.Fatalf("Swagger 2.0 $ref not resolved: %+v", routes)
	}
}

func TestAddSweepRoutesSkipsAddressParams(t *testing.T) {
	tu, _ := target.Parse("http://localhost:3000/")
	har := []byte(`{"log":{"entries":[{"request":{"method":"GET","url":"http://localhost:3000/api/v1/rooms.get?roomId=6b0281133568ca9b5b817585","headers":[{"name":"X-Auth-Token","value":"tok"}]},"response":{"content":{"text":"{}"}}}]}}`)
	h, err := ParseHAR(har, tu)
	if err != nil {
		t.Fatal(err)
	}
	// Rocket.Chat's chat.getURLPreview: its example makes the app fetch
	// another site. A uri-format parameter with no example is dropped too.
	spec := `{"openapi":"3.0.0","paths":{
	 "/api/v1/chat.getURLPreview":{"get":{"parameters":[
	  {"name":"roomId","in":"query","required":true,"schema":{"type":"string"}},
	  {"name":"url","in":"query","required":true,"schema":{"type":"string"},"example":"http://www.w3schools.com/tags/movie.mp4"}]}},
	 "/api/v1/hook":{"get":{"parameters":[{"name":"target","in":"query","required":true,"schema":{"type":"string","format":"uri"}}]}},
	 "/api/v1/proxy":{"get":{"parameters":[{"name":"src","in":"query","required":true,"schema":{"type":"string"},"example":"//cdn.example/x"}]}},
	 "/api/v1/rooms.info":{"get":{"parameters":[{"name":"roomId","in":"query","required":true,"schema":{"type":"string"}}]}}}}`
	h.AddSweepRoutes(SweepRoutes([]byte(spec), "json"), "")
	for _, r := range h.Requests {
		if strings.Contains(r.Path, "getURLPreview") || strings.Contains(r.Path, "/hook") || strings.Contains(r.Path, "/proxy") {
			t.Errorf("sent a route whose parameter is an address: %s", r.Path)
		}
	}
	if h.SweepURL != 3 {
		t.Errorf("SweepURL = %d, want 3", h.SweepURL)
	}
	if h.FromSweep != 1 {
		t.Errorf("FromSweep = %d, want 1 (rooms.info)", h.FromSweep)
	}
}

// A path parameter whose name is not an ID ({owner}, {repo}) is not filled
// with A's IDs: on Gitea that only earned 404s. An ID-named one no alias
// matches still takes any of A's IDs (ADR 0052).
func TestAddSweepRoutesPathNamesNotIDs(t *testing.T) {
	tu, _ := target.Parse("http://localhost:3000/")
	har := []byte(`{"log":{"entries":[{"request":{"method":"GET","url":"http://localhost:3000/api/x","headers":[{"name":"Cookie","value":"s=A"}]},"response":{"content":{"text":"{\"rid\":\"6b0281133568ca9b5b817585\"}"}}}]}}`)
	h, err := ParseHAR(har, tu)
	if err != nil {
		t.Fatal(err)
	}
	spec := `{"openapi":"3.0.0","paths":{
	 "/repos/{owner}/{repo}":{"get":{"parameters":[{"name":"owner","in":"path","required":true},{"name":"repo","in":"path","required":true}]}},
	 "/files/{file_id}":{"get":{"parameters":[{"name":"file_id","in":"path","required":true}]}}}}`
	h.AddSweepRoutes(SweepRoutes([]byte(spec), "json"), "")
	var paths []string
	for _, r := range h.Requests[1:] {
		paths = append(paths, r.Path)
	}
	if len(paths) != 1 || paths[0] != "/files/6b0281133568ca9b5b817585" {
		t.Errorf("swept %v, want only /files/<A's ID>", paths)
	}
	if h.SweepNoID != 1 {
		t.Errorf("SweepNoID = %d, want 1 (the {owner}/{repo} route)", h.SweepNoID)
	}
}

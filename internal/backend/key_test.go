package backend

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
)

func TestParseKey(t *testing.T) {
	anon := jwt(`{"iss":"supabase","ref":"abcdefghijklmnop","role":"anon"}`)
	pub := "sb_publishable_AbC123_xyz-987654"
	for _, c := range []struct {
		raw, want, err string
	}{
		{pub, pub, ""},
		{" " + pub + "\n", pub, ""}, // as $(cat file) or a pasted line gives it
		{anon, anon, ""},
		{jwt(`{"role":"anon"}`), jwt(`{"role":"anon"}`), ""}, // a local stack's key names no project
		{"sb_secret_AbC123_xyz-987654", "", "secret key (sb_secret_)"},
		{jwt(`{"iss":"supabase","ref":"abcdefghijklmnop","role":"service_role"}`), "", "service_role key"},
		{jwt(`{"role":"authenticated","sub":"u1"}`), "", `role is "authenticated"`},
		{jwt(`{"ref":"abcdefghijklmnop"}`), "", `role is ""`},
		{"", "", "is empty"},
		{"  ", "", "is empty"},
		{"sb_publishable_short", "", "not a Supabase anon key"},
		{"sb_publishable_AbC123 xyz-987654", "", "not a Supabase anon key"},
		{"eyJhbGciOiJIUzI1NiJ9.not-json.sig", "", "not a Supabase anon key"},
		{"password123", "", "not a Supabase anon key"},
	} {
		got, err := ParseKey(c.raw)
		if got != c.want || (err == nil) != (c.err == "") || err != nil && !strings.Contains(err.Error(), c.err) {
			t.Errorf("%q: %q, %v", c.raw, got, err)
		}
		// The error never holds the key.
		if err != nil && strings.TrimSpace(c.raw) != "" && strings.Contains(err.Error(), strings.TrimSpace(c.raw)) {
			t.Errorf("%q: the error holds the key: %v", c.raw, err)
		}
	}
}

func TestKeyForHost(t *testing.T) {
	anon := jwt(`{"role":"anon","ref":"abcdefghijklmnop"}`)
	for _, c := range []struct {
		key, host string
		want      bool
	}{
		{anon, "abcdefghijklmnop.supabase.co", true},
		{anon, "someotherproject.supabase.co", false},
		{anon, "127.0.0.1", true}, // not hosted: no ref to compare
		{jwt(`{"role":"anon"}`), "someotherproject.supabase.co", true},
		{"sb_publishable_AbC123_xyz-987654", "someotherproject.supabase.co", true}, // names no project: KeyAccepted tells
	} {
		if got := KeyForHost(c.key, c.host); got != c.want {
			t.Errorf("%s %s: %v", c.key, c.host, got)
		}
	}
	for host, ref := range map[string]string{"abcdefghijklmnop.supabase.co": "abcdefghijklmnop", "supabase.co": "", "a.b.supabase.co": "", "abc.supabase.com": "", "127.0.0.1": "", "db.example": ""} {
		if got := ProjectRef(host); got != ref {
			t.Errorf("ProjectRef(%q) = %q", host, got)
		}
	}
}

// settingsBody is the start of GET /auth/v1/settings as Supabase Auth
// v2.198.0 answered it behind Supabase's self-hosted gateway on 2026-11-23.
const settingsBody = `{"external":{"anonymous_users":false,"apple":false,"email":true,"phone":false},"disable_signup":false,"mailer_autoconfirm":true,"phone_autoconfirm":false,"sms_provider":"","saml_enabled":false}`

func TestKeyAccepted(t *testing.T) {
	b, err := Parse("https://abcdefghijklmnop.supabase.co")
	if err != nil {
		t.Fatal(err)
	}
	pub, anon := "sb_publishable_AbC123_xyz-987654", jwt(`{"role":"anon","ref":"abcdefghijklmnop"}`)
	for _, c := range []struct {
		name     string
		key      string
		answer   fakeAnswer
		requests int
		err      string
	}{
		{"accepted", pub, fakeAnswer{200, settingsBody, nil}, 1, ""},
		{"accepted JWT", anon, fakeAnswer{200, settingsBody, nil}, 1, ""},
		// The gateway's answer to a key that is not the project's (measured: 401 "Unauthorized").
		{"refused", pub, fakeAnswer{401, "Unauthorized", nil}, 1, "refused the key in SIEGEKIT_SUPABASE_KEY (GET /auth/v1/settings answered 401)"},
		{"not found", pub, fakeAnswer{404, "", nil}, 1, "answered 404"},
		// A 200 that is not Supabase Auth's settings does not show the key was checked.
		{"other 200", pub, fakeAnswer{200, `<html>app</html>`, nil}, 1, "did not answer with Supabase Auth's settings"},
		{"empty object", pub, fakeAnswer{200, `{}`, nil}, 1, "did not answer with Supabase Auth's settings"},
		{"too large", pub, fakeAnswer{200, settingsBody, errors.New("answer over the limit")}, 1, "did not answer with Supabase Auth's settings"},
		{"no answer", pub, fakeAnswer{0, "", errors.New("connection refused")}, 0, "did not answer: connection refused"},
	} {
		got := useSend(t, map[string]fakeAnswer{SettingsPath: c.answer})
		n, err := KeyAccepted(context.Background(), config(b), c.key)
		if n != c.requests || (err == nil) != (c.err == "") || err != nil && !strings.Contains(err.Error(), c.err) {
			t.Errorf("%s: %d, %v", c.name, n, err)
		}
		auth := ""
		if strings.HasPrefix(c.key, "eyJ") {
			auth = "Bearer " + c.key
		}
		if want := []string{SettingsPath + " " + c.key + " " + auth}; !slices.Equal(*got, want) {
			t.Errorf("%s: requests %q", c.name, *got)
		}
		if err != nil && strings.Contains(err.Error(), c.key) {
			t.Errorf("%s: the error holds the key", c.name)
		}
	}
	cfg := config(b)
	cfg.ReadOnly = false
	if _, err := KeyAccepted(context.Background(), cfg, pub); err == nil {
		t.Error("a configuration that allows writes was used")
	}
}

// TestKeyAcceptedOverHTTP sends the real request through egress.
func TestKeyAcceptedOverHTTP(t *testing.T) {
	key := "sb_publishable_AbC123_xyz-987654"
	var got []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = append(got, r.Method+" "+r.URL.RequestURI())
		if r.Header.Get("Apikey") != key {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if r.Header.Get("Authorization") != "" || r.Header.Get("Accept") != "application/json" || !strings.HasPrefix(r.UserAgent(), "SiegeKit/") {
			t.Errorf("headers %v", r.Header)
		}
		_, _ = w.Write([]byte(settingsBody))
	}))
	defer srv.Close()
	b, err := Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if n, err := KeyAccepted(context.Background(), config(b), key); n != 1 || err != nil {
		t.Errorf("accepted: %d %v", n, err)
	}
	if n, err := KeyAccepted(context.Background(), config(b), "sb_publishable_OtherProject_1"); n != 1 || err == nil {
		t.Errorf("refused: %d %v", n, err)
	}
	if want := []string{"GET /auth/v1/settings", "GET /auth/v1/settings"}; !slices.Equal(got, want) {
		t.Errorf("requests %q", got)
	}
}

// A local backend told to be Supabase by --source has no project ref: an
// anon key that names a project is still read from its scripts (the ref
// comes from the host, not the kind).
func TestReadScriptsLocalKindKeepsKey(t *testing.T) {
	b, err := Parse("http://127.0.0.1:54321")
	if err != nil {
		t.Fatal(err)
	}
	b.Kind = Supabase
	key := jwt(`{"role":"anon","ref":"abcdefghijklmnop"}`)
	if s := ReadScripts(b, map[string][]byte{"a.js": []byte(`x("` + key + `")`)}); s.Key != key {
		t.Errorf("key %q", s.Key)
	}
}

func FuzzParseKey(f *testing.F) {
	f.Add("sb_publishable_AbC123_xyz-987654")
	f.Add("sb_secret_AbC123_xyz-987654")
	f.Add(jwt(`{"role":"anon"}`))
	f.Add(jwt(`{"role":"service_role"}`))
	f.Fuzz(func(t *testing.T, raw string) {
		k, err := ParseKey(raw)
		if err != nil {
			if k != "" {
				t.Errorf("key returned with an error")
			}
			return
		}
		role, _, _ := jwtClaims(k)
		if !rePublishableKey.MatchString(k) && role != "anon" {
			t.Errorf("accepted %q", k)
		}
		if strings.Contains(k, "sb_secret_") && !rePublishableKey.MatchString(k) {
			t.Errorf("accepted a secret key %q", k)
		}
	})
}

package webform

import "testing"

func TestLoginPage(t *testing.T) {
	for loc, want := range map[string]bool{
		"/login?next=%2Fw%2F1": true, "/user/login?redirect_to=%2F": true, "https://app.test/signIn": true, "/auth/realms/x": true,
		"/users/sign_in": true, "/sign-in": true, "https://sso.example.test/oauth2/authorize?client_id=x": true, "https://vercel.com/sso-api?url=x": true,
		"": false, "%zz": false, "/": false, "/dashboard": false, "/orgs/3/settings": false, "/alice/pub": false, "/blog/authors": false,
		"/w/1?next=/login": false, "/author/42": false,
	} {
		if got := LoginPage(loc); got != want {
			t.Errorf("%q: %v", loc, got)
		}
	}
}

func TestWords(t *testing.T) {
	got := Words("createIssueComment_v2-sign_in")
	want := []string{"create", "issue", "comment", "v2", "sign", "in"}
	if len(got) != len(want) {
		t.Fatalf("%q", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("%q", got)
		}
	}
}

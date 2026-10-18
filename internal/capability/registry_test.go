package capability

import "testing"

func TestScopesAreDeduplicatedAndUnknownRejected(t *testing.T) {
	scopes, err := Scopes([]string{"identity.basic", "gmail.read", "gmail.read"})
	if err != nil {
		t.Fatal(err)
	}
	if len(scopes) != 4 {
		t.Fatalf("scopes=%v", scopes)
	}
	if _, err := Scopes([]string{"future.magic"}); err == nil {
		t.Fatal("unknown capability accepted")
	}
}

func TestCanonicalScopeGoogleIdentityAliases(t *testing.T) {
	cases := map[string]string{
		"openid":  "openid",
		"email":   "email",
		"profile": "profile",
		"https://www.googleapis.com/auth/userinfo.email":   "email",
		"https://www.googleapis.com/auth/userinfo.profile": "profile",
		"https://www.googleapis.com/auth/gmail.readonly":   "https://www.googleapis.com/auth/gmail.readonly",
		"https://www.googleapis.com/auth/drive.readonly":   "https://www.googleapis.com/auth/drive.readonly",
	}
	for raw, expected := range cases {
		if got := CanonicalScope(raw); got != expected {
			t.Errorf("CanonicalScope(%q)=%q, want %q", raw, got, expected)
		}
	}
}

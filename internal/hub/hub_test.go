package hub

import (
	"reflect"
	"testing"
)

func TestMergeCanonicalizesExistingGoogleIdentityGrant(t *testing.T) {
	existing := []string{"openid", "https://www.googleapis.com/auth/userinfo.email"}
	additional := []string{"email", "https://www.googleapis.com/auth/userinfo.profile"}
	got := merge(existing, additional)
	want := []string{"email", "openid", "profile"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("merge got=%v want=%v", got, want)
	}
	if existing[1] != "https://www.googleapis.com/auth/userinfo.email" {
		t.Fatal("merge mutated stored input")
	}
}

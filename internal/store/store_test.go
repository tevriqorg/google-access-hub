package store

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestStorePersistsAndConsumesPendingOnce(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hub.json")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1700000000, 0).UTC()
	if err := s.PutPending(PendingAuth{StateHash: "abc", EncryptedPKCEVerifier: "v1:test", ExpiresAt: now.Add(time.Minute), CreatedAt: now}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ConsumePending("abc", now); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ConsumePending("abc", now); err == nil {
		t.Fatal("pending state replay accepted")
	}
	if err := s.UpsertAccount(Account{Subject: "sub", Email: "me@example.test", EncryptedRefreshToken: "v1:cipher", GrantedScopes: []string{"openid"}, Status: "active", CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	account, ok := reopened.Account("sub")
	if !ok || account.Email != "me@example.test" {
		t.Fatalf("account=%+v ok=%v", account, ok)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("store mode=%o", info.Mode().Perm())
	}
}

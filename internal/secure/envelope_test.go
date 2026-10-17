package secure

import "testing"

func TestEnvelopeRoundTripAndAAD(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	encrypted, err := Encrypt(key, "refresh:subject", "top-secret")
	if err != nil {
		t.Fatal(err)
	}
	if encrypted == "top-secret" {
		t.Fatal("plaintext was not encrypted")
	}
	got, err := Decrypt(key, "refresh:subject", encrypted)
	if err != nil {
		t.Fatal(err)
	}
	if got != "top-secret" {
		t.Fatalf("decrypt=%q", got)
	}
	if _, err := Decrypt(key, "refresh:other", encrypted); err == nil {
		t.Fatal("aad mismatch should fail")
	}
}

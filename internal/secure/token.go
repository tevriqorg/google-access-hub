package secure

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

func RandomToken(bytes int) (string, error) {
	if bytes < 16 {
		return "", fmt.Errorf("random token size %d is too small", bytes)
	}
	raw := make([]byte, bytes)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func HashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func TokenHashEqual(wantHash, token string) bool {
	got := HashToken(token)
	if len(got) != len(wantHash) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(got), []byte(wantHash)) == 1
}

func PKCEChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

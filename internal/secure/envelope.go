package secure

import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "encoding/base64"
    "errors"
    "fmt"
    "io"
    "strings"
)

const envelopeVersion = "v1"

func Encrypt(key []byte, aad, plaintext string) (string, error) {
    if len(key) != 32 {
        return "", errors.New("master key must be 32 bytes")
    }
    block, err := aes.NewCipher(key)
    if err != nil {
        return "", err
    }
    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return "", err
    }
    nonce := make([]byte, gcm.NonceSize())
    if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
        return "", err
    }
    sealed := gcm.Seal(nil, nonce, []byte(plaintext), []byte(aad))
    payload := append(nonce, sealed...)
    return envelopeVersion + ":" + base64.RawURLEncoding.EncodeToString(payload), nil
}

func Decrypt(key []byte, aad, envelope string) (string, error) {
    if len(key) != 32 {
        return "", errors.New("master key must be 32 bytes")
    }
    parts := strings.SplitN(envelope, ":", 2)
    if len(parts) != 2 || parts[0] != envelopeVersion {
        return "", errors.New("unsupported encrypted envelope")
    }
    raw, err := base64.RawURLEncoding.DecodeString(parts[1])
    if err != nil {
        return "", fmt.Errorf("decode encrypted envelope: %w", err)
    }
    block, err := aes.NewCipher(key)
    if err != nil {
        return "", err
    }
    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return "", err
    }
    if len(raw) < gcm.NonceSize() {
        return "", errors.New("encrypted envelope is truncated")
    }
    plaintext, err := gcm.Open(nil, raw[:gcm.NonceSize()], raw[gcm.NonceSize():], []byte(aad))
    if err != nil {
        return "", errors.New("encrypted envelope authentication failed")
    }
    return string(plaintext), nil
}

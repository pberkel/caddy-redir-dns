package redirdns

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
)

const (
	encKeySize   = 32 // AES-256 requires a 32-byte key
	encNonceSize = 12 // AES-GCM standard nonce length
	encTagSize   = 16 // AES-GCM authentication tag length
	// encMinBlobLen is the minimum decoded blob length: nonce + tag, with zero plaintext bytes.
	encMinBlobLen = encNonceSize + encTagSize
)

// parseEncryptionKey returns the raw key bytes from s. If s is valid base64
// (standard or URL-safe, with or without padding) and decodes to exactly
// encKeySize bytes, those decoded bytes are used. Otherwise the raw bytes of
// the string are used directly, allowing a plain 32-character ASCII key
// without any encoding.
func parseEncryptionKey(s string) ([]byte, error) {
	for _, enc := range []*base64.Encoding{
		base64.StdEncoding,
		base64.RawStdEncoding,
		base64.URLEncoding,
		base64.RawURLEncoding,
	} {
		if decoded, err := enc.DecodeString(s); err == nil {
			return decoded, nil
		}
	}
	return []byte(s), nil
}

// encryptTxtRecord encrypts plaintext with AES-256-GCM and returns a base64
// RawURL-encoded string suitable for use as a DNS TXT record value. The binary
// format matches what decryptTxtRecord expects:
//
//	[12B nonce][ciphertext || 16B AES-GCM auth tag]
func encryptTxtRecord(key []byte, plaintext string) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("AES cipher init: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("GCM init: %w", err)
	}
	nonce := make([]byte, encNonceSize)
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("generate nonce: %w", err)
	}
	// Seal appends ciphertext+tag to nonce, producing [nonce || ciphertext || tag]
	blob := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.RawURLEncoding.EncodeToString(blob), nil
}

// decryptTxtRecord decodes and decrypts a base64-encoded encrypted DNS TXT record value.
//
// Binary format after base64 (RawURLEncoding) decoding:
//
//	[12B nonce][ciphertext || 16B AES-GCM auth tag]
//
// The AES-256-GCM authentication tag ensures that tampered ciphertext is rejected.
func decryptTxtRecord(key []byte, record string) (string, error) {
	raw, err := base64.RawURLEncoding.DecodeString(record)
	if err != nil {
		return "", fmt.Errorf("base64 decode: %w", err)
	}
	if len(raw) <= encMinBlobLen {
		return "", fmt.Errorf("ciphertext too short (%d bytes, need >%d)", len(raw), encMinBlobLen)
	}

	nonce := raw[:encNonceSize]
	ciphertext := raw[encNonceSize:]

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("AES cipher init: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("GCM init: %w", err)
	}
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("GCM decrypt: %w", err)
	}

	return string(plaintext), nil
}

package redirdns

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"testing"
)

// encryptRecord is the test-side counterpart to decryptTxtRecord.
// It encrypts plaintext with AES-256-GCM and returns a base64 RawURL-encoded
// string in the same binary format expected by decryptTxtRecord:
//
//	[12B nonce][ciphertext || 16B GCM auth tag]
func encryptRecord(key []byte, plaintext string) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return "", err
	}
	ciphertext := gcm.Seal(nil, nonce, []byte(plaintext), nil)
	blob := append(nonce, ciphertext...)
	return base64.RawURLEncoding.EncodeToString(blob), nil
}

func randomKey(t *testing.T) []byte {
	t.Helper()
	key := make([]byte, encKeySize)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return key
}

func TestDecryptTxtRecord_RoundTrip(t *testing.T) {
	t.Parallel()

	key := randomKey(t)
	cases := []string{
		"https://example.com",
		"https://example.com 301",
		"https://example.com/path?q=1&r=2 temporary",
		"https://very-long-target.example.com/some/path/here?with=query",
	}
	for _, plaintext := range cases {
		encrypted, err := encryptRecord(key, plaintext)
		if err != nil {
			t.Fatalf("encrypt %q: %v", plaintext, err)
		}
		decrypted, err := decryptTxtRecord(key, encrypted)
		if err != nil {
			t.Fatalf("decrypt %q: %v", plaintext, err)
		}
		if decrypted != plaintext {
			t.Errorf("round-trip mismatch: got %q, want %q", decrypted, plaintext)
		}
	}
}

func TestDecryptTxtRecord_WrongKey(t *testing.T) {
	t.Parallel()

	encKey := randomKey(t)
	decKey := randomKey(t)

	encrypted, err := encryptRecord(encKey, "https://example.com")
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	_, err = decryptTxtRecord(decKey, encrypted)
	if err == nil {
		t.Fatal("expected decryption to fail with wrong key, but it succeeded")
	}
}

func TestDecryptTxtRecord_InvalidBase64(t *testing.T) {
	t.Parallel()

	key := randomKey(t)
	_, err := decryptTxtRecord(key, "not!valid!base64!!")
	if err == nil {
		t.Fatal("expected error for invalid base64, got nil")
	}
}

func TestDecryptTxtRecord_TooShort(t *testing.T) {
	t.Parallel()

	key := randomKey(t)
	short := base64.RawURLEncoding.EncodeToString([]byte("tooshort"))
	_, err := decryptTxtRecord(key, short)
	if err == nil {
		t.Fatal("expected error for too-short ciphertext, got nil")
	}
}

func TestParseEncryptionKey_Base64Std(t *testing.T) {
	t.Parallel()

	key := randomKey(t)
	loaded, err := parseEncryptionKey(base64.StdEncoding.EncodeToString(key))
	if err != nil {
		t.Fatalf("parseEncryptionKey std: %v", err)
	}
	if string(loaded) != string(key) {
		t.Error("loaded key does not match original")
	}
}

func TestParseEncryptionKey_Base64URL(t *testing.T) {
	t.Parallel()

	key := randomKey(t)
	loaded, err := parseEncryptionKey(base64.RawURLEncoding.EncodeToString(key))
	if err != nil {
		t.Fatalf("parseEncryptionKey url: %v", err)
	}
	if string(loaded) != string(key) {
		t.Error("loaded key does not match original")
	}
}

func TestParseEncryptionKey_WrongLength(t *testing.T) {
	t.Parallel()

	// A base64 string encoding 16 bytes decodes successfully to 16 bytes — the
	// wrong length for AES-256. parseEncryptionKey does not check length; that
	// responsibility belongs to Provision.
	decoded, err := parseEncryptionKey(base64.StdEncoding.EncodeToString(make([]byte, 16)))
	if err != nil {
		t.Fatalf("unexpected parse error: %v", err)
	}
	if len(decoded) == encKeySize {
		t.Fatal("expected wrong length, got correct length")
	}
}

func TestParseEncryptionKey_RawASCII(t *testing.T) {
	t.Parallel()

	// A plain 32-character ASCII string should be accepted as-is.
	key := "this-is-a-32-char-ascii-secret!!"
	if len(key) != encKeySize {
		t.Fatalf("test key is %d bytes, want %d", len(key), encKeySize)
	}
	decoded, err := parseEncryptionKey(key)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(decoded) != key {
		t.Errorf("got %q, want %q", decoded, key)
	}
}

func TestParseEncryptionKey_InvalidBase64FallsBackToRaw(t *testing.T) {
	t.Parallel()

	// A string that is not valid base64 falls back to raw bytes without error.
	// Length validation (not 32 bytes here) is left to Provision.
	_, err := parseEncryptionKey("not!valid!base64")
	if err != nil {
		t.Fatalf("expected no error (raw fallback), got: %v", err)
	}
}

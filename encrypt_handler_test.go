package redirdns

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// newTestEncryptHandler returns a provisioned EncryptHandler using a freshly
// generated random key, ready for use in HTTP tests.
func newTestEncryptHandler(t *testing.T) *EncryptHandler {
	t.Helper()
	h := &EncryptHandler{encryptionKey: randomKey(t)}
	return h
}

func serveEncrypt(t *testing.T, h *EncryptHandler, method, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, "/api/encrypt", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	if err := h.ServeHTTP(w, req, nil); err != nil {
		t.Fatalf("ServeHTTP returned unexpected error: %v", err)
	}
	return w
}

func TestEncryptHandler_Success(t *testing.T) {
	t.Parallel()

	h := newTestEncryptHandler(t)
	w := serveEncrypt(t, h, http.MethodPost, `{"plaintext":"https://example.com"}`)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}

	var resp struct {
		Ciphertext string `json:"ciphertext"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Ciphertext == "" {
		t.Fatal("ciphertext is empty")
	}

	// Verify the ciphertext decrypts back to the original plaintext.
	plaintext, err := decryptTxtRecord(h.encryptionKey, resp.Ciphertext)
	if err != nil {
		t.Fatalf("decrypt ciphertext: %v", err)
	}
	if plaintext != "https://example.com" {
		t.Errorf("decrypted = %q, want %q", plaintext, "https://example.com")
	}
}

func TestEncryptHandler_MethodNotAllowed(t *testing.T) {
	t.Parallel()

	h := newTestEncryptHandler(t)
	for _, method := range []string{http.MethodGet, http.MethodPut, http.MethodDelete} {
		w := serveEncrypt(t, h, method, "")
		if w.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s: status = %d, want 405", method, w.Code)
		}
		if allow := w.Header().Get("Allow"); allow != "POST" {
			t.Errorf("%s: Allow header = %q, want POST", method, allow)
		}
	}
}

func TestEncryptHandler_InvalidJSON(t *testing.T) {
	t.Parallel()

	h := newTestEncryptHandler(t)
	w := serveEncrypt(t, h, http.MethodPost, `not json`)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestEncryptHandler_EmptyPlaintext(t *testing.T) {
	t.Parallel()

	h := newTestEncryptHandler(t)
	w := serveEncrypt(t, h, http.MethodPost, `{"plaintext":""}`)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestEncryptHandler_MissingPlaintextField(t *testing.T) {
	t.Parallel()

	h := newTestEncryptHandler(t)
	w := serveEncrypt(t, h, http.MethodPost, `{}`)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestEncryptHandler_EachCallProducesDifferentCiphertext(t *testing.T) {
	t.Parallel()

	h := newTestEncryptHandler(t)
	body := `{"plaintext":"https://example.com"}`

	w1 := serveEncrypt(t, h, http.MethodPost, body)
	w2 := serveEncrypt(t, h, http.MethodPost, body)

	var r1, r2 struct {
		Ciphertext string `json:"ciphertext"`
	}
	json.Unmarshal(w1.Body.Bytes(), &r1)
	json.Unmarshal(w2.Body.Bytes(), &r2)

	if r1.Ciphertext == r2.Ciphertext {
		t.Error("two calls with same plaintext produced identical ciphertext (nonce not randomised?)")
	}
}

func TestEncryptHandler_EmptyBody(t *testing.T) {
	t.Parallel()

	h := newTestEncryptHandler(t)
	req := httptest.NewRequest(http.MethodPost, "/api/encrypt", bytes.NewReader(nil))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req, nil) //nolint:errcheck
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

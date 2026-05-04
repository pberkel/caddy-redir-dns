package redirdns

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(EncryptHandler{})
	httpcaddyfile.RegisterHandlerDirective("redir_dns_encrypt", parseEncryptHandlerCaddyfile)
}

// EncryptHandler is a Caddy HTTP handler that encrypts a plaintext DNS TXT
// record value using AES-256-GCM and returns the ciphertext. It is intended
// to be paired with the redir_dns handler configured with the same key, so
// operators can generate encrypted TXT record values via HTTP without ever
// exposing the encryption key to clients.
//
// Requests: POST with a JSON body {"plaintext": "<redirect target>"}
// Responses: JSON {"ciphertext": "<base64url encoded encrypted value>"}
type EncryptHandler struct {
	// 32-byte AES-256 encryption key. Must match the encryption_key configured
	// on the redir_dns handler.
	// The key may be specified as:
	//   - A base64-encoded 32-byte value (recommended): openssl rand -base64 32
	//   - A plain 32-character ASCII string (e.g. a memorable passphrase)
	// Accepts a Caddy global placeholder (e.g. "{env.ENCRYPTION_KEY}").
	EncryptionKey string `json:"encryption_key,omitempty"`

	encryptionKey []byte
	logger        *zap.Logger
}

// CaddyModule returns the Caddy module information.
func (EncryptHandler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.redir_dns_encrypt",
		New: func() caddy.Module { return new(EncryptHandler) },
	}
}

// Provision implements caddy.Provisioner.
func (e *EncryptHandler) Provision(ctx caddy.Context) error {
	e.logger = ctx.Logger()

	repl := caddy.NewReplacer()
	e.EncryptionKey = repl.ReplaceAll(e.EncryptionKey, "")

	if e.EncryptionKey == "" {
		return fmt.Errorf("encryption_key is required")
	}
	var err error
	if e.encryptionKey, err = parseEncryptionKey(e.EncryptionKey); err != nil {
		return fmt.Errorf("encryption_key: %w", err)
	}
	if len(e.encryptionKey) < encKeySize {
		return fmt.Errorf("encryption_key: key must be at least %d bytes (AES-256), got %d", encKeySize, len(e.encryptionKey))
	}
	if len(e.encryptionKey) > encKeySize {
		e.logger.Warn("encryption_key is longer than 32 bytes; truncating to 32", zap.Int("original_len", len(e.encryptionKey)))
		e.encryptionKey = e.encryptionKey[:encKeySize]
	}
	return nil
}

// ServeHTTP implements caddyhttp.MiddlewareHandler.
func (e *EncryptHandler) ServeHTTP(w http.ResponseWriter, r *http.Request, _ caddyhttp.Handler) error {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		w.WriteHeader(http.StatusMethodNotAllowed)
		return nil
	}

	var req struct {
		Plaintext string `json:"plaintext"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid JSON body"}`, http.StatusBadRequest)
		return nil
	}
	if req.Plaintext == "" {
		http.Error(w, `{"error":"plaintext is required"}`, http.StatusBadRequest)
		return nil
	}

	ciphertext, err := encryptTxtRecord(e.encryptionKey, req.Plaintext)
	if err != nil {
		if c := e.logger.Check(zap.ErrorLevel, "encryption failed"); c != nil {
			c.Write(zap.Error(err))
		}
		http.Error(w, `{"error":"encryption failed"}`, http.StatusInternalServerError)
		return nil
	}

	w.Header().Set("Content-Type", "application/json")
	return json.NewEncoder(w).Encode(map[string]string{"ciphertext": ciphertext})
}

// UnmarshalCaddyfile implements caddyfile.Unmarshaler.
func (e *EncryptHandler) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		for nesting := d.Nesting(); d.NextBlock(nesting); {
			switch d.Val() {
			case "encryption_key":
				if !d.NextArg() {
					return d.ArgErr()
				}
				e.EncryptionKey = d.Val()
			default:
				return d.Errf("unrecognized option %q", d.Val())
			}
		}
	}
	return nil
}

func parseEncryptHandlerCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	e := new(EncryptHandler)
	return e, e.UnmarshalCaddyfile(h.Dispenser)
}

// String returns a JSON representation of the configuration with the
// EncryptionKey redacted. The value receiver is intentional: EncryptionKey is
// mutated on the copy so the original struct is never modified.
func (e EncryptHandler) String() string {
	const redacted = "REDACTED"
	if e.EncryptionKey != "" {
		e.EncryptionKey = redacted
	}
	b, _ := json.Marshal(e)
	return string(b)
}

// Interface guards
var (
	_ caddy.Provisioner           = (*EncryptHandler)(nil)
	_ caddyfile.Unmarshaler       = (*EncryptHandler)(nil)
	_ caddyhttp.MiddlewareHandler = (*EncryptHandler)(nil)
)

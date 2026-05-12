package mcpbouncer

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

// ParseAndVerifyJWT splits and verifies a compact JWT.
// getKey is called with kid and alg; it must return ed25519.PublicKey or *rsa.PublicKey.
func ParseAndVerifyJWT(token string, getKey func(kid, alg string) (interface{}, error)) (map[string]interface{}, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("malformed jwt: expected 3 parts")
	}

	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("header decode: %w", err)
	}

	var header map[string]interface{}
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return nil, fmt.Errorf("header parse: %w", err)
	}

	alg, _ := header["alg"].(string)
	if alg == "" {
		return nil, fmt.Errorf("missing alg")
	}
	if alg == "none" {
		return nil, fmt.Errorf("alg=none not allowed")
	}
	if alg != "EdDSA" && alg != "RS256" {
		return nil, fmt.Errorf("unsupported alg %q", alg)
	}

	kid, _ := header["kid"].(string)

	pub, err := getKey(kid, alg)
	if err != nil {
		return nil, fmt.Errorf("key lookup: %w", err)
	}

	signingInput := []byte(parts[0] + "." + parts[1])
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("signature decode: %w", err)
	}

	switch alg {
	case "EdDSA":
		edPub, ok := pub.(ed25519.PublicKey)
		if !ok {
			return nil, fmt.Errorf("expected ed25519.PublicKey for EdDSA")
		}
		if !ed25519.Verify(edPub, signingInput, sig) {
			return nil, fmt.Errorf("EdDSA signature invalid")
		}

	case "RS256":
		rsaPub, ok := pub.(*rsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("expected *rsa.PublicKey for RS256")
		}
		h := sha256.Sum256(signingInput)
		if err := rsa.VerifyPKCS1v15(rsaPub, crypto.SHA256, h[:], sig); err != nil {
			return nil, fmt.Errorf("RS256 signature invalid: %w", err)
		}
	}

	payloadJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("payload decode: %w", err)
	}

	var claims map[string]interface{}
	if err := json.Unmarshal(payloadJSON, &claims); err != nil {
		return nil, fmt.Errorf("payload parse: %w", err)
	}

	return claims, nil
}

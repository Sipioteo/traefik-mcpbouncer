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

	alg, kid, err := parseJWTHeader(parts[0])
	if err != nil {
		return nil, err
	}

	pub, err := getKey(kid, alg)
	if err != nil {
		return nil, fmt.Errorf("key lookup: %w", err)
	}

	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("signature decode: %w", err)
	}

	signingInput := []byte(parts[0] + "." + parts[1])
	if err := verifyJWTSignature(alg, pub, signingInput, sig); err != nil {
		return nil, err
	}

	return parseJWTPayload(parts[1])
}

func parseJWTHeader(headerPart string) (alg, kid string, err error) {
	headerJSON, err := base64.RawURLEncoding.DecodeString(headerPart)
	if err != nil {
		return "", "", fmt.Errorf("header decode: %w", err)
	}
	var header map[string]interface{}
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return "", "", fmt.Errorf("header parse: %w", err)
	}
	alg, _ = header["alg"].(string)
	switch alg {
	case "":
		return "", "", fmt.Errorf("missing alg")
	case "none":
		return "", "", fmt.Errorf("alg=none not allowed")
	case "EdDSA", "RS256":
		// ok
	default:
		return "", "", fmt.Errorf("unsupported alg %q", alg)
	}
	kid, _ = header["kid"].(string)
	return alg, kid, nil
}

func verifyJWTSignature(alg string, pub interface{}, signingInput, sig []byte) error {
	switch alg {
	case "EdDSA":
		edPub, ok := pub.(ed25519.PublicKey)
		if !ok {
			return fmt.Errorf("expected ed25519.PublicKey for EdDSA")
		}
		if !ed25519.Verify(edPub, signingInput, sig) {
			return fmt.Errorf("EdDSA signature invalid")
		}
		return nil
	case "RS256":
		rsaPub, ok := pub.(*rsa.PublicKey)
		if !ok {
			return fmt.Errorf("expected *rsa.PublicKey for RS256")
		}
		h := sha256.Sum256(signingInput)
		if err := rsa.VerifyPKCS1v15(rsaPub, crypto.SHA256, h[:], sig); err != nil {
			return fmt.Errorf("RS256 signature invalid: %w", err)
		}
		return nil
	}
	return fmt.Errorf("unsupported alg %q", alg)
}

func parseJWTPayload(payloadPart string) (map[string]interface{}, error) {
	payloadJSON, err := base64.RawURLEncoding.DecodeString(payloadPart)
	if err != nil {
		return nil, fmt.Errorf("payload decode: %w", err)
	}
	var claims map[string]interface{}
	if err := json.Unmarshal(payloadJSON, &claims); err != nil {
		return nil, fmt.Errorf("payload parse: %w", err)
	}
	return claims, nil
}

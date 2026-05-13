package traefik_mcpbouncer

import (
	"crypto/ed25519"
	"crypto/rsa"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"sync"
	"time"
)

type publicKey struct {
	kid string
	alg string
	key interface{} // ed25519.PublicKey or *rsa.PublicKey
}

type jwksCache struct {
	mu             sync.RWMutex
	sidecarBaseURL string
	resource       string
	ttl            time.Duration
	lastFetch      time.Time
	keys           map[string]publicKey
}

func newJWKSCache(sidecarBaseURL, resource string, ttlSeconds int) *jwksCache {
	if ttlSeconds <= 0 {
		ttlSeconds = 300
	}
	return &jwksCache{
		sidecarBaseURL: sidecarBaseURL,
		resource:       resource,
		ttl:            time.Duration(ttlSeconds) * time.Second,
		keys:           make(map[string]publicKey),
	}
}

func (c *jwksCache) Get(kid string) (publicKey, error) {
	c.mu.RLock()
	k, ok := c.keys[kid]
	expired := time.Since(c.lastFetch) > c.ttl
	c.mu.RUnlock()

	if ok && !expired {
		return k, nil
	}

	// Refresh if cache is stale or key is missing.
	// Only refresh if last attempt was more than 5 seconds ago to avoid hammering.
	c.mu.Lock()
	defer c.mu.Unlock()
	if time.Since(c.lastFetch) > 5*time.Second {
		if err := c.refresh(); err != nil {
			// On refresh error, still try to serve stale key if available.
			if k2, ok2 := c.keys[kid]; ok2 {
				return k2, nil
			}
			return publicKey{}, err
		}
	}
	k, ok = c.keys[kid]
	if !ok {
		return publicKey{}, fmt.Errorf("key %q not found in JWKS", kid)
	}
	return k, nil
}

type jwksResponse struct {
	Keys []jwkEntry `json:"keys"`
}

type jwkEntry struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	N   string `json:"n"`
	E   string `json:"e"`
}

func (c *jwksCache) refresh() error {
	url := c.sidecarBaseURL + "/oauth/jwks.json?resource=" + c.resource
	resp, err := http.Get(url) //nolint
	if err != nil {
		return fmt.Errorf("jwks fetch: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("jwks read: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("jwks fetch status %d", resp.StatusCode)
	}

	var jwks jwksResponse
	if err := json.Unmarshal(body, &jwks); err != nil {
		return fmt.Errorf("jwks parse: %w", err)
	}

	newKeys := make(map[string]publicKey, len(jwks.Keys))
	for _, entry := range jwks.Keys {
		pk, err := parseJWKEntry(entry)
		if err != nil {
			continue
		}
		newKeys[entry.Kid] = pk
	}
	c.keys = newKeys
	c.lastFetch = time.Now()
	return nil
}

func parseJWKEntry(e jwkEntry) (publicKey, error) {
	switch {
	case e.Kty == "OKP" && e.Crv == "Ed25519":
		xBytes, err := base64.RawURLEncoding.DecodeString(e.X)
		if err != nil {
			return publicKey{}, fmt.Errorf("ed25519 x decode: %w", err)
		}
		if len(xBytes) != ed25519.PublicKeySize {
			return publicKey{}, fmt.Errorf("ed25519 x wrong size %d", len(xBytes))
		}
		return publicKey{kid: e.Kid, alg: "EdDSA", key: ed25519.PublicKey(xBytes)}, nil

	case e.Kty == "RSA":
		nBytes, err := base64.RawURLEncoding.DecodeString(e.N)
		if err != nil {
			return publicKey{}, fmt.Errorf("rsa n decode: %w", err)
		}
		eBytes, err := base64.RawURLEncoding.DecodeString(e.E)
		if err != nil {
			return publicKey{}, fmt.Errorf("rsa e decode: %w", err)
		}
		// Pad eBytes to 4 bytes for big-endian uint32 interpretation.
		if len(eBytes) > 4 {
			return publicKey{}, fmt.Errorf("rsa e too large")
		}
		padded := make([]byte, 4)
		copy(padded[4-len(eBytes):], eBytes)
		exp := int(binary.BigEndian.Uint32(padded))
		pub := &rsa.PublicKey{
			N: new(big.Int).SetBytes(nBytes),
			E: exp,
		}
		return publicKey{kid: e.Kid, alg: "RS256", key: pub}, nil

	default:
		return publicKey{}, fmt.Errorf("unsupported kty=%q crv=%q", e.Kty, e.Crv)
	}
}

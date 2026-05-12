package mcpbouncer

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"
)

// Config holds middleware configuration populated by Traefik from labels.
type Config struct {
	ProviderIssuer      string
	ClientID            string
	ClientSecret        string
	Resource            string
	Scopes              string
	SidecarURL          string
	Audience            string
	JWKSCacheTTLSeconds int
	RequiredScopes      string
}

// CreateConfig returns a Config with sensible defaults.
func CreateConfig() *Config {
	return &Config{
		JWKSCacheTTLSeconds: 300,
	}
}

// MCPBouncer is the Traefik middleware handler.
type MCPBouncer struct {
	next      http.Handler
	cfg       *Config
	cache     *jwksCache
	sidecarU  *url.URL
}

// New constructs the middleware. Called once by Traefik/Yaegi per middleware instance.
func New(_ context.Context, next http.Handler, config *Config, _ string) (http.Handler, error) {
	if config.ProviderIssuer == "" {
		return nil, fmt.Errorf("mcpbouncer: providerIssuer is required")
	}
	if config.ClientID == "" {
		return nil, fmt.Errorf("mcpbouncer: clientID is required")
	}
	if config.ClientSecret == "" {
		return nil, fmt.Errorf("mcpbouncer: clientSecret is required")
	}
	if config.Resource == "" {
		return nil, fmt.Errorf("mcpbouncer: resource is required")
	}
	if config.SidecarURL == "" {
		return nil, fmt.Errorf("mcpbouncer: sidecarURL is required")
	}
	if config.Audience == "" {
		config.Audience = config.Resource
	}

	su, err := url.Parse(config.SidecarURL)
	if err != nil {
		return nil, fmt.Errorf("mcpbouncer: invalid sidecarURL: %w", err)
	}

	return &MCPBouncer{
		next:     next,
		cfg:      config,
		cache:    newJWKSCache(config.SidecarURL, config.Resource, config.JWKSCacheTTLSeconds),
		sidecarU: su,
	}, nil
}

func (m *MCPBouncer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Strip all incoming X-MCPB-* headers to prevent spoofing.
	for key := range r.Header {
		if strings.HasPrefix(strings.ToUpper(key), "X-MCPB-") {
			r.Header.Del(key)
		}
	}

	if _, _, ok := MatchOAuthSuffix(r.URL.Path); ok {
		m.proxyToSidecar(w, r)
		return
	}
	m.validateAndForward(w, r)
}

func (m *MCPBouncer) publicBase(r *http.Request) string {
	scheme := r.Header.Get("X-Forwarded-Proto")
	if scheme == "" {
		scheme = "https"
	}
	host := r.Header.Get("X-Forwarded-Host")
	if host == "" {
		host = r.Host
	}
	// Derive the path prefix by stripping any oauth suffix.
	_, prefix, ok := MatchOAuthSuffix(r.URL.Path)
	if !ok {
		prefix = r.URL.Path
	}
	// Trim trailing slash from prefix to produce a clean base URL.
	prefix = strings.TrimRight(prefix, "/")
	return scheme + "://" + host + prefix
}

func (m *MCPBouncer) proxyToSidecar(w http.ResponseWriter, r *http.Request) {
	suffix, prefix, _ := MatchOAuthSuffix(r.URL.Path)
	sidecarU := m.sidecarU

	proxy := &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			req.URL.Scheme = sidecarU.Scheme
			req.URL.Host = sidecarU.Host
			// Rewrite path to only the OAuth suffix.
			req.URL.Path = suffix

			scheme := r.Header.Get("X-Forwarded-Proto")
			if scheme == "" {
				scheme = "https"
			}
			host := r.Header.Get("X-Forwarded-Host")
			if host == "" {
				host = r.Host
			}
			publicBase := scheme + "://" + host + prefix

			req.Header.Set("X-MCPB-Resource", m.cfg.Resource)
			req.Header.Set("X-MCPB-Public-Base", publicBase)
			req.Header.Set("X-MCPB-Provider-Issuer", m.cfg.ProviderIssuer)
			req.Header.Set("X-MCPB-Client-ID", m.cfg.ClientID)
			req.Header.Set("X-MCPB-Client-Secret", m.cfg.ClientSecret)
			req.Header.Set("X-MCPB-Scopes", m.cfg.Scopes)
			req.Header.Set("X-MCPB-Audience", m.cfg.Audience)
		},
	}
	proxy.ServeHTTP(w, r)
}

func (m *MCPBouncer) validateAndForward(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	if !strings.HasPrefix(authHeader, "Bearer ") {
		m.unauthorized(w, r)
		return
	}
	token := strings.TrimPrefix(authHeader, "Bearer ")
	if token == "" {
		m.unauthorized(w, r)
		return
	}

	claims, err := ParseAndVerifyJWT(token, func(kid, alg string) (interface{}, error) {
		pk, err := m.cache.Get(kid)
		if err != nil {
			return nil, err
		}
		return pk.key, nil
	})
	if err != nil {
		m.unauthorized(w, r)
		return
	}

	// Validate standard claims.
	publicBase := m.publicBase(r)
	now := time.Now().Unix()
	const skew = int64(60)

	iss, _ := claims["iss"].(string)
	if iss != publicBase {
		m.unauthorized(w, r)
		return
	}

	// aud can be string or []interface{}.
	if !audContains(claims["aud"], m.cfg.Audience) {
		m.unauthorized(w, r)
		return
	}

	exp, ok := claimInt64(claims["exp"])
	if !ok || exp+skew < now {
		m.unauthorized(w, r)
		return
	}

	if nbfRaw, hasNbf := claims["nbf"]; hasNbf {
		nbf, ok := claimInt64(nbfRaw)
		if ok && nbf-skew > now {
			m.unauthorized(w, r)
			return
		}
	}

	// Optional scope enforcement.
	if m.cfg.RequiredScopes != "" {
		scopeClaim, _ := claims["scope"].(string)
		granted := make(map[string]bool)
		for _, s := range strings.Fields(scopeClaim) {
			granted[s] = true
		}
		for _, req := range strings.Fields(m.cfg.RequiredScopes) {
			if !granted[req] {
				m.unauthorized(w, r)
				return
			}
		}
	}

	sub, _ := claims["sub"].(string)
	scope, _ := claims["scope"].(string)
	r.Header.Set("X-Mcp-Sub", sub)
	r.Header.Set("X-Mcp-Scopes", scope)

	m.next.ServeHTTP(w, r)
}

func (m *MCPBouncer) unauthorized(w http.ResponseWriter, r *http.Request) {
	base := m.publicBase(r)
	w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer resource_metadata="%s/.well-known/oauth-protected-resource"`, base))
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	json.NewEncoder(w).Encode(map[string]string{"error": "unauthorized"}) //nolint
}

// audContains checks if the audience claim (string or []interface{}) contains target.
func audContains(aud interface{}, target string) bool {
	if aud == nil {
		return false
	}
	switch v := aud.(type) {
	case string:
		return v == target
	case []interface{}:
		for _, a := range v {
			if s, ok := a.(string); ok && s == target {
				return true
			}
		}
	}
	return false
}

// claimInt64 converts a JSON number claim (float64) to int64.
func claimInt64(v interface{}) (int64, bool) {
	if v == nil {
		return 0, false
	}
	f, ok := v.(float64)
	if !ok {
		return 0, false
	}
	return int64(f), true
}

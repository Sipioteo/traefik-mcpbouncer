package traefik_mcpbouncer

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
	// PathPrefix is the base path under the host used to build publicBase
	// (the JWT iss claim and the URLs in OAuth metadata documents).
	//
	//   ""   — host-only: publicBase = https://<host>           (one MCP per host)
	//   "/x" — subpath:   publicBase = https://<host>/x         (multi-MCP per host)
	//   "*"  — auto:      derive from request path (legacy / default)
	//
	// Set this explicitly for stable resource identity across all request paths.
	PathPrefix string
}

// CreateConfig returns a Config with sensible defaults.
func CreateConfig() *Config {
	return &Config{
		JWKSCacheTTLSeconds: 300,
		PathPrefix:          "*",
	}
}

// MCPBouncer is the Traefik middleware handler.
type MCPBouncer struct {
	next     http.Handler
	cfg      *Config
	cache    *jwksCache
	sidecarU *url.URL
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

	// CORS for browser-based MCP clients (Claude.ai etc).
	// Set headers on every response so the browser can read WWW-Authenticate
	// during discovery and follow the OAuth flow.
	setCORS(w, r)

	// Preflight short-circuit: never gate OPTIONS behind auth.
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	if _, _, ok := MatchOAuthSuffix(r.URL.Path); ok {
		m.proxyToSidecar(w, r)
		return
	}
	m.validateAndForward(w, r)
}

// setCORS reflects the request Origin (permissive default) and lists the
// headers MCP browser clients need to read and send.
// WWW-Authenticate is exposed so the client can follow RFC 9728 discovery.
func setCORS(w http.ResponseWriter, r *http.Request) {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return
	}
	h := w.Header()
	h.Set("Access-Control-Allow-Origin", origin)
	h.Add("Vary", "Origin")
	h.Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS, DELETE")
	h.Set("Access-Control-Allow-Headers", "Authorization, Content-Type, Accept, Mcp-Session-Id, Last-Event-Id, X-Requested-With")
	h.Set("Access-Control-Expose-Headers", "WWW-Authenticate, Mcp-Session-Id")
	h.Set("Access-Control-Max-Age", "600")
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
	// Explicit prefix wins — same publicBase for every request to this resource.
	if m.cfg.PathPrefix != "*" {
		return scheme + "://" + host + strings.TrimRight(m.cfg.PathPrefix, "/")
	}
	// Legacy auto-derive: strip OAuth suffix if present, else use full request path.
	_, prefix, ok := MatchOAuthSuffix(r.URL.Path)
	if !ok {
		prefix = r.URL.Path
	}
	return scheme + "://" + host + strings.TrimRight(prefix, "/")
}

func (m *MCPBouncer) proxyToSidecar(w http.ResponseWriter, r *http.Request) {
	suffix, _, _ := MatchOAuthSuffix(r.URL.Path)
	publicBase := m.publicBase(r)
	sidecarU := m.sidecarU

	proxy := &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			req.URL.Scheme = sidecarU.Scheme
			req.URL.Host = sidecarU.Host
			// Rewrite path to only the OAuth suffix.
			req.URL.Path = suffix

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
	token, ok := extractBearer(r)
	if !ok {
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

	if !m.validateClaims(claims, m.publicBase(r)) {
		m.unauthorized(w, r)
		return
	}

	sub, _ := claims["sub"].(string)
	scope, _ := claims["scope"].(string)
	r.Header.Set("X-Mcp-Sub", sub)
	r.Header.Set("X-Mcp-Scopes", scope)

	m.next.ServeHTTP(w, r)
}

func extractBearer(r *http.Request) (string, bool) {
	authHeader := r.Header.Get("Authorization")
	if !strings.HasPrefix(authHeader, "Bearer ") {
		return "", false
	}
	token := strings.TrimPrefix(authHeader, "Bearer ")
	return token, token != ""
}

// validateClaims checks iss / aud / exp / nbf and optional required scopes.
func (m *MCPBouncer) validateClaims(claims map[string]interface{}, publicBase string) bool {
	now := time.Now().Unix()
	const skew = int64(60)

	if iss, _ := claims["iss"].(string); iss != publicBase {
		return false
	}
	if !audContains(claims["aud"], m.cfg.Audience) {
		return false
	}
	exp, ok := claimInt64(claims["exp"])
	if !ok || exp+skew < now {
		return false
	}
	if nbfRaw, hasNbf := claims["nbf"]; hasNbf {
		if nbf, ok := claimInt64(nbfRaw); ok && nbf-skew > now {
			return false
		}
	}
	return m.hasRequiredScopes(claims)
}

func (m *MCPBouncer) hasRequiredScopes(claims map[string]interface{}) bool {
	if m.cfg.RequiredScopes == "" {
		return true
	}
	scopeClaim, _ := claims["scope"].(string)
	granted := make(map[string]bool)
	for _, s := range strings.Fields(scopeClaim) {
		granted[s] = true
	}
	for _, req := range strings.Fields(m.cfg.RequiredScopes) {
		if !granted[req] {
			return false
		}
	}
	return true
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

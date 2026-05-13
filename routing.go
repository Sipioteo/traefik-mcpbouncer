package traefik_mcpbouncer

import "strings"

var oauthSuffixes = []string{
	"/.well-known/oauth-protected-resource",
	"/.well-known/oauth-authorization-server",
	"/.well-known/openid-configuration",
	"/oauth/authorize",
	"/oauth/token",
	"/oauth/register",
	"/oauth/callback",
	"/oauth/jwks.json",
}

// MatchOAuthSuffix checks if path ends with a known OAuth suffix.
// Returns the matched suffix, the path prefix before it, and true on match.
func MatchOAuthSuffix(path string) (suffix string, prefix string, ok bool) {
	for _, s := range oauthSuffixes {
		if strings.HasSuffix(path, s) {
			p := path[:len(path)-len(s)]
			return s, p, true
		}
	}
	return "", "", false
}

# traefik-mcpbouncer

[![CI](https://github.com/Sipioteo/traefik-mcpbouncer/actions/workflows/ci.yml/badge.svg)](https://github.com/Sipioteo/traefik-mcpbouncer/actions/workflows/ci.yml)
[![CodeQL](https://github.com/Sipioteo/traefik-mcpbouncer/actions/workflows/codeql.yml/badge.svg)](https://github.com/Sipioteo/traefik-mcpbouncer/actions/workflows/codeql.yml)
[![govulncheck](https://github.com/Sipioteo/traefik-mcpbouncer/actions/workflows/govulncheck.yml/badge.svg)](https://github.com/Sipioteo/traefik-mcpbouncer/actions/workflows/govulncheck.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/Sipioteo/traefik-mcpbouncer)](https://goreportcard.com/report/github.com/Sipioteo/traefik-mcpbouncer)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Latest tag](https://img.shields.io/github/v/tag/Sipioteo/traefik-mcpbouncer?sort=semver)](https://github.com/Sipioteo/traefik-mcpbouncer/releases)
[![Traefik plugin](https://img.shields.io/badge/Traefik-plugin-1F2D5C.svg?logo=traefikproxy&logoColor=white)](https://plugins.traefik.io)

Traefik middleware plugin that adds OAuth 2.1 / OIDC authentication to MCP (Model Context Protocol) servers.

The plugin enforces the MCP Authorization spec (rev. 2025-06-18) in front of any MCP server image — including ones with no native auth — by:

- Validating Bearer JWTs locally against a JWKS cache (Ed25519 / RS256).
- Returning `401` with `WWW-Authenticate: Bearer resource_metadata=...` (RFC 9728) on missing or invalid tokens.
- Reverse-proxying OAuth endpoints (`/.well-known/oauth-protected-resource`, `/.well-known/oauth-authorization-server`, `/.well-known/openid-configuration`, `/oauth/authorize`, `/oauth/token`, `/oauth/register`, `/oauth/callback`, `/oauth/jwks.json`) to a companion sidecar.

The plugin is **stateless** and has **zero external dependencies** (stdlib only). All persistent state (DCR clients, signing keys, refresh tokens) lives in the sidecar.

## Configuration

The plugin is configured per-middleware instance via Traefik labels:

```yaml
labels:
  - traefik.enable=true
  - traefik.http.routers.wiki.rule=Host(`mcp.example.com`) && PathPrefix(`/wiki`)
  - traefik.http.routers.wiki.middlewares=mcpb-wiki@docker
  - traefik.http.middlewares.mcpb-wiki.plugin.mcpbouncer.providerIssuer=https://accounts.google.com
  - traefik.http.middlewares.mcpb-wiki.plugin.mcpbouncer.clientID=${GOOGLE_CLIENT_ID}
  - traefik.http.middlewares.mcpb-wiki.plugin.mcpbouncer.clientSecret=${GOOGLE_CLIENT_SECRET}
  - traefik.http.middlewares.mcpb-wiki.plugin.mcpbouncer.resource=wiki
  - traefik.http.middlewares.mcpb-wiki.plugin.mcpbouncer.scopes=openid email profile
  - traefik.http.middlewares.mcpb-wiki.plugin.mcpbouncer.sidecarURL=http://bouncer:8080
```

| Option | Required | Description |
|---|---|---|
| `providerIssuer` | yes | OIDC issuer URL of the upstream IdP (e.g. `https://accounts.google.com`). |
| `clientID` | yes | OAuth client ID registered with the upstream IdP. |
| `clientSecret` | yes | OAuth client secret. |
| `resource` | yes | Logical resource name; becomes the JWT `aud` and namespaces clients in the sidecar. |
| `sidecarURL` | yes | Internal URL of the sidecar (must NOT be exposed externally). |
| `scopes` | no | Space-separated upstream scopes. Default: `openid`. |
| `audience` | no | Override for JWT `aud` claim. Default: same as `resource`. |
| `jwksCacheTTLSeconds` | no | JWKS cache TTL. Default: `300`. |
| `requiredScopes` | no | Space-separated scopes that the JWT must carry to pass through. |

## Sidecar

The plugin needs the MCPBouncer sidecar running on the internal network. See the [full deployment guide](https://github.com/Sipioteo/MCPBouncer) for compose files, Dockerfile, and sidecar configuration.

## Security

- `alg=none` is rejected.
- Only `EdDSA` and `RS256` JWTs are accepted.
- `iss` and `aud` are exact-match checked against the resource's public base URL.
- All incoming `X-MCPB-*` headers are stripped before dispatch to prevent spoofing.

## Source

This repository is a read-only derivative of the [MCPBouncer monorepo](https://github.com/Sipioteo/MCPBouncer). Issues and pull requests should be filed there.

## License

MIT

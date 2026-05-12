# Security Policy

## Reporting

Please **do not** file public issues for security vulnerabilities.

Report privately via GitHub's security advisory mechanism:
<https://github.com/Sipioteo/traefik-mcpbouncer/security/advisories/new>

## Response

Best-effort acknowledgement and triage within **72 hours**.

## Scope

**In scope:** vulnerabilities in the source code of this plugin.

**Out of scope:**
- Vulnerabilities in [Traefik](https://github.com/traefik/traefik) itself — report those to the Traefik project.
- Vulnerabilities in [Yaegi](https://github.com/traefik/yaegi) (the interpreter Traefik uses to run plugins) — report those to the Yaegi project.
- Vulnerabilities in upstream OIDC providers (Google, Keycloak, etc.).
- Vulnerabilities in the MCPBouncer sidecar — file those at [Sipioteo/MCPBouncer](https://github.com/Sipioteo/MCPBouncer/security/advisories/new).

## Note

This plugin is intentionally **stdlib-only**. It has zero external Go dependencies, which means there is no supply-chain attack surface via `go.mod`.

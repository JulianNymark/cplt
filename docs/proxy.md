# Proxy and Domain Filtering

## Proxy

The proxy is **enabled by default** — all outbound traffic (Copilot CLI, `gh`, `curl`) is routed through a localhost CONNECT proxy via `HTTP_PROXY`/`HTTPS_PROXY` and `NODE_USE_ENV_PROXY=1`. The proxy listens on an OS-assigned ephemeral port, so there are no port conflicts.

**What the proxy gives you:**

- **Connection logging** — see every domain Copilot connects to in real time
- **Domain blocking** — block known exfiltration infrastructure (paste sites, webhook services, etc.)
- **Domain allowlisting** — restrict connections to only known-safe domains
- **Audit log** — persistent file log of all connections for post-session review
- **Port enforcement** — the proxy enforces the same port restrictions as the sandbox (443 + `--allow-port`)

**Disable for a single run** (override):

```bash
cplt --no-proxy -- -p "fix the tests"
```

**Disable the proxy:**

```bash
cplt config set proxy.enabled false
```

**Add connection filtering** (recommended):

```bash
cplt config set proxy.blocked_domains "~/.config/cplt/blocked-domains.txt"
# or restrict to known-safe domains only:
cplt config set proxy.allowed_domains "~/.config/cplt/allowed-domains.txt"
# optional audit log:
cplt config set proxy.log_file "~/.config/cplt/proxy.log"
```

<details>
<summary>CLI flags reference (override for a single run)</summary>

| Flag                        | What it does                                                                                     |
| --------------------------- | ------------------------------------------------------------------------------------------------ |
| `--with-proxy`              | Explicitly enable the proxy (no-op when proxy is already on by default).                         |
| `--no-proxy`                | Disable the proxy for this run.                                                                  |
| `--proxy-port <PORT>`       | Which port the proxy listens on (default: 0, OS-assigned ephemeral).                             |
| `--blocked-domains <FILE>`  | Domains to block, one per line. Re-read every ~5s (edit live, changes take effect within seconds). |
| `--allowed-domains <FILE>`  | Domains to allow — only listed domains can connect. Validated at startup (fail-closed); re-read every 5s.  |
| `--proxy-log <FILE>`        | Append a line per connection to this file for post-session audit.                                |
| `--proxy-log-level <LEVEL>` | Stderr verbosity: `none` (default/silent), `error`, `blocked`, or `all`. The audit log file always records everything. |
| `--allow-private-domain <DOMAIN>` | Allow connections to this domain even if it resolves to a private/internal IP. Use for corporate intranet services (e.g. internal MCP servers). Suffix matching: `intern.nav.no` covers all subdomains. Can be repeated. |

</details>

> **Domain matching:** both blocklist and allowlist use the same rules — `example.com` matches the exact domain and all subdomains (`sub.example.com`, `deep.sub.example.com`). Matching is case-insensitive. Trailing dots are stripped.
>
> **Localhost traffic** (MCP servers, dev servers) bypasses the proxy via `NO_PROXY` and will not appear in the audit log.
>
> **Quiet mode** (`-q` / `sandbox.quiet = true`) suppresses the startup banner. Proxy stderr output is controlled separately by `--proxy-log-level` (default: `none` — silent). Use `--proxy-log` to capture all connections to a file.

## Domain filtering

When the proxy is enabled, it supports both **blocking** (deny known-bad domains) and **allowlisting** (permit only known-good domains).

### Blocklist

Block domains commonly used for data exfiltration. A default blocklist is included based on real attack infrastructure observed in 2025–2026 supply chain incidents:

```bash
cplt config set proxy.blocked_domains "~/.config/cplt/blocked-domains.txt"
```

The blocklist covers webhook capture services, paste sites, file sharing, tunneling services, and IP recon endpoints. See [`blocked-domains.txt`](../blocked-domains.txt) for the full list with sources.

### Allowlist

Restrict connections to only specific domains. When set, the proxy blocks everything not in the list:

```bash
cplt config set proxy.allowed_domains "~/.config/cplt/allowed-domains.txt"
```

Example `allowed-domains.txt` for Copilot-only access:

```
api.github.com
api.githubcopilot.com
api.business.githubcopilot.com
proxy.business.githubcopilot.com
telemetry.business.githubcopilot.com
```

Both blocklist and allowlist can be used together — allowlist is checked first, then blocklist.

Set either permanently:

```bash
cplt config set proxy.blocked_domains "~/.config/cplt/blocked-domains.txt"
cplt config set proxy.allowed_domains "~/.config/cplt/allowed-domains.txt"
```

> **Note:** Both the allowlist and blocklist are re-read from disk every ~5 seconds (TTL-cached), so you can edit them live mid-session. Changes take effect within seconds without restarting cplt. If a file becomes unreadable at runtime, the last-known-good list is kept (fail-safe). At startup, an unreadable allowlist causes cplt to exit with an error (fail-closed).
>
> The `allow_private_domains` list in `config.toml` is also re-read every ~5 seconds. Domains added via `--allow-private-domain` CLI flags are always preserved regardless of config changes.

## Proxy operations

### Connection log

Every connection attempt is printed to stderr in real time:

```
[proxy] 14:23:01 CONNECT api.githubcopilot.com:443 → CONNECTED
[proxy] 14:23:04 CONNECT pastebin.com:443 → BLOCKED
[proxy] 14:23:07 CONNECT mcp-onboarding.intern.nav.no:443 → BLOCKED-PRIVATE-RESOLVED
```

To write a persistent audit log:

```bash
cplt config set proxy.log_file "~/.config/cplt/proxy.log"
```

Log file format (one line per connection):

```
2025-01-15T14:23:01Z CONNECT api.githubcopilot.com:443 CONNECTED
2025-01-15T14:23:04Z CONNECT pastebin.com:443 BLOCKED
```

### Status codes

| Status | Meaning | Action |
|---|---|---|
| `CONNECTED` | Connection succeeded | — |
| `BLOCKED` | Domain matched blocklist | Check `--blocked-domains` file |
| `BLOCKED-ALLOWLIST` | Domain not in allowlist | Add domain to `--allowed-domains` file |
| `BLOCKED-PORT` | Port not in allowed list | Add with `--allow-port <PORT>` |
| `BLOCKED-PRIVATE` | Pre-DNS private IP (`.local`, `127.*`, IP literals) | Use `--allow-localhost` for local ports |
| `BLOCKED-PRIVATE-RESOLVED` | DNS resolved to a private IP | Use `--allow-private-domain <DOMAIN>` |
| `DNS-FAIL` | DNS resolution failed | Check domain spelling or network |
| `CONNECT-FAIL:...` | TCP connection to target failed | Target may be down |
| `UNSUPPORTED` | Non-CONNECT HTTP method | Only CONNECT tunnels are supported |
| `LIMIT` | 64 concurrent connections reached | Reduce parallelism |

### Troubleshooting

**Tool blocked with `BLOCKED-PRIVATE-RESOLVED`** — a domain (typically corporate intranet) resolved to a private IP:

```bash
cplt config set proxy.allow_private_domains intern.nav.no
```

Or for a single run: `cplt --allow-private-domain intern.nav.no`

**MCP server on localhost blocked** — use `allow.localhost` (not `allow_private_domains`):

```bash
cplt config set allow.localhost 3000
```

**Tool needs a non-443 port** — add it explicitly:

```bash
cplt config set allow.ports 8443
```

**Nothing connects — check if proxy is running:**

```bash
cplt --print-profile | grep localhost   # shows the proxy port rule in the Seatbelt profile
```

**Disable the proxy entirely for debugging:**

```bash
cplt --no-proxy -- -p "fix tests"
```

### Corporate proxy environments

cplt injects its own `HTTP_PROXY`/`HTTPS_PROXY` into the sandbox environment, replacing any corporate proxy you may have set. The sandbox environment is cleared by default (sensitive env vars stripped), so your external `HTTP_PROXY` does not flow in.

If you need to chain through a corporate proxy instead of using cplt's built-in proxy:

```bash
cplt config set proxy.enabled false
cplt config set sandbox.pass_env HTTP_PROXY
cplt config set sandbox.pass_env HTTPS_PROXY
```

> **Note:** Disabling the proxy removes cplt's built-in domain filtering, connection logging, and port enforcement. The `blocked_domains` and `allowed_domains` settings are features of the built-in proxy — they have no effect when the proxy is disabled. If your corporate proxy has its own domain filtering, rely on that instead. The sandbox still enforces filesystem and process isolation regardless of proxy settings.

## Copilot CLI network endpoints

Copilot CLI 1.0.21 connects directly to these endpoints (empirically verified):

| Endpoint                           | Purpose                                  |
| ---------------------------------- | ---------------------------------------- |
| `api.github.com`                   | GitHub API (user info, token validation) |
| `api.githubcopilot.com`            | Copilot API                              |
| `api.business.githubcopilot.com`   | Copilot Business API (enterprise users)  |
| `proxy.business.githubcopilot.com` | Copilot Business proxy                   |

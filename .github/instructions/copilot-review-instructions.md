# Copilot Code Review Instructions

This is a security-critical sandbox tool. Every change is reviewed through
the lens of "can an untrusted AI agent exploit this?"

## Security-first review

### Deny-by-default principle

cplt uses `(deny default)` + specific allows. Any PR that adds an `(allow ...)`
rule must justify **why** the permission is needed and document the attack surface
it opens. Review questions:

- Does this weaken an existing deny rule? If yes, is the trade-off documented?
- Is the new allow scoped as narrowly as possible (subpath, regex anchor, exact match)?
- Could a rogue agent inside the sandbox abuse this permission?
- Is the rule gated behind an explicit opt-in flag or config key?

### SBPL profile rules (`sandbox_profile.rs`)

When reviewing changes to the Seatbelt profile:

- **Regex anchoring**: All SBPL regex patterns must use `^` and `$` anchors.
  Unanchored patterns like `(regex #"foo")` match substrings — always anchor.
- **Path separators in regex**: Prefer `[^/]+` over `.+` for individual path
  segments. `.+` matches `/` and can span directory boundaries.
- **Dot escaping**: In SBPL regex, `.` matches any character. Literal dots in
  paths/bundle IDs must be escaped as `\.`.
- **String matching for config gates**: Use exact match (`==`) or
  first-component prefix (`starts_with("foo/")`) — never substring
  (`contains("foo")`). Substring matching allows privilege escalation via
  crafted directory names (e.g., `evil-foo-hook/`).
- **Unscoped rules**: `(allow syscall*)`, `(allow iokit-open-user-client)`,
  and similar broad rules require a security rationale comment explaining why
  scoping is not feasible. These must be gated behind explicit opt-in config.

### Environment variable handling

- New env vars must be added to `ENV_ALLOWLIST` with a comment explaining why.
- Sensitive env vars (`*_TOKEN`, `*_KEY`, `*_SECRET`, `*_PASSWORD`, `DATABASE_URL`)
  must never be in the allowlist.
- `HARDENING_ENV_VARS` entries are injected to harden the sandbox — additions
  welcome, removals require justification.

### Path handling

- User-supplied paths (from config, CLI args) must be validated before use.
- Check for path traversal (`..`), null bytes, and SBPL injection characters
  (`\n`, `"`, `)`) — see `validate` in `sandbox.rs`.
- Canonical paths: macOS `/var/folders/` → `/private/var/folders/` (symlink).
  Use `canonicalize()` + `strip_prefix()` on canonical paths, not raw inputs.

### Network and proxy rules

- New `network-outbound` or `network-bind` rules must document which process
  needs them and what protocol is used.
- Unix socket rules must be regex-anchored to specific path patterns — never
  allow blanket unix socket access.
- Domain blocklist changes (`blocked-domains.txt`) require reviewing the
  domain's purpose. Do not remove domains without security justification.

### Config and trust model

- New config keys that weaken the sandbox must go through the trust approval
  flow (`cplt trust accept`). Check that `TRUST_PERMISSIONS` in `config.rs`
  includes the new key.
- Config precedence: CLI flag > config file > default. Secure defaults only.
- `allow_cache_exec_any` is a broad permission — features should prefer
  specific `allow_cache_exec` entries over `allow_cache_exec_any`.

## Code quality

### Rust conventions

- `&str`/`&[T]` over owned types in function signatures.
- Clippy must pass clean (warnings are errors in CI).
- Security-critical code must have doc comments explaining the *why*.
- Only comment code that needs clarification — but sandbox rules always
  need comments.

### Testing

Every sandbox rule change needs tests at the appropriate tier:

| Change type | Required test tier |
|---|---|
| New/changed SBPL rule | Unit test (profile string assertion) |
| New config option | Unit test for merge logic |
| Env var filtering | Unit test in `unit_tests.rs` |
| Kernel enforcement | Integration test (`integration.rs` / `integration_linux.rs`) |
| Full CLI pipeline | E2E test (`e2e.rs`) |
| Real-world workflow | E2E project test (`e2e_projects.rs`) |

Negative tests are as important as positive tests:

- Test that rules are **absent** when the feature is not opted in.
- Test **near-miss** inputs that should NOT activate a feature
  (e.g., `"ms-playwright-evil"` should NOT match `"ms-playwright"`).
- Test that `allow_cache_exec_any` does not activate feature-specific rules.

### Documentation

- Changes to sandbox rules, env handling, or network policy must update
  `SECURITY.md` if they alter the threat model or defense layers.
- New config keys must be documented in `README.md`.
- PR descriptions for security-relevant changes must include a
  "Security considerations" section.

## Platform parity

- `HOME_TOOL_DIRS` is a single unified list for both macOS and Linux.
  Do not create platform-specific duplicates.
- macOS-only SBPL rules (Seatbelt) do not need Linux equivalents, but
  consider whether Linux (Landlock + seccomp) needs corresponding changes.
- `#[cfg(target_os = "macos")]` gates: verify the guarded code is not
  used in cross-platform paths (common source of CI failures on Linux).

## File parsing and input handling

- File parsers (workspace files, config files) must bound reads with a
  max file size to prevent DoS from huge files.
- YAML/TOML/JSON parsers should handle comments, trailing whitespace,
  and edge cases (empty arrays, missing keys) gracefully.
- Glob pattern expansion from workspace files must validate that expanded
  paths stay within the project root (no directory traversal).

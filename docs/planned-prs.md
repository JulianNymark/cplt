# Planned PRs — sandbox UX + credential-surface hardening

Working doc. Hands off to other models (Sonnet-class). Each PR is independent
enough to implement alone, but the order below is intentional.

Repo: navikt/cplt (Rust, macOS Seatbelt + Linux Landlock/bwrap sandbox wrapper
for AI coding agents). Read `AGENTS.md` in repo root first. Always run
`mise run check` before finishing (fmt + clippy + unit + lib tests; safe
inside the cplt sandbox itself).

## Conventions for every PR

- PR body opens with a **2–4 sentence plain-human explainer** (what problem,
  what changes for the user, why it's safe). No jargon wall.
- Below the explainer, a **"Code proof"** section linking the key hunks:
  file + line refs a reviewer can click to verify each claim in the explainer.
- No AI attribution in commits (`Co-authored-by` etc. are banned). Clean
  subject line, repo style.
- Security-tool repo: any change to deny rules / env handling / network needs
  a one-line security rationale in the commit or code comment, and must not
  weaken existing denies without discussion. Update `SECURITY.md` if the
  threat model / defense layers change.
- Unit test for policy-string changes; integration test (macOS sandbox-exec)
  when kernel enforcement behavior changes. See AGENTS.md test-strategy table.

## Sandbox gotchas for the implementer (read before running anything)

- You are probably running **inside** cplt already. `mise run check` works;
  `mise run test:all` also works (macOS); `test:everything` does NOT (needs
  network + real Copilot auth).
- `git commit` locally is fine; **push/pull fails** (SSH blocked) — tell the
  user to push. `gh` remote ops fail too — use `peekrun` to delegate gh calls
  to the user when creating PRs.
- Never read `.env*` files or credential paths; they are EPERM on purpose.

---

## PR 0 — Agent sandbox brief (do first)

**Problem.** The agent inside the sandbox doesn't know it's sandboxed. It hits
EPERM, retries, burns tokens, fails confusingly. cplt injects zero context
into the agent today (verified: no AGENTS.md/CLAUDE.md/system-prompt plumbing
in `src/agent.rs` / `src/main.rs`).

**Change.** Generate a short brief from the *resolved* policy at launch, write
it to a stable readable path, point the agent at it, and add friendly wrapper
binaries for the most common dead-end commands.

**Mechanics.**

1. New `src/brief.rs`: `generate_brief(resolved: &config::Resolved, agent: Agent) -> String`.
   Render from the live config, not a static template — if the user allowed
   `~/.aws`, the brief must not claim AWS is blocked. Content sketch (modeled
   on the user's own AGENTS.md section):
   - "You are sandboxed by cplt." + config path is read-only.
   - SSH blocked → remote git ops fail; ask user to push/pull.
   - Credential paths unreadable (EPERM) → don't retry; tell user.
   - Network: HTTPS-only via proxy / fail-closed if enabled.
   - "EPERM = sandbox deny. Do not retry or search workarounds. Report to user:
     `cplt trust` / `allow.read`/`allow.write` in config.toml."
2. Write to `<scratch_dir>/CPLT_BRIEF.md` every launch (scratch is always
   readable+writable; avoids polluting project dir; avoids the symlink
   canonicalization trap from issue #171).
3. **Two-layer context injection** (user direction):
   - **Layer 1 (session):** the scratch brief above — accurate, per-session,
     generated from resolved policy.
   - **Layer 2 (persistent, project or global):** an idempotent managed block
     in an AGENTS.md the agent reads, written BEFORE the agent process starts
     (cplt setup is unsandboxed; `sandbox_exec::exec` at
     `src/sandbox_exec.rs:505` is the last step — ordering is free).
   - Target: **project-root `AGENTS.md` only** — create it if absent (it's
     the conventional agent file). Do NOT touch global/system-level agent
     configs: they're personal, and project files are where the guidance
     belongs anyway — committed to the repo, the guidance reaches every
     agent-user who clones it (virality by design).
   - Per-agent note: agents that read a different conventional project file
     (Claude → `CLAUDE.md`, Gemini → `GEMINI.md`) still read AGENTS.md in
     most modern versions — verify per agent; only if an agent truly ignores
     AGENTS.md, additionally write the same block to its conventional file.
     Keep the single-file default otherwise.
   - Block format: delimited by `<!-- cplt:sandbox begin -->` /
     `<!-- cplt:sandbox end -->`. Insert if absent, replace-in-place if
     present, never duplicate. If the file already has a hand-written
     `## Sandbox` section, DON'T stomp it — append a one-line pointer beneath
     instead. If insertion is ambiguous, skip + warn; never mangle.
   - Block content is **sandbox-agnostic** (viral-by-design, user direction):
     a short "agents in this repo are encouraged to run sandboxed (e.g.
     cplt)" note; a self-check ("if `$__CPLT_WRAPPED` or an equivalent marker
     is unset, you are NOT sandboxed — tell the user and proceed
     conservatively: no credential reads, no remote-mutating git without
     approval"); and the sandboxed-agent rules (EPERM = deny, don't retry,
     report to user with `cplt trust` / allow.* hints). Polite nudge, one
     short paragraph — no spam. Other sandboxes benefit equally; cplt is the
     named example.
   - The block is written to the repo before launch and left for the user to
     commit — the git diff IS the audit trail, no hidden writes.
4. Wrapper binaries in scratch `bin/` (already prepended to PATH by
   `install_command_wrappers` in `src/sandbox_exec.rs`): at minimum `ssh`
   printing "SSH blocked by cplt sandbox — ask the user to run this". Same
   pattern as the existing gh/git gate wrappers.
5. Add `(with message "cplt: <reason>")` to SBPL deny rules where the emitter
   already knows the reason (e.g. credential paths). Invisible to the agent —
   it lands in `log show` — but makes future `cplt check` (upstream #142)
   output self-explaining.
6. Opt-outs: `--no-brief` flag + `sandbox.brief = false` config key.

**Tests.** Brief text flips when config flips (`allow_env_files = true` → no
`.env` warning; proxy off → no proxy line). Managed-block: insert into absent
file, insert into existing file, idempotent re-run (no dup), replace stale
block, hand-written `## Sandbox` preserved + pointer appended, ambiguous file
→ skipped with warning. Project-file-only rule: no writes to global/system
agent configs. Block present on disk
before agent spawn (ordering test via a shim agent that asserts the file).

**Code proof links for PR body:** `src/brief.rs` (new), injection call site in
`src/main.rs`, agent mapping in `src/agent.rs`, wrapper install in
`src/sandbox_exec.rs`, tests.

**Upstream relation:** implements design issue #148 (agent-facing sandbox
policy exposure). Reference it.

---

## PR A — expand credential deny lists

**Problem.** `DENIED_DOTFILES` / `DENIED_FILES` / `DENIED_HOME_SUBPATHS` cover
ssh/aws/gcloud/etc. but miss many 2026-common plaintext-token locations.
Verified missing (all plaintext credentials at rest):

Files: `.git-credentials` (plaintext `https://user:token@github.com` —
sharpest gap), `.config/git/credentials`, `.pgpass`, `.my.cnf`,
`.bunfig.toml`, `.condarc`.
Dirs: `.fly`, `.wrangler`, `.supabase`, `.vercel`, `.netlify`, `.heroku`,
`.firebase`, `.config/firebase`, `.doppler`, `.render`, `.sentry`,
`.sentryclirc`, `.config/configstore` (firebase-tools etc.), `.config/gh`
(NO — handled by PR B, don't touch here), `.config/github-copilot` (VS Code
Copilot OAuth token!), `.config/netlify`, `.config/doctl`, `.config/heroku`,
`.config/stripe`, `.config/rclone`, `.config/infisical`, `.config/atlas`,
`.codex`, `.huggingface` + `.cache/huggingface/token`, `.snyk`, `.circleci`,
`.buildkite`, `.1password`,
`Library/Application Support/com.vercel.cli` (macOS Vercel auth.json).

**Change.** Add entries to the consts in `src/sandbox_policy.rs` with a
one-line comment per entry (what token it holds). No new code paths — the
emitters pick them up.

**Tests.** Unit tests asserting each new entry appears in generated SBPL
profile and Landlock policy (follow existing test patterns in
`tests/unit_tests.rs` and the lib tests in `sandbox_landlock.rs`).

**Docs.** Update the deny-list tables in `README.md` / `SECURITY.md` to stay
in sync (they enumerate the list today).

**Fold in while touching the same file (small, separable commits):**

- **A-fix — `.npmrc` doc bug.** Code has `.npmrc` in `DENIED_HOME_SUBPATHS`
  (overridable via `--allow-read`), but `docs/known-impacts.md:400,418` and
  `README.md:1293,1311` claim "hard deny — not overridable". Docs are wrong
  (placement is deliberate per inline comment in `sandbox_policy.rs:47-49`).
  Fix docs to say overridable. Don't move the entry.
- **A-flip — `.deno` / `.bun` write+exec.** `sandbox_policy.rs:859-870` gives
  both `write: true` + `process_exec: true`. `.cargo/bin` (same file,
  ~line 817) is deliberately `write: false` with a comment about
  trojan-persistence. Same risk applies to global deno/bun installs. Flip to
  `write: false` with matching comment. Behavior change: `deno install -g` /
  `bun add -g` inside sandbox will fail — acceptable, note in PR body.

---

## PR D — verbosity tiers + doctor severity (subjective UX)

**Problem.** Default startup prints a ~40-line config dump; `--quiet` still
prints warnings + prompt. Doctor reports "Critical issues found" when the only
"critical" is `~/.copilot` missing — irrelevant for a non-Copilot user.
Sensitive-to-info-density users (the requester self-identifies) get
overwhelmed; note in the PR body that the redesign is explicitly subjective
and tiered so nobody loses the current full output.

**Change.**

1. Three tiers: `--quiet` (near-silent, only blockers), **default = new
   compact summary**, `--verbose` = current full dump.
2. Compact summary design: few lines, high signal, emoji severity markers
   (🔴 broad/risky grant like home-dir write or keychain allowed; 🟡 notable
   non-default; 🟢 secure defaults). Collapse redundancy: child allow inside
   parent allow → show parent only (exception: keep both when a deny sits
   between them — e.g. allow `/a`, deny `/a/secret`, allow `/a/secret/ok` is
   meaningful). Suggested compact lines: Filesystem, Network, Keychain,
   Env-stripping, Guards (gh/git), Proxy.
3. Warnings under `--quiet`: keep only actionable ones. The OpenCode
   "No API keys passed / use ANTHROPIC_API_KEY" warning fires even when the
   user authenticates via OpenCode's stored Copilot auth — downgrade/suppress
   when `~/.local/share/opencode/auth.json` (or legacy config auth.json)
   exists. That file check replaces the naive env-var-only heuristic.
4. `doctor`: missing agent CLIs (e.g. `~/.copilot` when running
   `--agent opencode`) → informational, not "Critical". "Critical" reserved
   for "sandbox will not function".
5. `doctor` audit pass: warn about credential paths that EXIST on disk but are
   NOT in any deny list ("Undenied credential path detected: ~/.pgpass —
   fix: `cplt config set deny.paths ...`"). This is the discovery half of
   PR A; `is_credential_path` in `src/check.rs:133` already exists as the
   matching helper.

**Tests.** Tier selection logic; redundancy-collapse function (unit-test
allow/deny/allow chains); auth-warning suppression when auth.json exists.

---

## PR B — make `~/.config/gh` reads opt-in

**Problem.** cplt unconditionally grants EVERY agent read access to
`~/.config/gh/hosts.yml` + `config.yml`:
- macOS: `src/sandbox_profile.rs:369-380` ("Allow for all agents" comment)
- Linux: `src/sandbox_landlock.rs:231-232` (`LINUX_HOME_CONFIG_FILES`)

Rationale in code: Copilot spawns `gh auth token`. But on machines where gh
fell back to plaintext storage (common on Linux/WSL/no-keyring), `hosts.yml`
contains the OAuth token — every sandboxed agent can read it. Meanwhile
`main.rs:3186` uses that very file as the demo "protected credential" in
`pick_protected_read` — self-contradiction.

gh is a nice-to-have, not an essential cplt dependency: the only coupling is
the optional gh-guard feature, which runs `gh auth token` OUTSIDE the sandbox
(`inject_gh_token_if_needed`, `src/sandbox_exec.rs:179`). The agent never
needs the raw files unless the user wants it running `gh` itself. gh is
single-user full-permission tooling; command-level control is gh-gate's job,
raw config reads are a separate axis the user should choose.

**Change.** New config key + flag (name e.g. `gh.allow_config_read`, default
**false**). When off: omit both allow rules in both emitters. When on:
current behavior. Keep the gh-gate cached-token flow working — it reads the
token outside the sandbox and serves it from the scratch file, unaffected.

Also document the existing escape hatch both ways: today a user can already
revoke with `deny.paths = ["~/.config/gh"]` (user denies emit after the
allow, last-match-wins) — undocumented; add to docs/configuration.md.

**Tests.** Profile with flag on/off contains/omits the two literals
(both emitters). gh-guard token cache flow unaffected (existing tests pass).
Update the summary print in `config/loading.rs:800` to show blocked/allowed.

---

## PR E — close the metadata/existence oracle (hardening; defer)

**Problem.** Contents of denied paths are blocked, but `file-read-metadata`
is not denied → `ls -d ~/.fly` / `stat ~/.ssh` succeed (existence, mode,
mtime leak), and EPERM-vs-ENOENT is an existence oracle for arbitrary paths
under `$HOME`. Verified live: `ls ~` = EPERM, but `ls -d ~/.ssh` prints the
path, `stat ~/.ssh` returns full metadata.

User decision: **harden maximally** — a path should be invisible (no name, no
metadata) unless the user expressly granted read on it or an ancestor.
"If I didn't give permission, the agent shouldn't even see it's there."

**Change (careful, staged).**

1. Add `file-read-metadata` deny to the SBPL emissions for `DENIED_DOTFILES`
   + `DENIED_FILES` (and home-subpaths where feasible). Landlock: verify
   whether its deny already covers metadata (it gates FS access broadly;
   check + test).
2. Broader `$HOME` metadata deny (true "invisible unless allowed") is the
   end goal but high breakage risk: tools probe `~/.gitconfig`,
   `~/.tool-versions` at startup and some abort on EPERM where ENOENT was
   expected (precedent: git aborting on unreadable /etc/gitconfig, worked
   around with `GIT_CONFIG_NOSYSTEM` — see comment in HARDENING_ENV_VARS).
   Stage it: implement (1) first, gate (2) behind a config flag
   (`sandbox.hide_home_metadata = true`?), test mise/git/node/deno/bun.
3. Whatever remains observable gets **documented as a specified limitation**
   in SECURITY.md ("existence of arbitrary paths may be observable; contents
   are not") — specified leak beats unspecified leak.

**Tests.** Integration tests (macOS): `stat ~/.ssh` inside sandbox → EPERM
with (1) on; `ls ~` behavior unchanged. Unit tests for profile strings.

---

## PR C — OS credential stores (LAST, only after explicit user go-ahead)

**Problem.** Filesystem denies don't cover daemon-held secrets — both major
OSes serve credentials over IPC, and cplt leaves the IPC channel open:

- **macOS Keychain**: `securityd` serves secrets over Mach IPC. Profile does
  `(allow mach-lookup)` blanket (`src/sandbox_profile.rs:416`) because Node
  needs service lookups. The `needs_keychain()` gate at line 392 only guards
  `~/Library/Keychains` *files* — the wrong channel. Result: EVERY agent
  (OpenCode/Pi/Shell included) can run
  `security find-generic-password -s "gh:github.com"` and read the gh token,
  even though gh-gate blocks `gh auth token`. The user's original report.
- **Linux Secret Service**: gnome-keyring/KWallet/KeePassXC serve
  `org.freedesktop.secrets` over the D-Bus session bus
  (`$XDG_RUNTIME_DIR/bus`). Landlock can't filter unix-socket connects;
  bubblewrap deliberately shares the session (no D-Bus filtering). Any
  sandboxed process can `secret-tool lookup`.
- Also: `~/.1password/agent.sock` (1Password desktop agent socket) — separate
  channel from the already-denied `~/.config/op`.

**Change (split into per-platform commits).**

1. macOS: emit `(deny mach-lookup (global-name-regex #"^com\.apple\.security"))`
   (exact service name set TBD by empirical testing — see below) for agents
   with `needs_keychain() == false`. Mirrors the existing pasteboard carve-out
   at `sandbox_profile.rs:417-425`. Add `--deny-keychain` flag to force off
   even for Copilot-class agents. **Must verify empirically**: Node.js TLS /
   DNS / `gh` behavior without Security-framework Mach services — `trustd`
   (certificate trust) is a separate service and should keep working; test
   `node -e "fetch('https://github.com')"`, `gh api /zen`, dns lookups.
2. Linux: strip `DBUS_SESSION_BUS_ADDRESS` from the child env + Landlock-deny
   `$XDG_RUNTIME_DIR/bus` read/write. Verify gh/keyring-dependent tools fail
   closed with a comprehensible error (and that nothing in the standard dev
   toolchain requires D-Bus — git/node/cargo shouldn't).
3. Deny `~/.1password/agent.sock` (FS path, both emitters).
4. Coordinate with open upstream PR #173 ("skip Keychain rules when GitHub
   token env var is set") — it adds `allow_keychain` plumbing through
   `SandboxConfig`/`ProfileOptions`; build on it rather than conflict.
   Note: #173's reviewers flagged that its gating would wrongly disable
   keychain for Gemini/Claude when GH_TOKEN is set — our agent-scoped deny
   must not repeat that mistake.

**Tests.** Integration: `security find-generic-password` fails for
non-keychain agents, succeeds for Copilot default. Linux: `secret-tool`
unreachable. Doctor line reports keychain stance per agent.

**Docs.** SECURITY.md threat-model update: "daemon-held credentials" as a
defense layer with per-platform mechanism.

---

## Status tracker

| PR | State | Branch | Notes |
|----|-------|--------|-------|
| 0 brief | planned | — | start here |
| A deny-lists (+npmrc docs, deno/bun flip) | planned | — | |
| D verbosity/doctor | planned | — | subjective; tiered |
| B gh opt-in | planned | — | |
| E metadata oracle | planned | — | deferred, stage 1 first |
| C credential stores | blocked | — | needs explicit go-ahead + runtime verification |



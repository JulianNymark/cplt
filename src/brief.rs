//! Agent-facing sandbox brief.
//!
//! An agent running inside cplt today gets zero context: it hits EPERM,
//! retries, searches for workarounds, and burns tokens before giving up
//! confusingly. This module renders two things from the *resolved* policy
//! (never a static template, so the brief never claims something is
//! blocked/allowed that isn't):
//!
//! 1. A per-session brief written to the scratch directory
//!    (`CPLT_BRIEF.md`) — accurate for exactly this launch.
//! 2. A short, sandbox-agnostic managed block inserted into the
//!    project-root `AGENTS.md` (created if absent) — opt-in via
//!    `--agents-md` / `sandbox.agents_md`, persistent, and left for the user
//!    to review and commit. Delimited by stable markers so it can be inserted, updated in
//!    place, or safely skipped without ever duplicating or mangling
//!    hand-written content.
//!
//! Implements design issue #148 (agent-facing sandbox policy exposure).
//!
//! EXPERIMENTAL: both layers are off by default and unstable. Nothing else in
//! cplt reads what they emit, so the wording and the AGENTS.md markers may
//! change, or the feature may be removed.

use std::path::Path;

use crate::agent::Agent;
use crate::config::Resolved;

/// Begin marker for the managed AGENTS.md block. Never change this string
/// without also handling migration of the old marker (breaks idempotency
/// for anyone who already has the old block committed).
pub const BLOCK_BEGIN: &str = "<!-- cplt:sandbox begin -->";
/// End marker for the managed AGENTS.md block.
pub const BLOCK_END: &str = "<!-- cplt:sandbox end -->";

/// Generate the per-session brief written to the scratch dir.
///
/// Rendered from the live resolved config: if the user allowed `~/.aws`,
/// this must not claim AWS is blocked. Kept short — a few lines, not a
/// policy dump (`--verbose` / `cplt config show` cover that).
pub fn generate_session_brief(resolved: &Resolved, agent: Agent, home: &Path) -> String {
    use std::fmt::Write as _;

    let mut out = String::new();
    out.push_str("# cplt sandbox brief\n\n");
    let _ = write!(
        out,
        "You ({}) are running inside a cplt sandbox. This file is generated \
         fresh every launch from the resolved policy — trust it over guesses.\n\n",
        agent.display_name()
    );

    out.push_str("## Rules\n\n");
    out.push_str(
        "- `EPERM` / `Operation not permitted` = a deliberate sandbox deny, \
         not a transient error. Do NOT retry the same call, search for a \
         workaround, or try `sudo`. Report it to the user with the exact \
         command and path, and suggest the config key below.\n",
    );
    out.push_str(
        "- The cplt config (`~/.config/cplt/config.toml`) is not readable from \
         in here, let alone writable — `~/.config/cplt` has no allow rule, so \
         it falls under the profile's default deny. Only the user can change \
         the policy, from outside the sandbox, and it takes a re-run.\n",
    );

    out.push_str("\n## Network\n\n");
    if resolved.allow_all_domains {
        out.push_str(
            "- No domain allowlist this session (`--allow-all-domains`): any \
             domain is reachable except the ones on the blocklist.\n",
        );
    } else if resolved.default_allowlist {
        out.push_str(
            "- Only the agent's built-in allowlist (plus any configured \
             `allowed_domains`) is reachable. The proxy refuses everything \
             else.\n",
        );
    } else if resolved.with_proxy {
        out.push_str(
            "- HTTPS goes through a filtering CONNECT proxy, which refuses \
             blocked domains.\n",
        );
    } else {
        out.push_str("- No proxy is active for this session.\n");
    }
    if resolved.with_proxy {
        if resolved.proxy_forced {
            out.push_str(
                "- This fails closed: `proxy_forced` is on, so direct egress \
                 is blocked by the kernel and there is no route around the \
                 proxy.\n",
            );
        } else {
            out.push_str(
                "- Only the proxy enforces that. `proxy_forced` is off this \
                 session, so direct `*:443` connections are still permitted \
                 at the kernel level: a client that ignores `HTTPS_PROXY` is \
                 not stopped. Don't treat that as an invitation — the list is \
                 the policy — but don't report a blocked domain as \
                 kernel-enforced either.\n",
            );
        }
    }
    if !ssh_port_open(resolved) {
        out.push_str(
            "- SSH is blocked, and the blocker is the port, not the keys: \
             outbound TCP is limited to 443, so port 22 is refused however \
             `~/.ssh` is configured. `ssh`/`scp` and git over `ssh://` or \
             `git@host:...` remotes fail. Git over HTTPS still works — ask \
             the user to run the SSH-only parts outside the sandbox.\n",
        );
        if cfg!(target_os = "linux") {
            out.push_str(
                "- That port limit is a Landlock rule, and Landlock only \
                 restricts outbound connect from ABI v4 (kernel 6.7). cplt \
                 applies its ruleset best-effort, so on an older kernel the \
                 restriction is silently absent and the proxy is the only \
                 network control. Treat port 22 as blocked either way — the \
                 user configured it that way — but if a connection \
                 unexpectedly succeeds, that is why.\n",
            );
        }
    } else if !ssh_key_readable(&resolved.allow_read, home) && !ssh_agent_reaches(resolved) {
        out.push_str(
            "- SSH is blocked, and the blocker is the keys, not the port: \
             port 22 is open (`allow.ports`), but no key under `~/.ssh` is \
             readable and no agent socket reaches the sandbox, so `ssh` has \
             nothing to authenticate with. Ask the user for an `allow.read` \
             of the specific key file, or to run the SSH-only parts outside \
             the sandbox.\n",
        );
    } else {
        out.push_str(
            "- SSH may work this session: port 22 is open (`allow.ports`) and \
             the user allowed reading a key under `~/.ssh` and/or passed \
             `SSH_AUTH_SOCK` through. If `ssh`/`scp` or a `ssh://` remote \
             still fails, report the exact error rather than assuming the \
             sandbox blocked it.\n",
        );
    }
    if resolved.git_guard.enabled && resolved.git_guard.prevent_push {
        out.push_str(
            "- `git push` is additionally gated by cplt's git guard this \
             session, HTTPS remotes included.\n",
        );
    }

    out.push_str("\n## Credentials\n\n");
    out.push_str(
        "- Credential directories (`~/.ssh`, `~/.aws`, `~/.gnupg`, `~/.kube`, \
         and similar) are unreadable by design (EPERM). Don't retry; tell the \
         user.\n",
    );
    // `allow.read` of a path inside one of those directories is a supported
    // configuration — the backends re-allow it after the blanket deny — so the
    // blanket claim above needs its exceptions spelled out, or the agent will
    // report a working read as blocked.
    let credential_overrides = denied_dotfile_overrides(home, &resolved.allow_read);
    if !credential_overrides.is_empty() {
        let _ = writeln!(
            out,
            "- Exceptions the user granted this session (`allow.read`), which \
             ARE readable: {}. Use them for what they are for and don't send \
             their contents anywhere.",
            credential_overrides.join(", ")
        );
    }
    if cfg!(target_os = "linux") {
        out.push_str(
            "- Exception on Linux: registry credential files inside \
             otherwise-allowed tool directories (`~/.m2/settings.xml`, \
             `~/.gradle/gradle.properties`, `~/.npmrc`, ...) are NOT blocked — \
             Landlock cannot deny a subpath of an allowed directory. Treat \
             them as readable, and don't send their contents anywhere.\n",
        );
    }
    if resolved.allow_env_files {
        out.push_str("- `.env*` files are readable this session (`allow_env_files` is on).\n");
    } else {
        out.push_str("- `.env*` files are also denied by default in this session.\n");
    }

    out.push_str("\n## If you hit a wall\n\n");
    out.push_str(
        "- Tell the user exactly what failed (command + path). Point them at \
         `cplt check`, `cplt trust`, `allow.read`/`allow.write` in \
         `config.toml`, or `cplt --print-profile` to inspect the active \
         policy. Don't guess a fix and burn turns on it.\n",
    );

    out
}

/// Can an outbound connection to port 22 leave the sandbox at all?
///
/// Default egress is `*:443` only — SBPL emits one `(remote ip "*:443")`, and
/// the Landlock seed is a single `NetRule { port: 443 }`. So port 22 needs an
/// explicit `allow.ports = [22]`…
///
/// …except on Linux under `allow_localhost_any`, where `restrict_net_connect`
/// is `false` and cplt does not handle `AccessNet::ConnectTcp` at all: with no
/// connect restriction in the ruleset, *no* port is kernel-limited. The
/// `permissive` and `full-trust` presets both set it, so this is not a corner
/// case. macOS is unaffected — SBPL denies `(remote tcp)` by default and can
/// pin localhost, so its port list holds either way.
fn ssh_port_open(resolved: &Resolved) -> bool {
    resolved.allow_ports.contains(&22)
        || (cfg!(target_os = "linux") && resolved.allow_localhost_any)
}

/// Is a private key under `~/.ssh` actually readable?
///
/// The two backends disagree, so this does too:
///
/// - **macOS**: `~/.ssh` is denied as a subpath, and `emit_denied_dotfile_overrides`
///   re-allows approved paths afterwards — but it skips `*path == denied_dir`
///   and emits `(literal ...)`, never a subpath. Only a grant naming a *file*
///   inside `~/.ssh` opens anything.
/// - **Linux**: Landlock has no denied-dotfile layer at all. Every `extra_read`
///   path becomes a plain read rule, so a grant of `~/.ssh` — or of `~` — really
///   does make the keys readable, and the brief must not claim otherwise.
fn ssh_key_readable(allow_read: &[std::path::PathBuf], home: &Path) -> bool {
    let ssh_dir = home.join(".ssh");
    allow_read.iter().any(|p| {
        if cfg!(target_os = "macos") {
            p.starts_with(&ssh_dir) && *p != ssh_dir
        } else {
            p.starts_with(&ssh_dir) || ssh_dir.starts_with(p)
        }
    })
}

/// Does the ssh agent socket reach the sandbox?
///
/// `--pass-env SSH_AUTH_SOCK` delivers it: `extra_pass_env` is consumed in
/// `build_sandbox_env`'s sanitized branch, which never consults
/// `ENV_ALWAYS_DENY`.
///
/// `--inherit-env` takes the other branch, which pushes every `ENV_ALWAYS_DENY`
/// entry — `SSH_AUTH_SOCK` among them — onto `remove`, and never looks at
/// `extra_pass_env`. So inherit does not merely fail to help: it *cancels*
/// `--pass-env SSH_AUTH_SOCK`. Nothing conflicts the two flags, and
/// `sandbox.pass_env` in config makes the combination easy to hit by accident.
///
/// On macOS the variable alone is still not enough. The socket lives at
/// `/private/tmp/com.apple.launchd.*/Listeners`, and the profile grants no
/// `network-outbound unix-socket` for it — deliberately, which is why the JVM
/// carve-out is regex-pinned to `.java_pid`. It also takes an `allow.socket`.
fn ssh_agent_reaches(resolved: &Resolved) -> bool {
    !resolved.inherit_env
        && resolved.pass_env.iter().any(|v| v == "SSH_AUTH_SOCK")
        && (!cfg!(target_os = "macos") || !resolved.allow_socket.is_empty())
}

/// The `allow.read` paths that defeat a `DENIED_DOTFILES` deny, rendered with
/// `~` for the home prefix.
///
/// The Credentials section claims those directories are unreadable; this is
/// what keeps the claim honest by naming the exceptions. Which grants count is
/// per-backend, exactly as in [`ssh_key_readable`]: macOS re-allows approved
/// paths per file via `emit_denied_dotfile_overrides` (which skips the
/// directory itself), while Linux has no denied-dotfile layer at all, so a
/// grant *at or above* the directory — `~/.aws`, or plain `~` — opens it.
fn denied_dotfile_overrides(home: &Path, allow_read: &[std::path::PathBuf]) -> Vec<String> {
    allow_read
        .iter()
        .filter(|p| {
            crate::sandbox::DENIED_DOTFILES.iter().any(|d| {
                let denied = home.join(d);
                if cfg!(target_os = "macos") {
                    p.starts_with(&denied) && **p != denied
                } else {
                    p.starts_with(&denied) || denied.starts_with(p)
                }
            })
        })
        .map(|p| match p.strip_prefix(home) {
            // A grant of $HOME itself renders as `~`, not `~/`.
            Ok(rest) if rest.as_os_str().is_empty() => "`~`".to_string(),
            Ok(rest) => format!("`~/{}`", rest.display()),
            Err(_) => format!("`{}`", p.display()),
        })
        .collect()
}

/// Write the session brief to `<scratch_dir>/CPLT_BRIEF.md`.
///
/// Scratch is always readable+writable inside the sandbox and avoids
/// polluting the project directory or hitting the symlink canonicalization
/// trap of writing into a path the agent later globs (issue #171).
pub fn write_session_brief(
    scratch_dir: &Path,
    content: &str,
) -> std::io::Result<std::path::PathBuf> {
    let path = scratch_dir.join("CPLT_BRIEF.md");
    std::fs::write(&path, content)?;
    Ok(path)
}

/// The persistent managed block content for AGENTS.md.
///
/// Deliberately generic and factual: what cplt is, how an agent can tell
/// whether it is running under one, and what a denial means. It states nothing
/// about what this repository's maintainers want, and claims no protection the
/// sandbox does not actually deliver — the per-session brief is where the
/// resolved, verifiable policy lives.
pub fn managed_block() -> String {
    format!(
        "{BLOCK_BEGIN}\n\
         <!-- Managed by cplt (sandbox.agents_md). Regenerated on launch —\n\
         \x20    edits between these markers are overwritten. -->\n\
         ## Sandbox\n\n\
         This repository is sometimes worked on by agents running under \
         [cplt](https://github.com/navikt/cplt), an OS-level sandbox that \
         restricts filesystem and network access.\n\n\
         - You are running under cplt if `$__CPLT_WRAPPED` is set in your \
         environment. If it is not set, no cplt policy applies to this \
         session.\n\
         - Under cplt, a denied file or network access surfaces as `EPERM` / \
         `Operation not permitted`, or as a connection that fails to open. \
         That is the sandbox policy, not a bug in this repository's code and \
         not a transient error — retrying, `sudo`, or routing around it will \
         not help.\n\
         - Report the exact command and path to the user instead. Only they \
         can widen the policy, from outside the sandbox (`allow.read` / \
         `allow.write` / allowed domains in the cplt config, or `cplt trust` \
         for keys this repo proposes).\n\
         - The policy resolved for the current session is written to \
         `$TMPDIR/CPLT_BRIEF.md` (cplt redirects `$TMPDIR` to a per-session \
         scratch dir). `cplt check` reports the same policy from outside the \
         sandbox.\n\
         {BLOCK_END}"
    )
}

/// Outcome of inserting/updating the managed block in an AGENTS.md file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockOutcome {
    /// File didn't exist; created with the block.
    Created,
    /// File existed without a block; block appended.
    Inserted,
    /// File existed with a stale block; replaced in place.
    Updated,
    /// File existed with an identical block already; no write performed.
    Unchanged,
    /// More than one managed block found (corrupted file) — refused to
    /// guess which to replace. Nothing was written.
    SkippedAmbiguous,
}

/// Insert or update the managed sandbox block in `path` (typically the
/// project-root `AGENTS.md`).
///
/// Rules (never mangle, never duplicate):
/// - Absent file → create it with just the block.
/// - Markers present exactly once → replace the content between them.
/// - Markers present more than once → refuse (ambiguous); return
///   `SkippedAmbiguous`, caller should warn.
/// - No markers → append the block at EOF.
pub fn upsert_managed_block(path: &Path) -> Result<BlockOutcome, String> {
    let block = managed_block();

    // Symlink guard (pre-sandbox write): this function runs BEFORE the
    // sandbox is entered, with full host privileges, on a path supplied by
    // the (possibly untrusted) project repo. A symlinked AGENTS.md would
    // redirect fs::write to an arbitrary host file (e.g. ~/.zshrc).
    // symlink_metadata does not follow the link — refuse outright.
    match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_symlink() => {
            return Err(format!(
                "{} is a symlink — refusing to write (possible hostile repo)",
                path.display()
            ));
        }
        Ok(_) | Err(_) => {} // real file, or doesn't exist yet — fine
    }

    let existing = match std::fs::read_to_string(path) {
        Ok(content) => content,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            std::fs::write(path, format!("{block}\n"))
                .map_err(|e| format!("cannot write {}: {e}", path.display()))?;
            return Ok(BlockOutcome::Created);
        }
        // Any other error (permission denied, not valid UTF-8, etc.) — refuse
        // to guess. Overwriting here could destroy an existing file we just
        // couldn't read.
        Err(e) => return Err(format!("cannot read {}: {e}", path.display())),
    };

    let begin_count = existing.matches(BLOCK_BEGIN).count();
    let end_count = existing.matches(BLOCK_END).count();

    if begin_count > 1 || end_count > 1 || begin_count != end_count {
        return Ok(BlockOutcome::SkippedAmbiguous);
    }

    if begin_count == 1 {
        let start = existing.find(BLOCK_BEGIN).unwrap();
        let end_start = existing.find(BLOCK_END).unwrap();
        // END must open after BEGIN opens. Comparing the two *start* offsets
        // (rather than `end < start`, where `end` is past the END marker) also
        // catches the adjacent case `<!--end--><!--begin-->`: there the two
        // happen to be equal, the slice below would be empty, and we would
        // splice a second pair of markers into the file — corrupting it into
        // the permanently-ambiguous state.
        if end_start < start {
            return Ok(BlockOutcome::SkippedAmbiguous);
        }
        let end = end_start + BLOCK_END.len();
        let current_block = &existing[start..end];
        if current_block == block {
            return Ok(BlockOutcome::Unchanged);
        }
        let mut new_content = String::with_capacity(existing.len());
        new_content.push_str(&existing[..start]);
        new_content.push_str(&block);
        new_content.push_str(&existing[end..]);
        std::fs::write(path, new_content)
            .map_err(|e| format!("cannot write {}: {e}", path.display()))?;
        return Ok(BlockOutcome::Updated);
    }

    // No managed markers — plain append at EOF.
    let mut new_content = existing;
    if !new_content.ends_with('\n') {
        new_content.push('\n');
    }
    if !new_content.is_empty() {
        new_content.push('\n');
    }
    new_content.push_str(&block);
    new_content.push('\n');
    std::fs::write(path, new_content)
        .map_err(|e| format!("cannot write {}: {e}", path.display()))?;
    Ok(BlockOutcome::Inserted)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{GhGuardPolicy, GitGuardPolicy, Resolved};
    use std::path::PathBuf;

    fn base_resolved() -> Resolved {
        Resolved {
            with_proxy: true,
            proxy_forced: false,
            proxy_port: 0,
            blocked_domains: None,
            allowed_domains: None,
            default_allowlist: false,
            allow_all_domains: false,
            proxy_log_file: None,
            proxy_log_level: crate::proxy::ProxyLogLevel::default(),
            proxy_timeout: std::time::Duration::from_secs(30),
            proxy_upstream: None,
            proxy_upstream_no_proxy: Vec::new(),
            proxy_subscriptions: crate::subscriptions::SubscriptionSet {
                refresh: crate::subscriptions::RefreshInterval::Manual,
                blocklists: Vec::new(),
                cache_dir: std::path::PathBuf::new(),
            },
            allow_private_domains: Vec::new(),
            repo_private_domains: Vec::new(),
            allow_read: Vec::new(),
            allow_write: Vec::new(),
            allow_socket: Vec::new(),
            deny_paths: Vec::new(),
            allow_ports: Vec::new(),
            allow_localhost: Vec::new(),
            allow_localhost_any: false,
            allow_env_files: false,
            no_validate: false,
            brief: true,
            agents_md: false,
            pass_env: Vec::new(),
            inherit_env: false,
            allow_lifecycle_scripts: false,
            allow_gpg_signing: false,
            deny_clipboard: false,
            allow_jvm_attach: false,
            gradle_init: false,
            allow_docker: false,
            allow_msbuild: false,
            allow_tmp_exec: false,
            allow_cache_exec: Vec::new(),
            allow_cache_exec_any: false,
            allow_browser: false,
            scratch_dir: true,
            use_bubblewrap: None,
            quiet: false,
            audit: true,
            yes: false,
            gh_guard: GhGuardPolicy::default(),
            git_guard: GitGuardPolicy::default(),
            preset: None,
            agent: None,
            deny_env: Vec::new(),
        }
    }

    /// Home for the render-only tests: nothing is read from it, it only has to
    /// be a stable prefix the `~/.ssh` and credential checks can compare to.
    fn home() -> &'static Path {
        Path::new("/home/tester")
    }

    #[test]
    fn brief_flips_env_files_warning_with_config() {
        let mut resolved = base_resolved();
        resolved.allow_env_files = false;
        let brief = generate_session_brief(&resolved, Agent::Copilot, home());
        assert!(brief.contains("also denied by default"));

        resolved.allow_env_files = true;
        let brief = generate_session_brief(&resolved, Agent::Copilot, home());
        assert!(!brief.contains("also denied"));
        assert!(brief.contains("readable this session"));
    }

    #[test]
    fn brief_flips_network_line_with_default_allowlist() {
        let mut resolved = base_resolved();
        resolved.default_allowlist = false;
        let brief = generate_session_brief(&resolved, Agent::OpenCode, home());
        assert!(!brief.contains("built-in allowlist"));

        resolved.default_allowlist = true;
        let brief = generate_session_brief(&resolved, Agent::OpenCode, home());
        assert!(brief.contains("built-in allowlist"));
    }

    /// Plain proxy mode does not fail closed: direct `*:443` egress is still
    /// allowed by the kernel unless `proxy_forced` is on (sandbox_profile.rs).
    /// The brief must say so rather than promising a wall that isn't there.
    #[test]
    fn brief_claims_fail_closed_only_when_proxy_forced() {
        let mut resolved = base_resolved();
        resolved.default_allowlist = true;
        resolved.proxy_forced = false;
        let brief = generate_session_brief(&resolved, Agent::Claude, home());
        assert!(
            !brief.contains("fails closed"),
            "plain proxy mode must not claim fail-closed:\n{brief}"
        );
        assert!(brief.contains("direct `*:443` connections are still permitted"));

        resolved.proxy_forced = true;
        let brief = generate_session_brief(&resolved, Agent::Claude, home());
        assert!(brief.contains("fails closed"));
    }

    #[test]
    fn brief_says_ssh_blocked_but_not_https_git() {
        let resolved = base_resolved();
        let brief = generate_session_brief(&resolved, Agent::Claude, home());
        assert!(brief.contains("SSH is blocked"));
        // git_guard gates HTTPS push; the sandbox itself does not block
        // HTTPS remotes, and the brief must not claim otherwise.
        assert!(brief.contains("Git over HTTPS still works"));
    }

    /// Keys and the agent socket are irrelevant while port 22 is shut, which
    /// it is by default on both backends — so the brief must keep naming the
    /// port as the blocker.
    #[test]
    fn brief_keeps_ssh_denial_without_port_22() {
        let mut resolved = base_resolved();
        resolved.allow_read = vec![home().join(".ssh/id_ed25519")];
        resolved.pass_env = vec!["SSH_AUTH_SOCK".to_string()];
        resolved.allow_socket = vec![PathBuf::from("/private/tmp/x/Listeners")];
        let brief = generate_session_brief(&resolved, Agent::Claude, home());
        assert!(brief.contains("SSH is blocked"), "{brief}");
        assert!(brief.contains("outbound TCP is limited to 443"), "{brief}");
    }

    /// With port 22 open, an `allow.read` of a key file is enough — the brief
    /// must not assert a blanket denial over a supported configuration.
    #[test]
    fn brief_drops_ssh_denial_when_port_open_and_key_readable() {
        let mut resolved = base_resolved();
        resolved.allow_ports = vec![22];
        resolved.allow_read = vec![home().join(".ssh/id_ed25519")];
        let brief = generate_session_brief(&resolved, Agent::Claude, home());
        assert!(!brief.contains("SSH is blocked"), "{brief}");
        assert!(brief.contains("SSH may work this session"));
        // The blanket credentials claim needs the same treatment.
        assert!(brief.contains("`~/.ssh/id_ed25519`"), "{brief}");
    }

    /// Port open, nothing to authenticate with: the blocker is the keys, and
    /// the brief must not blame the port it just said was open.
    #[test]
    fn brief_blames_the_keys_when_the_port_is_open_but_nothing_authenticates() {
        let mut resolved = base_resolved();
        resolved.allow_ports = vec![22];
        let brief = generate_session_brief(&resolved, Agent::Claude, home());
        assert!(
            brief.contains("the blocker is the keys, not the port"),
            "{brief}"
        );
        assert!(
            !brief.contains("outbound TCP is limited to 443"),
            "port 22 is open — the port text is a lie here:\n{brief}"
        );
    }

    /// `--inherit-env` takes the branch that sweeps ENV_ALWAYS_DENY (which
    /// lists SSH_AUTH_SOCK) and never reads extra_pass_env — so it does not
    /// merely fail to help, it cancels `--pass-env SSH_AUTH_SOCK`. Nothing in
    /// clap conflicts the two, and `sandbox.pass_env` makes the pair easy to
    /// hit.
    #[test]
    fn brief_does_not_count_the_agent_socket_under_inherit_env() {
        let mut resolved = base_resolved();
        resolved.allow_ports = vec![22];
        resolved.pass_env = vec!["SSH_AUTH_SOCK".to_string()];
        resolved.allow_socket = vec![PathBuf::from("/private/tmp/x/Listeners")];
        resolved.inherit_env = true;
        let brief = generate_session_brief(&resolved, Agent::Claude, home());
        assert!(
            brief.contains("the blocker is the keys, not the port"),
            "--inherit-env strips SSH_AUTH_SOCK even with --pass-env:\n{brief}"
        );

        // Same config without inherit_env: the socket does arrive.
        resolved.inherit_env = false;
        let brief = generate_session_brief(&resolved, Agent::Claude, home());
        assert!(brief.contains("SSH may work this session"), "{brief}");
    }

    /// macOS re-allows approved paths inside `~/.ssh` per file
    /// (`emit_denied_dotfile_overrides` skips the directory itself and emits
    /// `(literal ...)`), so a grant of the bare directory opens nothing.
    #[test]
    #[cfg(target_os = "macos")]
    fn brief_treats_bare_ssh_dir_grant_as_no_grant_on_macos() {
        let mut resolved = base_resolved();
        resolved.allow_ports = vec![22];
        resolved.allow_read = vec![home().join(".ssh")];
        let brief = generate_session_brief(&resolved, Agent::Claude, home());
        assert!(
            brief.contains("the blocker is the keys, not the port"),
            "{brief}"
        );
        assert!(
            !brief.contains("Exceptions the user granted"),
            "a bare directory grant is not a readable exception on macOS:\n{brief}"
        );
    }

    /// Linux has no denied-dotfile layer — every extra_read path becomes a
    /// plain Landlock read rule — so a grant of `~/.ssh`, or of `~`, really
    /// does make the keys readable, and the brief must say so.
    #[test]
    #[cfg(target_os = "linux")]
    fn brief_honours_a_directory_grant_on_linux() {
        for grant in [home().join(".ssh"), home().to_path_buf()] {
            let mut resolved = base_resolved();
            resolved.allow_ports = vec![22];
            resolved.allow_read = vec![grant.clone()];
            let brief = generate_session_brief(&resolved, Agent::Claude, home());
            assert!(
                brief.contains("SSH may work this session"),
                "Landlock grants {} outright:\n{brief}",
                grant.display()
            );
            assert!(
                brief.contains("Exceptions the user granted"),
                "the credentials claim must name {}:\n{brief}",
                grant.display()
            );
        }
    }

    /// Linux + allow_localhost_any sets restrict_net_connect = false, so
    /// ConnectTcp is never handled and NO port is kernel-limited. Claiming
    /// port 22 is denied would be a promise the kernel is not making. Both the
    /// permissive and full-trust presets set this.
    #[test]
    #[cfg(target_os = "linux")]
    fn brief_does_not_claim_port_22_is_denied_under_allow_localhost_any() {
        let mut resolved = base_resolved();
        resolved.allow_localhost_any = true;
        assert!(!resolved.allow_ports.contains(&22), "port 22 not listed");
        let brief = generate_session_brief(&resolved, Agent::Claude, home());
        assert!(
            !brief.contains("outbound TCP is limited to 443"),
            "no connect restriction is in the ruleset at all:\n{brief}"
        );
        assert!(
            brief.contains("the blocker is the keys, not the port"),
            "{brief}"
        );
    }

    /// The cplt config directory has no allow rule, so it is unreadable inside
    /// the sandbox — not "read-only".
    #[test]
    fn brief_does_not_call_the_config_readable() {
        let brief = generate_session_brief(&base_resolved(), Agent::Claude, home());
        assert!(brief.contains("not readable from in here"), "{brief}");
        assert!(!brief.contains("read-only from in here"));
    }

    #[test]
    fn brief_flips_network_line_with_allow_all_domains() {
        let mut resolved = base_resolved();
        resolved.default_allowlist = true;
        resolved.allow_all_domains = true;
        let brief = generate_session_brief(&resolved, Agent::Claude, home());
        assert!(
            !brief.contains("built-in allowlist"),
            "must not claim an allowlist applies under --allow-all-domains"
        );
        assert!(brief.contains("No domain allowlist"));
    }

    #[test]
    fn managed_block_has_matching_markers() {
        let block = managed_block();
        assert!(block.starts_with(BLOCK_BEGIN));
        assert!(block.ends_with(BLOCK_END));
        assert!(block.contains("__CPLT_WRAPPED"));
    }

    #[test]
    fn managed_block_points_at_session_brief_via_tmpdir() {
        let block = managed_block();
        // Must reference the literal, unexpanded $TMPDIR var (not a baked-in
        // per-session scratch path) so the static managed block stays stable
        // across launches — see write_session_brief() / --scratch-dir.
        assert!(
            block.contains("$TMPDIR/CPLT_BRIEF.md"),
            "managed block should point agents at the session-specific brief"
        );
        assert!(
            !block.contains("/tmp/") || block.contains("$TMPDIR"),
            "must not embed a concrete scratch path"
        );
    }

    /// A symlinked AGENTS.md must never be written through: cplt runs this
    /// pre-sandbox with host privileges, so a hostile repo could otherwise
    /// redirect the write to an arbitrary file (e.g. ~/.zshrc).
    #[test]
    #[cfg(unix)]
    fn upsert_refuses_symlink() {
        let tmpdir = tempfile::tempdir().unwrap();
        let tmp = tmpdir.path();
        let target = tmp.join("target.txt");
        std::fs::write(&target, "precious\n").unwrap();
        let path = tmp.join("AGENTS.md");
        std::os::unix::fs::symlink(&target, &path).unwrap();

        let err = upsert_managed_block(&path).unwrap_err();
        assert!(err.contains("symlink"), "unexpected error: {err}");
        // Target untouched.
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "precious\n");
    }

    #[test]
    fn upsert_creates_absent_file() {
        let tmpdir = tempfile::tempdir().unwrap();
        let tmp = tmpdir.path();
        let path = tmp.join("AGENTS.md");

        let outcome = upsert_managed_block(&path).unwrap();
        assert_eq!(outcome, BlockOutcome::Created);
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains(BLOCK_BEGIN));
        assert!(content.contains(BLOCK_END));
    }

    #[test]
    fn upsert_inserts_into_existing_file_without_block() {
        let tmpdir = tempfile::tempdir().unwrap();
        let tmp = tmpdir.path();
        let path = tmp.join("AGENTS.md");
        std::fs::write(&path, "# My project\n\nSome existing content.\n").unwrap();

        let outcome = upsert_managed_block(&path).unwrap();
        assert_eq!(outcome, BlockOutcome::Inserted);
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("Some existing content."));
        assert!(content.contains(BLOCK_BEGIN));
    }

    #[test]
    fn upsert_idempotent_on_rerun() {
        let tmpdir = tempfile::tempdir().unwrap();
        let tmp = tmpdir.path();
        let path = tmp.join("AGENTS.md");

        assert_eq!(upsert_managed_block(&path).unwrap(), BlockOutcome::Created);
        let after_first = std::fs::read_to_string(&path).unwrap();

        assert_eq!(
            upsert_managed_block(&path).unwrap(),
            BlockOutcome::Unchanged
        );
        let after_second = std::fs::read_to_string(&path).unwrap();
        assert_eq!(after_first, after_second, "no duplication on re-run");
        assert_eq!(after_second.matches(BLOCK_BEGIN).count(), 1);
    }

    #[test]
    fn upsert_replaces_stale_block() {
        let tmpdir = tempfile::tempdir().unwrap();
        let tmp = tmpdir.path();
        let path = tmp.join("AGENTS.md");
        std::fs::write(
            &path,
            format!("# Project\n\n{BLOCK_BEGIN}\nstale content\n{BLOCK_END}\n\nfooter\n"),
        )
        .unwrap();

        let outcome = upsert_managed_block(&path).unwrap();
        assert_eq!(outcome, BlockOutcome::Updated);
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(!content.contains("stale content"));
        assert!(content.contains("footer"));
        assert_eq!(content.matches(BLOCK_BEGIN).count(), 1);
    }

    #[test]
    fn upsert_appends_after_hand_written_content() {
        let tmpdir = tempfile::tempdir().unwrap();
        let tmp = tmpdir.path();
        let path = tmp.join("AGENTS.md");
        std::fs::write(
            &path,
            "# Project\n\n## Sandbox\n\nWe run our own custom sandbox setup.\n",
        )
        .unwrap();

        let outcome = upsert_managed_block(&path).unwrap();
        assert_eq!(outcome, BlockOutcome::Inserted);
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(
            content.contains("We run our own custom sandbox setup."),
            "hand-written content must survive"
        );
        assert_eq!(content.matches(BLOCK_BEGIN).count(), 1);
    }

    #[test]
    fn upsert_skips_ambiguous_duplicate_markers() {
        let tmpdir = tempfile::tempdir().unwrap();
        let tmp = tmpdir.path();
        let path = tmp.join("AGENTS.md");
        let doubled = format!("{BLOCK_BEGIN}\na\n{BLOCK_END}\n\n{BLOCK_BEGIN}\nb\n{BLOCK_END}\n");
        std::fs::write(&path, &doubled).unwrap();

        let outcome = upsert_managed_block(&path).unwrap();
        assert_eq!(outcome, BlockOutcome::SkippedAmbiguous);
        let content = std::fs::read_to_string(&path).unwrap();
        assert_eq!(content, doubled, "ambiguous file must be left untouched");
    }

    /// `<!--end--><!--begin-->` with no gap: the END marker's *end* offset
    /// equals the BEGIN marker's start, so an `end < start` guard lets it
    /// through, splices the block into the zero-width slice between them, and
    /// leaves the file with two marker pairs — permanently ambiguous.
    #[test]
    fn upsert_refuses_adjacent_reversed_markers() {
        let tmpdir = tempfile::tempdir().unwrap();
        let tmp = tmpdir.path();
        let path = tmp.join("AGENTS.md");
        let reversed = format!("{BLOCK_END}{BLOCK_BEGIN}\n");
        std::fs::write(&path, &reversed).unwrap();

        let outcome = upsert_managed_block(&path).unwrap();
        assert_eq!(outcome, BlockOutcome::SkippedAmbiguous);
        let content = std::fs::read_to_string(&path).unwrap();
        assert_eq!(content, reversed, "malformed file must be left untouched");
    }

    #[test]
    fn upsert_refuses_to_overwrite_unreadable_file() {
        // A read error that ISN'T "file not found" (e.g. invalid UTF-8,
        // permission denied) must never be treated as "absent" — that would
        // silently destroy the user's existing AGENTS.md.
        let tmpdir = tempfile::tempdir().unwrap();
        let tmp = tmpdir.path();
        let path = tmp.join("AGENTS.md");
        // Invalid UTF-8 bytes make read_to_string fail with InvalidData,
        // not NotFound.
        std::fs::write(&path, [0xff, 0xfe, 0x00, 0xff]).unwrap();

        let result = upsert_managed_block(&path);
        assert!(result.is_err(), "non-NotFound read errors must surface");

        let raw = std::fs::read(&path).unwrap();
        assert_eq!(raw, vec![0xff, 0xfe, 0x00, 0xff], "file must be untouched");
    }
}

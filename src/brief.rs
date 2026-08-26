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
//!    `sandbox.agents_md`, persistent, and left for the user to review and
//!    commit. Delimited by stable markers so it can be inserted, updated in
//!    place, or safely skipped without ever duplicating or mangling
//!    hand-written content.
//!
//! Implements design issue #148 (agent-facing sandbox policy exposure).

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
pub fn generate_session_brief(resolved: &Resolved, agent: Agent) -> String {
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
        "- Config is read-only from in here (`~/.config/cplt/config.toml`). \
         Changes require the user to edit it and re-run.\n",
    );

    out.push_str("\n## Network\n\n");
    if resolved.allow_all_domains {
        out.push_str(
            "- No domain allowlist this session (`--allow-all-domains`): any \
             domain is reachable except the ones on the blocklist.\n",
        );
    } else if resolved.default_allowlist {
        out.push_str(
            "- Fail-closed: only the agent's built-in allowlist (plus any \
             configured `allowed_domains`) is reachable. Everything else is \
             blocked at the proxy.\n",
        );
    } else if resolved.with_proxy {
        out.push_str(
            "- HTTPS via a filtering CONNECT proxy. Non-HTTPS and unlisted \
             blocked domains fail closed.\n",
        );
    } else {
        out.push_str("- No proxy is active for this session.\n");
    }
    out.push_str(
        "- SSH is blocked: `~/.ssh` is unreadable and `SSH_AUTH_SOCK` is not \
         passed through, so `ssh`/`scp` and git over `ssh://` or \
         `git@host:...` remotes fail. Git over HTTPS still works — ask the \
         user to run the SSH-only parts outside the sandbox.\n",
    );
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

    #[test]
    fn brief_flips_env_files_warning_with_config() {
        let mut resolved = base_resolved();
        resolved.allow_env_files = false;
        let brief = generate_session_brief(&resolved, Agent::Copilot);
        assert!(brief.contains("also denied by default"));

        resolved.allow_env_files = true;
        let brief = generate_session_brief(&resolved, Agent::Copilot);
        assert!(!brief.contains("also denied"));
        assert!(brief.contains("readable this session"));
    }

    #[test]
    fn brief_flips_network_line_with_default_allowlist() {
        let mut resolved = base_resolved();
        resolved.default_allowlist = false;
        let brief = generate_session_brief(&resolved, Agent::OpenCode);
        assert!(!brief.contains("Fail-closed"));

        resolved.default_allowlist = true;
        let brief = generate_session_brief(&resolved, Agent::OpenCode);
        assert!(brief.contains("Fail-closed"));
    }

    #[test]
    fn brief_says_ssh_blocked_but_not_https_git() {
        let resolved = base_resolved();
        let brief = generate_session_brief(&resolved, Agent::Claude);
        assert!(brief.contains("SSH is blocked"));
        // git_guard gates HTTPS push; the sandbox itself does not block
        // HTTPS remotes, and the brief must not claim otherwise.
        assert!(brief.contains("Git over HTTPS still works"));
    }

    #[test]
    fn brief_flips_network_line_with_allow_all_domains() {
        let mut resolved = base_resolved();
        resolved.default_allowlist = true;
        resolved.allow_all_domains = true;
        let brief = generate_session_brief(&resolved, Agent::Claude);
        assert!(
            !brief.contains("Fail-closed"),
            "must not claim domains fail closed under --allow-all-domains"
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
        let tmp = std::env::temp_dir().join("cplt-test-brief-symlink");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();
        let target = tmp.join("target.txt");
        std::fs::write(&target, "precious\n").unwrap();
        let path = tmp.join("AGENTS.md");
        std::os::unix::fs::symlink(&target, &path).unwrap();

        let err = upsert_managed_block(&path).unwrap_err();
        assert!(err.contains("symlink"), "unexpected error: {err}");
        // Target untouched.
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "precious\n");

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn upsert_creates_absent_file() {
        let tmp = std::env::temp_dir().join("cplt-test-brief-create");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();
        let path = tmp.join("AGENTS.md");

        let outcome = upsert_managed_block(&path).unwrap();
        assert_eq!(outcome, BlockOutcome::Created);
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains(BLOCK_BEGIN));
        assert!(content.contains(BLOCK_END));

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn upsert_inserts_into_existing_file_without_block() {
        let tmp = std::env::temp_dir().join("cplt-test-brief-insert");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();
        let path = tmp.join("AGENTS.md");
        std::fs::write(&path, "# My project\n\nSome existing content.\n").unwrap();

        let outcome = upsert_managed_block(&path).unwrap();
        assert_eq!(outcome, BlockOutcome::Inserted);
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("Some existing content."));
        assert!(content.contains(BLOCK_BEGIN));

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn upsert_idempotent_on_rerun() {
        let tmp = std::env::temp_dir().join("cplt-test-brief-idempotent");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();
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

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn upsert_replaces_stale_block() {
        let tmp = std::env::temp_dir().join("cplt-test-brief-stale");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();
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

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn upsert_appends_after_hand_written_content() {
        let tmp = std::env::temp_dir().join("cplt-test-brief-handwritten");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();
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

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn upsert_skips_ambiguous_duplicate_markers() {
        let tmp = std::env::temp_dir().join("cplt-test-brief-ambiguous");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();
        let path = tmp.join("AGENTS.md");
        let doubled = format!("{BLOCK_BEGIN}\na\n{BLOCK_END}\n\n{BLOCK_BEGIN}\nb\n{BLOCK_END}\n");
        std::fs::write(&path, &doubled).unwrap();

        let outcome = upsert_managed_block(&path).unwrap();
        assert_eq!(outcome, BlockOutcome::SkippedAmbiguous);
        let content = std::fs::read_to_string(&path).unwrap();
        assert_eq!(content, doubled, "ambiguous file must be left untouched");

        let _ = std::fs::remove_dir_all(&tmp);
    }

    /// `<!--end--><!--begin-->` with no gap: the END marker's *end* offset
    /// equals the BEGIN marker's start, so an `end < start` guard lets it
    /// through, splices the block into the zero-width slice between them, and
    /// leaves the file with two marker pairs — permanently ambiguous.
    #[test]
    fn upsert_refuses_adjacent_reversed_markers() {
        let tmp = std::env::temp_dir().join("cplt-test-brief-reversed");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();
        let path = tmp.join("AGENTS.md");
        let reversed = format!("{BLOCK_END}{BLOCK_BEGIN}\n");
        std::fs::write(&path, &reversed).unwrap();

        let outcome = upsert_managed_block(&path).unwrap();
        assert_eq!(outcome, BlockOutcome::SkippedAmbiguous);
        let content = std::fs::read_to_string(&path).unwrap();
        assert_eq!(content, reversed, "malformed file must be left untouched");

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn upsert_refuses_to_overwrite_unreadable_file() {
        // A read error that ISN'T "file not found" (e.g. invalid UTF-8,
        // permission denied) must never be treated as "absent" — that would
        // silently destroy the user's existing AGENTS.md.
        let tmp = std::env::temp_dir().join("cplt-test-brief-unreadable");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();
        let path = tmp.join("AGENTS.md");
        // Invalid UTF-8 bytes make read_to_string fail with InvalidData,
        // not NotFound.
        std::fs::write(&path, [0xff, 0xfe, 0x00, 0xff]).unwrap();

        let result = upsert_managed_block(&path);
        assert!(result.is_err(), "non-NotFound read errors must surface");

        let raw = std::fs::read(&path).unwrap();
        assert_eq!(raw, vec![0xff, 0xfe, 0x00, 0xff], "file must be untouched");

        let _ = std::fs::remove_dir_all(&tmp);
    }
}

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
//!    project-root `AGENTS.md` (created if absent) — persistent, committed
//!    to the repo, so every agent that clones the repo benefits, sandboxed
//!    via cplt or otherwise. Delimited by stable markers so it can be
//!    inserted, updated in place, or safely skipped without ever
//!    duplicating or mangling hand-written content.
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

/// Heading a hand-written "## Sandbox" section would use. If present (and no
/// managed block yet), we don't stomp it — we append a one-line pointer
/// beneath it instead.
const HAND_WRITTEN_HEADING_PREFIX: &str = "## Sandbox";

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
    if resolved.default_allowlist {
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
        "- SSH is blocked — remote git push/pull/fetch and any `ssh`/`scp` \
         call will fail. Ask the user to run it outside the sandbox.\n",
    );

    out.push_str("\n## Credentials\n\n");
    out.push_str(
        "- Credential paths (SSH keys, cloud CLI configs, tokens, keychains) \
         are unreadable by design (EPERM). Don't retry; tell the user.\n",
    );
    if resolved.allow_env_files {
        out.push_str("- `.env*` files are readable this session (`allow_env_files` is on).\n");
    } else {
        out.push_str("- `.env*` files are also denied by default in this session.\n");
    }

    out.push_str("\n## If you hit a wall\n\n");
    out.push_str(
        "- Tell the user exactly what failed (command + path). Point them at \
         `cplt trust`, `allow.read`/`allow.write` in `config.toml`, or \
         `cplt --print-profile` to inspect the active policy. Don't guess a \
         fix and burn turns on it.\n",
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

/// The persistent, sandbox-agnostic managed block content for AGENTS.md.
///
/// Deliberately generic (not cplt-specific policy dump): a polite nudge that
/// other sandboxes benefit from equally, with cplt as the named example, plus
/// a self-check so an agent running WITHOUT a sandbox degrades to
/// conservative behavior instead of assuming it's protected.
pub fn managed_block() -> String {
    format!(
        "{BLOCK_BEGIN}\n\
         <!-- Managed by cplt. Do not edit by hand between these markers —\n\
         \x20    re-generated on every sandboxed launch. See below the block\n\
         \x20    for how to add your own notes. -->\n\
         ## Sandbox\n\n\
         Agents working in this repo are encouraged to run sandboxed (e.g. with \
         [cplt](https://github.com/navikt/cplt) or an equivalent OS-level \
         sandbox) rather than with full filesystem/network access.\n\n\
         **Self-check:** if `$__CPLT_WRAPPED` (or an equivalent sandbox marker) \
         is NOT set, you are running unsandboxed — tell the user and proceed \
         conservatively: no credential reads, no remote-mutating git without \
         explicit approval.\n\n\
         **If you are sandboxed:** `EPERM` / `Operation not permitted` is a \
         deliberate policy deny, not a transient error — don't retry or search \
         for a workaround. Report it to the user with the exact command and \
         path; they can adjust the sandbox config (e.g. `cplt trust`, \
         `allow.read`/`allow.write`).\n\
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
    /// File has a hand-written "## Sandbox" section but no managed block;
    /// a one-line pointer was appended beneath that heading instead of
    /// inserting the full block, to avoid stomping user content.
    PointerAppended,
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
/// - No markers, but a hand-written `## Sandbox` heading exists → don't
///   touch it; append a one-line pointer directly beneath the heading.
/// - No markers, no hand-written heading → append the block at EOF.
pub fn upsert_managed_block(path: &Path) -> Result<BlockOutcome, String> {
    let block = managed_block();

    let Ok(existing) = std::fs::read_to_string(path) else {
        std::fs::write(path, format!("{block}\n"))
            .map_err(|e| format!("cannot write {}: {e}", path.display()))?;
        return Ok(BlockOutcome::Created);
    };

    let begin_count = existing.matches(BLOCK_BEGIN).count();
    let end_count = existing.matches(BLOCK_END).count();

    if begin_count > 1 || end_count > 1 || begin_count != end_count {
        return Ok(BlockOutcome::SkippedAmbiguous);
    }

    if begin_count == 1 {
        let start = existing.find(BLOCK_BEGIN).unwrap();
        let end = existing.find(BLOCK_END).unwrap() + BLOCK_END.len();
        if end < start {
            // END appears before BEGIN — malformed, refuse.
            return Ok(BlockOutcome::SkippedAmbiguous);
        }
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

    // No managed markers. Check for a hand-written "## Sandbox" heading.
    if let Some(heading_pos) = existing
        .lines()
        .position(|l| l.trim_start().starts_with(HAND_WRITTEN_HEADING_PREFIX))
    {
        let pointer =
            "\n> cplt: see https://github.com/navikt/cplt for sandboxed-agent guidance.\n";
        let mut lines: Vec<&str> = existing.lines().collect();
        lines.insert(heading_pos + 1, pointer);
        let mut new_content = lines.join("\n");
        if existing.ends_with('\n') {
            new_content.push('\n');
        }
        std::fs::write(path, new_content)
            .map_err(|e| format!("cannot write {}: {e}", path.display()))?;
        return Ok(BlockOutcome::PointerAppended);
    }

    // Plain append at EOF.
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
            pass_env: Vec::new(),
            inherit_env: false,
            allow_lifecycle_scripts: false,
            allow_gpg_signing: false,
            deny_clipboard: false,
            allow_jvm_attach: false,
            gradle_init: false,
            allow_docker: false,
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
    fn brief_always_warns_ssh_blocked() {
        let resolved = base_resolved();
        let brief = generate_session_brief(&resolved, Agent::Claude);
        assert!(brief.contains("SSH is blocked"));
    }

    #[test]
    fn managed_block_has_matching_markers() {
        let block = managed_block();
        assert!(block.starts_with(BLOCK_BEGIN));
        assert!(block.ends_with(BLOCK_END));
        assert!(block.contains("__CPLT_WRAPPED"));
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
    fn upsert_preserves_hand_written_section_and_appends_pointer() {
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
        assert_eq!(outcome, BlockOutcome::PointerAppended);
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("We run our own custom sandbox setup."));
        assert!(
            !content.contains(BLOCK_BEGIN),
            "must not stomp hand-written section"
        );
        assert!(content.contains("cplt: see"));

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
}

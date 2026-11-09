# xrepo-review — design spec (contract for all modules)

Policy-gated, cross-repo PR review that runs **inside the official `anthropics/claude-code-action@v1`**.
The agent (Claude) gets exactly two MCP servers and nothing else:

| Server | Process | Network | Secrets | Writes |
|---|---|---|---|---|
| `xsearch` (code search) | `xrepo search-mcp` | none (`docker --network none`) | none | none (all mounts read-only) |
| `xreview` (review actions) | `xrepo review-mcp` | none | none | appends to one draft file |

A **deterministic publisher** (`xrepo publish`, no AI) runs in a *separate job* with the only
GitHub write token, validates the draft against the policy, and posts to GitHub.
The **policy manifest** (YAML) lives outside any PR-controlled checkout (runner host path or a
devops-owned repo) and is never mounted into the agent's reachable file roots.

## Threat model (what each layer guarantees)

- T1 Prompt injection (PR text, code in any repo) makes the agent try a disallowed action
  → disallowed tools are not *registered* (agent never sees them); the review job's GitHub token is
  read-only; the publisher re-validates everything against the policy.
- T2 Agent tries to read/modify the policy → the agent has no built-in file/shell tools; the search
  MCP only serves configured roots; the policy file is never under those roots.
- T3 Exfiltration of other repos' code / secrets via review comments → per-PR-repo cross-repo
  read allowlist enforced in the search MCP; path denylist; secret redaction on search output and
  again on publish; publisher neutralises markdown images, non-allowlisted links and @mentions.
- T4 0day in the search MCP → no network, no secrets, read-only mounts, non-root, read-only rootfs,
  all capabilities dropped. Worst case it reads what it could already read.
- T5 PR modifies `.claude/settings.json` / `.mcp.json` / hooks in its own checkout → Claude Code's
  working directory is a clean, trusted directory created by `prepare`; the PR checkout lives in a
  sub-directory that is only reachable through the search MCP.

## Directory layout

```
src/
  cli.ts                     # `xrepo <cmd>` dispatcher: search-mcp | review-mcp | prepare | publish | sync | policy
  policy/schema.ts           # zod schema + TS types for the manifest (SHARED CONTRACT — do not break)
  policy/load.ts             # loadPolicy(path) -> Policy; resolvePolicy(policy, repoFullName) -> ResolvedPolicy
  policy/glob.ts             # matchAny(globs, path) helpers (picomatch, dot:true)
  common/redact.ts           # redactSecrets(text) -> {text, count}
  common/audit.ts            # audit(event, fields) -> JSON line on stderr (+ optional file)
  common/draft.ts            # Draft schema (zod) shared by review-mcp and publisher
  search/vfs.ts              # virtual paths (/pr, /repos/o/n) <-> host paths; containment checks
  search/rg.ts               # ripgrep runner (spawn, no shell, timeout)
  search/server.ts           # MCP server: ListRepos, PrDiff, Grep, Glob, Read
  review/server.ts           # MCP server registering xreview tools (filtered by policy)
  prepare/prepare.ts         # writes workdir: .mcp config, claude_args, prompt, pr context
  publish/publish.ts         # validate draft vs policy -> GitHub API calls (or --dry-run plan)
  publish/github.ts          # thin Octokit wrapper (interface so tests can fake it)
  outcome/classify.ts        # outcome classification (usage_limit / error / incomplete / ...)
  outcome/template.ts        # message templates with per-channel escaping
  outcome/notify.ts          # Slack / webhook notifications
  outcome/dispatch.ts        # repository_dispatch
  outcome/retry.ts           # `xrepo retry` sweeper (re-runs postponed reviews)
  sync/sync.ts               # mirror sync (clone/fetch, atomic swap, meta.json)
test/                        # vitest; fixtures under test/fixtures
docker/Dockerfile            # node + ripgrep + git, non-root, CLI baked in
.github/workflows/review.yml # reusable workflow (workflow_call): review job + publish job
.github/workflows/sync.yml   # scheduled mirror sync on the self-hosted runner
examples/policy.yaml         # fully commented example manifest
examples/caller.yml          # what each repo adds (calls the reusable workflow)
docs/SECURITY.md, README.md
```

## On-disk layout (runner)

```
/srv/xrepo/mirror/<owner>/<repo>/current -> snapshots/<sha>   # symlink, atomically swapped
/srv/xrepo/mirror/<owner>/<repo>/snapshots/<sha>/              # shallow working tree (no .git creds)
/srv/xrepo/mirror/<owner>/<repo>/meta.json                     # {repo, sha, branch, synced_at, description}
/etc/xrepo-review/policy.yaml                                  # root-owned, read-only to runner
```

Per review (job workspace, created by `prepare`):
```
$WORK/agent/            # Claude Code cwd: only trusted generated files (no PR content)
$WORK/agent/mcp.json    # MCP config for xsearch + xreview
$WORK/ctx/pr.json       # PR context (repo, number, base/head sha, title, author, files[])
$WORK/ctx/diff.patch    # unified diff base...head (zero context lines not required; use -U3)
$WORK/ctx/policy.resolved.json  # resolved policy for THIS repo (read by MCP servers, not by agent)
$WORK/out/draft.jsonl   # the ONLY file xreview writes
$PR_CHECKOUT            # PR head checkout (actions/checkout path), served as /pr
```
The MCP servers receive file paths only via CLI args written by `prepare` (trusted), never from
tool arguments.

## xsearch: Claude Code's Grep / Glob / Read, made multi-repo

Design rule (user decision): give the agent the tools it already knows. Claude Code navigates code
with Grep (ripgrep), Glob and Read; Codex with `rg`, `rg --files`, `sed -n`. xsearch exposes the same
three tools with Claude Code's exact names, parameter names, defaults and output formats, plus two
small tools the review needs (`ListRepos`, `PrDiff`). No symbol indexes, no ctags, no ast-grep, no
repo maps, no clever ranking. Security limits stay (they are invisible to a well-behaved agent).

### Virtual paths — how "multi-repo" is expressed

Every path the agent sees or passes is an absolute virtual path:
- `/pr/<path>` — the PR head checkout of the repository under review;
- `/repos/<owner>/<name>/<path>` — the mirrored default-branch snapshot of each repo this PR's repo
  may read (policy `cross_repo`). The PR repo's own base branch is `/repos/<its owner>/<its name>/`
  when it is mirrored.
Choosing a repo is choosing a `path` (e.g. `Grep {pattern, path: "/repos/acme/api"}`), exactly like
Claude Code's `path` parameter. Every tool prints virtual paths so results can be passed straight to
Read. Anything outside `/pr` and the readable `/repos/*` does not exist (ENOENT-style error listing
the valid roots). Unreadable repos are never listed, not even their names.

### Tools (MCP names `mcp__xsearch__<Name>`; all output is plain text)

1. `ListRepos()` — like `ls` of the roots:
   ```
   /pr                 acme/web  PR #42  head 1a2b3c4 base 9f8e7d6  5 files changed
   /repos/acme/api     4d5e6f7  synced 3m ago  Orders API
   /repos/acme/web     9f8e7d6  synced 3m ago  (base branch of this PR)
   ```
2. `PrDiff({file_path?, offset?, limit?})` — no file_path: changed files, one per line
   `M  +12 -3  /pr/src/orders.ts` (A/M/D/R, renames `old -> new`); with file_path (`/pr/...`): that
   file's unified diff (`-U3`), hunk headers keep new-side line numbers; offset/limit window long
   diffs by line like Read. Denied files: `[content hidden by policy]`.
3. `Grep({pattern, path?, glob?, type?, output_mode?, "-i"?, "-n"?, "-A"?, "-B"?, "-C"?, context?,
   multiline?, head_limit?, offset?})` — Claude Code semantics. `path` (file or directory) defaults to
   all roots (`/pr` + every readable `/repos/...`). `output_mode`: `files_with_matches` (default),
   `content`, `count`. `-n` default true in content mode. `head_limit` default 250 (0 = no limit,
   still capped by max_output_chars), `offset` skips that many entries first. Output:
   files_with_matches → one virtual path per line; content → ripgrep style `path:line:text`, context
   lines `path-line-text`, groups separated by `--`; count → `path:N`. When head_limit cut results,
   append `[Showing results with pagination = limit: 250, offset: 0]` (same wording as Claude Code).
   Lines longer than 500 chars are cut with `… [line truncated]`.
4. `Glob({pattern, path?})` — matching files as virtual paths, sorted by path, max 100 then
   `(Results are truncated. Consider using a more specific path or pattern.)`.
5. `Read({file_path, offset?, limit?})` — `cat -n` format (right-aligned line number, tab, text),
   offset = first line (1-based), default limit = policy.search.max_read_lines (default 2000, Claude
   Code's default), lines longer than 2000 chars truncated. File bigger than max_filesize → error
   telling the agent to use offset/limit or Grep (as Claude Code does). Directory → error suggesting
   Glob. Binary → `[binary file]`.

Implementation: ripgrep spawned without a shell (`stdio[0]='ignore'`, explicit paths, `--no-config`,
`--no-follow`, `--hidden` + `--glob !.git`, deny/exclude globs as `--glob !…`, `--max-filesize`,
`--` before patterns / `-e`), one rg process over all target roots, timeout from policy. Output
rewritten from host paths to virtual paths. Every response capped at policy.search.max_output_chars
(default 30000, like Claude Code's tool output cap) with a one-line truncation note. redactSecrets on
all output. `exclude_globs` (lockfiles, minified, vendored) are skipped by Grep/Glob unless `path`/
`glob` explicitly targets them — the same effect ripgrep's .gitignore handling has in Claude Code.

Tool descriptions: short, written like Claude Code's own (what it does, key params, "use Grep to find
then Read with offset/limit"), plus one line on virtual paths. Errors say what to do next.

### Tool loading (no deferral)

Claude Code can defer MCP tools behind its built-in ToolSearch tool. Our agent has no built-in tools
(`--tools ""`), which the CLI research verified makes MCP tools load as normal, non-deferred tools.
Belt and braces, required in code:
- every xsearch and xreview tool is registered with `_meta: {"anthropic/alwaysLoad": true}`;
- prepare never adds `ToolSearch` to `--tools` / `--allowedTools`, even if policy.agent.builtin_tools
  is set;
- the integration test asserts, from the real Claude run's stream-json `system/init` message and
  tool_use blocks, that our tools were called directly (no ToolSearch call, no "No such tool" errors).

## xreview tools (registered only if the capability is enabled)

All writes append one JSON object per line to the draft file (schema in `src/common/draft.ts`).
Tool-time checks mirror the publisher (so the agent gets immediate feedback), but the publisher is
the source of truth.

- `add_comment({path, line, end_line?, body, severity, category?, suggestion?})` — inline comment on
  the PR's RIGHT side. `severity ∈ {info, low, medium, high, critical}`. `suggestion` only if
  `capabilities.inline_comments.suggestions`. Rejected if path not in PR files or count ≥ max.
- `set_summary({body})` — overall review body (last call wins). If `summary_comment.enabled`.
- `set_verdict({verdict, reason})` — `verdict` enum = only the allowed values among
  `comment | approve | request_changes`. Last call wins.
- `add_labels({labels[]})` — enum = `capabilities.labels.allowed`.
- `finish()` — marks the draft complete (publisher refuses incomplete drafts unless policy allows).

## Publisher rules (deterministic; `xrepo publish`)

Input: resolved policy, PR context, draft.jsonl, GitHub token (env). Steps:
1. Parse draft lines with zod; drop invalid lines (audit). Enforce max sizes.
2. Inline comments: path must be a changed file; line must fall inside a RIGHT-side diff hunk
   (computed from diff.patch); otherwise demote to the summary "Notes outside the diff" list.
   Drop below `inline_comments.min_severity`; sort by severity; cap at `max_comments`; dedupe by
   (path,line,body hash); truncate body to `max_comment_chars`.
3. Sanitize every outgoing text: redactSecrets; neutralize `@mentions` (`@` → `@​`) unless
   `output.allow_mentions`; remove markdown images; replace links whose host is not in
   `output.link_allowlist` with plain text; strip HTML tags except the hidden marker.
4. Verdict resolution (downgrade to `comment` when a rule fails, recording why in the summary footer):
   - `approve` requires: capability enabled; no findings ≥ `approve.max_severity_allowed`;
     no changed file matches `approve.never_paths`; changed lines ≤ `approve.max_changed_lines`.
   - `request_changes` requires: capability enabled; at least one finding ≥ `block.min_severity`.
5. Blocking: `block.method` ∈ `review` (REQUEST_CHANGES review) | `check` (check-run with
   conclusion `failure`) | `both`. If `check` is configured, a check-run named `check.name` is
   always created with `success|neutral|failure`.
6. Summary: sticky issue comment identified by `<!-- xrepo-review:sticky -->` (update in place) or
   review body, per `summary_comment.mode` (`sticky` | `review`).
7. Labels: only allowed ones.
8. `--dry-run` prints the full plan as JSON and makes no API calls. Every decision is audited.

## Outcomes, notifications, retries, workflow chaining

Schema: `outcomes`, `OutcomeActions`, `DEFAULT_OUTCOMES`, `notifications` in `src/policy/schema.ts`.
`resolvePolicy` deep-merges DEFAULT_OUTCOMES <- defaults.outcomes <- repos[x].outcomes per outcome
(arrays replace) and copies `notifications` into the resolved policy.

Module `src/outcome/` (no AI, runs in the publish job):
- `classify.ts`: `classifyOutcome(input:{skipped?:{reason:string}, agentStepOutcome?: 'success'|'failure'|'cancelled'|'skipped'|string, executionFileText?: string, draft?: Draft}): {outcome: 'completed'|'incomplete'|'usage_limit'|'error'|'skipped', reason: string, reset_at?: string}`.
  Order: skipped → usage_limit (execution file result/error text or any assistant/system message
  matching usage-limit/rate-limit/429/quota/overloaded/credit-balance patterns; parse reset time:
  `limit reached|<epoch>` → ISO, `resets <text>` → raw text) → completed (draft.finished) →
  incomplete (draft has entries or result subtype `error_max_turns`) → error (reason from step outcome
  / result subtype / "no output"). Robust to execution_file being a JSON array, JSON lines, or absent.
- `template.ts`: `renderTemplate(tpl, vars, escape: (s)=>string)`; unknown placeholders left
  literally; values escaped per channel (markdown → sanitizeMarkdown rules, slack → `&<>` escaped,
  `<!`/`@` neutralized, length capped). `{reset_at_suffix}` = ` (resets <reset_at>)` or "".
- `notify.ts`: `sendNotifications(refs, targets, vars, secrets, fetchImpl?)` → Slack incoming webhook
  `{text}` / generic webhook JSON `{event:'xrepo-review', outcome, repo, pr_number, pr_url, verdict,
  reason, reset_at, findings, top_severity, run_url, attempt, message}` with optional HMAC header.
  Secrets bundle = JSON object from env `XREPO_NOTIFY_SECRETS`, else file
  `/etc/xrepo-review/notify.json` (path overridable by flag). Only https URLs; timeouts; failures
  are audited and never fail the publish.
- `dispatch.ts`: repository_dispatch with token env `XREPO_DISPATCH_TOKEN` (fallback GITHUB_TOKEN only
  when target repo == PR repo); client_payload ≤ 10 top-level keys.
- `retry.ts`: `xrepo retry` sweeper (central scheduled workflow, GitHub App token with actions:write,
  pull-requests:write): for each open PR carrying a retry label in the policy's repos, find the latest
  run of the review workflow for that PR's head sha; if `run_attempt < max_attempts` re-run it
  (POST /actions/runs/{id}/rerun); else remove the label and comment once.

Publisher flow with outcomes (`xrepo publish`): extra flags `--agent-outcome`, `--execution-file`,
`--skip-reason`, `--run-url`, `--run-attempt`, `--github-output`. Steps: classify → if completed or
incomplete, build/execute the review plan (incomplete never approves/blocks) → derive extra outcomes
`approved`/`blocked` from the executed plan → for each fired outcome (primary first, then
approved/blocked): post `comment` (into the sticky comment; a completed review's summary stays primary
and outcome comments are appended), set check conclusion (outcome override wins over the plan's
default only for non-completed outcomes; for completed the plan decides unless configured),
add/remove labels, notify, dispatch, retry labelling (`retry.enabled` and run_attempt <
max_attempts → add retry label; on `completed` always remove any configured retry labels) → write
step outputs `outcome, verdict, reason, reset_at, findings, top_severity` → exit 1 only if a fired
outcome has `fail_job: true` (or on infrastructure failure of required API calls).

Workflow chaining: `review.yml` exposes those outputs as `on.workflow_call.outputs`, so callers add
jobs like `if: needs.review.outputs.outcome == 'usage_limit'`. The claude-code-action step uses
`continue-on-error: true`; the publish job runs `if: always()` (unless the run was cancelled) and gets
the action's outcome + execution file via the artifact.

Accounts: the reusable workflow reads `CLAUDE_CODE_OAUTH_TOKEN` (or `ANTHROPIC_API_KEY`) via
`secrets: inherit`; per-group accounts = org secrets with the same name scoped to repo groups, or an
optional `account` input selecting `CLAUDE_CODE_OAUTH_TOKEN_<ACCOUNT>`. No automatic failover between
personal subscriptions (terms risk) — documented in README.

## prepare (`xrepo prepare`)

Inputs (flags): `--policy`, `--repo owner/name`, `--pr N`, `--base-sha`, `--head-sha`,
`--pr-checkout DIR`, `--mirror DIR`, `--work DIR`, `--event PATH` (GitHub event JSON for title,
body, author, draft flag, fork flag), `--launcher docker|local`, `--image IMG`.
Outputs files under `--work` (see layout) and prints GitHub step outputs (`claude_args`, `prompt`,
`skip`, `skip_reason`) to `$GITHUB_OUTPUT` when set (multiline-safe heredoc delimiters).
- Skip rules from policy (`triggers`): drafts, forks, bots, title markers (`[skip review]`),
  max changed files/lines, ignored authors, `enabled: false` kill switch.
- Computes diff with `git -C <pr-checkout> diff --no-color -U3 <base>...<head>` (fetch depth
  must allow it; falls back to `git diff base head`).
- MCP config `mcp.json`: two stdio servers. `launcher=docker` wraps each in
  `docker run --rm -i --network none --read-only --cap-drop ALL --security-opt no-new-privileges
  --user 65534:65534 --tmpfs /tmp ... -v <mirror>:/mirror:ro -v <pr>:/pr:ro -v <ctx>:/ctx:ro
  [-v <out>:/out for xreview only] <image> <subcommand> <args>`; `launcher=local` runs
  `node <dist>/cli.js ...` directly (dev/tests).
- `claude_args` = `--mcp-config <work>/agent/mcp.json --strict-mcp-config
  --allowedTools <exact mcp__xsearch__* and mcp__xreview__* tool names>
  --disallowedTools <all built-ins: Bash Edit Write MultiEdit NotebookEdit Read Grep Glob LS
  WebFetch WebSearch Task TodoWrite ...> --model <policy.agent.model> --max-turns <n>`
  (exact flags subject to the verified CLI reference in docs/RESEARCH.md).
- Prompt = trusted template + policy `agent.instructions` + per-repo `related` dependency map +
  capability summary + PR overview (untrusted text fenced and labelled as data).

## sync (`xrepo sync`)

`--policy`, `--mirror DIR`, token from env `XREPO_GITHUB_TOKEN` (GitHub App installation token).
For each repo in `policy.mirror.repos` (explicit list; globs `org/*` resolved via API if allowed):
shallow fetch default branch into a new snapshot dir using a per-command auth header
(`git -c http.extraHeader=...`), never persisting credentials; remove `.git` remote URL creds;
delete `.git` from the snapshot; write meta.json; atomically swap `current` symlink (rename of a temp symlink); keep last N snapshots
(default 2) and delete older ones. Concurrency-safe with a lock file.

## Non-goals (v1)

Writing code / pushing commits; reviewing fork PRs; non-GitHub hosts.

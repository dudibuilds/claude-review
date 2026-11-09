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
  search/roots.ts            # repo roots registry: mirror repos + "@pr"; safe path resolution
  search/rg.ts               # ripgrep runner (spawn, no shell, timeout, --json parsing)
  search/ctags.ts            # ctags index load/query (JSON lines), outline, symbol ranges
  search/format.ts           # compact text formatting + output budget/truncation
  search/server.ts           # MCP server registering xsearch tools
  review/server.ts           # MCP server registering xreview tools (filtered by policy)
  prepare/prepare.ts         # writes workdir: .mcp config, claude_args, prompt, pr context
  publish/publish.ts         # validate draft vs policy -> GitHub API calls (or --dry-run plan)
  publish/github.ts          # thin Octokit wrapper (interface so tests can fake it)
  outcome/classify.ts        # outcome classification (usage_limit / error / incomplete / ...)
  outcome/template.ts        # message templates with per-channel escaping
  outcome/notify.ts          # Slack / webhook notifications
  outcome/dispatch.ts        # repository_dispatch
  outcome/retry.ts           # `xrepo retry` sweeper (re-runs postponed reviews)
  sync/sync.ts               # mirror sync (clone/fetch, atomic swap, ctags index, meta.json)
test/                        # vitest; fixtures under test/fixtures
docker/Dockerfile            # node + ripgrep + universal-ctags, non-root, CLI baked in
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
/srv/xrepo/mirror/<owner>/<repo>/meta.json                     # {repo, sha, branch, synced_at}
/srv/xrepo/mirror/<owner>/<repo>/tags.jsonl                    # ctags JSON index for `current`
/etc/xrepo-review/policy.yaml                                  # root-owned, read-only to runner
```

Per review (job workspace, created by `prepare`):
```
$WORK/agent/            # Claude Code cwd: only trusted generated files (no PR content)
$WORK/agent/mcp.json    # MCP config for xsearch + xreview
$WORK/ctx/pr.json       # PR context (repo, number, base/head sha, title, author, files[])
$WORK/ctx/diff.patch    # unified diff base...head (zero context lines not required; use -U3)
$WORK/ctx/policy.resolved.json  # resolved policy for THIS repo (read by MCP servers, not by agent)
$WORK/ctx/tags.pr.jsonl # ctags index for the PR checkout
$WORK/out/draft.jsonl   # the ONLY file xreview writes
$PR_CHECKOUT            # PR head checkout (actions/checkout path), served as repo "@pr"
```
The MCP servers receive file paths only via CLI args written by `prepare` (trusted), never from
tool arguments.

## Repo identifiers inside tools

- `@pr` = the PR head checkout of the repo under review.
- `owner/name` = a mirror repo (default branch snapshot). The PR repo's base branch is also
  available as its `owner/name` if it is in the mirror.
- Paths are repo-relative POSIX paths. Absolute paths, `..` segments, NUL bytes, backslashes and
  anything resolving (after realpath) outside the repo root are rejected. `.git/` is always denied.

## xsearch tools (token-efficient by design)

All tools return **plain text**, not JSON. Every response respects `policy.search.max_output_chars`
(default 12000); when truncated, the last line says what was dropped and how to narrow
(e.g. `… 214 more matches in 37 files — narrow with path_glob or repos, or use page=2`).
Lines longer than `max_line_chars` (default 240) are cut with `…`. All output passes `redactSecrets`.
Denied paths (policy.search.deny_globs) are invisible: never listed, matched, or readable.
Default excluded globs (policy.search.exclude_globs: vendored, lockfiles, minified, generated) are
skipped by search/find unless the call explicitly targets that path.

1. `list_repos()` → one line per readable repo: `owner/name  sha7  synced 2h ago  — description`
   (plus `@pr  head=sha7 base=sha7  <N files changed>`).
2. `pr_overview()` → title, author, base/head, and changed files with `+adds -dels status`, one per line.
3. `pr_diff({path?, max_lines?})` → unified diff hunks for one file (or all, budgeted).
4. `search({pattern, literal?=false, case_sensitive?=false, repos?, path_glob?, file_type?,
   context?=0..5 (default 1), mode?='content'|'files'|'count', max_matches?=50, page?=1})`
   → ripgrep across allowed repos. Content mode output, grouped by file:
   ```
   ## owner/repo:path/to/file.ts
   41-  const x = 1
   42:  createOrder(x)
   ```
   Overlapping context ranges merge. `repos` defaults to all readable repos incl. `@pr`.
5. `find_files({glob, repos?, max_results?=100})` → matching paths (like fd), grouped by repo.
6. `tree({repo, path?='', depth?=2})` → compact directory tree; dirs suffixed `/`, child counts
   shown for truncated dirs.
7. `read_file({repo, path, start_line?, end_line?})` → numbered lines `N\ttext`; default window
   `policy.search.max_read_lines` (default 250). Header: `owner/repo:path (lines a-b of total)`.
   If more remains, footer says how to continue.
8. `outline({repo, path})` → symbols in a file from ctags: `kind name  Lstart-Lend  (scope)`.
   Falls back to a regex heuristic for common languages if no tags.
9. `find_symbol({name, kind?, repos?, max_results?=20})` → definitions across repos:
   `owner/repo:path:line  kind  name  (scope)` using ctags indexes (exact name, then prefix).
10. `read_symbol({repo, path?, name})` → the full source of a symbol using ctags start/end lines
    (capped by max_read_lines, with numbered lines). If ambiguous, lists candidates.
11. `find_references({name, repos?, path_glob?, max_matches?=50})` → word-boundary search
    (`\bname\b`, fixed-string aware) excluding the definition lines, grouped by repo/file, context 0.

ripgrep is always spawned without a shell, with `--json` (or `--files`), `--no-config`,
`--max-columns`, `--max-filesize` (policy, default 1M), `--hidden` + explicit `--glob !.git`,
`--no-follow`, deny/exclude globs as `--glob !...`, a hard timeout (policy.search.timeout_ms,
default 8000) and `--` before the pattern. Rust regex is linear-time (no ReDoS); pattern length
capped at 512.

### Tool loading (no deferral)

Claude Code can defer MCP tools behind its built-in ToolSearch tool. Our agent has no built-in tools
(`--tools ""`), which the CLI research verified makes MCP tools load as normal, non-deferred tools.
Belt and braces, required in code:
- every xsearch and xreview tool is registered with `_meta: {"anthropic/alwaysLoad": true}`;
- prepare never adds `ToolSearch` to `--tools` / `--allowedTools`, even if policy.agent.builtin_tools
  is set;
- the integration test asserts, from the real Claude run's stream-json `system/init` message and
  tool_use blocks, that our tools were called directly (no ToolSearch call, no "No such tool" errors).

### Design rule: Claude Code's search model, made multi-repo

Claude Code navigates code with three tools — Grep (ripgrep), Glob, Read (line windows) — and Codex
with plain `rg` / `rg --files` / `sed -n` under a per-call output-token cap. Models are trained on
exactly that loop. xsearch therefore keeps those three as the core, with the same parameter names and
defaults (`pattern`, `glob`, `type`, `output_mode` default files_with_matches, `-i`, `-A/-B/-C`
default 0, `head_limit`, `offset`; Read `offset`/`limit`, `N\t` numbered lines), adds a `repos`
filter and `repo:path` grouping, and adds only tools that measurably cut reads (outline, symbol body,
references, PR map). Any tool the real end-to-end runs show the agent does not use, or uses wrongly,
is removed rather than kept "just in case". Errors always say what to do next.

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
  must allow it; falls back to `git diff base head`). Builds ctags index for the PR checkout.
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
build `tags.jsonl` with `ctags -R --output-format=json --fields=+nKSse --extras=-F`; write
meta.json; atomically swap `current` symlink (rename of a temp symlink); keep last N snapshots
(default 2) and delete older ones. Concurrency-safe with a lock file.

## Non-goals (v1)

Writing code / pushing commits; reviewing fork PRs; non-GitHub hosts.

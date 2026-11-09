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
  cli.ts                     # `xrepo <cmd>` dispatcher: search-mcp | review-mcp | prepare | collect | publish | sync | retry | policy
  policy/schema.ts           # zod schema + TS types for the manifest (SHARED CONTRACT — do not break)
  policy/load.ts             # loadPolicy(path) -> Policy; resolvePolicy(policy, repoFullName) -> ResolvedPolicy
  policy/glob.ts             # compileGlobs(globs) (picomatch, dot:true); owner/name repo patterns
  common/redact.ts           # redactSecrets(text) -> {text, count}; PEM block rules shared with search/text.ts
  common/audit.ts            # audit(event, fields) -> JSON line on stderr (+ optional file)
  common/draft.ts            # Draft schema (zod) shared by review-mcp and publisher
  common/args.ts             # strict CLI flag parsing (node:util parseArgs)
  common/context.ts          # PR context in ctx/ (written by prepare, read by both servers and the publisher)
  common/diff.ts             # unified diff parser, RIGHT-side commentable lines
  common/mcp.ts              # ALWAYS_LOAD_META (`anthropic/alwaysLoad`)
  search/vfs.ts              # virtual paths (/pr, /repos/o/n) <-> host paths; containment checks
  search/rg.ts               # ripgrep runner (spawn, no shell, timeout)
  search/safeglob.ts         # linear-time glob matcher for agent-supplied globs
  search/text.ts             # output helpers: line-preserving redaction, PEM blocks, line / output caps
  search/tools.ts            # ListRepos, PrDiff, Grep, Glob, Read implementations
  search/server.ts           # MCP server: ListRepos, PrDiff, Grep, Glob, Read
  review/rules.ts            # verdict / budget rules shared by xreview, prepare's prompt and the publisher
  review/server.ts           # MCP server registering xreview tools (filtered by policy)
  prepare/prepare.ts         # writes workdir: .mcp config, claude_args, prompt, pr context; `xrepo collect`
  publish/publish.ts         # validate draft vs policy -> GitHub API calls (or --dry-run plan)
  publish/plan.ts            # deterministic review plan (comments, verdict, check, summary)
  publish/sanitize.ts        # markdown sanitiser for every outgoing text
  publish/github.ts          # thin Octokit wrapper (interface so tests can fake it)
  outcome/classify.ts        # outcome classification (usage_limit / error / incomplete / ...)
  outcome/template.ts        # message templates with per-channel escaping
  outcome/notify.ts          # Slack / webhook notifications
  outcome/dispatch.ts        # repository_dispatch
  outcome/retry.ts           # `xrepo retry` sweeper (re-runs postponed reviews)
  outcome/reset.ts           # usage-limit reset time -> retry-after time
  outcome/api-base.ts        # GITHUB_API_URL validation (one implementation for every command)
  sync/sync.ts               # mirror sync (clone/fetch, atomic swap, meta.json)
test/                        # vitest (<area>.test.ts; fixtures are built in temporary directories)
docker/Dockerfile            # node + ripgrep + git, non-root, CLI baked in
.github/workflows/review.yml # reusable workflow (workflow_call): review job + publish job
.github/workflows/sync.yml   # scheduled mirror sync on the self-hosted runner (one job per owner)
.github/workflows/retry.yml  # scheduled `xrepo retry` sweeper (one job per owner)
.github/workflows/mirror-cache.yml # hosted mode: warms the default-branch mirror cache
.github/workflows/ci.yml, e2e.yml  # CI of this repository; real-agent end-to-end test (hosted mode)
examples/policy.yaml         # fully commented example manifest
examples/caller.yml          # what each repo adds (calls the reusable workflow)
examples/caller-hosted.yml, caller-with-hooks.yml   # hosted mode; follow-up jobs on the outputs
e2e/                         # fixture repositories + policy for e2e.yml and test/e2e.test.ts
docs/SECURITY.md, docs/TOOLS.md, docs/RESEARCH.md, docs/E2E-LOCAL.md, README.md
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
$WORK/ctx/pr.json       # PR context (repo, number, base sha, full 40-hex head sha, title, author, files[])
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
  when it is mirrored. Repository names may start with "." (`acme/.github`); owners may not.
Choosing a repo is choosing a `path` (e.g. `Grep {pattern, path: "/repos/acme/api"}`), exactly like
Claude Code's `path` parameter. Every tool prints virtual paths so results can be passed straight to
Read. Anything outside `/pr` and the readable `/repos/*` does not exist (ENOENT-style error listing
the valid roots). Unreadable repos are never listed, not even their names.

### Tools (MCP names `mcp__xsearch__<Name>`; all output is plain text)

1. `ListRepos({offset?, limit?})` — like `ls` of the roots:
   ```
   /pr                 acme/web  PR #42  head 1a2b3c4 base 9f8e7d6  5 files changed
   /repos/acme/api     4d5e6f7  synced 3m ago  Orders API
   /repos/acme/web     9f8e7d6  synced 3m ago  (base branch of this PR; searched only when passed as path)
   ```
   offset (1-based row) / limit page through a long list like PrDiff's file list; a cut list ends
   with `[Showing roots 1-N of M. Use offset: N+1 to see more.]`.
2. `PrDiff({file_path?, offset?, limit?})` — no file_path: changed files, one per line
   `M  +12 -3  /pr/src/orders.ts` (A/M/D/R, renames `old -> new`; a type change such as symlink →
   file is one `M` entry: git's deletion and addition sections of the same path are merged); with
   file_path (`/pr/...`): that file's unified diff (`-U3`), hunk headers keep new-side line numbers;
   offset/limit window long diffs by line like Read. Denied files: `[content hidden by policy]`.
   Redaction is per diff line (one output line per diff line): context and added lines inside a
   private-key block of the PR's version of the file (whole-file scan) are hidden, key blocks are
   also looked for on both sides of every hunk, and removed lines that look like key material are
   hidden when the hunk touches a key (the base version of the file is not available to xsearch).
3. `Grep({pattern, path?, glob?, type?, output_mode?, "-i"?, "-n"?, "-o"?, "-A"?, "-B"?, "-C"?,
   context?, multiline?, head_limit?, offset?})` — Claude Code semantics. `path` (file or directory)
   defaults to `/pr` + every readable `/repos/...` except the PR repo's own base snapshot, which
   would only repeat `/pr`; it is searched when passed explicitly as `path` (an empty result for
   `/repos` or `/repos/<owner>` says so). `-o` prints only the matched parts (a match on a line
   that holds a secret prints the whole redacted line instead). `output_mode`: `files_with_matches` (default),
   `content`, `count`. `-n` default true in content mode. `head_limit` default 250 (0 = no limit,
   still capped by max_output_chars), `offset` skips that many entries first. Output:
   files_with_matches → one virtual path per line; content → ripgrep style `path:line:text`, context
   lines `path-line-text`, groups separated by `--`; count → `path:N`. When head_limit cut results,
   append `[Showing results with pagination = limit: 250, offset: 0]` (same wording as Claude Code).
   Lines longer than 500 chars are cut with `… [line truncated]`. `offset` above 20000 is an error;
   so is a `glob` written as a virtual path (`/pr/...`, `/repos/...`: globs are relative to `path`),
   unless the searched directory really has such a top-level folder.
4. `Glob({pattern, path?})` — matching files as virtual paths, sorted by path, max 100 then
   `(Results are truncated. Consider using a more specific path or pattern.)`. Same default roots
   as Grep; an absolute pattern is a virtual path anchored at its root (it ignores `path`). A
   pattern that names a directory (only literal segments, or one that only matches repository
   roots such as `/repos/*/*`) is an error suggesting `X/**/*` and `X/*`. Agent globs are matched by
   a linear-time matcher (`search/safeglob.ts`, ripgrep's glob rules, at most 64 `{…}` expansions),
   never by a backtracking regex.
5. `Read({file_path, offset?, limit?})` — `cat -n` format (right-aligned line number, tab, text),
   offset = first line (1-based), default limit = policy.search.max_read_lines (default 2000, Claude
   Code's default), lines longer than 2000 chars truncated. File bigger than max_filesize → error
   telling the agent to use offset/limit or Grep (as Claude Code does). Directory → error listing
   its direct entries (sub-directories first, at most 100, hidden ones left out) with an anchored
   Glob example. Binary → `[binary file]`; Grep reports such a file as `binary file matches`
   (ripgrep runs with `--encoding=none`, so a UTF-16 file keeps its NUL bytes and is binary in both).

Every tool's input schema is strict: an unknown parameter is an error that names the right one
(e.g. `limit` → `head_limit`, `include` → `glob`, `start_line` → `offset`).

Implementation: ripgrep spawned without a shell (`stdio[0]='ignore'`, explicit paths, `--no-config`,
`--no-follow`, `--hidden` + `--glob !.git`, deny globs as `--iglob !…` (case-insensitive, and they
override any user glob), exclude globs as `--glob !…`, `--max-filesize`, `--` before patterns /
`-e`), one rg process over all target roots, timeout from policy. Output rewritten from host paths
to virtual paths. Every response capped at policy.search.max_output_chars (default 30000, like
Claude Code's tool output cap) with a one-line truncation note that names only parameters the tool
has; the paging tools always show at least one (cut) entry, so the next offset always moves
forward. A search over several roots that was cut adds `[Also matched, not shown: /repos/x/y (N
files), …. Pass one as path to see its results.]` (300 characters of the budget are reserved for
it). A root whose directory vanished while the review ran (a mirror repo deleted under it) is
skipped with `[Not searched: … (removed from the repository mirror while this review ran).]`; a
search of that root alone is an error. redactSecrets on all output; a
private-key block is hidden from BEGIN to the next `-----END ` (within 64 KiB) in Read and Grep
alike, whatever the window shown. `exclude_globs` (lockfiles, minified, vendored, build output) are
skipped by Grep/Glob unless `path`/`glob` explicitly targets them — the same effect ripgrep's
.gitignore handling has in Claude Code; when they hid a result, Grep/Glob add one line naming an
example path and the glob, and how to include it.

Policy location in mirrors: `.github/xrepo/` (the documented hosted-mode location of the manifest)
is hidden, case-insensitively, in every `/repos` root, as is the path prepare passes with
`search-mcp --policy-path <repo-relative path>` (`prepare --policy-repo-path`; review.yml passes
`policy_file` in hosted mode). `/pr` is unaffected: its author can read that copy anyway.

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
  `comment | approve | request_changes` (`request_changes` also needs inline comments: findings
  only come from add_comment). Last call wins. Approve / request_changes eligibility notes come from
  `src/review/rules.ts`, the same functions the publisher's plan and prepare's prompt use.
- `add_labels({labels[]})` — enum = `capabilities.labels.allowed`.
- `review_status()` — read-only: what the draft holds so far (comments, summary, verdict) and what
  is still allowed (comment budget, verdicts and their eligibility). Always registered; writes nothing.
- `finish()` — marks the draft complete (publisher refuses incomplete drafts unless policy allows).

## Publisher rules (deterministic; `xrepo publish`)

Input: the policy (resolved from the trusted manifest `--policy` whenever given; the artifact's
`ctx/policy.resolved.json` only without it), PR context, draft.jsonl, GitHub token (env), and the
PR identity from the workflow: `--repo <owner/name> --pr-number <n> [--head-sha <40-hex>]`
(required when `GITHUB_ACTIONS=true`, exit 2 without them). The identity comes from these flags,
never from `ctx/pr.json`, which passed through the agent's job: a pr.json naming another repo,
number or head publishes nothing and exits 1. Without `--head-sha` (workflow_dispatch) pr.json's
head is used only once GitHub confirms it is the PR head; otherwise nothing is published (exit 1),
and a stale run whose head moved posts no check. With no pr.json either (the review job failed
before uploading ctx) the head is read from GitHub (`pulls.get`) and drives the freshness checks
(head and newer-run markers) and the check run; an unreadable PR publishes nothing (exit 1). The PR
link (`pr_url` in templates and the repository_dispatch payload) is always
`${GITHUB_SERVER_URL:-https://github.com}/<repo>/pull/<number>`, never pr.json's `html_url`; with
the workflow's identity pr.json's `run_url` is ignored too: `{run_url}` in templates, notify and
dispatch comes from `--run-url`, else `GITHUB_SERVER_URL`/`GITHUB_REPOSITORY`/`GITHUB_RUN_ID`, else
is empty / null (title and author still come from pr.json). Steps:
1. Parse draft lines with zod; drop invalid lines (audit). Enforce max sizes.
2. Inline comments: path must be a changed file; line must fall inside a RIGHT-side diff hunk
   (computed from diff.patch); otherwise demote to the summary "Notes outside the diff" list.
   Drop below `inline_comments.min_severity`; sort by severity; cap at `max_comments`; dedupe by
   (path,line,body hash); truncate body to `max_comment_chars`.
3. Sanitize every outgoing text: redactSecrets; neutralize `@mentions` (`@` → `@​`) unless
   `output.allow_mentions`; remove markdown images; replace links whose host is not in
   `output.link_allowlist` with plain text; strip HTML tags except the hidden marker. An
   allowlisted bare URL containing `@` is kept as an angle autolink with `@` percent-encoded
   (`<https://github.com/%40user>`; a `www.` URL becomes `<http://www.…>`), because GitHub does
   not link every bare URL (e.g. `www.` after a letter, or inside an HTML block); it links an
   angle autolink in more places, but not everywhere (a math fence in a list or blockquote, or
   inline math, shows it as text, where the `%40` keeps it from pinging). No kept
   construct contains a literal `@`: it is `%40` in every kept link destination (absolute,
   relative and fragment; inline links, definitions, autolinks, `<img src>`), and kept `<img>` alt
   text gets U+200B after `@`, since GitHub shows a kept construct as text in several places (an
   escaping backslash, an HTML block, math blocks including nested ones, `` $`…`$ `` inline math,
   a link nested in a link) and the mention filter runs on that text. Kept destinations
   also percent-encode `|`, `'` and `"`; bare URLs end at `|` (a GFM table splits cells before
   inline parsing); kept `<img>` alt text has `|` replaced by a space; truncation (`safeCut`) drops
   a kept `<…>` it would leave unclosed. Text in front of a URL's `http`/`https` scheme (`a.` in
   `a.https://…`) is not part of the kept link: it stays outside the protected span, defanged
   (`www.` → `www​.`) and visible to the mention filter, and an `@` directly in front of any kept
   construct (link, autolink, allowed tag) also gets the invisible `@​`; so does an `@` right after
   `&` plus letters or digits (`&amp@user`: GitHub decodes semicolon-less legacy entities in HTML
   blocks). A backslash right before a kept construct is separated from it by U+200B, so it cannot
   escape the `<`, `[` or `]`. A top-level fence whose info string starts with the word `math`, or
   contains `&` or `\`, has its opener rewritten to `text` (GitHub renders math blocks as text with
   live mentions and references, and decodes entities and escapes in the info string).
4. Verdict resolution (downgrade to `comment` when a rule fails, recording why in the summary footer;
   rules in `src/review/rules.ts`, shared with xreview and prepare):
   - `approve` requires: capability enabled; no findings > `approve.max_severity_allowed`;
     no touched path (renamed-from and ignored files included) matches `approve.never_paths`;
     changed lines (ignored files included) ≤ `approve.max_changed_lines`.
   - `request_changes` requires: capability enabled; inline comments enabled; at least one finding
     ≥ `block.min_severity`.
   - A type change (git's deletion + addition sections of one path, e.g. symlink → file) is one
     changed file everywhere (`mergeSamePathDiffs` / `mergeSamePathFiles` in rules.ts): the file as
     it is at head, so comments on its new content are inline.
   - When GitHub refuses the APPROVE / REQUEST_CHANGES event itself (Actions may not approve, own
     PR), the same review is posted as a COMMENT with a note; it then neither approves nor blocks
     (no `approved` / `blocked`), unless `block.method: both` still blocks via the failing check.
     Every review (any event) is posted only while the reviewed commit is still the PR head: the
     PR is read right before posting, and a moved head posts nothing and makes the run stale; a PR
     that cannot be read then posts no review of any event (a failed review post: infrastructure
     failure, exit 1, re-run the publish job; sticky and check run as on any failed review post). An
     APPROVE is also withheld (posted as a COMMENT, "approval withheld", the same way) when the PR
     is not open, and when `approve.never_paths` / `approve.max_changed_lines`
     fail on GitHub's own file list for the PR (`GET pulls/{n}/files`: names including previous
     names, additions + deletions; an unreadable list, an entry without non-negative integer
     additions / deletions, or a list at GitHub's 3000-file cap, withholds it).
   - Every review body ends with the hidden marker `<!-- xrepo-review:review -->`. With
     `GITHUB_RUN_ID` set, the body carries `<!-- xrepo-review:run=<id> -->` on the line before it
     (at the very end of a body whose inline comments were folded in by the 422 fallback); a run
     marker is read only at the end of a body. Only reviews by
     the publisher's own identity that carry it (or the exact framing of reviews posted before the
     marker existed) are ever dismissed: `github-actions[bot]` is shared by every workflow that uses
     GITHUB_TOKEN (a GitHub App token with `--self-login` is better).
   - GitHub keeps APPROVED and CHANGES_REQUESTED reviews in force until dismissed. A finished run
     that does not request changes via a review dismisses our earlier approvals (except one it just
     posted) and our change requests on OLDER commits, the latter only while its commit is still
     the PR head (a change request on the current head is lifted only by a new commit or a person;
     re-running the same commit keeps it). Every other run that does not approve (incomplete,
     REQUEST_CHANGES, and runs without a plan: skipped, error, usage_limit, kill switch) dismisses
     our earlier approvals. Both best effort. With `approve.enabled`, also turn on branch
     protection's "Dismiss stale pull request approvals when new commits are pushed".
   - Stale runs: before publishing, the publisher asks GitHub whether this run still speaks for the
     PR (`runFreshness`): its commit must be the PR head (compared as a full 40-hex sha, never as a
     prefix), and no newer workflow run may have published: a check for that commit, or our sticky
     comment / one of our reviews ending with a newer run's marker `<!-- xrepo-review:run=<id> -->`
     (the run id only, so re-running just the publish job of the same run republishes). The head
     is verified again right before the review is posted; a push in between makes the run stale
     too. A stale run (a re-run of an older run, a push while it ran) posts
     only its check run and writes its outputs: no review, dismissal, sticky, labels,
     notifications, dispatch, retry marker or `approved` / `blocked`. Unknown (PR unreadable):
     publishing goes on, but the review is posted only once the head check right before posting
     succeeds; a PR still unreadable then posts no review and exits 1.
5. Blocking: `block.method` ∈ `review` (REQUEST_CHANGES review) | `check` (check-run with
   conclusion `failure`) | `both`. If `check` is configured, a check-run named `check.name` is
   always created with `success|neutral|failure` (neutral when inline comments are disabled).
   Check runs carry the workflow run in `external_id` (`xrepo-review:run=<id>:attempt=<n>`); a
   check is never posted over a newer workflow run's check for the same commit, and a run that is
   not `completed` never posts a passing conclusion over a failing check on the same commit
   (`keep_failure`). The report then says `superseded` instead of `posted`.
6. Summary: sticky issue comment identified by `<!-- xrepo-review:sticky -->` (update in place) or
   review body, per `summary_comment.mode` (`sticky` | `review`). `summary_comment.max_chars`
   limits the agent's text (set_summary checks it raw and as sanitized); the title, incomplete
   banner, status footer, trusted footer and "Notes outside the diff" get their own room on top
   (`summaryBudget` in `src/review/rules.ts`), within the sticky comment's room for the outcome
   comments and GitHub's review body cap. A run with nothing for the sticky (summary in the review
   or disabled, no outcome comment, e.g. a skip) replaces an earlier run's sticky with a short
   status note (never creates one). With `GITHUB_RUN_ID` set, the sticky comment (and that status
   note) ends with `<!-- xrepo-review:run=<id> -->`, after any retry-after / retry-stop marker.
   Sanitized text never ends inside an open fence or `<pre>`, so whatever follows (a suggestion
   block, outcome comments) cannot be swallowed.
7. Labels: only allowed ones.
8. `--dry-run` prints the full plan as JSON and makes no API calls. Every decision is audited.

## Outcomes, notifications, retries, workflow chaining

Schema: `outcomes`, `OutcomeActions`, `DEFAULT_OUTCOMES`, `notifications` in `src/policy/schema.ts`.
`resolvePolicy` deep-merges DEFAULT_OUTCOMES <- defaults.outcomes <- repos[x].outcomes per outcome
(arrays replace) and copies `notifications` into the resolved policy.

Module `src/outcome/` (no AI, runs in the publish job):
- `classify.ts`: `classifyOutcome(input:{skipped?:{reason:string}, agentStepOutcome?: 'success'|'failure'|'cancelled'|'skipped'|string, executionFileText?: string, draft?: Draft}): {outcome: 'completed'|'incomplete'|'usage_limit'|'error'|'skipped', reason: string, reset_at?: string}`.
  Order: skipped → completed (draft.finished: finish() was called, whatever failed afterwards) →
  usage_limit (structured evidence: result `api_error_status` 429/529, synthetic assistant
  `error` / `api_error` such as rate_limit, overloaded, usage_limit_reached, rejected
  `rate_limit_event`, `api_retry` 429/529 or rate_limit / overloaded; or the
  result/error text or a trailing synthetic message in unambiguous CLI / API wording
  (case-insensitive, `USAGE_LIMIT_PATTERNS`): "You've hit your" / "You've reached your" (straight
  or curly apostrophe), "You're out of (extra) usage", "your org(anization) is out of usage", "your
  seat type doesn't include", "your usage allocation has been disabled", "your group's usage
  limit", "requires usage credits", "usage limit reached", "reached your specified API usage
  limits", "session limit reached" / "weekly limit reached", "rate
  limited" / "rate limit exceeded|reached|rejected" (not followed by `/`, `_` or `-`), "too many
  requests", "API Error: 429", "API Error: 529", "API Error: Request rejected (429)", "529
  Overloaded", the quoted JSON type `"overloaded_error"`, "credit balance is too low". A bare
  "rate limit", "usage limit", "limit reached", "quota exceeded" or "<period> limit", any other
  "<period> limit reached" (daily, monthly, Opus, ...), a 429/529 not right after
  "API Error: ", or an overloaded / rate_limit token, as in a file path, is not evidence; parse reset time:
  `limit reached|<epoch>` → ISO, `resets <text>` → raw text) → incomplete (draft has entries or result subtype `error_max_turns`) → error (reason from step outcome
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
  when target repo == PR repo; the shipped review.yml grants the publish job `contents: read` only,
  so there every dispatch needs XREPO_DISPATCH_TOKEN and a 403 says so); client_payload ≤ 10
  top-level keys. `GITHUB_API_URL` is validated by `outcome/api-base.ts` for every command (https,
  http only for localhost; no credentials, query or fragment).
- `retry.ts`: `xrepo retry` sweeper (central scheduled workflow, GitHub App token with actions:write,
  pull-requests:write). Repositories swept: the `repos:` keys and exact `mirror.repos` names, plus
  every repository of the installation's account or of an owner named in `repos:` / `mirror.repos`
  that has an open PR with a retry label enabled in `defaults`, found with the search API
  (`is:pr is:open label:"<label>" org:<owner>`, `user:` for personal accounts; at most 20 searches
  per sweep). Repositories the token cannot see are not swept. `--repo` restricts the sweep to
  exactly those (no search); `--owner <login>` to one account (only its listed repositories, and
  discovery searches only it). For each open PR carrying a retry label, find the latest run of the
  review workflow for that PR's head sha; if `run_attempt < max_attempts` re-run it
  (POST /actions/runs/{id}/rerun) once its "not before" time has passed (waiting is not an
  attempt); else remove the label and comment once. "Not before": the publisher that adds a retry
  label appends `<!-- xrepo-review:retry-after <ISO> run=<run id> attempt=<n> -->` to its sticky
  comment (usage-limit reset time + 5 min, capped at 8 days; a weekday-only reset such as
  "Mon 9am" resolves to its next occurrence; unknown reset: backoff 2h, 4h, 8h… for usage_limit,
  1h, 2h, 4h… for error, max 24h). `max_attempts` is the one of the outcome that ended the run: a
  run at its own limit leaves the label and appends `<!-- xrepo-review:retry-stop run=<id>
  attempt=<n> max=<m> -->`, so the sweeper gives up even when another outcome sharing the label
  allows more; a retry-after marker allows the label's largest `max_attempts`; without a marker
  for the latest run the smallest `max_attempts` of the outcomes sharing the label applies. The
  sweeper trusts only markers for the latest run in comments by `--publisher-login` (retry.yml:
  github-actions[bot]) or, without it, a bot account; with none it backs off 1h, 2h, 4h… from the
  run's `updated_at`.

Publisher flow with outcomes (`xrepo publish`): extra flags `--agent-outcome`, `--execution-file`,
`--skip-reason`, `--run-url`, `--run-attempt`, `--github-output`, plus the PR identity flags
`--repo`, `--pr-number`, `--head-sha` (see Publisher rules). Steps: classify → if completed or
incomplete, build/execute the review plan (incomplete never approves/blocks) → derive extra outcomes
`approved`/`blocked` from the executed plan → for each fired outcome (primary first, then
approved/blocked): post `comment` (into the sticky comment; a completed review's summary stays primary
and outcome comments are appended), set check conclusion (outcome override wins over the plan's
default only for non-completed outcomes; for completed the plan decides unless configured; a plan
that blocks via the check is only overridden by `outcomes.blocked.check_conclusion`, and an
override that changes the plan's conclusion is named in the check title), add/remove labels,
notify, dispatch, retry labelling (`retry.enabled` and run_attempt < max_attempts on a usage_limit /
error run → add retry label (left in place at max_attempts, with a `<!-- xrepo-review:retry-stop
run=<id> attempt=<n> max=<m> -->` marker in the sticky comment, so the sweeper gives up and comments);
every other run removes every configured retry label) → write step outputs `outcome, verdict,
reason, reset_at, findings, top_severity, fired_outcomes` → exit 1 only if a fired outcome has
`fail_job: true` (or on infrastructure failure of required API calls).

Kill switch at publish time: the publisher checks `enabled: false` on the policy it acts on (the
live manifest), so a run whose policy was disabled after prepare is classified `skipped`.

Blocking checks and skips: with `block.method` `check` or `both`, a skip the PR author controls
(title marker, `max_changed_files` / `max_changed_lines`, "diff larger than…" — including a diff
the GitHub API will not serve, 300 files / 20000 lines — and "diff refused: …", an API diff
refused because the PR changes `.gitattributes`) fails the check ("Review required: skipped by the
pull request"), since GitHub counts skipped / neutral / success as passing. A draft skip fails it
as "Review pending: draft pull request (runs when marked ready)", so marking the PR ready and
merging at once cannot beat the review; the ready_for_review run then posts its own check. Fork,
bot, ignored-author and kill-switch skips keep the configured conclusion. Opt-out: set
`outcomes.skipped.check_conclusion` to `success` or `neutral` explicitly. A run that is not
`completed` (skip, error, usage limit, incomplete) never lifts a failing check on the same commit.

Workflow chaining: `review.yml` exposes those outputs as `on.workflow_call.outputs`, so callers add
jobs like `if: needs.review.outputs.outcome == 'usage_limit'`. The claude-code-action step uses
`continue-on-error: true`; the publish job runs `if: always()` (unless the run was cancelled) and gets
the action's outcome + execution file via the artifact.

Accounts: the reusable workflow reads `CLAUDE_CODE_OAUTH_TOKEN` and `ANTHROPIC_API_KEY` via
`secrets: inherit` and passes exactly one: the subscription token whenever it is visible, the API
key only otherwise (Claude Code prefers the API key when both are set). Per-group accounts = a
repository secret `CLAUDE_CODE_OAUTH_TOKEN` overriding the org secret of the same name; review.yml
has no `account` input and never selects a secret by dynamic name; an explicit switch is a fixed
expression in a fork. No automatic failover between personal subscriptions (terms risk) —
documented in README.

## prepare (`xrepo prepare`)

Inputs (flags): `--policy`, `--repo owner/name`, `--pr N`, `--base-sha`, `--head-sha` (full 40-hex),
`--pr-checkout DIR`, `--mirror DIR`, `--work DIR`, `--event PATH` (GitHub event JSON for title,
body, author, draft flag, fork flag), `--launcher docker|local`, `--image IMG`,
`--policy-repo-path PATH` (the manifest's path inside its own, possibly mirrored, repository;
passed to xsearch as `--policy-path`).
Outputs files under `--work` (see layout) and prints GitHub step outputs (`claude_args`, `prompt`,
`skip`, `skip_reason`) to `$GITHUB_OUTPUT` when set (multiline-safe heredoc delimiters).
- Skip rules from policy (`triggers`): drafts, forks, bots, title markers (`[skip review]`),
  max changed files/lines, ignored authors, `enabled: false` kill switch. The bot and ignored-author
  skips apply only when the event's sender (`sender.login`, else `GITHUB_ACTOR`) is the PR author
  itself: a person pushing to a Dependabot branch is reviewed. A diff the GitHub API refuses for
  its size (HTTP 406) skips with "diff larger than the GitHub API serves (300 files or 20000
  lines)", and a refused `.gitattributes` API diff skips with "diff refused: …" (exit 0, pr.json
  written); both are author-controlled skips for the publisher.
- Computes diff with `git -C <pr-checkout> diff --no-color -U3 <base>...<head>`. In a shallow
  checkout (`git rev-parse --is-shallow-repository` is not `false`) the local diff is used only when
  `git merge-base --is-ancestor <base> <head>` succeeds, because git may compute a missing or wrong
  merge base on truncated history. Otherwise it falls back to the GitHub API diff
  (`application/vnd.github.v3.diff`; prepare fails without `GITHUB_TOKEN`/`GH_TOKEN`), never to
  `git diff base head`, which shows every base commit since the fork point as reverted by the PR;
  `diff_method` is `three-dot` | `api`. Explicit options override
  the runner's git config (`--inter-hunk-context=0`, `--diff-algorithm=myers`, `--indent-heuristic`,
  `-O/dev/null`, `--submodule=short`, `--ignore-submodules=none`, `-c diff.suppressBlankEmpty=false`,
  `-c core.bigFileThreshold=512m`), so the patch is the same on every runner. gitattributes never
  come from the PR: `--attr-source <base>` (git ≥ 2.40), else an isolated empty work tree and
  index; an API diff is refused when the PR changes `.gitattributes` and files show as binary.
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
  capability summary + turn budget + PR overview (untrusted text fenced and labelled as data). It
  names at most 20 other repositories (related ones first, then "... and N more repositories") and
  is kept under 64 KiB as JSON (smaller steps: fewer repos, no descriptions, fewer relationship
  hints, shorter PR text), so `PROMPT` / `ALL_INPUTS` never hit the OS argument limit; only the
  policy's own text can make prepare fail. It ends "Begin with PrDiff.".

## sync (`xrepo sync`)

`--policy`, `--mirror DIR`, token from env `XREPO_GITHUB_TOKEN` (GitHub App installation token).
For each repo in `policy.mirror.repos` (explicit list; globs `org/*` resolved via API if allowed):
shallow fetch default branch into a new snapshot dir using a per-command auth header
(`git -c http.extraHeader=...`), never persisting credentials; remove `.git` remote URL creds;
delete `.git` from the snapshot; write meta.json; atomically swap `current` symlink (rename of a temp symlink); keep last N snapshots
(default 2) and delete older ones, but only once they have been retired for longer than the grace
period (default 60 min, `--snapshot-grace-minutes`; must exceed the review job's timeout, since a
review keeps reading the snapshot that was `current` when it started). A repo that drops out of the
desired set (policy edit, archived, renamed, made a fork, excluded) is retired at once — its
`current` is unlinked and `<repo>/.retired` (`{"retired_at": ISO}`) records when, so discovery stops
listing it for every review that starts from then on — and its directory is deleted only after the
same grace period (the report lists it under `retired`, then under `removed`); a retired repo that
is listed again is restored from its snapshot. Repository names are not case-sensitive in the
mirror: a repo whose policy or API spelling changes only in case keeps its existing
`<owner>/<repo>` directory under the original on-disk spelling (never retired for that reason);
meta.json's `repo` carries the newest spelling. Concurrency-safe with a lock file whose holder
refreshes it every 30 s; a lock not refreshed for 15 min (another host, or an unverifiable pid) is
taken over; exit 3 means a sync elsewhere holds a fresh lock.

An App installation token covers one account, so sync.yml and retry.yml run one job per owner
(`owners` job reads the policy; `max-parallel: 1`, `fail-fast: false`) and, when the policy names
more than one owner, pass `--owner <login>`: `xrepo sync --owner` syncs only that owner's
`mirror.repos` entries (exact and `owner/*`) and retires / removes only mirrors under it or under
owners the policy no longer names; `xrepo retry --owner` sweeps only that owner (see retry.ts). A
single-owner policy runs one unrestricted command, as before.

## Repository patterns (policy)

`cross_repo.readable`, `cross_repo.deny` and `mirror.exclude` accept exactly `owner/name`,
`owner/*` or `*` (`RepoPattern` in schema.ts; surrounding whitespace is tolerated). Any other form
(`acme/legacy-*`, `*/secrets`, a trailing `/`, a URL, `acme/**`) fails policy loading, naming the
location and the pattern: such a deny entry would never match and so fail open. `mirror.repos`
stays loose in the schema (a bad entry fails on its own at every sync, the others still sync); `xrepo
policy validate` warns about such entries, and about a repo layer whose `cross_repo.deny` (which
replaces the defaults list) drops a `defaults` deny entry that could still match a repository
readable for that repo (`policyFileWarnings`).

## Non-goals (v1)

Writing code / pushing commits; reviewing fork PRs; non-GitHub hosts.

# Research notes (verified facts the implementation relies on)

Checked 2026-11-09. "VERIFIED" = read in source or reproduced; "UNCERTAIN" = not confirmed, and the
implementation does not depend on it (or says how it copes). Sources are listed per section.

## 1. anthropics/claude-code-action@v1

Source: the action's repository at tag `v1` = `v1.0.269` = commit
`61a9c274fa7110a66dfafc1bbbced03833eb25fe` (pinned in `.github/workflows/review.yml`), its
`action.yml`, `src/entrypoints/run.ts`, `src/modes/*`, `src/github/operations/restore-config.ts`,
`base-action/src/parse-sdk-options.ts`; Agent SDK `@anthropic-ai/claude-agent-sdk@0.3.319`.

- **Inputs we use** (VERIFIED): `prompt`, `claude_args`, `github_token`, `claude_code_oauth_token` /
  `anthropic_api_key`, `plugins`, `plugin_marketplaces` (newline-separated). There is **no working
  directory input**: the CLI runs in the step's cwd, i.e. `$GITHUB_WORKSPACE`.
- **Outputs** (VERIFIED): `conclusion`, `execution_file`, `session_id`, `structured_output`,
  `branch_name`, `github_token`. On failure only `execution_file` is set (`conclusion` stays empty),
  so we record the step `outcome` instead.
- **Agent mode** (VERIFIED): any `pull_request` event with `prompt` set (and `track_progress` off)
  runs in agent mode. The prompt is passed verbatim; no PR context is injected; the action posts
  nothing itself. Agent mode adds no tools and no `--permission-mode`.
- **Actor check** (VERIFIED): the actor needs write/admin on the repo (`allowed_non_write_users`
  bypasses it only with `github_token`); bots must be listed in `allowed_bots`. `id-token: write`
  is not needed when `github_token` is passed. A read-only `github_token` suffices in agent mode
  without `mcp__github*` tools (UNCERTAIN: that the collaborator-permission endpoint accepts a
  token with only contents/pull-requests read; docs say metadata read, which GITHUB_TOKEN always has).
- **`claude_args` parsing** (VERIFIED, `parse-sdk-options.ts`): full-line `#` comments removed;
  `()|&;<>` escaped; then `shell-quote`. Only `--flags` are recognised; a flag is boolean only when
  the next token starts with `--`; `--allowedTools`, `--disallowedTools`, `--mcp-config`,
  `--add-dir` accumulate and consume every following non-flag token; every other flag takes one
  value (last wins). `--setting-sources` becomes the SDK `settingSources` (default
  `user,project,local`). Consequences: `--tools ""` turns into a bare `--tools` that swallows the
  next flag; `--setting-sources ""` falls back to all sources; a file path after `--mcp-config` is
  dropped when any inline-JSON config carries servers. → prepare emits `--tools ,`, quotes every
  value so shell-quote returns it verbatim, uses one mcp.json file, and the action adds no servers
  of its own unless `mcp__github*` tools are allowed (we never allow them).
- **PR checkout restore** (VERIFIED, `restore-config.ts`): on PR events the action deletes
  `.claude .mcp.json .claude.json .gitmodules .ripgreprc CLAUDE.md CLAUDE.local.md .husky` in the
  cwd, runs `git fetch origin <base.ref>` (`--depth=1` only if the repo is shallow) and restores
  them from `origin/<base>`. It runs `git diff ... HEAD` and `git ls-files` first, so **the cwd must
  be a git repository with a HEAD commit and an `origin` remote**, otherwise the step fails.
  `configureGitAuth` rewrites `origin` with the token embedded. → `xrepo prepare --action-cwd`
  turns `$GITHUB_WORKSPACE` into an empty git repo (one empty commit, marked shallow, `origin` =
  the PR repo); the PR checkout lives in the `pr/` sub-directory.
- **Settings** (VERIFIED): `~/.claude/settings.json` gets `enableAllProjectMcpServers: true`
  forced; with default setting sources the checkout's `.claude/settings.json`, hooks, `.mcp.json`
  and `CLAUDE.md` load. Not restored: nested `CLAUDE.md`, `package.json` scripts, paths passed to
  `settings` / `--mcp-config` from the checkout.
- **Environment** (VERIFIED): the CLI gets `{...process.env}` minus OIDC request variables, so
  `GITHUB_TOKEN`, `ANTHROPIC_API_KEY` / `CLAUDE_CODE_OAUTH_TOKEN` are visible to anything Claude
  can execute. → no built-in tool can execute or read files; MCP containers get no environment.
- **execution_file** (VERIFIED): `$RUNNER_TEMP/claude-execution-output.json`, a pretty-printed JSON
  array of every raw SDK message (unsanitised: includes all tool results), result message last;
  written on success and failure. Success only if `subtype == "success"` and `!is_error`. Logs show
  only a summary; the result text (where limit messages live) is only in the file. → the review job
  uploads a trimmed copy (`xrepo collect`).
- **Versions** (VERIFIED): installs Claude Code 2.1.319 (`curl … install.sh | bash -s -- 2.1.319`),
  Agent SDK 0.3.319, Bun 1.4.4.

## 2. Claude Code CLI 2.1.319 flags (reproduced against a local mock API)

- `--tools ""`, `--tools ","` and `--tools " "` remove every built-in; MCP tools from
  `--mcp-config` stay and load as normal, non-deferred tools. A call to a removed tool returns
  `No such tool available`. Unknown names in `--tools` are ignored silently.
- The subagent tool is `Agent` (`Task` is an alias); `TodoWrite` is replaced by
  `TaskCreate/TaskGet/TaskList/TaskUpdate` (TodoWrite only with `CLAUDE_CODE_ENABLE_TASKS=0`).
- `--strict-mcp-config` starts only servers from `--mcp-config` (not `~/.claude.json`, project
  `.mcp.json` or plugin servers); it does not stop hooks / CLAUDE.md / skills.
- `--setting-sources user` skips project and local hooks, `.mcp.json`, CLAUDE.md, skills and
  agents (also lazily-loaded subdirectory ones), keeps user settings and plugins enabled there.
  With default sources, `-p` in an untrusted directory still runs project hooks.
- `--allowedTools` accepts exact names, `mcp__server__*` and `mcp__server`; in `-p` mode a tool that
  is not allowed is denied (`permission_denials`). `--disallowedTools` removes a tool.
- Usage limit (OAuth): `You've hit your 5-hour limit · resets 1:32pm (UTC)` (also weekly / Opus /
  Sonnet / usage credit variants); JSON result `subtype:"success", is_error:true,
  api_error_status:429`; stream `rate_limit_event{status:"rejected", resetsAt}`. API key 429:
  `API Error: Request rejected (429) · …`. Older formats: `You've hit your session limit · resets
  3pm` (2.0.76), `Session limit reached ∙ resets X` (2.0.14), `Claude AI usage limit
  reached|<epoch>` (1.0.88). `error_max_turns` has `is_error:true` and no `result`.

**Recommended `claude_args`** (implemented in `buildClaudeArgs`):

```
--mcp-config <work>/agent/mcp.json --strict-mcp-config --setting-sources user --tools ,
--allowedTools <every xsearch / xreview tool name> --disallowedTools <dangerous built-ins>
[--model <m>] --max-turns <n>
```

`--disallowedTools` (Bash, Edit, Write, Read, Grep, Glob, WebFetch, WebSearch, ToolSearch, …) is
redundant with `--tools ,` and kept as defence in depth.

## 3. GitHub

Source: `github/docs` (rendered as docs.github.com) and `github/rest-api-description`.

- Reviews: `POST /repos/{o}/{r}/pulls/{n}/reviews` with `event` APPROVE / REQUEST_CHANGES /
  COMMENT, `comments[]` with `path`, `line`, `side`, `start_line`; `line` must be in the diff (RIGHT
  for added and context lines). Needs `pull-requests: write`. UNCERTAIN: one bad line fails the
  whole request with 422 (handled: the publisher retries with comments folded into the body).
- "Allow GitHub Actions to create and approve pull requests" controls whether GITHUB_TOKEN can
  approve; off by default. Whether a `github-actions[bot]` approval counts toward required reviews
  is UNCERTAIN (sources conflict) — approvals are off by default in the policy.
- Check runs need `checks: write`; conclusions success / neutral / failure / skipped /
  action_required / …; "successful" for required checks = success, skipped, neutral. A required
  check can be pinned to an expected source app.
- Labels / issue comments on PRs: `issues: write` or `pull-requests: write`; repository_dispatch:
  `contents: write`, `client_payload` ≤ 10 top-level keys, < 64 KB; re-runs: `actions: write`.
  The publish job's GITHUB_TOKEN is `contents: read` (a callee can only narrow the caller's grant),
  so every dispatch, also to the PR repository, needs `XREPO_DISPATCH_TOKEN`.
- Events caused by GITHUB_TOKEN start no new runs, except `workflow_dispatch` / `repository_dispatch`.
- Re-runs keep `run_id`, increment `run_attempt`, reuse the original SHA / ref, event payload and
  actor privileges; max 50 re-runs within 30 days. "Re-run this job" / "Re-run failed jobs" start
  only the selected jobs (and their dependents) as attempt N+1; jobs not re-run keep their result,
  outputs and artifacts from the attempt that produced them.
- Fork PRs: read-only token whatever `permissions:` request (private repositories can opt into
  write tokens for fork runs), no secrets except GITHUB_TOKEN. That token reads only the calling
  repository (and public ones), so checking out a private `xrepo_repo` fails in a fork run;
  review.yml tolerates that failure only for fork runs (`continue-on-error` takes an expression)
  and then skips every later step and the publish job.
- GitHub App installation tokens cover one installation, i.e. one account (organization or user):
  `actions/create-github-app-token` with `owner: X` reads X's repositories only, even when the same
  App is installed on other owners. Several owners need several tokens; a token cannot be passed
  between jobs (outputs holding secrets are dropped), so sync.yml / retry.yml use one matrix job
  per owner.
- actions/cache: an entry is scoped to the ref that saved it; a run restores entries of its own ref
  and of the base / default branch, never of a sibling pull request (`refs/pull/<n>/merge`).
  Caches are per repository, entries unused for 7 days are evicted, and a hit needs the same key
  and the same `path`. A default-branch entry must be saved by a non-PR run of that repository
  (mirror-cache.yml on a schedule).
- Claude authentication: claude-code-action@61a9c27 exports both `ANTHROPIC_API_KEY` and
  `CLAUDE_CODE_OAUTH_TOKEN` and only checks that one is set; Claude Code then uses the API key when
  both are present (verified with Claude Code 2.1.319 against a local server logging auth headers:
  both set → `x-api-key`; only the OAuth token, or an empty API key → `Authorization: Bearer`).
  review.yml therefore passes the API key only when no OAuth token is visible.
- Reusable workflows: `secrets: inherit` passes all caller secrets (only to the directly called
  workflow); a callee can only reduce the caller's permissions; outputs must map job outputs;
  `runs-on` may use `fromJSON(inputs.x)`; `uses:` cannot contain expressions; a SHA is the safest
  ref. Dynamic secret names (`secrets[format('X_{0}', inputs.account)]`) are UNCERTAIN (undocumented)
  → not used; per-group accounts use same-named org secrets scoped to repo groups.
- Ruleset "Require workflows to pass before merging": org/enterprise level, GHEC / GHES 3.12+,
  runs on `pull_request`, `pull_request_target`, `merge_group` with the workflow file taken from the
  central repository at a pinned ref.
- Artifacts (upload-artifact v4+): immutable per name within a run, visible to every attempt of the
  run (download-artifact looks them up by run id; an empty `name` downloads all of them). We name
  them per `run_attempt` and pass the name to the publish job as a review-job output, so a
  publish-only re-run downloads the review job's artifact rather than a non-existent
  `xrepo-review-<N+1>`. Retention 1–90 days, hidden files excluded by default.
  actions/checkout: `path` must be under `$GITHUB_WORKSPACE`; `persist-credentials: false` keeps
  the token out of the checkout.
- `if: ${{ !cancelled() }}` instead of `always()` for follow-up jobs; `steps.<id>.outcome` is the
  result before `continue-on-error`.
- Self-hosted runners: should almost never serve public repositories; use ephemeral / JIT runners;
  runner groups can be restricted to selected (pinned) workflows on GHEC / GHES.

Slack incoming webhooks (UNCERTAIN, docs host unreachable): `{"text": ...}` is mrkdwn; escape `&`,
`<`, `>` in untrusted text so it cannot form `<!channel>` / links (implemented in
`src/outcome/template.ts`).

## 4. Tools (why xsearch is Grep / Glob / Read)

Measured on hono (TS), httpx (Py), gin (Go), gson (Java) and t3code:

- Output format dominates cost: `rg --json` ≈ 5x grouped plain text; context lines double the cost.
- universal-ctags 5.9 on TypeScript: 0% of tags with end lines, no signatures, class methods
  missing, thousands of test-local constants as top-level symbols. ast-grep outlines are precise
  but structural patterns fail silently and repo maps collide on common names.
- ripgrep with no path argument and a non-TTY stdin reads stdin and hangs → always spawn with
  `stdio[0] = 'ignore'` and explicit paths (done in `src/search/rg.ts`).
- Claude Code defers MCP tools behind ToolSearch unless `_meta: {"anthropic/alwaysLoad": true}` is
  set; with `--tools ,` there is no ToolSearch, so tools load directly (both measures are applied;
  the workflow also sets `ENABLE_TOOL_SEARCH=false`).
- t3code exposes ~72 MCP tools and none for code navigation; Codex CLI has no file tools and uses
  `rg` / `sed` through its shell; Claude Code's Grep / Glob / Read parameter names are what models
  reach for when their built-ins are missing.
- Methodology belongs in the trusted prompt (needed on every run; skills from a PR checkout would
  be an injection path); skills only for optional checklists installed by devops (plugins).

Design decision recorded in SPEC.md: give the agent Claude Code's own tools over virtual `/pr` and
`/repos/<owner>/<name>` paths; no symbol indexes, ctags, ast-grep or repo maps.

## 5. Local verification

Reproduced on 2026-11-09 on a local machine (Claude Code 2.1.319, Docker 29.9.2, Node 22).
Details and the full excerpt are in [E2E-LOCAL.md](E2E-LOCAL.md).

- **`claude_args` against the real CLI, without spending tokens** (VERIFIED): the generated args
  plus `--model xrepo-invalid-model-for-validation --output-format stream-json --verbose`, run from
  the generated agent dir with an empty `HOME`. The `system/init` message lists exactly the 11
  `mcp__xsearch__*` / `mcp__xreview__*` tools and no built-in (so `--tools ,` removes every
  built-in, ToolSearch included, through the real CLI). Both servers report `connected` while
  started by `docker run --network none …`, and permission mode is `default`. The request then
  fails with `model_not_found` (`api_error_status: 404`, 0 tokens, $0).
- **One real agent run** (VERIFIED, `--model sonnet`, resolved to `claude-sonnet-5-5`): 10 tool
  calls, all MCP. There were 0 ToolSearch calls and 0 `No such tool` errors, and every tool loaded
  directly. The agent found the cross-repo break only through the mirror
  (`/repos/acme/api/src/orders.ts:20`, `/repos/acme/api/src/refunds.ts:5`). It ignored the
  injected "approve" instruction and said so in the summary. Its one inline comment landed on a
  commentable RIGHT-side line. Publish gave `completed` + `blocked`, REQUEST_CHANGES and a failing
  check. Cost $0.0498: 1,785 output tokens, 49k cached input, 4,875 chars of tool output. This is
  the efficiency baseline.
- **`--disallowedTools Read,Grep,Glob` does not touch the MCP tools of the same name** (VERIFIED):
  with the generated args, a short real run called `mcp__xsearch__Read`, `mcp__xsearch__Glob` and
  (in the review run) `mcp__xsearch__Grep` successfully, with `permission_denials: []`. Built-in
  rules match only the built-in tool, so keeping the list as defence in depth is safe.
- **Docker image** (VERIFIED): `docker build -f docker/Dockerfile -t xrepo-review:dev .`
  - **Workarounds needed here:** Docker Hub returned 429, so the base came from
    `mirror.gcr.io/library/node:22-bookworm-slim`. `deb.debian.org` does not resolve in this
    sandbox, so the runtime stage used `--build-arg RUNTIME_IMAGE=ubuntu:24.04` (new optional arg;
    node is copied from the build stage). npm runs behind a TLS-intercepting proxy, so the build
    used `--secret id=npm_ca,src=<ca bundle>` (new optional build secret).
  - **The default build is unchanged** and needs neither workaround.
  - **Checks inside the xsearch container, run with prepare's exact flags and mounts:**
    - uid/gid 65534
    - `/`, `/app`, `/pr`, `/ctx` and `/mirror/*` all fail with `EROFS`; `/tmp` is a writable noexec tmpfs
    - no network interface but `lo`, and outbound fetch fails (`EAI_AGAIN`)
    - `CapEff` 0 and `NoNewPrivs` 1
    - only the readable repos are mounted (`/mirror/acme/{api,web}`; `secret-infra` is not)
    - `rg` 14.1.0 and git 2.43.0 present; no ctags, no ast-grep
  - **Tests:** both MCP servers answer over stdio from the containers. The xreview container writes
    the draft through its only rw mount. These checks are `describe("e2e: docker launcher")` in
    `test/e2e.test.ts`, opt-in with `XREPO_TEST_DOCKER_IMAGE=xrepo-review:dev`.
- **Pipeline without a model** (`test/e2e.test.ts`, 18 tests + 3 docker): three local bare repos,
  `xrepo sync` with a `file://` URL template, `xrepo prepare --launcher local` with a fake event,
  both servers started exactly as `mcp.json` says and driven like an agent, then
  `xrepo publish --dry-run` for completed, usage_limit (dry run and a live run with a fake GitHub
  client and a signed webhook), error and incomplete.
- **Workflows** (VERIFIED): actionlint 1.7.12 (`go install github.com/rhysd/actionlint/cmd/actionlint@latest`)
  with shellcheck 0.11.0 and pyflakes, over `.github/workflows/*.yml`, `examples/caller.yml` and
  `examples/caller-with-hooks.yml`. One finding, SC2054 in `ci.yml` (a comma inside a bash array
  element: the unquoted `--tmpfs /tmp:rw,…` value), was fixed by quoting it. Now clean, exit 0.
  Workflows have not been run on GitHub from this machine.

<!-- Final verification report written by the build workflow's last agent. Numbers are from that run; HANDOFF.md has the current state. -->

# xrepo-review: final verification report

The repo builds and type-checks cleanly. The full test suite passes (847 of 847 with the Docker tests on), and the rebuilt Docker image passes the sandbox checks. I fixed doc drift in README, SPEC, TOOLS.md, review.yml, ci.yml and the hooks example. I also made one small CLI fix: `xrepo <command> --help` now works for every command. One gap: I could not re-run actionlint this round (details under Verification).

## 1. Architecture

- **Review job** (read-only token): it checks out the PR head as data only, never built or run. `xrepo prepare` then writes:
  - the context files (`pr.json`, `diff.patch`, `policy.resolved.json`);
  - `mcp.json` with exactly two stdio servers;
  - the prompt and `claude_args`;
  - an empty git repo as the action's working directory.

  `anthropics/claude-code-action@v1` (pinned SHA) then runs with no built-in tools, only our servers, and an exact tool allowlist. The two servers run in hardened containers: no network, read-only filesystem, all capabilities dropped, user 65534.
  - `xsearch`: read-only code search over `/pr` and `/repos/<owner>/<name>`.
  - `xreview`: appends to one draft file.

  `xrepo collect` trims the execution log, and the context, draft and log are uploaded as one artifact. Its name is a job output.
- **Publish job** (the only job with a write token; no PR checkout, no AI): `xrepo publish`
  1. classifies the run (completed, incomplete, usage_limit, error, skipped);
  2. re-resolves the policy from the trusted manifest;
  3. validates and sanitises the draft;
  4. checks the run is still current;
  5. posts the review, sticky comment, check run and labels;
  6. sends notifications, dispatches and the retry label;
  7. writes the workflow outputs.
- **Scheduled jobs:** `xrepo sync` keeps the mirror (snapshots, atomic swap, grace period before deletion, one job per owner). `xrepo retry` re-runs postponed reviews. In hosted mode, `mirror-cache.yml` warms the default-branch cache.

## 2. Files

| File | Purpose |
|---|---|
| `src/cli.ts` | `xrepo` dispatcher; `xrepo policy validate / resolve / tools`; per-command `--help` |
| `src/policy/schema.ts` | manifest schema and types (shared contract) |
| `src/policy/load.ts` | load and resolve the policy; layer merge; warnings |
| `src/policy/glob.ts` | path glob matching; `owner/name` repo patterns |
| `src/common/args.ts` | strict CLI flag parsing |
| `src/common/audit.ts` | JSON audit lines |
| `src/common/context.ts` | PR context files in `ctx/` |
| `src/common/diff.ts` | unified diff parser; which lines can take a comment |
| `src/common/draft.ts` | draft schema (shared contract) |
| `src/common/mcp.ts` | the "always load" flag set on every tool |
| `src/common/redact.ts` | secret redaction; private-key block rules |
| `src/search/vfs.ts` | virtual paths to host paths; containment; deny and hidden globs |
| `src/search/rg.ts` | ripgrep runner (no shell, timeout) |
| `src/search/safeglob.ts` | linear-time glob matcher for globs the agent supplies |
| `src/search/text.ts` | per-line redaction, private-key windows, output caps |
| `src/search/tools.ts` | ListRepos, PrDiff, Grep, Glob, Read |
| `src/search/server.ts` | xsearch server: strict schemas, parameter-name hints |
| `src/review/rules.ts` | verdict and budget rules shared by xreview, prompt and publisher |
| `src/review/server.ts` | xreview server |
| `src/prepare/prepare.ts` | `prepare` (skip rules, diff, mcp.json, claude_args, prompt) and `collect` |
| `src/publish/plan.ts` | pure review plan (what will be posted) |
| `src/publish/sanitize.ts` | sanitiser for everything posted |
| `src/publish/github.ts` | GitHub client wrapper (fakeable in tests) |
| `src/publish/publish.ts` | publisher main: outcomes, stale-run check, outputs |
| `src/outcome/classify.ts` | outcome classification |
| `src/outcome/template.ts` | message templates with per-channel escaping |
| `src/outcome/notify.ts` | Slack and webhook notifications |
| `src/outcome/dispatch.ts` | `repository_dispatch` |
| `src/outcome/retry.ts` | `xrepo retry` sweeper |
| `src/outcome/reset.ts` | usage-limit reset time to a retry time |
| `src/outcome/api-base.ts` | `GITHUB_API_URL` validation |
| `src/sync/sync.ts` | mirror sync |
| `docker/Dockerfile` | image: node, ripgrep, git, non-root |
| `.github/workflows/review.yml` | reusable workflow: review and publish jobs |
| `.github/workflows/sync.yml`, `retry.yml` | scheduled sync and retry, one job per owner |
| `.github/workflows/mirror-cache.yml` | hosted mode: warms the mirror cache |
| `.github/workflows/ci.yml` | this repository's CI |
| `.github/workflows/e2e.yml` | real-agent end-to-end test in hosted mode |
| `examples/policy.yaml`, `caller.yml`, `caller-hosted.yml`, `caller-with-hooks.yml` | example manifest and caller workflows |
| `e2e/` | fixture repos, bare-repo builder script, e2e policy |
| `docs/SECURITY.md`, `TOOLS.md`, `RESEARCH.md`, `E2E-LOCAL.md`; `README.md`, `SPEC.md` | documentation |
| `test/*.test.ts` | 14 test files |

## 3. Agent tool list

**xsearch** (read-only, always loaded, every tool marked read-only):
- `ListRepos`: the readable roots, each with commit, sync age and description; can be paged.
- `PrDiff`: the changed files, or one file's diff with 3 context lines; can be paged.
- `Grep`: Claude Code's Grep (ripgrep) with the same parameters, defaults and output.
- `Glob`: file-name search, sorted, at most 100 results; absolute patterns are anchored.
- `Read`: `cat -n` with offset/limit; a directory returns its entries.

**xreview** (registered only when the policy enables the capability):
- `add_comment`: inline comment on the new side of the diff, with severity and optional suggestion.
- `set_summary`: the overall review text.
- `set_verdict`: only the verdicts the policy allows.
- `add_labels`: only the labels the policy allows.
- `review_status`: read-only view of the draft and what is still allowed.
- `finish`: marks the review complete.

**Comparison:**
- **Claude Code:** we copy its own Grep, Glob and Read names, parameters and output, so the model needs no new API. Multi-repo is expressed through paths, not a new parameter.
- **Codex CLI:** has no file tools; it uses `rg` and `sed` through its shell.
- **t3code:** a control surface over the agent CLIs with no code-navigation tools of its own. Its review mode runs `claude -p --tools Read,Grep,Glob,Bash`; we give the same three tools without Bash or host filesystem access.
- **Serena, ast-grep MCP, github-mcp-server:** symbol, AST or API-shaped tools. ctags and ast-grep were measured and rejected as less reliable on TypeScript.

## 4. Deploy steps

1. Set up a dedicated, ephemeral self-hosted runner group with Docker, git and Node 22, labelled `xrepo-review`.
2. Build the image with a pinned base: `docker build -f docker/Dockerfile --build-arg NODE_IMAGE=node:22-bookworm-slim@sha256:<digest> --build-arg RUNTIME_IMAGE=ubuntu:24.04@sha256:<digest> -t xrepo-review:latest .`. Install the CLI with `npm ci && npm run build && npm install -g .`, or pass `xrepo_ref` and let the workflow build both. The installed CLI and image must come from the same commit the callers pin `review.yml` to (or pass `xrepo_ref`): on a mismatch the publish job fails without publishing, because `xrepo publish` now requires `--repo` / `--pr-number`.
3. Copy `examples/policy.yaml` to `/etc/xrepo-review/policy.yaml` (owner root, mode 0644). Check it with `xrepo policy validate` and `xrepo policy tools <file> <owner/repo>`.
4. Create a GitHub App with contents:read and install it on every owner in `mirror.repos`. Set `vars.XREPO_APP_CLIENT_ID` and `secrets.XREPO_APP_PRIVATE_KEY`. Run `sync.yml` on an `xrepo-sync` runner on the review host, or a systemd timer (one `--owner` run per owner).
5. Optional retries: a second App with actions:write and pull-requests:write, then `retry.yml`. Variables: `XREPO_CALLER_WORKFLOW`, `XREPO_PUBLISHER_LOGIN`, `XREPO_RETRY_OWNERS`.
6. Organisation secrets:
   - `CLAUDE_CODE_OAUTH_TOKEN` or `ANTHROPIC_API_KEY` (the subscription token wins when both are visible);
   - `XREPO_NOTIFY_SECRETS`, if notifications are used;
   - `XREPO_DISPATCH_TOKEN`, needed for any dispatch.
7. In each repo, add `examples/caller.yml` as `.github/workflows/xrepo-review.yml`, pinned to a commit SHA.
8. Make it binding: an org ruleset "Require workflows to pass", CODEOWNERS on `.github/workflows/`, and branch protection that dismisses stale approvals when approvals are on.
9. Hosted mode instead: use `examples/caller-hosted.yml` (mode hosted, `xrepo_ref` set to a SHA, a scheduled `mirror-cache` job, the `XREPO_GITHUB_TOKEN` secret).

## 5. Verification

- **Build and type-check:** `npm run build` passes. `npm run typecheck` (source and tests) passes, and so does `npx tsc --noEmit -p .`.
- **Tests:** without Docker, 843 passed and 4 skipped (the Docker tests) across 14 files. With `XREPO_TEST_DOCKER_IMAGE=xrepo-review:final`, 847 of 847 passed. One new test covers `--help`.
- **Docker image:** rebuilt as `xrepo-review:final`. The base images came from `mirror.gcr.io` (node, plus `ubuntu:24.04` as the runtime base) and npm used the proxy CA as a build secret. The mirror and the CA were sandbox workarounds; ubuntu:24.04 has since become the default runtime base (ripgrep 14.1, git 2.43). Checks inside the container with the production flags:
  - user is `nobody` (65534);
  - no capabilities (`CapEff` 0) and no-new-privileges is on;
  - only the `lo` network interface, and outbound fetch fails;
  - the root filesystem is read-only;
  - `/tmp` is writable but will not execute files;
  - ripgrep 14.1.0 and git 2.43.0 are present, ctags and ast-grep are absent;
  - `policy validate` works.
- **Real Claude CLI 2.1.319, no tokens spent:** I ran the generated docker-launcher args with an invalid model and an empty `HOME`. The CLI's start-up message listed exactly the 10 expected `mcp__xsearch__*` / `mcp__xreview__*` tools, no built-ins and no ToolSearch. Both servers connected from containers, permission mode was default, and the run ended with cost 0.
- **CLI flags:** every command rejects missing required flags, unknown flags and bad values with exit 2 (for example `--launcher podman`, `--run-attempt 0`, `--snapshot-grace-minutes -5`, a `--repo` outside `--owner`). `--help` now exits 0.
- **Tool outputs:** I rebuilt the e2e scenario and called every example in `docs/TOOLS.md` against the real servers. The commit SHAs match the doc; I corrected three examples to the real output.
- **Workflows:** all workflow and policy YAML files parse, and both policies pass `policy validate`. actionlint was not re-run: running the downloaded actionlint binary was blocked by a permission rule, so I stopped there. It was clean in an earlier round; the workflow tests passed now.

## 6. Fixes made in this pass

- **`.github/workflows/review.yml`:**
  - the header's output list now includes `fired_outcomes`;
  - removed the wrong "blocked = verdict request_changes" claim from the header;
  - the `verdict` output description now says when it is empty and points to `fired_outcomes`.
- **`examples/caller-with-hooks.yml`:** the header no longer says request_changes means blocked, and documents `fired_outcomes`.
- **`.github/workflows/ci.yml` and `README.md`:**
  - removed the CI step that generated a copy of the test tsconfig; `npm run typecheck` already covers the tests via `tsconfig.test.json`;
  - `test/workflows.test.ts` now checks that `npm run typecheck` step, and still proves a type error in a test file fails it;
  - corrected the README comment about what `npm run typecheck` covers.
- **`README.md`:**
  - default title markers now list both `[skip review]` and `[no review]`;
  - the `agent.builtin_tools` row now spells out the real tool mapping;
  - the local-run example uses `e2e/policy.yaml` for both sync and prepare.
- **`docs/TOOLS.md`:**
  - the Grep `-C` example now has the full line and the real "Also matched, not shown" note;
  - the count example is now reproducible (`path: /repos`);
  - the `review_status` example now includes the `set_summary` call it reflects;
  - `add_comment`'s `path` also accepts `/pr/<path>`.
- **`src/cli.ts`:** `xrepo <command> --help` and `-h` print that command's usage on stdout and exit 0. Before, they printed "Unknown option '--help'" and exited 2, although the top-level usage told people to use them. Supporting change: each command's usage string is now exported. This is a purely additive change.
- **`SPEC.md`** (small additive changes):
  - added a bullet for `review_status`, which was implemented and documented elsewhere but missing from the spec;
  - added the missing source files, workflows, examples and docs to the directory layout;
  - corrected two layout lines: the `test/fixtures` folder does not exist, and the `policy/glob.ts` description named a function that is not there.
- **`package.json`:** removed the non-existent `schema` folder from `files`.

## 7. Known limitations and residual risks

- The caller workflow comes from the PR head. Without the org ruleset and CODEOWNERS, an author with write access can remove the review.
- Grep works as a yes/no oracle on readable content, and readable code can be quoted in comments. The deny list is the real protection.
- Fork PRs are not reviewed. A required status check cannot gate them; use the required-workflow ruleset.
- Artifacts (3-day retention) hold the unsanitised draft and the resolved policy, visible to anyone with read access to Actions.
- The default `github-actions[bot]` identity is shared with other workflows; a GitHub App token with `--self-login` is better.
- The workflows have not been run on GitHub from here; `e2e.yml` covers that.
- `usage_limit`, `error` and `incomplete` were tested with recorded logs, not live runs.
- `package.json` says Node >=20, but everything was verified on Node 22 only.
- `docs/RESEARCH.md` says "t3code exposes ~72 MCP tools" while `docs/TOOLS.md` calls it a control surface with no code-navigation tools. Both can be true, but I could not re-check either claim offline.

## 8. Decisions for a human

1. `review.yml` and `mirror-cache.yml` default `xrepo_repo` to `dudibuilds/claude-review`, and the TOOLS.md samples show that name, while every example uses `acme/xrepo-review`. Confirm the canonical repo name, or make the input required.
2. Whether to enable approvals at all, and whether bot approvals should count toward required reviews (GitHub's behaviour here is unclear).
3. Self-hosted or hosted mode per organisation. Hosted mode needs `XREPO_GITHUB_TOKEN` and the cache warm-up job.
4. Subscription token versus API key per repo group. There is deliberately no automatic failover between personal subscriptions, because of the subscription terms.
5. The `--snapshot-grace-minutes` default of 60 must stay above the review job's 45-minute timeout if that timeout changes.
6. Whether to add actionlint to CI.
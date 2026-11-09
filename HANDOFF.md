# HANDOFF: continue this project on a local machine

You are a Claude Code agent picking up a project that was built in a cloud session. This file is
your briefing. Read it fully, then read `SPEC.md` (the design contract) and `README.md`. Before
changing anything, confirm the next step with the user.

The user's GitHub account is `dudibuilds`. The target repository is `dudibuilds/claude-review`.
The code and package are still named `xrepo-review` (CLI: `xrepo`); the rename is a later step
(see "Next steps").

---

## 1. What this is

**xrepo-review** is an org-grade, policy-gated, cross-repo pull-request reviewer. It runs inside
the official `anthropics/claude-code-action@v1`.

- **The agent gets no built-in tools.** It has exactly 11 MCP tools on two servers:
  - **xsearch** (read-only, network-isolated container): `ListRepos`, `PrDiff`, `Grep`, `Glob`,
    `Read`. These use the same names, parameters and output as Claude Code's own Grep, Glob and
    Read, over virtual paths: `/pr` is the PR head, `/repos/<owner>/<name>` is a mirrored repo.
  - **xreview**: `add_comment`, `set_summary`, `set_verdict`, `add_labels`, `review_status`,
    `finish`. It only appends to a draft file.
- **A devops-owned policy manifest** (`/etc/xrepo-review/policy.yaml`, or a pinned repo path in
  hosted mode) decides:
  - which repos are readable and what is denied;
  - which tools, verdicts and labels are allowed;
  - budgets;
  - what happens on each outcome: completed, incomplete, usage_limit, error or skipped. Options
    are comment, check run, labels, Slack/webhook, `repository_dispatch` and retry.
- **A separate publish job** posts everything after sanitising it. It is the only job holding a
  write token, and it runs no AI.
- **Scheduled jobs:** `sync` keeps a local mirror of the readable repos; `retry` re-runs postponed
  reviews.

Architecture, file map, deploy steps and verification evidence: `docs/BUILD-REPORT.md`.

## 2. The user's rules (non-negotiable)

1. **The agent can never read or change the policy manifest.** That includes the agent itself, a
   PR, and the mirror. In hosted mode the policy path is hidden from `/repos`.
2. **The MCP servers hold no credentials and have no network.** They run with
   `--network none`, a read-only root, all capabilities dropped and user 65534.
3. **Don't over-engineer.** No "guardrail" heuristics, no ctags and no ast-grep (both were measured
   and rejected). Keep the tools Claude-Code-shaped.
4. **No tool deferral.** Every MCP tool carries `_meta: {"anthropic/alwaysLoad": true}`, and
   `--tools ""` removes all built-ins, including ToolSearch.
5. **No automatic failover between personal Claude subscriptions.** Per-group accounts are
   configuration only. If both secrets are visible, `CLAUDE_CODE_OAUTH_TOKEN` wins over
   `ANTHROPIC_API_KEY`.
6. **Never ask the user to paste a secret into chat.** The user sets it themselves:
   `gh secret set CLAUDE_CODE_OAUTH_TOKEN -R dudibuilds/claude-review` (the token comes from
   `claude setup-token`).
7. **Confirm before anything outward-facing:** pushing, force-pushing, changing repo visibility,
   posting on PRs.

## 3. Current state (cloud session, then a local fix pass on 2026-11-10)

- **Git:** branch `main`. `origin` is `dudibuilds/claude-review` (public); `main` was first pushed
  on 2026-11-10.
- **Checks:**
  - `npm run build` passes.
  - `npm run typecheck` passes; it covers `src/` and `test/` via `tsconfig.test.json`.
  - `npx vitest run`: 14 files, 942 passed and 5 skipped (macOS, Node 24, git 2.50, ripgrep 15).
    Four skipped tests need Docker and one needs `pandoc`.
  - The Docker tests and the Docker image have not been run since the fix pass (no Docker on that
    machine). The CI `image` job is the first check of the new ubuntu:24.04 runtime base.
- **Docker sandbox:** checked inside the container with the production flags. It runs as user
  65534, has no capabilities, only the loopback interface (outbound fails), a read-only root, and
  `/tmp` mounted noexec. ripgrep 14.1 and git 2.43 are present.
- **Real Claude CLI 2.1.319** was run with the generated arguments (no tokens spent). It listed
  exactly the 10 `mcp__xsearch__*` and `mcp__xreview__*` tools expected for that policy (xreview
  registers a tool only when the policy enables it), with no built-ins and no ToolSearch. A real
  agent run had also completed earlier in the build.
- **actionlint** was clean on all workflows and example callers in the second-to-last pass. It
  was not re-run after the final doc and workflow-header edits.
- **Not yet verified on GitHub:**
  - the workflows have never run on GitHub;
  - nothing has been posted to a real PR;
  - the `usage_limit`, `error` and `incomplete` paths were tested only with recorded logs.

**How it was built.** A multi-agent build ran: research, build, integrate, then two rounds of 6
review lenses with adversarial verification, fixers, re-integration and a final check.
- Round 1 confirmed 40 findings, 3 of them high severity.
- Round 2 confirmed 44 findings, 2 of them high severity.
- Almost all were fixed. What is left is in section 6.

**Local fix pass (2026-11-10).** An audit of the build found eight problems. All were fixed and
independently reviewed over seven fix-and-review rounds:
- the publisher takes the PR identity from the workflow (`--repo`, `--pr-number`, `--head-sha`),
  refuses an artifact that disagrees, and checks the approve gates against GitHub's own file list;
- no review is posted unless the reviewed commit is still the PR head, and an older run never
  republishes over a newer one (hidden run marker);
- a finished draft is always `completed`, and usage-limit detection needs structured status or
  the CLI's own phrases;
- mention and fence bypasses in the sanitiser are closed;
- the two-dot diff fallback is used only when base is an ancestor of head;
- sync no longer retires a repo after a case-only rename;
- redaction covers more token formats and the default deny globs more credential files (an
  unquoted-YAML password rule was tried and removed, because it redacted ordinary code);
- the default image is ubuntu:24.04 (ripgrep 14.1, git 2.43), and the timing-flaky glob test is
  fixed.

What the reviewers left as follow-ups is at the end of section 6.

## 4. Set up on this machine (macOS)

```bash
brew install node@22 ripgrep git     # rg must be on PATH for the search tests; Apple's git is 2.39
cd ~/claude-review                   # wherever the bundle was cloned
npm ci
npm run build
npm run typecheck
npx vitest run                       # expect 942 passed, 5 skipped
```

Notes:
- **git version.** Apple's git 2.39 has no `--attr-source`. The code falls back to an isolated empty
  work tree, but everything was verified with git 2.43, so prefer Homebrew git (put
  `/opt/homebrew/bin` first on PATH).
- **Docker tests** need Docker Desktop:
  ```bash
  docker build -f docker/Dockerfile -t xrepo-review:dev .
  XREPO_TEST_DOCKER_IMAGE=xrepo-review:dev npx vitest run   # the 4 Docker tests then run too
  ```
  The cloud build needed sandbox-only workarounds that you should not need: base images from
  `mirror.gcr.io` and an `npm_ca` build secret. The default runtime base is now ubuntu:24.04
  (`RUNTIME_IMAGE`), for ripgrep 14.1 and git 2.43 (Debian 12 has ripgrep 13 and git 2.39, which
  lacks `--attr-source`); the CI image job asserts ripgrep >= 14.1 and git >= 2.43.
- Engines say Node >= 20, but only Node 22 was tested.

## 5. Next steps, in order

1. **Push to GitHub.** Done on 2026-11-10: `main` is on `dudibuilds/claude-review`, which the user
   chose to keep public (see `AGENTS.md`).
2. **Secrets.** The user runs `gh secret set CLAUDE_CODE_OAUTH_TOKEN -R dudibuilds/claude-review`.
3. **Real GitHub e2e (hosted mode).** Follow README "Testing on GitHub".
   - The README's `sed -i` line is GNU syntax; on macOS use `sed -i ''`, or edit the file directly.
   - Expected: a high-severity comment on `checkout.ts` citing `/repos/acme/api/src/orders.ts`, and
     a failing `xrepo-review-e2e` check.
   - Then deliberately exercise the `usage_limit` and `error` outcomes, and a re-run of an older
     run (the stale-run check), and confirm that what gets posted matches the policy.
4. **Add actionlint to CI.** Optional, but the user was asked (section 7).
5. **Fix the open items** in section 6, highest value first.
6. **Simplification pass.** The codebase (~14k src lines, ~12k test lines) is larger than it needs
   to be. Known duplication:
   - several truncate helpers;
   - several ways of reading and validating `GITHUB_API_URL` (`src/outcome/api-base.ts` should be
     the only one);
   - repo-name rules duplicated across modules;
   - duplicated MCP server bootstrap in `src/search/server.ts` and `src/review/server.ts`.

   Keep behaviour identical and the tests green.
7. **Rename `xrepo-review` to `claude-review`** if the user wants it. That is 375 occurrences in 55
   files: package name, labels, check names, markers, image name, docs. Markers such as
   `<!-- xrepo-review:... -->` and label names are matched at runtime, so keep the old forms
   recognised or accept a one-time break. Decide this before anyone deploys.
8. **Google Drive cleanup.** An earlier attempt uploaded the bundle to the user's Drive as 21
   base64 text parts in a folder named `claude-review`; parts 12 and 23 are missing, so that copy
   is incomplete. The user can delete that folder once this bundle is safe.

## 6. Open items (known, not fixed)

### Product behaviour
- **"Review context missing"** gives a neutral check, not a failing one, even with a blocking
  check. This is deliberate: the built-in error comment promises "does not block merging".
  Revisit only if the user wants fail-closed.
- **PrDiff hides removed key lines by heuristic.** Prepare does not save each file's base version,
  so key material on removed lines is detected by pattern.
- **PrDiff with no arguments returns only the file list,** not the diffs. Changing that would
  change the SPEC; the prompt asks for up to 10 files per turn instead.
- **`skip_bots` / `ignore_authors`** compare the event's sender with the PR author. Earlier
  commits by other people are not checked, because git authors can be faked.
- **A NUL byte makes a text file count as binary,** in every diff mode. The API-diff refusal for
  `.gitattributes` tricks is also a heuristic.
- **No retry marker is written without `GITHUB_RUN_ID`.** Only relevant outside Actions.
- **Surrogate pairs can still be split** in `search/text.ts` `oneLine` and in prepare's
  `cleanUntrusted`. That text goes only to the agent.
- **Lock race:** two syncs taking over the same stale lock at the same moment can still race on
  delete.
- **Inline comments off:** `block` then has no effect (the plan records why and the check is
  neutral). Approve was left unchanged in that configuration; decide whether it should behave the
  same way.
- **CI** generates its own test tsconfig in one step; `test/workflows.test.ts` depends on that.
  Harmless, but it duplicates `tsconfig.test.json`.

### Security limits (by design; documented in `docs/SECURITY.md`)
- **The caller workflow comes from the PR head.** Without an org ruleset ("Require workflows to
  pass") and CODEOWNERS on `.github/workflows/`, an author with write access can remove the
  review.
- **Grep is a yes/no oracle on readable content,** so a determined prompt can leak secrets one
  character at a time. The deny list is the real protection; keep secrets out of readable repos
  or deny them.
- **Fork PRs are not reviewed.** Use the required-workflow ruleset.
- **Artifacts** (3-day retention) contain the unsanitised draft and the resolved policy, readable
  by anyone with Actions read access.
- **The default `github-actions[bot]` identity** is shared with other workflows. A GitHub App token
  with `--self-login` is better.

### Follow-ups from the 2026-11-10 fix pass (reviewed, judged non-blocking)
- **Sanitiser:** a `</details>` inside a tilde fence nested in a list item or blockquote is kept
  as a tag, so the `<details>` can stay open over the publisher's footer. The hand-written
  Markdown sanitiser produced a new bypass in almost every review round; stripping all raw HTML
  would remove this whole class.
- **Publisher:** when posting the review fails, an approving plan still posts a `success` check
  titled "Approved" (the job exits 1). `listPullRequestFiles` validates line counts but not file
  names. `verifyReviewHead` with an empty head sha skips the read (not reachable from
  `xrepo publish`). A failed freshness read still means "publish as usual".
- **Classify:** an accepted phrase inside a sentence about the code under review still counts as
  a usage limit. The API's status-less `"rate_limit_error"` JSON and the old CLI wording
  "5-hour limit reached" (CLI 1.0.89 to 1.0.113) now classify as `error`.
- **Prepare:** a shallow probe that exits 0 with unexpected output is treated as shallow but has
  no test, and its error text blames a shallow checkout.
- **Deny globs:** a file named plain `kubeconfig`, or `kubeconfig.json`, stays readable.
- **Redaction:** unquoted YAML values, and quoted passwords with a space or kebab words, are not
  redacted. The deny globs are the protection.

### Docs to double-check
- `docs/RESEARCH.md` says t3code exposes ~72 MCP tools; `docs/TOOLS.md` calls it a control surface
  with no code-navigation tools. Both may be true; neither could be re-checked offline.

## 7. Decisions waiting for the user

1. **Canonical repo name.** `review.yml` and `mirror-cache.yml` default `xrepo_repo` to
   `dudibuilds/claude-review`, while the examples use `acme/xrepo-review`. Keep the default, or
   make the input required?
2. **Approvals.** Enable bot approvals at all? Should they count toward required reviews?
3. **Self-hosted or hosted mode** per organisation. Hosted mode needs `XREPO_GITHUB_TOKEN` and the
   cache warm-up job.
4. **Subscription token or API key** per repo group.
5. **Grace period.** `--snapshot-grace-minutes` defaults to 60 and must stay above the review job's
   45-minute timeout if that changes.
6. **actionlint** in CI: yes or no?
7. **Rename** to `claude-review` (section 5, step 7).
8. **Repo visibility:** decided on 2026-11-10: public (recorded in `AGENTS.md`).

## 8. Gotchas learned the hard way

- **Claude Code CLI flags:**
  - `--tools ""` removes all built-ins, including ToolSearch.
  - `--disallowedTools Read,Grep,Glob` still leaves `mcp__xsearch__*` working.
  - The subagent tool is called `Agent`.
  - MCP tools load non-deferred when they carry `_meta: {"anthropic/alwaysLoad": true}`.
- **Mentions:** a zero-width space after `@` neutralises it, including in inline code and in
  `_@user_` emphasis. The sanitiser does this; don't "clean it up".
- **Review markers:** every review body ends with `<!-- xrepo-review:review -->`. Dismissals only
  touch our own marked reviews, or the exact legacy wording. Review bodies and the sticky also
  carry `<!-- xrepo-review:run=<id> -->` (read only at the end of the body), so an older run
  re-run later never republishes over a newer run.
- **macOS:**
  - Terminal can't read `~/Downloads` or `~/Desktop` without permission (TCC). Move files to the
    home folder, or give Terminal Full Disk Access.
  - `sed -i` needs `''`.
- **Concurrency:** if you run a multi-agent workflow, its parallelism is capped by CPU count.
  Per-finding adversarial verification is expensive; one verifier per finding was enough here.

## 9. Where things are

| Path | What |
|---|---|
| `SPEC.md` | design contract (keep it in sync with the code) |
| `README.md` | user-facing docs: quick start, hosted mode, policy reference, outcomes, chaining, accounts, testing |
| `docs/BUILD-REPORT.md` | final verification report from the build: architecture, file map, tool comparison, deploy steps, evidence |
| `docs/SECURITY.md` | threat model and limits |
| `docs/TOOLS.md` | every agent tool with real example output |
| `docs/RESEARCH.md` | source-verified notes on claude-code-action, the Agent SDK and the tool survey |
| `docs/E2E-LOCAL.md` | running the full pipeline locally against the fixtures |
| `examples/` | `policy.yaml` and the caller workflows (self-hosted, hosted, with hooks) |
| `.github/workflows/` | `review.yml` (reusable), `sync.yml`, `retry.yml`, `mirror-cache.yml`, `ci.yml`, `e2e.yml` |
| `e2e/` | fixture repos, `make-bare-repos.mjs`, e2e policy |
| `src/` | see the file map in `docs/BUILD-REPORT.md` |

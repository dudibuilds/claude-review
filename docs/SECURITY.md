# Security model

xrepo-review lets an AI agent read code across repositories and comment on pull requests. The
agent reads attacker-controllable text (PR title, body, diff, code in every readable repository),
so the design assumes **the agent can be fully prompt-injected** and bounds what it can do
regardless of what it decides.

## Components and privileges

| Component | Runs | Can read | Can write | Network | Secrets |
|---|---|---|---|---|---|
| `xrepo prepare` | review job, trusted code | policy, event, PR checkout (as data), mirror | work dir, `$GITHUB_WORKSPACE/.git` | GitHub API (read-only token, diff fallback) | read-only job token |
| Claude Code (agent) | review job, inside claude-code-action | only through the two MCP servers | only through xreview | Anthropic API | Claude token (in its env, unreachable: no tool can execute or read files) |
| `xsearch` MCP | `docker run --network none --read-only --cap-drop ALL --user 65534` | `/pr`, readable `/repos/*` (read-only mounts), ctx | nothing | none | none |
| `xreview` MCP | same container hardening | ctx (read-only) | appends to `out/draft.jsonl` | none | none |
| `xrepo publish` | publish job, trusted code, no AI | artifact (ctx, draft, trimmed log), trusted policy | GitHub (review, comment, check, labels) | GitHub API, notification hosts | write token, notify / dispatch secrets |
| `xrepo sync` | scheduled, on the runner host | GitHub (App token, contents:read) | the mirror | GitHub | App installation token (per run and per owner: a token covers one account) |

## Threats and what each layer guarantees

**T1 — Prompt injection makes the agent attempt a disallowed action** (approve, block, label,
spam, leave the sandbox).
- Disallowed capabilities are not registered as tools at all; `set_verdict` / `add_labels` enums
  list only allowed values.
- Claude Code runs with `--tools ,` (no built-ins: no shell, no file read/write, no web),
  `--strict-mcp-config`, an exact `--allowedTools` list and `--disallowedTools` for every dangerous
  built-in. ToolSearch is never enabled.
- The review job's GitHub token is read-only (`contents: read`, `pull-requests: read`).
- The publisher re-validates everything (lines inside the diff, severities, caps, verdict rules:
  approve only within `approve.*` limits, request_changes only with a finding ≥ `block.min_severity`)
  and an incomplete run never approves or blocks. xreview, the prompt and the publisher take these
  rules from one module (`src/review/rules.ts`), so the agent is never told an action is possible
  that the publisher then refuses; PR-controlled file names never enter the trusted prompt.
- A blocking check (`block.method` `check` / `both`) cannot be passed by skipping the review
  through anything the PR author controls (title marker, size limits, a diff the GitHub API will
  not serve, a `.gitattributes` change that makes prepare refuse the API diff): such a skip fails
  the check unless `outcomes.skipped.check_conclusion` explicitly allows it. A draft skip fails it
  as "Review pending" until the ready_for_review run reviews the PR, so "mark ready and merge at
  once" cannot beat the review. A check that blocks a review is only overridden by
  `outcomes.blocked.check_conclusion`, never by `completed`'s.
- A run that did not review the commit (skip, error, usage limit, incomplete) never posts a
  passing conclusion over a failing check on that commit, and no run posts over a newer workflow
  run's check for the same commit (check runs carry the run id in `external_id`).
- The bot and ignored-author skips apply only when the event's sender is the PR author itself, so
  pushing to a bot's branch does not skip the review. (Earlier commits by other people are not
  checked: git commit authors can be forged.)
- When GitHub refuses the APPROVE / REQUEST_CHANGES event (workflow token not allowed to approve,
  own PR), the review is posted as a comment and is not counted as approving or blocking. No
  review is posted unless the reviewed commit is still the PR's head (read right before posting;
  a moved head makes the run stale, and a PR that cannot be read then posts no review and fails the
  publish job). An APPROVE also needs an open PR and is withheld
  when `approve.never_paths` / `approve.max_changed_lines` fail on GitHub's own file list for the
  PR (an unreadable or truncated list withholds it too), so a doctored artifact cannot approve
  paths the policy protects.
- The publisher takes the PR identity (repository, number, head sha) from the workflow
  (`--repo`, `--pr-number`, `--head-sha`), never from the artifact the agent's job uploaded: an
  artifact naming another PR or commit publishes nothing. The PR link in notifications and the
  repository_dispatch payload is built from that identity, never from the artifact. With neither
  `--head-sha` nor the artifact's context, the head is read from GitHub before anything is
  published, so the stale-run checks still apply; an unreadable PR publishes nothing.
- Approvals and change requests stay in force on GitHub until dismissed. The publisher dismisses
  its earlier approvals on every run that does not approve (skips, errors, usage limits,
  incomplete and request-changes runs included), and its change requests only from a run for the
  PR's current head and only those on older commits; a re-run of an older workflow run (or a run
  whose commit was superseded while it ran) is "stale" and posts only its check: it never
  approves, dismisses, comments or labels. Review bodies and the sticky comment end with the
  run's marker (`<!-- xrepo-review:run=<id> -->`), so an older run re-run later is stale too.
  Only reviews by the publisher's identity that carry the
  hidden `<!-- xrepo-review:review -->` marker are ever dismissed, because the default identity
  (`github-actions[bot]`) is shared by every workflow using `GITHUB_TOKEN`; prefer a GitHub App
  token with `--self-login`.
- The kill switch (`enabled: false`) is checked again by the publisher on the live manifest: a run
  that passed prepare before the switch was flipped publishes only the `skipped` outcome.
- Re-running only the publish job cannot lift a block: it downloads exactly the artifact the review
  job reported (job output `artifact`, unaffected by the new `run_attempt`) and republishes the same
  review; when that context is unavailable it fails without writing anything, instead of posting
  the neutral `error` check over a failing one.

**T2 — The agent tries to read or change the policy.**
- No built-in file or shell tools; xsearch serves only `/pr` and the readable `/repos/*`.
- `prepare` refuses a policy path that resolves (lexically or through symlinks) inside the PR
  checkout, the work dir, the mirror or any `--untrusted-dir`.
- The publish job deletes the artifact's `policy.resolved.json` and re-resolves the policy from the
  trusted manifest (`--policy`); the publisher itself also ignores `ctx/policy.resolved.json`
  whenever `--policy` is given (and an unreadable manifest fails the job instead of falling back),
  so nothing that passed through the agent's job decides what is allowed.
- Mirrors can contain the repository that holds the policy (hosted mode: `xrepo_repo`). xsearch
  hides `.github/xrepo/` (the documented location) in every `/repos` root, case-insensitively, and
  the exact `policy_file` path, which review.yml passes as `prepare --policy-repo-path` (→
  `search-mcp --policy-path`). `/pr` is unaffected (its author can read that copy anyway).

**T3 — Exfiltration of other repositories' code or secrets** through review comments.
- Per-PR-repository read allowlist (`cross_repo.readable` / `deny`) enforced by xsearch:
  unreadable repositories do not exist for the agent, not even their names.
- Path denylist (`.env`, keys and keystores (`*.jks`, `*.keystore`, `*.ppk`), credential files
  (`.git-credentials`, `.aws/credentials`, `.docker/config.json`, `.kube/config`,
  `*kubeconfig*.yaml` / `*kubeconfig*.yml` such as `prod-kubeconfig.yml`, `*.kubeconfig`; a plain
  `kubeconfig` file or directory without an extension stays readable), `secrets/`, tfstate
  and `terraform.tfvars` / `*.auto.tfvars`, … plus `search.deny_globs`) behaves like
  missing files, matched case-insensitively (`.ENV`, `KEY.PEM`; ripgrep gets them as `--iglob`,
  which also overrides any glob the agent passes); `.git` is never served; symlinks escaping a root
  are refused.
- Secret redaction on every xsearch response; a private-key block is hidden from `BEGIN` to the
  next `-----END ` (within 64 KiB) whatever window Read or Grep shows, the same rule
  `redactSecrets` applies to whole texts (one implementation of the block rules, exported by
  `src/common/redact.ts`). Besides token formats and key blocks, assignments are redacted in three
  forms: quoted values, env-file `KEY=value` lines whose UPPER_SNAKE key ends in a secret word, and
  `aws_secret_access_key` lines. Unquoted YAML values (`password: value` without quotes) are not
  redacted; the deny globs are the protection for config files. A `Bearer` token is redacted when
  it has a digit, or when it is at least 32 characters and not an identifier-like name. PrDiff redacts line by line: context and added lines inside a key block
  of the PR's version of the file, key blocks within each hunk on both sides, and removed lines
  that look like key material in a hunk that touches a key (heuristic: xsearch has no base
  version of the file). ripgrep runs with `--encoding=none`, so a UTF-16 file is binary for Grep
  as for Read and cannot slip past the whole-file key scan. Agent globs never reach a backtracking
  regex (linear matcher, bounded brace expansion), and every search honours its deadline. xreview rejects comment text that looks like a secret; the
  publisher redacts again and neutralises images, non-allowlisted links (shown as inert text),
  `@mentions`, HTML and link-reference tricks (no kept construct contains a literal `@`: `@`
  becomes `%40` in every kept link destination, a kept bare URL with `@` is written as
  `<https://…%40…>` (GitHub does not link even that everywhere), and kept `<img>` alt text gets
  U+200B after `@`, so a kept construct that GitHub shows as text (a math block, including one in
  a list or blockquote, inline math, an escaping backslash, an HTML block) cannot ping; a
  backslash right before any kept construct is also separated from it by U+200B, so it cannot
  escape the `<`; every kept destination has `|`, `'` and `"` percent-encoded,
  so a table cell boundary cannot split it and an HTML block cannot read it as a tag with an open
  attribute value, and a truncation that cuts through a kept `<…>` drops it instead of leaving it
  open; text glued in front of a kept URL's scheme, as in `@victim.https://…`, stays outside the
  link, defanged and subject to mention neutralisation; an `@` right after `&` plus letters or
  digits, as in `&amp@user`, is neutralised too, because GitHub decodes semicolon-less legacy
  entities in HTML blocks; a top-level fence whose info string starts with `math`, or contains `&`
  or `\`, is rewritten to a `text` fence, since GitHub renders math blocks as text with live
  mentions and references). Its sanitised output never ends inside an open code
  fence or `<pre>` (checked with CommonMark's block rules), so text that follows, such as a
  suggestion block, cannot be swallowed or turned into raw HTML.
- The execution log uploaded as an artifact is trimmed by `xrepo collect`: tool results, tool
  inputs and assistant text are replaced by markers before upload.

**T4 — 0-day in the search MCP / ripgrep** (malicious file content in a mirrored repo).
- Containers: `--network none --read-only --cap-drop ALL --security-opt no-new-privileges
  --pids-limit 256 --memory 1g --user 65534:65534 --tmpfs /tmp:noexec,nosuid`; mounts read-only
  except the draft directory for xreview; no environment variables, no Docker socket.
- Only the mirror repositories this PR may read are mounted (one bind mount per repository), and
  xreview gets neither the PR checkout nor the mirror.
- Worst case the attacker reads what xsearch could already read, from inside a container with no
  network; output still flows only through the agent and the publisher's sanitiser.

**T5 — The PR plants Claude configuration** (`.claude/settings.json` hooks, `.mcp.json`,
`CLAUDE.md`, skills) in its checkout.
- The PR checkout is the `pr/` sub-directory; Claude Code's working directory
  (`$GITHUB_WORKSPACE`, claude-code-action has no cwd input) is initialised by `prepare` as an
  empty git repository, so no PR file sits at its top level.
- `--setting-sources user` loads no project / local settings, hooks, CLAUDE.md, skills or agents
  (including lazily-loaded subdirectory ones); `--strict-mcp-config` ignores `.mcp.json`.
- claude-code-action additionally restores `.claude`, `.mcp.json`, `CLAUDE.md`, … from the base
  branch before starting the CLI.
- PR code is never built or executed (no `npm install`, no scripts): checkout with
  `persist-credentials: false`, no submodules, no LFS; git runs with argument arrays,
  `--no-ext-diff --no-textconv` and gitattributes from the base commit (`--attr-source`) so a PR
  cannot hide changes behind `-diff`. On git older than 2.40 (no `--attr-source`) the diff runs in
  an isolated empty work tree and index, i.e. with no repository attributes at all, never the
  PR's. The GitHub API diff fallback (a shallow checkout where base is not a visible ancestor of head,
  so the local merge base cannot be trusted) is refused when the PR
  changes a `.gitattributes` file and the API shows any file as binary; use `fetch_depth: 0`.
  That refusal, and an API diff GitHub will not serve for its size (HTTP 406), skip the review as
  author-controlled skips (a blocking check fails), never as an infrastructure error.
  (Binary detection by content remains: a NUL byte still makes a file show as binary.) git gets
  explicit diff options that override the runner's own git config, so operator settings cannot
  change the patch the agent and the publisher see.

## Residual risks (accepted, documented)

1. **The caller workflow comes from the PR head.** On `pull_request`, GitHub runs the workflow
   files of the PR's merge commit. A PR author **with write access** can edit their repository's
   caller workflow (drop the review, change inputs, point `uses:` elsewhere) in the same PR.
   Mitigation (required below): org ruleset "Require workflows to pass before merging" pointing at
   a centrally owned workflow at a pinned SHA, or a required check whose expected source is pinned,
   plus CODEOWNERS on `.github/workflows/`. Without those, xrepo-review is advisory for authors who
   can push workflow changes.
2. **Write-access PR authors are trusted by claude-code-action** (it refuses non-writers), so fork
   PRs are a non-goal (`skip_forks: true`). Fork `pull_request` runs get a read-only token, so the
   `skipped` check / comment of a fork PR are best effort (the publish job stays green); a
   required status check cannot gate fork PRs, the required-workflow ruleset can. With `xrepo_ref`
   set (hosted mode) and a private `xrepo_repo`, a fork run cannot check out the trusted source at
   all (no secrets, and `github.token` reads only the calling repository): the review job stops
   right after that checkout with a notice and the publish job is skipped, so nothing is written
   and the run ends green. Only that checkout may fail on a fork run; for any other run a failed
   trusted checkout still fails the job.
3. **Grep as an oracle**: `files_with_matches` / `count` answer yes/no for any regex, so an
   injected agent can probe a readable secret character by character and encode it into a
   comment. Redaction catches known secret shapes; the deny list is the real protection — keep
   secrets out of readable repositories and deny-list secret paths.
4. **Readable code can be quoted**: a comment may legitimately quote code from another readable
   repository. Anyone who can read the PR sees it. Only make repositories readable for PRs whose
   readers may see them.
5. **Artifacts** (3-day retention) are readable by everyone with read access to the repository's
   Actions: PR context, diff, resolved policy (no secret values: only key names) and the
   pre-sanitisation draft (which may quote other readable repositories). The execution log is
   trimmed.
6. **Self-hosted state**: `~/.claude`, the workspace and Docker images persist on non-ephemeral
   runners; a compromised job could poison them for the next one. Use ephemeral runners.
7. **Plugins are trusted code** (`agent.plugins`): they run inside the agent's job with its
   environment (hooks can execute commands and see the Claude token). Only install plugins devops
   reviewed, from pinned marketplaces. Plugin MCP servers do not start (`--strict-mcp-config`).
8. **Local launcher** (`--launcher local`) runs the MCP servers on the runner without isolation and
   with the job's environment. Development and tests only.
9. **Anthropic API**: the PR content and readable code are sent to the model provider configured
   by the token.

## Required hardening for production

- **Dedicated runner group** for these workflows (`runner_labels`), **ephemeral** (one job per
  runner) and restricted to the xrepo-review workflows (runner group "Selected workflows", GHEC /
  GHES). Never share these runners with CI that builds or runs PR code.
- **Mirror writable only by sync**: run `xrepo sync` under a separate identity (systemd timer or a
  dedicated `xrepo-sync` runner on the host) and mount / permission the mirror read-only for the
  review runners. Review jobs never write it. Keep `--snapshot-grace-minutes` (default 60) above
  the review job's timeout (45 minutes in review.yml) so a running review never loses the
  snapshot it reads. The same grace applies to a repository dropped from the mirror set: it is
  retired at once (no new review sees it; the sync report lists it under `retired`) and deleted
  only after the grace period. Should a root still vanish under a running review (manual
  deletion), xsearch skips it with a note instead of failing every search.
- **Policy root-owned and read-only** to the runner user (`/etc/xrepo-review/policy.yaml`, mode
  0644, owner root); `loadPolicy` warns when it is group- or world-writable. In hosted mode the
  policy comes from the trusted xrepo checkout at a pinned commit, never from the PR.
- **Pin everything by SHA / digest**: the reusable workflow (`uses: …/review.yml@<sha>`),
  `anthropics/claude-code-action@<sha>` (pinned in `review.yml`), every `actions/*` step, the base
  images (`NODE_IMAGE=node:22-bookworm-slim@sha256:…`, `RUNTIME_IMAGE=ubuntu:24.04@sha256:…`) and the published xrepo image
  (`ghcr.io/<org>/xrepo-review@sha256:…`). `xrepo_ref` must be a reviewed commit SHA.
- **Org ruleset** requiring the review workflow (or its check with a pinned expected source) on
  protected branches, and **CODEOWNERS** for `.github/workflows/` (and `.github/` in general)
  owned by the platform team.
- **Private repositories only** (self-hosted runners must not serve public repositories).
- **Least-privilege tokens**: the review job keeps `contents: read, pull-requests: read`; the
  publish job gets `pull-requests: write, issues: write, checks: write, contents: read`; the sync
  App only `contents: read`; the retry App only `actions: write, pull-requests: write`. An
  installation token covers one account, so sync.yml / retry.yml mint one per owner, each used only
  for that owner's repositories (`--owner`), and never a token broader than one installation. The
  review job passes Claude exactly one credential (the subscription token when visible, else the
  API key), so an API key visible to the repository cannot silently take over. Keep the
  caller's `permissions:` minimal — `github.token` is visible to the agent's process. Never grant
  `contents: write` for `repository_dispatch` (it would also allow pushing code): outcome
  dispatches use the separate `XREPO_DISPATCH_TOKEN` secret (a fine-grained token / App token with
  `contents: write` on the dispatch targets only), also for the PR's own repository.
- **Secrets**: notification URLs and HMAC keys live in `XREPO_NOTIFY_SECRETS` (or
  `/etc/xrepo-review/notify.json`), never in the manifest; only the publish job receives them.
- **Approvals off unless needed**: `approve.enabled: false` by default; when enabled, keep
  `never_paths` covering `.github/**` and `CODEOWNERS`, turn on branch protection's "Dismiss stale
  pull request approvals when new commits are pushed", and do not rely on bot approvals counting
  toward required reviews.
- **Policy patterns**: `cross_repo.readable` / `deny` and `mirror.exclude` take only `owner/name`,
  `owner/*` or `*`; any other form fails validation (a deny glob that never matches would fail
  open). Run `xrepo policy validate` after every edit: it also warns when a repository's own
  `cross_repo.deny` (which replaces the defaults list) drops a defaults entry that is still
  readable there.

## Reporting

Please report vulnerabilities privately to the repository owners (GitHub security advisories) and
not in public issues.

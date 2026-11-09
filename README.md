# xrepo-review

Policy-gated, **cross-repository** pull-request review that runs inside the official
[`anthropics/claude-code-action@v1`](https://github.com/anthropics/claude-code-action).

A PR in `acme/api` renames a JSON field; `acme/web` and `acme/mobile` still read the old name.
A reviewer that only sees the diff cannot notice. xrepo-review gives Claude read-only, sandboxed
search over the PR **and** the repositories that depend on it, lets it record findings through a
narrow review API, and publishes them with a deterministic, policy-checking publisher that holds
the only write token.

- **Exactly two tools servers, nothing else.** `xsearch` (Claude Code's own Grep / Glob / Read over
  virtual `/pr` and `/repos/<owner>/<name>` paths, plus `ListRepos` and `PrDiff`) and `xreview`
  (`add_comment`, `set_summary`, `set_verdict`, `add_labels`, `review_status`, `finish`). No
  shell, no file tools, no web. Disabled capabilities are not even registered.
- **One policy manifest** (YAML, owned by devops, outside every PR checkout) decides what each
  repository's reviews may read and do: comment budget, approve / block rules, labels, which other
  repositories are readable, what happens on usage limits and errors.
- **Deterministic publisher** in a separate job: validates the draft against the policy, keeps only
  comments on diff lines, sanitises every byte (secrets, links, mentions, images, HTML), posts the
  review / sticky summary / check run / labels, fires notifications and exposes outputs your
  workflows can chain on.

## Architecture

```
 pull_request ─► caller workflow (15 lines, per repo) ─► reusable workflow review.yml
                                                          │
 ┌────────────────────── job: review (read-only token) ───┴──────────────────────────────────┐
 │  checkout PR head → $GITHUB_WORKSPACE/pr      (data only: never built or executed)         │
 │  xrepo prepare  ── policy (/etc/xrepo-review/policy.yaml or trusted checkout @sha)         │
 │     ├─ skip rules (draft, fork, bot, size, markers, kill switch)                           │
 │     ├─ ctx/  pr.json, diff.patch, policy.resolved.json      out/draft.jsonl (empty)         │
 │     ├─ agent/mcp.json  (two stdio servers)    prompt    claude_args                         │
 │     └─ $GITHUB_WORKSPACE := empty git repo (claude-code-action's cwd)                      │
 │                                                                                            │
 │  claude-code-action@v1 (pinned SHA)                                                        │
 │     claude -p --tools , --setting-sources user --strict-mcp-config --allowedTools <exact>  │
 │        │ stdio                                   │ stdio                                   │
 │   ┌────▼──────────── docker ───────────┐   ┌────▼──────────── docker ───────────┐          │
 │   │ xsearch   --network none           │   │ xreview   --network none           │          │
 │   │ --read-only --cap-drop ALL         │   │ --read-only --cap-drop ALL         │          │
 │   │ uid 65534                          │   │ uid 65534                          │          │
 │   │ /pr ro   /mirror ro   /ctx ro      │   │ /ctx ro   /out rw (draft.jsonl)    │          │
 │   └────────────────────────────────────┘   └────────────────────────────────────┘          │
 │  xrepo collect → artifact: ctx/, out/draft.jsonl, trimmed execution log (3 days)           │
 └────────────────────────────────────────────────────────────────────────────────────────────┘
 ┌────────────────────── job: publish (only write token, no PR checkout, no AI) ──────────────┐
 │  xrepo publish: classify outcome (completed / incomplete / usage_limit / error / skipped)  │
 │     → re-resolve policy from the trusted manifest → validate + sanitise draft              │
 │     → review + sticky summary + check run + labels → notifications / dispatch / retry label│
 │     → outputs: outcome, verdict, reason, reset_at, findings, top_severity, fired_outcomes  │
 └────────────────────────────────────────────────────────────────────────────────────────────┘
 scheduled:  xrepo sync  (mirror: /srv/xrepo/mirror/<owner>/<repo>/current -> snapshots/<sha>)
             xrepo retry (re-runs reviews postponed by usage limits)
```

Details: [SPEC.md](SPEC.md) (design contract), [docs/SECURITY.md](docs/SECURITY.md) (threat model,
required hardening), [docs/TOOLS.md](docs/TOOLS.md) (agent tools with real outputs),
[docs/RESEARCH.md](docs/RESEARCH.md) (verified facts about the action, the CLI and GitHub),
[docs/E2E-LOCAL.md](docs/E2E-LOCAL.md) (one real agent run through the whole pipeline, with the
tool-call sequence, token / cost baseline and the published plan).

## Quick start (self-hosted, recommended)

1. **Runner host** (dedicated, ephemeral runners in their own group; see SECURITY.md): Docker,
   git, Node 22, label `xrepo-review`.
2. **Image and CLI**
   ```sh
   docker build -f docker/Dockerfile \
     --build-arg NODE_IMAGE=node:22-bookworm-slim@sha256:<digest> \
     --build-arg RUNTIME_IMAGE=ubuntu:24.04@sha256:<digest> -t xrepo-review:latest .
   npm ci && npm run build && npm install -g .     # puts `xrepo` on PATH
   ```
   (Or pass `xrepo_ref: <commit sha>` to the workflow and let it build both from this repository.)
   Build the CLI and image from the same commit your callers pin `review.yml` to (or pass
   `xrepo_ref`): on a mismatch the publish job fails without publishing, since `xrepo publish` now
   requires the `--repo` / `--pr-number` the workflow passes.
3. **Policy**: copy [examples/policy.yaml](examples/policy.yaml) to
   `/etc/xrepo-review/policy.yaml` (root-owned, mode 0644) and check it:
   ```sh
   xrepo policy validate /etc/xrepo-review/policy.yaml
   xrepo policy tools /etc/xrepo-review/policy.yaml acme/web     # what the agent will get
   ```
4. **Mirror**: create a GitHub App with `contents: read` on the repositories to mirror and run
   `xrepo sync --policy /etc/xrepo-review/policy.yaml --mirror /srv/xrepo/mirror` every few
   minutes (systemd timer, or [.github/workflows/sync.yml](.github/workflows/sync.yml) on a runner
   of that host), token in `XREPO_GITHUB_TOKEN`. An installation token covers **one account**
   (organization or user): install the App on every owner named in `mirror.repos` (the example
   mirrors `acme/*` and `acme-platform/ledger`, so two). sync.yml reads the owners from the policy
   and runs one job per owner with that owner's token; with more than one owner each job runs
   `xrepo sync --owner <owner>`, which syncs only that owner's repositories and leaves the other
   owners' mirrors to their own jobs. A systemd timer does the same: one
   `xrepo sync --owner <owner>` per owner, each with its own token.
   retry.yml (the `xrepo retry` sweeper) runs per owner the same way (`--owner`); its owners are
   those of `repos` keys and `mirror.repos` plus the workflow repository's owner, or exactly
   `vars.XREPO_RETRY_OWNERS` (JSON array) to leave out owners whose repositories are only mirrored.
5. **Secrets** (org level, `secrets: inherit`): `CLAUDE_CODE_OAUTH_TOKEN` (or
   `ANTHROPIC_API_KEY`; the subscription token wins when both are visible, see "Accounts");
   optional `XREPO_NOTIFY_SECRETS`. `XREPO_DISPATCH_TOKEN` is
   required for every `dispatch` outcome action, also one to the PR's own repository: a
   fine-grained token or GitHub App token with `contents: write` on the target repositories. The
   publish job's `GITHUB_TOKEN` has `contents: read` on purpose and cannot send
   `repository_dispatch`; without the secret the job logs a warning and every dispatch fails.
6. **Caller** in every repository: [examples/caller.yml](examples/caller.yml) as
   `.github/workflows/xrepo-review.yml`, pinned to a commit SHA of this repository.
7. Make it binding: org ruleset requiring the workflow (or its check) + CODEOWNERS for
   `.github/workflows/`.

### Hosted mode (GitHub-hosted runners: small orgs, evaluation)

```yaml
jobs:
  review:
    if: github.event_name == 'pull_request'
    permissions: { contents: read, pull-requests: write, issues: write, checks: write }
    uses: acme/xrepo-review/.github/workflows/review.yml@<sha>
    with:
      mode: hosted
      runner_labels: '["ubuntu-latest"]'
      xrepo_repo: acme/xrepo-review          # trusted source of CLI, image and policy
      xrepo_ref: <commit sha>                # never the PR head in production
      policy_file: .github/xrepo/policy.yaml # inside that trusted checkout
      image: ghcr.io/acme/xrepo-review@sha256:<digest>   # optional; otherwise built in the job
    secrets: inherit
  mirror-cache:                              # on: schedule (daily) / workflow_dispatch
    if: github.event_name != 'pull_request'
    permissions: { contents: read }
    uses: acme/xrepo-review/.github/workflows/mirror-cache.yml@<sha>
    with: { runner_labels: '["ubuntu-latest"]', xrepo_repo: acme/xrepo-review, xrepo_ref: <commit sha>, policy_file: .github/xrepo/policy.yaml }
    secrets: { XREPO_GITHUB_TOKEN: "${{ secrets.XREPO_GITHUB_TOKEN }}" }
```

Complete caller: [examples/caller-hosted.yml](examples/caller-hosted.yml). The review job checks
out `xrepo_repo@xrepo_ref` into `.xrepo-src`, builds the CLI, builds (or pulls) the image, and
syncs the mirror into `$RUNNER_TEMP/xrepo-mirror` with `XREPO_GITHUB_TOKEN` (a token with
`contents: read` on the mirrored repositories; falls back to `github.token`, which reads only the
current and public repositories), cached per policy hash and day. GitHub scopes a cache to the
ref that saved it: a pull request run restores what its own earlier runs saved, or an entry of the
default branch, never another pull request's. The `mirror-cache` job
([.github/workflows/mirror-cache.yml](.github/workflows/mirror-cache.yml), same inputs as the
review) saves that default-branch entry once a day; without it the first run of every pull request
clones every mirrored repository. If `xrepo_repo` is itself mirrored (readable through `/repos`),
xsearch hides the policy there: `.github/xrepo/` always, and the workflow passes `policy_file`
(`prepare --policy-repo-path`) for any other location.

## Policy manifest reference

Full commented example: [examples/policy.yaml](examples/policy.yaml). Schema:
[src/policy/schema.ts](src/policy/schema.ts). Layers merge as built-in defaults ← `defaults` ←
`repos.<owner/name>` (objects recursively; arrays and scalars replace; deny/exclude globs add up).

| Key | Default | Meaning |
|---|---|---|
| `enabled` | `true` | Kill switch; `false` skips every review (outcome `skipped`). The publisher re-checks it on the live manifest, so flipping it also stops runs already past prepare. |
| `capabilities.inline_comments` | on, 15, 1500 chars, `low`, suggestions on | Inline comments: budget, size, minimum severity, ```` ```suggestion ```` blocks. |
| `capabilities.summary_comment` | on, `sticky`, 6000 chars | Overall summary as one sticky PR comment (updated in place) or as the review body. |
| `capabilities.approve` | **off**; `max_severity_allowed: low`, `never_paths: [.github/**, **/CODEOWNERS]`, `max_changed_lines: 400` | When the agent's `approve` survives the publisher. |
| `capabilities.block` | **off**; `method: check`, `min_severity: high` | `request_changes` → REQUEST_CHANGES review, failing check run, or both. Needs inline comments (findings only come from them); `xrepo policy validate` warns otherwise. |
| `capabilities.check` | off, name `xrepo-review` | Always publish a check run with the result. |
| `capabilities.labels` | off, `allowed: []` | Labels the agent may add. |
| `search.*` | deny / exclude defaults, 30000 chars output, 2000 read lines, 1M file size, 8 s timeout | xsearch limits; `deny_globs` are never readable (matched case-insensitively), `exclude_globs` skipped unless targeted (Grep / Glob name the glob when it hid a result). |
| `cross_repo.readable` / `deny` | `[]` | Mirror repositories readable for this repository's PRs (`owner/name`, `owner/*`, `*`; deny wins). Any other form (`acme/legacy-*`, `*/secrets`, a URL) fails validation: list repositories by name. A repo's own `deny` replaces the `defaults` list; `xrepo policy validate` warns when that drops a still-readable entry. |
| `cross_repo.related` | `{}` | Dependency hints for the prompt, e.g. `acme/web: "calls /orders from src/api/orders.ts"`. |
| `triggers.*` | skip drafts, forks, bots; markers `[skip review]`, `[no review]`; ≤ 80 files, ≤ 4000 lines | When not to review; `include_paths` / `ignore_paths` filter files. |
| `agent.model` / `max_turns` | action default / 40 | Passed as `--model` / `--max-turns`. |
| `agent.instructions`, `focus`, `language` | – | Trusted review instructions in the prompt. |
| `agent.builtin_tools` | `[]` | Opt-in non-executing built-ins: `Skill`, `Agent` (alias `Task`), `TodoWrite` (also enables `TaskCreate` / `TaskGet` / `TaskList` / `TaskUpdate`). Never `ToolSearch`. |
| `agent.plugins`, `plugin_marketplaces`, `entry_command` | – | Trusted plugins passed to the action; `entry_command` starts the prompt with a slash command. |
| `output.*` | no mentions, no images, links only to `github.com`, no footer | Publisher sanitisation. |
| `outcomes.<outcome>` | see below | `comment`, `check_conclusion`, `add_labels` / `remove_labels`, `notify[]`, `dispatch`, `retry`, `fail_job`. |
| `mirror.*` | `repos: []`, keep 2 snapshots, skip archived / forks | What `xrepo sync` mirrors (`owner/name` or `owner/*`; `exclude` takes the `cross_repo` forms and rejects others; `xrepo policy validate` warns about `repos` entries sync can never mirror). |
| `notifications.<name>` | – | `type: slack | webhook`, `url_secret` (key in the secrets bundle), `hmac_secret`, `template`, `timeout_ms`. |

### Outcomes and notifications

Every run ends in one primary outcome; `approved` / `blocked` fire additionally after `completed`.

| Outcome | When | Built-in default |
|---|---|---|
| `completed` | the agent called `finish` and the review was published | – |
| `approved` / `blocked` | the published verdict approves / blocks (when GitHub refuses the APPROVE / REQUEST_CHANGES event, the review is posted as a comment and they do not fire, unless `block.method: both` still blocks via the check) | – |
| `incomplete` | the agent stopped without `finish` (max turns, crash) | comment, neutral check; never approves or blocks |
| `usage_limit` | Claude usage limit / rate limit / quota / overload | "postponed" comment with reset time, neutral check |
| `error` | anything else (action failed, cancelled, infrastructure) | comment with run link, neutral check |
| `skipped` | prepare's trigger rules | skipped check |

Per outcome: `comment` (sticky comment template; placeholders `{repo} {pr_number} {pr_url}
{pr_title} {author} {outcome} {reason} {reset_at} {reset_at_suffix} {verdict} {findings}
{top_severity} {run_url} {attempt}`), `check_conclusion`, labels, `notify` (Slack incoming webhook
or signed generic webhook), `dispatch` (`repository_dispatch`; needs the `XREPO_DISPATCH_TOKEN`
secret), `retry` (label the PR for the `xrepo retry` sweeper) and `fail_job`. Notification URLs live in `XREPO_NOTIFY_SECRETS` (JSON
object) or `/etc/xrepo-review/notify.json`, never in the manifest.

Rules worth knowing:

- **Check conclusion.** The plan's conclusion wins unless an outcome sets `check_conclusion`; a
  review that blocks via the check stays `failure` unless `outcomes.blocked.check_conclusion` says
  otherwise (`completed: {check_conclusion: success}` cannot pass a blocked PR). An override that
  changes the plan's conclusion is named in the check title.
- **Skips the PR author controls cannot pass a blocking check.** With `block.method: check` or
  `both`, a skip caused by a title marker (`[skip review]`), `max_changed_files`,
  `max_changed_lines`, an oversized diff (also one the GitHub API will not serve: 300 files /
  20000 lines) or a refused diff ("diff refused: …", an API diff while the PR changes
  `.gitattributes`) fails the check ("Review required: skipped by the pull request"), because
  GitHub treats a skipped or neutral check as passing. A **draft** fails it as "Review pending:
  draft pull request (runs when marked ready)": marking it ready and merging at once cannot beat
  the review, whose ready_for_review run posts the real check. Fork, bot, ignored-author and
  kill-switch skips keep the configured conclusion. To let such skips pass anyway, set
  `outcomes.skipped.check_conclusion: success` (or `neutral`) explicitly. The bot and
  ignored-author skips apply only when the event's sender is the PR author itself: a person
  pushing to a Dependabot branch gets a review.
- **A failing check stays failing.** A run that did not complete a review (skip, error, usage
  limit, incomplete) never posts a passing conclusion over a failing check on the same commit,
  and no run posts over a check of a newer workflow run for that commit.
- **Retry labels.** A `usage_limit` / `error` run with `retry.enabled` below `max_attempts` adds
  the retry label and a hidden "retry-after" marker in the sticky comment (the reset time plus 5
  minutes, or a backoff when the reset time is unknown); the sweeper waits until then. At its own
  `max_attempts` the run leaves the label and adds a hidden "retry-stop" marker instead, so the
  sweeper gives up even when another outcome sharing the label allows more attempts. Every other
  run removes the configured retry labels. The sweeper covers the `repos:` keys and exact
  `mirror.repos` names, plus every repository of the App installation's account or of an owner
  named in the policy that has an open PR with a retry label enabled in `defaults` (found with the
  search API); repositories its token cannot see are not swept.
- **Stale state.** GitHub keeps APPROVED and CHANGES_REQUESTED reviews in force until they are
  dismissed. A finished review that does not request changes dismisses this reviewer's earlier
  approvals and its change requests on older commits (only while it reviewed the current head; a
  change request on the current head is lifted only by a new commit or a person). Every other run
  that does not approve — incomplete, request-changes, skipped, error, usage-limit — dismisses this
  reviewer's earlier approvals. Only reviews carrying the hidden `<!-- xrepo-review:review -->`
  marker are touched. With `approve.enabled`, also turn on branch protection's "Dismiss stale pull
  request approvals when new commits are pushed". A run with nothing for the sticky comment (e.g.
  a skip, or the summary in the review) replaces an earlier one with a short status note.
- **Replayed runs.** A run that no longer reviews the PR's head (re-running an old workflow run,
  or a push while it ran) or whose commit a newer run already published (its check, or its hidden
  run marker on the sticky comment or on one of our reviews) posts only its check run (nothing
  when no check is configured); it never approves, dismisses, comments or labels.

## Chaining your own workflows

The reusable workflow exposes `outcome`, `verdict`, `reason`, `reset_at`, `findings`,
`top_severity`, `fired_outcomes` and `skip_reason`. Add jobs after `review` in the caller
([examples/caller-with-hooks.yml](examples/caller-with-hooks.yml)):

```yaml
  usage-limit-alert:
    needs: review
    if: ${{ !cancelled() && needs.review.outputs.outcome == 'usage_limit' }}
    ...
  on-blocked:
    needs: review
    if: ${{ !cancelled() && contains(needs.review.outputs.fired_outcomes, 'blocked') }}
    ...
```

`fired_outcomes` lists every outcome that fired, primary first (e.g. `completed,blocked`):
`blocked` / `approved` fire only when the publisher actually blocked or approved (after its own
rule checks), which `verdict` alone does not tell you. Follow-up jobs run
with the caller's own secrets and permissions. For cross-repository reactions use the policy's
`dispatch` action (`repository_dispatch` with a ≤ 10-key payload). It is sent with
`XREPO_DISPATCH_TOKEN` (`contents: write` on the target), also when the target is the PR's own
repository: the reusable workflow never gives its write token `contents: write` (that would also
allow pushing code), so do not add it to the caller's `permissions:` either.

## Accounts and usage limits

- The workflow reads `CLAUDE_CODE_OAUTH_TOKEN` (subscription, `claude setup-token`) or
  `ANTHROPIC_API_KEY` through `secrets: inherit`, and passes **exactly one** of them to the action:
  the subscription token whenever the repository can see one, the API key only otherwise. (Claude
  Code itself prefers `ANTHROPIC_API_KEY` when both are set, so an organization API key meant for
  other workflows would silently replace every group's subscription.) To run a group on an API
  key, keep `CLAUDE_CODE_OAUTH_TOKEN` invisible to its repositories (organization secret with
  selected repositories) and give them `ANTHROPIC_API_KEY`.
- **Per-group accounts** need no workflow change: GitHub resolves a secret name from the most
  specific level, so an **organization secret** `CLAUDE_CODE_OAUTH_TOKEN` (visible to selected
  repositories) serves the default group, and a **repository secret with the same
  name** overrides it for repositories that belong to another group / account. (Organization
  secret names are unique, so "one org secret per group" means one GitHub organization per group.)
  review.yml has no `account` input: selecting a secret by a dynamic name such as
  `secrets[format('…_{0}', inputs.account)]` is not documented by GitHub and is deliberately not
  used (a caller passing `account:` fails validation); if you want an explicit switch, add a fixed
  expression in your fork, e.g.
  `inputs.account == 'b' && secrets.CLAUDE_CODE_OAUTH_TOKEN_B || secrets.CLAUDE_CODE_OAUTH_TOKEN`.
- **No automatic failover between personal subscriptions.** Rotating to another person's
  subscription when one hits its limit would breach the subscription terms; xrepo-review never
  does it.
- **When a limit is hit**, the run ends with outcome `usage_limit` (detected from the execution log:
  `You've hit your … limit · resets …`, 429s, rejected rate-limit events), the PR gets a
  "postponed" comment with the reset time and a neutral check (merging is not blocked), and you can:
  enable `outcomes.usage_limit.retry` (the scheduled `xrepo retry` sweeper re-runs the review up to
  `max_attempts`), notify a channel, use an API key for high-volume repository groups, reduce
  `agent.max_turns`, tighten `triggers` (size limits, `include_paths`), or schedule busy
  repositories on a different account via repository-scoped secrets.

## Local development and tests

```sh
npm ci
npm run typecheck                         # src/ and test/ (tsconfig.test.json)
npm test                                  # vitest; needs git and ripgrep
npm run build && node dist/cli.js --help
XREPO_TEST_DOCKER_IMAGE=xrepo-review:dev npx vitest run test/prepare.test.ts -t "docker launcher"
```

Run a review end to end on your machine without GitHub (local launcher = no container isolation,
development only):

```sh
node e2e/make-bare-repos.mjs e2e/fixtures /tmp/xr/bare
xrepo sync --policy e2e/policy.yaml --mirror /tmp/xr/mirror \
  --url-template "file:///tmp/xr/bare/{owner}/{repo}.git"
xrepo prepare --policy e2e/policy.yaml --repo acme/web --pr 42 \
  --base-sha <base> --head-sha <head> --pr-checkout ~/src/web --mirror /tmp/xr/mirror \
  --work /tmp/xr/work --launcher local          # --launcher docker --image xrepo-review:dev
cd "$(mktemp -d)" && git init -q && claude -p "$(cat /tmp/xr/work/prompt.md)" \
  $(cat /tmp/xr/work/claude_args.txt) < /dev/null   # outside the action: --tools "" also works
xrepo publish --ctx /tmp/xr/work/ctx --draft /tmp/xr/work/out/draft.jsonl --dry-run
```

`prepare` without `--event` looks the PR up through the API (`GITHUB_TOKEN`). `publish --dry-run`
prints the full plan as JSON and makes no API calls.

## Testing on GitHub

[.github/workflows/e2e.yml](.github/workflows/e2e.yml) runs the real claude-code-action in hosted
mode against fixture repositories:

- `e2e/fixtures/acme/api` exports `createOrder(customerId, items, opts: { currency })`;
- `e2e/fixtures/acme/web` calls it from `src/checkout.ts`;
- `e2e/policy.yaml` makes `acme/*` readable, mirrors both fixtures (built into bare repos by
  `e2e/make-bare-repos.mjs`, synced through a `file://` URL template), disables approve and
  blocks via the `xrepo-review-e2e` check.

To run it:

1. Add a `CLAUDE_CODE_OAUTH_TOKEN` (or `ANTHROPIC_API_KEY`) repository secret. Allow the workflow's
   GitHub token to comment (default `GITHUB_TOKEN` permissions are set by the workflow).
2. Create a branch **in this repository** (fork PRs get no secrets) that breaks the consumer:
   ```sh
   git switch -c e2e/old-create-order-signature
   sed -i 's/createOrder(cart.customerId, cart.items, { currency: cart.currency })/createOrder(cart.customerId, cart.items)/' \
     e2e/fixtures/acme/web/src/checkout.ts
   git commit -am "web: simplify checkout" && git push -u origin HEAD
   ```
3. Open a pull request from that branch. The `e2e` workflow reviews it; the `assert` job passes
   when the outcome is `completed` with at least one finding (expected: a high-severity comment on
   `checkout.ts` citing `/repos/acme/api/src/orders.ts`, and a failing `xrepo-review-e2e` check).
4. Re-run against an existing PR with **Actions → e2e → Run workflow** (`pr_number`).

## CLI

```
xrepo search-mcp   --ctx <dir> --pr <dir> [--mirror <dir>] [--policy-path <repo-relative path>]
                                                                    xsearch MCP server (stdio)
xrepo review-mcp   --ctx <dir> --out <draft.jsonl>                  xreview MCP server (stdio)
xrepo prepare      --policy <file> --pr-checkout <dir> --work <dir> [--repo o/n] [--pr N]
                   [--base-sha S] [--head-sha S] [--event <json>] [--mirror <dir>]
                   [--launcher docker|local] [--image IMG] [--action-cwd <dir>]
                   [--untrusted-dir <dir> ...] [--policy-repo-path <path>] [--github-output <file>]
xrepo collect      --work <dir> --agent-outcome <outcome> [--execution-file <path>]
xrepo publish      --ctx <dir> --draft <file> [--dry-run] [--agent-outcome …] [--policy <file>]
                   [--repo o/n --pr-number N [--head-sha S]] …   (identity required in Actions)
xrepo sync         --policy <file> --mirror <dir> [--repo o/n …] [--owner L] [--url-template T]
                   [--snapshot-grace-minutes N] [--dry-run]
xrepo retry        --policy <file> --workflow <caller.yml> [--repo o/n …] [--owner L]
                   [--publisher-login L] [--dry-run]
xrepo policy       validate <file> | resolve <file> <o/n> | tools <file> <o/n>
```

- `search-mcp --policy-path` / `prepare --policy-repo-path`: the policy manifest's path inside
  its own repository; when that repository is mirrored, xsearch hides the path in every `/repos`
  root (`.github/xrepo/` is always hidden). review.yml passes `policy_file` in hosted mode.
- `publish --policy`: the trusted manifest. When given, the artifact's `ctx/policy.resolved.json`
  (which passed through the agent's job) is ignored; review.yml always passes it.
- `sync --snapshot-grace-minutes` (default 60): how long a retired snapshot is kept beyond
  `keep_snapshots`, and how long a repository dropped from the mirror set stays on disk. Such a
  repository is retired at once (its `current` link is removed, so new reviews no longer see it;
  the report lists it under `retired`) and deleted after the grace period (then under `removed`).
  It must exceed the review job's timeout (review.yml: 45 minutes), because a review keeps reading
  the snapshot that was current when it started.
- `retry --publisher-login`: whose sticky comments carry trusted retry-after markers (retry.yml:
  `github-actions[bot]`, overridable with `vars.XREPO_PUBLISHER_LOGIN`).
- `sync --owner` / `retry --owner`: restrict the run to one account's repositories, for a policy
  that names several owners (a GitHub App installation token covers one account). sync.yml and
  retry.yml run one job per owner with that owner's token. `sync --owner` syncs only that owner's
  `mirror.repos` entries and retires / removes only mirrors under it or under owners the policy no
  longer names; `retry --owner` sweeps and searches only that owner. `--repo` names must belong to
  the owner.
- `publish --self-login`: the token's identity for finding our own sticky comment and reviews.
  The default `github-actions[bot]` is shared with every other workflow that uses `GITHUB_TOKEN`;
  a GitHub App token with `--self-login <app-slug>[bot]` is better.

## FAQ

**Why not just let Claude use its built-in Read / Grep?** They read the runner's filesystem —
including the policy, `~/.claude` credentials and `/proc/self/environ` with tokens — and Bash would
run PR code. xsearch serves only the allowed roots, from a container with no network.

**Why Grep / Glob / Read instead of smarter symbol tools?** Models already use these tools well;
we measured ctags / ast-grep / repo maps and they were less reliable for TypeScript-heavy repos
(docs/TOOLS.md, docs/RESEARCH.md).

**Can the agent approve or block?** Only if the policy enables it, and only within its rules; the
publisher re-checks severity thresholds, protected paths and size limits and downgrades to a
plain comment otherwise (xreview, the prompt and the publisher share these rules in
`src/review/rules.ts`). Approvals are off by default. GitHub itself refuses APPROVE for the
workflow token unless "Allow GitHub Actions to create and approve pull requests" is on, and refuses
APPROVE / REQUEST_CHANGES on a PR the token's identity opened; the review is then posted as a
comment (with a note) and counts as neither approved nor blocked. An approval is also only
submitted while the reviewed commit is still the PR's head.

**What if the PR edits `.claude/settings.json`, `.mcp.json` or `CLAUDE.md`?** Nothing: project
settings are not loaded (`--setting-sources user`), only our two MCP servers start
(`--strict-mcp-config`), and the PR checkout is not the agent's working directory.

**What does a PR from a fork get?** Skipped by default (`skip_forks`): claude-code-action refuses
non-writers and fork runs get no secrets. GitHub also makes the token of a fork `pull_request` run
read-only, whatever `permissions:` say, so the `skipped` check / comment usually cannot be
written; the publish job then logs a warning and still succeeds (unless `outcomes.skipped.fail_job`
is set). With `xrepo_ref` set (always in hosted mode) and a **private** `xrepo_repo`, a fork run
cannot even check out the trusted source (no secrets; `github.token` reads only the calling
repository): the review job stops after that checkout with a notice, the publish job is skipped,
nothing is written and the run is still green (output `skip_reason` says why). A required *status
check* named `xrepo-review` therefore cannot pass on fork PRs; require the workflow (ruleset
"Require workflows to pass") instead.

**What happens when I re-run only the publish job?** ("Re-run this job", or "Re-run failed jobs"
after a `fail_job` outcome or an API error.) It republishes the same review from the review job's
artifact: the publish job downloads the artifact name the review job reports (output `artifact`),
not one derived from its own, incremented `run_attempt`. If that artifact is gone (3-day
retention), publish fails without touching the PR (no "could not run" comment, no neutral check
replacing a failing one). Once a newer workflow run has published (its run marker on the sticky
comment or on one of our reviews), the older run's re-run posts only its check (nothing when no
check is configured). Use **Re-run all jobs** to review again.

**Does a failed or rate-limited review block merging?** No — `usage_limit`, `error` and
`incomplete` publish a neutral check by default. Set `fail_job` or a `check_conclusion` per outcome
if you want otherwise.

**How fresh is cross-repo context?** As fresh as the last `xrepo sync` (every 10 minutes in the
example); `ListRepos` shows each snapshot's commit and age (`offset` / `limit` page through a long
list).

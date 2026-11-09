# Agent tool reference

The reviewing agent (Claude Code inside `anthropics/claude-code-action@v1`) gets exactly two MCP
servers and no built-in tools:

| Server | Tools (MCP name `mcp__<server>__<tool>`) | Writes |
|---|---|---|
| `xsearch` | `ListRepos`, `PrDiff`, `Grep`, `Glob`, `Read` | nothing (read-only mounts, no network) |
| `xreview` | `add_comment`, `set_summary`, `set_verdict`, `add_labels`, `review_status`, `finish` | one line per accepted call in `draft.jsonl` |

`xrepo prepare` passes `--tools ,` (no built-ins), `--strict-mcp-config` (only these two servers),
`--setting-sources user` (no project settings, hooks or CLAUDE.md from any checkout) and an
explicit `--allowedTools` list. xreview tools whose capability is disabled by the policy are not
registered at all, so the agent never sees them; `xrepo policy tools <policy> <owner/repo>` prints
the exact list for a repository. Every xsearch tool carries `readOnlyHint: true` and
`_meta: {"anthropic/alwaysLoad": true}` so Claude Code never defers it behind ToolSearch.

All outputs below are real outputs of the servers on the e2e fixtures (`e2e/`).

## Virtual paths: one namespace for several repositories

Every path the agent sees or passes is an absolute virtual path:

- `/pr/<path>` — the PR head checkout of the repository under review;
- `/repos/<owner>/<name>/<path>` — the default-branch snapshot of each repository this PR's
  repository may read (`cross_repo.readable` minus `cross_repo.deny`). The PR repository's own
  default branch is `/repos/<its owner>/<its name>` when it is mirrored. Repository names may
  start with "." (`/repos/acme/.github`); owner names may not.

Choosing a repository is choosing a `path`, exactly like Claude Code's own `path` parameter
(`Grep {pattern, path: "/repos/acme/api"}`). Every tool prints virtual paths, so results can be
passed straight to `Read`. Anything else does not exist: unreadable repositories are never listed,
not even by name, and `.git`, deny-listed files (`**/.env`, `**/*.pem`, …, matched
case-insensitively, so `.ENV` is hidden too) and paths escaping a root through symlinks behave
exactly like missing files. In every `/repos` root, `.github/xrepo/` (the hosted-mode policy
location) and the path passed with `search-mcp --policy-path` are hidden the same way.

Default search roots: without `path`, Grep and Glob search `/pr` and every readable `/repos/...`
except the PR repository's own snapshot, which would only repeat `/pr` (the code before the
change). That snapshot is searched when its root, or a path inside it, is passed as `path`.

Every tool's input schema is strict. An unknown parameter is an error that names the right one:

```
Grep {"pattern": "x", "limit": 5}                         (isError)
MCP error -32602: Input validation error: Invalid arguments for tool Grep: Unknown parameter "limit"
(use head_limit instead). Grep accepts only: pattern, path, glob, output_mode, -B, -A, -C, context,
-n, -i, -o, type, head_limit, offset, multiline.
```

## xsearch

### `ListRepos({offset?, limit?})`

```
/pr                 dudibuilds/claude-review  PR #7  head a47a3f2 base 4ac52ac  1 file changed
/repos/acme/api     53427f7  synced 14m ago
/repos/acme/web     b3b9496  synced 14m ago
```

The PR repository's own snapshot, when mirrored, is marked
`(base branch of this PR; searched only when passed as path)`. `offset` (1-based row) and `limit`
page through a long list, like PrDiff's file list; a list cut by `limit` or by the output cap ends
with `[Showing roots 1-120 of 340. Use offset: 121 to see more.]`.

### `PrDiff({file_path?, offset?, limit?})`

Without `file_path`: the changed files (`A`/`M`/`D`/`R`, renames `old -> new`, binary files
marked). Files hidden by `triggers.ignore_paths` are not shown; deny-listed files show
`[content hidden by policy]`. A type change (symlink → file and the like, which git prints as a
deletion and an addition of the same path) is one `M` entry, and its diff shows both sections.

```
M  +1 -1  /pr/e2e/fixtures/acme/web/src/checkout.ts
```

With `file_path`: that file's unified diff (`-U3`); hunk headers carry the new-side line numbers
the agent comments on. `offset` / `limit` page through long diffs by line, like `Read`. Secrets are
redacted line by line, so every diff line stays one output line: context and added lines inside a
private-key block of the PR's version of the file are replaced by `[REDACTED:private_key]`, key
blocks are also detected within each hunk on both sides, removed lines that look like key material
are hidden when the hunk touches a key, and a hunk header's function name that looks like key
material is hidden too.

```
diff --git a/e2e/fixtures/acme/web/src/checkout.ts b/e2e/fixtures/acme/web/src/checkout.ts
index da6d40b..c4535bb 100644
--- a/e2e/fixtures/acme/web/src/checkout.ts
+++ b/e2e/fixtures/acme/web/src/checkout.ts
@@ -4,5 +4,5 @@ import type { Cart } from "./cart.js";
 /** Turns the cart into an order. */
 export function checkout(cart: Cart): Order {
   if (cart.items.length === 0) throw new Error("cart is empty");
-  return createOrder(cart.customerId, cart.items, { currency: cart.currency });
+  return createOrder(cart.customerId, cart.items);
 }
```

### `Grep({pattern, path?, glob?, type?, output_mode?, "-i"?, "-n"?, "-o"?, "-A"?, "-B"?, "-C"?, context?, multiline?, head_limit?, offset?})`

Claude Code's Grep semantics on ripgrep. `path` (file or directory) defaults to `/pr` and every
other readable repository (see "Default search roots"). `output_mode`: `files_with_matches`
(default), `content`, `count`. `head_limit` defaults to 250 (0 = no limit, still capped by
`search.max_output_chars`), `offset` skips entries first. Lines over 500 characters are cut. `-o`
prints only the matched parts in content mode; a match on a line that holds a secret prints the
whole redacted line instead. `exclude_globs` (lockfiles, vendored, minified, build output, …) are
skipped unless the `path` or `glob` names them; when they hid a result, one line says so:
`[Matches in paths skipped by exclude_globs are not shown, e.g. <path> (<glob>). To include them,
pass that file or its directory as path, or a glob that names it.]`. A private-key block is hidden
from `BEGIN` to the next `-----END ` wherever a match falls inside it. A file ripgrep sees as binary
— UTF-16 included: it runs with `--encoding=none`, so a UTF-16 file keeps its NUL bytes — prints
`<path>: binary file matches`, as `Read` prints `[binary file]`.

Errors and notes:

- `offset` above 20000 is an error (page with a narrower `path` / `glob` instead).
- A `glob` written as a virtual path (`/pr/src/**/*.ts`, `/repos/acme/api/*.ts`) is an error that
  names the right `path` and `glob`: globs are relative to the searched directory. (It is allowed
  when that directory really has a top-level `pr` / `repos` folder.)
- A search over several roots whose results were cut names the roots none of whose results were
  shown: `[Also matched, not shown: /repos/acme/api (3 files), …. Pass one as path to see its
  results.]`.
- A root whose snapshot was removed from the mirror while the review ran is skipped with
  `[Not searched: /repos/acme/old (removed from the repository mirror while this review ran).]`;
  searching only that root is an error saying it is no longer available.
- When a single entry is longer than the whole output budget it is shown cut, so the next `offset`
  always moves forward.

```
Grep {"pattern": "createOrder", "path": "/repos"}
Found 6 files
/repos/acme/api/README.md
/repos/acme/api/src/index.ts
/repos/acme/api/src/orders.ts
/repos/acme/api/src/server.ts
/repos/acme/web/README.md
/repos/acme/web/src/checkout.ts
```

```
Grep {"pattern": "createOrder\\(", "path": "/repos/acme", "output_mode": "content", "-C": 1, "head_limit": 8}
/repos/acme/api/src/orders.ts-29-
/repos/acme/api/src/orders.ts:30:export function createOrder(customerId: string, items: Item[], opts: CreateOrderOptions): Order {
/repos/acme/api/src/orders.ts-31-  if (!customerId) throw new Error("customerId is required");
--
/repos/acme/api/src/server.ts-14-      const { customerId, items, currency } = JSON.parse(body) as { customerId: string; items: Item[]; currency: string };
/repos/acme/api/src/server.ts:15:      const order = createOrder(customerId, items, { currency });
/repos/acme/api/src/server.ts-16-      res.writeHead(201, { "content-type": "application/json" }).end(JSON.stringify(order));
--

[Showing results with pagination = limit: 8, offset: 0]
[Also matched, not shown: /repos/acme/web (1 file). Pass one as path to see its results.]
```

```
Grep {"pattern": "createOrder\\(", "path": "/repos/acme/api/src", "output_mode": "content", "-o": true}
/repos/acme/api/src/orders.ts:30:createOrder(
/repos/acme/api/src/server.ts:15:createOrder(
```

```
Grep {"pattern": "createOrder", "path": "/repos", "output_mode": "count"}
/repos/acme/api/README.md:1
/repos/acme/api/src/index.ts:1
/repos/acme/api/src/orders.ts:1
/repos/acme/api/src/server.ts:2
/repos/acme/web/README.md:2
/repos/acme/web/src/checkout.ts:2

Found 9 total occurrences across 6 files.
```

### `Glob({pattern, path?})`

Matching files as virtual paths, sorted by path, at most 100 (then
`(Results are truncated. Consider using a more specific path or pattern.)`). Same default roots as
Grep. Absolute virtual patterns such as `/repos/*/*/src/**/*.ts` also work and are anchored at
their root: `/repos/acme/api/src/*.ts` matches only that directory's direct files, `…/src/**/*.ts`
every depth. An absolute pattern ignores `path` (a missing directory's error says so and shows
both forms). A pattern that names a directory (`/repos/acme/api/src`, or `/repos/*/*`, which only
matches repository roots) is an error suggesting `…/**/*` and `…/*`. Globs are matched by a
linear-time matcher with ripgrep's rules (at most 64 `{…}` alternatives), so no pattern can stall
the server; the same `[Also matched, not shown …]` and `[Not searched: …]` notes as Grep apply.

```
Glob {"pattern": "**/*.ts", "path": "/repos/acme/api"}
/repos/acme/api/src/index.ts
/repos/acme/api/src/orders.ts
/repos/acme/api/src/server.ts
```

### `Read({file_path, offset?, limit?})`

`cat -n` format (right-aligned line number, tab, text). `offset` is the first line (1-based);
`limit` defaults to `search.max_read_lines` (2000, Claude Code's default); lines over 2000
characters are truncated. Files over `search.max_filesize` must be read with offset/limit;
directories (their direct entries, sub-directories first, at most 100, hidden ones left out) and
missing paths return an error that says what to do next.

```
Read {"file_path": "/repos/acme/api/src/orders.ts", "offset": 28, "limit": 6}
    28	}
    29
    30	export function createOrder(customerId: string, items: Item[], opts: CreateOrderOptions): Order {
    31	  if (!customerId) throw new Error("customerId is required");
    32	  if (items.length === 0) throw new Error("an order needs at least one item");
    33	  if (!opts || !/^[A-Z]{3}$/.test(opts.currency)) throw new Error("currency is required");
[Showing lines 28-33 of 47. Use offset: 34 to read more.]
```

```
Read {"file_path": "/etc/passwd"}                       (isError)
Path does not exist: /etc/passwd. Valid roots: /pr, /repos/acme/api, /repos/acme/web.

Read {"file_path": "/repos/acme/api/src"}                (isError)
EISDIR: /repos/acme/api/src is a directory, not a file. Its entries (sub-directories end with "/"):
/repos/acme/api/src/index.ts
/repos/acme/api/src/orders.ts
/repos/acme/api/src/server.ts
Read one of these files, Grep with path "/repos/acme/api/src" to search everything below it, or
Glob with an absolute pattern such as "/repos/acme/api/src/**/*.ts" to find files at any depth
below it.
```

Every xsearch response is secret-redacted and capped at `search.max_output_chars` (default
30000) with a one-line truncation note that suggests only parameters the tool has (e.g. Grep:
`Narrow it with path, glob or type, or page with head_limit/offset.`; Glob: `Use a more specific
path or pattern.`); every call is audited (`xsearch.call`).

## xreview

Each accepted call appends one JSON line to the draft (`src/common/draft.ts`). The checks mirror
the publisher so the agent gets immediate feedback; the publisher re-validates everything. The
verdict rules (approve / request_changes eligibility) and the inline comment budget (body plus
suggestion block count against `max_comment_chars`; the severity header does not) come from
`src/review/rules.ts`, which the publisher's plan and prepare's prompt use as well.

| Tool | Registered when | Input |
|---|---|---|
| `add_comment` | `inline_comments.enabled` and `max_comments > 0` | `path` (`/pr/<path>` as PrDiff lists it, or repo-relative), `line`, `end_line?`, `body`, `severity` (info…critical), `category?`, `suggestion?` (only when `suggestions: true`) |
| `set_summary` | `summary_comment.enabled` | `body` (last call wins) |
| `set_verdict` | always | `verdict` ∈ allowed values only (`comment`, plus `approve` when enabled, plus `request_changes` when blocking and inline comments are enabled), `reason` |
| `add_labels` | `labels.enabled` with a non-empty `allowed` list | `labels[]` ∈ `labels.allowed` |
| `review_status` | always | – (read-only) |
| `finish` | always | – (marks the draft complete; publisher treats a draft without it as `incomplete`) |

```
add_comment {"path": "e2e/fixtures/acme/web/src/checkout.ts", "line": 99, ...}      (isError)
Line 99 of e2e/fixtures/acme/web/src/checkout.ts is not inside a single diff hunk on the RIGHT
(new) side, so it cannot get an inline comment. Commentable lines: 4-8. Pick a line inside one of
these ranges (a multi-line range must stay within one), or mention the point in the summary.

add_comment {"path": "e2e/fixtures/acme/web/src/checkout.ts", "line": 7, "severity": "high",
             "category": "cross-repo-contract", "body": "`createOrder` requires ...",
             "suggestion": "  return createOrder(cart.customerId, cart.items, { currency: cart.currency });"}
Recorded comment #1 on e2e/fixtures/acme/web/src/checkout.ts:7 (high). 9 of 10 inline comments left.

set_summary {"body": "Checkout drops the required currency option; acme/api rejects such orders."}
Summary recorded (74 chars).

set_verdict {"verdict": "request_changes", "reason": "High-severity cross-repo contract break."}
Verdict set to "request_changes".

review_status {}
Review draft for dudibuilds/claude-review#7
Inline comments: 1 recorded, 9 of 10 left (severity >= low, <= 1500 chars, suggestions allowed)
  1. high     e2e/fixtures/acme/web/src/checkout.ts:7  [cross-repo-contract]
Summary: set (74 of max 6000 chars)
Verdict: request_changes (High-severity cross-repo contract break.); allowed: comment, request_changes
Request-changes rule: at least one finding with severity >= "high"
Finished: no (call finish last)
Tools: add_comment, set_summary, set_verdict, review_status, finish

finish {}
Review finished: 1 inline comment(s), summary set, verdict request_changes. No further changes are accepted.
```

## Design rationale

**Give the agent the tools it already knows.** Claude Code navigates code with Grep (ripgrep),
Glob and Read; Codex CLI has no file tools at all and navigates with `rg`, `rg --files` and
`sed -n` through its shell tool. Models are trained heavily on exactly these interactions. Since
the agent's own built-ins are disabled (they would read the runner's filesystem), xsearch exposes
the same three tools with Claude Code's names, parameter names (`pattern`, `path`, `glob`, `type`,
`output_mode`, `-i`, `-A/-B/-C`, `head_limit`, `offset`, `file_path`, `offset`, `limit`), defaults
and output formats (`path:line:text`, `cat -n`, the pagination note). There is no learning curve and
no prompt budget spent on teaching a bespoke API. Only two small tools are added: `ListRepos`
(which roots exist) and `PrDiff` (what changed, with new-side line numbers for comments).

**Multi-repo through paths, not parameters.** Instead of a `repos` parameter on every tool, each
readable repository is a directory under `/repos/<owner>/<name>` and the PR is `/pr`. Searching
one repository is passing its root as `path`; searching everything is omitting `path` (minus the
PR repository's own pre-change snapshot, which would duplicate every `/pr` hit). The security
boundary (which repositories exist) is the same mechanism as the namespace.

**What others do.** Claude Code: Grep / Glob / Read built-ins, MCP tools deferred behind ToolSearch
unless `anthropic/alwaysLoad` is set. Codex CLI: shell only (`exec_command` with `rg` / `sed`).
t3code (pingdotgg/t3code) exposes no code-navigation tools of its own: it is a control surface over
the agent CLIs and relies on each agent's built-ins; its read-only "PR review guide" mode runs
`claude -p --tools Read,Grep,Glob,Bash` with only `git diff/log/show` allowed. Serena, ast-grep MCP
and github-mcp-server offer symbol / AST / API-shaped tools (see docs/RESEARCH.md).

**Why no symbol or AST tools.** We measured them (docs/RESEARCH.md "Tools"): universal-ctags gives
no end lines and no signatures for TypeScript and floods outlines with test-local constants;
ast-grep outlines work but structural patterns fail silently (zero matches for a pattern that does
not parse the way the model expects), repo maps collide on common names (`Context`, `req`), and
every extra tool costs schema tokens and a decision per turn. Grep + Read with offset/limit answers
the review's real question — "who calls this, and does the call still match?" — with tools the
model uses reliably. The deliberate trade-off: no semantic precision (a grep for `getPath` also
finds unrelated `getPath`s), compensated by `cross_repo.related` hints in the prompt and by the
agent reading the hits.

**Token efficiency** comes from the defaults, not from cleverness: `files_with_matches` first,
`content` only on a narrowed path, `-C` only when asked, Read windows instead of whole files,
PrDiff instead of reading changed files, plain-text output (JSON costs ~5x), and a hard output cap.
The prompt states these habits in terms of the real parameter names.

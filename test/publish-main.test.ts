import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { PrContext } from "../src/common/context.js";
import { parsePolicy, resolvePolicy } from "../src/policy/load.js";
import { StaleHeadError, type CheckRunInput, type CreateReviewOptions, type CreateReviewResult, type GitHubApi, type GitHubApiOptions, type IssueCommentRef, type PullRequestFile } from "../src/publish/github.js";
import type { PlanReview } from "../src/publish/plan.js";
import { parseRetryAfterMarkers, parseRetryMarkers, decideRetry, retryLimit, retryRules, retryTiming } from "../src/outcome/retry.js";
import { repositoryDispatch } from "../src/outcome/dispatch.js";
import { API_DIFF_LIMIT, DIFF_REFUSED_PREFIX } from "../src/prepare/prepare.js";
import {
  authorControlledSkip,
  composeSticky,
  computeLabelOps,
  exhaustedRetry,
  main,
  planAfterRefusedEvent,
  resolveCheck,
  writeGithubOutputs,
  type PublishReport,
} from "../src/publish/publish.js";

const Z = "​";
const STICKY = "<!-- xrepo-review:sticky -->";
const root = mkdtempSync(join(tmpdir(), "xrepo-publish-"));
afterAll(() => rmSync(root, { recursive: true, force: true }));

/* -------------------------------- fixtures -------------------------------- */

const HEAD = "a".repeat(40);

const CTX: PrContext = {
  repo: "acme/web",
  number: 42,
  title: "Add orders",
  body: "",
  author: "alice",
  author_type: "User",
  base_sha: "b".repeat(40),
  head_sha: HEAD,
  base_ref: "main",
  head_ref: "feat",
  draft: false,
  fork: false,
  html_url: "https://github.com/acme/web/pull/42",
  files: [{ path: "src/orders.ts", status: "modified", additions: 2, deletions: 0 }],
  changed_lines: 2,
  ignored_files: [],
};

const DIFF = [
  "diff --git a/src/orders.ts b/src/orders.ts",
  "index 1111111..2222222 100644",
  "--- a/src/orders.ts",
  "+++ b/src/orders.ts",
  "@@ -10,6 +10,8 @@ export function createOrder() {",
  " const a = 1;",
  " const b = 2;",
  " const c = 3;",
  "+const d = 4;",
  "+const e = 5;",
  " const f = 6;",
  " const g = 7;",
  " const h = 8;",
  "",
].join("\n");

const BASE_POLICY = `
version: 1
notifications:
  chat: { type: slack, url_secret: SLACK_URL }
  hook: { type: webhook, url_secret: HOOK_URL, hmac_secret: HOOK_KEY }
defaults:
  capabilities:
    check: { enabled: true, name: "xrepo-review" }
    labels: { enabled: true, allowed: ["security"] }
  outcomes:
    usage_limit:
      retry: { enabled: true, max_attempts: 3 }
      add_labels: ["review-postponed"]
      notify: [{ target: chat, message: "Review of {repo}#{pr_number} ({pr_title}) postponed{reset_at_suffix}" }]
    completed:
      remove_labels: ["review-postponed"]
`;

function policyFor(yamlText: string, repo = "acme/web") {
  return resolvePolicy(parsePolicy(yamlText), repo);
}

interface Setup {
  dir: string;
  ctxDir: string;
  draft: string;
  exec: string;
  out: string;
  planOut: string;
}

let n = 0;
function setup(opts: { policy?: string | null; ctx?: PrContext | null; diff?: string | null; draft?: string[] | null; exec?: string | null } = {}): Setup {
  const dir = join(root, `case${n++}`);
  const ctxDir = join(dir, "ctx");
  mkdirSync(ctxDir, { recursive: true });
  const s: Setup = { dir, ctxDir, draft: join(dir, "draft.jsonl"), exec: join(dir, "exec.json"), out: join(dir, "github_output"), planOut: join(dir, "plan.json") };
  if (opts.policy !== null) writeFileSync(join(ctxDir, "policy.resolved.json"), JSON.stringify(policyFor(opts.policy ?? BASE_POLICY)));
  if (opts.ctx !== null) writeFileSync(join(ctxDir, "pr.json"), JSON.stringify(opts.ctx ?? CTX));
  if (opts.diff !== null) writeFileSync(join(ctxDir, "diff.patch"), opts.diff ?? DIFF);
  if (opts.draft !== null) writeFileSync(s.draft, `${(opts.draft ?? []).join("\n")}\n`);
  if (opts.exec !== undefined && opts.exec !== null) writeFileSync(s.exec, opts.exec);
  return s;
}

const line = (o: unknown): string => JSON.stringify(o);
const HIGH = line({ type: "comment", path: "src/orders.ts", line: 13, body: "Missing null check on `d`.", severity: "high" });
const LOW = line({ type: "comment", path: "src/orders.ts", line: 14, body: "Consider a constant.", severity: "low" });
const SUMMARY = line({ type: "summary", body: "Looks reasonable overall." });
const FINISH = line({ type: "finish" });
const verdict = (v: string): string => line({ type: "verdict", verdict: v, reason: "because" });

const OAUTH = "You've hit your 5-hour limit · resets 1:32pm (UTC)";
const EXEC_LIMIT = JSON.stringify(
  [
    { type: "system", subtype: "init", tools: [] },
    { type: "result", subtype: "success", is_error: true, num_turns: 1, total_cost_usd: 0, api_error_status: 429, result: OAUTH },
  ],
  null,
  2,
);
const EXEC_MAX_TURNS = JSON.stringify([
  { type: "system", subtype: "init" },
  { type: "result", subtype: "error_max_turns", is_error: true, num_turns: 40, errors: ["Reached maximum number of turns (40)"] },
]);

/* ------------------------------- fake GitHub ------------------------------- */

interface FakeGitHub extends GitHubApi {
  calls: { method: string; args: unknown[] }[];
  sticky?: IssueCommentRef;
  /** What GitHub lists as the PR's changed files (default: CTX.files). */
  files: PullRequestFile[];
  fail: Set<string>;
  opts?: GitHubApiOptions;
}

function fakeGitHub(init: { sticky?: IssueCommentRef; fail?: string[] } = {}): FakeGitHub {
  const gh: FakeGitHub = {
    calls: [],
    fail: new Set(init.fail ?? []),
    ...(init.sticky ? { sticky: init.sticky } : {}),
    files: CTX.files.map((f) => ({ path: f.path, additions: f.additions, deletions: f.deletions })),
    async listReviewCommentKeys() {
      rec("listReviewCommentKeys", []);
      return new Set<string>();
    },
    async findStickyComment(marker: string) {
      rec("findStickyComment", [marker]);
      return gh.sticky;
    },
    async createIssueComment(body: string) {
      rec("createIssueComment", [body]);
      return { id: 1 };
    },
    async updateIssueComment(id: number, body: string) {
      rec("updateIssueComment", [id, body]);
    },
    async createReview(r: PlanReview, opts?: CreateReviewOptions): Promise<CreateReviewResult> {
      rec("createReview", opts?.withholdApproval !== undefined ? [r, opts] : [r]);
      // Like github.ts: an approval the caller withholds is posted as a COMMENT.
      if (r.event === "APPROVE" && opts?.withholdApproval !== undefined) {
        return { id: 2, inlineFallback: false, event: "COMMENT", downgraded: { from: "APPROVE", reason: opts.withholdApproval, withheld: true } };
      }
      return { id: 2, inlineFallback: false };
    },
    async listPullRequestFiles() {
      rec("listPullRequestFiles", []);
      return gh.files;
    },
    async createCheckRun(c: CheckRunInput) {
      rec("createCheckRun", [c]);
      return { id: 3 };
    },
    async addLabels(labels: string[]) {
      rec("addLabels", [labels]);
    },
    async removeLabel(label: string) {
      rec("removeLabel", [label]);
    },
    async repositoryDispatch(repo: string, event_type: string, payload: Record<string, unknown>) {
      rec("repositoryDispatch", [repo, event_type, payload]);
    },
    async getAuthenticatedLogin() {
      return "github-actions[bot]";
    },
  };
  function rec(method: string, args: unknown[]): void {
    gh.calls.push({ method, args });
    if (gh.fail.has(method)) throw Object.assign(new Error(`${method} failed`), { status: 500 });
  }
  return gh;
}

const callsOf = (gh: FakeGitHub, method: string): unknown[][] => gh.calls.filter((c) => c.method === method).map((c) => c.args);

function fakeFetch() {
  const calls: { url: string; body: unknown; headers: Record<string, string> }[] = [];
  const impl = (async (input: string | URL | Request, init?: RequestInit) => {
    calls.push({ url: String(input), body: JSON.parse(String(init?.body ?? "null")), headers: (init?.headers ?? {}) as Record<string, string> });
    return new Response("ok", { status: 200 });
  }) as typeof fetch;
  return { calls, impl };
}

function parseOutputs(path: string): Record<string, string> {
  const text = readFileSync(path, "utf8");
  const out: Record<string, string> = {};
  const lines = text.split("\n");
  for (let i = 0; i < lines.length; i++) {
    const m = /^([A-Za-z_][A-Za-z0-9_-]*)<<(.+)$/.exec(lines[i] ?? "");
    if (!m) continue;
    const [, name, delim] = m;
    const value: string[] = [];
    for (i++; i < lines.length && lines[i] !== delim; i++) value.push(lines[i] ?? "");
    out[name as string] = value.join("\n");
  }
  return out;
}

interface RunResult {
  code: number;
  gh: FakeGitHub;
  fetch: ReturnType<typeof fakeFetch>;
  stdout: string;
  stderr: string;
  outputs: Record<string, string>;
  factoryCalls: number;
}

async function run(
  s: Setup,
  extra: string[] = [],
  o: { gh?: FakeGitHub; env?: Record<string, string | undefined>; noFactory?: boolean } = {},
): Promise<RunResult> {
  const gh = o.gh ?? fakeGitHub();
  const f = fakeFetch();
  const stdout: string[] = [];
  const stderr: string[] = [];
  let factoryCalls = 0;
  const code = await main(["--ctx", s.ctxDir, "--draft", s.draft, "--github-output", s.out, ...extra], {
    createApi: (opts) => {
      factoryCalls++;
      if (o.noFactory) throw new Error("the GitHub client must not be created");
      gh.opts = opts;
      return gh;
    },
    fetchImpl: f.impl,
    env: {
      GITHUB_TOKEN: "ghs_test",
      XREPO_NOTIFY_SECRETS: JSON.stringify({ SLACK_URL: "https://hooks.slack.example/T/B/X", HOOK_URL: "https://hooks.example.com/h", HOOK_KEY: "k" }),
      ...o.env,
    },
    stdout: { write: (x: string) => stdout.push(x) },
    stderr: { write: (x: string) => stderr.push(x) },
    nowSeconds: () => 1700000000,
  });
  let outputs: Record<string, string> = {};
  try {
    outputs = parseOutputs(s.out);
  } catch {
    /* no outputs */
  }
  return { code, gh, fetch: f, stdout: stdout.join(""), stderr: stderr.join(""), outputs, factoryCalls };
}

beforeEach(() => {
  vi.spyOn(process.stderr, "write").mockImplementation(() => true);
});
afterEach(() => vi.restoreAllMocks());

/* ---------------------------------- tests ---------------------------------- */

describe("xrepo publish: completed", () => {
  it("posts the review, sticky summary, check, labels and outputs", async () => {
    const s = setup({ draft: [HIGH, SUMMARY, verdict("comment"), line({ type: "labels", labels: ["security", "nope"] }), FINISH] });
    const r = await run(s, ["--agent-outcome", "success"]);
    expect(r.code).toBe(0);
    expect(r.gh.opts).toMatchObject({ token: "ghs_test", repo: "acme/web", prNumber: 42, headSha: HEAD });

    const [[review]] = callsOf(r.gh, "createReview") as [[PlanReview]];
    expect(review.event).toBe("COMMENT");
    expect(review.comments).toHaveLength(1);
    expect(review.comments[0]).toMatchObject({ path: "src/orders.ts", line: 13, side: "RIGHT" });

    const [[body]] = callsOf(r.gh, "createIssueComment") as [[string]];
    expect(body.startsWith(`${STICKY}\n`)).toBe(true);
    expect(body).toContain("Looks reasonable overall.");

    const [[check]] = callsOf(r.gh, "createCheckRun") as [[CheckRunInput]];
    expect(check).toMatchObject({ name: "xrepo-review", conclusion: "neutral", head_sha: HEAD });

    // completed: plan label added, outcome label removed, configured retry label removed.
    expect(callsOf(r.gh, "addLabels")).toEqual([[["security"]]]);
    expect(callsOf(r.gh, "removeLabel")).toEqual([["review-postponed"], ["xrepo-review:retry"]]);

    expect(r.outputs).toEqual({ outcome: "completed", verdict: "comment", reason: "review finished", reset_at: "", findings: "1", top_severity: "high", fired_outcomes: "completed" });
    expect(r.fetch.calls).toHaveLength(0);
    expect(r.stdout).toBe(""); // live mode prints nothing on stdout
  });

  it("updates an existing sticky comment in place (and skips unchanged bodies)", async () => {
    const s = setup({ draft: [SUMMARY, FINISH] });
    const gh = fakeGitHub({ sticky: { id: 77, body: `${STICKY}\nold` } });
    const r = await run(s, [], { gh });
    expect(callsOf(r.gh, "createIssueComment")).toHaveLength(0);
    const [[id, body]] = callsOf(r.gh, "updateIssueComment") as [[number, string]];
    expect(id).toBe(77);

    const again = await run(s, [], { gh: fakeGitHub({ sticky: { id: 77, body } }) });
    expect(callsOf(again.gh, "updateIssueComment")).toHaveLength(0);
    expect(callsOf(again.gh, "createIssueComment")).toHaveLength(0);
  });

  it("fires `blocked`: REQUEST_CHANGES, failing check, outcome labels and dispatch", async () => {
    const policy = `${BASE_POLICY}
    blocked:
      add_labels: ["needs-work"]
      dispatch: { event_type: "xrepo-review.blocked" }
`.replace("labels: { enabled: true", "block: { enabled: true, method: both, min_severity: high }\n    labels: { enabled: true");
    const s = setup({ policy, draft: [HIGH, SUMMARY, verdict("request_changes"), FINISH] });
    const r = await run(s, ["--agent-outcome", "success", "--run-attempt", "2"]);
    expect(r.code).toBe(0);
    const [[review]] = callsOf(r.gh, "createReview") as [[PlanReview]];
    expect(review.event).toBe("REQUEST_CHANGES");
    const [[check]] = callsOf(r.gh, "createCheckRun") as [[CheckRunInput]];
    expect(check.conclusion).toBe("failure");
    expect(callsOf(r.gh, "addLabels")).toEqual([[["needs-work"]]]);
    const [[repo, eventType, payload]] = callsOf(r.gh, "repositoryDispatch") as [[string, string, Record<string, unknown>]];
    expect([repo, eventType]).toEqual(["acme/web", "xrepo-review.blocked"]);
    expect(Object.keys(payload).length).toBeLessThanOrEqual(10);
    expect(payload).toMatchObject({ outcome: "blocked", pr_number: 42, head_sha: HEAD, attempt: 2, review: { verdict: "request_changes", findings: 1, top_severity: "high" } });
    expect(r.outputs.verdict).toBe("request_changes");
    expect(r.outputs.outcome).toBe("completed");
  });

  it("fires `approved` (with a signed webhook) only after the APPROVE review was posted", async () => {
    const policy = `${BASE_POLICY}
    approved:
      notify: [{ target: hook }]
      fail_job: false
`.replace("labels: { enabled: true", "approve: { enabled: true, max_severity_allowed: low }\n    labels: { enabled: true");
    const s = setup({ policy, draft: [LOW, SUMMARY, verdict("approve"), FINISH] });
    const r = await run(s);
    expect(r.code).toBe(0);
    expect((callsOf(r.gh, "createReview")[0]?.[0] as PlanReview).event).toBe("APPROVE");
    expect(r.fetch.calls).toHaveLength(1);
    expect(r.fetch.calls[0]?.url).toBe("https://hooks.example.com/h");
    expect(r.fetch.calls[0]?.body).toMatchObject({ event: "xrepo-review", outcome: "approved", verdict: "approve", pr_number: 42 });
    expect(r.fetch.calls[0]?.headers["x-xrepo-signature"]).toMatch(/^sha256=[0-9a-f]{64}$/);

    const failing = await run(setup({ policy, draft: [LOW, verdict("approve"), FINISH] }), [], { gh: fakeGitHub({ fail: ["createReview"] }) });
    expect(failing.code).toBe(1); // required API call failed
    expect(failing.fetch.calls).toHaveLength(0); // `approved` not fired
  });

  it("fail_job on a fired outcome exits 1 but still publishes", async () => {
    const policy = `${BASE_POLICY}\n      fail_job: true\n`; // appended to outcomes.completed
    const s = setup({ policy, draft: [SUMMARY, FINISH] });
    const r = await run(s);
    expect(r.code).toBe(1);
    expect(callsOf(r.gh, "createIssueComment")).toHaveLength(1);
    expect(r.outputs.outcome).toBe("completed");
  });
});

describe("xrepo publish: incomplete / usage_limit / error / skipped", () => {
  it("incomplete: partial findings, outcome comment first, neutral check, never approves", async () => {
    const s = setup({ draft: [HIGH, SUMMARY, verdict("approve")], exec: EXEC_MAX_TURNS });
    const r = await run(s, ["--agent-outcome", "failure", "--execution-file", s.exec]);
    expect(r.code).toBe(0);
    const review = callsOf(r.gh, "createReview")[0]?.[0] as PlanReview;
    expect(review.event).toBe("COMMENT");
    const [[body]] = callsOf(r.gh, "createIssueComment") as [[string]];
    const warn = body.indexOf("did not finish (maximum number of turns reached)");
    const summary = body.indexOf("Looks reasonable overall.");
    expect(warn).toBeGreaterThan(0);
    expect(summary).toBeGreaterThan(warn);
    expect((callsOf(r.gh, "createCheckRun")[0]?.[0] as CheckRunInput).conclusion).toBe("neutral");
    expect(r.outputs).toMatchObject({ outcome: "incomplete", reason: "maximum number of turns reached", verdict: "comment", findings: "1" });
  });

  it("usage_limit: postponed comment, neutral check, retry label below max_attempts, Slack notification", async () => {
    const s = setup({ draft: [HIGH], exec: EXEC_LIMIT, ctx: { ...CTX, title: "<!channel> Add orders @here" } });
    const r = await run(s, ["--agent-outcome", "failure", "--execution-file", s.exec, "--run-attempt", "1", "--run-url", "https://github.com/acme/web/actions/runs/5"]);
    expect(r.code).toBe(0);
    expect(callsOf(r.gh, "createReview")).toHaveLength(0);
    expect(callsOf(r.gh, "listReviewCommentKeys")).toHaveLength(0);
    const [[body]] = callsOf(r.gh, "createIssueComment") as [[string]];
    expect(body).toBe(`${STICKY}\n⏸️ Automated review postponed: Claude usage limit reached (resets 1:32pm (UTC)). This does not block merging.`);
    const [[check]] = callsOf(r.gh, "createCheckRun") as [[CheckRunInput]];
    expect(check).toMatchObject({ conclusion: "neutral", title: "Review postponed: usage limit reached (resets 1:32pm (UTC))" });
    expect(callsOf(r.gh, "addLabels")).toEqual([[["review-postponed", "xrepo-review:retry"]]]);
    expect(r.fetch.calls).toHaveLength(1);
    expect(r.fetch.calls[0]?.body).toEqual({
      text: `Review of acme/web#42 (&lt;!channel&gt; Add orders @${Z}here) postponed (resets 1:32pm (UTC))`,
    });
    expect(r.outputs).toEqual({ outcome: "usage_limit", verdict: "", reason: OAUTH, reset_at: "1:32pm (UTC)", findings: "0", top_severity: "", fired_outcomes: "usage_limit" });
  });

  it("cross-repo dispatch uses XREPO_DISPATCH_TOKEN and never the publisher client", async () => {
    const policy = BASE_POLICY.replace("    completed:", '    completed:\n      dispatch: { repo: "acme/ops", event_type: "review-done" }');
    const s = setup({ policy, draft: [FINISH] });
    const r = await run(s, [], { env: { XREPO_DISPATCH_TOKEN: "dtok" } });
    const dispatches = r.fetch.calls.filter((c) => c.url.endsWith("/dispatches"));
    expect(dispatches).toHaveLength(1);
    expect(dispatches[0]?.url).toBe("https://api.github.com/repos/acme/ops/dispatches");
    expect(dispatches[0]?.headers.authorization).toBe("Bearer dtok");
    expect(dispatches[0]?.body).toMatchObject({ event_type: "review-done", client_payload: { outcome: "completed", repo: "acme/web" } });
    expect(callsOf(r.gh, "repositoryDispatch")).toHaveLength(0);
  });

  it("usage_limit at max_attempts does not add the retry label", async () => {
    const s = setup({ draft: [], exec: EXEC_LIMIT });
    const r = await run(s, ["--execution-file", s.exec], { env: { GITHUB_RUN_ATTEMPT: "3" } });
    expect(callsOf(r.gh, "addLabels")).toEqual([[["review-postponed"]]]);
  });

  it("error with a missing ctx: PR from the event, policy from --policy, error comment, outputs", async () => {
    const s = setup({ policy: null, ctx: null, diff: null, draft: null });
    const manifest = join(s.dir, "policy.yaml");
    writeFileSync(manifest, `${BASE_POLICY}    error:\n      fail_job: true\n`, { mode: 0o644 });
    const event = join(s.dir, "event.json");
    writeFileSync(
      event,
      JSON.stringify({
        pull_request: {
          number: 42,
          html_url: "https://github.com/acme/web/pull/42",
          title: "Add ![x](https://evil.example/p.png)",
          user: { login: "alice" },
          head: { sha: HEAD },
          base: { repo: { full_name: "acme/web" } },
        },
      }),
    );
    const r = await run(s, ["--agent-outcome", "failure", "--policy", manifest], {
      env: { GITHUB_EVENT_PATH: event, GITHUB_SERVER_URL: "https://github.com", GITHUB_REPOSITORY: "acme/web", GITHUB_RUN_ID: "99" },
    });
    expect(r.code).toBe(1); // error.fail_job
    const [[body]] = callsOf(r.gh, "createIssueComment") as [[string]];
    expect(body).toBe(
      `${STICKY}\n⚠️ Automated review could not run (the review job failed before the agent ran (review context missing)). ` +
        "This does not block merging. [Run log](https://github.com/acme/web/actions/runs/99)\n\n<!-- xrepo-review:run=99 -->",
    );
    expect((callsOf(r.gh, "createCheckRun")[0]?.[0] as CheckRunInput).conclusion).toBe("neutral");
    expect(r.outputs).toMatchObject({ outcome: "error", reason: "the review job failed before the agent ran (review context missing)", findings: "0" });
  });

  it("error without any policy: no GitHub writes, outputs still written, exit 0", async () => {
    const s = setup({ policy: null, ctx: null, diff: null, draft: null });
    const r = await run(s, ["--agent-outcome", "failure"], { noFactory: true });
    expect(r.code).toBe(0);
    expect(r.factoryCalls).toBe(0);
    expect(r.outputs).toMatchObject({ outcome: "error", verdict: "", findings: "0" });
  });

  it("completed draft but missing ctx becomes error", async () => {
    const s = setup({ ctx: null, draft: [SUMMARY, FINISH] });
    const r = await run(s, [], { noFactory: true });
    expect(r.outputs.outcome).toBe("error");
    expect(r.outputs.reason).toBe("review context unavailable (PR context missing)");
  });

  it("skipped: skipped check, no comment, outputs", async () => {
    const s = setup({ draft: null });
    const r = await run(s, ["--skip-reason", "draft pull request"]);
    expect(r.code).toBe(0);
    expect(callsOf(r.gh, "createIssueComment")).toHaveLength(0);
    // It looks for an earlier sticky to replace (stale-sticky-after-skip), and finds none here.
    expect(callsOf(r.gh, "findStickyComment")).toHaveLength(1);
    expect(callsOf(r.gh, "updateIssueComment")).toHaveLength(0);
    const [[check]] = callsOf(r.gh, "createCheckRun") as [[CheckRunInput]];
    expect(check).toMatchObject({ conclusion: "skipped", title: "Review skipped: draft pull request", keep_failure: true });
    expect(r.outputs).toMatchObject({ outcome: "skipped", reason: "draft pull request" });
  });

  it("no check run when neither check.enabled nor a check-based block is configured", async () => {
    const s = setup({ policy: "version: 1\n", draft: null });
    const r = await run(s, ["--agent-outcome", "cancelled"]);
    expect(callsOf(r.gh, "createCheckRun")).toHaveLength(0);
    expect(r.outputs).toMatchObject({ outcome: "error", reason: "the run was cancelled" });
    expect(callsOf(r.gh, "createIssueComment")).toHaveLength(1);
  });
});

describe("xrepo publish: dry-run, failures and usage", () => {
  it("dry-run makes no network calls and prints the plan and actions", async () => {
    const s = setup({ draft: [HIGH], exec: EXEC_LIMIT });
    const r = await run(s, ["--dry-run", "--execution-file", s.exec, "--plan-out", s.planOut], { noFactory: true });
    expect(r.code).toBe(0);
    expect(r.factoryCalls).toBe(0);
    expect(r.fetch.calls).toHaveLength(0);
    const report = JSON.parse(r.stdout);
    expect(report).toMatchObject({
      dry_run: true,
      outcome: { outcome: "usage_limit", reset_at: "1:32pm (UTC)" },
      fired: ["usage_limit"],
      plan: null,
      actions: {
        sticky: { posted: false },
        check: { conclusion: "neutral", decided_by: "usage_limit", posted: false },
        labels: { add: ["review-postponed", "xrepo-review:retry"], remove: [] },
        notify: [{ outcome: "usage_limit", target: "chat", type: "slack" }],
      },
      outputs: { outcome: "usage_limit" },
      exit_code: 0,
    });
    expect(JSON.parse(readFileSync(s.planOut, "utf8"))).toEqual(report);
    expect(r.outputs.outcome).toBe("usage_limit");
  });

  it("dry-run of a completed review includes the full plan", async () => {
    const s = setup({ draft: [HIGH, SUMMARY, FINISH] });
    const r = await run(s, ["--dry-run"], { noFactory: true });
    const report = JSON.parse(r.stdout);
    expect(report.plan.review.comments).toHaveLength(1);
    expect(report.actions.review).toEqual({ event: "COMMENT", comments: 1, posted: false });
    expect(report.actions.sticky.body.startsWith(STICKY)).toBe(true);
  });

  it("a missing token is an infrastructure failure (exit 1) but outputs are written", async () => {
    const s = setup({ draft: [SUMMARY, FINISH] });
    const r = await run(s, [], { env: { GITHUB_TOKEN: undefined, GH_TOKEN: undefined }, noFactory: true });
    expect(r.code).toBe(1);
    expect(r.outputs.outcome).toBe("completed");
  });

  it("a failing check run is an infrastructure failure; label failures are not", async () => {
    const s = setup({ draft: [SUMMARY, FINISH] });
    expect((await run(s, [], { gh: fakeGitHub({ fail: ["createCheckRun"] }) })).code).toBe(1);
    expect((await run(s, [], { gh: fakeGitHub({ fail: ["removeLabel", "addLabels"] }) })).code).toBe(0);
  });

  it("policy / PR mismatch: nothing is published, exit 1", async () => {
    const s = setup({ draft: [SUMMARY, FINISH] });
    writeFileSync(join(s.ctxDir, "policy.resolved.json"), JSON.stringify(policyFor(BASE_POLICY, "acme/other")));
    const r = await run(s, [], { noFactory: true });
    expect(r.code).toBe(1);
    expect(r.factoryCalls).toBe(0);
    expect(r.outputs.outcome).toBe("error");
  });

  it("usage errors exit 2", async () => {
    const s = setup();
    const err: string[] = [];
    const io = { stderr: { write: (x: string) => err.push(x) }, env: {} };
    expect(await main(["--draft", s.draft], io)).toBe(2);
    expect(await main(["--ctx", s.ctxDir, "--draft", s.draft, "--run-attempt", "zero"], io)).toBe(2);
    expect(await main(["--ctx", s.ctxDir, "--draft", s.draft, "--bogus"], io)).toBe(2);
    expect(err.join("")).toContain("usage: xrepo publish");
  });
});

describe("helpers", () => {
  it("writeGithubOutputs uses unique heredoc delimiters that survive hostile values", () => {
    const path = join(root, "out-helper");
    writeGithubOutputs(path, { reason: "line1\nghadelimiter_x\nEOF\nline4", empty: "" });
    const text = readFileSync(path, "utf8");
    expect(text).toMatch(/^reason<<ghadelimiter_[0-9a-f]{32}\n/);
    expect(parseOutputs(path)).toEqual({ reason: "line1\nghadelimiter_x\nEOF\nline4", empty: "" });
    expect(() => writeGithubOutputs(path, { "bad name": "x" })).toThrow();
  });

  it("composeSticky orders summary and outcome comments by primary outcome", () => {
    expect(composeSticky("completed", "SUMMARY", ["NOTE"])).toBe(`${STICKY}\nSUMMARY\n\nNOTE`);
    expect(composeSticky("incomplete", "SUMMARY", ["NOTE"])).toBe(`${STICKY}\nNOTE\n\nSUMMARY`);
    expect(composeSticky("error", undefined, ["", " "])).toBeUndefined();
    const big = composeSticky("completed", "S".repeat(70000), ["N".repeat(100)]) ?? "";
    expect(big.length).toBeLessThanOrEqual(65536);
    expect(big.endsWith("N".repeat(100))).toBe(true);
  });
});

/* ------------------------- regression: round 1 fixes ------------------------ */

describe("retry labels on non-retried outcomes (retry-label-kept-on-skipped-incomplete)", () => {
  const MULTI = `${BASE_POLICY}    error:
      retry: { enabled: false, label: "xrepo:err-retry" }
`;

  it("computeLabelOps removes every configured retry label unless this run retries", () => {
    const policy = policyFor(MULTI);
    const ops = (primary: "completed" | "incomplete" | "skipped" | "error" | "usage_limit", attempt = 1) =>
      computeLabelOps({ policy, fired: [primary], primary, attempt });
    for (const primary of ["completed", "incomplete", "skipped", "error"] as const) {
      expect(ops(primary).remove, primary).toEqual(expect.arrayContaining(["xrepo-review:retry", "xrepo:err-retry"]));
      expect(ops(primary).add, primary).not.toContain("xrepo-review:retry");
    }
    // usage_limit below max: its own label is added, the other configured retry label is removed.
    expect(ops("usage_limit")).toEqual({ add: ["review-postponed", "xrepo-review:retry"], remove: ["xrepo:err-retry"] });
    // usage_limit at max: its label stays in place, so the sweeper gives up and comments once.
    expect(ops("usage_limit", 3)).toEqual({ add: ["review-postponed"], remove: ["xrepo:err-retry"] });
  });

  it("a skipped run removes the retry label left by an earlier usage_limit run", async () => {
    const s = setup({ draft: null });
    const r = await run(s, ["--skip-reason", "draft pull request"]);
    expect(callsOf(r.gh, "removeLabel")).toEqual([["xrepo-review:retry"]]);
  });

  it("an incomplete run removes it too", async () => {
    const s = setup({ draft: [HIGH, SUMMARY], exec: EXEC_MAX_TURNS });
    const r = await run(s, ["--agent-outcome", "failure", "--execution-file", s.exec]);
    expect(r.outputs.outcome).toBe("incomplete");
    expect(callsOf(r.gh, "removeLabel")).toEqual([["xrepo-review:retry"]]);
  });

  it("usage_limit at max_attempts neither adds nor removes the retry label", async () => {
    const s = setup({ draft: [], exec: EXEC_LIMIT });
    const r = await run(s, ["--execution-file", s.exec], { env: { GITHUB_RUN_ATTEMPT: "3" } });
    expect(callsOf(r.gh, "removeLabel")).toEqual([]);
  });
});

describe("blocking check vs. author-controlled skips (skip-marker-passes-blocking-check)", () => {
  const BLOCKING = BASE_POLICY.replace("labels: { enabled: true", "block: { enabled: true, method: check }\n    labels: { enabled: true");

  async function skipCheck(reason: string, opts: { policy?: string; ctx?: PrContext } = {}): Promise<CheckRunInput & { decided_by?: string }> {
    const s = setup({ policy: opts.policy ?? BLOCKING, draft: null, ...(opts.ctx ? { ctx: opts.ctx } : {}) });
    const r = await run(s, ["--skip-reason", reason]);
    expect(r.code).toBe(0);
    const [[check]] = callsOf(r.gh, "createCheckRun") as [[CheckRunInput]];
    return check;
  }

  it.each(['title contains "[skip review]"', "81 changed files (limit 80)", "4001 changed lines (limit 4000)", "diff larger than 32 MB", "diff refused: the GitHub API diff shows 2 files as binary while the PR changes .gitattributes (use fetch_depth: 0)"])(
    "%s fails the blocking check",
    async (reason) => {
      const check = await skipCheck(reason);
      expect(check.conclusion).toBe("failure");
      expect(check.title).toContain("Review required");
      expect(check.summary).toContain("cannot be passed by skipping the review");
    },
  );

  it.each(["author dependabot[bot] is a bot", "reviews are disabled for this repository (policy enabled: false)"])(
    "%s keeps the configured skipped conclusion",
    async (reason) => {
      expect((await skipCheck(reason, { ctx: { ...CTX, title: "Bump x [skip review]" } })).conclusion).toBe("skipped");
    },
  );

  it("an unrecognised reason fails closed when the title carries a marker or the PR is over the limits", async () => {
    expect((await skipCheck("some new reason", { ctx: { ...CTX, title: "Tweak [No Review]" } })).conclusion).toBe("failure");
    expect((await skipCheck("some new reason", { ctx: { ...CTX, changed_lines: 9000 } })).conclusion).toBe("failure");
    expect((await skipCheck("some new reason")).conclusion).toBe("skipped");
  });

  it("a non-blocking check, or an explicitly configured passing conclusion, is left alone", async () => {
    const notBlocking = BASE_POLICY.replace("labels: { enabled: true", "block: { enabled: true, method: review }\n    labels: { enabled: true");
    expect((await skipCheck('title contains "[skip review]"', { policy: notBlocking })).conclusion).toBe("skipped");
    const optOut = `${BLOCKING}    skipped:\n      check_conclusion: neutral\n`;
    expect((await skipCheck('title contains "[skip review]"', { policy: optOut })).conclusion).toBe("neutral");
    const strict = `${BLOCKING}    skipped:\n      check_conclusion: action_required\n`;
    expect((await skipCheck("draft pull request", { policy: strict })).conclusion).toBe("action_required");
  });

  it("authorControlledSkip", () => {
    const policy = policyFor(BLOCKING);
    expect(authorControlledSkip(policy, 'title contains "[no review]"')).toBe(true);
    expect(authorControlledSkip(policy, "pull request from a fork", { title: "[skip review]" })).toBe(false);
    expect(authorControlledSkip(policy, "?", { files: 81 })).toBe(true);
    expect(authorControlledSkip(policy, "?", { files: 80, changed_lines: 4000, title: "fine" })).toBe(false);
  });
});

describe("retry-after marker in the sticky comment (retry-ignores-reset-time)", () => {
  it("usage_limit below max_attempts: the marker carries the reset time, run id and attempt", async () => {
    const s = setup({ draft: [], exec: EXEC_LIMIT });
    // nowSeconds 1700000000 = 2023-11-14T22:13:20Z; "resets 1:32pm (UTC)" -> next day 13:32 + 5 min.
    const r = await run(s, ["--agent-outcome", "failure", "--execution-file", s.exec, "--run-attempt", "1"], { env: { GITHUB_RUN_ID: "5551" } });
    const [[body]] = callsOf(r.gh, "createIssueComment") as [[string]];
    expect(body).toBe(
      `${STICKY}\n⏸️ Automated review postponed: Claude usage limit reached (resets 1:32pm (UTC)). This does not block merging.\n\n` +
        "<!-- xrepo-review:retry-after 2023-11-15T13:37:00Z run=5551 attempt=1 -->\n<!-- xrepo-review:run=5551 -->",
    );
    // What the sweeper does with it: wait until the reset, then re-run.
    const markers = parseRetryAfterMarkers(body);
    const runInfo = { id: 5551, run_attempt: 1, status: "completed", updated_at: "2023-11-14T22:14:00Z" };
    expect(decideRetry(runInfo, 3, retryTiming(runInfo, markers, new Date("2023-11-15T13:17:00Z"))).action).toBe("wait");
    expect(decideRetry(runInfo, 3, retryTiming(runInfo, markers, new Date("2023-11-15T14:17:00Z"))).action).toBe("rerun");
  });

  it("dry-run reports the planned retry; no marker without GITHUB_RUN_ID or at max_attempts", async () => {
    const s = setup({ draft: [], exec: EXEC_LIMIT });
    const dry = await run(s, ["--dry-run", "--execution-file", s.exec], { noFactory: true, env: { GITHUB_RUN_ID: "77" } });
    const report = JSON.parse(dry.stdout) as PublishReport;
    expect(report.actions.retry).toEqual({ label: "xrepo-review:retry", max_attempts: 3, not_before: "2023-11-15T13:37:00Z", basis: "reset", marker: true });
    expect(report.actions.sticky?.body).toContain("<!-- xrepo-review:retry-after 2023-11-15T13:37:00Z run=77 attempt=1 -->");

    const noId = JSON.parse((await run(s, ["--dry-run", "--execution-file", s.exec], { noFactory: true })).stdout) as PublishReport;
    expect(noId.actions.retry).toMatchObject({ marker: false });
    expect(noId.actions.sticky?.body).not.toContain("retry-after");

    const atMax = JSON.parse((await run(s, ["--dry-run", "--execution-file", s.exec, "--run-attempt", "3"], { noFactory: true, env: { GITHUB_RUN_ID: "77" } })).stdout) as PublishReport;
    expect(atMax.actions.retry).toBeNull();
    expect(atMax.actions.sticky?.body).not.toContain("retry-after");
  });

  it("composeSticky appends the trailer after a blank line and never posts a trailer alone", () => {
    expect(composeSticky("usage_limit", undefined, ["NOTE"], "<!-- m -->")).toBe(`${STICKY}\nNOTE\n\n<!-- m -->`);
    expect(composeSticky("usage_limit", undefined, [""], "<!-- m -->")).toBeUndefined();
    const big = composeSticky("completed", "S".repeat(70000), ["N"], "<!-- m -->") ?? "";
    expect(big.length).toBeLessThanOrEqual(65536);
    expect(big.endsWith("N\n\n<!-- m -->")).toBe(true);
  });
});

describe("GITHUB_API_URL (github-api-url-four-ways)", () => {
  it("an invalid GITHUB_API_URL fails closed: no client, no writes, exit 1, outputs written", async () => {
    const s = setup({ draft: [SUMMARY, FINISH] });
    const r = await run(s, [], { noFactory: true, env: { GITHUB_API_URL: "http://ghe.internal/api/v3", XREPO_DISPATCH_TOKEN: "dtok" } });
    expect(r.code).toBe(1);
    expect(r.factoryCalls).toBe(0);
    expect(r.outputs.outcome).toBe("completed");
  });

  it("a valid GHES URL is passed to the client", async () => {
    const s = setup({ draft: [SUMMARY, FINISH] });
    const r = await run(s, [], { env: { GITHUB_API_URL: "https://ghe.example.com/api/v3" } });
    expect(r.code).toBe(0);
    expect(r.gh.opts?.baseUrl).toBe("https://ghe.example.com/api/v3");
  });
});

describe("outcome comment templates (markdown-escaper-tilde-fence)", () => {
  it("a PR title starting with ~~~ cannot inject HTML into the sticky comment or check summary", async () => {
    const policy =
      `${BASE_POLICY}    incomplete:\n      comment: "Review of \\u201C{pr_title}\\u201D did not finish ({reason})."\n` +
      `    error:\n      comment: "Review of \\u201C{pr_title}\\u201D could not run ({reason})."\n`;
    const title = "~~~ <img src=https://attacker.example/p.png> <a href=https://evil.example>x</a> @acme/security";
    const s = setup({ policy, draft: [HIGH], exec: EXEC_MAX_TURNS, ctx: { ...CTX, title } });
    const r = await run(s, ["--agent-outcome", "failure", "--execution-file", s.exec]);
    const [[body]] = callsOf(r.gh, "createIssueComment") as [[string]];
    expect(body).not.toMatch(/<img|<a |~~~/);
    expect(body).toContain(`@${Z}acme/security`);
    expect(body).toMatch(/did not finish \(maximum number of turns reached\)\./);

    // error: no plan, so the check summary is the rendered outcome comment.
    const e = setup({ policy, draft: null, ctx: { ...CTX, title } });
    const re = await run(e, ["--agent-outcome", "failure"]);
    const [[check]] = callsOf(re.gh, "createCheckRun") as [[CheckRunInput]];
    const [[errBody]] = callsOf(re.gh, "createIssueComment") as [[string]];
    for (const text of [check.summary, errBody]) {
      expect(text).not.toMatch(/<img|<a |~~~|\n~/);
      expect(text).toContain(`@${Z}acme/security`);
      expect(text).toMatch(/could not run \(the Claude Code step failed\)\.$/);
    }
  });
});

describe("xrepo publish: kill switch (publisher-ignores-kill-switch)", () => {
  const ON = `
version: 1
notifications:
  chat: { type: slack, url_secret: SLACK_URL }
defaults:
  enabled: true
  capabilities:
    approve: { enabled: true }
    block: { enabled: true, method: both }
    check: { enabled: true, name: "xrepo-review" }
    labels: { enabled: true, allowed: ["security"] }
  outcomes:
    completed:
      add_labels: ["reviewed"]
      notify: [{ target: chat, message: "Reviewed {repo}#{pr_number}" }]
      dispatch: { event_type: "xrepo-done" }
    approved:
      add_labels: ["auto-approved"]
`;
  const OFF = ON.replace("enabled: true\n  capabilities", "enabled: false\n  capabilities");

  it("a manifest flipped to enabled: false after prepare publishes nothing but the skipped outcome", async () => {
    expect(OFF).not.toBe(ON);
    const s = setup({ policy: null, draft: [SUMMARY, line({ type: "labels", labels: ["security"] }), verdict("approve"), FINISH] });
    const manifest = join(s.dir, "policy.yaml");
    writeFileSync(manifest, OFF, { mode: 0o644 });
    const r = await run(s, ["--agent-outcome", "success", "--policy", manifest]);
    expect(r.code).toBe(0);
    expect(callsOf(r.gh, "createReview")).toHaveLength(0);
    expect(callsOf(r.gh, "listReviewCommentKeys")).toHaveLength(0);
    expect(callsOf(r.gh, "createIssueComment")).toHaveLength(0);
    expect(callsOf(r.gh, "addLabels")).toHaveLength(0);
    expect(callsOf(r.gh, "removeLabel")).toHaveLength(0);
    expect(callsOf(r.gh, "repositoryDispatch")).toHaveLength(0);
    expect(r.fetch.calls).toHaveLength(0);
    const [[check]] = callsOf(r.gh, "createCheckRun") as [[CheckRunInput]];
    expect(check.conclusion).toBe("skipped");
    expect(r.outputs).toMatchObject({ outcome: "skipped", reason: "reviews are disabled for this repository (policy enabled: false)", verdict: "", fired_outcomes: "skipped" });
  });

  it("dry-run under a disabled resolved policy plans no review either", async () => {
    const s = setup({ policy: OFF, draft: [SUMMARY, verdict("approve"), FINISH] });
    const r = await run(s, ["--agent-outcome", "success", "--dry-run"], { noFactory: true });
    const rep = JSON.parse(r.stdout);
    expect(rep.outcome.outcome).toBe("skipped");
    expect(rep.fired).toEqual(["skipped"]);
    expect(rep.plan).toBeNull();
    expect(rep.actions.review).toBeNull();
    expect(rep.actions.labels).toEqual({ add: [], remove: [] });
    expect(rep.actions.notify).toEqual([]);
    expect(rep.actions.dispatch).toEqual([]);
  });

  it("the same run under the enabled manifest still approves (control)", async () => {
    const s = setup({ policy: null, draft: [SUMMARY, verdict("approve"), FINISH] });
    const manifest = join(s.dir, "policy.yaml");
    writeFileSync(manifest, ON, { mode: 0o644 });
    const r = await run(s, ["--agent-outcome", "success", "--policy", manifest]);
    const [[review]] = callsOf(r.gh, "createReview") as [[PlanReview]];
    expect(review.event).toBe("APPROVE");
    expect(r.outputs.fired_outcomes).toBe("completed,approved");
  });
});

describe("xrepo publish: the trusted manifest wins over ctx/policy.resolved.json (publish-trusts-artifact-policy)", () => {
  // The artifact's resolved policy passed through the agent's job: a forged one enables approve.
  const FORGED = `${BASE_POLICY.replace("check: {", "approve: { enabled: true, max_changed_lines: 100000 }\n    check: {")}`;

  it("with --policy, the forged ctx policy is ignored: no approval", async () => {
    expect(FORGED).toContain("approve: { enabled: true");
    const s = setup({ policy: FORGED, draft: [SUMMARY, verdict("approve"), FINISH] });
    const manifest = join(s.dir, "policy.yaml");
    writeFileSync(manifest, BASE_POLICY, { mode: 0o644 });
    const r = await run(s, ["--agent-outcome", "success", "--policy", manifest]);
    expect(r.code).toBe(0);
    expect((callsOf(r.gh, "createReview") as [PlanReview][]).map(([rv]) => rv.event)).not.toContain("APPROVE");
    expect(r.outputs).toMatchObject({ outcome: "completed", verdict: "comment", fired_outcomes: "completed" });
  });

  it("without --policy the ctx policy is used (local runs and tests)", async () => {
    const s = setup({ policy: FORGED, draft: [SUMMARY, verdict("approve"), FINISH] });
    const r = await run(s, ["--agent-outcome", "success"]);
    expect(r.outputs.fired_outcomes).toBe("completed,approved");
  });

  it("an unreadable --policy manifest is an infrastructure failure (exit 1), never a fallback to ctx", async () => {
    const s = setup({ policy: FORGED, draft: [SUMMARY, verdict("approve"), FINISH] });
    const r = await run(s, ["--agent-outcome", "success", "--policy", join(s.dir, "missing.yaml")]);
    expect(r.code).toBe(1);
    expect(callsOf(r.gh, "createReview")).toHaveLength(0);
    expect(r.outputs.outcome).toBe("error");
  });
});

describe("xrepo publish: check conclusion of a blocked review (completed-check-conclusion-overrides-block)", () => {
  const BLOCK = (outcomes: string) => `
version: 1
defaults:
  capabilities:
    block: { enabled: true, method: check, min_severity: high }
    check: { enabled: true, name: "xrepo-review" }
  outcomes:
${outcomes}`;

  it("completed: check_conclusion success does not pass a review that blocks via the check", async () => {
    const s = setup({ policy: BLOCK("    completed: { check_conclusion: success }\n"), draft: [HIGH, verdict("request_changes"), FINISH] });
    const r = await run(s, ["--agent-outcome", "success"]);
    const [[check]] = callsOf(r.gh, "createCheckRun") as [[CheckRunInput]];
    expect(check.conclusion).toBe("failure");
    expect(check.title).toMatch(/^Changes requested: 1 finding at or above high$/);
    expect(r.outputs.fired_outcomes).toBe("completed,blocked");
  });

  it("the blocked outcome's own check_conclusion still applies, and the title says why", async () => {
    const s = setup({ policy: BLOCK("    blocked: { check_conclusion: neutral }\n"), draft: [HIGH, verdict("request_changes"), FINISH] });
    const r = await run(s, ["--agent-outcome", "success"]);
    const [[check]] = callsOf(r.gh, "createCheckRun") as [[CheckRunInput]];
    expect(check.conclusion).toBe("neutral");
    expect(check.title).toBe("Changes requested: 1 finding at or above high (check neutral: outcomes.blocked.check_conclusion)");
  });

  it("a completed override of a non-blocking plan names itself in the title", () => {
    const policy = policyFor(BLOCK("    completed: { check_conclusion: failure }\n"));
    const check = resolveCheck({
      policy,
      plan: { check: { name: "xrepo-review", conclusion: "success", title: "No findings", summary: "s" }, blocked: false } as never,
      fired: ["completed"],
      cls: { outcome: "completed", reason: "review finished" },
      outcomeComments: [],
    });
    expect(check).toMatchObject({ conclusion: "failure", title: "No findings (check failure: outcomes.completed.check_conclusion)", decided_by: "completed" });
  });
});

describe("xrepo publish: GitHub refuses the review event (approve-refused-loses-review)", () => {
  const APPROVE_POLICY = `${BASE_POLICY.replace("check: {", "approve: { enabled: true }\n    block: { enabled: true, method: both, min_severity: high }\n    check: {")}
    approved: { add_labels: ["auto-approved"] }
    blocked: { add_labels: ["blocked"] }
`;
  const refusing = (from: "APPROVE" | "REQUEST_CHANGES") => {
    const gh = fakeGitHub();
    gh.createReview = async (r: PlanReview, opts?: { downgradeRefusedEvent?: boolean }): Promise<CreateReviewResult> => {
      gh.calls.push({ method: "createReview", args: [r, opts] });
      expect(opts?.downgradeRefusedEvent).toBe(true);
      return { id: 2, inlineFallback: false, event: "COMMENT", downgraded: { from, reason: "GitHub Actions is not permitted to approve pull requests" } };
    };
    return gh;
  };

  it("a refused APPROVE posts a comment review: no `approved`, verdict comment, check not 'Approved'", async () => {
    const s = setup({ policy: APPROVE_POLICY, draft: [SUMMARY, verdict("approve"), FINISH] });
    const r = await run(s, ["--agent-outcome", "success", "--plan-out", s.planOut], { gh: refusing("APPROVE") });
    expect(r.code).toBe(0);
    expect(r.outputs).toMatchObject({ outcome: "completed", verdict: "comment", fired_outcomes: "completed" });
    expect(callsOf(r.gh, "addLabels").flat(2)).not.toContain("auto-approved");
    const [[check]] = callsOf(r.gh, "createCheckRun") as [[CheckRunInput]];
    expect(check.conclusion).toBe("success");
    expect(check.title).toBe("Approval refused by GitHub, posted as a comment");
    const [[sticky]] = callsOf(r.gh, "createIssueComment") as [[string]];
    expect(sticky).toContain("GitHub refused to submit the review as APPROVE");
    const rep = JSON.parse(readFileSync(s.planOut, "utf8")) as PublishReport;
    expect(rep.actions.review).toMatchObject({ event: "COMMENT", refused_event: "APPROVE", posted: true });
  });

  it("a refused REQUEST_CHANGES with block.method both still blocks through the failing check", async () => {
    const s = setup({ policy: APPROVE_POLICY, draft: [HIGH, verdict("request_changes"), FINISH] });
    const r = await run(s, ["--agent-outcome", "success"], { gh: refusing("REQUEST_CHANGES") });
    expect(r.outputs).toMatchObject({ verdict: "request_changes", fired_outcomes: "completed,blocked" });
    const [[check]] = callsOf(r.gh, "createCheckRun") as [[CheckRunInput]];
    expect(check.conclusion).toBe("failure");
  });

  it("a refused REQUEST_CHANGES with block.method review does not block", () => {
    const policy = policyFor(APPROVE_POLICY.replace("method: both", "method: review"));
    const plan = {
      verdict: "request_changes",
      blocked: true,
      approved: false,
      findings: 1,
      summary: "S",
      summaryTarget: "sticky",
      review: { event: "REQUEST_CHANGES", body: "b", comments: [] },
      check: { name: "xrepo-review", conclusion: "neutral", title: "1 finding", summary: "S" },
      decisions: [],
      dismiss_change_requests: false,
    } as never;
    const after = planAfterRefusedEvent(plan, { from: "REQUEST_CHANGES", reason: "Can not request changes on your own pull request" }, policy);
    expect(after).toMatchObject({ verdict: "comment", blocked: false, approved: false, dismiss_change_requests: false, review: { event: "COMMENT" } });
    expect(after.check?.conclusion).toBe("neutral");
    expect(after.summary).toContain("so it was posted as a comment: it does not request changes.");
  });
});

describe("xrepo publish: stale change requests and stale sticky comments", () => {
  it("a finished run that does not request changes dismisses our earlier change requests (best effort)", async () => {
    const s = setup({ draft: [HIGH, SUMMARY, verdict("comment"), FINISH] });
    const gh = fakeGitHub();
    const messages: string[] = [];
    gh.dismissStaleChangeRequests = async (message: string) => {
      messages.push(message);
      return { dismissed: [5], failed: [6] };
    };
    const r = await run(s, ["--agent-outcome", "success", "--plan-out", s.planOut], { gh });
    expect(r.code).toBe(0); // a failed dismissal is not an infrastructure failure
    expect(messages).toEqual([`Superseded by a newer automated review of commit ${HEAD.slice(0, 7)} (verdict: comment).`]);
    const rep = JSON.parse(readFileSync(s.planOut, "utf8")) as PublishReport;
    expect(rep.actions.dismiss?.result).toEqual({ dismissed: [5], failed: [6] });
    expect(rep.errors.join("\n")).toContain("dismissing 1 earlier review(s) failed");
  });

  it("an incomplete run neither blocks nor dismisses", async () => {
    const s = setup({ draft: [HIGH], exec: EXEC_MAX_TURNS });
    const gh = fakeGitHub();
    let called = false;
    gh.dismissStaleChangeRequests = async () => {
      called = true;
      return { dismissed: [], failed: [] };
    };
    await run(s, ["--agent-outcome", "failure", "--execution-file", s.exec], { gh });
    expect(called).toBe(false);
  });

  it("with the summary in the review, an earlier run's sticky is replaced by a status note (never created)", async () => {
    const policy = BASE_POLICY.replace("check: {", 'summary_comment: { mode: review }\n    check: {');
    const s = setup({ policy, draft: [HIGH, SUMMARY, FINISH] });
    const old = { id: 9, body: `${STICKY}\nReview postponed: usage limit reached` };
    const r = await run(s, ["--agent-outcome", "success"], { gh: fakeGitHub({ sticky: old }) });
    expect(callsOf(r.gh, "createIssueComment")).toHaveLength(0);
    const [[id, body]] = callsOf(r.gh, "updateIssueComment") as [[number, string]];
    expect(id).toBe(9);
    expect(body).toBe(
      `${STICKY}\nThe latest automated review of commit ${HEAD.slice(0, 7)} completed (verdict: comment, 1 finding). ` +
        "Its results are in the pull request review. An earlier status message in this comment is no longer current.",
    );
    // Nothing to replace: no comment is created.
    const none = await run(setup({ policy, draft: [HIGH, SUMMARY, FINISH] }), ["--agent-outcome", "success"]);
    expect(callsOf(none.gh, "createIssueComment")).toHaveLength(0);
    expect(callsOf(none.gh, "updateIssueComment")).toHaveLength(0);
  });
});

describe("repository_dispatch without XREPO_DISPATCH_TOKEN (same-repo-dispatch-lacks-contents-write)", () => {
  it("a 403 from the publisher's GITHUB_TOKEN says that XREPO_DISPATCH_TOKEN is needed", async () => {
    const api = {
      repositoryDispatch: async () => {
        throw Object.assign(new Error("Resource not accessible by integration"), { status: 403 });
      },
    };
    const r = await repositoryDispatch({ event_type: "done" }, { prRepo: "acme/web", client_payload: {}, api, env: {} });
    expect(r).toMatchObject({ ok: false, via: "api", status: 403 });
    expect(r.error).toContain("set XREPO_DISPATCH_TOKEN");
  });
});

/* ------------------------- regression: round 2 fixes ------------------------ */

describe("retry-stop marker at an outcome's own max_attempts (retry-shared-label-max-attempts)", () => {
  // usage_limit and error share the default label "xrepo-review:retry" with different limits.
  const SHARED = BASE_POLICY.replace("retry: { enabled: true, max_attempts: 3 }", "retry: { enabled: true, max_attempts: 5 }") + "    error:\n      retry: { enabled: true, max_attempts: 2 }\n";

  it("exhaustedRetry: usage_limit / error with retry.enabled at or above their own max_attempts", () => {
    const policy = policyFor(SHARED);
    expect(exhaustedRetry(policy, "error", 1)).toBeUndefined();
    expect(exhaustedRetry(policy, "error", 2)).toEqual({ label: "xrepo-review:retry", max_attempts: 2 });
    expect(exhaustedRetry(policy, "usage_limit", 2)).toBeUndefined();
    expect(exhaustedRetry(policy, "usage_limit", 5)).toEqual({ label: "xrepo-review:retry", max_attempts: 5 });
    expect(exhaustedRetry(policy, "completed", 9)).toBeUndefined();
    expect(exhaustedRetry(policyFor(BASE_POLICY), "error", 9)).toBeUndefined(); // retry not enabled for error
  });

  it("an error run at attempt 2 leaves the label and a retry-stop marker; the sweeper then gives up instead of re-running up to 5", async () => {
    const s = setup({ policy: SHARED, draft: [] });
    const r = await run(s, ["--agent-outcome", "failure", "--run-attempt", "2"], { env: { GITHUB_RUN_ID: "88" } });
    expect(r.code).toBe(0);
    expect(r.outputs.outcome).toBe("error");
    const [[body]] = callsOf(r.gh, "createIssueComment") as [[string]];
    expect(body.endsWith("\n\n<!-- xrepo-review:retry-stop run=88 attempt=2 max=2 -->\n<!-- xrepo-review:run=88 -->")).toBe(true);
    expect(body).not.toContain("retry-after");
    // The label stays (neither added nor removed) for the sweeper to give up and comment.
    expect(callsOf(r.gh, "addLabels")).toEqual([]);
    expect(callsOf(r.gh, "removeLabel")).toEqual([]);
    // What the sweeper decides from this sticky comment, with the label's merged rules (max 5).
    const rules = retryRules(policyFor(SHARED));
    expect(rules).toEqual([{ label: "xrepo-review:retry", max_attempts: 5, unmarked_max_attempts: 2 }]);
    const runInfo = { id: 88, run_attempt: 2, status: "completed", updated_at: "2023-11-14T22:14:00Z" };
    const limit = retryLimit(runInfo, parseRetryMarkers(body), rules);
    expect(limit).toEqual({ max_attempts: 2, basis: "stop" });
    expect(decideRetry(runInfo, limit.max_attempts).action).toBe("give_up");
  });

  it("a usage_limit run at attempt 2 still asks for a retry (its own max is 5)", async () => {
    const s = setup({ policy: SHARED, draft: [], exec: EXEC_LIMIT });
    const r = await run(s, ["--execution-file", s.exec, "--run-attempt", "2"], { env: { GITHUB_RUN_ID: "89" } });
    const [[body]] = callsOf(r.gh, "createIssueComment") as [[string]];
    expect(body).toContain("<!-- xrepo-review:retry-after 2023-11-15T13:37:00Z run=89 attempt=2 -->");
    const runInfo = { id: 89, run_attempt: 2, status: "completed", updated_at: "2023-11-14T22:14:00Z" };
    const markers = parseRetryMarkers(body);
    const limit = retryLimit(runInfo, markers, retryRules(policyFor(SHARED)));
    expect(limit).toEqual({ max_attempts: 5, basis: "retry" });
    expect(decideRetry(runInfo, limit.max_attempts, retryTiming(runInfo, markers, new Date("2023-11-15T14:17:00Z"))).action).toBe("rerun");
  });

  it("dry-run reports retry_exhausted; no marker without GITHUB_RUN_ID; retry stays null", async () => {
    const s = setup({ draft: [], exec: EXEC_LIMIT });
    const atMax = JSON.parse((await run(s, ["--dry-run", "--execution-file", s.exec, "--run-attempt", "3"], { noFactory: true, env: { GITHUB_RUN_ID: "77" } })).stdout) as PublishReport;
    expect(atMax.actions.retry).toBeNull();
    expect(atMax.actions.retry_exhausted).toEqual({ label: "xrepo-review:retry", max_attempts: 3, marker: true });
    expect(atMax.actions.sticky?.body).toContain("<!-- xrepo-review:retry-stop run=77 attempt=3 max=3 -->");
    const noId = JSON.parse((await run(s, ["--dry-run", "--execution-file", s.exec, "--run-attempt", "3"], { noFactory: true })).stdout) as PublishReport;
    expect(noId.actions.retry_exhausted).toEqual({ label: "xrepo-review:retry", max_attempts: 3, marker: false });
    expect(noId.actions.sticky?.body).not.toContain("retry-stop");
    // Below max_attempts: no retry_exhausted.
    const below = JSON.parse((await run(s, ["--dry-run", "--execution-file", s.exec, "--run-attempt", "1"], { noFactory: true, env: { GITHUB_RUN_ID: "77" } })).stdout) as PublishReport;
    expect(below.actions.retry_exhausted).toBeUndefined();
    expect(below.actions.sticky?.body).not.toContain("retry-stop");
  });
});

/* ------------- round-3 publisher wiring (approvals, replays, draft skips, skip sticky) ------------- */

describe("xrepo publish: stale approvals are dismissed by every run that does not approve (stale-bot-approval-never-dismissed)", () => {
  const APPROVE = BASE_POLICY.replace("labels: { enabled: true", "approve: { enabled: true, max_severity_allowed: low }\n    labels: { enabled: true");
  const withDismissals = (): FakeGitHub & { approvals: string[]; changeRequests: string[] } => {
    const gh = fakeGitHub() as FakeGitHub & { approvals: string[]; changeRequests: string[] };
    gh.approvals = [];
    gh.changeRequests = [];
    gh.dismissStaleApprovals = async (message: string) => {
      gh.approvals.push(message);
      return { dismissed: [11], failed: [] };
    };
    gh.dismissStaleChangeRequests = async (message: string) => {
      gh.changeRequests.push(message);
      return { dismissed: [], failed: [] };
    };
    return gh;
  };

  it.each([
    ["skipped", ["--skip-reason", "draft pull request"], {}],
    ["error", ["--agent-outcome", "failure"], {}],
    ["usage_limit", ["--agent-outcome", "failure", "--execution-file", "EXEC"], { exec: EXEC_LIMIT }],
  ] as const)("a %s run (no plan) dismisses our earlier approvals", async (outcome, args, opts) => {
    const s = setup({ policy: APPROVE, draft: [], ...opts });
    const gh = withDismissals();
    const r = await run(s, [...args.map((a) => (a === "EXEC" ? s.exec : a)), "--plan-out", s.planOut], { gh });
    expect(r.outputs.outcome).toBe(outcome);
    expect(gh.approvals).toEqual([`Superseded: the latest automated review run of commit ${HEAD.slice(0, 7)} did not approve the pull request (outcome: ${outcome}).`]);
    expect(gh.changeRequests).toEqual([]);
    const rep = JSON.parse(readFileSync(s.planOut, "utf8")) as PublishReport;
    expect(rep.actions.dismiss_approvals?.result).toEqual({ dismissed: [11], failed: [] });
  });

  it("the kill switch dismisses them too", async () => {
    const s = setup({ policy: `${APPROVE}repos:\n  acme/web:\n    enabled: false\n`, draft: [SUMMARY, verdict("approve"), FINISH] });
    const gh = withDismissals();
    const r = await run(s, ["--agent-outcome", "success"], { gh });
    expect(r.outputs.outcome).toBe("skipped");
    expect(gh.approvals).toHaveLength(1);
  });

  it("an incomplete run and a REQUEST_CHANGES run dismiss approvals; neither lifts change requests", async () => {
    const inc = withDismissals();
    await run(setup({ policy: APPROVE, draft: [HIGH], exec: EXEC_MAX_TURNS }), ["--agent-outcome", "failure", "--execution-file", join(root, "none")], { gh: inc });
    expect(inc.approvals).toHaveLength(1);
    expect(inc.changeRequests).toEqual([]);

    const blocking = APPROVE.replace("labels: { enabled: true", "block: { enabled: true, method: review, min_severity: high }\n    labels: { enabled: true");
    const rc = withDismissals();
    const r = await run(setup({ policy: blocking, draft: [HIGH, verdict("request_changes"), FINISH] }), ["--agent-outcome", "success"], { gh: rc });
    expect((callsOf(r.gh, "createReview")[0]?.[0] as PlanReview).event).toBe("REQUEST_CHANGES");
    expect(rc.approvals).toEqual([`Superseded by a newer automated review of commit ${HEAD.slice(0, 7)} (verdict: request_changes).`]);
    expect(rc.changeRequests).toEqual([]);
  });

  it("a finished COMMENT run uses dismissStaleChangeRequests only (it dismisses approvals as well)", async () => {
    const gh = withDismissals();
    await run(setup({ policy: APPROVE, draft: [HIGH, SUMMARY, verdict("comment"), FINISH] }), ["--agent-outcome", "success"], { gh });
    expect(gh.changeRequests).toHaveLength(1);
    expect(gh.approvals).toEqual([]);
  });

  it("an approving run dismisses no approval; a failed APPROVE post does (fail closed)", async () => {
    const ok = withDismissals();
    const r = await run(setup({ policy: APPROVE, draft: [LOW, SUMMARY, verdict("approve"), FINISH] }), [], { gh: ok });
    expect((callsOf(r.gh, "createReview")[0]?.[0] as PlanReview).event).toBe("APPROVE");
    expect(ok.approvals).toEqual([]);

    const failed = withDismissals();
    failed.fail.add("createReview");
    await run(setup({ policy: APPROVE, draft: [LOW, verdict("approve"), FINISH] }), [], { gh: failed });
    expect(failed.approvals).toHaveLength(1);
    expect(failed.changeRequests).toEqual([]);
  });

  it("a missing token is not made an infrastructure failure by the best-effort dismissal alone", async () => {
    const quiet = "version: 1\n"; // no check, no comment for skipped
    const r = await run(setup({ policy: quiet, draft: null }), ["--skip-reason", "pull request from a fork"], { env: { GITHUB_TOKEN: "" }, noFactory: true });
    expect(r.code).toBe(0);
  });

  it("planAfterRefusedEvent: a withheld approval says so and dismisses earlier approvals", () => {
    const policy = policyFor(APPROVE);
    const plan = {
      verdict: "approve",
      blocked: false,
      approved: true,
      findings: 0,
      summary: "S",
      summaryTarget: "sticky",
      review: { event: "APPROVE", body: "b", comments: [] },
      check: { name: "xrepo-review", conclusion: "success", title: "Approved", summary: "S" },
      decisions: [],
      dismiss_change_requests: true,
      dismiss_approvals: false,
    } as never;
    const withheld = planAfterRefusedEvent(plan, { from: "APPROVE", reason: "the pull request head moved to 2222222 after commit abc1234 was reviewed", withheld: true }, policy);
    expect(withheld).toMatchObject({ approved: false, verdict: "comment", dismiss_approvals: true, dismiss_change_requests: true });
    expect(withheld.summary).toContain("The review was not submitted as an approval");
    expect(withheld.summary).not.toContain("GitHub refused");
    expect(withheld.check?.title).toBe("Approval withheld, posted as a comment");
    expect(withheld.decisions.at(-1)).toMatch(/^approval withheld \(/);
    const refused = planAfterRefusedEvent(plan, { from: "APPROVE", reason: "GitHub Actions is not permitted to approve pull requests" }, policy);
    expect(refused.summary).toContain("GitHub refused to submit the review as APPROVE");
    expect(refused.dismiss_approvals).toBe(true);
  });
});

describe("xrepo publish: replayed and superseded runs (replayed-old-run-overrides-current-state)", () => {
  const BLOCKING = `${BASE_POLICY.replace("labels: { enabled: true", "approve: { enabled: true }\n    block: { enabled: true, method: both, min_severity: high }\n    labels: { enabled: true")}
    blocked: { add_labels: ["blocked"], notify: [{ target: chat }] }
`;
  const staleGh = (freshness: () => Promise<{ current: boolean; head_sha: string; state: string; reason?: string; newer_run?: number }>) => {
    const gh = fakeGitHub({ sticky: { id: 9, body: `${STICKY}\nold` } });
    gh.runFreshness = async (name?: string) => {
      gh.calls.push({ method: "runFreshness", args: [name] });
      return freshness();
    };
    gh.dismissStaleApprovals = async () => {
      gh.calls.push({ method: "dismissStaleApprovals", args: [] });
      return { dismissed: [], failed: [] };
    };
    gh.dismissStaleChangeRequests = async () => {
      gh.calls.push({ method: "dismissStaleChangeRequests", args: [] });
      return { dismissed: [], failed: [] };
    };
    return gh;
  };

  it("passes the workflow run to the client and keep_failure only for runs that did not complete", async () => {
    const s = setup({ draft: [SUMMARY, FINISH] });
    const r = await run(s, ["--run-attempt", "2"], { env: { GITHUB_RUN_ID: "123" } });
    expect(r.gh.opts?.run).toEqual({ id: 123, attempt: 2 });
    expect((callsOf(r.gh, "createCheckRun")[0]?.[0] as CheckRunInput).keep_failure).toBe(false);
    const noRun = await run(setup({ draft: [SUMMARY, FINISH] }));
    expect(noRun.gh.opts?.run).toBeUndefined();
    const err = await run(setup({ draft: [] }), ["--agent-outcome", "failure"]);
    expect((callsOf(err.gh, "createCheckRun")[0]?.[0] as CheckRunInput).keep_failure).toBe(true);
  });

  it("a stale run posts only its check: no review, dismissal, sticky, labels, notifications or `blocked`", async () => {
    const s = setup({ policy: BLOCKING, draft: [HIGH, SUMMARY, verdict("request_changes"), FINISH] });
    const gh = staleGh(async () => ({ current: false, head_sha: "c".repeat(40), state: "open", reason: "this run reviewed aaaaaaa, but the pull request head is ccccccc" }));
    const r = await run(s, ["--agent-outcome", "success", "--plan-out", s.planOut], { gh });
    expect(r.code).toBe(0);
    expect(callsOf(gh, "runFreshness")).toEqual([["xrepo-review"]]);
    for (const m of ["createReview", "listReviewCommentKeys", "dismissStaleApprovals", "dismissStaleChangeRequests", "findStickyComment", "createIssueComment", "updateIssueComment", "addLabels", "removeLabel"]) {
      expect(callsOf(gh, m), m).toHaveLength(0);
    }
    expect(r.fetch.calls).toHaveLength(0);
    const [[check]] = callsOf(gh, "createCheckRun") as [[CheckRunInput]];
    expect(check.conclusion).toBe("failure"); // the plan's own conclusion, on the commit it reviewed
    expect(r.outputs).toMatchObject({ outcome: "completed", verdict: "request_changes", fired_outcomes: "completed" });
    const rep = JSON.parse(readFileSync(s.planOut, "utf8")) as PublishReport;
    expect(rep.stale).toEqual({ reason: "this run reviewed aaaaaaa, but the pull request head is ccccccc", head_sha: "c".repeat(40) });
    expect(rep.actions.review?.posted).toBe(false);
  });

  it("a stale usage_limit run neither labels for a retry nor writes a marker", async () => {
    const s = setup({ draft: [], exec: EXEC_LIMIT });
    const gh = staleGh(async () => ({ current: false, head_sha: HEAD, state: "open", newer_run: 200, reason: "workflow run 200 (newer than run 100) already published for this commit" }));
    const r = await run(s, ["--execution-file", s.exec, "--plan-out", s.planOut], { gh, env: { GITHUB_RUN_ID: "100" } });
    expect(callsOf(gh, "addLabels")).toHaveLength(0);
    expect(callsOf(gh, "createIssueComment")).toHaveLength(0);
    const rep = JSON.parse(readFileSync(s.planOut, "utf8")) as PublishReport;
    expect(rep.actions.retry).toBeNull();
    expect(rep.stale?.newer_run).toBe(200);
  });

  it("an unreadable pull request (freshness unknown) publishes as usual", async () => {
    const s = setup({ draft: [SUMMARY, FINISH] });
    const gh = staleGh(async () => {
      throw Object.assign(new Error("Not Found"), { status: 404 });
    });
    const r = await run(s, ["--plan-out", s.planOut], { gh });
    expect(r.code).toBe(0);
    expect(callsOf(gh, "updateIssueComment")).toHaveLength(1);
    expect((JSON.parse(readFileSync(s.planOut, "utf8")) as PublishReport).stale).toBeUndefined();
  });

  it("a check that GitHubApi refuses to post (superseded) is reported, not marked posted", async () => {
    const s = setup({ draft: [], exec: EXEC_LIMIT });
    const gh = fakeGitHub();
    gh.createCheckRun = async (c: CheckRunInput) => {
      gh.calls.push({ method: "createCheckRun", args: [c] });
      return { id: 7, superseded: { reason: "a failing xrepo-review check on this commit stays in force (a run that did not review it never lifts it)" } };
    };
    const r = await run(s, ["--execution-file", s.exec, "--plan-out", s.planOut], { gh });
    expect(r.code).toBe(0);
    const rep = JSON.parse(readFileSync(s.planOut, "utf8")) as PublishReport;
    expect(rep.actions.check).toMatchObject({ posted: false, superseded: { reason: expect.stringContaining("stays in force") } });
  });
});

describe("xrepo publish: draft skips under a blocking check (draft-skip-passes-blocking-check)", () => {
  const BLOCKING = BASE_POLICY.replace("labels: { enabled: true", "block: { enabled: true, method: check }\n    labels: { enabled: true");

  it("fails the blocking check as 'Review pending' and asks GitHub to keep a failing one", async () => {
    const r = await run(setup({ policy: BLOCKING, draft: null }), ["--skip-reason", "draft pull request"]);
    expect(r.code).toBe(0);
    const [[check]] = callsOf(r.gh, "createCheckRun") as [[CheckRunInput]];
    expect(check).toMatchObject({ conclusion: "failure", title: "Review pending: draft pull request (runs when marked ready)", keep_failure: true });
    expect(check.summary).toContain("marked ready for review");
  });

  it("a non-blocking check, or an explicitly configured conclusion, is left alone", async () => {
    const notBlocking = BASE_POLICY.replace("labels: { enabled: true", "block: { enabled: true, method: review }\n    labels: { enabled: true");
    const a = await run(setup({ policy: notBlocking, draft: null }), ["--skip-reason", "draft pull request"]);
    expect((callsOf(a.gh, "createCheckRun")[0]?.[0] as CheckRunInput).conclusion).toBe("skipped");
    const optOut = `${BLOCKING}    skipped:\n      check_conclusion: neutral\n`;
    const b = await run(setup({ policy: optOut, draft: null }), ["--skip-reason", "draft pull request"]);
    expect((callsOf(b.gh, "createCheckRun")[0]?.[0] as CheckRunInput).conclusion).toBe("neutral");
  });

  it("authorControlledSkip does not count a draft as author-controlled, even with a marker in the title", () => {
    expect(authorControlledSkip(policyFor(BLOCKING), "draft pull request", { title: "WIP [skip review]" })).toBe(false);
    expect(authorControlledSkip(policyFor(BLOCKING), "diff refused: x")).toBe(true);
    // The exact reasons prepare writes for the diffs GitHub will not serve / prepare refuses.
    expect(authorControlledSkip(policyFor(BLOCKING), `${DIFF_REFUSED_PREFIX}the GitHub API diff shows 2 files as binary`)).toBe(true);
    expect(authorControlledSkip(policyFor(BLOCKING), `diff larger than ${API_DIFF_LIMIT}`)).toBe(true);
  });
});

describe("xrepo publish: a skip replaces an earlier sticky (stale-sticky-after-skip)", () => {
  it("replaces an existing sticky with a run-status note; never creates one; idempotent", async () => {
    const old = { id: 9, body: `${STICKY}\n### Automated review\nOld findings` };
    const r = await run(setup({ draft: null }), ["--skip-reason", 'title contains "[skip review]"'], { gh: fakeGitHub({ sticky: old }) });
    const [[id, body]] = callsOf(r.gh, "updateIssueComment") as [[number, string]];
    expect(id).toBe(9);
    expect(body).toBe(
      `${STICKY}\nThe latest automated review run for commit ${HEAD.slice(0, 7)} was skipped (\`title contains "[skip review]"\`). ` +
        "An earlier review summary in this comment is outdated and no longer describes this pull request.",
    );
    expect(callsOf(r.gh, "createIssueComment")).toHaveLength(0);
    const again = await run(setup({ draft: null }), ["--skip-reason", 'title contains "[skip review]"'], { gh: fakeGitHub({ sticky: { id: 9, body } }) });
    expect(callsOf(again.gh, "updateIssueComment")).toHaveLength(0);
  });
});

describe("xrepo publish: the PR identity comes from the workflow, not the artifact (publisher-trusts-artifact-pr-identity)", () => {
  const APPROVING = BASE_POLICY.replace("labels: { enabled: true", "approve: { enabled: true, max_changed_lines: 10 }\n    labels: { enabled: true");
  const TRUSTED = ["--repo", "acme/web", "--pr-number", "42", "--head-sha", HEAD];

  it("a pr.json naming another pull request, repository or head publishes nothing and exits 1", async () => {
    for (const [ctx, what] of [
      [{ ...CTX, number: 43 }, "pull request #43, but this workflow runs for #42"],
      [{ ...CTX, repo: "acme/other" }, "repository acme/other, but this workflow runs for acme/web"],
      [{ ...CTX, head_sha: "c".repeat(40) }, "head commit cccccccccccc, but the event's head is aaaaaaaaaaaa"],
    ] as const) {
      const s = setup({ ctx, draft: [SUMMARY, verdict("approve"), FINISH] });
      const r = await run(s, [...TRUSTED, "--agent-outcome", "success", "--plan-out", s.planOut], { noFactory: true });
      expect(r.code, what).toBe(1);
      expect(r.factoryCalls).toBe(0);
      expect(r.fetch.calls).toHaveLength(0);
      expect(r.stderr).toContain(`refusing to publish anything: ctx/pr.json names ${what}`);
      expect(r.outputs).toEqual({});
    }
    // The same artifact with the matching identity publishes (repository names are case-insensitive).
    const ok = await run(setup({ draft: [SUMMARY, FINISH] }), ["--repo", "ACME/web", "--pr-number", "42", "--head-sha", HEAD.toUpperCase(), "--agent-outcome", "success"]);
    expect(ok.code).toBe(0);
    expect(ok.gh.opts).toMatchObject({ repo: "ACME/web", prNumber: 42, headSha: HEAD });
  });

  it("the run link never comes from pr.json: --run-url, else the workflow's run", async () => {
    const policy = `${BASE_POLICY}\n      notify: [{ target: hook }]\n`; // appended to outcomes.completed
    const ctx = { ...CTX, run_url: "https://evil.example/acme/web/actions/runs/1" };
    const env = { GITHUB_SERVER_URL: "https://github.com", GITHUB_REPOSITORY: "acme/web", GITHUB_RUN_ID: "77" };
    const r = await run(setup({ policy, ctx, draft: [SUMMARY, FINISH] }), [...TRUSTED, "--agent-outcome", "success"], { env });
    expect(r.fetch.calls[0]?.body).toMatchObject({ run_url: "https://github.com/acme/web/actions/runs/77" });
    const none = await run(setup({ policy, ctx, draft: [SUMMARY, FINISH] }), [...TRUSTED, "--agent-outcome", "success", "--run-url", "javascript:x"]);
    expect(none.fetch.calls[0]?.body).toMatchObject({ run_url: null });
  });

  it("validates the identity flags, and requires them in GitHub Actions", async () => {
    const s = setup({ draft: [SUMMARY, FINISH] });
    for (const bad of [
      ["--repo", "acme", "--pr-number", "42"],
      ["--repo", "acme/web", "--pr-number", "0"],
      ["--repo", "acme/web", "--pr-number", "42", "--head-sha", HEAD.slice(0, 7)],
      ["--pr-number", "42"],
    ]) {
      expect((await run(s, bad, { noFactory: true })).code, bad.join(" ")).toBe(2);
    }
    const actions = await run(s, ["--agent-outcome", "success"], { noFactory: true, env: { GITHUB_ACTIONS: "true" } });
    expect(actions.code).toBe(2);
    expect(actions.stderr).toContain("--repo and --pr-number are required in GitHub Actions");
  });

  it("pr.json's head_sha must be a full sha (never matched as a prefix)", () => {
    expect(PrContext.safeParse({ ...CTX, head_sha: HEAD.slice(0, 7) }).success).toBe(false);
    expect(PrContext.safeParse(CTX).success).toBe(true);
  });

  it("without pr.json the identity comes from the workflow (workflow_dispatch: no event PR)", async () => {
    const DISPATCH = ["--repo", "acme/web", "--pr-number", "42", "--agent-outcome", "failure"];
    // The head comes from GitHub; the client then reviews it, so freshness and the check apply.
    const withHead = (freshness: { current: boolean; newer_run?: number }): FakeGitHub => {
      const gh = fakeGitHub({ sticky: { id: 9, body: `${STICKY}\nnewer run's summary` } });
      gh.getPullRequest = async () => ({ head_sha: HEAD.toUpperCase(), state: "open", draft: false, merged: false });
      gh.dismissStaleApprovals = async (message: string) => {
        gh.calls.push({ method: "dismissStaleApprovals", args: [message] });
        return { dismissed: [5], failed: [] };
      };
      gh.runFreshness = async () => {
        expect(gh.opts?.headSha).toBe(HEAD);
        return { ...freshness, head_sha: HEAD, state: "open", ...(freshness.current ? {} : { reason: "workflow run 200 (newer than run 100) already published for this commit" }) };
      };
      return gh;
    };
    const fresh = await run(setup({ ctx: null, diff: null, draft: null }), DISPATCH, { gh: withHead({ current: true }) });
    expect(fresh.code).toBe(0);
    expect(fresh.gh.opts).toMatchObject({ repo: "acme/web", prNumber: 42, headSha: HEAD });
    expect(fresh.outputs.outcome).toBe("error");
    expect((callsOf(fresh.gh, "createCheckRun")[0]?.[0] as CheckRunInput).head_sha).toBe(HEAD);
    expect(callsOf(fresh.gh, "updateIssueComment")).toHaveLength(1);
    expect(callsOf(fresh.gh, "dismissStaleApprovals")).toHaveLength(1);
    // An older run re-run later never publishes over the newer run's sticky.
    const older = await run(setup({ ctx: null, diff: null, draft: null }), DISPATCH, { gh: withHead({ current: false, newer_run: 200 }), env: { GITHUB_RUN_ID: "100" } });
    expect(older.code).toBe(0);
    for (const m of ["createReview", "createIssueComment", "updateIssueComment", "dismissStaleApprovals"]) expect(callsOf(older.gh, m), m).toHaveLength(0);
    // GitHub cannot be read: nothing is published.
    const blind = fakeGitHub();
    blind.getPullRequest = async () => {
      throw new Error("503");
    };
    const r = await run(setup({ ctx: null, diff: null, draft: null }), DISPATCH, { gh: blind });
    expect(r.code).toBe(1);
    expect(r.stderr).toContain("the pull request's head could not be read from GitHub");
    expect(blind.calls).toEqual([]);
    expect(r.outputs).toEqual({});
  });

  it("the PR link comes from the workflow's identity, never from pr.json", async () => {
    const policy = `${BASE_POLICY}
    completed:
      notify: [{ target: chat, message: "Reviewed {pr_url}" }]
      dispatch: { event_type: "xrepo-done" }
`;
    for (const forged of ["https://github.com/acme/web/pull/43", "https://evil.example/acme/web/pull/42"]) {
      const s = setup({ policy: policy.replace("    completed:\n      remove_labels: [\"review-postponed\"]\n", ""), ctx: { ...CTX, html_url: forged }, draft: [SUMMARY, FINISH] });
      const r = await run(s, [...TRUSTED, "--agent-outcome", "success"], { env: { GITHUB_SERVER_URL: "https://github.com/" } });
      expect(r.code).toBe(0);
      const [[, , payload]] = callsOf(r.gh, "repositoryDispatch") as [[string, string, Record<string, unknown>]];
      expect(payload.pr_url).toBe("https://github.com/acme/web/pull/42");
      const slack = r.fetch.calls.find((c) => c.url.startsWith("https://hooks.slack.example"));
      expect(JSON.stringify(slack?.body)).toContain("Reviewed https://github.com/acme/web/pull/42");
      expect(JSON.stringify(slack?.body)).not.toContain(forged);
    }
  });

  it("without --head-sha, pr.json's head is used only once GitHub confirms it is the PR head", async () => {
    const DISPATCH = ["--repo", "acme/web", "--pr-number", "42", "--agent-outcome", "success"];
    // GitHub cannot be read: nothing is published.
    const blind = fakeGitHub();
    const r1 = await run(setup({ draft: [SUMMARY, FINISH] }), DISPATCH, { gh: blind });
    expect(r1.code).toBe(1);
    expect(r1.stderr).toContain("could not be confirmed as the pull request's head");
    expect(blind.calls.filter((c) => c.method !== "listReviewCommentKeys")).toEqual([]);
    // pr.json names a commit that is not the PR head (e.g. another PR's head): stale, and no check on it.
    const moved = fakeGitHub();
    moved.runFreshness = async () => ({ current: false, head_sha: "c".repeat(40), state: "open", reason: "moved" });
    const r2 = await run(setup({ draft: [SUMMARY, FINISH] }), DISPATCH, { gh: moved });
    expect(r2.code).toBe(0);
    for (const m of ["createReview", "createCheckRun", "createIssueComment", "updateIssueComment"]) expect(callsOf(moved, m), m).toHaveLength(0);
    // Confirmed: published as usual.
    const confirmed = fakeGitHub();
    confirmed.runFreshness = async () => ({ current: true, head_sha: HEAD, state: "open" });
    const r3 = await run(setup({ draft: [SUMMARY, FINISH] }), DISPATCH, { gh: confirmed });
    expect(r3.code).toBe(0);
    expect(callsOf(confirmed, "createCheckRun")).toHaveLength(1);
  });

  it("approves only when the approve gates also hold on GitHub's own file list", async () => {
    // The artifact's diff is tiny and harmless; GitHub lists a workflow change and 500 lines.
    const gh = fakeGitHub();
    gh.files = [
      { path: "src/orders.ts", additions: 2, deletions: 0 },
      { path: ".github/workflows/deploy.yml", previous_path: "ci/deploy.yml", additions: 400, deletions: 100 },
    ];
    const s = setup({ policy: APPROVING, draft: [SUMMARY, verdict("approve"), FINISH] });
    const r = await run(s, [...TRUSTED, "--agent-outcome", "success", "--plan-out", s.planOut], { gh });
    expect(r.code).toBe(0);
    const [[review, opts]] = callsOf(gh, "createReview") as [[PlanReview, CreateReviewOptions]];
    expect(review.event).toBe("APPROVE");
    expect(opts.withholdApproval).toContain("on GitHub's file list:");
    expect(opts.withholdApproval).toContain(".github/workflows/deploy.yml");
    expect(opts.withholdApproval).toContain("502 changed lines exceed approve.max_changed_lines (10)");
    expect(r.outputs).toMatchObject({ verdict: "comment", fired_outcomes: "completed" });
    expect((callsOf(gh, "createCheckRun")[0]?.[0] as CheckRunInput).title).toContain("Approval withheld");
    // A rename out of a never_paths directory counts too.
    const renamed = fakeGitHub();
    renamed.files = [{ path: "ci/deploy.yml", previous_path: ".github/workflows/deploy.yml", additions: 1, deletions: 0 }];
    await run(setup({ policy: APPROVING, draft: [SUMMARY, verdict("approve"), FINISH] }), TRUSTED, { gh: renamed });
    expect(String((callsOf(renamed, "createReview")[0] as [PlanReview, CreateReviewOptions])[1]?.withholdApproval)).toContain(".github/workflows/deploy.yml");
    // An unreadable file list withholds it (fail closed); a matching one approves.
    const blind = fakeGitHub({ fail: ["listPullRequestFiles"] });
    const r2 = await run(setup({ policy: APPROVING, draft: [SUMMARY, verdict("approve"), FINISH] }), TRUSTED, { gh: blind });
    expect(r2.outputs.fired_outcomes).toBe("completed");
    const fine = await run(setup({ policy: APPROVING, draft: [SUMMARY, verdict("approve"), FINISH] }), TRUSTED);
    expect(callsOf(fine.gh, "createReview")[0]).toHaveLength(1);
    expect(fine.outputs.fired_outcomes).toBe("completed,approved");
  });
});

describe("xrepo publish: stale runs never post a review (stale-run-posts-review)", () => {
  it("a push after the freshness read: createReview posts nothing and the run is stale", async () => {
    const BLOCKING = BASE_POLICY.replace("labels: { enabled: true", "block: { enabled: true, method: review, min_severity: high }\n    labels: { enabled: true");
    const s = setup({ policy: BLOCKING, draft: [HIGH, SUMMARY, verdict("request_changes"), FINISH] });
    const gh = fakeGitHub({ sticky: { id: 9, body: `${STICKY}\nold` } });
    gh.runFreshness = async () => ({ current: true, head_sha: HEAD, state: "open" });
    gh.createReview = async (r: PlanReview) => {
      gh.calls.push({ method: "createReview", args: [r] });
      throw new StaleHeadError("the pull request head moved to ccccccc after commit aaaaaaa was reviewed", "c".repeat(40));
    };
    gh.dismissStaleChangeRequests = async () => {
      gh.calls.push({ method: "dismissStaleChangeRequests", args: [] });
      return { dismissed: [], failed: [] };
    };
    const r = await run(s, ["--agent-outcome", "success", "--plan-out", s.planOut], { gh });
    expect(r.code).toBe(0);
    for (const m of ["dismissStaleChangeRequests", "updateIssueComment", "createIssueComment", "addLabels", "removeLabel"]) expect(callsOf(gh, m), m).toHaveLength(0);
    expect(r.fetch.calls).toHaveLength(0);
    const rep = JSON.parse(readFileSync(s.planOut, "utf8")) as PublishReport;
    expect(rep.stale).toEqual({ reason: "the pull request head moved to ccccccc after commit aaaaaaa was reviewed", head_sha: "c".repeat(40) });
    expect(rep.errors).toEqual([]);
    expect(r.outputs.fired_outcomes).toBe("completed");
  });
});

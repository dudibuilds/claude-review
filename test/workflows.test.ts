/**
 * Regression tests for the reusable workflow (.github/workflows/review.yml), the examples and the
 * docs that describe them.
 *
 * The publish job is simulated the way GitHub runs it: a small evaluator resolves the `${{ }}`
 * expressions of review.yml with the contexts of each job and run attempt, a fake artifact store
 * plays upload / download-artifact, and the real "Publish" step script runs under bash with the real
 * `xrepo` CLI (src/cli.ts through tsx) against a fake GitHub API on 127.0.0.1.
 */
import { spawn } from "node:child_process";
import { cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync, chmodSync, symlinkSync } from "node:fs";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { parse as parseYaml } from "yaml";

// Each publish run spawns bash and the real CLI (about a second).
vi.setConfig({ testTimeout: 90_000 });

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const TSX_LOADER = pathToFileURL(join(ROOT, "node_modules", "tsx", "dist", "loader.mjs")).href;
const scratch = mkdtempSync(join(tmpdir(), "xrepo-workflows-"));
afterAll(() => rmSync(scratch, { recursive: true, force: true }));
let seq = 0;
const tmp = (): string => {
  const d = join(scratch, `t${++seq}`);
  mkdirSync(d, { recursive: true });
  return d;
};

/* ------------------------- GitHub expression evaluator ------------------------- */
// Enough of https://docs.github.com/actions/learn-github-actions/expressions for review.yml:
// literals, context paths (hyphens allowed), ! == != && || (value-returning), parentheses,
// format() / contains() / always() / cancelled(), loose equality with case-insensitive strings.

type Ctx = Record<string, unknown>;

function tokenize(src: string): string[] {
  const re = /\s*('(?:[^']|'')*'|&&|\|\||==|!=|[!(),]|[A-Za-z_][A-Za-z0-9_-]*(?:\.[A-Za-z_*][A-Za-z0-9_-]*)*|\d+)/y;
  const out: string[] = [];
  let i = 0;
  while (i < src.length) {
    if (/^\s*$/.test(src.slice(i))) break;
    re.lastIndex = i;
    const m = re.exec(src);
    if (!m) throw new Error(`cannot tokenize expression at ${JSON.stringify(src.slice(i))}`);
    out.push(m[1]!);
    i = re.lastIndex;
  }
  return out;
}

const truthy = (v: unknown): boolean => !(v === null || v === undefined || v === false || v === 0 || v === "" || Number.isNaN(v));

function toNum(v: unknown): number {
  if (v === null || v === undefined) return 0;
  if (typeof v === "boolean") return v ? 1 : 0;
  if (typeof v === "number") return v;
  if (typeof v === "string") return v.trim() === "" ? 0 : Number(v);
  return Number.NaN;
}

function looseEq(a: unknown, b: unknown): boolean {
  if (typeof a === "string" && typeof b === "string") return a.toLowerCase() === b.toLowerCase();
  if (typeof a === typeof b && typeof a === "object" && a !== null) return a === b;
  return toNum(a) === toNum(b);
}

function evaluate(expr: string, ctx: Ctx): unknown {
  const t = tokenize(expr);
  let p = 0;
  const peek = (): string | undefined => t[p];
  const take = (want?: string): string => {
    const tok = t[p++];
    if (tok === undefined || (want !== undefined && tok !== want)) throw new Error(`expected ${want ?? "a token"} in ${JSON.stringify(expr)}`);
    return tok;
  };
  const lookup = (path: string): unknown => {
    let cur: unknown = ctx;
    for (const seg of path.split(".")) {
      if (cur === null || typeof cur !== "object") return null;
      cur = Object.prototype.hasOwnProperty.call(cur, seg) ? (cur as Record<string, unknown>)[seg] : null;
    }
    return cur ?? null;
  };
  const primary = (): unknown => {
    const tok = take();
    if (tok === "(") {
      const v = or();
      take(")");
      return v;
    }
    if (tok.startsWith("'")) return tok.slice(1, -1).replace(/''/g, "'");
    if (/^\d+$/.test(tok)) return Number(tok);
    if (tok === "true") return true;
    if (tok === "false") return false;
    if (tok === "null") return null;
    if (peek() === "(") {
      take("(");
      const args: unknown[] = [];
      while (peek() !== ")") {
        args.push(or());
        if (peek() === ",") take(",");
      }
      take(")");
      const s = (v: unknown): string => (v === null || v === undefined ? "" : String(v));
      switch (tok) {
        case "format":
          return s(args[0]).replace(/\{(\d+)\}/g, (_, n: string) => s(args[Number(n) + 1]));
        case "contains":
          return s(args[0]).toLowerCase().includes(s(args[1]).toLowerCase());
        case "cancelled":
          return false;
        case "always":
          return true;
        default:
          throw new Error(`unsupported function ${tok}`);
      }
    }
    return lookup(tok);
  };
  const unary = (): unknown => {
    if (peek() === "!") {
      take("!");
      return !truthy(unary());
    }
    return primary();
  };
  const eq = (): unknown => {
    let v = unary();
    while (peek() === "==" || peek() === "!=") {
      const op = take();
      const r = unary();
      v = op === "==" ? looseEq(v, r) : !looseEq(v, r);
    }
    return v;
  };
  const and = (): unknown => {
    let v = eq();
    while (peek() === "&&") {
      take("&&");
      const r = eq();
      v = truthy(v) ? r : v;
    }
    return v;
  };
  const or = (): unknown => {
    let v = and();
    while (peek() === "||") {
      take("||");
      const r = and();
      v = truthy(v) ? v : r;
    }
    return v;
  };
  const v = or();
  if (p !== t.length) throw new Error(`trailing tokens in ${JSON.stringify(expr)}`);
  return v;
}

const asString = (v: unknown): string => (v === null || v === undefined ? "" : typeof v === "object" ? JSON.stringify(v) : String(v));
const interpolate = (s: string, ctx: Ctx): string => s.replace(/\$\{\{([\s\S]*?)\}\}/g, (_, e: string) => asString(evaluate(e, ctx)));
const condition = (s: string | undefined, ctx: Ctx): boolean => {
  if (s === undefined) return true;
  const m = /^\s*\$\{\{([\s\S]*)\}\}\s*$/.exec(s);
  return truthy(evaluate(m ? m[1]! : s, ctx));
};

/* ----------------------------- the workflow under test ----------------------------- */

interface Step {
  id?: string;
  name?: string;
  if?: string;
  uses?: string;
  run?: string;
  env?: Record<string, string>;
  with?: Record<string, string>;
  "continue-on-error"?: boolean;
}
interface Job {
  permissions: Record<string, string>;
  if?: string;
  outputs: Record<string, string>;
  steps: Step[];
}
const WF = parseYaml(readFileSync(join(ROOT, ".github", "workflows", "review.yml"), "utf8")) as { jobs: { review: Job; publish: Job } };
const REVIEW = WF.jobs.review;
const PUBLISH = WF.jobs.publish;
const stepOf = (job: Job, pred: (s: Step) => boolean, what: string): Step => {
  const s = job.steps.find(pred);
  if (!s) throw new Error(`review.yml: no ${what} step`);
  return s;
};
const UPLOAD = stepOf(REVIEW, (s) => s.uses?.startsWith("actions/upload-artifact@") === true, "upload-artifact");
const DOWNLOAD = stepOf(PUBLISH, (s) => s.uses?.startsWith("actions/download-artifact@") === true, "download-artifact");
const PUBLISH_STEP = stepOf(PUBLISH, (s) => s.id === "publish", "Publish");

/* --------------------------------- fake GitHub API --------------------------------- */

interface Req {
  method: string;
  path: string;
  body: Record<string, unknown> | null;
}

class FakeGitHub {
  requests: Req[] = [];
  comments: { id: number; body: string; user: { login: string } }[] = [];
  /** "read" = a contents:read / fork token: every write answers 403. */
  mode: "write" | "read" = "write";
  private server: Server = createServer((req, res) => {
    let raw = "";
    req.on("data", (c: Buffer) => (raw += c.toString("utf8")));
    req.on("end", () => {
      const path = (req.url ?? "").split("?")[0]!;
      const method = req.method ?? "GET";
      let body: Record<string, unknown> | null = null;
      try {
        body = raw ? (JSON.parse(raw) as Record<string, unknown>) : null;
      } catch {
        body = null;
      }
      this.requests.push({ method, path, body });
      const send = (status: number, data: unknown): void => {
        res.writeHead(status, { "content-type": "application/json" });
        res.end(JSON.stringify(data));
      };
      if (path === "/user" || path === "/app") return send(403, { message: "Resource not accessible by integration" });
      if (method === "GET") {
        if (/\/pulls\/\d+$/.test(path)) return send(200, { state: "open", head: { sha: HEAD } });
        if (/\/issues\/\d+\/comments$/.test(path)) return send(200, this.comments);
        return send(200, []);
      }
      if (this.mode === "read") return send(403, { message: "Resource not accessible by integration" });
      if (method === "POST" && /\/issues\/\d+\/comments$/.test(path)) {
        const c = { id: 1000 + this.comments.length, body: String(body?.body ?? ""), user: { login: "github-actions[bot]" } };
        this.comments.push(c);
        return send(201, c);
      }
      const upd = /\/issues\/comments\/(\d+)$/.exec(path);
      if (method === "PATCH" && upd) {
        const c = this.comments.find((x) => x.id === Number(upd[1]));
        if (c) c.body = String(body?.body ?? "");
        return send(200, c ?? {});
      }
      return send(method === "POST" ? 201 : 200, { id: 7, number: 1 });
    });
  });
  url = "";
  async start(): Promise<void> {
    await new Promise<void>((r) => this.server.listen(0, "127.0.0.1", () => r()));
    this.url = `http://127.0.0.1:${(this.server.address() as AddressInfo).port}`;
  }
  async stop(): Promise<void> {
    await new Promise<void>((r) => this.server.close(() => r()));
  }
  reset(mode: "write" | "read" = "write"): void {
    this.requests = [];
    this.comments = [];
    this.mode = mode;
  }
  writes(): Req[] {
    return this.requests.filter((r) => r.method !== "GET");
  }
  checks(): string[] {
    return this.requests.filter((r) => r.method === "POST" && r.path.endsWith("/check-runs")).map((r) => String(r.body?.conclusion));
  }
}

const gh = new FakeGitHub();
beforeAll(() => gh.start());
afterAll(() => gh.stop());

/* ------------------------------------ fixtures ------------------------------------ */

const HEAD = "2".repeat(40);
const BASE = "1".repeat(40);

function prEvent(repo: string, headRepo: string | null, number = 42): Record<string, unknown> {
  return {
    action: "synchronize",
    number,
    pull_request: {
      number,
      title: "web: simplify checkout",
      body: "",
      draft: false,
      html_url: `https://github.com/${repo}/pull/${number}`,
      user: { login: "alice", type: "User" },
      base: { sha: BASE, ref: "main", repo: { full_name: repo } },
      head: { sha: HEAD, ref: "feat", repo: headRepo === null ? null : { full_name: headRepo } },
    },
    repository: { full_name: repo },
  };
}

function prContext(repo: string, fork: boolean, files: { path: string; status: "modified"; additions: number; deletions: number }[]): Record<string, unknown> {
  return {
    repo,
    number: 42,
    title: "web: simplify checkout",
    body: "",
    author: "alice",
    author_type: "User",
    base_sha: BASE,
    head_sha: HEAD,
    base_ref: "main",
    head_ref: "feat",
    draft: false,
    fork,
    html_url: `https://github.com/${repo}/pull/42`,
    files,
    changed_lines: files.reduce((n, f) => n + f.additions + f.deletions, 0),
    ignored_files: [],
  };
}

const DIFF = [
  "diff --git a/src/checkout.ts b/src/checkout.ts",
  "index 1111111..2222222 100644",
  "--- a/src/checkout.ts",
  "+++ b/src/checkout.ts",
  "@@ -1,3 +1,3 @@",
  " import { createOrder } from '@acme/api';",
  "-createOrder(cart.customerId, cart.items, { currency: cart.currency });",
  "+createOrder(cart.customerId, cart.items);",
  " export {};",
  "",
].join("\n");

const DRAFT_BLOCKING = [
  { type: "comment", path: "src/checkout.ts", line: 2, body: "createOrder now requires opts.currency (see /repos/acme/api/src/orders.ts).", severity: "high" },
  { type: "summary", body: "The checkout no longer passes the currency." },
  { type: "verdict", verdict: "request_changes", reason: "breaks the orders contract" },
  { type: "finish" },
]
  .map((e) => JSON.stringify(e))
  .join("\n");

/** Files the review job uploads (paths relative to $WORK, as upload-artifact stores them). */
function reviewArtifact(opts: { repo: string; fork?: boolean; skipped?: boolean }): Record<string, string> {
  const files = opts.skipped ? [] : [{ path: "src/checkout.ts", status: "modified" as const, additions: 1, deletions: 1 }];
  return {
    "ctx/pr.json": JSON.stringify(prContext(opts.repo, opts.fork ?? false, files)),
    // Must be ignored by the publish job (it re-resolves the trusted manifest).
    "ctx/policy.resolved.json": JSON.stringify({ repo: opts.repo, tampered: true }),
    ...(opts.skipped ? {} : { "ctx/diff.patch": DIFF }),
    "out/draft.jsonl": opts.skipped ? "" : `${DRAFT_BLOCKING}\n`,
    "agent-outcome.txt": opts.skipped ? "skipped\n" : "success\n",
  };
}

/* ------------------------------- simulated jobs ------------------------------- */

/** Artifacts of one workflow run (all attempts), by name, like the artifact service. */
type ArtifactStore = Map<string, Record<string, string>>;

interface ReviewRun {
  outputs: Record<string, string>;
  result: "success" | "failure";
}

/** One attempt of the review job: evaluates its outputs and stores the uploaded artifact. */
function runReviewJob(
  store: ArtifactStore,
  o: { attempt: number; files?: Record<string, string>; skip?: boolean; skipReason?: string; claude?: string; result?: "success" | "failure" },
): ReviewRun {
  const ctx: Ctx = {
    github: { run_attempt: o.attempt },
    steps: {
      prepare: { outputs: o.files ? { skip: String(o.skip ?? false), skip_reason: o.skipReason ?? "" } : {}, outcome: o.files ? "success" : "failure" },
      claude: { outcome: o.files ? (o.skip ? "skipped" : (o.claude ?? "success")) : "skipped", outputs: {} },
      upload: { outputs: {} as Record<string, string>, outcome: "skipped" },
    },
  };
  if (o.files && condition(UPLOAD.if, { ...ctx, steps: { prepare: { outcome: "success" } } })) {
    const name = interpolate(UPLOAD.with!.name!, ctx);
    expect(store.has(name), `artifact ${name} already exists in this run (upload-artifact would 409)`).toBe(false);
    store.set(name, o.files);
    (ctx.steps as { upload: { outputs: Record<string, string>; outcome: string } }).upload = { outputs: { "artifact-id": String(4000 + store.size) }, outcome: "success" };
  }
  const outputs = Object.fromEntries(Object.entries(REVIEW.outputs).map(([k, v]) => [k, interpolate(v, ctx)]));
  return { outputs, result: o.result ?? (o.files ? "success" : "failure") };
}

interface PublishRun {
  code: number;
  stdout: string;
  stderr: string;
  outputs: string;
  downloaded: string | null;
  env: Record<string, string>;
}

/**
 * Run a script the way GitHub runs `run:` (`bash --noprofile --norc -eo pipefail {0}`). Async: the
 * fake GitHub API lives in this process and must keep answering while the script runs.
 */
function runBash(script: string, cwd: string, env: Record<string, string>): Promise<{ code: number; stdout: string; stderr: string }> {
  return new Promise((resolve, reject) => {
    const child = spawn("bash", ["--noprofile", "--norc", "-eo", "pipefail", script], { cwd, env, stdio: ["ignore", "pipe", "pipe"] });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (c: Buffer) => (stdout += c.toString("utf8")));
    child.stderr.on("data", (c: Buffer) => (stderr += c.toString("utf8")));
    const timer = setTimeout(() => child.kill("SIGKILL"), 60_000);
    child.on("error", (e) => {
      clearTimeout(timer);
      reject(e);
    });
    child.on("close", (code) => {
      clearTimeout(timer);
      resolve({ code: code ?? -1, stdout, stderr });
    });
  });
}

/** One attempt of the publish job: download-artifact as configured, then the real Publish step. */
async function runPublishJob(
  store: ArtifactStore,
  review: ReviewRun,
  o: {
    attempt: number;
    repo: string;
    event: Record<string, unknown>;
    policy: string;
    dispatchToken?: string;
    xrepo?: "real" | { publishRc: number; dryRunRc: number };
  },
): Promise<PublishRun> {
  const t = tmp();
  const runnerTemp = join(t, "runner-temp");
  const workspace = join(t, "workspace");
  const bin = join(t, "bin");
  for (const d of [runnerTemp, workspace, bin]) mkdirSync(d, { recursive: true });
  const eventPath = join(t, "event.json");
  writeFileSync(eventPath, JSON.stringify(o.event));
  const ctx: Ctx = {
    github: {
      run_attempt: o.attempt,
      run_id: 777,
      repository: o.repo,
      server_url: "https://github.com",
      token: "ghs_publish_job_token",
      event: o.event,
    },
    needs: { review: { outputs: review.outputs, result: review.result } },
    inputs: { mode: "self-hosted", policy_path: o.policy, policy_file: ".github/xrepo/policy.yaml" },
    secrets: { XREPO_NOTIFY_SECRETS: "", XREPO_DISPATCH_TOKEN: o.dispatchToken ?? "" },
    runner: { temp: runnerTemp },
  };
  expect(condition(PUBLISH.if, ctx)).toBe(true);

  // actions/download-artifact (continue-on-error: a missing name only fails that step).
  let downloaded: string | null = null;
  if (condition(DOWNLOAD.if, ctx)) {
    const name = interpolate(DOWNLOAD.with!.name!, ctx);
    expect(name, "an empty name would download every artifact of the run").not.toBe("");
    const files = store.get(name);
    if (files) {
      downloaded = name;
      const dest = interpolate(DOWNLOAD.with!.path!, ctx);
      for (const [rel, text] of Object.entries(files)) {
        mkdirSync(dirname(join(dest, rel)), { recursive: true });
        writeFileSync(join(dest, rel), text);
      }
    } else {
      expect(DOWNLOAD["continue-on-error"]).toBe(true);
    }
  }

  const stepEnv = Object.fromEntries(Object.entries(PUBLISH_STEP.env ?? {}).map(([k, v]) => [k, interpolate(v, ctx)]));
  const log = join(t, "xrepo-calls.log");
  const xrepo = o.xrepo ?? "real";
  writeFileSync(
    join(bin, "xrepo"),
    xrepo === "real"
      ? `#!/bin/sh\nprintf '%s\\n' "$*" >> '${log}'\nexec '${process.execPath}' --import '${TSX_LOADER}' '${join(ROOT, "src", "cli.ts")}' "$@"\n`
      : [
          "#!/bin/sh",
          `printf '%s\\n' "$*" >> '${log}'`,
          `case "$1" in policy) exec '${process.execPath}' --import '${TSX_LOADER}' '${join(ROOT, "src", "cli.ts")}' "$@";; esac`,
          `for a in "$@"; do [ "$a" = --dry-run ] && exit ${xrepo.dryRunRc}; done`,
          `exit ${xrepo.publishRc}`,
          "",
        ].join("\n"),
  );
  chmodSync(join(bin, "xrepo"), 0o755);
  const script = join(t, "publish-step.sh");
  writeFileSync(script, PUBLISH_STEP.run!);
  const outputFile = join(t, "github-output");
  writeFileSync(outputFile, "");
  const env: Record<string, string> = {
    PATH: `${bin}:${process.env.PATH ?? "/usr/bin:/bin"}`,
    HOME: t,
    RUNNER_TEMP: runnerTemp,
    GITHUB_WORKSPACE: workspace,
    GITHUB_REPOSITORY: o.repo,
    GITHUB_RUN_ATTEMPT: String(o.attempt),
    GITHUB_RUN_ID: "777",
    GITHUB_SERVER_URL: "https://github.com",
    GITHUB_OUTPUT: outputFile,
    GITHUB_EVENT_PATH: eventPath,
    GITHUB_EVENT_NAME: "pull_request",
    GITHUB_API_URL: gh.url,
    NO_PROXY: "127.0.0.1,localhost",
    no_proxy: "127.0.0.1,localhost",
    ...stepEnv,
  };
  const r = await runBash(script, workspace, env);
  return {
    code: r.code,
    stdout: r.stdout,
    stderr: r.stderr,
    outputs: readFileSync(outputFile, "utf8"),
    downloaded,
    env: { ...stepEnv, XREPO_CALLS: existsSync(log) ? readFileSync(log, "utf8") : "" },
  };
}

const outputValue = (outputs: string, key: string): string | undefined => {
  // writeGithubOutputs uses heredoc syntax: key<<DELIM\nvalue\nDELIM
  const m = new RegExp(`^${key}<<(\\S+)\\n([\\s\\S]*?)\\n\\1$`, "m").exec(outputs);
  return m ? m[2] : undefined;
};

/* -------------------------------- the evaluator -------------------------------- */

describe("expression evaluator (test helper)", () => {
  it("follows GitHub's semantics for the operators review.yml uses", async () => {
    const ctx = { a: { b: "X", e: "" }, n: null, steps: { u: { outputs: { "artifact-id": "12" } } }, github: { run_attempt: 3 } };
    expect(evaluate("a.b == 'x'", ctx)).toBe(true);
    expect(evaluate("a.missing != ''", ctx)).toBe(false);
    expect(evaluate("n && 'y'", ctx)).toBe(null);
    expect(evaluate("a.e || 'fallback'", ctx)).toBe("fallback");
    expect(evaluate("steps.u.outputs.artifact-id && format('n-{0}', github.run_attempt) || ''", ctx)).toBe("n-3");
    expect(evaluate("!cancelled()", ctx)).toBe(true);
    expect(interpolate("x-${{ github.run_attempt }}", ctx)).toBe("x-3");
  });
});

/* ------------------------ re-running only the publish job ------------------------ */

describe("review.yml: re-running only the publish job (defect: artifact named after the publish job's run_attempt)", () => {
  it("the publish job downloads the artifact the review job reports, never one named after its own run_attempt", async () => {
    expect(UPLOAD.id).toBe("upload");
    expect(REVIEW.outputs.artifact).toContain("steps.upload.outputs.artifact-id");
    expect(REVIEW.outputs.artifact).toContain("github.run_attempt");
    expect(DOWNLOAD.with?.name).toBe("${{ needs.review.outputs.artifact }}");
    expect(DOWNLOAD.if).toContain("needs.review.outputs.artifact != ''");
    // Nothing in the publish job may derive the artifact from its own attempt number.
    const { steps } = PUBLISH;
    for (const s of steps) expect(JSON.stringify({ ...s, run: undefined }), s.name).not.toContain("github.run_attempt");
  });

  it("attempt 1 publishes the block; re-running publish (attempts 2, 3) republishes it instead of an 'error' / neutral check", async () => {
    gh.reset();
    const store: ArtifactStore = new Map();
    const review = runReviewJob(store, { attempt: 1, files: reviewArtifact({ repo: "acme/web" }) });
    expect(review.outputs.artifact).toBe("xrepo-review-1");
    const base = { repo: "acme/web", event: prEvent("acme/web", "acme/web"), policy: join(ROOT, "e2e", "policy.yaml") };

    const first = await runPublishJob(store, review, { ...base, attempt: 1 });
    expect(first.downloaded).toBe("xrepo-review-1");
    expect(first.code, first.stderr).toBe(0);
    expect(gh.checks()).toEqual(["failure"]);
    const sticky = gh.comments[0]?.body ?? "";
    expect(sticky).toContain("The checkout no longer passes the currency.");

    // "Re-run this job" / "Re-run failed jobs" on publish: new run_attempt, the review job's outputs
    // (and artifact) are those of attempt 1.
    for (const attempt of [2, 3]) {
      const rerun = await runPublishJob(store, review, { ...base, attempt });
      expect(rerun.downloaded, `attempt ${attempt}`).toBe("xrepo-review-1");
      expect(rerun.code, rerun.stderr).toBe(0);
      expect(outputValue(rerun.outputs, "outcome")).toBe("completed");
      expect(rerun.stderr).not.toContain("failed before the agent ran");
    }
    expect(gh.checks()).toEqual(["failure", "failure", "failure"]);
    expect(gh.comments).toHaveLength(1);
    expect(gh.comments[0]!.body).toBe(sticky);
    expect(gh.comments[0]!.body).not.toContain("could not run");
  });

  it("a full re-run (all jobs, the retry sweeper) reviews again under the new attempt's artifact", async () => {
    gh.reset();
    const store: ArtifactStore = new Map();
    runReviewJob(store, { attempt: 1, files: reviewArtifact({ repo: "acme/web" }) });
    const review2 = runReviewJob(store, { attempt: 2, files: reviewArtifact({ repo: "acme/web" }) });
    expect(review2.outputs.artifact).toBe("xrepo-review-2");
    const run = await runPublishJob(store, review2, { attempt: 2, repo: "acme/web", event: prEvent("acme/web", "acme/web"), policy: join(ROOT, "e2e", "policy.yaml") });
    expect(run.downloaded).toBe("xrepo-review-2");
    expect(run.code, run.stderr).toBe(0);
    expect(gh.checks()).toEqual(["failure"]);
  });

  it("fails closed when the uploaded context cannot be downloaded: no comment, no check, non-zero exit", async () => {
    gh.reset();
    const store: ArtifactStore = new Map();
    const review = runReviewJob(store, { attempt: 1, files: reviewArtifact({ repo: "acme/web" }) });
    const base = { repo: "acme/web", event: prEvent("acme/web", "acme/web"), policy: join(ROOT, "e2e", "policy.yaml") };
    expect((await runPublishJob(store, review, { ...base, attempt: 1 })).code).toBe(0);
    expect(gh.checks()).toEqual(["failure"]);
    const before = gh.comments[0]!.body;

    store.clear(); // retention expired (3 days) or not visible to this attempt
    gh.requests = [];
    const rerun = await runPublishJob(store, review, { ...base, attempt: 2 });
    expect(rerun.downloaded).toBeNull();
    expect(rerun.code).toBe(1);
    expect(rerun.stdout).toMatch(/::error::The review job uploaded its context \(artifact xrepo-review-1, result success\)/);
    expect(gh.requests).toEqual([]);
    expect(rerun.env.XREPO_CALLS).toBe("");
    expect(rerun.outputs).toBe("");
    expect(gh.comments[0]!.body).toBe(before);

    // Belt and braces: a successful review job always uploaded a context, even without the output.
    const noName = await runPublishJob(store, { outputs: { ...review.outputs, artifact: "" }, result: "success" }, { ...base, attempt: 2 });
    expect(noName.code).toBe(1);
    expect(gh.requests).toEqual([]);
  });

  it("still reports 'error' (neutral check, error comment) when the review job really failed before uploading", async () => {
    gh.reset();
    const store: ArtifactStore = new Map();
    const review = runReviewJob(store, { attempt: 1 }); // prepare failed: no artifact
    expect(review.outputs.artifact).toBe("");
    const run = await runPublishJob(store, review, { attempt: 1, repo: "acme/web", event: prEvent("acme/web", "acme/web"), policy: join(ROOT, "e2e", "policy.yaml") });
    expect(run.downloaded).toBeNull();
    expect(run.code, run.stderr).toBe(0);
    expect(outputValue(run.outputs, "outcome")).toBe("error");
    expect(gh.checks()).toEqual(["neutral"]);
    expect(gh.comments[0]?.body).toContain("could not run");
  });
});

/* ------------------------------ pull requests from forks ------------------------------ */

const FORK_FAIL_JOB_POLICY = `version: 1
defaults:
  capabilities:
    check: { enabled: true, name: xrepo-review }
  outcomes:
    skipped: { check_conclusion: skipped, fail_job: true }
`;

describe("review.yml: skipped pull requests from forks (defect: read-only token turns the publish job red)", () => {
  const forkEvent = prEvent("acme/web", "mallory/web");
  const skippedFork = (store: ArtifactStore): ReviewRun =>
    runReviewJob(store, { attempt: 1, files: reviewArtifact({ repo: "acme/web", fork: true, skipped: true }), skip: true, skipReason: "pull request from a fork" });

  it("FORK_PR is true only for pull requests whose head is another (or a deleted) repository", async () => {
    const expr = PUBLISH_STEP.env!.FORK_PR!;
    const fork = (event: Record<string, unknown>): string => interpolate(expr, { github: { repository: "acme/web", event } });
    expect(fork(forkEvent)).toBe("true");
    expect(fork(prEvent("acme/web", null))).toBe("true");
    expect(fork(prEvent("acme/web", "acme/web"))).toBe("false");
    expect(fork(prEvent("acme/web", "ACME/Web"))).toBe("false");
    expect(fork({ inputs: { pr_number: "42" } })).toBe(""); // workflow_dispatch
  });

  it("a skipped fork PR ends green although every write is refused (real publisher, read-only API)", async () => {
    gh.reset("read");
    const store: ArtifactStore = new Map();
    const run = await runPublishJob(store, skippedFork(store), { attempt: 1, repo: "acme/web", event: forkEvent, policy: join(ROOT, "examples", "policy.yaml") });
    expect(run.env.FORK_PR).toBe("true");
    expect(run.code, run.stderr).toBe(0);
    expect(run.stdout).toContain("::warning::The skipped check / comment could not be written");
    // The writes were attempted (they work where forks get write tokens) and refused here: the
    // skipped check, and the removal of the retry label (every run that requests no retry removes it).
    expect(gh.writes().map((r) => `${r.method} ${r.path}`)).toEqual([
      "POST /repos/acme/web/check-runs",
      "DELETE /repos/acme/web/issues/42/labels/xrepo-review%3Aretry",
    ]);
    expect(outputValue(run.outputs, "outcome")).toBe("skipped");
    expect(outputValue(run.outputs, "reason")).toBe("pull request from a fork");
    expect((run.env.XREPO_CALLS ?? "").trim().split("\n").at(-1)).toMatch(/^publish .* --dry-run$/);
  });

  it("a skipped fork PR still fails when the policy says fail_job for skipped", async () => {
    gh.reset("read");
    const policy = join(tmp(), "policy.yaml");
    writeFileSync(policy, FORK_FAIL_JOB_POLICY);
    const store: ArtifactStore = new Map();
    const run = await runPublishJob(store, skippedFork(store), { attempt: 1, repo: "acme/web", event: forkEvent, policy });
    expect(run.code).toBe(1);
  });

  it("write failures stay failures for same-repository PRs and for fork PRs that were reviewed", async () => {
    gh.reset("read");
    const store: ArtifactStore = new Map();
    const sameRepo = runReviewJob(store, { attempt: 1, files: reviewArtifact({ repo: "acme/web", skipped: true }), skip: true, skipReason: "draft pull request" });
    const run = await runPublishJob(store, sameRepo, { attempt: 1, repo: "acme/web", event: prEvent("acme/web", "acme/web"), policy: join(ROOT, "examples", "policy.yaml") });
    expect(run.env.FORK_PR).toBe("false");
    expect(run.code).toBe(1);
    expect(run.env.XREPO_CALLS).not.toContain("--dry-run");

    const store2: ArtifactStore = new Map();
    const reviewed = runReviewJob(store2, { attempt: 1, files: reviewArtifact({ repo: "acme/web", fork: true }) });
    const run2 = await runPublishJob(store2, reviewed, { attempt: 1, repo: "acme/web", event: forkEvent, policy: join(ROOT, "e2e", "policy.yaml"), xrepo: { publishRc: 1, dryRunRc: 0 } });
    expect(run2.code).toBe(1);
    expect(run2.env.XREPO_CALLS).not.toContain("--dry-run");
  });
});

/* ------------------------- the PR identity comes from the workflow ------------------------- */

describe("review.yml: the publish job takes the PR identity from the workflow (defect: publisher trusts the artifact's pr.json)", () => {
  it("passes the event's repository, number and head, or the pr_number input without a head", () => {
    const env = PUBLISH_STEP.env!;
    const ev = (ctx: Ctx): [string, string] => [interpolate(env.PR_NUMBER!, ctx), interpolate(env.EVENT_HEAD_SHA!, ctx)];
    expect(ev({ github: { event: prEvent("acme/web", "acme/web") }, inputs: {} })).toEqual(["42", HEAD]);
    expect(ev({ github: { event: {} }, inputs: { pr_number: "7" } })).toEqual(["7", ""]);
    expect(PUBLISH_STEP.run).toContain('--repo "$GITHUB_REPOSITORY" --pr-number "$PR_NUMBER"');
    expect(PUBLISH_STEP.run).toContain('args+=(--head-sha "$EVENT_HEAD_SHA")');
  });

  it("an artifact whose pr.json names another pull request publishes nothing and fails the job", async () => {
    gh.reset();
    const store: ArtifactStore = new Map();
    const files = reviewArtifact({ repo: "acme/web" });
    files["ctx/pr.json"] = JSON.stringify({ ...(JSON.parse(files["ctx/pr.json"]!) as Record<string, unknown>), number: 43 });
    const review = runReviewJob(store, { attempt: 1, files });
    const run = await runPublishJob(store, review, { attempt: 1, repo: "acme/web", event: prEvent("acme/web", "acme/web"), policy: join(ROOT, "e2e", "policy.yaml") });
    expect(run.code).toBe(1);
    expect(run.stderr).toContain("refusing to publish anything: ctx/pr.json names pull request #43, but this workflow runs for #42");
    expect(gh.requests).toEqual([]);
    expect(run.env.XREPO_CALLS).toContain(`--repo acme/web --pr-number 42 --head-sha ${HEAD}`);
  });
});

/* --------------------------- repository_dispatch token --------------------------- */

describe("repository_dispatch needs XREPO_DISPATCH_TOKEN (defect: same-repo fallback to a contents:read token)", () => {
  const run = async (repo: string, policy: string, dispatchToken?: string): Promise<PublishRun> => {
    gh.reset();
    const store: ArtifactStore = new Map();
    const review = runReviewJob(store, { attempt: 1, files: reviewArtifact({ repo, skipped: true }), skip: true, skipReason: "draft pull request" });
    return runPublishJob(store, review, {
      attempt: 1,
      repo,
      event: prEvent(repo, repo),
      policy,
      ...(dispatchToken ? { dispatchToken } : {}),
      xrepo: { publishRc: 0, dryRunRc: 0 },
    });
  };
  const WARNING = /::warning::The policy configures repository_dispatch outcome actions for acme\/payments, but the XREPO_DISPATCH_TOKEN secret is not set/;

  it("the publish job keeps contents: read (no code-push token) and the callers grant no more", async () => {
    expect(PUBLISH.permissions.contents).toBe("read");
    for (const f of ["caller.yml", "caller-with-hooks.yml"]) {
      const wf = parseYaml(readFileSync(join(ROOT, "examples", f), "utf8")) as { jobs: { review: { permissions: Record<string, string> } } };
      expect(wf.jobs.review.permissions.contents, f).toBe("read");
    }
  });

  it("warns up front when the policy dispatches and XREPO_DISPATCH_TOKEN is missing", async () => {
    const missing = await run("acme/payments", join(ROOT, "examples", "policy.yaml"));
    expect(missing.code, missing.stderr).toBe(0);
    expect(missing.stdout).toMatch(WARNING);
    const withToken = await run("acme/payments", join(ROOT, "examples", "policy.yaml"), "github_pat_dispatch");
    expect(withToken.stdout).not.toContain("XREPO_DISPATCH_TOKEN");
    expect(withToken.env.XREPO_DISPATCH_TOKEN).toBe("github_pat_dispatch");
    const noDispatch = await run("acme/web", join(ROOT, "e2e", "policy.yaml"));
    expect(noDispatch.stdout).not.toContain("XREPO_DISPATCH_TOKEN");
  });

  it("the secret, README and example policy say every dispatch needs XREPO_DISPATCH_TOKEN", async () => {
    const wf = parseYaml(readFileSync(join(ROOT, ".github", "workflows", "review.yml"), "utf8")) as {
      on: { workflow_call: { secrets: Record<string, { description: string }> } };
    };
    expect(wf.on.workflow_call.secrets.XREPO_DISPATCH_TOKEN!.description).toMatch(/Required for ANY dispatch, also to the PR's own repository/);
    const readme = readFileSync(join(ROOT, "README.md"), "utf8");
    expect(readme).toMatch(/`XREPO_DISPATCH_TOKEN`[^\n]*\n?[^\n]*required for every `dispatch`/i);
    expect(readme).not.toMatch(/optional `XREPO_NOTIFY_SECRETS`, `XREPO_DISPATCH_TOKEN`/);
    const example = readFileSync(join(ROOT, "examples", "policy.yaml"), "utf8").split("\n");
    const dispatchLines = example.flatMap((l, i) => (/^\s*dispatch:/.test(l) ? [i] : []));
    expect(dispatchLines.length).toBeGreaterThan(0);
    for (const i of dispatchLines) {
      const around = example.slice(Math.max(0, i - 3), i + 3).join("\n");
      expect(around, `examples/policy.yaml line ${i + 1}`).toContain("XREPO_DISPATCH_TOKEN");
    }
  });
});

/* ======================= round 2: scheduled workflows, forks, auth, cache, CI ======================= */

interface AnyJob {
  name?: string;
  needs?: string;
  if?: string;
  "runs-on"?: string;
  uses?: string;
  with?: Record<string, string>;
  secrets?: string | Record<string, string>;
  permissions?: Record<string, string>;
  outputs?: Record<string, string>;
  strategy?: { "max-parallel"?: number; "fail-fast"?: boolean; matrix: Record<string, unknown> };
  steps: Step[];
}
interface AnyWorkflow {
  on: Record<string, unknown>;
  permissions?: unknown;
  jobs: Record<string, AnyJob>;
}
const loadWorkflow = (...rel: string[]): AnyWorkflow => parseYaml(readFileSync(join(ROOT, ...rel), "utf8")) as AnyWorkflow;
const stepIn = (job: AnyJob | undefined, pred: (s: Step) => boolean, what: string): Step => {
  const s = job?.steps.find(pred);
  if (!s) throw new Error(`no ${what} step`);
  return s;
};
const bashEnv = (t: string, extra: Record<string, string> = {}): Record<string, string> => ({
  PATH: process.env.PATH ?? "/usr/bin:/bin",
  HOME: t,
  NO_PROXY: "127.0.0.1,localhost",
  no_proxy: "127.0.0.1,localhost",
  ...extra,
});
/** `key=value` lines (and heredoc-free) of a GITHUB_OUTPUT file. */
const kvOutputs = (text: string): Record<string, string> =>
  Object.fromEntries(
    text
      .split("\n")
      .filter((l) => /^[A-Za-z_][A-Za-z0-9_-]*=/.test(l))
      .map((l) => [l.slice(0, l.indexOf("=")), l.slice(l.indexOf("=") + 1)]),
  );

/** Runs a step's `run` script the way GitHub does, with its `env` resolved from `ctx`. */
async function runStep(step: Step, ctx: Ctx, cwd: string, extra: Record<string, string> = {}): Promise<{ code: number; stdout: string; stderr: string; outputs: Record<string, string> }> {
  const script = join(cwd, `.step-${++seq}.sh`);
  writeFileSync(script, step.run!);
  const out = join(cwd, `.github-output-${seq}`);
  writeFileSync(out, "");
  const stepEnv = Object.fromEntries(Object.entries(step.env ?? {}).map(([k, v]) => [k, interpolate(v, ctx)]));
  const r = await runBash(script, cwd, bashEnv(cwd, { GITHUB_OUTPUT: out, ...stepEnv, ...extra }));
  return { ...r, outputs: kvOutputs(readFileSync(out, "utf8")) };
}

/** A checkout of this repository whose `node dist/cli.js` records its argv / token and exits with FAKE_RC. */
function fakeCliCheckout(dir = tmp(), cli = join("dist", "cli.js")): { dir: string; calls: () => { argv: string[]; token: string | null }[] } {
  const log = join(dir, ".cli-calls.jsonl");
  mkdirSync(dirname(join(dir, cli)), { recursive: true });
  writeFileSync(join(dir, "package.json"), '{"type":"module"}\n');
  writeFileSync(
    join(dir, cli),
    [
      'import { appendFileSync } from "node:fs";',
      `appendFileSync(${JSON.stringify(log)}, JSON.stringify({ argv: process.argv.slice(2), token: process.env.XREPO_GITHUB_TOKEN ?? null }) + "\\n");`,
      'process.exit(Number(process.env.FAKE_RC ?? "0"));',
      "",
    ].join("\n"),
  );
  return {
    dir,
    calls: () => (existsSync(log) ? readFileSync(log, "utf8").trim().split("\n").filter(Boolean).map((l) => JSON.parse(l) as { argv: string[]; token: string | null }) : []),
  };
}

/* ------------------------- sync.yml / retry.yml: one token per owner ------------------------- */

describe("sync.yml / retry.yml: one App token per owner (defect: a single-owner token cannot serve a multi-owner policy)", () => {
  const SYNC = loadWorkflow(".github", "workflows", "sync.yml");
  const RETRY = loadWorkflow(".github", "workflows", "retry.yml");
  const cases = [
    { file: "sync.yml", wf: SYNC, leg: "sync", run: "Sync the mirror", command: "sync" },
    { file: "retry.yml", wf: RETRY, leg: "retry", run: "Re-run postponed reviews", command: "retry" },
  ] as const;

  /** Runs the `owners` job's script against a policy with the real loadPolicy (src through tsx). */
  async function owners(wf: AnyWorkflow, policyText: string | null, env: Record<string, string> = {}): Promise<{ code: number; stderr: string; stdout: string; owners?: string[]; scoped?: string }> {
    const t = tmp();
    mkdirSync(join(t, "dist", "policy"), { recursive: true });
    writeFileSync(join(t, "package.json"), '{"type":"module"}\n');
    writeFileSync(join(t, "dist", "policy", "load.js"), `export * from ${JSON.stringify(pathToFileURL(join(ROOT, "src", "policy", "load.ts")).href)};\n`);
    let policy = join(ROOT, "examples", "policy.yaml");
    if (policyText !== null) {
      policy = join(t, "policy.yaml");
      writeFileSync(policy, policyText);
    }
    const step = stepIn(wf.jobs.owners, (s) => s.id === "owners", "owners");
    const r = await runStep(step, { github: { repository_owner: "acme" }, vars: {} }, t, { POLICY: policy, NODE_OPTIONS: `--import=${TSX_LOADER}`, ...env });
    return { code: r.code, stderr: r.stderr, stdout: r.stdout, owners: r.outputs.owners ? (JSON.parse(r.outputs.owners) as string[]) : undefined, scoped: r.outputs.scoped };
  }

  it.each(cases)("$file: an owners job, then one job per owner that mints THAT owner's token", ({ wf, leg, run }) => {
    const ownersJob = wf.jobs.owners!;
    const legJob = wf.jobs[leg]!;
    expect(ownersJob.outputs).toEqual({ owners: "${{ steps.owners.outputs.owners }}", scoped: "${{ steps.owners.outputs.scoped }}" });
    // The policy lives on the host of these runners.
    expect(ownersJob["runs-on"]).toBe(legJob["runs-on"]);
    expect(legJob.needs).toBe("owners");
    expect(legJob.strategy?.matrix).toEqual({ owner: "${{ fromJSON(needs.owners.outputs.owners) }}" });
    expect(legJob.strategy?.["fail-fast"]).toBe(false);
    expect(legJob.strategy?.["max-parallel"]).toBe(1);
    const mint = stepIn(legJob, (s) => s.uses?.startsWith("actions/create-github-app-token@") === true, "create-github-app-token");
    expect(mint.with?.owner).toBe("${{ matrix.owner }}");
    for (const job of Object.values(wf.jobs)) {
      for (const s of job.steps) expect(JSON.stringify(s.with ?? {}), `${s.name}`).not.toContain("repository_owner");
    }
    const step = stepIn(legJob, (s) => s.name === run, run);
    expect(step.env?.XREPO_GITHUB_TOKEN).toBe("${{ steps.app-token.outputs.token }}");
    expect(step.env?.OWNER).toBe("${{ matrix.owner }}");
    expect(step.env?.SCOPED).toBe("${{ needs.owners.outputs.scoped }}");
  });

  it("sync owners: every account in mirror.repos (the example's acme + acme-platform), first spelling wins", async () => {
    const example = await owners(SYNC, null);
    expect(example.code, example.stderr).toBe(0);
    expect(example).toMatchObject({ owners: ["acme", "acme-platform"], scoped: "true" });
    const mixed = await owners(SYNC, 'version: 1\nmirror:\n  repos: ["Acme/api", "acme/*", "other/lib", "*", "bad/x/y"]\n');
    expect(mixed).toMatchObject({ code: 0, owners: ["Acme", "other"], scoped: "true" });
    // One owner: a single unrestricted sync, exactly as before the fix.
    expect(await owners(SYNC, readFileSync(join(ROOT, "e2e", "policy.yaml"), "utf8"))).toMatchObject({ code: 0, owners: ["acme"], scoped: "false" });
    // None: one run with the repository owner's token, which removes mirrors the policy dropped.
    expect(await owners(SYNC, "version: 1\n")).toMatchObject({ code: 0, owners: ["acme"], scoped: "false" });
    // An invalid policy fails the run (xrepo sync would exit 2 anyway).
    expect((await owners(SYNC, "version: 2\n")).code).not.toBe(0);
  });

  it("retry owners: policy.repos keys + mirror.repos + this repository's owner, or exactly vars.XREPO_RETRY_OWNERS", async () => {
    expect(await owners(RETRY, null)).toMatchObject({ code: 0, owners: ["acme", "acme-platform"], scoped: "true" });
    // Leave out an owner that is only mirrored (the retry App is not installed there).
    expect(await owners(RETRY, null, { OWNERS_OVERRIDE: '["acme"]' })).toMatchObject({ code: 0, owners: ["acme"], scoped: "true" });
    for (const bad of ["acme", "[]", '["acme/web"]', "[1]"]) {
      const r = await owners(RETRY, null, { OWNERS_OVERRIDE: bad });
      expect(r.code, bad).toBe(1);
      expect(r.stderr, bad).toContain("::error::vars.XREPO_RETRY_OWNERS must be a JSON array");
    }
    expect(await owners(RETRY, readFileSync(join(ROOT, "e2e", "policy.yaml"), "utf8"))).toMatchObject({ code: 0, owners: ["acme"], scoped: "false" });
    expect(await owners(RETRY, "version: 1\nrepos:\n  ACME/web: {}\n")).toMatchObject({ code: 0, owners: ["ACME"], scoped: "false" });
    // The workflow lives in another account than the reviewed repositories: both are swept.
    expect(await owners(RETRY, "version: 1\nrepos:\n  acme/web: {}\n", { REPO_OWNER: "acme-devops" })).toMatchObject({
      code: 0,
      owners: ["acme", "acme-devops"],
      scoped: "true",
    });
  });

  it.each(cases)("$file: each job passes its own token and, with several owners, --owner <its owner>", async ({ wf, leg, run, command }) => {
    const step = stepIn(wf.jobs[leg], (s) => s.name === run, run);
    const go = async (scoped: string, rc: number, dryRun = false): Promise<{ code: number; stdout: string; calls: { argv: string[]; token: string | null }[] }> => {
      const cli = fakeCliCheckout();
      const ctx: Ctx = {
        matrix: { owner: "acme-platform" },
        needs: { owners: { outputs: { scoped } } },
        steps: { "app-token": { outputs: { token: "ghs_acme_platform_installation" } } },
        vars: {},
        inputs: { dry_run: dryRun },
      };
      const r = await runStep(step, ctx, cli.dir, { FAKE_RC: String(rc) });
      return { code: r.code, stdout: r.stdout, calls: cli.calls() };
    };
    const scoped = await go("true", 0);
    expect(scoped.code).toBe(0);
    expect(scoped.calls).toHaveLength(1);
    expect(scoped.calls[0]!.token).toBe("ghs_acme_platform_installation");
    expect(scoped.calls[0]!.argv[0]).toBe(command);
    expect(scoped.calls[0]!.argv.join(" ")).toContain("--policy /etc/xrepo-review/policy.yaml");
    expect(scoped.calls[0]!.argv.slice(-2)).toEqual(["--owner", "acme-platform"]);
    // A single owner: the command line of before the fix (no --owner).
    const single = await go("false", 0);
    expect(single.calls[0]!.argv).not.toContain("--owner");
    // Failures still fail the job.
    expect((await go("true", 1)).code).toBe(1);
    if (command === "sync") {
      const locked = await go("true", 3);
      expect(locked.code).toBe(0);
      expect(locked.stdout).toContain("::notice::another xrepo sync is running");
    } else {
      expect((await go("true", 0, true)).calls[0]!.argv.slice(-3)).toEqual(["--owner", "acme-platform", "--dry-run"]);
    }
  });

  it("README and SECURITY.md say an installation token covers one account and how the workflows handle several", () => {
    const readme = readFileSync(join(ROOT, "README.md"), "utf8");
    expect(readme).toMatch(/installation token covers \*\*one account\*\*/);
    expect(readme).toContain("xrepo sync --owner <owner>");
    expect(readme).toContain("vars.XREPO_RETRY_OWNERS");
    expect(readme).toMatch(/xrepo sync +--policy <file> --mirror <dir> \[--repo o\/n …\] \[--owner L\]/);
    expect(readFileSync(join(ROOT, "docs", "SECURITY.md"), "utf8")).toMatch(/per owner: a token covers one account/);
  });
});

/* ------------------------- review.yml: fork PR, private xrepo_repo ------------------------- */

describe("review.yml: fork pull requests with a private xrepo_repo (defect: both jobs fail at the trusted checkout)", () => {
  const SRC = stepOf(REVIEW, (s) => s.id === "xrepo-src", "trusted checkout");
  const STOP = stepOf(REVIEW, (s) => s.id === "fork-stop", "fork-stop");
  const after = REVIEW.steps.slice(REVIEW.steps.indexOf(STOP) + 1);
  const forkEvent = prEvent("acme/web", "mallory/web");
  const ctxFor = (outcome: string, inputs: Record<string, unknown> = {}, event: Record<string, unknown> = forkEvent): Ctx => ({
    inputs: { mode: "hosted", launcher: "docker", xrepo_ref: "a".repeat(40), xrepo_repo: "acme/xrepo-review", mirror_url_template: "", ...inputs },
    github: { repository: "acme/web", event, event_name: "pull_request" },
    steps: {
      "xrepo-src": { outcome },
      "fork-stop": outcome === "failure" ? { outputs: { stopped: "true", skip_reason: "pull request from a fork" } } : { outputs: {} },
      prepare: outcome === "failure" ? { outcome: "skipped", outputs: {} } : { outcome: "success", outputs: { skip: "false" } },
    },
  });

  it("only a fork run may survive a failed trusted checkout", () => {
    expect(SRC.uses).toMatch(/^actions\/checkout@/);
    expect(SRC.with?.repository).toBe("${{ inputs.xrepo_repo }}");
    const coe = (event: Record<string, unknown>): boolean => condition(String(SRC["continue-on-error"]), { github: { repository: "acme/web", event } });
    expect(coe(forkEvent)).toBe(true);
    expect(coe(prEvent("acme/web", null))).toBe(true); // head repository deleted
    expect(coe(prEvent("acme/web", "acme/web"))).toBe(false);
    expect(coe(prEvent("acme/web", "ACME/Web"))).toBe(false);
    expect(coe({ inputs: { pr_number: "42" } })).toBe(false); // workflow_dispatch
    // The publish job's checkout keeps failing loudly: it only runs when the review job got past it.
    const pubSrc = stepOf(PUBLISH, (s) => s.uses?.startsWith("actions/checkout@") === true, "publish checkout");
    expect(pubSrc["continue-on-error"]).toBeUndefined();
  });

  it("after a failed checkout on a fork, every later review step is skipped, the job ends green and publish is skipped", async () => {
    const ctx = ctxFor("failure");
    expect(condition(STOP.if, ctx)).toBe(true);
    expect(after.length).toBeGreaterThan(10);
    for (const s of after) expect(condition(s.if, ctx), s.name).toBe(false);

    const r = await runStep(STOP, ctx, tmp());
    expect(r.code, r.stderr).toBe(0);
    expect(r.stdout).toMatch(/^::notice::Not reviewed: pull request from a fork: this run cannot read acme\/xrepo-review/m);
    expect(r.outputs.stopped).toBe("true");
    expect(r.outputs.skip_reason).toContain("pull request from a fork");

    const outCtx: Ctx = { ...ctx, github: { run_attempt: 1 }, steps: { ...(ctx.steps as object), "fork-stop": { outputs: r.outputs } } };
    const outputs = Object.fromEntries(Object.entries(REVIEW.outputs).map(([k, v]) => [k, interpolate(v, outCtx)]));
    expect(outputs).toMatchObject({ fork_stopped: "true", artifact: "", skip_reason: r.outputs.skip_reason });
    expect(condition(PUBLISH.if, { needs: { review: { outputs, result: "success" } } })).toBe(false);
    // Every other review result still publishes (artifact or error report).
    for (const fork_stopped of ["", "false"]) expect(condition(PUBLISH.if, { needs: { review: { outputs: { fork_stopped }, result: "failure" } } })).toBe(true);
  });

  it("runs that could check it out (or need no checkout) take exactly the steps they took before", () => {
    const GUARD = "steps.xrepo-src.outcome != 'failure'";
    for (const s of after.filter((x) => x.if?.includes("xrepo-src"))) expect(s.if, s.name).toContain(GUARD);
    const variants: Ctx[] = [
      ctxFor("success"),
      ctxFor("success", { launcher: "local", mirror_url_template: "file://{workspace}/.xrepo-src/e2e/fixtures-bare/{owner}/{repo}.git" }),
      ctxFor("skipped", { mode: "self-hosted", xrepo_ref: "" }, prEvent("acme/web", "acme/web")),
      ctxFor("skipped", { mode: "self-hosted", xrepo_ref: "" }, forkEvent),
    ];
    for (const ctx of variants) {
      for (const s of after) {
        const before = s.if === undefined ? undefined : s.if === GUARD ? undefined : s.if.replace(` && ${GUARD}`, "");
        expect(condition(s.if, ctx), s.name).toBe(condition(before, ctx));
      }
      // Self-hosted / successful checkouts never take the fork-stop path.
      expect(condition(STOP.if, ctx)).toBe(false);
    }
  });

  it("the header, README and SECURITY.md describe the green early stop", () => {
    const wfText = readFileSync(join(ROOT, ".github", "workflows", "review.yml"), "utf8");
    expect(wfText).toMatch(/xrepo_repo is private, a fork run cannot even check out the trusted source/);
    expect(readFileSync(join(ROOT, "README.md"), "utf8")).toMatch(/\*\*private\*\* `xrepo_repo`, a fork run\s+cannot even check out the trusted source/);
    expect(readFileSync(join(ROOT, "docs", "SECURITY.md"), "utf8")).toMatch(/private `xrepo_repo`, a fork run cannot check out the trusted source/);
  });
});

/* ------------------------- review.yml: exactly one Claude credential ------------------------- */

describe("review.yml: exactly one Claude credential (defect: a visible ANTHROPIC_API_KEY overrides the group's CLAUDE_CODE_OAUTH_TOKEN)", () => {
  const CLAUDE = stepOf(REVIEW, (s) => s.id === "claude", "claude");
  const creds = (oauth: string, key: string): { oauth: string; key: string } => {
    const ctx: Ctx = { secrets: { CLAUDE_CODE_OAUTH_TOKEN: oauth, ANTHROPIC_API_KEY: key } };
    return { oauth: interpolate(CLAUDE.with!.claude_code_oauth_token!, ctx), key: interpolate(CLAUDE.with!.anthropic_api_key!, ctx) };
  };

  it("the subscription token wins; the API key is passed only when no subscription token is visible", () => {
    expect(creds("sk-ant-oat01-group-b", "sk-ant-api03-org")).toEqual({ oauth: "sk-ant-oat01-group-b", key: "" });
    expect(creds("sk-ant-oat01-group-b", "")).toEqual({ oauth: "sk-ant-oat01-group-b", key: "" });
    expect(creds("", "sk-ant-api03-org")).toEqual({ oauth: "", key: "sk-ant-api03-org" });
    expect(creds("", "")).toEqual({ oauth: "", key: "" });
    // Secrets the caller cannot see are absent from the context (null).
    expect(interpolate(CLAUDE.with!.anthropic_api_key!, { secrets: { ANTHROPIC_API_KEY: "sk-ant-api03-org" } })).toBe("sk-ant-api03-org");
    expect(interpolate(CLAUDE.with!.anthropic_api_key!, { secrets: { CLAUDE_CODE_OAUTH_TOKEN: "sk-ant-oat01-x", ANTHROPIC_API_KEY: "k" } })).toBe("");
  });

  it("the secret descriptions and README state the precedence", () => {
    const wf = loadWorkflow(".github", "workflows", "review.yml") as unknown as { on: { workflow_call: { secrets: Record<string, { description: string }> } } };
    expect(wf.on.workflow_call.secrets.CLAUDE_CODE_OAUTH_TOKEN!.description).toMatch(/Wins over ANTHROPIC_API_KEY/);
    expect(wf.on.workflow_call.secrets.ANTHROPIC_API_KEY!.description).toMatch(/only when CLAUDE_CODE_OAUTH_TOKEN is not visible/);
    const readme = readFileSync(join(ROOT, "README.md"), "utf8");
    expect(readme).toMatch(/passes \*\*exactly one\*\* of them to the action/);
    expect(readme).toMatch(/Claude\s+Code itself prefers `ANTHROPIC_API_KEY` when both are set/);
  });
});

/* ------------------------- hosted mirror cache on the default branch ------------------------- */

describe("mirror-cache.yml (defect: the hosted mirror cache is saved only in each PR's own scope)", () => {
  const CACHE_WF = loadWorkflow(".github", "workflows", "mirror-cache.yml");
  const WARM = CACHE_WF.jobs.warm!;
  const isCache = (s: Step): boolean => s.uses?.startsWith("actions/cache@") === true;

  it("is a read-only reusable workflow that never sees a pull request", () => {
    expect(Object.keys(CACHE_WF.on)).toEqual(["workflow_call"]);
    expect(CACHE_WF.permissions).toEqual({});
    expect(Object.keys(CACHE_WF.jobs)).toEqual(["warm"]);
    expect(WARM.permissions).toEqual({ contents: "read" });
    expect(JSON.stringify(CACHE_WF)).not.toContain("pull_request");
    const call = CACHE_WF.on.workflow_call as { inputs: Record<string, { default?: string; required?: boolean }>; secrets: Record<string, unknown> };
    expect(Object.keys(call.secrets)).toEqual(["XREPO_GITHUB_TOKEN"]);
    const reviewInputs = (loadWorkflow(".github", "workflows", "review.yml").on.workflow_call as { inputs: Record<string, { default?: string }> }).inputs;
    for (const i of ["xrepo_repo", "policy_file"]) expect(call.inputs[i]!.default, i).toBe(reviewInputs[i]!.default);
    expect(call.inputs.xrepo_ref!.required).toBe(true);
  });

  it("saves under exactly review.yml's key, restore keys and path, from the same trusted checkout", async () => {
    const review = stepOf(REVIEW, isCache, "review cache");
    const warm = stepIn(WARM, isCache, "warm cache");
    expect(warm.uses).toBe(review.uses);
    expect(warm.with).toEqual(review.with);
    expect(stepIn(WARM, (s) => s.id === "mirror-key", "mirror-key").run).toBe(stepOf(REVIEW, (s) => s.id === "mirror-key", "mirror-key").run);
    const checkout = (job: AnyJob | Job): Step => job.steps.find((s) => s.uses?.startsWith("actions/checkout@") && s.with?.path === ".xrepo-src")!;
    expect(checkout(WARM).with).toEqual(checkout(REVIEW).with);
    expect(checkout(WARM).uses).toBe(checkout(REVIEW).uses);
    // Same resolved paths (hashFiles input and cache path) as the hosted review job.
    const t = tmp();
    const env = { RUNNER_TEMP: join(t, "_temp"), GITHUB_WORKSPACE: join(t, "ws") };
    const ctx: Ctx = { inputs: { mode: "hosted", policy_file: ".github/xrepo/policy.yaml", policy_path: "/etc/x.yaml", mirror_path: "/srv/m" } };
    const fromReview = await runStep(stepOf(REVIEW, (s) => s.id === "paths", "paths"), ctx, t, env);
    const fromWarm = await runStep(stepIn(WARM, (s) => s.id === "paths", "paths"), ctx, t, env);
    expect(fromWarm.outputs.mirror).toBe(join(t, "_temp", "xrepo-mirror"));
    expect(fromWarm.outputs.mirror).toBe(fromReview.outputs.mirror);
    expect(fromWarm.outputs.policy).toBe(fromReview.outputs.policy);
  });

  it("a partial sync is a warning, so the post step still saves the cache", async () => {
    const step = stepIn(WARM, (s) => s.name === "Sync mirror", "sync");
    const cli = fakeCliCheckout(tmp(), join(".xrepo-src", "dist", "cli.js"));
    const ctx: Ctx = { secrets: { XREPO_GITHUB_TOKEN: "ghs_mirror" }, github: { token: "ghs_job" }, steps: { paths: { outputs: { policy: "/p.yaml", mirror: "/m" } } } };
    const r = await runStep(step, ctx, cli.dir, { FAKE_RC: "1" });
    expect(r.code).toBe(0);
    expect(r.stdout).toContain("::warning::xrepo sync exited with 1");
    expect(cli.calls()).toEqual([{ argv: ["sync", "--policy", "/p.yaml", "--mirror", "/m"], token: "ghs_mirror" }]);
  });

  it("examples/caller-hosted.yml reviews pull requests and warms the cache on a schedule, with identical inputs", () => {
    const caller = loadWorkflow("examples", "caller-hosted.yml");
    expect(Object.keys(caller.on)).toEqual(expect.arrayContaining(["pull_request", "schedule"]));
    const { review, "mirror-cache": cache } = caller.jobs;
    expect(review!.uses).toMatch(/\/\.github\/workflows\/review\.yml@[0-9a-f]{40}$/);
    expect(cache!.uses).toMatch(/\/\.github\/workflows\/mirror-cache\.yml@[0-9a-f]{40}$/);
    expect(cache!.uses!.split("@")[1]).toBe(review!.uses!.split("@")[1]);
    for (const k of ["runner_labels", "xrepo_repo", "xrepo_ref", "policy_file"]) expect(cache!.with![k], k).toBe(review!.with![k]);
    expect(review!.with!.mode).toBe("hosted");
    for (const event_name of ["pull_request", "schedule", "workflow_dispatch"]) {
      const ctx = { github: { event_name } };
      expect(condition(review!.if, ctx), event_name).toBe(event_name === "pull_request");
      expect(condition(cache!.if, ctx), event_name).toBe(event_name !== "pull_request");
    }
    expect(cache!.permissions).toEqual({ contents: "read" });
    expect(cache!.secrets).toEqual({ XREPO_GITHUB_TOKEN: "${{ secrets.XREPO_GITHUB_TOKEN }}" });
  });

  it("README explains the cache scope and points to the warm-up", () => {
    const readme = readFileSync(join(ROOT, "README.md"), "utf8");
    expect(readme).toContain("examples/caller-hosted.yml");
    expect(readme).toContain(".github/workflows/mirror-cache.yml");
    expect(readme).toMatch(/never another pull request's/);
  });
});

/* ------------------------- ci.yml: the tests are type-checked ------------------------- */

describe("ci.yml type-checks test/ (defect: tsconfig.json covers src/ only and vitest strips types)", () => {
  const CI = loadWorkflow(".github", "workflows", "ci.yml");
  // `npm run typecheck` = tsconfig.json (src/) and tsconfig.test.json (src/ + test/).
  const step = stepIn(CI.jobs.test, (s) => s.run?.trim() === "npm run typecheck", "npm run typecheck");

  it("runs before the tests", () => {
    const steps = CI.jobs.test!.steps;
    const typecheck = steps.indexOf(step);
    expect(typecheck).toBeGreaterThan(-1);
    expect(typecheck).toBeLessThan(steps.findIndex((s) => s.name === "Tests"));
    const pkg = JSON.parse(readFileSync(join(ROOT, "package.json"), "utf8")) as { scripts: Record<string, string> };
    expect(pkg.scripts.typecheck).toContain("tsconfig.test.json");
  });

  it("fails on a type error in a test file and passes once it is fixed", async () => {
    const t = tmp();
    for (const f of ["package.json", "tsconfig.json", "tsconfig.test.json"]) cpSync(join(ROOT, f), join(t, f));
    symlinkSync(join(ROOT, "node_modules"), join(t, "node_modules"), "dir");
    mkdirSync(join(t, "src"));
    mkdirSync(join(t, "test"));
    writeFileSync(join(t, "src", "api.ts"), "export interface Api {\n  get(path: string): Promise<string>;\n}\n");
    // A test double that drifted from the interface it fakes.
    writeFileSync(join(t, "test", "api.test.ts"), 'import type { Api } from "../src/api.js";\nexport const fake: Api = { get: async (path: string) => path.length };\n');
    const bad = await runStep(step, {}, t);
    expect(bad.code).not.toBe(0);
    expect(bad.stdout).toMatch(/test\/api\.test\.ts\(2,\d+\): error TS2322/);
    writeFileSync(join(t, "test", "api.test.ts"), 'import type { Api } from "../src/api.js";\nexport const fake: Api = { get: async (path: string) => path };\n');
    const good = await runStep(step, {}, t);
    expect(good.code, good.stdout + good.stderr).toBe(0);
  });
});

/* ------------------------- per-group accounts: no `account` input ------------------------- */

describe("per-group accounts (defect: SPEC promised an `account` input review.yml does not have)", () => {
  it("review.yml has no account input and reads only the two fixed secret names; README says so", () => {
    const call = loadWorkflow(".github", "workflows", "review.yml").on.workflow_call as { inputs: Record<string, unknown> };
    expect(Object.keys(call.inputs)).not.toContain("account");
    const text = readFileSync(join(ROOT, ".github", "workflows", "review.yml"), "utf8");
    expect(text).not.toMatch(/inputs\.account|CLAUDE_CODE_OAUTH_TOKEN_/);
    expect(text).not.toMatch(/secrets\[/);
    expect(readFileSync(join(ROOT, "README.md"), "utf8")).toMatch(/review\.yml has no `account` input/);
    // SPEC.md (not owned by this area) must say the same; see the round-2 report for the text.
  });
});

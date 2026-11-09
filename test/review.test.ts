import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { PassThrough } from "node:stream";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { CTX_FILES, type PrContext } from "../src/common/context.js";
import { parseUnifiedDiff, type FileDiff } from "../src/common/diff.js";
import { DraftEntry, parseDraft } from "../src/common/draft.js";
import { parsePolicy, resolvePolicy } from "../src/policy/load.js";
import type { ResolvedPolicy } from "../src/policy/schema.js";
import { allowedVerdicts, createReviewServer, main, reviewToolNames } from "../src/review/server.js";

/* -------------------------------- fixtures -------------------------------- */

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
  "@@ -40,3 +42,4 @@ export function cancelOrder() {",
  " return a;",
  "+// added",
  " return c;",
  " }",
  "diff --git a/src/new.ts b/src/new.ts",
  "new file mode 100644",
  "index 0000000..3333333",
  "--- /dev/null",
  "+++ b/src/new.ts",
  "@@ -0,0 +1,3 @@",
  "+one",
  "+two",
  "+three",
  "diff --git a/old.txt b/old.txt",
  "deleted file mode 100644",
  "index 4444444..0000000",
  "--- a/old.txt",
  "+++ /dev/null",
  "@@ -1,2 +0,0 @@",
  "-x",
  "-y",
  "diff --git a/.github/workflows/ci.yml b/.github/workflows/ci.yml",
  "index 5555555..6666666 100644",
  "--- a/.github/workflows/ci.yml",
  "+++ b/.github/workflows/ci.yml",
  "@@ -1,2 +1,2 @@",
  " name: ci",
  "-on: push",
  "+on: [push, pull_request]",
  "diff --git a/img.png b/img.png",
  "index 7777777..8888888 100644",
  "Binary files a/img.png and b/img.png differ",
  "diff --git a/lib/a.ts b/lib/b.ts",
  "similarity index 100%",
  "rename from lib/a.ts",
  "rename to lib/b.ts",
  "diff --git a/docs/gen.md b/docs/gen.md",
  "index 9999999..aaaaaaa 100644",
  "--- a/docs/gen.md",
  "+++ b/docs/gen.md",
  "@@ -1 +1 @@",
  "-old",
  "+new",
  "",
].join("\n");

const diff: FileDiff[] = parseUnifiedDiff(DIFF);
const IGNORED = ["docs/gen.md"];

const ctx: PrContext = {
  repo: "acme/api",
  number: 7,
  title: "Add order fields",
  body: "",
  author: "dev",
  author_type: "User",
  base_sha: "b".repeat(40),
  head_sha: "h".repeat(40),
  base_ref: "main",
  head_ref: "feature",
  draft: false,
  fork: false,
  html_url: "https://github.com/acme/api/pull/7",
  files: diff
    .filter((f) => !IGNORED.includes(f.path))
    .map((f) => ({
      path: f.path,
      status: f.status,
      additions: f.additions,
      deletions: f.deletions,
      ...(f.oldPath !== undefined ? { previous_path: f.oldPath } : {}),
    })),
  changed_lines: 12,
  ignored_files: IGNORED,
};

function policyWith(caps: Record<string, unknown> = {}): ResolvedPolicy {
  return resolvePolicy(parsePolicy(JSON.stringify({ version: 1, defaults: { capabilities: caps } })), "acme/api");
}

/* --------------------------------- harness -------------------------------- */

let dir: string;
let fileNo = 0;
const clients: Client[] = [];

beforeAll(() => {
  dir = mkdtempSync(join(tmpdir(), "xrepo-review-"));
});
afterAll(() => {
  rmSync(dir, { recursive: true, force: true });
});
beforeEach(() => {
  // audit() writes JSON lines to stderr; keep test output readable.
  vi.spyOn(process.stderr, "write").mockImplementation(() => true);
});
afterEach(async () => {
  for (const c of clients.splice(0)) await c.close().catch(() => undefined);
  vi.restoreAllMocks();
  delete process.env.XREPO_AUDIT_FILE;
});

interface ToolInfo {
  name: string;
  inputSchema: { properties?: Record<string, { enum?: string[]; items?: { enum?: string[] } }>; additionalProperties?: unknown };
}

async function setup(caps: Record<string, unknown> = {}, outFile = join(dir, `draft-${++fileNo}.jsonl`)) {
  const policy = policyWith(caps);
  const server = createReviewServer({ policy, ctx, diff, outFile });
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  await server.connect(serverTransport);
  const client = new Client({ name: "test", version: "0.0.0" });
  await client.connect(clientTransport);
  clients.push(client);
  const call = async (name: string, args: Record<string, unknown> = {}) => {
    const r = await client.callTool({ name, arguments: args });
    const content = r.content as Array<{ type: string; text?: string }>;
    return { isError: r.isError === true, text: content[0]?.text ?? "" };
  };
  const text = (): string => (existsSync(outFile) ? readFileSync(outFile, "utf8") : "");
  const lines = (): string[] => text().split("\n").filter((l) => l !== "");
  const tools = async (): Promise<ToolInfo[]> => (await client.listTools()).tools as unknown as ToolInfo[];
  return { policy, client, call, text, lines, draft: () => parseDraft(text()), tools, outFile };
}

const comment = (over: Record<string, unknown> = {}) => ({
  path: "src/orders.ts",
  line: 13,
  body: "`d` is never validated before use; reject negative values (see acme/web:src/api/orders.ts:42).",
  severity: "medium",
  ...over,
});

/* ------------------------------ registration ------------------------------ */

describe("tool registration", () => {
  it("registers the default tool set and reviewToolNames matches listTools", async () => {
    const h = await setup();
    expect(reviewToolNames(h.policy)).toEqual(["add_comment", "set_summary", "set_verdict", "review_status", "finish"]);
    expect((await h.tools()).map((t) => t.name)).toEqual(reviewToolNames(h.policy));
  });

  it("registers add_labels only with labels enabled and a non-empty allow list", async () => {
    const all = await setup({ labels: { enabled: true, allowed: ["needs-tests", "breaking"] } });
    expect((await all.tools()).map((t) => t.name)).toEqual([
      "add_comment",
      "set_summary",
      "set_verdict",
      "add_labels",
      "review_status",
      "finish",
    ]);
    const empty = await setup({ labels: { enabled: true, allowed: [] } });
    expect(reviewToolNames(empty.policy)).not.toContain("add_labels");
    const off = await setup({ labels: { enabled: false, allowed: ["x"] } });
    expect(reviewToolNames(off.policy)).not.toContain("add_labels");
  });

  it("hides disabled capabilities entirely", async () => {
    const h = await setup({
      inline_comments: { enabled: false },
      summary_comment: { enabled: false },
      labels: { enabled: true, allowed: [] },
    });
    const names = (await h.tools()).map((t) => t.name);
    expect(names).toEqual(["set_verdict", "review_status", "finish"]);
    expect(reviewToolNames(h.policy)).toEqual(names);
    const r = await h.call("add_comment", comment());
    expect(r.isError).toBe(true);
    expect(r.text).toMatch(/not found/);
    const s = await h.call("set_summary", { body: "x" });
    expect(s.isError).toBe(true);
    expect(h.text()).toBe("");
  });

  it("hides add_comment when max_comments is 0", async () => {
    const h = await setup({ inline_comments: { max_comments: 0 } });
    expect(reviewToolNames(h.policy)).not.toContain("add_comment");
    expect((await h.tools()).map((t) => t.name)).not.toContain("add_comment");
  });
});

describe("set_verdict enum", () => {
  const cases: Array<[Record<string, unknown>, string[]]> = [
    [{}, ["comment"]],
    [{ approve: { enabled: true } }, ["comment", "approve"]],
    [{ block: { enabled: true } }, ["comment", "request_changes"]],
    [{ approve: { enabled: true }, block: { enabled: true } }, ["comment", "approve", "request_changes"]],
  ];
  for (const [caps, expected] of cases) {
    it(`advertises ${expected.join("|")}`, async () => {
      const h = await setup(caps);
      expect(allowedVerdicts(h.policy)).toEqual(expected);
      const tool = (await h.tools()).find((t) => t.name === "set_verdict");
      expect(tool?.inputSchema.properties?.verdict?.enum).toEqual(expected);
    });
  }

  it("rejects a verdict outside the enum and writes nothing", async () => {
    const h = await setup();
    for (const verdict of ["approve", "request_changes", "merge"]) {
      const r = await h.call("set_verdict", { verdict, reason: "looks good" });
      expect(r.isError).toBe(true);
    }
    expect(h.text()).toBe("");
    const ok = await h.call("set_verdict", { verdict: "comment", reason: "minor notes only" });
    expect(ok.isError).toBe(false);
    expect(h.draft().verdict).toEqual({ type: "verdict", verdict: "comment", reason: "minor notes only" });
  });
});

describe("suggestion field", () => {
  it("is advertised only when suggestions are enabled", async () => {
    const on = await setup();
    const onTool = (await on.tools()).find((t) => t.name === "add_comment");
    expect(onTool?.inputSchema.properties).toHaveProperty("suggestion");

    const off = await setup({ inline_comments: { suggestions: false } });
    const offTool = (await off.tools()).find((t) => t.name === "add_comment");
    expect(offTool?.inputSchema.properties).not.toHaveProperty("suggestion");
    expect(offTool?.inputSchema.additionalProperties).toBe(false);
    const r = await off.call("add_comment", comment({ suggestion: "const d = Math.max(0, 4);" }));
    expect(r.isError).toBe(true);
    expect(r.text).toMatch(/suggestion/);
    const fenced = await off.call("add_comment", comment({ body: "Fix:\n```suggestion\nconst d = 0;\n```" }));
    expect(fenced.isError).toBe(true);
    expect(fenced.text).toMatch(/disabled/);
    expect(off.text()).toBe("");
  });

  it("records a suggestion and rejects fenced suggestion text", async () => {
    const h = await setup();
    const fenced = await h.call("add_comment", comment({ suggestion: "```suggestion\nconst d = 0;\n```" }));
    expect(fenced.isError).toBe(true);
    expect(fenced.text).toMatch(/without ``` fences/);
    const r = await h.call("add_comment", comment({ suggestion: "const d = Math.max(0, 4);" }));
    expect(r.isError).toBe(false);
    expect(h.draft().comments[0]?.suggestion).toBe("const d = Math.max(0, 4);");
  });
});

/* ------------------------------- add_comment ------------------------------ */

describe("add_comment validation", () => {
  it("rejects paths that are not changed files, with hints", async () => {
    const h = await setup();
    const unknown = await h.call("add_comment", comment({ path: "src/missing.ts" }));
    expect(unknown.isError).toBe(true);
    expect(unknown.text).toMatch(/not a changed file/);
    expect(unknown.text).toContain("src/orders.ts");
    expect(unknown.text).toContain("owner/repo:path:line");

    for (const p of ["./src/orders.ts", "@pr:src/orders.ts", "acme/api:src/orders.ts:13", "b/src/orders.ts", "SRC/Orders.ts"]) {
      const r = await h.call("add_comment", comment({ path: p }));
      expect(r.isError).toBe(true);
      expect(r.text).toContain('Did you mean "src/orders.ts"?');
    }
    const renamed = await h.call("add_comment", comment({ path: "lib/a.ts", line: 1 }));
    expect(renamed.text).toMatch(/renamed to "lib\/b.ts"/);
    expect(h.text()).toBe("");
  });

  it("rejects ignored, deleted, binary and hunk-less files", async () => {
    const h = await setup();
    const cases: Array<[string, RegExp]> = [
      ["docs/gen.md", /excluded from this review by policy/],
      ["old.txt", /deleted in this PR/],
      ["img.png", /binary file/],
      ["lib/b.ts", /no diff hunks/],
    ];
    for (const [path, re] of cases) {
      const r = await h.call("add_comment", comment({ path, line: 1 }));
      expect(r.isError, path).toBe(true);
      expect(r.text, path).toMatch(re);
    }
    expect(h.text()).toBe("");
  });

  it("only accepts RIGHT-side hunk lines and lists the valid ranges", async () => {
    const h = await setup();
    const outside = await h.call("add_comment", comment({ line: 20 }));
    expect(outside.isError).toBe(true);
    expect(outside.text).toContain("Line 20 of src/orders.ts");
    expect(outside.text).toContain("Commentable lines: 10-17, 42-45.");

    const crossing = await h.call("add_comment", comment({ line: 15, end_line: 43 }));
    expect(crossing.isError).toBe(true);
    expect(crossing.text).toContain("Lines 15-43");
    expect(crossing.text).toContain("10-17, 42-45");

    const reversed = await h.call("add_comment", comment({ line: 14, end_line: 12 }));
    expect(reversed.isError).toBe(true);
    expect(reversed.text).toMatch(/end_line \(12\) must be >= line \(14\)/);

    const zero = await h.call("add_comment", comment({ line: 0 }));
    expect(zero.isError).toBe(true);
    expect(h.text()).toBe("");

    expect((await h.call("add_comment", comment({ line: 10 }))).isError).toBe(false); // context line
    expect((await h.call("add_comment", comment({ line: 12, end_line: 14, body: "range" }))).isError).toBe(false);
    expect((await h.call("add_comment", comment({ path: "src/new.ts", line: 3 }))).isError).toBe(false);
    expect((await h.call("add_comment", comment({ path: ".github/workflows/ci.yml", line: 2 }))).isError).toBe(false);
    const single = await h.call("add_comment", comment({ line: 43, end_line: 43, body: "single" }));
    expect(single.text).toContain("src/orders.ts:43 ");
    const d = h.draft();
    expect(d.comments.map((c) => [c.path, c.line, c.end_line])).toEqual([
      ["src/orders.ts", 10, undefined],
      ["src/orders.ts", 12, 14],
      ["src/new.ts", 3, undefined],
      [".github/workflows/ci.yml", 2, undefined],
      ["src/orders.ts", 43, undefined],
    ]);
  });

  it("enforces min_severity without encouraging inflation", async () => {
    const h = await setup();
    const r = await h.call("add_comment", comment({ severity: "info" }));
    expect(r.isError).toBe(true);
    expect(r.text).toMatch(/below this policy's minimum.*"low"/);
    expect(r.text).toMatch(/Do not raise the severity/);
    const bad = await h.call("add_comment", comment({ severity: "blocker" }));
    expect(bad.isError).toBe(true);
    const lowered = await setup({ inline_comments: { min_severity: "info" } });
    expect((await lowered.call("add_comment", comment({ severity: "info" }))).isError).toBe(false);
  });

  it("enforces max_comment_chars (including the suggestion)", async () => {
    const h = await setup({ inline_comments: { max_comment_chars: 100 } });
    const long = await h.call("add_comment", comment({ body: "x".repeat(101) }));
    expect(long.isError).toBe(true);
    expect(long.text).toMatch(/body 101 chars exceeds this policy's limit of 100/);
    const combined = await h.call("add_comment", comment({ body: "y".repeat(60), suggestion: "z".repeat(30) }));
    expect(combined.isError).toBe(true);
    expect(combined.text).toMatch(/\+ suggestion 30 chars/);
    expect((await h.call("add_comment", comment({ body: "w".repeat(100) }))).isError).toBe(false);
    const blank = await h.call("add_comment", comment({ body: "   \n " }));
    expect(blank.isError).toBe(true);
    expect(h.lines()).toHaveLength(1);
  });

  it("rejects duplicates (whitespace-insensitive) and enforces the comment budget", async () => {
    const h = await setup({ inline_comments: { max_comments: 2 } });
    const first = await h.call("add_comment", comment());
    expect(first).toEqual({ isError: false, text: expect.stringContaining("Recorded comment #1 on src/orders.ts:13 (medium). 1 of 2") });
    const dup = await h.call("add_comment", comment({ body: `  ${comment().body.replace(/ /g, "  ")}\n` }));
    expect(dup.isError).toBe(true);
    expect(dup.text).toMatch(/Duplicate/);
    expect((await h.call("add_comment", comment({ line: 14 }))).isError).toBe(false);
    const over = await h.call("add_comment", comment({ line: 15, body: "another issue" }));
    expect(over.isError).toBe(true);
    expect(over.text).toMatch(/Comment budget exhausted: 2 of 2/);
    expect(h.draft().comments).toHaveLength(2);
  });

  it("rejects text that looks like a secret", async () => {
    const h = await setup();
    const token = `ghp_${"a1".repeat(18)}`;
    const r = await h.call("add_comment", comment({ body: `Hard-coded token ${token} leaks.` }));
    expect(r.isError).toBe(true);
    expect(r.text).toMatch(/secret or credential \(github_token\)/);
    const s = await h.call("set_summary", { body: `password = "hunter2hunter2"` });
    expect(s.isError).toBe(true);
    const v = await h.call("set_verdict", { verdict: "comment", reason: `token ${token}` });
    expect(v.isError).toBe(true);
    expect(h.text()).not.toContain(token);
    expect(h.text()).toBe("");
  });

  it("normalizes category and rejects unknown fields", async () => {
    const h = await setup();
    expect((await h.call("add_comment", comment({ category: "  security " }))).isError).toBe(false);
    expect((await h.call("add_comment", comment({ line: 14, category: "   " }))).isError).toBe(false);
    const extra = await h.call("add_comment", comment({ line: 15, side: "LEFT" }));
    expect(extra.isError).toBe(true);
    const cs = h.draft().comments;
    expect(cs[0]?.category).toBe("security");
    expect(cs[1]).not.toHaveProperty("category");
  });
});

/* ------------------------------ summary/labels ---------------------------- */

describe("set_summary", () => {
  it("enforces max_chars and keeps the last summary", async () => {
    const h = await setup({ summary_comment: { max_chars: 200 } });
    const long = await h.call("set_summary", { body: "s".repeat(201) });
    expect(long.isError).toBe(true);
    expect(long.text).toMatch(/201 chars; this policy allows 200/);
    expect((await h.call("set_summary", { body: "first" })).text).toMatch(/recorded/);
    expect((await h.call("set_summary", { body: "second" })).text).toMatch(/replaced/);
    expect(h.draft().summary).toBe("second");
  });
});

describe("add_labels", () => {
  it("only accepts allowed labels and does not re-write existing ones", async () => {
    const h = await setup({ labels: { enabled: true, allowed: ["needs-tests", "breaking"] } });
    const tool = (await h.tools()).find((t) => t.name === "add_labels");
    expect(tool?.inputSchema.properties?.labels?.items?.enum).toEqual(["needs-tests", "breaking"]);
    expect((await h.call("add_labels", { labels: ["lgtm"] })).isError).toBe(true);
    expect((await h.call("add_labels", { labels: [] })).isError).toBe(true);
    expect((await h.call("add_labels", { labels: ["needs-tests", "needs-tests"] })).isError).toBe(false);
    const again = await h.call("add_labels", { labels: ["needs-tests"] });
    expect(again.text).toMatch(/Already added/);
    expect((await h.call("add_labels", { labels: ["needs-tests", "breaking"] })).text).toMatch(/needs-tests, breaking/);
    expect(h.lines().map((l) => JSON.parse(l))).toEqual([
      { type: "labels", labels: ["needs-tests"] },
      { type: "labels", labels: ["breaking"] },
    ]);
    expect(h.draft().labels).toEqual(["needs-tests", "breaking"]);
  });
});

describe("set_verdict notes", () => {
  it("warns when approval will be downgraded", async () => {
    const h = await setup({ approve: { enabled: true } });
    await h.call("add_comment", comment({ severity: "high" }));
    const r = await h.call("set_verdict", { verdict: "approve", reason: "fine" });
    expect(r.isError).toBe(false);
    expect(r.text).toMatch(/Verdict set to "approve"/);
    expect(r.text).toMatch(/1 recorded finding\(s\) are above "low"/);
    expect(r.text).toMatch(/\.github\/workflows\/ci\.yml, which this policy never auto-approves/);
    expect(h.draft().verdict?.verdict).toBe("approve");
  });

  it("warns when request_changes has no qualifying finding", async () => {
    const h = await setup({ block: { enabled: true } });
    const r1 = await h.call("set_verdict", { verdict: "request_changes", reason: "bug" });
    expect(r1.text).toMatch(/No recorded inline finding has severity >= "high"/);
    await h.call("add_comment", comment({ severity: "critical" }));
    const r2 = await h.call("set_verdict", { verdict: "request_changes", reason: "bug" });
    expect(r2.text).not.toMatch(/Note:/);
  });
});

/* ------------------------------ status/finish ----------------------------- */

describe("review_status", () => {
  it("reports counts, budget, verdict and capabilities", async () => {
    const h = await setup({ block: { enabled: true } });
    await h.call("add_comment", comment({ category: "correctness" }));
    const r = await h.call("review_status");
    expect(r.isError).toBe(false);
    expect(r.text).toContain("Review draft for acme/api#7");
    expect(r.text).toContain("Inline comments: 1 recorded, 14 of 15 left");
    expect(r.text).toContain("1. medium   src/orders.ts:13  [correctness]");
    expect(r.text).toContain("Summary: not set");
    expect(r.text).toContain("Verdict: not set (defaults to comment); allowed: comment, request_changes");
    expect(r.text).toContain('Request-changes rule: at least one finding with severity >= "high"');
    expect(r.text).toContain("Finished: no");
    expect(r.text).toContain("Tools: add_comment, set_summary, set_verdict, review_status, finish");
    expect(h.lines()).toHaveLength(1); // status writes nothing
  });
});

describe("finish", () => {
  it("asks once for a missing summary, then finishes and locks the draft", async () => {
    const h = await setup();
    const first = await h.call("finish");
    expect(first.isError).toBe(true);
    expect(first.text).toMatch(/No summary has been set/);
    const second = await h.call("finish");
    expect(second.isError).toBe(false);
    expect(second.text).toMatch(/Review finished: 0 inline comment\(s\), summary not set, verdict comment \(default\)/);
    for (const [tool, args] of [
      ["add_comment", comment()],
      ["set_summary", { body: "late" }],
      ["set_verdict", { verdict: "comment", reason: "late" }],
    ] as const) {
      const r = await h.call(tool, args);
      expect(r.isError, tool).toBe(true);
      expect(r.text, tool).toMatch(/already finished/);
    }
    expect((await h.call("finish")).text).toMatch(/already finished/);
    expect(h.lines()).toEqual(['{"type":"finish"}']);
    expect((await h.call("review_status")).text).toContain("FINISHED");
  });

  it("finishes immediately when summaries are disabled", async () => {
    const h = await setup({ summary_comment: { enabled: false } });
    expect((await h.call("finish")).isError).toBe(false);
    expect(h.draft().finished).toBe(true);
  });
});

/* ---------------------------------- draft --------------------------------- */

describe("draft output", () => {
  it("writes one valid draft line per accepted call that parseDraft reads back", async () => {
    const h = await setup({ block: { enabled: true }, labels: { enabled: true, allowed: ["needs-tests"] } });
    expect((await h.call("add_comment", comment({ severity: "high", category: "security" }))).isError).toBe(false);
    expect((await h.call("add_comment", comment({ path: "src/new.ts", line: 1, end_line: 3, body: "Unused module.", severity: "low", suggestion: "" }))).isError).toBe(false);
    expect((await h.call("add_comment", comment({ line: 99 }))).isError).toBe(true);
    expect((await h.call("set_summary", { body: "draft" })).isError).toBe(false);
    expect((await h.call("set_summary", { body: "One high-severity validation gap." })).isError).toBe(false);
    expect((await h.call("set_verdict", { verdict: "request_changes", reason: "unvalidated input" })).isError).toBe(false);
    expect((await h.call("add_labels", { labels: ["needs-tests"] })).isError).toBe(false);
    expect((await h.call("review_status")).isError).toBe(false);
    expect((await h.call("finish")).isError).toBe(false);

    const lines = h.lines();
    expect(lines).toHaveLength(7);
    for (const l of lines) expect(DraftEntry.safeParse(JSON.parse(l)).success).toBe(true);
    expect(h.text().endsWith("\n")).toBe(true);

    const d = h.draft();
    expect(d.invalidLines).toBe(0);
    expect(d.finished).toBe(true);
    expect(d.summary).toBe("One high-severity validation gap.");
    expect(d.verdict).toEqual({ type: "verdict", verdict: "request_changes", reason: "unvalidated input" });
    expect(d.labels).toEqual(["needs-tests"]);
    expect(d.comments).toEqual([
      { type: "comment", path: "src/orders.ts", line: 13, body: comment().body, severity: "high", category: "security" },
      { type: "comment", path: "src/new.ts", line: 1, end_line: 3, body: "Unused module.", severity: "low", suggestion: "" },
    ]);
  });

  it("resumes budget, duplicates and summary from an existing draft", async () => {
    const outFile = join(dir, "resume.jsonl");
    writeFileSync(
      outFile,
      [
        JSON.stringify({ type: "comment", path: "src/orders.ts", line: 13, body: "a", severity: "high" }),
        JSON.stringify({ type: "comment", path: "src/orders.ts", line: 14, body: "b", severity: "low" }),
        JSON.stringify({ type: "summary", body: "earlier" }),
        "",
      ].join("\n"),
    );
    const h = await setup({ inline_comments: { max_comments: 3 } }, outFile);
    expect((await h.call("add_comment", comment({ body: "a" }))).text).toMatch(/Duplicate/);
    expect((await h.call("add_comment", comment({ line: 15, body: "c" }))).isError).toBe(false);
    expect((await h.call("add_comment", comment({ line: 16, body: "d" }))).text).toMatch(/budget exhausted: 3 of 3/);
    expect((await h.call("finish")).isError).toBe(false); // summary already present
    const d = h.draft();
    expect(d.comments).toHaveLength(3);
    expect(d.finished).toBe(true);

    const again = await setup({}, outFile);
    expect((await again.call("set_summary", { body: "new" })).text).toMatch(/already finished/);
  });
});

/* ---------------------------------- audit --------------------------------- */

describe("audit", () => {
  it("audits every call, including schema errors and unknown tools, without logging bodies", async () => {
    const auditFile = join(dir, "audit.jsonl");
    process.env.XREPO_AUDIT_FILE = auditFile;
    const h = await setup();
    const secretBody = "UNIQUE-BODY-TEXT-1234 should not appear in audit logs";
    await h.call("add_comment", comment({ body: secretBody }));
    await h.call("add_comment", comment({ path: "nope.ts" }));
    await h.call("set_verdict", { verdict: "approve", reason: "x" });
    await h.call("approve_pr", {});
    await h.call("review_status");

    const raw = readFileSync(auditFile, "utf8");
    expect(raw).not.toContain("UNIQUE-BODY-TEXT-1234");
    const events = raw
      .split("\n")
      .filter((l) => l !== "")
      .map((l) => JSON.parse(l) as Record<string, unknown>)
      .filter((e) => e.event === "xreview.call");
    expect(events.map((e) => [e.tool, e.ok])).toEqual([
      ["add_comment", true],
      ["add_comment", false],
      ["set_verdict", false],
      ["approve_pr", false],
      ["review_status", true],
    ]);
    const first = events[0]!.args as Record<string, unknown>;
    expect(first.path).toBe("src/orders.ts");
    expect(first.body_chars).toBe(secretBody.length);
    expect(first.body_sha256).toMatch(/^[0-9a-f]{16}$/);
    expect(String(events[1]!.error)).toMatch(/not a changed file/);
  });
});

/* ----------------------------------- main --------------------------------- */

describe("main", () => {
  function writeCtx(policy: ResolvedPolicy, context: PrContext = ctx): string {
    const ctxDir = mkdtempSync(join(dir, "ctx-"));
    writeFileSync(join(ctxDir, CTX_FILES.pr), JSON.stringify(context));
    writeFileSync(join(ctxDir, CTX_FILES.diff), DIFF);
    writeFileSync(join(ctxDir, CTX_FILES.policy), JSON.stringify(policy));
    return ctxDir;
  }

  it("returns 2 on usage errors", async () => {
    expect(await main([])).toBe(2);
    expect(await main(["--ctx", dir])).toBe(2);
    expect(await main(["--ctx", dir, "--out", join(dir, "x.jsonl"), "--bogus"])).toBe(2);
  });

  it("returns 1 when inputs are missing or inconsistent", async () => {
    expect(await main(["--ctx", join(dir, "nope"), "--out", join(dir, "x.jsonl")])).toBe(1);
    const otherRepo = resolvePolicy(parsePolicy("version: 1\n"), "acme/other");
    expect(await main(["--ctx", writeCtx(otherRepo), "--out", join(dir, "x.jsonl")])).toBe(1);
    expect(await main(["--ctx", writeCtx(policyWith()), "--out", join(dir, "no-such-dir", "draft.jsonl")])).toBe(1);
  });

  it("serves xreview over stdio until stdin closes", async () => {
    const policy = policyWith({ approve: { enabled: true } });
    const ctxDir = writeCtx(policy);
    const outFile = join(dir, "main-draft.jsonl");
    const stdin = new PassThrough();
    const stdout = new PassThrough();
    const done = main(["--ctx", ctxDir, "--out", outFile], { stdin, stdout });

    const client = new Client({ name: "test", version: "0.0.0" });
    await client.connect(new StdioServerTransport(stdout, stdin));
    const names = (await client.listTools()).tools.map((t) => t.name);
    expect(names).toEqual(reviewToolNames(policy));
    const r = await client.callTool({ name: "add_comment", arguments: comment() });
    expect(r.isError).toBeFalsy();
    const v = await client.callTool({ name: "set_verdict", arguments: { verdict: "approve", reason: "ok" } });
    expect(v.isError).toBeFalsy();

    stdin.end();
    expect(await done).toBe(0);
    const d = parseDraft(readFileSync(outFile, "utf8"));
    expect(d.comments).toHaveLength(1);
    expect(d.verdict?.verdict).toBe("approve");
    await client.close().catch(() => undefined);
  });
});

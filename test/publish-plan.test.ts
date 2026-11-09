import { describe, expect, it } from "vitest";
import type { PrContext, PrFile } from "../src/common/context.js";
import { parseUnifiedDiff, type FileDiff } from "../src/common/diff.js";
import type { Draft, DraftComment } from "../src/common/draft.js";
import { parsePolicy, resolvePolicy } from "../src/policy/load.js";
import type { ResolvedPolicy } from "../src/policy/schema.js";
import {
  buildPlan,
  commentKey,
  commentMarker,
  extractCommentKeys,
  STICKY_MARKER,
  stickyCommentBody,
  type BuildPlanInput,
} from "../src/publish/plan.js";

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

  it("truncates bodies to max_comment_chars (marker excluded)", () => {
    const p = plan({
      policy: pol({ capabilities: { inline_comments: { max_comment_chars: 300 } } }),
      draft: draft({ comments: [cmt("src/orders.ts", 13, "medium", "word ".repeat(400))] }),
    });
    const body = p.review!.comments[0]!.body;
    const visible = body.slice(0, body.lastIndexOf("\n\n<!-- xrepo:c:"));
    expect(visible.length).toBeLessThanOrEqual(300);
    expect(visible).toContain("(truncated)");
    expect(p.stats.truncated).toBe(1);
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
    expect(p.review!.body).toBe(p.summary);
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

  it("respects summary_comment.max_chars", () => {
    const p = plan({
      policy: pol({ capabilities: { summary_comment: { max_chars: 1000 } } }),
      draft: draft({ summary: "lorem ipsum ".repeat(500), comments: Array.from({ length: 30 }, (_, i) => cmt("src/x.ts", i + 1, "medium", `note ${i} `.repeat(20))) }),
    });
    expect(p.summary.length).toBeLessThanOrEqual(1000);
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

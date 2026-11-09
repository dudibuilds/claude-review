/**
 * xreview MCP server: the agent's only way to act on the PR (`xrepo review-mcp`).
 *
 * Every accepted tool call appends exactly one JSON line (src/common/draft.ts) to the draft file.
 * A separate deterministic publisher re-validates the draft against the policy and posts it; the
 * checks here mirror the publisher so the agent gets immediate, actionable feedback.
 *
 * Security properties:
 * - Only capabilities enabled by the resolved policy are registered, so the agent never sees the
 *   others. set_verdict's enum lists only the allowed verdicts and add_labels' enum only the allowed
 *   labels.
 * - Inputs (policy, PR context, diff) are read once at startup from paths given as trusted CLI args.
 *   During tool calls the server only appends to the draft file: no other reads or writes, no
 *   network, no subprocesses.
 * - Text that looks like a secret is rejected, so it never reaches the draft (which is uploaded as
 *   a workflow artifact) or the PR.
 * - Every tools/call request is audited, including calls the SDK rejects before a tool callback
 *   runs (schema errors, unknown tools). Bodies are logged as length + hash only.
 */
import { createHash } from "node:crypto";
import { appendFileSync, readFileSync } from "node:fs";
import { basename, join } from "node:path";
import type { Readable, Writable } from "node:stream";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { CallToolRequestSchema, type CallToolResult } from "@modelcontextprotocol/sdk/types.js";
import { z } from "zod";
import { parseCli } from "../common/args.js";
import { audit } from "../common/audit.js";
import { CTX_FILES, readContext, type PrContext } from "../common/context.js";
import { isCommentable, parseUnifiedDiff, type FileDiff } from "../common/diff.js";
import { DraftEntry, MAX_BODY_CHARS, parseDraft, type DraftComment, type DraftVerdict } from "../common/draft.js";
import { redactSecrets } from "../common/redact.js";
import { compileGlobs } from "../policy/glob.js";
import { readResolvedPolicy } from "../policy/load.js";
import { Severity, severityRank, type ResolvedPolicy } from "../policy/schema.js";

export const REVIEW_SERVER_NAME = "xreview";
const VERSION = "0.1.0";

type Verdict = DraftVerdict["verdict"];

/** Caps on repeated "last call wins" writes (keeps the draft far below parseDraft's 500 lines). */
const MAX_SUMMARY_WRITES = 20;
const MAX_VERDICT_WRITES = 20;
const MAX_LABEL_WRITES = 20;
const MAX_LABELS_PER_CALL = 20;
/** Characters the publisher adds around a suggestion: "\n\n```suggestion\n" + "\n```". */
const SUGGESTION_OVERHEAD = 20;
const MAX_LISTED_RANGES = 40;
const MAX_LISTED_FILES = 15;

const FINISHED_MSG = "The review is already finished (finish was called); no further changes are accepted.";

const SEVERITY_RUBRIC =
  "Severity: critical = exploitable vulnerability, data loss/corruption, outage, or a definite break of " +
  "another repo's contract in production; high = definite bug on a realistic path, missing auth/validation, " +
  "breaking API change for a known consumer; medium = bug in edge cases, missing error handling, race, " +
  "real performance problem; low = minor bug risk, maintainability, misleading names/docs, missing test for " +
  "risky logic; info = question or observation, not a defect.";

/* ------------------------------ capabilities ----------------------------- */

function commentsEnabled(policy: ResolvedPolicy): boolean {
  const ic = policy.capabilities.inline_comments;
  return ic.enabled && ic.max_comments > 0;
}

function allowedLabels(policy: ResolvedPolicy): string[] {
  const labels = policy.capabilities.labels;
  return labels.enabled ? [...new Set(labels.allowed)] : [];
}

/** Verdicts the agent may choose: always "comment", plus approve / request_changes when enabled. */
export function allowedVerdicts(policy: ResolvedPolicy): Verdict[] {
  const out: Verdict[] = ["comment"];
  if (policy.capabilities.approve.enabled) out.push("approve");
  if (policy.capabilities.block.enabled) out.push("request_changes");
  return out;
}

/**
 * Exactly the tools createReviewServer registers for this policy, in registration order (bare
 * names; prepare prefixes them with `mcp__xreview__` for --allowedTools).
 */
export function reviewToolNames(policy: ResolvedPolicy): string[] {
  const names: string[] = [];
  if (commentsEnabled(policy)) names.push("add_comment");
  if (policy.capabilities.summary_comment.enabled) names.push("set_summary");
  names.push("set_verdict");
  if (allowedLabels(policy).length > 0) names.push("add_labels");
  names.push("review_status", "finish");
  return names;
}

/* --------------------------------- helpers -------------------------------- */

const ok = (text: string): CallToolResult => ({ content: [{ type: "text", text }] });
const fail = (text: string): CallToolResult => ({ content: [{ type: "text", text }], isError: true });

function sha256(s: string): string {
  return createHash("sha256").update(s, "utf8").digest("hex");
}

/** Duplicate key, matching the publisher's (path, line, body hash) dedupe; whitespace-insensitive. */
function commentKey(path: string, line: number, body: string): string {
  return `${path}\n${line}\n${sha256(body.replace(/\s+/g, " ").trim())}`;
}

function lineRange(line: number, end?: number): string {
  return end !== undefined && end !== line ? `${line}-${end}` : `${line}`;
}

function clip(s: string, max: number): string {
  return s.length > max ? `${s.slice(0, max)}…` : s;
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

/** Contiguous RIGHT-side line runs of each hunk (what isCommentable accepts). */
function rightRanges(fd: FileDiff): Array<[number, number]> {
  const out: Array<[number, number]> = [];
  for (const h of fd.hunks) {
    if (h.newLines <= 0) continue;
    const last = h.newStart + h.newLines - 1;
    let start = -1;
    for (let n = h.newStart; n <= last + 1; n++) {
      const inside = n <= last && fd.rightLines.has(n);
      if (inside && start < 0) start = n;
      else if (!inside && start >= 0) {
        out.push([start, n - 1]);
        start = -1;
      }
    }
  }
  return out;
}

function formatRanges(fd: FileDiff): string {
  const ranges = rightRanges(fd);
  const shown = ranges.slice(0, MAX_LISTED_RANGES).map(([a, b]) => (a === b ? `${a}` : `${a}-${b}`));
  const more = ranges.length > MAX_LISTED_RANGES ? ` (+${ranges.length - MAX_LISTED_RANGES} more; see pr_diff)` : "";
  return `${shown.join(", ")}${more}`;
}

/** Error text if `text` contains something redactSecrets treats as a secret. */
function secretProblem(field: string, text: string | undefined): string | null {
  if (text === undefined || text === "") return null;
  const r = redactSecrets(text);
  if (r.count === 0) return null;
  const kinds = [...new Set([...r.text.matchAll(/\[REDACTED:([^\]\s]{1,40})\]/g)].map((m) => m[1]))];
  return (
    `${field} appears to contain a secret or credential (${kinds.join(", ") || "secret"}). Never quote ` +
    `secrets in a review: say where it is instead (e.g. "hard-coded API key at owner/repo:path:line") and ` +
    `recommend rotating it.`
  );
}

/** Metadata-only view of tool arguments for the audit log (comment text as length + hash). */
function summarizeArgs(args: unknown): unknown {
  if (args === undefined) return undefined;
  if (!isRecord(args)) return `[${Array.isArray(args) ? "array" : typeof args}]`;
  const out: Record<string, unknown> = {};
  let n = 0;
  for (const [k, v] of Object.entries(args)) {
    if (n++ >= 20) {
      out["…"] = "truncated";
      break;
    }
    const key = clip(k, 60);
    if ((k === "body" || k === "suggestion") && typeof v === "string") {
      out[`${key}_chars`] = v.length;
      out[`${key}_sha256`] = sha256(v).slice(0, 16);
    } else if (typeof v === "string") out[key] = clip(v, 300);
    else if (typeof v === "number" || typeof v === "boolean" || v === null) out[key] = v;
    else if (Array.isArray(v)) out[key] = v.slice(0, 20).map((x) => (typeof x === "string" ? clip(x, 60) : typeof x));
    else out[key] = `[${typeof v}]`;
  }
  return out;
}

function resultText(result: unknown): string {
  if (!isRecord(result) || !Array.isArray(result.content)) return "";
  const first: unknown = result.content[0];
  return isRecord(first) && typeof first.text === "string" ? first.text : "";
}

function auditCall(tool: string, args: unknown, result: unknown, ms: number): void {
  const isError = isRecord(result) && result.isError === true;
  const text = clip(resultText(result), 300);
  audit("xreview.call", {
    tool,
    ok: !isError,
    ms,
    args: summarizeArgs(args),
    ...(isError ? { error: text } : { result: text }),
  });
}

/* ---------------------------------- state --------------------------------- */

interface ReviewState {
  comments: DraftComment[];
  commentKeys: Set<string>;
  summary?: string;
  summaryWrites: number;
  verdict?: { verdict: Verdict; reason: string };
  verdictWrites: number;
  labels: string[];
  labelWrites: number;
  finished: boolean;
  /** finish() without a summary is refused once, then accepted. */
  finishWarned: boolean;
}

/**
 * Starts from the existing draft file (if any) so a restarted server keeps its budget, duplicate
 * detection and finished flag. This reads only the server's own output file.
 */
function loadState(outFile: string): ReviewState {
  const st: ReviewState = {
    comments: [],
    commentKeys: new Set(),
    summaryWrites: 0,
    verdictWrites: 0,
    labels: [],
    labelWrites: 0,
    finished: false,
    finishWarned: false,
  };
  let text: string;
  try {
    text = readFileSync(outFile, "utf8");
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code !== "ENOENT") audit("xreview.resume_failed", { error: e });
    return st;
  }
  if (text.trim() === "") return st;
  const d = parseDraft(text);
  for (const c of d.comments) {
    st.comments.push(c);
    st.commentKeys.add(commentKey(c.path, c.line, c.body));
  }
  if (d.summary !== undefined) {
    st.summary = d.summary;
    st.summaryWrites = 1;
  }
  if (d.verdict) {
    st.verdict = { verdict: d.verdict.verdict, reason: d.verdict.reason };
    st.verdictWrites = 1;
  }
  st.labels = [...d.labels];
  st.labelWrites = d.labels.length > 0 ? 1 : 0;
  st.finished = d.finished;
  audit("xreview.resume", {
    comments: st.comments.length,
    summary: st.summary !== undefined,
    verdict: st.verdict?.verdict,
    labels: st.labels,
    finished: st.finished,
    invalid_lines: d.invalidLines,
  });
  return st;
}

/* --------------------------------- server --------------------------------- */

export interface ReviewServerOptions {
  policy: ResolvedPolicy;
  ctx: PrContext;
  diff: FileDiff[];
  /** The draft file; the only file this server writes (append-only). */
  outFile: string;
}

interface AddCommentArgs {
  path: string;
  line: number;
  end_line?: number;
  body: string;
  severity: Severity;
  category?: string;
  suggestion?: string;
}

type AnyHandler = (request: unknown, extra: unknown) => unknown;

export function createReviewServer(opts: ReviewServerOptions): McpServer {
  const { policy, ctx, outFile } = opts;
  const caps = policy.capabilities;
  const ic = caps.inline_comments;
  const sc = caps.summary_comment;
  const toolNames = reviewToolNames(policy);
  const verdicts = allowedVerdicts(policy);
  const labelsAllowed = allowedLabels(policy);

  const files = new Map(ctx.files.map((f) => [f.path, f] as const));
  const ignored = new Set(ctx.ignored_files);
  const diffs = new Map<string, FileDiff>();
  for (const fd of opts.diff) if (!diffs.has(fd.path)) diffs.set(fd.path, fd);
  const changedPaths = [...new Set([...ctx.files.map((f) => f.path), ...ctx.ignored_files])];

  const state = loadState(outFile);

  const server = new McpServer(
    { name: REVIEW_SERVER_NAME, version: VERSION },
    { instructions: serverInstructions(toolNames), maxToolInputElements: 200 },
  );

  /* ---- audit every tools/call: wrap McpServer's own handler as it is installed ---- */
  let callAuditInstalled = false;
  const low = server.server as unknown as { setRequestHandler: (schema: unknown, handler: AnyHandler) => void };
  const originalSet = low.setRequestHandler.bind(low);
  low.setRequestHandler = (schema, handler) => {
    const method = (schema as { shape?: { method?: { value?: unknown } } } | null)?.shape?.method?.value;
    if (schema === CallToolRequestSchema || method === "tools/call") {
      callAuditInstalled = true;
      originalSet(schema, async (request: unknown, extra: unknown) => {
        const t0 = Date.now();
        const params = isRecord(request) && isRecord(request.params) ? request.params : {};
        const tool = typeof params.name === "string" ? clip(params.name, 100) : "(invalid)";
        try {
          const result = await handler(request, extra);
          auditCall(tool, params.arguments, result, Date.now() - t0);
          return result;
        } catch (e) {
          audit("xreview.call", { tool, ok: false, ms: Date.now() - t0, args: summarizeArgs(params.arguments), error: e });
          throw e;
        }
      });
      return;
    }
    originalSet(schema, handler);
  };

  /** Runs a tool body; audits here only if the protocol-level wrapper could not be installed. */
  const run = (tool: string, args: unknown, fn: () => CallToolResult): CallToolResult => {
    let result: CallToolResult;
    try {
      result = fn();
    } catch (e) {
      audit("xreview.internal_error", { tool, error: e });
      result = fail(`Internal error in ${tool}; the call was not recorded.`);
    }
    if (!callAuditInstalled) auditCall(tool, args, result, 0);
    return result;
  };

  /** Validates against the draft schema and appends one line. Returns an error text or null. */
  const append = (entry: z.input<typeof DraftEntry>): string | null => {
    const parsed = DraftEntry.safeParse(entry);
    if (!parsed.success) {
      const issues = parsed.error.issues.map((i) => `${i.path.join(".") || "entry"}: ${i.message}`).join("; ");
      return `The entry does not match the draft format (${issues}); it was not recorded.`;
    }
    try {
      appendFileSync(outFile, `${JSON.stringify(parsed.data)}\n`, { encoding: "utf8", mode: 0o644 });
      return null;
    } catch (e) {
      audit("xreview.write_failed", { error: e });
      return "Internal error: the draft file could not be written; the call was not recorded.";
    }
  };

  /* ---- path / line validation ---- */

  const guessPath = (input: string): string | undefined => {
    const repo = ctx.repo.toLowerCase();
    let s = input.trim().replace(/\\/g, "/");
    for (let i = 0; i < 6; i++) {
      const before = s;
      s = s.replace(/:\d+(?:-\d+)?$/, "").replace(/^(?:\.\/)+/, "").replace(/^\/+/, "");
      if (s.startsWith("@pr:") || s.startsWith("@pr/")) s = s.slice(4);
      const lower = s.toLowerCase();
      if (lower.startsWith(`${repo}:`) || lower.startsWith(`${repo}/`)) s = s.slice(repo.length + 1);
      if ((s.startsWith("a/") || s.startsWith("b/")) && files.has(s.slice(2))) s = s.slice(2);
      if (s === before) break;
    }
    if (s !== input && files.has(s)) return s;
    const lower = s.toLowerCase();
    const ci = ctx.files.filter((f) => f.path.toLowerCase() === lower);
    if (ci.length === 1) return ci[0]!.path;
    const base = basename(s);
    const sameBase = base === "" ? [] : ctx.files.filter((f) => basename(f.path) === base);
    if (sameBase.length === 1) return sameBase[0]!.path;
    return undefined;
  };

  const unknownPathMessage = (input: string): string => {
    const renamed = ctx.files.find((f) => f.previous_path !== undefined && f.previous_path === input);
    if (renamed) return `"${input}" was renamed to "${renamed.path}" in this PR; comment on the new path.`;
    const guess = guessPath(input);
    if (guess !== undefined) {
      return `"${input}" is not a changed file in this PR. Did you mean "${guess}"? Use the repo-relative path exactly as pr_overview lists it.`;
    }
    const listed = ctx.files.slice(0, MAX_LISTED_FILES).map((f) => f.path);
    const more = ctx.files.length > MAX_LISTED_FILES ? ` (+${ctx.files.length - MAX_LISTED_FILES} more; see pr_overview)` : "";
    return (
      `"${input}" is not a changed file in this PR. Inline comments are only possible on the PR's changed ` +
      `files; cite other repos or unchanged files as owner/repo:path:line inside a comment or the summary. ` +
      `Changed files: ${listed.join(", ") || "(none)"}${more}.`
    );
  };

  const checkPath = (path: string): { fd: FileDiff } | { error: string } => {
    if (ignored.has(path)) {
      return { error: `"${path}" is excluded from this review by policy (triggers.ignore_paths) and cannot get inline comments.` };
    }
    const f = files.get(path);
    if (!f) return { error: unknownPathMessage(path) };
    const fd = diffs.get(path);
    if (f.status === "removed" || fd?.status === "removed") {
      return { error: `"${path}" is deleted in this PR, so it has no new-side lines to comment on. Mention it in the summary instead.` };
    }
    if (f.status === "binary" || fd?.status === "binary") {
      return { error: `"${path}" is a binary file and cannot get inline comments. Mention it in the summary instead.` };
    }
    if (!fd || !fd.hunks.some((h) => h.newLines > 0)) {
      return {
        error: `"${path}" has no diff hunks with new-side lines (e.g. a pure rename or mode change), so it cannot get inline comments. Mention it in the summary instead.`,
      };
    }
    return { fd };
  };

  /* ---- verdict heads-up (the publisher decides; these are non-binding notes) ---- */

  const neverApprove = compileGlobs(caps.approve.never_paths);
  const verdictNotes = (verdict: Verdict): string[] => {
    const notes: string[] = [];
    if (verdict === "approve") {
      const maxAllowed = caps.approve.max_severity_allowed;
      const above = state.comments.filter((c) => severityRank(c.severity) > severityRank(maxAllowed));
      if (above.length > 0) {
        notes.push(`${above.length} recorded finding(s) are above "${maxAllowed}"; the publisher will downgrade the approval to comment.`);
      }
      const never = changedPaths.filter((p) => neverApprove(p));
      if (never.length > 0) {
        const list = never.slice(0, 5).join(", ") + (never.length > 5 ? ` (+${never.length - 5} more)` : "");
        notes.push(`This PR changes ${list}, which this policy never auto-approves; the verdict will be published as comment.`);
      }
      if (ctx.changed_lines > caps.approve.max_changed_lines) {
        notes.push(
          `This PR changes ${ctx.changed_lines} lines; approval is limited to ${caps.approve.max_changed_lines}, so it will be published as comment.`,
        );
      }
    } else if (verdict === "request_changes") {
      const min = caps.block.min_severity;
      if (!state.comments.some((c) => severityRank(c.severity) >= severityRank(min))) {
        notes.push(
          `No recorded inline finding has severity >= "${min}" yet. request_changes is only published with at least one such finding; otherwise it is downgraded to comment.`,
        );
      }
    }
    return notes;
  };

  /* ---- status ---- */

  const statusText = (): string => {
    const out: string[] = [];
    out.push(`Review draft for ${ctx.repo}#${ctx.number}${state.finished ? " (FINISHED: no further changes accepted)" : ""}`);
    if (commentsEnabled(policy)) {
      const left = Math.max(0, ic.max_comments - state.comments.length);
      out.push(
        `Inline comments: ${state.comments.length} recorded, ${left} of ${ic.max_comments} left ` +
          `(severity >= ${ic.min_severity}, <= ${ic.max_comment_chars} chars, suggestions ${ic.suggestions ? "allowed" : "disabled"})`,
      );
      for (const [i, c] of state.comments.entries()) {
        out.push(`  ${i + 1}. ${c.severity.padEnd(8)} ${c.path}:${lineRange(c.line, c.end_line)}${c.category ? `  [${c.category}]` : ""}`);
      }
    } else {
      out.push("Inline comments: disabled by policy");
    }
    if (sc.enabled) {
      out.push(
        state.summary !== undefined
          ? `Summary: set (${state.summary.length} of max ${sc.max_chars} chars)`
          : `Summary: not set (max ${sc.max_chars} chars)`,
      );
    } else {
      out.push("Summary: disabled by policy");
    }
    out.push(
      `Verdict: ${state.verdict ? `${state.verdict.verdict} (${clip(state.verdict.reason, 200)})` : "not set (defaults to comment)"}; allowed: ${verdicts.join(", ")}`,
    );
    if (labelsAllowed.length > 0) {
      out.push(`Labels: ${state.labels.join(", ") || "none"}; allowed: ${labelsAllowed.join(", ")}`);
    }
    if (caps.approve.enabled) {
      out.push(
        `Approve rule: no finding above "${caps.approve.max_severity_allowed}", no changed file matching ` +
          `${caps.approve.never_paths.join(", ") || "(none)"}, <= ${caps.approve.max_changed_lines} changed lines (this PR: ${ctx.changed_lines})`,
      );
    }
    if (caps.block.enabled) out.push(`Request-changes rule: at least one finding with severity >= "${caps.block.min_severity}"`);
    out.push(`Finished: ${state.finished ? "yes" : "no (call finish last)"}`);
    out.push(`Tools: ${toolNames.join(", ")}`);
    return out.join("\n");
  };

  const writeAnnotations = { readOnlyHint: false, destructiveHint: false, openWorldHint: false } as const;

  /* ---- add_comment ---- */
  if (commentsEnabled(policy)) {
    const shape: z.ZodRawShape = {
      path: z
        .string()
        .min(1)
        .max(1024)
        .describe("Repo-relative path of a changed file, exactly as pr_overview lists it (e.g. src/api/orders.ts)."),
      line: z.number().int().min(1).describe("Line number in the NEW version of the file (RIGHT side); first line of a range."),
      end_line: z
        .number()
        .int()
        .min(1)
        .optional()
        .describe("Last line of a multi-line range (must be in the same diff hunk). Omit for a single line."),
      body: z
        .string()
        .min(1)
        .describe(`Markdown: the issue, why it matters, how to fix. Max ${ic.max_comment_chars} chars${ic.suggestions ? " including the suggestion" : ""}.`),
      severity: Severity.describe("critical | high | medium | low | info (see the rubric in the tool description)."),
      category: z
        .string()
        .max(60)
        .optional()
        .describe("Short tag, e.g. correctness, security, cross-repo-contract, error-handling, performance, tests."),
    };
    if (ic.suggestions) {
      shape.suggestion = z
        .string()
        .max(MAX_BODY_CHARS)
        .optional()
        .describe(
          "Optional exact replacement for lines line..end_line (GitHub suggestion): only the new code with its indentation, no ``` fences. Use only for small, certain fixes.",
        );
    }
    server.registerTool(
      "add_comment",
      {
        title: "Add inline review comment",
        description:
          "Add an inline comment on a changed line of the PR (new/RIGHT side; only lines inside diff hunks, see pr_diff). " +
          "One issue per comment. Make it actionable: what is wrong, why it matters (impact), how to fix. Only report " +
          "issues you verified; cite cross-repo evidence as owner/repo:path:line (e.g. acme/web:src/api/orders.ts:42). " +
          "No praise, no restating the code, no style nits. " +
          `${SEVERITY_RUBRIC} Policy: at most ${ic.max_comments} comments in total (spend them on the most important ` +
          `issues), severity >= ${ic.min_severity}, max ${ic.max_comment_chars} chars.` +
          (ic.suggestions ? " Optional `suggestion` = exact replacement code for the commented lines." : " Suggestion blocks are disabled."),
        inputSchema: z.object(shape).strict(),
        annotations: { ...writeAnnotations, idempotentHint: false },
      },
      (args) =>
        run("add_comment", args, () => {
          const a = args as AddCommentArgs;
          if (state.finished) return fail(FINISHED_MSG);
          if (state.comments.length >= ic.max_comments) {
            return fail(
              `Comment budget exhausted: ${state.comments.length} of ${ic.max_comments} inline comments already recorded. ` +
                (sc.enabled ? "Put any remaining points in the summary." : "Keep only the most important points."),
            );
          }
          const pc = checkPath(a.path);
          if ("error" in pc) return fail(pc.error);
          let end = a.end_line;
          if (end !== undefined && end < a.line) return fail(`end_line (${end}) must be >= line (${a.line}).`);
          if (end === a.line) end = undefined;
          if (!isCommentable(pc.fd, a.line, end)) {
            const what = end === undefined ? `Line ${a.line}` : `Lines ${a.line}-${end}`;
            return fail(
              `${what} of ${a.path} ${end === undefined ? "is" : "are"} not inside a single diff hunk on the RIGHT (new) side, ` +
                `so ${end === undefined ? "it" : "they"} cannot get an inline comment. Commentable lines: ${formatRanges(pc.fd)}. ` +
                `Pick a line inside one of these ranges (a multi-line range must stay within one), or mention the point in the summary.`,
            );
          }
          if (severityRank(a.severity) < severityRank(ic.min_severity)) {
            return fail(
              `Severity "${a.severity}" is below this policy's minimum for inline comments ("${ic.min_severity}"), so it would not be posted. ` +
                `Do not raise the severity to get it posted; mention it in the summary if it matters.`,
            );
          }
          const body = a.body;
          if (body.trim() === "") return fail("body must not be empty.");
          const suggestion = a.suggestion;
          const total = body.length + (suggestion !== undefined ? suggestion.length + SUGGESTION_OVERHEAD : 0);
          if (total > ic.max_comment_chars) {
            return fail(
              `Comment too long: body ${body.length} chars${suggestion !== undefined ? ` + suggestion ${suggestion.length} chars` : ""} ` +
                `exceeds this policy's limit of ${ic.max_comment_chars}. Shorten it: state the issue, impact and fix concisely.`,
            );
          }
          if (!ic.suggestions && /(`{3,}|~{3,})\s*suggestion\b/i.test(body)) {
            return fail("Suggestion blocks are disabled by this policy; describe the fix in prose instead.");
          }
          if (suggestion !== undefined && /^\s*(`{3,}|~{3,})/.test(suggestion)) {
            return fail("Pass only the replacement code in `suggestion`, without ``` fences; it is wrapped in a suggestion block automatically.");
          }
          const category = a.category?.trim() || undefined;
          const secret = secretProblem("body", body) ?? secretProblem("suggestion", suggestion) ?? secretProblem("category", category);
          if (secret) return fail(secret);
          const key = commentKey(a.path, a.line, body);
          if (state.commentKeys.has(key)) {
            return fail(`Duplicate: an identical comment on ${a.path}:${a.line} was already recorded.`);
          }
          const entry: DraftComment = {
            type: "comment",
            path: a.path,
            line: a.line,
            ...(end !== undefined ? { end_line: end } : {}),
            body,
            severity: a.severity,
            ...(category !== undefined ? { category } : {}),
            ...(suggestion !== undefined ? { suggestion } : {}),
          };
          const err = append(entry);
          if (err) return fail(err);
          state.comments.push(entry);
          state.commentKeys.add(key);
          const left = ic.max_comments - state.comments.length;
          return ok(
            `Recorded comment #${state.comments.length} on ${a.path}:${lineRange(a.line, end)} (${a.severity}). ` +
              `${left} of ${ic.max_comments} inline comments left.`,
          );
        }),
    );
  }

  /* ---- set_summary ---- */
  if (sc.enabled) {
    server.registerTool(
      "set_summary",
      {
        title: "Set review summary",
        description:
          `Set the overall review summary (markdown), posted as ${sc.mode === "sticky" ? "the PR's sticky review comment" : "the review body"}. ` +
          "Last call wins: always send the complete text. Structure: a 1-2 sentence assessment; key risks, most severe first; " +
          "cross-repo impact with owner/repo:path:line evidence; points that do not fit an inline comment; what you could not verify. " +
          `Do not repeat every inline comment. Max ${sc.max_chars} chars.`,
        inputSchema: z.object({ body: z.string().min(1).describe(`Summary markdown, max ${sc.max_chars} chars.`) }).strict(),
        annotations: { ...writeAnnotations, idempotentHint: true },
      },
      (args) =>
        run("set_summary", args, () => {
          const body = (args as { body: string }).body;
          if (state.finished) return fail(FINISHED_MSG);
          if (body.trim() === "") return fail("body must not be empty.");
          if (body.length > sc.max_chars) {
            return fail(`Summary too long: ${body.length} chars; this policy allows ${sc.max_chars}. Shorten it (inline comments carry the details).`);
          }
          const secret = secretProblem("body", body);
          if (secret) return fail(secret);
          if (state.summaryWrites >= MAX_SUMMARY_WRITES) {
            return fail(`set_summary was already called ${state.summaryWrites} times; no more updates are accepted. Call finish.`);
          }
          const replaced = state.summary !== undefined;
          const err = append({ type: "summary", body });
          if (err) return fail(err);
          state.summary = body;
          state.summaryWrites++;
          return ok(`Summary ${replaced ? "replaced" : "recorded"} (${body.length} chars).`);
        }),
    );
  }

  /* ---- set_verdict ---- */
  {
    const lines = [`Set the review verdict (last call wins). Allowed: ${verdicts.join(", ")}.`, "comment = feedback without approving or blocking (default)."];
    if (verdicts.includes("approve")) {
      lines.push(
        `approve = only when you checked the change and found nothing above "${caps.approve.max_severity_allowed}". ` +
          `Never approved when the PR touches ${caps.approve.never_paths.join(", ") || "(no paths)"} or changes more than ${caps.approve.max_changed_lines} lines.`,
      );
    }
    if (verdicts.includes("request_changes")) {
      lines.push(`request_changes = only when at least one inline comment has severity >= "${caps.block.min_severity}".`);
    }
    lines.push("The publisher re-checks these rules and downgrades to comment if one fails.");
    server.registerTool(
      "set_verdict",
      {
        title: "Set review verdict",
        description: lines.join(" "),
        inputSchema: z
          .object({
            verdict: z.enum(verdicts as [Verdict, ...Verdict[]]).describe(`One of: ${verdicts.join(", ")}.`),
            reason: z.string().min(1).max(2000).describe("One or two sentences justifying the verdict."),
          })
          .strict(),
        annotations: { ...writeAnnotations, idempotentHint: true },
      },
      (args) =>
        run("set_verdict", args, () => {
          const a = args as { verdict: Verdict; reason: string };
          if (state.finished) return fail(FINISHED_MSG);
          if (!verdicts.includes(a.verdict)) return fail(`Verdict "${a.verdict}" is not allowed. Allowed: ${verdicts.join(", ")}.`);
          const reason = a.reason.trim();
          if (reason === "") return fail("reason must not be empty.");
          const secret = secretProblem("reason", reason);
          if (secret) return fail(secret);
          if (state.verdictWrites >= MAX_VERDICT_WRITES) {
            return fail(`set_verdict was already called ${state.verdictWrites} times; no more updates are accepted. Call finish.`);
          }
          const err = append({ type: "verdict", verdict: a.verdict, reason });
          if (err) return fail(err);
          state.verdict = { verdict: a.verdict, reason };
          state.verdictWrites++;
          const notes = verdictNotes(a.verdict);
          return ok([`Verdict set to "${a.verdict}".`, ...notes.map((n) => `Note: ${n}`)].join("\n"));
        }),
    );
  }

  /* ---- add_labels ---- */
  if (labelsAllowed.length > 0) {
    server.registerTool(
      "add_labels",
      {
        title: "Add PR labels",
        description: `Add labels to the PR. Allowed: ${labelsAllowed.join(", ")}. Only add labels that clearly apply. Labels cannot be removed.`,
        inputSchema: z
          .object({
            labels: z
              .array(z.enum(labelsAllowed as [string, ...string[]]))
              .min(1)
              .max(MAX_LABELS_PER_CALL)
              .describe(`Labels to add; each one of: ${labelsAllowed.join(", ")}.`),
          })
          .strict(),
        annotations: { ...writeAnnotations, idempotentHint: true },
      },
      (args) =>
        run("add_labels", args, () => {
          const requested = [...new Set((args as { labels: string[] }).labels)];
          if (state.finished) return fail(FINISHED_MSG);
          const bad = requested.filter((l) => !labelsAllowed.includes(l));
          if (bad.length > 0) return fail(`Label(s) not allowed: ${bad.join(", ")}. Allowed: ${labelsAllowed.join(", ")}.`);
          const fresh = requested.filter((l) => !state.labels.includes(l));
          if (fresh.length === 0) return ok(`Already added: ${requested.join(", ")}. Labels on the draft: ${state.labels.join(", ")}.`);
          if (state.labelWrites >= MAX_LABEL_WRITES) {
            return fail(`add_labels was already called ${state.labelWrites} times; no more updates are accepted.`);
          }
          const err = append({ type: "labels", labels: fresh });
          if (err) return fail(err);
          state.labels.push(...fresh);
          state.labelWrites++;
          return ok(`Labels on the draft: ${state.labels.join(", ")}.`);
        }),
    );
  }

  /* ---- review_status ---- */
  server.registerTool(
    "review_status",
    {
      title: "Review status",
      description:
        "Show what you have recorded so far (comments, remaining comment budget, summary, verdict, labels) and what this review is allowed to do. Read-only.",
      inputSchema: z.object({}).strict(),
      annotations: { readOnlyHint: true, openWorldHint: false },
    },
    (args) => run("review_status", args, () => ok(statusText())),
  );

  /* ---- finish ---- */
  server.registerTool(
    "finish",
    {
      title: "Finish review",
      description:
        `Mark the review complete. Call exactly once, last${sc.enabled ? ", after set_summary" : ""} and set_verdict. ` +
        "No changes are accepted afterwards. Without finish the run counts as incomplete and is never published as approving or blocking.",
      inputSchema: z.object({}).strict(),
      annotations: { ...writeAnnotations, idempotentHint: true },
    },
    (args) =>
      run("finish", args, () => {
        if (state.finished) return ok("The review is already finished.");
        if (sc.enabled && state.summary === undefined && !state.finishWarned) {
          state.finishWarned = true;
          return fail(
            'No summary has been set. Call set_summary with your overall assessment first (even "no issues found" helps), or call finish again to finish without a summary.',
          );
        }
        const err = append({ type: "finish" });
        if (err) return fail(err);
        state.finished = true;
        const parts = [`${state.comments.length} inline comment(s)`];
        if (sc.enabled) parts.push(`summary ${state.summary !== undefined ? "set" : "not set"}`);
        parts.push(`verdict ${state.verdict?.verdict ?? "comment (default)"}`);
        if (state.labels.length > 0) parts.push(`labels ${state.labels.join(", ")}`);
        return ok(`Review finished: ${parts.join(", ")}. No further changes are accepted.`);
      }),
  );

  // Restore the prototype method (the tools/call handler is installed by now).
  delete (low as unknown as Record<string, unknown>).setRequestHandler;
  return server;
}

function serverInstructions(toolNames: string[]): string {
  const has = (n: string): boolean => toolNames.includes(n);
  const steps: string[] = [];
  if (has("add_comment")) steps.push("add_comment once per distinct, verified issue on changed lines");
  if (has("set_summary")) steps.push("set_summary with the overall assessment");
  steps.push("set_verdict");
  if (has("add_labels")) steps.push("add_labels if a label clearly applies");
  steps.push("finish last");
  return (
    "xreview records your review as a draft. A separate publisher re-validates it against the repository's policy " +
    "and posts it to GitHub after you finish. Workflow: investigate with the xsearch tools, then " +
    `${steps.join(", ")}. review_status shows what you recorded, the remaining budget and what this review may do.`
  );
}

/* ---------------------------------- CLI ----------------------------------- */

const USAGE = "usage: xrepo review-mcp --ctx <dir> --out <draft.jsonl>";

/**
 * `xrepo review-mcp --ctx <dir> --out <draft.jsonl>`: serves xreview over stdio until the client
 * disconnects. Returns 0 on a clean shutdown, 1 if the inputs cannot be loaded, 2 on usage errors.
 * `io` is for tests (defaults to process stdin/stdout).
 */
export async function main(args: string[], io: { stdin?: Readable; stdout?: Writable } = {}): Promise<number> {
  let ctxDir: string;
  let outFile: string;
  try {
    const v = parseCli(args, { ctx: { type: "string", required: true }, out: { type: "string", required: true } });
    ctxDir = v.ctx as string;
    outFile = v.out as string;
  } catch (e) {
    process.stderr.write(`xrepo review-mcp: ${(e as Error).message}\n${USAGE}\n`);
    return 2;
  }

  let policy: ResolvedPolicy;
  let ctx: PrContext;
  let diff: FileDiff[];
  try {
    policy = readResolvedPolicy(join(ctxDir, CTX_FILES.policy));
    ctx = readContext(ctxDir);
    if (policy.repo.toLowerCase() !== ctx.repo.toLowerCase()) {
      throw new Error(`resolved policy is for ${policy.repo} but the PR context is for ${ctx.repo}`);
    }
    diff = parseUnifiedDiff(readFileSync(join(ctxDir, CTX_FILES.diff), "utf8"));
    // Fail fast if the draft is not writable (creates it empty; writes nothing).
    appendFileSync(outFile, "", { encoding: "utf8", mode: 0o644 });
  } catch (e) {
    audit("xreview.start_failed", { error: e });
    process.stderr.write(`xrepo review-mcp: ${(e as Error).message}\n`);
    return 1;
  }

  const server = createReviewServer({ policy, ctx, diff, outFile });
  const stdin = io.stdin ?? process.stdin;
  const transport = new StdioServerTransport(stdin, io.stdout ?? process.stdout);
  const closed = new Promise<void>((resolve) => {
    server.server.onclose = () => resolve();
  });
  // The stdio transport does not close on EOF by itself.
  const onEnd = (): void => {
    void server.close().catch(() => undefined);
  };
  stdin.once("end", onEnd);
  try {
    await server.connect(transport);
  } catch (e) {
    stdin.off("end", onEnd);
    audit("xreview.start_failed", { error: e });
    process.stderr.write(`xrepo review-mcp: ${(e as Error).message}\n`);
    return 1;
  }
  audit("xreview.start", { repo: ctx.repo, pr: ctx.number, tools: reviewToolNames(policy), files: ctx.files.length });
  await closed;
  stdin.off("end", onEnd);
  audit("xreview.stop", { repo: ctx.repo, pr: ctx.number });
  return 0;
}

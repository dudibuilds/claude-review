/**
 * Review plan: a PURE function from (resolved policy, PR context, diff, draft) to exactly what the
 * publisher will post. No I/O, no clock, no randomness: `xrepo publish --dry-run` prints this plan
 * and the live run executes it.
 *
 * Rules (SPEC "Publisher rules"):
 * - Inline comments: the path must be a changed, non-ignored, non-deleted, non-binary file and the
 *   line range must lie inside one RIGHT-side hunk (isCommentable); otherwise the finding is demoted
 *   to "Notes outside the diff" in the summary. Below `inline_comments.min_severity` -> dropped.
 *   Sorted by severity (desc, stable). Deduplicated by key = sha256(path|line|normalized body)[:12];
 *   each posted comment carries `<!-- xrepo:c:KEY -->`; keys already on the PR are skipped. Capped at
 *   `max_comments` (overflow is listed in the summary). Bodies truncated to `max_comment_chars`.
 * - Suggestions only when `inline_comments.suggestions`; a suggestion containing a ``` line,
 *   control/bidi characters or a secret is dropped (the comment is kept). Suggestions are never
 *   truncated (dropped instead) because a cut suggestion would delete code when applied.
 * - Verdict: `approve` needs approve.enabled, no finding (across ALL draft comments, demoted ones
 *   included) above approve.max_severity_allowed, no changed file matching approve.never_paths and
 *   changed lines <= approve.max_changed_lines. `request_changes` needs block.enabled and >= 1
 *   finding >= block.min_severity. Otherwise the verdict is downgraded to `comment` and the reason
 *   is shown in the summary footer. An incomplete run (incomplete=true or draft not finished) never
 *   approves or blocks.
 * - Blocking via block.method: review (REQUEST_CHANGES), check (failing check run) or both.
 * - Labels: draft labels intersected with capabilities.labels.allowed (case-insensitive).
 * - Every untrusted string is passed through sanitizeMarkdown; hidden markers are appended after.
 */
import { createHash } from "node:crypto";
import type { PrContext } from "../common/context.js";
import { changedLineCount, isCommentable, type FileDiff } from "../common/diff.js";
import type { Draft, DraftComment } from "../common/draft.js";
import { redactSecrets } from "../common/redact.js";
import { compileGlobs } from "../policy/glob.js";
import { severityRank, type ResolvedPolicy, type Severity } from "../policy/schema.js";
import { inlineCode, safeCut, sanitizeMarkdownEx } from "./sanitize.js";

/* -------------------------------- markers -------------------------------- */

/** Identifies the sticky summary issue comment (only trusted when authored by our own identity). */
export const STICKY_MARKER = "<!-- xrepo-review:sticky -->";

/** Matches the hidden per-comment dedupe marker; group 1 = the 12-hex key. Use with matchAll. */
export const COMMENT_MARKER_RE = /<!-- xrepo:c:([0-9a-f]{12}) -->/g;

export function commentMarker(key: string): string {
  return `<!-- xrepo:c:${key} -->`;
}

/** Whitespace-insensitive body normalization used for dedupe keys. */
export function normalizeCommentBody(body: string): string {
  return body.replace(/\s+/g, " ").trim();
}

/** Dedupe key: first 12 hex chars of sha256("path|line|normalized body"). */
export function commentKey(path: string, line: number, body: string): string {
  return createHash("sha256").update(`${path}|${line}|${normalizeCommentBody(body)}`, "utf8").digest("hex").slice(0, 12);
}

/** Extract dedupe keys from a comment body. */
export function extractCommentKeys(body: string | null | undefined): string[] {
  if (typeof body !== "string" || body === "") return [];
  return [...body.matchAll(COMMENT_MARKER_RE)].map((m) => m[1] ?? "").filter((k) => k !== "");
}

/** Body of the sticky summary comment: marker first, then the summary. */
export function stickyCommentBody(summary: string): string {
  return `${STICKY_MARKER}\n${summary}`;
}

/* --------------------------------- types --------------------------------- */

export type Verdict = "comment" | "approve" | "request_changes";
export type ReviewEvent = "COMMENT" | "APPROVE" | "REQUEST_CHANGES";
export type CheckConclusion = "success" | "neutral" | "failure";
export type SummaryTarget = "sticky" | "review" | "none";

export interface PlanComment {
  path: string;
  /** Last line of the range (GitHub semantics). */
  line: number;
  /** First line of a multi-line range. */
  start_line?: number;
  side: "RIGHT";
  start_side?: "RIGHT";
  body: string;
}

export interface PlanReview {
  event: ReviewEvent;
  body: string;
  comments: PlanComment[];
}

export interface PlanCheck {
  name: string;
  conclusion: CheckConclusion;
  title: string;
  summary: string;
}

export interface PlanStats {
  /** Valid comment entries in the draft (before any filtering). */
  draft_comments: number;
  /** Lines of the draft file that failed validation. */
  invalid_draft_lines: number;
  /** Same key as an earlier draft comment. */
  duplicates: number;
  below_min_severity: number;
  /** Not commentable (outside the diff, unknown/deleted/binary/ignored file). */
  demoted: number;
  /** Key already present on the PR from an earlier run. */
  already_posted: number;
  /** Commentable but beyond max_comments (listed in the summary). */
  over_cap: number;
  /** Inline comments in the plan. */
  inline: number;
  /** Entries listed in the summary (demoted + over cap). */
  notes: number;
  suggestions: number;
  suggestions_dropped: number;
  /** Texts shortened to fit their limit. */
  truncated: number;
  /** Secrets redacted from outgoing text. */
  redactions: number;
  changed_files: number;
  changed_lines: number;
  labels_requested: number;
  labels_dropped: number;
}

export interface PublishPlan {
  review?: PlanReview;
  /** Sanitized summary markdown (sticky comment or review body per summary_comment.mode). */
  summary: string;
  summaryTarget: SummaryTarget;
  check?: PlanCheck;
  labels: string[];
  verdict: Verdict;
  /** What the agent asked for (before policy resolution). */
  requested_verdict: Verdict;
  blocked: boolean;
  approved: boolean;
  /** Distinct findings in the draft (all severities, demoted included). */
  findings: number;
  top_severity?: Severity;
  /** Human-readable decision log (audit). */
  decisions: string[];
  stats: PlanStats;
}

export interface BuildPlanInput {
  policy: ResolvedPolicy;
  ctx: PrContext;
  diff: FileDiff[];
  draft: Draft;
  /** Dedupe keys of inline comments already posted by us on this PR. */
  existingCommentKeys?: Set<string>;
  /** The agent run did not complete (max turns, crash): never approve/block. */
  incomplete?: boolean;
}

/* -------------------------------- helpers -------------------------------- */

const SEVERITY_EMOJI: Record<Severity, string> = {
  critical: "\u{1F534}",
  high: "\u{1F7E0}",
  medium: "\u{1F7E1}",
  low: "\u{1F535}",
  info: "\u26AA",
};
const SEVERITY_LABEL: Record<Severity, string> = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
  info: "Info",
};

const SUMMARY_TITLE = "### \u{1F916} Automated review";
const MAX_NOTES = 50;
const NOTE_BODY_CHARS = 500;
const MIN_COMMENT_BODY = 60;
const MAX_REVIEW_BODY = 60000;
const MAX_CHECK_SUMMARY = 65535;
const MAX_CHECK_TITLE = 200;
const MAX_LABELS = 20;

interface Finding {
  c: DraftComment;
  key: string;
  order: number;
}

interface Note {
  f: Finding;
  why: string;
}

function rank(s: Severity): number {
  return severityRank(s);
}

function bySeverity<T>(get: (x: T) => Finding): (a: T, b: T) => number {
  return (a, b) => {
    const fa = get(a);
    const fb = get(b);
    return rank(fb.c.severity) - rank(fa.c.severity) || fa.order - fb.order;
  };
}

function lineRange(c: DraftComment): string {
  return c.end_line !== undefined && c.end_line !== c.line ? `${c.line}-${c.end_line}` : `${c.line}`;
}

function loc(c: DraftComment): string {
  return `${JSON.stringify(c.path)}:${lineRange(c)}`;
}

function plural(n: number, word: string): string {
  return `${n} ${word}${n === 1 ? "" : "s"}`;
}

function oneLine(s: string, max: number): string {
  const t = s.replace(/\s+/g, " ").trim();
  return t.length > max ? `${t.slice(0, max - 1)}\u2026` : t;
}

function uniq<T>(xs: Iterable<T>): T[] {
  return [...new Set(xs)];
}

/** Validate and wrap a suggestion; returns the block or the reason it was dropped. */
function suggestionBlock(raw: string): { block: string } | { reason: string } {
  let t = raw.replace(/\r\n?/g, "\n");
  if (/^[ \t]*`{3,}/m.test(t)) return { reason: "contains a ``` line" };
  if (/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F\u202A-\u202E\u2066-\u2069]/.test(t)) {
    return { reason: "contains control or bidi characters" };
  }
  if (redactSecrets(t).count > 0) return { reason: "contains a secret" };
  if (t.endsWith("\n")) t = t.slice(0, -1);
  return { block: t === "" ? "\n\n```suggestion\n```" : `\n\n\`\`\`suggestion\n${t}\n\`\`\`` };
}

/* --------------------------------- plan ---------------------------------- */

export function buildPlan(input: BuildPlanInput): PublishPlan {
  const { policy, ctx, diff, draft } = input;
  const caps = policy.capabilities;
  const ic = caps.inline_comments;
  const sc = caps.summary_comment;
  const ap = caps.approve;
  const blk = caps.block;
  const chk = caps.check;
  const lb = caps.labels;
  const existing = input.existingCommentKeys ?? new Set<string>();
  const incomplete = input.incomplete === true || !draft.finished;

  const decisions: string[] = [];
  /** Reasons shown in the summary footer (verdict changes, incomplete run). */
  const footerNotes: string[] = [];
  const stats: PlanStats = {
    draft_comments: draft.comments.length,
    invalid_draft_lines: draft.invalidLines,
    duplicates: 0,
    below_min_severity: 0,
    demoted: 0,
    already_posted: 0,
    over_cap: 0,
    inline: 0,
    notes: 0,
    suggestions: 0,
    suggestions_dropped: 0,
    truncated: 0,
    redactions: 0,
    changed_files: 0,
    changed_lines: 0,
    labels_requested: draft.labels.length,
    labels_dropped: 0,
  };

  const san = (text: string, maxChars: number, allowSuggestions = false): string => {
    const r = sanitizeMarkdownEx(text, {
      allowMentions: policy.output.allow_mentions,
      allowImages: policy.output.allow_images,
      linkAllowlist: policy.output.link_allowlist,
      maxChars: Math.max(1, maxChars),
      allowSuggestions,
    });
    if (r.truncated) stats.truncated++;
    stats.redactions += r.redactions;
    return r.text;
  };

  if (draft.invalidLines > 0) decisions.push(`draft: ignored ${plural(draft.invalidLines, "invalid line")}`);
  if (incomplete) {
    const why = input.incomplete === true ? "the agent run did not complete" : "the draft was not finished";
    decisions.push(`incomplete: ${why}; the review will not approve or block`);
  }

  /* ---- changed files ---- */
  const prFiles = new Map(ctx.files.map((f) => [f.path, f] as const));
  const ignored = new Set(ctx.ignored_files);
  const diffs = new Map(diff.map((fd) => [fd.path, fd] as const));
  const changedPaths = uniq(
    [
      ...ctx.files.flatMap((f) => [f.path, f.previous_path]),
      ...ctx.ignored_files,
      ...diff.flatMap((fd) => [fd.path, fd.oldPath]),
    ].filter((p): p is string => typeof p === "string" && p !== ""),
  );
  const changedLines = Math.max(ctx.changed_lines, changedLineCount(diff));
  stats.changed_files = uniq([...ctx.files.map((f) => f.path), ...ctx.ignored_files, ...diff.map((fd) => fd.path)]).length;
  stats.changed_lines = changedLines;

  /* ---- findings: dedupe within the draft ---- */
  const inlineEnabled = ic.enabled && ic.max_comments > 0;
  const findings: Finding[] = [];
  if (!inlineEnabled) {
    if (draft.comments.length > 0) {
      decisions.push(`inline comments disabled by policy: ignored ${plural(draft.comments.length, "draft comment")}`);
    }
  } else {
    const seen = new Map<string, Finding>();
    draft.comments.forEach((c, order) => {
      const key = commentKey(c.path, c.line, c.body);
      const prev = seen.get(key);
      if (prev) {
        stats.duplicates++;
        decisions.push(`duplicate comment ${loc(c)} (key ${key}) dropped`);
        return;
      }
      const f: Finding = { c, key, order };
      seen.set(key, f);
      findings.push(f);
    });
  }
  const topRank = findings.reduce((m, f) => Math.max(m, rank(f.c.severity)), -1);
  const topSeverity = findings.find((f) => rank(f.c.severity) === topRank)?.c.severity;

  /* ---- classify: inline candidates vs notes ---- */
  const notCommentable = (c: DraftComment): string | undefined => {
    if (ignored.has(c.path)) return "file excluded from the review (triggers.ignore_paths)";
    const pf = prFiles.get(c.path);
    if (!pf) return "not a changed file";
    const fd = diffs.get(c.path);
    if (pf.status === "removed" || fd?.status === "removed") return "file deleted in this PR";
    if (pf.status === "binary" || fd?.status === "binary") return "binary file";
    if (!fd) return "file has no diff";
    if (!isCommentable(fd, c.line, c.end_line)) return "outside the diff hunks";
    return undefined;
  };

  const minRank = rank(ic.min_severity);
  const candidates: Finding[] = [];
  const demoted: Note[] = [];
  for (const f of findings) {
    if (rank(f.c.severity) < minRank) {
      stats.below_min_severity++;
      decisions.push(`dropped ${loc(f.c)}: severity ${f.c.severity} below min_severity ${ic.min_severity}`);
      continue;
    }
    const why = notCommentable(f.c);
    if (why !== undefined) {
      stats.demoted++;
      demoted.push({ f, why });
      decisions.push(`demoted ${loc(f.c)} to the summary: ${why}`);
      continue;
    }
    candidates.push(f);
  }
  candidates.sort(bySeverity<Finding>((x) => x));
  demoted.sort(bySeverity<Note>((x) => x.f));

  const fresh: Finding[] = [];
  for (const f of candidates) {
    if (existing.has(f.key)) {
      stats.already_posted++;
      decisions.push(`skipped ${loc(f.c)}: already posted (key ${f.key})`);
    } else {
      fresh.push(f);
    }
  }
  const toPost = fresh.slice(0, ic.max_comments);
  const overflow = fresh.slice(ic.max_comments);
  if (overflow.length > 0) {
    stats.over_cap = overflow.length;
    decisions.push(`${plural(overflow.length, "comment")} beyond max_comments (${ic.max_comments}) listed in the summary`);
  }

  /* ---- inline comment bodies ---- */
  const comments: PlanComment[] = toPost.map((f) => {
    const c = f.c;
    const category = c.category ? oneLine(c.category, 60) : "";
    const header = `${SEVERITY_EMOJI[c.severity]} **${SEVERITY_LABEL[c.severity]}**${category ? ` \u00B7 ${category}` : ""}`;
    let block = "";
    if (c.suggestion !== undefined) {
      if (!ic.suggestions) {
        stats.suggestions_dropped++;
        decisions.push(`suggestion on ${loc(c)} dropped: suggestions disabled by policy`);
      } else {
        const r = suggestionBlock(c.suggestion);
        if ("block" in r) block = r.block;
        else {
          stats.suggestions_dropped++;
          decisions.push(`suggestion on ${loc(c)} dropped: ${r.reason}`);
        }
      }
    }
    if (block !== "" && header.length + MIN_COMMENT_BODY + block.length > ic.max_comment_chars) {
      block = "";
      stats.suggestions_dropped++;
      decisions.push(`suggestion on ${loc(c)} dropped: does not fit max_comment_chars (${ic.max_comment_chars})`);
    }
    if (block !== "") stats.suggestions++;
    const body = san(`${header}\n\n${c.body}`, ic.max_comment_chars - block.length, ic.suggestions);
    const pc: PlanComment = { path: c.path, line: c.line, side: "RIGHT", body: `${body}${block}\n\n${commentMarker(f.key)}` };
    if (c.end_line !== undefined && c.end_line > c.line) {
      pc.start_line = c.line;
      pc.start_side = "RIGHT";
      pc.line = c.end_line;
    }
    return pc;
  });
  stats.inline = comments.length;

  /* ---- verdict ---- */
  const requested: Verdict = draft.verdict?.verdict ?? "comment";
  let verdict: Verdict = requested;
  const blockViaReview = blk.method === "review" || blk.method === "both";
  const blockViaCheck = blk.method === "check" || blk.method === "both";
  const atOrAboveBlock = findings.filter((f) => rank(f.c.severity) >= rank(blk.min_severity));
  if (requested !== "comment" && incomplete) {
    verdict = "comment";
    const what = requested === "approve" ? "Approval" : "Request for changes";
    footerNotes.push(`${what} not applied: the review did not finish, so it never approves or blocks.`);
    decisions.push(`verdict ${requested} -> comment: review incomplete`);
  } else if (requested === "approve") {
    const fails: string[] = [];
    if (!ap.enabled) fails.push("approving is disabled by policy");
    const above = findings.filter((f) => rank(f.c.severity) > rank(ap.max_severity_allowed));
    if (above.length > 0) fails.push(`${plural(above.length, "finding")} above "${ap.max_severity_allowed}"`);
    const never = compileGlobs(ap.never_paths);
    const hits = changedPaths.filter((p) => never(p));
    if (hits.length > 0) {
      const shown = hits.slice(0, 5).map((p) => inlineCode(p, 120)).join(", ");
      fails.push(`changed files match approve.never_paths (${shown}${hits.length > 5 ? `, +${hits.length - 5} more` : ""})`);
    }
    if (changedLines > ap.max_changed_lines) {
      fails.push(`${changedLines} changed lines exceed approve.max_changed_lines (${ap.max_changed_lines})`);
    }
    if (fails.length > 0) {
      verdict = "comment";
      footerNotes.push(`Approval downgraded to a comment: ${fails.join("; ")}.`);
      decisions.push(`verdict approve -> comment: ${fails.join("; ")}`);
    }
  } else if (requested === "request_changes") {
    const fails: string[] = [];
    if (!blk.enabled) fails.push("blocking is disabled by policy");
    if (atOrAboveBlock.length === 0) fails.push(`no finding at or above "${blk.min_severity}"`);
    if (fails.length > 0) {
      verdict = "comment";
      footerNotes.push(`Request for changes downgraded to a comment: ${fails.join("; ")}.`);
      decisions.push(`verdict request_changes -> comment: ${fails.join("; ")}`);
    }
  }
  if (verdict === requested) decisions.push(`verdict: ${verdict}`);
  const approved = verdict === "approve";
  const blocked = verdict === "request_changes";
  const event: ReviewEvent = approved ? "APPROVE" : blocked && blockViaReview ? "REQUEST_CHANGES" : "COMMENT";
  if (blocked) decisions.push(`blocking via ${blk.method}`);

  /* ---- labels ---- */
  let labels: string[] = [];
  if (draft.labels.length > 0) {
    if (!lb.enabled) {
      stats.labels_dropped = draft.labels.length;
      decisions.push(`labels capability disabled: ignored ${plural(draft.labels.length, "label")}`);
    } else {
      const allowed = new Map(lb.allowed.map((l) => [l.toLowerCase(), l] as const));
      const kept: string[] = [];
      for (const l of draft.labels) {
        const canonical = allowed.get(l.toLowerCase());
        if (canonical !== undefined && !kept.includes(canonical) && kept.length < MAX_LABELS) kept.push(canonical);
        else if (canonical === undefined) {
          stats.labels_dropped++;
          decisions.push(`label ${JSON.stringify(l)} not in labels.allowed: dropped`);
        }
      }
      labels = kept;
      if (kept.length > 0) decisions.push(`labels: ${kept.join(", ")}`);
    }
  }

  /* ---- summary ---- */
  const summaryTarget: SummaryTarget = sc.enabled ? sc.mode : "none";
  const notesTotal = demoted.length + overflow.length;
  stats.notes = notesTotal;
  const produced = Boolean(draft.summary?.trim()) || comments.length > 0 || notesTotal > 0 || stats.already_posted > 0;

  const noteLine = (f: Finding): string =>
    `- ${SEVERITY_EMOJI[f.c.severity]} **${SEVERITY_LABEL[f.c.severity]}** ${inlineCode(`${f.c.path}:${lineRange(f.c)}`, 200)}` +
    ` \u2014 ${oneLine(f.c.body, NOTE_BODY_CHARS)}`;
  const noteSection = (title: string, items: Finding[]): string => {
    if (items.length === 0) return "";
    const shown = items.slice(0, MAX_NOTES).map(noteLine);
    if (items.length > MAX_NOTES) shown.push(`- \u2026 and ${items.length - MAX_NOTES} more`);
    return `#### ${title} (${items.length})\n\n${shown.join("\n")}`;
  };
  const notesRaw = [
    noteSection("Notes outside the diff", demoted.map((n) => n.f)),
    noteSection("More findings (inline comment limit reached)", overflow),
  ]
    .filter((s) => s !== "")
    .join("\n\n");

  const banner = incomplete
    ? "> \u26A0\uFE0F **Incomplete review:** the agent did not finish. Findings may be partial; this review never approves or blocks."
    : "";
  const statusLine =
    `<sub>Verdict: **${verdict}**${verdict !== requested ? ` (requested: ${requested})` : ""}` +
    ` \u00B7 ${plural(findings.length, "finding")}${topSeverity ? ` (top: ${topSeverity})` : ""}` +
    ` \u00B7 ${plural(comments.length, "inline comment")}${notesTotal > 0 ? ` \u00B7 ${plural(notesTotal, "note")}` : ""}</sub>`;
  const reason = draft.verdict?.reason?.trim() ?? "";
  const reasonLine = reason !== "" ? [`- Reviewer's verdict reason: ${oneLine(reason, 300)}`] : [];
  const footerRaw = ["---", statusLine, ...reasonLine, ...footerNotes.map((n) => `- ${n}`)].join("\n");
  const trustedFooter = policy.output.footer.trim();

  const maxSummary = sc.max_chars;
  const footer = san(footerRaw, Math.min(3000, Math.max(200, Math.floor(maxSummary / 3))));
  const fixedLen = [SUMMARY_TITLE, banner, footer, trustedFooter].filter((s) => s !== "").join("\n\n").length;
  let remaining = Math.max(0, maxSummary - fixedLen - 4);

  let bodyRaw = draft.summary?.trim() ?? "";
  if (!produced) {
    bodyRaw = incomplete
      ? "_The automated review stopped before reporting any findings._"
      : "_No findings were reported by the automated review._";
  }
  let notesText = "";
  if (notesRaw !== "" && remaining > 0) {
    const want = notesRaw.length + 64;
    const budget = Math.min(want, Math.max(Math.floor(remaining * 0.4), remaining - bodyRaw.length - 64));
    if (budget > 80) {
      notesText = san(notesRaw, budget);
      remaining -= notesText.length + 2;
    }
  }
  const bodyText = bodyRaw !== "" && remaining > 40 ? san(bodyRaw, remaining) : "";
  let summary = [SUMMARY_TITLE, banner, bodyText, notesText, footer, trustedFooter].filter((s) => s !== "").join("\n\n");
  if (summary.length > maxSummary) {
    summary = safeCut(summary, maxSummary);
    stats.truncated++;
  }
  if (summaryTarget === "none" && (notesTotal > 0 || draft.summary)) {
    decisions.push("summary comment disabled by policy: summary and notes are not posted");
  } else {
    decisions.push(`summary target: ${summaryTarget}`);
  }

  /* ---- review ---- */
  let review: PlanReview | undefined;
  if (comments.length > 0 || event !== "COMMENT" || summaryTarget === "review") {
    let body: string;
    if (summaryTarget === "review") {
      body = summary;
    } else {
      const parts: string[] = [];
      if (event === "APPROVE") parts.push("\u2705 Approved by the automated review.");
      else if (event === "REQUEST_CHANGES") {
        parts.push(`\u274C Changes requested: ${plural(atOrAboveBlock.length, "finding")} at or above ${blk.min_severity}.`);
      } else parts.push("Automated review.");
      if (comments.length > 0) parts.push(`${plural(comments.length, "inline comment")}.`);
      if (summaryTarget === "sticky") parts.push("Details are in the summary comment.");
      let short = parts.join(" ");
      if (summaryTarget === "none" && footerNotes.length > 0) short += `\n\n${footerNotes.map((n) => `- ${n}`).join("\n")}`;
      body = san(short, 4000);
    }
    review = { event, body: safeCut(body, MAX_REVIEW_BODY), comments };
    decisions.push(`review: ${event} with ${plural(comments.length, "inline comment")}`);
  }

  /* ---- check run ---- */
  let check: PlanCheck | undefined;
  if (chk.enabled || (blk.enabled && blockViaCheck)) {
    let conclusion: CheckConclusion;
    let title: string;
    if (blocked && blockViaCheck) {
      conclusion = "failure";
      title = `Changes requested: ${plural(atOrAboveBlock.length, "finding")} at or above ${blk.min_severity}`;
    } else if (incomplete) {
      conclusion = "neutral";
      title = "Review incomplete";
    } else if (approved) {
      conclusion = "success";
      title = "Approved";
    } else if (findings.length === 0) {
      conclusion = "success";
      title = "No findings";
    } else {
      conclusion = "neutral";
      title = `${plural(findings.length, "finding")}${topSeverity ? `, top severity ${topSeverity}` : ""}`;
    }
    const checkSummary = summaryTarget !== "none" ? summary : footer;
    check = {
      name: chk.name,
      conclusion,
      title: title.slice(0, MAX_CHECK_TITLE),
      summary: safeCut(checkSummary, MAX_CHECK_SUMMARY),
    };
    decisions.push(`check ${JSON.stringify(chk.name)}: ${conclusion}`);
  }

  return {
    ...(review ? { review } : {}),
    summary,
    summaryTarget,
    ...(check ? { check } : {}),
    labels,
    verdict,
    requested_verdict: requested,
    blocked,
    approved,
    findings: findings.length,
    ...(topSeverity ? { top_severity: topSeverity } : {}),
    decisions,
    stats,
  };
}

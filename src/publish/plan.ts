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
 *   `max_comments` (overflow is listed in the summary). The agent-written part of a comment (body
 *   plus suggestion block) is limited to `max_comment_chars`, the same limit xreview checks at tool
 *   time; the severity/category header the publisher prepends does not count against it.
 * - Suggestions only when `inline_comments.suggestions`; a suggestion containing a ``` line,
 *   control/bidi characters or a secret is dropped (the comment is kept). Suggestions are never
 *   truncated (dropped instead) because a cut suggestion would delete code when applied; that
 *   includes a ```suggestion block written inside the body (sanitize drops it rather than cut it).
 *   The validated suggestion is appended after the sanitized body, which sanitize guarantees not to
 *   leave inside an open fence or HTML block (an unclosed "<pre>" cannot swallow it).
 * - Verdict: `approve` needs approve.enabled, no finding (across ALL draft comments, demoted ones
 *   included) above approve.max_severity_allowed, no changed file matching approve.never_paths and
 *   changed lines <= approve.max_changed_lines. `request_changes` needs block.enabled and >= 1
 *   finding >= block.min_severity. Otherwise the verdict is downgraded to `comment` and the reason
 *   is shown in the summary footer. An incomplete run (incomplete=true or draft not finished) never
 *   approves or blocks. These rules and the inline comment framing come from review/rules.ts, which
 *   xreview (tool-time feedback) and prepare (prompt) use too, so the three cannot disagree.
 * - Blocking via block.method: review (REQUEST_CHANGES), check (failing check run) or both. A
 *   REQUEST_CHANGES review stays in force on GitHub until it is dismissed (a later COMMENT review
 *   does not clear it), so a finished run that does not itself block via a review sets
 *   `dismiss_change_requests` for the publisher to dismiss our earlier ones.
 * - The same holds for an APPROVE: it keeps counting across later pushes unless branch protection
 *   dismisses stale approvals. Every run that does not itself approve sets `dismiss_approvals`
 *   (incomplete runs included: they never approve, so an older approval must not survive them);
 *   runs without a plan (skipped, error, usage_limit) must dismiss them too (fail closed).
 * - Every review body ends with REVIEW_MARKER, so that only reviews this tool posted are ever
 *   dismissed (the identity behind GITHUB_TOKEN, github-actions[bot], is shared by every workflow).
 * - Sticky summary budget: the publisher appends the outcome comments to the sticky summary and must
 *   never cut through it, so in sticky mode the summary is built small enough to leave room for the
 *   largest outcome comments the policy can render (stickySummaryLimit).
 * - With inline comments disabled there are no findings, so blocking cannot apply (recorded as a
 *   decision) and the check run is neutral rather than "No findings".
 * - Labels: draft labels intersected with capabilities.labels.allowed (case-insensitive).
 * - Every untrusted string is passed through sanitizeMarkdown; hidden markers are appended after.
 */
import { createHash } from "node:crypto";
import type { PrContext } from "../common/context.js";
import { isCommentable, type FileDiff } from "../common/diff.js";
import type { Draft, DraftComment } from "../common/draft.js";
import { severityRank, type OutcomeName, type ResolvedPolicy, type Severity } from "../policy/schema.js";
import {
  approveBlockers,
  changeFacts,
  commentFrame,
  inlineCommentsEnabled,
  INCOMPLETE_BANNER,
  MAX_REVIEW_BODY_CHARS,
  mergeSamePathDiffs,
  mergeSamePathFiles,
  requestChangesBlockers,
  SEVERITY_EMOJI,
  SEVERITY_LABEL,
  SUMMARY_TITLE,
  summaryBudget,
} from "../review/rules.js";
import { inlineCode, safeCut, sanitizeMarkdownEx, singleLine, sliceSafe } from "./sanitize.js";

/* -------------------------------- markers -------------------------------- */

/** Identifies the sticky summary issue comment (only trusted when authored by our own identity). */
export const STICKY_MARKER = "<!-- xrepo-review:sticky -->";

/**
 * Ends every pull request review body this tool posts. The publisher only ever dismisses reviews
 * that carry it (and are authored by its own identity), never another tool's.
 */
export const REVIEW_MARKER = "<!-- xrepo-review:review -->";

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

/**
 * Was this review body posted by xrepo-review? It carries REVIEW_MARKER, or (reviews posted before
 * the marker existed) starts with the publisher's exact framing. Only such reviews, authored by the
 * publisher's own identity, are ever dismissed: github-actions[bot] is shared by every workflow that
 * uses GITHUB_TOKEN, so the author alone does not identify our reviews.
 */
export function isXrepoReviewBody(body: string | null | undefined): boolean {
  if (typeof body !== "string" || body === "") return false;
  if (body.includes(REVIEW_MARKER)) return true;
  return LEGACY_REVIEW_RES.some((re) => re.test(body));
}

/** publish.ts composeSticky: the sticky comment's size cap (MAX_STICKY_CHARS). */
const STICKY_MAX_CHARS = 65000;
/** publish.ts renderOutcomeComment: each rendered outcome comment is capped at this length. */
const OUTCOME_COMMENT_MAX = 6000;
/**
 * Upper bound of one rendered placeholder value in an outcome comment (outcome/template.ts
 * markdownEscaper: URL values <= 2000 characters, other values <= 300 * 4 + 64 after sanitizing).
 */
const PLACEHOLDER_MAX = 2100;
/** publish.ts planAfterRefusedEvent appends a note (sanitized to <= 600 characters) to the summary. */
const REFUSAL_NOTE_RESERVE = 700;

function outcomeCommentBound(tpl: string): number {
  const t = tpl.trim();
  if (t === "") return 0;
  const placeholders = (t.match(/\{[a-z_]{1,40}\}/g) ?? []).length;
  return Math.min(OUTCOME_COMMENT_MAX, t.length + placeholders * PLACEHOLDER_MAX);
}

/**
 * Largest plan summary that still fits the sticky comment together with every outcome comment the
 * policy can append to it for a run with a plan (completed + approved or blocked, or incomplete),
 * the marker and a refused-event note. The publisher appends those after the summary and must never
 * cut the summary itself: a cut through sanitized agent text can land inside a fence or a <details>
 * that then swallows the outcome comments, and it drops the trusted footers at the end.
 */
export function stickySummaryLimit(policy: ResolvedPolicy): number {
  const room = (o: OutcomeName): number => {
    const n = outcomeCommentBound(policy.outcomes[o]?.comment ?? "");
    return n > 0 ? n + 2 : 0; // "\n\n" before each comment
  };
  const reserve = Math.max(room("incomplete"), room("completed") + Math.max(room("approved"), room("blocked")));
  return STICKY_MAX_CHARS - STICKY_MARKER.length - 1 - REFUSAL_NOTE_RESERVE - reserve;
}

const RUN_STATUS_TEXT: Record<string, string> = {
  skipped: "was skipped",
  usage_limit: "was postponed (usage limit reached)",
  error: "could not run",
  incomplete: "did not finish",
  completed: "completed",
};

/**
 * Sticky body that replaces an earlier run's sticky comment when this run has nothing for the
 * sticky and no review plan: a skipped run (draft, size limit, title marker, kill switch, ...), or
 * an error / usage_limit run whose outcome has no comment. The earlier summary (old findings, an
 * old "postponed" notice) must not read as the current result. Trusted text only; the reason is an
 * inert code span. Replace an existing sticky with it; never create one.
 */
export function runStatusStickyBody(input: { outcome: string; reason?: string; head_sha?: string }): string {
  const commit = input.head_sha && /^[0-9a-f]{7,64}$/i.test(input.head_sha) ? ` for commit ${input.head_sha.slice(0, 7)}` : "";
  const what = RUN_STATUS_TEXT[input.outcome] ?? "ended";
  const reason = singleLine(input.reason ?? "", 200);
  const why = reason !== "" ? ` (${inlineCode(reason, 200)})` : "";
  return stickyCommentBody(
    `The latest automated review run${commit} ${what}${why}. An earlier review summary in this comment is outdated and no longer describes this pull request.`,
  );
}

/* --------------------------------- types --------------------------------- */

export type Verdict = "comment" | "approve" | "request_changes";
export type ReviewEvent = "COMMENT" | "APPROVE" | "REQUEST_CHANGES";
export type CheckConclusion = "success" | "neutral" | "failure";
/** Conclusions a check run can carry: the plan's, plus the ones outcome actions may configure. */
export type CheckRunConclusion = CheckConclusion | "skipped" | "action_required";
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
  /**
   * Dismiss earlier CHANGES_REQUESTED reviews by our identity (GitHubApi.dismissStaleChangeRequests):
   * true when the run finished and does not itself request changes via a review. Never set for an
   * incomplete run, which neither blocks nor unblocks.
   */
  dismiss_change_requests?: boolean;
  /**
   * Dismiss earlier APPROVED reviews by our identity (GitHubApi.dismissStaleApprovals): true for
   * every run that does not itself approve, incomplete runs included. An approval stays in force on
   * GitHub across later pushes (unless branch protection dismisses stale approvals), so a run whose
   * approval was downgraded (never_paths, max_changed_lines, findings) must not leave an older one.
   */
  dismiss_approvals?: boolean;
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

/**
 * The exact framing of the review bodies posted before REVIEW_MARKER existed (see isXrepoReviewBody):
 * the short APPROVE / REQUEST_CHANGES bodies, and a summary-mode body (title ... status footer).
 */
const LEGACY_REVIEW_RES: readonly RegExp[] = [
  /^\u2705 Approved by the automated review\.(?: \d+ inline comments?\.)?(?: Details are in the summary comment\.)?(?:\n|$)/u,
  /^\u274C Changes requested: \d+ findings? at or above (?:info|low|medium|high|critical)\.(?: \d+ inline comments?\.)?(?: Details are in the summary comment\.)?(?:\n|$)/u,
  /^### \u{1F916} Automated review\n[\s\S]*\n<sub>Verdict: \*\*(?:approve|request_changes)\*\*/u,
];
const MAX_NOTES = 50;
const NOTE_BODY_CHARS = 500;
const MAX_REVIEW_BODY = MAX_REVIEW_BODY_CHARS;
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

function uniq<T>(xs: Iterable<T>): T[] {
  return [...new Set(xs)];
}

/* --------------------------------- plan ---------------------------------- */

export function buildPlan(input: BuildPlanInput): PublishPlan {
  const { policy, ctx, diff, draft } = input;
  const caps = policy.capabilities;
  const ic = caps.inline_comments;
  const sc = caps.summary_comment;
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
  const prFiles = new Map(mergeSamePathFiles(ctx.files).map((f) => [f.path, f] as const));
  const ignored = new Set(ctx.ignored_files);
  const diffs = new Map(mergeSamePathDiffs(diff).map((fd) => [fd.path, fd] as const));
  // The same facts xreview and prepare judge verdict eligibility on (review/rules.ts).
  const facts = changeFacts(ctx, diff);
  stats.changed_files = uniq([...ctx.files.map((f) => f.path), ...ctx.ignored_files, ...diff.map((fd) => fd.path)]).length;
  stats.changed_lines = facts.changedLines;

  /* ---- findings: dedupe within the draft ---- */
  const inlineEnabled = inlineCommentsEnabled(policy);
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
    // The framing xreview checks at tool time (review/rules.ts): max_comment_chars limits what the
    // agent wrote (body + suggestion block); the severity/category header is extra.
    const frame = commentFrame(ic, c);
    if (frame.suggestionDropped !== undefined) {
      stats.suggestions_dropped++;
      decisions.push(`suggestion on ${loc(c)} dropped: ${frame.suggestionDropped}`);
    }
    if (frame.block !== "") stats.suggestions++;
    const body = san(frame.text, frame.textBudget, ic.suggestions);
    const pc: PlanComment = { path: c.path, line: c.line, side: "RIGHT", body: `${body}${frame.block}\n\n${commentMarker(f.key)}` };
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
    const fails = approveBlockers(policy, facts, findings.map((f) => f.c)).map((b) => b.message);
    if (fails.length > 0) {
      verdict = "comment";
      footerNotes.push(`Approval downgraded to a comment: ${fails.join("; ")}.`);
      decisions.push(`verdict approve -> comment: ${fails.join("; ")}`);
    }
  } else if (requested === "request_changes") {
    const fails = requestChangesBlockers(policy, findings.map((f) => f.c)).map((b) => b.message);
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
  if (blk.enabled && !inlineEnabled) {
    decisions.push("block.enabled has no effect: inline comments are disabled, so no finding can reach block.min_severity");
  }
  const dismissChangeRequests = !incomplete && !(blocked && blockViaReview);
  const dismissApprovals = !approved;
  if (dismissApprovals && caps.approve.enabled) decisions.push("earlier approvals by this reviewer are stale: dismiss them");
  if (dismissChangeRequests && blk.enabled && blockViaReview) decisions.push("earlier change requests by this reviewer are stale: dismiss them");

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
    ` \u2014 ${singleLine(f.c.body, NOTE_BODY_CHARS)}`;
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

  const banner = incomplete ? INCOMPLETE_BANNER : "";
  const statusLine =
    `<sub>Verdict: **${verdict}**${verdict !== requested ? ` (requested: ${requested})` : ""}` +
    ` \u00B7 ${plural(findings.length, "finding")}${topSeverity ? ` (top: ${topSeverity})` : ""}` +
    ` \u00B7 ${plural(comments.length, "inline comment")}${notesTotal > 0 ? ` \u00B7 ${plural(notesTotal, "note")}` : ""}</sub>`;
  const reason = draft.verdict?.reason?.trim() ?? "";
  const reasonLine = reason !== "" ? [`- Reviewer's verdict reason: ${singleLine(reason, 300)}`] : [];
  const footerRaw = ["---", statusLine, ...reasonLine, ...footerNotes.map((n) => `- ${n}`)].join("\n");
  const trustedFooter = policy.output.footer.trim();

  // xreview's set_summary accepts exactly what this layout posts whole (review/rules.ts): max_chars
  // limits the agent's text; title, banner, notes and footers have their own room.
  const budget = summaryBudget(policy, stickySummaryLimit(policy));
  const maxSummary = budget.totalChars;
  if (budget.bodyChars < sc.max_chars) {
    decisions.push(`summary limited to ${budget.bodyChars} characters: the ${sc.mode === "sticky" ? "sticky comment needs room for the outcome comments" : "review body has a size cap"}`);
  }
  const footer = san(footerRaw, budget.footerChars);

  let bodyRaw = draft.summary?.trim() ?? "";
  if (!produced) {
    bodyRaw = incomplete
      ? "_The automated review stopped before reporting any findings._"
      : "_No findings were reported by the automated review._";
  }
  const bodyText = bodyRaw !== "" && budget.bodyChars > 0 ? san(bodyRaw, budget.bodyChars) : "";
  let notesText = "";
  if (notesRaw !== "") {
    // Body room the summary leaves unused goes to the notes.
    const room = Math.min(notesRaw.length + 64, budget.notesChars + budget.bodyChars - bodyText.length);
    if (room > 80) notesText = san(notesRaw, room);
  }
  let summary = [SUMMARY_TITLE, banner, bodyText, notesText, footer, trustedFooter].filter((s) => s !== "").join("\n\n");
  if (summary.length > maxSummary) {
    // Only when the fixed parts alone exceed max_chars (body and notes then got no budget). Never cut
    // through sanitized agent text: a cut can leave a fence or "<pre>" open for what follows.
    summary = safeCut([SUMMARY_TITLE, banner, footer, trustedFooter].filter((s) => s !== "").join("\n\n"), maxSummary);
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
    review = { event, body: `${safeCut(body, MAX_REVIEW_BODY)}\n\n${REVIEW_MARKER}`, comments };
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
    } else if (!inlineEnabled) {
      // Findings are only counted from inline comments; without them the plan cannot tell.
      conclusion = "neutral";
      title = "Review completed (inline findings are disabled by policy)";
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
      title: sliceSafe(title, MAX_CHECK_TITLE),
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
    dismiss_change_requests: dismissChangeRequests,
    dismiss_approvals: dismissApprovals,
    decisions,
    stats,
  };
}

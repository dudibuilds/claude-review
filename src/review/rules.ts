/**
 * Review rules shared by xreview (tool-time feedback), prepare (prompt capability summary) and the
 * publisher (enforcement), so the three cannot drift apart. Pure functions: no I/O, no clock.
 *
 * - Verdict eligibility: changeFacts() computes once what the PR changes (every touched path,
 *   renamed-from paths and triggers.ignore_paths files included, and the changed line count
 *   including ignored files); approveBlockers() / requestChangesBlockers() list every rule that
 *   would make the publisher downgrade the verdict to `comment`. The messages are the publisher's
 *   own footer wording (paths as safe inline code).
 * - Inline comment size: commentFrame() is the publisher's framing of one comment (severity header,
 *   validated ```suggestion block, and the character budget of the sanitized "header + body" part).
 *   `max_comment_chars` limits what the agent wrote: body plus suggestion block; the header the
 *   publisher prepends does not count against it.
 * - Summary size: summaryBudget() is the publisher's layout of the summary comment. Likewise,
 *   `summary_comment.max_chars` limits what the agent wrote (set_summary's body, also once
 *   sanitized); the title, incomplete banner, status footer, trusted footer and the "Notes outside
 *   the diff" sections get their own room on top, so an accepted summary is posted whole.
 * - One entry per path: mergeSamePathDiffs() / mergeSamePathFiles() merge the deletion + addition
 *   halves git emits for a type change (symlink <-> regular file) into one entry, the file as it is
 *   at head, so every consumer agrees on what a path is.
 *
 * Lives under src/review because the review module owns it; it depends only on common/, policy/
 * and the pure sanitize helpers, so prepare and the publisher can import it without cycles.
 */
import type { PrContext, PrFile } from "../common/context.js";
import { changedLineCount, type FileDiff } from "../common/diff.js";
import type { DraftComment } from "../common/draft.js";
import { redactSecrets } from "../common/redact.js";
import { compileGlobs } from "../policy/glob.js";
import { severityRank, type ResolvedPolicy, type Severity } from "../policy/schema.js";
import { inlineCode, singleLine } from "../publish/sanitize.js";

type InlineCommentsPolicy = ResolvedPolicy["capabilities"]["inline_comments"];

function plural(n: number, word: string): string {
  return `${n} ${word}${n === 1 ? "" : "s"}`;
}

/** Inline comments are possible at all (enabled with a non-zero budget). */
export function inlineCommentsEnabled(policy: ResolvedPolicy): boolean {
  const ic = policy.capabilities.inline_comments;
  return ic.enabled && ic.max_comments > 0;
}

/* --------------------------------- change --------------------------------- */

/** What the PR changes, as every verdict rule sees it. */
export interface ChangeFacts {
  /**
   * Every path the PR touches, deduplicated, in a stable order: the reviewed files and their
   * previous paths (renames), the files hidden by triggers.ignore_paths, and the diff's new and old
   * paths. A rename out of `.github/` therefore still counts as touching `.github/`.
   */
  paths: string[];
  /**
   * Changed lines including triggers.ignore_paths files: max(ctx.changed_lines, lines in the diff).
   * ctx.changed_lines alone excludes ignored files.
   */
  changedLines: number;
}

/**
 * Computes ChangeFacts from the PR context and the parsed diff (pass the full diff.patch; an empty
 * diff falls back to the context alone, which misses the line counts of ignored files).
 */
export function changeFacts(
  ctx: Pick<PrContext, "files" | "ignored_files" | "changed_lines">,
  diff: readonly FileDiff[],
): ChangeFacts {
  const paths = [
    ...ctx.files.flatMap((f) => [f.path, f.previous_path]),
    ...ctx.ignored_files,
    ...diff.flatMap((fd) => [fd.path, fd.oldPath]),
  ].filter((p): p is string => typeof p === "string" && p !== "");
  return {
    paths: [...new Set(paths)],
    changedLines: Math.max(ctx.changed_lines, changedLineCount([...diff])),
  };
}

/* --------------------------------- verdict -------------------------------- */

export type VerdictRule = "disabled" | "findings" | "never_paths" | "changed_lines" | "no_inline_comments";

/** One rule that makes the publisher downgrade a verdict to `comment`. */
export interface VerdictBlocker {
  rule: VerdictRule;
  /** The publisher's wording, e.g. `25 changed lines exceed approve.max_changed_lines (10)`. */
  message: string;
  /** never_paths only: the matching paths. */
  paths?: string[];
}

/** Only the severity of a finding matters to the verdict rules. */
export type FindingLike = Pick<DraftComment, "severity">;

/**
 * Every rule that stops `approve`: approve.enabled; no finding above approve.max_severity_allowed;
 * no touched path matching approve.never_paths; changedLines <= approve.max_changed_lines.
 * `findings` = the distinct recorded findings; omit it when they are not known yet (the prompt),
 * which skips the severity rule. Empty result = the publisher keeps the approval (for a finished run).
 */
export function approveBlockers(policy: ResolvedPolicy, facts: ChangeFacts, findings?: readonly FindingLike[]): VerdictBlocker[] {
  const ap = policy.capabilities.approve;
  const out: VerdictBlocker[] = [];
  if (!ap.enabled) out.push({ rule: "disabled", message: "approving is disabled by policy" });
  if (findings !== undefined) {
    const above = findings.filter((f) => severityRank(f.severity) > severityRank(ap.max_severity_allowed)).length;
    if (above > 0) out.push({ rule: "findings", message: `${plural(above, "finding")} above "${ap.max_severity_allowed}"` });
  }
  const never = compileGlobs(ap.never_paths);
  const hits = facts.paths.filter((p) => never(p));
  if (hits.length > 0) {
    const shown = hits.slice(0, 5).map((p) => inlineCode(p, 120)).join(", ");
    out.push({
      rule: "never_paths",
      message: `changed files match approve.never_paths (${shown}${hits.length > 5 ? `, +${hits.length - 5} more` : ""})`,
      paths: hits,
    });
  }
  if (facts.changedLines > ap.max_changed_lines) {
    out.push({
      rule: "changed_lines",
      message: `${facts.changedLines} changed lines exceed approve.max_changed_lines (${ap.max_changed_lines})`,
    });
  }
  return out;
}

/**
 * Every rule that stops `request_changes`: block.enabled; inline comments enabled (findings only
 * come from inline comments); at least one finding >= block.min_severity. Omit `findings` when they
 * are not known yet (the prompt), which skips the last rule.
 */
export function requestChangesBlockers(policy: ResolvedPolicy, findings?: readonly FindingLike[]): VerdictBlocker[] {
  const blk = policy.capabilities.block;
  const out: VerdictBlocker[] = [];
  if (!blk.enabled) out.push({ rule: "disabled", message: "blocking is disabled by policy" });
  if (!inlineCommentsEnabled(policy)) {
    out.push({ rule: "no_inline_comments", message: "inline comments are disabled by policy, so there are no findings to block on" });
  } else if (findings !== undefined && !findings.some((f) => severityRank(f.severity) >= severityRank(blk.min_severity))) {
    out.push({ rule: "findings", message: `no finding at or above "${blk.min_severity}"` });
  }
  return out;
}

/* ----------------------------- inline comments ---------------------------- */

export const SEVERITY_EMOJI: Record<Severity, string> = {
  critical: "\u{1F534}",
  high: "\u{1F7E0}",
  medium: "\u{1F7E1}",
  low: "\u{1F535}",
  info: "⚪",
};

export const SEVERITY_LABEL: Record<Severity, string> = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
  info: "Info",
};

/** A suggestion is dropped (never cut) when a body this short plus its block exceeds the limit. */
export const MIN_COMMENT_BODY = 60;

/** The header the publisher puts above every inline comment body. */
export function commentHeader(severity: Severity, category?: string): string {
  const cat = category ? singleLine(category, 60) : "";
  return `${SEVERITY_EMOJI[severity]} **${SEVERITY_LABEL[severity]}**${cat ? ` · ${cat}` : ""}`;
}

/**
 * Validates and wraps a suggestion exactly as it is posted; returns the block (appended after the
 * sanitized body) or why the publisher drops it. Suggestions are never cut.
 */
export function suggestionBlock(raw: string): { block: string } | { reason: string } {
  let t = raw.replace(/\r\n?/g, "\n");
  if (/^[ \t]*`{3,}/m.test(t)) return { reason: "contains a ``` line" };
  if (/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F‪-‮⁦-⁩]/.test(t)) {
    return { reason: "contains control or bidi characters" };
  }
  if (redactSecrets(t).count > 0) return { reason: "contains a secret" };
  if (t.endsWith("\n")) t = t.slice(0, -1);
  return { block: t === "" ? "\n\n```suggestion\n```" : `\n\n\`\`\`suggestion\n${t}\n\`\`\`` };
}

/** How the publisher frames one inline comment. */
export interface CommentFrame {
  /** Severity/category header (does not count against max_comment_chars). */
  header: string;
  /** The text the publisher sanitizes: `${header}\n\n${body}`. */
  text: string;
  /** Maximum length of the SANITIZED `text`; longer is cut and gets a truncation note. */
  textBudget: number;
  /** The suggestion block appended after the sanitized text ("" when none or dropped). */
  block: string;
  /** Set when the comment carried a suggestion that the publisher drops (with the reason). */
  suggestionDropped?: string;
  /**
   * What max_comment_chars limits: body chars + chars of the valid suggestion block (counted even
   * when the block is then dropped for not fitting). Within the limit, the publisher keeps the
   * suggestion, and the text is cut only if sanitizing makes it longer (see textBudget).
   */
  agentChars: number;
}

/**
 * The publisher's framing of one inline comment. It posts
 * `sanitize(text, textBudget) + block + "\n\n" + marker`.
 */
export function commentFrame(
  ic: Pick<InlineCommentsPolicy, "max_comment_chars" | "suggestions">,
  c: Pick<DraftComment, "body" | "severity" | "category" | "suggestion">,
): CommentFrame {
  const header = commentHeader(c.severity, c.category);
  let wrapped = "";
  let suggestionDropped: string | undefined;
  if (c.suggestion !== undefined) {
    if (!ic.suggestions) suggestionDropped = "suggestions disabled by policy";
    else {
      const r = suggestionBlock(c.suggestion);
      if ("block" in r) wrapped = r.block;
      else suggestionDropped = r.reason;
    }
  }
  let block = wrapped;
  if (block !== "" && Math.min(MIN_COMMENT_BODY, c.body.length) + block.length > ic.max_comment_chars) {
    block = "";
    suggestionDropped = `does not fit max_comment_chars (${ic.max_comment_chars})`;
  }
  return {
    header,
    text: `${header}\n\n${c.body}`,
    textBudget: ic.max_comment_chars - block.length + header.length + 2,
    block,
    ...(suggestionDropped !== undefined ? { suggestionDropped } : {}),
    agentChars: c.body.length + wrapped.length,
  };
}

/* --------------------------------- summary -------------------------------- */

/** Heading of the summary (sticky comment, review body or check-run summary). */
export const SUMMARY_TITLE = "### \u{1F916} Automated review";

/** Shown under the heading when the agent run did not finish. */
export const INCOMPLETE_BANNER =
  "> \u26A0\uFE0F **Incomplete review:** the agent did not finish. Findings may be partial; this review never approves or blocks.";

/** The most the publisher posts as a pull request review body (summary_comment.mode "review"). */
export const MAX_REVIEW_BODY_CHARS = 60000;

/** Room the notes sections keep even when a hard cap squeezes the summary. */
const MIN_NOTES_CHARS = 500;

/**
 * The publisher's layout of the summary: `[title, banner?, body, notes?, footer, trusted footer?]`
 * joined by blank lines. `summary_comment.max_chars` limits the agent's text (bodyChars); every
 * other part has its own budget, so the posted summary can be longer than max_chars, never shorter
 * than the accepted text.
 */
export interface SummaryBudget {
  /**
   * What set_summary accepts: the agent's summary, raw and once sanitized (trimmed, as posted).
   * max_chars, unless the hard cap (sticky comment or review body size) leaves less.
   */
  bodyChars: number;
  /** Maximum length of the sanitized status footer (verdict line, reviewer's reason, verdict notes). */
  footerChars: number;
  /** Room for the sanitized notes sections; body room the summary does not use is added to it. */
  notesChars: number;
  /** Upper bound of the whole posted summary (never above the hard cap). */
  totalChars: number;
}

/**
 * Sizes the summary for `policy`. `stickyLimit` is the publisher's stickySummaryLimit(policy): the
 * largest summary the sticky comment can hold next to the outcome comments (mode "sticky"); mode
 * "review" is capped by MAX_REVIEW_BODY_CHARS instead. The fixed parts are budgeted at their maximum
 * (incomplete banner included), so the result does not depend on how the run ends.
 */
export function summaryBudget(policy: Pick<ResolvedPolicy, "capabilities" | "output">, stickyLimit: number): SummaryBudget {
  const sc = policy.capabilities.summary_comment;
  const max = sc.max_chars;
  const hardCap = sc.mode === "sticky" ? stickyLimit : MAX_REVIEW_BODY_CHARS;
  const footerChars = Math.min(3000, Math.max(200, Math.floor(max / 3)));
  const trusted = policy.output.footer.trim();
  // "\n\n" after the title and after the banner, and before the trusted footer.
  const frame = SUMMARY_TITLE.length + 2 + INCOMPLETE_BANNER.length + 2 + footerChars + (trusted !== "" ? 2 + trusted.length : 0);
  // "\n\n" after the body and after the notes (before the footer).
  const room = Math.max(0, hardCap - frame - 4);
  const notesWanted = Math.max(MIN_NOTES_CHARS, Math.floor(max * 0.4));
  // Under a hard cap the agent's text comes first; the notes keep at least MIN_NOTES_CHARS.
  const bodyChars = Math.max(0, Math.min(max, room - MIN_NOTES_CHARS));
  const notesChars = Math.max(0, Math.min(notesWanted, room - bodyChars));
  return { bodyChars, footerChars, notesChars, totalChars: Math.min(hardCap, frame + 4 + bodyChars + notesChars) };
}

/* ---------------------------- one entry per path --------------------------- */

/** Groups by path (first appearance order) and merges every group of two or more entries. */
function mergeByPath<T extends { path: string }>(items: readonly T[], merge: (group: T[]) => T): T[] {
  const groups = new Map<string, T[]>();
  for (const it of items) {
    const g = groups.get(it.path);
    if (g) g.push(it);
    else groups.set(it.path, [it]);
  }
  if (groups.size === items.length) return [...items];
  return [...groups.values()].map((g) => (g.length === 1 ? g[0]! : merge(g)));
}

/**
 * The file at head of a same-path group: the last entry that does not delete the path. Its status,
 * "added" becoming "modified" when the group also deletes the path (it existed at base); all
 * deletions: the last entry's status.
 */
function headOf<T extends { status: string }>(group: readonly T[], isDeletion: (i: number) => boolean): { head?: T; status: T["status"] | "modified" } {
  for (let i = group.length - 1; i >= 0; i--) {
    if (isDeletion(i)) continue;
    const head = group[i]!;
    return { head, status: head.status === "added" && group.some((_, j) => isDeletion(j)) ? "modified" : head.status };
  }
  return { status: group[group.length - 1]!.status };
}

/** The deleting half of a type change: removed, or a binary section that deletes the file. */
function isDeletionDiff(fd: FileDiff): boolean {
  return fd.status === "removed" || (fd.status === "binary" && /^(?:deleted file mode |Binary files .* and \/dev\/null differ\r?$)/m.test(fd.raw));
}

/**
 * git diff splits a type change (symlink <-> regular file, file <-> submodule) into two sections
 * of the SAME path: a deletion of the old object, then an addition of the new one (`--name-status`
 * says T). Merges every such group into one entry: the file as it is at head (status of the
 * non-deleting half, "added" becoming "modified"), summed counts, all hunks and both sections' raw
 * text in diff order, the line sets of the new side. Without this, consumers disagreed on which
 * half wins (xreview called the new content deleted; PrDiff showed only the old half). Idempotent;
 * other entries are returned unchanged, in order.
 */
export function mergeSamePathDiffs(diff: readonly FileDiff[]): FileDiff[] {
  return mergeByPath(diff, (g) => {
    const { head, status } = headOf(g, (i) => isDeletionDiff(g[i]!));
    const merged: FileDiff = {
      path: g[0]!.path,
      status,
      additions: g.reduce((n, fd) => n + fd.additions, 0),
      deletions: g.reduce((n, fd) => n + fd.deletions, 0),
      hunks: g.flatMap((fd) => fd.hunks),
      raw: g.map((fd) => fd.raw).join(""),
      rightLines: new Set(g.flatMap((fd) => [...fd.rightLines])),
      addedLines: new Set(g.flatMap((fd) => [...fd.addedLines])),
    };
    if (head?.oldPath !== undefined) merged.oldPath = head.oldPath;
    return merged;
  });
}

/**
 * mergeSamePathDiffs for the PR context's file list (prepare's summarizeFiles copies both halves of
 * a type change into ctx.files): one entry per path, the file as it is at head. A PrFile has no raw
 * text, so a "binary" entry before the last one counts as the deleting half (git emits that first).
 */
export function mergeSamePathFiles(files: readonly PrFile[]): PrFile[] {
  return mergeByPath(files, (g) => {
    const isDeletion = (i: number): boolean => g[i]!.status === "removed" || (g[i]!.status === "binary" && i < g.length - 1);
    const { head, status } = headOf(g, isDeletion);
    const merged: PrFile = {
      path: g[0]!.path,
      status,
      additions: g.reduce((n, f) => n + f.additions, 0),
      deletions: g.reduce((n, f) => n + f.deletions, 0),
    };
    if (head?.previous_path !== undefined) merged.previous_path = head.previous_path;
    return merged;
  });
}

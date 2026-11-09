/**
 * `xrepo publish`: the deterministic publisher (no AI). Runs in the publish job, the only job with a
 * GitHub write token (env GITHUB_TOKEN, else GH_TOKEN; API root env GITHUB_API_URL).
 *
 *   xrepo publish --ctx <dir> --draft <draft.jsonl> [--dry-run] [--plan-out <file>]
 *     [--agent-outcome <success|failure|cancelled|skipped>] [--execution-file <path>]
 *     [--skip-reason <text>] [--run-url <url>] [--run-attempt <n>]
 *     [--github-output <path>  (default $GITHUB_OUTPUT)] [--notify-secrets-file <path>]
 *     [--policy <manifest.yaml>  (trusted manifest; when given, ctx/policy.resolved.json is ignored)]
 *     [--self-login <login>  (identity of the token, e.g. "my-app[bot]"; see publish/github.ts)]
 *
 * Flow (SPEC "Outcomes, notifications, retries, workflow chaining"):
 *  1. load ctx (pr.json, diff.patch), draft and execution file; every input may be missing (the
 *     review job can fail early): the PR falls back to $GITHUB_EVENT_PATH. The policy is resolved
 *     from the trusted manifest (--policy) whenever it is given; ctx/policy.resolved.json, which
 *     passed through the agent's job, is only used without --policy (tests, local runs);
 *  2. classify -> completed | incomplete | usage_limit | error | skipped; a policy with
 *     `enabled: false` (kill switch, possibly flipped after prepare) turns every run into skipped.
 *     Freshness (GitHubApi.runFreshness, best effort): a run that no longer reviews the pull
 *     request's head (a re-run of an older workflow run, or a push while it ran), or whose commit a
 *     newer workflow run already published, is "stale": it posts only its check run (which never
 *     overwrites a newer run's check, see github.ts) and writes its outputs; no review, dismissal,
 *     sticky comment, labels, notifications or dispatch, and no `approved` / `blocked`;
 *  3. completed / incomplete: build the review plan (incomplete never approves or blocks), post the
 *     review. When GitHub refuses the APPROVE / REQUEST_CHANGES event itself, or the approval is
 *     withheld because the head moved, the review is posted as a COMMENT and the plan is adjusted
 *     (planAfterRefusedEvent): no `approved` / `blocked` unless a failing check still blocks. A
 *     finished run that does not request changes via a review dismisses our earlier approvals and
 *     our CHANGES_REQUESTED reviews on older commits (dismissStaleChangeRequests); every other run
 *     that does not approve (incomplete, REQUEST_CHANGES, and runs without a plan: skipped, error,
 *     usage_limit, kill switch) dismisses our earlier approvals (dismissStaleApprovals). Both are
 *     best effort;
 *  4. fired outcomes: the primary one, then `approved` / `blocked` derived from the executed plan;
 *  5. sticky comment = plan summary (when summary_comment.mode is sticky) + rendered outcome comments
 *     (a completed review's summary first, otherwise the outcome comments first), marker
 *     <!-- xrepo-review:sticky -->, updated in place. A run with nothing for the sticky (summary in
 *     the review or disabled, no outcome comment; e.g. a skip) replaces an earlier run's sticky with
 *     a short status note (staleStickyNote / runStatusStickyBody), so it never shows a stale result;
 *     it never creates one;
 *  6. check run (only if check.enabled or block uses a check): the plan's conclusion, overridden by
 *     the last fired outcome that configures check_conclusion; a plan that blocks via the check is
 *     only overridden by the `blocked` outcome's own check_conclusion. A blocking check (block.method
 *     check / both) never passes a skip the PR author controls (title marker, size limits, a diff
 *     GitHub refuses) nor a draft skip (it fails as "Review pending" until the PR is marked ready):
 *     see resolveCheck. A run that is not `completed` never posts a passing conclusion over a
 *     failing check on the same commit (keep_failure), and with GITHUB_RUN_ID set no run posts over
 *     a newer workflow run's check (the report then says `superseded`);
 *  7. labels (plan labels, outcome add/remove, retry labels; later wins), notifications, dispatch.
 *     Retry labelling: a usage_limit / error run with retry.enabled below max_attempts adds the retry
 *     label and appends a hidden "retry-after" marker (reset time or backoff, see outcome/retry.ts)
 *     to the sticky comment for the sweeper; at max_attempts it leaves the label and appends a
 *     "retry-stop" marker instead, so the sweeper gives up at this outcome's max_attempts even when
 *     another outcome sharing the label allows more; every other run removes the configured retry
 *     labels;
 *  8. step outputs outcome, verdict, reason, reset_at, findings, top_severity, fired_outcomes
 *     (heredoc syntax);
 *  9. exit 1 only when a fired outcome has fail_job: true or a required GitHub write failed
 *     (review, sticky summary, check run); labels / notifications / dispatch are best effort.
 * --dry-run makes no network calls and prints the plan and every outcome action as JSON.
 */
import { appendFileSync, closeSync, fstatSync, openSync, readFileSync, readSync, writeFileSync } from "node:fs";
import { randomBytes } from "node:crypto";
import { join } from "node:path";
import { parseCli } from "../common/args.js";
import { audit } from "../common/audit.js";
import { CTX_FILES, readContext, type PrContext } from "../common/context.js";
import { parseUnifiedDiff, type FileDiff } from "../common/diff.js";
import { parseDraft, type Draft } from "../common/draft.js";
import { killSwitchReason, loadPolicy, readResolvedPolicy, resolvePolicy } from "../policy/load.js";
import { DEFAULT_OUTCOMES, type OutcomeName, type ResolvedPolicy } from "../policy/schema.js";
import { classifyOutcome, cleanReason, readExecutionFile, type Classification } from "../outcome/classify.js";
import { buildDispatchPayload, repositoryDispatch, type DispatchResult } from "../outcome/dispatch.js";
import { DEFAULT_NOTIFY_SECRETS_FILE, loadNotifySecrets, sendNotifications, type NotifyResult } from "../outcome/notify.js";
import { githubApiBase } from "../outcome/api-base.js";
import { configuredRetryLabels, retryAfterMarker, retryNotBefore, retryStopMarker, type RetryNotBefore } from "../outcome/retry.js";
import {
  DEFAULT_NOTIFY_TEMPLATE,
  markdownEscaper,
  plainEscaper,
  renderTemplate,
  safeUrl,
  slackEscaper,
  type TemplateVars,
} from "../outcome/template.js";
import { inlineCommentsEnabled } from "../review/rules.js";
import {
  createGitHubApi,
  type CheckRunResult,
  type CreateReviewResult,
  type DismissResult,
  type GitHubApi,
  type GitHubApiOptions,
  type RunFreshness,
} from "./github.js";
import { buildPlan, runStatusStickyBody, STICKY_MARKER, stickyCommentBody, type CheckRunConclusion, type PublishPlan } from "./plan.js";
import { inlineCode, safeCut, sanitizeMarkdown } from "./sanitize.js";

const MAX_DRAFT_BYTES = 8 * 1024 * 1024;
const MAX_STICKY_CHARS = 65000;
const MAX_OUTCOME_COMMENT_CHARS = 6000;
const MAX_CHECK_TITLE = 200;
const RETRYABLE_OUTCOMES = new Set<OutcomeName>(["usage_limit", "error"]);
const REPO_RE = /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/;

/* --------------------------------- types --------------------------------- */

/** Minimal PR identity: from pr.json, or from the GitHub event when the context is missing. */
export interface PrInfo {
  repo: string;
  number: number;
  head_sha?: string;
  html_url?: string;
  title?: string;
  author?: string;
  run_url?: string;
}

export type CheckConclusionOut = CheckRunConclusion;

export interface CheckAction {
  name: string;
  conclusion: CheckConclusionOut;
  title: string;
  summary: string;
  /** "plan" or the outcome whose check_conclusion decided. */
  decided_by: string;
}

export interface LabelOps {
  add: string[];
  remove: string[];
}

export interface PlannedNotification {
  outcome: OutcomeName;
  target: string;
  type?: "slack" | "webhook";
  message: string;
}

export interface PlannedDispatch {
  outcome: OutcomeName;
  repo: string;
  event_type: string;
  client_payload: Record<string, unknown>;
}

export interface RetryAction extends Partial<RetryNotBefore> {
  label: string;
  max_attempts: number;
  /** The retry-after marker went into the sticky comment (needs GITHUB_RUN_ID and a sticky body). */
  marker: boolean;
}

/** A retry this run's outcome no longer allows (label left in place for the sweeper to give up). */
export interface RetryExhaustedAction {
  label: string;
  max_attempts: number;
  /** The retry-stop marker went into the sticky comment (needs GITHUB_RUN_ID and a sticky body). */
  marker: boolean;
}

/** Why this run no longer speaks for the pull request (GitHubApi.runFreshness). */
export interface StaleRun {
  reason: string;
  /** The pull request's current head. */
  head_sha?: string;
  /** A newer workflow run that already published a check for this commit. */
  newer_run?: number;
}

export interface PublishReport {
  dry_run: boolean;
  outcome: Classification;
  fired: OutcomeName[];
  pr: PrInfo | null;
  plan: PublishPlan | null;
  /**
   * Set when this run is stale (a re-run of an older workflow run, a push while it ran, or a newer
   * run already published this commit): only the check run and the outputs were written.
   */
  stale?: StaleRun;
  actions: {
    review: {
      event: string;
      comments: number;
      posted: boolean;
      /** Set when GitHub refused this event and the review was posted as a COMMENT. */
      refused_event?: string;
    } | null;
    /** `replaces_stale`: a status note that replaced an earlier run's sticky (nothing else to post). */
    sticky: { body: string; posted: boolean; replaces_stale?: boolean } | null;
    /**
     * Our earlier reviews to dismiss (PublishPlan.dismiss_change_requests): earlier approvals, and
     * change requests on older commits (GitHubApi.dismissStaleChangeRequests).
     */
    dismiss?: { message: string; result?: DismissResult };
    /**
     * Our earlier approvals to dismiss (GitHubApi.dismissStaleApprovals): every run that does not
     * approve and did not dismiss them above, runs without a plan included.
     */
    dismiss_approvals?: { message: string; result?: DismissResult };
    /** `superseded`: nothing was posted, the named check run stays in force (see github.ts createCheckRun). */
    check: (CheckAction & { posted: boolean; superseded?: CheckRunResult["superseded"] }) | null;
    labels: LabelOps;
    /** Retry requested by this run (retry label added), or null. */
    retry: RetryAction | null;
    /** Set when this run's outcome reached its retry max_attempts (retry-stop marker for the sweeper). */
    retry_exhausted?: RetryExhaustedAction;
    notify: (PlannedNotification & { result?: NotifyResult })[];
    dispatch: (PlannedDispatch & { result?: DispatchResult })[];
  };
  outputs: Record<string, string>;
  errors: string[];
  exit_code: number;
}

export interface PublishDeps {
  /** GitHub client factory (tests inject a fake). */
  createApi?: (opts: GitHubApiOptions) => GitHubApi;
  /** fetch for notifications and dispatch. */
  fetchImpl?: typeof fetch;
  env?: Record<string, string | undefined>;
  stdout?: { write(s: string): unknown };
  stderr?: { write(s: string): unknown };
  /** Clock for webhook signatures and retry timing (unix seconds). */
  nowSeconds?: () => number;
}

/* -------------------------------- helpers -------------------------------- */

function readTextCapped(path: string, maxBytes: number): string | undefined {
  let fd: number | undefined;
  try {
    fd = openSync(path, "r");
    const st = fstatSync(fd);
    if (!st.isFile()) return undefined;
    const len = Math.min(st.size, maxBytes);
    const buf = Buffer.alloc(len);
    let off = 0;
    while (off < len) {
      const n = readSync(fd, buf, off, len - off, off);
      if (n <= 0) break;
      off += n;
    }
    let text = buf.subarray(0, off).toString("utf8");
    if (st.size > len) text = text.slice(0, Math.max(0, text.lastIndexOf("\n"))); // whole lines only
    return text;
  } catch {
    return undefined;
  } finally {
    if (fd !== undefined) {
      try {
        closeSync(fd);
      } catch {
        /* ignore */
      }
    }
  }
}

/** A DismissResult from a (possibly sloppy) client, normalised for the report. */
function dismissResult(res: DismissResult | undefined): DismissResult {
  return {
    dismissed: Array.isArray(res?.dismissed) ? res.dismissed : [],
    failed: Array.isArray(res?.failed) ? res.failed : [],
    ...(typeof res?.kept === "string" && res.kept !== "" ? { kept: res.kept } : {}),
  };
}

function shortError(e: unknown): string {
  return cleanReason((e as Error)?.message ?? String(e), 300);
}

function isRepo(s: unknown): s is string {
  return typeof s === "string" && REPO_RE.test(s) && !s.split("/").some((seg) => seg === "." || seg === "..");
}

function prFromContext(ctx: PrContext): PrInfo {
  return {
    repo: ctx.repo,
    number: ctx.number,
    head_sha: ctx.head_sha,
    html_url: ctx.html_url,
    title: ctx.title,
    author: ctx.author,
    ...(ctx.run_url ? { run_url: ctx.run_url } : {}),
  };
}

/** PR identity from the GitHub event payload ($GITHUB_EVENT_PATH), for runs whose ctx is missing. */
export function prFromEvent(env: Record<string, string | undefined>): PrInfo | undefined {
  const path = env.GITHUB_EVENT_PATH;
  if (!path) return undefined;
  const text = readTextCapped(path, 25 * 1024 * 1024);
  if (text === undefined) return undefined;
  try {
    const ev = JSON.parse(text) as Record<string, unknown>;
    const pr = (ev.pull_request ?? null) as Record<string, unknown> | null;
    if (!pr || typeof pr !== "object") return undefined;
    const base = (pr.base ?? {}) as { repo?: { full_name?: unknown } };
    const head = (pr.head ?? {}) as { sha?: unknown };
    const repo = isRepo(base.repo?.full_name) ? base.repo.full_name : env.GITHUB_REPOSITORY;
    const number = pr.number;
    if (!isRepo(repo) || typeof number !== "number" || !Number.isInteger(number) || number <= 0) return undefined;
    const user = (pr.user ?? {}) as { login?: unknown };
    return {
      repo,
      number,
      ...(typeof head.sha === "string" && /^[0-9a-f]{7,64}$/i.test(head.sha) ? { head_sha: head.sha } : {}),
      ...(typeof pr.html_url === "string" ? { html_url: pr.html_url } : {}),
      ...(typeof pr.title === "string" ? { title: pr.title } : {}),
      ...(typeof user.login === "string" ? { author: user.login } : {}),
    };
  } catch {
    return undefined;
  }
}

function defaultRunUrl(env: Record<string, string | undefined>): string | undefined {
  const server = (env.GITHUB_SERVER_URL ?? "").replace(/\/+$/, "");
  const repo = env.GITHUB_REPOSITORY;
  const id = env.GITHUB_RUN_ID;
  if (!server || !isRepo(repo) || !id || !/^\d+$/.test(id)) return undefined;
  return `${server}/${repo}/actions/runs/${id}`;
}

/* --------------------------- outcome composition -------------------------- */

export function buildTemplateVars(input: {
  pr?: PrInfo;
  cls: Classification;
  plan?: PublishPlan;
  runUrl?: string;
  attempt: number;
}): TemplateVars {
  const { pr, cls, plan } = input;
  return {
    repo: pr?.repo,
    pr_number: pr?.number,
    pr_url: pr?.html_url,
    pr_title: pr?.title,
    author: pr?.author,
    outcome: cls.outcome,
    reason: cls.reason,
    reset_at: cls.reset_at,
    verdict: plan?.verdict,
    findings: plan?.findings ?? 0,
    top_severity: plan?.top_severity,
    run_url: input.runUrl,
    attempt: input.attempt,
  };
}

/** Outcome comment for the sticky: trusted template, values escaped for markdown. "" = none. */
export function renderOutcomeComment(policy: ResolvedPolicy, outcome: OutcomeName, vars: TemplateVars): string {
  const tpl = policy.outcomes[outcome].comment;
  if (!tpl || tpl.trim() === "") return "";
  const text = renderTemplate(tpl, { ...vars, outcome }, markdownEscaper({ linkAllowlist: policy.output.link_allowlist })).trim();
  return safeCut(text, MAX_OUTCOME_COMMENT_CHARS);
}

/**
 * Sticky comment body: a completed review's summary first and outcome comments appended; for other
 * outcomes the outcome comments come first. undefined when there is nothing to post. `trailer`
 * (trusted hidden markers, e.g. the retry-after marker) is appended after a blank line; it never
 * makes an otherwise empty sticky worth posting.
 */
export function composeSticky(primary: OutcomeName, summary: string | undefined, outcomeComments: string[], trailer?: string): string | undefined {
  const comments = outcomeComments.filter((c) => c.trim() !== "");
  const commentsText = comments.join("\n\n");
  const tail = trailer && trailer.trim() !== "" ? `\n\n${trailer.trim()}` : "";
  const room = MAX_STICKY_CHARS - STICKY_MARKER.length - 1 - tail.length;
  let summaryText = summary && summary.trim() !== "" ? summary : "";
  if (summaryText === "" && commentsText === "") return undefined;
  const sep = summaryText !== "" && commentsText !== "" ? 2 : 0;
  const cappedComments = safeCut(commentsText, room);
  if (summaryText !== "") summaryText = safeCut(summaryText, Math.max(0, room - cappedComments.length - sep));
  const parts = primary === "completed" ? [summaryText, cappedComments] : [cappedComments, summaryText];
  return stickyCommentBody(parts.filter((p) => p !== "").join("\n\n") + tail);
}

function checkTitle(outcome: OutcomeName, cls: Classification): string {
  switch (outcome) {
    case "usage_limit":
      return `Review postponed: usage limit reached${cls.reset_at ? ` (resets ${cls.reset_at})` : ""}`;
    case "error":
      return `Review could not run: ${cls.reason}`;
    case "skipped":
      return `Review skipped: ${cls.reason}`;
    case "incomplete":
      return "Review incomplete";
    default:
      return "Automated review";
  }
}

/* ------------------------- author-controlled skips ------------------------ */

/**
 * Skip reasons (prepare.shouldSkip / prepare's diff checks) the PR author controls: title markers,
 * the size limits, a diff too large for the GitHub API and a diff GitHub refuses (.gitattributes).
 */
const AUTHOR_SKIP_REASONS: readonly RegExp[] = [
  /^title contains /i,
  /^\d+ changed files \(limit \d+\)/i,
  /^\d+ changed lines \(limit \d+\)/i,
  /^diff larger than /i,
  /^diff refused: /i,
];
/**
 * prepare's draft skip. Not author-controlled in the sense above (the caller re-runs on
 * ready_for_review), but a blocking check must not pass while the review has not run: marking the
 * PR ready and merging at once would otherwise beat the review (see resolveCheck).
 */
const DRAFT_SKIP_RE = /^draft pull request$/i;
/** Skip reasons decided by devops or GitHub state, not by the author's title or diff size. */
const OTHER_SKIP_REASONS: readonly RegExp[] = [
  /^reviews are disabled for this repository/i,
  /^pull request from a fork$/i,
  /^author .+ is a bot$/i,
  /^author .+ is in triggers\.ignore_authors$/i,
  /^every changed file matches triggers\.ignore_paths$/i,
  /^no changed files$/i,
  /^no changed file matches triggers\.include_paths$/i,
];

export interface SkipFacts {
  title?: string;
  files?: number;
  changed_lines?: number;
}

/**
 * Whether a skip was decided by something the PR author controls (a title marker, the size limits,
 * a diff GitHub will not serve). A draft skip is not (resolveCheck treats it separately). prepare's
 * reason is recognised first; for any other reason the PR itself is checked against
 * policy.triggers (fail closed: an unrecognised reason with a marker in the title counts).
 */
export function authorControlledSkip(policy: ResolvedPolicy, reason: string, facts: SkipFacts = {}): boolean {
  const r = reason.trim();
  if (AUTHOR_SKIP_REASONS.some((re) => re.test(r))) return true;
  if (DRAFT_SKIP_RE.test(r) || OTHER_SKIP_REASONS.some((re) => re.test(r))) return false;
  const t = policy.triggers;
  const title = (facts.title ?? "").toLowerCase();
  if (title !== "" && t.skip_title_markers.some((m) => m.trim() !== "" && title.includes(m.toLowerCase()))) return true;
  if (facts.files !== undefined && facts.files > t.max_changed_files) return true;
  return facts.changed_lines !== undefined && facts.changed_lines > t.max_changed_lines;
}

const PASSING_CONCLUSIONS = new Set<CheckConclusionOut>(["success", "neutral", "skipped"]);
/** Title of a blocking check while the pull request is a draft (resolveCheck). */
export const DRAFT_PENDING_TITLE = "Review pending: draft pull request (runs when marked ready)";

/** Check run, or undefined when neither check.enabled nor a check-based block is configured. */
export function resolveCheck(input: {
  policy: ResolvedPolicy;
  plan?: PublishPlan;
  fired: OutcomeName[];
  cls: Classification;
  outcomeComments: string[];
  /** PR facts for a `skipped` run (see authorControlledSkip). */
  skipFacts?: SkipFacts;
}): CheckAction | undefined {
  const { policy, plan, fired, cls } = input;
  const caps = policy.capabilities;
  const blockingCheck = caps.block.enabled && caps.block.method !== "review";
  const wanted = caps.check.enabled || blockingCheck;
  if (!wanted) return undefined;
  let conclusion: CheckConclusionOut | undefined = plan?.check?.conclusion;
  let decidedBy = conclusion !== undefined ? "plan" : "";
  // A plan that blocks via the check (failure) is only overridden by the `blocked` outcome's own
  // check_conclusion: e.g. `completed: {check_conclusion: success}` must not pass a blocked PR.
  const planBlocksViaCheck = plan?.blocked === true && plan.check?.conclusion === "failure";
  for (const o of fired) {
    const c = policy.outcomes[o].check_conclusion;
    if (c === undefined) continue;
    if (planBlocksViaCheck && o !== "blocked") {
      if (c !== "failure") audit("publish.check_override_ignored", { outcome: o, configured: c, reason: "the review blocks via the check" });
      continue;
    }
    conclusion = c;
    decidedBy = o;
  }
  if (conclusion === undefined) {
    conclusion = "neutral";
    decidedBy = "default";
  }
  const primary = fired[0] ?? cls.outcome;
  // A blocking check is meant to be required; GitHub counts success / neutral / skipped as passing.
  // The PR author must not be able to pass it by skipping the review (title marker, size limits),
  // so such a skip fails the check. Only an explicitly configured passing conclusion other than the
  // built-in default (outcomes.skipped.check_conclusion: success | neutral) lets it pass.
  const skipMayFail =
    primary === "skipped" &&
    blockingCheck &&
    PASSING_CONCLUSIONS.has(conclusion) &&
    (decidedBy !== "skipped" || conclusion === DEFAULT_OUTCOMES.skipped.check_conclusion);
  // A draft is reviewed once it is marked ready (ready_for_review). Until that review posts its own
  // check, the blocking check stays failing: "mark ready and merge at once" must not pass it.
  if (skipMayFail && DRAFT_SKIP_RE.test(cls.reason.trim())) {
    audit("publish.blocking_check_skip", { reason: cls.reason, configured: conclusion, conclusion: "failure" });
    const summary = sanitizeMarkdown(
      "The automated review runs when the pull request is marked ready for review. This check blocks merging until that review has run.",
      { allowMentions: false, allowImages: false, linkAllowlist: policy.output.link_allowlist, maxChars: 1000 },
    );
    return { name: caps.check.name, conclusion: "failure", title: DRAFT_PENDING_TITLE, summary, decided_by: "blocking_check" };
  }
  if (skipMayFail && authorControlledSkip(policy, cls.reason, input.skipFacts)) {
    audit("publish.blocking_check_skip", { reason: cls.reason, configured: conclusion, conclusion: "failure" });
    const title = cleanReason(`Review required: skipped by the pull request (${cls.reason})`, MAX_CHECK_TITLE);
    const summary = sanitizeMarkdown(
      `The automated review was skipped (${cls.reason}). This check blocks merging and cannot be passed by skipping the review: ` +
        "remove the skip marker from the title or split the pull request, then push a new commit; or ask a maintainer to merge it.",
      { allowMentions: false, allowImages: false, linkAllowlist: policy.output.link_allowlist, maxChars: 1000 },
    );
    return { name: caps.check.name, conclusion: "failure", title: title.slice(0, MAX_CHECK_TITLE), summary, decided_by: "blocking_check" };
  }
  let title = plan?.check?.title ?? cleanReason(checkTitle(primary, cls), MAX_CHECK_TITLE);
  // An outcome override that changes the plan's conclusion says so, so the title (e.g. "Changes
  // requested: ...") never contradicts the conclusion it is shown with.
  if (plan?.check && decidedBy !== "plan" && conclusion !== plan.check.conclusion) {
    title = cleanReason(`${plan.check.title} (check ${conclusion}: outcomes.${decidedBy}.check_conclusion)`, MAX_CHECK_TITLE);
  }
  const fallbackSummary = sanitizeMarkdown(cls.reason || primary, {
    allowMentions: false,
    allowImages: false,
    linkAllowlist: policy.output.link_allowlist,
    maxChars: 1000,
  });
  const comments = input.outcomeComments.filter((c) => c.trim() !== "").join("\n\n");
  const summary = plan?.check?.summary ?? (comments !== "" ? comments : fallbackSummary);
  return { name: caps.check.name, conclusion, title: title.slice(0, MAX_CHECK_TITLE), summary, decided_by: decidedBy };
}

/**
 * The plan after the review's APPROVE / REQUEST_CHANGES event was not submitted and the review was
 * posted as a COMMENT instead (GitHubApi.createReview with downgradeRefusedEvent): GitHub refused
 * the event, or (`withheld`) the approval was withheld because the reviewed commit is no longer the
 * pull request's head. No approval (earlier ones are dismissed: dismiss_approvals); no block unless
 * the failing check still blocks (block.method both); verdict, check and summary say so. Pure.
 */
export function planAfterRefusedEvent(
  plan: PublishPlan,
  refused: NonNullable<CreateReviewResult["downgraded"]>,
  policy: ResolvedPolicy,
): PublishPlan {
  const blk = policy.capabilities.block;
  const what = refused.from === "APPROVE" ? "it does not approve the pull request" : "it does not request changes";
  const withheld = refused.withheld === true && refused.from === "APPROVE";
  const note = sanitizeMarkdown(
    withheld
      ? `> **Note:** The review was not submitted as an approval (${inlineCode(refused.reason, 200)}), so it was posted as a comment: ${what}.`
      : `> **Note:** GitHub refused to submit the review as ${refused.from} (${inlineCode(refused.reason, 200)}), so it was posted as a comment: ${what}.`,
    { allowMentions: false, allowImages: false, linkAllowlist: [], maxChars: 600 },
  );
  const decisions = [
    ...plan.decisions,
    withheld ? `approval withheld (${refused.reason}): posted as COMMENT` : `GitHub refused the ${refused.from} review (${refused.reason}): posted as COMMENT`,
  ];
  const review = plan.review ? { ...plan.review, event: "COMMENT" as const } : undefined;
  const stillBlocked = refused.from === "REQUEST_CHANGES" && plan.blocked && blk.method === "both" && plan.check?.conclusion === "failure";
  if (stillBlocked) decisions.push("still blocking via the failing check (block.method both)");
  const approved = false;
  const blocked = refused.from === "REQUEST_CHANGES" ? stillBlocked : plan.blocked;
  const verdict = blocked ? plan.verdict : "comment";
  const summary = plan.summaryTarget === "sticky" ? `${plan.summary}\n\n${note}` : plan.summary;
  let check = plan.check;
  if (check && refused.from === "APPROVE") {
    check = {
      ...check,
      // What the plan concludes without an approval (plan.ts): success only for a clean review.
      conclusion: plan.findings === 0 && inlineCommentsEnabled(policy) ? "success" : "neutral",
      title: cleanReason(
        `${withheld ? "Approval withheld" : "Approval refused by GitHub"}, posted as a comment${plan.findings > 0 ? ` (${plan.findings} finding${plan.findings === 1 ? "" : "s"})` : ""}`,
        MAX_CHECK_TITLE,
      ),
    };
  } else if (check && refused.from === "REQUEST_CHANGES" && !stillBlocked && check.conclusion === "failure") {
    check = { ...check, conclusion: "neutral", title: cleanReason("Request for changes refused by GitHub, posted as a comment", MAX_CHECK_TITLE) };
  }
  if (check && plan.summaryTarget === "sticky") check = { ...check, summary: safeCut(summary, 65535) };
  return {
    ...plan,
    ...(review ? { review } : {}),
    summary,
    ...(check ? { check } : {}),
    verdict,
    approved,
    blocked,
    // A refused request for changes keeps our earlier ones (the run did want to block).
    dismiss_change_requests: refused.from === "REQUEST_CHANGES" ? false : plan.dismiss_change_requests === true,
    // This run approves nothing now, so no earlier approval of ours may stay in force.
    dismiss_approvals: refused.from === "APPROVE" ? true : plan.dismiss_approvals === true,
    decisions,
  };
}

/**
 * Status note that replaces an earlier run's sticky comment when this review run has nothing for
 * the sticky (summary in the review or disabled, no outcome comment): trusted text only.
 */
export function staleStickyNote(plan: PublishPlan, cls: Classification, headSha?: string): string {
  const commit = headSha && /^[0-9a-f]{7,64}$/i.test(headSha) ? ` of commit ${headSha.slice(0, 7)}` : "";
  const findings = `${plan.findings} finding${plan.findings === 1 ? "" : "s"}`;
  const where = plan.review ? " Its results are in the pull request review." : "";
  const head =
    cls.outcome === "incomplete"
      ? `The latest automated review${commit} did not finish (verdict: ${plan.verdict}, ${findings}).`
      : `The latest automated review${commit} completed (verdict: ${plan.verdict}, ${findings}).`;
  return stickyCommentBody(`${head}${where} An earlier status message in this comment is no longer current.`);
}

/** The retry this run requests: the primary outcome is usage_limit / error with retry.enabled and attempt < max_attempts. */
export function plannedRetry(policy: ResolvedPolicy, primary: OutcomeName, attempt: number): { label: string; max_attempts: number } | undefined {
  if (!RETRYABLE_OUTCOMES.has(primary)) return undefined;
  const r = policy.outcomes[primary].retry;
  return r?.enabled && attempt < r.max_attempts ? { label: r.label, max_attempts: r.max_attempts } : undefined;
}

/**
 * The retry this run gives up on: the primary outcome is usage_limit / error with retry.enabled and
 * attempt >= max_attempts. Its label stays (computeLabelOps) and the sticky gets a retry-stop marker,
 * so the sweeper gives up at this outcome's max_attempts even when the label is shared with an
 * outcome that allows more attempts.
 */
export function exhaustedRetry(policy: ResolvedPolicy, primary: OutcomeName, attempt: number): { label: string; max_attempts: number } | undefined {
  if (!RETRYABLE_OUTCOMES.has(primary)) return undefined;
  const r = policy.outcomes[primary].retry;
  return r?.enabled && attempt >= r.max_attempts ? { label: r.label, max_attempts: r.max_attempts } : undefined;
}

/**
 * Label changes: plan labels (add), then per fired outcome remove_labels and add_labels, then the
 * retry labels: a retryable outcome (usage_limit / error with retry.enabled) adds its label below
 * max_attempts and leaves it in place at max_attempts (the sweeper then gives up and comments once);
 * every other run (completed, incomplete, skipped, an error without retry, ...) removes every
 * configured retry label, so the sweeper never re-runs a run that did not ask for it. Later
 * operations win; comparison is case-insensitive.
 */
export function computeLabelOps(input: {
  policy: ResolvedPolicy;
  plan?: PublishPlan;
  fired: OutcomeName[];
  primary: OutcomeName;
  attempt: number;
}): LabelOps {
  const ops = new Map<string, { name: string; op: "add" | "remove" }>();
  const set = (name: string, op: "add" | "remove"): void => {
    ops.set(name.toLowerCase(), { name, op });
  };
  for (const l of input.plan?.labels ?? []) set(l, "add");
  for (const o of input.fired) {
    const a = input.policy.outcomes[o];
    for (const l of a.remove_labels) set(l, "remove");
    for (const l of a.add_labels) set(l, "add");
  }
  const keep = new Set<string>();
  for (const o of input.fired) {
    const r = input.policy.outcomes[o].retry;
    if (!r?.enabled) continue;
    if (!RETRYABLE_OUTCOMES.has(o)) {
      audit("publish.retry_ignored", { outcome: o, reason: "retry applies to usage_limit and error only" });
      continue;
    }
    keep.add(r.label.toLowerCase());
    if (input.attempt < r.max_attempts) set(r.label, "add");
    else audit("publish.retry_exhausted", { outcome: o, attempt: input.attempt, max_attempts: r.max_attempts });
  }
  for (const l of configuredRetryLabels(input.policy)) if (!keep.has(l.toLowerCase())) set(l, "remove");
  const add: string[] = [];
  const remove: string[] = [];
  for (const { name, op } of ops.values()) (op === "add" ? add : remove).push(name);
  return { add, remove };
}

/* -------------------------------- outputs -------------------------------- */

/** Append step outputs in GitHub's multiline syntax with random, collision-checked delimiters. */
export function writeGithubOutputs(path: string, values: Record<string, string>): void {
  let out = "";
  for (const [k, raw] of Object.entries(values)) {
    if (!/^[A-Za-z_][A-Za-z0-9_-]*$/.test(k)) throw new Error(`invalid output name ${JSON.stringify(k)}`);
    const v = String(raw ?? "").replace(/\r\n?/g, "\n");
    let delim = `ghadelimiter_${randomBytes(16).toString("hex")}`;
    while (v.includes(delim) || k.includes(delim)) delim = `ghadelimiter_${randomBytes(16).toString("hex")}`;
    out += `${k}<<${delim}\n${v}\n${delim}\n`;
  }
  appendFileSync(path, out, { encoding: "utf8" });
}

/* ---------------------------------- main ---------------------------------- */

export const USAGE =
  "usage: xrepo publish --ctx <dir> --draft <file> [--dry-run] [--plan-out <file>] [--agent-outcome <s>] " +
  "[--execution-file <path>] [--skip-reason <s>] [--run-url <url>] [--run-attempt <n>] [--github-output <path>] " +
  "[--notify-secrets-file <path>] [--policy <manifest>] [--self-login <login>]";

const EMPTY_DRAFT: Draft = { comments: [], labels: [], finished: false, invalidLines: 0 };

export async function main(args: string[], deps: PublishDeps = {}): Promise<number> {
  const env = deps.env ?? process.env;
  const stdout = deps.stdout ?? process.stdout;
  const stderr = deps.stderr ?? process.stderr;
  const fetchImpl = deps.fetchImpl ?? fetch;

  /* ---- flags ---- */
  let v: Record<string, string | boolean | string[] | undefined>;
  let attempt = 1;
  try {
    v = parseCli(args, {
      ctx: { type: "string", required: true },
      draft: { type: "string", required: true },
      "dry-run": { type: "boolean" },
      "plan-out": { type: "string" },
      "agent-outcome": { type: "string" },
      "execution-file": { type: "string" },
      "skip-reason": { type: "string" },
      "run-url": { type: "string" },
      "run-attempt": { type: "string" },
      "github-output": { type: "string" },
      "notify-secrets-file": { type: "string" },
      policy: { type: "string" },
      "self-login": { type: "string" },
    });
    const rawAttempt = ((v["run-attempt"] as string | undefined) ?? env.GITHUB_RUN_ATTEMPT ?? "").trim();
    if (rawAttempt !== "") {
      if (!/^\d{1,6}$/.test(rawAttempt) || Number(rawAttempt) < 1) throw new Error(`--run-attempt must be a positive integer, got ${JSON.stringify(rawAttempt)}`);
      attempt = Number(rawAttempt);
    }
  } catch (e) {
    stderr.write(`xrepo publish: ${(e as Error).message}\n${USAGE}\n`);
    return 2;
  }
  const dryRun = v["dry-run"] === true;
  const ctxDir = v.ctx as string;
  const errors: string[] = [];
  let infraFailure = false;
  const infra = (what: string, e?: unknown): void => {
    infraFailure = true;
    const msg = e === undefined ? what : `${what}: ${shortError(e)}`;
    errors.push(msg);
    audit("publish.infra_failure", { what, ...(e !== undefined ? { error: e } : {}) });
  };

  /* ---- 1. inputs (each may be missing) ---- */
  let ctx: PrContext | undefined;
  let ctxError: string | undefined;
  try {
    ctx = readContext(ctxDir);
  } catch (e) {
    ctxError = shortError(e);
    audit("publish.ctx_missing", { error: e });
  }
  const pr: PrInfo | undefined = ctx ? prFromContext(ctx) : prFromEvent(env);

  // The trusted manifest wins whenever it is given: ctx/policy.resolved.json is an artifact of the
  // agent's job, so it is only read without --policy (tests, local runs).
  let policy: ResolvedPolicy | undefined;
  const manifest = ((v.policy as string | undefined) ?? "").trim();
  if (manifest !== "") {
    if (pr) {
      try {
        policy = resolvePolicy(loadPolicy(manifest), pr.repo);
        audit("publish.policy", { source: "manifest", repo: pr.repo });
      } catch (e) {
        infra("loading the policy manifest (--policy) failed", e);
      }
    }
  } else {
    try {
      policy = readResolvedPolicy(join(ctxDir, CTX_FILES.policy));
      audit("publish.policy", { source: "ctx", repo: policy.repo });
    } catch (e) {
      audit("publish.policy_unavailable", { error: e });
    }
  }
  let integrityError = false;
  if (policy && pr && policy.repo.toLowerCase() !== pr.repo.toLowerCase()) {
    integrityError = true;
    infra(`resolved policy is for ${policy.repo} but the PR is in ${pr.repo}`);
  }

  let diff: FileDiff[] = [];
  if (ctx) {
    try {
      diff = parseUnifiedDiff(readFileSync(join(ctxDir, CTX_FILES.diff), "utf8"));
    } catch (e) {
      audit("publish.diff_missing", { error: e });
    }
  }
  const draftText = readTextCapped(v.draft as string, MAX_DRAFT_BYTES);
  const draft: Draft | undefined = draftText === undefined ? undefined : parseDraft(draftText);
  const execPath = v["execution-file"] as string | undefined;
  const executionFileText = execPath ? readExecutionFile(execPath) : undefined;
  if (execPath && executionFileText === undefined) audit("publish.execution_file_missing", { path: execPath });

  /* ---- 2. classify ---- */
  const skipReason = v["skip-reason"] as string | undefined;
  const agentOutcome = ((v["agent-outcome"] as string | undefined) ?? "").trim() || undefined;
  let cls = classifyOutcome({
    ...(skipReason !== undefined && skipReason.trim() !== "" ? { skipped: { reason: skipReason } } : {}),
    ...(agentOutcome ? { agentStepOutcome: agentOutcome } : {}),
    ...(executionFileText !== undefined ? { executionFileText } : {}),
    ...(draft ? { draft } : {}),
  });
  if ((cls.outcome === "completed" || cls.outcome === "incomplete") && (!ctx || !policy || integrityError)) {
    cls = { outcome: "error", reason: `review context unavailable (${!ctx ? "PR context missing" : !policy ? "resolved policy missing" : "policy does not match the PR"})` };
  } else if (cls.outcome === "error" && !ctx && agentOutcome !== "cancelled" && executionFileText === undefined) {
    cls = { outcome: "error", reason: "the review job failed before the agent ran (review context missing)" };
  }
  // Kill switch: the policy may have been set to `enabled: false` after prepare ran. Never review,
  // approve, block, label, notify or dispatch under a disabled policy: only the `skipped` outcome's
  // own actions run.
  const killed = policy && !integrityError ? killSwitchReason(policy) : undefined;
  if (killed !== undefined && cls.outcome !== "skipped") {
    audit("publish.kill_switch", { repo: policy?.repo, overridden: cls.outcome });
    cls = { outcome: "skipped", reason: killed };
  }
  audit("publish.outcome", { outcome: cls.outcome, reason: cls.reason, reset_at: cls.reset_at, attempt, dry_run: dryRun });

  /* ---- GitHub client (lazy) ---- */
  const runId = (env.GITHUB_RUN_ID ?? "").trim();
  const runIdOk = /^[1-9]\d{0,15}$/.test(runId);
  const hasToken = (env.GITHUB_TOKEN ?? env.GH_TOKEN ?? "").trim() !== "";
  let api: GitHubApi | undefined;
  let apiUnavailable = false;
  const getApi = (): GitHubApi | undefined => {
    if (dryRun || apiUnavailable || !pr || integrityError) return undefined;
    if (api) return api;
    const token = (env.GITHUB_TOKEN ?? env.GH_TOKEN ?? "").trim();
    if (!token) {
      apiUnavailable = true;
      infra("no GitHub token (env GITHUB_TOKEN)");
      return undefined;
    }
    try {
      githubApiBase(env); // fail closed on an invalid GITHUB_API_URL (throws)
      const factory = deps.createApi ?? createGitHubApi;
      const baseUrl = env.GITHUB_API_URL?.trim();
      const selfLogin = (v["self-login"] as string | undefined)?.trim() || env.XREPO_SELF_LOGIN?.trim();
      api = factory({
        token,
        repo: pr.repo,
        prNumber: pr.number,
        headSha: pr.head_sha ?? "",
        ...(baseUrl ? { baseUrl } : {}),
        ...(selfLogin ? { selfLogin } : {}),
        // Check runs carry the workflow run; a newer run's check for the same commit is never overwritten.
        ...(runIdOk ? { run: { id: Number(runId), attempt } } : {}),
      });
      return api;
    } catch (e) {
      apiUnavailable = true;
      infra("cannot create the GitHub client", e);
      return undefined;
    }
  };

  // Best-effort reads and dismissals never make a missing token an infrastructure failure by
  // themselves (the writes that need the token report it).
  const optionalApi = (): GitHubApi | undefined => (hasToken ? getApi() : undefined);

  /* ---- freshness: a stale run publishes only its check ---- */
  let stale: StaleRun | undefined;
  if (policy && pr?.head_sha && !integrityError) {
    const gh = optionalApi();
    if (gh?.runFreshness) {
      try {
        const f: RunFreshness = await gh.runFreshness(policy.capabilities.check.name);
        if (!f.current) {
          stale = { reason: f.reason ?? "this run no longer reviews the pull request's head", head_sha: f.head_sha, ...(f.newer_run !== undefined ? { newer_run: f.newer_run } : {}) };
          audit("publish.stale_run", { ...stale, outcome: cls.outcome });
        }
      } catch (e) {
        // Unknown: publish as usual. Approvals are still only submitted for the current head
        // (createReview verifies it) and change requests only dismissed by a run for it.
        audit("publish.freshness_unknown", { error: e });
      }
    }
  }

  /* ---- 3. review plan ---- */
  let plan: PublishPlan | undefined;
  let reviewPosted = false;
  let refusedEvent: string | undefined;
  let dismiss: PublishReport["actions"]["dismiss"];
  let dismissApprovals: PublishReport["actions"]["dismiss_approvals"];
  if ((cls.outcome === "completed" || cls.outcome === "incomplete") && ctx && policy) {
    let existing = new Set<string>();
    const gh = stale ? undefined : getApi();
    if (gh) {
      try {
        existing = await gh.listReviewCommentKeys();
      } catch (e) {
        audit("publish.list_keys_failed", { error: e, note: "inline comments may be duplicated" });
      }
    }
    try {
      plan = buildPlan({ policy, ctx, diff, draft: draft ?? EMPTY_DRAFT, existingCommentKeys: existing, incomplete: cls.outcome === "incomplete" });
      for (const d of plan.decisions) audit("publish.decision", { decision: d });
    } catch (e) {
      infra("building the review plan failed", e);
      cls = { outcome: "error", reason: "internal error while building the review" };
    }
    if (plan?.review && !stale) {
      if (dryRun) reviewPosted = true;
      else if (gh) {
        try {
          const r = await gh.createReview(plan.review, { downgradeRefusedEvent: true });
          reviewPosted = true;
          audit("publish.review", { id: r.id, event: r.event ?? plan.review.event, comments: plan.review.comments.length, inline_fallback: r.inlineFallback });
          if (r.downgraded) {
            refusedEvent = r.downgraded.from;
            plan = planAfterRefusedEvent(plan, r.downgraded, policy);
            audit("publish.review_event_refused", { from: r.downgraded.from, reason: r.downgraded.reason, verdict: plan.verdict, blocked: plan.blocked });
          }
        } catch (e) {
          infra("creating the review failed", e);
        }
      }
    }
    // A REQUEST_CHANGES review stays in force until dismissed: a finished run that does not request
    // changes via a review dismisses ours on older commits, and our earlier approvals (best effort;
    // never after a failed review post).
    if (plan?.dismiss_change_requests && (!plan.review || reviewPosted) && !stale) {
      const message = `Superseded by a newer automated review${pr?.head_sha ? ` of commit ${pr.head_sha.slice(0, 7)}` : ""} (verdict: ${plan.verdict}).`;
      dismiss = { message };
      if (gh?.dismissStaleChangeRequests) {
        try {
          const res = await gh.dismissStaleChangeRequests(message);
          dismiss.result = dismissResult(res);
          audit("publish.dismissed", { dismissed: dismiss.result.dismissed.length, failed: dismiss.result.failed.length, ...(dismiss.result.kept ? { kept: dismiss.result.kept } : {}) });
          if (dismiss.result.failed.length > 0) errors.push(`dismissing ${dismiss.result.failed.length} earlier review(s) failed`);
        } catch (e) {
          errors.push(`dismissing earlier reviews failed: ${shortError(e)}`);
          audit("publish.dismiss_failed", { error: e });
        }
      }
    }
  }

  // An APPROVE stays in force across later pushes (unless branch protection dismisses stale
  // approvals): every run that does not approve the head and did not dismiss them above dismisses
  // our earlier approvals, runs without a plan (skipped, error, usage_limit, kill switch) included.
  // Fail closed, best effort; a stale run touches nothing.
  // plan.dismiss_approvals: the plan does not approve; an approving plan whose review was not
  // posted approves nothing either.
  const wantsApprovalDismissal = !plan || plan.dismiss_approvals === true || (plan.approved && !reviewPosted);
  if (policy && pr && !integrityError && !stale && dismiss === undefined && wantsApprovalDismissal) {
    const commit = pr.head_sha ? ` of commit ${pr.head_sha.slice(0, 7)}` : "";
    const message = plan
      ? `Superseded by a newer automated review${commit} (verdict: ${plan.verdict}).`
      : `Superseded: the latest automated review run${commit} did not approve the pull request (outcome: ${cls.outcome}).`;
    dismissApprovals = { message };
    const gh = optionalApi();
    if (gh?.dismissStaleApprovals) {
      try {
        dismissApprovals.result = dismissResult(await gh.dismissStaleApprovals(message));
        audit("publish.approvals_dismissed", { dismissed: dismissApprovals.result.dismissed.length, failed: dismissApprovals.result.failed.length });
        if (dismissApprovals.result.failed.length > 0) errors.push(`dismissing ${dismissApprovals.result.failed.length} earlier approval(s) failed`);
      } catch (e) {
        errors.push(`dismissing earlier approvals failed: ${shortError(e)}`);
        audit("publish.dismiss_failed", { error: e, what: "approvals" });
      }
    }
  }

  /* ---- 4. fired outcomes ---- */
  const fired: OutcomeName[] = [cls.outcome];
  if (cls.outcome === "completed" && plan && !stale) {
    if (plan.approved && reviewPosted) fired.push("approved");
    const needsReview = plan.review?.event === "REQUEST_CHANGES";
    if (plan.blocked && (!needsReview || reviewPosted)) fired.push("blocked");
  }

  const runUrl = safeUrl((v["run-url"] as string | undefined) ?? "") || safeUrl(pr?.run_url ?? "") || defaultRunUrl(env) || undefined;
  const baseVars = buildTemplateVars({ ...(pr ? { pr } : {}), cls, ...(plan ? { plan } : {}), ...(runUrl ? { runUrl } : {}), attempt });
  const varsFor = (o: OutcomeName): TemplateVars => ({ ...baseVars, outcome: o });

  const report: PublishReport = {
    dry_run: dryRun,
    outcome: cls,
    fired,
    pr: pr ?? null,
    plan: plan ?? null,
    ...(stale ? { stale } : {}),
    actions: {
      review: plan?.review
        ? { event: plan.review.event, comments: plan.review.comments.length, posted: reviewPosted && !dryRun, ...(refusedEvent ? { refused_event: refusedEvent } : {}) }
        : null,
      sticky: null,
      ...(dismiss ? { dismiss } : {}),
      ...(dismissApprovals ? { dismiss_approvals: dismissApprovals } : {}),
      check: null,
      labels: { add: [], remove: [] },
      retry: null,
      notify: [],
      dispatch: [],
    },
    outputs: {},
    errors,
    exit_code: 0,
  };

  if (policy && pr && !integrityError) {
    /* ---- 5. sticky comment (+ retry-after marker for the sweeper) ---- */
    const outcomeComments = fired.map((o) => renderOutcomeComment(policy, o, varsFor(o)));
    const summaryForSticky = plan?.summaryTarget === "sticky" ? plan.summary : undefined;
    // A stale run neither asks for a retry nor gives one up: the run for the current head decides.
    const retry = stale ? undefined : plannedRetry(policy, cls.outcome, attempt);
    const exhausted = retry || stale ? undefined : exhaustedRetry(policy, cls.outcome, attempt);
    let trailer: string | undefined;
    if (retry) {
      const now = new Date(deps.nowSeconds ? deps.nowSeconds() * 1000 : Date.now());
      const timing = retryNotBefore({ outcome: cls.outcome, ...(cls.reset_at ? { reset_at: cls.reset_at } : {}), attempt, now });
      if (runIdOk) trailer = retryAfterMarker({ not_before: timing.not_before, run_id: Number(runId), attempt });
      else audit("publish.retry_marker_skipped", { reason: "GITHUB_RUN_ID unset; the sweeper falls back to its backoff" });
      report.actions.retry = { ...retry, ...timing, marker: false };
    } else if (exhausted) {
      if (runIdOk) trailer = retryStopMarker({ run_id: Number(runId), attempt, max_attempts: exhausted.max_attempts });
      else audit("publish.retry_marker_skipped", { reason: "GITHUB_RUN_ID unset; the sweeper uses the label's smallest max_attempts" });
      report.actions.retry_exhausted = { ...exhausted, marker: false };
    }
    const stickyBody = composeSticky(cls.outcome, summaryForSticky, outcomeComments, trailer);
    if (report.actions.retry) report.actions.retry.marker = trailer !== undefined && stickyBody !== undefined;
    if (report.actions.retry_exhausted) report.actions.retry_exhausted.marker = trailer !== undefined && stickyBody !== undefined;
    if (stale) {
      audit("publish.sticky_skipped", { reason: "stale run" });
    } else if (stickyBody !== undefined) {
      report.actions.sticky = { body: stickyBody, posted: false };
      const gh = getApi();
      if (gh) {
        try {
          const existing = await gh.findStickyComment(STICKY_MARKER);
          if (existing && existing.body === stickyBody) audit("publish.sticky_unchanged", { id: existing.id });
          else if (existing) await gh.updateIssueComment(existing.id, stickyBody);
          else await gh.createIssueComment(stickyBody);
          report.actions.sticky.posted = true;
          audit("publish.sticky", { updated: existing !== undefined, chars: stickyBody.length });
        } catch (e) {
          if (summaryForSticky !== undefined) infra("posting the summary comment failed", e);
          else {
            errors.push(`posting the outcome comment failed: ${shortError(e)}`);
            audit("publish.sticky_failed", { error: e });
          }
        }
      }
    } else {
      // Nothing for the sticky this run (summary in the review or disabled, no outcome comment, or
      // a skip): an earlier run's sticky (e.g. "review postponed", or an older summary with old
      // findings) must not stay as if current. Replace it with a short status note; never create
      // one. Best effort.
      const gh = optionalApi();
      if (gh) {
        const note = plan ? staleStickyNote(plan, cls, pr.head_sha) : runStatusStickyBody({ outcome: cls.outcome, reason: cls.reason, ...(pr.head_sha ? { head_sha: pr.head_sha } : {}) });
        try {
          const existing = await gh.findStickyComment(STICKY_MARKER);
          if (existing && existing.body !== note) {
            await gh.updateIssueComment(existing.id, note);
            report.actions.sticky = { body: note, posted: true, replaces_stale: true };
            audit("publish.sticky_superseded", { id: existing.id });
          }
        } catch (e) {
          errors.push(`replacing the earlier summary comment failed: ${shortError(e)}`);
          audit("publish.sticky_failed", { error: e });
        }
      }
    }

    /* ---- 6. check run ---- */
    const skipFacts: SkipFacts = {
      ...(pr.title !== undefined ? { title: pr.title } : {}),
      ...(ctx ? { files: ctx.files.length, changed_lines: ctx.changed_lines } : {}),
    };
    const check = resolveCheck({ policy, ...(plan ? { plan } : {}), fired, cls, outcomeComments, skipFacts });
    if (check) {
      report.actions.check = { ...check, posted: false };
      if (!pr.head_sha) {
        if (!dryRun) infra("cannot create the check run: head sha unknown");
      } else {
        const gh = getApi();
        if (gh) {
          try {
            const r = await gh.createCheckRun({
              name: check.name,
              conclusion: check.conclusion,
              title: check.title,
              summary: check.summary,
              head_sha: pr.head_sha,
              // A run that did not review the commit (skip, error, usage limit, incomplete) never
              // lifts a failing check on it.
              keep_failure: cls.outcome !== "completed",
            });
            if (r?.superseded) {
              report.actions.check.superseded = r.superseded;
              audit("publish.check_superseded", { id: r.id, name: check.name, conclusion: check.conclusion, reason: r.superseded.reason });
            } else {
              report.actions.check.posted = true;
              audit("publish.check", { id: r?.id, name: check.name, conclusion: check.conclusion, decided_by: check.decided_by });
            }
          } catch (e) {
            infra("creating the check run failed", e);
          }
        }
      }
    }

    /* ---- 7a. labels (incl. retry labelling) ---- */
    const labels: LabelOps = stale ? { add: [], remove: [] } : computeLabelOps({ policy, ...(plan ? { plan } : {}), fired, primary: cls.outcome, attempt });
    report.actions.labels = labels;
    if (labels.add.length > 0 || labels.remove.length > 0) {
      const gh = getApi();
      if (gh) {
        for (const l of labels.remove) {
          try {
            await gh.removeLabel(l);
          } catch (e) {
            errors.push(`removing label ${JSON.stringify(l)} failed: ${shortError(e)}`);
            audit("publish.label_remove_failed", { label: l, error: e });
          }
        }
        if (labels.add.length > 0) {
          try {
            await gh.addLabels(labels.add);
          } catch (e) {
            errors.push(`adding labels failed: ${shortError(e)}`);
            audit("publish.label_add_failed", { labels: labels.add, error: e });
          }
        }
        audit("publish.labels", { add: labels.add, remove: labels.remove });
      }
    }

    /* ---- 7b. notifications ---- */
    // A stale run notifies and dispatches nothing (the run for the current head does).
    const notifyPlan = stale ? [] : fired.flatMap((o) => policy.outcomes[o].notify.map((ref) => ({ o, ref })));
    if (notifyPlan.length > 0) {
      for (const { o, ref } of notifyPlan) {
        const target = Object.prototype.hasOwnProperty.call(policy.notifications, ref.target) ? policy.notifications[ref.target] : undefined;
        const tpl = ref.message ?? target?.template ?? DEFAULT_NOTIFY_TEMPLATE;
        const message = renderTemplate(tpl, varsFor(o), target?.type === "slack" ? slackEscaper() : plainEscaper());
        report.actions.notify.push({ outcome: o, target: ref.target, ...(target ? { type: target.type } : {}), message });
      }
      if (!dryRun) {
        const secrets = loadNotifySecrets({ env, file: (v["notify-secrets-file"] as string | undefined) ?? DEFAULT_NOTIFY_SECRETS_FILE });
        let i = 0;
        for (const o of fired) {
          const refs = policy.outcomes[o].notify;
          if (refs.length === 0) continue;
          const results = await sendNotifications(refs, policy.notifications, varsFor(o), secrets, fetchImpl, {
            ...(deps.nowSeconds ? { nowSeconds: deps.nowSeconds } : {}),
          });
          for (const r of results) {
            const entry = report.actions.notify[i++];
            if (entry) entry.result = r;
            if (!r.ok) errors.push(`notification ${JSON.stringify(r.target)} failed: ${r.error ?? "unknown error"}`);
          }
        }
      }
    }

    /* ---- 7c. dispatch ---- */
    for (const o of stale ? [] : fired) {
      const d = policy.outcomes[o].dispatch;
      if (!d) continue;
      const client_payload = buildDispatchPayload(varsFor(o), pr.head_sha ? { head_sha: pr.head_sha } : {});
      const entry: PlannedDispatch & { result?: DispatchResult } = { outcome: o, repo: d.repo ?? pr.repo, event_type: d.event_type, client_payload };
      report.actions.dispatch.push(entry);
      if (dryRun) continue;
      // The publisher client is only a fallback for same-repo dispatches without XREPO_DISPATCH_TOKEN.
      const sameRepo = entry.repo.toLowerCase() === pr.repo.toLowerCase();
      const hasToken = (env.GITHUB_TOKEN ?? env.GH_TOKEN ?? "").trim() !== "";
      const gh = sameRepo && hasToken && !env.XREPO_DISPATCH_TOKEN?.trim() ? getApi() : undefined;
      entry.result = await repositoryDispatch(d, { prRepo: pr.repo, client_payload, ...(gh ? { api: gh } : {}), env, fetchImpl });
      if (!entry.result.ok) errors.push(`dispatch ${d.event_type} failed: ${entry.result.error ?? "unknown error"}`);
    }
  } else if (!integrityError) {
    audit("publish.nothing_to_publish", {
      reason: !pr ? "PR unknown (no PR context and no pull_request event)" : "policy unavailable (no resolved policy and no --policy)",
      ...(ctxError ? { ctx_error: ctxError } : {}),
    });
  }

  /* ---- 8. outputs ---- */
  const outputs: Record<string, string> = {
    outcome: cls.outcome,
    verdict: plan?.verdict ?? "",
    reason: cls.reason,
    reset_at: cls.reset_at ?? "",
    findings: String(plan?.findings ?? 0),
    top_severity: plan?.top_severity ?? "",
    // Primary outcome first, then approved / blocked when they fired (comma-separated), so callers
    // can chain on `contains(needs.review.outputs.fired_outcomes, 'blocked')`.
    fired_outcomes: fired.join(","),
  };
  report.outputs = outputs;
  const outPath = ((v["github-output"] as string | undefined) ?? env.GITHUB_OUTPUT ?? "").trim();
  if (outPath !== "") {
    try {
      writeGithubOutputs(outPath, outputs);
    } catch (e) {
      infra("writing step outputs failed", e);
    }
  }

  /* ---- 9. exit code ---- */
  const failJob = policy !== undefined && !integrityError && fired.some((o) => policy.outcomes[o].fail_job);
  if (failJob) audit("publish.fail_job", { outcomes: fired.filter((o) => policy?.outcomes[o].fail_job) });
  report.exit_code = failJob || infraFailure ? 1 : 0;

  const json = `${JSON.stringify(report, null, 2)}\n`;
  const planOut = v["plan-out"] as string | undefined;
  if (planOut) {
    try {
      writeFileSync(planOut, json, { encoding: "utf8", mode: 0o644 });
    } catch (e) {
      errors.push(`writing --plan-out failed: ${shortError(e)}`);
      audit("publish.plan_out_failed", { error: e });
    }
  }
  if (dryRun) stdout.write(json);
  audit("publish.done", { outcome: cls.outcome, fired, exit_code: report.exit_code, errors: errors.length, dry_run: dryRun });
  return report.exit_code;
}

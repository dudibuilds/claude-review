/**
 * Thin GitHub REST wrapper for the publisher (the only component holding a write token).
 *
 * Identity / trust: hidden markers (<!-- xrepo-review:sticky -->, <!-- xrepo:c:KEY -->) are plain
 * text that anyone who can comment on the PR can post too. Every marker lookup therefore only
 * considers comments authored by the token's own identity, resolved by getAuthenticatedLogin():
 *   1. `selfLogin` option, if given (e.g. "<app-slug>[bot]" from actions/create-github-app-token);
 *   2. GET /user (PATs, OAuth and user-to-server tokens);
 *   3. GET /app -> "<slug>[bot]" (works only where the token may read its app; JWT-only in general);
 *   4. fallback "github-actions[bot]", the identity behind the workflow GITHUB_TOKEN (whose
 *      installation token can call neither /user nor /app).
 * A custom GitHub App installation token MUST pass `selfLogin`, otherwise step 4 picks the wrong
 * identity (our own old comments would not be found). Note that step 4's identity is shared by
 * every workflow of the repository that uses GITHUB_TOKEN: the author check alone does not tell our
 * comments from theirs. Reviews are therefore only treated as ours when they also carry
 * REVIEW_MARKER (plan.ts isXrepoReviewBody); a distinct identity (`selfLogin`) is still preferable.
 *
 * Review lifecycle: GitHub refuses APPROVE for the workflow GITHUB_TOKEN unless the repository
 * allows Actions to approve pull requests, and APPROVE / REQUEST_CHANGES on a pull request the
 * identity authored. createReview can then post the same review as a COMMENT instead
 * (`downgradeRefusedEvent`), so the inline comments are not lost; the result says so, and the
 * caller must not treat the review as approving or blocking. With `downgradeRefusedEvent` (or
 * `verifyHead`) an APPROVE is also only submitted while the commit it reviewed is still the pull
 * request's head (GET the pull request first): a re-run of an older workflow run must not approve
 * the current head. Both a REQUEST_CHANGES and an APPROVE review stay in force until they are
 * dismissed (a later COMMENT review clears neither, and an approval keeps counting across pushes
 * unless branch protection dismisses stale approvals):
 *   - dismissStaleChangeRequests (a finished run that does not request changes via a review)
 *     dismisses our earlier approvals (except one this client just posted) and our change requests
 *     on OLDER commits, and the latter only while this run's commit is still the pull request head
 *     (a re-run of an older run never lifts the current block; a change request on the current head
 *     is only lifted by a new commit or a human);
 *   - dismissStaleApprovals (every run that does not approve the head: incomplete, skipped, error,
 *     usage_limit) dismisses our earlier approvals; fail closed.
 * Only reviews by our identity that carry REVIEW_MARKER (or the legacy framing) are touched.
 *
 * Replayed runs (re-running an older workflow run): runFreshness() tells the caller whether this
 * run still reviews the pull request's head and, with `run`, whether a newer workflow run already
 * posted a check for that commit. With `run`, every check run carries the run id in external_id and
 * createCheckRun never posts over a check run of a newer workflow run for the same commit; with
 * `keep_failure`, a passing conclusion is not posted over a failing one (for runs that did not
 * review the commit: skips, errors, usage limits).
 */
import { Octokit } from "@octokit/rest";
import { audit } from "../common/audit.js";
import {
  extractCommentKeys,
  isXrepoReviewBody,
  type CheckRunConclusion,
  type PlanCheck,
  type PlanComment,
  type PlanReview,
  type ReviewEvent,
} from "./plan.js";
import { inlineCode, safeCut, sanitizeMarkdown, singleLine, sliceSafe } from "./sanitize.js";

export interface IssueCommentRef {
  id: number;
  body: string;
}

export interface CreateReviewResult {
  id: number;
  /** True when GitHub rejected the inline comments' lines and they were folded into the body. */
  inlineFallback: boolean;
  /** Only after a downgrade: the event GitHub accepted ("COMMENT"); otherwise the requested one. */
  event?: ReviewEvent;
  /**
   * Set when the requested event was not submitted and the review was posted as a COMMENT instead:
   * GitHub refused it, or (`withheld`) this client withheld an APPROVE because the reviewed commit is
   * no longer the open pull request's head (see CreateReviewOptions.verifyHead).
   */
  downgraded?: { from: ReviewEvent; reason: string; withheld?: boolean };
}

export interface CreateReviewOptions {
  /**
   * When GitHub refuses the review event itself (a 422 such as "GitHub Actions is not permitted to
   * approve pull requests", "Can not approve your own pull request", "Can not request changes on
   * your own pull request"), post the review once more as a COMMENT with the same inline comments
   * and a note at the top of the body, and report it in `downgraded`. Default false: rethrow. The
   * caller must then not count the review as approving / blocking (no `approved` / `blocked`).
   */
  downgradeRefusedEvent?: boolean;
  /**
   * Before submitting an APPROVE, GET the pull request and only approve while its head is still the
   * commit this client reviews (headSha) and it is open. Otherwise the review is posted as a COMMENT
   * (`downgraded`, like a refused event) with `downgradeRefusedEvent`, or the call throws. Default:
   * the value of `downgradeRefusedEvent`. A failed GET withholds the approval (fail closed).
   */
  verifyHead?: boolean;
}

export interface DismissResult {
  /** Ids of our CHANGES_REQUESTED / APPROVED reviews that were dismissed. */
  dismissed: number[];
  /** Ids whose dismissal failed (e.g. branch protection restricts who may dismiss reviews). */
  failed: number[];
  /** Why some of our reviews were deliberately left in force (e.g. a change request on the current head). */
  kept?: string;
}

/** The pull request as GitHub reports it now (GET /repos/{owner}/{repo}/pulls/{number}). */
export interface PullRequestState {
  head_sha: string;
  state: string;
  draft: boolean;
  merged: boolean;
}

/** The workflow run publishing (GITHUB_RUN_ID / GITHUB_RUN_ATTEMPT). */
export interface RunRef {
  id: number;
  attempt?: number;
}

export interface RunFreshness {
  /** This run reviews the pull request's current head and no newer workflow run posted a check for it. */
  current: boolean;
  /** The pull request's current head. */
  head_sha: string;
  state: string;
  /** A newer workflow run that already posted a check run for this commit (needs `run`). */
  newer_run?: number;
  reason?: string;
}

export type CheckRunInput = Omit<PlanCheck, "conclusion"> & {
  conclusion: CheckRunConclusion;
  head_sha?: string;
  /** Default with GitHubApiOptions.run: "xrepo-review:run=<id>:attempt=<n>" (see runExternalId). */
  external_id?: string;
  /**
   * Do not post a passing conclusion (success, neutral, skipped) over a failing one: when the
   * newest check run with this name on head_sha concluded `failure`, nothing is created and the
   * result names it in `superseded`. For runs that did not review the commit (skipped, error,
   * usage_limit, incomplete): toggling a PR to draft, or re-running a draft-time / failed run,
   * must not lift a blocking check on the same commit.
   */
  keep_failure?: boolean;
};

export interface CheckRunResult {
  id: number;
  /** Set when no check run was created; `id` is then the existing check run that stays in force. */
  superseded?: { reason: string; newer_run?: number };
}

export interface GitHubApi {
  /** Dedupe keys from xrepo:c markers in review comments / review bodies authored by us. */
  listReviewCommentKeys(): Promise<Set<string>>;
  /** Oldest issue comment authored by us that contains `marker`. */
  findStickyComment(marker: string): Promise<IssueCommentRef | undefined>;
  createIssueComment(body: string): Promise<{ id: number }>;
  updateIssueComment(id: number, body: string): Promise<void>;
  /**
   * POST a review at headSha; on a 422 about inline lines, retries once with comments in the body;
   * with `downgradeRefusedEvent`, a refused APPROVE / REQUEST_CHANGES is retried as a COMMENT.
   */
  createReview(r: PlanReview, opts?: CreateReviewOptions): Promise<CreateReviewResult>;
  /**
   * Call when the current run finished and does not request changes via a review
   * (PublishPlan.dismiss_change_requests). Dismisses our reviews (identity + REVIEW_MARKER) that are
   * stale: every APPROVED one except an approval this client just posted, and every
   * CHANGES_REQUESTED one on an older commit, the latter only while headSha is still the pull
   * request head. Optional so that existing test doubles stay valid.
   */
  dismissStaleChangeRequests?(message: string): Promise<DismissResult>;
  /**
   * Dismiss our APPROVED reviews (identity + REVIEW_MARKER), except an approval this client just
   * posted. Call it for every run that does not approve the head (PublishPlan.dismiss_approvals;
   * skipped, error, usage_limit runs, which have no plan): fail closed.
   */
  dismissStaleApprovals?(message: string): Promise<DismissResult>;
  /** The pull request as GitHub reports it now. */
  getPullRequest?(): Promise<PullRequestState>;
  /**
   * Is this run still current? False when the pull request head is no longer headSha (a re-run of
   * an older workflow run, or a push while this run was publishing), or, with `run` and a check
   * name, when a newer workflow run already posted that check for headSha. Throws when the pull
   * request cannot be read.
   */
  runFreshness?(checkName?: string): Promise<RunFreshness>;
  /** Completed check run (head_sha defaults to the configured headSha). */
  createCheckRun(c: CheckRunInput): Promise<CheckRunResult>;
  addLabels(labels: string[]): Promise<void>;
  /** Removes a label from the PR; a 404 (label not present) is ignored. */
  removeLabel(label: string): Promise<void>;
  /** POST /repos/{repo}/dispatches. client_payload is limited to 10 top-level keys. */
  repositoryDispatch(repo: string, event_type: string, client_payload: Record<string, unknown>): Promise<void>;
  getAuthenticatedLogin(): Promise<string>;
}

export interface GitHubApiOptions {
  token: string;
  /** owner/name of the PR repository. */
  repo: string;
  prNumber: number;
  headSha: string;
  /** API root, e.g. https://ghe.example.com/api/v3 (default https://api.github.com). */
  baseUrl?: string;
  /** Login of the token identity, e.g. "my-app[bot]". Skips auto-detection. */
  selfLogin?: string;
  /** fetch implementation (tests). */
  fetch?: typeof fetch;
  /** Pre-built Octokit (tests). */
  octokit?: Octokit;
  /** Page cap for list endpoints (100 items per page). Default 50. */
  maxPages?: number;
  /**
   * The workflow run publishing. When set, check runs carry it in external_id and createCheckRun /
   * runFreshness detect a newer workflow run's check run for the same commit.
   */
  run?: RunRef;
}

const RUN_EXTERNAL_ID_RE = /^xrepo-review:run=(\d{1,20})(?::attempt=(\d{1,6}))?$/;

/** external_id of a check run posted by workflow run `run`. */
export function runExternalId(run: RunRef): string {
  return `xrepo-review:run=${run.id}${run.attempt !== undefined ? `:attempt=${run.attempt}` : ""}`;
}

/** The workflow run id in a check run's external_id (undefined when it is not ours). */
export function runIdFromExternalId(externalId: string | null | undefined): number | undefined {
  const m = RUN_EXTERNAL_ID_RE.exec(typeof externalId === "string" ? externalId : "");
  const id = m ? Number(m[1]) : NaN;
  return Number.isSafeInteger(id) ? id : undefined;
}

const PASSING_CHECK = new Set<CheckRunConclusion>(["success", "neutral", "skipped"]);

export const GITHUB_ACTIONS_LOGIN = "github-actions[bot]";

const REPO_RE = /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/;
const MAX_BODY = 65536;
const MAX_FOLDED_BODY = 65000;
const MAX_CHECK_SUMMARY = 65535;
const MAX_CHECK_TITLE = 1000;

function splitRepo(repo: string): { owner: string; repo: string } {
  if (typeof repo !== "string" || !REPO_RE.test(repo) || repo.split("/").some((s) => s === "." || s === "..")) {
    throw new Error(`invalid repository ${JSON.stringify(repo)}: expected owner/name`);
  }
  const [owner = "", name = ""] = repo.split("/");
  return { owner, repo: name };
}

function statusOf(e: unknown): number | undefined {
  const s = (e as { status?: unknown } | null)?.status;
  return typeof s === "number" ? s : undefined;
}

function errorText(e: unknown): string {
  const msg = e instanceof Error ? e.message : String(e);
  let data = "";
  try {
    data = JSON.stringify((e as { response?: { data?: unknown } } | null)?.response?.data ?? "");
  } catch {
    /* ignore */
  }
  return `${msg} ${data}`;
}

/**
 * Does a 422 from POST .../reviews blame the inline comments' positions? (GitHub: "Line could not
 * be resolved", "pull_request_review_thread.line must be part of the diff", "start_line must be
 * part of the same hunk", "Path could not be resolved", "position is invalid", ...)
 */
export function isLineResolutionError(e: unknown): boolean {
  if (statusOf(e) !== 422) return false;
  const t = errorText(e);
  if (isEventRefusedError(e) || /body is too long/i.test(t)) return false;
  return /could not be resolved|part of the diff|same hunk|pull_request_review_thread|position is invalid|\b(?:start_)?line\b|\bpath\b|\bhunk\b/i.test(t);
}

const EVENT_REFUSED_RE = /approve your own|request changes on your own|not permitted to (?:approve|request changes)|can ?not (?:approve|request changes)/i;

/** Does a 422 from POST .../reviews refuse the review event (APPROVE / REQUEST_CHANGES) itself? */
export function isEventRefusedError(e: unknown): boolean {
  return statusOf(e) === 422 && EVENT_REFUSED_RE.test(errorText(e));
}

/** GitHub's reason for a refused event, short and on one line. */
function refusalReason(e: unknown): string {
  const t = errorText(e);
  const m = EVENT_REFUSED_RE.exec(t);
  // Prefer the sentence that names the refusal over Octokit's generic "Unprocessable Entity".
  const sentence = m ? (t.slice(0, m.index).split(/[".:\]]/).pop() ?? "") + t.slice(m.index).split(/["\]]/)[0] : t;
  return singleLine(sentence, 200);
}

function lineLabel(c: PlanComment): string {
  return c.start_line !== undefined && c.start_line !== c.line ? `lines ${c.start_line}-${c.line}` : `line ${c.line}`;
}

/**
 * Review body with the inline comments appended (used when GitHub refuses their positions). The
 * comment bodies are already sanitized and keep their xrepo:c markers; whole comments are dropped
 * (never cut) when the body would exceed GitHub's size limit. Every part is joined after a blank
 * line: sanitized text never ends inside a fence or a "<pre>" block (see sanitize.ts), and a blank
 * line ends any other HTML block, so no part can swallow the next one (e.g. its suggestion block).
 */
export function foldCommentsIntoBody(body: string, comments: PlanComment[]): string {
  const head = `${body}\n\n---\n**Inline comments** (GitHub could not attach them to diff lines):`;
  let out = head;
  let omitted = 0;
  for (const [i, c] of comments.entries()) {
    const title = sanitizeMarkdown(`#### ${inlineCode(c.path, 200)} ${lineLabel(c)}`, {
      allowMentions: false,
      allowImages: false,
      linkAllowlist: [],
      maxChars: 400,
    });
    const piece = `\n\n${title}\n\n${c.body}`;
    if (out.length + piece.length > MAX_FOLDED_BODY - 100) {
      omitted = comments.length - i;
      break;
    }
    out += piece;
  }
  if (omitted > 0) out += `\n\n_\u2026 ${omitted} more comment${omitted === 1 ? "" : "s"} omitted (size limit)._`;
  return out;
}

export function createGitHubApi(opts: GitHubApiOptions): GitHubApi {
  const { owner, repo } = splitRepo(opts.repo);
  const prNumber = opts.prNumber;
  if (!Number.isInteger(prNumber) || prNumber <= 0) throw new Error(`invalid PR number ${String(prNumber)}`);
  const headSha = opts.headSha;
  const maxPages = Math.max(1, opts.maxPages ?? 50);
  const octokit =
    opts.octokit ??
    new Octokit({
      auth: opts.token,
      userAgent: "xrepo-review",
      ...(opts.baseUrl ? { baseUrl: opts.baseUrl.replace(/\/+$/, "") } : {}),
      request: opts.fetch ? { fetch: opts.fetch } : {},
      log: {
        debug: () => {},
        info: () => {},
        warn: (message: string) => audit("github.warn", { message }),
        // request-log reports every non-2xx here, including expected ones (identity probe, 404 on label removal).
        error: (message: string) => audit("github.request_failed", { message }),
      },
    });

  let loginPromise: Promise<string> | undefined;
  const resolveLogin = async (): Promise<string> => {
    const configured = opts.selfLogin?.trim();
    if (configured) return configured;
    try {
      const r = await octokit.request("GET /user");
      const login = (r.data as { login?: unknown }).login;
      if (typeof login === "string" && login !== "") return login;
    } catch (e) {
      const st = statusOf(e);
      if (st !== 401 && st !== 403 && st !== 404) throw e;
    }
    try {
      const r = await octokit.request("GET /app");
      const slug = (r.data as { slug?: unknown } | null)?.slug;
      if (typeof slug === "string" && slug !== "") return `${slug}[bot]`;
    } catch {
      /* installation tokens cannot read /app; fall through */
    }
    audit("github.identity_fallback", { login: GITHUB_ACTIONS_LOGIN });
    return GITHUB_ACTIONS_LOGIN;
  };
  const getAuthenticatedLogin = (): Promise<string> => {
    loginPromise ??= resolveLogin().catch((e: unknown) => {
      loginPromise = undefined;
      throw e;
    });
    return loginPromise;
  };
  const isSelf = (self: string, user: { login?: string | null } | null | undefined): boolean =>
    typeof user?.login === "string" && user.login.toLowerCase() === self.toLowerCase();

  const checkBody = (body: string): string => {
    if (typeof body !== "string") throw new Error("comment body must be a string");
    if (body.length > MAX_BODY) throw new Error(`comment body too long (${body.length} > ${MAX_BODY} characters)`);
    return body;
  };

  /** Reviews this client posted (id -> accepted event): never dismissed as "earlier" ones. */
  const posted = new Map<number, ReviewEvent>();
  const short = (sha: string): string => (sha === "" ? "(unknown)" : sha.slice(0, 7));
  /** Is `sha` the commit this client reviews (headSha, or headSha abbreviated to >= 7 characters)? */
  const isOurHead = (sha: string | null | undefined): boolean => {
    if (typeof sha !== "string" || sha === "" || headSha === "") return false;
    const a = sha.toLowerCase();
    const b = headSha.toLowerCase();
    return a === b || (b.length >= 7 && a.startsWith(b));
  };

  const getPullRequest = async (): Promise<PullRequestState> => {
    const r = await octokit.rest.pulls.get({ owner, repo, pull_number: prNumber });
    const d = r.data as { head?: { sha?: unknown }; state?: unknown; draft?: unknown; merged?: unknown };
    const sha = d.head?.sha;
    if (typeof sha !== "string" || sha === "") throw new Error("GitHub returned a pull request without a head sha");
    return { head_sha: sha, state: typeof d.state === "string" ? d.state : "unknown", draft: d.draft === true, merged: d.merged === true };
  };

  interface OurReview {
    id: number;
    state: string;
    commit_id?: string;
  }
  /** Reviews by our identity that this tool posted (REVIEW_MARKER or the legacy framing). */
  const listOurReviews = async (): Promise<OurReview[]> => {
    const self = await getAuthenticatedLogin();
    const out: OurReview[] = [];
    let pages = 0;
    for await (const page of octokit.paginate.iterator(octokit.rest.pulls.listReviews, {
      owner,
      repo,
      pull_number: prNumber,
      per_page: 100,
    })) {
      for (const rv of page.data) {
        if (!isSelf(self, rv.user) || !isXrepoReviewBody(rv.body)) continue;
        out.push({ id: rv.id, state: rv.state, ...(typeof rv.commit_id === "string" ? { commit_id: rv.commit_id } : {}) });
      }
      if (++pages >= maxPages) break;
    }
    return out;
  };

  const dismissAll = async (ids: number[], message: string, result: DismissResult): Promise<void> => {
    const text = singleLine(message, 1000) || "Superseded by a newer automated review.";
    for (const id of ids) {
      try {
        await octokit.rest.pulls.dismissReview({ owner, repo, pull_number: prNumber, review_id: id, message: text, event: "DISMISS" });
        result.dismissed.push(id);
        audit("github.review.dismissed", { id });
      } catch (e) {
        result.failed.push(id);
        audit("github.review.dismiss_failed", { id, status: statusOf(e), error: sliceSafe(errorText(e), 500) });
      }
    }
  };

  const earlierApprovals = (ours: OurReview[]): number[] =>
    ours.filter((rv) => rv.state === "APPROVED" && posted.get(rv.id) !== "APPROVE").map((rv) => rv.id);

  /** Why an APPROVE for headSha must not be submitted now (undefined: it may). */
  const approvalWithheld = async (): Promise<string | undefined> => {
    if (headSha === "") return "the reviewed commit is unknown";
    let pr: PullRequestState;
    try {
      pr = await getPullRequest();
    } catch (e) {
      audit("github.pull_request_unreadable", { status: statusOf(e), error: sliceSafe(errorText(e), 300) });
      return "the pull request's current head could not be verified";
    }
    if (pr.state !== "open") return `the pull request is ${singleLine(pr.state, 20)}`;
    if (!isOurHead(pr.head_sha)) return `the pull request head moved to ${short(pr.head_sha)} after commit ${short(headSha)} was reviewed`;
    return undefined;
  };

  interface CheckRef {
    id: number;
    conclusion: string | null;
    run?: number;
  }
  /** Check runs named `name` on `sha`, newest first. */
  const listChecks = async (name: string, sha: string): Promise<CheckRef[]> => {
    const out: CheckRef[] = [];
    for (let page = 1; page <= Math.min(maxPages, 10); page++) {
      const r = await octokit.rest.checks.listForRef({ owner, repo, ref: sha, check_name: name, filter: "all", per_page: 100, page });
      const runs = (r.data as { check_runs?: { id: number; name?: string; conclusion: string | null; external_id?: string | null }[] }).check_runs ?? [];
      for (const c of runs) {
        if (c.name !== undefined && c.name !== name) continue;
        const run = runIdFromExternalId(c.external_id);
        out.push({ id: c.id, conclusion: c.conclusion, ...(run !== undefined ? { run } : {}) });
      }
      if (runs.length < 100) break;
    }
    return out.sort((a, b) => b.id - a.id);
  };
  /** The newest check run of a newer workflow run than opts.run among `checks`. */
  const newerRunCheck = (checks: CheckRef[]): CheckRef | undefined => {
    const run = opts.run;
    if (!run) return undefined;
    return checks.find((c) => c.run !== undefined && c.run > run.id);
  };

  return {
    getAuthenticatedLogin,

    async listReviewCommentKeys(): Promise<Set<string>> {
      const self = await getAuthenticatedLogin();
      const keys = new Set<string>();
      let pages = 0;
      for await (const page of octokit.paginate.iterator(octokit.rest.pulls.listReviewComments, {
        owner,
        repo,
        pull_number: prNumber,
        per_page: 100,
      })) {
        for (const c of page.data) if (isSelf(self, c.user)) for (const k of extractCommentKeys(c.body)) keys.add(k);
        if (++pages >= maxPages) break;
      }
      // Comments folded into a review body by the 422 fallback carry their markers there.
      pages = 0;
      for await (const page of octokit.paginate.iterator(octokit.rest.pulls.listReviews, {
        owner,
        repo,
        pull_number: prNumber,
        per_page: 100,
      })) {
        for (const r of page.data) if (isSelf(self, r.user)) for (const k of extractCommentKeys(r.body)) keys.add(k);
        if (++pages >= maxPages) break;
      }
      return keys;
    },

    async findStickyComment(marker: string): Promise<IssueCommentRef | undefined> {
      if (typeof marker !== "string" || marker.trim() === "") throw new Error("sticky marker must be non-empty");
      const self = await getAuthenticatedLogin();
      let pages = 0;
      for await (const page of octokit.paginate.iterator(octokit.rest.issues.listComments, {
        owner,
        repo,
        issue_number: prNumber,
        per_page: 100,
      })) {
        for (const c of page.data) {
          if (isSelf(self, c.user) && typeof c.body === "string" && c.body.includes(marker)) return { id: c.id, body: c.body };
        }
        if (++pages >= maxPages) break;
      }
      return undefined;
    },

    async createIssueComment(body: string): Promise<{ id: number }> {
      const r = await octokit.rest.issues.createComment({ owner, repo, issue_number: prNumber, body: checkBody(body) });
      return { id: r.data.id };
    },

    async updateIssueComment(id: number, body: string): Promise<void> {
      await octokit.rest.issues.updateComment({ owner, repo, comment_id: id, body: checkBody(body) });
    },

    async createReview(r: PlanReview, opts: CreateReviewOptions = {}): Promise<CreateReviewResult> {
      const comments = r.comments.map((c) => ({
        path: c.path,
        line: c.line,
        side: c.side,
        body: c.body,
        ...(c.start_line !== undefined && c.start_line !== c.line ? { start_line: c.start_line, start_side: c.start_side ?? "RIGHT" } : {}),
      }));
      const post = async (event: ReviewEvent, body: string): Promise<CreateReviewResult> => {
        const base = { owner, repo, pull_number: prNumber, commit_id: headSha, event };
        try {
          const res = await octokit.rest.pulls.createReview({
            ...base,
            body: checkBody(body),
            ...(comments.length > 0 ? { comments } : {}),
          });
          return { id: res.data.id, inlineFallback: false };
        } catch (e) {
          if (comments.length === 0 || !isLineResolutionError(e)) throw e;
          audit("github.review.inline_fallback", { comments: comments.length, error: sliceSafe(errorText(e), 500) });
          const res = await octokit.rest.pulls.createReview({ ...base, body: checkBody(foldCommentsIntoBody(body, r.comments)) });
          return { id: res.data.id, inlineFallback: true };
        }
      };
      const record = (res: CreateReviewResult, event: ReviewEvent): CreateReviewResult => {
        posted.set(res.id, event);
        return res;
      };
      const verifyHead = opts.verifyHead ?? opts.downgradeRefusedEvent === true;
      if (r.event === "APPROVE" && verifyHead) {
        const withheld = await approvalWithheld();
        if (withheld !== undefined) {
          audit("github.review.approval_withheld", { reason: withheld, head_sha: headSha });
          if (!opts.downgradeRefusedEvent) throw new Error(`approval withheld: ${withheld}`);
          const note = `> **Note:** This review was not submitted as an approval (${inlineCode(withheld, 200)}), so it was posted as a comment: it does not approve the pull request.`;
          const res = await post("COMMENT", `${note}\n\n${r.body}`);
          return { ...record(res, "COMMENT"), event: "COMMENT", downgraded: { from: "APPROVE", reason: withheld, withheld: true } };
        }
      }
      try {
        return record(await post(r.event, r.body), r.event);
      } catch (e) {
        if (!opts.downgradeRefusedEvent || r.event === "COMMENT" || !isEventRefusedError(e)) throw e;
        const reason = refusalReason(e);
        audit("github.review.event_downgraded", { from: r.event, to: "COMMENT", reason });
        const effect = r.event === "APPROVE" ? "it does not approve the pull request" : "it does not request changes";
        const note = `> **Note:** GitHub refused to submit this review as ${r.event} (${inlineCode(reason, 200)}), so it was posted as a comment: ${effect}.`;
        const res = await post("COMMENT", `${note}\n\n${r.body}`);
        return { ...record(res, "COMMENT"), event: "COMMENT", downgraded: { from: r.event, reason } };
      }
    },

    async dismissStaleChangeRequests(message: string): Promise<DismissResult> {
      const ours = await listOurReviews();
      const result: DismissResult = { dismissed: [], failed: [] };
      // An approval keeps counting across pushes: every earlier one is stale once a newer run finished.
      const ids = earlierApprovals(ours);
      const changeRequests = ours.filter((rv) => rv.state === "CHANGES_REQUESTED" && !posted.has(rv.id));
      if (changeRequests.length > 0) {
        // Only a run for the pull request's current head may lift a block, and only one placed on an
        // older commit: re-running an older workflow run must never dismiss the current block.
        let pr: PullRequestState | undefined;
        try {
          pr = await getPullRequest();
        } catch (e) {
          audit("github.pull_request_unreadable", { status: statusOf(e), error: sliceSafe(errorText(e), 300) });
        }
        if (!pr) result.kept = "change requests kept: the pull request's current head could not be read";
        else if (!isOurHead(pr.head_sha)) {
          result.kept = `change requests kept: this run reviewed ${short(headSha)}, but the pull request head is ${short(pr.head_sha)}`;
        } else {
          const head = pr.head_sha.toLowerCase();
          const older = changeRequests.filter((rv) => rv.commit_id !== undefined && rv.commit_id.toLowerCase() !== head);
          ids.push(...older.map((rv) => rv.id));
          const same = changeRequests.length - older.length;
          if (same > 0) result.kept = `${same} change request(s) on the current head ${short(pr.head_sha)} kept (only a new commit or a person lifts them)`;
        }
        if (result.kept) audit("github.review.dismiss_kept", { reason: result.kept });
      }
      await dismissAll(ids, message, result);
      return result;
    },

    async dismissStaleApprovals(message: string): Promise<DismissResult> {
      const result: DismissResult = { dismissed: [], failed: [] };
      await dismissAll(earlierApprovals(await listOurReviews()), message, result);
      return result;
    },

    getPullRequest,

    async runFreshness(checkName?: string): Promise<RunFreshness> {
      const pr = await getPullRequest();
      const base = { head_sha: pr.head_sha, state: pr.state };
      if (!isOurHead(pr.head_sha)) {
        return { ...base, current: false, reason: `this run reviewed ${short(headSha)}, but the pull request head is ${short(pr.head_sha)}` };
      }
      if (opts.run && checkName) {
        const newer = newerRunCheck(await listChecks(checkName, pr.head_sha));
        if (newer?.run !== undefined) {
          return { ...base, current: false, newer_run: newer.run, reason: `workflow run ${newer.run} (newer than run ${opts.run.id}) already published for this commit` };
        }
      }
      return { ...base, current: true };
    },

    async createCheckRun(c: CheckRunInput): Promise<CheckRunResult> {
      const sha = c.head_sha ?? headSha;
      if (opts.run || c.keep_failure) {
        const checks = await listChecks(c.name, sha);
        const newer = newerRunCheck(checks);
        if (newer) {
          audit("github.check.superseded", { name: c.name, head_sha: sha, newer_run: newer.run, existing: newer.id });
          return { id: newer.id, superseded: { reason: `workflow run ${newer.run} already published a newer check for this commit`, ...(newer.run !== undefined ? { newer_run: newer.run } : {}) } };
        }
        const latest = checks[0];
        if (c.keep_failure && PASSING_CHECK.has(c.conclusion) && latest?.conclusion === "failure") {
          audit("github.check.failure_kept", { name: c.name, head_sha: sha, existing: latest.id, conclusion: c.conclusion });
          return { id: latest.id, superseded: { reason: `a failing ${c.name} check on this commit stays in force (a run that did not review it never lifts it)` } };
        }
      }
      const externalId = c.external_id ?? (opts.run ? runExternalId(opts.run) : undefined);
      const res = await octokit.rest.checks.create({
        owner,
        repo,
        name: c.name,
        head_sha: sha,
        status: "completed",
        conclusion: c.conclusion,
        ...(externalId !== undefined ? { external_id: externalId } : {}),
        output: { title: sliceSafe(c.title, MAX_CHECK_TITLE), summary: safeCut(c.summary, MAX_CHECK_SUMMARY) },
      });
      return { id: res.data.id };
    },

    async addLabels(labels: string[]): Promise<void> {
      const list = [...new Set(labels.filter((l) => typeof l === "string" && l.trim() !== ""))];
      if (list.length === 0) return;
      await octokit.rest.issues.addLabels({ owner, repo, issue_number: prNumber, labels: list });
    },

    async removeLabel(label: string): Promise<void> {
      try {
        await octokit.rest.issues.removeLabel({ owner, repo, issue_number: prNumber, name: label });
      } catch (e) {
        if (statusOf(e) !== 404) throw e;
      }
    },

    async repositoryDispatch(target: string, event_type: string, client_payload: Record<string, unknown>): Promise<void> {
      const t = splitRepo(target);
      if (typeof event_type !== "string" || event_type.length < 1 || event_type.length > 100) {
        throw new Error("repository_dispatch event_type must be 1-100 characters");
      }
      if (client_payload === null || typeof client_payload !== "object" || Array.isArray(client_payload)) {
        throw new Error("repository_dispatch client_payload must be an object");
      }
      if (Object.keys(client_payload).length > 10) {
        throw new Error("repository_dispatch client_payload allows at most 10 top-level properties");
      }
      await octokit.rest.repos.createDispatchEvent({ owner: t.owner, repo: t.repo, event_type, client_payload });
    },
  };
}

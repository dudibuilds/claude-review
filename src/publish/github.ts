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
 * identity (our own old comments would not be found; foreign ones are still never adopted).
 */
import { Octokit } from "@octokit/rest";
import { audit } from "../common/audit.js";
import { extractCommentKeys, type PlanCheck, type PlanComment, type PlanReview } from "./plan.js";
import { inlineCode, safeCut, sanitizeMarkdown } from "./sanitize.js";

export interface IssueCommentRef {
  id: number;
  body: string;
}

export interface CreateReviewResult {
  id: number;
  /** True when GitHub rejected the inline comments' lines and they were folded into the body. */
  inlineFallback: boolean;
}

export type CheckRunInput = PlanCheck & { head_sha?: string };

export interface GitHubApi {
  /** Dedupe keys from xrepo:c markers in review comments / review bodies authored by us. */
  listReviewCommentKeys(): Promise<Set<string>>;
  /** Oldest issue comment authored by us that contains `marker`. */
  findStickyComment(marker: string): Promise<IssueCommentRef | undefined>;
  createIssueComment(body: string): Promise<{ id: number }>;
  updateIssueComment(id: number, body: string): Promise<void>;
  /** POST a review at headSha; on a 422 about inline lines, retries once with comments in the body. */
  createReview(r: PlanReview): Promise<CreateReviewResult>;
  /** Completed check run (head_sha defaults to the configured headSha). */
  createCheckRun(c: CheckRunInput): Promise<{ id: number }>;
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
}

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
  if (/approve your own|request changes on your own|not permitted to approve|body is too long/i.test(t)) return false;
  return /could not be resolved|part of the diff|same hunk|pull_request_review_thread|position is invalid|\b(?:start_)?line\b|\bpath\b|\bhunk\b/i.test(t);
}

function lineLabel(c: PlanComment): string {
  return c.start_line !== undefined && c.start_line !== c.line ? `lines ${c.start_line}-${c.line}` : `line ${c.line}`;
}

/**
 * Review body with the inline comments appended (used when GitHub refuses their positions). The
 * comment bodies are already sanitized and keep their xrepo:c markers; whole comments are dropped
 * (never cut) when the body would exceed GitHub's size limit.
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

    async createReview(r: PlanReview): Promise<CreateReviewResult> {
      const comments = r.comments.map((c) => ({
        path: c.path,
        line: c.line,
        side: c.side,
        body: c.body,
        ...(c.start_line !== undefined && c.start_line !== c.line ? { start_line: c.start_line, start_side: c.start_side ?? "RIGHT" } : {}),
      }));
      const base = { owner, repo, pull_number: prNumber, commit_id: headSha, event: r.event };
      try {
        const res = await octokit.rest.pulls.createReview({
          ...base,
          body: checkBody(r.body),
          ...(comments.length > 0 ? { comments } : {}),
        });
        return { id: res.data.id, inlineFallback: false };
      } catch (e) {
        if (comments.length === 0 || !isLineResolutionError(e)) throw e;
        audit("github.review.inline_fallback", { comments: comments.length, error: errorText(e).slice(0, 500) });
        const res = await octokit.rest.pulls.createReview({ ...base, body: checkBody(foldCommentsIntoBody(r.body, r.comments)) });
        return { id: res.data.id, inlineFallback: true };
      }
    },

    async createCheckRun(c: CheckRunInput): Promise<{ id: number }> {
      const res = await octokit.rest.checks.create({
        owner,
        repo,
        name: c.name,
        head_sha: c.head_sha ?? headSha,
        status: "completed",
        conclusion: c.conclusion,
        output: { title: c.title.slice(0, MAX_CHECK_TITLE), summary: safeCut(c.summary, MAX_CHECK_SUMMARY) },
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

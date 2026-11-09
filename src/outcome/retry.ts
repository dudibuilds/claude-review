/**
 * `xrepo retry`: the retry sweeper (run from a central scheduled workflow with a GitHub App token
 * that has actions:write + pull-requests:write on the reviewed repositories).
 *
 *   xrepo retry --policy <manifest.yaml> --workflow <caller workflow file, e.g. xrepo-review.yml>
 *               [--repo owner/name ...] [--owner <login>] [--publisher-login <login>] [--dry-run]
 *   token: env XREPO_GITHUB_TOKEN (API root: env GITHUB_API_URL, default https://api.github.com;
 *   validated, see api-base.ts)
 *
 * Repositories swept (without --repo, which restricts the sweep to exactly those):
 *   - policy.repos keys and exact mirror.repos names;
 *   - every other repository with an open PR carrying a retry label that `defaults` enables (the
 *     publisher applies `defaults` to every repository calling the workflow, owner/* mirror entries
 *     included): found with the search API (`is:pr is:open label:"<label>" org:<owner>`, `user:` for
 *     personal accounts) for each owner named in policy.repos / mirror.repos and the account of the
 *     token's App installation. Repositories the token cannot see are not found.
 * --owner <login> limits all of this to one account (an App installation token covers one account,
 * so the workflow runs one sweep per owner): only that owner's listed repositories are swept, and
 * discovery searches only that owner (no installation lookup). --repo names must then belong to it.
 * For each repository: resolve the policy, collect the retry labels (union of outcomes.*.retry.label
 * with retry.enabled), list the open PRs carrying one, find the latest run of the caller workflow
 * for the PR head sha, then:
 *   - run still queued / in progress          -> wait (nothing to do);
 *   - completed and run_attempt < max_attempts, but before its "not before" time -> wait (a wait is
 *     not an attempt);
 *   - completed and run_attempt < max_attempts -> POST /actions/runs/{id}/rerun (the label stays: the
 *     re-run's publisher re-adds or removes it, and the sweeper uses it to give up later);
 *   - completed and run_attempt >= max_attempts -> remove the retry label(s), then comment once (the
 *     comment is only posted after every label removal succeeded, so it cannot repeat).
 * max_attempts is the one of the outcome that ended the run, as its publisher recorded it in a hidden
 * marker of its sticky PR comment (see retryLimit): `<!-- xrepo-review:retry-after <ISO> run=<run id>
 * attempt=<n> -->` when it asked for a retry (the usage-limit reset time plus a margin, or a backoff
 * when the reset time is unknown; see retryNotBefore), `<!-- xrepo-review:retry-stop run=<run id>
 * attempt=<n> max=<m> -->` when that outcome's max_attempts was reached (the sweeper gives up even if
 * another outcome sharing the label allows more). Without a marker for the latest run the outcome is
 * unknown and the smallest max_attempts of the outcomes sharing the label applies. The sweeper only
 * honours markers of the latest run (same run id and attempt) found in comments written by a bot
 * account (or by --publisher-login); a "not before" time is capped at 8 days after the run. Without
 * one it backs off from the run's completion time: 1h, 2h, 4h ... (max 24h) for attempt 1, 2, 3 ...
 * Requests are sequential, writes are spaced out, and the sweep stops cleanly on a rate limit.
 * --dry-run performs the reads but no writes and prints the planned actions.
 * Exit codes: 0 ok, 1 API / policy errors, 2 usage errors.
 */
import { Octokit } from "@octokit/rest";
import { parseCli } from "../common/args.js";
import { audit } from "../common/audit.js";
import { killSwitchReason, loadPolicy, resolvePolicy } from "../policy/load.js";
import { OUTCOMES, type PolicyFile, type ResolvedPolicy } from "../policy/schema.js";
import { githubApiBase, validateGitHubApiUrl } from "./api-base.js";
import { resolveResetTime } from "./reset.js";
import { safeUrl } from "./template.js";

export const RETRY_TOKEN_ENV = "XREPO_GITHUB_TOKEN";
export const RETRY_EXHAUSTED_MARKER = "<!-- xrepo-review:retry-exhausted -->";
const REPO_RE = /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/;
const WORKFLOW_RE = /^(?:[A-Za-z0-9_.-]{1,100}\.ya?ml|\d{1,20})$/;
const DEFAULT_WRITE_DELAY_MS = 1000;
const MAX_PAGES = 5;
const LOGIN_RE = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})(?:\[bot\])?$/;
const OWNER_RE = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$/;
/** Labels that can be quoted in a search query (`label:"..."`). */
const SEARCHABLE_LABEL_RE = /^[^"\\\u0000-\u001f\u007f]{1,50}$/;
/** Search API calls per sweep for discovery (the search API allows 30 requests a minute). */
export const MAX_DISCOVERY_QUERIES = 20;
const HOUR_MS = 3_600_000;
/** Longest a retry is ever postponed (weekly limits reset within 7 days). */
export const MAX_RETRY_WAIT_MS = 8 * 24 * HOUR_MS;
/** Added to a known reset time (clock skew, the reset itself taking a moment). */
export const RESET_MARGIN_MS = 5 * 60_000;
const MAX_BACKOFF_MS = 24 * HOUR_MS;

/* --------------------------------- rules --------------------------------- */

export interface RetryRule {
  label: string;
  /** Largest max_attempts of the outcomes using this label: the bound for a run whose publisher asked for a retry. */
  max_attempts: number;
  /**
   * Smallest one: the bound for a run that left no publisher marker, whose outcome is therefore
   * unknown (no outcome's max_attempts is ever exceeded). Equal to max_attempts unless outcomes with
   * different max_attempts share the label.
   */
  unmarked_max_attempts: number;
}

/**
 * Enabled retry rules of a resolved policy, de-duplicated by label (case-insensitive): the largest
 * and the smallest max_attempts of the outcomes sharing a label (see retryLimit).
 */
export function retryRules(policy: ResolvedPolicy): RetryRule[] {
  const byLabel = new Map<string, RetryRule>();
  for (const o of OUTCOMES) {
    const r = policy.outcomes[o].retry;
    if (!r?.enabled) continue;
    const key = r.label.toLowerCase();
    const prev = byLabel.get(key);
    if (!prev) byLabel.set(key, { label: r.label, max_attempts: r.max_attempts, unmarked_max_attempts: r.max_attempts });
    else {
      prev.max_attempts = Math.max(prev.max_attempts, r.max_attempts);
      prev.unmarked_max_attempts = Math.min(prev.unmarked_max_attempts, r.max_attempts);
    }
  }
  return [...byLabel.values()];
}

/** Every configured retry label (enabled or not), de-duplicated case-insensitively. */
export function configuredRetryLabels(policy: ResolvedPolicy): string[] {
  const out = new Map<string, string>();
  for (const o of OUTCOMES) {
    const r = policy.outcomes[o].retry;
    if (r && !out.has(r.label.toLowerCase())) out.set(r.label.toLowerCase(), r.label);
  }
  return [...out.values()];
}

/* --------------------------------- timing -------------------------------- */

function isoSeconds(ms: number): string {
  return new Date(Math.ceil(ms / 1000) * 1000).toISOString().replace(/\.000Z$/, "Z");
}

/** Backoff after a failed attempt when no reset time is known: base * 2^(attempt-1), max 24h. */
export function retryBackoffMs(attempt: number, baseMs = HOUR_MS): number {
  const a = Number.isInteger(attempt) && attempt > 0 ? Math.min(attempt, 20) : 1;
  return Math.min(baseMs * 2 ** (a - 1), MAX_BACKOFF_MS);
}

export interface RetryNotBefore {
  /** ISO-8601 (whole seconds, UTC). */
  not_before: string;
  /** "reset": the usage-limit reset time is known; "backoff": it is not (or the outcome is an error). */
  basis: "reset" | "backoff";
}

/**
 * When the run that just ended in `outcome` should be retried at the earliest (written by the
 * publisher into its retry marker): usage_limit with a resolvable reset time -> reset + 5 min (now
 * when it already passed; at most 8 days ahead); usage_limit otherwise -> 2h, 4h, 8h ... (max 24h);
 * error -> 1h, 2h, 4h ... (max 24h). `timeZone`: zone for reset texts without one (see reset.ts).
 */
export function retryNotBefore(input: { outcome: string; reset_at?: string; attempt: number; now: Date; timeZone?: string }): RetryNotBefore {
  const now = input.now.getTime();
  if (input.outcome === "usage_limit" && input.reset_at) {
    const reset = resolveResetTime(input.reset_at, input.now, input.timeZone);
    if (reset) {
      const t = Math.min(Math.max(reset.getTime() + RESET_MARGIN_MS, now), now + MAX_RETRY_WAIT_MS);
      return { not_before: isoSeconds(t), basis: "reset" };
    }
  }
  const base = input.outcome === "usage_limit" ? 2 * HOUR_MS : HOUR_MS;
  return { not_before: isoSeconds(now + retryBackoffMs(input.attempt, base)), basis: "backoff" };
}

export interface RetryAfterMarker {
  not_before: string;
  run_id: number;
  attempt: number;
}

const RETRY_AFTER_RE = /<!-- xrepo-review:retry-after (\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z) run=(\d{1,20}) attempt=(\d{1,6}) -->/g;

/** Hidden marker the publisher appends to its sticky comment when it adds a retry label. */
export function retryAfterMarker(m: RetryAfterMarker): string {
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(m.not_before)) throw new Error("not_before must be ISO-8601 UTC in whole seconds");
  if (!Number.isSafeInteger(m.run_id) || m.run_id <= 0 || !Number.isSafeInteger(m.attempt) || m.attempt <= 0) {
    throw new Error("run_id and attempt must be positive integers");
  }
  return `<!-- xrepo-review:retry-after ${m.not_before} run=${m.run_id} attempt=${m.attempt} -->`;
}

/** Every well-formed retry-after marker in `text`. */
export function parseRetryAfterMarkers(text: string): RetryAfterMarker[] {
  if (typeof text !== "string" || !text.includes("xrepo-review:retry-after")) return [];
  const out: RetryAfterMarker[] = [];
  for (const m of text.matchAll(RETRY_AFTER_RE)) {
    const t = Date.parse(m[1] ?? "");
    const run_id = Number(m[2]);
    const attempt = Number(m[3]);
    if (Number.isFinite(t) && Number.isSafeInteger(run_id) && run_id > 0 && attempt > 0) out.push({ not_before: m[1] ?? "", run_id, attempt });
  }
  return out;
}

/**
 * The publisher of run `run_id` / `attempt` reached the max_attempts of the outcome that ended it
 * (it leaves the retry label in place so that the sweeper gives up and comments once).
 */
export interface RetryStopMarker {
  kind: "stop";
  run_id: number;
  attempt: number;
  /** max_attempts of the outcome that ended the run. */
  max_attempts: number;
}

/** A marker the sweeper reads from the publisher's sticky comment. */
export type RetryMarker = RetryAfterMarker | RetryStopMarker;

const RETRY_STOP_RE = /<!-- xrepo-review:retry-stop run=(\d{1,20}) attempt=(\d{1,6}) max=(\d{1,6}) -->/g;

export function isRetryStopMarker(m: RetryMarker): m is RetryStopMarker {
  return (m as Partial<RetryStopMarker>).kind === "stop";
}

/** Hidden marker the publisher appends to its sticky comment when it leaves an exhausted retry label. */
export function retryStopMarker(m: Omit<RetryStopMarker, "kind">): string {
  for (const n of [m.run_id, m.attempt, m.max_attempts]) {
    if (!Number.isSafeInteger(n) || n <= 0) throw new Error("run_id, attempt and max_attempts must be positive integers");
  }
  return `<!-- xrepo-review:retry-stop run=${m.run_id} attempt=${m.attempt} max=${m.max_attempts} -->`;
}

/** Every well-formed retry-stop marker in `text`. */
export function parseRetryStopMarkers(text: string): RetryStopMarker[] {
  if (typeof text !== "string" || !text.includes("xrepo-review:retry-stop")) return [];
  const out: RetryStopMarker[] = [];
  for (const m of text.matchAll(RETRY_STOP_RE)) {
    const run_id = Number(m[1]);
    const attempt = Number(m[2]);
    const max_attempts = Number(m[3]);
    if (Number.isSafeInteger(run_id) && run_id > 0 && attempt > 0 && max_attempts > 0) out.push({ kind: "stop", run_id, attempt, max_attempts });
  }
  return out;
}

/** Every well-formed retry-after and retry-stop marker in `text`. */
export function parseRetryMarkers(text: string): RetryMarker[] {
  return [...parseRetryAfterMarkers(text), ...parseRetryStopMarkers(text)];
}

/* -------------------------------- decision -------------------------------- */

export interface WorkflowRunInfo {
  id: number;
  run_attempt: number;
  status: string;
  conclusion?: string | null;
  html_url?: string;
  created_at?: string;
  /** Last update; for a completed run, about when it finished. */
  updated_at?: string;
}

export type RetryDecision =
  | { action: "rerun"; run_id: number; run_attempt: number; max_attempts: number }
  | { action: "give_up"; run_id: number; run_attempt: number; max_attempts: number; reason?: string }
  | { action: "wait"; run_id: number; reason: string; not_before?: string }
  | { action: "none"; reason: string };

export interface RetryTiming {
  now: Date;
  /** Earliest re-run time (ISO-8601 or epoch ms); absent = no constraint. */
  not_before?: string | number;
  /** Where not_before came from (for the decision's reason), e.g. "usage limit reset" or "backoff". */
  basis?: string;
}

function attemptOf(run: WorkflowRunInfo): number {
  return Number.isInteger(run.run_attempt) && run.run_attempt > 0 ? run.run_attempt : 1;
}

export function decideRetry(run: WorkflowRunInfo | undefined, maxAttempts: number, timing?: RetryTiming): RetryDecision {
  if (!run) return { action: "none", reason: "no run of the workflow for the PR head commit" };
  if (run.status !== "completed") return { action: "wait", run_id: run.id, reason: `latest run is ${run.status}` };
  const attempt = attemptOf(run);
  if (attempt < maxAttempts) {
    if (timing?.not_before !== undefined) {
      const nb = typeof timing.not_before === "number" ? timing.not_before : Date.parse(timing.not_before);
      const now = timing.now.getTime();
      if (Number.isFinite(nb) && Number.isFinite(now) && now < nb) {
        const iso = isoSeconds(nb);
        return { action: "wait", run_id: run.id, reason: `not before ${iso}${timing.basis ? ` (${timing.basis})` : ""}`, not_before: iso };
      }
    }
    return { action: "rerun", run_id: run.id, run_attempt: attempt, max_attempts: maxAttempts };
  }
  return { action: "give_up", run_id: run.id, run_attempt: attempt, max_attempts: maxAttempts };
}

/**
 * Timing for a completed run below max_attempts: the publisher's marker for exactly this run and
 * attempt (capped at 8 days after the run), else a backoff from the run's completion time, else none.
 */
export function retryTiming(run: WorkflowRunInfo, markers: readonly RetryMarker[], now: Date): RetryTiming {
  const attempt = attemptOf(run);
  const anchor = Date.parse(run.updated_at ?? run.created_at ?? "");
  const own = markers.filter((m): m is RetryAfterMarker => !isRetryStopMarker(m) && m.run_id === run.id && m.attempt === attempt);
  const marker = own[own.length - 1];
  if (marker) {
    const nb = Date.parse(marker.not_before);
    const cap = (Number.isFinite(anchor) ? anchor : now.getTime()) + MAX_RETRY_WAIT_MS;
    return { now, not_before: Math.min(nb, cap), basis: "requested by the publisher" };
  }
  if (Number.isFinite(anchor)) return { now, not_before: anchor + retryBackoffMs(attempt), basis: "backoff" };
  return { now };
}

export interface RetryLimit {
  max_attempts: number;
  /**
   * "stop": the run's publisher reached its outcome's max_attempts (retry-stop marker); "retry": it
   * asked for a retry (retry-after marker); "unmarked": no marker for this run and attempt.
   */
  basis: "stop" | "retry" | "unmarked";
}

/**
 * max_attempts for the latest (completed) run of a PR carrying the labels of `rules`. Only the run's
 * publisher knows which outcome ended it, so its marker for exactly this run and attempt decides: a
 * retry-stop marker gives up now (that outcome's own max_attempts was reached, even when another
 * outcome sharing the label allows more), a retry-after marker allows the rules' largest
 * max_attempts. Without a marker the smallest max_attempts of the outcomes sharing the label applies.
 */
export function retryLimit(run: WorkflowRunInfo, markers: readonly RetryMarker[], rules: readonly RetryRule[]): RetryLimit {
  const attempt = attemptOf(run);
  const own = markers.filter((m) => m.run_id === run.id && m.attempt === attempt);
  const stops = own.filter(isRetryStopMarker);
  if (stops.length > 0) return { max_attempts: Math.min(attempt, ...stops.map((m) => m.max_attempts)), basis: "stop" };
  if (rules.length === 0) return { max_attempts: 1, basis: "unmarked" };
  if (own.length > 0) return { max_attempts: Math.max(...rules.map((r) => r.max_attempts)), basis: "retry" };
  return { max_attempts: Math.max(...rules.map((r) => r.unmarked_max_attempts)), basis: "unmarked" };
}

export function giveUpComment(attempts: number, runUrl?: string): string {
  const link = runUrl ? safeUrl(runUrl) : "";
  return (
    `${RETRY_EXHAUSTED_MARKER}\n` +
    `\u23F9\uFE0F The automated review was attempted ${attempts} time${attempts === 1 ? "" : "s"} without completing, so automatic retries have stopped. ` +
    `Push a new commit or re-run the workflow manually to try again.${link ? ` [Last run](${link})` : ""}`
  );
}

/* ---------------------------------- API ---------------------------------- */

export interface LabeledPull {
  number: number;
  labels: string[];
}

export interface RetryApi {
  /** Open pull requests of `repo` carrying `label`. */
  listOpenPullsWithLabel(repo: string, label: string): Promise<LabeledPull[]>;
  /** Head sha of an open PR (undefined when it is closed). */
  getPullHeadSha(repo: string, pr: number): Promise<string | undefined>;
  /** Most recent run of `workflow` (file name or id) for `headSha`. */
  latestWorkflowRun(repo: string, workflow: string, headSha: string): Promise<WorkflowRunInfo | undefined>;
  rerunWorkflow(repo: string, runId: number): Promise<void>;
  /** Remove a label; a 404 (not present) is ignored. */
  removeLabel(repo: string, pr: number, label: string): Promise<void>;
  createComment(repo: string, pr: number, body: string): Promise<void>;
  /**
   * Retry markers (retry-after and retry-stop, see retryAfterMarker / retryStopMarker) in the PR's
   * comments written by the publisher (any bot account, or exactly `publisherLogin`). Optional:
   * without it, the sweeper backs off and uses the smallest max_attempts of a shared label.
   */
  retryAfterMarkers?(repo: string, pr: number): Promise<RetryMarker[]>;
  /**
   * Login of the account the token's GitHub App installation belongs to; undefined when the token is
   * not an installation token. Optional (discovery then searches the policy's owners only).
   */
  installationOwner?(): Promise<string | undefined>;
  /**
   * Repositories (owner/name) of `owner` with an open pull request carrying `label` (search API).
   * Optional: without it, only the policy's listed repositories are swept.
   */
  findReposWithLabeledPulls?(owner: string, label: string): Promise<string[]>;
}

export class RateLimitedError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "RateLimitedError";
  }
}

function statusOf(e: unknown): number | undefined {
  const s = (e as { status?: unknown } | null)?.status;
  return typeof s === "number" ? s : undefined;
}

function isRateLimit(e: unknown): boolean {
  const st = statusOf(e);
  if (st === 429) return true;
  if (st !== 403) return false;
  const headers = (e as { response?: { headers?: Record<string, unknown> } }).response?.headers ?? {};
  if (String(headers["x-ratelimit-remaining"] ?? "") === "0" || headers["retry-after"] !== undefined) return true;
  return /rate limit/i.test((e as Error)?.message ?? "");
}

function split(repo: string): { owner: string; repo: string } {
  const [owner = "", name = ""] = repo.split("/");
  return { owner, repo: name };
}

export function createRetryApi(opts: {
  token: string;
  baseUrl?: string;
  fetch?: typeof fetch;
  octokit?: Octokit;
  /** Login of the publisher's token (e.g. "github-actions[bot]"); default: any bot account. */
  publisherLogin?: string;
}): RetryApi {
  const publisher = opts.publisherLogin?.trim().toLowerCase() || undefined;
  const octokit =
    opts.octokit ??
    new Octokit({
      auth: opts.token,
      userAgent: "xrepo-review-retry",
      ...(opts.baseUrl ? { baseUrl: validateGitHubApiUrl(opts.baseUrl) } : {}),
      request: opts.fetch ? { fetch: opts.fetch } : {},
      log: {
        debug: () => {},
        info: () => {},
        warn: (message: string) => audit("retry.github_warn", { message }),
        error: () => {},
      },
    });
  const wrap = async <T>(what: string, fn: () => Promise<T>): Promise<T> => {
    try {
      return await fn();
    } catch (e) {
      if (isRateLimit(e)) throw new RateLimitedError(`GitHub rate limit reached during ${what}`);
      throw e;
    }
  };
  return {
    listOpenPullsWithLabel: (repo, label) =>
      wrap("list pull requests", async () => {
        const out: LabeledPull[] = [];
        let pages = 0;
        for await (const page of octokit.paginate.iterator(octokit.rest.issues.listForRepo, {
          ...split(repo),
          state: "open",
          labels: label,
          per_page: 100,
        })) {
          for (const issue of page.data) {
            if (!issue.pull_request) continue;
            const labels = (issue.labels ?? [])
              .map((l) => (typeof l === "string" ? l : (l.name ?? "")))
              .filter((l): l is string => typeof l === "string" && l !== "");
            out.push({ number: issue.number, labels });
          }
          if (++pages >= MAX_PAGES) break;
        }
        return out;
      }),
    getPullHeadSha: (repo, pr) =>
      wrap("get pull request", async () => {
        const r = await octokit.rest.pulls.get({ ...split(repo), pull_number: pr });
        return r.data.state === "open" ? r.data.head.sha : undefined;
      }),
    latestWorkflowRun: (repo, workflow, headSha) =>
      wrap("list workflow runs", async () => {
        const r = await octokit.rest.actions.listWorkflowRuns({
          ...split(repo),
          workflow_id: /^\d+$/.test(workflow) ? Number(workflow) : workflow,
          head_sha: headSha,
          per_page: 20,
        });
        const runs = [...r.data.workflow_runs].sort(
          (a, b) => Date.parse(b.created_at) - Date.parse(a.created_at) || b.id - a.id,
        );
        const run = runs[0];
        if (!run) return undefined;
        return {
          id: run.id,
          run_attempt: run.run_attempt ?? 1,
          status: run.status ?? "unknown",
          conclusion: run.conclusion,
          html_url: run.html_url,
          created_at: run.created_at,
          updated_at: run.updated_at,
        };
      }),
    rerunWorkflow: (repo, runId) =>
      wrap("re-run workflow", async () => {
        await octokit.rest.actions.reRunWorkflow({ ...split(repo), run_id: runId });
      }),
    removeLabel: (repo, pr, label) =>
      wrap("remove label", async () => {
        try {
          await octokit.rest.issues.removeLabel({ ...split(repo), issue_number: pr, name: label });
        } catch (e) {
          if (statusOf(e) !== 404) throw e;
        }
      }),
    createComment: (repo, pr, body) =>
      wrap("create comment", async () => {
        await octokit.rest.issues.createComment({ ...split(repo), issue_number: pr, body });
      }),
    retryAfterMarkers: (repo, pr) =>
      wrap("list comments", async () => {
        const out: RetryMarker[] = [];
        let pages = 0;
        for await (const page of octokit.paginate.iterator(octokit.rest.issues.listComments, {
          ...split(repo),
          issue_number: pr,
          per_page: 100,
        })) {
          for (const c of page.data) {
            const login = c.user?.login?.toLowerCase() ?? "";
            const trusted = publisher ? login === publisher : c.user?.type === "Bot";
            if (trusted && typeof c.body === "string") out.push(...parseRetryMarkers(c.body));
          }
          if (++pages >= MAX_PAGES) break;
        }
        return out;
      }),
    installationOwner: () =>
      wrap("list installation repositories", async () => {
        try {
          const r = await octokit.rest.apps.listReposAccessibleToInstallation({ per_page: 1 });
          const login = r.data.repositories[0]?.owner?.login;
          return typeof login === "string" && OWNER_RE.test(login) ? login : undefined;
        } catch (e) {
          // Not an installation token (a PAT, GITHUB_TOKEN): there is no installation account.
          const st = statusOf(e);
          if (!isRateLimit(e) && (st === 401 || st === 403 || st === 404)) return undefined;
          throw e;
        }
      }),
    findReposWithLabeledPulls: (owner, label) =>
      wrap("search pull requests", async () => {
        if (!OWNER_RE.test(owner)) throw new Error(`invalid owner ${JSON.stringify(owner)}`);
        if (!SEARCHABLE_LABEL_RE.test(label)) throw new Error(`label ${JSON.stringify(label)} cannot be quoted in a search query`);
        const search = async (qualifier: "org" | "user"): Promise<string[]> => {
          const found = new Map<string, string>();
          let pages = 0;
          for await (const page of octokit.paginate.iterator(octokit.rest.search.issuesAndPullRequests, {
            q: `is:pr is:open label:"${label}" ${qualifier}:${owner}`,
            per_page: 100,
          })) {
            for (const item of page.data) {
              if (!item.pull_request || item.state !== "open") continue;
              const m = /\/repos\/([^/]+)\/([^/]+)$/.exec(item.repository_url ?? "");
              const name = m ? `${decodeURIComponent(m[1] ?? "")}/${decodeURIComponent(m[2] ?? "")}` : "";
              if (!validRepoName(name) || name.split("/")[0]?.toLowerCase() !== owner.toLowerCase()) continue;
              if (!found.has(name.toLowerCase())) found.set(name.toLowerCase(), name);
            }
            if (++pages >= MAX_PAGES) break;
          }
          return [...found.values()];
        };
        try {
          return await search("org");
        } catch (e) {
          // 422: `org:` names a personal account (or nothing); `user:` covers personal accounts.
          if (statusOf(e) === 422 && !isRateLimit(e)) return await search("user");
          throw e;
        }
      }),
  };
}

/* ---------------------------------- sweep --------------------------------- */

export interface SweepAction {
  repo: string;
  pr: number;
  labels: string[];
  head_sha?: string;
  decision: RetryDecision;
  /** Writes performed (false in dry-run or when they failed). */
  done: boolean;
  error?: string;
}

export interface SweepDiscovery {
  /** Owners searched (policy.repos / mirror.repos owners and the token's installation account). */
  owners: string[];
  /** Retry labels `defaults` enables (searched for). */
  labels: string[];
  /** Repositories found with an open labelled PR (beyond the policy's listed ones, sorted). */
  repos: string[];
}

export interface SweepReport {
  dry_run: boolean;
  workflow: string;
  /** The account this sweep was limited to (--owner). */
  owner?: string;
  /** Every repository swept: the policy's listed ones, then the discovered ones. */
  repos: string[];
  /** Repositories covered by `defaults` found through the search API (absent with --repo). */
  discovery?: SweepDiscovery;
  actions: SweepAction[];
  errors: string[];
  rate_limited: boolean;
}

export interface SweepOptions {
  policy: PolicyFile;
  /** Caller workflow file name (or numeric id). */
  workflow: string;
  /**
   * Restrict to exactly these repositories (no discovery). Default: policy.repos keys + exact
   * mirror.repos names + the repositories discovered for `defaults` (see discoverRepos).
   */
  repos?: string[];
  /** Search for repositories covered by `defaults` (default true; ignored with `repos`). */
  discover?: boolean;
  /**
   * Only this account's repositories (case-insensitive): the listed ones of that owner, and
   * discovery searches only that owner (no installation lookup). `repos` must belong to it.
   */
  owner?: string;
  dryRun: boolean;
  api: RetryApi;
  /** Delay between write calls (default 1000 ms). */
  writeDelayMs?: number;
  sleep?: (ms: number) => Promise<void>;
  /** Clock (tests). */
  now?: () => Date;
}

function validRepoName(r: string): boolean {
  return REPO_RE.test(r) && !r.split("/").some((s) => s === "." || s === "..");
}

/**
 * Repositories the policy lists: policy.repos keys + exact mirror repos (no globs), de-duplicated
 * (or `only`, de-duplicated). Repositories covered only by `defaults` (owner/* mirror entries
 * included) are found by discoverRepos.
 */
export function sweepRepos(policy: PolicyFile, only?: string[]): string[] {
  const src = only && only.length > 0 ? only : [...Object.keys(policy.repos), ...policy.mirror.repos.filter((r) => !r.includes("*"))];
  const seen = new Map<string, string>();
  for (const r of src) {
    const t = r.trim();
    if (!validRepoName(t)) continue;
    if (!seen.has(t.toLowerCase())) seen.set(t.toLowerCase(), t);
  }
  return [...seen.values()];
}

/** Owners named in policy.repos keys and mirror.repos entries (exact names and owner/* patterns). */
export function policyOwners(policy: PolicyFile): string[] {
  const seen = new Map<string, string>();
  for (const r of [...Object.keys(policy.repos), ...policy.mirror.repos]) {
    const parts = r.trim().split("/");
    const owner = parts[0] ?? "";
    if (parts.length !== 2 || !OWNER_RE.test(owner)) continue;
    if (!seen.has(owner.toLowerCase())) seen.set(owner.toLowerCase(), owner);
  }
  return [...seen.values()];
}

/** The policy as the publisher applies it to a repository without a `repos:` entry (`defaults`). */
export function defaultsPolicy(policy: PolicyFile): ResolvedPolicy {
  const keys = new Set(Object.keys(policy.repos).map((k) => k.toLowerCase()));
  let name = "xrepo-review-defaults/defaults";
  while (keys.has(name)) name += "-";
  return resolvePolicy(policy, name);
}

/**
 * Repositories covered by `defaults` that carry one of its retry labels on an open PR: the publisher
 * labels PRs of every repository that calls the workflow, not only the ones the policy lists. One
 * search per owner and label (owners: policyOwners + the token's installation account), at most
 * MAX_DISCOVERY_QUERIES. Failures are recorded in `report.errors`; the listed repositories are swept
 * regardless. Throws RateLimitedError only for the (core) installation lookup.
 */
export async function discoverRepos(policy: PolicyFile, api: RetryApi, report: SweepReport, opts: { owner?: string } = {}): Promise<string[]> {
  if (!api.findReposWithLabeledPulls) return [];
  let defaults: ResolvedPolicy;
  try {
    defaults = defaultsPolicy(policy);
  } catch (e) {
    report.errors.push(`defaults: ${errMsg(e)}`);
    audit("retry.policy_error", { repo: "(defaults)", error: e });
    return [];
  }
  if (killSwitchReason(defaults) !== undefined) return [];
  const labels: string[] = [];
  for (const r of retryRules(defaults)) {
    if (SEARCHABLE_LABEL_RE.test(r.label)) labels.push(r.label);
    else {
      report.errors.push(
        `retry label ${JSON.stringify(r.label)} cannot be searched for: repositories covered only by defaults are not swept (rename the label or list them under repos:)`,
      );
    }
  }
  if (labels.length === 0) return [];

  const owners = new Map<string, string>(
    opts.owner !== undefined ? [[opts.owner.toLowerCase(), opts.owner]] : policyOwners(policy).map((o) => [o.toLowerCase(), o]),
  );
  if (opts.owner === undefined && api.installationOwner) {
    try {
      const o = await api.installationOwner();
      if (o && OWNER_RE.test(o) && !owners.has(o.toLowerCase())) owners.set(o.toLowerCase(), o);
    } catch (e) {
      if (e instanceof RateLimitedError) throw e;
      audit("retry.installation_owner_failed", { error: e, note: "searching the policy's owners only" });
    }
  }
  const discovery: SweepDiscovery = { owners: [...owners.values()], labels, repos: [] };
  report.discovery = discovery;
  if (owners.size === 0) {
    audit("retry.discovery_skipped", { reason: "no owner known (no repos / mirror.repos entries, not an installation token)" });
    return [];
  }

  const found = new Map<string, string>();
  let queries = 0;
  search: for (const owner of discovery.owners) {
    for (const label of labels) {
      if (++queries > MAX_DISCOVERY_QUERIES) {
        report.errors.push(`discovery: more than ${MAX_DISCOVERY_QUERIES} owner/label searches needed; the rest were skipped (use --repo or fewer retry labels)`);
        break search;
      }
      try {
        for (const r of await api.findReposWithLabeledPulls(owner, label)) {
          const t = r.trim();
          if (!validRepoName(t) || t.split("/")[0]?.toLowerCase() !== owner.toLowerCase()) continue;
          if (!found.has(t.toLowerCase())) found.set(t.toLowerCase(), t);
        }
      } catch (e) {
        if (e instanceof RateLimitedError) {
          // The search API has its own (per-minute) limit: sweep what is known.
          report.errors.push(`discovery stopped: ${e.message}`);
          audit("retry.discovery_rate_limited", { owner, label });
          break search;
        }
        report.errors.push(`discovery ${owner} ${JSON.stringify(label)}: ${errMsg(e)}`);
        audit("retry.discovery_failed", { owner, label, error: e });
      }
    }
  }
  discovery.repos = [...found.values()].sort((a, b) => a.toLowerCase().localeCompare(b.toLowerCase()));
  audit("retry.discovered", { owners: discovery.owners, labels, repos: discovery.repos });
  return discovery.repos;
}

function errMsg(e: unknown): string {
  const st = statusOf(e);
  const m = (e as Error)?.message ?? String(e);
  return `${st !== undefined ? `HTTP ${st}: ` : ""}${m}`.slice(0, 300);
}

export async function sweep(opts: SweepOptions): Promise<SweepReport> {
  const { api, workflow, dryRun } = opts;
  const sleep = opts.sleep ?? ((ms: number) => new Promise<void>((r) => setTimeout(r, ms)));
  const delay = opts.writeDelayMs ?? DEFAULT_WRITE_DELAY_MS;
  const now = opts.now ?? ((): Date => new Date());
  const restricted = opts.repos !== undefined && opts.repos.length > 0;
  const owner = opts.owner?.trim() || undefined;
  if (owner !== undefined && !OWNER_RE.test(owner)) throw new Error(`invalid owner ${JSON.stringify(owner)}`);
  const ofOwner = (r: string): boolean => owner === undefined || r.split("/")[0]?.toLowerCase() === owner.toLowerCase();
  const report: SweepReport = {
    dry_run: dryRun,
    workflow,
    ...(owner !== undefined ? { owner } : {}),
    repos: sweepRepos(opts.policy, opts.repos).filter(ofOwner),
    actions: [],
    errors: [],
    rate_limited: false,
  };
  let wrote = false;
  const pace = async (): Promise<void> => {
    if (wrote && delay > 0) await sleep(delay);
    wrote = true;
  };

  try {
    if (!restricted && opts.discover !== false) {
      const discovered = await discoverRepos(opts.policy, api, report, owner !== undefined ? { owner } : {});
      if (discovered.length > 0) report.repos = sweepRepos(opts.policy, [...report.repos, ...discovered]).filter(ofOwner);
    }
    for (const repo of report.repos) {
      let policy: ResolvedPolicy;
      try {
        policy = resolvePolicy(opts.policy, repo);
      } catch (e) {
        report.errors.push(`${repo}: ${errMsg(e)}`);
        audit("retry.policy_error", { repo, error: e });
        continue;
      }
      if (killSwitchReason(policy) !== undefined) {
        audit("retry.repo_disabled", { repo });
        continue;
      }
      const rules = retryRules(policy);
      if (rules.length === 0) continue;

      // PR number -> its labels keyed by lower case (the PR's own spelling wins).
      const prs = new Map<number, Map<string, string>>();
      try {
        for (const rule of rules) {
          for (const pr of await api.listOpenPullsWithLabel(repo, rule.label)) {
            const set = prs.get(pr.number) ?? new Map<string, string>();
            for (const l of pr.labels) if (!set.has(l.toLowerCase())) set.set(l.toLowerCase(), l);
            if (!set.has(rule.label.toLowerCase())) set.set(rule.label.toLowerCase(), rule.label);
            prs.set(pr.number, set);
          }
        }
      } catch (e) {
        if (e instanceof RateLimitedError) throw e;
        report.errors.push(`${repo}: ${errMsg(e)}`);
        audit("retry.list_failed", { repo, error: e });
        continue;
      }

      for (const pr of [...prs.keys()].sort((a, b) => a - b)) {
        const present = [...(prs.get(pr)?.values() ?? [])];
        const matching = rules.filter((r) => present.some((l) => l.toLowerCase() === r.label.toLowerCase()));
        const labels = present.filter((l) => matching.some((r) => r.label.toLowerCase() === l.toLowerCase()));
        const upper = Math.max(...matching.map((r) => r.max_attempts));
        const action: SweepAction = { repo, pr, labels, decision: { action: "none", reason: "" }, done: false };
        try {
          const sha = await api.getPullHeadSha(repo, pr);
          if (!sha) {
            action.decision = { action: "none", reason: "pull request is not open" };
            report.actions.push(action);
            continue;
          }
          action.head_sha = sha;
          const run = await api.latestWorkflowRun(repo, workflow, sha);
          let decision: RetryDecision | undefined;
          let maxAttempts = upper;
          let timing: RetryTiming | undefined;
          if (run && run.status === "completed" && attemptOf(run) < upper) {
            // Below the label's largest max_attempts: the run's own outcome decides (retryLimit).
            let markers: RetryMarker[] = [];
            let markersRead = true;
            if (api.retryAfterMarkers) {
              try {
                markers = await api.retryAfterMarkers(repo, pr);
              } catch (e) {
                if (e instanceof RateLimitedError) throw e;
                markersRead = false;
                audit("retry.marker_read_failed", { repo, pr, error: e, note: "falling back to the backoff" });
              }
            }
            const limit = retryLimit(run, markers, matching);
            maxAttempts = limit.max_attempts;
            timing = retryTiming(run, markers, now());
            if (!markersRead && attemptOf(run) >= maxAttempts) {
              // Only the publisher's marker tells whether this run may be retried: decide next sweep.
              decision = { action: "wait", run_id: run.id, reason: "the publisher's retry markers could not be read" };
              report.errors.push(`${repo}#${pr}: the publisher's retry markers could not be read; deciding at the next sweep`);
            } else if (limit.basis === "stop") {
              decision = {
                action: "give_up",
                run_id: run.id,
                run_attempt: attemptOf(run),
                max_attempts: maxAttempts,
                reason: "the outcome that ended this run reached its own max_attempts (retry-stop marker)",
              };
            }
          }
          action.decision = decision ?? decideRetry(run, maxAttempts, timing);
          report.actions.push(action);
          audit("retry.decision", { repo, pr, head_sha: sha, labels, decision: action.decision, dry_run: dryRun });
          if (dryRun) continue;
          if (action.decision.action === "rerun") {
            await pace();
            await api.rerunWorkflow(repo, action.decision.run_id);
            action.done = true;
            audit("retry.rerun", { repo, pr, run_id: action.decision.run_id, attempt: action.decision.run_attempt + 1 });
          } else if (action.decision.action === "give_up") {
            for (const l of labels) {
              await pace();
              await api.removeLabel(repo, pr, l);
            }
            await pace();
            await api.createComment(repo, pr, giveUpComment(action.decision.run_attempt, run?.html_url));
            action.done = true;
            audit("retry.gave_up", { repo, pr, run_id: action.decision.run_id, attempts: action.decision.run_attempt });
          }
        } catch (e) {
          if (e instanceof RateLimitedError) throw e;
          action.error = errMsg(e);
          if (!report.actions.includes(action)) report.actions.push(action);
          report.errors.push(`${repo}#${pr}: ${action.error}`);
          audit("retry.failed", { repo, pr, error: e });
        }
      }
    }
  } catch (e) {
    if (!(e instanceof RateLimitedError)) throw e;
    report.rate_limited = true;
    audit("retry.rate_limited", { message: e.message });
  }
  return report;
}

/* ----------------------------------- CLI ---------------------------------- */

export const USAGE =
  "usage: xrepo retry --policy <file> --workflow <caller workflow file> [--repo owner/name ...] [--owner <login>] [--publisher-login <login>] [--dry-run]\n" +
  "  --owner: sweep only this account's repositories (one App installation token covers one account)";

export interface RetryMainDeps {
  api?: RetryApi;
  env?: Record<string, string | undefined>;
  stdout?: { write(s: string): unknown };
  stderr?: { write(s: string): unknown };
  sleep?: (ms: number) => Promise<void>;
  writeDelayMs?: number;
  now?: () => Date;
}

export async function main(args: string[], deps: RetryMainDeps = {}): Promise<number> {
  const env = deps.env ?? process.env;
  const stdout = deps.stdout ?? process.stdout;
  const stderr = deps.stderr ?? process.stderr;
  let policyPath: string;
  let workflow: string;
  let repos: string[];
  let dryRun: boolean;
  let publisherLogin: string | undefined;
  let owner: string | undefined;
  try {
    const v = parseCli(args, {
      policy: { type: "string", required: true },
      workflow: { type: "string", required: true },
      repo: { type: "string", multiple: true },
      owner: { type: "string" },
      "publisher-login": { type: "string" },
      "dry-run": { type: "boolean" },
    });
    policyPath = v.policy as string;
    workflow = (v.workflow as string).trim();
    repos = ((v.repo as string[] | undefined) ?? []).map((r) => r.trim());
    dryRun = v["dry-run"] === true;
    if (!WORKFLOW_RE.test(workflow)) throw new Error(`--workflow must be a workflow file name (e.g. xrepo-review.yml) or id, got ${JSON.stringify(workflow)}`);
    const bad = repos.filter((r) => !REPO_RE.test(r) || r.split("/").some((s) => s === "." || s === ".."));
    if (bad.length > 0) throw new Error(`--repo must be owner/name: ${bad.map((b) => JSON.stringify(b)).join(", ")}`);
    const rawOwner = v.owner as string | undefined;
    if (rawOwner !== undefined) {
      owner = rawOwner.trim();
      if (!OWNER_RE.test(owner)) throw new Error(`--owner must be a GitHub account name, got ${JSON.stringify(rawOwner)}`);
      const foreign = repos.filter((r) => r.split("/")[0]?.toLowerCase() !== owner?.toLowerCase());
      if (foreign.length > 0) throw new Error(`--repo ${foreign.map((r) => JSON.stringify(r)).join(", ")} not owned by --owner ${owner}`);
    }
    publisherLogin = (v["publisher-login"] as string | undefined)?.trim() || undefined;
    if (publisherLogin !== undefined && !LOGIN_RE.test(publisherLogin)) {
      throw new Error(`--publisher-login must be a GitHub login (e.g. github-actions[bot]), got ${JSON.stringify(publisherLogin)}`);
    }
  } catch (e) {
    stderr.write(`xrepo retry: ${(e as Error).message}\n${USAGE}\n`);
    return 2;
  }

  let policy: PolicyFile;
  try {
    policy = loadPolicy(policyPath);
  } catch (e) {
    stderr.write(`xrepo retry: ${(e as Error).message}\n`);
    return 1;
  }

  let api = deps.api;
  if (!api) {
    const token = env[RETRY_TOKEN_ENV]?.trim();
    if (!token) {
      stderr.write(`xrepo retry: env ${RETRY_TOKEN_ENV} is required (GitHub App token with actions:write and pull-requests:write)\n`);
      return 1;
    }
    let baseUrl: string;
    try {
      baseUrl = githubApiBase(env);
    } catch (e) {
      stderr.write(`xrepo retry: ${(e as Error).message}\n`);
      return 1;
    }
    api = createRetryApi({ token, baseUrl, ...(publisherLogin ? { publisherLogin } : {}) });
  }

  let report: SweepReport;
  try {
    report = await sweep({
      policy,
      workflow,
      repos,
      ...(owner !== undefined ? { owner } : {}),
      dryRun,
      api,
      ...(deps.sleep ? { sleep: deps.sleep } : {}),
      ...(deps.writeDelayMs !== undefined ? { writeDelayMs: deps.writeDelayMs } : {}),
      ...(deps.now ? { now: deps.now } : {}),
    });
  } catch (e) {
    audit("retry.sweep_failed", { error: e });
    stderr.write(`xrepo retry: ${(e as Error).message}\n`);
    return 1;
  }
  stdout.write(`${JSON.stringify(report, null, 2)}\n`);
  audit("retry.done", {
    repos: report.repos.length,
    reruns: report.actions.filter((a) => a.decision.action === "rerun").length,
    waiting: report.actions.filter((a) => a.decision.action === "wait").length,
    gave_up: report.actions.filter((a) => a.decision.action === "give_up").length,
    errors: report.errors.length,
    rate_limited: report.rate_limited,
    dry_run: dryRun,
  });
  return report.errors.length > 0 ? 1 : 0;
}

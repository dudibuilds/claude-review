/**
 * repository_dispatch for workflow chaining (outcomes.<x>.dispatch).
 *
 * Token: env XREPO_DISPATCH_TOKEN (any target repo, needs contents:write there). Without it, only a
 * dispatch to the PR repository itself is attempted, with the publisher's own client (`api`, holding
 * GITHUB_TOKEN) or env GITHUB_TOKEN. Events created with GITHUB_TOKEN still start
 * repository_dispatch workflows (GitHub exempts workflow_dispatch / repository_dispatch). The
 * shipped review.yml gives the publish job `contents: read` only, so that fallback fails there with
 * 403 / 404; the error then says that XREPO_DISPATCH_TOKEN is needed.
 *
 * client_payload has at most 10 top-level keys (GitHub limit) and stays far below 64 KB:
 *   outcome, repo, pr_number, pr_url, head_sha, run_url, attempt, reason, reset_at,
 *   review: {verdict, findings, top_severity}
 * API root: env GITHUB_API_URL (validated by githubApiBase; an invalid value fails the dispatch
 * instead of sending the token to another host).
 * Failures are audited and returned, never thrown.
 */
import { audit } from "../common/audit.js";
import type { GitHubApi } from "../publish/github.js";
import { githubApiBase } from "./api-base.js";
import { cleanReason } from "./classify.js";
import { safeUrl, type TemplateVars } from "./template.js";

export const DISPATCH_TOKEN_ENV = "XREPO_DISPATCH_TOKEN";
const MAX_KEYS = 10;
const MAX_PAYLOAD_BYTES = 60 * 1024;
const REPO_RE = /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/;
const EVENT_TYPE_RE = /^[A-Za-z0-9._:-]{1,100}$/;
const TIMEOUT_MS = 10_000;

export interface DispatchConfig {
  /** owner/name; default = the PR repository. */
  repo?: string;
  event_type: string;
}

export interface DispatchResult {
  repo: string;
  event_type: string;
  ok: boolean;
  /** Which credential was used. */
  via?: "dispatch_token" | "api" | "github_token";
  status?: number;
  error?: string;
}

export interface DispatchOptions {
  /** owner/name of the PR repository. */
  prRepo: string;
  client_payload: Record<string, unknown>;
  /** Publisher client (GITHUB_TOKEN), used for same-repo dispatches when XREPO_DISPATCH_TOKEN is unset. */
  api?: Pick<GitHubApi, "repositoryDispatch">;
  env?: Record<string, string | undefined>;
  fetchImpl?: typeof fetch;
}

/** A 403 / 404 from the GITHUB_TOKEN fallback: the token lacks contents: write (review.yml grants read). */
function fallbackHint(status: number | undefined): string {
  return status === 403 || status === 404
    ? ` (GITHUB_TOKEN cannot dispatch here: repository_dispatch needs contents: write; set ${DISPATCH_TOKEN_ENV})`
    : "";
}

function isRepo(s: string): boolean {
  return REPO_RE.test(s) && !s.split("/").some((seg) => seg === "." || seg === "..");
}

function num(v: unknown): number | null {
  if (typeof v === "number" && Number.isFinite(v)) return v;
  if (typeof v === "string" && /^\d{1,15}$/.test(v.trim())) return Number(v.trim());
  return null;
}

function str(v: unknown, max: number): string | null {
  if (v === undefined || v === null) return null;
  const s = cleanReason(String(v), max);
  return s === "" ? null : s;
}

/** Outcome payload for repository_dispatch (exactly 10 top-level keys). */
export function buildDispatchPayload(vars: TemplateVars, extra: { head_sha?: string } = {}): Record<string, unknown> {
  const prUrl = typeof vars.pr_url === "string" ? safeUrl(vars.pr_url) : "";
  const runUrl = typeof vars.run_url === "string" ? safeUrl(vars.run_url) : "";
  const head = typeof extra.head_sha === "string" && /^[0-9a-f]{7,64}$/i.test(extra.head_sha) ? extra.head_sha : null;
  return {
    outcome: str(vars.outcome, 40),
    repo: str(vars.repo, 200),
    pr_number: num(vars.pr_number),
    pr_url: prUrl || null,
    head_sha: head,
    run_url: runUrl || null,
    attempt: num(vars.attempt),
    reason: str(vars.reason, 300),
    reset_at: str(vars.reset_at, 80),
    review: {
      verdict: str(vars.verdict, 40),
      findings: num(vars.findings) ?? 0,
      top_severity: str(vars.top_severity, 20),
    },
  };
}

async function postDispatch(
  base: string,
  token: string,
  repo: string,
  event_type: string,
  client_payload: Record<string, unknown>,
  fetchImpl: typeof fetch,
): Promise<{ ok: boolean; status?: number; error?: string }> {
  const [owner = "", name = ""] = repo.split("/");
  let res: Response;
  try {
    res = await fetchImpl(`${base}/repos/${encodeURIComponent(owner)}/${encodeURIComponent(name)}/dispatches`, {
      method: "POST",
      headers: {
        authorization: `Bearer ${token}`,
        accept: "application/vnd.github+json",
        "x-github-api-version": "2022-11-28",
        "content-type": "application/json",
        "user-agent": "xrepo-review",
      },
      body: JSON.stringify({ event_type, client_payload }),
      redirect: "manual",
      signal: AbortSignal.timeout(TIMEOUT_MS),
    });
  } catch (e) {
    const n = (e as { name?: unknown })?.name;
    return { ok: false, error: n === "TimeoutError" || n === "AbortError" ? `timeout after ${TIMEOUT_MS}ms` : `request failed (${String(n ?? "Error")})` };
  }
  let detail = "";
  if (res.status < 200 || res.status >= 300) {
    try {
      const body = (await res.text()).slice(0, 2000);
      const msg = (JSON.parse(body) as { message?: unknown }).message;
      if (typeof msg === "string") detail = `: ${cleanReason(msg, 200)}`;
    } catch {
      /* ignore */
    }
  } else {
    try {
      await res.body?.cancel();
    } catch {
      /* ignore */
    }
  }
  if (res.status >= 200 && res.status < 300) return { ok: true, status: res.status };
  return { ok: false, status: res.status, error: `HTTP ${res.status}${detail}` };
}

/** Send one repository_dispatch. Never throws; the result is audited. */
export async function repositoryDispatch(cfg: DispatchConfig, opts: DispatchOptions): Promise<DispatchResult> {
  const env = opts.env ?? process.env;
  const target = (cfg.repo ?? opts.prRepo ?? "").trim();
  const event_type = cfg.event_type;
  const done = (r: DispatchResult): DispatchResult => {
    if (r.ok) audit("dispatch.sent", { repo: r.repo, event_type: r.event_type, via: r.via, status: r.status });
    else audit("dispatch.failed", { repo: r.repo, event_type: r.event_type, via: r.via, status: r.status, error: r.error });
    return r;
  };
  const base: DispatchResult = { repo: target, event_type, ok: false };
  try {
    if (!isRepo(target)) return done({ ...base, error: "invalid target repository" });
    if (typeof event_type !== "string" || !EVENT_TYPE_RE.test(event_type)) return done({ ...base, error: "invalid event_type" });
    const payload = opts.client_payload ?? {};
    if (Object.keys(payload).length > MAX_KEYS) return done({ ...base, error: `client_payload has more than ${MAX_KEYS} top-level keys` });
    if (Buffer.byteLength(JSON.stringify(payload), "utf8") > MAX_PAYLOAD_BYTES) return done({ ...base, error: "client_payload too large" });

    const fetchImpl = opts.fetchImpl ?? fetch;
    const dispatchToken = env[DISPATCH_TOKEN_ENV]?.trim();
    // Fail closed on an invalid GITHUB_API_URL: never substitute another host for the token.
    let apiRoot: string;
    try {
      apiRoot = githubApiBase(env);
    } catch (e) {
      return done({ ...base, error: (e as Error).message });
    }
    if (dispatchToken) {
      const r = await postDispatch(apiRoot, dispatchToken, target, event_type, payload, fetchImpl);
      return done({ ...base, ...r, via: "dispatch_token" });
    }
    const sameRepo = target.toLowerCase() === String(opts.prRepo ?? "").trim().toLowerCase();
    if (!sameRepo) {
      return done({ ...base, error: `${DISPATCH_TOKEN_ENV} is required to dispatch to another repository` });
    }
    if (opts.api) {
      try {
        await opts.api.repositoryDispatch(target, event_type, payload);
        return done({ ...base, ok: true, via: "api" });
      } catch (e) {
        const status = (e as { status?: unknown })?.status;
        return done({
          ...base,
          via: "api",
          ...(typeof status === "number" ? { status } : {}),
          error: (cleanReason((e as Error)?.message ?? String(e), 200) || "request failed") + fallbackHint(typeof status === "number" ? status : undefined),
        });
      }
    }
    const ghToken = env.GITHUB_TOKEN?.trim();
    if (ghToken) {
      const r = await postDispatch(apiRoot, ghToken, target, event_type, payload, fetchImpl);
      return done({ ...base, ...r, ...(r.ok ? {} : { error: `${r.error ?? "request failed"}${fallbackHint(r.status)}` }), via: "github_token" });
    }
    return done({ ...base, error: `no token: set ${DISPATCH_TOKEN_ENV} or GITHUB_TOKEN` });
  } catch (e) {
    return done({ ...base, error: cleanReason((e as Error)?.message ?? String(e), 200) || "dispatch failed" });
  }
}

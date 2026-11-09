/**
 * Outcome notifications: Slack incoming webhooks and generic JSON webhooks.
 *
 * - URLs (and HMAC keys) live in a secrets bundle, never in the manifest: env XREPO_NOTIFY_SECRETS
 *   (JSON object of key -> string), else the file /etc/xrepo-review/notify.json (path overridable).
 * - Only https URLs; no redirects (redirect: "manual", any 3xx is a failure); per-target timeout.
 * - Slack: POST {"text": message}; placeholder values escaped with escapeSlack.
 * - Webhook: POST {event:"xrepo-review", outcome, repo, pr_number, pr_url, verdict, reason, reset_at,
 *   findings, top_severity, run_url, attempt, message}. With `hmac_secret`:
 *     X-Xrepo-Timestamp: <unix seconds>
 *     X-Xrepo-Signature: sha256=<hex HMAC-SHA256(secret, "<timestamp>.<raw body>")>
 *   Receivers should recompute the HMAC over the timestamp, a ".", and the exact body bytes, compare
 *   in constant time and reject stale timestamps (replay protection).
 * - Failures are audited (target name, type, status / error class; never the URL or a secret) and
 *   never thrown: notifications can not fail the publish.
 */
import { createHmac } from "node:crypto";
import { closeSync, fstatSync, openSync, readFileSync } from "node:fs";
import { audit } from "../common/audit.js";
import type { NotificationTarget, OutcomeActions } from "../policy/schema.js";
import { cleanReason } from "./classify.js";
import { DEFAULT_NOTIFY_TEMPLATE, plainEscaper, renderTemplate, safeUrl, slackEscaper, type TemplateVars } from "./template.js";

export const NOTIFY_SECRETS_ENV = "XREPO_NOTIFY_SECRETS";
export const DEFAULT_NOTIFY_SECRETS_FILE = "/etc/xrepo-review/notify.json";
const MAX_SECRETS_BYTES = 1024 * 1024;
const MAX_MESSAGE_CHARS = 3000;

export type NotifyRef = OutcomeActions["notify"][number];
export type NotifySecrets = Record<string, string>;

export interface NotifyResult {
  target: string;
  type?: "slack" | "webhook";
  ok: boolean;
  /** HTTP status when a response was received. */
  status?: number;
  /** Why it failed / was not sent (never contains the URL). */
  error?: string;
}

/* -------------------------------- secrets -------------------------------- */

function toSecrets(v: unknown): NotifySecrets | undefined {
  if (v === null || typeof v !== "object" || Array.isArray(v)) return undefined;
  const out: NotifySecrets = Object.create(null) as NotifySecrets;
  for (const [k, x] of Object.entries(v as Record<string, unknown>)) if (typeof x === "string") out[k] = x;
  return out;
}

export interface LoadSecretsOptions {
  env?: Record<string, string | undefined>;
  /** Secrets file (default /etc/xrepo-review/notify.json). */
  file?: string;
}

/**
 * Load the secrets bundle: env XREPO_NOTIFY_SECRETS (JSON object), else the secrets file. Problems
 * are audited (never with values); the result is {} when nothing usable is found.
 */
export function loadNotifySecrets(opts: LoadSecretsOptions = {}): NotifySecrets {
  const env = opts.env ?? process.env;
  const fromEnv = env[NOTIFY_SECRETS_ENV];
  if (typeof fromEnv === "string" && fromEnv.trim() !== "") {
    try {
      const s = toSecrets(JSON.parse(fromEnv));
      if (s) return s;
      audit("notify.secrets_invalid", { source: "env", error: "not a JSON object" });
    } catch {
      audit("notify.secrets_invalid", { source: "env", error: "invalid JSON" });
    }
  }
  const file = opts.file ?? DEFAULT_NOTIFY_SECRETS_FILE;
  let fd: number | undefined;
  try {
    fd = openSync(file, "r");
    const st = fstatSync(fd);
    if (!st.isFile()) throw Object.assign(new Error("not a regular file"), { code: "EINVAL" });
    if (st.size > MAX_SECRETS_BYTES) throw Object.assign(new Error("file too large"), { code: "EFBIG" });
    const text = readFileSync(fd, "utf8");
    const s = toSecrets(JSON.parse(text));
    if (s) return s;
    audit("notify.secrets_invalid", { source: "file", file, error: "not a JSON object" });
  } catch (e) {
    const code = (e as { code?: unknown }).code;
    audit("notify.secrets_unavailable", {
      source: "file",
      file,
      error: e instanceof SyntaxError ? "invalid JSON" : typeof code === "string" ? code : "unreadable",
    });
  } finally {
    if (fd !== undefined) {
      try {
        closeSync(fd);
      } catch {
        /* ignore */
      }
    }
  }
  return Object.create(null) as NotifySecrets;
}

/* -------------------------------- payloads -------------------------------- */

function num(v: unknown): number | null {
  if (typeof v === "number" && Number.isFinite(v)) return v;
  if (typeof v === "string" && /^\d{1,15}$/.test(v.trim())) return Number(v.trim());
  return null;
}

function text(v: unknown, max = 500): string | null {
  if (v === undefined || v === null) return null;
  const s = cleanReason(String(v), max);
  return s === "" ? null : s;
}

function url(v: unknown): string | null {
  const s = typeof v === "string" ? safeUrl(v) : "";
  return s === "" ? null : s;
}

/** Generic webhook JSON body. */
export function buildWebhookPayload(vars: TemplateVars, message: string): Record<string, unknown> {
  return {
    event: "xrepo-review",
    outcome: text(vars.outcome, 40),
    repo: text(vars.repo, 200),
    pr_number: num(vars.pr_number),
    pr_url: url(vars.pr_url),
    verdict: text(vars.verdict, 40),
    reason: text(vars.reason, 300),
    reset_at: text(vars.reset_at, 80),
    findings: num(vars.findings) ?? 0,
    top_severity: text(vars.top_severity, 20),
    run_url: url(vars.run_url),
    attempt: num(vars.attempt),
    message,
  };
}

/** X-Xrepo-Signature value for `body` signed at `timestamp`. */
export function signWebhook(secret: string, timestamp: string, body: string): string {
  return `sha256=${createHmac("sha256", secret).update(`${timestamp}.${body}`, "utf8").digest("hex")}`;
}

function describeError(e: unknown, timeoutMs: number): string {
  const name = (e as { name?: unknown } | null)?.name;
  if (name === "TimeoutError" || name === "AbortError") return `timeout after ${timeoutMs}ms`;
  const cause = (e as { cause?: { code?: unknown } } | null)?.cause;
  const code = typeof cause?.code === "string" ? cause.code : typeof (e as { code?: unknown })?.code === "string" ? (e as { code: string }).code : "";
  const base = typeof name === "string" && name !== "" ? name : "Error";
  return code ? `${base} (${code})` : base;
}

/* --------------------------------- send ---------------------------------- */

async function sendOne(
  ref: NotifyRef,
  targets: Record<string, NotificationTarget>,
  vars: TemplateVars,
  secrets: NotifySecrets,
  fetchImpl: typeof fetch,
  nowSeconds: () => number,
): Promise<NotifyResult> {
  const name = ref.target;
  const target = Object.prototype.hasOwnProperty.call(targets, name) ? targets[name] : undefined;
  if (!target) return { target: name, ok: false, error: "unknown notification target" };
  const fail = (error: string, status?: number): NotifyResult => ({
    target: name,
    type: target.type,
    ok: false,
    ...(status !== undefined ? { status } : {}),
    error,
  });

  const rawUrl = Object.prototype.hasOwnProperty.call(secrets, target.url_secret) ? secrets[target.url_secret] : undefined;
  if (typeof rawUrl !== "string" || rawUrl.trim() === "") return fail(`secret "${target.url_secret}" not found`);
  let parsed: URL;
  try {
    parsed = new URL(rawUrl.trim());
  } catch {
    return fail(`secret "${target.url_secret}" is not a valid URL`);
  }
  if (parsed.protocol !== "https:") return fail("only https URLs are allowed");

  const tpl = ref.message ?? target.template ?? DEFAULT_NOTIFY_TEMPLATE;
  let body: string;
  const headers: Record<string, string> = { "content-type": "application/json", "user-agent": "xrepo-review" };
  if (target.type === "slack") {
    const message = renderTemplate(tpl, vars, slackEscaper()).slice(0, MAX_MESSAGE_CHARS * 2);
    body = JSON.stringify({ text: message });
  } else {
    const message = renderTemplate(tpl, vars, plainEscaper()).slice(0, MAX_MESSAGE_CHARS);
    body = JSON.stringify(buildWebhookPayload(vars, message));
    if (target.hmac_secret !== undefined) {
      const key = Object.prototype.hasOwnProperty.call(secrets, target.hmac_secret) ? secrets[target.hmac_secret] : undefined;
      if (typeof key !== "string" || key === "") return fail(`hmac secret "${target.hmac_secret}" not found`);
      const ts = String(Math.floor(nowSeconds()));
      headers["x-xrepo-timestamp"] = ts;
      headers["x-xrepo-signature"] = signWebhook(key, ts, body);
    }
  }

  let res: Response;
  try {
    res = await fetchImpl(parsed.href, {
      method: "POST",
      headers,
      body,
      redirect: "manual",
      signal: AbortSignal.timeout(target.timeout_ms),
    });
  } catch (e) {
    return fail(describeError(e, target.timeout_ms));
  }
  try {
    await res.body?.cancel();
  } catch {
    /* ignore */
  }
  if (res.type === "opaqueredirect" || (res.status >= 300 && res.status < 400)) return fail("redirect refused", res.status || undefined);
  if (res.status < 200 || res.status >= 300) return fail(`HTTP ${res.status}`, res.status);
  return { target: name, type: target.type, ok: true, status: res.status };
}

/**
 * Send one notification per ref (in parallel). Never throws; every result is audited.
 * `vars` are the template placeholders ({outcome}, {repo}, ...).
 */
export async function sendNotifications(
  refs: NotifyRef[],
  targets: Record<string, NotificationTarget>,
  vars: TemplateVars,
  secrets: NotifySecrets,
  fetchImpl: typeof fetch = fetch,
  opts: { nowSeconds?: () => number } = {},
): Promise<NotifyResult[]> {
  const nowSeconds = opts.nowSeconds ?? (() => Date.now() / 1000);
  const list = Array.isArray(refs) ? refs : [];
  const results = await Promise.all(
    list.map(async (ref): Promise<NotifyResult> => {
      try {
        return await sendOne(ref, targets ?? {}, vars, secrets ?? {}, fetchImpl, nowSeconds);
      } catch (e) {
        return { target: String(ref?.target ?? ""), ok: false, error: describeError(e, 0) };
      }
    }),
  );
  for (const r of results) {
    if (r.ok) audit("notify.sent", { target: r.target, type: r.type, status: r.status, outcome: vars.outcome });
    else audit("notify.failed", { target: r.target, type: r.type, status: r.status, error: r.error, outcome: vars.outcome });
  }
  return results;
}

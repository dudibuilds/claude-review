/**
 * Outcome classification (SPEC "Outcomes"): decides what a review run ended in, from the prepare
 * skip decision, the claude-code-action step outcome, the action's execution file and the draft.
 *
 * Order: skipped -> usage_limit -> completed -> incomplete -> error.
 *
 * Execution file (claude-code-action@v1 `execution_file`): a pretty-printed JSON array of raw SDK
 * messages whose last element is the `result` message. JSON lines, truncated files (we read only the
 * tail of huge files), garbage and absence are all tolerated.
 *
 * Usage-limit detection only looks at evidence of the FINAL failure, never at ordinary assistant
 * text or tool results (a PR about rate limiting must not look like a usage limit):
 * - the `result` message when the run failed (is_error / error subtype): api_error_status 429/529,
 *   or its result / errors text matching the usage-limit patterns;
 * - messages after the last real progress (last non-synthetic assistant message or user message):
 *   synthetic API-error assistant messages (`error: "rate_limit"`, `api_error:
 *   "usage_limit_reached"`, model "<synthetic>"), `rate_limit_event` with status "rejected",
 *   `system/api_retry` with error rate_limit / overloaded or status 429 / 529.
 * Retries the CLI recovered from are therefore ignored, and a successful run is never usage_limit.
 */
import { closeSync, fstatSync, openSync, readSync } from "node:fs";
import type { Draft } from "../common/draft.js";
import { redactSecrets } from "../common/redact.js";
import { singleLine } from "../publish/sanitize.js";
import { resolveResetTime } from "./reset.js";

export type PrimaryOutcome = "completed" | "incomplete" | "usage_limit" | "error" | "skipped";

export interface ClassifyInput {
  /** prepare decided not to review. */
  skipped?: { reason: string };
  /** `steps.<claude>.outcome`: success | failure | cancelled | skipped (anything else tolerated). */
  agentStepOutcome?: "success" | "failure" | "cancelled" | "skipped" | string;
  /** Content of the action's execution file (absent when the step did not produce one). */
  executionFileText?: string;
  /** Parsed draft (absent when the draft file does not exist). */
  draft?: Draft;
}

export interface Classification {
  outcome: PrimaryOutcome;
  /** Short human-readable reason (single line, secrets redacted, <= 300 chars). */
  reason: string;
  /** Usage-limit reset: ISO-8601 when an epoch was found, else the raw "resets ..." text (<= 80 chars). */
  reset_at?: string;
}

/** Bytes of the execution file that are read (the tail; the result message is the last element). */
export const MAX_EXECUTION_FILE_BYTES = 20 * 1024 * 1024;
const MAX_REASON_CHARS = 300;
const MAX_RESET_CHARS = 80;
/** How far back from the end the trailing-window scan goes at most. */
const MAX_TRAILING_MESSAGES = 200;

/* ------------------------------- patterns -------------------------------- */

/**
 * Usage-limit / rate-limit / quota / overload messages. Real CLI strings (claude 1.0.x - 2.1.319):
 * "You've hit your 5-hour limit · resets 1:32pm (UTC)", "You've hit your weekly limit · resets Nov 12,
 * 11:33am (UTC)", "You've hit your session limit · resets 3pm", "You’ve hit your limit for Claude
 * messages. Limits will reset at 9:30 AM.", "Session limit reached ∙ resets 3pm", "Claude AI usage
 * limit reached|1753441200", "You're out of usage credits", "Credit balance is too low",
 * "API Error: Request rejected (429) · ...", "API Error: 529 Overloaded".
 */
export const USAGE_LIMIT_PATTERNS: readonly RegExp[] = [
  /\byou(?:'|\u2019|&#39;)?ve (?:hit|reached) your\b/i,
  /\byou(?:'|\u2019)?re out of (?:usage|extra usage)/i,
  /\byour org(?:anization)? is out of usage/i,
  /\byour seat type doesn(?:'|\u2019)?t include\b/i,
  /\byour usage allocation has been disabled/i,
  /\byour group(?:'|\u2019)?s usage limit\b/i,
  /\brequires usage credits\b/i,
  /\busage[ _-]limit/i,
  /\blimit reached\b/i,
  /\b(?:session|weekly|daily|monthly|opus|sonnet|fable|5-hour) limit\b/i,
  /\brate[ _-]?limit/i,
  /\btoo many requests\b/i,
  /\b429\b/,
  /\b529\b/,
  /\bquota\b/i,
  /\boverloaded\b/i,
  /\bcredit balance is too low\b/i,
];

export function matchesUsageLimit(text: string): boolean {
  if (typeof text !== "string" || text === "") return false;
  const t = text.length > 20000 ? text.slice(0, 20000) : text;
  return USAGE_LIMIT_PATTERNS.some((re) => re.test(t));
}

function epochToIso(n: number): string | undefined {
  if (!Number.isFinite(n) || n <= 0) return undefined;
  const ms = n < 1e11 ? n * 1000 : n; // seconds or milliseconds
  const d = new Date(ms);
  const y = d.getUTCFullYear();
  if (Number.isNaN(d.getTime()) || y < 2000 || y > 2200) return undefined;
  return d.toISOString().replace(/\.000Z$/, "Z");
}

/**
 * Reset time from a usage-limit message: "...limit reached|<epoch>" -> ISO-8601; "resets <text>" /
 * "reset at <text>" -> the raw text (trimmed, sentence end removed, <= 80 chars).
 */
export function parseResetAt(text: string): string | undefined {
  if (typeof text !== "string" || text === "") return undefined;
  const epoch = /limit reached\s*\|\s*(\d{9,13})(?!\d)/i.exec(text);
  if (epoch?.[1]) {
    const iso = epochToIso(Number(epoch[1]));
    if (iso) return iso;
  }
  const m = /\bresets?\s+(?:at\s+|on\s+|in\s+)?([^\n\r\u00B7\u2219|"<>]{1,200})/i.exec(text);
  if (m?.[1]) {
    let s = (m[1].split(/[.!?;](?:\s|$)/)[0] ?? "").replace(/\s+/g, " ").trim();
    s = s.replace(/[\s,.;:]+$/, "");
    // "(resets 3pm)" -> "3pm", but "1:32pm (UTC)" keeps its parenthesis.
    while (s.endsWith(")") && (s.match(/\)/g)?.length ?? 0) > (s.match(/\(/g)?.length ?? 0)) s = s.slice(0, -1).replace(/[\s,.;:]+$/, "");
    if (s.length > MAX_RESET_CHARS) s = `${s.slice(0, MAX_RESET_CHARS - 1).trimEnd()}\u2026`;
    if (s !== "") return s;
  }
  return undefined;
}

/* ---------------------------- execution file ----------------------------- */

type Msg = Record<string, unknown>;

const TOP_LEVEL_TYPES = new Set(["result", "assistant", "user", "system", "rate_limit_event"]);

function isMsg(v: unknown): v is Msg {
  return v !== null && typeof v === "object" && !Array.isArray(v) && typeof (v as Msg).type === "string" && TOP_LEVEL_TYPES.has((v as Msg).type as string);
}

/**
 * Read the execution file: the last `maxBytes` bytes (the result message is at the end). When the
 * file is larger, the partial first line is dropped so parsing starts outside any JSON string
 * (JSON strings never contain raw newlines). Returns undefined when the file cannot be read.
 */
export function readExecutionFile(path: string, maxBytes = MAX_EXECUTION_FILE_BYTES): string | undefined {
  let fd: number | undefined;
  try {
    fd = openSync(path, "r");
    const st = fstatSync(fd);
    if (!st.isFile()) return undefined;
    const size = st.size;
    const len = Math.max(0, Math.min(size, maxBytes));
    const buf = Buffer.alloc(len);
    let off = 0;
    while (off < len) {
      const n = readSync(fd, buf, off, len - off, size - len + off);
      if (n <= 0) break;
      off += n;
    }
    let text = buf.subarray(0, off).toString("utf8");
    if (size > len) {
      const nl = text.indexOf("\n");
      text = nl >= 0 ? text.slice(nl + 1) : "";
    }
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

/** Linear, string-aware scan for balanced top-level `{...}` objects (pretty-printed / truncated arrays). */
function scanObjects(text: string): Msg[] {
  const out: Msg[] = [];
  let depth = 0;
  let start = -1;
  let inString = false;
  let escaped = false;
  for (let i = 0; i < text.length; i++) {
    const ch = text.charCodeAt(i);
    if (depth === 0) {
      if (ch === 0x7b /* { */) {
        depth = 1;
        start = i;
        inString = false;
        escaped = false;
      }
      continue;
    }
    if (inString) {
      if (escaped) escaped = false;
      else if (ch === 0x5c /* \ */) escaped = true;
      else if (ch === 0x22 /* " */) inString = false;
      else if (ch === 0x0a /* \n */) {
        // Raw newline inside a JSON string is impossible: we are out of sync. Start over.
        depth = 0;
        inString = false;
        start = -1;
      }
      continue;
    }
    if (ch === 0x22) inString = true;
    else if (ch === 0x7b || ch === 0x5b) depth++;
    else if (ch === 0x7d || ch === 0x5d) {
      depth--;
      if (depth === 0 && start >= 0) {
        try {
          const v: unknown = JSON.parse(text.slice(start, i + 1));
          if (isMsg(v)) out.push(v);
        } catch {
          /* not an object after all */
        }
        start = -1;
      }
    }
  }
  return out;
}

/** Last-resort extraction of the result message's key fields with regexes (badly damaged files). */
function regexResult(text: string): Msg | undefined {
  const tail = text.length > 262144 ? text.slice(-262144) : text;
  const re = /"type"\s*:\s*"result"/g;
  let last = -1;
  for (let m = re.exec(tail); m; m = re.exec(tail)) last = m.index;
  if (last < 0) return undefined;
  const seg = tail.slice(last, last + 65536);
  const msg: Msg = { type: "result" };
  const sub = /"subtype"\s*:\s*"([a-z_]{1,60})"/.exec(seg);
  if (sub?.[1]) msg.subtype = sub[1];
  const isErr = /"is_error"\s*:\s*(true|false)/.exec(seg);
  if (isErr?.[1]) msg.is_error = isErr[1] === "true";
  const st = /"api_error_status"\s*:\s*(\d{3})/.exec(seg);
  if (st?.[1]) msg.api_error_status = Number(st[1]);
  const res = /"result"\s*:\s*("(?:[^"\\\n]|\\.){0,20000}")/.exec(seg);
  if (res?.[1]) {
    try {
      msg.result = JSON.parse(res[1]);
    } catch {
      /* ignore */
    }
  }
  const errs = /"errors"\s*:\s*\[\s*((?:"(?:[^"\\\n]|\\.){0,2000}"\s*(?:,\s*)?){0,20})\]/.exec(seg);
  if (errs?.[1] !== undefined) {
    try {
      const arr: unknown = JSON.parse(`[${errs[1].replace(/,\s*$/, "")}]`);
      if (Array.isArray(arr)) msg.errors = arr.filter((e) => typeof e === "string");
    } catch {
      /* ignore */
    }
  }
  return msg;
}

/**
 * Parse execution-file text into SDK messages (objects with a top-level type of result, assistant,
 * user, system or rate_limit_event). Accepts a JSON array, a single object, JSON lines, a truncated
 * array or garbage (-> whatever can be recovered, possibly []).
 */
export function parseExecutionMessages(text: string | undefined): Msg[] {
  if (typeof text !== "string") return [];
  let t = text;
  if (t.length > MAX_EXECUTION_FILE_BYTES) {
    t = t.slice(-MAX_EXECUTION_FILE_BYTES);
    const nl = t.indexOf("\n");
    t = nl >= 0 ? t.slice(nl + 1) : "";
  }
  t = t.trim();
  if (t === "") return [];
  if (t[0] === "[" || t[0] === "{") {
    try {
      const v: unknown = JSON.parse(t);
      const arr = Array.isArray(v) ? v : [v];
      const msgs = arr.filter(isMsg);
      if (msgs.length > 0 || Array.isArray(v)) return msgs;
    } catch {
      /* fall through */
    }
  }
  // JSON lines.
  const lines: Msg[] = [];
  for (const raw of t.split("\n")) {
    const line = raw.trim().replace(/,$/, "");
    if (line.length < 2 || line[0] !== "{") continue;
    try {
      const v: unknown = JSON.parse(line);
      if (isMsg(v)) lines.push(v);
    } catch {
      /* not a JSON line */
    }
  }
  if (lines.length > 0) return lines;
  const scanned = scanObjects(t);
  if (!scanned.some((m) => m.type === "result")) {
    const r = regexResult(t);
    if (r) scanned.push(r);
  }
  return scanned;
}

/* ------------------------------- helpers --------------------------------- */

function str(v: unknown): string | undefined {
  return typeof v === "string" ? v : undefined;
}

function obj(v: unknown): Msg | undefined {
  return v !== null && typeof v === "object" && !Array.isArray(v) ? (v as Msg) : undefined;
}

/** Single line, secrets redacted, controls removed, length capped. */
export function cleanReason(s: string, max = MAX_REASON_CHARS): string {
  // singleLine: controls / bidi / line separators -> spaces, and a cut never splits a surrogate
  // pair (reasons end up in check titles, step outputs and dispatch payloads).
  return singleLine(redactSecrets(String(s ?? "")).text, max);
}

function assistantText(m: Msg): string {
  const message = obj(m.message);
  const content = message?.content;
  if (typeof content === "string") return content;
  if (!Array.isArray(content)) return "";
  return content
    .map((b) => (obj(b)?.type === "text" ? (str(obj(b)?.text) ?? "") : ""))
    .filter((s) => s !== "")
    .join("\n");
}

function isSyntheticAssistant(m: Msg): boolean {
  if (m.type !== "assistant") return false;
  if (m.error !== undefined && m.error !== null) return true;
  if (m.isApiErrorMessage === true || m.api_error !== undefined) return true;
  return obj(m.message)?.model === "<synthetic>";
}

function resultText(r: Msg): string {
  const parts: string[] = [];
  const res = str(r.result);
  if (res) parts.push(res);
  if (Array.isArray(r.errors)) for (const e of r.errors) if (typeof e === "string") parts.push(e);
  return parts.join("\n");
}

function resetFromInfo(info: unknown): string | undefined {
  const i = obj(info);
  const v = i?.resetsAt ?? i?.resets_at;
  if (typeof v === "number") return epochToIso(v);
  if (typeof v === "string" && /^\d{9,13}$/.test(v)) return epochToIso(Number(v));
  return undefined;
}

interface Evidence {
  text?: string;
  reset?: string;
}

const RATE_ERRORS = new Set(["rate_limit", "overloaded", "billing_error", "usage_limit_reached", "overloaded_error", "rate_limit_error"]);

/** Usage-limit evidence of the final failure (see module doc), or undefined. */
function usageLimitEvidence(msgs: Msg[], result: Msg | undefined): Evidence | undefined {
  const found: Evidence[] = [];
  if (result) {
    const text = resultText(result);
    const status = result.api_error_status;
    if (status === 429 || status === 529 || matchesUsageLimit(text)) found.push({ text: text || `API error ${String(status)}` });
  }
  // Trailing window: messages after the last real progress, newest first.
  let seen = 0;
  for (let i = msgs.length - 1; i >= 0 && seen < MAX_TRAILING_MESSAGES; i--, seen++) {
    const m = msgs[i] as Msg;
    if (m === result || m.type === "result") continue;
    if (m.type === "user") break;
    if (m.type === "assistant") {
      if (!isSyntheticAssistant(m)) break;
      const text = assistantText(m);
      const err = str(m.error) ?? "";
      const apiErr = str(m.api_error) ?? "";
      const reset = resetFromInfo(obj(obj(m.api_error_params)?.rate_limit_info));
      if (RATE_ERRORS.has(err) || RATE_ERRORS.has(apiErr) || matchesUsageLimit(text)) {
        found.push({ ...(text ? { text } : apiErr || err ? { text: apiErr || err } : {}), ...(reset ? { reset } : {}) });
      }
      continue;
    }
    if (m.type === "rate_limit_event") {
      const info = obj(m.rate_limit_info);
      if (info?.status === "rejected") {
        const reset = resetFromInfo(info);
        const kind = str(info.rateLimitType);
        found.push({ text: kind ? `rate limit rejected (${kind})` : "rate limit rejected", ...(reset ? { reset } : {}) });
      }
      continue;
    }
    if (m.type === "system") {
      const subtype = str(m.subtype) ?? "";
      if (subtype === "api_retry") {
        const err = str(m.error) ?? "";
        const st = m.error_status;
        if (RATE_ERRORS.has(err) || st === 429 || st === 529) found.push({ text: `API ${err || "error"}${typeof st === "number" ? ` (${st})` : ""}` });
      } else if (/error|limit/i.test(subtype)) {
        const text = [m.error, m.message, m.content, m.text].map(str).filter((s): s is string => !!s).join("\n");
        if (matchesUsageLimit(text)) found.push({ text });
      }
    }
  }
  if (found.length === 0) return undefined;
  // Prefer a human-readable message (the result text or the synthetic assistant text).
  const withText = found.find((e) => e.text && matchesUsageLimit(e.text) && /[a-z]{3}/i.test(e.text)) ?? found[0];
  const textReset = found.map((e) => (e.text ? parseResetAt(e.text) : undefined)).find((r) => r !== undefined);
  const structuredReset = found.map((e) => e.reset).find((r) => r !== undefined);
  // The CLI's text reads better in comments, but a text the retry timing cannot resolve (see
  // reset.ts) must not hide a structured (epoch) reset time. Resolvability does not depend on the
  // clock: every supported form resolves for any "now".
  const reset =
    textReset !== undefined && (structuredReset === undefined || resolveResetTime(textReset, new Date()) !== undefined) ? textReset : structuredReset;
  return { ...(withText?.text ? { text: withText.text } : {}), ...(reset ? { reset } : {}) };
}

export function draftHasEntries(draft: Draft | undefined): boolean {
  if (!draft) return false;
  return draft.comments.length > 0 || Boolean(draft.summary?.trim()) || draft.verdict !== undefined || draft.labels.length > 0 || draft.finished;
}

const SUBTYPE_REASON: Record<string, string> = {
  error_max_turns: "maximum number of turns reached",
  error_during_execution: "the agent failed during execution",
  error_max_budget_usd: "maximum budget reached",
  error_max_structured_output_retries: "structured output retries exhausted",
};

function stepReason(step: string): string | undefined {
  switch (step) {
    case "failure":
      return "the Claude Code step failed";
    case "cancelled":
      return "the run was cancelled";
    case "skipped":
      return "the Claude Code step was skipped";
    default:
      return undefined;
  }
}

/** Reason derived from the result message, if it reports a failure. */
function resultFailureReason(result: Msg | undefined): string | undefined {
  if (!result) return undefined;
  const subtype = str(result.subtype) ?? "";
  if (subtype !== "" && subtype !== "success") {
    const base = SUBTYPE_REASON[subtype] ?? `agent error (${subtype})`;
    const first = Array.isArray(result.errors) ? result.errors.find((e): e is string => typeof e === "string" && e.trim() !== "") : undefined;
    return first && subtype !== "error_max_turns" ? `${base}: ${first}` : base;
  }
  if (result.is_error === true) {
    const text = str(result.result)?.trim();
    return text ? `the agent reported an error: ${text}` : "the agent reported an error";
  }
  return undefined;
}

/* -------------------------------- classify -------------------------------- */

export function classifyOutcome(input: ClassifyInput): Classification {
  const skipReason = input.skipped ? cleanReason(input.skipped.reason ?? "") : undefined;
  if (input.skipped) return { outcome: "skipped", reason: skipReason || "skipped by policy" };

  const step = String(input.agentStepOutcome ?? "").trim().toLowerCase();
  const msgs = parseExecutionMessages(input.executionFileText);
  let result: Msg | undefined;
  for (let i = msgs.length - 1; i >= 0; i--) {
    if (msgs[i]?.type === "result") {
      result = msgs[i];
      break;
    }
  }
  const succeeded = result !== undefined && result.subtype === "success" && result.is_error !== true;

  if (!succeeded && msgs.length > 0) {
    const ev = usageLimitEvidence(msgs, result);
    if (ev) {
      const reason = cleanReason(ev.text ?? "") || "usage limit reached";
      return { outcome: "usage_limit", reason, ...(ev.reset ? { reset_at: ev.reset } : {}) };
    }
  }

  const draft = input.draft;
  if (draft?.finished) return { outcome: "completed", reason: "review finished" };

  const subtype = str(result?.subtype);
  if (draftHasEntries(draft) || subtype === "error_max_turns") {
    const reason =
      resultFailureReason(result) ??
      stepReason(step) ??
      (result ? "the agent ended without calling finish()" : "the agent stopped before calling finish()");
    return { outcome: "incomplete", reason: cleanReason(reason) };
  }

  const reason =
    resultFailureReason(result) ??
    stepReason(step) ??
    (result ? "no output from the agent (the review draft is empty)" : "no output from the agent");
  return { outcome: "error", reason: cleanReason(reason) };
}

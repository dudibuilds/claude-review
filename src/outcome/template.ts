/**
 * Outcome message templates (PR comments, Slack, webhooks).
 *
 * Templates are trusted (written by devops in the policy manifest); placeholder VALUES are not
 * (PR title, author, failure reasons) and are escaped per channel by the `escape` callback:
 * - markdown: single line, then sanitizeMarkdown rules (secrets redacted, images removed, links to
 *   non-allowlisted hosts defanged, HTML stripped, @mentions always neutralized), length capped.
 *   Values usually land mid-line, where GitHub never opens a fenced code block, while the sanitizer
 *   (which sees the value as a document of its own) would keep a leading ``` / ~~~ line verbatim as
 *   "code". Every run of 3+ backticks or tildes is therefore broken first (U+200B), so the whole
 *   value is always sanitized as prose, and the result is forced back onto one line;
 * - slack: single line, escapeSlack (`&` `<` `>` escaped, so `<!channel>` / `<@U..>` / `<url|x>` cannot
 *   be injected; @channel/@here/@everyone broken), length capped;
 * - plain (generic webhook): single line, secrets redacted, control characters removed, capped.
 * URL placeholders ({pr_url}, {run_url}) must be plain http(s) URLs without characters that could
 * break out of a markdown link destination; anything else renders as "".
 *
 * Rendering is a single pass: unknown placeholders stay literally, and values that contain `{x}` are
 * never expanded again.
 */
import { redactSecrets } from "../common/redact.js";
import { escapeSlack, sanitizeMarkdown, ZWSP } from "../publish/sanitize.js";

/** Placeholders documented on NotifyRef in src/policy/schema.ts, plus {reset_at_suffix}. */
export const TEMPLATE_PLACEHOLDERS = [
  "repo",
  "pr_number",
  "pr_url",
  "pr_title",
  "author",
  "outcome",
  "reason",
  "reset_at",
  "verdict",
  "findings",
  "top_severity",
  "run_url",
  "attempt",
  "reset_at_suffix",
] as const;
export type Placeholder = (typeof TEMPLATE_PLACEHOLDERS)[number];
export type TemplateVars = Partial<Record<Placeholder, string | number | null | undefined>>;
/** Escapes one placeholder value for the target channel (`key` tells which placeholder it is). */
export type Escaper = (value: string, key: Placeholder) => string;

const KNOWN = new Set<string>(TEMPLATE_PLACEHOLDERS);
const URL_KEYS = new Set<string>(["pr_url", "run_url"]);
const PLACEHOLDER_RE = /\{([a-z_]{1,40})\}/g;

/** Default message when neither the NotifyRef nor the target has a template. */
export const DEFAULT_NOTIFY_TEMPLATE = "xrepo-review {outcome} for {repo}#{pr_number}: {reason}{reset_at_suffix} {pr_url}";

function valueOf(v: string | number | null | undefined): string {
  if (v === undefined || v === null) return "";
  if (typeof v === "number") return Number.isFinite(v) ? String(v) : "";
  return String(v);
}

export function renderTemplate(tpl: string, vars: TemplateVars, escape: Escaper): string {
  if (typeof tpl !== "string" || tpl === "") return "";
  return tpl.replace(PLACEHOLDER_RE, (whole: string, key: string) => {
    if (!KNOWN.has(key)) return whole;
    const k = key as Placeholder;
    if (k === "reset_at_suffix" && (vars.reset_at_suffix === undefined || vars.reset_at_suffix === null)) {
      const reset = valueOf(vars.reset_at).trim();
      if (reset === "") return "";
      const escaped = escape(reset, "reset_at");
      return escaped === "" ? "" : ` (resets ${escaped})`;
    }
    const raw = valueOf(vars[k]);
    return raw === "" ? "" : escape(raw, k);
  });
}

/* -------------------------------- escapers -------------------------------- */

/** Collapse to one line: controls / bidi overrides / line breaks become spaces. */
export function oneLine(s: string, max: number): string {
  let t = String(s ?? "")
    .replace(/[\u0000-\u001F\u007F\u202A-\u202E\u2066-\u2069\u2028\u2029]+/g, " ")
    .replace(/\s+/g, " ")
    .trim();
  if (t.length > max) {
    t = t.slice(0, Math.max(1, max - 1));
    if (/[\uD800-\uDBFF]$/.test(t)) t = t.slice(0, -1);
    t = `${t.trimEnd()}\u2026`;
  }
  return t;
}

const SAFE_URL_RE = /^https?:\/\/[A-Za-z0-9.-]{1,253}(?::\d{1,5})?(?:[/?#][A-Za-z0-9\-._~!$&*+,;=:@%/?#]*)?$/;

/** The URL if it is a plain http(s) URL safe inside a markdown link destination, else "". */
export function safeUrl(s: string): string {
  const t = String(s ?? "").trim();
  if (t.length > 2000 || !SAFE_URL_RE.test(t)) return "";
  return t;
}

export interface MarkdownEscaperOptions {
  /** Hosts whose links stay clickable inside values (policy.output.link_allowlist). */
  linkAllowlist: string[];
  /** Max characters per value (default 300). */
  maxChars?: number;
}

/**
 * "```" -> "``\u200B`", "~~~~" -> "~~\u200B~~": no run of 3 is left, so the text can neither open nor
 * close a fenced code block anywhere (and still looks the same).
 */
export function breakFenceRuns(s: string): string {
  return s.replace(/`{3,}|~{3,}/g, (run) => (run.match(/[`~]{1,2}/g) ?? []).join(ZWSP));
}

export function markdownEscaper(opts: MarkdownEscaperOptions): Escaper {
  const max = Math.max(10, opts.maxChars ?? 300);
  return (value, key) => {
    if (URL_KEYS.has(key)) return safeUrl(value);
    const line = breakFenceRuns(oneLine(value, max));
    if (line === "") return "";
    return sanitizeMarkdown(line, {
      allowMentions: false,
      allowImages: false,
      linkAllowlist: opts.linkAllowlist,
      maxChars: max * 4 + 64,
    })
      .replace(/[ \t]*\n[ \t\n]*/g, " ") // e.g. a truncation note: values stay single-line
      .trim();
  };
}

export function slackEscaper(maxChars = 500): Escaper {
  const max = Math.max(10, maxChars);
  return (value, key) => {
    if (URL_KEYS.has(key)) {
      const u = safeUrl(value);
      return u === "" ? "" : escapeSlack(u, 2100);
    }
    const line = oneLine(value, max * 2);
    return line === "" ? "" : escapeSlack(line, max);
  };
}

export function plainEscaper(maxChars = 1000): Escaper {
  const max = Math.max(10, maxChars);
  return (value, key) => {
    if (URL_KEYS.has(key)) return safeUrl(value);
    return oneLine(redactSecrets(String(value ?? "")).text, max);
  };
}

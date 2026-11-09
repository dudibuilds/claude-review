/**
 * Output sanitization for everything the publisher posts to GitHub (markdown) and to Slack.
 *
 * The review text is written by an agent that may be prompt-injected (T1/T3). Once rendered on
 * GitHub it must not:
 *   - load remote resources (markdown images, <img>, reference-style images: exfiltration),
 *   - produce clickable links to hosts outside `output.link_allowlist` (inline, reference and
 *     autolinks, GFM bare URLs, HTML <a>),
 *   - notify people or teams (@user, @org/team) unless `output.allow_mentions`,
 *   - render raw HTML other than <details> <summary> <br> <code> <pre> <sub> <sup> (no attributes),
 *   - spoof our hidden markers (all HTML comments are dropped; markers are added after sanitizing),
 *   - create closing-keyword issue references ("fixes #12"),
 *   - leak secrets (redactSecrets runs on everything, code included).
 *
 * Design (every pass is a linear scan or a linear regex; scans that could restart are capped):
 *   1. normalize: CR/CRLF -> LF, strip C0 controls, bidi overrides and our placeholder range.
 *   2. redactSecrets.
 *   3. split into top-level fenced code blocks and prose. Fences are recognised conservatively
 *      (opener at column 0, never inside an HTML block); unclosed fences are closed at the end.
 *      Code is left alone apart from redaction (suggestions must stay byte-exact) and a
 *      disallowed ```suggestion info string is rewritten to `text`.
 *   4. prose: drop HTML comments; neutralize entity references (U+200B after "&"); rewrite link
 *      reference definitions, inline links and images; handle every "<" (autolinks, allowed tags,
 *      other tags stripped, stray "<" neutralized); defang bare URLs; then safety nets that break
 *      any remaining "![", "](" and "]:" so that a construct this parser did not recognise cannot
 *      render; closing keywords; @mentions. Constructs that are kept (allowlisted links, allowed
 *      tags) are swapped for private-use placeholders so later passes cannot touch them.
 *   5. truncate (never inside a kept URL; an open fence is closed) and append a note.
 *
 * Neutralization uses U+200B (zero-width space): it is invisible, so text inside inline code spans
 * (which this module does not need to identify for safety) still looks unchanged, while the syntax
 * it breaks ("@user", "&#64;", "<img", "https://") no longer parses. Inline code spans are detected
 * on a best-effort basis only to choose between two equally safe rewrites (e.g. keep "`<div>`"
 * readable instead of stripping the tag).
 */
import { redactSecrets } from "../common/redact.js";

export interface SanitizeOptions {
  allowMentions: boolean;
  allowImages: boolean;
  /** Hosts whose links stay clickable (subdomains included). Entries may carry a scheme or "*." prefix. */
  linkAllowlist: string[];
  /** Maximum length of the returned text, truncation note included. */
  maxChars: number;
  /**
   * Keep ```suggestion fenced blocks (top-level, column-0 fences only). Default false: the info
   * string is rewritten to `text`, so the block renders as plain code.
   */
  allowSuggestions?: boolean;
}

export interface SanitizeResult {
  text: string;
  truncated: boolean;
  /** Number of secrets redacted. */
  redactions: number;
}

export const ZWSP = "\u200B";

const TRUNCATION_NOTE = "\n\n\u2026 (truncated)";
const MAX_URL = 2048;
const MAX_LINK_TAIL = 1024;
const MAX_TITLE = 1000;
const MAX_TAG = 4096;
const SLACK_DEFAULT_MAX = 3000;

const PH_OPEN = "\uE000";
const PH_CLOSE = "\uE001";
const PH_DIGIT0 = 0xe010;
const PH_RE = /\uE000([\uE010-\uE019]+)\uE001/g;

/** C0 controls (except TAB/LF), DEL, bidi embeddings/overrides/isolates, our placeholder range. */
const STRIP_RE = /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F\u202A-\u202E\u2066-\u2069\uE000-\uE01F]/g;
/** Characters never allowed inside a URL we keep (whitespace, controls, invisible format chars). */
const UNSAFE_URL_CHARS =
  /[\s\u0000-\u001F\u007F-\u009F\u00AD\u034F\u061C\u115F\u1160\u17B4\u17B5\u180B-\u180F\u200B-\u200F\u202A-\u202E\u2060-\u206F\u3164\uFE00-\uFE0F\uFEFF\uFFA0]/;

const ALLOWED_TAGS = new Set(["details", "summary", "br", "code", "pre", "sub", "sup"]);

/* --------------------------------- helpers -------------------------------- */

function isHighSurrogate(code: number): boolean {
  return code >= 0xd800 && code <= 0xdbff;
}

/** s.slice(0, n) without splitting a surrogate pair. */
function sliceSafe(s: string, n: number): string {
  if (n <= 0) return "";
  if (n >= s.length) return s;
  return isHighSurrogate(s.charCodeAt(n - 1)) ? s.slice(0, n - 1) : s.slice(0, n);
}

function normalizeInput(text: unknown): string {
  const s = typeof text === "string" ? text : text === undefined || text === null ? "" : String(text);
  return s.replace(/\r\n?/g, "\n").replace(STRIP_RE, "");
}

/** Break autolink triggers in a URL-ish string: "://" -> ":\u200B//", "www." -> "www\u200B.". */
export function defangUrlText(text: string): string {
  return text.replace(/:\/\//g, `:${ZWSP}//`).replace(/www\./gi, `www${ZWSP}.`);
}

function defangHost(host: string): string {
  return host.replace(/www\./gi, `www${ZWSP}.`);
}

function lastWhitespace(s: string): number {
  return Math.max(s.lastIndexOf(" "), s.lastIndexOf("\n"), s.lastIndexOf("\t"));
}

/**
 * Cut `text` to at most `max` characters without splitting a surrogate pair. Prefers a whitespace
 * boundary near the end (whole tokens only); when a long token has to be split, its URL triggers
 * are defanged so a cut URL ("https://github.co") cannot become a link to a different host.
 */
export function safeCut(text: string, max: number): string {
  if (text.length <= max) return text;
  const head = sliceSafe(text, Math.max(0, max));
  if (/\s/.test(text.charAt(head.length))) return head;
  const ws = lastWhitespace(head);
  if (ws > 0 && ws >= head.length - 200) return head.slice(0, ws);
  const tokStart = ws + 1;
  const tok = head.slice(tokStart);
  if (!/:\/|www|\/\//i.test(tok)) return head;
  // Every "://" / "www." in the defanged token carries a U+200B, so any prefix of it is inert too.
  return head.slice(0, tokStart) + sliceSafe(defangUrlText(tok), max - tokStart);
}

/**
 * Render untrusted text as an inline code span: no line breaks, a backtick fence longer than any
 * backtick run inside, padded when needed. Inline code is inert on GitHub (no links, mentions, HTML).
 */
export function inlineCode(text: string, maxChars = 300): string {
  let s = String(text ?? "").replace(/[\u0000-\u001F\u007F\u202A-\u202E\u2066-\u2069\u2028\u2029]+/g, " ");
  if (s.length > maxChars) s = `${sliceSafe(s, Math.max(1, maxChars - 1))}\u2026`;
  if (s === "") s = " ";
  let longest = 0;
  let run = 0;
  for (let i = 0; i < s.length; i++) {
    if (s.charCodeAt(i) === 96) longest = Math.max(longest, ++run);
    else run = 0;
  }
  const fence = "`".repeat(longest + 1);
  const pad = s.startsWith("`") || s.endsWith("`") || (s.startsWith(" ") && s.endsWith(" ")) ? " " : "";
  return `${fence}${pad}${s}${pad}${fence}`;
}

/* ------------------------------- allowlist -------------------------------- */

function normalizeAllowEntry(entry: string): string | null {
  if (typeof entry !== "string") return null;
  let h = entry.trim().toLowerCase();
  h = h.replace(/^[a-z][a-z0-9+.-]*:\/\//, "");
  h = h.split(/[/?#]/)[0] ?? "";
  h = h.replace(/:\d+$/, "").replace(/^\*\./, "").replace(/^\.+/, "").replace(/\.+$/, "");
  return /^[a-z0-9-]+(?:\.[a-z0-9-]+)*$/.test(h) ? h : null;
}

function hostAllowed(host: string, allow: readonly string[]): boolean {
  const h = host.toLowerCase().replace(/\.+$/, "");
  if (h === "") return false;
  return allow.some((e) => h === e || h.endsWith(`.${e}`));
}

/* ---------------------------- URL classification --------------------------- */

const BASE_URL = "https://github.com/";

type UrlInfo =
  | { ok: true; href: string; kind: "absolute" | "relative" | "fragment" | "empty"; host?: string }
  | { ok: false; host?: string };

const DEST_DECODE_RE = /\\([!-/:-@[-`{-~])|&(lt|gt|amp|quot|nbsp);/g;
const ENTITY_VALUES: Record<string, string> = { lt: "<", gt: ">", amp: "&", quot: '"', nbsp: "\u00A0" };

/** Single-pass CommonMark decoding of a link destination: backslash escapes + surviving entities. */
function decodeDestination(raw: string): string {
  return raw.replace(DEST_DECODE_RE, (_m, esc: string | undefined, ent: string | undefined) =>
    esc !== undefined ? esc : (ENTITY_VALUES[ent ?? ""] ?? ""),
  );
}

function decodeEntitiesOnly(raw: string): string {
  return raw.replace(/&(lt|gt|amp|quot|nbsp);/g, (_m, ent: string) => ENTITY_VALUES[ent] ?? "");
}

/** Host as a naive authority parse sees it (undefined when the authority is not plain host[:port]). */
function naiveAuthorityHost(d: string): string | undefined {
  let rest = d.replace(/^[A-Za-z][A-Za-z0-9+.-]*:/, "").replace(/^[\\/]+/, "");
  const end = rest.search(/[\\/?#]/);
  rest = (end === -1 ? rest : rest.slice(0, end)).toLowerCase();
  const m = /^([a-z0-9.-]+)(?::\d{0,5})?$/.exec(rest);
  return m ? (m[1] ?? "").replace(/\.+$/, "") : undefined;
}

/** Percent-encode what could break out of a "<...>" destination; protect "&" from entity decoding. */
/**
 * Percent-encode what could break out of a "<...>" destination or form block-level syntax ("[" and
 * "]": kept text must never contain "]:" / "](", or a definition could hide inside it); protect "&"
 * that would otherwise be decoded as an entity reference.
 */
function encodeHref(h: string): string {
  return h
    .replace(/[\s<>\\`[\]]/g, (c) => `%${c.charCodeAt(0).toString(16).toUpperCase().padStart(2, "0")}`)
    .replace(/&(?=#[0-9xX]|[A-Za-z][A-Za-z0-9]{0,31};)/g, "&amp;");
}

function classifyUrl(raw: string, allow: readonly string[], decode: boolean): UrlInfo {
  const d = (decode ? decodeDestination(raw) : raw).trim();
  if (d === "") return { ok: true, href: "", kind: "empty" };
  if (d.length > MAX_URL || UNSAFE_URL_CHARS.test(d)) return { ok: false };
  if (d.startsWith("#")) return { ok: true, href: encodeHref(d), kind: "fragment" };
  let absolute = false;
  const scheme = /^([A-Za-z][A-Za-z0-9+.-]*):/.exec(d);
  if (scheme) {
    const s = (scheme[1] ?? "").toLowerCase();
    if (s !== "http" && s !== "https") return { ok: false };
    absolute = true;
  } else if (/^[\\/]{2}/.test(d)) {
    absolute = true; // protocol-relative ("//host", "\\host", "/\host")
  }
  let url: URL;
  try {
    url = new URL(d, BASE_URL);
  } catch {
    return { ok: false };
  }
  if (url.protocol !== "https:" && url.protocol !== "http:") return { ok: false };
  const host = url.hostname.toLowerCase();
  const hostOk = /^[a-z0-9.-]+$/.test(host);
  if (url.username !== "" || url.password !== "" || !hostOk) return { ok: false, ...(hostOk ? { host } : {}) };
  if (absolute && naiveAuthorityHost(d) !== host.replace(/\.+$/, "")) return { ok: false, host };
  if (!hostAllowed(host, allow)) return { ok: false, host };
  return absolute
    ? { ok: true, href: encodeHref(url.href), kind: "absolute", host }
    : { ok: true, href: encodeHref(d), kind: "relative", host };
}

function displayHost(info: UrlInfo): string {
  return info.host ? defangHost(info.host) : "link removed";
}

/* ------------------------------ placeholders ------------------------------ */

class Placeholders {
  private items: string[] = [];

  add(text: string): string {
    const idx = this.items.push(text) - 1;
    let digits = "";
    for (const ch of String(idx)) digits += String.fromCharCode(PH_DIGIT0 + ch.charCodeAt(0) - 48);
    return `${PH_OPEN}${digits}${PH_CLOSE}`;
  }

  restore(s: string): string {
    if (this.items.length === 0) return s;
    return s.replace(PH_RE, (_m, d: string) => {
      let idx = 0;
      for (let i = 0; i < d.length; i++) idx = idx * 10 + (d.charCodeAt(i) - PH_DIGIT0);
      return this.items[idx] ?? "";
    });
  }
}

interface Ctx {
  allow: string[];
  allowImages: boolean;
  allowMentions: boolean;
  allowSuggestions: boolean;
  ph: Placeholders;
}

/* ------------------------------- segmentation ------------------------------ */

interface Segment {
  code: boolean;
  text: string;
  /** Code segments: the fence string that closes them (used when truncating inside). */
  fence?: string;
}

const FENCE_OPEN_RE = /^(`{3,}|~{3,})(.*)$/;
const FENCE_CLOSE_RE = /^[ \t]*(`{3,}|~{3,})[ \t]*$/;

function isSuggestionInfo(info: string): boolean {
  return /^[ \t]*suggestion/i.test(info);
}

/**
 * End condition of an HTML block starting on this line (CommonMark types 1-7, over-approximated:
 * any line starting with "<letter" or "</" is treated as a block that ends at a blank line). Being
 * generous here only means fewer fences are recognised as code, which is the safe direction.
 */
function htmlBlockEnd(line: string): RegExp | "blank" | null {
  const m = /^ {0,3}</.exec(line);
  if (!m) return null;
  const rest = line.slice(m[0].length - 1);
  if (/^<(?:script|pre|style|textarea)(?:[\s>]|$)/i.test(rest)) return /<\/(?:script|pre|style|textarea)>/i;
  if (rest.startsWith("<!--")) return /-->/;
  if (rest.startsWith("<?")) return /\?>/;
  if (rest.startsWith("<![CDATA[")) return /\]\]>/;
  if (/^<![A-Za-z]/.test(rest)) return />/;
  if (/^<\/?[A-Za-z]/.test(rest)) return "blank";
  return null;
}

function segment(s: string, allowSuggestions: boolean): Segment[] {
  const lines = s.split("\n");
  const segs: Segment[] = [];
  let prose: string[] = [];
  const flush = (): void => {
    if (prose.length > 0) segs.push({ code: false, text: prose.join("\n") });
    prose = [];
  };
  let html: RegExp | "blank" | null = null;
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i] ?? "";
    if (html !== null) {
      prose.push(line);
      if (html === "blank" ? line.trim() === "" : html.test(line)) html = null;
      continue;
    }
    const fm = FENCE_OPEN_RE.exec(line);
    const open = fm?.[1] ?? "";
    const info = fm?.[2] ?? "";
    if (fm && !(open.startsWith("`") && info.includes("`"))) {
      let j = i + 1;
      for (; j < lines.length; j++) {
        const cm = FENCE_CLOSE_RE.exec(lines[j] ?? "");
        const close = cm?.[1] ?? "";
        if (cm && close[0] === open[0] && close.length >= open.length) break;
      }
      flush();
      const closed = j < lines.length;
      const opener = !allowSuggestions && isSuggestionInfo(info) ? `${open}text` : line;
      const body = lines.slice(i + 1, closed ? j : lines.length);
      segs.push({ code: true, text: [opener, ...body, closed ? (lines[j] ?? open) : open].join("\n"), fence: open });
      i = closed ? j : lines.length;
      continue;
    }
    const hb = htmlBlockEnd(line);
    if (hb !== null) {
      prose.push(line);
      if (hb === "blank" || !hb.test(line)) html = hb; // types 1-5 can end on their start line
      continue;
    }
    prose.push(line);
  }
  flush();
  return segs;
}

/* ---------------------------- inline code spans ---------------------------- */

/**
 * Best-effort CommonMark code spans: a backtick run opens, the next run of equal length in the same
 * paragraph closes. Returns flat [start, end, start, end, ...] ranges (end exclusive). Only used to
 * choose between two safe rewrites, so mistakes are cosmetic.
 */
function codeSpanRanges(s: string): number[] {
  if (!s.includes("`")) return [];
  const pos: number[] = [];
  const len: number[] = [];
  const esc: number[] = [];
  const para: number[] = [];
  const n = s.length;
  let p = 0;
  for (let i = 0; i < n; ) {
    const c = s.charCodeAt(i);
    if (c === 10) {
      i++;
      let k = i;
      while (k < n && (s.charCodeAt(k) === 32 || s.charCodeAt(k) === 9)) k++;
      if (k >= n || s.charCodeAt(k) === 10) p++;
      continue;
    }
    if (c === 96) {
      let j = i;
      while (j < n && s.charCodeAt(j) === 96) j++;
      let b = 0;
      for (let q = i - 1; q >= 0 && s.charCodeAt(q) === 92; q--) b++;
      pos.push(i);
      len.push(j - i);
      esc.push(b % 2);
      para.push(p);
      i = j;
      continue;
    }
    i++;
  }
  const buckets = new Map<string, { list: number[]; ptr: number }>();
  for (let r = 0; r < pos.length; r++) {
    const key = `${para[r]}:${len[r]}`;
    const b = buckets.get(key);
    if (b) b.list.push(r);
    else buckets.set(key, { list: [r], ptr: 0 });
  }
  const ranges: number[] = [];
  for (let r = 0; r < pos.length; ) {
    const e = esc[r] ?? 0;
    const openLen = (len[r] ?? 0) - e;
    if (openLen <= 0) {
      r++;
      continue;
    }
    const b = buckets.get(`${para[r]}:${openLen}`);
    let found = -1;
    if (b) {
      while (b.ptr < b.list.length && (b.list[b.ptr] ?? 0) <= r) b.ptr++;
      if (b.ptr < b.list.length) found = b.list[b.ptr] ?? -1;
    }
    if (found === -1) {
      r++;
      continue;
    }
    ranges.push((pos[r] ?? 0) + e, (pos[found] ?? 0) + (len[found] ?? 0));
    r = found + 1;
  }
  return ranges;
}

/** Membership test for monotonically non-decreasing positions. */
function makeInCode(ranges: number[]): (pos: number) => boolean {
  let k = 0;
  return (pos: number): boolean => {
    while (k < ranges.length && (ranges[k + 1] ?? 0) <= pos) k += 2;
    return k < ranges.length && (ranges[k] ?? 0) <= pos;
  };
}

/* ------------------------------- prose passes ------------------------------ */

/** Remove complete HTML comments (incl. spoofed markers); U+200B keeps neighbours from joining. */
function dropHtmlComments(s: string): string {
  let out = "";
  let pos = 0;
  for (;;) {
    const i = s.indexOf("<!--", pos);
    if (i === -1) break;
    const j = s.indexOf("-->", i + 2);
    if (j === -1) break;
    out += s.slice(pos, i) + ZWSP;
    pos = j + 3;
  }
  return pos === 0 ? s : out + s.slice(pos);
}

const ENTITY_RE = /&(?=#[0-9]|#[xX][0-9A-Fa-f]|[A-Za-z][A-Za-z0-9]{0,31};)/g;
const SAFE_ENTITY_RE = /^&(?:lt|gt|amp|quot|nbsp);/;

/**
 * Entity references can smuggle "@", "#", ":" past later passes (GitHub's mention filter works on
 * decoded text). Numeric references are neutralized with or without ";" (HTML blocks decode "&#64"
 * too); named ones only with ";" (CommonMark requires it, and HTML's legacy semicolon-less names
 * all decode to harmless Latin-1 characters), so "?a=1&type=x" in URLs stays intact.
 * Only &lt; &gt; &amp; &quot; &nbsp; survive.
 */
function neutralizeEntities(s: string): string {
  if (!s.includes("&")) return s;
  return s.replace(ENTITY_RE, (_m, off: number) => (SAFE_ENTITY_RE.test(s.slice(off, off + 6)) ? "&" : `&${ZWSP}`));
}

const DEF_RE =
  /^( {0,3})\[((?:[^[\]\\\n]|\\[^\n]){1,999})\]:[ \t]*(<[^<>\n]*>|[^\s<]\S*)(?:[ \t]+("(?:[^"\\\n]|\\.)*"|'(?:[^'\\\n]|\\.)*'|\((?:[^()\\\n]|\\.)*\)))?[ \t]*$/;

/**
 * Link reference definitions at the start of a paragraph (top level, dest on the same line). Kept
 * when allowlisted (destination normalised, title dropped), otherwise rewritten to "label (host)".
 * Anything else that looks like a definition is broken by the "]:" safety net later.
 */
function rewriteDefinitions(s: string, ctx: Ctx): string {
  if (!s.includes("]:")) return s;
  const lines = s.split("\n");
  let canStart = true;
  for (let k = 0; k < lines.length; k++) {
    const line = lines[k] ?? "";
    if (canStart) {
      const m = DEF_RE.exec(line);
      const label = m?.[2] ?? "";
      if (m && label.trim() !== "") {
        const indent = m[1] ?? "";
        const destRaw = m[3] ?? "";
        const dest = destRaw.startsWith("<") ? destRaw.slice(1, -1) : destRaw;
        const info = classifyUrl(dest, ctx.allow, true);
        lines[k] = info.ok
          ? `${indent}[${label}${ctx.ph.add(`]: <${info.href}>`)}`
          : `${indent}${label} (${displayHost(info)})`;
        continue;
      }
    }
    canStart = line.trim() === "";
  }
  return lines.join("\n");
}

function isAsciiPunct(c: number): boolean {
  return (c >= 33 && c <= 47) || (c >= 58 && c <= 64) || (c >= 91 && c <= 96) || (c >= 123 && c <= 126);
}

function isEscaped(s: string, pos: number): boolean {
  let b = 0;
  for (let q = pos - 1; q >= 0 && s.charCodeAt(q) === 92; q--) b++;
  return b % 2 === 1;
}

/** Spaces/tabs, at most one line ending, spaces/tabs. */
function skipLinkWs(s: string, p: number): number {
  let j = p;
  while (j < s.length && (s[j] === " " || s[j] === "\t")) j++;
  if (s[j] === "\n") {
    j++;
    while (j < s.length && (s[j] === " " || s[j] === "\t")) j++;
  }
  return j;
}

/** Parse "(dest "title")" starting right after "](". Returns the raw destination and end index. */
function parseLinkTail(s: string, p: number): { end: number; dest: string } | null {
  const n = s.length;
  let j = skipLinkWs(s, p);
  if (j >= n) return null;
  let dest: string;
  if (s[j] === ")") return { end: j + 1, dest: "" };
  if (s[j] === "<") {
    let k = j + 1;
    const lim = Math.min(n, k + MAX_LINK_TAIL);
    while (k < lim) {
      const c = s[k];
      if (c === "\\" && k + 1 < n) {
        k += 2;
        continue;
      }
      if (c === ">" || c === "<" || c === "\n") break;
      k++;
    }
    if (k >= lim || s[k] !== ">") return null;
    dest = s.slice(j + 1, k);
    j = k + 1;
  } else {
    const start = j;
    const lim = Math.min(n, j + MAX_LINK_TAIL);
    let depth = 0;
    while (j < lim) {
      const c = s.charCodeAt(j);
      if (c === 92 && j + 1 < n && isAsciiPunct(s.charCodeAt(j + 1))) {
        j += 2;
        continue;
      }
      if (c <= 32 || c === 127) break;
      if (c === 40) {
        if (++depth > 32) return null;
      } else if (c === 41) {
        if (depth === 0) break;
        depth--;
      }
      j++;
    }
    if (j >= lim && lim < n) return null;
    if (depth !== 0 || j === start) return null;
    dest = s.slice(start, j);
  }
  const afterDest = j;
  j = skipLinkWs(s, j);
  if (j < n && j > afterDest && (s[j] === '"' || s[j] === "'" || s[j] === "(")) {
    const close = s[j] === "(" ? ")" : s[j];
    let k = j + 1;
    const lim = Math.min(n, k + MAX_TITLE);
    while (k < lim) {
      const c = s[k];
      if (c === "\\" && k + 1 < n) {
        k += 2;
        continue;
      }
      if (c === close) break;
      if (close === ")" && c === "(") return null;
      if (c === "\n" && /^[ \t]*(?:\n|$)/.test(s.slice(k + 1, k + 64))) return null; // blank line
      k++;
    }
    if (k >= lim || s[k] !== close) return null;
    j = skipLinkWs(s, k + 1);
  }
  if (j >= n || s[j] !== ")") return null;
  return { end: j + 1, dest };
}

interface Edit {
  start: number;
  end: number;
  text: string;
}

function applyEdits(s: string, edits: Edit[]): string {
  if (edits.length === 0) return s;
  edits.sort((a, b) => a.start - b.start);
  let out = "";
  let last = 0;
  for (const e of edits) {
    if (e.start < last) continue; // defensive: never overlap
    out += s.slice(last, e.start) + e.text;
    last = e.end;
  }
  return out + s.slice(last);
}

/**
 * Inline links "[label](dest)" and images "![alt](dest)". Only the brackets and the "(dest)" tail
 * are rewritten, so nested constructs inside labels are handled independently (edits never overlap).
 *   - allowlisted link: tail normalised to "](<href>)" and protected; label stays (and is sanitized).
 *   - other link: "label (host)" as plain text.
 *   - image: kept only with allowImages + allowlisted host, else "(image: alt)".
 */
function rewriteInlineLinks(s: string, ctx: Ctx): string {
  if (!s.includes("](")) return s;
  const inCode = makeInCode(codeSpanRanges(s));
  const edits: Edit[] = [];
  const stack: number[] = [];
  for (let i = 0; i < s.length; i++) {
    const ch = s[i];
    if (ch === "\\") {
      i++;
      continue;
    }
    if (ch !== "[" && ch !== "]") continue;
    if (inCode(i)) continue;
    if (ch === "[") {
      stack.push(i);
      continue;
    }
    const open = stack.pop();
    if (open === undefined || s[i + 1] !== "(") continue;
    const tail = parseLinkTail(s, i + 2);
    if (!tail) continue;
    const isImage = open > 0 && s[open - 1] === "!" && !isEscaped(s, open - 1);
    const info = classifyUrl(tail.dest, ctx.allow, true);
    if (isImage) {
      if (ctx.allowImages && info.ok && (info.kind === "absolute" || info.kind === "relative")) {
        edits.push({ start: open - 1, end: open + 1, text: ctx.ph.add("![") });
        edits.push({ start: i, end: tail.end, text: ctx.ph.add(`](<${info.href}>)`) });
      } else {
        const altEmpty = s.slice(open + 1, i).trim() === "";
        edits.push({ start: open - 1, end: open + 1, text: `${ZWSP}(image${altEmpty ? "" : ": "}` });
        edits.push({ start: i, end: tail.end, text: ")" });
      }
    } else if (info.ok) {
      edits.push({ start: i, end: tail.end, text: ctx.ph.add(`](<${info.href}>)`) });
    } else {
      edits.push({ start: open, end: open + 1, text: ZWSP });
      edits.push({ start: i, end: tail.end, text: ` (${displayHost(info)})` });
    }
    i = tail.end - 1;
  }
  return applyEdits(s, edits);
}

function isAlpha(c: number): boolean {
  return (c >= 65 && c <= 90) || (c >= 97 && c <= 122);
}

function isTagNameChar(c: number): boolean {
  return isAlpha(c) || (c >= 48 && c <= 57) || c === 45;
}

function isAttrNameStart(c: number): boolean {
  return isAlpha(c) || c === 95 || c === 58;
}

function isAttrNameChar(c: number): boolean {
  return isTagNameChar(c) || c === 95 || c === 46 || c === 58;
}

function isUnquotedValueChar(c: number): boolean {
  return !(c <= 32 || c === 34 || c === 39 || c === 61 || c === 60 || c === 62 || c === 96);
}

function skipTagWs(s: string, p: number, lim: number): number {
  let j = p;
  while (j < lim) {
    const c = s.charCodeAt(j);
    if (c === 32 || c === 9 || c === 10) j++;
    else break;
  }
  return j;
}

interface OpenTag {
  name: string;
  attrs: [string, string | undefined][];
  end: number;
}

/** CommonMark open tag at s[i] === "<" (bounded by MAX_TAG). */
function parseOpenTag(s: string, i: number): OpenTag | null {
  const lim = Math.min(s.length, i + MAX_TAG);
  let j = i + 1;
  if (j >= lim || !isAlpha(s.charCodeAt(j))) return null;
  const ns = j;
  while (j < lim && isTagNameChar(s.charCodeAt(j))) j++;
  const name = s.slice(ns, j).toLowerCase();
  const attrs: [string, string | undefined][] = [];
  for (;;) {
    const ws = j;
    j = skipTagWs(s, j, lim);
    if (j >= lim) return null;
    const c = s[j];
    if (c === ">") return { name, attrs, end: j + 1 };
    if (c === "/") return s[j + 1] === ">" ? { name, attrs, end: j + 2 } : null;
    if (j === ws || !isAttrNameStart(s.charCodeAt(j))) return null;
    const as = j;
    j++;
    while (j < lim && isAttrNameChar(s.charCodeAt(j))) j++;
    const attrName = s.slice(as, j).toLowerCase();
    let k = skipTagWs(s, j, lim);
    if (k < lim && s[k] === "=") {
      k = skipTagWs(s, k + 1, lim);
      if (k >= lim) return null;
      const q = s[k];
      if (q === '"' || q === "'") {
        let e = k + 1;
        while (e < lim && s[e] !== q) e++;
        if (e >= lim) return null;
        attrs.push([attrName, s.slice(k + 1, e)]);
        j = e + 1;
      } else {
        const vs = k;
        while (k < lim && isUnquotedValueChar(s.charCodeAt(k))) k++;
        if (k === vs) return null;
        attrs.push([attrName, s.slice(vs, k)]);
        j = k;
      }
    } else {
      attrs.push([attrName, undefined]);
    }
  }
}

function escapeAttr(v: string): string {
  return v.replace(/&/g, "&amp;").replace(/"/g, "&quot;").replace(/'/g, "&#39;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

function plainAlt(v: string): string {
  const s = v.replace(/[\u0000-\u001F\u007F\u200B[\]]+/g, " ").replace(/\s+/g, " ").trim();
  return s.length > 200 ? `${sliceSafe(s, 199)}\u2026` : s;
}

const AUTOLINK_RE = /<([A-Za-z][A-Za-z0-9+.-]{1,31}):([^\s<>]{0,2048})>/y;
const CLOSE_TAG_RE = /<\/([A-Za-z][A-Za-z0-9-]{0,63})[ \t\n]*>/y;

function angleAt(s: string, i: number, ctx: Ctx): { text: string; end: number } {
  AUTOLINK_RE.lastIndex = i;
  const al = AUTOLINK_RE.exec(s);
  if (al) {
    const scheme = (al[1] ?? "").toLowerCase();
    const uri = `${al[1]}:${al[2]}`;
    // Brackets are refused: kept text must never contain "]:" (a definition could hide inside).
    if ((scheme === "http" || scheme === "https") && !/[[\]]/.test(uri)) {
      const info = classifyUrl(uri, ctx.allow, false);
      if (info.ok && info.kind === "absolute") return { text: ctx.ph.add(`<${uri}>`), end: AUTOLINK_RE.lastIndex };
    }
    return { text: defangUrlText(uri), end: AUTOLINK_RE.lastIndex };
  }
  CLOSE_TAG_RE.lastIndex = i;
  const ct = CLOSE_TAG_RE.exec(s);
  if (ct) {
    const name = (ct[1] ?? "").toLowerCase();
    return { text: ALLOWED_TAGS.has(name) ? ctx.ph.add(`</${name}>`) : ZWSP, end: CLOSE_TAG_RE.lastIndex };
  }
  const tag = parseOpenTag(s, i);
  if (tag) {
    if (ALLOWED_TAGS.has(tag.name)) return { text: ctx.ph.add(`<${tag.name}>`), end: tag.end };
    if (tag.name === "img" && ctx.allowImages) {
      const src = tag.attrs.find(([k]) => k === "src")?.[1];
      const alt = tag.attrs.find(([k]) => k === "alt")?.[1] ?? "";
      if (src !== undefined) {
        const info = classifyUrl(decodeEntitiesOnly(src), ctx.allow, false);
        if (info.ok && (info.kind === "absolute" || info.kind === "relative")) {
          const html = `<img src="${escapeAttr(info.href)}" alt="${escapeAttr(plainAlt(decodeEntitiesOnly(alt)))}">`;
          return { text: ctx.ph.add(html), end: tag.end };
        }
      }
    }
    return { text: ZWSP, end: tag.end };
  }
  return { text: `<${ZWSP}`, end: i + 1 };
}

/**
 * Every "<" outside a code span: autolinks (kept if allowlisted, else defanged text), allowed tags
 * (re-emitted bare), <img> (only with allowImages + allowlisted src), other tags stripped, anything
 * else neutralized. Inside code spans "<" is only neutralized, so `Array<string>` stays readable.
 */
function rewriteAngles(s: string, ctx: Ctx): string {
  if (!s.includes("<")) return s;
  const inCode = makeInCode(codeSpanRanges(s));
  let out = "";
  let last = 0;
  for (let i = s.indexOf("<"); i !== -1; i = s.indexOf("<", last)) {
    out += s.slice(last, i);
    if (inCode(i)) {
      out += `<${ZWSP}`;
      last = i + 1;
      continue;
    }
    const r = angleAt(s, i, ctx);
    out += r.text;
    last = r.end;
  }
  return out + s.slice(last);
}

/** URL extent stops: whitespace/controls, "<", placeholders, and "[" / "]" (see encodeHref). */
function isUrlStop(c: number): boolean {
  return c <= 32 || c === 127 || c === 60 || c === 91 || c === 93 || (c >= 0xe000 && c <= 0xe01f);
}

/** cmark-gfm drops trailing punctuation, unbalanced ")" and a trailing entity from autolinks. */
function trimAutolinkTail(t: string): string {
  let opens = 0;
  let closes = 0;
  for (let i = 0; i < t.length; i++) {
    if (t[i] === "(") opens++;
    else if (t[i] === ")") closes++;
  }
  let e = t.length;
  while (e > 0) {
    const c = t[e - 1] ?? "";
    if ("?!.,:*_~'\"".includes(c)) {
      e--;
      continue;
    }
    if (c === ")" && closes > opens) {
      closes--;
      e--;
      continue;
    }
    if (c === ";") {
      const m = /&[A-Za-z0-9]{1,32};$/.exec(t.slice(Math.max(0, e - 40), e));
      if (m) {
        e -= m[0].length;
        continue;
      }
    }
    break;
  }
  return t.slice(0, e);
}

const URL_START_RE = /([A-Za-z][A-Za-z0-9+.-]{0,31}):\/\/|www\./gi;

/**
 * GFM extended autolinks. Matching is deliberately looser than GitHub's (any position, any scheme),
 * so everything GitHub could linkify is seen. Allowlisted http(s) URLs are protected; everything
 * else is defanged (stays readable, not clickable).
 */
function rewriteBareUrls(s: string, ctx: Ctx): string {
  if (!s.includes("://") && !/www\./i.test(s)) return s;
  let out = "";
  let last = 0;
  URL_START_RE.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = URL_START_RE.exec(s)) !== null) {
    const start = m.index;
    let end = start + m[0].length;
    const lim = Math.min(s.length, end + MAX_URL);
    while (end < lim && !isUrlStop(s.charCodeAt(end))) end++;
    const overlong = end === lim && lim < s.length && !isUrlStop(s.charCodeAt(lim));
    const text = s.slice(start, end);
    let replacement: string | undefined;
    if (!overlong) {
      const core = trimAutolinkTail(text);
      let url: string | undefined;
      if (m[1] !== undefined) {
        const alpha = (/[A-Za-z]+$/.exec(m[1])?.[0] ?? "").toLowerCase();
        if (alpha === "http" || alpha === "https") url = alpha + core.slice(m[1].length);
      } else {
        url = `http://${core}`;
      }
      if (url !== undefined && core.length > m[0].length) {
        const info = classifyUrl(url, ctx.allow, false);
        if (info.ok && info.kind === "absolute") replacement = ctx.ph.add(core) + text.slice(core.length);
      }
    }
    out += s.slice(last, start) + (replacement ?? defangUrlText(text));
    last = end;
    URL_START_RE.lastIndex = end;
  }
  return out + s.slice(last);
}

/** Break any link/image/definition syntax the passes above did not positively handle. */
function safetyNets(s: string): string {
  return s
    .replace(/!\[/g, `!${ZWSP}[`)
    .replace(/\]\(/g, `]${ZWSP}(`)
    .replace(/\]:/g, `]${ZWSP}:`)
    .replace(/^([ \t>*+\-0-9.)]*)(`{3,}|~{3,})([ \t]*)suggestion/gim, (_m, a: string, f: string, w: string) => `${a}${f}${w}text`);
}

const CLOSE_REF_RE =
  /\b(close[sd]?|fix(?:e[sd])?|resolve[sd]?)\b([\s:]{0,10})(#|GH-|[A-Za-z0-9_.-]{1,100}\/[A-Za-z0-9_.-]{1,100}#)(?=[0-9])/gi;
const CLOSE_URL_RE = /\b(close[sd]?|fix(?:e[sd])?|resolve[sd]?)\b(?=[\s:]{0,10}(?:[<(]?(?:https?:\/\/|\uE000)|\[))/gi;

/** "fixes #12" -> "fixes #\u200B12" (also GH-12, owner/repo#12); "fixes <issue URL>" -> keyword broken. */
function neutralizeClosingRefs(s: string): string {
  return s
    .replace(CLOSE_REF_RE, (_m, kw: string, sep: string, ref: string) => `${kw}${sep}${ref}${ZWSP}`)
    .replace(CLOSE_URL_RE, (kw: string) => `${kw}${ZWSP}`);
}

/** @user / @org/team (GitHub needs a non-word char or start before "@"; emails are left alone). */
const MENTION_RE = /(?<![A-Za-z0-9_])@(?=[A-Za-z0-9])/g;

function sanitizeProse(s: string, ctx: Ctx): string {
  let t = dropHtmlComments(s);
  t = neutralizeEntities(t);
  t = rewriteDefinitions(t, ctx);
  t = rewriteInlineLinks(t, ctx);
  t = rewriteAngles(t, ctx);
  t = rewriteBareUrls(t, ctx);
  t = safetyNets(t);
  t = neutralizeClosingRefs(t);
  if (!ctx.allowMentions) t = t.replace(MENTION_RE, `@${ZWSP}`);
  return ctx.ph.restore(t);
}

/* ---------------------------------- public --------------------------------- */

function assemble(parts: Segment[], max: number, forceNote: boolean): { text: string; truncated: boolean } {
  const full = parts.map((p) => p.text).join("\n");
  if (full.length <= max && !forceNote) return { text: full, truncated: false };
  if (max < TRUNCATION_NOTE.length + 16) return { text: safeCut(full, max), truncated: true };
  const budget = max - TRUNCATION_NOTE.length;
  let out = "";
  for (const [idx, p] of parts.entries()) {
    const piece = (idx === 0 ? "" : "\n") + p.text;
    if (out.length + piece.length <= budget) {
      out += piece;
      continue;
    }
    if (p.code) {
      const closing = `\n${p.fence ?? "```"}`;
      const room = budget - out.length - closing.length;
      const openerLen = piece.indexOf("\n", idx === 0 ? 0 : 1);
      if (openerLen !== -1 && room > openerLen) out += safeCut(piece, room) + closing;
    } else {
      const room = budget - out.length;
      if (room > 0) out += safeCut(piece, room);
    }
    break;
  }
  return { text: out + TRUNCATION_NOTE, truncated: true };
}

export function sanitizeMarkdownEx(text: string, opts: SanitizeOptions): SanitizeResult {
  const max = Number.isFinite(opts.maxChars) ? Math.max(1, Math.floor(opts.maxChars)) : 6000;
  let input = normalizeInput(text);
  let preCut = false;
  const inputCap = Math.max(4096, max * 4);
  if (input.length > inputCap) {
    input = sliceSafe(input, inputCap);
    preCut = true;
  }
  const red = redactSecrets(input);
  const ctx: Ctx = {
    allow: (opts.linkAllowlist ?? []).map(normalizeAllowEntry).filter((e): e is string => e !== null),
    allowImages: opts.allowImages === true,
    allowMentions: opts.allowMentions === true,
    allowSuggestions: opts.allowSuggestions === true,
    ph: new Placeholders(),
  };
  const parts = segment(red.text, ctx.allowSuggestions).map((seg) =>
    seg.code ? seg : { code: false, text: sanitizeProse(seg.text, ctx) },
  );
  const { text: out, truncated } = assemble(parts, max, preCut);
  return { text: out, truncated, redactions: red.count };
}

/**
 * Sanitize untrusted markdown for GitHub (comments, review bodies, check-run output).
 * Markers such as `<!-- xrepo:c:KEY -->` must be appended AFTER calling this (all comments are dropped).
 */
export function sanitizeMarkdown(text: string, opts: SanitizeOptions): string {
  return sanitizeMarkdownEx(text, opts).text;
}

/**
 * Escape untrusted text for Slack mrkdwn (incoming webhooks): secrets redacted, controls removed,
 * "&" "<" ">" escaped (which neutralizes <!channel>, <!here>, <!everyone>, <@U...>, <#C...>, <!subteam^...>
 * and <url|text> links), plain @channel/@here/@everyone broken with U+200B, length capped.
 */
export function escapeSlack(text: string, maxChars = SLACK_DEFAULT_MAX): string {
  const max = Number.isFinite(maxChars) ? Math.max(1, Math.floor(maxChars)) : SLACK_DEFAULT_MAX;
  let s = redactSecrets(normalizeInput(text)).text;
  if (s.length > max * 6) s = sliceSafe(s, max * 6);
  s = s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
  s = s.replace(/(?<![A-Za-z0-9_])@(?=(?:channel|here|everyone)\b)/gi, `@${ZWSP}`);
  if (s.length > max) {
    let cut = sliceSafe(s, Math.max(0, max - 1)).length;
    const amp = s.lastIndexOf("&", cut - 1);
    if (amp !== -1 && amp > cut - 6 && s.indexOf(";", amp) >= cut) cut = amp; // never split "&amp;"
    if (cut > 0 && s[cut - 1] === "@") cut--; // never leave "@" right before the cut
    s = `${s.slice(0, cut)}\u2026`;
  }
  return s;
}

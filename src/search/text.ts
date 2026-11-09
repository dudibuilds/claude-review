/**
 * Output helpers for xsearch: line-preserving secret redaction, line truncation, output caps.
 *
 * Line numbers must stay exact (review comments cite them), so redaction runs per line. PEM
 * private-key blocks span lines, and once their BEGIN marker is replaced no later redactSecrets
 * pass can find the block again, so they are handled here. pemLineMap hides at least every line
 * redactPem (src/common/redact.ts) would remove from the same text: a block runs from its BEGIN
 * marker to the next "-----END " within 64 KiB; without such an END, redactPem's own body rule
 * (pemUnterminatedStop, imported from redact.ts) decides where it stops, widened by a per-line
 * heuristic that also covers commented-out keys. Every line that holds any part of a block is
 * replaced.
 */
import { PEM_BEGIN_SOURCE, PEM_END, PEM_MAX_BLOCK, pemUnterminatedStop, redactSecrets } from "../common/redact.js";

export { PEM_MAX_BLOCK };
export const LINE_TRUNCATED = "… [line truncated]";
export const PEM_TAG = "[REDACTED:private_key]";

const PEM_BEGIN = new RegExp(PEM_BEGIN_SOURCE);
/** Characters redactPem's body rule consumes that carry no key material (quotes, joins, whitespace). */
const BODY_DECORATION = new Set([..." \t\r\n\f\v\"'`+,"]);
/** Body lines of an unterminated block (no END within PEM_MAX_BLOCK) hidden at most. */
const MAX_PEM_LINES = 400;
const DECORATION = new Set([..." \t\r\"'`+,;()"]);
const BASE64_RE = /^[A-Za-z0-9+/=]*$/;
const PEM_HEADER_RE = /^(?:Proc-Type|DEK-Info|Comment|Version|Hash):/;

function isBase64Char(c: number): boolean {
  return (
    (c >= 65 && c <= 90) || // A-Z
    (c >= 97 && c <= 122) || // a-z
    (c >= 48 && c <= 57) || // 0-9
    c === 43 || // +
    c === 47 || // /
    c === 61 // =
  );
}

function isSpace(c: number): boolean {
  return c === 32 || c === 9 || c === 13;
}

/**
 * A line that can be part of a PEM body: base64, RFC 1421 headers, optionally wrapped in quotes,
 * "+" / "," and literal "\n" of string-concatenated keys. Linear time (no regex backtracking).
 */
function isPemBodyLine(line: string): boolean {
  let a = 0;
  let b = line.length;
  for (;;) {
    while (a < b && DECORATION.has(line[a]!)) a++;
    while (b > a && DECORATION.has(line[b - 1]!)) b--;
    if (b - a >= 2 && line[b - 2] === "\\" && (line[b - 1] === "n" || line[b - 1] === "r")) {
      b -= 2;
      continue;
    }
    break;
  }
  const core = line.slice(a, b);
  return BASE64_RE.test(core) || PEM_HEADER_RE.test(core);
}

/**
 * Looser body test for the lines after an unterminated BEGIN: also accepts base64 wrapped in
 * any short decoration (b"...\n", .append("..."), "// ", "# ", "> " prefixes) and lines of any
 * length. The longest base64 run must be at least 16 characters and everything else on the line
 * (whitespace aside) at most 40. Linear time.
 */
function isLoosePemBodyLine(line: string): boolean {
  if (isPemBodyLine(line)) return true;
  let longest = 0;
  let run = 0;
  let other = 0;
  for (let i = 0; i < line.length; i++) {
    const c = line.charCodeAt(i);
    if (isBase64Char(c)) {
      run++;
      continue;
    }
    if (run > longest) {
      other += longest;
      longest = run;
    } else {
      other += run;
    }
    run = 0;
    if (!isSpace(c)) other++;
    if (other > 40) return false; // `other` never shrinks: a longer run moves the old longest into it
  }
  if (run > longest) {
    other += longest;
    longest = run;
  } else {
    other += run;
  }
  return longest >= 16 && other <= 40;
}

/**
 * Streaming tracker for files too large to scan up front (Read of a huge file with offset/limit).
 * Without lookahead it cannot tell whether an END follows, so it is conservative: after a BEGIN
 * marker every line is hidden until a line containing "-----END " or until PEM_MAX_BLOCK bytes of
 * body, whichever comes first.
 */
export class PemTracker {
  private inPem = false;
  private bytes = 0;

  /** Returns the redacted replacement for `line` if it belongs to a PEM block, else null. */
  step(line: string): string | null {
    if (this.inPem) {
      const end = line.indexOf(PEM_END);
      if (end !== -1 && this.bytes + end <= PEM_MAX_BLOCK) {
        this.inPem = false;
        return PEM_TAG;
      }
      if (end === -1 && this.bytes + line.length + 1 <= PEM_MAX_BLOCK) {
        this.bytes += line.length + 1;
        return PEM_TAG;
      }
      this.inPem = false; // bound reached: unterminated block ended; handle this line normally
    }
    const m = PEM_BEGIN.exec(line);
    if (!m) return null;
    const rest = line.slice(m.index + m[0].length);
    if (rest.includes(PEM_END)) return null; // one-line key: redactSecrets handles it
    this.inPem = true;
    this.bytes = rest.length + 1;
    return beginLineReplacement(line, m.index);
  }
}

/** The BEGIN line keeps what precedes the marker (e.g. `KEY = "`), itself redacted. */
function beginLineReplacement(line: string, markerAt: number): string {
  const prefix = line.slice(0, markerAt);
  return prefix.includes(PEM_END) ? PEM_TAG : redactSecrets(prefix).text + PEM_TAG;
}

/**
 * Replacement text for every line (1-based) that belongs to a PEM private-key block, computed
 * over the whole file with redactPem's rules (BEGIN, then the next "-----END " within
 * PEM_MAX_BLOCK; otherwise every line its body rule (pemUnterminatedStop) consumes key material
 * from, plus following lines that pass the per-line body heuristic, at most MAX_PEM_LINES of
 * them). The lines hidden always
 * cover what redactSecrets would remove from the same text. A key whose BEGIN and END share one
 * line is left to the per-line redactSecrets pass.
 */
export function pemLineMap(text: string): Map<number, string> {
  const out = new Map<number, string>();
  if (!text.includes("PRIVATE KEY")) return out;
  const starts: number[] = [0];
  for (let i = text.indexOf("\n"); i !== -1; i = text.indexOf("\n", i + 1)) starts.push(i + 1);
  const lineCount = starts.length;
  /** 0-based index of the line holding `offset`. */
  const lineAt = (offset: number): number => {
    let lo = 0;
    let hi = lineCount - 1;
    while (lo < hi) {
      const mid = (lo + hi + 1) >> 1;
      if (starts[mid]! <= offset) lo = mid;
      else hi = mid - 1;
    }
    return lo;
  };
  const lineEnd = (idx: number): number => (idx + 1 < lineCount ? starts[idx + 1]! - 1 : text.length);
  const lineText = (idx: number): string => text.slice(starts[idx]!, lineEnd(idx));
  const add = (idx: number, replacement: string): void => {
    if (!out.has(idx + 1)) out.set(idx + 1, replacement);
  };

  const re = new RegExp(PEM_BEGIN.source, "g");
  let endSearchFrom = -1; // memo of the last END search (as in redactPem)
  let endFound = -1;
  let m: RegExpExecArray | null;
  while ((m = re.exec(text)) !== null) {
    const bodyStart = m.index + m[0].length;
    const first = lineAt(m.index);
    if (!(endSearchFrom >= 0 && endSearchFrom <= bodyStart && (endFound === -1 || endFound >= bodyStart))) {
      endSearchFrom = bodyStart;
      endFound = text.indexOf(PEM_END, bodyStart);
    }
    if (endFound !== -1 && endFound < lineEnd(first)) {
      re.lastIndex = endFound + PEM_END.length; // one-line key
      continue;
    }
    const lineStr = lineText(first);
    add(first, beginLineReplacement(lineStr, m.index - starts[first]!));
    if (endFound !== -1 && endFound - bodyStart <= PEM_MAX_BLOCK) {
      const last = lineAt(endFound);
      for (let i = first + 1; i <= last; i++) add(i, PEM_TAG);
      re.lastIndex = endFound + PEM_END.length; // a BEGIN later on the END line starts a new block
      continue;
    }
    // Unterminated. redactPem removes what its body rule consumes: hide every line holding consumed
    // key material (not lines where it only took a quote or whitespace)...
    const stop = pemUnterminatedStop(text, bodyStart);
    let q = stop - 1;
    while (q >= bodyStart && BODY_DECORATION.has(text[q]!)) q--;
    const lastByBody = q >= bodyStart ? lineAt(q) : first;
    for (let i = first + 1; i <= lastByBody; i++) add(i, PEM_TAG);
    // ...and, beyond that, lines that still look like key material (b"...\n", "# " prefixes).
    let i = lastByBody + 1;
    while (i < lineCount && i - first <= MAX_PEM_LINES && isLoosePemBodyLine(lineText(i))) add(i++, PEM_TAG);
    // [bodyStart, stop) holds no "-" and so no BEGIN marker; the lines after it are searched again.
    re.lastIndex = Math.max(stop, m.index + 1);
  }
  return out;
}

/**
 * The replacement for one line known to lie inside a PEM block (for callers that know the line
 * numbers from a whole-file scan but show the line from elsewhere, e.g. a diff): the BEGIN line
 * keeps what precedes the marker, every other line becomes PEM_TAG.
 */
export function pemReplacement(line: string): string {
  const m = PEM_BEGIN.exec(line);
  return m ? beginLineReplacement(line, m.index) : PEM_TAG;
}

/**
 * Text of a file as Read and Grep see it. UTF-16 with a byte-order mark is decoded (ripgrep runs
 * with --encoding=none, so it treats such files as binary; this keeps PEM scans right should a
 * caller ever see their text).
 */
export function decodeText(buf: Buffer): string {
  if (buf.length >= 2 && buf[0] === 0xff && buf[1] === 0xfe) return buf.subarray(2).toString("utf16le");
  if (buf.length >= 2 && buf[0] === 0xfe && buf[1] === 0xff) {
    const le = Buffer.from(buf.subarray(2, 2 + ((buf.length - 2) & ~1)));
    le.swap16();
    return le.toString("utf16le");
  }
  return buf.toString("utf8");
}

function hasUtf16Bom(buf: Buffer): boolean {
  return buf.length >= 2 && ((buf[0] === 0xff && buf[1] === 0xfe) || (buf[0] === 0xfe && buf[1] === 0xff));
}

/**
 * PEM lines of a whole file, numbered as ripgrep (run with --encoding=none) and Read number them:
 * by "\n" bytes of the raw content. For a file with a UTF-16 byte-order mark, the lines its decoded
 * text marks are hidden too (PEM_TAG only), should anything ever show that file as text.
 */
export function filePemLineMap(buf: Buffer): Map<number, string> {
  const out = buf.includes("PRIVATE KEY") ? pemLineMap(buf.toString("utf8")) : new Map<number, string>();
  if (hasUtf16Bom(buf)) {
    for (const n of pemLineMap(decodeText(buf)).keys()) if (!out.has(n)) out.set(n, PEM_TAG);
  }
  return out;
}

/** 1-based line numbers inside PEM private-key blocks. */
export function pemLineSet(text: string): Set<number> {
  return new Set(pemLineMap(text).keys());
}

/**
 * Lines that could be PEM key material when seen out of context: only used for Grep hits in a
 * file that cannot be scanned as a whole.
 */
export function looksLikeKeyMaterial(line: string): boolean {
  return line.includes("PRIVATE KEY") || (/[A-Za-z0-9+/=]{16,}/.test(line) && isLoosePemBodyLine(line));
}

export function redactLine(line: string, enabled: boolean): string {
  return enabled ? redactSecrets(line).text : line;
}

export function truncateLine(line: string, max: number): string {
  return line.length > max ? `${line.slice(0, max)}${LINE_TRUNCATED}` : line;
}

/** Strip one trailing "\r" (CRLF files). */
export function stripCr(line: string): string {
  return line.endsWith("\r") ? line.slice(0, -1) : line;
}

/** How many leading lines fit into `budget` characters when joined with "\n". */
export function fitLines(lines: string[], budget: number): number {
  let used = 0;
  for (let i = 0; i < lines.length; i++) {
    used += lines[i]!.length + (i > 0 ? 1 : 0);
    if (used > budget) return i;
  }
  return lines.length;
}

/** Smallest budget fitAtLeastOne cuts a single over-long entry to. */
const MIN_ENTRY_BUDGET = 80;

/**
 * Like fitLines, but pagination always makes progress: when not even the first entry fits, it is
 * cut to the budget (in place) and counted, so "Use offset: N" always names a later entry.
 */
export function fitAtLeastOne(lines: string[], budget: number): number {
  const k = fitLines(lines, budget);
  if (k > 0 || lines.length === 0) return k;
  const room = Math.max(MIN_ENTRY_BUDGET, budget - LINE_TRUNCATED.length);
  lines[0] = truncateLine(lines[0]!, room);
  return 1;
}

/** Room left for content after reserving space for a trailing note. */
export const NOTE_RESERVE = 200;

/** Default advice of finalizeOutput's truncation note (callers pass the advice that fits the tool). */
export const DEFAULT_TRUNCATION_HINT = "Narrow the request (path, glob, type) or use offset/limit.";

/**
 * Final pass over every response: redact secrets (whole text), then enforce max_output_chars at a
 * line boundary with a one-line note. `hint` is the advice in that note: it must name only
 * parameters the tool has.
 */
export function finalizeOutput(text: string, opts: { redact: boolean; maxChars: number; hint?: string }): { text: string; truncated: boolean } {
  let out = opts.redact ? redactSecrets(text).text : text;
  if (out.length <= opts.maxChars) return { text: out, truncated: false };
  const note = `[Output truncated: exceeded ${opts.maxChars} characters. ${opts.hint ?? DEFAULT_TRUNCATION_HINT}]`;
  const budget = Math.max(0, opts.maxChars - note.length - 1);
  let cut = out.lastIndexOf("\n", budget);
  if (cut < budget / 2) cut = budget;
  out = `${out.slice(0, cut)}\n${note}`;
  return { text: out, truncated: true };
}

/** Single-line, length-capped text for untrusted metadata (repo descriptions). */
export function oneLine(s: string, max: number): string {
  const t = s.replace(/[\u0000-\u001f\u007f]+/g, " ").replace(/\s+/g, " ").trim();
  return t.length > max ? `${t.slice(0, max - 1)}…` : t;
}

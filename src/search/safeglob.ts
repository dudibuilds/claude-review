/**
 * Glob matching for agent-supplied patterns without backtracking regular expressions.
 *
 * picomatch compiles a glob into a V8 RegExp; a pattern such as "*a*a*a*a*a*a*a*a*b" then
 * backtracks exponentially on a long file name, and the synchronous match blocks the event loop
 * for minutes (no timeout can interrupt it). Agent globs are therefore matched here instead, in
 * O(pattern x path) time:
 * - braces are expanded first ("{a,b}", nested), at most MAX_BRACE_EXPANSIONS alternatives;
 * - a pattern is split into "/" segments; "**" segments match any number of path segments
 *   (a trailing "/**" at least one), via dynamic programming over (pattern, path) segment pairs;
 * - inside a segment, "*" (any run), "?" (one character), "[...]" classes ("!" / "^" negate,
 *   ranges) and "\x" escapes are matched with the classic two-pointer wildcard algorithm.
 * Semantics follow ripgrep's globs (globset with literal separators): "*" never crosses "/",
 * dotfiles are not special, matching is case-sensitive, and there are no extglobs.
 */

export const MAX_BRACE_EXPANSIONS = 64;

type Tok = { k: "lit"; c: string } | { k: "any" } | { k: "star" } | { k: "cls"; neg: boolean; items: [string, string][] };

/** One "/" segment: "**" or a token list. */
type Seg = "**" | Tok[];

/** Index of the "}" closing the "{" at `open`, or -1. */
function closingBrace(s: string, open: number): number {
  let depth = 0;
  for (let i = open; i < s.length; i++) {
    const c = s[i];
    if (c === "\\") {
      i++;
      continue;
    }
    if (c === "{") depth++;
    else if (c === "}" && --depth === 0) return i;
  }
  return -1;
}

/** Split the inside of a brace group at top-level commas. */
function splitAlternatives(inner: string): string[] {
  const out: string[] = [];
  let depth = 0;
  let from = 0;
  for (let i = 0; i < inner.length; i++) {
    const c = inner[i];
    if (c === "\\") {
      i++;
      continue;
    }
    if (c === "{") depth++;
    else if (c === "}") depth--;
    else if (c === "," && depth === 0) {
      out.push(inner.slice(from, i));
      from = i + 1;
    }
  }
  out.push(inner.slice(from));
  return out;
}

/** Brace expansion; null when it would produce more than `cap` patterns. */
export function expandBraces(pattern: string, cap = MAX_BRACE_EXPANSIONS): string[] | null {
  const out: string[] = [];
  const walk = (s: string, from: number): boolean => {
    for (let i = from; i < s.length; i++) {
      const c = s[i];
      if (c === "\\") {
        i++;
        continue;
      }
      if (c !== "{") continue;
      const close = closingBrace(s, i);
      if (close === -1) break; // unbalanced: the rest is literal
      const head = s.slice(0, i);
      const tail = s.slice(close + 1);
      for (const alt of splitAlternatives(s.slice(i + 1, close))) {
        if (!walk(head + alt + tail, head.length)) return false;
        if (out.length > cap) return false;
      }
      return true;
    }
    out.push(s);
    return out.length <= cap;
  };
  return walk(pattern, 0) && out.length <= cap ? out : null;
}

function parseSegment(seg: string): Tok[] {
  const chars = Array.from(seg);
  const toks: Tok[] = [];
  for (let i = 0; i < chars.length; i++) {
    const c = chars[i]!;
    if (c === "\\" && i + 1 < chars.length) {
      toks.push({ k: "lit", c: chars[++i]! });
    } else if (c === "*") {
      if (toks.length === 0 || toks[toks.length - 1]!.k !== "star") toks.push({ k: "star" });
    } else if (c === "?") {
      toks.push({ k: "any" });
    } else if (c === "[") {
      let j = i + 1;
      let neg = false;
      if (chars[j] === "!" || chars[j] === "^") {
        neg = true;
        j++;
      }
      const items: [string, string][] = [];
      let first = true;
      let closed = false;
      for (; j < chars.length; j++) {
        let a = chars[j]!;
        if (a === "]" && !first) {
          closed = true;
          break;
        }
        first = false;
        if (a === "\\" && j + 1 < chars.length) a = chars[++j]!;
        if (chars[j + 1] === "-" && j + 2 < chars.length && chars[j + 2] !== "]") {
          let b = chars[j + 2]!;
          j += 2;
          if (b === "\\" && j + 1 < chars.length) b = chars[++j]!;
          items.push([a, b]);
        } else {
          items.push([a, a]);
        }
      }
      if (closed) {
        toks.push({ k: "cls", neg, items });
        i = j;
      } else {
        toks.push({ k: "lit", c: "[" }); // unclosed: literal "["
      }
    } else {
      toks.push({ k: "lit", c });
    }
  }
  return toks;
}

function tokMatches(t: Tok, c: string): boolean {
  switch (t.k) {
    case "lit":
      return t.c === c;
    case "any":
      return true;
    case "cls": {
      let hit = false;
      for (const [a, b] of t.items) {
        if (c >= a && c <= b) {
          hit = true;
          break;
        }
      }
      return hit !== t.neg;
    }
    default:
      return false;
  }
}

/** Two-pointer wildcard match: O(|toks| x |s|) worst case, never exponential. */
function matchSegment(toks: Tok[], s: string[]): boolean {
  let ti = 0;
  let si = 0;
  let starTi = -1;
  let starSi = 0;
  while (si < s.length) {
    const t = toks[ti];
    if (t !== undefined && t.k === "star") {
      starTi = ti++;
      starSi = si;
    } else if (t !== undefined && tokMatches(t, s[si]!)) {
      ti++;
      si++;
    } else if (starTi !== -1) {
      ti = starTi + 1;
      si = ++starSi;
    } else {
      return false;
    }
  }
  while (ti < toks.length && toks[ti]!.k === "star") ti++;
  return ti === toks.length;
}

function compileOne(pattern: string): (segs: string[][]) => boolean {
  const raw = pattern.split("/").filter((s) => s !== "" && s !== ".");
  const segs: Seg[] = [];
  for (const s of raw) {
    if (s === "**") {
      if (segs[segs.length - 1] !== "**") segs.push("**");
    } else {
      segs.push(parseSegment(s));
    }
  }
  const m = segs.length;
  return (path: string[][]): boolean => {
    const n = path.length;
    // dp over pattern segments i (from the end): row[j] = segs[i..] matches path[j..].
    let next = new Uint8Array(n + 1);
    next[n] = 1;
    let cur = new Uint8Array(n + 1);
    for (let i = m - 1; i >= 0; i--) {
      const seg = segs[i]!;
      cur.fill(0);
      if (seg === "**") {
        const trailing = i === m - 1 && m > 1;
        if (trailing) {
          for (let j = 0; j < n; j++) cur[j] = 1; // "x/**": at least one more segment
        } else {
          cur[n] = next[n]!;
          for (let j = n - 1; j >= 0; j--) cur[j] = next[j]! || cur[j + 1]! ? 1 : 0;
        }
      } else {
        for (let j = n - 1; j >= 0; j--) cur[j] = next[j + 1]! && matchSegment(seg, path[j]!) ? 1 : 0;
      }
      [next, cur] = [cur, next];
    }
    return next[0] === 1;
  };
}

/**
 * Matcher for one normalized glob (relative, as rgGlobPattern returns it), applied to a relative
 * POSIX path. Null when brace expansion exceeds MAX_BRACE_EXPANSIONS.
 */
export function compileSafeGlob(pattern: string): ((path: string) => boolean) | null {
  const alts = expandBraces(pattern);
  if (alts === null) return null;
  const matchers = alts.map(compileOne);
  return (path: string): boolean => {
    const segs = path
      .split("/")
      .filter((s) => s !== "")
      .map((s) => Array.from(s));
    if (segs.length === 0) return false;
    return matchers.some((f) => f(segs));
  };
}

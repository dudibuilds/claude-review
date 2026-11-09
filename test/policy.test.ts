import { chmodSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { compileGlobs, repoPatternMatch } from "../src/policy/glob.js";
import {
  PolicyError,
  loadPolicy,
  parsePolicy,
  readResolvedPolicy,
  readableRepos,
  resolvePolicy,
} from "../src/policy/load.js";
import { DEFAULT_DENY_GLOBS, DEFAULT_EXCLUDE_GLOBS, OUTCOMES } from "../src/policy/schema.js";

let dir: string;
beforeAll(() => {
  dir = mkdtempSync(join(tmpdir(), "xrepo-policy-"));
});
afterAll(() => {
  rmSync(dir, { recursive: true, force: true });
});
afterEach(() => {
  vi.restoreAllMocks();
});

function errorOf(fn: () => unknown): PolicyError {
  try {
    fn();
  } catch (e) {
    expect(e).toBeInstanceOf(PolicyError);
    return e as PolicyError;
  }
  throw new Error("expected a PolicyError");
}

/* --------------------------------- globs -------------------------------- */

describe("compileGlobs", () => {
  it("empty list never matches", () => {
    const m = compileGlobs([]);
    expect(m("a")).toBe(false);
    expect(m(".env")).toBe(false);
    expect(m("")).toBe(false);
  });

  it("patterns without a slash match the basename at any depth", () => {
    const m = compileGlobs(["*.pem", "id_rsa*"]);
    expect(m("c.pem")).toBe(true);
    expect(m("a/b/c.pem")).toBe(true);
    expect(m("home/.ssh/id_rsa.pub")).toBe(true);
    expect(m("a/b/c.pem.txt")).toBe(false);
  });

  it("patterns with a slash are anchored at the repo root", () => {
    const m = compileGlobs(["src/*.ts"]);
    expect(m("src/a.ts")).toBe(true);
    expect(m("src/a/b.ts")).toBe(false);
    expect(m("lib/src/a.ts")).toBe(false);
  });

  it("'**/x' matches x at the root and nested", () => {
    const m = compileGlobs(["**/x"]);
    expect(m("x")).toBe(true);
    expect(m("a/b/x")).toBe(true);
    expect(m("a/b/xy")).toBe(false);
  });

  it("matches dotfiles and dot-directories", () => {
    const m = compileGlobs(["**/.env", "**/.env.*", ".github/**"]);
    expect(m(".env")).toBe(true);
    expect(m("svc/.env")).toBe(true);
    expect(m("config/.env.production")).toBe(true);
    expect(m(".github/workflows/ci.yml")).toBe(true);
    expect(m("env")).toBe(false);
    const star = compileGlobs(["*"]);
    expect(star(".hidden")).toBe(true);
    expect(star("a/.hidden")).toBe(true);
  });

  it("'dir/**' also matches the directory itself; trailing slash and leading slash forms", () => {
    const m = compileGlobs(["**/secrets/**"]);
    expect(m("secrets")).toBe(true);
    expect(m("secrets/a.txt")).toBe(true);
    expect(m("a/secrets/b/c")).toBe(true);
    const dirForm = compileGlobs(["build/"]);
    expect(dirForm("build/out.js")).toBe(true);
    expect(dirForm("pkg/build/out.js")).toBe(true);
    const anchored = compileGlobs(["/Makefile"]);
    expect(anchored("Makefile")).toBe(true);
    expect(anchored("sub/Makefile")).toBe(false);
  });

  it("a matching directory covers everything below it (ripgrep / gitignore pruning semantics)", () => {
    const m = compileGlobs(["secrets", "config/prod", "*.pem"]);
    expect(m("secrets")).toBe(true);
    expect(m("secrets/db.yml")).toBe(true);
    expect(m("a/b/secrets/db.yml")).toBe(true);
    expect(m("config/prod/x.yml")).toBe(true);
    expect(m("x/config/prod/y")).toBe(false); // slash patterns stay anchored
    expect(m("certs.pem/inner.txt")).toBe(true);
    expect(m("secretsx/db.yml")).toBe(false);
    expect(m("config/production/x.yml")).toBe(false);
    // anchored single-segment patterns still only cover the root entry
    expect(compileGlobs(["src/*.ts"])("src/a/b.ts")).toBe(false);
    expect(compileGlobs(["/build"])("build/out.js")).toBe(true);
    expect(compileGlobs(["/build"])("pkg/build/out.js")).toBe(false);
  });

  it("normalises ./ and leading / in paths", () => {
    const m = compileGlobs(["*.key"]);
    expect(m("./a/b.key")).toBe(true);
    expect(m("/a/b.key")).toBe(true);
  });

  it("default deny / exclude globs behave as intended", () => {
    const deny = compileGlobs(DEFAULT_DENY_GLOBS);
    for (const p of [".env", "app/.env.local", "certs/server.pem", "k.key", ".npmrc", "x/.netrc", "infra/prod.tfstate", "infra/prod.tfstate.backup", "home/.ssh/id_ed25519", "config/secrets/db.yml"]) {
      expect(deny(p), p).toBe(true);
    }
    for (const p of ["src/env.ts", "README.md", "keys.ts", "src/secret.ts"]) expect(deny(p), p).toBe(false);
    const excl = compileGlobs(DEFAULT_EXCLUDE_GLOBS);
    for (const p of ["node_modules/x/index.js", "a/vendor/b.go", "web/app.min.js", "package-lock.json", "svc/go.sum", "dist/a.js"]) {
      expect(excl(p), p).toBe(true);
    }
    expect(excl("src/app.js")).toBe(false);
  });
});

describe("repoPatternMatch", () => {
  it("exact owner/name, case-insensitive", () => {
    expect(repoPatternMatch("acme/web", "acme/web")).toBe(true);
    expect(repoPatternMatch("Acme/Web", "acme/WEB")).toBe(true);
    expect(repoPatternMatch("acme/web", "acme/web2")).toBe(false);
  });
  it("owner/* and *", () => {
    expect(repoPatternMatch("acme/*", "acme/api")).toBe(true);
    expect(repoPatternMatch("ACME/*", "acme/api")).toBe(true);
    expect(repoPatternMatch("acme/*", "acmex/api")).toBe(false);
    expect(repoPatternMatch("acme/*", "other/acme")).toBe(false);
    expect(repoPatternMatch("*", "anyone/anything")).toBe(true);
  });
  it("rejects malformed input", () => {
    expect(repoPatternMatch("", "acme/web")).toBe(false);
    expect(repoPatternMatch("acme/*", "acme")).toBe(false);
    expect(repoPatternMatch("acme/*", "acme/")).toBe(false);
    expect(repoPatternMatch("a/*/*", "a/b")).toBe(false);
  });
});

/* --------------------------------- parse -------------------------------- */

describe("parsePolicy", () => {
  it("minimal manifest yields safe defaults", () => {
    const f = parsePolicy("version: 1\n");
    expect(f.version).toBe(1);
    expect(f.repos).toEqual({});
    expect(f.notifications).toEqual({});
    const r = resolvePolicy(f, "acme/web");
    expect(r.enabled).toBe(true);
    expect(r.capabilities.approve.enabled).toBe(false);
    expect(r.capabilities.block.enabled).toBe(false);
    expect(r.capabilities.inline_comments.max_comments).toBe(15);
    expect(r.search.deny_globs).toEqual(DEFAULT_DENY_GLOBS);
    expect(r.search.exclude_globs).toEqual(DEFAULT_EXCLUDE_GLOBS);
  });

  it("lists every schema issue with a readable path", () => {
    const e = errorOf(() =>
      parsePolicy(
        [
          "version: 2",
          "bogus: true",
          "defaults:",
          "  capabilities:",
          "    inline_comments:",
          "      min_severity: urgent",
          "repos:",
          "  acme/web:",
          "    search:",
          "      max_output_chars: 5",
          "  not-a-repo: {}",
        ].join("\n"),
      ),
    );
    const msg = e.message;
    expect(msg).toMatch(/^invalid policy manifest \(\d+ issues\):/);
    expect(msg).toContain("  - version:");
    expect(msg).toContain("  - bogus: unknown key");
    expect(msg).toContain("  - defaults.capabilities.inline_comments.min_severity:");
    expect(msg).toContain('  - repos["acme/web"].search.max_output_chars:');
    expect(msg).toContain('repos["not-a-repo"]');
    expect(msg.split("\n").length).toBeGreaterThanOrEqual(6);
  });

  it("rejects unknown notification targets (superRefine) with the exact path", () => {
    const e = errorOf(() =>
      parsePolicy(
        [
          "version: 1",
          "notifications:",
          "  ops: { type: slack, url_secret: OPS_SLACK }",
          "defaults:",
          "  outcomes:",
          "    error:",
          "      notify: [{ target: ops }, { target: opz }]",
          "repos:",
          "  acme/web:",
          "    outcomes:",
          "      usage_limit:",
          "        notify: [{ target: nope }]",
        ].join("\n"),
      ),
    );
    expect(e.message).toContain('defaults.outcomes.error.notify[1].target: unknown notification target "opz"');
    expect(e.message).toContain('repos["acme/web"].outcomes.usage_limit.notify[0].target: unknown notification target "nope"');
    expect(e.message).not.toContain('"ops"');
  });

  it("reports unknown notify targets together with other schema errors", () => {
    const e = errorOf(() =>
      parsePolicy(["version: 1", "defaults:", "  enabled: maybe", "  outcomes:", "    error:", "      notify: [{ target: ghost }]"].join("\n")),
    );
    expect(e.message).toContain("defaults.enabled:");
    expect(e.message).toContain('unknown notification target "ghost"');
  });

  it("accepts valid notify targets", () => {
    const f = parsePolicy(
      [
        "version: 1",
        "notifications:",
        "  ops: { type: webhook, url_secret: OPS_HOOK, hmac_secret: OPS_HMAC }",
        "defaults:",
        "  outcomes:",
        "    usage_limit:",
        "      notify: [{ target: ops, message: 'paused {repo}' }]",
      ].join("\n"),
    );
    expect(f.notifications.ops?.timeout_ms).toBe(5000);
  });

  it("rejects YAML syntax errors, duplicate keys, custom tags and alias bombs", () => {
    expect(errorOf(() => parsePolicy("version: 1\ndefaults: [unclosed\n")).message).toMatch(/YAML/);
    expect(errorOf(() => parsePolicy("version: 1\nversion: 1\n")).message).toMatch(/YAML/);
    expect(errorOf(() => parsePolicy("version: 1\ndefaults: !custom {}\n")).message).toMatch(/YAML/);
    expect(errorOf(() => parsePolicy("version: 1\nx: !!binary aGVsbG8=\n")).message).toMatch(/YAML/);
    const bomb = [
      "version: 1",
      "a: &a [x, x, x, x, x, x, x, x, x, x]",
      "b: &b [*a, *a, *a, *a, *a, *a, *a, *a, *a, *a]",
      "c: &c [*b, *b, *b, *b, *b, *b, *b, *b, *b, *b]",
      "d: &d [*c, *c, *c, *c, *c, *c, *c, *c, *c, *c]",
      "e: [*d, *d, *d, *d, *d, *d, *d, *d, *d, *d]",
    ].join("\n");
    expect(() => parsePolicy(bomb)).toThrow(PolicyError);
  });

  it("empty document reports the missing version", () => {
    expect(errorOf(() => parsePolicy("")).message).toContain("version:");
    expect(errorOf(() => parsePolicy("# just a comment\n")).message).toContain("version:");
  });

  it("rejects repo keys that differ only by case", () => {
    const e = errorOf(() => parsePolicy("version: 1\nrepos:\n  acme/web: {}\n  Acme/Web: {}\n"));
    expect(e.message).toContain("case-insensitive");
  });

  it("rejects non-executing builtin tool escalation", () => {
    const e = errorOf(() => parsePolicy("version: 1\ndefaults:\n  agent:\n    builtin_tools: [Bash]\n"));
    expect(e.message).toContain("defaults.agent.builtin_tools[0]");
  });
});

/* -------------------------------- resolve ------------------------------- */

const LAYERED = `
version: 1
notifications:
  ops: { type: slack, url_secret: OPS_SLACK }
defaults:
  enabled: true
  capabilities:
    inline_comments: { max_comments: 5, min_severity: medium }
    approve: { enabled: true, never_paths: ["infra/**"] }
    labels: { enabled: true, allowed: [bug, security] }
  search:
    deny_globs: ["**/*.secret"]
    exclude_globs: ["**/generated/**"]
    max_output_chars: 20000
  cross_repo:
    readable: ["acme/*"]
    related: { "acme/api": "orders API" }
  agent:
    max_turns: 30
    instructions: "be terse"
  outcomes:
    error:
      notify: [{ target: ops }]
      add_labels: [review-error]
    usage_limit:
      retry: { max_attempts: 5 }
      add_labels: [postponed]
repos:
  Acme/Web:
    capabilities:
      inline_comments: { suggestions: false }
      approve: { never_paths: ["db/**"] }
    search:
      deny_globs: ["**/*.secret", "**/*.vault"]
      max_read_lines: 100
    cross_repo:
      deny: ["acme/payroll"]
      related: { "acme/auth": "token issuer" }
    agent:
      max_turns: 60
    outcomes:
      usage_limit:
        retry: { enabled: true }
        add_labels: [later]
      error:
        comment: "custom error {reason}"
  acme/off:
    enabled: false
`;

describe("resolvePolicy", () => {
  const file = parsePolicy(LAYERED);

  it("deep-merges nested objects: repo keys win, unspecified keys come from defaults, then schema defaults", () => {
    const r = resolvePolicy(file, "acme/web");
    expect(r.repo).toBe("acme/web");
    // defaults layer value survives a partial repo override of the same object
    expect(r.capabilities.inline_comments.max_comments).toBe(5);
    expect(r.capabilities.inline_comments.min_severity).toBe("medium");
    expect(r.capabilities.inline_comments.suggestions).toBe(false);
    // schema defaults for untouched keys
    expect(r.capabilities.inline_comments.max_comment_chars).toBe(1500);
    expect(r.capabilities.approve.enabled).toBe(true);
    expect(r.capabilities.approve.max_changed_lines).toBe(400);
    expect(r.capabilities.block.enabled).toBe(false);
    expect(r.agent.max_turns).toBe(60);
    expect(r.agent.instructions).toBe("be terse");
    expect(r.search.max_output_chars).toBe(20000);
    expect(r.search.max_read_lines).toBe(100);
    expect(r.search.timeout_ms).toBe(8000);
  });

  it("arrays from the more specific layer replace", () => {
    const r = resolvePolicy(file, "acme/web");
    expect(r.capabilities.approve.never_paths).toEqual(["db/**"]);
    expect(r.capabilities.labels.allowed).toEqual(["bug", "security"]);
    expect(r.cross_repo.readable).toEqual(["acme/*"]);
    expect(r.cross_repo.deny).toEqual(["acme/payroll"]);
    expect(r.cross_repo.related).toEqual({ "acme/api": "orders API", "acme/auth": "token issuer" });
  });

  it("deny/exclude globs accumulate on top of the built-in defaults (deduplicated)", () => {
    const r = resolvePolicy(file, "acme/web");
    expect(r.search.deny_globs).toEqual([...DEFAULT_DENY_GLOBS, "**/*.secret", "**/*.vault"]);
    expect(r.search.exclude_globs).toEqual([...DEFAULT_EXCLUDE_GLOBS, "**/generated/**"]);
    const other = resolvePolicy(file, "acme/api");
    expect(other.search.deny_globs).toEqual([...DEFAULT_DENY_GLOBS, "**/*.secret"]);
  });

  it("replace_defaults drops the built-in lists but keeps both layers", () => {
    const f = parsePolicy(
      "version: 1\ndefaults:\n  search: { deny_globs: ['a/**'], exclude_globs: ['x/**'] }\nrepos:\n  o/r:\n    search: { replace_defaults: true, deny_globs: ['b/**', 'a/**'] }\n",
    );
    const r = resolvePolicy(f, "o/r");
    expect(r.search.deny_globs).toEqual(["a/**", "b/**"]);
    expect(r.search.exclude_globs).toEqual(["x/**"]);
    expect(resolvePolicy(f, "o/other").search.deny_globs).toEqual([...DEFAULT_DENY_GLOBS, "a/**"]);
  });

  it("looks up repo keys case-insensitively and falls back to defaults for unknown repos", () => {
    expect(resolvePolicy(file, "ACME/WEB").agent.max_turns).toBe(60);
    expect(resolvePolicy(file, "acme/unknown").agent.max_turns).toBe(30);
    expect(resolvePolicy(file, "acme/unknown").capabilities.inline_comments.suggestions).toBe(true);
  });

  it("enabled: repo layer > defaults layer > true", () => {
    expect(resolvePolicy(file, "acme/off").enabled).toBe(false);
    expect(resolvePolicy(file, "acme/web").enabled).toBe(true);
    const f = parsePolicy("version: 1\ndefaults: { enabled: false }\nrepos:\n  o/on: { enabled: true }\n");
    expect(resolvePolicy(f, "o/x").enabled).toBe(false);
    expect(resolvePolicy(f, "o/on").enabled).toBe(true);
  });

  it("resolves all 7 outcomes over DEFAULT_OUTCOMES <- defaults <- repo", () => {
    const r = resolvePolicy(file, "acme/web");
    expect(Object.keys(r.outcomes).sort()).toEqual([...OUTCOMES].sort());
    // built-in default comment kept when a layer only adds notify
    expect(resolvePolicy(file, "acme/api").outcomes.error.comment).toContain("could not run");
    expect(resolvePolicy(file, "acme/api").outcomes.error.notify).toEqual([{ target: "ops" }]);
    // repo override of a scalar, defaults-layer arrays kept when not overridden
    expect(r.outcomes.error.comment).toBe("custom error {reason}");
    expect(r.outcomes.error.add_labels).toEqual(["review-error"]);
    expect(r.outcomes.error.check_conclusion).toBe("neutral");
    // nested object merge across layers + schema defaults inside it
    expect(r.outcomes.usage_limit.retry).toEqual({ enabled: true, max_attempts: 5, label: "xrepo-review:retry" });
    expect(resolvePolicy(file, "acme/api").outcomes.usage_limit.retry).toEqual({
      enabled: false,
      max_attempts: 5,
      label: "xrepo-review:retry",
    });
    // arrays replace
    expect(r.outcomes.usage_limit.add_labels).toEqual(["later"]);
    expect(r.outcomes.usage_limit.check_conclusion).toBe("neutral");
    expect(r.outcomes.usage_limit.comment).toContain("{reset_at_suffix}");
    // untouched outcomes fully defaulted
    expect(r.outcomes.skipped).toEqual({
      comment: "",
      check_conclusion: "skipped",
      add_labels: [],
      remove_labels: [],
      notify: [],
      fail_job: false,
    });
    expect(r.outcomes.completed.comment).toBe("");
    expect(r.outcomes.approved.check_conclusion).toBeUndefined();
  });

  it("copies notifications into the resolved policy", () => {
    const r = resolvePolicy(file, "acme/web");
    expect(r.notifications).toEqual({ ops: { type: "slack", url_secret: "OPS_SLACK", timeout_ms: 5000 } });
  });

  it("does not mutate the policy file and resolves deterministically", () => {
    const snapshot = JSON.stringify(file);
    const a = resolvePolicy(file, "acme/web");
    a.search.deny_globs.push("mutated");
    const b = resolvePolicy(file, "acme/web");
    expect(b.search.deny_globs).not.toContain("mutated");
    expect(JSON.stringify(file)).toBe(snapshot);
  });

  it("rejects invalid repo names", () => {
    expect(() => resolvePolicy(file, "not a repo")).toThrow(PolicyError);
    expect(() => resolvePolicy(file, "../etc")).toThrow(PolicyError);
  });
});

describe("readableRepos", () => {
  const file = parsePolicy(LAYERED);
  const mirror = ["acme/web", "acme/api", "acme/payroll", "other/lib", "acme/auth", "@pr", "bad"];

  it("matches readable patterns, deny wins, includes the PR repo's own mirror, sorted", () => {
    const r = resolvePolicy(file, "acme/web");
    expect(readableRepos(r, mirror)).toEqual(["acme/api", "acme/auth", "acme/web"]);
  });

  it("PR repo is readable even without a readable pattern, unless denied; absent mirrors are not invented", () => {
    const f = parsePolicy("version: 1\nrepos:\n  other/lib: {}\n  x/y:\n    cross_repo: { deny: ['x/*'] }\n");
    expect(readableRepos(resolvePolicy(f, "other/lib"), mirror)).toEqual(["other/lib"]);
    expect(readableRepos(resolvePolicy(f, "x/y"), ["x/y", "x/z"])).toEqual([]);
    expect(readableRepos(resolvePolicy(f, "nobody/here"), mirror)).toEqual([]);
  });

  it("'*' readable with a deny list; '*' deny blocks everything", () => {
    const f = parsePolicy(
      "version: 1\nrepos:\n  a/b:\n    cross_repo: { readable: ['*'], deny: ['acme/payroll', 'OTHER/*'] }\n  c/d:\n    cross_repo: { readable: ['*'], deny: ['*'] }\n",
    );
    expect(readableRepos(resolvePolicy(f, "a/b"), mirror)).toEqual(["acme/api", "acme/auth", "acme/web"]);
    expect(readableRepos(resolvePolicy(f, "c/d"), [...mirror, "c/d"])).toEqual([]);
  });
});

/* ------------------------------ load / read ----------------------------- */

describe("loadPolicy / readResolvedPolicy", () => {
  it("loads a file and warns (audit on stderr) when it is group/world-writable", () => {
    const writes: string[] = [];
    vi.spyOn(process.stderr, "write").mockImplementation(((chunk: string | Uint8Array) => {
      writes.push(String(chunk));
      return true;
    }) as typeof process.stderr.write);
    const p = join(dir, "policy.yaml");
    writeFileSync(p, "version: 1\n");
    chmodSync(p, 0o644);
    expect(loadPolicy(p).version).toBe(1);
    expect(writes.join("")).not.toContain("policy.insecure_permissions");
    chmodSync(p, 0o666);
    expect(loadPolicy(p).version).toBe(1);
    const line = writes.find((w) => w.includes("policy.insecure_permissions"));
    expect(line).toBeDefined();
    const rec = JSON.parse(line!);
    expect(rec).toMatchObject({ event: "policy.insecure_permissions", path: p, mode: "666" });
    chmodSync(p, 0o644);
  });

  it("errors name the file", () => {
    const p = join(dir, "bad.yaml");
    writeFileSync(p, "version: 3\n");
    const e = errorOf(() => loadPolicy(p));
    expect(e.message.startsWith(`${p}: invalid policy manifest`)).toBe(true);
    expect(errorOf(() => loadPolicy(join(dir, "missing.yaml"))).message).toContain("cannot read policy file");
  });

  it("round-trips a resolved policy through JSON", () => {
    const r = resolvePolicy(parsePolicy(LAYERED), "acme/web");
    const p = join(dir, "policy.resolved.json");
    writeFileSync(p, JSON.stringify(r));
    expect(readResolvedPolicy(p)).toEqual(r);
    writeFileSync(p, JSON.stringify({ ...r, extra: 1 }));
    expect(errorOf(() => readResolvedPolicy(p)).message).toContain("extra: unknown key");
    writeFileSync(p, "{not json");
    expect(() => readResolvedPolicy(p)).toThrow(PolicyError);
  });
});

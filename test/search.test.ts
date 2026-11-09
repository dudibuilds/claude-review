import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { PassThrough } from "node:stream";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { PrContext } from "../src/common/context.js";
import { parsePolicy, resolvePolicy } from "../src/policy/load.js";
import type { ResolvedPolicy } from "../src/policy/schema.js";
import { redactSecrets } from "../src/common/redact.js";
import { DEFAULT_DENY_GLOBS } from "../src/policy/schema.js";
import { XSEARCH_TOOL_NAMES, createSearchServer, main, policyPathGlob, type SearchServerOptions } from "../src/search/server.js";
import { ExcludeSet, Vfs, VfsError, discoverMirror, isCwdIndependentGlob, isMirrorRepoName } from "../src/search/vfs.js";
import { PEM_MAX_BLOCK, PEM_TAG, PemTracker, decodeText, finalizeOutput, pemLineMap, pemLineSet, redactLine } from "../src/search/text.js";
import { redactDiffLines, splitGlobParam } from "../src/search/tools.js";
import { compileSafeGlob, expandBraces } from "../src/search/safeglob.js";

/* --------------------------------- fixture -------------------------------- */

const NOW = Date.parse("2026-11-09T12:00:00Z");
const SHA_API = "4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e";
const SHA_PY = "abcdef0123456789abcdef0123456789abcdef01";
const SHA_WEB = "9f8e7d6c5b4a39281706f5e4d3c2b1a098765432";
const SHA_DENIED = "1111111111111111111111111111111111111111";
const SHA_OTHER = "2222222222222222222222222222222222222222";
const GH_TOKEN = `ghp_${"A1b2C3d4E5f6".repeat(3)}`; // 36 chars after the prefix
const B64 = "MIIEowIBAAKCAQEAu1SU1LfVLPHCozMxH2Mo4lgOEePzNm0tRgeLezV6ffAt0gun";

let base: string;
let mirrorDir: string;
let prDir: string;
let ctxDir: string;
let policy: ResolvedPolicy;
let ctx: PrContext;
let diffText: string;

function write(path: string, content: string | Buffer): void {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, content);
}

function mirrorRepo(repo: string, sha: string, files: Record<string, string | Buffer>, description = "", dir = mirrorDir): string {
  const repoDir = join(dir, ...repo.split("/"));
  const snap = join(repoDir, "snapshots", sha);
  for (const [p, c] of Object.entries(files)) write(join(snap, p), c);
  mkdirSync(snap, { recursive: true });
  symlinkSync(`snapshots/${sha}`, join(repoDir, "current"));
  write(
    join(repoDir, "meta.json"),
    JSON.stringify({ repo, sha, branch: "main", synced_at: new Date(NOW - 3 * 60_000).toISOString(), description }),
  );
  return snap;
}

const DIFF = `diff --git a/src/orders.ts b/src/orders.ts
index 1111111..2222222 100644
--- a/src/orders.ts
+++ b/src/orders.ts
@@ -1,3 +1,3 @@
 export function total(items: number[]): number {
-  return items.reduce((a, b) => a + b, 0);
+  return items.reduce((a, b) => a + b, 1);
 }
diff --git a/src/new.ts b/src/new.ts
new file mode 100644
index 0000000..3333333
--- /dev/null
+++ b/src/new.ts
@@ -0,0 +1,2 @@
+export const NEW = 1;
+export const OTHER = 2;
diff --git a/src/gone.ts b/src/gone.ts
deleted file mode 100644
index 4444444..0000000
--- a/src/gone.ts
+++ /dev/null
@@ -1 +0,0 @@
-export const GONE = 1;
diff --git a/src/old-name.ts b/src/renamed.ts
similarity index 90%
rename from src/old-name.ts
rename to src/renamed.ts
index 5555555..6666666 100644
--- a/src/old-name.ts
+++ b/src/renamed.ts
@@ -1 +1 @@
-export const NAME = "old";
+export const NAME = "new";
diff --git a/.env b/.env
index 7777777..8888888 100644
--- a/.env
+++ b/.env
@@ -1 +1 @@
-API_KEY=old-secret-value
+API_KEY=new-secret-value
diff --git a/img/logo.png b/img/logo.png
index 9999999..aaaaaaa 100644
Binary files a/img/logo.png and b/img/logo.png differ
diff --git a/src/big-change.ts b/src/big-change.ts
new file mode 100644
index 0000000..bbbbbbb
--- /dev/null
+++ b/src/big-change.ts
@@ -0,0 +1,50 @@
${Array.from({ length: 50 }, (_, i) => `+export const C${i + 1} = ${i + 1};`).join("\n")}
`;

beforeAll(() => {
  base = mkdtempSync(join(tmpdir(), "xsearch-test-"));
  mirrorDir = join(base, "mirror");
  prDir = join(base, "pr");
  ctxDir = join(base, "ctx");

  const pemFile = [
    "# test fixture",
    'KEY = """',
    "-----BEGIN RSA PRIVATE KEY-----",
    B64,
    "Zm9vYmFyYmF6cXV4cXV1eGNvcmdlZ3JhdWx0Z2FycGx5d2FsZG9mcmVkcGx1Z3h5",
    "-----END RSA PRIVATE KEY-----",
    '"""',
    "after = 1",
  ].join("\n");

  const gen: Record<string, string> = {};
  for (let i = 0; i < 300; i++) gen[`gen/f${String(i).padStart(3, "0")}.ts`] = `export const G${i} = ${i};\n`;

  const apiSnap = mirrorRepo(
    "acme/api",
    SHA_API,
    {
      "README.md": "# Orders API\nSee src/server.ts\n",
      "src/server.ts": [
        "import { total } from './orders';",
        "export function handle(req: Request) {",
        "  // TODO: validate",
        "  return total([1, 2, 3]);",
        "}",
        "export const PORT = 8080;",
        "",
      ].join("\n"),
      "src/orders.ts": "export function total(items: number[]): number {\n  return items.reduce((a, b) => a + b, 0);\n}\n",
      "src/long.ts": `const x = '${"y".repeat(3000)}'; // LONGLINE_NEEDLE\n`,
      "src/big.ts": Array.from({ length: 3000 }, (_, i) => `// line ${i + 1} padding`).join("\n") + "\n",
      "src/many.ts": Array.from({ length: 1500 }, (_, i) => `export const value${i + 1} = "${"v".repeat(20)}";`).join("\n") + "\n",
      "src/empty.ts": "",
      ".env": "DATABASE_URL=TOPSECRET_ENV\n",
      ".eslintrc.json": '{ "root": true }\n',
      "package-lock.json": '{ "name": "api", "lockfileVersion": 3, "needle": "LOCK_NEEDLE" }\n',
      "node_modules/lib/index.js": "module.exports = 'NODE_MODULES_NEEDLE';\n",
      "bin/logo.png": Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x00, 0x00, 0x01, 0x02, 0x4e, 0x45, 0x45, 0x44, 0x4c, 0x45]),
      ...gen,
    },
    "Orders API",
  );
  symlinkSync("/etc/passwd", join(apiSnap, "src", "passwd-link"));
  symlinkSync("server.ts", join(apiSnap, "src", "inner-link.ts"));

  mirrorRepo(
    "acme/py",
    SHA_PY,
    {
      "app/main.py": "from app.util import helper\n\n\ndef main():\n    return helper()  # TODO: tidy\n",
      "app/util.py": "def helper():\n    return 42\n",
      "keys/test_key.py": pemFile + "\n",
      "secrets/db.yml": "password: TOPSECRET_DB\n",
    },
    "Python service",
  );
  mirrorRepo("acme/web", SHA_WEB, { "src/orders.ts": "export function total(items: number[]): number {\n  return 0;\n}\n" });
  mirrorRepo("acme/denied", SHA_DENIED, { "secret.txt": "TOPSECRET_NEEDLE denied\n" });
  mirrorRepo("other/secret-repo", SHA_OTHER, { "secret.txt": "TOPSECRET_NEEDLE other\n" });

  // PR head checkout of acme/web.
  write(join(prDir, "src/orders.ts"), "export function total(items: number[]): number {\n  return items.reduce((a, b) => a + b, 1);\n}\n");
  write(join(prDir, "src/new.ts"), "export const NEW = 1;\nexport const OTHER = 2;\n");
  write(join(prDir, "src/renamed.ts"), 'export const NAME = "new";\n');
  write(join(prDir, "src/big-change.ts"), Array.from({ length: 50 }, (_, i) => `export const C${i + 1} = ${i + 1};`).join("\n") + "\n");
  write(join(prDir, "src/config.ts"), `export const token = "${GH_TOKEN}";\nexport const region = "eu";\n`);
  write(join(prDir, ".env"), "API_KEY=new-secret-value\n");
  write(join(prDir, "img/logo.png"), Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x00, 0x01]));
  write(join(prDir, "vendor/lib.js"), "var v = 'VENDOR_NEEDLE';\n");
  write(join(prDir, ".git/config"), "[core]\n\tGIT_NEEDLE = 1\n");
  write(join(prDir, "docs/ignored.md"), "ignored\n");
  symlinkSync("../mirror/other/secret-repo/current/secret.txt", join(prDir, "escape.txt"));
  symlinkSync("/etc", join(prDir, "etc-link"));

  policy = resolvePolicy(
    parsePolicy(
      [
        "version: 1",
        "repos:",
        "  acme/web:",
        "    cross_repo:",
        '      readable: ["acme/*"]',
        '      deny: ["acme/denied"]',
        "    search:",
        '      max_filesize: "20K"',
      ].join("\n"),
    ),
    "acme/web",
  );

  diffText = DIFF;
  ctx = {
    repo: "acme/web",
    number: 42,
    title: "Fix totals",
    body: "",
    author: "dev",
    author_type: "User",
    base_sha: SHA_WEB,
    head_sha: "1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b",
    base_ref: "main",
    head_ref: "fix",
    draft: false,
    fork: false,
    html_url: "https://github.com/acme/web/pull/42",
    files: [
      { path: "src/orders.ts", status: "modified", additions: 1, deletions: 1 },
      { path: "src/new.ts", status: "added", additions: 2, deletions: 0 },
      { path: "src/gone.ts", status: "removed", additions: 0, deletions: 1 },
      { path: "src/renamed.ts", status: "renamed", additions: 1, deletions: 1, previous_path: "src/old-name.ts" },
      { path: ".env", status: "modified", additions: 1, deletions: 1 },
      { path: "img/logo.png", status: "binary", additions: 0, deletions: 0 },
      { path: "src/big-change.ts", status: "added", additions: 50, deletions: 0 },
    ],
    changed_lines: 57,
    ignored_files: ["docs/ignored.md"],
  };
  write(join(ctxDir, "pr.json"), JSON.stringify(ctx));
  write(join(ctxDir, "diff.patch"), DIFF);
  write(join(ctxDir, "policy.resolved.json"), JSON.stringify(policy));
});

afterAll(() => {
  rmSync(base, { recursive: true, force: true });
});

/* --------------------------------- helpers -------------------------------- */

async function connect(extra: Partial<SearchServerOptions> = {}): Promise<Client> {
  const server = createSearchServer({ policy, ctx, diffText, prDir, mirrorDir, now: () => NOW, ...extra });
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  await server.connect(serverTransport);
  const client = new Client({ name: "test", version: "1.0.0" });
  await client.connect(clientTransport);
  return client;
}

interface CallOut {
  text: string;
  isError: boolean;
  raw: Record<string, unknown>;
}

async function call(client: Client, name: string, args: Record<string, unknown> = {}): Promise<CallOut> {
  const res = (await client.callTool({ name, arguments: args })) as Record<string, unknown>;
  const content = res.content as { type: string; text: string }[];
  expect(content.every((c) => c.type === "text")).toBe(true);
  return { text: content.map((c) => c.text).join(""), isError: res.isError === true, raw: res };
}

let client: Client;
beforeAll(async () => {
  client = await connect();
});

/* ---------------------------------- tests --------------------------------- */

describe("tools/list", () => {
  it("registers exactly the 5 xsearch tools, always loaded and read-only", async () => {
    const { tools } = await client.listTools();
    expect(tools.map((t) => t.name)).toEqual([...XSEARCH_TOOL_NAMES]);
    expect([...XSEARCH_TOOL_NAMES]).toEqual(["ListRepos", "PrDiff", "Grep", "Glob", "Read"]);
    for (const t of tools) {
      expect(t._meta?.["anthropic/alwaysLoad"]).toBe(true);
      expect(t.annotations?.readOnlyHint).toBe(true);
      expect(t.outputSchema).toBeUndefined();
      expect(t.description && t.description.length).toBeGreaterThan(40);
    }
  });

  it("uses Claude Code's parameter names", async () => {
    const { tools } = await client.listTools();
    const props = (name: string) => Object.keys((tools.find((t) => t.name === name)!.inputSchema.properties ?? {}) as object);
    expect(props("Grep")).toEqual([
      "pattern",
      "path",
      "glob",
      "output_mode",
      "-B",
      "-A",
      "-C",
      "context",
      "-n",
      "-i",
      "-o",
      "type",
      "head_limit",
      "offset",
      "multiline",
    ]);
    expect(props("Glob")).toEqual(["pattern", "path"]);
    expect(props("Read")).toEqual(["file_path", "offset", "limit"]);
    expect(props("PrDiff")).toEqual(["file_path", "offset", "limit"]);
    expect(props("ListRepos")).toEqual(["offset", "limit"]);
    const grep = tools.find((t) => t.name === "Grep")!;
    expect(grep.inputSchema.required).toEqual(["pattern"]);
    expect(grep.description).toContain("ALWAYS use Grep for search tasks");
    expect(grep.description).toContain("/repos/<owner>/<name>");
    expect(tools.find((t) => t.name === "Read")!.description).toContain("cat -n format");
  });
});

describe("ListRepos", () => {
  it("lists /pr and only the readable mirror repos", async () => {
    const r = await call(client, "ListRepos");
    expect(r.isError).toBe(false);
    expect(r.text.split("\n")).toEqual([
      "/pr                 acme/web  PR #42  head 1a2b3c4 base 9f8e7d6  7 files changed",
      "/repos/acme/api     4d5e6f7  synced 3m ago  Orders API",
      "/repos/acme/py      abcdef0  synced 3m ago  Python service",
      "/repos/acme/web     9f8e7d6  synced 3m ago  (base branch of this PR; searched only when passed as path)",
    ]);
    expect(r.text).not.toContain("denied");
    expect(r.text).not.toContain("secret-repo");
    expect(r.raw.structuredContent).toBeUndefined();
  });

  it("works without a mirror", async () => {
    const c = await connect({ mirrorDir: undefined });
    const r = await call(c, "ListRepos");
    expect(r.text).toContain("/pr                 acme/web  PR #42");
    expect(r.text).toContain("(no mirrored repositories are readable for this PR)");
  });
});

describe("Grep", () => {
  it("defaults to files_with_matches over /pr and the other repos (not the PR repo's own base copy)", async () => {
    const r = await call(client, "Grep", { pattern: "export function total" });
    expect(r.text).toBe(["Found 2 files", "/pr/src/orders.ts", "/repos/acme/api/src/orders.ts"].join("\n"));
    expect((await call(client, "Grep", { pattern: "export function total", path: "/" })).text).toBe(r.text);
    // The base snapshot is searched when named explicitly.
    const base = await call(client, "Grep", { pattern: "export function total", path: "/repos/acme/web" });
    expect(base.text).toBe("Found 1 file\n/repos/acme/web/src/orders.ts");
    const count = await call(client, "Grep", { pattern: "export function total", output_mode: "count" });
    expect(count.text).toContain("Found 2 total occurrences across 2 files.");
  });

  it("content mode prints ripgrep-style path:line:text", async () => {
    const r = await call(client, "Grep", { pattern: "reduce", output_mode: "content" });
    expect(r.text).toBe(
      ["/pr/src/orders.ts:2:  return items.reduce((a, b) => a + b, 1);", "/repos/acme/api/src/orders.ts:2:  return items.reduce((a, b) => a + b, 0);"].join(
        "\n",
      ),
    );
  });

  it("content mode with context uses path-line-text and -- separators", async () => {
    const r = await call(client, "Grep", { pattern: "TODO", output_mode: "content", "-C": 1 });
    expect(r.text).toBe(
      [
        "/repos/acme/api/src/server.ts-2-export function handle(req: Request) {",
        "/repos/acme/api/src/server.ts:3:  // TODO: validate",
        "/repos/acme/api/src/server.ts-4-  return total([1, 2, 3]);",
        "--",
        "/repos/acme/py/app/main.py-4-def main():",
        "/repos/acme/py/app/main.py:5:    return helper()  # TODO: tidy",
      ].join("\n"),
    );
    const before = await call(client, "Grep", { pattern: "TODO: validate", output_mode: "content", "-B": 2, path: "/repos/acme/api" });
    expect(before.text.split("\n")).toHaveLength(3);
    const noNums = await call(client, "Grep", { pattern: "TODO: validate", output_mode: "content", "-n": false });
    expect(noNums.text).toBe("/repos/acme/api/src/server.ts:  // TODO: validate");
  });

  it("count mode prints path:N and a total like Claude Code", async () => {
    const r = await call(client, "Grep", { pattern: "export", path: "/pr/src", output_mode: "count" });
    expect(r.text).toBe(
      [
        "/pr/src/big-change.ts:50",
        "/pr/src/config.ts:2",
        "/pr/src/new.ts:2",
        "/pr/src/orders.ts:1",
        "/pr/src/renamed.ts:1",
        "",
        "Found 56 total occurrences across 5 files.",
      ].join("\n"),
    );
    const none = await call(client, "Grep", { pattern: "zzz_nothing_here", output_mode: "count" });
    expect(none.text).toBe("No matches found\n\nFound 0 total occurrences across 0 files.");
  });

  it("paginates with head_limit / offset and Claude Code's note", async () => {
    const page1 = await call(client, "Grep", { pattern: "export const G", path: "/repos/acme/api/gen", head_limit: 2 });
    expect(page1.text).toBe(
      ["Found 2 files", "/repos/acme/api/gen/f000.ts", "/repos/acme/api/gen/f001.ts", "", "[Showing results with pagination = limit: 2, offset: 0]"].join("\n"),
    );
    const page2 = await call(client, "Grep", { pattern: "export const G", path: "/repos/acme/api/gen", head_limit: 2, offset: 2 });
    expect(page2.text).toContain("/repos/acme/api/gen/f002.ts\n/repos/acme/api/gen/f003.ts");
    expect(page2.text).toContain("[Showing results with pagination = limit: 2, offset: 2]");
    const content = await call(client, "Grep", { pattern: "export const C", path: "/pr", output_mode: "content", head_limit: 3 });
    expect(content.text.split("\n").slice(0, 3)).toEqual([
      "/pr/src/big-change.ts:1:export const C1 = 1;",
      "/pr/src/big-change.ts:2:export const C2 = 2;",
      "/pr/src/big-change.ts:3:export const C3 = 3;",
    ]);
    expect(content.text).toContain("[Showing results with pagination = limit: 3, offset: 0]");
    const def = await call(client, "Grep", { pattern: "export const", path: "/repos/acme/api" });
    expect(def.text).toContain("[Showing results with pagination = limit: 250, offset: 0]");
    const unlimited = await call(client, "Grep", { pattern: "export const G", path: "/repos/acme/api/gen", head_limit: 0 });
    expect(unlimited.text.startsWith("Found 300 files")).toBe(true);
    expect(unlimited.text).not.toContain("pagination");
    const past = await call(client, "Grep", { pattern: "export const G", path: "/repos/acme/api/gen", offset: 1000 });
    expect(past.text).toBe("No files found\n\n[Showing results with pagination = offset: 1000]");
    const pastContent = await call(client, "Grep", { pattern: "export const G", output_mode: "content", offset: 5000, head_limit: 0 });
    expect(pastContent.text).toBe("No matches found\n\n[Showing results with pagination = offset: 5000]");
  });

  it("scopes by virtual path: one repo, an owner, a sub-directory, a file", async () => {
    const one = await call(client, "Grep", { pattern: "TODO", path: "/repos/acme/py" });
    expect(one.text).toBe("Found 1 file\n/repos/acme/py/app/main.py");
    const owner = await call(client, "Grep", { pattern: "TODO", path: "/repos/acme" });
    expect(owner.text).toBe("Found 2 files\n/repos/acme/api/src/server.ts\n/repos/acme/py/app/main.py");
    const mirrors = await call(client, "Grep", { pattern: "export function total", path: "/repos" });
    expect(mirrors.text).toBe("Found 1 file\n/repos/acme/api/src/orders.ts");
    // Only the PR repo's base copy has it: say how to search that copy.
    const onlyBase = await call(client, "Grep", { pattern: "return 0;", path: "/repos/acme" });
    expect(onlyBase.text).toBe(
      "No files found\n\n[/repos/acme/web (this PR's repository before the change) is searched only when you pass it as path.]",
    );
    expect((await call(client, "Grep", { pattern: "return 0;", path: "/repos/acme/web" })).text).toBe("Found 1 file\n/repos/acme/web/src/orders.ts");
    const sub = await call(client, "Grep", { pattern: "helper", path: "/repos/acme/py/app", output_mode: "content" });
    expect(sub.text.split("\n")).toEqual([
      "/repos/acme/py/app/main.py:1:from app.util import helper",
      "/repos/acme/py/app/main.py:5:    return helper()  # TODO: tidy",
      "/repos/acme/py/app/util.py:1:def helper():",
    ]);
    const file = await call(client, "Grep", { pattern: "helper", path: "/repos/acme/py/app/util.py", output_mode: "content" });
    expect(file.text).toBe("/repos/acme/py/app/util.py:1:def helper():");
    const ci = await call(client, "Grep", { pattern: "orders api", path: "/Repos/ACME/API", "-i": true });
    expect(ci.text).toBe("Found 1 file\n/repos/acme/api/README.md");
  });

  it("filters with glob (relative to the searched directory) and type", async () => {
    const g = await call(client, "Grep", { pattern: "helper", glob: "*.py" });
    expect(g.text).toBe("Found 2 files\n/repos/acme/py/app/main.py\n/repos/acme/py/app/util.py");
    const anchored = await call(client, "Grep", { pattern: "helper", path: "/repos/acme/py", glob: "app/util.py" });
    expect(anchored.text).toBe("Found 1 file\n/repos/acme/py/app/util.py");
    const multi = await call(client, "Grep", { pattern: "TODO", glob: "*.ts,*.py" });
    expect(multi.text).toContain("Found 2 files");
    const t = await call(client, "Grep", { pattern: "TODO", type: "py" });
    expect(t.text).toBe("Found 1 file\n/repos/acme/py/app/main.py");
  });

  it("supports -i and multiline", async () => {
    const ci = await call(client, "Grep", { pattern: "export FUNCTION total", "-i": true, path: "/pr" });
    expect(ci.text).toBe("Found 1 file\n/pr/src/orders.ts");
    const ml = await call(client, "Grep", { pattern: "def main\\(\\):.*helper", multiline: true, output_mode: "content" });
    expect(ml.text.split("\n")).toEqual([
      "/repos/acme/py/app/main.py:4:def main():",
      "/repos/acme/py/app/main.py:5:    return helper()  # TODO: tidy",
    ]);
  });

  it("round-trips virtual paths from Grep into Read", async () => {
    const r = await call(client, "Grep", { pattern: "PORT = 8080", output_mode: "content" });
    const m = /^(\/[^:]+):(\d+):(.*)$/.exec(r.text);
    expect(m).not.toBeNull();
    const [, path, line, text] = m!;
    const read = await call(client, "Read", { file_path: path, offset: Number(line), limit: 1 });
    expect(read.text).toBe(`${String(line).padStart(6)}\t${text}`);
  });

  it("never shows .git, denied files or unreadable repos", async () => {
    for (const pattern of ["TOPSECRET", "GIT_NEEDLE", "API_KEY="]) {
      const r = await call(client, "Grep", { pattern });
      expect(r.text).toBe("No files found");
    }
    const hiddenDir = await call(client, "Grep", { pattern: "TOPSECRET", path: "/repos/acme/py/secrets" });
    expect(hiddenDir.isError).toBe(true);
    expect(hiddenDir.text).toContain("Path does not exist: /repos/acme/py/secrets");
    const withGlob = await call(client, "Grep", { pattern: "TOPSECRET", glob: "**/.env" });
    expect(withGlob.text).toBe("No files found");
    const gitGlob = await call(client, "Grep", { pattern: "GIT_NEEDLE", glob: ".git/**" });
    expect(gitGlob.text).toBe("No files found");
    expect((await call(client, "Glob", { pattern: ".git/*" })).text).toBe("No files found");
    expect((await call(client, "Glob", { pattern: "/pr/.git/*" })).isError).toBe(true);
    const denied = await call(client, "Grep", { pattern: "x", path: "/repos/acme/denied" });
    expect(denied.isError).toBe(true);
    expect(denied.text).not.toContain("denied ");
    expect(denied.text).not.toContain("secret-repo");
  });

  it("skips exclude_globs unless explicitly targeted, and says when that hid matches", async () => {
    const note = (example: string, glob: string) =>
      `\n\n[Matches in paths skipped by exclude_globs are not shown, e.g. ${example} (${glob}). ` +
      "To include them, pass that file or its directory as path, or a glob that names it.]";
    expect((await call(client, "Grep", { pattern: "NODE_MODULES_NEEDLE" })).text).toBe(
      `No files found${note("/repos/acme/api/node_modules/lib/index.js", "**/node_modules/**")}`,
    );
    expect((await call(client, "Grep", { pattern: "LOCK_NEEDLE", output_mode: "content" })).text).toBe(
      `No matches found${note("/repos/acme/api/package-lock.json", "**/package-lock.json")}`,
    );
    expect((await call(client, "Grep", { pattern: "VENDOR_NEEDLE", output_mode: "count" })).text).toBe(
      `No matches found\n\nFound 0 total occurrences across 0 files.${note("/pr/vendor/lib.js", "**/vendor/**")}`,
    );
    // Shown next to real results too; the user's glob still applies to the probe.
    const mixed = await call(client, "Grep", { pattern: "NEEDLE", path: "/repos/acme/api", glob: "*.json" });
    expect(mixed.text).toBe(`No files found${note("/repos/acme/api/package-lock.json", "**/package-lock.json")}`);
    expect((await call(client, "Grep", { pattern: "NODE_MODULES_NEEDLE", glob: "*.ts" })).text).toBe("No files found");
    expect((await call(client, "Grep", { pattern: "zzz_nothing_here" })).text).toBe("No files found");
    expect((await call(client, "Grep", { pattern: "NODE_MODULES_NEEDLE", path: "/repos/acme/api/node_modules" })).text).toBe(
      "Found 1 file\n/repos/acme/api/node_modules/lib/index.js",
    );
    expect((await call(client, "Grep", { pattern: "LOCK_NEEDLE", glob: "**/package-lock.json" })).text).toBe(
      "Found 1 file\n/repos/acme/api/package-lock.json",
    );
    expect((await call(client, "Grep", { pattern: "VENDOR_NEEDLE", path: "/pr/vendor/lib.js" })).text).toBe("Found 1 file\n/pr/vendor/lib.js");
  });

  it("does not follow symlinks out of a repo", async () => {
    const r = await call(client, "Grep", { pattern: "root:", path: "/repos/acme/api" });
    expect(r.text).toBe("No files found");
    const esc = await call(client, "Grep", { pattern: "x", path: "/pr/etc-link" });
    expect(esc.isError).toBe(true);
    expect(esc.text).toContain("outside its repository");
  });

  it("redacts secrets and PEM key lines in content output", async () => {
    const r = await call(client, "Grep", { pattern: "token", path: "/pr", output_mode: "content" });
    expect(r.text).toBe('/pr/src/config.ts:1:export const token = "[REDACTED:github_token]";');
    expect(r.text).not.toContain(GH_TOKEN);
    const pem = await call(client, "Grep", { pattern: "Zm9vYmFy", output_mode: "content" });
    expect(pem.text).toBe(`/repos/acme/py/keys/test_key.py:5:${PEM_TAG}`);
    const files = await call(client, "Grep", { pattern: "Zm9vYmFy" });
    expect(files.text).toBe("Found 1 file\n/repos/acme/py/keys/test_key.py");
  });

  it("reports matches in an explicitly searched binary file without dumping it", async () => {
    const r = await call(client, "Grep", { pattern: "NEEDLE", path: "/repos/acme/api/bin/logo.png", output_mode: "content" });
    expect(r.text).toBe("/repos/acme/api/bin/logo.png: binary file matches");
    const all = await call(client, "Grep", { pattern: "NEEDLE", path: "/repos/acme/api/bin" });
    expect(all.text).toBe("No files found"); // binary files are skipped during traversal
  });

  it("cuts long lines at 500 characters", async () => {
    const r = await call(client, "Grep", { pattern: "LONGLINE_NEEDLE", output_mode: "content" });
    const prefix = "/repos/acme/api/src/long.ts:1:";
    expect(r.text.startsWith(prefix)).toBe(true);
    expect(r.text.length).toBe(prefix.length + 500 + "… [line truncated]".length);
    expect(r.text.endsWith("… [line truncated]")).toBe(true);
  });

  it("reports pattern and type errors helpfully; agent input is never a flag", async () => {
    const bad = await call(client, "Grep", { pattern: "foo(" });
    expect(bad.isError).toBe(true);
    expect(bad.text).toContain("regex parse error");
    expect(bad.text).toContain("escape literal");
    const type = await call(client, "Grep", { pattern: "x", type: "nosuchtype" });
    expect(type.isError).toBe(true);
    expect(type.text).toContain("nosuchtype");
    const flagType = await call(client, "Grep", { pattern: "x", type: "--files" });
    expect(flagType.isError).toBe(true);
    const flag = await call(client, "Grep", { pattern: "--files" });
    expect(flag.text).toBe("No files found");
    const flagGlob = await call(client, "Grep", { pattern: "helper", glob: "--pre=sh" });
    expect(flagGlob.text).toBe("No files found");
    const long = await call(client, "Grep", { pattern: "a".repeat(1001) });
    expect(long.isError).toBe(true);
    expect(long.text).toContain("max 1000");
  });

  it("validates arguments and accepts numeric strings", async () => {
    const r = await call(client, "Grep", { pattern: "export const G", path: "/repos/acme/api/gen", head_limit: "1" });
    expect(r.text).toContain("[Showing results with pagination = limit: 1, offset: 0]");
    const huge = await call(client, "Grep", { pattern: "export const value", path: "/repos/acme/api/src/many.ts", output_mode: "content", head_limit: 5000 });
    expect(huge.text).toContain("Output truncated");
    const neg = await call(client, "Grep", { pattern: "x", head_limit: -1 });
    expect(neg.isError).toBe(true);
    const ctxCap = await call(client, "Grep", { pattern: "value750 ", path: "/repos/acme/api/src/many.ts", output_mode: "content", context: 50 });
    expect(ctxCap.text.split("\n")).toHaveLength(21);
    const undef = await call(client, "Grep", { pattern: "TODO: tidy", path: "undefined" });
    expect(undef.text).toBe("Found 1 file\n/repos/acme/py/app/main.py");
  });
});

describe("Glob", () => {
  it("finds files across roots as virtual paths", async () => {
    const r = await call(client, "Glob", { pattern: "**/*.py" });
    expect(r.text).toBe(["/repos/acme/py/app/main.py", "/repos/acme/py/app/util.py", "/repos/acme/py/keys/test_key.py"].join("\n"));
    // The PR repo's own base copy is left out unless named (as path or by an absolute pattern).
    const orders = await call(client, "Glob", { pattern: "**/orders.ts" });
    expect(orders.text).toBe(["/pr/src/orders.ts", "/repos/acme/api/src/orders.ts"].join("\n"));
    expect((await call(client, "Glob", { pattern: "**/orders.ts", path: "/repos" })).text).toBe("/repos/acme/api/src/orders.ts");
    expect((await call(client, "Glob", { pattern: "**/orders.ts", path: "/repos/acme/web" })).text).toBe("/repos/acme/web/src/orders.ts");
  });

  it("scopes by path and supports relative and absolute patterns", async () => {
    const scoped = await call(client, "Glob", { pattern: "*.ts", path: "/repos/acme/web" });
    expect(scoped.text).toBe("/repos/acme/web/src/orders.ts");
    const rel = await call(client, "Glob", { pattern: "src/*.ts", path: "/pr" });
    expect(rel.text.split("\n")).toEqual([
      "/pr/src/big-change.ts",
      "/pr/src/config.ts",
      "/pr/src/new.ts",
      "/pr/src/orders.ts",
      "/pr/src/renamed.ts",
    ]);
    const abs = await call(client, "Glob", { pattern: "/repos/*/*/src/orders.ts" });
    expect(abs.text).toBe("/repos/acme/api/src/orders.ts\n/repos/acme/web/src/orders.ts");
    const absDeep = await call(client, "Glob", { pattern: "/repos/acme/py/**/*.py" });
    expect(absDeep.text.split("\n")).toHaveLength(3);
    const top = await call(client, "Glob", { pattern: "/repos/acme/api/*.md" });
    expect(top.text).toBe("/repos/acme/api/README.md");
    const none = await call(client, "Glob", { pattern: "**/*.rs" });
    expect(none.text).toBe("No files found");
  });

  it("truncates at 100 results with Claude Code's note", async () => {
    const r = await call(client, "Glob", { pattern: "**/*.ts", path: "/repos/acme/api/gen" });
    const lines = r.text.split("\n");
    expect(lines).toHaveLength(101);
    expect(lines[0]).toBe("/repos/acme/api/gen/f000.ts");
    expect(lines[100]).toBe("(Results are truncated. Consider using a more specific path or pattern.)");
  });

  it("hides .git and denied files; shows dotfiles; excludes vendored files unless named", async () => {
    expect((await call(client, "Glob", { pattern: "**/.env" })).text).toBe("No files found");
    expect((await call(client, "Glob", { pattern: "**/config" })).text).toBe("No files found");
    expect((await call(client, "Glob", { pattern: "**/*.yml" })).text).toBe("No files found");
    expect((await call(client, "Glob", { pattern: ".eslintrc.json" })).text).toBe("/repos/acme/api/.eslintrc.json");
    expect((await call(client, "Glob", { pattern: "**/*.js" })).text).toBe(
      "No files found\n\n[Files in paths skipped by exclude_globs are not listed, e.g. /pr/vendor/lib.js (**/vendor/**). " +
        "To include them, pass its directory as path or name it in the pattern.]",
    );
    expect((await call(client, "Glob", { pattern: "**/node_modules/**/*.js" })).text).toBe("/repos/acme/api/node_modules/lib/index.js");
    expect((await call(client, "Glob", { pattern: "**/*.json" })).text).toBe(
      "/repos/acme/api/.eslintrc.json\n\n[Files in paths skipped by exclude_globs are not listed, e.g. /repos/acme/api/package-lock.json " +
        "(**/package-lock.json). To include them, pass its directory as path or name it in the pattern.]",
    );
    expect((await call(client, "Glob", { pattern: "**/package-lock.json" })).text).toBe("/repos/acme/api/package-lock.json");
    // symlinks are not listed (no-follow)
    expect((await call(client, "Glob", { pattern: "**/*link*" })).text).toBe("No files found");
  });

  it("errors helpfully", async () => {
    const file = await call(client, "Glob", { pattern: "*", path: "/pr/src/orders.ts" });
    expect(file.isError).toBe(true);
    expect(file.text).toContain("not a directory");
    const rel = await call(client, "Glob", { pattern: "*", path: "src" });
    expect(rel.isError).toBe(true);
    expect(rel.text).toContain("Did you mean /pr/src?");
  });
});

describe("Read", () => {
  it("returns cat -n formatted lines", async () => {
    const r = await call(client, "Read", { file_path: "/repos/acme/py/app/util.py" });
    expect(r.text).toBe("     1\tdef helper():\n     2\t    return 42");
    const w = await call(client, "Read", { file_path: "/repos/acme/api/src/server.ts", offset: 2, limit: 2 });
    expect(w.text).toBe(
      "     2\texport function handle(req: Request) {\n     3\t  // TODO: validate\n[Showing lines 2-3 of 6. Use offset: 4 to read more.]",
    );
    const inner = await call(client, "Read", { file_path: "/repos/acme/api/src/inner-link.ts", limit: 1 });
    expect(inner.text.startsWith("     1\timport { total }")).toBe(true);
    const upper = await call(client, "Read", { file_path: "/repos/ACME/Api/README.md" });
    expect(upper.text).toBe("     1\t# Orders API\n     2\tSee src/server.ts");
  });

  it("handles long lines, binary, empty, short and big files", async () => {
    const long = await call(client, "Read", { file_path: "/repos/acme/api/src/long.ts" });
    expect(long.text.length).toBe(7 + 2000 + "… [line truncated]".length);
    expect((await call(client, "Read", { file_path: "/repos/acme/api/bin/logo.png" })).text).toBe("[binary file]");
    expect((await call(client, "Read", { file_path: "/repos/acme/api/src/empty.ts" })).text).toBe(
      "Warning: the file exists but the contents are empty.",
    );
    expect((await call(client, "Read", { file_path: "/repos/acme/py/app/util.py", offset: 10 })).text).toBe(
      "Warning: the file exists but is shorter than the provided offset (10). The file has 2 lines.",
    );
    const big = await call(client, "Read", { file_path: "/repos/acme/api/src/big.ts" });
    expect(big.isError).toBe(true);
    expect(big.text).toContain("exceeds maximum allowed size");
    expect(big.text).toContain("use offset and limit parameters");
    expect(big.text).toContain("Grep");
    const part = await call(client, "Read", { file_path: "/repos/acme/api/src/big.ts", offset: 2999, limit: 5 });
    expect(part.text).toBe("  2999\t// line 2999 padding\n  3000\t// line 3000 padding");
    const mid = await call(client, "Read", { file_path: "/repos/acme/api/src/big.ts", offset: 10, limit: 1 });
    expect(mid.text).toBe("    10\t// line 10 padding\n[Showing lines 10-10; the file continues. Use offset: 11 to read more.]");
  });

  it("caps output at max_output_chars with a continuation note", async () => {
    // many.ts is larger than max_filesize (20K): reading it needs offset/limit, like Claude Code.
    const r = await call(client, "Read", { file_path: "/repos/acme/api/src/many.ts", offset: 1 });
    expect(r.text.length).toBeLessThanOrEqual(policy.search.max_output_chars);
    const note = /\[Output truncated at 30000 characters: showing lines 1-(\d+)\. Use offset: (\d+) to read more\.\]$/.exec(r.text);
    expect(note).not.toBeNull();
    expect(Number(note![2])).toBe(Number(note![1]) + 1);
    const small = { ...policy, search: { ...policy.search, max_output_chars: 1000 } };
    const c = await connect({ policy: small });
    const s = await call(c, "Read", { file_path: "/repos/acme/api/src/many.ts", offset: 1, limit: 100 });
    expect(s.text.length).toBeLessThanOrEqual(1000);
    expect(s.text).toContain("[Output truncated at 1000 characters");
    const g = await call(c, "Grep", { pattern: "value", path: "/repos/acme/api/src/many.ts", output_mode: "content" });
    expect(g.text.length).toBeLessThanOrEqual(1000);
    expect(g.text).toMatch(/Use offset: \d+ to see more/);
  });

  it("refuses directories, denied files, .git and symlink escapes", async () => {
    const dir = await call(client, "Read", { file_path: "/pr/src" });
    expect(dir.isError).toBe(true);
    expect(dir.text).toContain("is a directory");
    expect(dir.text).toContain("Glob");
    const root = await call(client, "Read", { file_path: "/repos" });
    expect(root.isError).toBe(true);
    expect(root.text).toContain("It contains: /repos/acme/api, /repos/acme/py, /repos/acme/web.");
    for (const p of ["/pr/.env", "/repos/acme/api/.env", "/pr/.git/config", "/repos/acme/py/secrets/db.yml", "/pr/src/nope.ts"]) {
      const r = await call(client, "Read", { file_path: p });
      expect(r.isError).toBe(true);
      expect(r.text).toBe(`Path does not exist: ${p}. Valid roots: /pr, /repos/acme/api, /repos/acme/py, /repos/acme/web.`);
    }
    for (const p of ["/repos/acme/api/src/passwd-link", "/pr/escape.txt"]) {
      const r = await call(client, "Read", { file_path: p });
      expect(r.isError).toBe(true);
      expect(r.text).toContain("outside its repository");
      expect(r.text).not.toContain("TOPSECRET");
      expect(r.text).not.toContain("root:");
    }
  });

  it("rejects malformed and unknown paths with the valid roots", async () => {
    const rel = await call(client, "Read", { file_path: "src/orders.ts" });
    expect(rel.isError).toBe(true);
    expect(rel.text).toContain("Did you mean /pr/src/orders.ts?");
    expect(rel.text).toContain("Valid roots: /pr, /repos/acme/api, /repos/acme/py, /repos/acme/web.");
    const dots = await call(client, "Read", { file_path: "/pr/../mirror/other/secret-repo/current/secret.txt" });
    expect(dots.isError).toBe(true);
    expect(dots.text).toContain('".."');
    const bs = await call(client, "Read", { file_path: "/pr\\src\\orders.ts" });
    expect(bs.isError).toBe(true);
    expect(bs.text).toContain("forward slashes");
    const nul = await call(client, "Read", { file_path: "/pr/src/orders.ts\u0000x" });
    expect(nul.isError).toBe(true);
    for (const p of ["/etc/passwd", "/repos/other/secret-repo/secret.txt", "/repos/acme/denied/secret.txt", "/repos/other"]) {
      const r = await call(client, "Read", { file_path: p });
      expect(r.isError).toBe(true);
      expect(r.text).toContain("Path does not exist");
      expect(r.text.split("Valid roots:")[1]).toBe(" /pr, /repos/acme/api, /repos/acme/py, /repos/acme/web.");
    }
  });

  it("redacts secrets and PEM bodies while keeping line numbers", async () => {
    const cfg = await call(client, "Read", { file_path: "/pr/src/config.ts" });
    expect(cfg.text).toBe('     1\texport const token = "[REDACTED:github_token]";\n     2\texport const region = "eu";');
    const key = await call(client, "Read", { file_path: "/repos/acme/py/keys/test_key.py" });
    expect(key.text.split("\n")).toEqual([
      "     1\t# test fixture",
      '     2\tKEY = """',
      `     3\t${PEM_TAG}`,
      `     4\t${PEM_TAG}`,
      `     5\t${PEM_TAG}`,
      `     6\t${PEM_TAG}`,
      '     7\t"""',
      "     8\tafter = 1",
    ]);
    const window = await call(client, "Read", { file_path: "/repos/acme/py/keys/test_key.py", offset: 4, limit: 1 });
    expect(window.text).toContain(PEM_TAG);
    expect(window.text).not.toContain(B64);
  });

  it("does not redact when the policy turns redaction off", async () => {
    const c = await connect({ policy: { ...policy, search: { ...policy.search, redact_secrets: false } } });
    const r = await call(c, "Read", { file_path: "/pr/src/config.ts" });
    expect(r.text).toContain(GH_TOKEN);
  });
});

describe("PrDiff", () => {
  it("lists changed files like the SPEC", async () => {
    const r = await call(client, "PrDiff");
    expect(r.text.split("\n")).toEqual([
      "M  +1 -1  /pr/src/orders.ts",
      "A  +2 -0  /pr/src/new.ts",
      "D  +0 -1  /pr/src/gone.ts",
      "R  +1 -1  /pr/src/old-name.ts -> /pr/src/renamed.ts",
      "M  +1 -1  /pr/.env  [content hidden by policy]",
      "M  +0 -0  /pr/img/logo.png  (binary)",
      "A  +50 -0  /pr/src/big-change.ts",
    ]);
    expect(r.text).not.toContain("ignored.md");
  });

  it("shows one file's unified diff with new-side hunk headers", async () => {
    const r = await call(client, "PrDiff", { file_path: "/pr/src/orders.ts" });
    expect(r.text).toBe(
      [
        "diff --git a/src/orders.ts b/src/orders.ts",
        "index 1111111..2222222 100644",
        "--- a/src/orders.ts",
        "+++ b/src/orders.ts",
        "@@ -1,3 +1,3 @@",
        " export function total(items: number[]): number {",
        "-  return items.reduce((a, b) => a + b, 0);",
        "+  return items.reduce((a, b) => a + b, 1);",
        " }",
      ].join("\n"),
    );
    const renamedByOld = await call(client, "PrDiff", { file_path: "/pr/src/old-name.ts" });
    expect(renamedByOld.text).toContain("rename to src/renamed.ts");
    const bin = await call(client, "PrDiff", { file_path: "/pr/img/logo.png" });
    expect(bin.text.endsWith("[binary file]")).toBe(true);
  });

  it("windows long diffs with offset/limit", async () => {
    const r = await call(client, "PrDiff", { file_path: "/pr/src/big-change.ts", offset: 7, limit: 3 });
    expect(r.text).toBe(
      ["+export const C1 = 1;", "+export const C2 = 2;", "+export const C3 = 3;", "[Showing diff lines 7-9 of 56. Use offset: 10 to see more.]"].join("\n"),
    );
    const list = await call(client, "PrDiff", { limit: 2 });
    expect(list.text).toBe("M  +1 -1  /pr/src/orders.ts\nA  +2 -0  /pr/src/new.ts\n[Showing files 1-2 of 7. Use offset: 3 to see more.]");
  });

  it("hides denied files and rejects files outside the PR", async () => {
    const env = await call(client, "PrDiff", { file_path: "/pr/.env" });
    expect(env.isError).toBe(false);
    expect(env.text).toBe("M  +1 -1  /pr/.env  [content hidden by policy]\n[content hidden by policy]");
    expect(env.text).not.toContain("secret-value");
    const notChanged = await call(client, "PrDiff", { file_path: "/pr/src/config.ts" });
    expect(notChanged.isError).toBe(true);
    expect(notChanged.text).toContain("is not changed in this PR");
    const ignored = await call(client, "PrDiff", { file_path: "/pr/docs/ignored.md" });
    expect(ignored.isError).toBe(true);
    const mirror = await call(client, "PrDiff", { file_path: "/repos/acme/api/src/orders.ts" });
    expect(mirror.isError).toBe(true);
    expect(mirror.text).toContain("under /pr");
    const guess = await call(client, "PrDiff", { file_path: "/pr/orders.ts" });
    expect(guess.text).toContain("Did you mean /pr/src/orders.ts?");
  });
});

describe("audit and startup", () => {
  it("audits every call", async () => {
    const file = join(base, "audit.jsonl");
    const prev = process.env.XREPO_AUDIT_FILE;
    process.env.XREPO_AUDIT_FILE = file;
    try {
      await call(client, "Grep", { pattern: "TODO", output_mode: "content" });
      await call(client, "Read", { file_path: "/nope" });
      expect((await call(client, "Grep", {})).isError).toBe(true); // schema validation error
      expect((await call(client, "Bash", { command: "id" })).isError).toBe(true); // unknown tool
    } finally {
      if (prev === undefined) delete process.env.XREPO_AUDIT_FILE;
      else process.env.XREPO_AUDIT_FILE = prev;
    }
    const events = readFileSync(file, "utf8")
      .trim()
      .split("\n")
      .map((l) => JSON.parse(l) as Record<string, unknown>);
    const calls = events.filter((e) => e.event === "xsearch.call");
    expect(calls).toHaveLength(4);
    expect(calls[0]).toMatchObject({ tool: "Grep", ok: true, truncated: false, args: { pattern: "TODO", output_mode: "content" } });
    expect(typeof calls[0]!.chars).toBe("number");
    expect(calls[1]).toMatchObject({ tool: "Read", ok: false });
    expect(calls[2]).toMatchObject({ tool: "Grep", ok: false, rejected: true });
    expect(calls[3]).toMatchObject({ tool: "Bash", ok: false, rejected: true });
  });

  it("reports a missing ripgrep binary", async () => {
    const c = await connect({ rgPath: join(base, "no-such-rg") });
    const r = await call(c, "Grep", { pattern: "x" });
    expect(r.isError).toBe(true);
    expect(r.text).toContain("ripgrep (rg) is not installed");
    expect(r.text).not.toContain(base);
  });

  it("kills ripgrep at the policy timeout", async () => {
    const fake = join(base, "slow-rg.sh");
    writeFileSync(fake, "#!/bin/sh\nsleep 5\n", { mode: 0o755 });
    const slow = { ...policy, search: { ...policy.search, timeout_ms: 500 } };
    const c = await connect({ policy: slow, rgPath: fake });
    const t0 = Date.now();
    const r = await call(c, "Grep", { pattern: "x", path: "/pr" });
    expect(Date.now() - t0).toBeLessThan(3000);
    expect(r.isError).toBe(true);
    expect(r.text).toBe("Search timed out after 500ms. Narrow it with path, glob or type.");
    const g = await call(c, "Glob", { pattern: "*.ts", path: "/pr" });
    expect(g.isError).toBe(true);
    expect(g.text).toContain("timed out");
  });

  it("main: usage and startup errors", async () => {
    expect(await main([])).toBe(2);
    expect(await main(["--ctx", ctxDir])).toBe(2);
    expect(await main(["--ctx", join(base, "missing"), "--pr", prDir])).toBe(1);
  });

  it("main: serves MCP over stdio until stdin closes", async () => {
    const stdin = new PassThrough();
    const stdout = new PassThrough();
    let out = "";
    stdout.on("data", (d: Buffer) => (out += d.toString("utf8")));
    const done = main(["--ctx", ctxDir, "--pr", prDir, "--mirror", mirrorDir], { stdin, stdout });
    const send = (msg: unknown) => stdin.write(`${JSON.stringify(msg)}\n`);
    send({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "t", version: "1" } } });
    send({ jsonrpc: "2.0", method: "notifications/initialized" });
    send({ jsonrpc: "2.0", id: 2, method: "tools/call", params: { name: "ListRepos", arguments: {} } });
    for (let i = 0; i < 100 && !out.includes('"id":2'); i++) await new Promise((r) => setTimeout(r, 20));
    stdin.end();
    expect(await done).toBe(0);
    const reply = out
      .trim()
      .split("\n")
      .map((l) => JSON.parse(l) as { id?: number; result?: { content: { text: string }[] } })
      .find((m) => m.id === 2);
    expect(reply?.result?.content[0]?.text).toContain("/repos/acme/api");
  });
});

describe("internals", () => {
  it("discoverMirror skips broken layouts", () => {
    const m = join(base, "mirror2");
    const good = join(m, "o", "good");
    write(join(good, "snapshots", SHA_API, "a.txt"), "a");
    symlinkSync(`snapshots/${SHA_API}`, join(good, "current"));
    write(join(good, "meta.json"), JSON.stringify({ repo: "o/good", sha: SHA_API, branch: "main", synced_at: "", description: "" }));
    const abs = join(m, "o", "abs");
    write(join(abs, "snapshots", SHA_API, "a.txt"), "a");
    symlinkSync(join(abs, "snapshots", SHA_API), join(abs, "current")); // absolute link: rejected
    write(join(abs, "meta.json"), JSON.stringify({ repo: "o/abs" }));
    const wrong = join(m, "o", "wrong");
    write(join(wrong, "snapshots", SHA_API, "a.txt"), "a");
    symlinkSync(`snapshots/${SHA_API}`, join(wrong, "current"));
    write(join(wrong, "meta.json"), JSON.stringify({ repo: "o/other" })); // identity mismatch
    const nometa = join(m, "o", "nometa");
    write(join(nometa, "snapshots", SHA_API, "a.txt"), "a");
    symlinkSync(`snapshots/${SHA_API}`, join(nometa, "current"));
    expect(discoverMirror(m).map((r) => r.repo)).toEqual(["o/good"]);
    expect(discoverMirror(join(base, "nope"))).toEqual([]);
    expect(discoverMirror(undefined)).toEqual([]);
  });

  it("Vfs parse rules", () => {
    const vfs = new Vfs({ prDir, prRepo: "acme/web", mirror: [], denyGlobs: ["**/.env"] });
    expect(vfs.parse("/").kind).toBe("vdir");
    expect(vfs.parse("/pr/./src//a.ts")).toMatchObject({ kind: "repo", rel: "src/a.ts", vpath: "/pr/src/a.ts" });
    expect(() => vfs.parse("/repos")).toThrow(VfsError);
    expect(() => vfs.parse("/pr/a/../b")).toThrow(/\.\./);
    expect(vfs.isHidden(".git")).toBe(true);
    expect(vfs.isHidden("a/.GIT/x")).toBe(true);
    expect(vfs.isHidden("x/.env")).toBe(true);
    expect(vfs.isHidden("x/env")).toBe(false);
  });

  it("ExcludeSet targeting and rg-safe globs", () => {
    const ex = new ExcludeSet(["**/node_modules/**", "**/*.min.js", "**/package-lock.json", "build/**"]);
    expect(ex.active([""], [])).toEqual(["**/node_modules/**", "**/*.min.js", "**/package-lock.json", "build/**"]);
    expect(ex.active(["node_modules/x"], [])).not.toContain("**/node_modules/**");
    expect(ex.active([""], ["**/*.min.js"])).not.toContain("**/*.min.js");
    expect(ex.active([""], ["*.js"])).toContain("**/*.min.js");
    expect(ex.active(["build"], [])).not.toContain("build/**");
    expect(isCwdIndependentGlob("**/x/**")).toBe(true);
    expect(isCwdIndependentGlob("*.pem")).toBe(true);
    expect(isCwdIndependentGlob("secrets/")).toBe(true);
    expect(isCwdIndependentGlob("config/prod")).toBe(false);
    expect(isCwdIndependentGlob("/build")).toBe(false);
    expect(isCwdIndependentGlob("!x")).toBe(false);
  });

  it("splits glob parameters like Claude Code", () => {
    expect(splitGlobParam("*.ts,*.tsx")).toEqual(["*.ts", "*.tsx"]);
    expect(splitGlobParam("*.{ts,tsx} *.js")).toEqual(["*.{ts,tsx}", "*.js"]);
    expect(splitGlobParam(undefined)).toEqual([]);
  });

  it("PEM tracking is line-preserving and bounded", () => {
    const text = ["a", "-----BEGIN PRIVATE KEY-----", B64, "-----END PRIVATE KEY-----", "b"].join("\n");
    expect([...pemLineSet(text)]).toEqual([2, 3, 4]);
    const unterminated = ["-----BEGIN EC PRIVATE KEY-----", B64, "this is prose, not base64!", "x"].join("\n");
    expect([...pemLineSet(unterminated)]).toEqual([1, 2]);
    const t = new PemTracker();
    expect(t.step('k = "-----BEGIN PRIVATE KEY-----\\nABC\\n-----END PRIVATE KEY-----"')).toBeNull();
    // The streaming tracker (huge files only) has no lookahead: it hides everything up to END.
    const evil = "+".repeat(5000) + "!";
    const t0 = Date.now();
    const t2 = new PemTracker();
    expect(t2.step('KEY = "-----BEGIN PRIVATE KEY-----')).toBe(`KEY = "${PEM_TAG}`);
    expect(t2.step(evil)).toBe(PEM_TAG);
    expect(t2.step("prose, not base64")).toBe(PEM_TAG);
    expect(t2.step("-----END PRIVATE KEY-----")).toBe(PEM_TAG);
    expect(t2.step("after")).toBeNull();
    expect(Date.now() - t0).toBeLessThan(200);
    const t3 = new PemTracker();
    t3.step("-----BEGIN PRIVATE KEY-----");
    expect(t3.step("x".repeat(PEM_MAX_BLOCK))).toBeNull(); // past the 64 KiB bound: unterminated
    expect(t3.step("y")).toBeNull();
  });

  it("pemLineMap follows redactPem's block rules", () => {
    // END within 64 KiB: every line in between is key material, whatever it looks like.
    const block = ["x = (", '    b"-----BEGIN RSA PRIVATE KEY-----\\n"', `    b"${B64}\\n"`, "    # not base64 at all!", '    b"-----END RSA PRIVATE KEY-----\\n"', ")"];
    expect([...pemLineMap(block.join("\n"))]).toEqual([
      [2, `    b"${PEM_TAG}`],
      [3, PEM_TAG],
      [4, PEM_TAG],
      [5, PEM_TAG],
    ]);
    // END further than 64 KiB away does not close the block: body heuristic (decorated base64).
    const far = ["-----BEGIN PRIVATE KEY-----", `// ${B64}`, `    b"${B64}\\n"`, "AbCdXyz1234==", "prose ends it", "z".repeat(PEM_MAX_BLOCK), "-----END PRIVATE KEY-----"];
    expect([...pemLineSet(far.join("\n"))]).toEqual([1, 2, 3, 4]);
    // A BEGIN on the END line of a previous block starts a new block; the END line hides both.
    const chained = ["-----BEGIN PRIVATE KEY-----", B64, "-----END PRIVATE KEY----------BEGIN EC PRIVATE KEY-----", B64, "-----END EC PRIVATE KEY-----", "ok"];
    expect(pemLineMap(chained.join("\n")).get(3)).toBe(PEM_TAG);
    expect([...pemLineSet(chained.join("\n"))]).toEqual([1, 2, 3, 4, 5]);
    // One-line keys are left to redactSecrets; secrets before a BEGIN marker are redacted.
    expect(pemLineSet('k = "-----BEGIN PRIVATE KEY-----\\nABC\\n-----END PRIVATE KEY-----"').size).toBe(0);
    expect(pemLineMap(`t = "${GH_TOKEN}"; k = "-----BEGIN PRIVATE KEY-----\n${B64}\n-----END PRIVATE KEY-----`).get(1)).toBe(
      `t = "[REDACTED:github_token]"; k = "${PEM_TAG}`,
    );
    // Linear on hostile input: many BEGIN markers without any END.
    const many = Array.from({ length: 20000 }, () => "-----BEGIN PRIVATE KEY-----").join("\n");
    const t0 = Date.now();
    expect(pemLineSet(many).size).toBe(20000);
    expect(Date.now() - t0).toBeLessThan(1000);
  });

  it("finalizeOutput caps at a line boundary", () => {
    const text = Array.from({ length: 200 }, (_, i) => `line ${i}`).join("\n");
    const out = finalizeOutput(text, { redact: true, maxChars: 1000 });
    expect(out.truncated).toBe(true);
    expect(out.text.length).toBeLessThanOrEqual(1000);
    expect(out.text.endsWith("or use offset/limit.]")).toBe(true);
    expect(finalizeOutput(text, { redact: true, maxChars: 1000, hint: "Use offset/limit to page through the list." }).text.endsWith(
      "characters. Use offset/limit to page through the list.]",
    )).toBe(true);
    expect(finalizeOutput(`x ${GH_TOKEN}`, { redact: true, maxChars: 1000 }).text).toBe("x [REDACTED:github_token]");
  });
});

/* ------------------------- regressions (review round 1) ------------------------- */

describe("PEM blocks in any format are hidden by Read and Grep (pem-tracker-redaction-bypass)", () => {
  const B64B = "Zm9vYmFyYmF6cXV4cXV1eGNvcmdlZ3JhdWx0Z2FycGx5d2FsZG9mcmVkcGx1Z3h5";
  const TAIL = "AbCdXyz1234==";
  const UNWRAPPED = `MII${"QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo".repeat(15)}`; // > 500 chars, one line
  let c: Client;
  let m2: string;

  beforeAll(async () => {
    m2 = join(base, "mirror-pem");
    mirrorRepo(
      "acme/keys",
      "3333333333333333333333333333333333333333",
      {
        "tests/keys.py": [
          "KEY = (",
          '    b"-----BEGIN RSA PRIVATE KEY-----\\n"',
          `    b"${B64}\\n"`,
          `    b"${B64B}\\n"`,
          `    b"${TAIL}\\n"`,
          '    b"-----END RSA PRIVATE KEY-----\\n"',
          ")",
          "OTHER = 1",
          "",
        ].join("\n"),
        "tests/key.js": ["const k = [", "// -----BEGIN PRIVATE KEY-----", `// ${B64}`, `// ${TAIL}`, "// -----END PRIVATE KEY-----", "];", ""].join("\n"),
        "tests/unwrapped.txt": ["-----BEGIN PRIVATE KEY-----", UNWRAPPED, "-----END PRIVATE KEY-----", "done", ""].join("\n"),
        "tests/wrapped.pemtxt": ["-----BEGIN PRIVATE KEY-----", B64, B64B, TAIL, "-----END PRIVATE KEY-----", ""].join("\n"),
        "big/huge.py":
          Array.from({ length: 400 }, (_, i) => `# filler line ${i + 1} ${"f".repeat(40)}`).join("\n") +
          "\n" +
          ['KEY = (', '    b"-----BEGIN RSA PRIVATE KEY-----\\n"', `    b"${B64}\\n"`, `    b"${TAIL}\\n"`, '    b"-----END RSA PRIVATE KEY-----\\n"', ")", "AFTER = 2", ""].join("\n"),
      },
      "",
      m2,
    );
    c = await connect({ mirrorDir: m2 });
  });

  const fragments = [B64, B64B, TAIL, UNWRAPPED.slice(0, 40), "MIIEowIBAAKCAQEA", "AbCdXyz"];
  const noKey = (text: string) => {
    for (const f of fragments) expect(text).not.toContain(f);
  };

  it("Read hides b\"...\" concatenated, comment-prefixed and unwrapped key bodies", async () => {
    const py = await call(c, "Read", { file_path: "/repos/acme/keys/tests/keys.py" });
    expect(py.text.split("\n")).toEqual([
      "     1\tKEY = (",
      `     2\t    b"${PEM_TAG}`,
      `     3\t${PEM_TAG}`,
      `     4\t${PEM_TAG}`,
      `     5\t${PEM_TAG}`,
      `     6\t${PEM_TAG}`,
      "     7\t)",
      "     8\tOTHER = 1",
    ]);
    // A window that starts inside the block still hides it.
    const win = await call(c, "Read", { file_path: "/repos/acme/keys/tests/keys.py", offset: 4, limit: 2 });
    expect(win.text).toBe(`     4\t${PEM_TAG}\n     5\t${PEM_TAG}\n[Showing lines 4-5 of 8. Use offset: 6 to read more.]`);
    for (const f of ["tests/key.js", "tests/unwrapped.txt", "tests/wrapped.pemtxt"]) {
      const r = await call(c, "Read", { file_path: `/repos/acme/keys/${f}` });
      expect(r.isError, f).toBe(false);
      noKey(r.text);
    }
    const un = await call(c, "Read", { file_path: "/repos/acme/keys/tests/unwrapped.txt" });
    expect(un.text).toBe([`     1\t${PEM_TAG}`, `     2\t${PEM_TAG}`, `     3\t${PEM_TAG}`, "     4\tdone"].join("\n"));
  });

  it("Read is never weaker than redactSecrets on the raw file", async () => {
    const snap = join(m2, "acme", "keys", "snapshots", "3333333333333333333333333333333333333333");
    for (const f of ["tests/keys.py", "tests/key.js", "tests/unwrapped.txt", "tests/wrapped.pemtxt"]) {
      const raw = readFileSync(join(snap, f), "utf8");
      const whole = redactSecrets(raw).text;
      for (const fr of fragments) expect(whole).not.toContain(fr); // the reference hides them…
      noKey((await call(c, "Read", { file_path: `/repos/acme/keys/${f}` })).text); // …and so does Read
    }
  });

  it("Grep content mode hides every line of a key block, matched alone or with context", async () => {
    for (const pattern of ["MII|Zm9v", "AbCdXyz", "QUJDREVG", "-----END"]) {
      const r = await call(c, "Grep", { pattern, output_mode: "content", path: "/repos/acme/keys/tests" });
      expect(r.isError, pattern).toBe(false);
      expect(r.text, pattern).toContain(PEM_TAG);
      noKey(r.text);
    }
    const tail = await call(c, "Grep", { pattern: "AbCdXyz1234", output_mode: "content", path: "/repos/acme/keys/tests/keys.py" });
    expect(tail.text).toBe(`/repos/acme/keys/tests/keys.py:5:${PEM_TAG}`);
    const ctx = await call(c, "Grep", { pattern: "OTHER", output_mode: "content", "-B": 4, path: "/repos/acme/keys/tests/keys.py" });
    expect(ctx.text.split("\n")).toEqual([
      `/repos/acme/keys/tests/keys.py-4-${PEM_TAG}`,
      `/repos/acme/keys/tests/keys.py-5-${PEM_TAG}`,
      `/repos/acme/keys/tests/keys.py-6-${PEM_TAG}`,
      "/repos/acme/keys/tests/keys.py-7-)",
      "/repos/acme/keys/tests/keys.py:8:OTHER = 1",
    ]);
    const o = await call(c, "Grep", { pattern: "[A-Za-z0-9+/]{20,}", output_mode: "content", "-o": true, path: "/repos/acme/keys" });
    noKey(o.text);
  });

  it("files above the scan size are streamed and hide everything from BEGIN to END", async () => {
    const small = { ...policy, search: { ...policy.search, max_filesize: "1K" } }; // scan limit 8K < huge.py
    const s = await connect({ mirrorDir: m2, policy: small });
    const r = await call(s, "Read", { file_path: "/repos/acme/keys/big/huge.py", offset: 400, limit: 10 });
    expect(r.text.split("\n").slice(0, 8)).toEqual([
      expect.stringContaining("filler line 400"),
      "   401\tKEY = (",
      `   402\t    b"${PEM_TAG}`,
      `   403\t${PEM_TAG}`,
      `   404\t${PEM_TAG}`,
      `   405\t${PEM_TAG}`,
      "   406\t)",
      "   407\tAFTER = 2",
    ]);
    noKey(r.text);
  });
});

describe("deny globs match case-insensitively (deny-globs-case-sensitive)", () => {
  let c: Client;
  let m3: string;
  let pr3: string;

  beforeAll(async () => {
    m3 = join(base, "mirror-case");
    pr3 = join(base, "pr-case");
    mirrorRepo(
      "acme/cs",
      "4444444444444444444444444444444444444444",
      {
        "Config/Secrets/prod.yml": "password: CASE_SECRET_1\n",
        "certs/Server.Key": "CASE_SECRET_2\n",
        ".ENV": "DB_PASSWORD=CASE_SECRET_3\n",
        "x/.Env.local": "DB_PASSWORD=CASE_SECRET_4\n",
        "ID_RSA": "CASE_SECRET_5\n",
        "keys/KEY.PEM": "CASE_SECRET_6\n",
        "SECRETS/a.txt": "CASE_SECRET_7\n",
        "src/ok.ts": "export const ok = 'CASE_PUBLIC';\n",
      },
      "",
      m3,
    );
    write(join(pr3, ".ENV"), "CASE_SECRET_8\n");
    write(join(pr3, "Secrets/db.yml"), "password: CASE_SECRET_9\n");
    write(join(pr3, "server.PEM"), "CASE_SECRET_10\n");
    write(join(pr3, "src/a.ts"), "export const a = 'CASE_PUBLIC';\n");
    c = await connect({ mirrorDir: m3, prDir: pr3 });
  });

  it("Grep, Glob and Read treat case variants of default deny globs as missing", async () => {
    for (const mode of ["files_with_matches", "content", "count"]) {
      const r = await call(c, "Grep", { pattern: "CASE_", output_mode: mode });
      expect(r.text, mode).not.toContain("CASE_SECRET");
      expect(r.text, mode).toContain("CASE_PUBLIC".slice(0, 0) || "/pr/src/a.ts");
      expect(r.text, mode).toContain("/repos/acme/cs/src/ok.ts");
      expect(r.text, mode).not.toMatch(/Secrets|Server\.Key|\.ENV|\.Env|ID_RSA|KEY\.PEM|SECRETS|server\.PEM/);
    }
    const all = await call(c, "Glob", { pattern: "**/*" });
    expect(all.text).toBe("/pr/src/a.ts\n/repos/acme/cs/src/ok.ts");
    const named = await call(c, "Grep", { pattern: "CASE_SECRET", glob: "**/*.PEM" });
    expect(named.text).toBe("No files found");
    for (const p of [
      "/pr/.ENV",
      "/pr/Secrets/db.yml",
      "/pr/server.PEM",
      "/repos/acme/cs/Config/Secrets/prod.yml",
      "/repos/acme/cs/certs/Server.Key",
      "/repos/acme/cs/.ENV",
      "/repos/acme/cs/x/.Env.local",
      "/repos/acme/cs/ID_RSA",
      "/repos/acme/cs/keys/KEY.PEM",
      "/repos/acme/cs/SECRETS/a.txt",
    ]) {
      const r = await call(c, "Read", { file_path: p });
      expect(r.isError, p).toBe(true);
      expect(r.text, p).toContain(`Path does not exist: ${p}`);
    }
    const dir = await call(c, "Grep", { pattern: "CASE", path: "/repos/acme/cs/Config/Secrets" });
    expect(dir.isError).toBe(true);
  });

  it("Vfs.isHidden: upper- and mixed-case variants of every default deny pattern", () => {
    const vfs = new Vfs({ prDir: pr3, prRepo: "acme/web", mirror: [], denyGlobs: [...DEFAULT_DENY_GLOBS] });
    for (const p of [
      ".ENV",
      "a/.Env",
      ".ENV.LOCAL",
      "x/.env.Production",
      "Server.PEM",
      "a/b/KEY.Key",
      "cert.P12",
      "cert.PFX",
      "ID_RSA",
      "home/Id_Rsa.pub",
      "ID_ED25519",
      ".NPMRC",
      ".PyPirc",
      ".NETRC",
      "Secrets/db.yml",
      "a/SECRETS/b/c.txt",
      "infra/Main.TFSTATE",
      "infra/x.TfState.backup",
    ]) {
      expect(vfs.isHidden(p), p).toBe(true);
    }
    for (const p of ["src/env.ts", "secret.ts", "docs/pem.md", "Secretsauce/x.ts"]) expect(vfs.isHidden(p), p).toBe(false);
    // Custom deny globs too.
    const custom = new Vfs({ prDir: pr3, prRepo: "acme/web", mirror: [], denyGlobs: ["**/Private/**", "*.Credentials.json"] });
    expect(custom.isHidden("a/PRIVATE/b")).toBe(true);
    expect(custom.isHidden("prod.credentials.JSON")).toBe(true);
  });
});

describe("the policy manifest is hidden in mirrors (hosted-policy-readable-via-mirror)", () => {
  let m4: string;
  const POLICY = "# xrepo-review policy manifest\nversion: 1\ncross_repo:\n  deny: [\"acme/secrets-vault\"]\n";

  beforeAll(() => {
    m4 = join(base, "mirror-policy");
    mirrorRepo(
      "acme/xrepo-review",
      "5555555555555555555555555555555555555555",
      {
        ".github/xrepo/policy.yaml": POLICY,
        ".github/xrepo/notes.md": "secrets-vault\n",
        ".GitHub/XRepo/other.yaml": POLICY,
        "config/review-policy.yml": POLICY,
        "src/cli.ts": "export const cli = 'secrets-vault-free';\n",
      },
      "",
      m4,
    );
  });

  it("hides .github/xrepo/ in every /repos root, and --policy-path when given", async () => {
    const c = await connect({ mirrorDir: m4, policyPath: "./config/review-policy.yml" });
    expect((await call(c, "ListRepos")).text).toContain("/repos/acme/xrepo-review");
    for (const p of [
      "/repos/acme/xrepo-review/.github/xrepo/policy.yaml",
      "/repos/acme/xrepo-review/.github/xrepo",
      "/repos/acme/xrepo-review/.GitHub/XRepo/other.yaml",
      "/repos/acme/xrepo-review/config/review-policy.yml",
      "/repos/acme/xrepo-review/Config/Review-Policy.yml",
    ]) {
      const r = await call(c, "Read", { file_path: p });
      expect(r.isError, p).toBe(true);
      expect(r.text, p).toContain("Path does not exist");
    }
    for (const mode of ["files_with_matches", "content", "count"]) {
      const g = await call(c, "Grep", { pattern: "secrets-vault", output_mode: mode });
      expect(g.text, mode).not.toMatch(/policy|notes\.md|other\.yaml|deny/);
      expect(g.text, mode).toContain("/repos/acme/xrepo-review/src/cli.ts");
    }
    const explicit = await call(c, "Grep", { pattern: "secrets-vault", path: "/repos/acme/xrepo-review/.github" });
    expect(explicit.text).toBe("No files found");
    const files = await call(c, "Glob", { pattern: "/repos/acme/xrepo-review/**" });
    expect(files.text).toBe("/repos/acme/xrepo-review/src/cli.ts");
    const dir = await call(c, "Read", { file_path: "/repos/acme/xrepo-review/config" });
    expect(dir.text).toContain("(empty)");
    // Without --policy-path only the default location is hidden.
    const d = await connect({ mirrorDir: m4 });
    expect((await call(d, "Read", { file_path: "/repos/acme/xrepo-review/config/review-policy.yml" })).isError).toBe(false);
    expect((await call(d, "Read", { file_path: "/repos/acme/xrepo-review/.github/xrepo/policy.yaml" })).isError).toBe(true);
  });

  it("does not hide the PR checkout's own copy (the PR author can read it anyway)", async () => {
    const vfs = new Vfs({ prDir, prRepo: "acme/web", mirror: [], denyGlobs: [], mirrorHiddenGlobs: ["/config/p.yml"] });
    expect(vfs.isHidden(".github/xrepo/policy.yaml", vfs.prRoot)).toBe(false);
    expect(vfs.isHidden("config/p.yml", vfs.prRoot)).toBe(false);
    const mirrorRoot = { vpath: "/repos/a/b", kind: "mirror" as const, repo: "a/b", host: prDir };
    expect(vfs.isHidden(".github/xrepo/policy.yaml", mirrorRoot)).toBe(true);
    expect(vfs.isHidden("config/p.yml", mirrorRoot)).toBe(true);
    expect(vfs.isHidden("sub/config/p.yml", mirrorRoot)).toBe(false);
  });

  it("validates --policy-path", async () => {
    expect(policyPathGlob(".github/xrepo/policy.yaml")).toBe("/.github/xrepo/policy.yaml");
    expect(policyPathGlob("./a/[x]*.yml")).toBe("/a/\\[x\\]\\*.yml");
    for (const bad of ["/etc/policy.yaml", "../x.yml", "a/../../b", "", "a\\b"]) expect(() => policyPathGlob(bad), bad).toThrow();
    expect(await main(["--ctx", ctxDir, "--pr", prDir, "--policy-path", "../escape.yml"])).toBe(2);
  });
});

describe("repos whose name starts with '.' are served (dot-named-mirror-repos-invisible)", () => {
  it("discovers, lists, reads and searches acme/.github", async () => {
    const m5 = join(base, "mirror-dot");
    mirrorRepo("acme/.github", "6666666666666666666666666666666666666666", { "workflows/ci.yml": "name: DOT_REPO_NEEDLE\n" }, "Org defaults", m5);
    mirrorRepo("acme/api", SHA_API, { "a.ts": "x\n" }, "", m5);
    expect(discoverMirror(m5).map((r) => r.repo)).toEqual(["acme/.github", "acme/api"]);
    const c = await connect({ mirrorDir: m5 });
    expect((await call(c, "ListRepos")).text).toContain("/repos/acme/.github  6666666  synced 3m ago  Org defaults");
    expect((await call(c, "Read", { file_path: "/repos/acme/.github/workflows/ci.yml" })).text).toBe("     1\tname: DOT_REPO_NEEDLE");
    expect((await call(c, "Grep", { pattern: "DOT_REPO_NEEDLE" })).text).toBe("Found 1 file\n/repos/acme/.github/workflows/ci.yml");
    expect((await call(c, "Glob", { pattern: "/repos/acme/.github/**/*.yml" })).text).toBe("/repos/acme/.github/workflows/ci.yml");
  });

  it("isMirrorRepoName: leading '.' only for the repository name, never '.', '..' or '.git'", () => {
    for (const ok of ["acme/.github", "acme/.dotfiles", "acme/api", "a-b/c.d"]) expect(isMirrorRepoName(ok), ok).toBe(true);
    for (const bad of [".acme/api", "acme/.", "acme/..", "acme/.git", "acme/.GIT", "acme", "a/b/c", "acme/a b", "acme/"]) {
      expect(isMirrorRepoName(bad), bad).toBe(false);
    }
  });
});

describe("unknown parameters are rejected with a hint (xsearch-unknown-params-silently-dropped)", () => {
  it("names the right parameter instead of running with defaults", async () => {
    const limit = await call(client, "Grep", { pattern: "export const G", path: "/repos/acme/api/gen", limit: 5 });
    expect(limit.isError).toBe(true);
    expect(limit.text).toContain('Unknown parameter "limit" (use head_limit instead).');
    expect(limit.text).toContain("Grep accepts only: pattern, path, glob, output_mode,");
    const include = await call(client, "Grep", { pattern: "x", include: "*.d.ts", foo: 1 });
    expect(include.isError).toBe(true);
    expect(include.text).toContain('Unknown parameters "include" (use glob instead), "foo".');
    const read = await call(client, "Read", { file_path: "/repos/acme/api/src/server.ts", start_line: 2, end_line: 3 });
    expect(read.isError).toBe(true);
    expect(read.text).toContain('"start_line" (use offset (the first line to read, 1-based) instead)');
    expect(read.text).toContain('"end_line" (use limit (the number of lines: end_line - offset + 1) instead)');
    const glob = await call(client, "Glob", { pattern: "*.ts", root: "/repos/acme/api" });
    expect(glob.text).toContain('"root" (use path instead)');
    const repos = await call(client, "ListRepos", { verbose: true });
    expect(repos.isError).toBe(true);
    expect(repos.text).toContain("ListRepos accepts only: offset, limit.");
    const diff = await call(client, "PrDiff", { path: "/pr/src/orders.ts" });
    expect(diff.text).toContain('"path" (use file_path instead)');
  });

  it("advertises additionalProperties: false", async () => {
    const { tools } = await client.listTools();
    for (const t of tools) expect((t.inputSchema as Record<string, unknown>).additionalProperties, t.name).toBe(false);
  });
});

describe("Grep -o (only-matching)", () => {
  it("prints each match part on its own line, numbered by its line", async () => {
    const r = await call(client, "Grep", { pattern: "helper\\(\\)", output_mode: "content", "-o": true });
    expect(r.text).toBe("/repos/acme/py/app/main.py:5:helper()\n/repos/acme/py/app/util.py:1:helper()");
    const two = await call(client, "Grep", { pattern: "[ab]\\b", path: "/pr/src/orders.ts", output_mode: "content", "-o": true });
    expect(two.text.split("\n").slice(0, 2)).toEqual(["/pr/src/orders.ts:2:a", "/pr/src/orders.ts:2:b"]);
    const files = await call(client, "Grep", { pattern: "helper\\(\\)", "-o": true });
    expect(files.text).toBe("Found 2 files\n/repos/acme/py/app/main.py\n/repos/acme/py/app/util.py");
  });

  it("never reveals part of a secret the whole line would redact", async () => {
    const r = await call(client, "Grep", { pattern: "ghp_[A-Za-z0-9]{30}", path: "/pr", output_mode: "content", "-o": true });
    expect(r.text).toBe('/pr/src/config.ts:1:export const token = "[REDACTED:github_token]";');
    expect(r.text).not.toContain(GH_TOKEN.slice(0, 12));
  });
});

describe("tool descriptions", () => {
  it("Read steers to offset/limit windows (read-description-recommends-whole-file)", async () => {
    const { tools } = await client.listTools();
    const read = tools.find((t) => t.name === "Read")!.description!;
    expect(read).toContain("Prefer offset/limit windows around Grep hits (typically 40-150 lines)");
    expect(read).not.toContain("recommended to read the whole file");
    const glob = tools.find((t) => t.name === "Glob")!.description!;
    expect(glob).toContain('Absolute patterns are anchored: "/repos/acme/api/*.js" lists only the files directly in that directory');
    const grep = tools.find((t) => t.name === "Grep")!;
    expect(grep.description).toContain("exclude_globs");
    expect(grep.description).toContain("is searched only when you pass it as path");
    expect(JSON.stringify(grep.inputSchema)).not.toContain("include");
  });
});

describe("Read on a directory lists its entries (eisdir-glob-hint-recursive)", () => {
  it("lists direct entries, sub-directories first, without hidden ones", async () => {
    const r = await call(client, "Read", { file_path: "/pr" });
    expect(r.isError).toBe(true);
    expect(r.text).toBe(
      [
        'EISDIR: /pr is a directory, not a file. Its entries (sub-directories end with "/"):',
        "/pr/docs/",
        "/pr/img/",
        "/pr/src/",
        "/pr/vendor/",
        'Read one of these files, Grep with path "/pr" to search everything below it, or Glob with an absolute pattern such as "/pr/**/*.ts" to find files at any depth below it.',
      ].join("\n"),
    );
    const src = await call(client, "Read", { file_path: "/repos/acme/py/app/" });
    expect(src.text.split("\n").slice(1, 3)).toEqual(["/repos/acme/py/app/main.py", "/repos/acme/py/app/util.py"]);
    expect(src.text).toContain('"/repos/acme/py/app/**/*.py"');
    const gen = await call(client, "Read", { file_path: "/repos/acme/api/gen" });
    expect(gen.text.split("\n")).toHaveLength(1 + 100 + 2);
    expect(gen.text).toContain("[200 more entries not shown]");
    const py = await call(client, "Read", { file_path: "/repos/acme/py" });
    expect(py.text).not.toContain("secrets");
  });

  it("absolute Glob patterns list only a directory's direct files", async () => {
    expect((await call(client, "Glob", { pattern: "/repos/acme/api/*" })).text).toBe(
      ["/repos/acme/api/.eslintrc.json", "/repos/acme/api/README.md"].join("\n") +
        "\n\n[Files in paths skipped by exclude_globs are not listed, e.g. /repos/acme/api/package-lock.json (**/package-lock.json). To include them, pass its directory as path or name it in the pattern.]",
    );
  });
});

describe("exclude_globs skips are reported (exclude-build-hides-tracked-source)", () => {
  it("notes a skipped build/ consumer and finds it when targeted", async () => {
    const m6 = join(base, "mirror-build");
    mirrorRepo(
      "acme/fw",
      "7777777777777777777777777777777777777777",
      {
        "lib/config-validator.js": "module.exports = validate; // generated\n",
        "build/build-validation.js": "const standalone = require('@acme/ajv-compiler/standalone'); // writes lib/config-validator.js\n",
        "lib/server.js": "require('./config-validator')\n",
      },
      "",
      m6,
    );
    const c = await connect({ mirrorDir: m6 });
    const r = await call(c, "Grep", { pattern: "config-validator", path: "/repos/acme/fw" });
    expect(r.text).toBe(
      "Found 1 file\n/repos/acme/fw/lib/server.js\n\n" +
        "[Matches in paths skipped by exclude_globs are not shown, e.g. /repos/acme/fw/build/build-validation.js (**/build/**). " +
        "To include them, pass that file or its directory as path, or a glob that names it.]",
    );
    const only = await call(c, "Grep", { pattern: "ajv-compiler/standalone", output_mode: "content", glob: "*.js" });
    expect(only.text).toContain("e.g. /repos/acme/fw/build/build-validation.js (**/build/**)");
    const targeted = await call(c, "Grep", { pattern: "ajv-compiler/standalone", path: "/repos/acme/fw/build" });
    expect(targeted.text).toBe("Found 1 file\n/repos/acme/fw/build/build-validation.js");
    const byGlob = await call(c, "Grep", { pattern: "ajv-compiler/standalone", glob: "build/**" });
    expect(byGlob.text).toBe("Found 1 file\n/repos/acme/fw/build/build-validation.js");
  });

  it("notes results dropped by anchored (post-filtered) exclude globs too", async () => {
    const p2 = { ...policy, search: { ...policy.search, exclude_globs: [...policy.search.exclude_globs, "/gen/"] } };
    const c = await connect({ policy: p2 });
    const r = await call(c, "Grep", { pattern: "export const G1 = 1;", path: "/repos/acme/api" });
    expect(r.text).toBe(
      "No files found\n\n[Matches in paths skipped by exclude_globs are not shown, e.g. /repos/acme/api/gen/f001.ts (/gen/). " +
        "To include them, pass that file or its directory as path, or a glob that names it.]",
    );
  });
});

/* ------------------------- regressions (review round 2) ------------------------- */

/** Policy for acme/web with `search` overrides. */
function policyWith(search: Partial<ResolvedPolicy["search"]>): ResolvedPolicy {
  return { ...policy, search: { ...policy.search, ...search } };
}

/** A real `git diff -U3` (staged) between `before` and `after`; null = file absent. Returns the diff and the work tree. */
function gitDiff(files: Record<string, [string | null, string | null]>): { diff: string; dir: string } {
  const dir = mkdtempSync(join(base, "gitdiff-"));
  const git = (...args: string[]): string =>
    execFileSync("git", ["-c", "user.email=t@example.com", "-c", "user.name=t", "-c", "core.autocrlf=false", ...args], { cwd: dir, encoding: "utf8" });
  git("init", "-q");
  for (const [p, [before]] of Object.entries(files)) if (before !== null) write(join(dir, p), before);
  git("add", "-A");
  git("commit", "-q", "--allow-empty", "-m", "base");
  for (const [p, [, after]] of Object.entries(files)) {
    if (after === null) rmSync(join(dir, p));
    else write(join(dir, p), after);
  }
  git("add", "-A");
  return { diff: git("diff", "--cached", "--no-color", "-U3"), dir };
}

/** A distinct 68-character key body line ("AAAA" + B64, "BBBB" + B64, …). */
const bodyLine = (i: number): string => `${String.fromCharCode(65 + (i % 26)).repeat(4)}${B64}`;
const KEY_FRAGMENT = B64.slice(0, 16); // in every body line

describe("Grep agrees with Read on UTF-16 files (grep-utf16-pem-leak)", () => {
  it("never transcodes UTF-16: the key body is not printed, the file counts as binary", async () => {
    const m = join(base, "mirror-utf16");
    const keyText = ["-----BEGIN RSA PRIVATE KEY-----", B64, bodyLine(1), "-----END RSA PRIVATE KEY-----", ""].join("\r\n");
    const le = Buffer.concat([Buffer.from([0xff, 0xfe]), Buffer.from(keyText, "utf16le")]);
    const be = Buffer.from(le);
    be.swap16(); // FE FF + UTF-16BE
    const fakeBom = Buffer.concat([Buffer.from([0xff, 0xfe]), Buffer.from(keyText.replace(B64, bodyLine(9)), "utf8")]); // no NULs: text to rg
    mirrorRepo(
      "acme/infra",
      "4444444444444444444444444444444444444444",
      { "ops/deploy.config": le, "ops/be.txt": be, "ops/u8.txt": keyText, "ops/fake-bom.txt": fakeBom },
      "",
      m,
    );
    const c = await connect({ mirrorDir: m });
    const all = await call(c, "Grep", { pattern: "[A-Za-z0-9+/]{40,}", output_mode: "content", path: "/repos" });
    expect(all.text).not.toContain(KEY_FRAGMENT);
    expect(all.text).toContain(`/repos/acme/infra/ops/u8.txt:2:${PEM_TAG}`);
    expect(all.text).not.toContain("deploy.config");
    for (const f of ["ops/deploy.config", "ops/be.txt"]) {
      const one = await call(c, "Grep", { pattern: ".", output_mode: "content", path: `/repos/acme/infra/${f}` });
      expect(one.text).toBe(`/repos/acme/infra/${f}: binary file matches`);
      const ctxd = await call(c, "Grep", { pattern: "M.I.I.E", output_mode: "content", "-A": 3, path: `/repos/acme/infra/${f}` });
      expect(ctxd.text).not.toContain(KEY_FRAGMENT);
      expect((await call(c, "Read", { file_path: `/repos/acme/infra/${f}` })).text).toBe("[binary file]");
    }
    const viaPath = await call(c, "Grep", { pattern: "[A-Za-z0-9+/]{40,}", output_mode: "content", path: "/", "-o": true });
    expect(viaPath.text).not.toContain(KEY_FRAGMENT);
    // A UTF-16 byte-order mark in front of UTF-8 text: lines are numbered as ripgrep reads the bytes.
    const fake = await call(c, "Grep", { pattern: ".", output_mode: "content", path: "/repos/acme/infra/ops/fake-bom.txt" });
    expect(fake.text.split("\n").slice(1, 4)).toEqual([2, 3, 4].map((n) => `/repos/acme/infra/ops/fake-bom.txt:${n}:${PEM_TAG}`));
    expect((await call(c, "Read", { file_path: "/repos/acme/infra/ops/fake-bom.txt" })).text).not.toContain(KEY_FRAGMENT);
    // The whole-file PEM scan reads text the way a decoder would, should it ever see UTF-16.
    expect([...pemLineSet(decodeText(le))]).toEqual([1, 2, 3, 4]);
    expect([...pemLineSet(decodeText(be))]).toEqual([1, 2, 3, 4]);
  });
});

describe("agent globs never reach a backtracking regex (probe-glob-redos)", () => {
  const EVIL = `${"*a".repeat(12)}*b`;
  let c: Client;

  beforeAll(async () => {
    const m = join(base, "mirror-redos");
    mirrorRepo("acme/redos", "5555555555555555555555555555555555555555", { [`dist/${"a".repeat(60)}.js`]: "x\n", "src/ok.js": "y\n" }, "", m);
    c = await connect({ mirrorDir: m });
  });

  it("Glob and Grep return promptly with a pathological glob over a long excluded file name", async () => {
    let ticks = 0;
    const timer = setInterval(() => ticks++, 20);
    const t0 = Date.now();
    try {
      expect((await call(c, "Glob", { pattern: EVIL, path: "/repos/acme/redos" })).text).toBe("No files found");
      expect((await call(c, "Grep", { pattern: "x", glob: EVIL, path: "/repos/acme/redos" })).text).toBe("No files found");
      expect((await call(c, "Glob", { pattern: `/repos/acme/redos/**/${EVIL}` })).text).toBe("No files found");
    } finally {
      clearInterval(timer);
    }
    expect(Date.now() - t0).toBeLessThan(3000);
    expect(ticks).toBeGreaterThan(0); // the event loop kept running
  });

  it("the exclude probe still applies user globs (rg semantics)", async () => {
    const hit = await call(c, "Glob", { pattern: "*.js", path: "/repos/acme/redos" });
    expect(hit.text).toContain(`/repos/acme/redos/src/ok.js\n\n[Files in paths skipped by exclude_globs are not listed, e.g. /repos/acme/redos/dist/${"a".repeat(60)}.js`);
    const neg = await call(c, "Grep", { pattern: "x", glob: "!dist", path: "/repos/acme/redos" });
    expect(neg.text).toBe("No files found"); // "!dist" prunes the directory, so the probe finds nothing either
    const other = await call(c, "Grep", { pattern: "x", glob: "*.ts", path: "/repos/acme/redos" });
    expect(other.text).toBe("No files found");
    const named = await call(c, "Grep", { pattern: "x", glob: "*.js", path: "/repos/acme/redos" });
    expect(named.text).toContain(`[Matches in paths skipped by exclude_globs are not shown, e.g. /repos/acme/redos/dist/${"a".repeat(60)}.js`);
  });

  it("compileSafeGlob: ripgrep glob semantics in linear time", () => {
    const m = (p: string, s: string): boolean => compileSafeGlob(p)!(s);
    expect(m("**/*.ts", "a/b/c.ts")).toBe(true);
    expect(m("**/*.ts", "c.ts")).toBe(true);
    expect(m("**/*.ts", "c.tsx")).toBe(false);
    expect(m("src/**/*.ts", "src/x/y/a.ts")).toBe(true);
    expect(m("src/**/*.ts", "lib/a.ts")).toBe(false);
    expect(m("**/dist/**", "x/dist/a/b.js")).toBe(true);
    expect(m("**/dist/**", "x/distx/a.js")).toBe(false);
    expect(m("**/*.{ts,tsx}", "a/b.tsx")).toBe(true);
    expect(m("**/{src,lib/x}/*.ts", "lib/x/a.ts")).toBe(true);
    expect(m("**/[a-c]?.md", "x/b1.md")).toBe(true);
    expect(m("**/[!a-c]?.md", "x/b1.md")).toBe(false);
    expect(m("**/.env", ".env")).toBe(true);
    expect(m("a/*/c", "a/b/x/c")).toBe(false);
    expect(m("**/a\\*b", "a*b")).toBe(true);
    expect(m("**/a\\*b", "axb")).toBe(false);
    expect(expandBraces("{a,b}{c,d}")).toEqual(["ac", "ad", "bc", "bd"]);
    expect(expandBraces("{a,b}".repeat(7))).toBeNull(); // 128 > 64 alternatives
    const t0 = Date.now();
    expect(m(`**/${EVIL}`, `dist/${"a".repeat(4000)}.js`)).toBe(false);
    expect(m(`${"**/".repeat(168)}*.ts`, `${"a/".repeat(2000)}x.ts`)).toBe(true);
    expect(Date.now() - t0).toBeLessThan(500);
  });
});

describe("PrDiff redacts per line, per side and per hunk (prdiff-pem-hunk-leak, prdiff-pem-collapses-lines)", () => {
  let c: Client;
  let diff: string;
  let pr2: string;
  const key20 = (label: string, from: number, changed?: number): string[] => [
    `-----BEGIN ${label}PRIVATE KEY-----`,
    ...Array.from({ length: 20 }, (_, i) => (i === changed ? `ZZZZ${B64}` : bodyLine(from + i))),
    `-----END ${label}PRIVATE KEY-----`,
  ];
  const lines = (n: number, f: (i: number) => string): string[] => Array.from({ length: n }, (_, i) => f(i + 1));

  // app/keys.py: a key inside a Python string; the PR changes one body line in the middle.
  const keysOld = ["import os", "", 'SIGNING_KEY = """', ...key20("RSA ", 0), '"""', "", ...lines(13, (i) => `def f${i}(): return ${i}`), ""].join("\n");
  const keysNew = keysOld.replace(bodyLine(11), `ZZZZ${B64}`);
  // app/new.py: a new file, key on lines 2-7, eval on line 9.
  const newPy = ["KEY = '''", "-----BEGIN PRIVATE KEY-----", bodyLine(1), bodyLine(2), bodyLine(3), "-----END PRIVATE KEY-----", "'''", "", "def sign(data): return eval(data)", "# end", ""].join("\n");
  // app/multi.py: hunk 1 shows key A's BEGIN only, hunk 2 is code, hunk 3 shows key B's END only.
  const multi = (v: "old" | "new"): string => {
    const out = lines(400, (i) => `    pad${i} = ${i}`);
    out[2] = v === "old" ? "x = 1" : "x = 2";
    out.splice(4, 22, ...key20("", 0));
    out[99] = v === "old" ? "    return safe(data)" : "    return eval(data)";
    out.splice(289, 22, ...key20("EC ", 5, v === "old" ? undefined : 18));
    return out.join("\n") + "\n";
  };
  // app/far.py: an edit below a key; git puts the last key line (it starts with a letter) in the hunk header.
  const farOld = ['K = """', ...key20("", 3), '"""', ...lines(12, (i) => `    x${i} = ${i}`), ""].join("\n");
  const farNew = farOld.replace("    x8 = 8", "    x8 = 88");
  // app/gone.py: a deleted file holding a key.
  const gonePy = ["A = 1", "-----BEGIN PRIVATE KEY-----", bodyLine(7), "-----END PRIVATE KEY-----", ""].join("\n");

  beforeAll(async () => {
    const g = gitDiff({
      "app/keys.py": [keysOld, keysNew],
      "app/new.py": [null, newPy],
      "app/multi.py": [multi("old"), multi("new")],
      "app/far.py": [farOld, farNew],
      "app/gone.py": [gonePy, null],
    });
    diff = g.diff;
    pr2 = g.dir;
    const ctx2: PrContext = {
      ...ctx,
      files: [
        { path: "app/keys.py", status: "modified", additions: 1, deletions: 1 },
        { path: "app/new.py", status: "added", additions: 10, deletions: 0 },
        { path: "app/multi.py", status: "modified", additions: 3, deletions: 3 },
        { path: "app/far.py", status: "modified", additions: 1, deletions: 1 },
        { path: "app/gone.py", status: "removed", additions: 0, deletions: 4 },
      ],
    };
    c = await connect({ prDir: pr2, ctx: ctx2, diffText: diff });
  });

  /** Raw diff lines of one file's section. */
  const section = (path: string): string[] => {
    const all = diff.replace(/\n$/, "").split("\n");
    const start = all.findIndex((l) => l === `diff --git a/${path} b/${path}`);
    let end = all.findIndex((l, i) => i > start && l.startsWith("diff --git "));
    if (end === -1) end = all.length;
    return all.slice(start, end);
  };

  /** New-side line number of each "+"/" " line, from the hunk headers. */
  const newSideNumbers = (out: string[]): Map<number, string> => {
    const map = new Map<number, string>();
    let n = 0;
    for (const l of out) {
      const h = /^@@ -\d+(?:,\d+)? \+(\d+)/.exec(l);
      if (h) n = Number(h[1]);
      else if (n > 0 && (l.startsWith("+") || l.startsWith(" "))) map.set(n++, l.slice(1));
    }
    return map;
  };

  it("hides key lines inside a hunk that shows neither BEGIN nor END, on both sides", async () => {
    const r = await call(c, "PrDiff", { file_path: "/pr/app/keys.py" });
    expect(r.isError).toBe(false);
    expect(r.text).not.toContain(KEY_FRAGMENT);
    const out = r.text.split("\n");
    const raw = section("app/keys.py");
    expect(out).toHaveLength(raw.length); // one output line per diff line
    expect(out.filter((l) => l === `-${PEM_TAG}`)).toHaveLength(1);
    expect(out.filter((l) => l === `+${PEM_TAG}`)).toHaveLength(1);
    expect(out.filter((l) => l === ` ${PEM_TAG}`)).toHaveLength(6);
    // The hunk header's function context ("    HHHH…" in git's choice) is key material too.
    for (const l of out.filter((x) => x.startsWith("@@"))) expect(l).toMatch(/^@@ -\d+,\d+ \+\d+,\d+ @@( \[REDACTED:private_key\])?$/);
    // Read shows the same lines redacted, at the same numbers.
    const read = await call(c, "Read", { file_path: "/pr/app/keys.py", offset: 13, limit: 7 });
    expect(read.text.split("\n").slice(0, 7)).toEqual([13, 14, 15, 16, 17, 18, 19].map((n) => `${String(n).padStart(6)}\t${PEM_TAG}`));
  });

  it("keeps the hunk's line count, so new-side numbers stay right (a new file with a key)", async () => {
    const r = await call(c, "PrDiff", { file_path: "/pr/app/new.py" });
    const out = r.text.split("\n");
    expect(out).toHaveLength(section("app/new.py").length);
    expect(out).toContain("@@ -0,0 +1,10 @@");
    const numbered = newSideNumbers(out);
    expect(numbered.get(9)).toBe("def sign(data): return eval(data)");
    expect(numbered.get(1)).toBe("KEY = '''");
    expect(numbered.get(2)).toBe(PEM_TAG);
    for (let n = 3; n <= 6; n++) expect(numbered.get(n)).toBe(PEM_TAG);
    expect(numbered.get(7)).toBe("'''");
    expect(r.text).not.toContain(KEY_FRAGMENT);
  });

  it("never pairs a BEGIN in one hunk with an END in another: the code hunk between stays visible", async () => {
    const r = await call(c, "PrDiff", { file_path: "/pr/app/multi.py" });
    const out = r.text.split("\n");
    expect(out).toHaveLength(section("app/multi.py").length);
    expect(out.filter((l) => l.startsWith("@@"))).toHaveLength(3);
    expect(out).toContain("-    return safe(data)");
    expect(out).toContain("+    return eval(data)");
    expect(newSideNumbers(out).get(100)).toBe("    return eval(data)");
    expect(r.text).not.toContain(KEY_FRAGMENT);
    expect(r.text).not.toContain("ZZZZ");
  });

  it("hides key lines shown as context of an unrelated edit, the hunk header context, and deleted keys", async () => {
    const far = await call(c, "PrDiff", { file_path: "/pr/app/far.py" });
    expect(far.text).not.toContain(KEY_FRAGMENT);
    expect(far.text).toContain("+    x8 = 88");
    const gone = await call(c, "PrDiff", { file_path: "/pr/app/gone.py" });
    expect(gone.text).not.toContain(KEY_FRAGMENT);
    expect(gone.text.split("\n").slice(-4)).toEqual(["-A = 1", `-${PEM_TAG}`, `-${PEM_TAG}`, `-${PEM_TAG}`]);
  });

  it("redactDiffLines: without the new version, key-like hunk lines are hidden; plain code is not", () => {
    const hunk = ["@@ -10,4 +10,4 @@ def f():", ` ${bodyLine(1)}`, `-${bodyLine(2)}`, `+${bodyLine(3)}`, "   return compute_total(items)", "-x = 1", "+x = 2"];
    expect(redactDiffLines(hunk, null)).toEqual(["@@ -10,4 +10,4 @@ def f():", ` ${PEM_TAG}`, `-${PEM_TAG}`, `+${PEM_TAG}`, "   return compute_total(items)", "-x = 1", "+x = 2"]);
    // With the new version known to hold no key there, removed lines are hidden only near a key.
    expect(redactDiffLines(["@@ -1,2 +1,2 @@", "-someVeryLongIdentifierName = 1", "+someVeryLongIdentifierName = 2"], new Set())).toEqual([
      "@@ -1,2 +1,2 @@",
      "-someVeryLongIdentifierName = 1",
      "+someVeryLongIdentifierName = 2",
    ]);
    expect(redactDiffLines(["@@ -1,1 +1,1 @@", `-t = "${GH_TOKEN}"`, '+t = "x"'], new Set())[1]).toBe('-t = "[REDACTED:github_token]"');
  });
});

describe("Grep -o with multiline stays linear (grep-o-multiline-quadratic)", () => {
  let c: Client;
  beforeAll(async () => {
    const m = join(base, "mirror-bigo");
    mirrorRepo("acme/bigo", "6666666666666666666666666666666666666666", { "src/big.txt": "x\n".repeat(60000) }, "", m);
    c = await connect({ mirrorDir: m, policy: policyWith({ max_filesize: "1M" }) });
  });

  it("numbers -o parts correctly and pages deep without quadratic work", async () => {
    const args = { pattern: "x\\n", multiline: true, "-o": true, output_mode: "content", path: "/repos/acme/bigo/src/big.txt" };
    const first = await call(c, "Grep", { ...args, head_limit: 2, offset: 5 });
    expect(first.text.split("\n").slice(0, 2)).toEqual(["/repos/acme/bigo/src/big.txt:6:x", "/repos/acme/bigo/src/big.txt:7:x"]);
    const t0 = Date.now();
    const deep = await call(c, "Grep", { ...args, head_limit: 2, offset: 19990 });
    expect(Date.now() - t0).toBeLessThan(1500); // quadratic newline counting took > 2 s here
    expect(deep.text.split("\n")[0]).toBe("/repos/acme/bigo/src/big.txt:19991:x");
    const tooDeep = await call(c, "Grep", { ...args, offset: 100000 });
    expect(tooDeep.isError).toBe(true);
    expect(tooDeep.text).toContain("offset is too large (max 20000)");
  });
});

describe("absolute Glob patterns with many ** stay cheap (glob-abs-remainders-cpu)", () => {
  it("collapses ** runs and memoizes the per-root walk", async () => {
    const t0 = Date.now();
    const r = await call(client, "Glob", { pattern: `/${"**/".repeat(168)}*.py` });
    expect(Date.now() - t0).toBeLessThan(1500);
    expect(r.text).toBe((await call(client, "Glob", { pattern: "/**/*.py" })).text);
    expect(r.text).toContain("/repos/acme/py/app/main.py");
    const mid = await call(client, "Glob", { pattern: "/repos/**/**/acme/**/src/**/**/orders.ts" });
    expect(mid.text).toBe("/repos/acme/api/src/orders.ts\n/repos/acme/web/src/orders.ts");
  });
});

describe("pagination always makes progress (pagination-no-progress)", () => {
  it("PrDiff and Grep show an over-long entry cut to the budget and point past it", async () => {
    const g = gitDiff({ "min.js": ["a\nb\nc\n", `a\n${"x".repeat(1200)}\nc\n`] });
    const deepDir = join("d".repeat(200), "e".repeat(200));
    write(join(g.dir, deepDir, "f.txt"), `${"q".repeat(450)} NEEDLE\n${"r".repeat(450)} NEEDLE\n`);
    const c = await connect({
      prDir: g.dir,
      diffText: g.diff,
      ctx: { ...ctx, files: [{ path: "min.js", status: "modified", additions: 1, deletions: 1 }] },
      policy: policyWith({ max_output_chars: 1000 }),
    });
    const head = await call(c, "PrDiff", { file_path: "/pr/min.js" });
    expect(head.text).toMatch(/\[Showing diff lines 1-7 of 9\. Use offset: 8 to see more\.\]$/);
    const long = await call(c, "PrDiff", { file_path: "/pr/min.js", offset: 8 });
    expect(long.text.startsWith("+xxxx")).toBe(true);
    expect(long.text).toContain("… [line truncated]");
    expect(long.text).toMatch(/\[Showing diff lines 8-8 of 9\. Use offset: 9 to see more\.\]$/);
    expect(long.text.length).toBeLessThanOrEqual(1000);
    const grep = await call(c, "Grep", { pattern: "NEEDLE", output_mode: "content", path: "/pr" });
    expect(grep.text.startsWith(`/pr/${deepDir}/f.txt:1:qqqq`)).toBe(true);
    expect(grep.text).toContain("Use offset: 1 to see more");
    const next = await call(c, "Grep", { pattern: "NEEDLE", output_mode: "content", path: "/pr", offset: 1 });
    expect(next.text.startsWith(`/pr/${deepDir}/f.txt:2:rrrr`)).toBe(true);
  });
});

describe("one PEM rule for redactSecrets and line-wise redaction (pem-redaction-two-implementations-diverge)", () => {
  /** Base64 runs (16+) that redactSecrets removes from `text` but line-wise redaction still shows. */
  const leaked = (text: string): string[] => {
    const whole = redactSecrets(text).text;
    const map = pemLineMap(text);
    const shown = text
      .split("\n")
      .map((l, i) => map.get(i + 1) ?? redactLine(l, true))
      .join("\n");
    return (text.match(/[A-Za-z0-9+/=]{16,}/g) ?? []).filter((run) => !whole.includes(run) && shown.includes(run));
  };
  const chunk = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASC";
  const cases: Record<string, string> = {
    chunksNoEnd: ["KEY_CHUNKS = [", '  "-----BEGIN PRIVATE KEY-----",', `  "${chunk}1", "${chunk}2", "${chunk}3",`, `  "${chunk}4", "${chunk}5", "${chunk}6",`, "]"].join("\n"),
    concatNoEnd: ['k = "-----BEGIN PRIVATE KEY-----\\n" +', `  "${B64}\\n" + "${bodyLine(1)}\\n" +`, `  "${bodyLine(2)}\\n" + "${bodyLine(3)}\\n"`, 'print("ok")'].join("\n"),
    terminated: ["-----BEGIN PRIVATE KEY-----", `"${chunk}1", "${chunk}2", "${chunk}3", "${chunk}4"`, "-----END PRIVATE KEY-----"].join("\n"),
    plainNoEnd: ["-----BEGIN EC PRIVATE KEY-----", B64, bodyLine(4), "prose, not base64!"].join("\n"),
    headers: ["-----BEGIN RSA PRIVATE KEY-----", "Proc-Type: 4,ENCRYPTED", "DEK-Info: AES-128-CBC,0123456789ABCDEF", "", B64, "x"].join("\n"),
  };

  it("line-wise redaction hides every key run redactSecrets hides, with or without END", () => {
    for (const [name, text] of Object.entries(cases)) expect(leaked(text), name).toEqual([]);
    expect([...pemLineSet(cases.chunksNoEnd!)]).toEqual([2, 3, 4]);
    expect([...pemLineSet(cases.concatNoEnd!)]).toEqual([1, 2, 3]);
    expect([...pemLineSet(cases.plainNoEnd!)]).toEqual([1, 2, 3]);
  });

  it("Read and Grep hide string-chunked key lines without an END marker", async () => {
    const m = join(base, "mirror-chunks");
    mirrorRepo("acme/chunks", "8888888888888888888888888888888888888888", { "keys.py": `${cases.chunksNoEnd}\n` }, "", m);
    const c = await connect({ mirrorDir: m });
    const read = await call(c, "Read", { file_path: "/repos/acme/chunks/keys.py" });
    expect(read.text).not.toContain(chunk);
    expect(read.text.split("\n")[4]).toBe("     5\t]");
    const grep = await call(c, "Grep", { pattern: "MIIE", output_mode: "content", path: "/repos/acme/chunks" });
    expect(grep.text).not.toContain(chunk);
  });
});

describe("cross-repo hits cut by head_limit are named (implicit-search-root-starvation)", () => {
  it("Grep and Glob name the repositories whose matches fell past the cut", async () => {
    const m = join(base, "mirror-starve");
    const pr3 = join(base, "pr-starve");
    for (let i = 0; i < 120; i++) write(join(pr3, "src", `f${String(i).padStart(3, "0")}.test.ts`), "useNext();\n");
    mirrorRepo("acme/consumer", "9999999999999999999999999999999999999999", Object.fromEntries(Array.from({ length: 7 }, (_, i) => [`lib/c${i}.test.ts`, "useNext();\n"])), "", m);
    mirrorRepo("acme/other", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", { "x.test.ts": "useNext();\n" }, "", m);
    const c = await connect({ prDir: pr3, mirrorDir: m });
    const files = await call(c, "Grep", { pattern: "useNext", head_limit: 50 });
    expect(files.text).toContain("[Showing results with pagination = limit: 50, offset: 0]");
    expect(files.text).toContain("[Also matched, not shown: /repos/acme/consumer (7 files), /repos/acme/other (1 file). Pass one as path to see its results.]");
    const content = await call(c, "Grep", { pattern: "useNext", output_mode: "content", head_limit: 50 });
    expect(content.text).toContain("[Also matched, not shown: /repos/acme/consumer (7 files), /repos/acme/other (1 file).");
    const count = await call(c, "Grep", { pattern: "useNext", output_mode: "count", head_limit: 125 });
    expect(count.text).toContain("[Also matched, not shown: /repos/acme/other (1 file).");
    const glob = await call(c, "Glob", { pattern: "**/*.test.ts" });
    expect(glob.text).toContain("(Results are truncated. Consider using a more specific path or pattern.)\n[Also matched, not shown: /repos/acme/consumer (7 files), /repos/acme/other (1 file).");
    // No note when everything fits, or when a single repository is searched.
    expect((await call(c, "Grep", { pattern: "useNext" })).text).not.toContain("Also matched");
    expect((await call(c, "Grep", { pattern: "useNext", path: "/pr", head_limit: 5 })).text).not.toContain("Also matched");
  });
});

describe("Grep glob given as a virtual path is an error, not a silent miss (grep-glob-virtual-path-silent-miss)", () => {
  it("explains how to split it into path + glob", async () => {
    const r = await call(client, "Grep", { pattern: "total", glob: "/pr/src/**/*.ts" });
    expect(r.isError).toBe(true);
    expect(r.text).toContain('pass path "/pr/src" and glob "**/*.ts"');
    const repo = await call(client, "Grep", { pattern: "total", glob: "/repos/acme/api/src/*.ts", path: "/repos/acme/api" });
    expect(repo.isError).toBe(true);
    expect(repo.text).toContain('pass path "/repos/acme/api/src" and glob "*.ts"');
    expect((await call(client, "Grep", { pattern: "total", glob: "!/repos/x/**" })).isError).toBe(true);
    // A glob anchored at the searched directory still works.
    expect((await call(client, "Grep", { pattern: "total", path: "/pr", glob: "/src/*.ts" })).text).toBe("Found 1 file\n/pr/src/orders.ts");
    // Glob: an absolute pattern ignores path, and the error says so.
    const g = await call(client, "Glob", { pattern: "/src/*.ts", path: "/repos/acme/api" });
    expect(g.isError).toBe(true);
    expect(g.text).toContain('An absolute pattern is a virtual path and ignores path (/repos/acme/api): pass "src/*.ts" with that path, or the absolute pattern "/repos/acme/api/src/*.ts".');
  });
});

describe("Glob of a directory path is an error (glob-absolute-dir-no-files)", () => {
  it("says the pattern names a directory instead of 'No files found'", async () => {
    for (const p of ["/repos/acme/api", "/repos/acme/api/", "/pr", "/pr/src", "/repos", "/repos/acme"]) {
      const r = await call(client, "Glob", { pattern: p });
      expect(r.isError, p).toBe(true);
      expect(r.text, p).toContain("names a directory");
      expect(r.text, p).toContain(`"${p.replace(/\/+$/, "")}/**/*"`);
    }
    expect((await call(client, "Glob", { pattern: "/repos/*/*" })).text).toContain('names a directory; add a file pattern such as "/repos/*/*/**/*"');
    expect((await call(client, "Glob", { pattern: "/pr/src/orders.ts" })).text).toBe("/pr/src/orders.ts");
    expect((await call(client, "Glob", { pattern: "/pr/src/missing.ts" })).text).toBe("No files found");
  });
});

describe("relative paths get a hint that exists (relative-path-guess-doubles-root)", () => {
  it("does not prepend /pr to a path that already names a root", async () => {
    expect((await call(client, "Read", { file_path: "pr/src/orders.ts" })).text).toContain("Did you mean /pr/src/orders.ts?");
    expect((await call(client, "Read", { file_path: "./PR/src/orders.ts" })).text).toContain("Did you mean /PR/src/orders.ts?");
    expect((await call(client, "Read", { file_path: "repos/acme/api/README.md" })).text).toContain("Did you mean /repos/acme/api/README.md?");
    expect((await call(client, "Read", { file_path: "src/orders.ts" })).text).toContain("Did you mean /pr/src/orders.ts?");
    expect((await call(client, "Read", { file_path: "prod/x.ts" })).text).toContain("Did you mean /pr/prod/x.ts?");
  });
});

describe("the EISDIR Glob example uses a code extension (eisdir-example-uses-dotfile-ext)", () => {
  it("skips dotfiles and prefers code, also from one level down", async () => {
    const m = join(base, "mirror-eisdir");
    mirrorRepo(
      "acme/js",
      "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
      { ".gitignore": "x\n", ".codecov.yml": "x\n", "History.md": "x\n", "package.json": "{}\n", "lib/a.js": "1\n", "lib/b.js": "1\n", "test/c.js": "1\n" },
      "",
      m,
    );
    mirrorRepo(
      "acme/ts",
      "cccccccccccccccccccccccccccccccccccccccc",
      { ".gitignore": "x\n", ".editorconfig": "x\n", "a.json": "{}\n", "b.json": "{}\n", "vitest.config.ts": "1\n", "src/x.ts": "1\n" },
      "",
      m,
    );
    const c = await connect({ mirrorDir: m });
    expect((await call(c, "Read", { file_path: "/repos/acme/js" })).text).toContain('"/repos/acme/js/**/*.js"');
    expect((await call(c, "Read", { file_path: "/repos/acme/ts" })).text).toContain('"/repos/acme/ts/**/*.ts"');
  });
});

describe("tools/list states each rule once (schema-repeats-own-base-note)", () => {
  it("keeps the own-base rule in the Grep and Glob descriptions only", async () => {
    const { tools } = await client.listTools();
    const json = JSON.stringify(tools);
    expect(json.split("only when you pass it as path")).toHaveLength(3); // Grep + Glob descriptions
    expect(json).not.toContain("only when passed as path");
    expect(json).not.toContain("only when passed here");
    const listRepos = tools.find((t) => t.name === "ListRepos")!;
    expect(listRepos.description).not.toContain("its code before the PR");
    const instructions = client.getInstructions() ?? "";
    expect(instructions).not.toContain("every result prints paths you can pass straight to Read");
    expect(instructions).toContain("/repos/<owner>/<name>");
  });
});

describe("a mirror repo deleted under a running review is skipped, not fatal (remove-unlisted-ignores-grace, search side)", () => {
  it("Grep and Glob without path skip the vanished root with a note; with it as path they say it is gone", async () => {
    const m = join(base, "mirror-vanish");
    mirrorRepo("acme/api", SHA_API, { "src/v.ts": "export const VANISH_NEEDLE = 1;\n" }, "", m);
    mirrorRepo("acme/py", SHA_PY, { "src/v.py": "VANISH_NEEDLE = 2\n" }, "", m);
    const c = await connect({ mirrorDir: m });
    expect((await call(c, "Grep", { pattern: "VANISH_NEEDLE" })).text).toBe("Found 2 files\n/repos/acme/api/src/v.ts\n/repos/acme/py/src/v.py");
    rmSync(join(m, "acme", "py"), { recursive: true, force: true });

    const g = await call(c, "Grep", { pattern: "VANISH_NEEDLE" });
    expect(g.isError).toBe(false);
    expect(g.text).toBe("Found 1 file\n/repos/acme/api/src/v.ts\n\n[Not searched: /repos/acme/py (removed from the repository mirror while this review ran).]");
    expect(g.text).not.toContain("not installed");
    const content = await call(c, "Grep", { pattern: "VANISH_NEEDLE", output_mode: "content" });
    expect(content.text).toContain("/repos/acme/api/src/v.ts:1:export const VANISH_NEEDLE = 1;");
    expect(content.text).toContain("[Not searched: /repos/acme/py");
    const gl = await call(c, "Glob", { pattern: "**/v.*" });
    expect(gl.text).toBe("/repos/acme/api/src/v.ts\n\n[Not searched: /repos/acme/py (removed from the repository mirror while this review ran).]");

    const only = await call(c, "Grep", { pattern: "VANISH_NEEDLE", path: "/repos/acme/py" });
    expect(only.isError).toBe(true);
    expect(only.text).not.toContain("not installed");
    expect(only.text).toMatch(/no longer available|does not exist/);
  });
});

describe("ListRepos pages through long lists (repo-list-unbounded-listrepos-unpageable)", () => {
  it("offset/limit window the rows; a cut list says how to see more; the output cap is never hit", async () => {
    const m = join(base, "mirror-many");
    for (let i = 0; i < 60; i++) mirrorRepo(`many/r${String(i).padStart(2, "0")}`, SHA_API, { "a.ts": "x\n" }, "d".repeat(100), m);
    const p = resolvePolicy(
      parsePolicy('version: 1\ndefaults:\n  cross_repo: { readable: ["many/*"] }\n  search: { max_output_chars: 2000 }\n'),
      "acme/web",
    );
    const c = await connect({ mirrorDir: m, policy: p });
    const first = await call(c, "ListRepos");
    expect(first.isError).toBe(false);
    expect(first.text.length).toBeLessThanOrEqual(2000);
    expect(first.text).not.toContain("[Output truncated");
    const m1 = /\[Showing roots 1-(\d+) of 61\. Use offset: (\d+) to see more\.\]$/.exec(first.text);
    expect(m1).not.toBeNull();
    expect(first.text.split("\n")[0]).toMatch(/^\/pr /);
    const next = await call(c, "ListRepos", { offset: Number(m1![2]) });
    expect(next.text.split("\n")[0]).toMatch(new RegExp(`^/repos/many/r${String(Number(m1![1]) - 1).padStart(2, "0")} `));
    const two = await call(c, "ListRepos", { offset: 2, limit: 2 });
    expect(two.text.split("\n")).toEqual([
      expect.stringMatching(/^\/repos\/many\/r00 /),
      expect.stringMatching(/^\/repos\/many\/r01 /),
      "[Showing roots 2-3 of 61. Use offset: 4 to see more.]",
    ]);
    expect((await call(c, "ListRepos", { offset: 99 })).text).toBe("There are 61 roots; offset 99 is past the end.");
    const bad = await call(c, "ListRepos", { owner: "many" });
    expect(bad.isError).toBe(true);
  });
});

describe("PrDiff lists a type change once, as modified (typechange-split-filediff, search side)", () => {
  it("merges git's deletion + addition sections of one path and shows both halves", async () => {
    const TC = [
      "diff --git a/blob b/blob",
      "deleted file mode 120000",
      "index 3eddab3..0000000",
      "--- a/blob",
      "+++ /dev/null",
      "@@ -1 +0,0 @@",
      "-t.txt",
      "\\ No newline at end of file",
      "diff --git a/blob b/blob",
      "new file mode 100644",
      "index 0000000..3e3315e",
      "Binary files /dev/null and b/blob differ",
      "diff --git a/link b/link",
      "deleted file mode 120000",
      "index 3eddab3..0000000",
      "--- a/link",
      "+++ /dev/null",
      "@@ -1 +0,0 @@",
      "-t.txt",
      "\\ No newline at end of file",
      "diff --git a/link b/link",
      "new file mode 100644",
      "index 0000000..c0d0fb4",
      "--- /dev/null",
      "+++ b/link",
      "@@ -0,0 +1,2 @@",
      "+line1",
      "+line2",
      "",
    ].join("\n");
    const tcCtx: PrContext = {
      ...ctx,
      files: [
        { path: "blob", status: "removed", additions: 0, deletions: 1 },
        { path: "blob", status: "binary", additions: 0, deletions: 0 },
        { path: "link", status: "removed", additions: 0, deletions: 1 },
        { path: "link", status: "added", additions: 2, deletions: 0 },
      ],
      changed_lines: 4,
    };
    const c = await connect({ ctx: tcCtx, diffText: TC });
    expect((await call(c, "PrDiff")).text).toBe("M  +0 -1  /pr/blob  (binary)\nM  +2 -1  /pr/link");
    const link = await call(c, "PrDiff", { file_path: "/pr/link" });
    expect(link.text).toContain("-t.txt");
    expect(link.text).toContain("+line2");
    expect((await call(c, "ListRepos")).text.split("\n")[0]).toContain("2 files changed");
  });
});

import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { parseCli } from "../src/common/args.js";
import { CTX_FILES, PrContext, readContext, writeJsonAtomic } from "../src/common/context.js";
import { changedLineCount, isCommentable, parseUnifiedDiff, type FileDiff } from "../src/common/diff.js";

let dir: string;
beforeAll(() => {
  dir = mkdtempSync(join(tmpdir(), "xrepo-diff-"));
});
afterAll(() => {
  rmSync(dir, { recursive: true, force: true });
});

/** Real `git diff -M` output (see the git-generated test below for the live equivalent). */
const PATCH = [
  "diff --git a/a.txt b/a.txt",
  "index 4083766..cce669b 100644",
  "--- a/a.txt",
  "+++ b/a.txt",
  "@@ -1,10 +1,11 @@",
  " line1",
  "-line2",
  "+line2 changed",
  " line3",
  " line4",
  " line5",
  " line6",
  " line7",
  " line8",
  "-line9",
  "+line9 changed",
  " line10",
  "+line11",
  "diff --git a/added.txt b/added.txt",
  "new file mode 100644",
  "index 0000000..17b617d",
  "--- /dev/null",
  "+++ b/added.txt",
  "@@ -0,0 +1,2 @@",
  "+new file",
  "+second",
  'diff --git "a/caf\\303\\251.txt" "b/caf\\303\\251.txt"',
  "new file mode 100644",
  "index 0000000..572eb43",
  "--- /dev/null",
  '+++ "b/caf\\303\\251.txt"',
  "@@ -0,0 +1 @@",
  "+café",
  "diff --git a/delbin.bin b/delbin.bin",
  "deleted file mode 100644",
  "index f9cd9dc..0000000",
  "Binary files a/delbin.bin and /dev/null differ",
  "diff --git a/empty_new.txt b/empty_new.txt",
  "new file mode 100644",
  "index 0000000..e69de29",
  "diff --git a/gone.txt b/gone.txt",
  "deleted file mode 100644",
  "index 2fa992c..0000000",
  "--- a/gone.txt",
  "+++ /dev/null",
  "@@ -1 +0,0 @@",
  "-keep",
  "diff --git a/img.bin b/img.bin",
  "index 6772730..4e0e1df 100644",
  "Binary files a/img.bin and b/img.bin differ",
  "diff --git a/newbin.bin b/newbin.bin",
  "new file mode 100644",
  "index 0000000..f0f8652",
  "Binary files /dev/null and b/newbin.bin differ",
  "diff --git a/noeol.txt b/noeol.txt",
  "index 117827f..07aad1e 100644",
  "--- a/noeol.txt",
  "+++ b/noeol.txt",
  "@@ -1 +1 @@",
  "-noeol",
  "\\ No newline at end of file",
  "+noeol2",
  "\\ No newline at end of file",
  "diff --git a/rename_me.txt b/renamed.txt",
  "similarity index 90%",
  "rename from rename_me.txt",
  "rename to renamed.txt",
  "index e8823e1..5401050 100644",
  "--- a/rename_me.txt",
  "+++ b/renamed.txt",
  "@@ -12,7 +12,7 @@ function context()",
  " 12",
  " 13",
  " 14",
  "-15",
  "+fifteen",
  " 16",
  " 17",
  " 18",
  "diff --git a/script.sh b/script.sh",
  "old mode 100644",
  "new mode 100755",
  "diff --git a/with space.txt b/with space.txt",
  "index 587be6b..975fbec 100644",
  "--- a/with space.txt\t",
  "+++ b/with space.txt\t",
  "@@ -1 +1 @@",
  "-x",
  "+y",
  "",
].join("\n");

function byPath(files: FileDiff[]): Map<string, FileDiff> {
  return new Map(files.map((f) => [f.path, f]));
}

function get(files: FileDiff[], path: string): FileDiff {
  const f = byPath(files).get(path);
  if (!f) throw new Error(`no diff for ${path}; have ${files.map((x) => x.path).join(", ")}`);
  return f;
}

describe("parseUnifiedDiff", () => {
  const files = parseUnifiedDiff(PATCH);

  it("splits every file and raw slices reproduce the exact input", () => {
    expect(files.map((f) => f.path)).toEqual([
      "a.txt",
      "added.txt",
      "café.txt",
      "delbin.bin",
      "empty_new.txt",
      "gone.txt",
      "img.bin",
      "newbin.bin",
      "noeol.txt",
      "renamed.txt",
      "script.sh",
      "with space.txt",
    ]);
    expect(files.map((f) => f.raw).join("")).toBe(PATCH);
    expect(get(files, "gone.txt").raw).toBe(
      "diff --git a/gone.txt b/gone.txt\ndeleted file mode 100644\nindex 2fa992c..0000000\n--- a/gone.txt\n+++ /dev/null\n@@ -1 +0,0 @@\n-keep\n",
    );
  });

  it("modified file: hunk geometry, counts, right/added lines", () => {
    const f = get(files, "a.txt");
    expect(f.status).toBe("modified");
    expect(f.oldPath).toBeUndefined();
    expect(f.additions).toBe(3);
    expect(f.deletions).toBe(2);
    expect(f.hunks).toHaveLength(1);
    const h = f.hunks[0]!;
    expect([h.oldStart, h.oldLines, h.newStart, h.newLines]).toEqual([1, 10, 1, 11]);
    expect(h.header).toBe("@@ -1,10 +1,11 @@");
    expect(h.lines).toHaveLength(13);
    expect([...f.rightLines].sort((a, b) => a - b)).toEqual([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]);
    expect([...f.addedLines].sort((a, b) => a - b)).toEqual([2, 9, 11]);
  });

  it("new file, quoted UTF-8 path, empty new file", () => {
    const a = get(files, "added.txt");
    expect(a.status).toBe("added");
    expect([a.additions, a.deletions]).toEqual([2, 0]);
    expect([...a.addedLines]).toEqual([1, 2]);
    const cafe = get(files, "café.txt");
    expect(cafe.status).toBe("added");
    expect(cafe.hunks[0]).toMatchObject({ oldStart: 0, oldLines: 0, newStart: 1, newLines: 1 });
    const empty = get(files, "empty_new.txt");
    expect(empty.status).toBe("added");
    expect(empty.hunks).toEqual([]);
  });

  it("deleted file has no right-side lines", () => {
    const g = get(files, "gone.txt");
    expect(g.status).toBe("removed");
    expect([g.additions, g.deletions]).toEqual([0, 1]);
    expect(g.rightLines.size).toBe(0);
    expect(g.hunks[0]).toMatchObject({ oldStart: 1, oldLines: 1, newStart: 0, newLines: 0 });
  });

  it("binary files (modified, new, deleted) are 'binary' with no hunks", () => {
    for (const p of ["img.bin", "newbin.bin", "delbin.bin"]) {
      const b = get(files, p);
      expect(b.status, p).toBe("binary");
      expect(b.hunks, p).toEqual([]);
      expect(b.additions + b.deletions, p).toBe(0);
    }
  });

  it("'\\ No newline at end of file' is kept in the hunk but not counted", () => {
    const n = get(files, "noeol.txt");
    expect([n.additions, n.deletions]).toEqual([1, 1]);
    expect(n.hunks[0]!.lines).toEqual(["-noeol", "\\ No newline at end of file", "+noeol2", "\\ No newline at end of file"]);
    expect([...n.rightLines]).toEqual([1]);
  });

  it("rename with edits keeps oldPath and the full hunk header", () => {
    const r = get(files, "renamed.txt");
    expect(r.status).toBe("renamed");
    expect(r.oldPath).toBe("rename_me.txt");
    expect([r.additions, r.deletions]).toEqual([1, 1]);
    expect(r.hunks[0]!.header).toBe("@@ -12,7 +12,7 @@ function context()");
    expect([...r.addedLines]).toEqual([15]);
    expect([...r.rightLines].sort((a, b) => a - b)).toEqual([12, 13, 14, 15, 16, 17, 18]);
  });

  it("mode-only change and paths with spaces (trailing TAB convention)", () => {
    expect(get(files, "script.sh")).toMatchObject({ status: "modified", additions: 0, deletions: 0, hunks: [] });
    const s = get(files, "with space.txt");
    expect([s.additions, s.deletions]).toEqual([1, 1]);
  });

  it("pure renames, copies and quoted rename targets", () => {
    const text = [
      "diff --git a/added.txt b/copied.txt",
      "similarity index 72%",
      "copy from added.txt",
      "copy to copied.txt",
      "index 17b617d..d61d00b 100644",
      "--- a/added.txt",
      "+++ b/copied.txt",
      "@@ -1,2 +1,3 @@",
      " new file",
      " second",
      "+extra",
      'diff --git a/a.txt "b/dir \\"q\\"/b.txt"',
      "similarity index 100%",
      "rename from a.txt",
      'rename to "dir \\"q\\"/b.txt"',
      "diff --git a/noeol.txt b/pure_rename.txt",
      "similarity index 100%",
      "rename from noeol.txt",
      "rename to pure_rename.txt",
      "",
    ].join("\n");
    const fs = parseUnifiedDiff(text);
    expect(fs.map((f) => [f.path, f.oldPath, f.status])).toEqual([
      ["copied.txt", "added.txt", "added"],
      ['dir "q"/b.txt', "a.txt", "renamed"],
      ["pure_rename.txt", "noeol.txt", "renamed"],
    ]);
    expect([...fs[0]!.addedLines]).toEqual([3]);
    expect(fs.map((f) => f.raw).join("")).toBe(text);
  });

  it("GIT binary patch payload is not parsed as hunks or headers", () => {
    const text = [
      "diff --git a/img.bin b/img.bin",
      "index 4e0e1df..6b3e62f 100644",
      "GIT binary patch",
      "literal 7",
      "OcmZSJWKPP=GX?+z9szj(",
      "",
      "literal 7",
      "OcmZQzWKPP=GXeku?E!EA",
      "",
      "diff --git a/x.txt b/x.txt",
      "--- a/x.txt",
      "+++ b/x.txt",
      "@@ -1 +1 @@",
      "-a",
      "+b",
      "",
    ].join("\n");
    const fs = parseUnifiedDiff(text);
    expect(fs.map((f) => [f.path, f.status, f.hunks.length])).toEqual([
      ["img.bin", "binary", 0],
      ["x.txt", "modified", 1],
    ]);
  });

  it("removed lines that look like headers stay inside the hunk ('--- ', '+++ ', 'diff --git')", () => {
    const text = [
      "diff --git a/q.sql b/q.sql",
      "--- a/q.sql",
      "+++ b/q.sql",
      "@@ -1,3 +1,3 @@",
      "--- old comment",
      "+++ new comment",
      " select 1;",
      "-diff --git looks like a header",
      "+diff --git still content",
      "",
    ].join("\n");
    // counts: old 1 ("-- old comment") + 1 context + 1 ("diff --git...") = 3; new likewise.
    const fs = parseUnifiedDiff(text);
    expect(fs).toHaveLength(1);
    expect(fs[0]).toMatchObject({ path: "q.sql", additions: 2, deletions: 2 });
    expect(fs[0]!.hunks[0]!.lines).toHaveLength(5);
  });

  it("multiple hunks, CRLF content, hunk header without counts", () => {
    const text = [
      "diff --git a/m.txt b/m.txt",
      "index 1..2 100644",
      "--- a/m.txt",
      "+++ b/m.txt",
      "@@ -1,2 +1,3 @@",
      " a\r",
      "+b\r",
      " c\r",
      "@@ -50 +51 @@",
      "-x",
      "+y",
      "",
    ].join("\n");
    const [f] = parseUnifiedDiff(text);
    expect(f!.hunks.map((h) => [h.oldStart, h.oldLines, h.newStart, h.newLines])).toEqual([
      [1, 2, 1, 3],
      [50, 1, 51, 1],
    ]);
    expect(f!.hunks[0]!.lines[1]).toBe("+b\r");
    expect([...f!.rightLines].sort((a, b) => a - b)).toEqual([1, 2, 3, 51]);
    expect(changedLineCount([f!])).toBe(3);
  });

  it("plain `diff -u` output without git headers", () => {
    const text = [
      "--- old/x.c\t2024-01-01 00:00:00",
      "+++ new/x.c\t2024-01-02 00:00:00",
      "@@ -1 +1,2 @@",
      " int a;",
      "+int b;",
      "",
    ].join("\n");
    const [f] = parseUnifiedDiff(text);
    expect(f).toMatchObject({ path: "new/x.c", status: "modified", additions: 1 });
  });

  it("empty / garbage input yields no files", () => {
    expect(parseUnifiedDiff("")).toEqual([]);
    expect(parseUnifiedDiff("hello\nworld\n")).toEqual([]);
  });

  it("changedLineCount sums additions and deletions", () => {
    expect(changedLineCount(files)).toBe(3 + 2 + 2 + 1 + 1 + 2 + 2 + 2);
    expect(changedLineCount([])).toBe(0);
  });

  it("matches live git output", () => {
    let gitOk = true;
    try {
      execFileSync("git", ["--version"], { stdio: "ignore" });
    } catch {
      gitOk = false;
    }
    if (!gitOk) return;
    const repo = join(dir, "repo");
    mkdirSync(repo);
    const git = (...args: string[]): string =>
      execFileSync("git", ["-C", repo, "-c", "user.email=t@t", "-c", "user.name=t", "-c", "core.quotepath=true", ...args], {
        encoding: "utf8",
      });
    git("init", "-q");
    writeFileSync(join(repo, "a.txt"), "1\n2\n3\n4\n5\n");
    writeFileSync(join(repo, "old name.txt"), Array.from({ length: 20 }, (_, i) => `l${i}`).join("\n") + "\n");
    writeFileSync(join(repo, "bye.txt"), "bye\n");
    git("add", "-A");
    git("commit", "-qm", "base");
    writeFileSync(join(repo, "a.txt"), "1\nTWO\n3\n4\n5\n6");
    git("mv", "old name.txt", "new näme.txt");
    writeFileSync(join(repo, "new näme.txt"), Array.from({ length: 20 }, (_, i) => (i === 10 ? "ten" : `l${i}`)).join("\n") + "\n");
    git("rm", "-q", "bye.txt");
    writeFileSync(join(repo, "bin.dat"), Buffer.from([0, 1, 2, 3]));
    git("add", "-A");
    git("commit", "-qm", "head");
    const text = git("diff", "--no-color", "-U3", "-M", "HEAD~1", "HEAD");
    const fs = parseUnifiedDiff(text);
    expect(fs.map((f) => f.raw).join("")).toBe(text);
    const m = byPath(fs);
    expect(m.get("a.txt")).toMatchObject({ status: "modified", additions: 2, deletions: 1 }); // -2 +TWO +6 (no EOL)
    expect(m.get("new näme.txt")).toMatchObject({ status: "renamed", oldPath: "old name.txt", additions: 1, deletions: 1 });
    expect(m.get("bye.txt")).toMatchObject({ status: "removed", deletions: 1 });
    expect(m.get("bin.dat")?.status).toBe("binary");
    expect(isCommentable(m.get("a.txt")!, 6)).toBe(true);
    expect(isCommentable(m.get("new näme.txt")!, 11)).toBe(true);
  });
});

/* ------------------------------ isCommentable ------------------------------ */

describe("isCommentable", () => {
  // Hunk 1 covers new lines 10..14, hunk 2 covers new lines 20..22; pure-deletion hunk at 30.
  const text = [
    "diff --git a/f.ts b/f.ts",
    "--- a/f.ts",
    "+++ b/f.ts",
    "@@ -10,4 +10,5 @@",
    " ten",
    "-eleven",
    "+ELEVEN",
    "+ELEVEN.5",
    " twelve",
    " thirteen",
    "@@ -19,3 +20,3 @@",
    " a",
    "-b",
    "+B",
    " c",
    "@@ -40,2 +40,0 @@",
    "-gone1",
    "-gone2",
    "",
  ].join("\n");
  const [fd] = parseUnifiedDiff(text);

  it("single lines: context and added lines inside a hunk only", () => {
    expect(fd!.hunks).toHaveLength(3);
    for (const n of [10, 11, 12, 13, 14, 20, 21, 22]) expect(isCommentable(fd!, n), String(n)).toBe(true);
    for (const n of [9, 15, 19, 23, 40, 41, 1000]) expect(isCommentable(fd!, n), String(n)).toBe(false);
  });

  it("ranges must stay within one hunk", () => {
    expect(isCommentable(fd!, 10, 14)).toBe(true);
    expect(isCommentable(fd!, 11, 12)).toBe(true);
    expect(isCommentable(fd!, 20, 22)).toBe(true);
    expect(isCommentable(fd!, 10, 15)).toBe(false); // runs past the hunk end
    expect(isCommentable(fd!, 9, 10)).toBe(false); // starts before the hunk
    expect(isCommentable(fd!, 13, 20)).toBe(false); // spans two hunks
    expect(isCommentable(fd!, 14, 14)).toBe(true);
  });

  it("rejects invalid ranges and line numbers", () => {
    expect(isCommentable(fd!, 12, 11)).toBe(false);
    expect(isCommentable(fd!, 0)).toBe(false);
    expect(isCommentable(fd!, -1)).toBe(false);
    expect(isCommentable(fd!, 1.5)).toBe(false);
    expect(isCommentable(fd!, Number.NaN)).toBe(false);
    expect(isCommentable(fd!, 10, Number.POSITIVE_INFINITY)).toBe(false);
  });

  it("files without hunks (binary, deleted, pure rename) are never commentable", () => {
    const fs = parseUnifiedDiff(PATCH);
    for (const p of ["img.bin", "gone.txt", "script.sh", "empty_new.txt"]) {
      expect(isCommentable(get(fs, p), 1), p).toBe(false);
    }
  });

  it("a truncated hunk only exposes the lines actually present", () => {
    const [t] = parseUnifiedDiff(["--- a/t", "+++ b/t", "@@ -1,3 +1,4 @@", " a", "+b", ""].join("\n"));
    expect(isCommentable(t!, 1)).toBe(true);
    expect(isCommentable(t!, 2)).toBe(true);
    expect(isCommentable(t!, 3)).toBe(false);
    expect(isCommentable(t!, 1, 4)).toBe(false);
  });
});

/* -------------------------------- args ---------------------------------- */

describe("parseCli", () => {
  const spec = {
    repo: { type: "string", required: true },
    pr: { type: "string" },
    "dry-run": { type: "boolean", default: false },
    launcher: { type: "string", default: "docker" },
    glob: { type: "string", multiple: true },
  } as const;

  it("parses strings, booleans, defaults and repeated flags", () => {
    const v = parseCli(["--repo", "acme/api", "--dry-run", "--glob", "a", "--glob=b"], spec);
    expect(v).toEqual({ repo: "acme/api", pr: undefined, "dry-run": true, launcher: "docker", glob: ["a", "b"] });
  });

  it("applies defaults when flags are omitted", () => {
    const v = parseCli(["--repo=x/y"], spec);
    expect(v["dry-run"]).toBe(false);
    expect(v.launcher).toBe("docker");
    expect(v.glob).toBeUndefined();
  });

  it("reports every missing required flag", () => {
    expect(() => parseCli([], spec)).toThrow(/missing required flag: --repo/);
    expect(() => parseCli(["--repo", "  "], spec)).toThrow(/--repo/);
    expect(() =>
      parseCli([], { a: { type: "string", required: true }, b: { type: "string", required: true } }),
    ).toThrow("missing required flags: --a, --b");
  });

  it("rejects unknown flags, positionals and missing values (strict)", () => {
    expect(() => parseCli(["--repo", "x/y", "--nope"], spec)).toThrow();
    expect(() => parseCli(["--repo", "x/y", "extra"], spec)).toThrow();
    expect(() => parseCli(["--repo"], spec)).toThrow();
  });

  it("rejects a default of the wrong type", () => {
    expect(() => parseCli([], { x: { type: "boolean", default: "yes" } })).toThrow(/default must be a boolean/);
  });
});

/* ------------------------------- context -------------------------------- */

describe("PR context", () => {
  const ctx: PrContext = {
    repo: "acme/api",
    number: 42,
    title: "Add orders endpoint",
    body: "",
    author: "octo",
    author_type: "User",
    base_sha: "a".repeat(40),
    head_sha: "b".repeat(40),
    base_ref: "main",
    head_ref: "feature",
    draft: false,
    fork: false,
    html_url: "https://github.com/acme/api/pull/42",
    files: [
      { path: "src/a.ts", status: "modified", additions: 3, deletions: 1 },
      { path: "src/b.ts", status: "renamed", additions: 0, deletions: 0, previous_path: "src/old.ts" },
    ],
    changed_lines: 4,
    ignored_files: [],
  };

  it("CTX_FILES names", () => {
    expect(CTX_FILES).toEqual({ pr: "pr.json", diff: "diff.patch", policy: "policy.resolved.json", prTags: "tags.pr.jsonl" });
  });

  it("writeJsonAtomic + readContext round-trip, leaving no temp files", () => {
    const ctxDir = join(dir, "ctx");
    mkdirSync(ctxDir);
    writeJsonAtomic(join(ctxDir, CTX_FILES.pr), ctx);
    writeJsonAtomic(join(ctxDir, CTX_FILES.pr), { ...ctx, title: "v2" }); // overwrite in place
    expect(readContext(ctxDir)).toEqual({ ...ctx, title: "v2" });
    expect(readdirSync(ctxDir)).toEqual(["pr.json"]);
    expect(readFileSync(join(ctxDir, "pr.json"), "utf8").endsWith("\n")).toBe(true);
  });

  it("readContext reports missing files and schema issues with paths", () => {
    expect(() => readContext(join(dir, "nope"))).toThrow(/cannot read PR context/);
    const bad = join(dir, "bad");
    mkdirSync(bad);
    writeFileSync(join(bad, "pr.json"), JSON.stringify({ ...ctx, number: -1, author_type: "Robot" }));
    let msg = "";
    try {
      readContext(bad);
    } catch (e) {
      msg = (e as Error).message;
    }
    expect(msg).toMatch(/invalid PR context/);
    expect(msg).toMatch(/number/);
    expect(msg).toMatch(/author_type/);
  });

  it("writeJsonAtomic fails cleanly when the directory does not exist", () => {
    expect(() => writeJsonAtomic(join(dir, "missing", "x.json"), {})).toThrow();
  });
});

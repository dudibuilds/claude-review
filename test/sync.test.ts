import { execFileSync, spawnSync } from "node:child_process";
import {
  chmodSync,
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  readlinkSync,
  realpathSync,
  rmSync,
  statSync,
  symlinkSync,
  utimesSync,
  writeFileSync,
} from "node:fs";
import { createServer, type Server } from "node:http";
import { hostname, tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import type { PrContext } from "../src/common/context.js";
import { parsePolicy, resolvePolicy } from "../src/policy/load.js";
import { buildSearchContext } from "../src/search/server.js";
import { grep as searchGrep, read as searchRead } from "../src/search/tools.js";
// Mirror discovery is asserted with the reader xsearch actually uses (there is no second one in sync).
import { discoverMirror } from "../src/search/vfs.js";
import * as syncModule from "../src/sync/sync.js";
import {
  DEFAULT_URL_TEMPLATE,
  LOCK_FILE,
  LOCK_STALE_MS,
  RETIRED_FILE,
  SNAPSHOT_GRACE_MS,
  SyncLockError,
  SyncUsageError,
  acquireLock,
  buildRepoUrl,
  gitEnv,
  isValidRepoName,
  main,
  pruneSnapshots,
  spawnGit,
  syncMirror,
  validateUrlTemplate,
  type GitRunner,
  type GithubApi,
  type SyncReport,
} from "../src/sync/sync.js";

let root: string;
let remotes: string;
let template: string;
let caseNo = 0;

/** Test git helper (inherited env config is fine for local repos; never sign commits). */
function git(cwd: string, ...args: string[]): string {
  return execFileSync(
    "git",
    ["-c", "user.name=Test", "-c", "user.email=test@example.com", "-c", "commit.gpgsign=false", ...args],
    { cwd, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] },
  ).trim();
}

function workDir(repo: string): string {
  return join(root, "work", repo);
}

function bareDir(repo: string): string {
  return join(remotes, `${repo}.git`);
}

function writeFiles(dir: string, files: Record<string, string>): void {
  for (const [rel, text] of Object.entries(files)) {
    mkdirSync(dirname(join(dir, rel)), { recursive: true });
    writeFileSync(join(dir, rel), text);
  }
}

/** Creates work repo + bare remote for owner/name with one commit; returns the commit sha. */
function makeRepo(repo: string, files: Record<string, string> = { "README.md": `# ${repo}\n` }): string {
  const w = workDir(repo);
  mkdirSync(w, { recursive: true });
  git(w, "init", "-q", "-b", "main");
  writeFiles(w, files);
  git(w, "add", "-A");
  git(w, "commit", "-q", "-m", "initial");
  mkdirSync(dirname(bareDir(repo)), { recursive: true });
  git(root, "clone", "-q", "--bare", w, bareDir(repo));
  return git(w, "rev-parse", "HEAD");
}

/** New commit pushed to the bare remote's main; returns its sha. */
function commit(repo: string, files: Record<string, string>): string {
  const w = workDir(repo);
  writeFiles(w, files);
  git(w, "add", "-A");
  git(w, "commit", "-q", "-m", `change ${Object.keys(files).join(",")}`);
  git(w, "push", "-q", bareDir(repo), "HEAD:main");
  return git(w, "rev-parse", "HEAD");
}

function newMirror(): string {
  return join(root, `mirror-${++caseNo}`);
}

function writePolicy(mirrorYaml: string): string {
  const p = join(root, `policy-${++caseNo}.yaml`);
  writeFileSync(p, `version: 1\nmirror:\n${mirrorYaml.replace(/^/gm, "  ")}\n`);
  return p;
}

function policyOf(mirrorYaml: string) {
  return parsePolicy(`version: 1\nmirror:\n${mirrorYaml.replace(/^/gm, "  ")}\n`);
}

interface RunResult {
  code: number;
  stdout: string;
  stderr: string;
  report?: SyncReport;
}

/** stdout / stderr captured for every test (audit lines go to stderr). */
let capturedOut = "";
let capturedErr = "";

async function run(args: string[]): Promise<RunResult> {
  const o0 = capturedOut.length;
  const e0 = capturedErr.length;
  const code = await main(args);
  const stdout = capturedOut.slice(o0);
  const stderr = capturedErr.slice(e0);
  let report: SyncReport | undefined;
  try {
    report = JSON.parse(stdout) as SyncReport;
  } catch {
    report = undefined;
  }
  return { code, stdout, stderr, report };
}

function sync(policy: string, mirror: string, ...extra: string[]): Promise<RunResult> {
  return run(["--policy", policy, "--mirror", mirror, "--url-template", template, ...extra]);
}

function currentTarget(mirror: string, repo: string): string {
  return readlinkSync(join(mirror, repo, "current"));
}

function snapshots(mirror: string, repo: string): string[] {
  return readdirSync(join(mirror, repo, "snapshots")).sort();
}

function meta(mirror: string, repo: string): Record<string, unknown> {
  return JSON.parse(readFileSync(join(mirror, repo, "meta.json"), "utf8")) as Record<string, unknown>;
}

function resultFor(r: RunResult | SyncReport, repo: string) {
  const report = "results" in r ? r : r.report;
  return report?.results.find((x) => x.repo === repo);
}

/** Wrap the real git runner, recording every call. */
function recordingGit(hook?: (args: string[]) => ReturnType<GitRunner> | undefined) {
  const calls: { args: string[]; env: NodeJS.ProcessEnv }[] = [];
  const runner: GitRunner = (args, opts) => {
    calls.push({ args, env: opts.env });
    return hook?.(args) ?? spawnGit(args, opts);
  };
  return { calls, runner };
}

/** Minimal PR context for a search context over the mirror (no changed files). */
function prContext(repo: string): PrContext {
  return {
    repo,
    number: 1,
    title: "t",
    body: "",
    author: "dev",
    author_type: "User",
    base_sha: "0".repeat(40),
    head_sha: "1".repeat(40),
    base_ref: "main",
    head_ref: "fix",
    draft: false,
    fork: false,
    html_url: `https://github.com/${repo}/pull/1`,
    files: [],
    changed_lines: 0,
    ignored_files: [],
  };
}

const quietGithub: GithubApi = {
  listOwnerRepos: async () => {
    throw new Error("unexpected API call");
  },
};

beforeAll(() => {
  root = mkdtempSync(join(tmpdir(), "xrepo-sync-"));
  remotes = join(root, "remotes");
  template = `file://${remotes}/{owner}/{repo}.git`;
});

afterAll(() => {
  rmSync(root, { recursive: true, force: true });
});

let savedToken: string | undefined;
beforeEach(() => {
  savedToken = process.env.XREPO_GITHUB_TOKEN;
  delete process.env.XREPO_GITHUB_TOKEN;
  capturedOut = "";
  capturedErr = "";
  vi.spyOn(process.stdout, "write").mockImplementation((chunk: string | Uint8Array) => {
    capturedOut += String(chunk);
    return true;
  });
  vi.spyOn(process.stderr, "write").mockImplementation((chunk: string | Uint8Array) => {
    capturedErr += String(chunk);
    return true;
  });
});
afterEach(() => {
  if (savedToken === undefined) delete process.env.XREPO_GITHUB_TOKEN;
  else process.env.XREPO_GITHUB_TOKEN = savedToken;
  vi.restoreAllMocks();
});

/* ------------------------------------------------------------------------- */

describe("initial sync", () => {
  it("creates current -> snapshots/<sha>, meta.json and a working tree without .git", async () => {
    const shaA = makeRepo("init1/api", { "src/orders.ts": "export const x = 1;\n", ".github/ci.yml": "on: push\n" });
    const shaB = makeRepo("init1/web");
    const mirror = newMirror();
    const policy = writePolicy("repos: [init1/api, init1/web]");

    const r = await sync(policy, mirror);
    expect(r.code).toBe(0);
    expect(r.report?.failed).toBe(0);
    expect(resultFor(r, "init1/api")).toMatchObject({ action: "synced", sha: shaA, branch: "main" });
    expect(resultFor(r, "init1/web")).toMatchObject({ action: "synced", sha: shaB });

    expect(currentTarget(mirror, "init1/api")).toBe(`snapshots/${shaA}`); // relative symlink
    expect(lstatSync(join(mirror, "init1/api/current")).isSymbolicLink()).toBe(true);
    const snap = join(mirror, "init1/api/snapshots", shaA);
    expect(readFileSync(join(snap, "src/orders.ts"), "utf8")).toBe("export const x = 1;\n");
    expect(readFileSync(join(mirror, "init1/api/current/.github/ci.yml"), "utf8")).toBe("on: push\n");
    expect(existsSync(join(snap, ".git"))).toBe(false);
    expect(snapshots(mirror, "init1/api")).toEqual([shaA]);

    const m = meta(mirror, "init1/api");
    expect(m).toMatchObject({ repo: "init1/api", sha: shaA, branch: "main", description: "" });
    expect(Object.keys(m).sort()).toEqual(["branch", "description", "repo", "sha", "synced_at"]);
    expect(new Date(String(m.synced_at)).toISOString()).toBe(m.synced_at);

    // Readable by the unprivileged search container.
    expect(statSync(join(snap, "src/orders.ts")).mode & 0o444).toBe(0o444);
    expect(statSync(join(snap, "src")).mode & 0o555).toBe(0o555);
    expect(statSync(join(mirror, "init1/api/meta.json")).mode & 0o777).toBe(0o644);

    // The lock is released.
    expect(existsSync(join(mirror, LOCK_FILE))).toBe(false);

    const found = discoverMirror(mirror);
    expect(found.map((e) => e.repo)).toEqual(["init1/api", "init1/web"]);
    expect(found[0]).toMatchObject({ repo: "init1/api", host: realpathSync(snap), sha: shaA, branch: "main" });
  });

  it("makes the mirror readable by the unprivileged search user regardless of umask", async () => {
    makeRepo("umask/api", { "dir/file.txt": "x\n", "run.sh": "#!/bin/sh\n" });
    chmodSync(join(workDir("umask/api"), "run.sh"), 0o755);
    commit("umask/api", { "other.txt": "y\n" });
    const mirror = newMirror();
    const old = process.umask(0o077);
    try {
      const r = await sync(writePolicy("repos: [umask/api]"), mirror);
      expect(r.code).toBe(0);
    } finally {
      process.umask(old);
    }
    const mode = (p: string) => statSync(join(mirror, p)).mode & 0o7777;
    expect(mode("")).toBe(0o755);
    expect(mode("umask")).toBe(0o755);
    expect(mode("umask/api")).toBe(0o755);
    expect(mode("umask/api/snapshots")).toBe(0o755);
    expect(mode("umask/api/current")).toBe(0o755);
    expect(mode("umask/api/current/dir")).toBe(0o755);
    expect(mode("umask/api/current/dir/file.txt")).toBe(0o644);
    expect(mode("umask/api/current/run.sh")).toBe(0o755);
    expect(mode("umask/api/meta.json")).toBe(0o644);
  });

  it("checks symlinks out as plain files and runs no repository hooks", async () => {
    const w = workDir("init2/links");
    mkdirSync(w, { recursive: true });
    git(w, "init", "-q", "-b", "main");
    writeFileSync(join(w, "a.txt"), "a\n");
    symlinkSync("/etc/passwd", join(w, "escape"));
    symlinkSync("a.txt", join(w, "inner"));
    git(w, "add", "-A");
    git(w, "commit", "-q", "-m", "links");
    git(root, "clone", "-q", "--bare", w, bareDir("init2/links"));
    const mirror = newMirror();

    const r = await sync(writePolicy("repos: [init2/links]"), mirror);
    expect(r.code).toBe(0);
    const cur = join(mirror, "init2/links/current");
    expect(lstatSync(join(cur, "escape")).isSymbolicLink()).toBe(false);
    expect(readFileSync(join(cur, "escape"), "utf8")).toBe("/etc/passwd");
    expect(lstatSync(join(cur, "inner")).isFile()).toBe(true);
  });
});

describe("incremental sync", () => {
  it("is a no-op when the remote HEAD equals meta.json sha", async () => {
    const sha = makeRepo("noop/api");
    const mirror = newMirror();
    const policy = writePolicy("repos: [noop/api]");
    expect((await sync(policy, mirror)).code).toBe(0);
    const snapIno = statSync(join(mirror, "noop/api/snapshots", sha)).ino;
    const firstSynced = meta(mirror, "noop/api").synced_at;

    await new Promise((r) => setTimeout(r, 5));
    const r = await sync(policy, mirror);
    expect(r.code).toBe(0);
    expect(resultFor(r, "noop/api")).toMatchObject({ action: "unchanged", sha });
    expect(snapshots(mirror, "noop/api")).toEqual([sha]);
    expect(statSync(join(mirror, "noop/api/snapshots", sha)).ino).toBe(snapIno);
    expect(meta(mirror, "noop/api").sha).toBe(sha);
    expect(String(meta(mirror, "noop/api").synced_at) >= String(firstSynced)).toBe(true);
  });

  it("only runs ls-remote on a no-op", async () => {
    makeRepo("noop2/api");
    const mirror = newMirror();
    const policy = policyOf("repos: [noop2/api]");
    await syncMirror({ policy, mirrorDir: mirror, urlTemplate: template, github: quietGithub });
    const rec = recordingGit();
    const report = await syncMirror({ policy, mirrorDir: mirror, urlTemplate: template, git: rec.runner, github: quietGithub });
    expect(report.results[0]?.action).toBe("unchanged");
    expect(rec.calls.map((c) => c.args[0])).toEqual(["ls-remote"]);
  });

  it("swaps current to a new snapshot when the remote moves", async () => {
    const sha1 = makeRepo("upd/api", { "a.txt": "one\n" });
    const mirror = newMirror();
    const policy = writePolicy("repos: [upd/api]");
    await sync(policy, mirror);
    const sha2 = commit("upd/api", { "a.txt": "two\n" });

    const r = await sync(policy, mirror);
    expect(r.code).toBe(0);
    expect(resultFor(r, "upd/api")).toMatchObject({ action: "synced", sha: sha2, previous_sha: sha1 });
    expect(currentTarget(mirror, "upd/api")).toBe(`snapshots/${sha2}`);
    expect(readFileSync(join(mirror, "upd/api/current/a.txt"), "utf8")).toBe("two\n");
    expect(meta(mirror, "upd/api").sha).toBe(sha2);
    // The previous snapshot is still there (keep_snapshots: 2) and intact.
    expect(snapshots(mirror, "upd/api")).toEqual([sha1, sha2].sort());
    expect(readFileSync(join(mirror, "upd/api/snapshots", sha1, "a.txt"), "utf8")).toBe("one\n");
    expect(discoverMirror(mirror)[0]?.host).toBe(realpathSync(join(mirror, "upd/api/snapshots", sha2)));
    // No temp symlinks / dirs left behind.
    expect(readdirSync(join(mirror, "upd/api")).sort()).toEqual(["current", "meta.json", "snapshots"]);
  });

  it("falls back to fetching HEAD when the server refuses the sha", async () => {
    const sha = makeRepo("fallback/api");
    const mirror = newMirror();
    const rec = recordingGit((args) =>
      args[0] === "fetch" && args[args.length - 1] !== "HEAD"
        ? Promise.resolve({ code: 128, signal: null, stdout: "", stderr: "fatal: not our ref", timedOut: false })
        : undefined,
    );
    const report = await syncMirror({
      policy: policyOf("repos: [fallback/api]"),
      mirrorDir: mirror,
      urlTemplate: template,
      git: rec.runner,
      github: quietGithub,
    });
    expect(report.results[0]).toMatchObject({ action: "synced", sha });
    expect(rec.calls.filter((c) => c.args[0] === "fetch").map((c) => c.args.at(-1))).toEqual([sha, "HEAD"]);
  });

  it("reuses an existing complete snapshot (rollback) without fetching", async () => {
    const sha1 = makeRepo("rollback/api", { "a.txt": "one\n" });
    const mirror = newMirror();
    const policy = policyOf("repos: [rollback/api]");
    const opts = { policy, mirrorDir: mirror, urlTemplate: template, github: quietGithub };
    await syncMirror(opts);
    commit("rollback/api", { "a.txt": "two\n" });
    await syncMirror(opts);
    git(workDir("rollback/api"), "push", "-q", "--force", bareDir("rollback/api"), `${sha1}:main`);

    const rec = recordingGit();
    const report = await syncMirror({ ...opts, git: rec.runner });
    expect(report.results[0]).toMatchObject({ action: "synced", sha: sha1, reused: true });
    expect(rec.calls.map((c) => c.args[0])).toEqual(["ls-remote"]);
    expect(currentTarget(mirror, "rollback/api")).toBe(`snapshots/${sha1}`);
    expect(readFileSync(join(mirror, "rollback/api/current/a.txt"), "utf8")).toBe("one\n");
  });

  it("repairs a missing current symlink even when meta.json is up to date", async () => {
    const sha = makeRepo("repair/api");
    const mirror = newMirror();
    const policy = writePolicy("repos: [repair/api]");
    await sync(policy, mirror);
    rmSync(join(mirror, "repair/api/current"));
    expect(discoverMirror(mirror)).toEqual([]);
    const r = await sync(policy, mirror);
    expect(resultFor(r, "repair/api")).toMatchObject({ action: "synced", sha, reused: true });
    expect(currentTarget(mirror, "repair/api")).toBe(`snapshots/${sha}`);
  });

  it("reports an empty remote without failing", async () => {
    mkdirSync(dirname(bareDir("empty/repo")), { recursive: true });
    git(root, "init", "-q", "--bare", bareDir("empty/repo"));
    makeRepo("empty/ok");
    const mirror = newMirror();
    const r = await sync(writePolicy("repos: [empty/repo, empty/ok]"), mirror);
    expect(r.code).toBe(0);
    expect(resultFor(r, "empty/repo")?.action).toBe("empty");
    expect(resultFor(r, "empty/ok")?.action).toBe("synced");
  });
});

describe("pruning", () => {
  it("keeps current + newest, honouring the grace period for retired snapshots", async () => {
    const sha1 = makeRepo("prune/api", { "v.txt": "1\n" });
    const mirror = newMirror();
    const policy = policyOf("repos: [prune/api]\nkeep_snapshots: 2");
    let now = Date.parse("2026-01-01T00:00:00Z");
    const opts = { policy, mirrorDir: mirror, urlTemplate: template, github: quietGithub, now: () => now };
    await syncMirror(opts);
    const sha2 = commit("prune/api", { "v.txt": "2\n" });
    now += 60_000;
    await syncMirror(opts);
    const sha3 = commit("prune/api", { "v.txt": "3\n" });
    now += 60_000;
    const r3 = await syncMirror(opts);
    expect(r3.pruned).toBe(0);
    // sha1 was retired only a minute ago: still kept although beyond keep_snapshots.
    expect(snapshots(mirror, "prune/api")).toEqual([sha1, sha2, sha3].sort());

    now += SNAPSHOT_GRACE_MS + 60_000;
    const r4 = await syncMirror(opts);
    expect(r4.results[0]?.action).toBe("unchanged");
    expect(r4.pruned).toBe(1);
    expect(snapshots(mirror, "prune/api")).toEqual([sha2, sha3].sort());
    expect(currentTarget(mirror, "prune/api")).toBe(`snapshots/${sha3}`);
  });

  it("never prunes current and cleans stale tmp dirs, temp files and trash", () => {
    const repoDir = join(newMirror(), "acme", "api");
    const snap = join(repoDir, "snapshots");
    const now = Date.parse("2026-02-01T00:00:00Z");
    const sha = (c: string) => c.repeat(40);
    const mk = (name: string, ageMs: number) => {
      mkdirSync(join(snap, name, "sub"), { recursive: true });
      writeFileSync(join(snap, name, "sub", "f"), "x");
      const t = (now - ageMs) / 1000;
      utimesSync(join(snap, name), t, t);
    };
    mk(sha("a"), 5 * 3600_000); // current, but oldest
    mk(sha("b"), 4 * 3600_000);
    mk(sha("c"), 3 * 3600_000);
    mk(`${sha("d")}.tmp-12345`, 2 * 3600_000); // stale tmp
    mk(`${sha("e")}.tmp-12346`, 5 * 60_000); // recent tmp: maybe in progress elsewhere
    mk(".del-1-abc", 0); // leftover trash
    symlinkSync(`snapshots/${sha("a")}`, join(repoDir, "current"));
    writeFileSync(join(repoDir, ".meta.json.1.ab.tmp"), "{}");
    const old = (now - 2 * 3600_000) / 1000;
    utimesSync(join(repoDir, ".meta.json.1.ab.tmp"), old, old);

    const pruned = pruneSnapshots(repoDir, 1, now);
    expect(pruned).toBe(2);
    expect(readdirSync(snap).sort()).toEqual([sha("a"), `${sha("e")}.tmp-12346`]);
    expect(existsSync(join(repoDir, ".meta.json.1.ab.tmp"))).toBe(false);
  });

  it("keeps a snapshot retired within the grace period even with keep_snapshots: 1", () => {
    const repoDir = join(newMirror(), "acme", "api");
    const snap = join(repoDir, "snapshots");
    const now = Date.parse("2026-02-01T00:00:00Z");
    const set = (name: string, ageMs: number) => {
      mkdirSync(join(snap, name), { recursive: true });
      const t = (now - ageMs) / 1000;
      utimesSync(join(snap, name), t, t);
    };
    set("a".repeat(40), 3 * 3600_000);
    set("b".repeat(40), 2 * 60_000); // became current 2 minutes ago -> a retired 2 minutes ago
    symlinkSync(`snapshots/${"b".repeat(40)}`, join(repoDir, "current"));
    expect(pruneSnapshots(repoDir, 1, now)).toBe(0);
    expect(pruneSnapshots(repoDir, 1, now + SNAPSHOT_GRACE_MS - 3 * 60_000)).toBe(0);
    expect(pruneSnapshots(repoDir, 1, now + SNAPSHOT_GRACE_MS)).toBe(1);
    expect(readdirSync(snap)).toEqual(["b".repeat(40)]);
  });

  // Regression (sync-prunes-snapshot-in-use / snapshot-pruned-mid-review): the grace period used to
  // be 10 minutes, so two synced pushes (one with keep_snapshots: 1) deleted the snapshot a running
  // review had pinned about 12 minutes in, although a review job may run for 45 minutes.
  it("the grace period exceeds the review job timeout (review.yml timeout-minutes: 45)", () => {
    const reviewYml = readFileSync(join(import.meta.dirname, "..", ".github", "workflows", "review.yml"), "utf8");
    const timeouts = [...reviewYml.matchAll(/timeout-minutes:\s*(\d+)/g)].map((m) => Number(m[1]));
    expect(timeouts.length).toBeGreaterThan(0);
    expect(SNAPSHOT_GRACE_MS).toBeGreaterThan(Math.max(...timeouts) * 60_000);
  });

  for (const keep of [1, 2]) {
    it(`a running review keeps its pinned snapshot for the whole review job (keep_snapshots: ${keep})`, async () => {
      const repo = `pin${keep}/api`;
      makeRepo(repo, { "api.ts": "export const v = 0;\n" });
      const mirror = newMirror();
      const t0 = Date.parse("2026-03-01T00:00:00Z");
      let now = t0;
      const opts = {
        policy: policyOf(`repos: [${repo}]\nkeep_snapshots: ${keep}`),
        mirrorDir: mirror,
        urlTemplate: template,
        github: quietGithub,
        now: () => now,
      };
      await syncMirror(opts);
      // The review's xsearch pins the snapshot `current` names when it starts (vfs.discoverMirror).
      const pinned = discoverMirror(mirror).find((r) => r.repo === repo)!;
      expect(readFileSync(join(pinned.host, "api.ts"), "utf8")).toBe("export const v = 0;\n");

      // A push lands before every scheduled sync (*/10) while the review runs; the first one retires
      // the pinned snapshot right after the review started (worst case).
      const REVIEW_JOB_MS = 45 * 60_000;
      let pruned = 0;
      let v = 0;
      for (const at of [30_000, 10 * 60_000, 20 * 60_000, 30 * 60_000, 40 * 60_000]) {
        commit(repo, { "api.ts": `export const v = ${++v};\n` });
        now = t0 + at;
        const r = await syncMirror(opts);
        expect(r.results[0]?.action).toBe("synced");
        pruned += r.pruned;
        expect(readFileSync(join(pinned.host, "api.ts"), "utf8"), `+${at / 60_000} min`).toBe("export const v = 0;\n");
      }
      now = t0 + REVIEW_JOB_MS; // the latest a review job can still be reading
      pruned += (await syncMirror(opts)).pruned;
      expect(existsSync(join(pinned.host, "api.ts"))).toBe(true);
      expect(discoverMirror(mirror).find((r) => r.repo === repo)?.sha).not.toBe(pinned.sha);

      // Once retired for the whole grace period it is pruned: retained snapshots stay bounded.
      now = t0 + 30_000 + SNAPSHOT_GRACE_MS;
      pruned += (await syncMirror(opts)).pruned;
      expect(existsSync(pinned.host)).toBe(false);
      expect(pruned).toBeGreaterThanOrEqual(1);
      now = t0 + 40 * 60_000 + SNAPSHOT_GRACE_MS;
      await syncMirror(opts);
      expect(snapshots(mirror, repo)).toHaveLength(keep);
    });
  }

  it("the grace period is configurable (snapshotGraceMs, --snapshot-grace-minutes) and validated", async () => {
    const repoDir = join(newMirror(), "acme", "api");
    const snap = join(repoDir, "snapshots");
    const now = Date.parse("2026-02-01T00:00:00Z");
    for (const [name, ageMs] of [["a".repeat(40), 3600_000], ["b".repeat(40), 60_000]] as const) {
      mkdirSync(join(snap, name), { recursive: true });
      utimesSync(join(snap, name), (now - ageMs) / 1000, (now - ageMs) / 1000);
    }
    symlinkSync(`snapshots/${"b".repeat(40)}`, join(repoDir, "current"));
    expect(pruneSnapshots(repoDir, 1, now, 2 * 60_000)).toBe(0);
    expect(pruneSnapshots(repoDir, 1, now, 60_000)).toBe(1);

    const policy = policyOf("repos: [acme/api]");
    for (const bad of [-1, 1.5, Number.NaN, 8 * 24 * 3600_000]) {
      await expect(syncMirror({ policy, mirrorDir: newMirror(), urlTemplate: template, snapshotGraceMs: bad })).rejects.toThrow(
        SyncUsageError,
      );
    }

    const sha1 = makeRepo("grace/api", { "v.txt": "1\n" });
    const mirror = newMirror();
    const policyFile = writePolicy("repos: [grace/api]\nkeep_snapshots: 1");
    for (const bad of ["abc", "-5", "1.5", "10081", ""]) {
      expect((await sync(policyFile, mirror, "--snapshot-grace-minutes", bad)).code, bad).toBe(2);
    }
    expect(existsSync(mirror)).toBe(false);
    expect((await sync(policyFile, mirror, "--snapshot-grace-minutes", "0")).code).toBe(0);
    const sha2 = commit("grace/api", { "v.txt": "2\n" });
    expect((await sync(policyFile, mirror, "--snapshot-grace-minutes", "0")).code).toBe(0);
    await new Promise((r) => setTimeout(r, 5));
    expect((await sync(policyFile, mirror, "--snapshot-grace-minutes", "0")).code).toBe(0);
    expect(snapshots(mirror, "grace/api")).toEqual([sha2]);
    expect(sha1).not.toBe(sha2);
    // Default (no flag): a just-retired snapshot is kept.
    commit("grace/api", { "v.txt": "3\n" });
    expect((await sync(policyFile, mirror)).code).toBe(0);
    expect(snapshots(mirror, "grace/api")).toContain(sha2);
  });
});

describe("removal", () => {
  it("removes mirrored repos no longer in the policy, but nothing that is not a mirror repo", async () => {
    makeRepo("rm/api");
    makeRepo("rm/web");
    makeRepo("rmother/lib");
    const mirror = newMirror();
    await sync(writePolicy("repos: [rm/api, rm/web, rmother/lib]"), mirror);
    // Unrelated data inside the mirror dir must survive.
    mkdirSync(join(mirror, "rm", "notes"), { recursive: true });
    writeFileSync(join(mirror, "rm", "notes", "todo.txt"), "keep me");

    const policy2 = writePolicy("repos: [rm/api]");
    const dry = await sync(policy2, mirror, "--dry-run");
    expect(dry.code).toBe(0);
    expect(dry.report?.retired.sort()).toEqual(["rm/web", "rmother/lib"]);
    expect(dry.report?.removed).toEqual([]);
    expect(existsSync(join(mirror, "rm/web/current"))).toBe(true);
    expect(existsSync(join(mirror, "rm/web", RETIRED_FILE))).toBe(false);
    // Grace 0, dry run: would be deleted at once.
    const dry0 = await sync(policy2, mirror, "--dry-run", "--snapshot-grace-minutes", "0");
    expect(dry0.report?.removed.sort()).toEqual(["rm/web", "rmother/lib"]);
    expect(existsSync(join(mirror, "rm/web/current"))).toBe(true);

    // Default grace: retired (no longer discoverable), still on disk.
    const r = await sync(policy2, mirror);
    expect(r.code).toBe(0);
    expect(r.report?.retired.sort()).toEqual(["rm/web", "rmother/lib"]);
    expect(r.report?.removed).toEqual([]);
    expect(existsSync(join(mirror, "rm/web/current"))).toBe(false);
    expect(existsSync(join(mirror, "rm/web/snapshots"))).toBe(true);
    expect(discoverMirror(mirror).map((e) => e.repo)).toEqual(["rm/api"]);

    // Grace 0: deleted.
    const r0 = await sync(policy2, mirror, "--snapshot-grace-minutes", "0");
    expect(r0.code).toBe(0);
    expect(r0.report?.removed.sort()).toEqual(["rm/web", "rmother/lib"]);
    expect(r0.report?.retired).toEqual([]);
    expect(existsSync(join(mirror, "rm/web"))).toBe(false);
    expect(existsSync(join(mirror, "rmother"))).toBe(false); // emptied owner dir removed
    expect(readFileSync(join(mirror, "rm/notes/todo.txt"), "utf8")).toBe("keep me");
    expect(discoverMirror(mirror).map((e) => e.repo)).toEqual(["rm/api"]);
    expect(readdirSync(mirror).filter((e) => e.startsWith("."))).toEqual([]); // no trash left
  });

  it("removes excluded repos and keeps everything when --repo restricts the run", async () => {
    makeRepo("rmx/api");
    makeRepo("rmx/web");
    const mirror = newMirror();
    await sync(writePolicy("repos: [rmx/api, rmx/web]"), mirror);

    const partial = await sync(writePolicy("repos: [rmx/api]"), mirror, "--repo", "rmx/api");
    expect(partial.code).toBe(0);
    expect(partial.report?.removed).toEqual([]);
    expect(existsSync(join(mirror, "rmx/web/current"))).toBe(true);

    expect(partial.report?.retired).toEqual([]);
    expect(existsSync(join(mirror, "rmx/web", RETIRED_FILE))).toBe(false);

    const exclPolicy = writePolicy("repos: [rmx/api, rmx/web]\nexclude: [rmx/web]");
    const excl = await sync(exclPolicy, mirror);
    expect(excl.report?.retired).toEqual(["rmx/web"]);
    expect(existsSync(join(mirror, "rmx/web/current"))).toBe(false);
    const excl0 = await sync(exclPolicy, mirror, "--snapshot-grace-minutes", "0");
    expect(excl0.report?.removed).toEqual(["rmx/web"]);
    expect(existsSync(join(mirror, "rmx/web"))).toBe(false);
  });

  it("does not remove an owner's mirrors when listing owner/* fails", async () => {
    makeRepo("rmapi/api");
    const mirror = newMirror();
    const policy = policyOf("repos: [rmapi/api]");
    await syncMirror({ policy, mirrorDir: mirror, urlTemplate: template, github: quietGithub });
    const failing: GithubApi = {
      listOwnerRepos: async () => {
        throw new Error("HTTP 502");
      },
    };
    const report = await syncMirror({
      policy: policyOf('repos: ["rmapi/*"]'),
      mirrorDir: mirror,
      urlTemplate: template,
      github: failing,
    });
    expect(report.failed).toBe(1);
    expect(report.results[0]).toMatchObject({ repo: "rmapi/*", action: "failed" });
    expect(report.results[0]?.error).toContain("HTTP 502");
    expect(report.removed).toEqual([]);
    expect(report.retired).toEqual([]);
    expect(existsSync(join(mirror, "rmapi/api/current"))).toBe(true);
    expect(existsSync(join(mirror, "rmapi/api", RETIRED_FILE))).toBe(false);
  });

  // Regression (remove-unlisted-ignores-grace): a repo dropped from the desired set was deleted on the
  // very next sync, under reviews reading it; an xsearch whose root vanished failed every default Grep.
  it("retires a dropped repo at once and deletes it only after the grace period, under a running review", async () => {
    makeRepo("grc/api", { "src/api.ts": "export const NEEDLE_API = 1;\n" });
    makeRepo("grc/web", { "src/a.ts": "export const NEEDLE_WEB = 1;\n" });
    const mirror = newMirror();
    let now = Date.parse("2026-01-01T00:00:00Z");
    const base = { mirrorDir: mirror, urlTemplate: template, github: quietGithub, now: () => now };
    const both = policyOf("repos: [grc/api, grc/web]");
    const one = policyOf("repos: [grc/api]");
    expect((await syncMirror({ ...base, policy: both })).failed).toBe(0);

    // A review starts: xsearch pins the snapshot `current` names (the same code path as the server).
    const prDir = join(root, `pr-${++caseNo}`);
    writeFiles(prDir, { "src/pr.ts": "export const NEEDLE_PR = 1;\n" });
    const sc = buildSearchContext({
      policy: resolvePolicy(parsePolicy('version: 1\nrepos:\n  grc/app:\n    cross_repo:\n      readable: ["grc/*"]\n'), "grc/app"),
      ctx: prContext("grc/app"),
      diffText: "",
      prDir,
      mirrorDir: mirror,
    });
    const grepAll = async () => {
      const res = await searchGrep(sc, { pattern: "NEEDLE_" });
      expect(res.isError).toBeFalsy();
      return res.text.split("\n").filter((l) => l.startsWith("/")).sort();
    };
    const expected = ["/pr/src/pr.ts", "/repos/grc/api/src/api.ts", "/repos/grc/web/src/a.ts"];
    expect(await grepAll()).toEqual(expected);

    // Mid-review the repo drops out of the desired set (archived, renamed, policy edit, ...).
    now += 10 * 60_000;
    const retiredAt = now;
    const r1 = await syncMirror({ ...base, policy: one });
    expect(r1).toMatchObject({ removed: [], retired: ["grc/web"], failed: 0 });
    expect(existsSync(join(mirror, "grc/web/current"))).toBe(false);
    expect(discoverMirror(mirror).map((e) => e.repo)).toEqual(["grc/api"]); // reviews starting now no longer see it
    const marker = () => JSON.parse(readFileSync(join(mirror, "grc/web", RETIRED_FILE), "utf8")) as unknown;
    expect(marker()).toEqual({ retired_at: new Date(retiredAt).toISOString() });
    // The running review still reads it, and its default Grep still works.
    expect(await grepAll()).toEqual(expected);
    expect((await searchRead(sc, { file_path: "/repos/grc/web/src/a.ts" })).text).toContain("NEEDLE_WEB");

    // Every sync within the grace period (the cron runs every 10 minutes) keeps it, marker untouched.
    for (const dt of [10 * 60_000, 45 * 60_000, SNAPSHOT_GRACE_MS - 1]) {
      now = retiredAt + dt;
      expect(await syncMirror({ ...base, policy: one })).toMatchObject({ removed: [], retired: ["grc/web"], failed: 0 });
      expect(await grepAll()).toEqual(expected);
    }
    expect(marker()).toEqual({ retired_at: new Date(retiredAt).toISOString() });

    // Grace period over: a dry run says so without deleting; the real run deletes it.
    now = retiredAt + SNAPSHOT_GRACE_MS;
    expect(await syncMirror({ ...base, policy: one, dryRun: true })).toMatchObject({ removed: ["grc/web"], retired: [] });
    expect(existsSync(join(mirror, "grc/web", RETIRED_FILE))).toBe(true);
    const r2 = await syncMirror({ ...base, policy: one });
    expect(r2).toMatchObject({ removed: ["grc/web"], retired: [], failed: 0 });
    expect(existsSync(join(mirror, "grc/web"))).toBe(false);
    expect(existsSync(join(mirror, "grc/api/current"))).toBe(true);
    expect(readdirSync(mirror).filter((e) => e.startsWith("."))).toEqual([]);
  });

  it("honours a custom grace period for dropped repos", async () => {
    makeRepo("grx/api");
    makeRepo("grx/web");
    const mirror = newMirror();
    let now = Date.parse("2026-01-01T00:00:00Z");
    const base = { mirrorDir: mirror, urlTemplate: template, github: quietGithub, now: () => now, snapshotGraceMs: 5 * 60_000 };
    await syncMirror({ ...base, policy: policyOf("repos: [grx/api, grx/web]") });
    const one = policyOf("repos: [grx/api]");
    expect(await syncMirror({ ...base, policy: one })).toMatchObject({ retired: ["grx/web"], removed: [] });
    now += 5 * 60_000 - 1;
    expect(await syncMirror({ ...base, policy: one })).toMatchObject({ retired: ["grx/web"], removed: [] });
    now += 1;
    expect(await syncMirror({ ...base, policy: one })).toMatchObject({ retired: [], removed: ["grx/web"] });
  });

  it("restores a retired repo that is listed again, and restarts the grace period when it drops out again", async () => {
    makeRepo("grb/api");
    const shaWeb = makeRepo("grb/web");
    const mirror = newMirror();
    let now = Date.parse("2026-01-01T00:00:00Z");
    const base = { mirrorDir: mirror, urlTemplate: template, github: quietGithub, now: () => now };
    const both = policyOf("repos: [grb/api, grb/web]");
    const one = policyOf("repos: [grb/api]");
    await syncMirror({ ...base, policy: both });
    now += 60_000;
    expect(await syncMirror({ ...base, policy: one })).toMatchObject({ retired: ["grb/web"] });

    now += 30 * 60_000; // listed again (e.g. unarchived) within the grace period
    const back = await syncMirror({ ...base, policy: both });
    expect(back).toMatchObject({ removed: [], retired: [], failed: 0 });
    expect(resultFor(back, "grb/web")).toMatchObject({ action: "synced", sha: shaWeb, reused: true });
    expect(currentTarget(mirror, "grb/web")).toBe(`snapshots/${shaWeb}`);
    expect(existsSync(join(mirror, "grb/web", RETIRED_FILE))).toBe(false);
    expect(discoverMirror(mirror).map((e) => e.repo)).toEqual(["grb/api", "grb/web"]);

    // Dropped again 70 minutes after the first retirement: reviews may have started on it since it
    // came back, so the grace period starts over instead of counting from the first retirement.
    now += 40 * 60_000;
    expect(await syncMirror({ ...base, policy: one })).toMatchObject({ removed: [], retired: ["grb/web"] });
    expect(existsSync(join(mirror, "grb/web/snapshots", shaWeb))).toBe(true);
    now += SNAPSHOT_GRACE_MS;
    expect(await syncMirror({ ...base, policy: one })).toMatchObject({ removed: ["grb/web"], retired: [] });
  });

  it("never deletes early: a missing, unreadable or future-dated marker, or a live current, restarts the grace period", async () => {
    makeRepo("grm/api");
    const sha = makeRepo("grm/web");
    const mirror = newMirror();
    let now = Date.parse("2026-01-01T00:00:00Z");
    const base = { mirrorDir: mirror, urlTemplate: template, github: quietGithub, now: () => now };
    const one = policyOf("repos: [grm/api]");
    await syncMirror({ ...base, policy: policyOf("repos: [grm/api, grm/web]") });
    const repoDir = join(mirror, "grm/web");
    const markerPath = join(repoDir, RETIRED_FILE);
    const markerAt = () => (JSON.parse(readFileSync(markerPath, "utf8")) as { retired_at: string }).retired_at;
    const step = async (prepare: () => void) => {
      now += SNAPSHOT_GRACE_MS; // the previous retirement's grace period is over...
      prepare();
      const r = await syncMirror({ ...base, policy: one });
      expect(r).toMatchObject({ removed: [], retired: ["grm/web"] }); // ...but the repo stays
      expect(markerAt()).toBe(new Date(now).toISOString()); // retired again from now
      expect(existsSync(join(repoDir, "current"))).toBe(false);
      expect(existsSync(join(repoDir, "snapshots", sha))).toBe(true);
    };
    await step(() => {}); // first retirement (current present)
    await step(() => writeFileSync(markerPath, "not json")); // unreadable marker
    await step(() => rmSync(markerPath)); // missing marker
    await step(() => writeFileSync(markerPath, JSON.stringify({ retired_at: new Date(now + 86_400_000).toISOString() })));
    // A crash between writing the marker and unlinking current (or a stale marker next to a restored
    // current): the repo was listed until now.
    await step(() => {
      writeFileSync(markerPath, JSON.stringify({ retired_at: new Date(0).toISOString() }));
      symlinkSync(`snapshots/${sha}`, join(repoDir, "current"));
    });
    now += SNAPSHOT_GRACE_MS;
    expect(await syncMirror({ ...base, policy: one })).toMatchObject({ removed: ["grm/web"], retired: [] });
    expect(existsSync(repoDir)).toBe(false);
  });

  // Regression: GitHub names are case-insensitive. After "csr/api" became "CsR/API" (policy edit) or
  // "CSR/Api" (owner/* listing), sync wrote into the existing directory on a case-insensitive
  // filesystem and then retired it as unlisted; on a case-sensitive one it cloned a second copy.
  it("keeps one directory per repo, never retired, when the desired spelling changes case", async () => {
    const sha = makeRepo("csr/api");
    for (const spelling of ["CsR/API", "CSR/Api"]) {
      // The file:// remote must resolve under every spelling on a case-sensitive filesystem too.
      if (!existsSync(bareDir(spelling))) {
        mkdirSync(dirname(bareDir(spelling)), { recursive: true });
        symlinkSync(bareDir("csr/api"), bareDir(spelling));
      }
    }
    const mirror = newMirror();
    const base = { mirrorDir: mirror, urlTemplate: template, snapshotGraceMs: 0 };
    await syncMirror({ ...base, policy: policyOf("repos: [csr/api]"), github: quietGithub });
    const listing: GithubApi = { listOwnerRepos: async () => [{ full_name: "CSR/Api" }] };
    for (const [policy, github, repo] of [
      [policyOf("repos: [CsR/API]"), quietGithub, "CsR/API"],
      [policyOf('repos: ["csr/*"]'), listing, "CSR/Api"],
    ] as const) {
      for (let i = 0; i < 2; i++) {
        const r = await syncMirror({ ...base, policy, github });
        expect(r).toMatchObject({ removed: [], retired: [], failed: 0 });
        expect(resultFor(r, repo)).toMatchObject({ action: "unchanged", sha });
        expect(readdirSync(mirror)).toEqual(["csr"]);
        expect(readdirSync(join(mirror, "csr"))).toEqual(["api"]);
        expect(existsSync(join(mirror, "csr/api", RETIRED_FILE))).toBe(false);
        expect(discoverMirror(mirror).map((e) => [e.repo, e.sha])).toEqual([["csr/api", sha]]);
      }
    }
  });

  it("still refuses to delete a retired-looking directory that holds anything sync does not create", async () => {
    makeRepo("grs/api");
    makeRepo("grs/web");
    const mirror = newMirror();
    const one = writePolicy("repos: [grs/api]");
    await sync(writePolicy("repos: [grs/api, grs/web]"), mirror);
    expect((await sync(one, mirror)).report?.retired).toEqual(["grs/web"]);
    writeFileSync(join(mirror, "grs/web/notes.txt"), "keep me");
    const r = await sync(one, mirror, "--snapshot-grace-minutes", "0");
    expect(r.report).toMatchObject({ removed: [], retired: [] });
    expect(readFileSync(join(mirror, "grs/web/notes.txt"), "utf8")).toBe("keep me");
    expect(r.stderr).toContain('"event":"sync.remove_skipped"');
  });
});

describe("lock", () => {
  it("refuses to run while a live process holds the lock (exit 3) and leaves the lock alone", async () => {
    makeRepo("lock1/api");
    const mirror = newMirror();
    mkdirSync(mirror, { recursive: true });
    const held = acquireLock(mirror);
    const before = readFileSync(held.path, "utf8");
    try {
      const r = await sync(writePolicy("repos: [lock1/api]"), mirror);
      expect(r.code).toBe(3);
      expect(r.stderr).toContain("another sync holds");
      expect(existsSync(join(mirror, "lock1"))).toBe(false);
      expect(readFileSync(held.path, "utf8")).toBe(before);
    } finally {
      held.release();
    }
    expect(existsSync(join(mirror, LOCK_FILE))).toBe(false);
  });

  it("takes over a lock left by a dead process", async () => {
    makeRepo("lock2/api");
    const mirror = newMirror();
    mkdirSync(mirror, { recursive: true });
    const dead = spawnSync(process.execPath, ["-e", ""]).pid;
    writeFileSync(
      join(mirror, LOCK_FILE),
      JSON.stringify({ pid: dead, host: hostname(), started_at: new Date().toISOString() }),
    );
    const r = await sync(writePolicy("repos: [lock2/api]"), mirror);
    expect(r.code).toBe(0);
    expect(resultFor(r, "lock2/api")?.action).toBe("synced");
    expect(existsSync(join(mirror, LOCK_FILE))).toBe(false);
  });

  it("treats a lock from another host or a reused pid correctly", () => {
    const mirror = newMirror();
    mkdirSync(mirror, { recursive: true });
    const lockPath = join(mirror, LOCK_FILE);
    // Another host with a recent heartbeat: held.
    writeFileSync(lockPath, JSON.stringify({ pid: 1, host: "some-other-host", started_at: "x" }));
    expect(() => acquireLock(mirror)).toThrow(SyncLockError);
    let err: unknown;
    try {
      acquireLock(mirror);
    } catch (e) {
      err = e;
    }
    expect((err as SyncLockError).message).toMatch(/another sync holds .* \(last heartbeat \d+s ago\)/);
    expect((err as SyncLockError).heartbeatAgeMs).toBeLessThan(60_000);
    expect((err as SyncLockError).holder).toMatchObject({ pid: 1, host: "some-other-host" });
    // "null" / non-object content is not a crash: a fresh one is held, an old one is stale.
    writeFileSync(lockPath, "null");
    expect(() => acquireLock(mirror)).toThrow(SyncLockError);
    const old = (Date.now() - 120_000) / 1000;
    utimesSync(lockPath, old, old);
    acquireLock(mirror).release();
    expect(existsSync(lockPath)).toBe(false);
    // Our own pid but a different process start time -> pid was reused -> stale.
    writeFileSync(lockPath, JSON.stringify({ pid: process.pid, host: hostname(), start: "-1", started_at: "x" }));
    if (existsSync(`/proc/${process.pid}/stat`)) {
      const lock = acquireLock(mirror);
      expect(JSON.parse(readFileSync(lockPath, "utf8")).pid).toBe(process.pid);
      lock.release();
      expect(existsSync(lockPath)).toBe(false);
    }
  });

  // Regression (sync-foreign-host-lock-never-expires): a lock from another hostname used to be held
  // forever, so one killed sync froze the mirror while every scheduled run exited 3 (green).
  it("takes over another host's lock once its heartbeat is older than LOCK_STALE_MS", async () => {
    makeRepo("lock4/api");
    const mirror = newMirror();
    mkdirSync(mirror, { recursive: true });
    const lockPath = join(mirror, LOCK_FILE);
    const foreign = JSON.stringify({ pid: 12345, host: "runner-pod-7f9c-old", started_at: "2026-01-01T00:00:00Z" });
    const policy = writePolicy("repos: [lock4/api]");

    // Heartbeat a minute short of stale: a live sync elsewhere, refused (exit 3) and left alone.
    writeFileSync(lockPath, foreign);
    const recent = (Date.now() - LOCK_STALE_MS + 60_000) / 1000;
    utimesSync(lockPath, recent, recent);
    const held = await sync(policy, mirror);
    expect(held.code).toBe(3);
    expect(held.stderr).toContain('"event":"sync.lock_held"');
    expect(held.stderr).toMatch(/"heartbeat_age_s":\d+/);
    expect(readFileSync(lockPath, "utf8")).toBe(foreign);
    expect(existsSync(join(mirror, "lock4"))).toBe(false);

    // Ten months without a heartbeat: abandoned, taken over, synced.
    const ancient = Date.parse("2026-01-01T00:00:00Z") / 1000;
    utimesSync(lockPath, ancient, ancient);
    const r = await sync(policy, mirror);
    expect(r.code).toBe(0);
    expect(r.stderr).toContain('"event":"sync.lock_stale_removed"');
    expect(resultFor(r, "lock4/api")?.action).toBe("synced");
    expect(existsSync(lockPath)).toBe(false);

    // Same host, live pid, but no start time to verify it: the heartbeat decides as well.
    writeFileSync(lockPath, JSON.stringify({ pid: process.pid, host: hostname(), started_at: "x" }));
    expect(() => acquireLock(mirror)).toThrow(SyncLockError);
    utimesSync(lockPath, ancient, ancient);
    acquireLock(mirror).release();
    expect(existsSync(lockPath)).toBe(false);
  });

  it("refreshes the lock's mtime while held and never touches or removes a lock taken over meanwhile", async () => {
    const mirror = newMirror();
    mkdirSync(mirror, { recursive: true });
    const lockPath = join(mirror, LOCK_FILE);
    const old = (Date.now() - 3600_000) / 1000;

    const lock = acquireLock(mirror, { heartbeatMs: 10 });
    utimesSync(lockPath, old, old);
    await vi.waitFor(() => expect(Date.now() - statSync(lockPath).mtimeMs).toBeLessThan(60_000), { timeout: 2000 });
    lock.release();
    lock.release(); // idempotent
    expect(existsSync(lockPath)).toBe(false);

    // Taken over (the file replaced by another holder): the old holder neither heartbeats nor removes it.
    const lock2 = acquireLock(mirror, { heartbeatMs: 10 });
    rmSync(lockPath);
    const other = JSON.stringify({ pid: 1, host: "other-host", started_at: "y" });
    writeFileSync(lockPath, other);
    utimesSync(lockPath, old, old);
    await vi.waitFor(() => expect(capturedErr).toContain('"event":"sync.lock_lost"'), { timeout: 2000 });
    await new Promise((r) => setTimeout(r, 50));
    expect(Date.now() - statSync(lockPath).mtimeMs).toBeGreaterThan(3000_000);
    lock2.release();
    expect(readFileSync(lockPath, "utf8")).toBe(other);
  });

  it("xrepo sync releases the lock when it is interrupted by a signal", async () => {
    const mirror = newMirror();
    const bin = join(root, "fake-git-bin");
    mkdirSync(bin, { recursive: true });
    // A git that hangs for a moment, like a slow fetch when the job is cancelled.
    writeFileSync(join(bin, "git"), "#!/bin/sh\nsleep 1\nexit 1\n");
    chmodSync(join(bin, "git"), 0o755);
    const savedPath = process.env.PATH;
    process.env.PATH = `${bin}:${savedPath ?? ""}`;
    const exit = vi.spyOn(process, "exit").mockImplementation((() => undefined) as never);
    type Listener = (...args: unknown[]) => void;
    const before = {
      SIGINT: process.listeners("SIGINT") as Listener[],
      SIGTERM: process.listeners("SIGTERM") as Listener[],
    };
    try {
      const running = sync(writePolicy("repos: [sig/api]"), mirror);
      await vi.waitFor(() => expect(existsSync(join(mirror, LOCK_FILE))).toBe(true), { timeout: 5000 });
      const added = (process.listeners("SIGINT") as Listener[]).filter((l) => !before.SIGINT.includes(l));
      expect(added).toHaveLength(1);
      added[0]!("SIGINT");
      expect(exit).toHaveBeenCalledWith(130);
      expect(existsSync(join(mirror, LOCK_FILE))).toBe(false);
      expect(capturedErr).toContain('"event":"sync.interrupted"');
      await running; // process.exit is mocked: the run finishes (git fails) without a lock to release
    } finally {
      process.env.PATH = savedPath;
    }
    expect(process.listeners("SIGINT")).toEqual(before.SIGINT);
    expect(process.listeners("SIGTERM")).toEqual(before.SIGTERM);
  });

  it("allows only one of two concurrent syncs and releases the lock after failures", async () => {
    makeRepo("lock3/api");
    const mirror = newMirror();
    const policy = policyOf("repos: [lock3/api, lock3/missing]");
    const opts = { policy, mirrorDir: mirror, urlTemplate: template, github: quietGithub };
    const results = await Promise.allSettled([syncMirror(opts), syncMirror(opts)]);
    const ok = results.filter((r) => r.status === "fulfilled");
    const locked = results.filter((r) => r.status === "rejected");
    expect(ok).toHaveLength(1);
    expect(locked).toHaveLength(1);
    expect((locked[0] as PromiseRejectedResult).reason).toBeInstanceOf(SyncLockError);
    expect((ok[0] as PromiseFulfilledResult<SyncReport>).value.failed).toBe(1);
    expect(existsSync(join(mirror, LOCK_FILE))).toBe(false);
  });
});

describe("repo names and errors", () => {
  it("validates repo names strictly", () => {
    for (const ok of ["acme/api", "Acme-Inc/web.app", "acme/.github", "user_emu/repo_1", "a/b"]) {
      expect(isValidRepoName(ok), ok).toBe(true);
    }
    for (const bad of [
      "acme",
      "a/b/c",
      "acme/..",
      "acme/.",
      "../x",
      ".hidden/x",
      "-x/y",
      "acme/-y",
      "acme/foo$bar",
      "acme/.git", // never served by xsearch
      "acme/.GIT",
      "acme/x:y",
      "acme/x y",
      "acme/",
      "/x",
      "acme/*",
      "",
      `acme/${"x".repeat(101)}`,
    ]) {
      expect(isValidRepoName(bad), bad).toBe(false);
    }
    expect(() => buildRepoUrl(DEFAULT_URL_TEMPLATE, "acme/../x")).toThrow();
    expect(buildRepoUrl(DEFAULT_URL_TEMPLATE, "acme/api")).toBe("https://github.com/acme/api.git");
  });

  it("fails invalid policy entries per repo and still syncs the valid ones (exit 1)", async () => {
    makeRepo("names/ok");
    const mirror = newMirror();
    const r = await sync(
      writePolicy('repos: [names/ok, "names/bad$name", "a/b/c", "-x/y", ".hidden/x", "names", "*"]'),
      mirror,
    );
    expect(r.code).toBe(1);
    expect(resultFor(r, "names/ok")?.action).toBe("synced");
    for (const bad of ["names/bad$name", "a/b/c", "-x/y", ".hidden/x", "names", "*"]) {
      expect(resultFor(r, bad), bad).toMatchObject({ action: "failed" });
    }
    expect(readdirSync(mirror).sort()).toEqual(["names"]);
    expect(readdirSync(join(mirror, "names"))).toEqual(["ok"]);
  });

  // Regression (mirror-discovery-duplicated-divergent): sync had its own discoverMirror with other
  // name rules than the one xsearch uses, so a synced "owner/.github" could be invisible to reviews.
  it("everything sync mirrors, including owner/.github, is discovered by the reader xsearch uses", async () => {
    expect("discoverMirror" in syncModule).toBe(false); // a single reader of the mirror layout
    const shaDot = makeRepo("dot/.github", { "workflows/ci.yml": "name: ci\n" });
    const shaApi = makeRepo("dot/api");
    const mirror = newMirror();
    const r = await sync(writePolicy("repos: [dot/.github, dot/api, dot/.git]"), mirror);
    expect(r.code).toBe(1);
    expect(resultFor(r, "dot/.github")).toMatchObject({ action: "synced", sha: shaDot });
    expect(resultFor(r, "dot/api")).toMatchObject({ action: "synced", sha: shaApi });
    expect(resultFor(r, "dot/.git")).toMatchObject({ action: "failed", error: expect.stringContaining("invalid repository name") });
    expect(readdirSync(join(mirror, "dot")).sort()).toEqual([".github", "api"]);

    const found = discoverMirror(mirror);
    expect(found.map((e) => e.repo)).toEqual(["dot/.github", "dot/api"]);
    const dot = found.find((e) => e.repo === "dot/.github")!;
    expect(dot.sha).toBe(shaDot);
    expect(readFileSync(join(dot.host, "workflows/ci.yml"), "utf8")).toBe("name: ci\n");
  });

  it("rejects policy files with path-traversal repo entries (exit 2)", async () => {
    const r = await sync(writePolicy('repos: ["acme/../etc"]'), newMirror());
    expect(r.code).toBe(2);
  });

  it("keeps going when one repo fails", async () => {
    makeRepo("errs/api");
    const mirror = newMirror();
    const r = await sync(writePolicy("repos: [errs/missing, errs/api]"), mirror);
    expect(r.code).toBe(1);
    expect(resultFor(r, "errs/missing")).toMatchObject({ action: "failed" });
    expect(resultFor(r, "errs/missing")?.error).toContain("git ls-remote");
    expect(resultFor(r, "errs/api")?.action).toBe("synced");
    expect(existsSync(join(mirror, "errs/missing"))).toBe(false);
  });

  it("ignores API results with invalid names", async () => {
    makeRepo("apinames/good");
    const mirror = newMirror();
    const github: GithubApi = {
      listOwnerRepos: async () => [
        { full_name: "apinames/good" },
        { full_name: "apinames/../../etc" },
        { full_name: "apinames/x;rm -rf" },
        { full_name: "other/repo" }, // not this owner
      ],
    };
    const report = await syncMirror({
      policy: policyOf('repos: ["apinames/*"]'),
      mirrorDir: mirror,
      urlTemplate: template,
      github,
    });
    expect(report.results.find((r) => r.repo === "apinames/good")?.action).toBe("synced");
    expect(report.failed).toBe(2);
    expect(readdirSync(mirror).filter((e) => !e.startsWith("."))).toEqual(["apinames"]);
    expect(readdirSync(join(mirror, "apinames"))).toEqual(["good"]);
  });

  it("validates --repo and the URL template (exit 2)", async () => {
    makeRepo("cli/api");
    const mirror = newMirror();
    const policy = writePolicy("repos: [cli/api]");
    expect((await sync(policy, mirror, "--repo", "cli/../x")).code).toBe(2);
    expect((await sync(policy, mirror, "--repo", "cli/other")).code).toBe(2);
    expect((await run(["--policy", policy, "--mirror", mirror, "--url-template", "http://h/{owner}/{repo}"])).code).toBe(2);
    expect((await run(["--policy", policy])).code).toBe(2);
    expect((await run(["--policy", policy, "--mirror", mirror, "--bogus"])).code).toBe(2);
    // https template without a token
    expect((await run(["--policy", policy, "--mirror", mirror])).code).toBe(2);
    expect(existsSync(mirror)).toBe(false);

    expect(validateUrlTemplate(DEFAULT_URL_TEMPLATE)).toBe("https");
    expect(validateUrlTemplate("file:///srv/git/{owner}/{repo}.git")).toBe("file");
    for (const bad of [
      "http://github.com/{owner}/{repo}.git",
      "https://user:pw@github.com/{owner}/{repo}.git",
      "https://github.com/{owner}/x.git",
      "https://github.com/{owner}/{repo}/{branch}",
      "ext::sh -c touch% /tmp/pwned",
      "ssh://git@github.com/{owner}/{repo}.git",
      "https://github.com/{owner}/{repo} .git",
    ]) {
      expect(() => validateUrlTemplate(bad), bad).toThrow();
    }
  });

  it("--repo syncs only the named repo", async () => {
    makeRepo("only/api");
    makeRepo("only/web");
    const mirror = newMirror();
    const r = await sync(writePolicy('repos: ["only/*"]'), mirror, "--repo", "only/web");
    expect(r.code).toBe(0);
    expect(r.report?.results.map((x) => x.repo)).toEqual(["only/web"]);
    expect(readdirSync(join(mirror, "only"))).toEqual(["web"]);
  });

  it("--dry-run writes nothing", async () => {
    const sha = makeRepo("dry/api");
    const mirror = newMirror();
    const r = await sync(writePolicy("repos: [dry/api]"), mirror, "--dry-run");
    expect(r.code).toBe(0);
    expect(r.report).toMatchObject({ dry_run: true, removed: [], failed: 0 });
    expect(resultFor(r, "dry/api")).toMatchObject({ action: "would_sync", sha });
    expect(existsSync(mirror)).toBe(false);
  });
});

describe("authentication", () => {
  const TOKEN = "ghs_0123456789abcdefghijABCDEFGHIJ012345";

  it("injects the token only as an origin-scoped extraHeader via GIT_CONFIG_* env", () => {
    const base = {
      PATH: "/usr/bin",
      GIT_CONFIG_COUNT: "2",
      GIT_CONFIG_KEY_0: "url.https://evil/.insteadOf",
      GIT_CONFIG_VALUE_0: "https://github.com/",
      GIT_CONFIG_KEY_1: "credential.helper",
      GIT_CONFIG_VALUE_1: "store",
      GIT_CONFIG_PARAMETERS: "'http.extraheader'='x'",
      GIT_TRACE_CURL: "1",
      GIT_DIR: "/somewhere",
      XREPO_GITHUB_TOKEN: TOKEN,
    };
    const env = gitEnv("https://github.com/acme/api.git", TOKEN, base);
    expect(env.GIT_CONFIG_KEY_0).toBe("http.https://github.com/.extraHeader");
    expect(env.GIT_CONFIG_VALUE_0).toBe(
      `Authorization: Basic ${Buffer.from(`x-access-token:${TOKEN}`).toString("base64")}`,
    );
    const count = Number(env.GIT_CONFIG_COUNT);
    const keys = Array.from({ length: count }, (_, i) => env[`GIT_CONFIG_KEY_${i}`]);
    expect(keys).toContain("credential.helper");
    expect(env[`GIT_CONFIG_VALUE_${keys.indexOf("credential.helper")}`]).toBe("");
    expect(keys).toContain("core.symlinks");
    expect(keys).not.toContain("url.https://evil/.insteadOf");
    expect(env.GIT_CONFIG_PARAMETERS).toBeUndefined();
    expect(env.GIT_TRACE_CURL).toBeUndefined();
    expect(env.GIT_DIR).toBeUndefined();
    expect(env.XREPO_GITHUB_TOKEN).toBeUndefined();
    expect(env.GIT_TERMINAL_PROMPT).toBe("0");
    expect(env.GIT_ALLOW_PROTOCOL).toBe("https");
    expect(env.PATH).toBe("/usr/bin");
    // The raw token appears nowhere in the environment.
    expect(Object.values(env).some((v) => v?.includes(TOKEN))).toBe(false);

    const ghes = gitEnv("https://ghe.example.com:8443/acme/api.git", TOKEN, {});
    expect(ghes.GIT_CONFIG_KEY_0).toBe("http.https://ghe.example.com:8443/.extraHeader");

    const local = gitEnv("file:///srv/acme/api.git", TOKEN, {});
    expect(Object.values(local).some((v) => v?.startsWith("Authorization"))).toBe(false);
    expect(local.GIT_ALLOW_PROTOCOL).toBe("file");
  });

  it("never passes the token in argv and scrubs it from errors and output", async () => {
    process.env.XREPO_GITHUB_TOKEN = TOKEN;
    const b64 = Buffer.from(`x-access-token:${TOKEN}`).toString("base64");
    const rec = recordingGit(() =>
      Promise.resolve({
        code: 128,
        signal: null,
        stdout: "",
        stderr: `fatal: auth failed for ${TOKEN} (header ${b64})`,
        timedOut: false,
      }),
    );
    const mirror = newMirror();
    const report = await syncMirror({
      policy: policyOf("repos: [auth/api]"),
      mirrorDir: mirror,
      urlTemplate: "https://git.example.com/{owner}/{repo}.git",
      token: TOKEN,
      git: rec.runner,
      github: quietGithub,
    });
    expect(report.failed).toBe(1);
    expect(rec.calls.length).toBeGreaterThan(0);
    for (const c of rec.calls) {
      expect(c.args.join(" ")).not.toContain(TOKEN);
      expect(c.args.join(" ")).not.toContain(b64);
      expect(c.env.GIT_CONFIG_KEY_0).toBe("http.https://git.example.com/.extraHeader");
    }
    const text = JSON.stringify(report);
    expect(text).not.toContain(TOKEN);
    expect(text).not.toContain(b64);
    expect(report.results[0]?.error).toContain("[REDACTED]");
  });

  it("main() never prints the token, even when git fails", async () => {
    process.env.XREPO_GITHUB_TOKEN = TOKEN;
    const mirror = newMirror();
    const r = await run([
      "--policy",
      writePolicy("repos: [auth2/api]"),
      "--mirror",
      mirror,
      "--url-template",
      "https://127.0.0.1:1/{owner}/{repo}.git",
    ]);
    expect(r.code).toBe(1);
    expect(r.stdout + r.stderr).not.toContain(TOKEN);
    expect(r.stdout + r.stderr).not.toContain(Buffer.from(`x-access-token:${TOKEN}`).toString("base64"));
  }, 30_000);
});

describe("owner/* expansion via the GitHub API", () => {
  let server: Server;
  let base: string;
  const requests: string[] = [];
  let savedApi: string | undefined;

  beforeAll(async () => {
    server = createServer((req, res) => {
      const url = new URL(req.url ?? "/", "http://x");
      requests.push(`${req.method} ${url.pathname}${url.search}`);
      const json = (status: number, body: unknown, headers: Record<string, string> = {}) => {
        res.writeHead(status, { "content-type": "application/json", ...headers });
        res.end(JSON.stringify(body));
      };
      if (url.pathname === "/orgs/exp/repos") {
        if (url.searchParams.get("page") === "2") {
          return json(200, [
            { full_name: "exp/web", archived: false, fork: false, description: null },
            { full_name: "exp/legacy", archived: false, fork: false, description: "excluded" },
          ]);
        }
        return json(
          200,
          [
            { full_name: "exp/api", archived: false, fork: false, description: "Orders\nAPI \u0007service" },
            { full_name: "exp/old", archived: true, fork: false, description: "archived" },
            { full_name: "exp/forked", archived: false, fork: true, description: "a fork" },
          ],
          { link: `<${base}/orgs/exp/repos?per_page=100&type=all&page=2>; rel="next"` },
        );
      }
      if (url.pathname === "/orgs/expuser/repos") return json(404, { message: "Not Found" });
      if (url.pathname === "/users/expuser/repos") {
        return json(200, [{ full_name: "expuser/tool", archived: false, fork: false, description: "CLI" }]);
      }
      return json(404, { message: "Not Found" });
    });
    await new Promise<void>((r) => server.listen(0, "127.0.0.1", () => r()));
    const addr = server.address();
    base = `http://127.0.0.1:${typeof addr === "object" && addr ? addr.port : 0}`;
    savedApi = process.env.GITHUB_API_URL;
    process.env.GITHUB_API_URL = base;
    for (const r of ["exp/api", "exp/web", "exp/legacy", "exp/old", "exp/forked", "expuser/tool"]) makeRepo(r);
  });

  afterAll(async () => {
    if (savedApi === undefined) delete process.env.GITHUB_API_URL;
    else process.env.GITHUB_API_URL = savedApi;
    await new Promise<void>((r) => server.close(() => r()));
  });

  it("paginates, falls back to /users, honours skip_archived / skip_forks / exclude", async () => {
    const mirror = newMirror();
    const r = await sync(writePolicy('repos: ["exp/*", "expuser/*"]\nexclude: [exp/legacy]'), mirror);
    expect(r.code).toBe(0);
    expect(r.report?.results.map((x) => x.repo).sort()).toEqual(["exp/api", "exp/web", "expuser/tool"]);
    expect(requests.some((q) => q.startsWith("GET /orgs/exp/repos") && q.includes("page=2"))).toBe(true);
    expect(requests.some((q) => q.startsWith("GET /users/expuser/repos"))).toBe(true);
    expect(meta(mirror, "exp/api").description).toBe("Orders API service");
    expect(meta(mirror, "expuser/tool").description).toBe("CLI");
    expect(discoverMirror(mirror).map((e) => e.repo)).toEqual(["exp/api", "exp/web", "expuser/tool"]);

    // Policy now forks too -> exp/forked appears; a later exclude removes it again.
    const r2 = await sync(writePolicy('repos: ["exp/*"]\nskip_forks: false\nexclude: [exp/legacy]'), mirror);
    expect(r2.report?.results.map((x) => x.repo).sort()).toEqual(["exp/api", "exp/forked", "exp/web"]);
    expect(r2.report?.retired).toEqual(["expuser/tool"]);
    expect(r2.report?.removed).toEqual([]);
    expect(discoverMirror(mirror).map((e) => e.repo)).toEqual(["exp/api", "exp/forked", "exp/web"]);
  });
});

describe("discoverMirror", () => {
  it("returns [] for a missing directory and skips malformed entries", async () => {
    expect(discoverMirror(join(root, "does-not-exist"))).toEqual([]);
    const sha = makeRepo("disc/api");
    const mirror = newMirror();
    await sync(writePolicy("repos: [disc/api]"), mirror);

    // meta.json naming another repo -> ignored (identity comes from the layout).
    mkdirSync(join(mirror, "disc", "fake", "snapshots", sha), { recursive: true });
    symlinkSync(`snapshots/${sha}`, join(mirror, "disc", "fake", "current"));
    writeFileSync(
      join(mirror, "disc", "fake", "meta.json"),
      JSON.stringify({ repo: "secret/repo", sha, branch: "main", synced_at: "", description: "" }),
    );
    // current pointing outside its snapshots dir -> ignored.
    mkdirSync(join(mirror, "disc", "escape"), { recursive: true });
    symlinkSync("/etc", join(mirror, "disc", "escape", "current"));
    writeFileSync(
      join(mirror, "disc", "escape", "meta.json"),
      JSON.stringify({ repo: "disc/escape", sha, branch: "main", synced_at: "", description: "" }),
    );
    // symlinked owner dir -> ignored.
    symlinkSync(join(mirror, "disc"), join(mirror, "alias"));

    expect(discoverMirror(mirror).map((e) => e.repo)).toEqual(["disc/api"]);
  });
});

describe("--owner (one App installation token per account)", () => {
  it("syncs only that owner's entries and retires only its mirrors or those of owners the policy no longer names", async () => {
    makeRepo("own1/api");
    makeRepo("own1/web");
    makeRepo("own2/lib");
    makeRepo("own3/old");
    const mirror = newMirror();
    // Everything mirrored once (unscoped).
    const all = await sync(writePolicy("repos: [own1/api, own1/web, own2/lib, own3/old]"), mirror);
    expect(all.code).toBe(0);

    // own1 drops own1/web; own2 stays named (with a new, unreachable entry); own3 is no longer named.
    const policy = writePolicy("repos: [own1/api, own2/lib, own2/gone]");
    const r = await sync(policy, mirror, "--owner", "OWN1");
    expect(r.code).toBe(0);
    expect(r.report?.owner).toBe("OWN1");
    // Only own1's entries were synced (own2/lib and the failing own2/gone belong to the own2 run).
    expect(r.report?.results.map((x) => x.repo)).toEqual(["own1/api"]);
    // own1/web (this owner) and own3/old (no longer named) are retired; own2's mirrors are untouched.
    expect(r.report?.retired.sort()).toEqual(["own1/web", "own3/old"]);
    expect(existsSync(join(mirror, "own2/lib/current"))).toBe(true);
    expect(existsSync(join(mirror, "own2/lib", RETIRED_FILE))).toBe(false);

    // The own2 run syncs own2's entries (its failure is its own) and leaves own1 alone.
    const r2 = await sync(policy, mirror, "--owner", "own2", "--snapshot-grace-minutes", "0");
    expect(r2.report?.results.map((x) => `${x.repo}:${x.action}`).sort()).toEqual(["own2/gone:failed", "own2/lib:unchanged"]);
    expect(r2.report?.removed).toEqual(["own3/old"]);
    expect(existsSync(join(mirror, "own1/api/current"))).toBe(true);
    expect(existsSync(join(mirror, "own1/web/snapshots"))).toBe(true); // own1's grace is own1's run's business
  });

  it("validates --owner and requires --repo names to belong to it (exit 2)", async () => {
    makeRepo("ownv/api");
    const mirror = newMirror();
    const policy = writePolicy("repos: [ownv/api]");
    for (const bad of ["-x", "a/b", "", ".hidden"]) {
      const r = await sync(policy, mirror, "--owner", bad);
      expect(r.code, bad).toBe(2);
    }
    const foreign = await sync(policy, mirror, "--owner", "other", "--repo", "ownv/api");
    expect(foreign.code).toBe(2);
    expect(foreign.stderr).toContain("not owned by --owner other");
    const ok = await sync(policy, mirror, "--owner", "ownv", "--repo", "ownv/api");
    expect(ok.code).toBe(0);
    expect(resultFor(ok, "ownv/api")?.action).toBe("synced");
  });

  it("expands only that owner's owner/* entry", async () => {
    const calls: string[] = [];
    const github: GithubApi = {
      listOwnerRepos: async (owner: string) => {
        calls.push(owner);
        return [];
      },
    };
    const report = await syncMirror({ policy: policyOf('repos: ["owna/*", "ownb/*"]'), mirrorDir: newMirror(), urlTemplate: template, github, owner: "ownb", dryRun: true });
    expect(calls).toEqual(["ownb"]);
    expect(report.owner).toBe("ownb");
  });
});

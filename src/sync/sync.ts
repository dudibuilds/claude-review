/**
 * Mirror sync (`xrepo sync`): keeps a shallow, default-branch working-tree snapshot of every repo
 * listed in `policy.mirror.repos` under `<mirror>/<owner>/<repo>/` for the search MCP.
 *
 * On-disk layout per repo:
 *   current -> snapshots/<sha>     relative symlink, atomically swapped (temp symlink + rename)
 *   snapshots/<sha>/               working tree only: `.git` is deleted after checkout
 *   meta.json                      {repo, sha, branch, synced_at, description}, written atomically
 *
 * Per repo: `git ls-remote --symref <url> HEAD` -> equal to meta.json sha (and `current` intact)
 * -> nothing to fetch. Otherwise `git init` + `fetch --depth 1 --no-tags <url> <sha>` (falls back to
 * HEAD) + `checkout --detach` in `snapshots/<sha>.tmp-<pid>`, delete `.git`, rename to
 * `snapshots/<sha>`, repoint `current`, write meta.json, prune old snapshots.
 *
 * Security:
 * - The token (env XREPO_GITHUB_TOKEN) reaches git only as an `http.<origin>/.extraHeader` config
 *   entry passed through GIT_CONFIG_COUNT/GIT_CONFIG_KEY_0/GIT_CONFIG_VALUE_0: never in argv, never
 *   in a URL, never written to disk, scoped to the remote's origin. Inherited GIT_CONFIG_* / GIT_TRACE*
 *   variables are dropped, credential helpers are reset, prompts disabled, only the template's
 *   protocol is allowed (GIT_ALLOW_PROTOCOL). Error text is scrubbed of the token before logging.
 * - Repository content is untrusted: checkout runs without hooks (`--template=`, core.hooksPath),
 *   with core.symlinks=false (symlinks become small text files, so a snapshot never points outside
 *   itself), without LFS smudge or submodules.
 * - Repo names are validated strictly before they become paths, and only names the search MCP
 *   serves (search/vfs.ts isMirrorRepoName, the one reader of this layout) are mirrored; deletion
 *   only touches directories that look like mirror repos; an API failure while expanding `owner/*`
 *   never removes that owner's mirrors.
 * - One sync at a time per mirror: `<mirror>/.sync.lock` (O_EXCL). The holder refreshes the lock's
 *   mtime every LOCK_HEARTBEAT_MS; a lock is taken over when its process is dead (same host) or its
 *   heartbeat is older than LOCK_STALE_MS (another host, or a liveness that cannot be verified).
 *   `xrepo sync` releases the lock on SIGINT / SIGTERM / SIGHUP.
 *
 * Snapshot lifetime: xsearch pins every mirror repo to the snapshot `current` names when it starts
 * and never re-resolves it, and review jobs cannot write to the mirror (no reader leases). A retired
 * snapshot is therefore kept for SNAPSHOT_GRACE_MS (> the review job timeout) after it stopped being
 * `current`, whatever `keep_snapshots` says.
 *
 * Repo lifetime: the same rule applies to a repo that drops out of the desired set (policy edit,
 * archived, renamed, made a fork, out of the installation's selection). It is first retired: the
 * time is recorded in `<repo>/.retired` ({"retired_at": ISO}) and `current` is unlinked, so mirror
 * discovery (prepare, xsearch) stops listing it for every review that starts from then on, while
 * reviews already running keep reading the snapshot they pinned. The directory is deleted only once
 * it has been retired for the grace period. A retired repo that is listed again is restored on its
 * next sync (an existing snapshot is reused) and its marker removed.
 */
import { spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import {
  closeSync,
  existsSync,
  fchmodSync,
  fstatSync,
  fsyncSync,
  futimesSync,
  lstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  readdirSync,
  readlinkSync,
  renameSync,
  rmSync,
  rmdirSync,
  symlinkSync,
  unlinkSync,
  utimesSync,
  writeSync,
  chmodSync,
  type Stats,
} from "node:fs";
import { constants as osConstants, hostname } from "node:os";
import { join, resolve } from "node:path";
import { Octokit } from "@octokit/rest";
import { z } from "zod";
import { parseCli } from "../common/args.js";
import { audit } from "../common/audit.js";
import { redactSecrets } from "../common/redact.js";
import { isExactRepoName, isRepoOwner, repoPatternMatch } from "../policy/glob.js";
import { githubApiBase } from "../outcome/api-base.js";
import { loadPolicy } from "../policy/load.js";
import type { PolicyFile } from "../policy/schema.js";
import { isMirrorRepoName } from "../search/vfs.js";

/* -------------------------------- constants ------------------------------- */

export const DEFAULT_URL_TEMPLATE = "https://github.com/{owner}/{repo}.git";
export const LOCK_FILE = ".sync.lock";
export const TOKEN_ENV = "XREPO_GITHUB_TOKEN";
/**
 * Marker of a repo retired from the mirror (`<mirror>/<owner>/<repo>/.retired`, {"retired_at": ISO}).
 * Its `current` is gone; the directory is deleted once retired for the grace period.
 */
export const RETIRED_FILE = ".retired";

/**
 * A retired snapshot stays at least this long after it stopped being `current` (default of
 * `--snapshot-grace-minutes`). A running review keeps reading the snapshot that was `current` when
 * its xsearch server started, for as long as the review job may run (review.yml
 * `timeout-minutes: 45`), so this must exceed the review job timeout.
 */
export const SNAPSHOT_GRACE_MS = 60 * 60 * 1000;
/** Upper bound of `--snapshot-grace-minutes` (one week). */
export const MAX_SNAPSHOT_GRACE_MS = 7 * 24 * 60 * 60 * 1000;
/** The lock holder refreshes the lock file's mtime this often. */
export const LOCK_HEARTBEAT_MS = 30_000;
/**
 * A lock whose heartbeat (mtime) is older than this was abandoned by a sync that died without
 * releasing it (killed, cancelled, crashed) and is taken over, whichever host wrote it.
 */
export const LOCK_STALE_MS = 15 * 60_000;
/** Leftover `.tmp-<pid>` snapshot dirs / temp files older than this are removed. */
export const STALE_TMP_MS = 60 * 60 * 1000;
/** Repos synced in parallel. */
const CONCURRENCY = 4;

const SHA_RE = /^(?:[0-9a-f]{40}|[0-9a-f]{64})$/;
const SNAPSHOT_TMP_RE = /^(?:[0-9a-f]{40}|[0-9a-f]{64})\.tmp-\d+$/;
const TRASH_PREFIX = ".del-";
const CURRENT = "current";
const SNAPSHOTS = "snapshots";
const META = "meta.json";
const CURRENT_TMP_RE = /^\.current\.tmp-/;
const META_TMP_RE = /^\.meta\.json\..*\.tmp$/;

const TIMEOUTS = {
  lsRemote: 2 * 60_000,
  init: 60_000,
  fetch: 30 * 60_000,
  revParse: 60_000,
  checkout: 15 * 60_000,
};
const MAX_STDOUT = 4 * 1024 * 1024;
const MAX_STDERR = 64 * 1024;
const MAX_DESCRIPTION_CHARS = 300;

/* --------------------------------- types --------------------------------- */

export const MirrorMeta = z.object({
  repo: z.string(),
  sha: z.string().regex(SHA_RE),
  branch: z.string(),
  synced_at: z.string(),
  description: z.string(),
});
export type MirrorMeta = z.infer<typeof MirrorMeta>;

/** A repository returned by the owner listing (`GET /orgs/{owner}/repos`, `/users/{owner}/repos`). */
export interface OwnerRepo {
  full_name: string;
  archived?: boolean;
  fork?: boolean;
  disabled?: boolean;
  description?: string | null;
}

export interface GithubApi {
  listOwnerRepos(owner: string): Promise<OwnerRepo[]>;
  /** Repository description, for exact entries (only called when a token is configured). */
  getDescription?(owner: string, repo: string): Promise<string | null | undefined>;
}

export interface GitResult {
  code: number | null;
  signal: NodeJS.Signals | null;
  stdout: string;
  stderr: string;
  timedOut: boolean;
}

export type GitRunner = (
  args: string[],
  opts: { cwd?: string; env: NodeJS.ProcessEnv; timeoutMs: number },
) => Promise<GitResult>;

export type RepoAction = "synced" | "unchanged" | "empty" | "failed" | "would_sync";

export interface RepoResult {
  repo: string;
  action: RepoAction;
  sha?: string;
  previous_sha?: string;
  branch?: string;
  /** An existing complete snapshot was reused instead of fetching. */
  reused?: boolean;
  error?: string;
}

export interface SyncReport {
  dry_run: boolean;
  /** The account this run was limited to (--owner). */
  owner?: string;
  results: RepoResult[];
  /**
   * Mirrored repos deleted from disk this run (dry run: that would be deleted) because the policy no
   * longer lists them and they have been retired for the grace period.
   */
  removed: string[];
  /**
   * Mirrored repos the policy no longer lists that are retired but still on disk (dry run: that
   * would be): no `current`, so new reviews no longer see them, and their directory is kept until
   * the grace period since retirement is over, because a running review may still read it.
   */
  retired: string[];
  /** Snapshot directories pruned. */
  pruned: number;
  failed: number;
}

export interface SyncOptions {
  policy: PolicyFile;
  mirrorDir: string;
  /** Restrict this run to these repos (each must be covered by mirror.repos and not excluded). */
  repos?: string[];
  /**
   * Restrict this run to one account (an App installation token covers one account): only its
   * mirror.repos entries (exact and owner/*) are synced, and only mirrors under it, or under owners
   * the policy no longer names, are retired / removed. Other owners' mirrors are left alone.
   */
  owner?: string;
  urlTemplate?: string;
  token?: string;
  dryRun?: boolean;
  /** GitHub API access (default: Octokit against GITHUB_API_URL or api.github.com). */
  github?: GithubApi;
  /** git runner (default: spawn without a shell). */
  git?: GitRunner;
  /** Clock (ms since epoch), for tests. */
  now?: () => number;
  /**
   * How long a retired snapshot is kept beyond `keep_snapshots` after it stopped being `current`,
   * and how long a repo dropped from the desired set stays on disk after it was retired (default
   * SNAPSHOT_GRACE_MS; 0 .. MAX_SNAPSHOT_GRACE_MS). Must exceed the review job timeout.
   */
  snapshotGraceMs?: number;
  /** Lock heartbeat / staleness (defaults LOCK_HEARTBEAT_MS / LOCK_STALE_MS). */
  lock?: LockOptions;
}

export class SyncLockError extends Error {
  constructor(
    message: string,
    readonly holder?: unknown,
    /** Age of the holder's last heartbeat (lock file mtime), when known. */
    readonly heartbeatAgeMs?: number,
  ) {
    super(message);
    this.name = "SyncLockError";
  }
}

/** Invalid arguments / configuration (exit code 2). */
export class SyncUsageError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "SyncUsageError";
  }
}

/* ------------------------------ validation ------------------------------- */

/** GitHub repo name (".github" is valid). */
const REPO_SEG_RE = /^[A-Za-z0-9_.][A-Za-z0-9_.-]{0,99}$/;

/**
 * GitHub owner: starts alphanumeric (never ".", so it can't collide with mirror-level dot files).
 * The one grammar of policy/glob.ts (isRepoOwner).
 */
function isOwnerSegment(s: string): boolean {
  return isRepoOwner(s);
}

function isRepoSegment(s: string): boolean {
  return REPO_SEG_RE.test(s) && s !== "." && s !== "..";
}

/**
 * Strict owner/name validation (names become filesystem paths and URL components). A name the
 * search MCP would not serve (search/vfs.ts isMirrorRepoName, e.g. "owner/.git") is never mirrored,
 * so everything sync writes is discoverable by xsearch.
 */
export function isValidRepoName(name: unknown): name is string {
  return typeof name === "string" && isExactRepoName(name) && isMirrorRepoName(name);
}

/** "owner/*" with a valid owner -> owner, else undefined. */
function ownerGlob(entry: string): string | undefined {
  const m = /^([^/]+)\/\*$/.exec(entry);
  return m && isOwnerSegment(m[1]!) ? m[1] : undefined;
}

/** The owner a mirror.repos entry names ("owner/name" or "owner/*"), lower-cased; undefined if neither. */
function entryOwner(entry: string): string | undefined {
  const owner = ownerGlob(entry) ?? (isValidRepoName(entry) ? entry.split("/")[0] : undefined);
  return owner?.toLowerCase();
}

/**
 * Validates a clone URL template ({owner} / {repo} placeholders). Only https:// (no embedded
 * credentials) and file:// are accepted. Returns the URL scheme.
 */
export function validateUrlTemplate(template: string): "https" | "file" {
  if (typeof template !== "string" || template.length === 0 || template.length > 2048) {
    throw new SyncUsageError("--url-template must be a non-empty string");
  }
  if (/[\s\0-\x1f\x7f]/.test(template)) throw new SyncUsageError("--url-template must not contain whitespace or control characters");
  if (!template.includes("{repo}")) throw new SyncUsageError("--url-template must contain {repo}");
  const sample = template.replaceAll("{owner}", "owner").replaceAll("{repo}", "repo");
  if (/[{}]/.test(sample)) throw new SyncUsageError("--url-template: only {owner} and {repo} placeholders are supported");
  let url: URL;
  try {
    url = new URL(sample);
  } catch {
    throw new SyncUsageError("--url-template is not a valid URL");
  }
  if (url.protocol === "file:") return "file";
  if (url.protocol !== "https:") throw new SyncUsageError("--url-template must use https:// or file://");
  if (url.username || url.password) {
    throw new SyncUsageError(`--url-template must not embed credentials (use ${TOKEN_ENV})`);
  }
  if (!url.hostname) throw new SyncUsageError("--url-template has no host");
  return "https";
}

export function buildRepoUrl(template: string, repo: string): string {
  if (!isValidRepoName(repo)) throw new Error(`invalid repository name ${JSON.stringify(repo)}`);
  const [owner, name] = repo.split("/") as [string, string];
  return template.replaceAll("{owner}", owner).replaceAll("{repo}", name);
}

/* --------------------------------- git env -------------------------------- */

function basicAuthHeader(token: string): string {
  return `Authorization: Basic ${Buffer.from(`x-access-token:${token}`, "utf8").toString("base64")}`;
}

/**
 * Environment for git child processes. The auth header (https only) is config entry 0, scoped to
 * the remote's origin; nothing secret is ever placed in argv.
 */
export function gitEnv(url: string, token?: string, base: NodeJS.ProcessEnv = process.env): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = {};
  for (const [k, v] of Object.entries(base)) {
    if (v === undefined) continue;
    if (
      /^GIT_CONFIG_(COUNT|KEY_\d+|VALUE_\d+|PARAMETERS)$/.test(k) ||
      /^GIT_TRACE/.test(k) ||
      k === "GIT_CURL_VERBOSE" ||
      k === "GIT_ASKPASS" ||
      k === "SSH_ASKPASS" ||
      k === "GIT_DIR" ||
      k === "GIT_WORK_TREE" ||
      k === "GIT_INDEX_FILE" ||
      k === "GIT_OBJECT_DIRECTORY" ||
      k === "GIT_ALTERNATE_OBJECT_DIRECTORIES" ||
      k === "GIT_COMMON_DIR" ||
      k === "GIT_NAMESPACE" ||
      k === "GIT_PROTOCOL_FROM_USER" ||
      k === "GIT_REDACT_COOKIES" ||
      k === "GIT_ALLOW_PROTOCOL" ||
      k === TOKEN_ENV
    ) {
      continue;
    }
    env[k] = v;
  }
  const scheme = url.startsWith("file:") ? "file" : "https";
  const config: [string, string][] = [];
  if (token && scheme === "https") {
    const origin = new URL(url).origin;
    config.push([`http.${origin}/.extraHeader`, basicAuthHeader(token)]);
  }
  config.push(
    ["credential.helper", ""], // reset helpers: never read or store credentials
    ["credential.interactive", "false"],
    ["core.askPass", ""], // no askpass program (GIT_ASKPASS / SSH_ASKPASS are dropped as well)
    ["http.followRedirects", "initial"],
    ["core.hooksPath", "/dev/null"],
    ["core.symlinks", "false"],
    ["core.fsmonitor", "false"],
    ["core.autocrlf", "false"],
    ["advice.detachedHead", "false"],
    ["init.defaultBranch", "main"],
    ["gc.auto", "0"],
    ["maintenance.auto", "false"],
    ["fetch.recurseSubmodules", "false"],
    ["submodule.recurse", "false"],
  );
  env.GIT_CONFIG_COUNT = String(config.length);
  config.forEach(([k, v], i) => {
    env[`GIT_CONFIG_KEY_${i}`] = k;
    env[`GIT_CONFIG_VALUE_${i}`] = v;
  });
  env.GIT_TERMINAL_PROMPT = "0";
  env.GCM_INTERACTIVE = "never";
  env.GIT_LFS_SKIP_SMUDGE = "1";
  env.GIT_ALLOW_PROTOCOL = scheme;
  env.GIT_TRACE_REDACT = "1";
  return env;
}

/** Default git runner: spawn without a shell, stdin ignored, bounded output, SIGKILL on timeout. */
export const spawnGit: GitRunner = (args, opts) =>
  new Promise<GitResult>((resolvePromise) => {
    let stdout = "";
    let stderr = "";
    let timedOut = false;
    let settled = false;
    const finish = (r: GitResult): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolvePromise(r);
    };
    let child: ReturnType<typeof spawn>;
    try {
      child = spawn("git", args, { cwd: opts.cwd, env: opts.env, stdio: ["ignore", "pipe", "pipe"], shell: false });
    } catch (e) {
      resolvePromise({ code: null, signal: null, stdout: "", stderr: (e as Error).message, timedOut: false });
      return;
    }
    const timer = setTimeout(() => {
      timedOut = true;
      child.kill("SIGKILL");
    }, opts.timeoutMs);
    // After a timeout, do not wait for grandchildren that may still hold the pipes open.
    child.on("exit", (code, signal) => {
      if (!timedOut) return;
      child.stdout?.destroy();
      child.stderr?.destroy();
      finish({ code, signal, stdout, stderr, timedOut });
    });
    child.stdout?.setEncoding("utf8");
    child.stderr?.setEncoding("utf8");
    child.stdout?.on("data", (d: string) => {
      if (stdout.length < MAX_STDOUT) stdout += d;
    });
    child.stderr?.on("data", (d: string) => {
      stderr += d;
      if (stderr.length > MAX_STDERR) stderr = stderr.slice(-MAX_STDERR);
    });
    child.on("error", (e) => finish({ code: null, signal: null, stdout, stderr: `${stderr}${e.message}`, timedOut }));
    child.on("close", (code, signal) => finish({ code, signal, stdout, stderr, timedOut }));
  });

/* -------------------------------- helpers -------------------------------- */

function errCode(e: unknown): string | undefined {
  const c = (e as { code?: unknown } | null)?.code;
  return typeof c === "string" ? c : undefined;
}

function lstatOrUndefined(p: string): Stats | undefined {
  try {
    return lstatSync(p);
  } catch (e) {
    if (errCode(e) === "ENOENT" || errCode(e) === "ENOTDIR") return undefined;
    throw e;
  }
}

function randHex(): string {
  return randomBytes(6).toString("hex");
}

/** Creates `p` (mode 0755) if missing; it must be a real directory, not a symlink. */
function ensureRealDir(p: string): void {
  const st = lstatOrUndefined(p);
  if (st === undefined) {
    try {
      mkdirSync(p, { mode: 0o755 });
      chmodSync(p, 0o755); // independent of the process umask: the search container runs as nobody
    } catch (e) {
      if (errCode(e) !== "EEXIST") throw e;
    }
    const again = lstatSync(p);
    if (!again.isDirectory()) throw new Error(`${p} is not a directory`);
    return;
  }
  if (st.isSymbolicLink() || !st.isDirectory()) throw new Error(`${p} exists and is not a directory`);
}

/** Make a snapshot readable by everyone (the search container runs as 65534) and writable by none but the owner. */
function ensureWorldReadable(root: string): void {
  const stack = [root];
  while (stack.length > 0) {
    const dir = stack.pop()!;
    const st = lstatSync(dir);
    if ((st.mode & 0o7777) !== 0o755) chmodSync(dir, 0o755);
    for (const ent of readdirSync(dir, { withFileTypes: true })) {
      const p = join(dir, ent.name);
      if (ent.isDirectory()) {
        stack.push(p);
      } else if (ent.isFile()) {
        const fst = lstatSync(p);
        const fwant = fst.mode & 0o111 ? 0o755 : 0o644; // no setuid, no group / world write
        if ((fst.mode & 0o7777) !== fwant) chmodSync(p, fwant);
      }
    }
  }
}

/** Remove a tree by first renaming it to a trash name in the same directory, so a partial
 *  deletion can never be mistaken for a complete snapshot / repo. */
function removeTree(path: string, trashDir: string): void {
  const trash = join(trashDir, `${TRASH_PREFIX}${process.pid}-${randHex()}`);
  renameSync(path, trash);
  rmSync(trash, { recursive: true, force: true, maxRetries: 2 });
}

/** Atomic file write with an explicit mode (independent of umask): temp + fchmod + fsync + rename. */
function writeFileAtomic(path: string, dir: string, text: string, mode = 0o644): void {
  const tmp = join(dir, `.${META}.${process.pid}.${randHex()}.tmp`);
  let fd: number | undefined;
  try {
    fd = openSync(tmp, "wx", mode);
    fchmodSync(fd, mode);
    writeSync(fd, text);
    fsyncSync(fd);
    closeSync(fd);
    fd = undefined;
    renameSync(tmp, path);
  } catch (e) {
    if (fd !== undefined) {
      try {
        closeSync(fd);
      } catch {
        /* ignore */
      }
    }
    try {
      unlinkSync(tmp);
    } catch {
      /* ignore */
    }
    throw e;
  }
}

function fsyncDir(dir: string): void {
  try {
    const fd = openSync(dir, "r");
    try {
      fsyncSync(fd);
    } finally {
      closeSync(fd);
    }
  } catch {
    /* best effort */
  }
}

function sanitizeDescription(d: unknown): string {
  if (typeof d !== "string") return "";
  let s = d.replace(/[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]+/gu, " ").replace(/\s+/g, " ").trim();
  s = redactSecrets(s).text;
  if (s.length > MAX_DESCRIPTION_CHARS) s = `${s.slice(0, MAX_DESCRIPTION_CHARS - 1)}…`;
  return s;
}

function sanitizeBranch(b: string): string {
  return /^[^\s\0-\x1f\x7f]{1,255}$/.test(b) ? b : "HEAD";
}

/** Removes the token (raw and in its header encodings) and anything secret-looking from text. */
function makeScrubber(token?: string): (s: string) => string {
  const needles: string[] = [];
  if (token) {
    needles.push(token, basicAuthHeader(token).slice("Authorization: Basic ".length), Buffer.from(token).toString("base64"));
  }
  return (s: string): string => {
    let out = s;
    for (const n of needles) if (n) out = out.split(n).join("[REDACTED]");
    return redactSecrets(out).text;
  };
}

function gitError(what: string, r: GitResult, scrub: (s: string) => string): Error {
  const detail = r.timedOut
    ? "timed out"
    : r.code === null
      ? `failed${r.signal ? ` (signal ${r.signal})` : ""}`
      : `exited with code ${r.code}`;
  const tail = scrub(r.stderr.trim().split("\n").slice(-5).join(" | ")).slice(0, 1000);
  return new Error(`${what} ${detail}${tail ? `: ${tail}` : ""}`);
}

/* ------------------------------- meta / current ------------------------------- */

function readMeta(repoDir: string): MirrorMeta | undefined {
  try {
    const res = MirrorMeta.safeParse(JSON.parse(readFileSync(join(repoDir, META), "utf8")));
    return res.success ? res.data : undefined;
  } catch {
    return undefined;
  }
}

/** sha `current` points to (`snapshots/<sha>`, an existing real directory), else undefined. */
function readCurrent(repoDir: string): string | undefined {
  let target: string;
  try {
    target = readlinkSync(join(repoDir, CURRENT));
  } catch {
    return undefined;
  }
  const m = /^snapshots\/([0-9a-f]{40}|[0-9a-f]{64})$/.exec(target);
  if (!m) return undefined;
  const snapDir = lstatOrUndefined(join(repoDir, SNAPSHOTS));
  if (!snapDir?.isDirectory() || snapDir.isSymbolicLink()) return undefined;
  const st = lstatOrUndefined(join(repoDir, SNAPSHOTS, m[1]!));
  return st?.isDirectory() && !st.isSymbolicLink() ? m[1] : undefined;
}

/** Atomically repoint `current` -> snapshots/<sha> (relative temp symlink + rename). */
function swapCurrent(repoDir: string, sha: string): void {
  const cur = join(repoDir, CURRENT);
  const st = lstatOrUndefined(cur);
  if (st && !st.isSymbolicLink()) throw new Error(`${cur} exists and is not a symlink`);
  const tmp = join(repoDir, `.current.tmp-${process.pid}-${randHex()}`);
  symlinkSync(`${SNAPSHOTS}/${sha}`, tmp);
  try {
    renameSync(tmp, cur);
  } catch (e) {
    try {
      unlinkSync(tmp);
    } catch {
      /* ignore */
    }
    throw e;
  }
  fsyncDir(repoDir);
}

function writeMeta(repoDir: string, meta: MirrorMeta): void {
  writeFileAtomic(join(repoDir, META), repoDir, `${JSON.stringify(meta, null, 2)}\n`);
}

/** Retirement time (ms) recorded in `<repoDir>/.retired`, or undefined if absent / unreadable. */
function readRetiredAt(repoDir: string): number | undefined {
  const p = join(repoDir, RETIRED_FILE);
  try {
    if (!lstatSync(p).isFile()) return undefined;
    const v = JSON.parse(readFileSync(p, "utf8")) as { retired_at?: unknown } | null;
    const t = typeof v?.retired_at === "string" ? Date.parse(v.retired_at) : Number.NaN;
    return Number.isFinite(t) ? t : undefined;
  } catch {
    return undefined;
  }
}

/** Whether mirror discovery can list the repo (it requires `current` to be a symlink). */
function isServable(repoDir: string): boolean {
  return lstatOrUndefined(join(repoDir, CURRENT))?.isSymbolicLink() === true;
}

/**
 * Takes a repo out of service: records the retirement time, then unlinks `current`, so mirror
 * discovery (prepare, xsearch) no longer lists it for any review that starts from now on. Reviews
 * already running keep reading the snapshot they pinned at start; it stays until the repo directory
 * is deleted, `graceMs` after the time recorded here. The marker is written first: a crash between
 * the two steps leaves `current` in place, and the next run retires the repo again from scratch.
 */
function retireRepo(repoDir: string, nowMs: number): void {
  writeFileAtomic(
    join(repoDir, RETIRED_FILE),
    repoDir,
    `${JSON.stringify({ retired_at: new Date(nowMs).toISOString() })}\n`,
  );
  const cur = join(repoDir, CURRENT);
  if (lstatOrUndefined(cur)?.isSymbolicLink()) unlinkSync(cur);
  fsyncDir(repoDir);
}

/**
 * Drops the retirement marker of a repo that is in service again (`current` restored). Best effort:
 * a marker left next to a live `current` is ignored (removal retires such a repo again from scratch).
 */
function clearRetiredQuietly(repoDir: string): void {
  const p = join(repoDir, RETIRED_FILE);
  try {
    const st = lstatOrUndefined(p);
    if (st === undefined || st.isDirectory()) return;
    unlinkSync(p);
    audit("sync.unretire", { repo_dir: repoDir });
  } catch (e) {
    audit("sync.unretire_failed", { repo_dir: repoDir, error: e });
  }
}

/* --------------------------------- prune --------------------------------- */

/**
 * Prune `<repoDir>/snapshots`: keep `current`, then the newest snapshots up to `keep` in total.
 * Older ones are deleted only once they have been retired (replaced as `current`) for at least
 * `graceMs` (default SNAPSHOT_GRACE_MS). A review pins the snapshot that was `current` when its
 * xsearch server started and may read it until the review job times out; that snapshot was retired
 * no earlier than the review started, so a grace period longer than the review job timeout means a
 * running review never loses its snapshot, however many pushes are synced meanwhile and whatever
 * `keep` is. A snapshot's mtime is the time it became `current` (touched at swap). Also removes
 * `.tmp-<pid>` dirs and temp files older than STALE_TMP_MS and leftover trash. Returns the number
 * of snapshots deleted.
 */
export function pruneSnapshots(
  repoDir: string,
  keep: number,
  nowMs: number = Date.now(),
  graceMs: number = SNAPSHOT_GRACE_MS,
): number {
  const snapRoot = join(repoDir, SNAPSHOTS);
  // Repo-level temp files (interrupted swaps / meta writes).
  for (const ent of safeReaddir(repoDir)) {
    if (!CURRENT_TMP_RE.test(ent) && !META_TMP_RE.test(ent)) continue;
    const st = lstatOrUndefined(join(repoDir, ent));
    if (st && !st.isDirectory() && nowMs - st.mtimeMs > STALE_TMP_MS) {
      try {
        unlinkSync(join(repoDir, ent));
      } catch {
        /* ignore */
      }
    }
  }
  const snapSt = lstatOrUndefined(snapRoot);
  if (!snapSt?.isDirectory() || snapSt.isSymbolicLink()) return 0;

  const current = readCurrent(repoDir);
  const snaps: { sha: string; mtimeMs: number }[] = [];
  for (const ent of safeReaddir(snapRoot)) {
    const p = join(snapRoot, ent);
    const st = lstatOrUndefined(p);
    if (!st || st.isSymbolicLink() || !st.isDirectory()) continue;
    if (SHA_RE.test(ent)) {
      snaps.push({ sha: ent, mtimeMs: st.mtimeMs });
    } else if (ent.startsWith(TRASH_PREFIX)) {
      rmSync(p, { recursive: true, force: true, maxRetries: 2 });
    } else if (SNAPSHOT_TMP_RE.test(ent) && nowMs - st.mtimeMs > STALE_TMP_MS) {
      rmSync(p, { recursive: true, force: true, maxRetries: 2 });
      audit("sync.prune_tmp", { dir: p });
    }
  }
  snaps.sort((a, b) => b.mtimeMs - a.mtimeMs || (a.sha < b.sha ? -1 : 1));

  const kept = new Set<string>();
  if (current) kept.add(current);
  for (const s of snaps) {
    if (kept.size >= Math.max(1, keep)) break;
    kept.add(s.sha);
  }
  let pruned = 0;
  snaps.forEach((s, i) => {
    if (kept.has(s.sha)) return;
    // Retired when the next newer snapshot became current. A non-current snapshot with nothing
    // newer was never current after its own mtime (e.g. a crash before the swap): use that.
    const newer = snaps.slice(0, i).filter((n) => n.mtimeMs > s.mtimeMs);
    const retiredAt = newer.length > 0 ? Math.min(...newer.map((n) => n.mtimeMs)) : s.mtimeMs;
    if (nowMs - retiredAt < graceMs) return;
    try {
      removeTree(join(snapRoot, s.sha), snapRoot);
      pruned++;
      audit("sync.prune", { repo_dir: repoDir, sha: s.sha });
    } catch (e) {
      audit("sync.prune_failed", { repo_dir: repoDir, sha: s.sha, error: e });
    }
  });
  return pruned;
}

function safeReaddir(dir: string): string[] {
  try {
    return readdirSync(dir);
  } catch {
    return [];
  }
}

/**
 * `repo`'s owner and name segments as already spelled in the mirror. GitHub names are
 * case-insensitive, so a desired name whose case changed (policy edit, API listing) maps to the
 * existing directory on case-sensitive and case-insensitive filesystems alike; an exact match wins.
 */
function onDiskName(mirrorDir: string, repo: string): [string, string] {
  const pick = (dir: string, seg: string): string => {
    const entries = safeReaddir(dir);
    return entries.includes(seg) ? seg : (entries.find((e) => e.toLowerCase() === seg.toLowerCase()) ?? seg);
  };
  const [owner, name] = repo.split("/") as [string, string];
  const o = pick(mirrorDir, owner);
  return [o, pick(join(mirrorDir, o), name)];
}

/* ---------------------------------- lock ---------------------------------- */

interface LockInfo {
  pid: number;
  host: string;
  start?: string;
  started_at: string;
}

/** Process start time (clock ticks since boot) from /proc, to detect pid reuse. Linux only. */
function procStartTime(pid: number): string | undefined {
  try {
    const stat = readFileSync(`/proc/${pid}/stat`, "utf8");
    const fields = stat.slice(stat.lastIndexOf(")") + 2).split(" ");
    return fields[19]; // field 22 overall; fields after ")" start at field 3
  } catch {
    return undefined;
  }
}

function pidAlive(pid: number): boolean {
  if (!Number.isInteger(pid) || pid <= 0) return false;
  try {
    process.kill(pid, 0);
    return true;
  } catch (e) {
    return errCode(e) === "EPERM";
  }
}

export interface LockOptions {
  /** How often the holder refreshes the lock file's mtime (default LOCK_HEARTBEAT_MS). */
  heartbeatMs?: number;
  /** A lock whose heartbeat is older than this is taken over when liveness cannot be verified (default LOCK_STALE_MS). */
  staleMs?: number;
}

/**
 * Whether the lock content `text` (file mtime `mtimeMs`) was abandoned:
 * - unreadable / incomplete content: once it is older than a minute (it may be being written now);
 * - this host: the holder pid is dead, or was reused by another process (start time differs); if the
 *   start time cannot be compared, a heartbeat older than `staleMs`;
 * - another host (its processes cannot be checked; container / ephemeral runners sharing one
 *   mirror): a heartbeat older than `staleMs`. Without this, a sync killed without releasing the
 *   lock would block every later sync from another hostname forever.
 */
function lockIsStale(text: string, mtimeMs: number, staleMs: number): boolean {
  const age = Date.now() - mtimeMs;
  let info: Partial<LockInfo> | null;
  try {
    info = JSON.parse(text) as Partial<LockInfo> | null;
  } catch {
    return age > 60_000;
  }
  if (info === null || typeof info !== "object" || typeof info.pid !== "number" || typeof info.host !== "string") {
    return age > 60_000;
  }
  if (info.host !== hostname()) return age > staleMs;
  if (!pidAlive(info.pid)) return true;
  const start = typeof info.start === "string" ? procStartTime(info.pid) : undefined;
  if (start !== undefined) return start !== info.start; // differs: pid reused by another process
  return age > staleMs;
}

export interface SyncLock {
  path: string;
  /** Stops the heartbeat and removes the lock file if it is still this holder's. Idempotent. */
  release(): void;
}

/** Locks held by this process, released by `xrepo sync`'s signal handlers. */
const heldLocks = new Set<SyncLock>();

function sameFile(a: Stats, b: Stats): boolean {
  return a.ino === b.ino && a.dev === b.dev;
}

/**
 * Acquire `<mirror>/.sync.lock` (O_EXCL). A stale lock (see lockIsStale) is taken over. While held,
 * the lock file's mtime is refreshed every `heartbeatMs` through the open descriptor, so a lock that
 * was replaced by a takeover is never touched or removed by its previous holder.
 */
export function acquireLock(mirrorDir: string, opts: LockOptions = {}): SyncLock {
  const heartbeatMs = opts.heartbeatMs ?? LOCK_HEARTBEAT_MS;
  const staleMs = opts.staleMs ?? LOCK_STALE_MS;
  const path = join(mirrorDir, LOCK_FILE);
  const info: LockInfo = {
    pid: process.pid,
    host: hostname(),
    start: procStartTime(process.pid),
    started_at: new Date().toISOString(),
  };
  const content = `${JSON.stringify(info)}\n`;
  for (let attempt = 0; attempt < 3; attempt++) {
    let fd: number;
    try {
      fd = openSync(path, "wx", 0o644);
    } catch (e) {
      if (errCode(e) !== "EEXIST") throw e;
      let text: string;
      let mtimeMs: number;
      try {
        text = readFileSync(path, "utf8");
        mtimeMs = lstatSync(path).mtimeMs;
      } catch (re) {
        if (errCode(re) === "ENOENT") continue; // released meanwhile
        throw re;
      }
      if (!lockIsStale(text, mtimeMs, staleMs)) {
        let holder: unknown = text.trim();
        try {
          holder = JSON.parse(text);
        } catch {
          /* keep raw */
        }
        const ageMs = Math.max(0, Date.now() - mtimeMs);
        throw new SyncLockError(
          `another sync holds ${path} (last heartbeat ${Math.round(ageMs / 1000)}s ago)`,
          holder,
          ageMs,
        );
      }
      // Take over only if the file still holds the stale content we inspected.
      try {
        if (readFileSync(path, "utf8") === text) {
          unlinkSync(path);
          audit("sync.lock_stale_removed", {
            path,
            previous: text.trim(),
            heartbeat_age_s: Math.round((Date.now() - mtimeMs) / 1000),
          });
        }
      } catch (re) {
        if (errCode(re) !== "ENOENT") throw re;
      }
      continue;
    }
    try {
      writeSync(fd, content);
      fsyncSync(fd);
    } catch (e) {
      try {
        closeSync(fd);
        unlinkSync(path);
      } catch {
        /* ignore */
      }
      throw e;
    }
    const lockFd = fd;
    const owned = (): boolean => {
      try {
        return sameFile(fstatSync(lockFd), lstatSync(path));
      } catch {
        return false;
      }
    };
    let released = false;
    let lost = false;
    const timer = setInterval(() => {
      if (released || lost) return;
      if (!owned()) {
        lost = true;
        clearInterval(timer);
        audit("sync.lock_lost", { path });
        return;
      }
      try {
        const t = Date.now() / 1000;
        futimesSync(lockFd, t, t);
      } catch {
        /* best effort; the next beat retries */
      }
    }, heartbeatMs);
    timer.unref();
    const lock: SyncLock = {
      path,
      release(): void {
        if (released) return;
        released = true;
        clearInterval(timer);
        heldLocks.delete(lock);
        try {
          if (owned() && readFileSync(path, "utf8") === content) unlinkSync(path);
        } catch {
          /* already gone */
        }
        try {
          closeSync(lockFd);
        } catch {
          /* ignore */
        }
      },
    };
    heldLocks.add(lock);
    return lock;
  }
  throw new SyncLockError(`could not acquire ${path}`);
}

/* ------------------------------ GitHub API ------------------------------ */

/** GITHUB_API_URL validated like every other xrepo command (outcome/api-base.ts). */
function apiBaseUrl(): string {
  try {
    return githubApiBase(process.env);
  } catch (e) {
    throw new SyncUsageError((e as Error).message);
  }
}

const silentLog = { debug(): void {}, info(): void {}, warn(): void {}, error(): void {} };

/** Octokit-backed GithubApi. The token is optional (unauthenticated requests for public data). */
export function createGithubApi(token?: string): GithubApi {
  let client: Octokit | undefined;
  const octokit = (): Octokit =>
    (client ??= new Octokit({
      auth: token || undefined,
      baseUrl: apiBaseUrl(),
      userAgent: "xrepo-review-sync",
      log: silentLog,
    }));
  const map = (r: {
    full_name: string;
    archived?: boolean;
    fork?: boolean;
    disabled?: boolean;
    description?: string | null;
  }): OwnerRepo => ({
    full_name: r.full_name,
    archived: r.archived,
    fork: r.fork,
    disabled: r.disabled,
    description: r.description,
  });
  return {
    async listOwnerRepos(owner) {
      const o = octokit();
      try {
        const repos = await o.paginate(o.rest.repos.listForOrg, {
          org: owner,
          type: "all",
          per_page: 100,
          request: { signal: AbortSignal.timeout(5 * 60_000) },
        });
        return repos.map(map);
      } catch (e) {
        if ((e as { status?: number }).status !== 404) throw e;
        const repos = await o.paginate(o.rest.repos.listForUser, {
          username: owner,
          type: "owner",
          per_page: 100,
          request: { signal: AbortSignal.timeout(5 * 60_000) },
        });
        return repos.map(map);
      }
    },
    async getDescription(owner, repo) {
      const o = octokit();
      const res = await o.rest.repos.get({ owner, repo, request: { signal: AbortSignal.timeout(60_000) } });
      return res.data.description;
    },
  };
}

/* ---------------------------- repo resolution ---------------------------- */

interface Desired {
  name: string;
  description?: string;
}

/**
 * Validates `--repo` names against the policy (no API calls): each must be covered by an exact or
 * `owner/*` entry of mirror.repos and not excluded. Returns the names, preferring the policy's
 * spelling of an exact entry. Throws SyncUsageError.
 */
function selectOnly(mirror: PolicyFile["mirror"], only: string[], owner?: string): string[] {
  const entries = mirror.repos.map((e) => e.trim());
  return only.map((r) => {
    if (!isValidRepoName(r)) throw new SyncUsageError(`--repo ${JSON.stringify(r)}: expected owner/name`);
    if (owner !== undefined && r.split("/")[0]!.toLowerCase() !== owner.toLowerCase()) {
      throw new SyncUsageError(`--repo ${r} is not owned by --owner ${owner}`);
    }
    const covered = entries.some((p) => (ownerGlob(p) !== undefined || isValidRepoName(p)) && repoPatternMatch(p, r));
    if (!covered || mirror.exclude.some((p) => repoPatternMatch(p, r))) {
      throw new SyncUsageError(`--repo ${r} is not covered by policy mirror.repos`);
    }
    return entries.find((p) => isValidRepoName(p) && p.toLowerCase() === r.toLowerCase()) ?? r;
  });
}

interface Resolution {
  desired: Desired[];
  failures: RepoResult[];
  /** owner/* patterns whose expansion failed: their existing mirrors are never removed. */
  failedPatterns: string[];
}

async function resolveRepos(
  mirror: PolicyFile["mirror"],
  github: GithubApi,
  only: string[] | undefined,
  scrub: (s: string) => string,
  owner?: string,
): Promise<Resolution> {
  // With an owner, only that account's entries (other owners have their own runs and tokens);
  // entries naming no owner are reported by the run that covers them all (no --owner) and by
  // `xrepo policy validate`.
  const entries = mirror.repos
    .map((e) => e.trim())
    .filter((e) => e.length > 0 && (owner === undefined || entryOwner(e) === owner.toLowerCase()));
  const excluded = (name: string): boolean => mirror.exclude.some((p) => repoPatternMatch(p, name));
  const desired = new Map<string, Desired>();
  const failures: RepoResult[] = [];
  const failedPatterns: string[] = [];
  const add = (name: string, description?: string): void => {
    const key = name.toLowerCase();
    if (!desired.has(key)) desired.set(key, { name, description });
  };

  if (only !== undefined) {
    for (const r of selectOnly(mirror, only, owner)) add(r);
    return { desired: [...desired.values()], failures, failedPatterns };
  }

  // Exact entries first, so their spelling wins over API results.
  for (const entry of entries) {
    if (ownerGlob(entry) !== undefined) continue;
    if (!isValidRepoName(entry)) {
      failures.push({ repo: entry, action: "failed", error: "invalid repository name (expected owner/name or owner/*)" });
      continue;
    }
    if (!excluded(entry)) add(entry);
  }
  const seenOwners = new Set<string>();
  for (const entry of entries) {
    const owner = ownerGlob(entry);
    if (owner === undefined || seenOwners.has(owner.toLowerCase())) continue;
    seenOwners.add(owner.toLowerCase());
    let list: OwnerRepo[];
    try {
      list = await github.listOwnerRepos(owner);
    } catch (e) {
      const msg = scrub(`cannot list repositories of ${owner}: ${(e as Error).message}`);
      failures.push({ repo: entry, action: "failed", error: msg });
      failedPatterns.push(entry);
      continue;
    }
    for (const r of list) {
      const name = typeof r?.full_name === "string" ? r.full_name : "";
      if (!isValidRepoName(name)) {
        failures.push({ repo: String(name).slice(0, 200), action: "failed", error: `invalid repository name from ${entry} listing` });
        continue;
      }
      if (name.split("/")[0]!.toLowerCase() !== owner.toLowerCase()) continue;
      if (r.disabled) continue;
      if (mirror.skip_archived && r.archived) continue;
      if (mirror.skip_forks && r.fork) continue;
      if (excluded(name)) continue;
      add(name, sanitizeDescription(r.description));
    }
  }
  return { desired: [...desired.values()], failures, failedPatterns };
}

/* ------------------------------ per-repo sync ------------------------------ */

interface RepoCtx {
  mirrorDir: string;
  template: string;
  token?: string;
  dryRun: boolean;
  keep: number;
  git: GitRunner;
  github: GithubApi;
  now: () => number;
  scrub: (s: string) => string;
}

async function lsRemote(ctx: RepoCtx, url: string, env: NodeJS.ProcessEnv): Promise<{ sha: string; branch: string } | null> {
  const r = await ctx.git(["ls-remote", "--symref", url, "HEAD"], { env, timeoutMs: TIMEOUTS.lsRemote });
  if (r.code !== 0) throw gitError("git ls-remote", r, ctx.scrub);
  let sha: string | undefined;
  let branch = "HEAD";
  for (const line of r.stdout.split("\n")) {
    const [left, right] = line.split("\t");
    if (right?.trim() !== "HEAD" || left === undefined) continue;
    if (left.startsWith("ref: ")) {
      branch = sanitizeBranch(left.slice(5).trim().replace(/^refs\/heads\//, ""));
    } else if (SHA_RE.test(left.trim())) {
      sha = left.trim();
    }
  }
  return sha ? { sha, branch } : null;
}

/** Fetch `sha` (fallback: HEAD) into a fresh tmp dir and check it out; returns the commit sha checked out. */
async function buildSnapshot(ctx: RepoCtx, url: string, env: NodeJS.ProcessEnv, tmp: string, sha: string): Promise<string> {
  const run = async (what: string, args: string[], timeoutMs: number, cwd?: string): Promise<GitResult> => {
    const r = await ctx.git(args, { cwd, env, timeoutMs });
    if (r.code !== 0) throw gitError(what, r, ctx.scrub);
    return r;
  };
  await run("git init", ["init", "--quiet", "--template=", tmp], TIMEOUTS.init);
  const fetchArgs = ["fetch", "--quiet", "--depth", "1", "--no-tags", "--no-recurse-submodules", url];
  const bySha = await ctx.git([...fetchArgs, sha], { cwd: tmp, env, timeoutMs: TIMEOUTS.fetch });
  if (bySha.code !== 0) {
    if (bySha.timedOut) throw gitError("git fetch", bySha, ctx.scrub);
    // The server may refuse unadvertised object ids; HEAD may have moved on, which is fine.
    await run("git fetch", [...fetchArgs, "HEAD"], TIMEOUTS.fetch, tmp);
  }
  const rev = await run("git rev-parse", ["rev-parse", "--verify", "--quiet", "FETCH_HEAD^{commit}"], TIMEOUTS.revParse, tmp);
  const fetched = rev.stdout.trim();
  if (!SHA_RE.test(fetched)) throw new Error(`git rev-parse returned an unexpected object id`);
  await run("git checkout", ["checkout", "--quiet", "--detach", fetched], TIMEOUTS.checkout, tmp);
  // The search needs only the working tree: no history, no remote config, nothing credential-like.
  rmSync(join(tmp, ".git"), { recursive: true, force: true, maxRetries: 2 });
  ensureWorldReadable(tmp);
  return fetched;
}

async function syncRepo(ctx: RepoCtx, want: Desired): Promise<RepoResult> {
  const repo = want.name;
  const [owner, name] = repo.split("/") as [string, string];
  let tmp: string | undefined;
  try {
    const url = buildRepoUrl(ctx.template, repo);
    const env = gitEnv(url, ctx.token);
    const remote = await lsRemote(ctx, url, env);
    if (remote === null) {
      audit("sync.repo_empty", { repo });
      return { repo, action: "empty", error: "remote has no HEAD (empty repository?)" };
    }
    // Resolved with no await before the mkdirs below, so concurrent repos of one owner agree.
    const [ownerSeg, nameSeg] = onDiskName(ctx.mirrorDir, repo);
    const ownerDir = join(ctx.mirrorDir, ownerSeg);
    const repoDir = join(ownerDir, nameSeg);
    const snapRoot = join(repoDir, SNAPSHOTS);
    const meta = readMeta(repoDir);
    const current = readCurrent(repoDir);
    const previous = meta?.sha ?? current;

    if (meta?.sha === remote.sha && current === remote.sha) {
      if (!ctx.dryRun) {
        writeMeta(repoDir, {
          ...meta,
          repo,
          branch: remote.branch,
          synced_at: new Date(ctx.now()).toISOString(),
          description: want.description ?? meta.description,
        });
        clearRetiredQuietly(repoDir);
      }
      return { repo, action: "unchanged", sha: remote.sha, branch: remote.branch };
    }
    if (ctx.dryRun) {
      return { repo, action: "would_sync", sha: remote.sha, previous_sha: previous, branch: remote.branch };
    }

    ensureRealDir(ownerDir);
    ensureRealDir(repoDir);
    ensureRealDir(snapRoot);

    let sha = remote.sha;
    let reused = existsSync(join(snapRoot, sha)) && lstatSync(join(snapRoot, sha)).isDirectory();
    if (!reused) {
      tmp = join(snapRoot, `${sha}.tmp-${process.pid}`);
      rmSync(tmp, { recursive: true, force: true, maxRetries: 2 });
      sha = await buildSnapshot(ctx, url, env, tmp, sha);
      const final = join(snapRoot, sha);
      const existing = lstatOrUndefined(final);
      if (existing?.isDirectory() && !existing.isSymbolicLink()) {
        // HEAD moved to a commit we already have a complete snapshot of.
        rmSync(tmp, { recursive: true, force: true, maxRetries: 2 });
        reused = true;
      } else {
        if (existing) throw new Error(`${final} exists and is not a directory`);
        renameSync(tmp, final);
      }
      tmp = undefined;
    }
    // mtime = the time this snapshot became current (drives the prune grace period).
    const t = ctx.now() / 1000;
    utimesSync(join(snapRoot, sha), t, t);
    swapCurrent(repoDir, sha);
    // In service again (a repo retired earlier and listed again): its marker is stale.
    clearRetiredQuietly(repoDir);

    let description = want.description;
    if (description === undefined && ctx.token && ctx.github.getDescription) {
      try {
        description = sanitizeDescription(await ctx.github.getDescription(owner, name));
      } catch (e) {
        audit("sync.description_failed", { repo, error: ctx.scrub((e as Error).message) });
      }
    }
    writeMeta(repoDir, {
      repo,
      sha,
      branch: remote.branch,
      synced_at: new Date(ctx.now()).toISOString(),
      description: description ?? meta?.description ?? "",
    });
    return { repo, action: "synced", sha, previous_sha: previous, branch: remote.branch, ...(reused ? { reused } : {}) };
  } catch (e) {
    if (tmp !== undefined) {
      try {
        rmSync(tmp, { recursive: true, force: true, maxRetries: 2 });
      } catch {
        /* pruned later as a stale tmp dir */
      }
    }
    return { repo, action: "failed", error: ctx.scrub((e as Error).message) };
  }
}

/* --------------------------- removal of old repos --------------------------- */

/** True if `dir` contains only what sync creates (guards against deleting unrelated data). */
function looksLikeMirrorRepo(dir: string): boolean {
  const entries = safeReaddir(dir);
  const own = (e: string): boolean => e === META || e === SNAPSHOTS || e === CURRENT || e === RETIRED_FILE;
  if (!entries.some(own)) return false;
  return entries.every((e) => own(e) || CURRENT_TMP_RE.test(e) || META_TMP_RE.test(e));
}

interface Removal {
  removed: string[];
  retired: string[];
}

/**
 * Mirrored repos that are not in `keepNames` (spelled as on disk, see onDiskName; and not protected by a failed `owner/*` expansion,
 * unless excluded) are retired first (see retireRepo) and deleted only once they have been retired
 * for `graceMs`: a review that started while the repo was still listed may read its pinned snapshot
 * for as long as the review job runs. A marker that is missing, unreadable or dated in the future,
 * or a `current` that is still (or again) in place, restarts the grace period from `nowMs`, so a
 * repo is never deleted earlier than `graceMs` after discovery last could list it.
 */
function removeUnlisted(
  mirrorDir: string,
  keepNames: Set<string>,
  protectedPatterns: string[],
  exclude: string[],
  dryRun: boolean,
  nowMs: number,
  graceMs: number,
  /** --owner: only that owner's directory, and those of owners the policy no longer names (lower case). */
  scope?: { owner: string; named: Set<string> },
): Removal {
  const removed: string[] = [];
  const retired: string[] = [];
  for (const owner of safeReaddir(mirrorDir)) {
    if (!isOwnerSegment(owner)) continue;
    const lower = owner.toLowerCase();
    if (scope && lower !== scope.owner && scope.named.has(lower)) continue; // another owner's run
    const ownerDir = join(mirrorDir, owner);
    const ost = lstatOrUndefined(ownerDir);
    if (!ost?.isDirectory() || ost.isSymbolicLink()) continue;
    let removedHere = false;
    for (const name of safeReaddir(ownerDir)) {
      if (!isRepoSegment(name)) continue;
      const repo = `${owner}/${name}`;
      if (keepNames.has(repo)) continue;
      const isExcluded = exclude.some((p) => repoPatternMatch(p, repo));
      if (!isExcluded && protectedPatterns.some((p) => repoPatternMatch(p, repo))) continue;
      const repoDir = join(ownerDir, name);
      const st = lstatOrUndefined(repoDir);
      if (!st?.isDirectory() || st.isSymbolicLink()) continue;
      if (!looksLikeMirrorRepo(repoDir)) {
        audit("sync.remove_skipped", { repo, reason: "directory does not look like a mirror repo" });
        continue;
      }
      let retiredAt = readRetiredAt(repoDir);
      if (retiredAt === undefined || retiredAt > nowMs || isServable(repoDir)) {
        if (!dryRun) {
          try {
            retireRepo(repoDir, nowMs);
            audit("sync.retire", { repo, delete_after_s: Math.round(graceMs / 1000) });
          } catch (e) {
            audit("sync.retire_failed", { repo, error: e });
            continue;
          }
        }
        retiredAt = nowMs;
      }
      if (nowMs - retiredAt < graceMs) {
        retired.push(repo);
        continue;
      }
      if (dryRun) {
        removed.push(repo);
        continue;
      }
      try {
        removeTree(repoDir, mirrorDir);
        removed.push(repo);
        removedHere = true;
        audit("sync.remove", { repo, retired_s: Math.round((nowMs - retiredAt) / 1000) });
      } catch (e) {
        audit("sync.remove_failed", { repo, error: e });
      }
    }
    if (removedHere) {
      try {
        rmdirSync(ownerDir);
      } catch {
        /* not empty */
      }
    }
  }
  return { removed, retired };
}

/* ---------------------------------- main ---------------------------------- */

async function pool<T, R>(items: T[], limit: number, fn: (item: T) => Promise<R>): Promise<R[]> {
  const out = new Array<R>(items.length);
  let next = 0;
  const worker = async (): Promise<void> => {
    while (next < items.length) {
      const i = next++;
      out[i] = await fn(items[i]!);
    }
  };
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, worker));
  return out;
}

/** Sync the mirror according to the policy. Throws SyncLockError if another sync holds the lock. */
export async function syncMirror(opts: SyncOptions): Promise<SyncReport> {
  const mirrorDir = resolve(opts.mirrorDir);
  const template = opts.urlTemplate ?? DEFAULT_URL_TEMPLATE;
  validateUrlTemplate(template);
  const dryRun = opts.dryRun === true;
  const token = opts.token?.trim() || undefined;
  const scrub = makeScrubber(token);
  const now = opts.now ?? Date.now;
  const github = opts.github ?? createGithubApi(token);
  const mirror = opts.policy.mirror;
  const graceMs = opts.snapshotGraceMs ?? SNAPSHOT_GRACE_MS;
  if (!Number.isInteger(graceMs) || graceMs < 0 || graceMs > MAX_SNAPSHOT_GRACE_MS) {
    throw new SyncUsageError(`snapshot grace period must be an integer between 0 and ${MAX_SNAPSHOT_GRACE_MS} ms`);
  }
  const owner = opts.owner?.trim() || undefined;
  if (owner !== undefined && !isOwnerSegment(owner)) throw new SyncUsageError(`--owner ${JSON.stringify(owner)}: expected a GitHub account name`);
  if (opts.repos !== undefined) selectOnly(mirror, opts.repos, owner); // fail fast, before touching the mirror

  let lock: SyncLock | undefined;
  if (!dryRun) {
    if (!existsSync(mirrorDir)) {
      mkdirSync(mirrorDir, { recursive: true, mode: 0o755 });
      chmodSync(mirrorDir, 0o755); // independent of umask: the search container runs as nobody
    }
    lock = acquireLock(mirrorDir, opts.lock);
  }
  try {
    if (!dryRun) {
      for (const ent of safeReaddir(mirrorDir)) {
        if (ent.startsWith(TRASH_PREFIX)) rmSync(join(mirrorDir, ent), { recursive: true, force: true, maxRetries: 2 });
      }
    }
    audit("sync.start", { mirror: mirrorDir, dry_run: dryRun, only: opts.repos, owner, entries: mirror.repos.length });
    const res = await resolveRepos(mirror, github, opts.repos, scrub, owner);
    const ctx: RepoCtx = {
      mirrorDir,
      template,
      token,
      dryRun,
      keep: mirror.keep_snapshots,
      git: opts.git ?? spawnGit,
      github,
      now,
      scrub,
    };
    let pruned = 0;
    const results = await pool(res.desired, CONCURRENCY, async (want) => {
      const r = await syncRepo(ctx, want);
      if (!dryRun) {
        const repoDir = join(mirrorDir, ...onDiskName(mirrorDir, want.name));
        const st = lstatOrUndefined(repoDir);
        if (st?.isDirectory() && !st.isSymbolicLink()) {
          try {
            pruned += pruneSnapshots(repoDir, mirror.keep_snapshots, now(), graceMs);
          } catch (e) {
            audit("sync.prune_failed", { repo: want.name, error: e });
          }
        }
      }
      audit("sync.repo", { ...r });
      return r;
    });
    for (const f of res.failures) audit("sync.repo", { ...f });

    let removal: Removal = { removed: [], retired: [] };
    if (opts.repos === undefined) {
      removal = removeUnlisted(
        mirrorDir,
        new Set(res.desired.map((d) => onDiskName(mirrorDir, d.name).join("/"))),
        res.failedPatterns,
        mirror.exclude,
        dryRun,
        now(),
        graceMs,
        owner !== undefined
          ? {
              owner: owner.toLowerCase(),
              named: new Set(mirror.repos.map((e) => entryOwner(e.trim())).filter((o): o is string => o !== undefined)),
            }
          : undefined,
      );
    }
    const { removed, retired } = removal;
    const all = [...res.failures, ...results];
    const report: SyncReport = {
      dry_run: dryRun,
      ...(owner !== undefined ? { owner } : {}),
      results: all,
      removed,
      retired,
      pruned,
      failed: all.filter((r) => r.action === "failed").length,
    };
    audit("sync.done", {
      dry_run: dryRun,
      repos: all.length,
      synced: all.filter((r) => r.action === "synced").length,
      failed: report.failed,
      removed: removed.length,
      retired: retired.length,
      pruned,
    });
    return report;
  } finally {
    lock?.release();
  }
}

export const USAGE =
  "usage: xrepo sync --policy <file> --mirror <dir> [--repo owner/name ...] [--owner <login>] [--url-template <tpl>]\n" +
  "                  [--snapshot-grace-minutes <n>] [--dry-run]\n" +
  "  --owner: sync only this account's mirror.repos entries, and retire / remove only mirrors under\n" +
  "    it or under owners the policy no longer names (one App installation token covers one account)\n" +
  `  token: env ${TOKEN_ENV} (required unless the URL template is file://)\n` +
  `  --snapshot-grace-minutes: keep a retired snapshot, and a repo dropped from the mirror set, this\n` +
  `    long after it was retired (default ${SNAPSHOT_GRACE_MS / 60_000}; must exceed the review job\n` +
  "    timeout, or a running review loses its cross-repo snapshot)\n" +
  "  exit: 0 ok, 1 some repos failed, 2 usage/config error, 3 another sync holds the lock (heartbeat\n" +
  `    younger than ${LOCK_STALE_MS / 60_000} minutes), 128+n killed by signal n (the lock is released)`;

const RELEASE_SIGNALS = ["SIGINT", "SIGTERM", "SIGHUP"] as const;

/** Signal handler of `xrepo sync`: release held locks (so the next sync is not blocked), then exit. */
function onSyncSignal(sig: (typeof RELEASE_SIGNALS)[number]): void {
  const held = [...heldLocks];
  for (const l of held) l.release();
  audit("sync.interrupted", { signal: sig, released_locks: held.length });
  process.exit(128 + (osConstants.signals[sig] ?? 0));
}

function parseGraceMinutes(v: string | undefined): number | undefined {
  if (v === undefined) return undefined;
  const t = v.trim();
  const max = MAX_SNAPSHOT_GRACE_MS / 60_000;
  if (!/^\d{1,6}$/.test(t) || Number(t) > max) {
    throw new SyncUsageError(`--snapshot-grace-minutes must be an integer between 0 and ${max}`);
  }
  return Number(t) * 60_000;
}

/**
 * `xrepo sync`: prints a JSON report on stdout (audit lines on stderr).
 * Exit codes: 0 ok, 1 some repos failed, 2 usage/config error, 3 lock held by another sync.
 */
export async function main(args: string[]): Promise<number> {
  let policyPath: string;
  let mirrorDir: string;
  let repos: string[] | undefined;
  let owner: string | undefined;
  let template: string;
  let dryRun: boolean;
  let snapshotGraceMs: number | undefined;
  let policy: PolicyFile;
  try {
    const v = parseCli(args, {
      policy: { type: "string", required: true },
      mirror: { type: "string", required: true },
      repo: { type: "string", multiple: true },
      owner: { type: "string" },
      "url-template": { type: "string" },
      "snapshot-grace-minutes": { type: "string" },
      "dry-run": { type: "boolean" },
    });
    policyPath = v.policy as string;
    mirrorDir = v.mirror as string;
    const r = v.repo as string[] | undefined;
    repos = r && r.length > 0 ? r.map((x) => x.trim()) : undefined;
    const o = v.owner as string | undefined;
    if (o !== undefined) {
      owner = o.trim();
      if (!isOwnerSegment(owner)) throw new SyncUsageError(`--owner ${JSON.stringify(o)}: expected a GitHub account name`);
    }
    template = (v["url-template"] as string | undefined) ?? DEFAULT_URL_TEMPLATE;
    dryRun = v["dry-run"] === true;
    snapshotGraceMs = parseGraceMinutes(v["snapshot-grace-minutes"] as string | undefined);
    const scheme = validateUrlTemplate(template);
    if (scheme !== "file" && !process.env[TOKEN_ENV]?.trim()) {
      throw new SyncUsageError(`env ${TOKEN_ENV} is required for ${scheme}:// URL templates`);
    }
    for (const x of repos ?? []) {
      if (!isValidRepoName(x)) throw new SyncUsageError(`--repo ${JSON.stringify(x)}: expected owner/name`);
    }
  } catch (e) {
    process.stderr.write(`xrepo sync: ${(e as Error).message}\n${USAGE}\n`);
    return 2;
  }
  try {
    policy = loadPolicy(policyPath);
  } catch (e) {
    process.stderr.write(`xrepo sync: ${(e as Error).message}\n`);
    return 2;
  }

  const token = process.env[TOKEN_ENV]?.trim() || undefined;
  // A sync killed by a cancelled / timed-out job must not leave its lock behind.
  const handlers = RELEASE_SIGNALS.map((sig) => {
    const h = (): void => onSyncSignal(sig);
    process.on(sig, h);
    return [sig, h] as const;
  });
  try {
    const report = await syncMirror({ policy, mirrorDir, repos, ...(owner !== undefined ? { owner } : {}), urlTemplate: template, token, dryRun, snapshotGraceMs });
    process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
    return report.failed > 0 ? 1 : 0;
  } catch (e) {
    if (e instanceof SyncLockError) {
      audit("sync.lock_held", {
        mirror: mirrorDir,
        holder: e.holder,
        heartbeat_age_s: e.heartbeatAgeMs === undefined ? undefined : Math.round(e.heartbeatAgeMs / 1000),
      });
      process.stderr.write(`xrepo sync: ${e.message}\n`);
      return 3;
    }
    if (e instanceof SyncUsageError) {
      process.stderr.write(`xrepo sync: ${e.message}\n`);
      return 2;
    }
    const msg = makeScrubber(token)((e as Error).message ?? String(e));
    audit("sync.failed", { mirror: mirrorDir, error: msg });
    process.stderr.write(`xrepo sync: ${msg}\n`);
    return 1;
  } finally {
    for (const [sig, h] of handlers) process.removeListener(sig, h);
  }
}

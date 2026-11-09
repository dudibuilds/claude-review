/**
 * Virtual file system of the xsearch MCP: maps the agent's virtual paths to host paths.
 *
 *   /pr/<path>                     PR head checkout of the repository under review
 *   /repos/<owner>/<name>/<path>   mirrored default-branch snapshot of each readable repo
 *
 * Security properties (SPEC threat model T2/T3/T4):
 * - Only `/pr` and the mirror repos readable under the resolved policy exist. Other repos are never
 *   listed or named, not even in error messages.
 * - Virtual paths are parsed strictly: absolute only, no "..", NUL or backslash.
 * - Every resolved path is realpath'd and must stay inside its repo root (a symlink inside a repo
 *   that points elsewhere is refused).
 * - `.git` and `search.deny_globs` are invisible: they resolve exactly like missing files. Both the
 *   requested path and the symlink-resolved path are checked. Deny globs match case-insensitively
 *   (".ENV", "Secrets/", "KEY.PEM" are as hidden as ".env", "secrets/", "key.pem").
 * - In mirror roots, the policy manifest's location is hidden too: MIRROR_HIDDEN_GLOBS (the
 *   documented hosted-mode location) plus any path passed by prepare (`--policy-path`), so a
 *   mirrored copy of the repository that holds the policy never exposes it (SPEC T2/T3).
 * - Host paths never appear in output; callers convert results back with `toVirtual`.
 */
import { lstatSync, readFileSync, readdirSync, readlinkSync, realpathSync, statSync } from "node:fs";
import { join, relative, sep } from "node:path";
import { compileGlobs } from "../policy/glob.js";

export class VfsError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "VfsError";
  }
}

/** One mirrored repository with a valid `current` snapshot and meta.json. */
export interface MirrorRepoInfo {
  /** owner/name from the directory layout (authoritative identity). */
  repo: string;
  /** realpath of the snapshot directory `current` points to. */
  host: string;
  sha: string;
  branch: string;
  synced_at: string;
  description: string;
}

export interface Root {
  /** "/pr" or "/repos/<owner>/<name>". */
  vpath: string;
  kind: "pr" | "mirror";
  /** owner/name (for /pr: the PR repository). */
  repo: string;
  /** realpath of the root directory on the host. */
  host: string;
  mirror?: MirrorRepoInfo;
}

/** A virtual directory above the repo roots: "/", "/repos" or "/repos/<owner>". */
export interface VirtualDir {
  kind: "vdir";
  vpath: string;
  roots: Root[];
}

/** An existing file or directory inside a root. */
export interface RepoEntry {
  kind: "file" | "dir";
  vpath: string;
  root: Root;
  /** Repo-relative path after resolving symlinks ("" for the root itself). */
  rel: string;
  /** realpath on the host. */
  host: string;
  size: number;
}

export type Resolved = VirtualDir | RepoEntry;

/** Syntactic parse result (no filesystem access). */
export type ParsedPath = VirtualDir | { kind: "repo"; vpath: string; root: Root; rel: string };

const SEGMENT_RE = /^[A-Za-z0-9_.-]{1,100}$/;
const SHA_LINK_RE = /^snapshots\/([0-9A-Fa-f]{7,64})\/?$/;
const MAX_PATH_CHARS = 4096;
const MAX_LISTED_ROOTS = 20;

/**
 * Repo-relative locations hidden in every mirror root (case-insensitive): where the hosted-mode
 * policy manifest lives by default (review.yml `policy_file: .github/xrepo/policy.yaml`).
 */
export const MIRROR_HIDDEN_GLOBS: readonly string[] = ["/.github/xrepo/"];

/** Owner directory: no leading "." (sync's lock and temp files live at that level). */
function isSafeOwnerSegment(s: string): boolean {
  return SEGMENT_RE.test(s) && !s.startsWith(".");
}

/**
 * Repository directory: GitHub allows a leading "." (e.g. "acme/.github", sync mirrors it), but
 * never "." / ".." or ".git".
 */
function isSafeRepoSegment(s: string): boolean {
  return SEGMENT_RE.test(s) && s !== "." && s !== ".." && s.toLowerCase() !== ".git";
}

/** "owner/name" as laid out in the mirror (the rule discoverMirror applies to each directory). */
export function isMirrorRepoName(repo: string): boolean {
  const parts = typeof repo === "string" ? repo.split("/") : [];
  return parts.length === 2 && isSafeOwnerSegment(parts[0]!) && isSafeRepoSegment(parts[1]!);
}

function lstatOrNull(p: string): ReturnType<typeof lstatSync> | null {
  try {
    return lstatSync(p);
  } catch {
    return null;
  }
}

function str(v: unknown): string {
  return typeof v === "string" ? v : "";
}

/**
 * Mirrored repos under `<mirror>/<owner>/<repo>/{current -> snapshots/<sha>, meta.json}`, sorted
 * by name. `current` must be a relative symlink to `snapshots/<sha>`; meta.json must name the same
 * repo (case-insensitive). Anything else is skipped silently.
 */
export function discoverMirror(mirrorDir: string | undefined): MirrorRepoInfo[] {
  if (!mirrorDir) return [];
  let base: string;
  try {
    base = realpathSync(mirrorDir);
    if (!statSync(base).isDirectory()) return [];
  } catch {
    return [];
  }
  const out: MirrorRepoInfo[] = [];
  const seen = new Set<string>();
  const list = (dir: string): string[] => {
    try {
      return readdirSync(dir).sort();
    } catch {
      return [];
    }
  };
  for (const owner of list(base)) {
    if (!isSafeOwnerSegment(owner)) continue;
    const ownerDir = join(base, owner);
    const ost = lstatOrNull(ownerDir);
    if (!ost || ost.isSymbolicLink() || !ost.isDirectory()) continue;
    for (const name of list(ownerDir)) {
      if (!isSafeRepoSegment(name)) continue;
      const repo = `${owner}/${name}`;
      if (seen.has(repo.toLowerCase())) continue;
      const repoDir = join(ownerDir, name);
      try {
        const rst = lstatOrNull(repoDir);
        if (!rst || rst.isSymbolicLink() || !rst.isDirectory()) continue;
        const cur = join(repoDir, "current");
        const cst = lstatOrNull(cur);
        if (!cst || !cst.isSymbolicLink()) continue;
        const m = SHA_LINK_RE.exec(readlinkSync(cur));
        if (!m) continue;
        const sha = m[1]!;
        const expected = join(repoDir, "snapshots", sha);
        const real = realpathSync(cur);
        if (real !== expected || !statSync(real).isDirectory()) continue;
        const meta = JSON.parse(readFileSync(join(repoDir, "meta.json"), "utf8")) as Record<string, unknown>;
        if (meta === null || typeof meta !== "object" || str(meta.repo).toLowerCase() !== repo.toLowerCase()) continue;
        out.push({
          repo,
          host: real,
          sha,
          branch: str(meta.branch),
          synced_at: str(meta.synced_at),
          description: str(meta.description),
        });
        seen.add(repo.toLowerCase());
      } catch {
        /* skip unreadable / half-synced entries */
      }
    }
  }
  return out;
}

export interface VfsOptions {
  /** PR head checkout directory (served as /pr). */
  prDir: string;
  /** owner/name of the PR repository. */
  prRepo: string;
  /** Readable mirror repos only (already filtered by policy). */
  mirror: MirrorRepoInfo[];
  denyGlobs: string[];
  /**
   * Extra repo-relative globs hidden in mirror roots only (case-insensitive), added to
   * MIRROR_HIDDEN_GLOBS; e.g. "/<policy path>" for the policy manifest's own repository.
   */
  mirrorHiddenGlobs?: string[];
}

/** Case-insensitive glob matcher: the patterns as written, or both sides lowercased. */
function compileGlobsNocase(globs: string[]): (rel: string) => boolean {
  const exact = compileGlobs(globs);
  const lower = compileGlobs(globs.map((g) => g.toLowerCase()));
  return (rel: string): boolean => exact(rel) || lower(rel.toLowerCase());
}

export class Vfs {
  readonly roots: Root[];
  readonly prRoot: Root;
  private readonly deny: (rel: string) => boolean;
  private readonly mirrorHidden: (rel: string) => boolean;

  constructor(opts: VfsOptions) {
    let prHost: string;
    try {
      prHost = realpathSync(opts.prDir);
      if (!statSync(prHost).isDirectory()) throw new Error("not a directory");
    } catch (e) {
      throw new Error(`PR checkout ${opts.prDir} is not readable: ${(e as Error).message}`);
    }
    this.prRoot = { vpath: "/pr", kind: "pr", repo: opts.prRepo, host: prHost };
    const mirrorRoots: Root[] = [...opts.mirror]
      .sort((a, b) => (a.repo < b.repo ? -1 : a.repo > b.repo ? 1 : 0))
      .map((m) => ({ vpath: `/repos/${m.repo}`, kind: "mirror" as const, repo: m.repo, host: m.host, mirror: m }));
    this.roots = [this.prRoot, ...mirrorRoots];
    this.deny = compileGlobsNocase(opts.denyGlobs);
    this.mirrorHidden = compileGlobsNocase([...MIRROR_HIDDEN_GLOBS, ...(opts.mirrorHiddenGlobs ?? [])]);
  }

  /**
   * True for paths the agent must never see: anything under `.git`, deny_globs (case-insensitive)
   * and, inside a mirror root, the policy manifest's location. Pass the root whenever it is known.
   */
  isHidden(rel: string, root?: Root): boolean {
    if (rel === "") return false;
    if (rel.split("/").some((s) => s.toLowerCase() === ".git")) return true;
    if (this.deny(rel)) return true;
    return root?.kind === "mirror" && this.mirrorHidden(rel);
  }

  /**
   * Roots searched when the agent does not name a repository (path omitted, "/", "/repos",
   * "/repos/<owner>"): everything except the PR repository's own mirror, whose unchanged files
   * would duplicate /pr. That base snapshot is searched only when its root is passed explicitly.
   */
  implicitRoots(roots: Root[]): Root[] {
    return roots.filter((r) => !this.isOwnBase(r));
  }

  /** The mirror root of the PR repository itself (its base / default branch). */
  isOwnBase(root: Root): boolean {
    return root.kind === "mirror" && root.repo.toLowerCase() === this.prRoot.repo.toLowerCase();
  }

  /** "/pr, /repos/a/b, ..." (capped). */
  rootsText(): string {
    const names = this.roots.map((r) => r.vpath);
    const shown = names.slice(0, MAX_LISTED_ROOTS).join(", ");
    return names.length > MAX_LISTED_ROOTS ? `${shown} (+${names.length - MAX_LISTED_ROOTS} more; see ListRepos)` : shown;
  }

  toVirtual(root: Root, rel: string): string {
    return rel === "" ? root.vpath : `${root.vpath}/${rel}`;
  }

  /** Repo-relative path segments of a vroot relative to a virtual dir ("/repos" + "/repos/a/b" -> ["a","b"]). */
  rootSegmentsBelow(vdir: string, root: Root): string[] {
    const r = root.vpath.split("/").filter(Boolean);
    const d = vdir.split("/").filter(Boolean);
    return r.slice(d.length);
  }

  private notFound(vpath: string): VfsError {
    return new VfsError(`Path does not exist: ${vpath}. Valid roots: ${this.rootsText()}.`);
  }

  /** Strict syntactic parse; throws VfsError with a helpful message. */
  parse(input: unknown): ParsedPath {
    if (typeof input !== "string") throw new VfsError("Path must be a string.");
    const p = input.trim();
    if (p === "") throw new VfsError(`Path must not be empty. Valid roots: ${this.rootsText()}.`);
    if (p.length > MAX_PATH_CHARS) throw new VfsError(`Path is too long (max ${MAX_PATH_CHARS} characters).`);
    if (p.includes("\0")) throw new VfsError("Path must not contain NUL characters.");
    if (p.includes("\\")) throw new VfsError(`Path must use forward slashes, not backslashes: ${JSON.stringify(p)}.`);
    if (!p.startsWith("/")) {
      const rel = p.replace(/^(?:\.\/+)+/, "");
      // A virtual path that only lost its leading "/" ("pr/src/x.ts", "repos/o/n/x") is that path.
      const guess = /^(?:pr|repos)(?:\/|$)/i.test(rel) ? `/${rel}` : `/pr/${rel}`;
      throw new VfsError(
        `Path must be an absolute virtual path starting with /pr or /repos/<owner>/<name> (got ${JSON.stringify(p)}). ` +
          `Did you mean ${guess}? Valid roots: ${this.rootsText()}.`,
      );
    }
    const segs = p.split("/").filter((s) => s !== "" && s !== ".");
    if (segs.includes("..")) {
      throw new VfsError(`Path must not contain ".." segments: ${JSON.stringify(p)}. Valid roots: ${this.rootsText()}.`);
    }
    const vpath = `/${segs.join("/")}`;
    if (segs.length === 0) return { kind: "vdir", vpath: "/", roots: [...this.roots] };
    const head = segs[0]!.toLowerCase();
    if (head === "pr") return { kind: "repo", vpath, root: this.prRoot, rel: segs.slice(1).join("/") };
    if (head === "repos") {
      const mirrors = this.roots.filter((r) => r.kind === "mirror");
      if (segs.length === 1) {
        if (mirrors.length === 0) throw this.notFound(vpath);
        return { kind: "vdir", vpath: "/repos", roots: mirrors };
      }
      const owner = segs[1]!.toLowerCase();
      const ofOwner = mirrors.filter((r) => r.repo.split("/")[0]!.toLowerCase() === owner);
      if (ofOwner.length === 0) throw this.notFound(vpath);
      if (segs.length === 2) {
        return { kind: "vdir", vpath: `/repos/${ofOwner[0]!.repo.split("/")[0]}`, roots: ofOwner };
      }
      const name = segs[2]!.toLowerCase();
      const root = ofOwner.find((r) => r.repo.split("/")[1]!.toLowerCase() === name);
      if (!root) throw this.notFound(vpath);
      const rel = segs.slice(3).join("/");
      return { kind: "repo", vpath: this.toVirtual(root, rel), root, rel };
    }
    throw this.notFound(vpath);
  }

  /**
   * Parse and resolve against the filesystem. Hidden (.git / denied) and escaping paths fail exactly
   * like missing ones (except symlink escapes, which say so).
   */
  resolve(input: unknown): Resolved {
    const parsed = this.parse(input);
    if (parsed.kind === "vdir") return parsed;
    const { root, rel, vpath } = parsed;
    if (this.isHidden(rel, root)) throw this.notFound(vpath);
    let real: string;
    try {
      real = realpathSync(rel === "" ? root.host : join(root.host, ...rel.split("/")));
    } catch {
      throw this.notFound(vpath);
    }
    if (real !== root.host && !real.startsWith(root.host + sep)) {
      throw new VfsError(`Path ${vpath} is a symbolic link that points outside its repository; it cannot be read.`);
    }
    const realRel = real === root.host ? "" : relative(root.host, real).split(sep).join("/");
    if (this.isHidden(realRel, root)) throw this.notFound(vpath);
    let st: ReturnType<typeof statSync>;
    try {
      st = statSync(real);
    } catch {
      throw this.notFound(vpath);
    }
    if (st.isDirectory()) return { kind: "dir", vpath, root, rel: realRel, host: real, size: 0 };
    if (st.isFile()) return { kind: "file", vpath, root, rel: realRel, host: real, size: st.size };
    throw this.notFound(vpath);
  }
}

/* ------------------------------ exclude_globs ----------------------------- */

const GLOB_CHARS = /[*?[\]{}!]/;

/** Literal core of a glob ("**\/node_modules/**" -> "node_modules", "**\/*.min.js" -> ".min.js"). */
function literalCore(glob: string): string {
  let g = glob.trim().replace(/^!+/, "");
  g = g.replace(/^\/+/, "").replace(/\/+$/, "");
  while (g.startsWith("**/")) g = g.slice(3);
  while (g.endsWith("/**")) g = g.slice(0, -3);
  if (!GLOB_CHARS.test(g)) return g;
  const runs = g.split(/[*?[\]{}!]+/).filter(Boolean);
  return runs.reduce((a, b) => (b.length > a.length ? b : a), "");
}

/**
 * search.exclude_globs (lockfiles, minified, vendored) are skipped by Grep/Glob unless the search
 * explicitly targets them: the searched path lies inside an excluded location, or the user's
 * glob/pattern names them literally (e.g. "**\/package-lock.json", "node_modules/**").
 */
export class ExcludeSet {
  private readonly entries: { glob: string; match: (rel: string) => boolean; core: string }[];

  constructor(globs: string[]) {
    this.entries = globs.map((glob) => ({ glob, match: compileGlobs([glob]), core: literalCore(glob) }));
  }

  /** Exclude globs that stay active for a search of `targetRels` with the given user globs. */
  active(targetRels: string[], userGlobs: string[]): string[] {
    return this.entries
      .filter((e) => {
        if (targetRels.some((rel) => rel !== "" && e.match(rel))) return false;
        if (e.core.length >= 3 && userGlobs.some((u) => u.includes(e.core))) return false;
        return true;
      })
      .map((e) => e.glob);
  }

  /** The first of the `active` exclude globs that matches `rel`, if any. */
  which(rel: string, active: string[]): string | undefined {
    for (const e of this.entries) if (active.includes(e.glob) && e.match(rel)) return e.glob;
    return undefined;
  }
}

/**
 * Globs whose ripgrep meaning does not depend on rg's working directory (basename globs and
 * "**\/..." globs). Only these are passed to rg for pruning; every result is post-filtered with
 * compileGlobs anyway, so anchored globs are still enforced.
 */
export function isCwdIndependentGlob(glob: string): boolean {
  const g = glob.trim().replace(/\/+$/, "");
  if (g === "" || g.startsWith("!") || g.startsWith("/")) return false;
  return !g.includes("/") || g.startsWith("**/");
}

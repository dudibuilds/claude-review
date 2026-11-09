/**
 * xsearch tool implementations: ListRepos, PrDiff, Grep, Glob, Read.
 *
 * They behave like Claude Code's own Grep / Glob / Read (same parameter names, defaults and output
 * formats), over virtual paths (/pr, /repos/<owner>/<name>). Each returns plain text; the server
 * applies the final secret redaction and the max_output_chars cap (src/search/text.ts).
 */
import { existsSync, type Dirent } from "node:fs";
import { open, readFile, readdir, stat } from "node:fs/promises";
import { join } from "node:path";
import type { PrContext, PrFile } from "../common/context.js";
import type { DiffHunk, FileDiff } from "../common/diff.js";
import { compileGlobs } from "../policy/glob.js";
import type { ResolvedPolicy } from "../policy/schema.js";
import { baseRgArgs, mapLimit, rgErrorText, runRg, type RgOutcome } from "./rg.js";
import { compileSafeGlob } from "./safeglob.js";
import {
  NOTE_RESERVE,
  PEM_TAG,
  PemTracker,
  filePemLineMap,
  fitAtLeastOne,
  looksLikeKeyMaterial,
  oneLine,
  pemLineMap,
  pemReplacement,
  redactLine,
  stripCr,
  truncateLine,
} from "./text.js";
import { VfsError, isCwdIndependentGlob, type ExcludeSet, type RepoEntry, type Root, type VirtualDir, type Vfs } from "./vfs.js";

export const DEFAULT_HEAD_LIMIT = 250;
export const MAX_HEAD_LIMIT = 1000;
export const MAX_CONTEXT = 10;
export const MAX_PATTERN_CHARS = 1000;
export const GLOB_RESULT_LIMIT = 100;
/** Grep content lines longer than this are cut (Claude Code passes --max-columns 500 to rg). */
export const GREP_MAX_LINE_CHARS = 500;
const MAX_USER_GLOBS = 20;
const MAX_GLOB_CHARS = 512;
const RG_CONCURRENCY = 4;
/** Hard cap on entries collected per rg process, whatever head_limit says. */
const MAX_COLLECT = 20000;
/** Longest extra time spent looking for matches hidden by exclude_globs (see probeExcluded). */
const EXCLUDE_PROBE_MS = 1000;
/** Entries listed in Read's EISDIR error. */
const DIR_LIST_LIMIT = 100;

export interface SearchContext {
  vfs: Vfs;
  search: ResolvedPolicy["search"];
  ctx: PrContext;
  /** Diff of each changed file, keyed by its (new) path. */
  diffs: Map<string, FileDiff>;
  excludes: ExcludeSet;
  rgPath: string;
  now: () => number;
}

export interface ToolResult {
  text: string;
  isError?: boolean;
  /** A head_limit / window / char-budget cut happened (for the audit log). */
  truncated?: boolean;
}

export class ToolError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ToolError";
  }
}

/* --------------------------------- helpers -------------------------------- */

/** Claude Code models sometimes send "", "undefined" or "null" for an omitted path. */
function optionalPath(p: unknown): string | undefined {
  if (typeof p !== "string") return undefined;
  const t = p.trim();
  return t === "" || t === "undefined" || t === "null" ? undefined : t;
}

export function parseSize(s: string): number {
  const m = /^(\d+)([KMG]?)$/.exec(s.trim());
  if (!m) return 1024 * 1024;
  const mult = m[2] === "K" ? 1024 : m[2] === "M" ? 1024 ** 2 : m[2] === "G" ? 1024 ** 3 : 1;
  return Number(m[1]) * mult;
}

/** Files up to this size are scanned whole for PEM blocks (Read and Grep content). */
function pemScanMax(sc: SearchContext): number {
  return 8 * parseSize(sc.search.max_filesize);
}

function formatSize(bytes: number): string {
  if (bytes >= 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)}MB`;
  return `${Math.ceil(bytes / 1024)}KB`;
}

function plural(n: number, one: string, many: string): string {
  return n === 1 ? one : many;
}

function short(sha: string): string {
  return sha.slice(0, 7);
}

function age(iso: string, now: number): string {
  const t = Date.parse(iso);
  if (!Number.isFinite(t)) return "at an unknown time";
  const s = Math.max(0, Math.round((now - t) / 1000));
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 48 * 3600) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}

function decodeRgText(v: unknown): string {
  if (v && typeof v === "object") {
    const o = v as { text?: unknown; bytes?: unknown };
    if (typeof o.text === "string") return o.text;
    if (typeof o.bytes === "string") return Buffer.from(o.bytes, "base64").toString("utf8");
  }
  return "";
}

/** Raw bytes of an rg JSON text field (submatch offsets are byte offsets). */
function rgBytes(v: unknown): Buffer {
  if (v && typeof v === "object") {
    const o = v as { text?: unknown; bytes?: unknown };
    if (typeof o.text === "string") return Buffer.from(o.text, "utf8");
    if (typeof o.bytes === "string") return Buffer.from(o.bytes, "base64");
  }
  return Buffer.alloc(0);
}

function stripDotSlash(p: string): string {
  let s = p;
  while (s.startsWith("./")) s = s.slice(2);
  return s;
}

/** Split Claude Code style: whitespace-separated, commas split unless the pattern has braces. */
export function splitGlobParam(glob: string | undefined): string[] {
  if (!glob) return [];
  const out: string[] = [];
  for (const raw of glob.split(/\s+/)) {
    if (raw === "") continue;
    if (raw.includes("{") && raw.includes("}")) out.push(raw);
    else out.push(...raw.split(",").filter(Boolean));
  }
  return out;
}

function checkGlob(g: string, what: string): void {
  if (g.length > MAX_GLOB_CHARS) throw new ToolError(`${what} is too long (max ${MAX_GLOB_CHARS} characters).`);
  if (g.includes("\0")) throw new ToolError(`${what} must not contain NUL characters.`);
}

/* --------------------------------- targets -------------------------------- */

/** One rg invocation: cwd is a repo root or a directory inside it; `arg` is "." or a file path. */
interface Target {
  root: Root;
  cwd: string;
  arg: string;
  /** Repo-relative path of cwd ("" = root); rg output is relative to cwd. */
  baseRel: string;
  /** Repo-relative path of the searched path itself (for exclude targeting). */
  targetRel: string;
  file: boolean;
  globs: string[];
}

function rootTarget(root: Root, globs: string[]): Target {
  return { root, cwd: root.host, arg: ".", baseRel: "", targetRel: "", file: false, globs };
}

function repoRelOf(t: Target, printed: string): string {
  const p = stripDotSlash(printed);
  if (t.file || t.baseRel === "") return p;
  return p === "" ? t.baseRel : `${t.baseRel}/${p}`;
}

interface Targets {
  targets: Target[];
  /**
   * The PR repository's own mirror root, left out of a "/repos" or "/repos/<owner>" search (one
   * that does not cover /pr either), for the "searched only when passed as path" note.
   */
  skippedBase?: Root;
}

/**
 * Roots searched when no repository is named (path omitted, "/", "/repos", "/repos/<owner>"):
 * everything but the PR repository's own base snapshot, whose unchanged files duplicate /pr.
 */
function implicitTargets(sc: SearchContext, roots: Root[], globs: string[]): Targets {
  const kept = sc.vfs.implicitRoots(roots);
  const skippedBase = roots.includes(sc.vfs.prRoot) ? undefined : roots.find((r) => sc.vfs.isOwnBase(r));
  return { targets: kept.map((r) => rootTarget(r, globs)), ...(skippedBase ? { skippedBase } : {}) };
}

function grepTargets(sc: SearchContext, pathArg: string | undefined, userGlobs: string[]): Targets {
  if (pathArg === undefined) return implicitTargets(sc, sc.vfs.roots, userGlobs);
  const r = sc.vfs.resolve(pathArg);
  if (r.kind === "vdir") return implicitTargets(sc, r.roots, userGlobs);
  if (r.kind === "dir") {
    return { targets: [{ root: r.root, cwd: r.host, arg: ".", baseRel: r.rel, targetRel: r.rel, file: false, globs: userGlobs }] };
  }
  return { targets: [{ root: r.root, cwd: r.root.host, arg: r.rel, baseRel: "", targetRel: r.rel, file: true, globs: userGlobs }] };
}

/** rg arguments that prune deny globs (case-insensitively, --iglob) and .git. */
function denyPruneArgs(sc: SearchContext): string[] {
  const out: string[] = [];
  for (const g of sc.search.deny_globs) {
    if (isCwdIndependentGlob(g)) out.push(`--iglob=!${g.trim()}`);
  }
  // rg applies every --iglob after every --glob, so these also win over any user glob.
  out.push("--iglob=!.git");
  return out;
}

/** Deny + active exclude prune arguments (only cwd-independent globs; see vfs.ts). */
function pruneArgs(sc: SearchContext, activeExcludes: string[]): string[] {
  const out: string[] = [];
  for (const g of activeExcludes) {
    if (isCwdIndependentGlob(g)) out.push(`--glob=!${g.trim()}`);
  }
  return [...out, ...denyPruneArgs(sc)];
}

/** Note for an implicit search that found nothing while the PR repo's base snapshot was skipped. */
function skippedBaseNote(skipped: Root | undefined): string {
  if (!skipped) return "";
  return `\n\n[${skipped.vpath} (this PR's repository before the change) is searched only when you pass it as path.]`;
}

/**
 * Roots whose directory vanished while this review ran (a mirror repo deleted by `xrepo sync`, or by
 * hand): rg could not run there. Those are skipped with a note; a search whose every target
 * vanished fails with a clear error instead of "rg is not installed" or a silent "No matches".
 */
function vanishedRootsNote(targets: Target[], outcomes: RgOutcome[]): string {
  const gone = targets.filter((_, i) => outcomes[i]?.missingCwd === true);
  if (gone.length === 0) return "";
  const names = [...new Set(gone.map((t) => t.root.vpath))];
  const list = names.slice(0, 5).join(", ") + (names.length > 5 ? ` and ${names.length - 5} more` : "");
  if (gone.length === targets.length) {
    throw new ToolError(`${list} ${names.length === 1 ? "is" : "are"} no longer available: removed from the repository mirror while this review ran.`);
  }
  return `\n\n[Not searched: ${list} (removed from the repository mirror while this review ran).]`;
}

/** Longest "also matched, not shown" note (see unshownRootsNote). */
const ROOTS_NOTE_MAX = 300;

interface RootCount {
  root: Root;
  /** Index of the root's first entry in the joined result list. */
  first: number;
  /** Files with results in that root. */
  files: number;
  /** The root's search stopped early: more files may match. */
  more: boolean;
}

/**
 * A search over several roots joins their results in root order (/pr first), so a head_limit or
 * size cut can hide every hit of the later roots. Names the roots none of whose results were shown
 * (all entries at or after `shownEnd`), with their file counts.
 */
function unshownRootsNote(counts: RootCount[], shownEnd: number): string {
  const missed = counts.filter((c) => c.files > 0 && c.first >= shownEnd);
  if (missed.length === 0) return "";
  const parts: string[] = [];
  let len = 0;
  for (const c of missed) {
    const part = `${c.root.vpath} (${c.files}${c.more ? "+" : ""} ${plural(c.files, "file", "files")})`;
    if (parts.length > 0 && len + part.length > ROOTS_NOTE_MAX - 100) break;
    parts.push(part);
    len += part.length + 2;
  }
  const rest = missed.length - parts.length;
  const more = rest > 0 ? ` and ${rest} more ${plural(rest, "repository", "repositories")}` : "";
  return `\n[Also matched, not shown: ${parts.join(", ")}${more}. Pass one as path to see its results.]`;
}

/**
 * A Grep glob written as a virtual path ("/pr/src/**\/*.ts"): rg anchors a leading "/" at the
 * searched directory, so it would silently match nothing. Returns the error to show, or undefined
 * (also when a searched directory really has a top-level "pr" / "repos" entry).
 */
function virtualPathGlobError(sc: SearchContext, globs: string[], targets: Target[]): string | undefined {
  for (const g of globs) {
    const body = g.startsWith("!") ? g.slice(1) : g;
    if (!body.startsWith("/")) continue;
    const segs = body.split("/").filter((x) => x !== "" && x !== ".");
    const head = segs[0]?.toLowerCase();
    if (head !== "pr" && head !== "repos") continue;
    if (targets.some((t) => !t.file && existsSync(join(t.cwd, segs[0]!)))) continue;
    let i = 0;
    while (i < segs.length && !GLOB_META.test(segs[i]!)) i++;
    const dir = `/${segs.slice(0, i).join("/")}`;
    const rest = segs.slice(i).join("/");
    let example = 'pass a repository root from ListRepos (or a directory in it) as path, and a glob relative to it such as "src/**/*.ts"';
    try {
      const parsed = sc.vfs.parse(dir);
      if (parsed.kind === "repo") {
        example = rest === "" ? `pass ${dir} as path (and no glob)` : `pass path "${dir}" and glob "${rest}"`;
      }
    } catch {
      /* not a readable root: keep the generic example */
    }
    return (
      `glob ${JSON.stringify(g)} looks like a virtual path, but glob is matched relative to the searched directory ` +
      `(like rg --glob), so it would match nothing. Instead, ${example}.`
    );
  }
  return undefined;
}

/* --------------------------- exclude_globs probe -------------------------- */

interface SkippedExample {
  vpath: string;
  glob: string;
}

/** One rg --glob pattern in plain glob form (gitignore rules: no "/" = any depth, leading "/" anchors). */
function rgGlobPattern(glob: string): string {
  let g = glob.trim();
  const anchored = g.startsWith("/");
  g = g.replace(/^\/+/, "");
  if (g.endsWith("/")) g = `${g.replace(/\/+$/, "")}/**`;
  return !anchored && !g.includes("/") ? `**/${g}` : g;
}

/**
 * rg-style filter for user globs ("!x" excludes), on a path relative to the search directory.
 * Unlike compileGlobs, a file must match a whitelist glob itself (a matching parent directory
 * is not enough), as with rg's --glob; an ignore glob also drops everything below a matching
 * directory (rg prunes it). Agent globs never reach a backtracking RegExp (picomatch): a pattern
 * like "*a*a*a*a*a*a*a*a*b" would block the event loop for minutes on a long file name. Null
 * when a glob is too complex to check (too many {…} alternatives): the probe is then skipped.
 */
function userGlobMatcher(globs: string[]): ((printed: string) => boolean) | null {
  const compile = (list: string[]): ((x: string) => boolean) | null => {
    const pats = list.map(rgGlobPattern).filter((g) => g !== "" && g !== "**/");
    const fns: ((x: string) => boolean)[] = [];
    for (const g of pats) {
      const f = compileSafeGlob(g);
      if (f === null) return null;
      fns.push(f);
    }
    return (x) => fns.some((f) => f(x));
  };
  const pos = globs.filter((g) => !g.startsWith("!"));
  const p = compile(pos);
  const n = compile(globs.filter((g) => g.startsWith("!")).map((g) => g.slice(1)));
  if (p === null || n === null) return null;
  const ignored = (x: string): boolean => {
    if (n(x)) return true;
    for (let i = x.indexOf("/"); i > 0; i = x.indexOf("/", i + 1)) if (n(x.slice(0, i))) return true;
    return false;
  };
  return (x) => (pos.length === 0 || p(x)) && !ignored(x);
}

/**
 * Looks for one hit that the active exclude globs pruned from the main search (rg never reports
 * pruned paths), so the agent learns that skipped paths matched. Runs rg once more over the same
 * targets but reads only excluded files, in path order, and reports the first hit of the earliest
 * target (deterministic); later targets are stopped as soon as an earlier one has a hit. Gets at
 * most EXCLUDE_PROBE_MS. Best effort: errors and timeouts just mean no note.
 */
async function probeExcluded(
  sc: SearchContext,
  targets: Target[],
  activeExcludes: string[],
  selectArgs: string[],
  deadline: number,
): Promise<SkippedExample | undefined> {
  const whitelist = activeExcludes.filter(isCwdIndependentGlob);
  const dirs = targets.filter((t) => !t.file);
  if (whitelist.length === 0 || dirs.length === 0) return undefined;
  const matchers = dirs.map((t) => userGlobMatcher(t.globs));
  if (matchers.some((m) => m === null)) return undefined;
  const excluded = compileGlobs(activeExcludes);
  const stopAt = Math.min(deadline, Date.now() + EXCLUDE_PROBE_MS);
  const hits: (SkippedExample | undefined)[] = dirs.map(() => undefined);
  const stops = dirs.map(() => new AbortController());
  const settled = (i: number): boolean => hits.slice(0, i).some((h) => h !== undefined);
  await mapLimit(dirs, RG_CONCURRENCY, async (t, i) => {
    if (settled(i)) return;
    const userMatch = matchers[i]!;
    const args = [
      ...baseRgArgs(sc.search.max_filesize),
      "--sort=path",
      ...whitelist.map((g) => `--glob=${g.trim()}`),
      ...denyPruneArgs(sc),
      ...selectArgs,
      "--null",
      "--",
      t.arg,
    ];
    await runRg({
      rgPath: sc.rgPath,
      cwd: t.cwd,
      args,
      deadline: stopAt,
      separator: "\0",
      signal: stops[i]!.signal,
      onRecord: (rec) => {
        if (Date.now() > stopAt) return false; // matching runs in JS: honour the deadline here too
        if (rec === "") return true;
        const rel = repoRelOf(t, rec);
        if (rel === "" || sc.vfs.isHidden(rel, t.root) || !excluded(rel) || !userMatch(stripDotSlash(rec))) return true;
        hits[i] = { vpath: sc.vfs.toVirtual(t.root, rel), glob: sc.excludes.which(rel, activeExcludes) ?? whitelist[0]! };
        for (let j = i + 1; j < stops.length; j++) stops[j]!.abort();
        return false;
      },
    }).catch(() => undefined);
  });
  return hits.find((h) => h !== undefined);
}

function skippedNote(ex: SkippedExample | undefined, what: "Grep" | "Glob"): string {
  if (!ex) return "";
  const where = oneLine(ex.vpath, 240);
  return what === "Grep"
    ? `\n\n[Matches in paths skipped by exclude_globs are not shown, e.g. ${where} (${ex.glob}). To include them, pass that file or its directory as path, or a glob that names it.]`
    : `\n\n[Files in paths skipped by exclude_globs are not listed, e.g. ${where} (${ex.glob}). To include them, pass its directory as path or name it in the pattern.]`;
}

/* -------------------------------- ListRepos ------------------------------- */

/**
 * `ListRepos({offset?, limit?})`: one row per root, /pr first. offset (1-based row) and limit page
 * through long lists like PrDiff's file list, so a mirror with hundreds of readable repositories
 * stays listable within max_output_chars.
 */
export function listRepos(sc: SearchContext, a: { offset?: number; limit?: number } = {}): ToolResult {
  const pr = sc.ctx;
  const n = pr.files.length;
  const rows: [string, string][] = [
    [
      "/pr",
      `${pr.repo}  PR #${pr.number}  head ${short(pr.head_sha)} base ${short(pr.base_sha)}  ${n} ${plural(n, "file", "files")} changed`,
    ],
  ];
  const now = sc.now();
  for (const root of sc.vfs.roots) {
    if (root.kind !== "mirror" || !root.mirror) continue;
    const m = root.mirror;
    let desc = oneLine(m.description, 120);
    if (root.repo.toLowerCase() === pr.repo.toLowerCase()) {
      const what = m.branch !== "" && m.branch === pr.base_ref ? "base branch of this PR" : `${m.branch || "default"} branch of this PR's repository`;
      const note = `(${what}; searched only when passed as path)`;
      desc = desc === "" ? note : `${desc} ${note}`;
    }
    rows.push([root.vpath, `${short(m.sha)}  synced ${age(m.synced_at, now)}  ${desc}`.trimEnd()]);
  }
  const width = Math.max(20, ...rows.map(([p]) => p.length + 2));
  const lines = rows.map(([p, rest]) => `${p.padEnd(width)}${rest}`);
  if (rows.length === 1) {
    lines.push("(no mirrored repositories are readable for this PR)");
    return { text: lines.join("\n") };
  }
  const { start, shown, more } = windowLines(lines, a.offset, a.limit, lines.length);
  if (shown.length === 0) return { text: `There are ${lines.length} roots; offset ${start} is past the end.` };
  const k = fitAtLeastOne(shown, sc.search.max_output_chars - NOTE_RESERVE);
  let text = shown.slice(0, k).join("\n");
  const last = start + k - 1;
  if (k < shown.length || more) text += `\n[Showing roots ${start}-${last} of ${lines.length}. Use offset: ${last + 1} to see more.]`;
  return { text, truncated: k < shown.length || more };
}

/* --------------------------------- PrDiff --------------------------------- */

function statusLetter(f: PrFile, fd: FileDiff | undefined): string {
  switch (f.status) {
    case "added":
    case "copied":
      return "A";
    case "removed":
      return "D";
    case "renamed":
      return "R";
    case "binary": {
      const raw = fd?.raw ?? "";
      const adds = /^new file mode|^Binary files \/dev\/null and /m.test(raw);
      const deletes = /^deleted file mode|^Binary files .* and \/dev\/null differ/m.test(raw);
      // Both: a type change (e.g. symlink -> binary file) merged into one entry (mergeSamePathDiffs).
      if (adds && deletes) return "M";
      if (adds) return "A";
      if (deletes) return "D";
      if (f.previous_path || fd?.oldPath) return "R";
      return "M";
    }
    default:
      return "M";
  }
}

function isBinaryChange(f: PrFile, fd: FileDiff | undefined): boolean {
  return f.status === "binary" || fd?.status === "binary";
}

function changeLine(sc: SearchContext, f: PrFile): string {
  const fd = sc.diffs.get(f.path);
  const letter = statusLetter(f, fd);
  const prev = f.previous_path ?? fd?.oldPath;
  const where = letter === "R" && prev && prev !== f.path ? `/pr/${prev} -> /pr/${f.path}` : `/pr/${f.path}`;
  let line = `${letter}  +${f.additions} -${f.deletions}  ${where}`;
  if (isBinaryChange(f, fd)) line += "  (binary)";
  if (isHiddenChange(sc, f)) line += "  [content hidden by policy]";
  return line;
}

function isHiddenChange(sc: SearchContext, f: PrFile): boolean {
  const pr = sc.vfs.prRoot;
  return sc.vfs.isHidden(f.path, pr) || (f.previous_path !== undefined && sc.vfs.isHidden(f.previous_path, pr));
}

/** Read-like window over `lines`: offset is 1-based. */
function windowLines(lines: string[], offset: number | undefined, limit: number | undefined, maxLimit: number) {
  const start = Math.max(1, offset ?? 1);
  const lim = limit === undefined || limit <= 0 ? maxLimit : Math.min(limit, maxLimit);
  const shown = lines.slice(start - 1, start - 1 + lim);
  return { start, shown, more: start - 1 + lim < lines.length };
}

/**
 * New-side (1-based) line numbers of PEM private-key blocks in the PR's version of `rel`, from a
 * whole-file scan (the same rules Read uses), or null when the file cannot be scanned (missing,
 * hidden, outside the repo, too large).
 */
async function prFilePemLines(sc: SearchContext, rel: string): Promise<Set<number> | null> {
  try {
    const r = sc.vfs.resolve(`/pr/${rel}`);
    if (r.kind !== "file" || r.size > pemScanMax(sc)) return null;
    const buf = await readFile(r.host);
    if (buf.subarray(0, 8000).includes(0)) return null;
    return new Set(filePemLineMap(buf).keys());
  } catch {
    return null;
  }
}

const HUNK_HEADER_RE = /^(@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@)(.*)$/;

interface DiffBodyLine {
  /** Index in the section's lines. */
  idx: number;
  kind: " " | "+" | "-";
  /** The line's first character as written ("" for an empty context line). */
  prefix: string;
  payload: string;
  /** New-side line number (context and added lines). */
  newNo: number;
}

/**
 * Secret redaction for one file's diff section, one output line per input line. PEM key lines are
 * hidden per side, never across hunks: the new side ("+" and context lines) by the whole-file
 * line numbers of the PR's version (`newPem`); within each hunk, blocks whose BEGIN marker is
 * shown are found on both sides; removed lines that look like key material are hidden when the
 * hunk touches a key (the base version is not available to scan). With `newPem` null (the new
 * version could not be scanned), every hunk line that looks like key material is hidden. A hunk
 * header's function context is hidden when it looks like key material in a file that holds a key.
 * Everything else is redacted line by line.
 */
export function redactDiffLines(lines: string[], newPem: Set<number> | null): string[] {
  const out = lines.slice();
  const hunks: { header: number; func: string; body: DiffBodyLine[] }[] = [];
  let cur: (typeof hunks)[number] | null = null;
  let oldLeft = 0;
  let newLeft = 0;
  let newNo = 0;
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]!;
    const h = HUNK_HEADER_RE.exec(line);
    if (h) {
      cur = { header: i, func: h[6] ?? "", body: [] };
      hunks.push(cur);
      oldLeft = h[3] === undefined ? 1 : Number(h[3]);
      newLeft = h[5] === undefined ? 1 : Number(h[5]);
      newNo = Number(h[4]);
      continue;
    }
    const c = line[0];
    if (cur && (oldLeft > 0 || newLeft > 0) && (c === " " || c === "+" || c === "-" || line === "")) {
      const kind = c === "+" ? "+" : c === "-" ? "-" : " ";
      cur.body.push({ idx: i, kind, prefix: line.slice(0, 1), payload: line.slice(1), newNo: kind === "-" ? 0 : newNo });
      if (kind !== "+") oldLeft--;
      if (kind !== "-") {
        newLeft--;
        newNo++;
      }
      continue;
    }
    if (c !== "\\") cur = null; // "\ No newline at end of file" stays inside the hunk
    out[i] = redactLine(line, true);
  }

  const fileHasKey = (newPem !== null && newPem.size > 0) || lines.some((l) => l.includes("PRIVATE KEY"));
  for (const hunk of hunks) {
    const newSide = hunk.body.filter((b) => b.kind !== "-");
    const oldSide = hunk.body.filter((b) => b.kind !== "+");
    const localNew = pemLineMap(newSide.map((b) => b.payload).join("\n"));
    const localOld = pemLineMap(oldSide.map((b) => b.payload).join("\n"));
    const hidden = new Set<DiffBodyLine>();
    newSide.forEach((b, k) => {
      if (localNew.has(k + 1) || (newPem !== null && newPem.has(b.newNo))) hidden.add(b);
    });
    oldSide.forEach((b, k) => {
      if (localOld.has(k + 1)) hidden.add(b);
    });
    const touchesKey = hidden.size > 0;
    for (const b of hunk.body) {
      if (hidden.has(b)) continue;
      if (looksLikeKeyMaterial(b.payload) && (newPem === null || (b.kind === "-" && touchesKey))) hidden.add(b);
    }
    for (const b of hunk.body) {
      out[b.idx] = b.prefix + (hidden.has(b) ? pemReplacement(b.payload) : redactLine(b.payload, true));
    }
    const head = HUNK_HEADER_RE.exec(lines[hunk.header]!)![1]!;
    const func = hunk.func;
    const hideFunc = func.includes("PRIVATE KEY") || ((fileHasKey || hidden.size > 0) && looksLikeKeyMaterial(func));
    out[hunk.header] = hideFunc ? `${head} ${PEM_TAG}` : head + redactLine(func, true);
  }
  return out;
}

export async function prDiff(sc: SearchContext, a: { file_path?: string; offset?: number; limit?: number }): Promise<ToolResult> {
  const maxLines = sc.search.max_read_lines;
  const budget = sc.search.max_output_chars - NOTE_RESERVE;
  const filePath = optionalPath(a.file_path);

  if (filePath === undefined) {
    const files = sc.ctx.files;
    if (files.length === 0) return { text: "No files changed in this PR." };
    const all = files.map((f) => changeLine(sc, f));
    const { start, shown, more } = windowLines(all, a.offset, a.limit, maxLines);
    if (shown.length === 0) return { text: `The PR changes ${all.length} ${plural(all.length, "file", "files")}; offset ${start} is past the end.` };
    const k = fitAtLeastOne(shown, budget);
    let text = shown.slice(0, k).join("\n");
    const last = start + k - 1;
    if (k < shown.length || more) {
      text += `\n[Showing files ${start}-${last} of ${all.length}. Use offset: ${last + 1} to see more.]`;
    }
    return { text, truncated: k < shown.length || more };
  }

  const parsed = sc.vfs.parse(filePath);
  if (parsed.kind !== "repo" || parsed.root.kind !== "pr" || parsed.rel === "") {
    throw new ToolError(
      `PrDiff file_path must be a changed file under /pr, as listed by PrDiff without arguments (got ${parsed.vpath}). ` +
        "To compare with another repository, Read both files.",
    );
  }
  const rel = parsed.rel;
  const f = sc.ctx.files.find((x) => x.path === rel) ?? sc.ctx.files.find((x) => x.previous_path === rel);
  if (!f) {
    const base = rel.split("/").pop()!;
    const same = sc.ctx.files.filter((x) => x.path.split("/").pop() === base);
    const hint = same.length === 1 ? ` Did you mean /pr/${same[0]!.path}?` : "";
    throw new ToolError(`/pr/${rel} is not changed in this PR.${hint} Call PrDiff without file_path to list the changed files.`);
  }
  const header = changeLine(sc, f);
  if (isHiddenChange(sc, f)) return { text: `${header}\n[content hidden by policy]` };
  const fd = sc.diffs.get(f.path);
  if (!fd || fd.raw === "") return { text: `${header}\n(no textual diff available)` };

  let raw = fd.raw;
  if (fd.status === "binary") {
    const lines = raw.split("\n");
    const cut = lines.findIndex((l) => l.startsWith("GIT binary patch") || l.startsWith("Binary files "));
    raw = `${(cut >= 0 ? lines.slice(0, cut) : lines).join("\n")}\n[binary file]`;
  }
  let rawLines = raw.replace(/\n$/, "").split("\n");
  // Redact line by line (one output line per diff line, so hunk headers keep counting right).
  if (sc.search.redact_secrets) {
    const newPem = fd.status === "binary" || f.status === "removed" ? new Set<number>() : await prFilePemLines(sc, f.path);
    rawLines = redactDiffLines(rawLines, newPem);
  }
  const lines = rawLines.map((l) => truncateLine(stripCr(l), sc.search.max_line_chars));
  const { start, shown, more } = windowLines(lines, a.offset, a.limit, maxLines);
  if (shown.length === 0) {
    return { text: `The diff of /pr/${f.path} has ${lines.length} lines; offset ${start} is past the end.` };
  }
  const k = fitAtLeastOne(shown, budget);
  let text = shown.slice(0, k).join("\n");
  const last = start + k - 1;
  if (k < shown.length || more) {
    text += `\n[Showing diff lines ${start}-${last} of ${lines.length}. Use offset: ${last + 1} to see more.]`;
  }
  return { text, truncated: k < shown.length || more };
}

/* ---------------------------------- Grep ---------------------------------- */

export interface GrepArgs {
  pattern: string;
  path?: string;
  glob?: string;
  type?: string;
  output_mode?: "content" | "files_with_matches" | "count";
  "-i"?: boolean;
  "-n"?: boolean;
  "-o"?: boolean;
  "-A"?: number;
  "-B"?: number;
  "-C"?: number;
  context?: number;
  multiline?: boolean;
  head_limit?: number;
  offset?: number;
}

interface GrepLine {
  n: number;
  text: string;
  match: boolean;
  /** -o: the whole line the match part was taken from (redaction looks at the whole line). */
  full?: string;
}

interface Block {
  root: Root;
  repoRel: string;
  vpath: string;
  lines: GrepLine[];
  binary: boolean;
}

type Entry = { kind: "sep" } | { kind: "line"; block: Block; i: number } | { kind: "binary"; block: Block };

interface TargetResult {
  outcome: RgOutcome;
  files: string[];
  counts: [string, number][];
  blocks: Block[];
}

function paginationNote(truncated: boolean, limit: number, offset: number): string {
  if (truncated) return `\n\n[Showing results with pagination = limit: ${limit}, offset: ${offset}]`;
  if (offset > 0) return `\n\n[Showing results with pagination = offset: ${offset}]`;
  return "";
}

/** Count "\n" bytes in buf[from, end). */
function countNewlines(buf: Buffer, from: number, end: number): number {
  let n = 0;
  for (let i = buf.indexOf(10, from); i !== -1 && i < end; i = buf.indexOf(10, i + 1)) n++;
  return n;
}

export async function grep(sc: SearchContext, a: GrepArgs): Promise<ToolResult> {
  const pattern = a.pattern;
  if (typeof pattern !== "string" || pattern === "") throw new ToolError("pattern must be a non-empty regular expression.");
  if (pattern.length > MAX_PATTERN_CHARS) {
    throw new ToolError(`pattern is too long (${pattern.length} characters, max ${MAX_PATTERN_CHARS}).`);
  }
  const mode = a.output_mode ?? "files_with_matches";
  const headLimit = a.head_limit ?? DEFAULT_HEAD_LIMIT;
  const limit = headLimit === 0 ? Infinity : Math.min(headLimit, MAX_HEAD_LIMIT);
  const offset = a.offset ?? 0;
  if (offset > MAX_COLLECT) {
    throw new ToolError(`offset is too large (max ${MAX_COLLECT}). Narrow the search with path, glob or type instead of paging this far.`);
  }
  const showNumbers = a["-n"] ?? true;
  const onlyMatching = mode === "content" && a["-o"] === true;
  const userGlobs = splitGlobParam(a.glob?.trim());
  if (userGlobs.length > MAX_USER_GLOBS) throw new ToolError(`glob has too many patterns (max ${MAX_USER_GLOBS}).`);
  for (const g of userGlobs) checkGlob(g, "glob");
  const type = a.type?.trim();
  if (type !== undefined && type !== "" && !/^[A-Za-z0-9][A-Za-z0-9_+.-]{0,39}$/.test(type)) {
    throw new ToolError(`type must be a ripgrep file type name such as js, ts, py, go, rust or java (got ${JSON.stringify(type)}).`);
  }

  const { targets, skippedBase } = grepTargets(sc, optionalPath(a.path), userGlobs);
  const vglob = virtualPathGlobError(sc, userGlobs, targets);
  if (vglob !== undefined) throw new ToolError(vglob);
  const activeExcludes = sc.excludes.active(
    targets.map((t) => t.targetRel),
    userGlobs,
  );
  const excluded = compileGlobs(activeExcludes);
  /** First result dropped only by a post-filtered exclude glob (anchored globs rg cannot prune). */
  let skipped: SkippedExample | undefined;
  const keep = (root: Root, repoRel: string): boolean => {
    if (repoRel === "" || sc.vfs.isHidden(repoRel, root)) return false;
    if (!excluded(repoRel)) return true;
    skipped ??= { vpath: sc.vfs.toVirtual(root, repoRel), glob: sc.excludes.which(repoRel, activeExcludes) ?? activeExcludes[0]! };
    return false;
  };

  // Context: context / -C win over -A / -B (Claude Code semantics), each capped.
  const clampCtx = (v: number | undefined): number | undefined => (v === undefined ? undefined : Math.min(Math.max(0, v), MAX_CONTEXT));
  const both = clampCtx(a.context ?? a["-C"]);
  const before = mode === "content" ? (both ?? clampCtx(a["-B"]) ?? 0) : 0;
  const after = mode === "content" ? (both ?? clampCtx(a["-A"]) ?? 0) : 0;
  const withContext = before > 0 || after > 0;

  const common = [...baseRgArgs(sc.search.max_filesize), "--sort=path"];
  const prune = pruneArgs(sc, activeExcludes);
  const select: string[] = []; // what counts as a hit (shared with the exclude probe)
  if (type) select.push(`--type=${type}`);
  if (a["-i"]) select.push("--ignore-case");
  if (a.multiline) select.push("--multiline", "--multiline-dotall");
  select.push(`--regexp=${pattern}`);
  const opt: string[] = [];
  if (mode === "files_with_matches") opt.push("--files-with-matches", "--null");
  else if (mode === "count") opt.push("--count", "--with-filename", "--null");
  else {
    opt.push("--json");
    if (before > 0) opt.push(`--before-context=${before}`);
    if (after > 0) opt.push(`--after-context=${after}`);
  }

  const need = offset + Math.min(limit, MAX_COLLECT) + 1;
  const charStop = sc.search.max_output_chars + NOTE_RESERVE;
  const deadline = Date.now() + sc.search.timeout_ms;

  const runTarget = async (t: Target): Promise<TargetResult> => {
    const res: TargetResult = { outcome: { code: 0, stderr: "", timedOut: false, stopped: false }, files: [], counts: [], blocks: [] };
    let entries = 0;
    let charsPastOffset = 0;
    const add = (n: number, chars: number): boolean => {
      for (let i = 0; i < n; i++) {
        if (entries >= offset) charsPastOffset += chars / n;
        entries++;
      }
      // Collect up to twice the output budget so the final cut happens in fitLines (exact note).
      return entries < need && charsPastOffset <= 2 * charStop;
    };
    const args = [...common, ...t.globs.map((g) => `--glob=${g}`), ...prune, ...opt, ...select, "--", t.arg];
    /** Record handling is JS work the rg kill timer cannot interrupt: it checks the deadline itself. */
    let lateStop = false;
    const late = (): boolean => {
      if (Date.now() <= deadline) return false;
      lateStop = true;
      return true;
    };

    let onRecord: (rec: string) => boolean;
    if (mode === "files_with_matches") {
      onRecord = (rec) => {
        if (rec === "") return true;
        const rel = repoRelOf(t, rec);
        if (!keep(t.root, rel)) return true;
        const vp = sc.vfs.toVirtual(t.root, rel);
        res.files.push(vp);
        return add(1, vp.length + 1);
      };
    } else if (mode === "count") {
      let pendingRec = "";
      onRecord = (rec) => {
        const full = pendingRec === "" ? rec : `${pendingRec}\n${rec}`;
        const z = full.indexOf("\0");
        if (z < 0) {
          pendingRec = full; // a path containing a newline: wait for the rest
          return true;
        }
        pendingRec = "";
        const rel = repoRelOf(t, full.slice(0, z));
        const count = Number.parseInt(full.slice(z + 1), 10);
        if (!Number.isFinite(count) || !keep(t.root, rel)) return true;
        const vp = sc.vfs.toVirtual(t.root, rel);
        res.counts.push([vp, count]);
        return add(1, vp.length + 8);
      };
    } else {
      let cur: Block | null = null;
      let lastLine = -1;
      const startBlock = (printed: string): void => {
        const rel = repoRelOf(t, printed);
        cur = keep(t.root, rel) ? { root: t.root, repoRel: rel, vpath: sc.vfs.toVirtual(t.root, rel), lines: [], binary: false } : null;
        lastLine = -1;
      };
      const pushLine = (b: Block, line: GrepLine): boolean => {
        if (line.text.includes("\0") || (line.full ?? "").includes("\0")) b.binary = true;
        let seps = 0;
        if (b.lines.length === 0) {
          res.blocks.push(b);
          if (withContext && res.blocks.length > 1) seps++;
        } else if (withContext && line.n > lastLine + 1) seps++;
        b.lines.push(line);
        lastLine = Math.max(lastLine, line.n);
        return add(1 + seps, b.vpath.length + line.text.length + 10);
      };
      onRecord = (rec) => {
        if (late()) return false;
        let msg: { type?: string; data?: Record<string, unknown> };
        try {
          msg = JSON.parse(rec) as typeof msg;
        } catch {
          return true;
        }
        const data = msg.data ?? {};
        if (msg.type === "begin") {
          startBlock(decodeRgText(data.path));
          return true;
        }
        if (msg.type === "end") {
          const b = cur as Block | null;
          if (b && data.binary_offset !== null && data.binary_offset !== undefined) b.binary = true;
          cur = null;
          return true;
        }
        if (msg.type !== "match" && msg.type !== "context") return true;
        const b = cur as Block | null;
        if (!b) return true;
        let text = decodeRgText(data.lines);
        if (text.endsWith("\n")) text = text.slice(0, -1);
        const first = typeof data.line_number === "number" ? data.line_number : 0;
        const isMatch = msg.type === "match";
        const fullLines = text.split("\n");
        if (onlyMatching && isMatch) {
          // -o: one output line per non-empty match part, numbered by the line it starts on.
          const raw = rgBytes(data.lines);
          const subs = Array.isArray(data.submatches) ? (data.submatches as { match?: unknown; start?: unknown }[]) : [];
          // Submatches come in order: count newlines incrementally (a multiline record can hold a
          // whole file and hundreds of thousands of submatches).
          let nlPos = 0;
          let nlCount = 0;
          for (let si = 0; si < subs.length; si++) {
            const sm = subs[si]!;
            if ((si & 1023) === 1023 && late()) return false;
            let part = decodeRgText(sm.match);
            if (part.endsWith("\n")) part = part.slice(0, -1);
            if (part === "") continue;
            const st = typeof sm.start === "number" ? Math.max(0, sm.start) : 0;
            if (st < nlPos) {
              nlPos = 0;
              nlCount = 0;
            }
            nlCount += countNewlines(raw, nlPos, st);
            nlPos = st;
            const li = nlCount;
            const pieces = part.split("\n");
            for (let j = 0; j < pieces.length; j++) {
              if (pieces[j] === "") continue;
              const full = fullLines[li + j] ?? pieces[j]!;
              if (!pushLine(b, { n: first + li + j, text: pieces[j]!, match: true, full })) return false;
            }
          }
          return true;
        }
        for (let i = 0; i < fullLines.length; i++) {
          if (!pushLine(b, { n: first + i, text: fullLines[i]!, match: isMatch })) return false;
        }
        return true;
      };
    }
    res.outcome = await runRg({ rgPath: sc.rgPath, cwd: t.cwd, args, deadline, separator: mode === "files_with_matches" ? "\0" : "\n", onRecord });
    if (lateStop) res.outcome = { ...res.outcome, timedOut: true, stopped: false };
    return res;
  };

  const results = await mapLimit(targets, RG_CONCURRENCY, runTarget);
  const goneNote = vanishedRootsNote(targets, results.map((r) => r.outcome));
  const timedOut = results.some((r) => r.outcome.timedOut);
  const failure = results.find((r) => r.outcome.code === 2 && r.outcome.stderr.trim() !== "");
  /** Some rg stopped early, so more results exist than were collected. */
  const stoppedEarly = results.some((r) => r.outcome.stopped);

  const total =
    mode === "files_with_matches"
      ? results.reduce((s, r) => s + r.files.length, 0)
      : mode === "count"
        ? results.reduce((s, r) => s + r.counts.length, 0)
        : results.reduce((s, r) => s + r.blocks.length, 0);
  if (total === 0) {
    if (failure) {
      let msg = rgErrorText(failure.outcome.stderr);
      if (/regex parse error|error parsing regex/i.test(msg)) {
        msg += "\nPatterns use ripgrep (Rust regex) syntax: escape literal ( ) [ ] { } with a backslash, e.g. interface\\{\\}.";
      } else if (/unrecognized file type/i.test(msg)) {
        msg += "\nUse a standard ripgrep type such as js, ts, py, go, rust, java, or filter with glob instead.";
      }
      throw new ToolError(msg);
    }
    if (timedOut) {
      throw new ToolError(`Search timed out after ${sc.search.timeout_ms}ms. Narrow it with path, glob or type.`);
    }
  }
  const timeoutNote = timedOut ? `\n[Search timed out after ${sc.search.timeout_ms}ms; results may be incomplete. Narrow it with path, glob or type.]` : "";
  if (!skipped && !timedOut && !failure) {
    skipped = await probeExcluded(sc, targets, activeExcludes, ["--files-with-matches", ...select], deadline);
  }
  const notes = skippedNote(skipped, "Grep") + timeoutNote + goneNote;
  const multiRoot = targets.length > 1;
  const budget = sc.search.max_output_chars - NOTE_RESERVE - notes.length - (multiRoot ? ROOTS_NOTE_MAX : 0);
  /** Per-root counts for unshownRootsNote, from per-root entry counts. */
  const rootCounts = (sizes: number[]): RootCount[] => {
    let first = 0;
    return results.map((r, i) => {
      const c = { root: targets[i]!.root, first, files: sizes[i]!, more: r.outcome.stopped };
      first += sizes[i]!;
      return c;
    });
  };

  if (mode === "files_with_matches") {
    const all = results.flatMap((r) => r.files);
    const win = all.slice(offset, offset + limit);
    if (win.length === 0) return { text: `No files found${paginationNote(false, limit, offset)}${total === 0 ? skippedBaseNote(skippedBase) : ""}${notes}` };
    const cutByLimit = all.length > offset + limit;
    const k = fitAtLeastOne(win, budget);
    const shown = win.slice(0, k);
    let text = `Found ${shown.length} ${plural(shown.length, "file", "files")}\n${shown.join("\n")}`;
    if (k < win.length || (stoppedEarly && !cutByLimit)) text += charNote(sc, offset + k);
    else text += paginationNote(cutByLimit, limit, offset);
    if (multiRoot) text += unshownRootsNote(rootCounts(results.map((r) => r.files.length)), offset + k);
    return { text: text + notes, truncated: cutByLimit || k < win.length };
  }

  if (mode === "count") {
    const all = results.flatMap((r) => r.counts);
    const win = all.slice(offset, offset + limit);
    const cutByLimit = all.length > offset + limit;
    const lines = win.map(([p, c]) => `${p}:${c}`);
    const k = fitAtLeastOne(lines, budget);
    const shownCounts = win.slice(0, k);
    const matches = shownCounts.reduce((s, [, c]) => s + c, 0);
    const files = shownCounts.length;
    let text = lines.slice(0, k).join("\n") || "No matches found";
    text += `\n\nFound ${matches} total ${plural(matches, "occurrence", "occurrences")} across ${files} ${plural(files, "file", "files")}.`;
    if (k < lines.length || (stoppedEarly && !cutByLimit)) text += charNote(sc, offset + k);
    else text += paginationNote(cutByLimit, limit, offset);
    if (multiRoot) text += unshownRootsNote(rootCounts(results.map((r) => r.counts.length)), offset + k);
    if (total === 0) text += skippedBaseNote(skippedBase);
    return { text: text + notes, truncated: cutByLimit || k < lines.length };
  }

  // content
  const entries: Entry[] = [];
  const contentCounts: RootCount[] = [];
  results.forEach((r, i) => {
    contentCounts.push({ root: targets[i]!.root, first: entries.length + (withContext && entries.length > 0 ? 1 : 0), files: r.blocks.length, more: r.outcome.stopped });
    for (const block of r.blocks) addBlock(block);
  });
  function addBlock(block: Block): void {
    if (withContext && entries.length > 0) entries.push({ kind: "sep" });
    if (block.binary) {
      entries.push({ kind: "binary", block });
      return;
    }
    let prev = -1;
    block.lines.forEach((l, i) => {
      if (withContext && prev >= 0 && l.n > prev + 1) entries.push({ kind: "sep" });
      entries.push({ kind: "line", block, i });
      prev = Math.max(prev, l.n);
    });
  }
  const win = entries.slice(offset, offset + limit);
  if (win.length === 0) return { text: `No matches found${paginationNote(false, limit, offset)}${total === 0 ? skippedBaseNote(skippedBase) : ""}${notes}` };
  const cutByLimit = entries.length > offset + limit;
  const pemCache = new Map<Block, Promise<Map<number, string>>>();
  const lineMax = Math.min(GREP_MAX_LINE_CHARS, sc.search.max_line_chars);
  const lines: string[] = [];
  let used = 0;
  for (const e of win) {
    let out: string;
    if (e.kind === "sep") out = "--";
    else if (e.kind === "binary") out = `${e.block.vpath}: binary file matches`;
    else {
      const l = e.block.lines[e.i]!;
      let text = stripCr(l.text);
      if (sc.search.redact_secrets) {
        let pem = pemCache.get(e.block);
        if (!pem) {
          pem = pemLinesOf(sc, e.block);
          pemCache.set(e.block, pem);
        }
        const replacement = (await pem).get(l.n);
        if (replacement !== undefined) text = replacement;
        else if (l.full !== undefined) {
          // -o: a part of a line that holds a secret could expose what the whole line would not.
          const full = stripCr(l.full);
          const redactedFull = redactLine(full, true);
          text = redactedFull !== full ? redactedFull : redactLine(text, true);
        } else text = redactLine(text, true);
      }
      text = truncateLine(text, lineMax);
      const s = l.match ? ":" : "-";
      out = showNumbers ? `${e.block.vpath}${s}${l.n}${s}${text}` : `${e.block.vpath}${s}${text}`;
    }
    lines.push(out);
    used += out.length + (lines.length > 1 ? 1 : 0);
    if (used > budget) break; // the rest cannot be shown: do not read more files for PEM checks
  }
  const k = fitAtLeastOne(lines, budget);
  let text = lines.slice(0, k).join("\n");
  // `lines` stops early once the budget is used up, so compare with the whole window.
  if (k < win.length || (stoppedEarly && !cutByLimit)) text += charNote(sc, offset + k);
  else text += paginationNote(cutByLimit, limit, offset);
  if (multiRoot) text += unshownRootsNote(contentCounts, offset + k);
  return { text: text + notes, truncated: cutByLimit || stoppedEarly || k < win.length };
}

function charNote(sc: SearchContext, nextOffset: number): string {
  return `\n\n[Output truncated at ${sc.search.max_output_chars} characters. Use offset: ${nextOffset} to see more, or narrow with path/glob/type.]`;
}

/**
 * Replacement text for the lines of a Grep hit's file that belong to PEM private-key blocks.
 * The whole file is scanned (a matched base64 line need not look like key material on its own,
 * e.g. b"MIIE...\n" or a short last line); a file that cannot be scanned hides its suspicious lines.
 */
async function pemLinesOf(sc: SearchContext, block: Block): Promise<Map<number, string>> {
  try {
    const host = join(block.root.host, ...block.repoRel.split("/"));
    if ((await stat(host)).size > pemScanMax(sc)) throw new Error("too large");
    const buf = await readFile(host);
    return filePemLineMap(buf);
  } catch {
    const suspicious = block.lines.filter((l) => looksLikeKeyMaterial(l.full ?? l.text));
    return new Map(suspicious.map((l) => [l.n, PEM_TAG]));
  }
}

/* ---------------------------------- Glob ---------------------------------- */

const GLOB_META = /[*?[\]{}!]/;

/**
 * Pattern segments left to match below a root, given the root's segments below the search
 * directory (absolute patterns such as "/repos/*\/*\/src/**\/*.ts"). Every remainder is a suffix
 * of `pat`, so this is a memoized walk over (pattern index, segment index) pairs: O(|pat| x |segs|)
 * segment matches, whatever the number of "**" (callers collapse runs of them first).
 */
function remainders(pat: string[], segs: string[], isMatch: (s: string, p: string) => boolean): string[][] {
  const width = segs.length + 1;
  const seen = new Uint8Array((pat.length + 1) * width);
  const suffixes = new Set<number>();
  const stack: [number, number][] = [[0, 0]];
  while (stack.length > 0) {
    const [pi, si] = stack.pop()!;
    const key = pi * width + si;
    if (seen[key]) continue;
    seen[key] = 1;
    if (si === segs.length) {
      suffixes.add(pi);
      continue;
    }
    if (pi === pat.length) continue;
    const p = pat[pi]!;
    if (p === "**") stack.push([pi + 1, si], [pi, si + 1]);
    else if (isMatch(segs[si]!, p)) stack.push([pi + 1, si + 1]);
  }
  return [...suffixes].sort((x, y) => x - y).map((k) => pat.slice(k));
}

/** "a/**\/**\/b" -> "a/**\/b": consecutive "**" segments match exactly what one does. */
function collapseGlobstars(segs: string[]): string[] {
  return segs.filter((s, i) => !(s === "**" && segs[i - 1] === "**"));
}

export async function glob(sc: SearchContext, a: { pattern: string; path?: string }): Promise<ToolResult> {
  const pattern = typeof a.pattern === "string" ? a.pattern.trim() : "";
  if (pattern === "") throw new ToolError('pattern must be a non-empty glob, e.g. "**/*.ts".');
  if (pattern.length > MAX_PATTERN_CHARS) throw new ToolError(`pattern is too long (max ${MAX_PATTERN_CHARS} characters).`);
  checkGlob(pattern, "pattern");
  const deadline = Date.now() + sc.search.timeout_ms;
  // Agent patterns never reach a backtracking RegExp (see userGlobMatcher).
  const segMatchers = new Map<string, ((s: string) => boolean) | null>();
  const segMatch = (s: string, p: string): boolean => {
    let f = segMatchers.get(p);
    if (f === undefined) {
      f = compileSafeGlob(p);
      segMatchers.set(p, f);
    }
    if (f === null) throw new ToolError(`pattern segment ${JSON.stringify(p)} has too many {…} alternatives; use a simpler pattern.`);
    return f(s);
  };

  let targets: Target[] = [];
  let skippedBase: Root | undefined;
  if (pattern.startsWith("/")) {
    // Absolute patterns match virtual paths literally, so "/repos/*/*/..." includes this PR's base.
    // Absolute virtual pattern: the literal leading directories are the search path.
    const segs = collapseGlobstars(pattern.split("/").filter((s) => s !== "" && s !== "."));
    if (segs.includes("..")) throw new ToolError('pattern must not contain ".." segments.');
    const dirPattern = `/${segs.join("/")}`;
    const dirError = `pattern ${pattern} names a directory; add a file pattern such as "${dirPattern === "/" ? "" : dirPattern}/**/*" (everything below it) or "${dirPattern === "/" ? "" : dirPattern}/*" (its direct files).`;
    let i = 0;
    while (i < segs.length && !GLOB_META.test(segs[i]!)) i++;
    if (i === segs.length) {
      // Only literal segments: a directory is an error (it would silently list nothing), a file
      // is matched by its name in its parent directory.
      let whole: ReturnType<Vfs["resolve"]> | undefined;
      try {
        whole = sc.vfs.resolve(dirPattern);
      } catch {
        whole = undefined; // missing: handled below like any other pattern
      }
      if (whole !== undefined && whole.kind !== "file") throw new ToolError(dirError);
      i = Math.max(0, segs.length - 1);
    }
    const base = `/${segs.slice(0, i).join("/")}`;
    const rest = segs.slice(i);
    if (rest.length === 0) throw new ToolError(dirError);
    let r: ReturnType<Vfs["resolve"]>;
    try {
      r = sc.vfs.resolve(base);
    } catch (e) {
      const pathArg = optionalPath(a.path);
      if (e instanceof VfsError && pathArg !== undefined) {
        throw new ToolError(
          `${e.message} An absolute pattern is a virtual path and ignores path (${pathArg}): pass ${JSON.stringify(pattern.replace(/^\/+/, ""))} ` +
            `with that path, or the absolute pattern ${JSON.stringify(`${pathArg.replace(/\/+$/, "")}${pattern}`)}.`,
        );
      }
      throw e;
    }
    if (r.kind === "vdir") {
      let rootItself = false;
      for (const root of r.roots) {
        if (Date.now() > deadline) throw new ToolError(`File search timed out after ${sc.search.timeout_ms}ms. Use a more specific path or pattern.`);
        const all = remainders(rest, sc.vfs.rootSegmentsBelow(r.vpath, root), segMatch);
        const rems = all.filter((x) => x.length > 0);
        if (rems.length < all.length) rootItself = true;
        if (rems.length > 0) targets.push(rootTarget(root, [...new Set(rems.map((x) => `/${x.join("/")}`))]));
      }
      // "/repos/*/*" matches repository roots, which are directories: say so rather than "No files found".
      if (targets.length === 0 && rootItself) throw new ToolError(dirError);
    } else if (r.kind === "dir") {
      targets.push({ root: r.root, cwd: r.host, arg: ".", baseRel: r.rel, targetRel: r.rel, file: false, globs: [`/${rest.join("/")}`] });
    } else {
      throw new ToolError(`${r.vpath} is a file, not a directory.`);
    }
  } else {
    const pathArg = optionalPath(a.path);
    const r = pathArg === undefined ? null : sc.vfs.resolve(pathArg);
    if (r === null || r.kind === "vdir") {
      ({ targets, skippedBase } = implicitTargets(sc, r === null ? sc.vfs.roots : r.roots, [pattern]));
    } else if (r.kind === "dir") {
      targets = [{ root: r.root, cwd: r.host, arg: ".", baseRel: r.rel, targetRel: r.rel, file: false, globs: [pattern] }];
    } else {
      throw new ToolError(`Path is not a directory: ${r.vpath}. Use Read to read a file, or pass its directory as path.`);
    }
  }

  const activeExcludes = sc.excludes.active(
    targets.map((t) => t.targetRel),
    [pattern],
  );
  const excluded = compileGlobs(activeExcludes);
  let skipped: SkippedExample | undefined;
  const prune = pruneArgs(sc, activeExcludes);
  const common = [...baseRgArgs(sc.search.max_filesize), "--sort=path", "--files", "--null"];
  const results = await mapLimit(targets, RG_CONCURRENCY, async (t) => {
    const files: string[] = [];
    const outcome = await runRg({
      rgPath: sc.rgPath,
      cwd: t.cwd,
      args: [...common, ...t.globs.map((g) => `--glob=${g}`), ...prune, "--", t.arg],
      deadline,
      separator: "\0",
      onRecord: (rec) => {
        if (rec === "") return true;
        const rel = repoRelOf(t, rec);
        if (rel === "" || sc.vfs.isHidden(rel, t.root)) return true;
        if (excluded(rel)) {
          skipped ??= { vpath: sc.vfs.toVirtual(t.root, rel), glob: sc.excludes.which(rel, activeExcludes) ?? activeExcludes[0]! };
          return true;
        }
        files.push(sc.vfs.toVirtual(t.root, rel));
        return files.length <= GLOB_RESULT_LIMIT;
      },
    });
    return { files, outcome };
  });
  const all = results.flatMap((r) => r.files);
  const goneNote = vanishedRootsNote(targets, results.map((r) => r.outcome));
  const timedOut = results.some((r) => r.outcome.timedOut);
  if (all.length === 0 && timedOut) {
    throw new ToolError(`File search timed out after ${sc.search.timeout_ms}ms. Use a more specific path or pattern.`);
  }
  if (!skipped && !timedOut) skipped = await probeExcluded(sc, targets, activeExcludes, ["--files"], deadline);
  const note = skippedNote(skipped, "Glob") + goneNote;
  if (all.length === 0) return { text: `No files found${skippedBaseNote(skippedBase)}${note}` };
  const shown = all.slice(0, GLOB_RESULT_LIMIT);
  const truncated = all.length > GLOB_RESULT_LIMIT || timedOut;
  let text = shown.join("\n");
  if (truncated) text += "\n(Results are truncated. Consider using a more specific path or pattern.)";
  if (targets.length > 1 && all.length > GLOB_RESULT_LIMIT) {
    let first = 0;
    const counts = results.map((r, i) => {
      const c = { root: targets[i]!.root, first, files: Math.min(r.files.length, GLOB_RESULT_LIMIT), more: r.outcome.stopped || r.files.length > GLOB_RESULT_LIMIT };
      first += r.files.length;
      return c;
    });
    text += unshownRootsNote(counts, GLOB_RESULT_LIMIT);
  }
  return { text: text + note, truncated };
}

/* ---------------------------------- Read ---------------------------------- */

interface ReadWindow {
  binary: boolean;
  lines: { n: number; text: string }[];
  /** Total line count when the whole file was scanned. */
  total?: number;
  more: boolean;
}

const READ_CHUNK = 64 * 1024;

/**
 * Read a file from the start (PEM blocks need every line) and keep the requested window. Files up
 * to `scanMax` bytes are loaded whole when redacting, so PEM blocks get redactPem's exact rules
 * (lookahead for the END marker); larger ones are streamed with the conservative PemTracker.
 */
async function readWindow(
  host: string,
  size: number,
  start: number,
  limit: number,
  opts: { countAll: boolean; redact: boolean; maxLineChars: number; deadline: number; scanMax: number },
): Promise<ReadWindow> {
  const out: ReadWindow = { binary: false, lines: [], more: false };
  let whole: Buffer | null = null;
  let pemMap: Map<number, string> | null = null;
  if (opts.redact && size <= opts.scanMax) {
    whole = await readFile(host);
    if (whole.subarray(0, 8000).includes(0)) {
      out.binary = true;
      return out;
    }
    pemMap = filePemLineMap(whole);
  }
  const tracker = opts.redact && pemMap === null ? new PemTracker() : null;
  const fh = whole === null ? await open(host, "r") : null;
  try {
    const lineCap = opts.maxLineChars * 4 + 16;
    const buf = whole === null ? Buffer.alloc(READ_CHUNK) : Buffer.alloc(0);
    let pending: Buffer[] = [];
    let pendingLen = 0;
    let lineNo = 0;
    let first = true;
    let done = false;
    let wholeRead = false;
    const end = start + limit; // exclusive

    const onLine = (bytes: Buffer): void => {
      lineNo++;
      const text = stripCr(bytes.toString("utf8"));
      const pemText = pemMap !== null ? (pemMap.get(lineNo) ?? null) : tracker !== null ? tracker.step(text) : null;
      if (lineNo >= start && lineNo < end) {
        out.lines.push({ n: lineNo, text: pemText ?? redactLine(text, opts.redact) });
      } else if (lineNo >= end) {
        out.more = true;
        if (!opts.countAll) done = true;
      }
    };
    const take = (chunk: Buffer): void => {
      if (pendingLen < lineCap) {
        const room = lineCap - pendingLen;
        const part = chunk.length > room ? chunk.subarray(0, room) : chunk;
        pending.push(Buffer.from(part));
        pendingLen += part.length;
      }
    };

    while (!done) {
      if (Date.now() > opts.deadline) throw new ToolError("Reading the file timed out. Use a smaller offset/limit window or Grep.");
      let chunk: Buffer;
      if (whole !== null) {
        if (wholeRead) break;
        wholeRead = true;
        chunk = whole;
      } else {
        const { bytesRead } = await fh!.read(buf, 0, READ_CHUNK, null);
        if (bytesRead === 0) break;
        chunk = buf.subarray(0, bytesRead);
      }
      if (first) {
        first = false;
        if (chunk.subarray(0, 8000).includes(0)) {
          out.binary = true;
          return out;
        }
      }
      let s = 0;
      for (let i = chunk.indexOf(10, s); i !== -1 && !done; i = chunk.indexOf(10, s)) {
        take(chunk.subarray(s, i));
        onLine(pending.length === 1 ? pending[0]! : Buffer.concat(pending));
        pending = [];
        pendingLen = 0;
        s = i + 1;
      }
      if (!done && s < chunk.length) take(chunk.subarray(s));
    }
    if (!done) {
      if (pendingLen > 0) onLine(Buffer.concat(pending));
      out.total = lineNo;
    }
    return out;
  } finally {
    await fh?.close();
  }
}

/** Direct entries of a directory for Read's EISDIR error: sub-directories (with "/"), then files. */
async function directoryListing(sc: SearchContext, r: RepoEntry): Promise<{ dir: string; entries: string[]; more: number; ext?: string }> {
  const dir = sc.vfs.toVirtual(r.root, r.rel);
  let ents: Dirent[] = [];
  try {
    ents = await readdir(r.host, { withFileTypes: true });
  } catch {
    /* unreadable: list nothing */
  }
  const dirs: string[] = [];
  const files: string[] = [];
  for (const d of ents) {
    if (/[\u0000-\u001f\u007f]/.test(d.name)) continue;
    const rel = r.rel === "" ? d.name : `${r.rel}/${d.name}`;
    if (sc.vfs.isHidden(rel, r.root)) continue;
    if (d.isDirectory()) dirs.push(`${sc.vfs.toVirtual(r.root, rel)}/`);
    else if (d.isFile()) files.push(sc.vfs.toVirtual(r.root, rel));
  }
  dirs.sort();
  files.sort();
  const all = [...dirs, ...files];
  let ext = exampleExtension(files.map((f) => f.slice(f.lastIndexOf("/") + 1)), true);
  if (ext === undefined) {
    // Repository roots often hold only config files: look one level down for code.
    const below: string[] = [];
    for (const d of ents.filter((x) => x.isDirectory() && !x.name.startsWith(".")).slice(0, EXT_PEEK_DIRS)) {
      const rel = r.rel === "" ? d.name : `${r.rel}/${d.name}`;
      if (sc.vfs.isHidden(rel, r.root)) continue;
      try {
        for (const e of (await readdir(join(r.host, d.name), { withFileTypes: true })).slice(0, EXT_PEEK_ENTRIES)) {
          if (e.isFile()) below.push(e.name);
        }
      } catch {
        /* unreadable: skip */
      }
    }
    ext = exampleExtension(below, true) ?? exampleExtension(files.map((f) => f.slice(f.lastIndexOf("/") + 1)), false);
  }
  return { dir, entries: all.slice(0, DIR_LIST_LIMIT), more: Math.max(0, all.length - DIR_LIST_LIMIT), ...(ext ? { ext } : {}) };
}

/** Sub-directories (and entries in each) looked at when a directory holds no code files itself. */
const EXT_PEEK_DIRS = 20;
const EXT_PEEK_ENTRIES = 200;

/** Extensions that name source code (preferred for the EISDIR Glob example). */
const CODE_EXTENSIONS = new Set(
  "ts tsx mts cts js jsx mjs cjs py go rs java kt kts scala rb php cs fs c h cc cpp cxx hpp m mm swift dart ex exs erl clj lua pl sh vue svelte sql proto tf".split(" "),
);

/**
 * The most frequent extension among `names` (ties: the first in sorted order), skipping dotfiles
 * (".gitignore" has no extension); with `codeOnly`, only source-code extensions count.
 */
function exampleExtension(names: string[], codeOnly: boolean): string | undefined {
  const counts = new Map<string, number>();
  for (const n of [...names].sort()) {
    if (n.startsWith(".")) continue;
    const ext = /\.([A-Za-z0-9]{1,10})$/.exec(n)?.[1];
    if (ext === undefined || (codeOnly && !CODE_EXTENSIONS.has(ext.toLowerCase()))) continue;
    counts.set(ext, (counts.get(ext) ?? 0) + 1);
  }
  let best: string | undefined;
  for (const [ext, c] of counts) if (best === undefined || c > counts.get(best)!) best = ext;
  return best;
}

async function eisdir(sc: SearchContext, r: RepoEntry): Promise<string> {
  const { dir, entries, more, ext } = await directoryListing(sc, r);
  const lines = [`EISDIR: ${dir} is a directory, not a file. Its entries (sub-directories end with "/"):`];
  if (entries.length === 0) lines.push("(empty)");
  else lines.push(...entries);
  if (more > 0) lines.push(`[${more} more ${plural(more, "entry", "entries")} not shown]`);
  lines.push(
    `Read one of these files, Grep with path "${dir}" to search everything below it, or Glob with an absolute pattern ` +
      `such as "${dir}/**/*.${ext ?? "ts"}" to find files at any depth below it.`,
  );
  return lines.join("\n");
}

function vdirError(r: VirtualDir): string {
  const names = r.roots.map((x) => x.vpath);
  const shown = names.slice(0, 20).join(", ");
  const rest = names.length > 20 ? ` (+${names.length - 20} more; see ListRepos)` : "";
  return `${r.vpath} is a directory, not a file. It contains: ${shown}${rest}. Use ListRepos to see the roots, or pass one of them as path to Grep or Glob.`;
}

export async function read(sc: SearchContext, a: { file_path: string; offset?: number; limit?: number }): Promise<ToolResult> {
  const filePath = optionalPath(a.file_path);
  if (filePath === undefined) throw new ToolError("file_path is required: an absolute virtual path such as /pr/src/index.ts.");
  const r = sc.vfs.resolve(filePath);
  if (r.kind === "vdir") throw new ToolError(vdirError(r));
  if (r.kind === "dir") throw new ToolError(await eisdir(sc, r));
  const maxBytes = parseSize(sc.search.max_filesize);
  if (r.size > maxBytes && a.offset === undefined && a.limit === undefined) {
    throw new ToolError(
      `File content (${formatSize(r.size)}) exceeds maximum allowed size (${formatSize(maxBytes)}). ` +
        "Please use offset and limit parameters to read specific portions of the file, or use Grep to search for specific content.",
    );
  }
  const maxLines = sc.search.max_read_lines;
  const start = Math.max(1, a.offset ?? 1);
  const limit = a.limit === undefined || a.limit <= 0 ? maxLines : Math.min(a.limit, maxLines);
  const win = await readWindow(r.host, r.size, start, limit, {
    countAll: r.size <= maxBytes,
    redact: sc.search.redact_secrets,
    maxLineChars: sc.search.max_line_chars,
    deadline: Date.now() + sc.search.timeout_ms,
    scanMax: pemScanMax(sc),
  });
  if (win.binary) return { text: "[binary file]" };
  if (win.lines.length === 0) {
    if (win.total === 0 || r.size === 0) return { text: "Warning: the file exists but the contents are empty." };
    return {
      text: `Warning: the file exists but is shorter than the provided offset (${start}). The file has ${win.total ?? "fewer"} lines.`,
    };
  }
  const lines = win.lines.map((l) => `${String(l.n).padStart(6)}\t${truncateLine(l.text, sc.search.max_line_chars)}`);
  const k = fitAtLeastOne(lines, sc.search.max_output_chars - NOTE_RESERVE);
  const first = win.lines[0]!.n;
  const last = win.lines[Math.min(k, lines.length) - 1]!.n;
  let text = lines.slice(0, k).join("\n");
  if (k < lines.length) {
    text += `\n[Output truncated at ${sc.search.max_output_chars} characters: showing lines ${first}-${last}. Use offset: ${last + 1} to read more.]`;
  } else if (win.more) {
    text +=
      win.total !== undefined
        ? `\n[Showing lines ${first}-${last} of ${win.total}. Use offset: ${last + 1} to read more.]`
        : `\n[Showing lines ${first}-${last}; the file continues. Use offset: ${last + 1} to read more.]`;
  }
  return { text, truncated: k < lines.length || win.more };
}


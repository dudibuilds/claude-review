/**
 * Glob helpers shared by the search MCP, prepare and the publisher.
 *
 * Semantics (gitignore-like, always with dotfiles):
 * - picomatch with `{ dot: true }`, matched against repo-relative POSIX paths.
 * - A pattern without "/" also matches the basename anywhere ("*.pem" matches "a/b/c.pem").
 * - A leading "/" anchors the pattern at the repo root ("/build" matches "build" only).
 * - "**\/x" matches "x" at the root, "a/**" matches "a" itself and everything below it.
 * - A path also matches when any of its ancestor directories matches ("secrets" and "config/prod"
 *   cover everything below them), mirroring how ripgrep/gitignore prune matching directories.
 * - An empty pattern list never matches.
 */
import picomatch from "picomatch";

const PM_OPTS = { dot: true } as const;

function normalizePath(p: string): string {
  let s = p;
  while (s.startsWith("./")) s = s.slice(2);
  while (s.startsWith("/")) s = s.slice(1);
  return s;
}

function expandPattern(glob: string): string {
  let g = glob.trim();
  const anchored = g.startsWith("/");
  g = g.replace(/^\/+/, "");
  while (g.startsWith("./")) g = g.slice(2);
  // A trailing "/" (gitignore "directory" form) means "that directory and everything below it".
  const dirOnly = g.endsWith("/");
  g = g.replace(/\/+$/, "");
  if (g === "") return "";
  // No slash at all -> match the basename at any depth (unless anchored with a leading "/").
  if (!anchored && !g.includes("/")) g = `**/${g}`;
  if (dirOnly) g = `${g}/**`;
  return g;
}

export function compileGlobs(globs: string[]): (relPath: string) => boolean {
  const patterns = globs.map(expandPattern).filter((g) => g.length > 0);
  if (patterns.length === 0) return () => false;
  const matcher = picomatch(patterns, PM_OPTS);
  return (relPath: string): boolean => {
    if (typeof relPath !== "string" || relPath.length === 0) return false;
    const p = normalizePath(relPath);
    if (p === "") return false;
    if (matcher(p)) return true;
    // gitignore / ripgrep semantics: when a directory matches, everything below it matches too
    // ("secrets" covers "secrets/db.yml"). Keeps this matcher at least as strict as `rg --glob !x`,
    // which prunes matching directories during traversal.
    for (let i = p.indexOf("/"); i > 0; i = p.indexOf("/", i + 1)) {
      if (matcher(p.slice(0, i))) return true;
    }
    return false;
  };
}

/* --------------------------- repository patterns -------------------------- */

/**
 * The one grammar of repository names and patterns (cross_repo.readable / deny, mirror.repos /
 * exclude). Names follow what `xrepo sync` mirrors and xsearch serves (sync isValidRepoName,
 * search/vfs.ts isMirrorRepoName): an owner starts alphanumeric; a repository name may start with
 * "." (".github") but is never ".", ".." or ".git"; both are [A-Za-z0-9_.-], at most 100 chars.
 */
const OWNER_RE = /^[A-Za-z0-9][A-Za-z0-9_.-]{0,99}$/;
const NAME_RE = /^[A-Za-z0-9_.][A-Za-z0-9_.-]{0,99}$/;

/** Human-readable list of the supported repository pattern forms (for error messages). */
export const REPO_PATTERN_FORMS = "owner/name, owner/* or *";

export function isRepoOwner(s: string): boolean {
  return typeof s === "string" && OWNER_RE.test(s);
}

/** Exact "owner/name" in the grammar above (case is preserved; matching ignores it). */
export function isExactRepoName(s: string): boolean {
  if (typeof s !== "string") return false;
  const parts = s.split("/");
  if (parts.length !== 2) return false;
  const [owner, name] = parts as [string, string];
  return OWNER_RE.test(owner) && NAME_RE.test(name) && name !== "." && name !== ".." && name.toLowerCase() !== ".git";
}

/**
 * Kind of a repository pattern, or undefined when it is not one of the supported forms:
 * "all" for "*", "owner" for "owner/*", "exact" for "owner/name". Anything else (other globs such
 * as "acme/legacy-*" or "*\/secrets", a trailing "/", a URL, extra segments, surrounding
 * whitespace) is unsupported: repoPatternMatch would never match it, which silently fails open in
 * a deny list, so the schema rejects it.
 */
export function repoPatternKind(pattern: string): "all" | "owner" | "exact" | undefined {
  if (typeof pattern !== "string") return undefined;
  if (pattern === "*") return "all";
  if (pattern.endsWith("/*")) return isRepoOwner(pattern.slice(0, -2)) ? "owner" : undefined;
  return isExactRepoName(pattern) ? "exact" : undefined;
}

/** Problem with a repository pattern (undefined when supported), naming the pattern. */
export function repoPatternProblem(pattern: string, opts: { allowAll?: boolean } = {}): string | undefined {
  const kind = repoPatternKind(pattern);
  const allowAll = opts.allowAll ?? true;
  if (kind !== undefined && (allowAll || kind !== "all")) return undefined;
  const forms = allowAll ? REPO_PATTERN_FORMS : "owner/name or owner/*";
  const hint = kind === undefined && pattern.includes("*") ? "; other globs are not supported, list repositories by name" : "";
  return `${JSON.stringify(pattern)} is not a supported repository pattern (expected ${forms}${hint})`;
}

/**
 * True when every repository `inner` matches is also matched by `outer` (both supported patterns,
 * case-insensitive). Unsupported patterns never cover and are never covered.
 */
export function repoPatternCovers(outer: string, inner: string): boolean {
  const ko = repoPatternKind(outer);
  const ki = repoPatternKind(inner);
  if (ko === undefined || ki === undefined) return false;
  if (ko === "all") return true;
  if (ki === "all") return false;
  const ownerOf = (p: string): string => p.slice(0, p.indexOf("/")).toLowerCase();
  if (ko === "owner") return ownerOf(outer) === ownerOf(inner);
  return ki === "exact" && outer.toLowerCase() === inner.toLowerCase();
}

/**
 * True when some repository could match both patterns (supported patterns only). For these three
 * forms, two patterns overlap exactly when one covers the other.
 */
export function repoPatternsOverlap(a: string, b: string): boolean {
  return repoPatternCovers(a, b) || repoPatternCovers(b, a);
}

/**
 * Repo pattern match: "owner/name" (exact, case-insensitive), "owner/*" (any repo of owner) or "*".
 * Other patterns never match (see repoPatternKind; the policy schema rejects them).
 */
export function repoPatternMatch(pattern: string, repo: string): boolean {
  const p = pattern.trim().toLowerCase();
  const r = repo.trim().toLowerCase();
  if (p === "" || r === "") return false;
  if (p === "*") return true;
  const slash = r.indexOf("/");
  if (slash <= 0 || slash === r.length - 1) return false;
  if (p.endsWith("/*")) {
    const owner = p.slice(0, -2);
    return owner.length > 0 && !owner.includes("/") && r.slice(0, slash) === owner;
  }
  return p === r;
}

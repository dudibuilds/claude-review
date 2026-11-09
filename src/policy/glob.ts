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

/**
 * Repo pattern match: "owner/name" (exact, case-insensitive), "owner/*" (any repo of owner) or "*".
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

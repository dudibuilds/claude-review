/**
 * The GitHub REST API root from env GITHUB_API_URL, validated in one place.
 *
 * Unset or empty -> https://api.github.com. Otherwise it must be an absolute https URL (http only for
 * loopback hosts, used by tests) without credentials, query or fragment; a path is kept (GHES:
 * https://ghe.example.com/api/v3). Anything else throws GitHubApiUrlError: a credential is never
 * sent to a host other than the configured one (no silent fallback to api.github.com).
 */

export const DEFAULT_GITHUB_API_URL = "https://api.github.com";

export class GitHubApiUrlError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "GitHubApiUrlError";
  }
}

const LOOPBACK = new Set(["localhost", "127.0.0.1", "[::1]"]);

/** Validated API root for an explicit value (no trailing slash). Throws GitHubApiUrlError. */
export function validateGitHubApiUrl(raw: string): string {
  const value = raw.trim();
  let u: URL;
  try {
    u = new URL(value);
  } catch {
    throw new GitHubApiUrlError("GITHUB_API_URL is not a valid absolute URL");
  }
  if (u.protocol !== "https:" && !(u.protocol === "http:" && LOOPBACK.has(u.hostname))) {
    throw new GitHubApiUrlError("GITHUB_API_URL must use https:// (http:// only for localhost)");
  }
  if (u.username !== "" || u.password !== "") throw new GitHubApiUrlError("GITHUB_API_URL must not contain credentials");
  if (u.search !== "" || u.hash !== "" || value.includes("?") || value.includes("#")) {
    throw new GitHubApiUrlError("GITHUB_API_URL must not contain a query or fragment");
  }
  return u.href.replace(/\/+$/, "");
}

/** API root from `env.GITHUB_API_URL` (default https://api.github.com). Throws GitHubApiUrlError. */
export function githubApiBase(env: Record<string, string | undefined>): string {
  const raw = (env.GITHUB_API_URL ?? "").trim();
  return raw === "" ? DEFAULT_GITHUB_API_URL : validateGitHubApiUrl(raw);
}

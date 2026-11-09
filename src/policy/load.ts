/**
 * Policy manifest loading and resolution.
 *
 * - parsePolicy: YAML (core schema, no custom tags, bounded aliases) + zod validation; every issue
 *   is reported with a readable path.
 * - resolvePolicy: schema defaults <- `defaults` layer <- `repos[repo]` layer (objects merge
 *   recursively, arrays/scalars replace), except search.deny_globs / search.exclude_globs which
 *   accumulate on top of the built-in defaults. Outcomes merge over DEFAULT_OUTCOMES.
 */
import { readFileSync, statSync } from "node:fs";
import { parseDocument } from "yaml";
import { z } from "zod";
import { audit } from "../common/audit.js";
import { repoPatternMatch } from "./glob.js";
import {
  DEFAULT_DENY_GLOBS,
  DEFAULT_EXCLUDE_GLOBS,
  DEFAULT_OUTCOMES,
  OUTCOMES,
  OutcomeActions,
  PolicyFile,
  ResolvedPolicy,
  type PolicyLayer,
} from "./schema.js";

export class PolicyError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "PolicyError";
  }
}

const MAX_ALIAS_COUNT = 50;
const MAX_POLICY_BYTES = 1024 * 1024;
const REPO_NAME_RE = /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/;

/** owner/name with no "." / ".." segments (repo names end up in filesystem paths). */
function isRepoName(s: unknown): s is string {
  return typeof s === "string" && REPO_NAME_RE.test(s) && !s.split("/").some((seg) => seg === "." || seg === "..");
}
const UNSAFE_KEYS = new Set(["__proto__", "constructor", "prototype"]);

/* -------------------------------- helpers ------------------------------- */

type Plain = Record<string, unknown>;

function isPlainObject(v: unknown): v is Plain {
  if (v === null || typeof v !== "object" || Array.isArray(v)) return false;
  const proto = Object.getPrototypeOf(v);
  return proto === Object.prototype || proto === null;
}

/** Deep merge: plain objects merge recursively; arrays and scalars from `over` replace. */
function deepMerge(base: unknown, over: unknown): unknown {
  if (over === undefined) return clone(base);
  if (isPlainObject(base) && isPlainObject(over)) {
    const out: Plain = {};
    for (const [k, v] of Object.entries(base)) if (!UNSAFE_KEYS.has(k)) out[k] = clone(v);
    for (const [k, v] of Object.entries(over)) {
      if (UNSAFE_KEYS.has(k) || v === undefined) continue;
      out[k] = deepMerge(out[k], v);
    }
    return out;
  }
  return clone(over);
}

function clone(v: unknown): unknown {
  if (Array.isArray(v)) return v.map(clone);
  if (isPlainObject(v)) {
    const out: Plain = {};
    for (const [k, x] of Object.entries(v)) if (!UNSAFE_KEYS.has(k) && x !== undefined) out[k] = clone(x);
    return out;
  }
  return v;
}

/**
 * Keep only the keys the author actually wrote. zod fills defaults inside partially specified
 * nested objects of a layer (e.g. `capabilities.inline_comments: {suggestions: false}` comes back
 * with `max_comments: 15`), which would wrongly override the `defaults` layer during merging.
 */
function pruneToRaw(parsed: unknown, raw: unknown): unknown {
  if (!isPlainObject(parsed) || !isPlainObject(raw)) return parsed;
  const out: Plain = {};
  for (const [k, v] of Object.entries(parsed)) {
    if (!Object.prototype.hasOwnProperty.call(raw, k)) continue;
    out[k] = pruneToRaw(v, raw[k]);
  }
  return out;
}

function formatPath(path: (string | number)[]): string {
  if (path.length === 0) return "(root)";
  let s = "";
  for (const seg of path) {
    if (typeof seg === "number") s += `[${seg}]`;
    else if (/^[A-Za-z_][A-Za-z0-9_]*$/.test(seg)) s += s === "" ? seg : `.${seg}`;
    else s += `[${JSON.stringify(seg)}]`;
  }
  return s;
}

interface Issue {
  path: (string | number)[];
  message: string;
}

function issuesFromZod(err: z.ZodError): Issue[] {
  const out: Issue[] = [];
  for (const i of err.issues) {
    if (i.code === z.ZodIssueCode.unrecognized_keys) {
      for (const k of i.keys) out.push({ path: [...i.path, k], message: "unknown key" });
    } else {
      out.push({ path: i.path, message: i.message });
    }
  }
  return out;
}

function formatIssues(header: string, issues: Issue[]): string {
  const seen = new Set<string>();
  const lines: string[] = [];
  for (const i of issues) {
    const line = `  - ${formatPath(i.path)}: ${i.message}`;
    if (!seen.has(line)) {
      seen.add(line);
      lines.push(line);
    }
  }
  return `${header} (${lines.length} issue${lines.length === 1 ? "" : "s"}):\n${lines.join("\n")}`;
}

/** Best-effort notify-target check on raw input, so typos are reported with other schema errors. */
function rawNotifyIssues(raw: unknown): Issue[] {
  if (!isPlainObject(raw)) return [];
  const targets = isPlainObject(raw.notifications) ? new Set(Object.keys(raw.notifications)) : new Set<string>();
  const issues: Issue[] = [];
  const layers: [(string | number)[], unknown][] = [[["defaults"], raw.defaults]];
  if (isPlainObject(raw.repos)) for (const [k, v] of Object.entries(raw.repos)) layers.push([["repos", k], v]);
  for (const [base, layer] of layers) {
    if (!isPlainObject(layer) || !isPlainObject(layer.outcomes)) continue;
    for (const [outcome, actions] of Object.entries(layer.outcomes)) {
      if (!isPlainObject(actions) || !Array.isArray(actions.notify)) continue;
      actions.notify.forEach((ref, i) => {
        if (isPlainObject(ref) && typeof ref.target === "string" && ref.target !== "" && !targets.has(ref.target)) {
          issues.push({
            path: [...base, "outcomes", outcome, "notify", i, "target"],
            message: `unknown notification target "${ref.target}"`,
          });
        }
      });
    }
  }
  return issues;
}

/* --------------------------------- parse -------------------------------- */

export function parsePolicy(yamlText: string): PolicyFile {
  if (typeof yamlText !== "string") throw new PolicyError("invalid policy manifest: expected YAML text");
  if (yamlText.length > MAX_POLICY_BYTES) {
    throw new PolicyError(`invalid policy manifest: larger than ${MAX_POLICY_BYTES} bytes`);
  }
  let raw: unknown;
  try {
    const doc = parseDocument(yamlText, {
      version: "1.2",
      schema: "core",
      customTags: [],
      resolveKnownTags: false, // no !!binary / !!set / !!timestamp / !!omap
      merge: false,
      uniqueKeys: true,
      strict: true,
      prettyErrors: true,
    });
    const problems = [...doc.errors, ...doc.warnings];
    if (problems.length > 0) {
      throw new PolicyError(
        `invalid policy manifest: YAML syntax:\n${problems.map((e) => `  - ${e.message.trim().split("\n")[0]}`).join("\n")}`,
      );
    }
    raw = doc.toJS({ maxAliasCount: MAX_ALIAS_COUNT });
  } catch (e) {
    if (e instanceof PolicyError) throw e;
    throw new PolicyError(`invalid policy manifest: YAML: ${(e as Error).message}`);
  }
  if (raw === null || raw === undefined) raw = {};

  const parsed = PolicyFile.safeParse(raw);
  if (!parsed.success) {
    const issues = issuesFromZod(parsed.error);
    for (const ni of rawNotifyIssues(raw)) {
      if (!issues.some((i) => formatPath(i.path) === formatPath(ni.path) && i.message === ni.message)) issues.push(ni);
    }
    throw new PolicyError(formatIssues("invalid policy manifest", issues));
  }
  const file = parsed.data;

  // Repo keys are matched case-insensitively, so case-only duplicates are ambiguous. Repo names
  // also end up in filesystem paths (mirror layout), so "." / ".." segments are rejected.
  const byLower = new Map<string, string>();
  const extraIssues: Issue[] = [];
  for (const key of Object.keys(file.repos)) {
    const lower = key.toLowerCase();
    const prev = byLower.get(lower);
    if (!isRepoName(key)) extraIssues.push({ path: ["repos", key], message: 'repo name must not contain "." or ".." segments' });
    if (prev !== undefined) extraIssues.push({ path: ["repos", key], message: `duplicates "${prev}" (repo keys are case-insensitive)` });
    else byLower.set(lower, key);
  }
  for (const listName of ["repos", "exclude"] as const) {
    file.mirror[listName].forEach((entry, i) => {
      if (entry.split("/").some((seg) => seg === "." || seg === "..") || /[\\\0\s]/.test(entry)) {
        extraIssues.push({ path: ["mirror", listName, i], message: "expected owner/name or owner/*" });
      }
    });
  }
  if (extraIssues.length > 0) throw new PolicyError(formatIssues("invalid policy manifest", extraIssues));

  // Drop zod-filled defaults inside layers so that merging respects what was actually written.
  const rawObj = raw as Plain;
  const rawRepos = isPlainObject(rawObj.repos) ? rawObj.repos : {};
  file.defaults = pruneToRaw(file.defaults, rawObj.defaults ?? {}) as PolicyLayer;
  for (const key of Object.keys(file.repos)) {
    file.repos[key] = pruneToRaw(file.repos[key], rawRepos[key] ?? {}) as PolicyLayer;
  }
  return file;
}

export function loadPolicy(path: string): PolicyFile {
  let text: string;
  try {
    const st = statSync(path);
    if (!st.isFile()) throw new Error("not a regular file");
    if ((st.mode & 0o022) !== 0) {
      const mode = (st.mode & 0o777).toString(8).padStart(3, "0");
      audit("policy.insecure_permissions", {
        path,
        mode,
        warning: "policy file is group/world-writable; it should be owned by root and read-only to the runner",
      });
    }
    text = readFileSync(path, "utf8");
  } catch (e) {
    throw new PolicyError(`cannot read policy file ${path}: ${(e as Error).message}`);
  }
  try {
    return parsePolicy(text);
  } catch (e) {
    if (e instanceof PolicyError) throw new PolicyError(`${path}: ${e.message}`);
    throw e;
  }
}

/* -------------------------------- resolve ------------------------------- */

function findRepoLayer(file: PolicyFile, repo: string): PolicyLayer | undefined {
  const lower = repo.toLowerCase();
  for (const [key, layer] of Object.entries(file.repos)) {
    if (key.toLowerCase() === lower) return layer;
  }
  return undefined;
}

function dedupe(list: string[]): string[] {
  return [...new Set(list)];
}

export function resolvePolicy(file: PolicyFile, repo: string): ResolvedPolicy {
  if (!isRepoName(repo)) {
    throw new PolicyError(`invalid repository name ${JSON.stringify(repo)}: expected owner/name`);
  }
  const d: PolicyLayer = file.defaults ?? {};
  const r: PolicyLayer = findRepoLayer(file, repo) ?? {};

  const merged = (key: "capabilities" | "search" | "cross_repo" | "triggers" | "agent" | "output"): Plain =>
    deepMerge(deepMerge({}, d[key] ?? {}), r[key] ?? {}) as Plain;

  const search = merged("search");
  const replaceDefaults = search.replace_defaults === true;
  search.deny_globs = dedupe([
    ...(replaceDefaults ? [] : DEFAULT_DENY_GLOBS),
    ...(d.search?.deny_globs ?? []),
    ...(r.search?.deny_globs ?? []),
  ]);
  search.exclude_globs = dedupe([
    ...(replaceDefaults ? [] : DEFAULT_EXCLUDE_GLOBS),
    ...(d.search?.exclude_globs ?? []),
    ...(r.search?.exclude_globs ?? []),
  ]);

  const outcomes: Plain = {};
  const outcomeIssues: Issue[] = [];
  for (const o of OUTCOMES) {
    const layered = deepMerge(deepMerge(DEFAULT_OUTCOMES[o], d.outcomes?.[o] ?? {}), r.outcomes?.[o] ?? {});
    const res = OutcomeActions.safeParse(layered);
    if (res.success) outcomes[o] = res.data;
    else for (const i of issuesFromZod(res.error)) outcomeIssues.push({ path: ["outcomes", o, ...i.path], message: i.message });
  }
  if (outcomeIssues.length > 0) {
    throw new PolicyError(formatIssues(`invalid resolved policy for ${repo}`, outcomeIssues));
  }

  const candidate = {
    repo,
    enabled: r.enabled ?? d.enabled ?? true,
    capabilities: merged("capabilities"),
    search,
    cross_repo: merged("cross_repo"),
    triggers: merged("triggers"),
    agent: merged("agent"),
    output: merged("output"),
    outcomes,
    notifications: clone(file.notifications ?? {}),
  };
  const res = ResolvedPolicy.safeParse(candidate);
  if (!res.success) {
    throw new PolicyError(formatIssues(`invalid resolved policy for ${repo}`, issuesFromZod(res.error)));
  }
  return res.data;
}

/**
 * Mirror repos readable while reviewing `policy.repo`: those matching a cross_repo.readable pattern
 * and no cross_repo.deny pattern (deny wins). The PR repo's own default-branch mirror is readable
 * when present unless denied. "@pr" (the PR head checkout) is not a mirror repo and is handled by
 * the caller. Entries that are not owner/name are ignored. Sorted, de-duplicated.
 */
export function readableRepos(policy: ResolvedPolicy, mirrorRepos: string[]): string[] {
  const { readable, deny } = policy.cross_repo;
  const self = policy.repo.toLowerCase();
  const out = new Set<string>();
  for (const repo of mirrorRepos) {
    if (!isRepoName(repo)) continue;
    if (deny.some((p) => repoPatternMatch(p, repo))) continue;
    if (repo.toLowerCase() === self || readable.some((p) => repoPatternMatch(p, repo))) out.add(repo);
  }
  return [...out].sort();
}

export function readResolvedPolicy(path: string): ResolvedPolicy {
  let json: unknown;
  try {
    json = JSON.parse(readFileSync(path, "utf8"));
  } catch (e) {
    throw new PolicyError(`cannot read resolved policy ${path}: ${(e as Error).message}`);
  }
  const res = ResolvedPolicy.safeParse(json);
  if (!res.success) {
    throw new PolicyError(formatIssues(`invalid resolved policy ${path}`, issuesFromZod(res.error)));
  }
  return res.data;
}

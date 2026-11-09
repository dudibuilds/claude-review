/**
 * xsearch MCP server (`xrepo search-mcp`): Claude Code's Grep / Glob / Read, made multi-repo, plus
 * ListRepos and PrDiff. See SPEC.md "xsearch: Claude Code's Grep / Glob / Read, made multi-repo".
 *
 * - Read-only: no writes, no network; ripgrep is the only subprocess (spawned without a shell).
 * - Inputs (resolved policy, PR context, diff, PR checkout, mirror) come only from trusted CLI
 *   flags written by `prepare`; tool arguments are only ever virtual paths and search parameters.
 * - Plain-text results only (no structuredContent). Every tool carries readOnlyHint and
 *   `_meta: {"anthropic/alwaysLoad": true}` so Claude Code never defers it behind ToolSearch.
 * - Every response is secret-redacted (search.redact_secrets) and capped at
 *   search.max_output_chars; every call is audited as `xsearch.call`.
 * - Input schemas are strict: an unknown or misnamed parameter is an MCP input-validation error
 *   that names the right one (PARAM_HINTS), never silently dropped.
 * - `--policy-path` (from prepare) names the policy manifest's repo-relative path; that path is
 *   hidden in every /repos root, as is MIRROR_HIDDEN_GLOBS (see vfs.ts).
 */
import { readFileSync } from "node:fs";
import { join } from "node:path";
import type { Readable, Writable } from "node:stream";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { CallToolRequestSchema, type CallToolResult } from "@modelcontextprotocol/sdk/types.js";
import { z } from "zod";
import { parseCli } from "../common/args.js";
import { audit } from "../common/audit.js";
import { CTX_FILES, readContext, type PrContext } from "../common/context.js";
import { parseUnifiedDiff, type FileDiff } from "../common/diff.js";
import { mergeSamePathDiffs, mergeSamePathFiles } from "../review/rules.js";
import { readResolvedPolicy, readableRepos } from "../policy/load.js";
import type { ResolvedPolicy } from "../policy/schema.js";
import { finalizeOutput } from "./text.js";
import {
  DEFAULT_HEAD_LIMIT,
  GLOB_RESULT_LIMIT,
  ToolError,
  glob,
  grep,
  listRepos,
  prDiff,
  read,
  type GrepArgs,
  type SearchContext,
  type ToolResult,
} from "./tools.js";
import { ExcludeSet, Vfs, VfsError, discoverMirror } from "./vfs.js";
import { ALWAYS_LOAD_META } from "../common/mcp.js";

export const SEARCH_SERVER_NAME = "xsearch";
const VERSION = "0.1.0";

/** Tool names exactly as registered (prepare prefixes them with `mcp__xsearch__` for --allowedTools). */
export const XSEARCH_TOOL_NAMES = ["ListRepos", "PrDiff", "Grep", "Glob", "Read"] as const;
export type XsearchToolName = (typeof XSEARCH_TOOL_NAMES)[number];

/** Claude Code defers MCP tools behind ToolSearch unless this is set (SPEC "Tool loading"). */
export { ALWAYS_LOAD_META };

export interface SearchServerOptions {
  policy: ResolvedPolicy;
  ctx: PrContext;
  /** Unified diff base...head (ctx/diff.patch). */
  diffText: string;
  /** PR head checkout, served as /pr. */
  prDir: string;
  /** Mirror root (<mirror>/<owner>/<repo>/{current,meta.json}); omitted = no /repos. */
  mirrorDir?: string;
  /** ripgrep binary (default "rg" from PATH). */
  rgPath?: string;
  /**
   * Repo-relative path of the policy manifest inside the repository that holds it (hosted mode:
   * review.yml's policy_file). Hidden in every /repos root, in addition to MIRROR_HIDDEN_GLOBS.
   */
  policyPath?: string;
  now?: () => number;
}

/* ------------------------------ input schemas ----------------------------- */

/** Non-negative integer; numeric strings are accepted (models sometimes quote numbers). */
const int = (description: string) =>
  z
    .preprocess((v) => (typeof v === "string" && /^\s*\d+\s*$/.test(v) ? Number(v) : v), z.number().int().min(0))
    .optional()
    .describe(description);

const bool = (description: string) =>
  z
    .preprocess((v) => (v === "true" ? true : v === "false" ? false : v), z.boolean())
    .optional()
    .describe(description);

const VIRTUAL_PATHS =
  "Paths are virtual: /pr is the PR head checkout, /repos/<owner>/<name> are the other readable repositories (see ListRepos); every result prints paths you can pass straight to Read.";

const DEFAULT_ROOTS =
  "Without path it searches /pr and every other readable repository; this PR's own repository under /repos (its code before the PR, which would repeat /pr) is searched only when you pass it as path.";

const excludedLine = (names: string): string =>
  `Generated, vendored and lock files (the policy's exclude_globs, e.g. node_modules/, dist/, build/, *.min.js, lockfiles) are skipped unless ${names} names them; a note says when that hid results.`;

function descriptions(policy: ResolvedPolicy): Record<XsearchToolName, string> {
  const s = policy.search;
  return {
    ListRepos:
      "Lists the code you can read, as virtual roots: /pr (the pull request's head checkout) and /repos/<owner>/<name> " +
      "(default-branch snapshot of each repository this PR's repo may read, with commit, sync age and description).\n\n" +
      "Usage:\n" +
      "- Pass a root as `path` to Grep or Glob to search only that repository\n" +
      "- Read files under any root, e.g. /repos/acme/api/src/server.ts\n" +
      "- offset and limit page through a long list by row, like Read",
    PrDiff:
      "Shows what this pull request changes (base...head).\n\n" +
      "Usage:\n" +
      "- Without file_path: the changed files, one per line, e.g. `M  +12 -3  /pr/src/orders.ts` (A added, M modified, D deleted, R renamed `old -> new`)\n" +
      "- With file_path (a /pr/... path from that list): the file's unified diff with 3 lines of context; hunk headers (@@ -a,b +c,d @@) give the new-side line numbers\n" +
      "- offset and limit page through long diffs by line, like Read\n" +
      "- Use Read on /pr/... for the whole new version of a file",
    Grep:
      "A powerful search tool built on ripgrep\n\n" +
      "Usage:\n" +
      "- ALWAYS use Grep for search tasks. It searches the PR checkout and the readable repositories.\n" +
      `- ${VIRTUAL_PATHS} Pass e.g. /repos/acme/api as path to search one repository. ${DEFAULT_ROOTS}\n` +
      '- Supports full regex syntax (e.g., "log.*Error", "function\\s+\\w+")\n' +
      '- Filter files with glob parameter (e.g., "*.js", "**/*.tsx") or type parameter (e.g., "js", "py", "rust")\n' +
      '- Output modes: "content" shows matching lines, "files_with_matches" shows only file paths (default), "count" shows match counts\n' +
      "- Pattern syntax: Uses ripgrep (not grep) - literal braces need escaping (use `interface\\{\\}` to find `interface{}` in Go code)\n" +
      "- Multiline matching: By default patterns match within single lines only. For cross-line patterns like `struct \\{[\\s\\S]*?field`, use `multiline: true`\n" +
      `- ${excludedLine("path or glob")}\n` +
      "- Use Grep to find code, then Read with offset/limit to see the surrounding lines",
    Glob:
      "- Fast file pattern matching tool across the PR checkout and the readable repositories\n" +
      '- Supports glob patterns like "**/*.js" or "src/**/*.ts"\n' +
      `- Returns matching file paths sorted by path (at most ${GLOB_RESULT_LIMIT})\n` +
      "- Use this tool when you need to find files by name patterns\n" +
      `- ${VIRTUAL_PATHS} ${DEFAULT_ROOTS}\n` +
      '- A relative pattern without "/" matches file names at any depth below path (like ripgrep): "*.js" with path /repos/acme/api ' +
      'finds every .js file in that repository. Patterns with "/" are relative to path. Absolute patterns are anchored: ' +
      '"/repos/acme/api/*.js" lists only the files directly in that directory, "/repos/acme/api/src/**/*.go" everything below src.\n' +
      `- ${excludedLine("path or pattern")}`,
    Read:
      "Reads a file from the PR checkout or a readable repository.\n\n" +
      "Usage:\n" +
      "- The file_path parameter must be an absolute virtual path, e.g. /pr/src/index.ts or /repos/acme/api/README.md (exactly as Grep, Glob and PrDiff print them)\n" +
      `- By default, it reads up to ${s.max_read_lines} lines starting from the beginning of the file\n` +
      "- Prefer offset/limit windows around Grep hits (typically 40-150 lines); read a whole file only when it is short or you need all of it\n" +
      `- Any lines longer than ${s.max_line_chars} characters will be truncated\n` +
      "- Results are returned using cat -n format, with line numbers starting at 1\n" +
      "- This tool can only read files, not directories. Reading a directory returns an error that lists its entries.",
  };
}

const grepShape = {
  pattern: z.string().describe("The regular expression pattern to search for in file contents"),
  path: z
    .string()
    .optional()
    .describe(
      "File or directory to search in (rg PATH), as a virtual path such as /pr/src or /repos/<owner>/<name>. Defaults to the roots described above.",
    ),
  glob: z.string().optional().describe('Glob pattern to filter files (e.g. "*.js", "*.{ts,tsx}"), relative to path - maps to rg --glob'),
  output_mode: z
    .enum(["content", "files_with_matches", "count"])
    .optional()
    .describe(
      'Output mode: "content" shows matching lines (supports -A/-B/-C context, -n line numbers, head_limit), "files_with_matches" shows file paths (supports head_limit), "count" shows match counts (supports head_limit). Defaults to "files_with_matches".',
    ),
  "-B": int('Number of lines to show before each match (rg -B). Requires output_mode: "content", ignored otherwise.'),
  "-A": int('Number of lines to show after each match (rg -A). Requires output_mode: "content", ignored otherwise.'),
  "-C": int("Alias for context."),
  context: int('Number of lines to show before and after each match (rg -C). Requires output_mode: "content", ignored otherwise.'),
  "-n": bool('Show line numbers in output (rg -n). Requires output_mode: "content", ignored otherwise. Defaults to true.'),
  "-i": bool("Case insensitive search (rg -i)"),
  "-o": bool(
    'Print only the matched (non-empty) parts of each matching line, one match per output line (rg -o / --only-matching). Requires output_mode: "content", ignored otherwise. Defaults to false.',
  ),
  type: z
    .string()
    .optional()
    .describe("File type to search (rg --type). Common types: js, py, rust, go, java, etc. More efficient than glob for standard file types."),
  head_limit: int(
    `Limit output to first N lines/entries, equivalent to "| head -N". Works across all output modes: content (limits output lines), files_with_matches (limits file paths), count (limits count entries). Defaults to ${DEFAULT_HEAD_LIMIT} when unspecified. Pass 0 for unlimited (use sparingly — large result sets waste context).`,
  ),
  offset: int('Skip first N lines/entries before applying head_limit, equivalent to "| tail -n +N | head -N". Works across all output modes. Defaults to 0.'),
  multiline: bool("Enable multiline mode where . matches newlines and patterns can span lines (rg -U --multiline-dotall). Default: false."),
};

const globShape = {
  pattern: z.string().describe("The glob pattern to match files against"),
  path: z
    .string()
    .optional()
    .describe(
      'The directory to search in, as a virtual path such as /pr/src or /repos/<owner>/<name>. If not specified, the default roots described above are searched. IMPORTANT: Omit this field to use the default directory. DO NOT enter "undefined" or "null" - simply omit it for the default behavior. Must be a valid directory path if provided.',
    ),
};

/* ------------------------- unknown parameter hints ------------------------- */

/**
 * Misnamed parameters models commonly send, with what to use instead. Unknown parameters are
 * rejected (never silently dropped: a dropped `limit` or `include` would run with defaults and
 * return a far larger, unfiltered result).
 */
const PARAM_HINTS: Record<XsearchToolName, Record<string, string>> = {
  ListRepos: {
    head_limit: "limit",
    max_results: "limit",
    start: "offset",
    path: 'Grep or Glob with path (e.g. "/repos/acme") to look inside roots',
  },
  PrDiff: {
    path: "file_path",
    file: "file_path",
    filePath: "file_path",
    start_line: "offset",
    startLine: "offset",
    end_line: "limit (a number of lines)",
    endLine: "limit (a number of lines)",
  },
  Grep: {
    limit: "head_limit",
    max_results: "head_limit",
    maxResults: "head_limit",
    max_count: "head_limit",
    headLimit: "head_limit",
    include: "glob",
    includes: "glob",
    file_pattern: "glob",
    filePattern: "glob",
    files: "glob",
    exclude: 'glob with a "!" prefix, e.g. "!**/*.test.ts"',
    query: "pattern",
    regex: "pattern",
    search: "pattern",
    directory: "path",
    dir: "path",
    file: "path",
    file_path: "path",
    case_insensitive: "-i",
    ignore_case: "-i",
    ignoreCase: "-i",
    only_matching: "-o",
    line_numbers: "-n",
    context_lines: "context",
    before: "-B",
    after: "-A",
    mode: "output_mode",
    outputMode: "output_mode",
    file_type: "type",
    fileType: "type",
    skip: "offset",
  },
  Glob: {
    root: "path",
    directory: "path",
    dir: "path",
    cwd: "path",
    glob: "pattern",
    query: "pattern",
    limit: `nothing (results are capped at ${GLOB_RESULT_LIMIT}; use a more specific path or pattern)`,
    head_limit: `nothing (results are capped at ${GLOB_RESULT_LIMIT}; use a more specific path or pattern)`,
  },
  Read: {
    path: "file_path",
    file: "file_path",
    filePath: "file_path",
    filename: "file_path",
    start_line: "offset (the first line to read, 1-based)",
    startLine: "offset (the first line to read, 1-based)",
    line: "offset (the first line to read, 1-based)",
    from: "offset (the first line to read, 1-based)",
    end_line: "limit (the number of lines: end_line - offset + 1)",
    endLine: "limit (the number of lines: end_line - offset + 1)",
    lines: "limit (the number of lines)",
    max_lines: "limit (the number of lines)",
    count: "limit (the number of lines)",
  },
};

export function unknownParamsMessage(tool: XsearchToolName, keys: string[], valid: string[]): string {
  const hints = PARAM_HINTS[tool];
  const parts = keys.slice(0, 10).map((k) => {
    const name = JSON.stringify(k.length > 60 ? `${k.slice(0, 60)}…` : k);
    const use = Object.prototype.hasOwnProperty.call(hints, k) ? hints[k] : undefined;
    return use ? `${name} (use ${use} instead)` : name;
  });
  const accepted = valid.length > 0 ? `${tool} accepts only: ${valid.join(", ")}.` : `${tool} takes no parameters.`;
  return `Unknown ${plural(keys.length, "parameter", "parameters")} ${parts.join(", ")}. ${accepted}`;
}

function plural(n: number, one: string, many: string): string {
  return n === 1 ? one : many;
}

/** The tool's input schema: unknown keys are an error that names the right parameter. */
function inputSchema<S extends z.ZodRawShape>(tool: XsearchToolName, shape: S) {
  const valid = Object.keys(shape);
  return z
    .object(shape, {
      errorMap: (issue, ctx) =>
        issue.code === z.ZodIssueCode.unrecognized_keys
          ? { message: unknownParamsMessage(tool, issue.keys, valid) }
          : { message: ctx.defaultError },
    })
    .strict();
}

const readShape = {
  file_path: z.string().describe("The absolute virtual path to the file to read, e.g. /pr/src/index.ts or /repos/<owner>/<name>/README.md"),
  offset: int("The line number to start reading from. Only provide if the file is too large to read at once"),
  limit: int("The number of lines to read. Only provide if the file is too large to read at once."),
};

const listReposShape = {
  offset: int("The row to start from, 1-based. Only provide if the list is too long to show at once"),
  limit: int("The number of rows to show. Only provide if the list is too long to show at once."),
};

/** finalizeOutput's truncation advice per tool: only parameters that tool has. */
const TRUNCATION_HINTS: Record<XsearchToolName, string> = {
  ListRepos: "Use offset/limit to page through the list.",
  PrDiff: "Use offset/limit to page through it.",
  Grep: "Narrow it with path, glob or type, or page with head_limit/offset.",
  Glob: "Use a more specific path or pattern.",
  Read: "Use offset/limit to read a smaller window.",
};

const prDiffShape = {
  file_path: z
    .string()
    .optional()
    .describe("A changed file as listed by PrDiff, e.g. /pr/src/orders.ts. Omit to list the changed files."),
  offset: int("The line of the diff (or of the file list) to start from, 1-based. Only provide if the diff is too long to show at once"),
  limit: int("The number of lines to show. Only provide if the diff is too long to show at once."),
};

/* --------------------------------- server --------------------------------- */

const ANNOTATIONS = { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false } as const;

function clip(s: string, max: number): string {
  return s.length > max ? `${s.slice(0, max)}…` : s;
}

function summarizeArgs(args: unknown): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  if (args && typeof args === "object") {
    for (const [k, v] of Object.entries(args as Record<string, unknown>)) {
      out[k] = typeof v === "string" ? clip(v, 200) : v;
    }
  }
  return out;
}

type AnyHandler = (request: unknown, extra: unknown) => unknown;

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

/**
 * Tool callbacks audit their own calls. Calls the SDK rejects before a callback runs (schema
 * validation errors, unknown tools) are audited here by wrapping McpServer's tools/call handler as
 * it is installed. Those results are recognisable by the SDK's "MCP error -326xx" text.
 */
function auditRejectedCalls(server: McpServer): void {
  const low = server.server as unknown as { setRequestHandler: (schema: unknown, handler: AnyHandler) => void };
  const originalSet = low.setRequestHandler.bind(low);
  low.setRequestHandler = (schema, handler) => {
    const method = (schema as { shape?: { method?: { value?: unknown } } } | null)?.shape?.method?.value;
    if (schema !== CallToolRequestSchema && method !== "tools/call") {
      originalSet(schema, handler);
      return;
    }
    originalSet(schema, async (request: unknown, extra: unknown) => {
      const params = isRecord(request) && isRecord(request.params) ? request.params : {};
      const tool = typeof params.name === "string" ? clip(params.name, 100) : "(invalid)";
      try {
        const result = await handler(request, extra);
        const content = isRecord(result) && Array.isArray(result.content) ? (result.content as unknown[]) : [];
        const first = content[0];
        const text = isRecord(first) && typeof first.text === "string" ? first.text : "";
        if (isRecord(result) && result.isError === true && /^MCP error -32\d{3}:/.test(text)) {
          audit("xsearch.call", { tool, args: summarizeArgs(params.arguments), ok: false, rejected: true, error: clip(text, 500) });
        }
        return result;
      } catch (e) {
        audit("xsearch.call", { tool, args: summarizeArgs(params.arguments), ok: false, rejected: true, error: e });
        throw e;
      }
    });
  };
}

/**
 * Anchored, escaped glob for the policy manifest's repo-relative path. Throws on paths that could
 * not name a file inside a repository (absolute, "..", control characters).
 */
export function policyPathGlob(path: string): string {
  const p = path.trim().replace(/^(?:\.\/)+/, "");
  if (p === "" || p.startsWith("/") || p.includes("\\") || /[\u0000-\u001f\u007f]/.test(p) || p.split("/").some((x) => x === "..")) {
    throw new Error(`--policy-path must be a relative path inside the repository that holds the policy (got ${JSON.stringify(path)})`);
  }
  const segs = p.split("/").filter((x) => x !== "" && x !== ".");
  return `/${segs.map((x) => x.replace(/[*?[\]{}()!+@\\]/g, "\\$&")).join("/")}`;
}

/** Build the search context (mirror discovery filtered by policy, VFS, parsed diff). */
export function buildSearchContext(opts: SearchServerOptions): SearchContext {
  const discovered = discoverMirror(opts.mirrorDir);
  const readable = new Set(readableRepos(opts.policy, discovered.map((m) => m.repo)).map((r) => r.toLowerCase()));
  const mirror = discovered.filter((m) => readable.has(m.repo.toLowerCase()));
  const policyGlob = opts.policyPath === undefined ? undefined : policyPathGlob(opts.policyPath);
  const vfs = new Vfs({
    prDir: opts.prDir,
    prRepo: opts.ctx.repo,
    mirror,
    denyGlobs: opts.policy.search.deny_globs,
    ...(policyGlob ? { mirrorHiddenGlobs: [policyGlob] } : {}),
  });
  const diffs = new Map<string, FileDiff>();
  for (const fd of mergeSamePathDiffs(parseUnifiedDiff(opts.diffText))) if (!diffs.has(fd.path)) diffs.set(fd.path, fd);
  return {
    vfs,
    search: opts.policy.search,
    ctx: { ...opts.ctx, files: mergeSamePathFiles(opts.ctx.files) },
    diffs,
    excludes: new ExcludeSet(opts.policy.search.exclude_globs),
    rgPath: opts.rgPath ?? "rg",
    now: opts.now ?? Date.now,
  };
}

export function createSearchServer(opts: SearchServerOptions): McpServer {
  const sc = buildSearchContext(opts);
  const desc = descriptions(opts.policy);
  const server = new McpServer(
    { name: SEARCH_SERVER_NAME, version: VERSION },
    {
      instructions:
        "Read-only code search over the pull request (/pr) and the repositories it may read (/repos/<owner>/<name>). " +
        "Start with PrDiff, find code with Grep and Glob (without path they search every root; ListRepos lists them), and read it with Read.",
    },
  );

  auditRejectedCalls(server);

  /** Host paths must never leak into error text. */
  const scrub = (text: string): string => {
    let out = text;
    const pairs: [string, string][] = sc.vfs.roots.map((r) => [r.host, r.vpath]);
    if (opts.mirrorDir) pairs.push([opts.mirrorDir, "/repos"]);
    pairs.push([opts.prDir, "/pr"]);
    for (const [host, v] of pairs.sort((a, b) => b[0].length - a[0].length)) {
      if (host.length > 1) out = out.split(host).join(v);
    }
    return out;
  };

  const register = <S extends z.ZodRawShape>(
    name: XsearchToolName,
    shape: S,
    run: (args: z.objectOutputType<S, z.ZodTypeAny>) => ToolResult | Promise<ToolResult>,
  ): void => {
    server.registerTool(
      name,
      { title: name, description: desc[name], inputSchema: inputSchema(name, shape), annotations: ANNOTATIONS, _meta: { ...ALWAYS_LOAD_META } },
      (async (args: z.objectOutputType<S, z.ZodTypeAny>): Promise<CallToolResult> => {
        const t0 = Date.now();
        let res: ToolResult;
        let error: unknown;
        try {
          res = await run(args);
        } catch (e) {
          error = e;
          const known = e instanceof VfsError || e instanceof ToolError;
          res = { text: known ? (e as Error).message : `Error: ${scrub((e as Error)?.message ?? String(e))}`, isError: true };
        }
        const fin = finalizeOutput(res.text, { redact: opts.policy.search.redact_secrets, maxChars: opts.policy.search.max_output_chars, hint: TRUNCATION_HINTS[name] });
        audit("xsearch.call", {
          tool: name,
          args: summarizeArgs(args),
          ok: !res.isError,
          chars: fin.text.length,
          truncated: Boolean(res.truncated) || fin.truncated,
          ms: Date.now() - t0,
          ...(error !== undefined && !(error instanceof VfsError || error instanceof ToolError) ? { error: scrub(String(error)) } : {}),
        });
        const result: CallToolResult = { content: [{ type: "text", text: fin.text }] };
        if (res.isError) result.isError = true;
        return result;
      }) as never,
    );
  };

  register("ListRepos", listReposShape, (a) => listRepos(sc, a));
  register("PrDiff", prDiffShape, (a) => prDiff(sc, a));
  register("Grep", grepShape, (a) => grep(sc, a as GrepArgs));
  register("Glob", globShape, (a) => glob(sc, a));
  register("Read", readShape, (a) => read(sc, a));
  return server;
}

/* ---------------------------------- main ---------------------------------- */

export const USAGE = "usage: xrepo search-mcp --ctx <dir> --pr <dir> [--mirror <dir>] [--policy-path <repo-relative path>]";

/**
 * `xrepo search-mcp`: serves MCP over stdio until stdin closes. Exit codes: 0 after a clean
 * shutdown, 1 startup failure, 2 usage error.
 */
export async function main(args: string[], io: { stdin?: Readable; stdout?: Writable } = {}): Promise<number> {
  let ctxDir: string;
  let prDir: string;
  let mirrorDir: string | undefined;
  let policyPath: string | undefined;
  try {
    const v = parseCli(args, {
      ctx: { type: "string", required: true },
      pr: { type: "string", required: true },
      mirror: { type: "string" },
      "policy-path": { type: "string" },
    });
    ctxDir = v.ctx as string;
    prDir = v.pr as string;
    mirrorDir = (v.mirror as string | undefined) || undefined;
    policyPath = (v["policy-path"] as string | undefined) || undefined;
    if (policyPath !== undefined) policyPathGlob(policyPath);
  } catch (e) {
    process.stderr.write(`xrepo search-mcp: ${(e as Error).message}\n${USAGE}\n`);
    return 2;
  }

  let server: McpServer;
  let ctx: PrContext;
  try {
    const policy = readResolvedPolicy(join(ctxDir, CTX_FILES.policy));
    ctx = readContext(ctxDir);
    if (policy.repo.toLowerCase() !== ctx.repo.toLowerCase()) {
      throw new Error(`resolved policy is for ${policy.repo} but the PR context is for ${ctx.repo}`);
    }
    let diffText = "";
    try {
      diffText = readFileSync(join(ctxDir, CTX_FILES.diff), "utf8");
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code !== "ENOENT") throw e;
      audit("xsearch.no_diff", { warning: `${CTX_FILES.diff} is missing; PrDiff will show no diffs` });
    }
    server = createSearchServer({ policy, ctx, diffText, prDir, mirrorDir, ...(policyPath ? { policyPath } : {}) });
  } catch (e) {
    audit("xsearch.start_failed", { error: e });
    process.stderr.write(`xrepo search-mcp: ${(e as Error).message}\n`);
    return 1;
  }

  const stdin = io.stdin ?? process.stdin;
  const transport = new StdioServerTransport(stdin, io.stdout ?? process.stdout);
  const closed = new Promise<void>((resolve) => {
    server.server.onclose = () => resolve();
  });
  // The stdio transport does not close on EOF by itself.
  const onEnd = (): void => {
    void server.close().catch(() => undefined);
  };
  stdin.once("end", onEnd);
  try {
    await server.connect(transport);
  } catch (e) {
    stdin.off("end", onEnd);
    audit("xsearch.start_failed", { error: e });
    process.stderr.write(`xrepo search-mcp: ${(e as Error).message}\n`);
    return 1;
  }
  audit("xsearch.start", { repo: ctx.repo, pr: ctx.number, tools: [...XSEARCH_TOOL_NAMES] });
  await closed;
  stdin.off("end", onEnd);
  audit("xsearch.stop", { repo: ctx.repo, pr: ctx.number });
  return 0;
}

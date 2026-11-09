/**
 * Policy manifest schema — the SHARED CONTRACT between prepare, the MCP servers and the publisher.
 *
 * The manifest is owned by devops and lives outside any PR-controlled checkout. Every field has a
 * safe default: an empty manifest yields a comment-only reviewer that cannot approve or block.
 */
import { z } from "zod";

export const SEVERITIES = ["info", "low", "medium", "high", "critical"] as const;
export const Severity = z.enum(SEVERITIES);
export type Severity = z.infer<typeof Severity>;

export function severityRank(s: Severity): number {
  return SEVERITIES.indexOf(s);
}

const RepoName = z
  .string()
  .regex(/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/, "expected owner/name");

const Glob = z.string().min(1).max(512);

export const DEFAULT_DENY_GLOBS = [
  "**/.env",
  "**/.env.*",
  "**/*.pem",
  "**/*.key",
  "**/*.p12",
  "**/*.pfx",
  "**/id_rsa*",
  "**/id_ed25519*",
  "**/.npmrc",
  "**/.pypirc",
  "**/.netrc",
  "**/secrets/**",
  "**/*.tfstate",
  "**/*.tfstate.*",
];

export const DEFAULT_EXCLUDE_GLOBS = [
  "**/node_modules/**",
  "**/vendor/**",
  "**/third_party/**",
  "**/dist/**",
  "**/build/**",
  "**/*.min.js",
  "**/*.min.css",
  "**/*.map",
  "**/package-lock.json",
  "**/yarn.lock",
  "**/pnpm-lock.yaml",
  "**/Cargo.lock",
  "**/go.sum",
  "**/poetry.lock",
  "**/*.snap",
];

/* ----------------------------- capabilities ----------------------------- */

export const InlineCommentsCap = z
  .object({
    enabled: z.boolean().default(true),
    max_comments: z.number().int().min(0).max(100).default(15),
    max_comment_chars: z.number().int().min(100).max(10000).default(1500),
    min_severity: Severity.default("low"),
    /** Allow GitHub ```suggestion blocks. */
    suggestions: z.boolean().default(true),
  })
  .strict();

export const SummaryCommentCap = z
  .object({
    enabled: z.boolean().default(true),
    /** sticky = one issue comment updated in place; review = body of the PR review. */
    mode: z.enum(["sticky", "review"]).default("sticky"),
    max_chars: z.number().int().min(200).max(60000).default(6000),
  })
  .strict();

export const ApproveCap = z
  .object({
    enabled: z.boolean().default(false),
    /** Approve only if no finding is above this severity. */
    max_severity_allowed: Severity.default("low"),
    /** Never approve when any changed file matches these globs. */
    never_paths: z.array(Glob).default([".github/**", "**/CODEOWNERS"]),
    max_changed_lines: z.number().int().min(0).default(400),
  })
  .strict();

export const BlockCap = z
  .object({
    enabled: z.boolean().default(false),
    /** review = REQUEST_CHANGES review; check = failing check-run; both = both. */
    method: z.enum(["review", "check", "both"]).default("check"),
    min_severity: Severity.default("high"),
  })
  .strict();

export const CheckCap = z
  .object({
    /** Always publish a check-run with the outcome (needed for block.method=check). */
    enabled: z.boolean().default(false),
    name: z.string().min(1).max(100).default("xrepo-review"),
  })
  .strict();

export const LabelsCap = z
  .object({
    enabled: z.boolean().default(false),
    allowed: z.array(z.string().min(1).max(50)).default([]),
  })
  .strict();

export const Capabilities = z
  .object({
    inline_comments: InlineCommentsCap.default({}),
    summary_comment: SummaryCommentCap.default({}),
    approve: ApproveCap.default({}),
    block: BlockCap.default({}),
    check: CheckCap.default({}),
    labels: LabelsCap.default({}),
  })
  .strict();
export type Capabilities = z.infer<typeof Capabilities>;

/* ------------------------------- search -------------------------------- */

export const SearchPolicy = z
  .object({
    /** Never readable, listed or searchable (secrets). Appended to DEFAULT_DENY_GLOBS. */
    deny_globs: z.array(Glob).default([]),
    /** Skipped by search/find unless explicitly targeted. Appended to DEFAULT_EXCLUDE_GLOBS. */
    exclude_globs: z.array(Glob).default([]),
    /** Replace default deny/exclude lists instead of appending (rarely wanted). */
    replace_defaults: z.boolean().default(false),
    redact_secrets: z.boolean().default(true),
    max_output_chars: z.number().int().min(1000).max(100000).default(12000),
    max_line_chars: z.number().int().min(80).max(2000).default(240),
    max_read_lines: z.number().int().min(20).max(5000).default(250),
    max_filesize: z.string().regex(/^\d+[KMG]?$/).default("1M"),
    timeout_ms: z.number().int().min(500).max(60000).default(8000),
  })
  .strict();
export type SearchPolicy = z.infer<typeof SearchPolicy>;

/* ----------------------------- cross-repo ------------------------------ */

export const CrossRepoPolicy = z
  .object({
    /**
     * Mirror repos readable while reviewing a PR of this repo. Supports "owner/*" and "*".
     * The PR head checkout ("@pr") is always readable.
     */
    readable: z.array(z.string().min(1)).default([]),
    /** Explicitly unreadable, wins over `readable`. */
    deny: z.array(z.string().min(1)).default([]),
    /**
     * Dependency hints injected into the prompt so the agent searches the right place first,
     * e.g. { "acme/web": "calls /orders API from src/api/orders.ts" }.
     */
    related: z.record(z.string(), z.string().max(500)).default({}),
  })
  .strict();

/* ------------------------------ triggers ------------------------------- */

export const TriggerPolicy = z
  .object({
    skip_drafts: z.boolean().default(true),
    skip_forks: z.boolean().default(true),
    skip_bots: z.boolean().default(true),
    ignore_authors: z.array(z.string()).default([]),
    skip_title_markers: z.array(z.string()).default(["[skip review]", "[no review]"]),
    max_changed_files: z.number().int().min(1).default(80),
    max_changed_lines: z.number().int().min(1).default(4000),
    /** Only review PRs that touch at least one of these globs (empty = all). */
    include_paths: z.array(Glob).default([]),
    /** Files matching these are not counted / not shown to the agent as changed. */
    ignore_paths: z.array(Glob).default([]),
  })
  .strict();

/* -------------------------------- agent -------------------------------- */

export const AgentPolicy = z
  .object({
    model: z.string().min(1).max(100).optional(),
    max_turns: z.number().int().min(1).max(200).default(40),
    /** Extra trusted review instructions appended to the built-in prompt. */
    instructions: z.string().max(20000).default(""),
    /** Review focus areas listed in the prompt. */
    focus: z
      .array(z.string().max(200))
      .default(["correctness", "security", "cross-repo contract breaks", "error handling"]),
    /** Language for review comments. */
    language: z.string().max(40).default("English"),
  })
  .strict();

/* -------------------------------- output ------------------------------- */

export const OutputPolicy = z
  .object({
    allow_mentions: z.boolean().default(false),
    allow_images: z.boolean().default(false),
    /** Hosts whose links are kept clickable. Others become plain text. */
    link_allowlist: z.array(z.string()).default(["github.com"]),
    /** Footer appended to the summary (trusted). */
    footer: z.string().max(500).default(""),
  })
  .strict();

/* ------------------------------ composition ---------------------------- */

/** Everything that can be set globally (`defaults`) or per repo (`repos.<owner/name>`). */
export const PolicyLayer = z
  .object({
    enabled: z.boolean().optional(),
    capabilities: Capabilities.deepPartial().optional(),
    search: SearchPolicy.partial().optional(),
    cross_repo: CrossRepoPolicy.partial().optional(),
    triggers: TriggerPolicy.partial().optional(),
    agent: AgentPolicy.partial().optional(),
    output: OutputPolicy.partial().optional(),
  })
  .strict();
export type PolicyLayer = z.infer<typeof PolicyLayer>;

export const MirrorPolicy = z
  .object({
    /** Repos to mirror. Exact owner/name, or "owner/*" (resolved via the GitHub API at sync). */
    repos: z.array(z.string().min(1)).default([]),
    exclude: z.array(z.string().min(1)).default([]),
    keep_snapshots: z.number().int().min(1).max(10).default(2),
    /** Skip archived repos / forks when expanding owner/* */
    skip_archived: z.boolean().default(true),
    skip_forks: z.boolean().default(true),
  })
  .strict();

export const PolicyFile = z
  .object({
    version: z.literal(1),
    defaults: PolicyLayer.default({}),
    repos: z.record(RepoName, PolicyLayer).default({}),
    mirror: MirrorPolicy.default({}),
  })
  .strict();
export type PolicyFile = z.infer<typeof PolicyFile>;

/** Fully-resolved policy for one repository (defaults <- repo override), all fields concrete. */
export const ResolvedPolicy = z
  .object({
    repo: RepoName,
    enabled: z.boolean(),
    capabilities: Capabilities,
    search: SearchPolicy,
    cross_repo: CrossRepoPolicy,
    triggers: TriggerPolicy,
    agent: AgentPolicy,
    output: OutputPolicy,
  })
  .strict();
export type ResolvedPolicy = z.infer<typeof ResolvedPolicy>;

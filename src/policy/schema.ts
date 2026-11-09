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
    max_output_chars: z.number().int().min(1000).max(100000).default(30000),
    max_line_chars: z.number().int().min(80).max(2000).default(2000),
    max_read_lines: z.number().int().min(20).max(5000).default(2000),
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
    /**
     * Extra Claude Code built-in tools to enable (all built-ins are disabled by default). Only
     * non-executing tools are accepted; shell/file-write/web tools can never be enabled here.
     */
    builtin_tools: z.array(z.enum(["Skill", "Task", "Agent", "TodoWrite"])).default([]),
    /** Plugin marketplaces (git URLs) and plugins (name@marketplace) passed to claude-code-action.
     *  Plugins are trusted code chosen by devops (they may ship skills, hooks and MCP servers). */
    plugin_marketplaces: z.array(z.string().url().max(500)).default([]),
    plugins: z.array(z.string().regex(/^[A-Za-z0-9_.-]+@[A-Za-z0-9_.-]+$/)).default([]),
    /** Optional slash command / skill to run as the review entry point (e.g. "/acme-review:review"). */
    entry_command: z.string().regex(/^\/[A-Za-z0-9_.:-]{1,100}$/).optional(),
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

/* ------------------------------- outcomes ------------------------------ */

/**
 * Every run ends in exactly one primary outcome; `approved` / `blocked` additionally fire after
 * `completed` when the published verdict is APPROVE / blocking.
 * - completed:   draft finished and published.
 * - incomplete:  agent ran but did not call finish() (max turns, crash mid-way); partial findings
 *                are published but never approve/block.
 * - usage_limit: subscription usage limit / API rate limit / quota / overload detected.
 * - error:       any other failure (action failed, cancelled, timeout, infrastructure).
 * - skipped:     prepare decided not to review (draft, fork, bot, size, kill switch...).
 */
export const OUTCOMES = ["completed", "approved", "blocked", "incomplete", "usage_limit", "error", "skipped"] as const;
export const OutcomeName = z.enum(OUTCOMES);
export type OutcomeName = z.infer<typeof OutcomeName>;

const LabelName = z.string().min(1).max(50);
const SecretKey = z.string().regex(/^[A-Za-z0-9_.-]{1,64}$/, "secret key: [A-Za-z0-9_.-]");

export const NotifyRef = z
  .object({
    /** Name of an entry in the top-level `notifications` map. */
    target: z.string().min(1).max(64),
    /** Message template; placeholders: {repo} {pr_number} {pr_url} {pr_title} {author} {outcome}
     *  {reason} {reset_at} {verdict} {findings} {top_severity} {run_url} {attempt}. */
    message: z.string().max(2000).optional(),
  })
  .strict();

export const OutcomeActions = z
  .object({
    /** Text for the sticky PR comment (template, same placeholders as notify). Empty = none. */
    comment: z.string().max(4000).default(""),
    /** Conclusion of the check-run (only if check.enabled or block uses a check). */
    check_conclusion: z.enum(["success", "neutral", "failure", "skipped", "action_required"]).optional(),
    /** Devops-configured labels (not limited by capabilities.labels.allowed). */
    add_labels: z.array(LabelName).default([]),
    remove_labels: z.array(LabelName).default([]),
    notify: z.array(NotifyRef).default([]),
    /** Send repository_dispatch {event_type} with an outcome payload (token: env XREPO_DISPATCH_TOKEN). */
    dispatch: z
      .object({
        /** owner/name; default = the PR repository. */
        repo: RepoName.optional(),
        event_type: z.string().regex(/^[A-Za-z0-9._:-]{1,100}$/),
      })
      .strict()
      .optional(),
    /** Mark the PR for automatic re-run by the `xrepo retry` sweeper (usage_limit / error only). */
    retry: z
      .object({
        enabled: z.boolean().default(false),
        max_attempts: z.number().int().min(1).max(10).default(3),
        label: LabelName.default("xrepo-review:retry"),
      })
      .strict()
      .optional(),
    /** Exit non-zero so the workflow run shows as failed (default false: never block on infra). */
    fail_job: z.boolean().default(false),
  })
  .strict();
export type OutcomeActions = z.infer<typeof OutcomeActions>;

/** Safe built-in defaults; manifests override per outcome (deep-merged). */
export const DEFAULT_OUTCOMES: Record<OutcomeName, Partial<z.input<typeof OutcomeActions>>> = {
  completed: {},
  approved: {},
  blocked: {},
  incomplete: {
    comment:
      "⚠️ The automated review did not finish ({reason}). Partial findings are shown; this review never approves or blocks.",
    check_conclusion: "neutral",
  },
  usage_limit: {
    comment:
      "⏸️ Automated review postponed: Claude usage limit reached{reset_at_suffix}. This does not block merging.",
    check_conclusion: "neutral",
  },
  error: {
    comment: "⚠️ Automated review could not run ({reason}). This does not block merging. [Run log]({run_url})",
    check_conclusion: "neutral",
  },
  skipped: { check_conclusion: "skipped" },
};

export const NotificationTarget = z
  .object({
    type: z.enum(["slack", "webhook"]),
    /**
     * Key of the URL inside the secrets bundle: env XREPO_NOTIFY_SECRETS (JSON object) or the file
     * /etc/xrepo-review/notify.json. URLs never appear in the manifest.
     */
    url_secret: SecretKey,
    /** webhook only: key of an HMAC-SHA256 secret; adds X-Xrepo-Signature: sha256=<hex>. */
    hmac_secret: SecretKey.optional(),
    /** Default message template when a NotifyRef has none. */
    template: z.string().max(2000).optional(),
    timeout_ms: z.number().int().min(500).max(30000).default(5000),
  })
  .strict();
export type NotificationTarget = z.infer<typeof NotificationTarget>;

export const ResolvedOutcomes = z
  .object({
    completed: OutcomeActions,
    approved: OutcomeActions,
    blocked: OutcomeActions,
    incomplete: OutcomeActions,
    usage_limit: OutcomeActions,
    error: OutcomeActions,
    skipped: OutcomeActions,
  })
  .strict();
export type ResolvedOutcomes = z.infer<typeof ResolvedOutcomes>;

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
    /** Per-outcome actions; each outcome object deep-merges over DEFAULT_OUTCOMES. */
    outcomes: z.record(OutcomeName, OutcomeActions.deepPartial()).optional(),
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
    /** Named notification targets (global). Referenced from outcomes.*.notify[].target. */
    notifications: z.record(z.string().regex(/^[A-Za-z0-9_.-]{1,64}$/), NotificationTarget).default({}),
  })
  .strict()
  .superRefine((file, ctx) => {
    // Every notify target referenced anywhere must exist (fail closed on typos).
    const layers: [string, PolicyLayer][] = [["defaults", file.defaults], ...Object.entries(file.repos)];
    for (const [where, layer] of layers) {
      for (const [outcome, actions] of Object.entries(layer.outcomes ?? {})) {
        for (const [i, ref] of (actions?.notify ?? []).entries()) {
          if (ref?.target && !(ref.target in file.notifications)) {
            ctx.addIssue({
              code: z.ZodIssueCode.custom,
              path: [where === "defaults" ? "defaults" : "repos", ...(where === "defaults" ? [] : [where]), "outcomes", outcome, "notify", i, "target"],
              message: `unknown notification target "${ref.target}"`,
            });
          }
        }
      }
    }
  });
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
    /** All 7 outcomes present, fully defaulted. */
    outcomes: ResolvedOutcomes,
    /** Copied from the policy file so the publisher has everything in one resolved file. */
    notifications: z.record(z.string(), NotificationTarget),
  })
  .strict();
export type ResolvedPolicy = z.infer<typeof ResolvedPolicy>;

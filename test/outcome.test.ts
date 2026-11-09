import { createHmac } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { Draft } from "../src/common/draft.js";
import { parsePolicy, resolvePolicy } from "../src/policy/load.js";
import type { NotificationTarget } from "../src/policy/schema.js";
import {
  classifyOutcome,
  matchesUsageLimit,
  parseExecutionMessages,
  parseResetAt,
  readExecutionFile,
} from "../src/outcome/classify.js";
import { DEFAULT_GITHUB_API_URL, githubApiBase, GitHubApiUrlError } from "../src/outcome/api-base.js";
import { buildDispatchPayload, repositoryDispatch } from "../src/outcome/dispatch.js";
import { buildWebhookPayload, loadNotifySecrets, sendNotifications, signWebhook } from "../src/outcome/notify.js";
import { resolveResetTime } from "../src/outcome/reset.js";
import {
  configuredRetryLabels,
  createRetryApi,
  decideRetry,
  defaultsPolicy,
  main as retryMain,
  MAX_DISCOVERY_QUERIES,
  MAX_RETRY_WAIT_MS,
  parseRetryAfterMarkers,
  parseRetryMarkers,
  policyOwners,
  RateLimitedError,
  retryAfterMarker,
  retryLimit,
  retryNotBefore,
  retryRules,
  retryStopMarker,
  retryTiming,
  sweep,
  sweepRepos,
  type RetryAfterMarker,
  type RetryApi,
  type RetryMarker,
  type WorkflowRunInfo,
} from "../src/outcome/retry.js";
import {
  breakFenceRuns,
  markdownEscaper,
  plainEscaper,
  renderTemplate,
  safeUrl,
  slackEscaper,
  TEMPLATE_PLACEHOLDERS,
} from "../src/outcome/template.js";

const Z = "​";
const tmp = mkdtempSync(join(tmpdir(), "xrepo-outcome-"));
afterAll(() => rmSync(tmp, { recursive: true, force: true }));

/* -------------------------------- fixtures -------------------------------- */

function draft(over: Partial<Draft> = {}): Draft {
  return { comments: [], labels: [], finished: false, invalidLines: 0, ...over };
}

const PARTIAL = draft({
  comments: [{ type: "comment", path: "a.ts", line: 1, body: "x", severity: "low" }],
});
const FINISHED = draft({ ...PARTIAL, finished: true });

const INIT = {
  type: "system",
  subtype: "init",
  session_id: "s1",
  tools: ["mcp__xsearch__Grep", "mcp__xreview__add_comment"],
  mcp_servers: [{ name: "xsearch", status: "connected" }],
  model: "claude-opus-5-5",
};

function assistantText(text: string): Record<string, unknown> {
  return {
    type: "assistant",
    message: { id: "m1", model: "claude-opus-5-5", role: "assistant", content: [{ type: "text", text }] },
    session_id: "s1",
  };
}

function toolUse(): Record<string, unknown> {
  return {
    type: "assistant",
    message: {
      model: "claude-opus-5-5",
      role: "assistant",
      content: [{ type: "tool_use", id: "t1", name: "mcp__xsearch__Grep", input: { pattern: "rate limit" } }],
    },
  };
}

function toolResult(text: string): Record<string, unknown> {
  return { type: "user", message: { role: "user", content: [{ type: "tool_result", tool_use_id: "t1", content: text }] } };
}

function result(over: Record<string, unknown>): Record<string, unknown> {
  return {
    type: "result",
    subtype: "success",
    is_error: false,
    duration_ms: 1200,
    duration_api_ms: 900,
    num_turns: 3,
    result: "Review recorded.",
    stop_reason: "end_turn",
    total_cost_usd: 0.12,
    usage: { input_tokens: 10, output_tokens: 20 },
    modelUsage: {},
    permission_denials: [],
    session_id: "s1",
    uuid: "u1",
    ...over,
  };
}

/** claude-code-action writes JSON.stringify(messages, null, 2). */
const pretty = (msgs: unknown[]): string => JSON.stringify(msgs, null, 2);
const jsonl = (msgs: unknown[]): string => msgs.map((m) => JSON.stringify(m)).join("\n");

const OAUTH_5H = "You've hit your 5-hour limit · resets 1:32pm (UTC)";
const OAUTH_WEEKLY = "You've hit your weekly limit · resets Nov 12, 11:33am (UTC)";

/* ------------------------------ classification ----------------------------- */

describe("classifyOutcome", () => {
  const cases: {
    name: string;
    input: Parameters<typeof classifyOutcome>[0];
    outcome: string;
    reason?: string | RegExp;
    reset_at?: string;
  }[] = [
    {
      name: "skipped wins over everything",
      input: { skipped: { reason: "draft PR" }, agentStepOutcome: "failure", draft: FINISHED },
      outcome: "skipped",
      reason: "draft PR",
    },
    {
      name: "OAuth 5-hour limit (CLI 2.1.319 result: success + is_error + 429)",
      input: {
        agentStepOutcome: "failure",
        executionFileText: pretty([
          INIT,
          {
            type: "assistant",
            message: { model: "<synthetic>", role: "assistant", content: [{ type: "text", text: OAUTH_5H }] },
            error: "rate_limit",
            api_error: "usage_limit_reached",
          },
          result({ is_error: true, num_turns: 1, total_cost_usd: 0, api_error_status: 429, terminal_reason: "api_error", result: OAUTH_5H }),
        ]),
      },
      outcome: "usage_limit",
      reason: OAUTH_5H,
      reset_at: "1:32pm (UTC)",
    },
    {
      name: "weekly limit with a rejected rate_limit_event",
      input: {
        agentStepOutcome: "failure",
        executionFileText: pretty([
          INIT,
          { type: "rate_limit_event", rate_limit_info: { status: "rejected", resetsAt: 1762947180, rateLimitType: "seven_day" } },
          result({ is_error: true, result: OAUTH_WEEKLY }),
        ]),
      },
      outcome: "usage_limit",
      reset_at: "Nov 12, 11:33am (UTC)",
    },
    {
      name: "legacy 'Claude AI usage limit reached|<epoch>' -> ISO reset",
      input: {
        agentStepOutcome: "failure",
        executionFileText: pretty([INIT, result({ is_error: true, result: "Claude AI usage limit reached|1753441200" })]),
      },
      outcome: "usage_limit",
      reset_at: "2025-07-25T11:00:00Z",
    },
    {
      name: "older 'You've hit your limit for Claude messages' wording",
      input: {
        executionFileText: pretty([
          INIT,
          result({ is_error: true, result: "You’ve hit your limit for Claude messages. Limits will reset at 9:30 AM." }),
        ]),
      },
      outcome: "usage_limit",
      reset_at: "9:30 AM",
    },
    {
      name: "JSON lines, crash without result: structured resetsAt from the synthetic message",
      input: {
        agentStepOutcome: "failure",
        executionFileText: jsonl([
          INIT,
          toolUse(),
          toolResult("ok"),
          {
            type: "assistant",
            message: { model: "<synthetic>", role: "assistant", content: [{ type: "text", text: "Usage credit limit" }] },
            error: "rate_limit",
            api_error: "usage_limit_reached",
            api_error_params: { rate_limit_info: { resetsAt: 1753441200 } },
          },
        ]),
      },
      outcome: "usage_limit",
      reset_at: "2025-07-25T11:00:00Z",
    },
    {
      name: "API key 429 after retries",
      input: {
        agentStepOutcome: "failure",
        executionFileText: pretty([
          INIT,
          { type: "system", subtype: "api_retry", attempt: 1, error: "rate_limit", error_status: 429 },
          result({ is_error: true, result: "API Error: Request rejected (429) · Number of request tokens has exceeded your rate limit" }),
        ]),
      },
      outcome: "usage_limit",
      reason: /^API Error: Request rejected \(429\)/,
    },
    {
      name: "credit balance too low",
      input: { executionFileText: pretty([INIT, result({ is_error: true, result: "Credit balance is too low" })]) },
      outcome: "usage_limit",
      reason: "Credit balance is too low",
    },
    {
      name: "overloaded (error_during_execution)",
      input: {
        executionFileText: pretty([INIT, result({ subtype: "error_during_execution", is_error: true, result: undefined, errors: ["API Error: 529 Overloaded"] })]),
      },
      outcome: "usage_limit",
    },
    {
      name: "retry the CLI recovered from is ignored",
      input: {
        agentStepOutcome: "success",
        draft: FINISHED,
        executionFileText: pretty([
          INIT,
          toolUse(),
          toolResult("ok"),
          { type: "system", subtype: "api_retry", attempt: 1, error: "rate_limit", error_status: 429 },
          assistantText("Continuing the review."),
          result({}),
        ]),
      },
      outcome: "completed",
      reason: "review finished",
    },
    {
      name: "a PR about rate limiting is not a usage limit",
      input: {
        agentStepOutcome: "success",
        draft: PARTIAL,
        executionFileText: pretty([
          INIT,
          toolUse(),
          toolResult("src/limits.ts:3: // HTTP 429 when the rate limit quota is exceeded"),
          assistantText("The rate limit check returns 429 too early; quota is overloaded."),
          result({ result: "Rate limit logic reviewed (429 / quota / overloaded)." }),
        ]),
      },
      outcome: "incomplete",
      reason: "the agent ended without calling finish()",
    },
    {
      name: "a finished review followed by a trailing overload error is still completed",
      input: {
        agentStepOutcome: "failure",
        draft: draft({
          comments: [{ type: "comment", path: "a.ts", line: 1, body: "x", severity: "critical" }],
          verdict: { type: "verdict", verdict: "request_changes", reason: "critical finding" },
          finished: true,
        }),
        executionFileText: pretty([
          INIT,
          toolUse(),
          toolResult("finished"),
          {
            type: "assistant",
            message: { model: "<synthetic>", role: "assistant", content: [{ type: "text", text: "API Error: 529 Overloaded" }] },
            error: "overloaded",
          },
          result({ subtype: "error_during_execution", is_error: true, result: undefined, api_error_status: 529, errors: ["API Error: 529 Overloaded"] }),
        ]),
      },
      outcome: "completed",
      reason: "review finished",
    },
    {
      name: "a number or word in a path inside errors[] is not a usage limit",
      input: {
        agentStepOutcome: "failure",
        executionFileText: pretty([
          INIT,
          result({ subtype: "error_during_execution", is_error: true, errors: ["ENOENT: src/quota/limits.ts line 429 not found (overloaded/rate_limit.ts)"] }),
        ]),
      },
      outcome: "error",
      reason: /^the agent failed during execution: ENOENT/,
    },
    {
      name: "finished draft -> completed",
      input: { agentStepOutcome: "success", draft: FINISHED, executionFileText: pretty([INIT, result({})]) },
      outcome: "completed",
    },
    {
      name: "max turns with partial draft -> incomplete",
      input: {
        agentStepOutcome: "failure",
        draft: PARTIAL,
        executionFileText: pretty([INIT, result({ subtype: "error_max_turns", is_error: true, result: undefined, errors: ["Reached maximum number of turns (40)"] })]),
      },
      outcome: "incomplete",
      reason: "maximum number of turns reached",
    },
    {
      name: "max turns with an empty draft is still incomplete",
      input: {
        agentStepOutcome: "failure",
        executionFileText: pretty([INIT, result({ subtype: "error_max_turns", is_error: true, errors: ["Reached maximum number of turns (1)"] })]),
      },
      outcome: "incomplete",
    },
    {
      name: "cancelled with a partial draft -> incomplete",
      input: { agentStepOutcome: "cancelled", draft: PARTIAL },
      outcome: "incomplete",
      reason: "the run was cancelled",
    },
    {
      name: "step failure, no execution file, no draft -> error",
      input: { agentStepOutcome: "failure" },
      outcome: "error",
      reason: "the Claude Code step failed",
    },
    {
      name: "garbage execution file -> error from the step outcome",
      input: { agentStepOutcome: "failure", executionFileText: "\u0000\u0001 not json {{{ ]] \"unterminated" },
      outcome: "error",
      reason: "the Claude Code step failed",
    },
    {
      name: "successful step but nothing recorded -> error 'no output'",
      input: { agentStepOutcome: "success", executionFileText: pretty([INIT, result({})]) },
      outcome: "error",
      reason: /^no output from the agent/,
    },
    {
      name: "nothing at all -> error 'no output'",
      input: {},
      outcome: "error",
      reason: "no output from the agent",
    },
    {
      name: "error_during_execution reason carries the first error, secrets redacted",
      input: {
        agentStepOutcome: "failure",
        executionFileText: pretty([
          INIT,
          result({ subtype: "error_during_execution", is_error: true, errors: [`MCP server crashed with token ghp_${"A1b2".repeat(9)}`] }),
        ]),
      },
      outcome: "error",
      reason: /^the agent failed during execution: MCP server crashed with token \[REDACTED:github_token\]$/,
    },
  ];

  for (const c of cases) {
    it(c.name, () => {
      const r = classifyOutcome(c.input);
      expect(r.outcome).toBe(c.outcome);
      if (typeof c.reason === "string") expect(r.reason).toBe(c.reason);
      else if (c.reason) expect(r.reason).toMatch(c.reason);
      if (c.reset_at !== undefined) expect(r.reset_at).toBe(c.reset_at);
      expect(r.reason.length).toBeLessThanOrEqual(300);
      expect(r.reason).not.toMatch(/[\n\r]/);
    });
  }

  it("never reports a reset when none is known", () => {
    const r = classifyOutcome({ executionFileText: pretty([INIT, result({ is_error: true, result: "Credit balance is too low" })]) });
    expect(r.reset_at).toBeUndefined();
  });

  it("recovers the result from a damaged file with the regex fallback", () => {
    const text =
      '[\n  {\n    "type": "system", "subtype": "init" broken\n  },\n  {\n    "type": "result",\n    "subtype": "success",\n' +
      '    "is_error": true,\n    "result": "You\'ve hit your limit · resets 2:50pm (America/Toronto)",\n    "session_id": "x"';
    const r = classifyOutcome({ agentStepOutcome: "failure", executionFileText: text });
    expect(r).toEqual({
      outcome: "usage_limit",
      reason: "You've hit your limit · resets 2:50pm (America/Toronto)",
      reset_at: "2:50pm (America/Toronto)",
    });
  });
});

describe("execution file parsing", () => {
  const msgs = [INIT, toolUse(), toolResult("x"), result({ is_error: true, result: OAUTH_5H, api_error_status: 429 })];

  it("parses a JSON array, JSON lines and a single object", () => {
    expect(parseExecutionMessages(pretty(msgs)).map((m) => m.type)).toEqual(["system", "assistant", "user", "result"]);
    expect(parseExecutionMessages(jsonl(msgs)).map((m) => m.type)).toEqual(["system", "assistant", "user", "result"]);
    expect(parseExecutionMessages(JSON.stringify(msgs[3])).map((m) => m.type)).toEqual(["result"]);
    expect(parseExecutionMessages("")).toEqual([]);
    expect(parseExecutionMessages(undefined)).toEqual([]);
    expect(parseExecutionMessages("garbage")).toEqual([]);
  });

  it("recovers whole messages from an array truncated at the front", () => {
    const text = pretty(msgs);
    const cut = text.slice(text.indexOf('"role"')); // starts mid-object
    const nl = cut.indexOf("\n");
    const types = parseExecutionMessages(cut.slice(nl + 1)).map((m) => m.type);
    expect(types).toContain("result");
  });

  it("reads only the tail of huge files and still classifies them", () => {
    const big = [INIT, ...Array.from({ length: 300 }, (_, i) => toolResult(`line ${i} ${"x".repeat(200)} "quoted {braces}"`)), ...msgs.slice(1)];
    const path = join(tmp, "exec-big.json");
    writeFileSync(path, pretty(big));
    const tail = readExecutionFile(path, 8192);
    expect(tail).toBeDefined();
    expect((tail ?? "").length).toBeLessThanOrEqual(8192);
    expect(classifyOutcome({ agentStepOutcome: "failure", executionFileText: tail })).toMatchObject({
      outcome: "usage_limit",
      reset_at: "1:32pm (UTC)",
    });
  });

  it("the regex fallback stays linear on hostile whitespace", () => {
    const hostile = `{"type": "result", "is_error": true, "errors": ["a"${" ".repeat(20000)}"b"${" ".repeat(20000)}`;
    const t0 = Date.now();
    parseExecutionMessages(hostile);
    expect(Date.now() - t0).toBeLessThan(1000);
  });

  it("returns undefined for a missing file or a directory", () => {
    expect(readExecutionFile(join(tmp, "nope.json"))).toBeUndefined();
    expect(readExecutionFile(tmp)).toBeUndefined();
  });
});

describe("usage-limit patterns and reset parsing", () => {
  it.each([
    [OAUTH_5H, "1:32pm (UTC)"],
    [OAUTH_WEEKLY, "Nov 12, 11:33am (UTC)"],
    ["You've hit your session limit · resets 3pm", "3pm"],
    ["Session limit reached ∙ resets 3pm", "3pm"],
    ["You've hit your limit · resets 2:50pm (America/Toronto)", "2:50pm (America/Toronto)"],
    ["Usage limit reached (resets 3pm)", "3pm"],
    ["Claude AI usage limit reached|1753441200", "2025-07-25T11:00:00Z"],
    ["Claude AI usage limit reached|1753441200000", "2025-07-25T11:00:00Z"],
    ["Credit balance is too low", undefined],
    [`You've hit your limit · resets ${"very long ".repeat(20)}`, undefined],
  ])("parseResetAt(%j)", (text, expected) => {
    const r = parseResetAt(text);
    if (expected === undefined && text.includes("very long")) {
      expect(r?.length).toBeLessThanOrEqual(80);
      expect(r?.endsWith("…")).toBe(true);
    } else expect(r).toBe(expected);
  });

  it.each([
    "You've hit your Opus limit · resets 5pm (UTC)",
    "You're out of usage credits",
    "Your org is out of usage credits",
    "Your seat type doesn't include usage credits",
    "Your usage allocation has been disabled by your admin",
    "Your group's usage limit is set to $0",
    "Fable 5 requires usage credits",
    "Weekly limit reached ∙ resets Mon 9am",
    "rate limit exceeded",
    "The request was rate limited.",
    "HTTP 429 Too Many Requests",
    "API Error: 429 {\"type\":\"error\",\"error\":{\"type\":\"rate_limit_error\",\"message\":\"This request would exceed your organization's rate limit of 40,000 input tokens per minute\"}}",
    "API Error: 529 status code (no body)",
    "API Error: 529 Overloaded",
    "API Error: Repeated 529 Overloaded errors",
    'API Error: 529 {"type":"error","error":{"type":"overloaded_error","message":"Overloaded"}}',
    'API Error: {"type":"error","error":{"details":null,"type":"overloaded_error","message":"Overloaded"},"request_id":null}',
    "You have reached your specified API usage limits. You will regain access on 2026-12-01 at 00:00 UTC.",
    "Credit balance is too low",
  ])("matches %j", (text) => {
    expect(matchesUsageLimit(text)).toBe(true);
  });

  it("does not match ordinary failures", () => {
    for (const t of [
      "Reached maximum number of turns (40)",
      "MCP server xsearch failed to start",
      "Invalid API key",
      "src/quota/limits.ts line 429 not found",
      "cannot read src/rate_limit/overloaded.ts (529 bytes)",
      "src/usage_limit.ts: syntax error",
      "ENOENT: no such file or directory, open 'src/errors/overloaded_error.ts'",
    ]) {
      expect(matchesUsageLimit(t)).toBe(false);
    }
  });

  it("a failed run whose message only mentions rate limit / usage limit / limit reached is an error", () => {
    for (const t of [
      "Cannot find module 'src/rate limit/index.ts'",
      "TypeError: usageLimit is undefined in checkUsageLimit (src/usage limit.ts:12)",
      "Error: limit reached flag never set in src/limitReached.ts",
      "The PR adds a rate limit to /login but the review could not finish",
      "Reviewing the usage limit banner: MCP server xsearch failed to start",
      "Assertion failed: retry limit reached before the mock answered",
      "API error handling for 429 responses lives in src/http.ts; tool call failed",
      "quota exceeded check in src/billing.ts throws on null",
      "API Error: 500 Internal server error",
      "API Error: 4290 unknown",
      "Error: session limit of 5 exceeded in src/session.ts",
      "the weekly limit banner test failed: MCP server xsearch failed to start",
      "Error: daily limit reached for free-tier users (tests/quota.spec.ts)",
      "monthly limit reached flag is never reset in src/billing.ts",
    ]) {
      const cls = classifyOutcome({ agentStepOutcome: "failure", executionFileText: pretty([INIT, result({ is_error: true, result: t })]) });
      expect(cls.outcome, t).toBe("error");
    }
  });

  it("the module's own 'rate limit rejected' evidence text is preferred as the reason", () => {
    const cls = classifyOutcome({
      agentStepOutcome: "failure",
      executionFileText: jsonl([
        INIT,
        { type: "rate_limit_event", rate_limit_info: { status: "rejected", rateLimitType: "five_hour" } },
        { type: "assistant", message: { model: "<synthetic>", role: "assistant", content: [{ type: "text", text: "Usage credit limit" }] }, error: "rate_limit" },
      ]),
    });
    expect(cls).toMatchObject({ outcome: "usage_limit", reason: "rate limit rejected (five_hour)" });
  });
});

/* -------------------------------- templates -------------------------------- */

describe("renderTemplate", () => {
  const id = (s: string): string => s;

  it("substitutes every documented placeholder and leaves unknown ones", () => {
    const vars = {
      repo: "acme/web",
      pr_number: 42,
      pr_url: "https://github.com/acme/web/pull/42",
      pr_title: "Add orders",
      author: "alice",
      outcome: "usage_limit",
      reason: "limit",
      reset_at: "3pm",
      verdict: "comment",
      findings: 0,
      top_severity: "high",
      run_url: "https://github.com/acme/web/actions/runs/1",
      attempt: 2,
    };
    const tpl = TEMPLATE_PLACEHOLDERS.map((p) => `{${p}}`).join("|") + "|{unknown}|{REPO}|{ repo }";
    expect(renderTemplate(tpl, vars, id)).toBe(
      "acme/web|42|https://github.com/acme/web/pull/42|Add orders|alice|usage_limit|limit|3pm|comment|0|high|" +
        "https://github.com/acme/web/actions/runs/1|2| (resets 3pm)|{unknown}|{REPO}|{ repo }",
    );
  });

  it("does not re-expand placeholders inside values", () => {
    expect(renderTemplate("{pr_title} / {repo}", { pr_title: "{repo} {reason_suffix}", repo: "acme/web" }, id)).toBe("{repo} {reason_suffix} / acme/web");
  });

  it("missing values render as empty; {reset_at_suffix} is empty without a reset", () => {
    expect(renderTemplate("a{reason}b{reset_at_suffix}c", {}, id)).toBe("abc");
    expect(renderTemplate("x{reset_at_suffix}", { reset_at: "  " }, id)).toBe("x");
  });

  it("escapes values, never the template", () => {
    const shout = (s: string): string => s.toUpperCase();
    expect(renderTemplate("<!here> {author}", { author: "bob" }, shout)).toBe("<!here> BOB");
  });

  it("markdown escaping neutralizes images, links, mentions, HTML and newlines in values", () => {
    const esc = markdownEscaper({ linkAllowlist: ["github.com"] });
    const out = renderTemplate("Title: {pr_title}", { pr_title: "Fix @octocat ![x](https://evil.example/a.png)\n# heading <img src=x> [c](https://evil.example)" }, esc);
    expect(out).not.toMatch(/!\[/);
    expect(out).not.toContain("<img");
    expect(out).not.toContain("](https://evil");
    expect(out).toContain(`@${Z}octocat`);
    expect(out).not.toContain("\n");
    expect(renderTemplate("{reason}", { reason: `token ghp_${"A1b2".repeat(9)}` }, esc)).toBe("token [REDACTED:github_token]");
  });

  it("URL placeholders must be plain http(s) URLs", () => {
    const esc = markdownEscaper({ linkAllowlist: [] });
    expect(renderTemplate("[log]({run_url})", { run_url: "https://ghe.example.com/acme/web/actions/runs/1" }, esc)).toBe(
      "[log](https://ghe.example.com/acme/web/actions/runs/1)",
    );
    expect(renderTemplate("[log]({run_url})", { run_url: "javascript:alert(1)" }, esc)).toBe("[log]()");
    expect(renderTemplate("[log]({run_url})", { run_url: "https://x.example/a) [y](https://evil" }, esc)).toBe("[log]()");
    expect(safeUrl("https://user:pw@github.com/x")).toBe("");
  });

  it("slack escaping prevents broadcast mentions and link injection", () => {
    const out = renderTemplate("<!here> {pr_title} by {author}", { pr_title: "<!channel> & <https://evil|click>", author: "@everyone" }, slackEscaper());
    expect(out.startsWith("<!here> ")).toBe(true); // trusted template untouched
    expect(out).toContain("&lt;!channel&gt; &amp; &lt;https://evil|click&gt;");
    expect(out).toContain(`@${Z}everyone`);
    expect(renderTemplate("{reason}", { reason: "x".repeat(2000) }, slackEscaper(100)).length).toBeLessThanOrEqual(100);
  });

  it("plain escaping redacts secrets and flattens control characters", () => {
    expect(renderTemplate("{reason}", { reason: `a\nb\u0007c sk-ant-api03-${"x1".repeat(40)}` }, plainEscaper())).toMatch(/^a b c \[REDACTED/);
  });
});

/* ------------------------------ notifications ------------------------------ */

interface FetchCall {
  url: string;
  init: RequestInit;
}

function fakeFetch(respond: (call: FetchCall) => Response | Promise<Response> = () => new Response("ok", { status: 200 })) {
  const calls: FetchCall[] = [];
  const impl = (async (input: string | URL | Request, init?: RequestInit) => {
    const call = { url: String(input), init: init ?? {} };
    calls.push(call);
    return respond(call);
  }) as typeof fetch;
  return { calls, impl };
}

const SLACK_URL = "https://hooks.slack.example/services/T000/B000/SECRETPATH";
const HOOK_URL = "https://hooks.example.com/xrepo/SECRETHOOK";

const TARGETS: Record<string, NotificationTarget> = {
  slack: { type: "slack", url_secret: "SLACK_URL", template: "Review {outcome} on {repo}#{pr_number}: {pr_title}", timeout_ms: 5000 },
  hook: { type: "webhook", url_secret: "HOOK_URL", hmac_secret: "HOOK_KEY", timeout_ms: 5000 },
  plainhook: { type: "webhook", url_secret: "HOOK_URL", timeout_ms: 1000 },
  insecure: { type: "slack", url_secret: "HTTP_URL", timeout_ms: 5000 },
  missing: { type: "slack", url_secret: "NOPE", timeout_ms: 5000 },
};
const SECRETS = { SLACK_URL, HOOK_URL, HOOK_KEY: "k3y", HTTP_URL: "http://hooks.example.com/x" };
const VARS = {
  repo: "acme/web",
  pr_number: 42,
  pr_url: "https://github.com/acme/web/pull/42",
  pr_title: "<!channel> pwn",
  author: "alice",
  outcome: "usage_limit",
  reason: "You've hit your 5-hour limit",
  reset_at: "1:32pm (UTC)",
  verdict: undefined,
  findings: 0,
  top_severity: undefined,
  run_url: "https://github.com/acme/web/actions/runs/7",
  attempt: 1,
};

describe("sendNotifications", () => {
  let stderr: string[];
  beforeEach(() => {
    stderr = [];
    vi.spyOn(process.stderr, "write").mockImplementation((chunk: string | Uint8Array) => {
      stderr.push(String(chunk));
      return true;
    });
  });
  afterEach(() => vi.restoreAllMocks());

  it("posts {text} to Slack with escaped values, https only, no redirects", async () => {
    const f = fakeFetch();
    const [r] = await sendNotifications([{ target: "slack" }], TARGETS, VARS, SECRETS, f.impl);
    expect(r).toMatchObject({ target: "slack", type: "slack", ok: true, status: 200 });
    expect(f.calls).toHaveLength(1);
    const call = f.calls[0]!;
    expect(call.url).toBe(SLACK_URL);
    expect(call.init.method).toBe("POST");
    expect(call.init.redirect).toBe("manual");
    expect(call.init.signal).toBeInstanceOf(AbortSignal);
    expect(JSON.parse(String(call.init.body))).toEqual({ text: "Review usage_limit on acme/web#42: &lt;!channel&gt; pwn" });
    expect(stderr.join("")).not.toContain("SECRETPATH");
  });

  it("a NotifyRef message overrides the target template", async () => {
    const f = fakeFetch();
    await sendNotifications([{ target: "slack", message: "postponed{reset_at_suffix}" }], TARGETS, VARS, SECRETS, f.impl);
    expect(JSON.parse(String(f.calls[0]!.init.body))).toEqual({ text: "postponed (resets 1:32pm (UTC))" });
  });

  it("posts the webhook JSON with a verifiable HMAC signature", async () => {
    const f = fakeFetch(() => new Response(null, { status: 204 }));
    const [r] = await sendNotifications([{ target: "hook" }], TARGETS, VARS, SECRETS, f.impl, { nowSeconds: () => 1700000000.9 });
    expect(r?.ok).toBe(true);
    const call = f.calls[0]!;
    const headers = call.init.headers as Record<string, string>;
    const body = String(call.init.body);
    expect(headers["x-xrepo-timestamp"]).toBe("1700000000");
    const expected = `sha256=${createHmac("sha256", "k3y").update(`1700000000.${body}`).digest("hex")}`;
    expect(headers["x-xrepo-signature"]).toBe(expected);
    expect(signWebhook("k3y", "1700000000", body)).toBe(expected);
    const payload = JSON.parse(body);
    expect(Object.keys(payload)).toEqual([
      "event",
      "outcome",
      "repo",
      "pr_number",
      "pr_url",
      "verdict",
      "reason",
      "reset_at",
      "findings",
      "top_severity",
      "run_url",
      "attempt",
      "message",
    ]);
    expect(payload).toMatchObject({
      event: "xrepo-review",
      outcome: "usage_limit",
      repo: "acme/web",
      pr_number: 42,
      verdict: null,
      findings: 0,
      attempt: 1,
      reset_at: "1:32pm (UTC)",
    });
    expect(payload.message).toContain("xrepo-review usage_limit for acme/web#42");
  });

  it("no signature headers without hmac_secret", async () => {
    const f = fakeFetch();
    await sendNotifications([{ target: "plainhook" }], TARGETS, VARS, SECRETS, f.impl);
    const headers = f.calls[0]!.init.headers as Record<string, string>;
    expect(headers["x-xrepo-signature"]).toBeUndefined();
  });

  it("refuses http URLs, unknown targets and missing secrets without calling fetch", async () => {
    const f = fakeFetch();
    const rs = await sendNotifications(
      [{ target: "insecure" }, { target: "missing" }, { target: "ghost" }],
      TARGETS,
      VARS,
      SECRETS,
      f.impl,
    );
    expect(f.calls).toHaveLength(0);
    expect(rs.map((r) => r.ok)).toEqual([false, false, false]);
    expect(rs[0]?.error).toMatch(/https/);
    expect(rs[1]?.error).toMatch(/secret "NOPE" not found/);
    expect(rs[2]?.error).toMatch(/unknown/);
    expect(await sendNotifications([{ target: "hook" }], TARGETS, VARS, { HOOK_URL }, f.impl)).toMatchObject([
      { ok: false, error: 'hmac secret "HOOK_KEY" not found' },
    ]);
    expect(f.calls).toHaveLength(0);
  });

  it("reports HTTP errors, redirects, network errors and timeouts without leaking the URL", async () => {
    const statuses = [500, 302];
    let i = 0;
    const f = fakeFetch(() => new Response("", { status: statuses[i++] ?? 200, headers: { location: "https://elsewhere" } }));
    const rs = await sendNotifications([{ target: "slack" }, { target: "slack" }], TARGETS, VARS, SECRETS, f.impl);
    expect(rs.map((r) => r.error).sort()).toEqual(["HTTP 500", "redirect refused"]);

    const boom = (async () => {
      throw Object.assign(new TypeError(`fetch failed for ${SLACK_URL}`), { cause: { code: "ECONNREFUSED" } });
    }) as typeof fetch;
    const [netErr] = await sendNotifications([{ target: "slack" }], TARGETS, VARS, SECRETS, boom);
    expect(netErr).toMatchObject({ ok: false, error: "TypeError (ECONNREFUSED)" });

    const slow = ((_: unknown, init?: RequestInit) =>
      new Promise((_resolve, reject) => {
        init?.signal?.addEventListener("abort", () => reject(init.signal?.reason));
      })) as typeof fetch;
    const [timeout] = await sendNotifications([{ target: "plainhook" }], TARGETS, VARS, SECRETS, slow);
    expect(timeout).toMatchObject({ ok: false, error: "timeout after 1000ms" });

    const syncThrow = (() => {
      throw new Error(SLACK_URL);
    }) as unknown as typeof fetch;
    await expect(sendNotifications([{ target: "slack" }], TARGETS, VARS, SECRETS, syncThrow)).resolves.toMatchObject([{ ok: false }]);

    const log = stderr.join("");
    expect(log).toContain("notify.failed");
    expect(log).not.toContain("SECRETPATH");
    expect(log).not.toContain("hooks.slack.example");
  });

  it("buildWebhookPayload normalizes values", () => {
    const p = buildWebhookPayload({ pr_number: "12", findings: "3", pr_url: "javascript:x", reason: "a\nb" }, "m");
    expect(p).toMatchObject({ pr_number: 12, findings: 3, pr_url: null, reason: "a b", message: "m", repo: null });
  });
});

describe("loadNotifySecrets", () => {
  beforeEach(() => {
    vi.spyOn(process.stderr, "write").mockImplementation(() => true);
  });
  afterEach(() => vi.restoreAllMocks());

  it("prefers the env bundle and keeps only string values", () => {
    const s = loadNotifySecrets({ env: { XREPO_NOTIFY_SECRETS: JSON.stringify({ A: "1", B: 2, C: "3" }) }, file: join(tmp, "none.json") });
    expect({ ...s }).toEqual({ A: "1", C: "3" });
  });

  it("falls back to the file when the env is unset or invalid", () => {
    const file = join(tmp, "notify.json");
    writeFileSync(file, JSON.stringify({ SLACK_URL: "https://x" }));
    expect({ ...loadNotifySecrets({ env: {}, file }) }).toEqual({ SLACK_URL: "https://x" });
    expect({ ...loadNotifySecrets({ env: { XREPO_NOTIFY_SECRETS: "{not json" }, file }) }).toEqual({ SLACK_URL: "https://x" });
  });

  it("returns {} when nothing is available", () => {
    expect({ ...loadNotifySecrets({ env: {}, file: join(tmp, "absent.json") }) }).toEqual({});
    const bad = join(tmp, "bad.json");
    writeFileSync(bad, "[1,2]");
    expect({ ...loadNotifySecrets({ env: {}, file: bad }) }).toEqual({});
  });
});

/* -------------------------------- dispatch -------------------------------- */

describe("repository_dispatch", () => {
  beforeEach(() => {
    vi.spyOn(process.stderr, "write").mockImplementation(() => true);
  });
  afterEach(() => vi.restoreAllMocks());

  const payload = buildDispatchPayload({ ...VARS, verdict: "comment", findings: 2, top_severity: "high" }, { head_sha: "a".repeat(40) });

  it("payload has at most 10 top-level keys", () => {
    expect(Object.keys(payload)).toHaveLength(10);
    expect(payload).toMatchObject({ outcome: "usage_limit", pr_number: 42, head_sha: "a".repeat(40), review: { verdict: "comment", findings: 2, top_severity: "high" } });
  });

  it("uses XREPO_DISPATCH_TOKEN for any repository", async () => {
    const f = fakeFetch(() => new Response(null, { status: 204 }));
    const r = await repositoryDispatch(
      { repo: "acme/deploys", event_type: "xrepo-review.usage_limit" },
      { prRepo: "acme/web", client_payload: payload, env: { XREPO_DISPATCH_TOKEN: "dtok", GITHUB_TOKEN: "gtok" }, fetchImpl: f.impl },
    );
    expect(r).toMatchObject({ ok: true, via: "dispatch_token", status: 204, repo: "acme/deploys" });
    expect(f.calls[0]!.url).toBe("https://api.github.com/repos/acme/deploys/dispatches");
    expect((f.calls[0]!.init.headers as Record<string, string>).authorization).toBe("Bearer dtok");
    expect(JSON.parse(String(f.calls[0]!.init.body))).toEqual({ event_type: "xrepo-review.usage_limit", client_payload: payload });
  });

  it("honours GITHUB_API_URL", async () => {
    const f = fakeFetch(() => new Response(null, { status: 204 }));
    await repositoryDispatch(
      { event_type: "x" },
      { prRepo: "acme/web", client_payload: {}, env: { XREPO_DISPATCH_TOKEN: "t", GITHUB_API_URL: "https://ghe.example.com/api/v3/" }, fetchImpl: f.impl },
    );
    expect(f.calls[0]!.url).toBe("https://ghe.example.com/api/v3/repos/acme/web/dispatches");
  });

  it("falls back to the publisher client / GITHUB_TOKEN only for the PR repository", async () => {
    const api = { repositoryDispatch: vi.fn(async () => undefined) };
    const f = fakeFetch(() => new Response(null, { status: 204 }));
    expect(await repositoryDispatch({ event_type: "x" }, { prRepo: "acme/web", client_payload: {}, api, env: {}, fetchImpl: f.impl })).toMatchObject({ ok: true, via: "api" });
    expect(api.repositoryDispatch).toHaveBeenCalledWith("acme/web", "x", {});

    expect(
      await repositoryDispatch({ repo: "ACME/Web", event_type: "x" }, { prRepo: "acme/web", client_payload: {}, env: { GITHUB_TOKEN: "g" }, fetchImpl: f.impl }),
    ).toMatchObject({ ok: true, via: "github_token" });

    const cross = await repositoryDispatch({ repo: "acme/other", event_type: "x" }, { prRepo: "acme/web", client_payload: {}, api, env: { GITHUB_TOKEN: "g" }, fetchImpl: f.impl });
    expect(cross).toMatchObject({ ok: false, error: expect.stringMatching(/XREPO_DISPATCH_TOKEN is required/) });
    expect(await repositoryDispatch({ event_type: "x" }, { prRepo: "acme/web", client_payload: {}, env: {}, fetchImpl: f.impl })).toMatchObject({ ok: false });
    expect(f.calls).toHaveLength(1);
    expect(api.repositoryDispatch).toHaveBeenCalledTimes(1);
  });

  it("reports API errors and oversized payloads, never throws", async () => {
    const f = fakeFetch(() => new Response(JSON.stringify({ message: "Resource not accessible by integration" }), { status: 403 }));
    expect(await repositoryDispatch({ event_type: "x" }, { prRepo: "acme/web", client_payload: {}, env: { XREPO_DISPATCH_TOKEN: "t" }, fetchImpl: f.impl })).toMatchObject({
      ok: false,
      status: 403,
      error: "HTTP 403: Resource not accessible by integration",
    });
    const eleven = Object.fromEntries(Array.from({ length: 11 }, (_, i) => [`k${i}`, i]));
    expect(await repositoryDispatch({ event_type: "x" }, { prRepo: "acme/web", client_payload: eleven, env: { XREPO_DISPATCH_TOKEN: "t" }, fetchImpl: f.impl })).toMatchObject({
      ok: false,
      error: expect.stringMatching(/10 top-level keys/),
    });
    const api = { repositoryDispatch: vi.fn(async () => Promise.reject(Object.assign(new Error("Not Found"), { status: 404 }))) };
    expect(await repositoryDispatch({ event_type: "x" }, { prRepo: "acme/web", client_payload: {}, api, env: {} })).toMatchObject({ ok: false, status: 404, via: "api" });
    expect(await repositoryDispatch({ event_type: "bad type!" }, { prRepo: "acme/web", client_payload: {}, env: {} })).toMatchObject({ ok: false, error: "invalid event_type" });
  });
});

/* ---------------------------------- retry ---------------------------------- */

const RETRY_POLICY = parsePolicy(`
version: 1
defaults:
  outcomes:
    usage_limit:
      retry: { enabled: true, max_attempts: 3 }
    error:
      retry: { enabled: true, max_attempts: 2, label: "xrepo-review:retry" }
    incomplete:
      retry: { enabled: false, label: "xrepo:stale" }
repos:
  acme/web: {}
  acme/api:
    outcomes:
      usage_limit:
        retry: { enabled: true, max_attempts: 5, label: "review-later" }
  acme/off:
    enabled: false
mirror:
  repos: ["acme/web", "acme/lib", "acme/*"]
`);

describe("retry rules and decisions", () => {
  it("unions enabled retry labels, keeping the largest and the smallest max_attempts", () => {
    expect(retryRules(resolvePolicy(RETRY_POLICY, "acme/web"))).toEqual([{ label: "xrepo-review:retry", max_attempts: 3, unmarked_max_attempts: 2 }]);
    expect(retryRules(resolvePolicy(RETRY_POLICY, "acme/api"))).toEqual([
      { label: "review-later", max_attempts: 5, unmarked_max_attempts: 5 },
      { label: "xrepo-review:retry", max_attempts: 2, unmarked_max_attempts: 2 },
    ]);
    expect(configuredRetryLabels(resolvePolicy(RETRY_POLICY, "acme/web"))).toEqual(["xrepo:stale", "xrepo-review:retry"]);
  });

  const run = (over: Partial<WorkflowRunInfo>): WorkflowRunInfo => ({ id: 9, run_attempt: 1, status: "completed", conclusion: "success", ...over });
  it.each([
    [undefined, 3, "none"],
    [run({ status: "in_progress" }), 3, "wait"],
    [run({ status: "queued" }), 3, "wait"],
    [run({ run_attempt: 1 }), 3, "rerun"],
    [run({ run_attempt: 2 }), 3, "rerun"],
    [run({ run_attempt: 3 }), 3, "give_up"],
    [run({ run_attempt: 4 }), 3, "give_up"],
    [run({ run_attempt: 1 }), 1, "give_up"],
  ] as const)("decideRetry(%j, %d) -> %s", (r, max, action) => {
    expect(decideRetry(r, max).action).toBe(action);
  });
});

interface FakeRetryState {
  pulls: Record<string, { number: number; labels: string[]; head?: string }[]>;
  runs: Record<string, WorkflowRunInfo | undefined>;
  calls: string[];
  failOn?: string;
  rateLimitOn?: string;
}

function fakeRetryApi(state: FakeRetryState): RetryApi {
  const check = (what: string): void => {
    state.calls.push(what);
    if (state.rateLimitOn && what.startsWith(state.rateLimitOn)) throw new RateLimitedError("rate limited");
    if (state.failOn && what.startsWith(state.failOn)) throw Object.assign(new Error("boom"), { status: 500 });
  };
  return {
    async listOpenPullsWithLabel(repo, label) {
      check(`list ${repo} ${label}`);
      return (state.pulls[repo] ?? []).filter((p) => p.labels.some((l) => l.toLowerCase() === label.toLowerCase())).map((p) => ({ number: p.number, labels: p.labels }));
    },
    async getPullHeadSha(repo, pr) {
      check(`get ${repo}#${pr}`);
      return (state.pulls[repo] ?? []).find((p) => p.number === pr)?.head;
    },
    async latestWorkflowRun(repo, workflow, sha) {
      check(`runs ${repo} ${workflow} ${sha}`);
      return state.runs[sha];
    },
    async rerunWorkflow(repo, id) {
      check(`rerun ${repo} ${id}`);
    },
    async removeLabel(repo, pr, label) {
      check(`unlabel ${repo}#${pr} ${label}`);
    },
    async createComment(repo, pr, body) {
      check(`comment ${repo}#${pr} ${body.includes("<!-- xrepo-review:retry-exhausted -->") ? "exhausted" : "other"}`);
    },
  };
}

function retryState(): FakeRetryState {
  return {
    pulls: {
      "acme/web": [
        { number: 1, labels: ["bug", "xrepo-review:retry"], head: "s1" },
        { number: 2, labels: ["XREPO-REVIEW:RETRY"], head: "s2" },
        { number: 3, labels: ["xrepo-review:retry"], head: "s3" },
        { number: 4, labels: ["xrepo-review:retry"], head: "s4" },
        { number: 5, labels: ["xrepo-review:retry"] }, // closed
        { number: 6, labels: ["unrelated"], head: "s6" },
      ],
      "acme/api": [{ number: 7, labels: ["review-later", "xrepo-review:retry"], head: "s7" }],
    },
    runs: {
      s1: { id: 101, run_attempt: 1, status: "completed", conclusion: "success" },
      s2: { id: 102, run_attempt: 1, status: "in_progress" },
      s3: { id: 103, run_attempt: 3, status: "completed", conclusion: "success", html_url: "https://github.com/acme/web/actions/runs/103" },
      s7: { id: 107, run_attempt: 4, status: "completed", conclusion: "success" },
    },
    calls: [],
  };
}

describe("retry sweep", () => {
  beforeEach(() => {
    vi.spyOn(process.stderr, "write").mockImplementation(() => true);
  });
  afterEach(() => vi.restoreAllMocks());

  it("re-runs, waits, gives up (label first, then one comment) and skips", async () => {
    const state = retryState();
    const sleeps: number[] = [];
    const report = await sweep({
      policy: RETRY_POLICY,
      workflow: "xrepo-review.yml",
      dryRun: false,
      api: fakeRetryApi(state),
      sleep: async (ms) => {
        sleeps.push(ms);
      },
    });
    expect(report.repos).toEqual(["acme/web", "acme/api", "acme/off", "acme/lib"]);
    const byPr = Object.fromEntries(report.actions.map((a) => [`${a.repo}#${a.pr}`, a.decision.action]));
    expect(byPr).toEqual({
      "acme/web#1": "rerun",
      "acme/web#2": "wait",
      "acme/web#3": "give_up",
      "acme/web#4": "none",
      "acme/web#5": "none",
      "acme/api#7": "rerun", // review-later allows 5 attempts
    });
    const writes = state.calls.filter((c) => /^(rerun|unlabel|comment)/.test(c));
    expect(writes).toEqual([
      "rerun acme/web 101",
      "unlabel acme/web#3 xrepo-review:retry",
      "comment acme/web#3 exhausted",
      "rerun acme/api 107",
    ]);
    expect(sleeps.length).toBe(writes.length - 1);
    expect(state.calls.some((c) => c.startsWith("list acme/off"))).toBe(false); // disabled repo
    expect(report.errors).toEqual([]);
    expect(report.rate_limited).toBe(false);
  });

  it("dry-run reads but never writes", async () => {
    const state = retryState();
    const report = await sweep({ policy: RETRY_POLICY, workflow: "xrepo-review.yml", dryRun: true, api: fakeRetryApi(state), writeDelayMs: 0 });
    expect(state.calls.filter((c) => /^(rerun|unlabel|comment)/.test(c))).toEqual([]);
    expect(report.actions.find((a) => a.pr === 1)).toMatchObject({ done: false, decision: { action: "rerun", run_id: 101 } });
  });

  it("does not comment when the label removal fails", async () => {
    const state = { ...retryState(), failOn: "unlabel" };
    const report = await sweep({ policy: RETRY_POLICY, workflow: "xrepo-review.yml", repos: ["acme/web"], dryRun: false, api: fakeRetryApi(state), writeDelayMs: 0 });
    expect(state.calls.some((c) => c.startsWith("comment"))).toBe(false);
    expect(report.errors).toEqual(["acme/web#3: HTTP 500: boom"]);
  });

  it("removes a retry label once, with the PR's own spelling", async () => {
    const state: FakeRetryState = {
      pulls: { "acme/web": [{ number: 8, labels: ["XRepo-Review:Retry"], head: "s8" }] },
      runs: { s8: { id: 108, run_attempt: 3, status: "completed" } },
      calls: [],
    };
    await sweep({ policy: RETRY_POLICY, workflow: "xrepo-review.yml", repos: ["acme/web"], dryRun: false, api: fakeRetryApi(state), writeDelayMs: 0 });
    expect(state.calls.filter((c) => /^(unlabel|comment)/.test(c))).toEqual(["unlabel acme/web#8 XRepo-Review:Retry", "comment acme/web#8 exhausted"]);
  });

  it("stops cleanly on a rate limit", async () => {
    const state = { ...retryState(), rateLimitOn: "runs acme/web xrepo-review.yml s3" };
    const report = await sweep({ policy: RETRY_POLICY, workflow: "xrepo-review.yml", dryRun: false, api: fakeRetryApi(state), writeDelayMs: 0 });
    expect(report.rate_limited).toBe(true);
    expect(state.calls.some((c) => c.includes("acme/api"))).toBe(false);
    expect(state.calls).toContain("rerun acme/web 101");
  });

  it("main: flags, token and output", async () => {
    const policyFile = join(tmp, "retry-policy.yaml");
    writeFileSync(policyFile, "version: 1\ndefaults:\n  outcomes:\n    usage_limit:\n      retry: { enabled: true }\nrepos:\n  acme/web: {}\n", { mode: 0o644 });
    const out: string[] = [];
    const err: string[] = [];
    const io = { stdout: { write: (s: string) => out.push(s) }, stderr: { write: (s: string) => err.push(s) } };

    expect(await retryMain(["--policy", policyFile], io)).toBe(2);
    expect(await retryMain(["--policy", policyFile, "--workflow", "../x.yml"], io)).toBe(2);
    expect(await retryMain(["--policy", policyFile, "--workflow", "x.yml", "--repo", "bad"], io)).toBe(2);
    expect(await retryMain(["--policy", policyFile, "--workflow", "x.yml"], { ...io, env: {} })).toBe(1);
    expect(err.join("")).toContain("XREPO_GITHUB_TOKEN");
    expect(await retryMain(["--policy", join(tmp, "missing.yaml"), "--workflow", "x.yml"], { ...io, env: { XREPO_GITHUB_TOKEN: "t" } })).toBe(1);

    const state = retryState();
    const code = await retryMain(["--policy", policyFile, "--workflow", "xrepo-review.yml", "--dry-run"], { ...io, api: fakeRetryApi(state) });
    expect(code).toBe(0);
    const report = JSON.parse(out.join(""));
    expect(report).toMatchObject({ dry_run: true, workflow: "xrepo-review.yml", repos: ["acme/web"], rate_limited: false });
    expect(report.actions.map((a: { pr: number; decision: { action: string } }) => [a.pr, a.decision.action])).toEqual([
      [1, "rerun"],
      [2, "wait"],
      [3, "give_up"],
      [4, "none"],
      [5, "none"],
    ]);
  });
});

/* ------------------------- regression: round 1 fixes ------------------------ */

describe("markdown escaper: leading fence runs (markdown-escaper-tilde-fence)", () => {
  const esc = markdownEscaper({ linkAllowlist: ["github.com"] });
  const PAYLOAD = "<img src=https://attacker.example/p.png> <a href=https://evil.example>x</a> [l](https://evil.example) ![i](https://attacker.example/i.png) @octocat https://evil.example/bare";

  it.each(["~~~", "```", "~~~~~", "```js", "````"])("a value starting with %s is sanitized as prose, mid-line", (fence) => {
    const out = renderTemplate("Review of “{pr_title}” did not finish ({reason}).", { pr_title: `${fence} ${PAYLOAD}`, reason: `${fence} ${PAYLOAD}` }, esc);
    expect(out).not.toContain("\n");
    expect(out).not.toMatch(/<img|<a |!\[|\]\(https/);
    expect(out).not.toMatch(/```|~~~/); // never a fence run, wherever the template puts the value
    expect(out).toContain(`@${Z}octocat`);
    expect(out).not.toContain("https://evil.example/bare");
    expect(out.startsWith("Review of \u201C")).toBe(true);
    expect(out.endsWith(").")).toBe(true); // the trusted template around the values is intact
  });

  it("a value alone on its line cannot open a code block either", () => {
    const out = renderTemplate("{pr_title}\n\nrest of the comment", { pr_title: `~~~ ${PAYLOAD}` }, esc);
    expect(out.split("\n")[0]).not.toMatch(/^(`{3,}|~{3,})/);
    expect(out).not.toContain("<img");
    expect(out.endsWith("\n\nrest of the comment")).toBe(true);
  });

  it("breakFenceRuns leaves no run of three and keeps shorter runs", () => {
    expect(breakFenceRuns("~~~ a ``` b ~~ c `` d ``````")).toBe(`~~${Z}~ a \`\`${Z}\` b ~~ c \`\` d \`\`${Z}\`\`${Z}\`\``);
    expect(breakFenceRuns("plain")).toBe("plain");
  });

  it("values stay on one line even when the sanitizer truncates them", () => {
    const esc10 = markdownEscaper({ linkAllowlist: [], maxChars: 10 });
    expect(renderTemplate("[{pr_title}]", { pr_title: "<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<" }, esc10)).not.toContain("\n");
  });
});

describe("GITHUB_API_URL validation (github-api-url-four-ways)", () => {
  beforeEach(() => {
    vi.spyOn(process.stderr, "write").mockImplementation(() => true);
  });
  afterEach(() => vi.restoreAllMocks());

  it("githubApiBase accepts https (with a path) and loopback http, rejects everything else", () => {
    expect(githubApiBase({})).toBe(DEFAULT_GITHUB_API_URL);
    expect(githubApiBase({ GITHUB_API_URL: "  " })).toBe(DEFAULT_GITHUB_API_URL);
    expect(githubApiBase({ GITHUB_API_URL: "https://ghe.example.com/api/v3/" })).toBe("https://ghe.example.com/api/v3");
    expect(githubApiBase({ GITHUB_API_URL: "http://127.0.0.1:8080" })).toBe("http://127.0.0.1:8080");
    expect(githubApiBase({ GITHUB_API_URL: "http://localhost:3000/api" })).toBe("http://localhost:3000/api");
    for (const bad of ["http://ghe.internal/api/v3", "ghe.internal/api/v3", "ftp://x.example", "https://u:p@ghe.example.com", "https://ghe.example.com/?x=1", "https://ghe.example.com/#f"]) {
      expect(() => githubApiBase({ GITHUB_API_URL: bad }), bad).toThrow(GitHubApiUrlError);
    }
  });

  it("dispatch fails closed instead of sending the token to api.github.com", async () => {
    for (const GITHUB_API_URL of ["http://ghe.internal/api/v3", "ghe.internal/api/v3"]) {
      const f = fakeFetch(() => new Response(null, { status: 204 }));
      const r = await repositoryDispatch({ event_type: "x" }, { prRepo: "acme/web", client_payload: {}, env: { XREPO_DISPATCH_TOKEN: "ghes-token", GITHUB_API_URL }, fetchImpl: f.impl });
      expect(r).toMatchObject({ ok: false, error: expect.stringMatching(/GITHUB_API_URL/) });
      const g = await repositoryDispatch({ event_type: "x" }, { prRepo: "acme/web", client_payload: {}, env: { GITHUB_TOKEN: "gtok", GITHUB_API_URL }, fetchImpl: f.impl });
      expect(g).toMatchObject({ ok: false });
      expect(f.calls).toHaveLength(0);
    }
    const f = fakeFetch(() => new Response(null, { status: 204 }));
    await repositoryDispatch({ event_type: "x" }, { prRepo: "acme/web", client_payload: {}, env: { XREPO_DISPATCH_TOKEN: "t", GITHUB_API_URL: "http://127.0.0.1:9/api" }, fetchImpl: f.impl });
    expect(f.calls[0]!.url).toBe("http://127.0.0.1:9/api/repos/acme/web/dispatches");
  });

  it("retry main refuses an invalid GITHUB_API_URL; createRetryApi validates baseUrl", async () => {
    const policyFile = join(tmp, "retry-policy-url.yaml");
    writeFileSync(policyFile, "version: 1\nrepos:\n  acme/web: {}\n", { mode: 0o644 });
    const err: string[] = [];
    const io = { stdout: { write: () => true }, stderr: { write: (x: string) => err.push(x) } };
    expect(await retryMain(["--policy", policyFile, "--workflow", "x.yml"], { ...io, env: { XREPO_GITHUB_TOKEN: "t", GITHUB_API_URL: "http://ghe.internal/api/v3" } })).toBe(1);
    expect(err.join("")).toContain("GITHUB_API_URL must use https://");
    expect(() => createRetryApi({ token: "t", baseUrl: "ghe.internal" })).toThrow(GitHubApiUrlError);
  });
});

describe("usage-limit reset times (retry-ignores-reset-time)", () => {
  const now = new Date("2026-11-09T12:00:00Z");
  it.each([
    ["2030-01-01T00:00:00Z", "2030-01-01T00:00:00.000Z"],
    ["1:32pm (UTC)", "2026-11-09T13:32:00.000Z"],
    ["11:33am (UTC)", "2026-11-09T11:33:00.000Z"], // just passed: not tomorrow
    ["5am (UTC)", "2026-11-10T05:00:00.000Z"], // long passed: tomorrow
    ["3pm", "2026-11-09T15:00:00.000Z"], // default zone (UTC here)
    ["9:30 AM", "2026-11-09T09:30:00.000Z"],
    ["3pm (Europe/Berlin)", "2026-11-09T14:00:00.000Z"],
    ["3pm (America/New_York)", "2026-11-09T20:00:00.000Z"],
    ["Nov 12, 11:33am (UTC)", "2026-11-12T11:33:00.000Z"],
    ["Jan 2, 1am (UTC)", "2027-01-02T01:00:00.000Z"],
    ["Wed, Nov 11, 3pm UTC", "2026-11-11T15:00:00.000Z"],
    ["12 Nov 2026 at 9:00 (UTC)", "2026-11-12T09:00:00.000Z"],
    ["2 hours", "2026-11-09T14:00:00.000Z"],
    ["in 45 minutes", "2026-11-09T12:45:00.000Z"],
    // Weekday alone (weekly limits; now is Monday 12:00 UTC): next occurrence, up to 1 hour old.
    ["Thu 9am (UTC)", "2026-11-12T09:00:00.000Z"],
    ["Mon 9am", "2026-11-16T09:00:00.000Z"], // 3 hours ago: next Monday
    ["Monday 9am", "2026-11-16T09:00:00.000Z"],
    ["Mon 11:30am", "2026-11-09T11:30:00.000Z"], // 30 minutes old: today
    ["Mon 3pm", "2026-11-09T15:00:00.000Z"],
    ["tues. 9:15 AM (UTC)", "2026-11-10T09:15:00.000Z"],
    ["Sunday at 11pm (Europe/Berlin)", "2026-11-15T22:00:00.000Z"],
    ["Thursday, 9am GMT", "2026-11-12T09:00:00.000Z"],
  ])("resolveResetTime(%j)", (text, iso) => {
    expect(resolveResetTime(text, now, "UTC")?.toISOString()).toBe(iso);
  });

  it.each(["", "soon", "12", "13pm", "Feb 30, 1pm", "Mondy 9am", "Funday 9am", "Mon", "3pm (Not/AZone)", "noon"])("resolveResetTime(%j) is undefined", (text) => {
    expect(resolveResetTime(text, now, "UTC")).toBeUndefined();
  });

  it("retryNotBefore: reset + 5 min, now when already reset, capped at 8 days; backoff otherwise", () => {
    expect(retryNotBefore({ outcome: "usage_limit", reset_at: "3pm (UTC)", attempt: 1, now })).toEqual({ not_before: "2026-11-09T15:05:00Z", basis: "reset" });
    expect(retryNotBefore({ outcome: "usage_limit", reset_at: "11:33am (UTC)", attempt: 2, now })).toEqual({ not_before: "2026-11-09T12:00:00Z", basis: "reset" });
    expect(retryNotBefore({ outcome: "usage_limit", reset_at: "2030-01-01T00:00:00Z", attempt: 1, now })).toEqual({ not_before: "2026-11-17T12:00:00Z", basis: "reset" });
    expect(retryNotBefore({ outcome: "usage_limit", attempt: 1, now })).toEqual({ not_before: "2026-11-09T14:00:00Z", basis: "backoff" });
    expect(retryNotBefore({ outcome: "usage_limit", reset_at: "whenever", attempt: 2, now })).toEqual({ not_before: "2026-11-09T16:00:00Z", basis: "backoff" });
    expect(retryNotBefore({ outcome: "error", attempt: 3, now })).toEqual({ not_before: "2026-11-09T16:00:00Z", basis: "backoff" });
    expect(retryNotBefore({ outcome: "error", attempt: 9, now }).not_before).toBe("2026-11-10T12:00:00Z"); // max 24h
  });

  it("retry markers round-trip; malformed ones are ignored", () => {
    const m: RetryAfterMarker = { not_before: "2026-11-09T15:05:00Z", run_id: 123, attempt: 2 };
    const body = `<!-- xrepo-review:sticky -->\npostponed\n\n${retryAfterMarker(m)}\n<!-- xrepo-review:retry-after 2026-11-09 run=1 attempt=1 -->`;
    expect(parseRetryAfterMarkers(body)).toEqual([m]);
    expect(() => retryAfterMarker({ ...m, not_before: "tomorrow" })).toThrow();
    expect(() => retryAfterMarker({ ...m, run_id: 0 })).toThrow();
  });

  it("decideRetry waits until not_before; retryTiming only trusts the marker of this run and attempt", () => {
    const run: WorkflowRunInfo = { id: 7, run_attempt: 1, status: "completed", conclusion: "success", updated_at: "2026-11-09T10:00:00Z" };
    const marker = { not_before: "2026-11-09T15:05:00Z", run_id: 7, attempt: 1 };
    const t = retryTiming(run, [marker], now);
    expect(decideRetry(run, 3, t)).toEqual({ action: "wait", run_id: 7, reason: "not before 2026-11-09T15:05:00Z (requested by the publisher)", not_before: "2026-11-09T15:05:00Z" });
    expect(decideRetry(run, 3, retryTiming(run, [marker], new Date("2026-11-09T15:05:00Z"))).action).toBe("rerun");
    // A marker of another run or attempt is ignored: backoff of 1h from the run's end applies.
    const other = retryTiming(run, [{ ...marker, run_id: 8 }, { ...marker, attempt: 2 }], now);
    expect(other).toMatchObject({ not_before: Date.parse("2026-11-09T11:00:00Z"), basis: "backoff" });
    expect(decideRetry(run, 3, other).action).toBe("rerun");
    // Far-future markers are capped at 8 days after the run.
    const far = retryTiming(run, [{ ...marker, not_before: "2099-01-01T00:00:00Z" }], now);
    expect(far.not_before).toBe(Date.parse("2026-11-09T10:00:00Z") + MAX_RETRY_WAIT_MS);
    // No marker and no timestamps: no constraint (previous behaviour); give_up ignores timing.
    expect(decideRetry({ id: 7, run_attempt: 1, status: "completed" }, 3, retryTiming({ id: 7, run_attempt: 1, status: "completed" }, [], now)).action).toBe("rerun");
    expect(decideRetry({ ...run, run_attempt: 3 }, 3, t).action).toBe("give_up");
  });

  it("hourly sweeps wait for the reset instead of burning every attempt", async () => {
    // The review hit "You've hit your 5-hour limit · resets 5pm (UTC)" at 12:00; the publisher wrote
    // its marker; retry.yml sweeps hourly.
    const policy = parsePolicy("version: 1\nrepos:\n  acme/web:\n    outcomes:\n      usage_limit:\n        retry: { enabled: true, max_attempts: 3 }\n");
    let attempt = 1;
    let label = true;
    let clock = Date.parse("2026-11-09T12:00:00Z");
    const markers: RetryAfterMarker[] = [];
    const publish = (): void => {
      // what the publisher does for a usage_limit run (see publish.ts): marker for this run + attempt
      const t = retryNotBefore({ outcome: "usage_limit", reset_at: "5pm (UTC)", attempt, now: new Date(clock), timeZone: "UTC" });
      markers.splice(0, markers.length, { not_before: t.not_before, run_id: 7, attempt });
    };
    publish();
    const log: string[] = [];
    const api: RetryApi = {
      listOpenPullsWithLabel: async () => (label ? [{ number: 1, labels: ["xrepo-review:retry"] }] : []),
      getPullHeadSha: async () => "a".repeat(40),
      latestWorkflowRun: async () => ({ id: 7, run_attempt: attempt, status: "completed", conclusion: "success", updated_at: "2026-11-09T12:00:00Z" }),
      rerunWorkflow: async () => {
        attempt++;
        log.push(`${new Date(clock).toISOString().slice(11, 16)} rerun -> attempt ${attempt}`);
      },
      removeLabel: async () => {
        label = false;
        log.push("label removed");
      },
      createComment: async () => {
        log.push("comment");
      },
      retryAfterMarkers: async () => [...markers],
    };
    const decisions: string[] = [];
    for (let hour = 1; hour <= 6; hour++) {
      clock = Date.parse("2026-11-09T12:17:00Z") + (hour - 1) * 3_600_000;
      const now = new Date(clock);
      const report = await sweep({ policy, workflow: "xrepo-review.yml", dryRun: false, api, writeDelayMs: 0, now: () => now });
      decisions.push(report.actions.map((a) => a.decision.action).join(","));
    }
    expect(decisions).toEqual(["wait", "wait", "wait", "wait", "wait", "rerun"]); // 12:17 ... 16:17 wait, 17:17 re-runs
    expect(log).toEqual(["17:17 rerun -> attempt 2"]);
    expect(label).toBe(true);
  });

  it("createRetryApi.retryAfterMarkers only reads comments written by bots (or --publisher-login)", async () => {
    const good = retryAfterMarker({ not_before: "2026-11-09T15:05:00Z", run_id: 7, attempt: 1 });
    const spoof = retryAfterMarker({ not_before: "2026-11-16T00:00:00Z", run_id: 7, attempt: 1 });
    const comments = [
      { id: 1, body: `<!-- xrepo-review:sticky -->\nx\n\n${good}`, user: { login: "github-actions[bot]", type: "Bot" } },
      { id: 2, body: spoof, user: { login: "mallory", type: "User" } },
      { id: 3, body: spoof, user: { login: "other-app[bot]", type: "Bot" } },
    ];
    const f = fakeFetch(() => new Response(JSON.stringify(comments), { status: 200, headers: { "content-type": "application/json" } }));
    const api = createRetryApi({ token: "t", fetch: f.impl });
    expect(await api.retryAfterMarkers!("acme/web", 1)).toEqual([
      { not_before: "2026-11-09T15:05:00Z", run_id: 7, attempt: 1 },
      { not_before: "2026-11-16T00:00:00Z", run_id: 7, attempt: 1 },
    ]);
    expect(f.calls[0]!.url).toMatch(/^https:\/\/api\.github\.com\/repos\/acme\/web\/issues\/1\/comments\?per_page=100/);
    const pinned = createRetryApi({ token: "t", fetch: f.impl, publisherLogin: "GitHub-Actions[bot]" });
    expect(await pinned.retryAfterMarkers!("acme/web", 1)).toEqual([{ not_before: "2026-11-09T15:05:00Z", run_id: 7, attempt: 1 }]);
  });

  it("main validates --publisher-login", async () => {
    const policyFile = join(tmp, "retry-policy-login.yaml");
    writeFileSync(policyFile, "version: 1\nrepos:\n  acme/web: {}\n", { mode: 0o644 });
    const err: string[] = [];
    const io = { stdout: { write: () => true }, stderr: { write: (x: string) => err.push(x) } };
    expect(await retryMain(["--policy", policyFile, "--workflow", "x.yml", "--publisher-login", "bad login!"], io)).toBe(2);
    expect(err.join("")).toContain("--publisher-login");
  });
});

/* ------------------------- regression: round 2 fixes ------------------------ */

const EXAMPLE_POLICY = parsePolicy(readFileSync(join(import.meta.dirname, "..", "examples", "policy.yaml"), "utf8"));

/** fakeRetryApi plus discovery: the search finds every open PR with a head in `state.pulls`. */
function discoveringApi(state: FakeRetryState, opts: { installation?: string; searchFail?: (owner: string) => Error | undefined } = {}): RetryApi {
  return {
    ...fakeRetryApi(state),
    async installationOwner() {
      state.calls.push("installation");
      return opts.installation;
    },
    async findReposWithLabeledPulls(owner, label) {
      state.calls.push(`search ${owner} ${label}`);
      const err = opts.searchFail?.(owner);
      if (err) throw err;
      return Object.entries(state.pulls)
        .filter(([repo, prs]) => repo.split("/")[0] === owner && prs.some((p) => p.head && p.labels.some((l) => l.toLowerCase() === label.toLowerCase())))
        .map(([repo]) => repo);
    },
  };
}

describe("retry sweeper discovers repositories covered by defaults (retry-sweeper-skips-default-repos, retry-sweeper-repo-discovery)", () => {
  beforeEach(() => {
    vi.spyOn(process.stderr, "write").mockImplementation(() => true);
  });
  afterEach(() => vi.restoreAllMocks());

  it("the example policy: acme/web (defaults only, under acme/*) is labelled by the publisher and now swept", async () => {
    expect(sweepRepos(EXAMPLE_POLICY)).toEqual(["acme/payments", "acme/docs", "acme-platform/ledger"]);
    expect(policyOwners(EXAMPLE_POLICY)).toEqual(["acme", "acme-platform"]);
    expect(retryRules(defaultsPolicy(EXAMPLE_POLICY))).toEqual([{ label: "xrepo-review:retry", max_attempts: 3, unmarked_max_attempts: 3 }]);
    const state: FakeRetryState = {
      pulls: {
        "acme/web": [{ number: 7, labels: ["xrepo-review:retry"], head: "w7" }],
        "acme/payments": [{ number: 3, labels: ["xrepo-review:retry"], head: "p3" }],
      },
      runs: { w7: { id: 701, run_attempt: 1, status: "completed" }, p3: { id: 301, run_attempt: 1, status: "completed" } },
      calls: [],
    };
    const report = await sweep({ policy: EXAMPLE_POLICY, workflow: "xrepo-review.yml", dryRun: false, api: discoveringApi(state, { installation: "acme" }), writeDelayMs: 0 });
    expect(report.repos).toEqual(["acme/payments", "acme/docs", "acme-platform/ledger", "acme/web"]);
    expect(report.discovery).toEqual({ owners: ["acme", "acme-platform"], labels: ["xrepo-review:retry"], repos: ["acme/payments", "acme/web"] });
    expect(state.calls.filter((c) => c.startsWith("search"))).toEqual(["search acme xrepo-review:retry", "search acme-platform xrepo-review:retry"]);
    expect(report.actions.map((a) => [`${a.repo}#${a.pr}`, a.decision.action, a.done])).toEqual([
      ["acme/payments#3", "rerun", true],
      ["acme/web#7", "rerun", true],
    ]);
    expect(state.calls).toContain("rerun acme/web 701");
    expect(report.errors).toEqual([]);
  });

  it("the give-up path also reaches discovered repositories (label removed, one comment)", async () => {
    const state: FakeRetryState = {
      pulls: { "acme/api": [{ number: 9, labels: ["xrepo-review:retry"], head: "a9" }] },
      runs: { a9: { id: 909, run_attempt: 3, status: "completed" } },
      calls: [],
    };
    await sweep({ policy: EXAMPLE_POLICY, workflow: "xrepo-review.yml", dryRun: false, api: discoveringApi(state), writeDelayMs: 0 });
    expect(state.calls.filter((c) => /^(rerun|unlabel|comment)/.test(c))).toEqual(["unlabel acme/api#9 xrepo-review:retry", "comment acme/api#9 exhausted"]);
  });

  it("the installation account is searched even when the policy names no repository", async () => {
    const policy = parsePolicy("version: 1\ndefaults:\n  outcomes:\n    error:\n      retry: { enabled: true, max_attempts: 2, label: retry-me }\n");
    const state: FakeRetryState = { pulls: { "octo/app": [{ number: 1, labels: ["Retry-Me"], head: "o1" }] }, runs: { o1: { id: 11, run_attempt: 1, status: "completed" } }, calls: [] };
    const report = await sweep({ policy, workflow: "x.yml", dryRun: true, api: discoveringApi(state, { installation: "octo" }), writeDelayMs: 0 });
    expect(report.repos).toEqual(["octo/app"]);
    expect(report.actions[0]).toMatchObject({ repo: "octo/app", pr: 1, decision: { action: "rerun" }, done: false });
    // Not an installation token and no owner in the policy: nothing to search, nothing swept.
    const none = await sweep({ policy, workflow: "x.yml", dryRun: true, api: discoveringApi({ ...state, calls: [] }), writeDelayMs: 0 });
    expect(none).toMatchObject({ repos: [], discovery: { owners: [], repos: [] }, actions: [], errors: [] });
  });

  it("no search without retry in defaults, with a disabled default, or with --repo", async () => {
    const listed = parsePolicy("version: 1\nrepos:\n  acme/web:\n    outcomes:\n      usage_limit:\n        retry: { enabled: true }\n");
    const disabled = parsePolicy("version: 1\ndefaults:\n  enabled: false\n  outcomes:\n    usage_limit:\n      retry: { enabled: true }\nrepos:\n  acme/web: { enabled: true }\n");
    for (const [policy, repos] of [
      [listed, undefined],
      [disabled, undefined],
      [EXAMPLE_POLICY, ["acme/docs"]],
    ] as const) {
      const state: FakeRetryState = { pulls: {}, runs: {}, calls: [] };
      const report = await sweep({ policy, workflow: "x.yml", ...(repos ? { repos: [...repos] } : {}), dryRun: true, api: discoveringApi(state, { installation: "acme" }), writeDelayMs: 0 });
      expect(state.calls.filter((c) => c.startsWith("search") || c === "installation")).toEqual([]);
      expect(report.discovery).toBeUndefined();
    }
  });

  it("search failures are reported; the policy's listed repositories are still swept", async () => {
    const state: FakeRetryState = {
      pulls: { "acme/payments": [{ number: 3, labels: ["xrepo-review:retry"], head: "p3" }], "acme/web": [{ number: 7, labels: ["xrepo-review:retry"], head: "w7" }] },
      runs: { p3: { id: 301, run_attempt: 1, status: "completed" }, w7: { id: 701, run_attempt: 1, status: "completed" } },
      calls: [],
    };
    const report = await sweep({
      policy: EXAMPLE_POLICY,
      workflow: "xrepo-review.yml",
      dryRun: true,
      api: discoveringApi(state, { searchFail: (o) => (o === "acme" ? Object.assign(new Error("Validation Failed"), { status: 422 }) : undefined) }),
      writeDelayMs: 0,
    });
    expect(report.errors).toEqual(['discovery acme "xrepo-review:retry": HTTP 422: Validation Failed']);
    expect(report.actions.map((a) => `${a.repo}#${a.pr}`)).toEqual(["acme/payments#3"]);
    // A search rate limit stops discovery only (the search API has its own per-minute limit).
    const limited = await sweep({
      policy: EXAMPLE_POLICY,
      workflow: "xrepo-review.yml",
      dryRun: true,
      api: discoveringApi({ ...state, calls: [] }, { searchFail: () => new RateLimitedError("GitHub rate limit reached during search pull requests") }),
      writeDelayMs: 0,
    });
    expect(limited.rate_limited).toBe(false);
    expect(limited.errors).toEqual(["discovery stopped: GitHub rate limit reached during search pull requests"]);
    expect(limited.actions.map((a) => `${a.repo}#${a.pr}`)).toEqual(["acme/payments#3"]);
  });

  it("caps the number of searches and refuses labels that cannot be quoted", async () => {
    const owners = Array.from({ length: MAX_DISCOVERY_QUERIES + 3 }, (_, i) => `org${i}/*`);
    const many = parsePolicy(`version: 1\ndefaults:\n  outcomes:\n    usage_limit:\n      retry: { enabled: true }\nmirror:\n  repos: ${JSON.stringify(owners)}\n`);
    const state: FakeRetryState = { pulls: {}, runs: {}, calls: [] };
    const report = await sweep({ policy: many, workflow: "x.yml", dryRun: true, api: discoveringApi(state), writeDelayMs: 0 });
    expect(state.calls.filter((c) => c.startsWith("search"))).toHaveLength(MAX_DISCOVERY_QUERIES);
    expect(report.errors).toEqual([expect.stringMatching(/more than 20 owner\/label searches/)]);

    const quoted = parsePolicy('version: 1\ndefaults:\n  outcomes:\n    usage_limit:\n      retry: { enabled: true, label: \'say "again"\' }\nrepos:\n  acme/web: {}\n');
    const q = await sweep({ policy: quoted, workflow: "x.yml", dryRun: true, api: discoveringApi({ pulls: {}, runs: {}, calls: [] }), writeDelayMs: 0 });
    expect(q.errors).toEqual([expect.stringMatching(/cannot be searched for/)]);
    expect(q.repos).toEqual(["acme/web"]);
  });

  it("end to end through createRetryApi (dry-run): the example policy's acme/web PR is found, listed and re-run", async () => {
    const seen: string[] = [];
    const f = fakeFetch((call) => {
      const u = new URL(call.url);
      seen.push(`${call.init.method ?? "GET"} ${u.pathname}`);
      const q = u.searchParams.get("q") ?? "";
      if (u.pathname === "/installation/repositories") return Response.json({ total_count: 1, repositories: [{ full_name: "acme/web", owner: { login: "acme" } }] });
      if (u.pathname === "/search/issues") {
        const items = q.endsWith("org:acme") ? [{ number: 7, state: "open", repository_url: "https://api.github.com/repos/acme/web", pull_request: { url: "x" }, labels: [{ name: "xrepo-review:retry" }] }] : [];
        return Object.defineProperty(Response.json({ total_count: items.length, incomplete_results: false, items }), "url", { value: call.url });
      }
      if (u.pathname === "/repos/acme/web/issues") return Response.json([{ number: 7, pull_request: { url: "x" }, labels: [{ name: "xrepo-review:retry" }] }]);
      if (/^\/repos\/[^/]+\/[^/]+\/issues$/.test(u.pathname)) return Response.json([]);
      if (u.pathname === "/repos/acme/web/pulls/7") return Response.json({ state: "open", head: { sha: "f".repeat(40) } });
      if (u.pathname === "/repos/acme/web/actions/workflows/xrepo-review.yml/runs") {
        return Response.json({ total_count: 1, workflow_runs: [{ id: 701, run_attempt: 1, status: "completed", conclusion: "success", created_at: "2026-11-09T08:50:00Z", updated_at: "2026-11-09T09:00:00Z" }] });
      }
      if (u.pathname === "/repos/acme/web/issues/7/comments") return Response.json([]);
      return Response.json({ message: "Not Found" }, { status: 404 });
    });
    const report = await sweep({
      policy: EXAMPLE_POLICY,
      workflow: "xrepo-review.yml",
      dryRun: true,
      api: createRetryApi({ token: "t", fetch: f.impl }),
      writeDelayMs: 0,
      now: () => new Date("2026-11-09T12:00:00Z"),
    });
    expect(report.errors).toEqual([]);
    expect(report.discovery?.repos).toEqual(["acme/web"]);
    expect(report.actions).toEqual([
      expect.objectContaining({ repo: "acme/web", pr: 7, decision: { action: "rerun", run_id: 701, run_attempt: 1, max_attempts: 3 }, done: false }),
    ]);
    expect(seen).toContain("GET /repos/acme/web/issues");
    expect(seen.some((x) => x.startsWith("POST"))).toBe(false);
  });

  it("createRetryApi: installation account and the PR search (org:, then user:), filtered to open PRs of that owner", async () => {
    const item = (repo: string, over: Record<string, unknown> = {}) => ({
      number: 1,
      state: "open",
      repository_url: `https://api.github.com/repos/${repo}`,
      pull_request: { url: "x" },
      labels: [{ name: "xrepo-review:retry" }],
      ...over,
    });
    const items = [item("acme/web"), item("acme/web", { number: 2 }), item("Acme/API"), item("other/x"), item("acme/issue", { pull_request: undefined }), item("acme/closed", { state: "closed" })];
    // Real responses carry their URL (octokit's paginate reads it for search results).
    const at = (r: Response, url: string): Response => Object.defineProperty(r, "url", { value: url });
    const f = fakeFetch((call) => {
      const u = new URL(call.url);
      if (u.pathname === "/installation/repositories") return Response.json({ total_count: 1, repositories: [{ full_name: "acme/web", owner: { login: "acme" } }] });
      if (u.pathname === "/search/issues") {
        if (u.searchParams.get("q")?.includes("org:solo")) return Response.json({ message: "Validation Failed" }, { status: 422 });
        return at(Response.json({ total_count: items.length, incomplete_results: false, items }), call.url);
      }
      return new Response("not found", { status: 404 });
    });
    const api = createRetryApi({ token: "t", fetch: f.impl });
    expect(await api.installationOwner!()).toBe("acme");
    expect(await api.findReposWithLabeledPulls!("acme", "xrepo-review:retry")).toEqual(["acme/web", "Acme/API"]);
    const q = new URL(f.calls.at(-1)!.url).searchParams;
    expect(q.get("q")).toBe('is:pr is:open label:"xrepo-review:retry" org:acme');
    expect(q.get("per_page")).toBe("100");
    await api.findReposWithLabeledPulls!("solo", "xrepo-review:retry");
    expect(f.calls.slice(-2).map((c) => new URL(c.url).searchParams.get("q"))).toEqual([
      'is:pr is:open label:"xrepo-review:retry" org:solo',
      'is:pr is:open label:"xrepo-review:retry" user:solo',
    ]);
    await expect(api.findReposWithLabeledPulls!("acme", 'a"b')).rejects.toThrow(/cannot be quoted/);
    await expect(api.findReposWithLabeledPulls!("acme org:evil", "x")).rejects.toThrow(/invalid owner/);
    // A PAT / GITHUB_TOKEN has no installation: undefined, not an error.
    const pat = createRetryApi({ token: "t", fetch: fakeFetch(() => Response.json({ message: "A JSON web token could not be decoded" }, { status: 401 })).impl });
    expect(await pat.installationOwner!()).toBeUndefined();
  });
});

describe("retry label shared by outcomes with different max_attempts (retry-shared-label-max-attempts)", () => {
  beforeEach(() => {
    vi.spyOn(process.stderr, "write").mockImplementation(() => true);
  });
  afterEach(() => vi.restoreAllMocks());

  const SHARED = parsePolicy(`
version: 1
defaults:
  outcomes:
    usage_limit:
      retry: { enabled: true, max_attempts: 5 }
    error:
      retry: { enabled: true, max_attempts: 2 }
repos:
  acme/web: {}
`);
  const rules = retryRules(resolvePolicy(SHARED, "acme/web"));
  const run = (attempt: number): WorkflowRunInfo => ({ id: 7, run_attempt: attempt, status: "completed", conclusion: "success", updated_at: "2026-11-09T10:00:00Z" });

  it("retry-stop markers round-trip and are told apart from retry-after markers", () => {
    const body = `<!-- xrepo-review:sticky -->\nx\n\n${retryStopMarker({ run_id: 7, attempt: 2, max_attempts: 2 })}\n<!-- xrepo-review:retry-stop run=7 attempt=0 max=2 -->`;
    expect(parseRetryMarkers(body)).toEqual([{ kind: "stop", run_id: 7, attempt: 2, max_attempts: 2 }]);
    expect(parseRetryAfterMarkers(body)).toEqual([]);
    expect(() => retryStopMarker({ run_id: 7, attempt: 2, max_attempts: 0 })).toThrow();
  });

  it("retryLimit: the run's own outcome decides; without a marker the smallest max_attempts applies", () => {
    expect(rules).toEqual([{ label: "xrepo-review:retry", max_attempts: 5, unmarked_max_attempts: 2 }]);
    const stop: RetryMarker = { kind: "stop", run_id: 7, attempt: 2, max_attempts: 2 };
    const after: RetryMarker = { not_before: "2026-11-09T11:00:00Z", run_id: 7, attempt: 2 };
    expect(retryLimit(run(2), [stop], rules)).toEqual({ max_attempts: 2, basis: "stop" });
    expect(retryLimit(run(2), [after], rules)).toEqual({ max_attempts: 5, basis: "retry" });
    expect(retryLimit(run(2), [], rules)).toEqual({ max_attempts: 2, basis: "unmarked" });
    // Markers of another run or attempt do not count.
    expect(retryLimit(run(3), [stop, after], rules)).toEqual({ max_attempts: 2, basis: "unmarked" });
    expect(retryLimit(run(2), [{ ...stop, run_id: 8 }], rules).basis).toBe("unmarked");
  });

  it("an error run (max 2) on the shared label is given up at attempt 2, a usage_limit run (max 5) is not", async () => {
    // What the publisher writes at attempt 2 (see publish.ts): error -> retry-stop, usage_limit -> retry-after.
    const markersFor: Record<string, RetryMarker[]> = {
      error: parseRetryMarkers(retryStopMarker({ run_id: 7, attempt: 2, max_attempts: 2 })),
      usage_limit: parseRetryMarkers(retryAfterMarker({ not_before: "2026-11-09T11:00:00Z", run_id: 7, attempt: 2 })),
      none: [],
    };
    const decide = async (kind: string): Promise<{ action: string; calls: string[] }> => {
      const state: FakeRetryState = { pulls: { "acme/web": [{ number: 1, labels: ["xrepo-review:retry"], head: "h" }] }, runs: { h: run(2) }, calls: [] };
      const api: RetryApi = { ...fakeRetryApi(state), retryAfterMarkers: async () => markersFor[kind] ?? [] };
      const report = await sweep({ policy: SHARED, workflow: "x.yml", dryRun: false, api, writeDelayMs: 0, now: () => new Date("2026-11-09T12:00:00Z") });
      return { action: report.actions[0]!.decision.action, calls: state.calls.filter((c) => /^(rerun|unlabel|comment)/.test(c)) };
    };
    expect(await decide("error")).toEqual({ action: "give_up", calls: ["unlabel acme/web#1 xrepo-review:retry", "comment acme/web#1 exhausted"] });
    expect(await decide("usage_limit")).toEqual({ action: "rerun", calls: ["rerun acme/web 7"] });
    expect(await decide("none")).toEqual({ action: "give_up", calls: ["unlabel acme/web#1 xrepo-review:retry", "comment acme/web#1 exhausted"] });
  });

  it("when the markers cannot be read and only they could decide, the sweeper waits and reports it", async () => {
    const state: FakeRetryState = { pulls: { "acme/web": [{ number: 1, labels: ["xrepo-review:retry"], head: "h" }] }, runs: { h: run(2) }, calls: [] };
    const api: RetryApi = {
      ...fakeRetryApi(state),
      retryAfterMarkers: async () => {
        throw Object.assign(new Error("boom"), { status: 502 });
      },
    };
    const report = await sweep({ policy: SHARED, workflow: "x.yml", dryRun: false, api, writeDelayMs: 0 });
    expect(report.actions[0]!.decision).toEqual({ action: "wait", run_id: 7, reason: "the publisher's retry markers could not be read" });
    expect(report.errors).toEqual(["acme/web#1: the publisher's retry markers could not be read; deciding at the next sweep"]);
    expect(state.calls.filter((c) => /^(rerun|unlabel|comment)/.test(c))).toEqual([]);
  });

  it("createRetryApi.retryAfterMarkers returns retry-stop markers too (trusted authors only)", async () => {
    const stop = retryStopMarker({ run_id: 7, attempt: 2, max_attempts: 2 });
    const comments = [
      { id: 1, body: `<!-- xrepo-review:sticky -->\nx\n\n${stop}`, user: { login: "github-actions[bot]", type: "Bot" } },
      { id: 2, body: retryStopMarker({ run_id: 7, attempt: 1, max_attempts: 1 }), user: { login: "mallory", type: "User" } },
    ];
    const f = fakeFetch(() => Response.json(comments));
    expect(await createRetryApi({ token: "t", fetch: f.impl }).retryAfterMarkers!("acme/web", 1)).toEqual([{ kind: "stop", run_id: 7, attempt: 2, max_attempts: 2 }]);
  });
});

describe("weekday-only reset times (reset-weekday-not-resolved)", () => {
  const now = new Date("2026-11-09T12:00:00Z"); // a Monday

  it("'Weekly limit reached ∙ resets Thu 9am' is timed to the reset, not backed off 2h / 4h", () => {
    const cls = classifyOutcome({ agentStepOutcome: "failure", executionFileText: pretty([INIT, result({ is_error: true, result: "Weekly limit reached ∙ resets Thu 9am (UTC)" })]) });
    expect(cls).toMatchObject({ outcome: "usage_limit", reset_at: "Thu 9am (UTC)" });
    for (const attempt of [1, 2, 3]) {
      expect(retryNotBefore({ outcome: "usage_limit", reset_at: cls.reset_at!, attempt, now })).toEqual({ not_before: "2026-11-12T09:05:00Z", basis: "reset" });
    }
    // Same weekday as today, already past: next week's reset (within the 8-day cap), not "now".
    expect(retryNotBefore({ outcome: "usage_limit", reset_at: "Mon 9am", attempt: 1, now, timeZone: "UTC" })).toEqual({ not_before: "2026-11-16T09:05:00Z", basis: "reset" });
    expect(retryNotBefore({ outcome: "usage_limit", reset_at: "Monday 9am (America/New_York)", attempt: 1, now })).toEqual({ not_before: "2026-11-09T14:05:00Z", basis: "reset" });
  });

  it("an unresolvable text reset no longer hides a structured (epoch) one", () => {
    const resolvable = classifyOutcome({
      agentStepOutcome: "failure",
      executionFileText: pretty([
        INIT,
        { type: "rate_limit_event", rate_limit_info: { status: "rejected", resetsAt: 1762947180, rateLimitType: "seven_day" } },
        result({ is_error: true, result: "Weekly limit reached ∙ resets Thu 9am" }),
      ]),
    });
    expect(resolvable.reset_at).toBe("Thu 9am"); // readable text kept when it resolves
    const unresolvable = classifyOutcome({
      agentStepOutcome: "failure",
      executionFileText: pretty([
        INIT,
        { type: "rate_limit_event", rate_limit_info: { status: "rejected", resetsAt: 1762947180, rateLimitType: "seven_day" } },
        result({ is_error: true, result: "Weekly limit reached ∙ resets next week sometime" }),
      ]),
    });
    expect(unresolvable.reset_at).toBe("2025-11-12T11:33:00Z");
    // Without a structured reset the text is still reported (and the retry backs off).
    const textOnly = classifyOutcome({ agentStepOutcome: "failure", executionFileText: pretty([INIT, result({ is_error: true, result: "Weekly limit reached ∙ resets next week sometime" })]) });
    expect(textOnly.reset_at).toBe("next week sometime");
  });
});

describe("xrepo retry --owner (one App installation token per account)", () => {
  beforeEach(() => {
    vi.spyOn(process.stderr, "write").mockImplementation(() => true);
  });
  afterEach(() => vi.restoreAllMocks());

  it("sweeps only that owner's listed repositories and searches only that owner (no installation lookup)", async () => {
    const state: FakeRetryState = {
      pulls: {
        "acme/web": [{ number: 7, labels: ["xrepo-review:retry"], head: "w7" }],
        "acme-platform/ledger": [{ number: 2, labels: ["xrepo-review:retry"], head: "l2" }],
      },
      runs: { w7: { id: 701, run_attempt: 1, status: "completed" }, l2: { id: 201, run_attempt: 1, status: "completed" } },
      calls: [],
    };
    const report = await sweep({ policy: EXAMPLE_POLICY, workflow: "xrepo-review.yml", owner: "ACME-platform", dryRun: true, api: discoveringApi(state, { installation: "acme" }), writeDelayMs: 0 });
    expect(report.owner).toBe("ACME-platform");
    expect(report.repos).toEqual(["acme-platform/ledger"]);
    expect(report.discovery?.owners).toEqual(["ACME-platform"]);
    expect(state.calls.filter((c) => c.startsWith("search") || c === "installation")).toEqual(["search ACME-platform xrepo-review:retry"]);
    expect(report.actions.map((a) => `${a.repo}#${a.pr}`)).toEqual(["acme-platform/ledger#2"]);

    const acme = await sweep({ policy: EXAMPLE_POLICY, workflow: "xrepo-review.yml", owner: "acme", dryRun: true, api: discoveringApi({ ...state, calls: [] }), writeDelayMs: 0 });
    expect(acme.repos).toEqual(["acme/payments", "acme/docs", "acme/web"]);
  });

  it("main validates --owner and that --repo names belong to it", async () => {
    const policyFile = join(tmp, "retry-policy-owner.yaml");
    writeFileSync(policyFile, "version: 1\nrepos:\n  acme/web: {}\n  other/x: {}\n", { mode: 0o644 });
    const err: string[] = [];
    const out: string[] = [];
    const io = { stdout: { write: (x: string) => out.push(x) }, stderr: { write: (x: string) => err.push(x) } };
    expect(await retryMain(["--policy", policyFile, "--workflow", "x.yml", "--owner", "bad owner"], io)).toBe(2);
    expect(await retryMain(["--policy", policyFile, "--workflow", "x.yml", "--owner", "acme", "--repo", "other/x"], io)).toBe(2);
    expect(err.join("")).toContain("not owned by --owner acme");
    const state: FakeRetryState = { pulls: {}, runs: {}, calls: [] };
    expect(await retryMain(["--policy", policyFile, "--workflow", "x.yml", "--owner", "acme", "--dry-run"], { ...io, api: fakeRetryApi(state) })).toBe(0);
    expect((JSON.parse(out.join("")) as { repos: string[]; owner: string }).repos).toEqual(["acme/web"]);
  });
});

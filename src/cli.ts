#!/usr/bin/env node
/**
 * `xrepo <command>`: dispatcher for every xrepo-review entry point. Each command's module is loaded
 * lazily so the MCP servers start without loading Octokit & co.
 *
 *   search-mcp   xsearch MCP server (stdio)            src/search/server.ts
 *   review-mcp   xreview MCP server (stdio)            src/review/server.ts
 *   prepare      build the agent's work dir            src/prepare/prepare.ts
 *   collect      record the agent step's outcome       src/prepare/prepare.ts
 *   publish      deterministic publisher               src/publish/publish.ts
 *   sync         mirror sync                           src/sync/sync.ts
 *   retry        re-run postponed reviews              src/outcome/retry.ts
 *   policy       validate | resolve | tools            (below)
 *
 * Exit codes: whatever the command returns; 2 for usage errors (unknown command, bad flags).
 */
import { readFileSync, realpathSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

type Main = (args: string[]) => Promise<number>;

/** `help` returns the command's usage text (`xrepo <command> --help`, printed on stdout, exit 0). */
const COMMANDS: Record<string, { summary: string; load: () => Promise<Main>; help: () => Promise<string> }> = {
  "search-mcp": {
    summary: "serve the xsearch MCP server on stdio (--ctx <dir> --pr <dir> [--mirror <dir>] [--policy-path <path>])",
    load: async () => (await import("./search/server.js")).main,
    help: async () => (await import("./search/server.js")).USAGE,
  },
  "review-mcp": {
    summary: "serve the xreview MCP server on stdio (--ctx <dir> --out <draft.jsonl>)",
    load: async () => (await import("./review/server.js")).main,
    help: async () => (await import("./review/server.js")).USAGE,
  },
  prepare: {
    summary: "write the agent work dir, prompt and claude_args for a pull request",
    load: async () => (await import("./prepare/prepare.js")).main,
    help: async () => (await import("./prepare/prepare.js")).USAGE,
  },
  collect: {
    summary: "record the agent step outcome and a trimmed execution log (--work <dir> --agent-outcome <o>)",
    load: async () => (await import("./prepare/prepare.js")).collectMain,
    help: async () => (await import("./prepare/prepare.js")).COLLECT_USAGE,
  },
  publish: {
    summary: "validate the draft against the policy and publish it to GitHub",
    load: async () => (await import("./publish/publish.js")).main,
    help: async () => (await import("./publish/publish.js")).USAGE,
  },
  sync: {
    summary: "sync the read-only repository mirror (--policy <file> --mirror <dir>)",
    load: async () => (await import("./sync/sync.js")).main,
    help: async () => (await import("./sync/sync.js")).USAGE,
  },
  retry: {
    summary: "re-run reviews postponed by usage limits (--policy <file> --workflow <file>)",
    load: async () => (await import("./outcome/retry.js")).main,
    help: async () => (await import("./outcome/retry.js")).USAGE,
  },
  policy: {
    summary: "validate <file> | resolve <file> <owner/repo> | tools <file> <owner/repo>",
    load: async () => policyMain,
    help: async () => POLICY_USAGE,
  },
};

function version(): string {
  try {
    const here = dirname(fileURLToPath(import.meta.url));
    const pkg = JSON.parse(readFileSync(join(here, "..", "package.json"), "utf8")) as { version?: unknown };
    return typeof pkg.version === "string" ? pkg.version : "unknown";
  } catch {
    return "unknown";
  }
}

export function usage(): string {
  const width = Math.max(...Object.keys(COMMANDS).map((c) => c.length));
  const lines = Object.entries(COMMANDS).map(([name, c]) => `  ${name.padEnd(width)}  ${c.summary}`);
  return `usage: xrepo <command> [flags]\n\ncommands:\n${lines.join("\n")}\n\nRun \`xrepo <command> --help\` for the flags of a command.\n`;
}

/* --------------------------------- policy --------------------------------- */

const POLICY_USAGE =
  "usage: xrepo policy validate <file>\n" +
  "       xrepo policy resolve <file> <owner/repo>   # resolved policy JSON for one repository\n" +
  "       xrepo policy tools <file> <owner/repo>     # tools the agent gets for that repository\n";

export interface PolicyIo {
  stdout?: { write(s: string): unknown };
  stderr?: { write(s: string): unknown };
}

/** `xrepo policy ...`: 0 ok, 1 invalid policy / repository, 2 usage. */
export async function policyMain(args: string[], io: PolicyIo = {}): Promise<number> {
  const stdout = io.stdout ?? process.stdout;
  const stderr = io.stderr ?? process.stderr;
  const [sub, file, repo, ...rest] = args;
  const needsRepo = sub === "resolve" || sub === "tools";
  if (
    !sub ||
    !["validate", "resolve", "tools"].includes(sub) ||
    !file ||
    (needsRepo && !repo) ||
    (!needsRepo && repo !== undefined) ||
    rest.length > 0
  ) {
    if (sub === "--help" || sub === "-h" || sub === "help") {
      stdout.write(POLICY_USAGE);
      return 0;
    }
    stderr.write(POLICY_USAGE);
    return 2;
  }
  const { loadPolicy, resolvePolicy, policyWarnings, policyFileWarnings, PolicyError } = await import("./policy/load.js");
  try {
    const policy = loadPolicy(file);
    if (sub === "validate") {
      // File-level problems: mirror.repos entries sync always fails, a dropped defaults deny.
      for (const w of policyFileWarnings(policy)) stderr.write(`warning: ${w}
`);
      // Resolve every configured repository too: outcome merges are only checked at resolve time.
      const repos = Object.keys(policy.repos);
      const scopes: [string, string][] = repos.map((r) => [r, r]);
      // Repositories without an override get the defaults: a name no repos key matches.
      const unlisted = "xrepo-validate/defaults";
      if (!repos.some((r) => r.toLowerCase() === unlisted)) scopes.unshift(["defaults", unlisted]);
      for (const [label, r] of scopes) {
        for (const w of policyWarnings(resolvePolicy(policy, r))) stderr.write(`warning: ${label}: ${w}\n`);
      }
      stdout.write(
        `ok: ${file} is valid (${repos.length} repository override${repos.length === 1 ? "" : "s"}, ` +
          `${Object.keys(policy.notifications).length} notification target${Object.keys(policy.notifications).length === 1 ? "" : "s"}, ` +
          `${policy.mirror.repos.length} mirror entr${policy.mirror.repos.length === 1 ? "y" : "ies"})\n`,
      );
      return 0;
    }
    const resolved = resolvePolicy(policy, repo as string);
    if (sub === "resolve") {
      stdout.write(`${JSON.stringify(resolved, null, 2)}\n`);
      return 0;
    }
    const { buildClaudeArgs } = await import("./prepare/prepare.js");
    const claude = buildClaudeArgs(resolved, { mcpConfigPath: "/WORK/agent/mcp.json" });
    stdout.write(
      [
        `# tools the agent can call when reviewing ${resolved.repo}${resolved.enabled ? "" : " (reviews disabled: enabled: false)"}`,
        ...claude.allowedTools,
        `# built-in Claude Code tools: ${claude.builtinTools.length > 0 ? claude.builtinTools.join(", ") : "none"}`,
        `# claude_args: ${claude.text}`,
        "",
      ].join("\n"),
    );
    return 0;
  } catch (e) {
    if (e instanceof PolicyError || (e as Error)?.name === "PrepareError") {
      stderr.write(`xrepo policy: ${(e as Error).message}\n`);
      return 1;
    }
    throw e;
  }
}

/* ---------------------------------- main ---------------------------------- */

export async function run(argv: string[]): Promise<number> {
  const [cmd, ...args] = argv;
  if (cmd === undefined || cmd === "--help" || cmd === "-h" || cmd === "help") {
    (cmd === undefined ? process.stderr : process.stdout).write(usage());
    return cmd === undefined ? 2 : 0;
  }
  if (cmd === "--version" || cmd === "-v" || cmd === "version") {
    process.stdout.write(`${version()}\n`);
    return 0;
  }
  const entry = Object.prototype.hasOwnProperty.call(COMMANDS, cmd) ? COMMANDS[cmd] : undefined;
  if (!entry) {
    process.stderr.write(`xrepo: unknown command ${JSON.stringify(cmd)}\n\n${usage()}`);
    return 2;
  }
  if (args.length === 1 && (args[0] === "--help" || args[0] === "-h")) {
    const text = await entry.help();
    process.stdout.write(text.endsWith("\n") ? text : `${text}\n`);
    return 0;
  }
  const main = await entry.load();
  return main(args);
}

/** True when this file is the process entry point (not when imported by tests). */
function isEntryPoint(): boolean {
  const argv1 = process.argv[1];
  if (!argv1) return false;
  try {
    return realpathSync(argv1) === realpathSync(fileURLToPath(import.meta.url));
  } catch {
    return false;
  }
}

if (isEntryPoint()) {
  run(process.argv.slice(2)).then(
    (code) => {
      process.exitCode = code;
      // MCP servers resolve once their transport closed; do not let a stray handle keep us alive.
      setTimeout(() => process.exit(code), 2000).unref();
    },
    (e: unknown) => {
      process.stderr.write(`xrepo: ${(e as Error)?.stack ?? String(e)}\n`);
      process.exitCode = 1;
      setTimeout(() => process.exit(1), 2000).unref();
    },
  );
}

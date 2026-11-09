/**
 * PR context written by `prepare` into $WORK/ctx and read by the MCP servers and the publisher.
 */
import { closeSync, fsyncSync, openSync, readFileSync, renameSync, unlinkSync, writeSync } from "node:fs";
import { randomBytes } from "node:crypto";
import { basename, dirname, join } from "node:path";
import { z } from "zod";

export const CTX_FILES = {
  pr: "pr.json",
  diff: "diff.patch",
  policy: "policy.resolved.json",
  prTags: "tags.pr.jsonl",
} as const;

export const PrFile = z.object({
  path: z.string().min(1),
  /** FileDiff statuses plus GitHub API statuses (copied / changed / unchanged). */
  status: z.enum(["added", "modified", "removed", "renamed", "binary", "copied", "changed", "unchanged"]),
  additions: z.number().int().min(0),
  deletions: z.number().int().min(0),
  previous_path: z.string().optional(),
});
export type PrFile = z.infer<typeof PrFile>;

export const PrContext = z.object({
  repo: z.string().regex(/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/, "expected owner/name"),
  number: z.number().int().positive(),
  title: z.string(),
  body: z.string(),
  author: z.string(),
  author_type: z.enum(["User", "Bot", "Organization", "Unknown"]),
  base_sha: z.string().min(1),
  head_sha: z.string().min(1),
  base_ref: z.string(),
  head_ref: z.string(),
  draft: z.boolean(),
  fork: z.boolean(),
  html_url: z.string(),
  run_url: z.string().optional(),
  files: z.array(PrFile),
  changed_lines: z.number().int().min(0),
  /** Changed files hidden from the agent by triggers.ignore_paths. */
  ignored_files: z.array(z.string()),
});
export type PrContext = z.infer<typeof PrContext>;

export function readContext(ctxDir: string): PrContext {
  const path = join(ctxDir, CTX_FILES.pr);
  let json: unknown;
  try {
    json = JSON.parse(readFileSync(path, "utf8"));
  } catch (e) {
    throw new Error(`cannot read PR context ${path}: ${(e as Error).message}`);
  }
  const res = PrContext.safeParse(json);
  if (!res.success) {
    const issues = res.error.issues.map((i) => `  - ${i.path.join(".") || "(root)"}: ${i.message}`).join("\n");
    throw new Error(`invalid PR context ${path}:\n${issues}`);
  }
  return res.data;
}

/** Write JSON via a temp file in the same directory + fsync + rename (readers never see a partial file). */
export function writeJsonAtomic(path: string, data: unknown): void {
  const text = `${JSON.stringify(data, null, 2)}\n`;
  const tmp = join(dirname(path), `.${basename(path)}.${process.pid}.${randomBytes(6).toString("hex")}.tmp`);
  let fd: number | undefined;
  try {
    fd = openSync(tmp, "wx", 0o644);
    writeSync(fd, text);
    fsyncSync(fd);
    closeSync(fd);
    fd = undefined;
    renameSync(tmp, path);
  } catch (e) {
    if (fd !== undefined) {
      try {
        closeSync(fd);
      } catch {
        /* ignore */
      }
    }
    try {
      unlinkSync(tmp);
    } catch {
      /* ignore */
    }
    throw e;
  }
}

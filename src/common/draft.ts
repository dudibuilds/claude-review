/**
 * Draft review format — written by the xreview MCP (agent side, UNTRUSTED), read and re-validated
 * by the publisher. One JSON object per line in draft.jsonl.
 */
import { z } from "zod";
import { Severity } from "../policy/schema.js";

export const MAX_BODY_CHARS = 20000;

const SafePath = z
  .string()
  .min(1)
  .max(1024)
  .refine((p) => !p.startsWith("/") && !p.split("/").includes("..") && !p.includes("\0") && !p.includes("\\"), {
    message: "path must be repo-relative",
  });

export const DraftComment = z
  .object({
    type: z.literal("comment"),
    path: SafePath,
    line: z.number().int().min(1),
    end_line: z.number().int().min(1).optional(),
    body: z.string().min(1).max(MAX_BODY_CHARS),
    severity: Severity,
    category: z.string().max(60).optional(),
    suggestion: z.string().max(MAX_BODY_CHARS).optional(),
  })
  .strict();
export type DraftComment = z.infer<typeof DraftComment>;

export const DraftSummary = z
  .object({ type: z.literal("summary"), body: z.string().min(1).max(MAX_BODY_CHARS * 3) })
  .strict();

export const DraftVerdict = z
  .object({
    type: z.literal("verdict"),
    verdict: z.enum(["comment", "approve", "request_changes"]),
    reason: z.string().max(2000).default(""),
  })
  .strict();
export type DraftVerdict = z.infer<typeof DraftVerdict>;

export const DraftLabels = z
  .object({ type: z.literal("labels"), labels: z.array(z.string().min(1).max(50)).max(20) })
  .strict();

export const DraftFinish = z.object({ type: z.literal("finish") }).strict();

export const DraftEntry = z.discriminatedUnion("type", [
  DraftComment,
  DraftSummary,
  DraftVerdict,
  DraftLabels,
  DraftFinish,
]);
export type DraftEntry = z.infer<typeof DraftEntry>;

/** Collapsed view of a draft file after parsing (last summary/verdict wins, labels union). */
export interface Draft {
  comments: DraftComment[];
  summary?: string;
  verdict?: DraftVerdict;
  labels: string[];
  finished: boolean;
  invalidLines: number;
}

export function parseDraft(text: string, maxLines = 500): Draft {
  const draft: Draft = { comments: [], labels: [], finished: false, invalidLines: 0 };
  const lines = text.split("\n").filter((l) => l.trim() !== "");
  for (const [i, line] of lines.entries()) {
    if (i >= maxLines) {
      draft.invalidLines += lines.length - maxLines;
      break;
    }
    let json: unknown;
    try {
      json = JSON.parse(line);
    } catch {
      draft.invalidLines++;
      continue;
    }
    const parsed = DraftEntry.safeParse(json);
    if (!parsed.success) {
      draft.invalidLines++;
      continue;
    }
    const e = parsed.data;
    switch (e.type) {
      case "comment":
        draft.comments.push(e);
        break;
      case "summary":
        draft.summary = e.body;
        break;
      case "verdict":
        draft.verdict = e;
        break;
      case "labels":
        for (const l of e.labels) if (!draft.labels.includes(l)) draft.labels.push(l);
        break;
      case "finish":
        draft.finished = true;
        break;
    }
  }
  return draft;
}

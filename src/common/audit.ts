/**
 * Structured audit log: one JSON line per event on stderr (stdout is reserved for MCP stdio) and,
 * if XREPO_AUDIT_FILE is set, appended to that file. String values are passed through
 * redactSecrets. Never throws.
 */
import { appendFileSync } from "node:fs";
import { redactSecrets } from "./redact.js";

const MAX_STRING_CHARS = 10_000;
const MAX_DEPTH = 6;
const MAX_ITEMS = 200;

function cleanString(s: string): string {
  let out = redactSecrets(s).text;
  if (out.length > MAX_STRING_CHARS) {
    out = `${out.slice(0, MAX_STRING_CHARS)}…(+${out.length - MAX_STRING_CHARS} chars)`;
  }
  return out;
}

function sanitize(value: unknown, depth: number, seen: WeakSet<object>): unknown {
  switch (typeof value) {
    case "string":
      return cleanString(value);
    case "number":
      return Number.isFinite(value) ? value : String(value);
    case "boolean":
      return value;
    case "bigint":
      return value.toString();
    case "undefined":
      return undefined;
    case "symbol":
      return value.toString();
    case "function":
      return `[function ${value.name || "anonymous"}]`;
  }
  if (value === null) return null;
  const obj = value as object;
  if (seen.has(obj)) return "[circular]";
  if (depth >= MAX_DEPTH) return "[truncated]";
  seen.add(obj);
  try {
    if (value instanceof Error) {
      const e: Record<string, unknown> = { name: value.name, message: cleanString(value.message) };
      const code = (value as { code?: unknown }).code;
      if (typeof code === "string" || typeof code === "number") e.code = code;
      return e;
    }
    if (value instanceof Date) return Number.isNaN(value.getTime()) ? "Invalid Date" : value.toISOString();
    if (value instanceof Set || Array.isArray(value)) {
      const arr = [...(value as Iterable<unknown>)];
      const out = arr.slice(0, MAX_ITEMS).map((v) => sanitize(v, depth + 1, seen) ?? null);
      if (arr.length > MAX_ITEMS) out.push(`…(+${arr.length - MAX_ITEMS} items)`);
      return out;
    }
    if (value instanceof Map) value = Object.fromEntries(value);
    const out: Record<string, unknown> = {};
    let n = 0;
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      if (n++ >= MAX_ITEMS) {
        out["…"] = "truncated";
        break;
      }
      const s = sanitize(v, depth + 1, seen);
      if (s !== undefined) out[k] = s;
    }
    return out;
  } finally {
    seen.delete(obj);
  }
}

export function audit(event: string, fields?: Record<string, unknown>): void {
  try {
    const seen = new WeakSet<object>();
    const record: Record<string, unknown> = { ts: new Date().toISOString(), event: cleanString(String(event)) };
    if (fields && typeof fields === "object") {
      for (const [k, v] of Object.entries(fields)) {
        if (k === "ts" || k === "event") continue;
        const s = sanitize(v, 1, seen);
        if (s !== undefined) record[k] = s;
      }
    }
    const line = `${JSON.stringify(record)}\n`;
    try {
      process.stderr.write(line);
    } catch {
      /* ignore */
    }
    const file = process.env.XREPO_AUDIT_FILE;
    if (file) {
      try {
        appendFileSync(file, line, { encoding: "utf8", mode: 0o600 });
      } catch {
        /* ignore */
      }
    }
  } catch {
    /* never throw */
  }
}

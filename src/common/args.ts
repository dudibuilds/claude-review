/**
 * Strict CLI flag parsing on top of node:util parseArgs (no positionals, unknown flags rejected).
 */
import { parseArgs, type ParseArgsConfig } from "node:util";

export interface FlagSpec {
  type: "string" | "boolean";
  required?: boolean;
  default?: string | boolean;
  multiple?: boolean;
}

export type CliValues = Record<string, string | boolean | string[] | undefined>;

export function parseCli(argv: string[], spec: Record<string, FlagSpec>): CliValues {
  const options: NonNullable<ParseArgsConfig["options"]> = {};
  for (const [name, s] of Object.entries(spec)) {
    const opt: NonNullable<ParseArgsConfig["options"]>[string] = { type: s.type };
    if (s.multiple) opt.multiple = true;
    if (s.default !== undefined) {
      if (typeof s.default !== (s.type === "boolean" ? "boolean" : "string")) {
        throw new Error(`flag --${name}: default must be a ${s.type}`);
      }
      // parseArgs requires array defaults for `multiple` options.
      opt.default = (s.multiple ? [s.default] : s.default) as string | boolean | string[] | boolean[];
    }
    options[name] = opt;
  }

  let values: Record<string, unknown>;
  try {
    ({ values } = parseArgs({ args: argv, options, strict: true, allowPositionals: false }));
  } catch (e) {
    throw new Error((e as Error).message);
  }

  const missing: string[] = [];
  const out: CliValues = {};
  for (const [name, s] of Object.entries(spec)) {
    let v = values[name] as string | boolean | string[] | boolean[] | undefined;
    if (Array.isArray(v) && s.type === "boolean") v = v.length > 0 ? (v[v.length - 1] as boolean) : undefined;
    out[name] = v as string | boolean | string[] | undefined;
    if (s.required) {
      const empty =
        v === undefined || (typeof v === "string" && v.trim() === "") || (Array.isArray(v) && v.length === 0);
      if (empty) missing.push(`--${name}`);
    }
  }
  if (missing.length > 0) {
    throw new Error(`missing required flag${missing.length > 1 ? "s" : ""}: ${missing.join(", ")}`);
  }
  return out;
}

/**
 * ripgrep runner: spawned without a shell, stdin closed (rg reads stdin and hangs otherwise),
 * minimal environment, hard deadline (SIGKILL), streaming record parsing with early stop.
 *
 * Callers build the argument array; agent input only ever appears as the value of `--regexp=`,
 * `--glob=`, `--type=` or as a path after `--`, never as a flag.
 */
import { spawn } from "node:child_process";
import { existsSync } from "node:fs";

export interface RgRun {
  rgPath: string;
  /** Working directory (a repo root or a directory inside it). */
  cwd: string;
  args: string[];
  /** Absolute epoch-ms deadline; rg is killed when it passes. */
  deadline: number;
  /** Record separator in rg's stdout. */
  separator: "\n" | "\0";
  /** Called for every complete record; return false to stop rg early. */
  onRecord: (record: string) => boolean | void;
  /** Safety cap on bytes read from stdout (default 64 MiB). */
  maxBytes?: number;
  /** Aborting stops rg like an onRecord `false` (outcome.stopped). */
  signal?: AbortSignal;
}

export interface RgOutcome {
  /** rg exit code (null when killed). 0 = matches, 1 = no matches, 2 = error. */
  code: number | null;
  stderr: string;
  timedOut: boolean;
  /** Stopped early by onRecord (or by the byte cap). */
  stopped: boolean;
  /**
   * The working directory does not exist (e.g. a mirror repo deleted under a running review):
   * rg did not run. Callers skip that root instead of failing the whole search.
   */
  missingCwd?: boolean;
}

const MAX_STDERR = 8192;

/** Arguments every rg invocation starts with. */
export function baseRgArgs(maxFilesize: string): string[] {
  return [
    "--no-config",
    "--no-ignore", // policy exclude_globs replace .gitignore/.ignore (a PR must not hide files from search)
    "--hidden",
    "--no-follow",
    "--no-messages",
    "--color=never",
    // No BOM sniffing / transcoding: a UTF-16 file keeps its NUL bytes and counts as binary, as in
    // Read. Transcoded text would bypass the whole-file PEM scan, which reads the raw bytes.
    "--encoding=none",
    `--max-filesize=${maxFilesize}`,
    "--glob=!.git",
  ];
}

export function runRg(run: RgRun): Promise<RgOutcome> {
  return new Promise((resolve, reject) => {
    const remaining = run.deadline - Date.now();
    if (remaining <= 0) {
      resolve({ code: null, stderr: "", timedOut: true, stopped: false });
      return;
    }
    let child: ReturnType<typeof spawn>;
    try {
      child = spawn(run.rgPath, run.args, {
        cwd: run.cwd,
        stdio: ["ignore", "pipe", "pipe"],
        env: { PATH: process.env.PATH ?? "/usr/local/bin:/usr/bin:/bin" },
        shell: false,
        windowsHide: true,
      });
    } catch (e) {
      reject(new Error(`cannot start ripgrep: ${(e as Error).message}`));
      return;
    }
    const sepByte = run.separator === "\0" ? 0 : 10;
    const maxBytes = run.maxBytes ?? 64 * 1024 * 1024;
    /** Bytes of the record being received, as separate chunks: joined once, when it is complete. */
    let pending: Buffer[] = [];
    let bytes = 0;
    let stopped = false;
    let timedOut = false;
    let stderr = "";
    let settled = false;

    const kill = (): void => {
      try {
        child.kill("SIGKILL");
      } catch {
        /* already gone */
      }
    };
    const timer = setTimeout(() => {
      timedOut = true;
      kill();
    }, remaining);
    const onAbort = (): void => {
      if (stopped) return;
      stopped = true;
      kill();
    };
    if (run.signal?.aborted) onAbort();
    else run.signal?.addEventListener("abort", onAbort, { once: true });

    const emit = (buf: Buffer): void => {
      if (stopped) return;
      if (run.onRecord(buf.toString("utf8")) === false) {
        stopped = true;
        kill();
      }
    };

    // Linear in the output size: only the new chunk is scanned for separators, and a record that
    // spans many chunks (rg --multiline can print a whole file as one JSON record) is joined once.
    child.stdout!.on("data", (chunk: Buffer) => {
      if (stopped) return;
      bytes += chunk.length;
      let start = 0;
      for (let i = chunk.indexOf(sepByte, start); i !== -1 && !stopped; i = chunk.indexOf(sepByte, start)) {
        const piece = chunk.subarray(start, i);
        const rec = pending.length > 0 ? Buffer.concat([...pending, piece]) : piece;
        pending = [];
        emit(rec);
        start = i + 1;
      }
      if (stopped) pending = [];
      else if (start < chunk.length) pending.push(Buffer.from(chunk.subarray(start)));
      if (!stopped && bytes > maxBytes) {
        stopped = true;
        kill();
      }
    });
    child.stderr!.on("data", (chunk: Buffer) => {
      if (stderr.length < MAX_STDERR) stderr += chunk.toString("utf8").slice(0, MAX_STDERR - stderr.length);
    });
    child.on("error", (e: NodeJS.ErrnoException) => {
      clearTimeout(timer);
      run.signal?.removeEventListener("abort", onAbort);
      if (settled) return;
      settled = true;
      // spawn reports a missing cwd as "spawn rg ENOENT", like a missing binary: tell them apart.
      if (e.code === "ENOENT" && !existsSync(run.cwd)) {
        resolve({ code: null, stderr: "", timedOut: false, stopped: false, missingCwd: true });
        return;
      }
      reject(new Error(e.code === "ENOENT" ? "ripgrep (rg) is not installed" : `ripgrep failed: ${e.message}`));
    });
    const finish = (code: number | null): void => {
      clearTimeout(timer);
      run.signal?.removeEventListener("abort", onAbort);
      if (settled) return;
      settled = true;
      if (!stopped && !timedOut && pending.length > 0) emit(Buffer.concat(pending));
      resolve({ code, stderr, timedOut: timedOut && !stopped, stopped });
    };
    child.on("close", finish);
    // Once killed, do not wait for "close": anything else holding the pipes would delay it.
    child.on("exit", (code) => {
      if (!stopped && !timedOut) return;
      child.stdout?.destroy();
      child.stderr?.destroy();
      finish(code);
    });
  });
}

/** Run `fn` over `items` with at most `limit` concurrent calls; results keep input order. */
export async function mapLimit<T, R>(items: T[], limit: number, fn: (item: T, index: number) => Promise<R>): Promise<R[]> {
  const out = new Array<R>(items.length);
  let next = 0;
  const workers = Array.from({ length: Math.max(1, Math.min(limit, items.length)) }, async () => {
    while (next < items.length) {
      const i = next++;
      out[i] = await fn(items[i]!, i);
    }
  });
  await Promise.all(workers);
  return out;
}

/** Clean an rg error message for the agent ("rg: regex parse error: ..."). */
export function rgErrorText(stderr: string): string {
  const lines = stderr
    .split("\n")
    .map((l) => l.replace(/^rg: /, "").trimEnd())
    .filter((l) => l !== "");
  return lines.slice(0, 20).join("\n");
}

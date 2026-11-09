/**
 * Unified diff parser for `git diff` output (also accepts plain `diff -u` style file sections).
 *
 * Handles: diff --git headers, new/deleted files, renames and copies, mode changes, binary files
 * ("Binary files ... differ" and "GIT binary patch"), "\ No newline at end of file", C-quoted
 * paths, paths with spaces (git's trailing-TAB convention), CRLF headers.
 */

export interface DiffHunk {
  header: string;
  oldStart: number;
  oldLines: number;
  newStart: number;
  newLines: number;
  lines: string[];
}

export interface FileDiff {
  path: string;
  oldPath?: string;
  status: "added" | "modified" | "removed" | "renamed" | "binary";
  additions: number;
  deletions: number;
  hunks: DiffHunk[];
  /** Exact text of this file's section of the diff. */
  raw: string;
  /** New-file line numbers that are added or context lines inside a hunk. */
  rightLines: Set<number>;
  addedLines: Set<number>;
}

const HUNK_RE = /^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@/;

/** Decode a git C-style quoted path ("a/caf\303\251\tx"). Returns the input unchanged if not quoted. */
function unquote(s: string): string {
  if (!(s.length >= 2 && s.startsWith('"') && s.endsWith('"'))) return s;
  const body = s.slice(1, -1);
  const simple: Record<string, number> = { a: 7, b: 8, t: 9, n: 10, v: 11, f: 12, r: 13, '"': 34, "\\": 92 };
  const parts: Buffer[] = [];
  let lit = "";
  const flush = (): void => {
    if (lit !== "") parts.push(Buffer.from(lit, "utf8"));
    lit = "";
  };
  for (let i = 0; i < body.length; i++) {
    const ch = body[i]!;
    if (ch !== "\\" || i === body.length - 1) {
      lit += ch;
      continue;
    }
    flush();
    const next = body[i + 1]!;
    const oct = /^[0-7]{1,3}/.exec(body.slice(i + 1, i + 4));
    if (oct) {
      parts.push(Buffer.from([parseInt(oct[0], 8) & 0xff]));
      i += oct[0].length;
    } else if (Object.prototype.hasOwnProperty.call(simple, next)) {
      parts.push(Buffer.from([simple[next]!]));
      i += 1;
    } else {
      lit += "\\";
    }
  }
  flush();
  return Buffer.concat(parts).toString("utf8");
}

/** Path from a "--- " / "+++ " line: null for /dev/null; strips the a/ or b/ prefix. */
function headerPath(rest: string, prefix: "a/" | "b/"): string | null {
  let p = rest;
  if (p.startsWith('"')) {
    // Quoted path, possibly followed by a TAB + timestamp.
    const end = findClosingQuote(p);
    p = unquote(end > 0 ? p.slice(0, end + 1) : p);
  } else {
    const tab = p.indexOf("\t");
    if (tab >= 0) p = p.slice(0, tab);
  }
  if (p === "/dev/null") return null;
  return stripPrefix(p, prefix);
}

function stripPrefix(p: string, prefix: string): string {
  return p.startsWith(prefix) ? p.slice(prefix.length) : p;
}

function findClosingQuote(s: string): number {
  for (let i = 1; i < s.length; i++) {
    if (s[i] === "\\") i++;
    else if (s[i] === '"') return i;
  }
  return -1;
}

/** Parse the two paths of a "diff --git a/x b/y" line (best effort when unquoted with spaces). */
function gitHeaderPaths(rest: string): { a?: string; b?: string } {
  if (rest.startsWith('"')) {
    const end = findClosingQuote(rest);
    if (end < 0) return {};
    const a = unquote(rest.slice(0, end + 1));
    const tail = rest.slice(end + 1).trimStart();
    const b = tail.startsWith('"') ? unquote(tail) : tail;
    return { a: stripPrefix(a, "a/"), b: stripPrefix(b, "b/") };
  }
  if (rest.endsWith('"')) {
    const start = rest.lastIndexOf(' "');
    if (start >= 0) {
      return { a: stripPrefix(rest.slice(0, start), "a/"), b: stripPrefix(unquote(rest.slice(start + 1)), "b/") };
    }
  }
  // Unquoted: "a/P b/P" for same-name diffs; split in the middle when both halves agree.
  if (rest.startsWith("a/") && (rest.length - 5) % 2 === 0) {
    const n = (rest.length - 5) / 2; // "a/" + P + " b/" + P  =>  2|P| + 5
    const pa = rest.slice(2, 2 + n);
    const sep = rest.slice(2 + n, 2 + n + 3);
    const pb = rest.slice(2 + n + 3);
    if (sep === " b/" && pa === pb && pa !== "") return { a: pa, b: pb };
  }
  const idx = rest.indexOf(" b/");
  if (idx >= 0) return { a: stripPrefix(rest.slice(0, idx), "a/"), b: rest.slice(idx + 3) };
  return {};
}

interface Builder {
  fd: FileDiff;
  start: number;
  aPath?: string;
  bPath?: string;
  fromPath?: string | null; // from "---"
  toPath?: string | null; // from "+++"
  renameFrom?: string;
  renameTo?: string;
  copy: boolean;
  isNew: boolean;
  isDeleted: boolean;
  isBinary: boolean;
  isRename: boolean;
}

function newBuilder(start: number): Builder {
  return {
    fd: {
      path: "",
      status: "modified",
      additions: 0,
      deletions: 0,
      hunks: [],
      raw: "",
      rightLines: new Set(),
      addedLines: new Set(),
    },
    start,
    copy: false,
    isNew: false,
    isDeleted: false,
    isBinary: false,
    isRename: false,
  };
}

function finish(b: Builder, text: string, end: number): FileDiff | null {
  const fd = b.fd;
  fd.raw = text.slice(b.start, end);
  const newPath = b.renameTo ?? (b.toPath === null ? undefined : b.toPath) ?? b.bPath;
  const oldPath = b.renameFrom ?? (b.fromPath === null ? undefined : b.fromPath) ?? b.aPath;
  const isNew = b.isNew || (b.fromPath === null && b.toPath !== undefined && b.toPath !== null);
  const isDeleted = b.isDeleted || (b.toPath === null && b.fromPath !== undefined && b.fromPath !== null);
  if (isDeleted) {
    fd.path = oldPath ?? newPath ?? "";
  } else {
    fd.path = newPath ?? oldPath ?? "";
    if ((b.isRename || b.copy) && oldPath !== undefined && oldPath !== fd.path) fd.oldPath = oldPath;
  }
  if (fd.path === "") return null;
  if (b.isBinary) fd.status = "binary";
  else if (isNew || b.copy) fd.status = "added";
  else if (isDeleted) fd.status = "removed";
  else if (b.isRename) fd.status = "renamed";
  else fd.status = "modified";
  return fd;
}

export function parseUnifiedDiff(text: string): FileDiff[] {
  const files: FileDiff[] = [];
  if (typeof text !== "string" || text.length === 0) return files;

  // Line table with start offsets (split on "\n" only; CR stays part of content lines).
  const lines: string[] = [];
  const offsets: number[] = [];
  for (let pos = 0; pos < text.length; ) {
    const nl = text.indexOf("\n", pos);
    const end = nl === -1 ? text.length : nl;
    lines.push(text.slice(pos, end));
    offsets.push(pos);
    pos = nl === -1 ? text.length : nl + 1;
  }
  const offsetOf = (i: number): number => (i < offsets.length ? offsets[i]! : text.length);

  let cur: Builder | null = null;
  let hunk: DiffHunk | null = null;
  let oldLeft = 0;
  let newLeft = 0;
  let oldNo = 0;
  let newNo = 0;
  let inBinaryPatch = false;

  const close = (i: number): void => {
    if (cur) {
      const fd = finish(cur, text, offsetOf(i));
      if (fd) files.push(fd);
    }
    cur = null;
    hunk = null;
    inBinaryPatch = false;
  };

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]!;

    // Inside a hunk: consume body lines according to the header counts.
    if (hunk && cur) {
      const h: DiffHunk = hunk;
      const c: Builder = cur;
      const first = line.charAt(0);
      if (first === "\\") {
        h.lines.push(line); // "\ No newline at end of file"
        continue;
      }
      if (oldLeft > 0 || newLeft > 0) {
        if (first === " " || (line === "" && oldLeft > 0 && newLeft > 0)) {
          h.lines.push(line);
          c.fd.rightLines.add(newNo);
          oldNo++;
          newNo++;
          oldLeft--;
          newLeft--;
          continue;
        }
        if (first === "+" && newLeft > 0) {
          h.lines.push(line);
          c.fd.rightLines.add(newNo);
          c.fd.addedLines.add(newNo);
          c.fd.additions++;
          newNo++;
          newLeft--;
          continue;
        }
        if (first === "-" && oldLeft > 0) {
          h.lines.push(line);
          c.fd.deletions++;
          oldNo++;
          oldLeft--;
          continue;
        }
      }
      hunk = null; // hunk finished (or malformed); fall through to header handling
    }

    const header = line.endsWith("\r") ? line.slice(0, -1) : line;

    if (header.startsWith("diff --git ")) {
      close(i);
      cur = newBuilder(offsetOf(i));
      const p = gitHeaderPaths(header.slice("diff --git ".length));
      cur.aPath = p.a;
      cur.bPath = p.b;
      continue;
    }

    // Plain unified diff (no "diff --git" header): "--- x" immediately followed by "+++ y".
    if (header.startsWith("--- ") && (lines[i + 1] ?? "").startsWith("+++ ")) {
      if (!cur || cur.fd.hunks.length > 0 || cur.fromPath !== undefined || inBinaryPatch) {
        close(i);
        cur = newBuilder(offsetOf(i));
      }
      const c: Builder = cur;
      const next = lines[i + 1]!.replace(/\r$/, "");
      c.fromPath = headerPath(header.slice(4), "a/");
      c.toPath = headerPath(next.slice(4), "b/");
      i++;
      continue;
    }

    if (!cur) continue; // preamble / garbage before the first file
    const c: Builder = cur;

    if (header.startsWith("@@ ")) {
      const m = HUNK_RE.exec(header);
      if (!m || inBinaryPatch) continue;
      const h: DiffHunk = {
        header,
        oldStart: Number(m[1]),
        oldLines: m[2] === undefined ? 1 : Number(m[2]),
        newStart: Number(m[3]),
        newLines: m[4] === undefined ? 1 : Number(m[4]),
        lines: [],
      };
      c.fd.hunks.push(h);
      hunk = h;
      oldLeft = h.oldLines;
      newLeft = h.newLines;
      oldNo = h.oldStart;
      newNo = h.newStart;
      continue;
    }
    if (inBinaryPatch) continue;

    if (header.startsWith("new file mode")) c.isNew = true;
    else if (header.startsWith("deleted file mode")) c.isDeleted = true;
    else if (header.startsWith("rename from ")) {
      c.isRename = true;
      c.renameFrom = unquote(header.slice("rename from ".length));
    } else if (header.startsWith("rename to ")) {
      c.isRename = true;
      c.renameTo = unquote(header.slice("rename to ".length));
    } else if (header.startsWith("copy from ")) {
      c.copy = true;
      c.renameFrom = unquote(header.slice("copy from ".length));
    } else if (header.startsWith("copy to ")) {
      c.copy = true;
      c.renameTo = unquote(header.slice("copy to ".length));
    } else if (header.startsWith("Binary files ") && header.endsWith(" differ")) {
      c.isBinary = true;
      if (header.startsWith("Binary files /dev/null and ")) c.isNew = true;
      if (header.endsWith(" and /dev/null differ")) c.isDeleted = true;
    } else if (header === "GIT binary patch") {
      c.isBinary = true;
      inBinaryPatch = true;
    }
  }
  close(lines.length);
  return files;
}

/** True if every line in [line, endLine] is a RIGHT-side line of one single hunk. */
export function isCommentable(fd: FileDiff, line: number, endLine?: number): boolean {
  const end = endLine ?? line;
  if (!Number.isInteger(line) || !Number.isInteger(end) || line < 1 || end < line) return false;
  for (const h of fd.hunks) {
    if (h.newLines <= 0) continue;
    const last = h.newStart + h.newLines - 1;
    if (line < h.newStart || end > last) continue;
    for (let n = line; n <= end; n++) if (!fd.rightLines.has(n)) return false;
    return true;
  }
  return false;
}

export function changedLineCount(files: FileDiff[]): number {
  let n = 0;
  for (const f of files) n += f.additions + f.deletions;
  return n;
}

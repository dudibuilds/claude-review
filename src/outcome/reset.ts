/**
 * Usage-limit reset times as absolute instants (used to time retries, see retry.ts).
 *
 * classifyOutcome reports `reset_at` either as ISO-8601 (from an epoch) or as the raw text of the CLI
 * message: "1:32pm (UTC)", "Nov 12, 11:33am (UTC)", "3pm", "9:30 AM", "3pm (Europe/Berlin)",
 * "2 hours". resolveResetTime turns these into a Date:
 *   - ISO-8601 with a zone designator: as is;
 *   - "<n> minutes|hours|days" (also "in 2h"): relative to `now`;
 *   - wall-clock time, optionally preceded by a date ("Nov 12", "12 Nov", with or without a year and
 *     a weekday) or by a weekday alone ("Mon 9am", "Thursday 9am"), and followed by a zone ("(UTC)",
 *     "(Europe/Berlin)", "UTC", "GMT"). Without a zone the time is read in `defaultTimeZone` (the CLI
 *     prints the runner's local time, and the publisher runs on the same runners). A time without a
 *     date is the next occurrence of that time, allowing for the message being up to 6 hours old (a
 *     5-hour limit cannot mean tomorrow); a date without a year is the next occurrence of that date
 *     (up to one day old); a weekday alone (weekly limits) is the next occurrence of that weekday and
 *     time, up to one hour old: earlier than that, the same weekday means next week, which is what a
 *     weekly limit printed right before the publisher ran means.
 * Anything else (unknown zone, ambiguous text) is undefined: the caller then falls back to a backoff.
 */

const MONTHS = ["january", "february", "march", "april", "may", "june", "july", "august", "september", "october", "november", "december"];
const ISO_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(?::\d{2}(?:\.\d{1,9})?)?(?:Z|[+-]\d{2}:?\d{2})$/i;
const REL_RE = /^(?:in\s+)?(\d{1,4})\s*(m|mins?|minutes?|h|hrs?|hours?|d|days?)$/i;
const TIME_RE = /(?:^|[\s,])(?:at\s+)?(\d{1,2})(?::(\d{2}))?\s*(am|pm|a\.m\.|p\.m\.)?$/i;
const WEEKDAY = "(?:(?:mon|tues?|wed(?:nes)?|thu(?:rs)?|fri|sat(?:ur)?|sun)(?:day)?\\.?,?\\s+)?";
const DATE_MD_RE = new RegExp(`^${WEEKDAY}([a-z]{3,9})\\.?\\s+(\\d{1,2})(?:st|nd|rd|th)?(?:,?\\s+(\\d{4}))?$`, "i");
const DATE_DM_RE = new RegExp(`^${WEEKDAY}(\\d{1,2})(?:st|nd|rd|th)?\\s+([a-z]{3,9})\\.?(?:,?\\s+(\\d{4}))?$`, "i");
const ZONE_PAREN_RE = /\s*\(\s*([A-Za-z][A-Za-z0-9_+\-/]{0,63})\s*\)\s*$/;
const ZONE_WORD_RE = /\s+(utc|gmt|z)$/i;

const HOUR_MS = 3_600_000;
const DAY_MS = 24 * HOUR_MS;
/** A time-only reset may be this old (the message was printed before the publisher ran). */
const TIME_ONLY_TOLERANCE_MS = 6 * HOUR_MS;
const DATED_TOLERANCE_MS = DAY_MS;
/** A weekday-only reset ("Mon 9am") further in the past than this is next week's. */
const WEEKDAY_TOLERANCE_MS = HOUR_MS;
/** Weekday names accepted alone before a time (index = Date#getUTCDay). */
const WEEKDAYS: ReadonlyMap<string, number> = new Map(
  (
    [
      [0, ["sun", "sunday"]],
      [1, ["mon", "monday"]],
      [2, ["tue", "tues", "tuesday"]],
      [3, ["wed", "wednesday"]],
      [4, ["thu", "thur", "thurs", "thursday"]],
      [5, ["fri", "friday"]],
      [6, ["sat", "saturday"]],
    ] as const
  ).flatMap(([i, names]) => names.map((n) => [n, i] as const)),
);

const formatters = new Map<string, Intl.DateTimeFormat>();

function formatter(zone: string): Intl.DateTimeFormat {
  let f = formatters.get(zone);
  if (!f) {
    f = new Intl.DateTimeFormat("en-US", {
      timeZone: zone,
      hourCycle: "h23",
      year: "numeric",
      month: "numeric",
      day: "numeric",
      hour: "numeric",
      minute: "numeric",
      second: "numeric",
    });
    formatters.set(zone, f);
  }
  return f;
}

/** Canonical IANA name of `zone`, or undefined when Intl does not know it. */
export function validTimeZone(zone: string | undefined): string | undefined {
  if (typeof zone !== "string" || zone.trim() === "" || zone.length > 64) return undefined;
  const z = /^z$/i.test(zone.trim()) ? "UTC" : zone.trim();
  try {
    return new Intl.DateTimeFormat("en-US", { timeZone: z }).resolvedOptions().timeZone;
  } catch {
    return undefined;
  }
}

/** The process's own time zone (falls back to UTC). */
export function localTimeZone(): string {
  try {
    return validTimeZone(Intl.DateTimeFormat().resolvedOptions().timeZone) ?? "UTC";
  } catch {
    return "UTC";
  }
}

interface Wall {
  y: number;
  mo: number; // 0-based
  d: number;
  h: number;
  mi: number;
}

function wallOf(ms: number, zone: string): Wall {
  const parts = formatter(zone).formatToParts(new Date(ms));
  const get = (t: string): number => Number(parts.find((p) => p.type === t)?.value ?? Number.NaN);
  return { y: get("year"), mo: get("month") - 1, d: get("day"), h: get("hour") % 24, mi: get("minute") };
}

/** UTC offset (ms) of `zone` at the instant `ms`. */
function offsetAt(ms: number, zone: string): number {
  const parts = formatter(zone).formatToParts(new Date(ms));
  const get = (t: string): number => Number(parts.find((p) => p.type === t)?.value ?? Number.NaN);
  const asUtc = Date.UTC(get("year"), get("month") - 1, get("day"), get("hour") % 24, get("minute"), get("second"));
  return asUtc - (ms - (((ms % 1000) + 1000) % 1000));
}

/** Instant of a wall-clock time in `zone` (day / month overflow normalised like Date.UTC). */
function wallToUtc(w: Wall, zone: string): number {
  const guess = Date.UTC(w.y, w.mo, w.d, w.h, w.mi);
  let t = guess - offsetAt(guess, zone);
  const second = offsetAt(t, zone);
  if (guess - second !== t) t = guess - second;
  return t;
}

function monthIndex(name: string): number {
  const n = name.toLowerCase();
  if (n.length < 3) return -1;
  return MONTHS.findIndex((m) => m.startsWith(n) && (n.length === 3 || n === m || (m === "september" && n === "sept")));
}

/**
 * Absolute reset time of a usage-limit `reset_at` (see module doc), or undefined.
 * `defaultTimeZone`: zone for texts without one (default: the process's own zone).
 */
export function resolveResetTime(text: string | undefined, now: Date, defaultTimeZone?: string): Date | undefined {
  if (typeof text !== "string") return undefined;
  let s = text.replace(/\s+/g, " ").trim();
  const nowMs = now.getTime();
  if (s === "" || s.length > 120 || !Number.isFinite(nowMs)) return undefined;

  if (ISO_RE.test(s)) {
    const t = Date.parse(s);
    return Number.isFinite(t) ? new Date(t) : undefined;
  }
  const rel = REL_RE.exec(s);
  if (rel) {
    const n = Number(rel[1]);
    const unit = (rel[2] ?? "").toLowerCase();
    const ms = unit.startsWith("m") ? 60_000 : unit.startsWith("h") ? HOUR_MS : DAY_MS;
    return new Date(nowMs + n * ms);
  }

  let zoneText: string | undefined;
  const zp = ZONE_PAREN_RE.exec(s);
  if (zp) {
    zoneText = zp[1];
    s = s.slice(0, zp.index).trim();
  } else {
    const zw = ZONE_WORD_RE.exec(s);
    if (zw) {
      zoneText = zw[1];
      s = s.slice(0, zw.index).trim();
    }
  }
  const zone = zoneText !== undefined ? validTimeZone(zoneText) : (validTimeZone(defaultTimeZone) ?? localTimeZone());
  if (!zone) return undefined;

  const tm = TIME_RE.exec(s);
  if (!tm) return undefined;
  const minutesGiven = tm[2] !== undefined;
  const ampm = (tm[3] ?? "").toLowerCase().replace(/\./g, "");
  if (!minutesGiven && ampm === "") return undefined; // a bare number is not a time
  let h = Number(tm[1]);
  const mi = minutesGiven ? Number(tm[2]) : 0;
  if (mi > 59) return undefined;
  if (ampm !== "") {
    if (h < 1 || h > 12) return undefined;
    h = (h % 12) + (ampm === "pm" ? 12 : 0);
  } else if (h > 23) return undefined;

  const datePart = s
    .slice(0, tm.index)
    .replace(/[\s,]+$/, "")
    .replace(/\s+at$/i, "")
    .trim();
  const today = wallOf(nowMs, zone);

  if (datePart === "") {
    // Next occurrence of the time (yesterday / today / tomorrow), the message may be a few hours old.
    for (let k = -1; k <= 1; k++) {
      const t = wallToUtc({ y: today.y, mo: today.mo, d: today.d + k, h, mi }, zone);
      if (t >= nowMs - TIME_ONLY_TOLERANCE_MS) return new Date(t);
    }
    return undefined;
  }

  // A weekday alone ("Mon 9am", weekly limits): its next occurrence (k = -1 only near midnight).
  const weekday = WEEKDAYS.get(datePart.toLowerCase().replace(/\.$/, ""));
  if (weekday !== undefined) {
    const dow = new Date(Date.UTC(today.y, today.mo, today.d)).getUTCDay();
    for (let k = -1; k <= 7; k++) {
      if ((dow + k + 7) % 7 !== weekday) continue;
      const t = wallToUtc({ y: today.y, mo: today.mo, d: today.d + k, h, mi }, zone);
      if (t >= nowMs - WEEKDAY_TOLERANCE_MS) return new Date(t);
    }
    return undefined;
  }

  let mo = -1;
  let d = 0;
  let year: number | undefined;
  const md = DATE_MD_RE.exec(datePart);
  const dm = md ? null : DATE_DM_RE.exec(datePart);
  if (md) {
    mo = monthIndex(md[1] ?? "");
    d = Number(md[2]);
    year = md[3] !== undefined ? Number(md[3]) : undefined;
  } else if (dm) {
    d = Number(dm[1]);
    mo = monthIndex(dm[2] ?? "");
    year = dm[3] !== undefined ? Number(dm[3]) : undefined;
  } else {
    return undefined;
  }
  if (mo < 0 || d < 1 || d > 31) return undefined;
  const valid = (y: number): boolean => new Date(Date.UTC(y, mo, d)).getUTCDate() === d; // no "Feb 30"
  if (year !== undefined) {
    if (year < 2000 || year > 2200 || !valid(year)) return undefined;
    return new Date(wallToUtc({ y: year, mo, d, h, mi }, zone));
  }
  for (let y = today.y - 1; y <= today.y + 1; y++) {
    if (!valid(y)) continue;
    const t = wallToUtc({ y, mo, d, h, mi }, zone);
    if (t >= nowMs - DATED_TOLERANCE_MS) return new Date(t);
  }
  return undefined;
}

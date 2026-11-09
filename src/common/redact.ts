/**
 * Secret redaction for everything that leaves the sandbox (search output, audit lines, published
 * review text). Replaces each detected secret with "[REDACTED:<kind>]".
 *
 * Every pattern is designed to run in linear time on the V8 backtracking engine:
 * - token patterns start with a negative lookbehind for their own character class, so a scan can
 *   only begin at the start of a run (no quadratic re-scans of long runs);
 * - all other repetitions are bounded;
 * - PEM blocks are handled procedurally with indexOf (memoised END search).
 */

export interface RedactResult {
  text: string;
  count: number;
}

type Replacer = (match: string, ...groups: string[]) => string | null;

interface Rule {
  kind: string;
  re: RegExp;
  /** Returns the replacement text, or null to keep the match unchanged. Default: whole match. */
  replace?: Replacer;
}

const tag = (kind: string): string => `[REDACTED:${kind}]`;

const hasDigit = (s: string): boolean => /[0-9]/.test(s);

/** Values that are obviously placeholders / references, not secrets. */
function isPlaceholder(v: string): boolean {
  if (v.length > 512) return false;
  return (
    v.startsWith("[REDACTED:") ||
    /^\$\{[^}]*\}$/.test(v) || // ${VAR}, ${{ secrets.X }} (no spaces variant)
    /^\$[A-Za-z_][A-Za-z0-9_]*$/.test(v) || // $VAR
    /^\{\{.*\}\}$/.test(v) || // {{ template }}
    /^%\(.*\)s$/.test(v) || // %(name)s
    /^<[^<>]*>$/.test(v) || // <your-token>
    /^(.)\1*$/.test(v) // ******** / xxxxxxxx
  );
}

/**
 * Quoted values that are ordinary code rather than credentials: placeholders, URLs (credentials in
 * them have their own rule), lowercase paths, kebab/snake identifiers ("x-auth-token", "refresh_token") and
 * UPPER_SNAKE env-var names ("GITHUB_TOKEN").
 */
function isBenignValue(v: string): boolean {
  return (
    isPlaceholder(v) ||
    /^[A-Za-z][A-Za-z0-9+.-]*:\/\//.test(v) ||
    /^\.{0,2}\/[a-z0-9_.\/-]*$/.test(v) ||
    /^[a-z]+(?:[-_.][a-z]+)+$/.test(v) ||
    /^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+$/.test(v)
  );
}

/** "Basic" credentials are base64 of printable "user:password". */
const isBasicCredential = (tok: string): boolean =>
  /^[\x20-\x7e]*:[\x20-\x7e]*$/.test(Buffer.from(tok, "base64").toString("latin1"));

const RULES: Rule[] = [
  // GitHub tokens: classic (ghp_/gho_/ghu_/ghs_/ghr_ + 36) and fine-grained PATs.
  { kind: "github_token", re: /(?<![A-Za-z0-9_])gh[pousr]_[A-Za-z0-9]{36,255}(?![A-Za-z0-9])/g },
  { kind: "github_token", re: /(?<![A-Za-z0-9_])github_pat_[A-Za-z0-9_]{22,255}/g },
  // AWS access key ids.
  { kind: "aws_access_key", re: /(?<![A-Za-z0-9])(?:AKIA|ASIA)[A-Z0-9]{16}(?![A-Za-z0-9])/g },
  // Slack webhooks (before generic URL handling) and tokens.
  {
    kind: "slack_webhook",
    re: /(?:https?:\/\/)?hooks\.slack\.com\/(?:services|workflows|triggers)\/[A-Za-z0-9_\/-]{8,512}/g,
  },
  { kind: "slack_token", re: /(?<![A-Za-z0-9_-])xox[abposre]-[A-Za-z0-9-]{10,250}/g },
  { kind: "slack_token", re: /(?<![A-Za-z0-9_-])xapp-\d-[A-Za-z0-9-]{10,250}/g },
  // Google API keys.
  { kind: "google_api_key", re: /(?<![A-Za-z0-9_-])AIza[0-9A-Za-z_-]{35}(?![A-Za-z0-9_-])/g },
  // Google OAuth access tokens.
  { kind: "google_oauth_token", re: /(?<![A-Za-z0-9._-])ya29\.[A-Za-z0-9._-]{20,2048}/g },
  // Stripe secret / restricted keys (live and test) and webhook signing secrets.
  { kind: "stripe_key", re: /(?<![A-Za-z0-9_])(?:sk|rk)_(?:live|test)_[0-9A-Za-z]{16,255}/g },
  { kind: "stripe_key", re: /(?<![A-Za-z0-9_])whsec_[0-9A-Za-z]{24,255}/g },
  // GitLab personal access tokens, npm tokens, SendGrid keys, Hugging Face tokens.
  { kind: "gitlab_token", re: /(?<![A-Za-z0-9_-])glpat-[A-Za-z0-9_-]{20,255}/g },
  { kind: "npm_token", re: /(?<![A-Za-z0-9_])npm_[A-Za-z0-9]{36}(?![A-Za-z0-9])/g },
  { kind: "sendgrid_key", re: /(?<![A-Za-z0-9_.-])SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}(?![A-Za-z0-9_-])/g },
  { kind: "huggingface_token", re: /(?<![A-Za-z0-9_])hf_[A-Za-z]{34}(?![A-Za-z0-9_])/g },
  // Azure storage / Service Bus connection-string keys (keep the key name).
  {
    kind: "azure_key",
    re: /(?<![A-Za-z0-9])((?:Account|SharedAccess)Key=)([A-Za-z0-9+\/]{40,256}={0,2})/g,
    replace: (_m, prefix = "") => `${prefix}${tag("azure_key")}`,
  },
  // Anthropic keys (must run before the generic sk- rule).
  { kind: "anthropic_key", re: /(?<![A-Za-z0-9_-])sk-ant-[A-Za-z0-9_-]{20,300}/g },
  // OpenAI-style keys; require a digit to avoid kebab-case identifiers like "sk-spinner-...".
  {
    kind: "openai_key",
    re: /(?<![A-Za-z0-9_-])sk-(?:proj-)?[A-Za-z0-9_-]{20,300}/g,
    replace: (m) => (hasDigit(m) ? tag("openai_key") : null),
  },
  // JWTs (header.payload.signature, header and payload are base64url JSON objects).
  {
    kind: "jwt",
    re: /(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{8,4096}\.eyJ[A-Za-z0-9_-]{8,8192}\.[A-Za-z0-9_-]{0,4096}/g,
  },
  // Bearer tokens in headers / curl commands (keep the scheme word). A token without a digit must
  // be long enough not to be an identifier in prose or code ("Bearer accessTokenFromEnv").
  {
    kind: "bearer_token",
    re: /\b([Bb]earer[ \t]+)([A-Za-z0-9._~+\/-]{20,1024}=*)/g,
    replace: (_m, prefix = "", tok = "") =>
      hasDigit(tok) || (tok.length >= 32 && !isBenignValue(tok)) ? `${prefix}${tag("bearer_token")}` : null,
  },
  // HTTP Basic credentials (keep the scheme word). The value must decode to "user:password", so
  // prose ("Basic authentication") and expressions ("Basic " + encoded) are left alone.
  {
    kind: "basic_auth",
    re: /\b(Basic[ \t]+)([A-Za-z0-9+\/]{8,1024}={0,2})/gi,
    replace: (_m, prefix = "", tok = "") => (isBasicCredential(tok) ? `${prefix}${tag("basic_auth")}` : null),
  },
  // URLs with embedded credentials: scheme://user:pass@host -> scheme://[REDACTED]@host.
  {
    kind: "url_credentials",
    re: /\b([A-Za-z][A-Za-z0-9+.-]{1,20}:\/\/)([^\s\/@:"'`<>]{1,256}):([^\s\/@"'`<>]{1,256})@/g,
    replace: (_m, scheme = "", _user = "", pass = "") =>
      isPlaceholder(pass) ? null : `${scheme}${tag("url_credentials")}@`,
  },
  // A token as the whole userinfo: https://<token>@host (usernames are shorter or have no digit).
  {
    kind: "url_credentials",
    re: /\b(https?:\/\/)([A-Za-z0-9_-]{20,256})@/g,
    replace: (_m, scheme = "", tok = "") => (hasDigit(tok) ? `${scheme}${tag("url_credentials")}@` : null),
  },
  // AWS secret access keys (40 base64 chars) in unquoted ini / env assignments (~/.aws/credentials).
  {
    kind: "aws_secret_key",
    re: /(?<![A-Za-z0-9])(aws_secret_access_key[ \t]{0,5}[=:][ \t]{0,5})([A-Za-z0-9+\/]{40})(?![A-Za-z0-9+\/=])/gi,
    replace: (_m, head = "") => `${head}${tag("aws_secret_key")}`,
  },
  // Quoted assignments: password = "....", "api_key": '....', SECRET_TOKEN := "...." (keep key).
  {
    kind: "secret_assignment",
    re: /((?:password|passwd|passphrase|secret|token|api[_-]?key|access[_-]?key|private[_-]?key)[A-Za-z0-9_.-]{0,40}["'`]?[ \t]{0,5}(?::=|=>|=|:)[ \t]{0,5})(["'`])([^"'`\s\\]{8,512})\2/gi,
    replace: (_m, head = "", quote = "", value = "") =>
      isBenignValue(value) ? null : `${head}${quote}${tag("secret_assignment")}${quote}`,
  },
  // Unquoted env-file / shell assignments: an UPPER_SNAKE key ending in a secret word at the start
  // of a line, "=" with no spaces, a value up to whitespace (DB_PASSWORD=..., export X_TOKEN=...).
  {
    kind: "secret_assignment",
    re: /^([ \t]*(?:(?:export|ENV)[ \t]+|-[ \t]+)?[A-Z0-9_]{0,40}(?:PASSWORD|PASSWD|PASSPHRASE|SECRET(?:_KEY)?|TOKEN|API_?KEY|ACCESS_KEY|PRIVATE_KEY)=)([^\s"'`$(){}\[\];,<>]{8,512})(?!\S)/gm,
    replace: (_m, head = "", value = "") => (isBenignValue(value) ? null : `${head}${tag("secret_assignment")}`),
  },
];

/**
 * PEM private-key block rules, shared with src/search/text.ts (pemLineMap hides, line by line,
 * every line this module's redactPem removes from the same text, so both must use these).
 */
export const PEM_BEGIN_SOURCE = "-----BEGIN (?:[A-Z0-9]{1,20} ){0,3}PRIVATE KEY(?: BLOCK)?-----";
export const PEM_END = "-----END ";
/** An END further than this from the BEGIN marker does not close the block. */
export const PEM_MAX_BLOCK = 64 * 1024;
const PEM_BEGIN = new RegExp(PEM_BEGIN_SOURCE, "g");
/**
 * Body of an unterminated block (e.g. truncated output): base64 runs, whitespace, quotes / "+" /
 * literal "\\n" of string-concatenated keys, and RFC 1421 headers (Proc-Type: 4,ENCRYPTED).
 * Linear: the pattern always succeeds, so the engine never backtracks into the loop.
 */
const PEM_BODY = /(?:[\s"'`+,]|\\[nr]|[A-Za-z0-9+\/=]{16,}|(?:Proc-Type|DEK-Info|Comment):[^\r\n]{0,200})*/y;

/**
 * Where redaction of a block without an END (within PEM_MAX_BLOCK) stops: the end of what
 * PEM_BODY consumes from `bodyStart` (just after the BEGIN marker), at most PEM_MAX_BLOCK on.
 */
export function pemUnterminatedStop(text: string, bodyStart: number): number {
  PEM_BODY.lastIndex = bodyStart;
  PEM_BODY.exec(text);
  return Math.min(Math.max(PEM_BODY.lastIndex, bodyStart), bodyStart + PEM_MAX_BLOCK);
}

function redactPem(text: string): RedactResult {
  if (!text.includes("PRIVATE KEY")) return { text, count: 0 };
  PEM_BEGIN.lastIndex = 0;
  let out = "";
  let last = 0;
  let count = 0;
  let endSearchFrom = -1; // memo of the last END search
  let endFound = -1;
  let m: RegExpExecArray | null;
  while ((m = PEM_BEGIN.exec(text)) !== null) {
    const start = m.index;
    const bodyStart = start + m[0].length;
    if (!(endSearchFrom >= 0 && endSearchFrom <= bodyStart && (endFound === -1 || endFound >= bodyStart))) {
      endSearchFrom = bodyStart;
      endFound = text.indexOf(PEM_END, bodyStart);
    }
    let stop: number;
    if (endFound !== -1 && endFound - bodyStart <= PEM_MAX_BLOCK) {
      // Consume "-----END <label>-----" (bounded).
      const close = text.indexOf("-----", endFound + PEM_END.length);
      stop = close !== -1 && close - endFound < 120 ? close + 5 : endFound + PEM_END.length;
    } else {
      stop = pemUnterminatedStop(text, bodyStart);
    }
    out += text.slice(last, start) + tag("private_key");
    last = stop;
    count++;
    PEM_BEGIN.lastIndex = Math.max(stop, start + 1);
  }
  if (count === 0) return { text, count: 0 };
  return { text: out + text.slice(last), count };
}

export function redactSecrets(text: string): RedactResult {
  if (typeof text !== "string" || text.length === 0) return { text: typeof text === "string" ? text : "", count: 0 };
  const pem = redactPem(text);
  let out = pem.text;
  let count = pem.count;
  for (const rule of RULES) {
    rule.re.lastIndex = 0;
    out = out.replace(rule.re, (match: string, ...rest: unknown[]) => {
      // rest = [...groups, offset, input(, namedGroups)] — keep only string capture groups.
      const groups: string[] = [];
      for (const g of rest) {
        if (typeof g === "number") break;
        groups.push(typeof g === "string" ? g : "");
      }
      const replacement = rule.replace ? rule.replace(match, ...groups) : tag(rule.kind);
      if (replacement === null) return match;
      count++;
      return replacement;
    });
  }
  return { text: out, count };
}

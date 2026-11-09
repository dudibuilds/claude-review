import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { audit } from "../src/common/audit.js";
import { redactSecrets } from "../src/common/redact.js";

// Fake secrets are assembled at runtime so that secret scanners do not flag this file.
const rep = (s: string, n: number): string => s.repeat(n);
const GH_PAT = "ghp_" + rep("A1b2", 9); // 36 chars
const GH_FINE = "github_" + "pat_" + "11ABCDEFG0" + rep("x9", 20) + "_" + rep("Zq3", 19);
const AWS_ID = "AKIA" + "IOSFODNN7EXAMPLE";
const SLACK_TOKEN = "xoxb-" + "123456789012-1234567890123-" + rep("aB3d", 6);
const SLACK_HOOK = "https://hooks.slack.com/services/" + "T00000000/B00000000/" + rep("XXXXXXXX", 3);
const GOOGLE = "AIza" + "Sy" + rep("D3fG5hJ7kL", 3) + "abc";
const STRIPE = "sk_" + "live_" + rep("4eC39HqLyjWDarjtT1zdp7dc", 1);
const ANTHROPIC = "sk-" + "ant-" + "api03-" + rep("Ab9_-xY7", 10);
const OPENAI = "sk-" + "proj-" + rep("T3BlbkFJ", 6);
const JWT =
  "eyJ" + "hbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" + ".eyJ" + "zdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0" + ".SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
const PEM = [
  "-----BEGIN RSA PRIVATE KEY-----",
  "MIIEpAIBAAKCAQEA1c7+9z5Pad7OejecsQ0bu3aozN3tihPmljnnudb9G3HecSgs",
  "Vr8cXyZAD0p6kcgsHGJ1xqTeDzTuEzxvnSSqAjLq3XX3WuvfN0E1LuZ3+hmeeSAa",
  "-----END RSA PRIVATE KEY-----",
].join("\n");

describe("redactSecrets: true positives", () => {
  const cases: [string, string, string][] = [
    ["github classic token", `token: ${GH_PAT}`, "github_token"],
    ["github fine-grained PAT", `export GH=${GH_FINE}`, "github_token"],
    ["aws access key id", `aws_access_key_id = ${AWS_ID}`, "aws_access_key"],
    ["aws session key id", `id=ASIA${"Q2W3E4R5T6Y7U8I9"}`, "aws_access_key"],
    ["slack token", `SLACK=${SLACK_TOKEN}`, "slack_token"],
    ["slack webhook", `curl -X POST ${SLACK_HOOK} -d @msg.json`, "slack_webhook"],
    ["google api key", `key=${GOOGLE}`, "google_api_key"],
    ["stripe live key", `Stripe(${STRIPE})`, "stripe_key"],
    ["anthropic key", `ANTHROPIC_API_KEY=${ANTHROPIC}`, "anthropic_key"],
    ["openai key", `OPENAI_API_KEY=${OPENAI}`, "openai_key"],
    ["jwt", `Cookie: session=${JWT}; Path=/`, "jwt"],
    ["bearer token", `curl -H "Authorization: Bearer abc123def456ghi789jkl0" https://x`, "bearer_token"],
  ];
  for (const [name, input, kind] of cases) {
    it(name, () => {
      const r = redactSecrets(input);
      expect(r.count).toBeGreaterThanOrEqual(1);
      expect(r.text).toContain(`[REDACTED:${kind}]`);
      for (const secret of [GH_PAT, GH_FINE, AWS_ID, SLACK_TOKEN, SLACK_HOOK, GOOGLE, STRIPE, ANTHROPIC, OPENAI, JWT]) {
        expect(r.text).not.toContain(secret);
      }
    });
  }

  it("anthropic keys are not reported as openai keys", () => {
    expect(redactSecrets(ANTHROPIC).text).toBe("[REDACTED:anthropic_key]");
    expect(redactSecrets(`sk-${rep("aZ9x", 8)}`).text).toBe("[REDACTED:openai_key]");
  });

  it("PEM private key blocks (multi-line, escaped, OPENSSH, unterminated)", () => {
    const code = `const a = 1;\n${PEM}\nconst b = 2;`;
    const r = redactSecrets(code);
    expect(r).toEqual({ text: "const a = 1;\n[REDACTED:private_key]\nconst b = 2;", count: 1 });

    const escaped = `key = "-----BEGIN PRIVATE KEY-----\\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC\\n-----END PRIVATE KEY-----\\n"; next()`;
    expect(redactSecrets(escaped).text).toBe('key = "[REDACTED:private_key]\\n"; next()');

    const ssh = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\n-----END OPENSSH PRIVATE KEY-----";
    expect(redactSecrets(ssh).text).toBe("[REDACTED:private_key]");

    const truncated = "x\n-----BEGIN EC PRIVATE KEY-----\nMHcCAQEEIBkg4LVWM9nuwNSk3yByxZpYRTBnVJk5oY3LSwgcPDJroAoGCCqGSM49\nAwEHoUQDQgAE\n12: }; // more code";
    const t = redactSecrets(truncated);
    expect(t.count).toBe(1);
    expect(t.text).not.toContain("MHcCAQEEIBkg4LVWM9nuwNSk3yByxZpYRTBnVJk5oY3LSwgcPDJroAoGCCqGSM49");
    expect(t.text).toContain("}; // more code");
    expect(t.text.startsWith("x\n[REDACTED:private_key]")).toBe(true);
  });

  it("does not touch public keys / certificates", () => {
    const pub = "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE\n-----END PUBLIC KEY-----";
    expect(redactSecrets(pub)).toEqual({ text: pub, count: 0 });
  });

  it("URLs with embedded credentials keep scheme and host", () => {
    expect(redactSecrets("DATABASE_URL=postgres://admin:s3cr3tP4ss@db.internal:5432/app").text).toBe(
      "DATABASE_URL=postgres://[REDACTED:url_credentials]@db.internal:5432/app",
    );
    expect(redactSecrets("git clone https://x-access-token:ghs_abc@github.com/o/r.git").text).toBe(
      "git clone https://[REDACTED:url_credentials]@github.com/o/r.git",
    );
  });

  it("quoted secret assignments keep the key name", () => {
    const cases: [string, string][] = [
      [`password = "hunter2hunter2"`, `password = "[REDACTED:secret_assignment]"`],
      [`"api_key": "a8f5f167f44f4964e6c998dee827110c",`, `"api_key": "[REDACTED:secret_assignment]",`],
      [`client_secret: 'Xyz123abcDEF456'`, `client_secret: '[REDACTED:secret_assignment]'`],
      [`token := "tok_9f8e7d6c5b4a"`, `token := "[REDACTED:secret_assignment]"`],
      [`apikey="Q1w2E3r4T5y6"`, `apikey="[REDACTED:secret_assignment]"`],
      [`AWS_SECRET_ACCESS_KEY="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"`, `AWS_SECRET_ACCESS_KEY="[REDACTED:secret_assignment]"`],
      [`'db_password' => 'correcthorsebattery'`, `'db_password' => '[REDACTED:secret_assignment]'`],
      ["SECRET = `9b1deb4d3b7d4bad`", "SECRET = `[REDACTED:secret_assignment]`"],
    ];
    for (const [input, expected] of cases) {
      const r = redactSecrets(input);
      expect(r.text, input).toBe(expected);
      expect(r.count, input).toBe(1);
    }
  });

  it("more well-known token formats", () => {
    const cases: [string, string][] = [
      ["glpat-" + rep("aB3dE", 4), "gitlab_token"],
      ["npm_" + rep("aB3d", 9), "npm_token"],
      ["SG." + rep("aB3dE6", 3) + "abcd" + "." + rep("aB3dE6", 7) + "x", "sendgrid_key"],
      ["sk_" + "test_" + "4eC39HqLyjWDarjtT1zdp7dc", "stripe_key"],
      ["whsec_" + rep("aB3d", 8), "stripe_key"],
      ["xoxe-1-" + rep("aB3d", 10), "slack_token"],
      ["hf_" + rep("abcDEFghiJ", 3) + "klmN", "huggingface_token"],
      ["ya29." + rep("a0AfH6SM", 4), "google_oauth_token"],
      ["ya29." + rep("a0AfH6SM", 4) + "." + rep("xY9z", 5), "google_oauth_token"],
      ["ya29.c." + rep("b0AXv0zT", 4), "google_oauth_token"],
    ];
    for (const [secret, kind] of cases) {
      expect(redactSecrets(`key: ${secret} # x`).text, secret).toBe(`key: [REDACTED:${kind}] # x`);
    }
  });

  it("credentials in connection strings, auth headers and URLs keep their context", () => {
    const azureKey = rep("aB3d+/9Z", 11);
    const cases: [string, string][] = [
      [`AccountName=x;AccountKey=${azureKey};EndpointSuffix=core`, "AccountName=x;AccountKey=[REDACTED:azure_key];EndpointSuffix=core"],
      [`Endpoint=sb://x/;SharedAccessKeyName=root;SharedAccessKey=${azureKey}`, "Endpoint=sb://x/;SharedAccessKeyName=root;SharedAccessKey=[REDACTED:azure_key]"],
      [`curl -H "Authorization: Basic dXNlcjpwYXNzd29yZDEyMw==" x`, `curl -H "Authorization: Basic [REDACTED:basic_auth]" x`],
      [`headers = {"Authorization": "Basic YWRtaW46czNjcjN0"}`, `headers = {"Authorization": "Basic [REDACTED:basic_auth]"}`],
      [`xhr.setRequestHeader("Authorization", "Basic YWRtaW46czNjcjN0");`, `xhr.setRequestHeader("Authorization", "Basic [REDACTED:basic_auth]");`],
      [`'Authorization' => 'Basic YWRtaW46czNjcjN0',`, `'Authorization' => 'Basic [REDACTED:basic_auth]',`],
      [`proxy_set_header Authorization "Basic YWRtaW46czNjcjN0";`, `proxy_set_header Authorization "Basic [REDACTED:basic_auth]";`],
      [`headers["Authorization"] = "Basic YWRtaW46czNjcjN0"`, `headers["Authorization"] = "Basic [REDACTED:basic_auth]"`],
      [`http.Header{"Authorization": {"Basic YWRtaW46czNjcjN0"}}`, `http.Header{"Authorization": {"Basic [REDACTED:basic_auth]"}}`],
      ["const AUTH = `Basic YWRtaW46czNjcjN0`;", "const AUTH = `Basic [REDACTED:basic_auth]`;"],
      [`git clone https://${rep("0a1b2c3d4e", 4)}@github.com/o/r`, "git clone https://[REDACTED:url_credentials]@github.com/o/r"],
      [`Authorization: Bearer ${rep("abcdefGHIJ", 4)}`, "Authorization: Bearer [REDACTED:bearer_token]"],
      [`Authorization: Bearer abc_def-ghi_${rep("Xy9", 7)}`, "Authorization: Bearer [REDACTED:bearer_token]"],
      // A token with a digit is redacted even when it reads like an UPPER_SNAKE name.
      ["Authorization: Bearer AB12CD34_EF56GH78_IJ90KL12", "Authorization: Bearer [REDACTED:bearer_token]"],
    ];
    for (const [input, expected] of cases) expect(redactSecrets(input).text, input).toBe(expected);
  });

  it("unquoted env-file assignments keep the key", () => {
    const cases: [string, string][] = [
      ["DB_PASSWORD=hunter2hunter2", "DB_PASSWORD=[REDACTED:secret_assignment]"],
      ["export GITLAB_API_TOKEN=Zq3xWv8tYu # ci", "export GITLAB_API_TOKEN=[REDACTED:secret_assignment] # ci"],
      ["ENV JWT_SECRET=supersecretvalue", "ENV JWT_SECRET=[REDACTED:secret_assignment]"],
      ["      - CLIENT_SECRET=abcDEF123ghi\r", "      - CLIENT_SECRET=[REDACTED:secret_assignment]\r"],
      ["SECRET_KEY=django-insecure-0123456789abcdef", "SECRET_KEY=[REDACTED:secret_assignment]"],
      ["MINIO_SECRET_KEY=0123456789abcdef0123", "MINIO_SECRET_KEY=[REDACTED:secret_assignment]"],
      ["aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "aws_secret_access_key = [REDACTED:aws_secret_key]"],
      ['password = "Qw3r!ty://x"', 'password = "[REDACTED:secret_assignment]"'],
    ];
    for (const [input, expected] of cases) {
      const r = redactSecrets(input);
      expect(r.text, input).toBe(expected);
      expect(r.count, input).toBe(1);
    }
  });

  it("counts every secret and is idempotent", () => {
    const text = [`a=${GH_PAT}`, `b=${AWS_ID}`, `c = "${OPENAI}"`, PEM, `password: "Sup3rS3cret!"`].join("\n");
    const r = redactSecrets(text);
    expect(r.count).toBe(5);
    expect(redactSecrets(r.text)).toEqual({ text: r.text, count: 0 });
  });
});

describe("redactSecrets: false positives", () => {
  const benign = [
    "const token = getToken()",
    "password: string",
    "function setPassword(password: string): void {}",
    'const input = { type: "password", name: "pw" }',
    'const TOKEN_HEADER = "x-auth-token"',
    'const tokenType = "refresh_token"',
    'secretName: "DATABASE_PASSWORD"',
    'env: { GITHUB_TOKEN: "${{ secrets.GITHUB_TOKEN }}" }',
    'password = "${DB_PASSWORD}"',
    'secret: "********"',
    'apiKey: "<your-api-key-here>"',
    'tokenUrl: "https://oauth2.googleapis.com/token"',
    'const PASSWORD_RESET = "/auth/password/reset"',
    'password: "short"',
    'placeholder="Enter your password"',
    "task-management-service-for-everyone",
    "import 'sk-spinner-double-bounce-animation'",
    "risk-assessment-pipeline-for-orders",
    "https://github.com/acme/web/blob/main/src/a.ts",
    "git@github.com:acme/web.git",
    "ssh://git@github.com/acme/web.git",
    "http://localhost:8080/api",
    "commit 4e0e1df897e1d1c62cc34ba4198ecc6c02b2c878",
    "sha256-47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=",
    "The Bearer token is sent in the Authorization header",
    "const ghp = 'ghp_short'",
    "AKIASHORT",
    "eyJhbGciOi without dots",
    "-----BEGIN CERTIFICATE-----",
    "xoxb-short",
    // Ordinary code and config next to the newer rules.
    "password = getPassword()",
    "const password = await vault.read('db/password')",
    "  password: null",
    "  password: string",
    "  token: AccessToken",
    "  password: process.env.DB_PASSWORD",
    "  password: form.password1",
    "    secretAccessKey: process.env.R2_SECRET_ACCESS_KEY!",
    "  token: session?.oauth2?.accessToken",
    "  password: *db_password_ref2",
    "  secret: my-app-secret-2",
    "  token: newToken2,",
    // Unquoted YAML values are not redacted (the deny globs cover config files), so type
    // annotations and names are left alone.
    "  token: ERC721Token!",
    "  privateKey: Bytes32!",
    "  privateKey: P256.Signing.PrivateKey?",
    "  timeout: 30000000\n  password: 12345678",
    "  publicKey: Uint8Array\n  privateKey: Uint8Array",
    "    private_key: Ed25519PrivateKey",
    "  secret: Uint8Array",
    "  accessToken: AccessTokenV2",
    "  existingSecret: postgresql2",
    "  password: hunter2hunter2",
    "SECRET_KEY=${DJANGO_SECRET_KEY}",
    "SECRET_KEY_PATH=/run/secrets/django2",
    "  password: config.get(name1)",
    "    password: Optional[Secret1]",
    "  api_key: ${API_KEY_V2}",
    "PASSWORD=${DB_PASSWORD}",
    "GITHUB_TOKEN=$(gh auth token)",
    "TOKEN_PATH=/var/run/secrets/token",
    "PASSWORD_FILE=/run/secrets/db",
    "SECRET_NAME=prod-db-secret-2",
    "MAX_TOKENS=4096",
    "API_TOKEN=REPLACE_ME_WITH_TOKEN",
    "    password=password",
    "password = os.environ['DB_PASSWORD']",
    "const TOKEN=getToken()",
    "url: https://registry.npmjs.org/npm_" + "config",
    "ssh://git@github.com/acme/web.git",
    "https://user@example.com/path",
    "https://abcdefghijklmnopqrstuvwxyz@example.com",
    "Authorization: Basic ${btoa(user + ':' + pass)}",
    "Authorization: Basic authentication",
    "Basic configuration options",
    `xhr.setRequestHeader("Authorization", "Basic " + encoded);`,
    "proxy_set_header Authorization $http_authorization;",
    "Authorization: Bearer ${accessToken}",
    "Authorization: Bearer YOUR_ACCESS_TOKEN_GOES_HERE_NOW",
    "Bearer accessTokenFromEnv",
    "AccountKey=<storage-account-key>",
    "hf_loadPretrainedModel",
    "const sk_test_mode = true",
    "SG.setApiKey(process.env.SENDGRID_API_KEY)",
    "  tokenUrl: https://oauth2.googleapis.com/token",
  ];
  for (const line of benign) {
    it(JSON.stringify(line), () => {
      expect(redactSecrets(line)).toEqual({ text: line, count: 0 });
    });
  }

  it("handles empty input", () => {
    expect(redactSecrets("")).toEqual({ text: "", count: 0 });
  });
});

describe("redactSecrets: performance (linear time)", () => {
  const time = (input: string): number => {
    const t0 = performance.now();
    redactSecrets(input);
    return performance.now() - t0;
  };

  it("1MB of ordinary code with a few secrets", () => {
    const chunk = [
      "export function createOrder(input: OrderInput, token = getToken()): Promise<Order> {",
      "  const url = `${BASE}/orders?id=${input.id}`; // see https://example.com/docs",
      '  const headers = { Authorization: `Bearer ${token}`, "x-request-id": uuid() };',
      "  return fetch(url, { method: 'POST', headers, body: JSON.stringify(input) });",
      "}",
    ].join("\n");
    let big = "";
    while (big.length < 1_000_000) big += chunk + "\n";
    big += `\n${PEM}\nconst k = "${GH_PAT}";\n`;
    const t0 = performance.now();
    const r = redactSecrets(big);
    expect(performance.now() - t0).toBeLessThan(1500);
    expect(r.count).toBe(2);
  });

  it("adversarial inputs stay fast", () => {
    const n = 1_000_000;
    const inputs = [
      "-eyJ".repeat(n / 4),
      "eyJaaaaaaaaaa.".repeat(n / 14),
      "-sk-".repeat(n / 4),
      "sk-" + "a".repeat(n),
      "xoxb-".repeat(n / 5),
      "-----BEGIN RSA PRIVATE KEY-----\n".repeat(n / 32),
      "-----BEGIN PRIVATE KEY-----" + "A".repeat(n),
      'password="'.repeat(n / 10),
      'token: "' + "a".repeat(n),
      "a://b:".repeat(n / 6),
      "postgres://" + "u".repeat(n),
      "Bearer ".repeat(n / 7),
      "ghp_".repeat(n / 4),
      "AKIA".repeat(n / 4),
      "a".repeat(n),
      "DB_PASSWORD=" + "a".repeat(n),
      "DB_PASSWORD=x\n".repeat(n / 14),
      "  password: " + "a1".repeat(n / 2) + " x",
      "password: a1\n".repeat(n / 13),
      ("A".repeat(39) + "\n").repeat(n / 40),
      "aws_secret_access_key=".repeat(n / 22),
      "Authorization: Basic ".repeat(n / 21),
      "Basic ".repeat(n / 6),
      "Basic " + "A".repeat(n),
      "https://" + "a1".repeat(n / 2),
      "AccountKey=" + "A".repeat(n),
      "ya29.".repeat(n / 5),
    ];
    for (const input of inputs) {
      expect(time(input), input.slice(0, 30)).toBeLessThan(2000);
    }
  });
});

/* --------------------------------- audit -------------------------------- */

describe("audit", () => {
  let dir: string;
  const prevEnv = process.env.XREPO_AUDIT_FILE;
  beforeAll(() => {
    dir = mkdtempSync(join(tmpdir(), "xrepo-audit-"));
  });
  afterAll(() => {
    rmSync(dir, { recursive: true, force: true });
    if (prevEnv === undefined) delete process.env.XREPO_AUDIT_FILE;
    else process.env.XREPO_AUDIT_FILE = prevEnv;
  });
  afterEach(() => {
    vi.restoreAllMocks();
    delete process.env.XREPO_AUDIT_FILE;
  });

  const captureStderr = (): string[] => {
    const writes: string[] = [];
    vi.spyOn(process.stderr, "write").mockImplementation(((chunk: string | Uint8Array) => {
      writes.push(String(chunk));
      return true;
    }) as typeof process.stderr.write);
    return writes;
  };

  it("writes one JSON line to stderr (never stdout) with ts, event and redacted fields", () => {
    const writes = captureStderr();
    const stdout = vi.spyOn(process.stdout, "write");
    audit("publish.comment", {
      path: "a.ts",
      n: 3,
      ok: true,
      body: `leaked ${GH_PAT}`,
      nested: { list: [`x ${AWS_ID}`, 1], deep: { url: "https://u:p4ssw0rd@h.example/x" } },
      err: new Error(`boom ${SLACK_TOKEN}`),
      skip: undefined,
    });
    expect(stdout).not.toHaveBeenCalled();
    expect(writes).toHaveLength(1);
    const line = writes[0]!;
    expect(line.endsWith("\n")).toBe(true);
    expect(line.trim().includes("\n")).toBe(false);
    const rec = JSON.parse(line);
    expect(Object.keys(rec).slice(0, 2)).toEqual(["ts", "event"]);
    expect(new Date(rec.ts).toISOString()).toBe(rec.ts);
    expect(rec.event).toBe("publish.comment");
    expect(rec.path).toBe("a.ts");
    expect(rec.n).toBe(3);
    expect(rec.ok).toBe(true);
    expect(rec.body).toBe("leaked [REDACTED:github_token]");
    expect(rec.nested.list).toEqual(["x [REDACTED:aws_access_key]", 1]);
    expect(rec.nested.deep.url).toBe("https://[REDACTED:url_credentials]@h.example/x");
    expect(rec.err).toEqual({ name: "Error", message: "boom [REDACTED:slack_token]" });
    expect("skip" in rec).toBe(false);
    expect(line).not.toContain(GH_PAT);
  });

  it("appends to XREPO_AUDIT_FILE when set", () => {
    captureStderr();
    const file = join(dir, "audit.jsonl");
    process.env.XREPO_AUDIT_FILE = file;
    audit("a", { i: 1 });
    audit("b");
    const lines = readFileSync(file, "utf8").trim().split("\n").map((l) => JSON.parse(l));
    expect(lines.map((l) => l.event)).toEqual(["a", "b"]);
    expect(lines[0].i).toBe(1);
  });

  it("never throws (circular, bigint, unwritable file, failing stderr)", () => {
    const writes = captureStderr();
    process.env.XREPO_AUDIT_FILE = join(dir, "no/such/dir/audit.jsonl");
    const circ: Record<string, unknown> = { a: 1 };
    circ.self = circ;
    expect(() => audit("weird", { circ, big: 10n, fn: () => 1, sym: Symbol("s"), nan: NaN, set: new Set([1]) })).not.toThrow();
    const rec = JSON.parse(writes[0]!);
    expect(rec.circ.self).toBe("[circular]");
    expect(rec.big).toBe("10");
    expect(rec.nan).toBe("NaN");
    expect(rec.set).toEqual([1]);
    vi.restoreAllMocks();
    vi.spyOn(process.stderr, "write").mockImplementation(() => {
      throw new Error("EPIPE");
    });
    expect(() => audit("x", { a: 1 })).not.toThrow();
  });

  it("does not let fields override ts/event", () => {
    const writes = captureStderr();
    audit("real", { event: "fake", ts: "never" });
    const rec = JSON.parse(writes[0]!);
    expect(rec.event).toBe("real");
    expect(rec.ts).not.toBe("never");
  });
});

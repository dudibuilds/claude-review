#!/usr/bin/env node
/**
 * Turns every e2e/fixtures/<owner>/<repo>/ directory into a bare git repository
 * <out>/<owner>/<repo>.git with a single commit on `main`, so `xrepo sync` can mirror the fixtures
 * through a file:// URL template:
 *
 *   node e2e/make-bare-repos.mjs e2e/fixtures e2e/fixtures-bare
 *   xrepo sync --policy e2e/policy.yaml --mirror /tmp/mirror \
 *     --url-template "file://$PWD/e2e/fixtures-bare/{owner}/{repo}.git"
 *
 * git is spawned with argument arrays (no shell); author, committer and dates are fixed so the
 * commit SHAs are reproducible for identical fixture content.
 */
import { execFileSync } from "node:child_process";
import { cpSync, mkdirSync, mkdtempSync, readdirSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

const NAME_RE = /^[A-Za-z0-9_.-]+$/;
const [srcArg = "e2e/fixtures", outArg = "e2e/fixtures-bare"] = process.argv.slice(2);
const src = resolve(srcArg);
const out = resolve(outArg);

const env = {
  ...process.env,
  GIT_CONFIG_NOSYSTEM: "1",
  GIT_CONFIG_GLOBAL: "/dev/null",
  GIT_TERMINAL_PROMPT: "0",
  GIT_AUTHOR_NAME: "xrepo-review e2e",
  GIT_AUTHOR_EMAIL: "e2e@xrepo-review.invalid",
  GIT_COMMITTER_NAME: "xrepo-review e2e",
  GIT_COMMITTER_EMAIL: "e2e@xrepo-review.invalid",
  GIT_AUTHOR_DATE: "2026-01-01T00:00:00Z",
  GIT_COMMITTER_DATE: "2026-01-01T00:00:00Z",
};
const git = (args) => execFileSync("git", args, { env, stdio: ["ignore", "pipe", "inherit"] }).toString("utf8").trim();
const dirs = (p) => readdirSync(p).filter((n) => NAME_RE.test(n) && !n.startsWith(".") && statSync(join(p, n)).isDirectory()).sort();

let count = 0;
for (const owner of dirs(src)) {
  for (const repo of dirs(join(src, owner))) {
    const work = mkdtempSync(join(tmpdir(), "xrepo-fixture-"));
    try {
      cpSync(join(src, owner, repo), work, { recursive: true });
      git(["-C", work, "init", "-q", "-b", "main"]);
      git(["-C", work, "add", "-A"]);
      git(["-C", work, "commit", "-q", "--no-verify", "-m", `fixture ${owner}/${repo}`]);
      const dest = join(out, owner, `${repo}.git`);
      rmSync(dest, { recursive: true, force: true });
      mkdirSync(join(out, owner), { recursive: true });
      git(["clone", "-q", "--bare", work, dest]);
      const sha = git(["--git-dir", dest, "rev-parse", "HEAD"]);
      process.stdout.write(`${owner}/${repo} ${sha} ${dest}\n`);
      count++;
    } finally {
      rmSync(work, { recursive: true, force: true });
    }
  }
}
if (count === 0) {
  process.stderr.write(`no fixtures found under ${src}\n`);
  process.exit(1);
}

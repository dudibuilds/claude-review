import { describe, expect, it } from "vitest";
import { createGitHubApi, foldCommentsIntoBody, GITHUB_ACTIONS_LOGIN, isLineResolutionError } from "../src/publish/github.js";
import { commentMarker, STICKY_MARKER, type PlanReview } from "../src/publish/plan.js";

/* ------------------------------ fake GitHub ------------------------------ */

interface Call {
  method: string;
  path: string;
  query: URLSearchParams;
  body: unknown;
}

type Handler = (call: Call) => { status?: number; body?: unknown; headers?: Record<string, string> } | undefined;

const BASE = "https://api.test";

function fakeGitHub(routes: Record<string, Handler | { status?: number; body?: unknown; headers?: Record<string, string> }>) {
  const calls: Call[] = [];
  const fetchImpl = (async (input: string | URL | Request, init?: RequestInit) => {
    const url = new URL(typeof input === "string" ? input : input instanceof URL ? input.href : input.url);
    const method = (init?.method ?? "GET").toUpperCase();
    const body = typeof init?.body === "string" && init.body !== "" ? JSON.parse(init.body) : undefined;
    const call: Call = { method, path: url.pathname, query: url.searchParams, body };
    calls.push(call);
    const route = routes[`${method} ${url.pathname}`];
    const res = typeof route === "function" ? route(call) : route;
    if (!res) {
      return new Response(JSON.stringify({ message: "Not Found" }), { status: 404, headers: { "content-type": "application/json" } });
    }
    const status = res.status ?? 200;
    return new Response(status === 204 ? null : JSON.stringify(res.body ?? {}), {
      status,
      headers: { "content-type": "application/json", ...(res.headers ?? {}) },
    });
  }) as typeof fetch;
  return { calls, fetchImpl };
}

function api(routes: Parameters<typeof fakeGitHub>[0], extra: { selfLogin?: string } = {}) {
  const gh = fakeGitHub(routes);
  const client = createGitHubApi({
    token: "ghs_test",
    repo: "acme/api",
    prNumber: 7,
    headSha: "abc123",
    baseUrl: BASE,
    fetch: gh.fetchImpl,
    ...extra,
  });
  return { ...gh, client };
}

const forbidden = { status: 403, body: { message: "Resource not accessible by integration" } };
const unauthorized = { status: 401, body: { message: "A JSON web token could not be decoded" } };

/* --------------------------------- tests --------------------------------- */

describe("getAuthenticatedLogin", () => {
  it("uses GET /user for user tokens", async () => {
    const { client, calls } = api({ "GET /user": { body: { login: "octo-bot" } } });
    expect(await client.getAuthenticatedLogin()).toBe("octo-bot");
    expect(await client.getAuthenticatedLogin()).toBe("octo-bot");
    expect(calls.filter((c) => c.path === "/user")).toHaveLength(1); // memoized
  });

  it("uses GET /app slug when /user is not accessible", async () => {
    const { client } = api({ "GET /user": forbidden, "GET /app": { body: { slug: "acme-reviewer" } } });
    expect(await client.getAuthenticatedLogin()).toBe("acme-reviewer[bot]");
  });

  it("falls back to github-actions[bot] for GITHUB_TOKEN", async () => {
    const { client } = api({ "GET /user": forbidden, "GET /app": unauthorized });
    expect(await client.getAuthenticatedLogin()).toBe(GITHUB_ACTIONS_LOGIN);
  });

  it("prefers the configured selfLogin without any request", async () => {
    const { client, calls } = api({}, { selfLogin: "my-app[bot]" });
    expect(await client.getAuthenticatedLogin()).toBe("my-app[bot]");
    expect(calls).toHaveLength(0);
  });

  it("propagates unexpected errors", async () => {
    const { client } = api({ "GET /user": { status: 500, body: { message: "boom" } } });
    await expect(client.getAuthenticatedLogin()).rejects.toMatchObject({ status: 500 });
  });
});

describe("findStickyComment", () => {
  const routes = {
    "GET /user": forbidden,
    "GET /app": unauthorized,
    "GET /repos/acme/api/issues/7/comments": (c: Call) =>
      c.query.get("page") === "2"
        ? { body: [{ id: 30, user: { login: "github-actions[bot]" }, body: `${STICKY_MARKER}\nours` }] }
        : {
            body: [
              { id: 10, user: { login: "attacker" }, body: `${STICKY_MARKER}\nfake summary` },
              { id: 20, user: { login: "github-actions[bot]" }, body: "unrelated bot comment" },
              { id: 21, user: null, body: STICKY_MARKER },
            ],
            headers: { link: `<${BASE}/repos/acme/api/issues/7/comments?per_page=100&page=2>; rel="next"` },
          },
  };

  it("only returns comments authored by the token identity (paginated)", async () => {
    const { client } = api(routes);
    expect(await client.findStickyComment(STICKY_MARKER)).toEqual({ id: 30, body: `${STICKY_MARKER}\nours` });
  });

  it("returns undefined when only foreign comments carry the marker", async () => {
    const { client } = api({ ...routes, "GET /repos/acme/api/issues/7/comments": { body: [{ id: 10, user: { login: "attacker" }, body: STICKY_MARKER }] } });
    expect(await client.findStickyComment(STICKY_MARKER)).toBeUndefined();
  });

  it("matches the login case-insensitively and respects selfLogin", async () => {
    const { client } = api(
      { "GET /repos/acme/api/issues/7/comments": { body: [{ id: 5, user: { login: "My-App[bot]" }, body: `x ${STICKY_MARKER}` }] } },
      { selfLogin: "my-app[bot]" },
    );
    expect((await client.findStickyComment(STICKY_MARKER))?.id).toBe(5);
  });

  it("rejects an empty marker", async () => {
    const { client } = api({});
    await expect(client.findStickyComment("")).rejects.toThrow(/non-empty/);
  });
});

describe("listReviewCommentKeys", () => {
  it("collects keys from our review comments and review bodies only", async () => {
    const { client } = api(
      {
        "GET /repos/acme/api/pulls/7/comments": {
          body: [
            { id: 1, user: { login: "me[bot]" }, body: `a ${commentMarker("aaaaaaaaaaaa")}` },
            { id: 2, user: { login: "attacker" }, body: `b ${commentMarker("bbbbbbbbbbbb")}` },
            { id: 3, user: { login: "me[bot]" }, body: "no marker" },
          ],
        },
        "GET /repos/acme/api/pulls/7/reviews": {
          body: [
            { id: 9, user: { login: "me[bot]" }, body: `${commentMarker("cccccccccccc")} ${commentMarker("dddddddddddd")}` },
            { id: 8, user: { login: "someone" }, body: commentMarker("eeeeeeeeeeee") },
          ],
        },
      },
      { selfLogin: "me[bot]" },
    );
    expect([...(await client.listReviewCommentKeys())].sort()).toEqual(["aaaaaaaaaaaa", "cccccccccccc", "dddddddddddd"]);
  });
});

describe("createReview", () => {
  const review: PlanReview = {
    event: "COMMENT",
    body: "Automated review.",
    comments: [
      { path: "src/a.ts", line: 3, side: "RIGHT", body: `first ${commentMarker("111111111111")}` },
      { path: "src/`odd`.ts", line: 9, start_line: 7, side: "RIGHT", start_side: "RIGHT", body: `second ${commentMarker("222222222222")}` },
    ],
  };

  it("posts the review at the head SHA with inline comments", async () => {
    const { client, calls } = api({ "POST /repos/acme/api/pulls/7/reviews": { body: { id: 77 } } });
    expect(await client.createReview(review)).toEqual({ id: 77, inlineFallback: false });
    const body = calls[0]!.body as Record<string, unknown>;
    expect(body).toMatchObject({ commit_id: "abc123", event: "COMMENT", body: "Automated review." });
    expect(body.comments).toEqual([
      { path: "src/a.ts", line: 3, side: "RIGHT", body: review.comments[0]!.body },
      { path: "src/`odd`.ts", line: 9, side: "RIGHT", start_line: 7, start_side: "RIGHT", body: review.comments[1]!.body },
    ]);
  });

  it("on a 422 about lines, retries once with the comments folded into the body", async () => {
    let n = 0;
    const { client, calls } = api({
      "POST /repos/acme/api/pulls/7/reviews": () =>
        ++n === 1
          ? { status: 422, body: { message: "Unprocessable Entity", errors: ["Line could not be resolved"] } }
          : { body: { id: 78 } },
    });
    expect(await client.createReview(review)).toEqual({ id: 78, inlineFallback: true });
    expect(calls).toHaveLength(2);
    const retry = calls[1]!.body as Record<string, unknown>;
    expect(retry.comments).toBeUndefined();
    const body = String(retry.body);
    expect(body.startsWith("Automated review.")).toBe(true);
    expect(body).toContain("`src/a.ts` line 3");
    expect(body).toContain("``src/`odd`.ts`` lines 7-9");
    expect(body).toContain(commentMarker("111111111111"));
    expect(body).toContain(commentMarker("222222222222"));
  });

  it("does not retry other 422s or other errors", async () => {
    for (const res of [
      { status: 422, body: { message: "Unprocessable Entity", errors: ["Can not approve your own pull request"] } },
      { status: 403, body: { message: "Resource not accessible by integration" } },
    ]) {
      const { client, calls } = api({ "POST /repos/acme/api/pulls/7/reviews": res });
      await expect(client.createReview({ ...review, event: "APPROVE" })).rejects.toMatchObject({ status: res.status });
      expect(calls).toHaveLength(1);
    }
  });

  it("does not retry a 422 when there are no inline comments", async () => {
    const { client, calls } = api({
      "POST /repos/acme/api/pulls/7/reviews": { status: 422, body: { message: "Validation Failed", errors: ["line is invalid"] } },
    });
    await expect(client.createReview({ ...review, comments: [] })).rejects.toMatchObject({ status: 422 });
    expect(calls).toHaveLength(1);
    expect((calls[0]!.body as Record<string, unknown>).comments).toBeUndefined();
  });
});

describe("isLineResolutionError / foldCommentsIntoBody", () => {
  it("classifies GitHub's line errors", () => {
    const err = (message: string, status = 422) => Object.assign(new Error(message), { status });
    expect(isLineResolutionError(err("Unprocessable Entity: \"pull_request_review_thread.line must be part of the diff\""))).toBe(true);
    expect(isLineResolutionError(err("start_line must be part of the same hunk as the line."))).toBe(true);
    expect(isLineResolutionError(err("Path could not be resolved"))).toBe(true);
    expect(isLineResolutionError(err("Body is too long (maximum is 65536 characters)"))).toBe(false);
    expect(isLineResolutionError(err("Line could not be resolved", 500))).toBe(false);
  });

  it("drops whole comments instead of cutting when the body gets too large", () => {
    const big = "x".repeat(20000);
    const comments = Array.from({ length: 5 }, (_, i) => ({ path: `f${i}.ts`, line: 1, side: "RIGHT" as const, body: `${big} ${commentMarker(`${i}`.repeat(12))}` }));
    const out = foldCommentsIntoBody("head", comments);
    expect(out.length).toBeLessThanOrEqual(65000);
    expect(out).toContain("more comments omitted");
    for (const m of out.matchAll(/<!-- xrepo:c:(\d{12}) -->/g)) expect(out).toContain(`f${m[1]![0]}.ts`);
  });
});

describe("comments, checks, labels, dispatch", () => {
  it("creates and updates issue comments", async () => {
    const { client, calls } = api({
      "POST /repos/acme/api/issues/7/comments": { status: 201, body: { id: 5 } },
      "PATCH /repos/acme/api/issues/comments/5": { body: { id: 5 } },
    });
    expect(await client.createIssueComment("hello")).toEqual({ id: 5 });
    await client.updateIssueComment(5, "updated");
    expect(calls.map((c) => [c.method, c.path, (c.body as { body: string }).body])).toEqual([
      ["POST", "/repos/acme/api/issues/7/comments", "hello"],
      ["PATCH", "/repos/acme/api/issues/comments/5", "updated"],
    ]);
    await expect(client.createIssueComment("x".repeat(70000))).rejects.toThrow(/too long/);
  });

  it("creates a completed check run at the head SHA by default", async () => {
    const { client, calls } = api({ "POST /repos/acme/api/check-runs": { status: 201, body: { id: 9 } } });
    expect(await client.createCheckRun({ name: "xrepo-review", conclusion: "failure", title: "Blocked", summary: "s" })).toEqual({ id: 9 });
    expect(calls[0]!.body).toMatchObject({
      name: "xrepo-review",
      head_sha: "abc123",
      status: "completed",
      conclusion: "failure",
      output: { title: "Blocked", summary: "s" },
    });
    await client.createCheckRun({ name: "n", conclusion: "success", title: "t", summary: "s", head_sha: "other" });
    expect((calls[1]!.body as { head_sha: string }).head_sha).toBe("other");
  });

  it("adds labels (no request when empty) and ignores 404 on removal", async () => {
    const { client, calls } = api({
      "POST /repos/acme/api/issues/7/labels": { body: [] },
      "DELETE /repos/acme/api/issues/7/labels/xrepo-review%3Aretry": { status: 404, body: { message: "Label does not exist" } },
      "DELETE /repos/acme/api/issues/7/labels/boom": { status: 500, body: { message: "boom" } },
    });
    await client.addLabels([]);
    expect(calls).toHaveLength(0);
    await client.addLabels(["a", "a", "b"]);
    expect(calls[0]!.body).toEqual({ labels: ["a", "b"] });
    await expect(client.removeLabel("xrepo-review:retry")).resolves.toBeUndefined();
    await expect(client.removeLabel("boom")).rejects.toMatchObject({ status: 500 });
  });

  it("sends repository_dispatch and validates its inputs", async () => {
    const { client, calls } = api({ "POST /repos/acme/ops/dispatches": { status: 204 } });
    await client.repositoryDispatch("acme/ops", "xrepo-review.usage_limit", { outcome: "usage_limit", pr: 7 });
    expect(calls[0]!.body).toEqual({ event_type: "xrepo-review.usage_limit", client_payload: { outcome: "usage_limit", pr: 7 } });
    const eleven = Object.fromEntries(Array.from({ length: 11 }, (_, i) => [`k${i}`, i]));
    await expect(client.repositoryDispatch("acme/ops", "e", eleven)).rejects.toThrow(/at most 10/);
    await expect(client.repositoryDispatch("acme/../x", "e", {})).rejects.toThrow(/invalid repository/);
    await expect(client.repositoryDispatch("acme/ops", "", {})).rejects.toThrow(/1-100/);
  });

  it("validates constructor arguments", () => {
    expect(() => createGitHubApi({ token: "t", repo: "nope", prNumber: 1, headSha: "s" })).toThrow(/invalid repository/);
    expect(() => createGitHubApi({ token: "t", repo: "a/b", prNumber: 0, headSha: "s" })).toThrow(/invalid PR number/);
  });
});

# AGENTS.md

Instructions for coding agents working in this repository.

Start with `HANDOFF.md` (state, the owner's rules in section 2, open items), then `SPEC.md` (the
design contract; keep it in sync with the code) and `README.md`.

## Checks

```bash
npm ci
npm run build
npm run typecheck
npx vitest run
```

## Standing decisions

- 2026-11-10: The repository `dudibuilds/claude-review` is public. Never commit secrets, personal
  data, private repository names or machine-specific paths; everything pushed is world-readable.
  Details: `HANDOFF.md` section 7, item 8.
- 2026-11-10: The scheduled `xrepo-sync` (`sync.yml`) and `xrepo-retry` (`retry.yml`) workflows
  are disabled on GitHub, because no self-hosted runner exists yet and their runs would only queue.
  Re-enable both (`gh workflow enable sync.yml` / `retry.yml`) once a runner with the
  `xrepo-sync` / `xrepo-review` labels and the policy file is set up.

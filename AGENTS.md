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

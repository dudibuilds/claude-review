# syntax=docker/dockerfile:1
#
# xrepo-review image: the `xrepo` CLI with production dependencies, ripgrep and git.
# Used for the two MCP servers (`search-mcp`, `review-mcp`), which `prepare` starts with
#   docker run --rm -i --network none --read-only --cap-drop ALL --security-opt no-new-privileges
#     --pids-limit 256 --memory 1g --user 65534:65534 --tmpfs /tmp:rw,noexec,nosuid,size=64m ...
# and optionally for `sync` / `publish` / `retry`.
#
# Build:  docker build -f docker/Dockerfile -t xrepo-review:<version> .
#
# PRODUCTION: pin the base image by digest so a re-tag upstream cannot change what runs, e.g.
#   docker build --build-arg NODE_IMAGE=node:22-bookworm-slim@sha256:<digest> ...
# (look the digest up with `docker buildx imagetools inspect node:22-bookworm-slim`), and reference
# the resulting image by digest (ghcr.io/<org>/xrepo-review@sha256:...) in the workflows.
# No ctags and no ast-grep: xsearch is ripgrep only (SPEC "xsearch").
#
# RUNTIME_IMAGE (optional): base of the runtime stage; any glibc-based Debian/Ubuntu image with apt.
# Defaults to NODE_IMAGE. The node binary is copied from the build stage, so e.g.
#   --build-arg RUNTIME_IMAGE=ubuntu:24.04
# works where the Debian package mirrors are unreachable (docs/RESEARCH.md "Local verification").
ARG NODE_IMAGE=node:22-bookworm-slim
ARG RUNTIME_IMAGE=${NODE_IMAGE}

FROM ${NODE_IMAGE} AS build
WORKDIR /src
COPY package.json package-lock.json tsconfig.json ./
# --ignore-scripts: no dependency lifecycle scripts run during the build.
# Optional build secret `npm_ca`: extra CA certificates for a TLS-intercepting proxy, e.g.
#   docker build --secret id=npm_ca,src=/path/to/ca-bundle.crt ...  (never stored in a layer).
RUN --mount=type=secret,id=npm_ca \
    if [ -s /run/secrets/npm_ca ]; then export NODE_EXTRA_CA_CERTS=/run/secrets/npm_ca; fi; \
    npm ci --ignore-scripts --no-audit --no-fund
COPY src ./src
RUN npm run build \
 && npm prune --omit=dev --ignore-scripts --no-audit --no-fund \
 && rm -rf node_modules/.cache

FROM ${RUNTIME_IMAGE} AS runtime
RUN apt-get update \
 && apt-get install -y --no-install-recommends ripgrep git ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && rg --version && git --version
# Same node as the build stage (a no-op when RUNTIME_IMAGE is the node image).
COPY --from=build --chown=0:0 /usr/local/bin/node /usr/local/bin/node
RUN node --version
WORKDIR /app
COPY --from=build --chown=0:0 /src/package.json ./package.json
COPY --from=build --chown=0:0 /src/node_modules ./node_modules
COPY --from=build --chown=0:0 /src/dist ./dist
LABEL org.opencontainers.image.title="xrepo-review" \
      org.opencontainers.image.description="Policy-gated cross-repo PR review: sandboxed code-search MCP, review MCP, deterministic publisher" \
      org.opencontainers.image.licenses="MIT"
ENV NODE_ENV=production \
    NO_UPDATE_NOTIFIER=1
# Non-root (nobody). The app files are root-owned and read-only to this user.
USER 65534:65534
ENTRYPOINT ["node", "/app/dist/cli.js"]

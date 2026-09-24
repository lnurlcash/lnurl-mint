# Stage 1: install Python dependencies into a venv. Kept separate from the
# runtime stage so that if a future dependency ever needs a C toolchain to
# build, only this stage grows, not the shipped image. --no-install-project:
# the app is run straight from its source directory (see the runtime CMD),
# it's never needed as an installed package.
# pinned by digest, not just tag - both python:3.12-slim and uv:latest are
# mutable tags a registry/upstream compromise could move to a poisoned
# image, which would then be baked into every deployer's runtime .venv
# (COPY --from=builder below) unnoticed. Update deliberately: `docker pull
# python:3.12-slim` / `docker pull ghcr.io/astral-sh/uv:latest`, then swap
# in the new Digest each reports.
FROM python:3.12-slim@sha256:229a2c5bfa27522db7815ea81f9bed70af17ccb9de9fc7ad142b1877b5830d36 AS builder

COPY --from=ghcr.io/astral-sh/uv:latest@sha256:2d890623d310b57771ce840f0da5eed5fc6d657da05ffaa45d82797b53fa3abc /uv /usr/local/bin/uv

WORKDIR /app
COPY pyproject.toml uv.lock README.md ./
RUN uv sync --frozen --no-dev --no-cache --no-install-project


# Stage 2: Python runtime - no uv, no compilers, just the venv built above
# plus the app's own source
FROM python:3.12-slim@sha256:229a2c5bfa27522db7815ea81f9bed70af17ccb9de9fc7ad142b1877b5830d36 AS runtime

WORKDIR /app

COPY --from=builder /app/.venv ./.venv
COPY lnurl_mint/ ./lnurl_mint/

# /docs' Swagger UI assets are deliberately not committed to the repo (no
# static blobs in git) - fetched here, at image build time, from a pinned
# swagger-ui-dist version with a pinned sha256 per file (see
# scripts/fetch_swagger_ui.py), so a CDN serving anything but those exact
# bytes fails the build loudly. Same integrity guarantee as vendoring; the
# tradeoff is the CDN must be reachable at build time.
COPY scripts/fetch_swagger_ui.py scripts/
RUN python scripts/fetch_swagger_ui.py

# the version this image reports (see lnurl_mint/__init__.py) - passed by
# the release workflow from the git tag being released; local `make build`
# / CI's build-check leave it at this placeholder since neither is a release
ARG VERSION=0.0.0+unknown
ENV LNURL_MINT_VERSION=${VERSION}

ENV FORWARDED_ALLOW_IPS=*
ENV PATH="/app/.venv/bin:${PATH}"
# overridable at `docker run -e PORT=...` - with --network host (see the
# Makefile's `run` target) there's no docker -p mapping to remap a port
# with, so the app itself must listen on whatever port the host expects.
# 8111, matching the Makefile's own default (not 8000, which a full
# lnurl_server instance on the same host typically already claims)
ENV PORT=8111

# runtime settings (see lnurl_mint/config.py) are read from real
# environment variables - pass them with `docker run --env-file .env`
# (see .env.example for what's available), no file needs copying in
EXPOSE 8111

# non-root by default - limits what a future RCE in this app gains to this
# UID's own permissions, not root on the container. chown /app (not the
# COPY'd .venv/lnurl_mint under it, which only ever need to be read) so
# this user can still create mint.db/error.log there when not bind-mounted
# in. `make run`'s local dev flow overrides this UID at `docker run` time
# (--user, matching the host's own) so its bind-mounted data/mint.db keeps
# working regardless of what's baked in here.
RUN groupadd --gid 1000 app && useradd --uid 1000 --gid app --no-create-home --shell /usr/sbin/nologin app \
    && chown app:app /app
USER app

CMD ["sh", "-c", "uvicorn lnurl_mint.server:app --host 0.0.0.0 --port ${PORT}"]

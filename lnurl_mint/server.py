import asyncio
import contextlib
import logging
from contextlib import asynccontextmanager
from typing import AsyncGenerator

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.openapi.utils import get_openapi

from . import __version__
from .config import settings
from .errors import log_internal_error
from .frontend import frontend_router
from .node import LightningBackendConfig, fetch_node_info
from .router import publish_zap_receipts, reconcile_pending_melts, router


async def _reconcile_pending_melts_safely(funding_source: LightningBackendConfig) -> None:
    """reconcile_pending_melts, guarded against its own unexpected
    exceptions - called both at boot and from every healthy tick of
    _monitor_funding_source below, and an uncaught one from either call
    site must not crash the thing calling it (app startup entirely, or
    the background monitor loop for the rest of the process's life)."""
    try:
        await reconcile_pending_melts(funding_source)
    except Exception as exc:
        log_internal_error("reconcile_pending_melts failed", exc)


async def _monitor_funding_source(funding_source: LightningBackendConfig, healthy: bool) -> None:
    """Keeps re-probing the funding source in the background for as long
    as the process runs, every funding_source_health_check_interval_seconds
    - the one-shot check in lifespan below only catches a connection
    problem that already existed at boot (see issue #2: a mint whose
    funding source went bad *after* startup kept silently accepting melts
    it couldn't fulfill, with nothing in the logs to say why). `healthy` is
    the boot check's own already-known state, so the first tick here
    doesn't have to guess whether a transition actually happened.

    Health-state logging only fires on an actual transition (became
    unreachable / recovered), never every tick - otherwise this would just
    add its own noise every interval instead of a signal worth alerting
    on. reconcile_pending_melts, by contrast, runs on *every* healthy
    tick, not just a recovery - a note can be left stuck pending by a
    crash mid-melt (or _melt_pay's own left-pending fallback) at any time,
    not only right as the funding source happens to flip from unreachable
    to reachable, and reconcile_pending_melts is already cheap/a no-op
    when nothing is actually pending (see NoteStore.pending_melts). This
    is what used to require an operator to notice and restart the process
    by hand to pick such a note back up.

    Cancelled from lifespan at shutdown; CancelledError during the sleep
    is expected and left to propagate so that cancellation actually stops
    the loop."""
    while True:
        await asyncio.sleep(settings.funding_source_health_check_interval_seconds)
        try:
            await fetch_node_info(funding_source)
        except Exception as exc:
            if healthy:
                logging.warning(
                    f"{funding_source.backend} funding source became unreachable: {exc!s}. "
                    "Minting, melting, and offline verification are unavailable until it recovers."
                )
            healthy = False
            continue
        if not healthy:
            logging.info(f"{funding_source.backend} funding source is reachable again.")
        healthy = True
        await _reconcile_pending_melts_safely(funding_source)


async def _publish_zap_receipts_forever(funding_source: LightningBackendConfig) -> None:
    """NIP-57: a zapping client waits on the kind 9735 receipt, and this
    mint only learns an invoice settled by asking, so ask often (see
    router.publish_zap_receipts; a round with nothing pending is one
    cheap query). Cancelled from lifespan at shutdown."""
    while True:
        await asyncio.sleep(settings.zap_poll_interval_seconds)
        try:
            await publish_zap_receipts(funding_source)
        except Exception as exc:
            log_internal_error("publish_zap_receipts failed", exc)


@asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncGenerator[None, None]:
    # LUD-25: a bearer note's k1 lives in the query string of /w and
    # /w/cb for as long as the note is held - unlike an ephemeral
    # LUD-03 k1, that can be a long time, turning access logs into a
    # durable theft vector (see the spec's "Secrets in GET query strings").
    # uvicorn's default access log records the full request line, query
    # string included, for every route - disabled here rather than scoped
    # to just those two, since nothing below the ASGI app can tell
    # uvicorn's access logger apart per route. An operator wanting access
    # logs for the rest should add them at a reverse proxy in front of this
    # app, which is the layer the spec assigns this same responsibility to.
    #
    # This must happen here, in a startup hook, not at module import time:
    # both `fastapi run` and `fastapi dev` reconfigure "uvicorn.access"
    # themselves as part of their own startup sequence, which runs after
    # this module is imported but before requests are served - disabling
    # it at import time gets silently undone by that later reconfiguration.
    logging.getLogger("uvicorn.access").disabled = True

    # a misconfigured or unreachable funding source degrades every
    # funding-source-backed feature (minting, melting, LUD-25 offline
    # verification) silently and per-request rather than failing outright
    # (see signing.mint_pubkey/sign_note, router._funding_source) - that's
    # the right behavior for a request, but an operator should still find
    # out from the logs at boot, not from a wallet failing to mint hours
    # later. This check is purely diagnostic: it changes no runtime
    # behavior, and every route still probes the funding source fresh on
    # its own.
    funding_source = settings.funding_source()
    monitor_task: asyncio.Task | None = None
    zap_task: asyncio.Task | None = None
    if not funding_source.backend:
        logging.warning(
            "No funding source configured (FUNDINGSOURCE_BACKEND unset) - "
            "minting, melting, and offline verification are all unavailable."
        )
    else:
        healthy = False
        try:
            info = await fetch_node_info(funding_source)
        except Exception as exc:
            logging.warning(
                f"Configured {funding_source.backend} funding source is unreachable at startup: {exc!s}. "
                "Minting, melting, and offline verification will be unavailable until it responds."
            )
        else:
            healthy = True
            pubkey = info.uri.split("@")[0] if info.uri else "unknown pubkey"
            logging.info(
                f"Connected to {funding_source.backend} funding source: {info.alias or 'no alias'} ({pubkey})."
            )
            # a note left pending by a melt whose outcome never resolved
            # before this process last stopped would otherwise reject every
            # callback with "pending" forever - resolve what we now can
            # while the funding source is confirmed reachable (see
            # router.reconcile_pending_melts); only reachable here, not in
            # the branches above, since it needs a working funding_source
            await _reconcile_pending_melts_safely(funding_source)
        # spawned regardless of whether the boot check above succeeded -
        # even if unreachable right now, this is what notices it recovering
        # later, or breaking again after a boot-time success (see issue #2)
        monitor_task = asyncio.create_task(_monitor_funding_source(funding_source, healthy))
        if settings.nostr_key is not None:
            if funding_source.backend in ("lnd", "cln"):
                logging.info(f"NIP-57 zaps on: receipts signed as {settings.nostr_pubkey()}.")
                zap_task = asyncio.create_task(_publish_zap_receipts_forever(funding_source))
            else:
                logging.warning(
                    f"NOSTR_KEY is set but the {funding_source.backend} funding source cannot bind an invoice "
                    "to a description hash - zaps stay off."
                )

    yield

    for task in (monitor_task, zap_task):
        if task is not None:
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task

    # the spark backend's SDK singleton owns background tasks and its own
    # store (see spark.py) - disconnected here so they stop with the
    # process instead of being torn down under a request by the
    # interpreter. The boot-time fetch_node_info above already built it,
    # so this is a no-op exactly when spark was never configured/unreachable
    # the whole run.
    if funding_source.backend == "spark":
        from . import spark as spark_backend

        await spark_backend.shutdown()


app = FastAPI(
    title="lnurl-mint",
    description="Minimal lnurlcash (LUD-25, Lightning bearer assets) mint - LUD-03/LUD-06 only.",
    version=__version__,
    # the default /docs and /redoc load Swagger UI / ReDoc from a CDN;
    # frontend.py serves /docs from a local copy instead (fetched at build
    # time, see scripts/fetch_swagger_ui.py), and there is no local ReDoc
    docs_url=None,
    redoc_url=None,
    lifespan=lifespan,
)

# every endpoint here is a public LNURL wire-protocol endpoint, meant to be
# fetched cross-origin by arbitrary third-party wallets; none reads a
# cookie, so a wide-open origin is safe. allow_methods must cover more than
# GET: POST/DELETE /p/{username} (router.upsert_registered_username,
# delete_registered_username) are real cross-origin wallet calls too, and a
# non-GET method always triggers a real preflight (unlike a bodyless GET/
# POST, which Starlette's CORSMiddleware answers from its own unconditional
# simple-response path regardless of allow_methods - only the preflight
# path actually checks this list, which is exactly why a GET-only value
# here silently passed every existing GET-based check while still 400-ing
# any browser's DELETE preflight).
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

app.include_router(router)
app.include_router(frontend_router)


def _lnurl_openapi() -> dict:
    """Every route in `router` always answers 200, success or failure alike
    (see error_handler.LnurlErrorResponseHandler and each route's own
    `LnurlErrorResponse`-widened response_model) - the framework's default
    422 Validation Error can never actually happen on the wire, so it's
    stripped here rather than left in the generated schema to mislead a
    wallet author into handling a status this mint never sends. Cached on
    app.openapi_schema exactly like FastAPI's own default implementation
    (which this replaces wholesale, per its documented override pattern)."""
    if app.openapi_schema:
        return app.openapi_schema
    schema = get_openapi(title=app.title, version=app.version, description=app.description, routes=app.routes)
    for path_item in schema.get("paths", {}).values():
        for operation in path_item.values():
            operation.get("responses", {}).pop("422", None)
    schemas = schema.get("components", {}).get("schemas", {})
    schemas.pop("HTTPValidationError", None)
    schemas.pop("ValidationError", None)
    app.openapi_schema = schema
    return app.openapi_schema


app.openapi = _lnurl_openapi  # type: ignore[method-assign]

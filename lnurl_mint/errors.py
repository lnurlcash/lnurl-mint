import logging
import os
import secrets
import sys

from .config import settings


class _ErrorFileHandler(logging.FileHandler):
    def handleError(self, record: logging.LogRecord) -> None:
        # Python 3.14.8 also sends delayed-open failures through handleError
        # instead of raising them. Preserve log_internal_error's fallback,
        # including when logging.raiseExceptions is false in production.
        exc = sys.exc_info()[1]
        if isinstance(exc, OSError):
            raise exc
        super().handleError(record)


# a dedicated logger/file, kept separate from the app's normal (stdout)
# logging: internal error details (backend error bodies, connection info,
# database errors, ...) must never reach an anonymous caller directly (see
# error_handler.py, router.get_pay_callback, db.NoteStore.swap), but an
# operator still needs the full picture to debug a report - the id handed
# back to the caller is the only link between the two.
#
# Written next to the database (settings.database_path's own directory)
# rather than the process's cwd - there's no separate "data dir" setting,
# and this mint already treats that directory as where its persistent state
# lives (e.g. an operator pointing DATABASE_PATH at /var/lib/lnurl-mint/).
_logger = logging.getLogger("lnurl_mint.errors")
_logger.setLevel(logging.ERROR)
_logger.propagate = False
if not _logger.handlers:
    log_path = os.path.join(os.path.dirname(settings.database_path) or ".", "error.log")
    # delay=True: don't open (or fail to open) error.log until the first
    # error is actually logged, rather than at import time - an unwritable
    # directory must not crash the whole app over what's only a diagnostic
    # side channel, before a single request has even been served.
    _handler = _ErrorFileHandler(log_path, delay=True)
    _handler.setFormatter(logging.Formatter("%(asctime)s %(message)s"))
    _logger.addHandler(_handler)


def log_internal_error(context: str, exc: BaseException) -> str:
    """Logs `exc` (with its full traceback) to error.log under a random
    reference id, and returns a client-safe message carrying only that id -
    the exception's own text is never handed back on the wire."""
    reference = secrets.token_hex(4)
    try:
        _logger.error("[%s] %s: %s", reference, context, exc, exc_info=exc)
    except OSError as log_exc:
        # error.log itself is unwritable (see delay=True above) - falls
        # back to stdout (docker logs) rather than vanish entirely: _logger
        # has propagate=False specifically so this never doubles up with
        # error.log in the normal case, but that means an unwritable
        # error.log would otherwise leave no trace of this error anywhere,
        # not even a hint that error.log itself needs attention. Both
        # channels are operator-only either way (never caller-facing, see
        # this function's own docstring), so this fallback crosses no
        # trust boundary the primary path didn't already cross.
        logging.error("[%s] %s: %s (error.log unwritable: %s)", reference, context, exc, log_exc, exc_info=exc)
    return f"{context} (reference: {reference})."

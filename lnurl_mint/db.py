import sqlite3
import threading
import time
from typing import Callable

from .config import settings
from .errors import log_internal_error


class PendingNoteError(Exception):
    """Raised when a callback tries to burn a note that's mid-melt (see
    NoteStore.mark_pending) - a distinct case from "invalid or already
    spent" per the spec, which requires SERVICE reject it with
    {"status": "ERROR", "reason": "pending"} rather than a generic error."""


class OutputCollisionError(ValueError):
    """Raised when a replacement note id is already registered."""

    def __init__(self, note_id: str) -> None:
        super().__init__("already in use")
        self.note_id = note_id


class NoteStore:
    """The set of outstanding bearer notes this mint has issued, plus the
    pending mints (invoices that become a note once paid).

    No spendable secret is ever persisted: per LUD-25 a note is its taproot
    output key Q, and is stored under hex(Q) - the `cp1` a WALLET disclosed
    on the payRequest `comment` (see create_mint/settle_mint) or as `p1`/`p2`
    on a rotate/split/merge. A leaked database reveals how many notes are
    outstanding and for how much, but lets nobody spend them: this mint never
    has a spend to begin with, on top of never persisting one.

    Burned notes are kept with spent=1 rather than deleted, so a
    replayed k1 fails as "already spent" instead of dangling.

    Every operation that burns and/or mints runs in a single transaction:
    per the spec, if any k1 in a multi-k1 request is invalid the whole
    request fails and no note may be burned or minted.

    Also holds `usernames` (upsert_username/username_branch/
    claim_next_index): LUD-25's cx1 registration, letting a WALLET
    claim a Lightning Address that auto-mints `cp1` notes off its own
    branch. This is the one piece of durable per-caller state this mint
    keeps beyond bearer notes themselves - a public key binding, never a
    balance or an account."""

    def __init__(self, path: str) -> None:
        self.path = path
        self._lock = threading.Lock()
        self._conn: sqlite3.Connection | None = None

    @property
    def conn(self) -> sqlite3.Connection:
        if self._conn is None:
            self._conn = sqlite3.connect(self.path, check_same_thread=False)
            # wait up to 5s on a locked database instead of raising
            # "database is locked" at once (sqlite's default). Only matters
            # if a second process ever opens this same file (an operator
            # inspecting it with the sqlite CLI, or someone ignoring the
            # single-process rule in the README) - within this process all
            # access is serialized above anyway.
            self._conn.execute("PRAGMA busy_timeout = 5000")
            self._conn.execute(
                "CREATE TABLE IF NOT EXISTS notes ("
                " id TEXT PRIMARY KEY,"  # hex(Q), the note's taproot output key - never a spend
                " amount_msat INTEGER NOT NULL,"
                " spent INTEGER NOT NULL DEFAULT 0,"
                " pending INTEGER NOT NULL DEFAULT 0,"  # reserved by an in-flight melt, see mark_pending
                " pending_payment_hash TEXT)"  # that melt's invoice hash, for reconcile_pending_melts
            )
            self._conn.execute(
                "CREATE TABLE IF NOT EXISTS mints ("
                " payment_hash TEXT PRIMARY KEY,"
                " pr TEXT NOT NULL,"  # LUD-21 verify only, never the secret
                " amount_msat INTEGER NOT NULL,"
                " minted INTEGER NOT NULL DEFAULT 0,"
                " note_id TEXT)"  # the note this mint credits, as hex(Q), see create_mint
            )
            self._conn.execute(
                "CREATE TABLE IF NOT EXISTS melts ("
                " payment_hash TEXT PRIMARY KEY,"
                " pr TEXT NOT NULL,"  # the melted-into invoice, for LUD-25 melt verify
                " settled INTEGER NOT NULL DEFAULT 0)"  # see mark_melt_settled
            )
            self._conn.execute(
                "CREATE TABLE IF NOT EXISTS burns ("
                " burn_key TEXT PRIMARY KEY,"  # sorted, '|'-joined note ids burned together, see _burn_key
                " id TEXT NOT NULL,"  # the note minted (p1), as hex(Q)
                " id2 TEXT,"  # the change note (p2), as hex(Q); NULL unless this burn was a split
                " amount1_msat INTEGER NOT NULL,"  # value minted under id
                " amount2_msat INTEGER)"  # value minted under id2; NULL unless a split
            )
            self._conn.execute(
                "CREATE TABLE IF NOT EXISTS usernames ("
                " username TEXT PRIMARY KEY,"
                " cx1 TEXT NOT NULL,"  # hex(P || chain_code), LUD-25's watch-only branch export
                " next_index INTEGER NOT NULL DEFAULT 0)"  # see claim_next_index
            )
            # databases from before these columns were renamed: a mint's note
            # was `comment_hash`, and a burn's outputs `h`/`h2` - the same
            # hex(Q) values, only renamed
            self._rename_column_if_present(self._conn, "mints", "comment_hash", "note_id")
            self._rename_column_if_present(self._conn, "burns", "h", "id")
            self._rename_column_if_present(self._conn, "burns", "h2", "id2")
            # add-a-column migrations for databases created before that
            # column existed - this mint has no other migration mechanism,
            # so the alternative would be telling an operator to delete
            # their database (real outstanding notes, not just disposable
            # dev state). See _add_column_if_missing.
            #
            # a database from before LUD-21 verify has no `pr` on `mints` -
            # existing rows predate it entirely, so they get an empty one;
            # they're pending mint invoices, not notes, and short-lived
            self._add_column_if_missing(self._conn, "mints", "pr", "TEXT NOT NULL DEFAULT ''")
            # a database from before the async-melt pending lock has no
            # `pending` on `notes` - existing rows predate it entirely, so
            # nothing was ever mid-melt and 0 is the correct default
            self._add_column_if_missing(self._conn, "notes", "pending", "INTEGER NOT NULL DEFAULT 0")
            # a database from before reconcile_pending_melts has no way to
            # look a stranded pending note's invoice back up - existing
            # pending rows (if any) predate this column and are simply
            # invisible to pending_melts until the next mark_pending call
            # touches them, same as any other pre-migration NULL
            self._add_column_if_missing(self._conn, "notes", "pending_payment_hash", "TEXT")
            # a database from before LUD-25 comment protection has no
            # `note_id` (nor `comment_hash`) on `mints` - existing rows predate
            # it entirely, so they get NULL and never settle into a note
            self._add_column_if_missing(self._conn, "mints", "note_id", "TEXT")
            # when this mint credited a note - where a spend's relative
            # timelock (BIP-68, via lnurlcashkernel) starts counting. Rows
            # from before it get 0: credited "long ago", the right answer
            # for any relative lock on a note that old.
            self._add_column_if_missing(self._conn, "notes", "locked_at", "INTEGER NOT NULL DEFAULT 0")
            # a database from before mark_melt_settled has no `settled` on
            # `melts` - existing rows predate it entirely; router._melt_settled
            # falls back to a live is_payment_complete check whenever this is
            # 0, so a pre-migration row (correctly defaulted to 0) just costs
            # one such check the first time it's polled, same as before
            self._add_column_if_missing(self._conn, "melts", "settled", "INTEGER NOT NULL DEFAULT 0")
            # NIP-57 zaps (see nostr.py): the kind 9734 request an invoice
            # was bound to, verbatim, and the id of the kind 9735 receipt
            # once one was published; both NULL for an ordinary mint.
            # `created_at` bounds how long an unpaid zap invoice is polled
            # for settlement - rows from before it get 0 and are never
            # polled, which is right: they predate zaps entirely
            self._add_column_if_missing(self._conn, "mints", "zap_request", "TEXT")
            self._add_column_if_missing(self._conn, "mints", "zap_receipt", "TEXT")
            self._add_column_if_missing(self._conn, "mints", "created_at", "INTEGER NOT NULL DEFAULT 0")
            # NIP-05 (see upsert_username/nostr_pubkey): an optional npub
            # a WALLET supplied alongside cx1, hex-decoded. NULL for a
            # username registered before this existed, or that never
            # supplied one - both mean "not a NIP-05 name", same as any
            # other unregistered name (see router.get_nip05)
            self._add_column_if_missing(self._conn, "usernames", "nostr_pubkey", "TEXT")
            self._conn.commit()
        return self._conn

    @staticmethod
    def _add_column_if_missing(conn: sqlite3.Connection, table: str, column: str, ddl_suffix: str) -> None:
        """`ALTER TABLE table ADD COLUMN column ddl_suffix`, unless `column`
        is already there - table/column always come from literals in this
        file, never external input. The only migration mechanism this mint
        has; see the callers above for why each one exists."""
        columns = {row[1] for row in conn.execute(f"PRAGMA table_info({table})")}
        if column not in columns:
            conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {ddl_suffix}")

    @staticmethod
    def _rename_column_if_present(conn: sqlite3.Connection, table: str, old: str, new: str) -> None:
        """`ALTER TABLE table RENAME COLUMN old TO new`, if `old` is still
        there - table/column always come from literals in this file."""
        columns = {row[1] for row in conn.execute(f"PRAGMA table_info({table})")}
        if old in columns and new not in columns:
            conn.execute(f"ALTER TABLE {table} RENAME COLUMN {old} TO {new}")

    def create_mint(
        self,
        payment_hash: str,
        pr: str,
        amount_msat: int,
        note_id: str,
        zap_request: str | None = None,
    ) -> None:
        """Record an invoice that becomes a note worth `amount_msat` once it
        settles (see settle_mint). Only the payment hash and the invoice
        itself (`pr`, for LUD-21 verify) are stored.

        `note_id` is hex(Q) of the note to credit, from the `cp1` (or a
        bearer note's hex `h`) a WALLET sent as the LUD-12 `comment`, or
        derived by this mint for a registered Lightning Address. Raises
        ValueError, recording nothing, if it collides with an id already in
        use, either a note or another mint's - a WALLET generating a fresh
        note each time should never hit this honestly.

        `zap_request` is the NIP-57 kind 9734 the invoice was bound to,
        verbatim, for the receipt published once it settles (see
        unpublished_zaps)."""
        with self._lock, self.conn:
            if self._id_in_use(note_id):
                raise ValueError("already in use")
            self.conn.execute(
                "INSERT INTO mints (payment_hash, pr, amount_msat, note_id, zap_request, created_at)"
                " VALUES (?, ?, ?, ?, ?, ?)",
                (payment_hash, pr, amount_msat, note_id, zap_request, int(time.time())),
            )

    def _id_in_use(self, note_id: str) -> bool:
        """Whether `note_id` already names a note, spent or not, or the note
        some mint invoice will credit once paid - either way, crediting a
        new note under it would collide. Caller holds the lock."""
        return (
            self.conn.execute(
                "SELECT 1 FROM notes WHERE id = ? UNION SELECT 1 FROM mints WHERE note_id = ?",
                (note_id, note_id),
            ).fetchone()
            is not None
        )

    def id_in_use(self, note_id: str) -> bool:
        with self._lock:
            return self._id_in_use(note_id)

    def pending_zap_mints(self, created_since: int, limit: int) -> list[str]:
        """Payment hashes of the `limit` newest unpaid zap invoices created
        at or after `created_since` (unix seconds) - what the settlement
        poll checks. Older ones are left alone."""
        rows = self.conn.execute(
            "SELECT payment_hash FROM mints WHERE minted = 0 AND zap_request IS NOT NULL AND created_at >= ?"
            " ORDER BY created_at DESC LIMIT ?",
            (created_since, limit),
        ).fetchall()
        return [row[0] for row in rows]

    def unpublished_zaps(self) -> list[tuple[str, str, str]]:
        """(payment_hash, pr, zap_request) of every settled zap invoice
        whose kind 9735 receipt has not reached a relay yet."""
        rows = self.conn.execute(
            "SELECT payment_hash, pr, zap_request FROM mints"
            " WHERE minted = 1 AND zap_request IS NOT NULL AND zap_receipt IS NULL"
        ).fetchall()
        return [(row[0], row[1], row[2]) for row in rows]

    def mark_zap_published(self, payment_hash: str, receipt_id: str) -> None:
        with self._lock, self.conn:
            self.conn.execute("UPDATE mints SET zap_receipt = ? WHERE payment_hash = ?", (receipt_id, payment_hash))

    def zap_receipt_id(self, payment_hash: str) -> str | None:
        row = self.conn.execute("SELECT zap_receipt FROM mints WHERE payment_hash = ?", (payment_hash,)).fetchone()
        return row[0] if row else None

    def pending_mint(self, payment_hash: str) -> int | None:
        """amount_msat of the not-yet-minted invoice `payment_hash`, if any."""
        row = self.conn.execute(
            "SELECT amount_msat FROM mints WHERE payment_hash = ? AND minted = 0", (payment_hash,)
        ).fetchone()
        return row[0] if row else None

    def pending_mint_by_note_id(self, note_id: str) -> tuple[str, int] | None:
        """(payment_hash, amount_msat) of the not-yet-minted invoice whose
        note is `note_id`, if any - the
        comment-keyed counterpart to pending_mint, used to lazily settle a
        note looked up by its WALLET-chosen secret rather than by the
        funding invoice's own payment hash (see router._mint_settled_by_note_id)."""
        row = self.conn.execute(
            "SELECT payment_hash, amount_msat FROM mints WHERE note_id = ? AND minted = 0", (note_id,)
        ).fetchone()
        return (row[0], row[1]) if row else None

    def mint_uses_comment(self, payment_hash: str) -> bool:
        """Whether the mint invoice `payment_hash` used LUD-25 comment
        protection. Gates LUD-21 verify (router.verify_invoice): per spec,
        `SERVICE` MUST NOT offer verify for a mint's payment hash in the
        no-comment fallback, since there the payment preimage IS the note's
        entire bearer secret and verify would hand it to anyone holding the
        verify URL, not just the payer. Once a comment was used, the
        preimage redeems nothing, so verify is unconditionally safe there."""
        row = self.conn.execute("SELECT note_id FROM mints WHERE payment_hash = ?", (payment_hash,)).fetchone()
        return bool(row and row[0] is not None)

    def mint_pr(self, payment_hash: str) -> str | None:
        """The invoice `payment_hash` was minted from (LUD-21 verify's `pr`
        field), or None if this mint never issued that payment_hash at all -
        regardless of whether it has since settled or been spent."""
        row = self.conn.execute("SELECT pr FROM mints WHERE payment_hash = ?", (payment_hash,)).fetchone()
        return row[0] if row else None

    def mint_settled(self, payment_hash: str) -> bool:
        """Whether the mint invoice `payment_hash` has ever settled - for
        LUD-21 verify, which must keep answering True even after the note
        it produced is later rotated/split/merged/melted away (see
        note_amount, which only answers "is there a spendable note *right
        now*", a different question)."""
        row = self.conn.execute("SELECT minted FROM mints WHERE payment_hash = ?", (payment_hash,)).fetchone()
        return bool(row and row[0])

    def settle_mint(self, payment_hash: str) -> int | None:
        """Turn a settled mint invoice into an outstanding note, under the
        note_id create_mint recorded (already checked not to collide).
        Returns its value, or None if a concurrent request already minted it
        (in which case the note already exists and note_amount finds it), or
        if the mint names no note at all."""
        with self._lock, self.conn:
            cursor = self.conn.execute(
                "UPDATE mints SET minted = 1 WHERE payment_hash = ? AND minted = 0 AND note_id IS NOT NULL",
                (payment_hash,),
            )
            if cursor.rowcount != 1:
                return None
            row = self.conn.execute(
                "SELECT amount_msat, note_id FROM mints WHERE payment_hash = ?", (payment_hash,)
            ).fetchone()
            amount_msat, note_id = row
            self.conn.execute(
                "INSERT INTO notes (id, amount_msat, locked_at) VALUES (?, ?, ?)",
                (note_id, amount_msat, int(time.time())),
            )
            return amount_msat

    def note_record(self, note_id: str) -> tuple[int, int, bool, bool] | None:
        """(amount_msat, locked_at, spent, pending) of the note `note_id`,
        spent or not - what verifying a spend of it needs (locked_at starts
        a relative timelock), even for a burn being retried. None if this
        mint never issued it."""
        row = self.conn.execute(
            "SELECT amount_msat, locked_at, spent, pending FROM notes WHERE id = ?", (note_id,)
        ).fetchone()
        return (row[0], row[1], bool(row[2]), bool(row[3])) if row else None

    def note_amount(self, note_id: str) -> int | None:
        """Value of the outstanding (unspent) note with id `note_id`
        (hex(Q)), or None."""
        row = self.conn.execute("SELECT amount_msat FROM notes WHERE id = ? AND spent = 0", (note_id,)).fetchone()
        return row[0] if row else None

    def outstanding_msat(self) -> int:
        """Total value (msat) of every currently outstanding bearer note -
        this mint's total liability, for the transparency field on the
        mint-address discovery endpoint (router._mint_address_response) and
        the frontend one-pager. Includes notes reserved by an in-flight melt
        (pending = 1): mark_pending only reserves a note, it doesn't burn it
        (see its own docstring) - it's still outstanding, per LUD-25, until
        its melt actually settles.

        Only counts notes already materialized into this table - a freshly
        paid mint invoice this mint hasn't been asked about yet (GET /w, or
        a mutating callback) still only exists as a settled row in `mints`
        (see settle_mint's lazy-materialize-on-first-lookup design, e.g.
        router._mint_settled): the spec's own minting diagram makes that
        informational GET optional, so a WALLET is never required to make
        it happen. This total is therefore a lower bound, same as every
        other lazily-resolved fact this store reports about a note."""
        row = self.conn.execute("SELECT COALESCE(SUM(amount_msat), 0) FROM notes WHERE spent = 0").fetchone()
        return row[0]

    def note_spent(self, note_id: str) -> bool:
        """Whether `note_id` names a note this mint actually issued and has
        since burned - as opposed to one that never existed at all. Burned
        rows are kept (see the class docstring), so this is exactly what
        distinguishes "already spent" from "unknown" for callers that want
        to report which."""
        row = self.conn.execute("SELECT spent FROM notes WHERE id = ?", (note_id,)).fetchone()
        return bool(row and row[0])

    def note_pending(self, note_id: str) -> bool:
        """Whether `note_id` names an outstanding note currently reserved by
        an in-flight melt (see mark_pending). Distinct from note_spent: the
        note still exists and may return to circulation (restore), but right
        now no callback may touch it - and the informational withdraw
        endpoint must say so instead of advertising it as withdrawable (see
        router.get_withdraw), which is exactly the lie a sell-during-melt
        scam needs."""
        row = self.conn.execute("SELECT pending FROM notes WHERE id = ? AND spent = 0", (note_id,)).fetchone()
        return bool(row and row[0])

    def swap(
        self,
        burn_ids: list[str],
        mint_note_ids: list[str],
        mint_amounts: list[int],
    ) -> None:
        """Atomically burn every note in `burn_ids` and mint one fresh note
        per (id, amount) in zip(mint_note_ids, mint_amounts). Per LUD-25,
        `mint_note_ids` are output keys the WALLET itself generated and
        disclosed (`p1`/`p2` on the callback) - this side never generates,
        sees, or persists a spend, only registers a note under the Q it was
        given. Raises ValueError - burning and
        minting nothing - if any burn id is unknown, already spent, or
        repeated (the second burn of a duplicate finds it spent by the
        first). Raises OutputCollisionError if any mint id is repeated or
        collides with an existing note (a WALLET generating a fresh note
        each time should never hit this honestly), or names the note some
        mint invoice will credit once paid: planted there, it would block
        settle_mint's INSERT under the same key forever - bricking a paid
        mint for the price of a dust note. Raises
        PendingNoteError instead if any burn id is reserved by an
        in-flight melt (see mark_pending): per the spec, that's a
        distinct "pending" rejection, not a plain invalid/spent one.

        Also records this burn (see find_burn) keyed by the exact set of
        `burn_ids`, atomically alongside the burn/mint itself - LUD-25's
        "Retrying a mutation" needs this to answer a retried rotate/split/
        merge with the original result rather than "already spent", and
        recording it in the same transaction means a crash between burning
        the notes and recording the burn can never happen: either both
        happened, or neither did."""
        with self._lock:
            try:
                with self.conn:
                    seen_burn_ids: set[str] = set()
                    for note_id in burn_ids:
                        if note_id in seen_burn_ids:
                            raise ValueError("Invalid or already spent k1.")
                        seen_burn_ids.add(note_id)
                        row = self.conn.execute(
                            "SELECT pending FROM notes WHERE id = ? AND spent = 0", (note_id,)
                        ).fetchone()
                        if row is None:
                            raise ValueError("Invalid or already spent k1.")
                        if row[0]:
                            raise PendingNoteError("pending")

                    seen_mint_ids: set[str] = set()
                    for note_id in mint_note_ids:
                        if self.conn.execute(
                            "SELECT 1 FROM mints WHERE note_id = ?",
                            (note_id,),
                        ).fetchone():
                            # the note some mint invoice will credit: as taken
                            # as one already on file, per LUD-25
                            raise OutputCollisionError(note_id)
                        if (
                            note_id in seen_mint_ids
                            or self.conn.execute("SELECT 1 FROM notes WHERE id = ?", (note_id,)).fetchone()
                        ):
                            raise OutputCollisionError(note_id)
                        seen_mint_ids.add(note_id)

                    for note_id in burn_ids:
                        self.conn.execute("UPDATE notes SET spent = 1 WHERE id = ?", (note_id,))
                    locked_at = int(time.time())
                    for note_id, amount_msat in zip(mint_note_ids, mint_amounts):
                        self.conn.execute(
                            "INSERT INTO notes (id, amount_msat, locked_at) VALUES (?, ?, ?)",
                            (note_id, amount_msat, locked_at),
                        )
                    self.conn.execute(
                        "INSERT INTO burns (burn_key, id, id2, amount1_msat, amount2_msat) VALUES (?, ?, ?, ?, ?)",
                        (
                            self._burn_key(burn_ids),
                            mint_note_ids[0],
                            mint_note_ids[1] if len(mint_note_ids) > 1 else None,
                            mint_amounts[0],
                            mint_amounts[1] if len(mint_amounts) > 1 else None,
                        ),
                    )
            except sqlite3.Error as exc:
                # exc's own text (raw sqlite3 error) is never handed back on
                # the wire - see log_internal_error
                raise ValueError(log_internal_error("Note swap failed", exc)) from exc

    @staticmethod
    def _burn_key(note_ids: list[str]) -> str:
        """Canonical identity of a burn: the note ids it spent, order
        independent (a merge's k1s can arrive in any order) but otherwise
        exact - the same set burned by two different requests is the same
        burn. Used by both swap (to record a burn) and find_burn (to look
        one up)."""
        return "|".join(sorted(note_ids))

    def find_burn(self, note_ids: list[str]) -> tuple[str, str | None, int, int | None] | None:
        """If `note_ids`, as a set, were burned together by one earlier
        rotate/split/merge (see swap), returns the (id, id2, amount1_msat,
        amount2_msat) that burn produced - everything router.py's LUD-25
        retry handling (Retrying a mutation) needs to answer a retried
        callback with the original result instead of "already spent".
        None if this exact set of note_ids was never burned together as a
        single swap - including when it only partially overlaps one, which
        is a genuine conflict, not a replay, and must still fail normally."""
        row = self.conn.execute(
            "SELECT id, id2, amount1_msat, amount2_msat FROM burns WHERE burn_key = ?", (self._burn_key(note_ids),)
        ).fetchone()
        return tuple(row) if row else None

    def record_melt(self, payment_hash: str, pr: str) -> None:
        """Record which invoice a melt is paying into, keyed by its
        payment_hash - for LUD-25's melt verify (router.verify_invoice),
        which needs `pr` back long after the note(s) that funded it are
        burned and their own pending-melt bookkeeping (mark_pending/
        finalize_melt) is gone. Written unconditionally, the same way a
        mint invoice's `pr` is always stored regardless of VERIFY_ENABLED -
        recording is cheap and lets the endpoint simply serve whatever was
        recorded while the setting is on (and 404 everything when off,
        see router.verify_invoice)."""
        with self._lock, self.conn:
            self.conn.execute("INSERT OR IGNORE INTO melts (payment_hash, pr) VALUES (?, ?)", (payment_hash, pr))

    def melt_pr(self, payment_hash: str) -> str | None:
        """The invoice a melt paid into (LUD-25 verify's `pr` field), or
        None if this mint never recorded a melt for that payment_hash."""
        row = self.conn.execute("SELECT pr FROM melts WHERE payment_hash = ?", (payment_hash,)).fetchone()
        return row[0] if row else None

    def mark_melt_settled(self, payment_hash: str) -> None:
        """Records that this melt's outgoing payment has been positively
        confirmed settled - called once (router._melt_pay/
        reconcile_pending_melts) right alongside the finalize_melt that
        burns its note(s) for good, since at that point this mint has
        already independently established the outcome (either pay_invoice's
        own success response, or a since-confirmed is_payment_complete
        retry) and has no reason to re-derive it later.

        This is what LUD-25 melt verify (router._melt_settled) checks
        first, before ever re-querying the funding source: right after a
        payment lands, a live is_payment_complete call can still lag or
        answer inconsistently for a moment (a backend's own payment record
        catching up asynchronously - see is_payment_complete's own
        docstring), which would otherwise make verify report `settled:
        false` for a melt this mint itself already knows completed."""
        with self._lock, self.conn:
            self.conn.execute("UPDATE melts SET settled = 1 WHERE payment_hash = ?", (payment_hash,))

    def melt_settled(self, payment_hash: str) -> bool:
        """Whether mark_melt_settled has already confirmed this melt
        locally - the fast, authoritative path router._melt_settled checks
        before falling back to a live is_payment_complete call."""
        row = self.conn.execute("SELECT settled FROM melts WHERE payment_hash = ?", (payment_hash,)).fetchone()
        return bool(row and row[0])

    def mark_pending(self, note_ids: list[str], payment_hash: str) -> None:
        """Reserve `note_ids` for an in-flight melt without burning them yet.
        Per the spec, SERVICE MUST NOT burn a melted k1 until its outgoing
        payment actually settles, but every other callback naming one of
        these ids meanwhile (another melt, a rotate, a split, a merge) MUST
        be rejected with reason "pending" - see swap and this method's
        raises. All-or-nothing, like swap. Follow with finalize_melt once
        the payment settles, or restore if it doesn't - or, if the process
        stops before either happens, reconcile_pending_melts picks up
        `payment_hash` (persisted alongside the reservation, since that's
        what a later confirmation check needs) at the next boot."""
        with self._lock, self.conn:
            for note_id in note_ids:
                row = self.conn.execute("SELECT pending FROM notes WHERE id = ? AND spent = 0", (note_id,)).fetchone()
                if row is None:
                    raise ValueError("Invalid or already spent k1.")
                if row[0]:
                    raise PendingNoteError("pending")
            for note_id in note_ids:
                self.conn.execute(
                    "UPDATE notes SET pending = 1, pending_payment_hash = ? WHERE id = ?", (payment_hash, note_id)
                )

    def finalize_melt(self, note_ids: list[str]) -> None:
        """Burn notes for good once their melt's outgoing payment has
        settled (or is confirmed/assumed unrecoverable - see router.py) -
        the counterpart to mark_pending that actually spends them. A melt
        mints nothing, unlike swap."""
        with self._lock, self.conn:
            for note_id in note_ids:
                self.conn.execute(
                    "UPDATE notes SET spent = 1, pending = 0, pending_payment_hash = NULL WHERE id = ?", (note_id,)
                )

    def restore(self, note_ids: list[str]) -> None:
        """Release notes reserved by mark_pending after their melt's
        outgoing payment failed (and is confirmed not to have gone through)
        - the notes were never burned, so this just clears the reservation,
        leaving them outstanding again."""
        with self._lock, self.conn:
            for note_id in note_ids:
                self.conn.execute("UPDATE notes SET pending = 0, pending_payment_hash = NULL WHERE id = ?", (note_id,))

    def pending_melts(self) -> dict[str, list[str]]:
        """Every note currently reserved by an in-flight melt (see
        mark_pending), grouped by the payment_hash their outgoing payment
        was for - every note_id burned together into one melt shares the
        same hash, the same grouping mark_pending itself received. A note
        only shows up here across a restart if its melt's outcome was never
        resolved before the process stopped (a crash, or _melt_pay's own
        left-pending fallback for a genuinely unconfirmable outcome - see
        its docstring); reconcile_pending_melts is what resolves it.
        Excludes pre-migration pending rows with no recorded hash (see the
        ALTER TABLE note above) - nothing else can look their invoice up."""
        grouped: dict[str, list[str]] = {}
        for note_id, payment_hash in self.conn.execute(
            "SELECT id, pending_payment_hash FROM notes WHERE pending = 1 AND spent = 0"
        ):
            if payment_hash is not None:
                grouped.setdefault(payment_hash, []).append(note_id)
        return grouped

    def upsert_username(self, username: str, cx1_hex: str, nostr_pubkey_hex: str | None = None) -> None:
        """Claims `username` for the watch-only branch `cx1_hex` (LUD-25
        cx1 = hex(P || chain_code)), or wholesale replaces an
        existing claim's branch/npub with this call's own (see router.py's
        POST /p/{username}) - router.py gates every call behind its own
        ownership-proof signature before ever calling this (a fresh claim
        proves control of THIS cx1, an overwrite proves control of
        whichever branch is already on file - see
        upsert_registered_username's own docstring), since this method
        itself has no way to tell a fresh claim from a hijack. `next_index`
        always resets to 0 - an overwrite means a different branch, whose
        own index 0 was never tried yet.

        `nostr_pubkey_hex`, if given, doubles `username` as a NIP-05 name
        (see nostr_pubkey/router.get_nip05) - a WALLET-supplied npub,
        decoded, orthogonal to cx1 (a username can carry one, the other,
        both, or neither). Omitting it on an overwrite clears any
        previously registered one, same replace-wholesale semantics as
        cx1 itself."""
        with self._lock, self.conn:
            self.conn.execute(
                "INSERT INTO usernames (username, cx1, nostr_pubkey, next_index) VALUES (?, ?, ?, 0)"
                " ON CONFLICT(username) DO UPDATE SET cx1 = excluded.cx1, nostr_pubkey = excluded.nostr_pubkey,"
                " next_index = 0",
                (username, cx1_hex, nostr_pubkey_hex),
            )

    def delete_username(self, username: str) -> None:
        """Frees `username` entirely - it goes back to being unclaimed,
        first-come-first-served for anyone (see router.py's DELETE
        /p/{username}, which gates this behind the same ownership-proof
        signature the overwrite path uses). A no-op if it was never
        claimed."""
        with self._lock, self.conn:
            self.conn.execute("DELETE FROM usernames WHERE username = ?", (username,))

    def username_branch(self, username: str) -> str | None:
        """The cx1 hex (P || chain_code) registered under `username`, or
        None if it was never claimed (see upsert_username)."""
        row = self.conn.execute("SELECT cx1 FROM usernames WHERE username = ?", (username,)).fetchone()
        return row[0] if row else None

    def nostr_pubkey(self, username: str) -> str | None:
        """The hex Nostr pubkey `username` registered (see
        upsert_username), or None if it was never claimed, or was claimed
        with no npub - both are "not a NIP-05 name" to router.get_nip05."""
        row = self.conn.execute("SELECT nostr_pubkey FROM usernames WHERE username = ?", (username,)).fetchone()
        return row[0] if row else None

    def next_index_hint(self, username: str) -> int | None:
        """The persisted best-known next-unused index on `username`'s
        registered branch (LUD-25's Internal transfer,
        router.get_lnaddress's `text/cpub` metadata entry) - a plain read
        of the same `next_index` column claim_next_index reserves from,
        with none of its collision-skipping. Purely advisory ("`i` is
        only a hint" per spec): a WALLET starts guessing from it, but
        SERVICE still rejects a stale or already-taken index exactly like
        any other p1/p2 collision, the same way claim_next_index itself
        would skip past one. None if `username` was never claimed."""
        row = self.conn.execute("SELECT next_index FROM usernames WHERE username = ?", (username,)).fetchone()
        return row[0] if row else None

    def claim_next_index(self, username: str, derive: Callable[[int], str]) -> tuple[str, int]:
        """Picks and reserves the next usable note index on `username`'s
        registered branch - LUD-25's own race-avoidance paragraph under
        Lightning Address auto-mint: `derive(i)` (router.py, wrapping
        derivation.derive_pubkey at PURPOSE_LIGHTNING_ADDRESS) is tried
        starting at the persisted next_index, skipping any index whose
        resulting pubkey already names an outstanding *or* previously-minted
        note - the same collision create_mint itself would reject - rather
        than crediting into an index a pending rotate/split/merge (or
        another internal transfer targeting this same branch) might also be
        about to install. Since PURPOSE_LIGHTNING_ADDRESS is its own counter,
        separate from a WALLET's own PURPOSE_WALLET/PURPOSE_CHANGE notes on
        this same branch, this can never collide with one of those - only
        with another use of this same purpose. Persists next_index past the
        winner and returns
        (pk_hex, index) for the caller to mint under, exactly like a
        WALLET-supplied cp1. Raises ValueError if `username` was
        never registered."""
        with self._lock, self.conn:
            row = self.conn.execute("SELECT next_index FROM usernames WHERE username = ?", (username,)).fetchone()
            if row is None:
                raise ValueError("Unknown username.")
            index = row[0]
            while True:
                pk_hex = derive(index)
                if not self._id_in_use(pk_hex):
                    break
                index += 1
            self.conn.execute("UPDATE usernames SET next_index = ? WHERE username = ?", (index + 1, username))
            return pk_hex, index


notes = NoteStore(settings.database_path)

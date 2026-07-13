"""Durable crash-aware replay journal for signed twin chat."""

from __future__ import annotations

import contextlib
import datetime as dt
import os
import re
import secrets
import sqlite3
import stat
from dataclasses import dataclass
from pathlib import Path

_HEX_64_RE = re.compile(r"^[0-9a-f]{64}$")
_KEY_ID_RE = _HEX_64_RE
_NONCE_RE = re.compile(r"^[A-Za-z0-9_-]{22,128}$")
_OWNER_RE = re.compile(r"^[A-Za-z0-9_-]{16,128}$")
_MAX_RESPONSE_BYTES = 2 * 1024 * 1024


class ReplayJournalError(RuntimeError):
    """Raised for unsafe journal paths or invalid state transitions."""


@dataclass(frozen=True, slots=True)
class ClaimResult:
    outcome: str
    response_json: str | None = None
    state: str | None = None
    phase: str | None = None

    @property
    def first_seen(self) -> bool:
        return self.outcome == "claimed"

    @property
    def dispatch_allowed(self) -> bool:
        return self.outcome in {"claimed", "reclaimed"}


class ReplayJournal:
    """Claim, mark dispatch intent, and durably complete signed requests."""

    def __init__(
        self,
        path: str | os.PathLike[str],
        *,
        key_epoch: int = 1,
        lease_seconds: int = 300,
        owner_id: str | None = None,
    ) -> None:
        self.path = Path(path)
        self.key_epoch = _validate_epoch(key_epoch)
        if (
            not isinstance(lease_seconds, int)
            or isinstance(lease_seconds, bool)
            or not 1 <= lease_seconds <= 3600
        ):
            raise ReplayJournalError("lease_seconds must be between 1 and 3600")
        self.lease_seconds = lease_seconds
        self.owner_id = owner_id or secrets.token_urlsafe(24)
        if not isinstance(self.owner_id, str) or not _OWNER_RE.fullmatch(
            self.owner_id
        ):
            raise ReplayJournalError("owner_id is invalid")
        self.owner_pid = os.getpid()
        self.owner_started_at = _utc_now()
        self._prepare()

    def claim(
        self,
        sender_rappid: str,
        key_id: str,
        nonce: str,
        request_digest: str,
    ) -> ClaimResult:
        """Claim a new request or recover an abandoned processing row."""

        self._validate_key(sender_rappid, key_id, nonce, request_digest)
        now = _utc_now()
        deadline = _utc_after(self.lease_seconds)
        with contextlib.closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                """
                SELECT request_digest, state, response_json, dispatch_phase,
                       owner_id, owner_pid, lease_deadline
                FROM twin_chat_replay
                WHERE sender_rappid = ? AND key_id = ? AND key_epoch = ?
                      AND nonce = ?
                """,
                (
                    sender_rappid,
                    key_id,
                    self.key_epoch,
                    nonce,
                ),
            ).fetchone()
            if row is None:
                connection.execute(
                    """
                    INSERT INTO twin_chat_replay (
                        sender_rappid, key_id, key_epoch, nonce,
                        request_digest, state, response_json, dispatch_phase,
                        owner_id, owner_pid, owner_started_at, lease_deadline,
                        created_at, updated_at
                    ) VALUES (
                        ?, ?, ?, ?, ?, 'processing', NULL, 'claimed',
                        ?, ?, ?, ?, ?, ?
                    )
                    """,
                    (
                        sender_rappid,
                        key_id,
                        self.key_epoch,
                        nonce,
                        request_digest,
                        self.owner_id,
                        self.owner_pid,
                        self.owner_started_at,
                        deadline,
                        now,
                        now,
                    ),
                )
                connection.commit()
                return ClaimResult(
                    "claimed", state="processing", phase="claimed"
                )
            (
                stored_digest,
                state,
                response_json,
                phase,
                owner_id,
                owner_pid,
                lease_deadline,
            ) = row
            if stored_digest != request_digest:
                connection.commit()
                return ClaimResult(
                    "digest_conflict", state=str(state), phase=str(phase)
                )
            if state in {"completed", "rejected"} and isinstance(
                response_json, str
            ):
                connection.commit()
                return ClaimResult(
                    "replay",
                    response_json=response_json,
                    state=str(state),
                    phase="terminal",
                )
            if state == "failed" and response_json is None:
                connection.commit()
                return ClaimResult(
                    "terminal_failure", state="failed", phase="terminal"
                )
            if state != "processing" or phase not in {"claimed", "dispatched"}:
                connection.rollback()
                raise ReplayJournalError(
                    "replay journal row has invalid processing state"
                )
            if owner_id == self.owner_id:
                connection.commit()
                return ClaimResult(
                    "processing", state="processing", phase=str(phase)
                )
            if not _owner_is_stale(owner_pid, lease_deadline):
                connection.commit()
                return ClaimResult(
                    "processing", state="processing", phase=str(phase)
                )
            connection.execute(
                """
                UPDATE twin_chat_replay
                SET owner_id = ?, owner_pid = ?, owner_started_at = ?,
                    lease_deadline = ?, updated_at = ?
                WHERE sender_rappid = ? AND key_id = ? AND key_epoch = ?
                      AND nonce = ?
                """,
                (
                    self.owner_id,
                    self.owner_pid,
                    self.owner_started_at,
                    deadline,
                    now,
                    sender_rappid,
                    key_id,
                    self.key_epoch,
                    nonce,
                ),
            )
            connection.commit()
        if phase == "claimed":
            return ClaimResult(
                "reclaimed", state="processing", phase="claimed"
            )
        return ClaimResult(
            "ambiguous", state="processing", phase="dispatched"
        )

    def lookup(
        self,
        sender_rappid: str,
        key_id: str,
        nonce: str,
        request_digest: str,
    ) -> ClaimResult:
        """Inspect an existing request identity without creating or recovering it."""

        self._validate_key(sender_rappid, key_id, nonce, request_digest)
        with contextlib.closing(self._connect()) as connection:
            row = connection.execute(
                """
                SELECT request_digest, state, response_json, dispatch_phase
                FROM twin_chat_replay
                WHERE sender_rappid = ? AND key_id = ? AND key_epoch = ?
                      AND nonce = ?
                """,
                (
                    sender_rappid,
                    key_id,
                    self.key_epoch,
                    nonce,
                ),
            ).fetchone()
        if row is None:
            return ClaimResult("absent")
        stored_digest, state, response_json, phase = row
        if stored_digest != request_digest:
            return ClaimResult(
                "digest_conflict", state=str(state), phase=str(phase)
            )
        if state == "processing":
            return ClaimResult(
                "processing", state="processing", phase=str(phase)
            )
        if state == "failed" and response_json is None:
            return ClaimResult(
                "terminal_failure", state="failed", phase="terminal"
            )
        if state in {"completed", "rejected"} and isinstance(
            response_json, str
        ):
            return ClaimResult(
                "replay",
                response_json=response_json,
                state=str(state),
                phase="terminal",
            )
        raise ReplayJournalError("replay journal row has invalid terminal state")

    def mark_dispatched(
        self,
        sender_rappid: str,
        key_id: str,
        nonce: str,
        request_digest: str,
    ) -> None:
        """Persist that side-effect dispatch may occur before invoking it."""

        self._validate_key(sender_rappid, key_id, nonce, request_digest)
        with contextlib.closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                """
                SELECT request_digest, state, dispatch_phase, owner_id
                FROM twin_chat_replay
                WHERE sender_rappid = ? AND key_id = ? AND key_epoch = ?
                      AND nonce = ?
                """,
                (
                    sender_rappid,
                    key_id,
                    self.key_epoch,
                    nonce,
                ),
            ).fetchone()
            if (
                row is None
                or row[0] != request_digest
                or row[1] != "processing"
                or row[2] != "claimed"
                or row[3] != self.owner_id
            ):
                connection.rollback()
                raise ReplayJournalError(
                    "cannot mark an unowned claimed request dispatched"
                )
            connection.execute(
                """
                UPDATE twin_chat_replay
                SET dispatch_phase = 'dispatched', lease_deadline = ?,
                    updated_at = ?
                WHERE sender_rappid = ? AND key_id = ? AND key_epoch = ?
                      AND nonce = ?
                """,
                (
                    _utc_after(self.lease_seconds),
                    _utc_now(),
                    sender_rappid,
                    key_id,
                    self.key_epoch,
                    nonce,
                ),
            )
            connection.commit()

    def finish(
        self,
        sender_rappid: str,
        key_id: str,
        nonce: str,
        request_digest: str,
        response_json: str,
        *,
        rejected: bool = False,
    ) -> None:
        self._validate_key(sender_rappid, key_id, nonce, request_digest)
        _validate_response_json(response_json)
        state = "rejected" if rejected else "completed"
        with contextlib.closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                """
                SELECT request_digest, state, owner_id
                FROM twin_chat_replay
                WHERE sender_rappid = ? AND key_id = ? AND key_epoch = ?
                      AND nonce = ?
                """,
                (
                    sender_rappid,
                    key_id,
                    self.key_epoch,
                    nonce,
                ),
            ).fetchone()
            if row is None or row[0] != request_digest:
                connection.rollback()
                raise ReplayJournalError("cannot finish an unclaimed request")
            if row[1] != "processing" or row[2] != self.owner_id:
                connection.rollback()
                raise ReplayJournalError(
                    "cannot finish an unowned or terminal request"
                )
            connection.execute(
                """
                UPDATE twin_chat_replay
                SET state = ?, response_json = ?, dispatch_phase = 'terminal',
                    lease_deadline = ?, updated_at = ?
                WHERE sender_rappid = ? AND key_id = ? AND key_epoch = ?
                      AND nonce = ?
                """,
                (
                    state,
                    response_json,
                    _utc_now(),
                    _utc_now(),
                    sender_rappid,
                    key_id,
                    self.key_epoch,
                    nonce,
                ),
            )
            connection.commit()

    def fail(
        self,
        sender_rappid: str,
        key_id: str,
        nonce: str,
        request_digest: str,
    ) -> None:
        """Record the rare case where no signed terminal value can be stored."""

        self._validate_key(sender_rappid, key_id, nonce, request_digest)
        with contextlib.closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                """
                SELECT request_digest, state, owner_id
                FROM twin_chat_replay
                WHERE sender_rappid = ? AND key_id = ? AND key_epoch = ?
                      AND nonce = ?
                """,
                (
                    sender_rappid,
                    key_id,
                    self.key_epoch,
                    nonce,
                ),
            ).fetchone()
            if row is None or row[0] != request_digest:
                connection.rollback()
                raise ReplayJournalError("cannot fail an unclaimed request")
            if row[1] in {"completed", "rejected", "failed"}:
                connection.commit()
                return
            if row[1] != "processing" or row[2] != self.owner_id:
                connection.rollback()
                raise ReplayJournalError(
                    "cannot fail an unowned processing request"
                )
            connection.execute(
                """
                UPDATE twin_chat_replay
                SET state = 'failed', response_json = NULL,
                    dispatch_phase = 'terminal', lease_deadline = ?,
                    updated_at = ?
                WHERE sender_rappid = ? AND key_id = ? AND key_epoch = ?
                      AND nonce = ?
                """,
                (
                    _utc_now(),
                    _utc_now(),
                    sender_rappid,
                    key_id,
                    self.key_epoch,
                    nonce,
                ),
            )
            connection.commit()

    def recover_failed(
        self,
        sender_rappid: str,
        key_id: str,
        nonce: str,
        request_digest: str,
        response_json: str,
    ) -> None:
        """Store a signed rejection for a previously failed terminal row."""

        self._validate_key(sender_rappid, key_id, nonce, request_digest)
        _validate_response_json(response_json)
        with contextlib.closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                """
                SELECT request_digest, state
                FROM twin_chat_replay
                WHERE sender_rappid = ? AND key_id = ? AND key_epoch = ?
                      AND nonce = ?
                """,
                (
                    sender_rappid,
                    key_id,
                    self.key_epoch,
                    nonce,
                ),
            ).fetchone()
            if (
                row is None
                or row[0] != request_digest
                or row[1] != "failed"
            ):
                connection.rollback()
                raise ReplayJournalError("cannot recover a non-failed request")
            connection.execute(
                """
                UPDATE twin_chat_replay
                SET state = 'rejected', response_json = ?,
                    dispatch_phase = 'terminal', updated_at = ?
                WHERE sender_rappid = ? AND key_id = ? AND key_epoch = ?
                      AND nonce = ?
                """,
                (
                    response_json,
                    _utc_now(),
                    sender_rappid,
                    key_id,
                    self.key_epoch,
                    nonce,
                ),
            )
            connection.commit()

    def counts(self) -> dict[str, int]:
        with contextlib.closing(self._connect()) as connection:
            rows = connection.execute(
                """
                SELECT state, COUNT(*)
                FROM twin_chat_replay
                WHERE key_epoch = ?
                GROUP BY state
                ORDER BY state
                """,
                (self.key_epoch,),
            ).fetchall()
        counts = {
            "processing": 0,
            "completed": 0,
            "rejected": 0,
            "failed": 0,
        }
        for state, count in rows:
            if state in counts:
                counts[state] = int(count)
        counts["total"] = sum(counts.values())
        return counts

    def processing_fingerprints(
        self, *, limit: int = 20
    ) -> list[dict[str, str]]:
        if (
            not isinstance(limit, int)
            or isinstance(limit, bool)
            or not 1 <= limit <= 100
        ):
            raise ReplayJournalError("limit must be between 1 and 100")
        with contextlib.closing(self._connect()) as connection:
            rows = connection.execute(
                """
                SELECT key_id, request_digest, dispatch_phase, created_at,
                       lease_deadline
                FROM twin_chat_replay
                WHERE key_epoch = ? AND state = 'processing'
                ORDER BY created_at, key_id, request_digest
                LIMIT ?
                """,
                (self.key_epoch, limit),
            ).fetchall()
        return [
            {
                "key_id": str(key_id),
                "key_epoch": str(self.key_epoch),
                "request_digest": str(digest),
                "phase": str(phase),
                "created_at": str(created_at),
                "lease_deadline": str(deadline),
            }
            for key_id, digest, phase, created_at, deadline in rows
        ]

    def _prepare(self) -> None:
        if not self.path.is_absolute():
            raise ReplayJournalError("replay journal path must be absolute")
        parent = self.path.parent
        _reject_symlink_components(parent)
        parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        _reject_symlink_components(self.path)
        if self.path.exists() and (
            self.path.is_symlink() or not self.path.is_file()
        ):
            raise ReplayJournalError("replay journal must be a regular file")
        os.chmod(parent, 0o700)
        old_umask = os.umask(0o077)
        try:
            with contextlib.closing(
                self._connect(initialize=True)
            ) as connection:
                existing = connection.execute(
                    """
                    SELECT sql FROM sqlite_master
                    WHERE type = 'table' AND name = 'twin_chat_replay'
                    """
                ).fetchone()
                if existing is not None:
                    columns = {
                        str(row[1])
                        for row in connection.execute(
                            "PRAGMA table_info(twin_chat_replay)"
                        ).fetchall()
                    }
                    required = {
                        "key_epoch",
                        "dispatch_phase",
                        "owner_id",
                        "owner_pid",
                        "owner_started_at",
                        "lease_deadline",
                    }
                    if not required <= columns:
                        connection.execute(
                            "ALTER TABLE twin_chat_replay "
                            "RENAME TO twin_chat_replay_legacy"
                        )
                        existing = None
                self._create_schema(connection)
                legacy = connection.execute(
                    """
                    SELECT 1 FROM sqlite_master
                    WHERE type = 'table'
                          AND name = 'twin_chat_replay_legacy'
                    """
                ).fetchone()
                if legacy is not None:
                    connection.execute(
                        """
                        INSERT INTO twin_chat_replay (
                            sender_rappid, key_id, key_epoch, nonce,
                            request_digest, state, response_json,
                            dispatch_phase, owner_id, owner_pid,
                            owner_started_at, lease_deadline,
                            created_at, updated_at
                        )
                        SELECT sender_rappid, key_id, 1, nonce,
                               request_digest, state, response_json,
                               CASE
                                   WHEN state = 'processing'
                                   THEN 'dispatched'
                                   ELSE 'terminal'
                               END,
                               'legacy-replay-owner', 0, created_at,
                               created_at, created_at, updated_at
                        FROM twin_chat_replay_legacy
                        """
                    )
                    connection.execute(
                        "DROP TABLE twin_chat_replay_legacy"
                    )
                metadata = connection.execute(
                    "SELECT key_epoch FROM twin_chat_metadata WHERE singleton = 1"
                ).fetchone()
                if metadata is None:
                    stored = connection.execute(
                        "SELECT MAX(key_epoch) FROM twin_chat_replay"
                    ).fetchone()
                    stored_epoch = (
                        self.key_epoch
                        if stored is None or stored[0] is None
                        else int(stored[0])
                    )
                    connection.execute(
                        """
                        INSERT INTO twin_chat_metadata (singleton, key_epoch)
                        VALUES (1, ?)
                        """,
                        (stored_epoch,),
                    )
                    metadata = (stored_epoch,)
                if int(metadata[0]) != self.key_epoch:
                    connection.rollback()
                    raise ReplayJournalError(
                        "replay journal key epoch does not match pairing"
                    )
                connection.commit()
        finally:
            os.umask(old_umask)
        os.chmod(self.path, 0o600)
        for suffix in ("-wal", "-shm"):
            auxiliary = Path(str(self.path) + suffix)
            if auxiliary.exists():
                os.chmod(auxiliary, 0o600)
        _fsync_directory(parent)

    @staticmethod
    def _create_schema(connection: sqlite3.Connection) -> None:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS twin_chat_metadata (
                singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                key_epoch INTEGER NOT NULL CHECK (key_epoch >= 1)
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS twin_chat_replay (
                sender_rappid TEXT NOT NULL,
                key_id TEXT NOT NULL,
                key_epoch INTEGER NOT NULL CHECK (key_epoch >= 1),
                nonce TEXT NOT NULL,
                request_digest TEXT NOT NULL,
                state TEXT NOT NULL CHECK (
                    state IN ('processing', 'completed', 'rejected', 'failed')
                ),
                response_json TEXT,
                dispatch_phase TEXT NOT NULL CHECK (
                    dispatch_phase IN ('claimed', 'dispatched', 'terminal')
                ),
                owner_id TEXT NOT NULL,
                owner_pid INTEGER NOT NULL,
                owner_started_at TEXT NOT NULL,
                lease_deadline TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                PRIMARY KEY (
                    sender_rappid, key_id, key_epoch, nonce
                ),
                CHECK (
                    (
                        state = 'processing'
                        AND response_json IS NULL
                        AND dispatch_phase IN ('claimed', 'dispatched')
                    )
                    OR
                    (
                        state IN ('completed', 'rejected')
                        AND response_json IS NOT NULL
                        AND dispatch_phase = 'terminal'
                    )
                    OR
                    (
                        state = 'failed'
                        AND response_json IS NULL
                        AND dispatch_phase = 'terminal'
                    )
                )
            ) WITHOUT ROWID
            """
        )

    def _connect(self, *, initialize: bool = False) -> sqlite3.Connection:
        if not initialize:
            _reject_symlink_components(self.path)
        try:
            connection = sqlite3.connect(
                self.path,
                timeout=10.0,
                isolation_level=None,
                check_same_thread=False,
            )
            connection.execute("PRAGMA busy_timeout = 10000")
            connection.execute("PRAGMA foreign_keys = ON")
            connection.execute("PRAGMA temp_store = MEMORY")
            connection.execute("PRAGMA synchronous = FULL")
            connection.execute("PRAGMA journal_mode = WAL")
            connection.execute("PRAGMA wal_autocheckpoint = 1")
            if self.path.exists():
                os.chmod(self.path, 0o600)
            for suffix in ("-wal", "-shm"):
                auxiliary = Path(str(self.path) + suffix)
                if auxiliary.exists():
                    os.chmod(auxiliary, 0o600)
            return connection
        except sqlite3.Error as error:
            raise ReplayJournalError(
                "replay journal is unavailable"
            ) from error

    @staticmethod
    def _validate_key(
        sender_rappid: str,
        key_id: str,
        nonce: str,
        request_digest: str,
    ) -> None:
        if (
            not isinstance(sender_rappid, str)
            or not 1 <= len(sender_rappid) <= 256
        ):
            raise ReplayJournalError("sender RAPPID is invalid")
        if not isinstance(key_id, str) or not _KEY_ID_RE.fullmatch(key_id):
            raise ReplayJournalError("key ID is invalid")
        if not isinstance(nonce, str) or not _NONCE_RE.fullmatch(nonce):
            raise ReplayJournalError("nonce is invalid")
        if (
            not isinstance(request_digest, str)
            or not _HEX_64_RE.fullmatch(request_digest)
        ):
            raise ReplayJournalError("request digest is invalid")


def _validate_epoch(value: object) -> int:
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or not 1 <= value <= 2**31 - 1
    ):
        raise ReplayJournalError("key_epoch is invalid")
    return value


def _validate_response_json(response_json: str) -> None:
    try:
        encoded_size = (
            len(response_json.encode("utf-8"))
            if isinstance(response_json, str)
            else 0
        )
    except UnicodeEncodeError as error:
        raise ReplayJournalError(
            "signed response JSON is invalid or too large"
        ) from error
    if (
        not isinstance(response_json, str)
        or not response_json
        or encoded_size > _MAX_RESPONSE_BYTES
    ):
        raise ReplayJournalError(
            "signed response JSON is invalid or too large"
        )


def _owner_is_stale(owner_pid: object, lease_deadline: object) -> bool:
    try:
        deadline = _parse_utc(str(lease_deadline))
    except (TypeError, ValueError):
        return True
    if deadline <= dt.datetime.now(dt.timezone.utc):
        return True
    if (
        not isinstance(owner_pid, int)
        or isinstance(owner_pid, bool)
        or owner_pid <= 0
    ):
        return True
    if owner_pid == os.getpid():
        return False
    try:
        os.kill(owner_pid, 0)
    except ProcessLookupError:
        return True
    except (PermissionError, OSError):
        return False
    return False


def _utc_now() -> str:
    return (
        dt.datetime.now(dt.timezone.utc)
        .replace(microsecond=0)
        .strftime("%Y-%m-%dT%H:%M:%SZ")
    )


def _utc_after(seconds: int) -> str:
    return (
        dt.datetime.now(dt.timezone.utc)
        .replace(microsecond=0)
        + dt.timedelta(seconds=seconds)
    ).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_utc(value: str) -> dt.datetime:
    return dt.datetime.strptime(
        value, "%Y-%m-%dT%H:%M:%SZ"
    ).replace(tzinfo=dt.timezone.utc)


def _reject_symlink_components(path: Path) -> None:
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current = current / part
        try:
            details = os.lstat(current)
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(details.st_mode):
            raise ReplayJournalError(
                "replay journal path must not contain symbolic links"
            )


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)

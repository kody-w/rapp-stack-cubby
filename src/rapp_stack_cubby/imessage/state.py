"""Durable privacy-preserving state for the owner-only iMessage bridge.

Adapted from ``python/openrappter/imessage/state.py`` at the pinned
OpenRappter commit recorded in ``PROVENANCE.json``.  Raw transport identifiers
are replaced with keyed logical identifiers before any database write.
"""

from __future__ import annotations

import fcntl
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import stat
import threading
import time
import uuid
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Mapping

from .config import IMessageConfig


STATE_SCHEMA_VERSION = 4
OUTBOX_STATES = frozenset(
    {"staged", "flushed", "submitted", "unknown", "not_sent"}
)
TERMINAL_OUTBOX_STATES = frozenset({"submitted", "unknown", "not_sent"})
_PAYLOAD_KEYS = frozenset(
    {
        "created_at",
        "is_from_me",
        "service",
        "target_hmac",
        "target_kind",
        "text",
    }
)
_STATUS_KEYS = frozenset(
    {
        "controller_ready",
        "dropped",
        "failed",
        "heartbeat_at",
        "imsg_version",
        "lifecycle",
        "pending",
        "processed",
        "read_ready",
        "ready",
        "restart_count",
        "send_ready",
        "transport_ready",
    }
)
_IN_PROCESS_LEASES: set[str] = set()
_IN_PROCESS_LEASES_LOCK = threading.Lock()


class StateError(RuntimeError):
    """Raised when durable iMessage state cannot be used safely."""


class LeaseConflictError(StateError):
    """Raised when another writer owns the private bridge state."""


class IMessageState:
    """SQLite state, HMAC identities, cursor safety, and a writer lease."""

    def __init__(self, config: IMessageConfig) -> None:
        if not isinstance(config, IMessageConfig):
            raise TypeError("config must be an IMessageConfig")
        self.config = config
        self.directory = config.state_dir
        self.database_path = self.directory / "state.sqlite3"
        self.status_path = self.directory / "status.json"
        self.secret_path = self.directory / "identity.secret"
        self.lock_path = self.directory / "writer.lock"
        self._lock = threading.RLock()
        self._lease_holder_hmac: str | None = None
        self._lease_registry_key: str | None = None
        self._lock_descriptor: int | None = None
        self._closed = False
        self._ensure_directory()
        self._secret = self._load_or_create_secret()
        if self.database_path.is_symlink():
            raise StateError("private SQLite path must not be a symbolic link")
        try:
            self._db = sqlite3.connect(
                self.database_path,
                timeout=10.0,
                isolation_level=None,
                check_same_thread=False,
            )
            self._db.row_factory = sqlite3.Row
            self._db.execute("PRAGMA journal_mode=WAL")
            self._db.execute("PRAGMA synchronous=FULL")
            self._db.execute("PRAGMA busy_timeout=10000")
            self._db.execute("PRAGMA foreign_keys=ON")
            self._db.execute("PRAGMA secure_delete=ON")
            self._migrate()
            self._secure_sqlite_files()
        except (OSError, sqlite3.Error) as error:
            raise StateError("unable to initialize private iMessage state") from error

    @contextmanager
    def _transaction(self):
        with self._lock:
            self._require_open()
            self._db.execute("BEGIN IMMEDIATE")
            try:
                yield
            except BaseException:
                self._db.execute("ROLLBACK")
                raise
            else:
                self._db.execute("COMMIT")
                self._secure_sqlite_files()

    def logical_id(self, purpose: str, raw_value: object) -> str:
        if (
            not isinstance(purpose, str)
            or not purpose
            or any(ord(character) < 0x21 for character in purpose)
        ):
            raise ValueError("logical ID purpose is invalid")
        value = str(raw_value)
        payload = (
            purpose
            + "\0"
            + self.config.rappter_instance_id
            + "\0"
            + self.config.account_id
            + "\0"
            + value
        ).encode("utf-8")
        return hmac.new(self._secret, payload, hashlib.sha256).hexdigest()

    def owner_session_key(self) -> str:
        return "imessage-owner-" + self.logical_id(
            "owner-session", self.config.rappter_instance_id
        )[:32]

    owner_audience_id = owner_session_key

    def target_hmac(self, value: object) -> str:
        return self.logical_id("owner-chat", value)

    def resolve_target(self, target_hmac: str) -> str | None:
        for value in self.config.owner_chat_ids:
            if hmac.compare_digest(self.target_hmac(value), target_hmac):
                return value
        return None

    @property
    def cursor_rowid(self) -> int | None:
        row = self._db.execute(
            "SELECT rowid_value FROM cursor WHERE singleton=1"
        ).fetchone()
        return int(row["rowid_value"]) if row and row["rowid_value"] is not None else None

    @property
    def watch_resume_rowid(self) -> int | None:
        row = self._db.execute(
            """
            SELECT MIN(rowid_value) AS minimum
            FROM inbox WHERE state!='processed'
            """
        ).fetchone()
        if row and row["minimum"] is not None:
            return max(0, int(row["minimum"]) - 1)
        return self.cursor_rowid

    def acquire_lease(self, holder: str, ttl_seconds: float = 30.0) -> bool:
        if (
            not isinstance(holder, str)
            or not holder
            or isinstance(ttl_seconds, bool)
            or not 1.0 <= float(ttl_seconds) <= 300.0
        ):
            raise ValueError("writer lease parameters are invalid")
        if self._lease_holder_hmac is not None:
            return True
        registry_key = str(self.database_path)
        with _IN_PROCESS_LEASES_LOCK:
            if registry_key in _IN_PROCESS_LEASES:
                return False
            _IN_PROCESS_LEASES.add(registry_key)
        descriptor: int | None = None
        try:
            descriptor = os.open(
                self.lock_path,
                os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0),
                0o600,
            )
            os.fchmod(descriptor, 0o600)
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError:
                return False
            holder_hmac = self.logical_id("lease-holder", holder)
            now = time.time()
            with self._transaction():
                row = self._db.execute(
                    "SELECT holder_hmac,expires_at FROM leases WHERE name='writer'"
                ).fetchone()
                if (
                    row
                    and row["holder_hmac"] != holder_hmac
                    and float(row["expires_at"]) > now
                ):
                    return False
                self._db.execute(
                    """
                    INSERT INTO leases(name,holder_hmac,expires_at)
                    VALUES('writer',?,?)
                    ON CONFLICT(name) DO UPDATE SET
                      holder_hmac=excluded.holder_hmac,
                      expires_at=excluded.expires_at
                    """,
                    (holder_hmac, now + float(ttl_seconds)),
                )
            self._lock_descriptor = descriptor
            descriptor = None
            self._lease_holder_hmac = holder_hmac
            self._lease_registry_key = registry_key
            return True
        finally:
            if descriptor is not None:
                try:
                    fcntl.flock(descriptor, fcntl.LOCK_UN)
                except OSError:
                    pass
                os.close(descriptor)
            if self._lease_holder_hmac is None:
                with _IN_PROCESS_LEASES_LOCK:
                    _IN_PROCESS_LEASES.discard(registry_key)

    acquire_writer = acquire_lease

    def refresh_lease(self, holder: str, ttl_seconds: float = 30.0) -> bool:
        if (
            not isinstance(holder, str)
            or not holder
            or isinstance(ttl_seconds, bool)
            or not 1.0 <= float(ttl_seconds) <= 300.0
        ):
            raise ValueError("writer lease parameters are invalid")
        if self._lease_holder_hmac is None:
            return False
        expected = self.logical_id("lease-holder", holder)
        if not hmac.compare_digest(expected, self._lease_holder_hmac):
            return False
        with self._transaction():
            cursor = self._db.execute(
                """
                UPDATE leases SET expires_at=?
                WHERE name='writer' AND holder_hmac=?
                """,
                (time.time() + float(ttl_seconds), expected),
            )
        return cursor.rowcount == 1

    def release_lease(self, holder: str) -> None:
        expected = self.logical_id("lease-holder", holder)
        if (
            self._lease_holder_hmac is not None
            and hmac.compare_digest(expected, self._lease_holder_hmac)
        ):
            with self._transaction():
                self._db.execute(
                    "DELETE FROM leases WHERE name='writer' AND holder_hmac=?",
                    (expected,),
                )
            self._release_file_lease()

    release_writer = release_lease

    def claim_event(
        self,
        rowid: int,
        guid: str,
        payload: Mapping[str, Any],
    ) -> str | None:
        if isinstance(rowid, bool) or not isinstance(rowid, int) or rowid < 0:
            raise StateError("event row must be a non-negative integer")
        if not isinstance(guid, str) or not guid or len(guid) > 512:
            raise StateError("event GUID is invalid")
        normalized = self._validate_private_payload(payload)
        guid_hmac = self.logical_id("message-guid", guid)
        event_digest = self.logical_id("event", f"{rowid}\0{guid}")
        encoded = self._bounded_json(normalized, self.config.max_message_chars + 4096)
        with self._transaction():
            existing = self._db.execute(
                "SELECT event_digest FROM inbox WHERE guid_hmac=?",
                (guid_hmac,),
            ).fetchone()
            if existing is not None:
                return None
            self._db.execute(
                """
                INSERT INTO inbox(
                  event_digest,guid_hmac,rowid_value,state,payload_json,outcome,
                  attempts,next_retry,observed_at,claimed_at,processed_at,
                  controller_idempotency_key,route_request,
                  route_request_sha256,in_flight
                ) VALUES(?,?,?,'claimed',?,NULL,0,0,?,?,NULL,?,NULL,NULL,0)
                """,
                (
                    event_digest,
                    guid_hmac,
                    rowid,
                    encoded,
                    time.time(),
                    time.time(),
                    "imessage-" + event_digest,
                ),
            )
            self._classify_claimed_echo_locked(
                event_digest,
                guid_hmac=guid_hmac,
                payload=normalized,
            )
        return event_digest

    def observe(
        self,
        rowid: int | None,
        guid: str,
        message: Mapping[str, Any] | None = None,
    ) -> str | None:
        if rowid is None:
            return None
        raw = dict(message or {})
        target_value = next(
            (
                value
                for value in (
                    raw.get("chat_id"),
                    raw.get("chat_guid"),
                    raw.get("chat_identifier"),
                )
                if self.config.owner_chat_matches(value)
            ),
            self.config.owner_chat_ids[0],
        )
        target_kind = (
            "chat_id"
            if self.config.owner_chat_matches(raw.get("chat_id"))
            else "chat_guid"
        )
        payload = {
            "created_at": str(raw.get("created_at") or ""),
            "is_from_me": bool(raw.get("is_from_me")),
            "service": str(raw.get("service") or "imessage").casefold(),
            "target_hmac": self.target_hmac(target_value),
            "target_kind": target_kind,
            "text": str(raw.get("text") or ""),
        }
        return self.claim_event(int(rowid), guid, payload)

    def event_for_processing(self, event_digest: str) -> dict[str, Any] | None:
        row = self._db.execute(
            """
            SELECT event_digest,guid_hmac,rowid_value,payload_json,attempts,
                   state,outcome,next_retry,controller_idempotency_key,
                   route_request,route_request_sha256,in_flight
            FROM inbox WHERE event_digest=? AND state!='processed'
            """,
            (event_digest,),
        ).fetchone()
        if row is None:
            return None
        try:
            payload = json.loads(row["payload_json"])
        except (TypeError, json.JSONDecodeError) as error:
            raise StateError("private inbox payload is corrupt") from error
        if not isinstance(payload, dict):
            raise StateError("private inbox payload is corrupt")
        return {
            "event_digest": str(row["event_digest"]),
            "guid_hmac": str(row["guid_hmac"]),
            "rowid": int(row["rowid_value"]),
            "attempts": int(row["attempts"]),
            "state": str(row["state"]),
            "outcome": row["outcome"],
            "next_retry": float(row["next_retry"]),
            "controller_idempotency_key": str(
                row["controller_idempotency_key"]
            ),
            "route_request": row["route_request"],
            "route_request_sha256": row["route_request_sha256"],
            "in_flight": bool(row["in_flight"]),
            **payload,
        }

    def claim_for_processing(
        self,
        event_digest: str,
        *,
        maximum_attempts: int = 8,
        now: float | None = None,
    ) -> dict[str, Any] | None:
        """Atomically recheck terminal/backoff state and mark one worker active."""

        if (
            not isinstance(maximum_attempts, int)
            or isinstance(maximum_attempts, bool)
            or maximum_attempts < 1
        ):
            raise StateError("maximum attempts is invalid")
        selected_now = time.time() if now is None else float(now)
        with self._transaction():
            row = self._db.execute(
                """
                SELECT state,outcome,attempts,next_retry,in_flight
                FROM inbox WHERE event_digest=?
                """,
                (event_digest,),
            ).fetchone()
            if row is None:
                return None
            if row["state"] == "processed":
                return None
            if (
                bool(row["in_flight"])
                or float(row["next_retry"]) > selected_now
            ):
                return None
            if int(row["attempts"]) >= maximum_attempts:
                self._db.execute(
                    """
                    UPDATE inbox SET state='processed',outcome='controller_failed',
                      processed_at=?,in_flight=0 WHERE event_digest=?
                    """,
                    (selected_now, event_digest),
                )
                self._advance_cursor_locked()
                return None
            self._db.execute(
                """
                UPDATE inbox SET in_flight=1,claimed_at=?
                WHERE event_digest=? AND state!='processed' AND in_flight=0
                """,
                (selected_now, event_digest),
            )
        return self.event_for_processing(event_digest)

    def prepare_controller_route(
        self,
        event_digest: str,
        route_request: str,
    ) -> dict[str, str]:
        """Persist the exact deterministic request before any global call."""

        self._validate_content(
            route_request,
            self.config.max_message_chars + 4096,
            "controller route",
        )
        request_sha256 = hashlib.sha256(
            route_request.encode("utf-8")
        ).hexdigest()
        with self._transaction():
            row = self._db.execute(
                """
                SELECT controller_idempotency_key,route_request,
                       route_request_sha256,state
                FROM inbox WHERE event_digest=?
                """,
                (event_digest,),
            ).fetchone()
            if row is None or row["state"] == "processed":
                raise StateError("inbox event is unavailable")
            key = str(row["controller_idempotency_key"])
            if not key.startswith("imessage-") or len(key) != 73:
                raise StateError("controller idempotency key is corrupt")
            if row["route_request"] is None:
                self._db.execute(
                    """
                    UPDATE inbox SET route_request=?,route_request_sha256=?
                    WHERE event_digest=?
                    """,
                    (route_request, request_sha256, event_digest),
                )
            elif (
                row["route_request"] != route_request
                or row["route_request_sha256"] != request_sha256
            ):
                raise StateError("controller route request changed after persistence")
        return {
            "idempotency_key": key,
            "route_request": route_request,
            "request_sha256": request_sha256,
        }

    def pending_events(
        self,
        limit: int = 100,
        *,
        now: float | None = None,
    ) -> list[dict[str, Any]]:
        rows = self._db.execute(
            """
            SELECT event_digest FROM inbox
            WHERE state!='processed' AND in_flight=0 AND next_retry<=?
            ORDER BY rowid_value ASC LIMIT ?
            """,
            (time.time() if now is None else float(now), int(limit)),
        ).fetchall()
        return [
            event
            for row in rows
            if (event := self.event_for_processing(str(row["event_digest"]))) is not None
        ]

    retryable_messages = pending_events

    def is_processed(self, guid: str) -> bool:
        row = self._db.execute(
            "SELECT state FROM inbox WHERE guid_hmac=?",
            (self.logical_id("message-guid", guid),),
        ).fetchone()
        return bool(row and row["state"] == "processed")

    def event_digest_for_guid(self, guid: str) -> str | None:
        row = self._db.execute(
            "SELECT event_digest FROM inbox WHERE guid_hmac=?",
            (self.logical_id("message-guid", guid),),
        ).fetchone()
        return str(row["event_digest"]) if row else None

    def complete_event(self, event_digest: str, outcome: str) -> None:
        if (
            not isinstance(outcome, str)
            or not outcome
            or len(outcome) > 64
            or not outcome.replace("_", "").isalnum()
        ):
            raise StateError("event outcome is invalid")
        with self._transaction():
            self._db.execute(
                """
                UPDATE inbox SET state='processed',outcome=?,processed_at=?,
                  in_flight=0
                WHERE event_digest=?
                """,
                (outcome, time.time(), event_digest),
            )
            self._advance_cursor_locked()

    def mark_decision(self, rowid: int | None, guid: str, outcome: str) -> None:
        del rowid
        event_digest = self.event_digest_for_guid(guid)
        if event_digest is not None:
            self.complete_event(event_digest, outcome)

    def mark_retryable_event(self, event_digest: str) -> None:
        with self._transaction():
            row = self._db.execute(
                "SELECT attempts FROM inbox WHERE event_digest=?",
                (event_digest,),
            ).fetchone()
            if row is None:
                return
            attempts = int(row["attempts"]) + 1
            delay = min(60.0, 2.0 ** min(attempts, 6))
            self._db.execute(
                """
                UPDATE inbox SET state='retryable',attempts=?,next_retry=?,
                  in_flight=0
                WHERE event_digest=? AND state!='processed'
                """,
                (attempts, time.time() + delay, event_digest),
            )

    def event_outcome(self, event_digest: str) -> str | None:
        row = self._db.execute(
            "SELECT outcome FROM inbox WHERE event_digest=? AND state='processed'",
            (event_digest,),
        ).fetchone()
        return str(row["outcome"]) if row and row["outcome"] else None

    def mark_retryable(self, rowid: int | None, guid: str) -> None:
        del rowid
        event_digest = self.event_digest_for_guid(guid)
        if event_digest is not None:
            self.mark_retryable_event(event_digest)

    def retry_attempts(self, guid: str) -> int:
        row = self._db.execute(
            "SELECT attempts FROM inbox WHERE guid_hmac=?",
            (self.logical_id("message-guid", guid),),
        ).fetchone()
        return int(row["attempts"]) if row else 0

    def get_global_session(self) -> str | None:
        row = self._db.execute(
            "SELECT session_id FROM global_session WHERE singleton=1"
        ).fetchone()
        return str(row["session_id"]) if row else None

    def set_global_session(self, session_id: str) -> None:
        if (
            not isinstance(session_id, str)
            or not session_id
            or len(session_id) > 128
            or not all(
                character.isascii()
                and (character.isalnum() or character in "._:-")
                for character in session_id
            )
        ):
            raise StateError("global session ID is invalid")
        with self._transaction():
            self._db.execute(
                """
                INSERT INTO global_session(singleton,session_id,updated_at)
                VALUES(1,?,?)
                ON CONFLICT(singleton) DO UPDATE SET
                  session_id=excluded.session_id,
                  updated_at=excluded.updated_at
                """,
                (session_id, time.time()),
            )

    def stage_controller_result(
        self,
        event_digest: str,
        *,
        conversation_hmac: str,
        target_hmac: str,
        target_kind: str,
        user_text: str,
        response_text: str,
        global_session_id: str,
    ) -> None:
        self._validate_content(user_text, self.config.max_message_chars, "message")
        self._validate_content(
            response_text, self.config.max_response_chars, "response"
        )
        if target_kind not in {"chat_id", "chat_guid"}:
            raise StateError("outbound target kind is invalid")
        if conversation_hmac != self.owner_session_key():
            raise StateError("conversation logical ID is invalid")
        if self.resolve_target(target_hmac) is None:
            raise StateError("outbound target logical ID is invalid")
        with self._transaction():
            self._db.execute(
                """
                INSERT OR IGNORE INTO staged(
                  event_digest,conversation_hmac,target_hmac,target_kind,
                  user_content,response_content,global_session_id,created_at,
                  outbound_record
                ) VALUES(?,?,?,?,?,?,?,?,NULL)
                """,
                (
                    event_digest,
                    conversation_hmac,
                    target_hmac,
                    target_kind,
                    user_text,
                    response_text,
                    global_session_id,
                    time.time(),
                ),
            )
            self._db.execute(
                """
                INSERT INTO global_session(singleton,session_id,updated_at)
                VALUES(1,?,?)
                ON CONFLICT(singleton) DO UPDATE SET
                  session_id=excluded.session_id,
                  updated_at=excluded.updated_at
                """,
                (global_session_id, time.time()),
            )

    def stage_brainstem_result(
        self,
        guid: str,
        conversation_key: str,
        user_text: str,
        response_text: str,
    ) -> None:
        event_digest = self.event_digest_for_guid(guid)
        if event_digest is None:
            raise StateError("inbox event must be claimed before staging")
        event = self.event_for_processing(event_digest)
        if event is None:
            return
        session = self.get_global_session() or self.owner_session_key()
        self.stage_controller_result(
            event_digest,
            conversation_hmac=conversation_key,
            target_hmac=str(event["target_hmac"]),
            target_kind=str(event["target_kind"]),
            user_text=user_text,
            response_text=response_text,
            global_session_id=session,
        )

    def staged_dispatch(self, event_or_guid: str) -> dict[str, Any] | None:
        event_digest = self._coerce_event_digest(event_or_guid)
        row = self._db.execute(
            """
            SELECT event_digest,conversation_hmac,target_hmac,target_kind,
                   response_content,global_session_id,created_at,outbound_record
            FROM staged WHERE event_digest=?
            """,
            (event_digest,),
        ).fetchone()
        if row is None:
            return None
        value = dict(row)
        value["conversation"] = value["conversation_hmac"]
        value["response"] = value["response_content"]
        return value

    def begin_outbound(
        self,
        event_or_guid: str,
        conversation_key: str,
        text: str,
    ) -> str:
        event_digest = self._coerce_event_digest(event_or_guid)
        self._validate_content(text, self.config.max_response_chars + 64, "outbound")
        if conversation_key != self.owner_session_key():
            raise StateError("conversation logical ID is invalid")
        with self._transaction():
            staged = self._db.execute(
                """
                SELECT target_hmac,target_kind,outbound_record
                FROM staged WHERE event_digest=?
                """,
                (event_digest,),
            ).fetchone()
            if staged is None:
                raise StateError("controller response must be staged before send")
            if staged["outbound_record"]:
                return str(staged["outbound_record"])
            record_id = uuid.uuid4().hex
            now = time.time()
            self._db.execute(
                """
                INSERT INTO outbox(
                  record_id,event_digest,conversation_hmac,target_hmac,target_kind,
                  text_content,text_hmac,status,outbound_guid_hmac,echo_consumed,
                  created_at,updated_at
                ) VALUES(?,?,?,?,?,?,?,'staged',NULL,0,?,?)
                """,
                (
                    record_id,
                    event_digest,
                    conversation_key,
                    staged["target_hmac"],
                    staged["target_kind"],
                    text,
                    self.logical_id(
                        "outbound-text",
                        f"{conversation_key}\0{staged['target_hmac']}\0{text}",
                    ),
                    now,
                    now,
                ),
            )
            self._db.execute(
                "UPDATE staged SET outbound_record=? WHERE event_digest=?",
                (record_id, event_digest),
            )
        return record_id

    def mark_outbound_flushed(self, record_id: str) -> None:
        self._transition_outbound(record_id, "flushed")

    def finish_outbound(
        self,
        record_id: str,
        *,
        status: str,
        outbound_guid: str | None = None,
    ) -> None:
        if status not in TERMINAL_OUTBOX_STATES:
            raise StateError("terminal outbox state is invalid")
        guid_hmac = (
            self.logical_id("message-guid", outbound_guid)
            if outbound_guid
            else None
        )
        with self._transaction():
            row = self._db.execute(
                "SELECT status FROM outbox WHERE record_id=?",
                (record_id,),
            ).fetchone()
            if row is None:
                raise StateError("outbox record is unavailable")
            current = str(row["status"])
            allowed = {
                "staged": {"not_sent"},
                "flushed": {"submitted", "unknown", "not_sent"},
                "submitted": {"submitted"},
                "unknown": {"unknown"},
                "not_sent": {"not_sent"},
            }
            if status not in allowed[current]:
                raise StateError("outbox transition is invalid")
            self._db.execute(
                """
                UPDATE outbox SET status=?,
                  outbound_guid_hmac=COALESCE(?,outbound_guid_hmac),
                  updated_at=? WHERE record_id=?
                """,
                (status, guid_hmac, time.time(), record_id),
            )

    def outbound_record(self, record_id: str) -> dict[str, Any] | None:
        row = self._db.execute(
            """
            SELECT record_id,event_digest,conversation_hmac,target_hmac,
                   target_kind,status,outbound_guid_hmac,echo_consumed,
                   created_at,updated_at
            FROM outbox WHERE record_id=?
            """,
            (record_id,),
        ).fetchone()
        return dict(row) if row else None

    def outbound_text(self, record_id: str) -> str:
        row = self._db.execute(
            "SELECT text_content FROM outbox WHERE record_id=?",
            (record_id,),
        ).fetchone()
        if row is None:
            raise StateError("outbox record is unavailable")
        return str(row["text_content"])

    def consume_outbound_echo(
        self,
        conversation_key: str,
        *,
        guid: str,
        text: str,
        is_from_me: bool = True,
        target_hmac: str | None = None,
    ) -> bool:
        if is_from_me is not True:
            return False
        if conversation_key != self.owner_session_key():
            raise StateError("conversation logical ID is invalid")
        if target_hmac is not None and self.resolve_target(target_hmac) is None:
            return False
        guid_hmac = self.logical_id("message-guid", guid)
        return self.consume_outbound_echo_hmac(
            conversation_key,
            guid_hmac=guid_hmac,
            text=text,
            is_from_me=is_from_me,
            target_hmac=target_hmac,
        )

    def consume_outbound_echo_hmac(
        self,
        conversation_key: str,
        *,
        guid_hmac: str,
        text: str,
        is_from_me: bool = True,
        target_hmac: str | None = None,
    ) -> bool:
        if is_from_me is not True:
            return False
        if conversation_key != self.owner_session_key():
            raise StateError("conversation logical ID is invalid")
        if target_hmac is not None and self.resolve_target(target_hmac) is None:
            return False
        if (
            not isinstance(guid_hmac, str)
            or len(guid_hmac) != 64
            or any(character not in "0123456789abcdef" for character in guid_hmac)
        ):
            raise StateError("message GUID HMAC is invalid")
        with self._transaction():
            if target_hmac is None:
                query = """
                    SELECT record_id FROM outbox
                    WHERE conversation_hmac=?
                      AND status IN ('submitted','unknown')
                      AND echo_consumed=0
                      AND outbound_guid_hmac=?
                      AND created_at>=?
                    ORDER BY created_at ASC LIMIT 1
                """
                parameters: list[object] = [
                    conversation_key,
                    guid_hmac,
                    time.time() - 12 * 60 * 60,
                ]
            else:
                query = """
                    SELECT record_id FROM outbox
                    WHERE conversation_hmac=?
                      AND target_hmac=?
                      AND status IN ('submitted','unknown')
                      AND echo_consumed=0
                      AND outbound_guid_hmac=?
                      AND created_at>=?
                    ORDER BY created_at ASC LIMIT 1
                """
                parameters = [
                    conversation_key,
                    target_hmac,
                    guid_hmac,
                    time.time() - 12 * 60 * 60,
                ]
            row = self._db.execute(query, tuple(parameters)).fetchone()
            if row is None:
                return False
            self._db.execute(
                """
                UPDATE outbox SET echo_consumed=1,updated_at=?
                WHERE record_id=? AND echo_consumed=0
                """,
                (time.time(), row["record_id"]),
            )
            return True

    def _classify_claimed_echo_locked(
        self,
        event_digest: str,
        *,
        guid_hmac: str,
        payload: Mapping[str, Any],
    ) -> None:
        if payload.get("is_from_me") is not True:
            return
        conversation = self.owner_session_key()
        target_hmac = str(payload["target_hmac"])
        text_hmac = self.logical_id(
            "outbound-text",
            f"{conversation}\0{target_hmac}\0{payload['text']}",
        )
        row = self._db.execute(
            """
            SELECT record_id,outbound_guid_hmac FROM outbox
            WHERE conversation_hmac=? AND target_hmac=?
              AND status IN ('submitted','unknown')
              AND echo_consumed=0
              AND (
                outbound_guid_hmac=?
                OR (
                  status='unknown' AND outbound_guid_hmac IS NULL
                  AND text_hmac=?
                )
              )
              AND created_at>=?
            ORDER BY
              CASE WHEN outbound_guid_hmac=? THEN 0 ELSE 1 END,
              created_at ASC
            LIMIT 1
            """,
            (
                conversation,
                target_hmac,
                guid_hmac,
                text_hmac,
                time.time() - 12 * 60 * 60,
                guid_hmac,
            ),
        ).fetchone()
        if row is None:
            return
        exact = row["outbound_guid_hmac"] == guid_hmac
        outcome = "outbound_echo" if exact else "ambiguous_outbound_echo"
        self._db.execute(
            """
            UPDATE outbox SET echo_consumed=1,updated_at=?
            WHERE record_id=? AND echo_consumed=0
            """,
            (time.time(), row["record_id"]),
        )
        self._db.execute(
            """
            UPDATE inbox SET state='processed',outcome=?,processed_at=?,
              in_flight=0 WHERE event_digest=?
            """,
            (outcome, time.time(), event_digest),
        )
        self._advance_cursor_locked()

    def recover_after_restart(self) -> dict[str, int]:
        recovered = {
            "flushed_to_unknown": 0,
            "in_flight_to_retryable": 0,
            "terminal_events": 0,
        }
        with self._transaction():
            cursor = self._db.execute(
                """
                UPDATE inbox SET state='retryable',in_flight=0,next_retry=0
                WHERE state!='processed' AND in_flight=1
                """
            )
            recovered["in_flight_to_retryable"] = cursor.rowcount
            rows = self._db.execute(
                """
                SELECT record_id,event_digest,status FROM outbox
                WHERE status IN ('flushed','submitted','unknown','not_sent')
                """
            ).fetchall()
            for row in rows:
                status = str(row["status"])
                if status == "flushed":
                    status = "unknown"
                    self._db.execute(
                        "UPDATE outbox SET status='unknown',updated_at=? WHERE record_id=?",
                        (time.time(), row["record_id"]),
                    )
                    recovered["flushed_to_unknown"] += 1
                outcome = {
                    "submitted": "replied",
                    "unknown": "send_unknown",
                    "not_sent": "send_not_sent",
                }[status]
                cursor = self._db.execute(
                    """
                    UPDATE inbox SET state='processed',outcome=?,processed_at=?,
                      in_flight=0
                    WHERE event_digest=? AND state!='processed'
                    """,
                    (outcome, time.time(), row["event_digest"]),
                )
                recovered["terminal_events"] += cursor.rowcount
            self._advance_cursor_locked()
        return recovered

    def counts(self) -> dict[str, int]:
        inbox = {
            str(row["state"]): int(row["count"])
            for row in self._db.execute(
                "SELECT state,COUNT(*) AS count FROM inbox GROUP BY state"
            )
        }
        outbox = {
            str(row["status"]): int(row["count"])
            for row in self._db.execute(
                "SELECT status,COUNT(*) AS count FROM outbox GROUP BY status"
            )
        }
        return {
            "inbox_claimed": inbox.get("claimed", 0),
            "inbox_retryable": inbox.get("retryable", 0),
            "inbox_processed": inbox.get("processed", 0),
            **{f"outbox_{name}": outbox.get(name, 0) for name in sorted(OUTBOX_STATES)},
        }

    def lifecycle_counts(self) -> dict[str, int]:
        rows = self._db.execute(
            """
            SELECT outcome,COUNT(*) AS count FROM inbox
            WHERE state='processed' GROUP BY outcome
            """
        ).fetchall()
        processed = dropped = failed = 0
        for row in rows:
            outcome = str(row["outcome"] or "")
            count = int(row["count"])
            if outcome == "replied":
                processed += count
            elif outcome in {
                "controller_failed",
                "controller_rejected",
                "send_not_sent",
                "send_unknown",
            }:
                failed += count
            else:
                dropped += count
        retry_row = self._db.execute(
            "SELECT COALESCE(SUM(attempts),0) AS count FROM inbox WHERE state!='processed'"
        ).fetchone()
        failed += int(retry_row["count"]) if retry_row else 0
        state_counts = self.counts()
        return {
            "processed": processed,
            "dropped": dropped,
            "failed": failed,
            "pending": (
                state_counts["inbox_claimed"]
                + state_counts["inbox_retryable"]
            ),
        }

    def raw_state_for_tests(self) -> dict[str, Any]:
        return {
            "schema_version": STATE_SCHEMA_VERSION,
            "cursor_rowid": self.cursor_rowid,
            "watch_resume_rowid": self.watch_resume_rowid,
            "counts": self.counts(),
            "inbox": [
                {
                    "event_digest": row["event_digest"],
                    "guid_hmac": row["guid_hmac"],
                    "rowid": row["rowid_value"],
                    "state": row["state"],
                    "outcome": row["outcome"],
                }
                for row in self._db.execute(
                    """
                    SELECT event_digest,guid_hmac,rowid_value,state,outcome
                    FROM inbox ORDER BY rowid_value
                    """
                )
            ],
            "outbox": [
                dict(row)
                for row in self._db.execute(
                    """
                    SELECT record_id,event_digest,conversation_hmac,target_hmac,
                           target_kind,status,outbound_guid_hmac,echo_consumed
                    FROM outbox ORDER BY created_at
                    """
                )
            ],
        }

    def write_status(self, status_value: Mapping[str, Any]) -> None:
        if not isinstance(status_value, Mapping):
            raise StateError("status must be an object")
        unknown = set(status_value) - _STATUS_KEYS
        if unknown:
            raise StateError("status contains private or unsupported fields")
        value = dict(status_value)
        lifecycle = value.get("lifecycle")
        if lifecycle not in {"starting", "running", "stopped", "failed"}:
            raise StateError("status lifecycle is invalid")
        if value.get("imsg_version") != self.config.imsg_version:
            raise StateError("status transport version is invalid")
        for key in (
            "ready",
            "read_ready",
            "transport_ready",
            "controller_ready",
            "send_ready",
        ):
            if value.get(key) is not None and not isinstance(value.get(key), bool):
                raise StateError("status readiness values must be boolean or null")
        for key in ("processed", "dropped", "failed", "pending", "restart_count"):
            if (
                key in value
                and (
                    isinstance(value[key], bool)
                    or not isinstance(value[key], int)
                    or value[key] < 0
                )
            ):
                raise StateError("status counters must be non-negative integers")
        value.setdefault("heartbeat_at", time.time())
        heartbeat = value["heartbeat_at"]
        if (
            isinstance(heartbeat, bool)
            or not isinstance(heartbeat, (int, float))
            or float(heartbeat) < 0
        ):
            raise StateError("status heartbeat is invalid")
        payload = (
            json.dumps(value, allow_nan=False, indent=2, sort_keys=True) + "\n"
        ).encode("utf-8")
        self._atomic_bytes(self.status_path, payload, 0o600)
        with self._transaction():
            self._db.execute(
                """
                INSERT INTO heartbeat(singleton,lifecycle,ready,updated_at)
                VALUES(1,?,?,?)
                ON CONFLICT(singleton) DO UPDATE SET
                  lifecycle=excluded.lifecycle,
                  ready=excluded.ready,
                  updated_at=excluded.updated_at
                """,
                (lifecycle, int(value.get("ready") is True), value["heartbeat_at"]),
            )

    def read_status(self) -> dict[str, Any]:
        try:
            info = self.status_path.stat()
            if (
                self.status_path.is_symlink()
                or not stat.S_ISREG(info.st_mode)
                or stat.S_IMODE(info.st_mode) != 0o600
                or info.st_size > 64 * 1024
            ):
                return {}
            value = json.loads(self.status_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError):
            return {}
        if not isinstance(value, dict) or set(value) - _STATUS_KEYS:
            return {}
        return value

    def close(self) -> None:
        if self._closed:
            return
        if self._lease_holder_hmac is not None:
            try:
                with self._transaction():
                    self._db.execute(
                        "DELETE FROM leases WHERE name='writer' AND holder_hmac=?",
                        (self._lease_holder_hmac,),
                    )
            except (OSError, sqlite3.Error, StateError):
                pass
        self._release_file_lease()
        with self._lock:
            self._db.close()
            self._closed = True

    def __enter__(self) -> "IMessageState":
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.close()

    def _coerce_event_digest(self, event_or_guid: str) -> str:
        row = self._db.execute(
            "SELECT event_digest FROM inbox WHERE event_digest=?",
            (event_or_guid,),
        ).fetchone()
        if row:
            return str(row["event_digest"])
        event_digest = self.event_digest_for_guid(event_or_guid)
        if event_digest is None:
            raise StateError("inbox event is unavailable")
        return event_digest

    def _transition_outbound(self, record_id: str, target: str) -> None:
        if target not in OUTBOX_STATES:
            raise StateError("outbox state is invalid")
        with self._transaction():
            row = self._db.execute(
                "SELECT status FROM outbox WHERE record_id=?",
                (record_id,),
            ).fetchone()
            if row is None:
                raise StateError("outbox record is unavailable")
            if row["status"] != "staged" or target != "flushed":
                raise StateError("outbox transition is invalid")
            self._db.execute(
                "UPDATE outbox SET status=?,updated_at=? WHERE record_id=?",
                (target, time.time(), record_id),
            )

    def _advance_cursor_locked(self) -> None:
        unresolved = self._db.execute(
            "SELECT MIN(rowid_value) AS minimum FROM inbox WHERE state!='processed'"
        ).fetchone()["minimum"]
        if unresolved is None:
            row = self._db.execute(
                "SELECT MAX(rowid_value) AS maximum FROM inbox WHERE state='processed'"
            ).fetchone()
        else:
            row = self._db.execute(
                """
                SELECT MAX(rowid_value) AS maximum FROM inbox
                WHERE state='processed' AND rowid_value<?
                """,
                (unresolved,),
            ).fetchone()
        candidate = row["maximum"] if row else None
        if candidate is None:
            return
        current = self.cursor_rowid
        if current is None or int(candidate) > current:
            self._db.execute(
                """
                INSERT INTO cursor(singleton,rowid_value) VALUES(1,?)
                ON CONFLICT(singleton) DO UPDATE SET
                  rowid_value=excluded.rowid_value
                """,
                (int(candidate),),
            )

    def _validate_private_payload(self, payload: Mapping[str, Any]) -> dict[str, Any]:
        if not isinstance(payload, Mapping) or set(payload) != _PAYLOAD_KEYS:
            raise StateError("private inbox payload shape is invalid")
        text = payload.get("text")
        self._validate_content(text, self.config.max_message_chars, "message")
        target_hmac = payload.get("target_hmac")
        if (
            not isinstance(target_hmac, str)
            or len(target_hmac) != 64
            or any(character not in "0123456789abcdef" for character in target_hmac)
        ):
            raise StateError("private inbox target is invalid")
        if payload.get("target_kind") not in {"chat_id", "chat_guid"}:
            raise StateError("private inbox target kind is invalid")
        if payload.get("service") not in {"imessage", "sms", "unsupported"}:
            raise StateError("private inbox service is invalid")
        if not isinstance(payload.get("is_from_me"), bool):
            raise StateError("private inbox direction is invalid")
        created_at = payload.get("created_at")
        if not isinstance(created_at, str) or len(created_at) > 64:
            raise StateError("private inbox timestamp is invalid")
        return {
            "created_at": created_at,
            "is_from_me": payload["is_from_me"],
            "service": payload["service"],
            "target_hmac": target_hmac,
            "target_kind": payload["target_kind"],
            "text": text,
        }

    @staticmethod
    def _validate_content(value: object, limit: int, label: str) -> None:
        if (
            not isinstance(value, str)
            or not value
            or len(value) > limit
            or "\x00" in value
        ):
            raise StateError(f"{label} content is invalid")

    @staticmethod
    def _bounded_json(value: Mapping[str, Any], limit: int) -> str:
        try:
            encoded = json.dumps(
                dict(value),
                ensure_ascii=False,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            )
        except (TypeError, ValueError, RecursionError) as error:
            raise StateError("private payload is not JSON encodable") from error
        if len(encoded.encode("utf-8")) > limit:
            raise StateError("private payload exceeds the size limit")
        return encoded

    def _ensure_directory(self) -> None:
        try:
            self.directory.mkdir(parents=True, exist_ok=True, mode=0o700)
            if self.directory.is_symlink() or not self.directory.is_dir():
                raise StateError("state directory is unsafe")
            os.chmod(self.directory, 0o700)
        except OSError as error:
            raise StateError("unable to create the private state directory") from error

    def _load_or_create_secret(self) -> bytes:
        if self.secret_path.is_symlink():
            raise StateError("identity secret must not be a symbolic link")
        try:
            info = self.secret_path.stat()
            if (
                self.secret_path.is_symlink()
                or not stat.S_ISREG(info.st_mode)
                or stat.S_IMODE(info.st_mode) != 0o600
                or info.st_size != 32
            ):
                raise StateError("identity secret is unsafe")
            secret = self.secret_path.read_bytes()
            if len(secret) != 32:
                raise StateError("identity secret is invalid")
            return secret
        except FileNotFoundError:
            secret = secrets.token_bytes(32)
            self._atomic_bytes(self.secret_path, secret, 0o600)
            return secret
        except OSError as error:
            raise StateError("identity secret cannot be read") from error

    def _migrate(self) -> None:
        version = int(self._db.execute("PRAGMA user_version").fetchone()[0])
        if version not in {0, 1, 2, 3, STATE_SCHEMA_VERSION}:
            raise StateError("unsupported iMessage state schema version")
        self._db.execute("BEGIN IMMEDIATE")
        try:
            legacy_cursor: int | None = None
            legacy_outbox_rows: list[tuple[str, str, str, float]] = []
            existing = {
                str(row[0])
                for row in self._db.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                )
            }
            if "inbox" in existing:
                inbox_columns = {
                    str(row[1])
                    for row in self._db.execute("PRAGMA table_info(inbox)")
                }
                if "event_digest" not in inbox_columns:
                    if "outbox" in existing:
                        outbox_columns = {
                            str(row[1])
                            for row in self._db.execute(
                                "PRAGMA table_info(outbox)"
                            )
                        }
                        if "status" in outbox_columns:
                            for legacy in self._db.execute(
                                """
                                SELECT * FROM outbox
                                WHERE status IN ('flushed','unknown')
                                """
                            ).fetchall():
                                normalized = {
                                    key: (
                                        value.hex()
                                        if isinstance(value, bytes)
                                        else value
                                    )
                                    for key, value in dict(legacy).items()
                                }
                                payload = json.dumps(
                                    normalized,
                                    ensure_ascii=False,
                                    allow_nan=False,
                                    sort_keys=True,
                                    separators=(",", ":"),
                                    default=str,
                                )
                                digest = hashlib.sha256(
                                    payload.encode("utf-8")
                                ).hexdigest()
                                legacy_outbox_rows.append(
                                    (
                                        digest,
                                        "unknown",
                                        payload,
                                        time.time(),
                                    )
                                )
                    if {"rowid_value", "processed"} <= inbox_columns:
                        row = self._db.execute(
                            """
                            SELECT MAX(rowid_value) FROM inbox
                            WHERE processed=1
                            """
                        ).fetchone()
                        if row and row[0] is not None:
                            legacy_cursor = int(row[0])
                    for table in (
                        "staged",
                        "outbox",
                        "history",
                        "group_bindings",
                        "owner_bindings",
                        "inbox",
                        "metadata",
                        "leases",
                        "heartbeat",
                        "cursor",
                        "global_session",
                    ):
                        self._db.execute(f"DROP TABLE IF EXISTS {table}")
            elif "leases" in existing:
                lease_columns = {
                    str(row[1])
                    for row in self._db.execute("PRAGMA table_info(leases)")
                }
                if "holder_hmac" not in lease_columns:
                    self._db.execute("DROP TABLE leases")
            statements = (
                """
                CREATE TABLE IF NOT EXISTS cursor(
                  singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                  rowid_value INTEGER
                )
                """,
                """
                CREATE TABLE IF NOT EXISTS inbox(
                  event_digest TEXT PRIMARY KEY,
                  guid_hmac TEXT NOT NULL UNIQUE,
                  rowid_value INTEGER NOT NULL,
                  state TEXT NOT NULL CHECK(state IN ('claimed','retryable','processed')),
                  payload_json TEXT NOT NULL,
                  outcome TEXT,
                  attempts INTEGER NOT NULL DEFAULT 0,
                  next_retry REAL NOT NULL DEFAULT 0,
                  observed_at REAL NOT NULL,
                  claimed_at REAL NOT NULL,
                  processed_at REAL,
                  controller_idempotency_key TEXT,
                  route_request TEXT,
                  route_request_sha256 TEXT,
                  in_flight INTEGER NOT NULL DEFAULT 0
                    CHECK(in_flight IN (0,1))
                )
                """,
                """
                CREATE INDEX IF NOT EXISTS idx_inbox_pending
                ON inbox(state,next_retry,rowid_value)
                """,
                """
                CREATE TABLE IF NOT EXISTS staged(
                  event_digest TEXT PRIMARY KEY REFERENCES inbox(event_digest),
                  conversation_hmac TEXT NOT NULL,
                  target_hmac TEXT NOT NULL,
                  target_kind TEXT NOT NULL,
                  user_content TEXT NOT NULL,
                  response_content TEXT NOT NULL,
                  global_session_id TEXT NOT NULL,
                  created_at REAL NOT NULL,
                  outbound_record TEXT
                )
                """,
                """
                CREATE TABLE IF NOT EXISTS outbox(
                  record_id TEXT PRIMARY KEY,
                  event_digest TEXT NOT NULL UNIQUE REFERENCES inbox(event_digest),
                  conversation_hmac TEXT NOT NULL,
                  target_hmac TEXT NOT NULL,
                  target_kind TEXT NOT NULL,
                  text_content TEXT NOT NULL,
                  text_hmac TEXT NOT NULL,
                  status TEXT NOT NULL CHECK(
                    status IN ('staged','flushed','submitted','unknown','not_sent')
                  ),
                  outbound_guid_hmac TEXT,
                  echo_consumed INTEGER NOT NULL DEFAULT 0 CHECK(echo_consumed IN (0,1)),
                  created_at REAL NOT NULL,
                  updated_at REAL NOT NULL
                )
                """,
                """
                CREATE INDEX IF NOT EXISTS idx_outbox_echo
                ON outbox(conversation_hmac,target_hmac,status,echo_consumed,created_at)
                """,
                """
                CREATE TABLE IF NOT EXISTS global_session(
                  singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                  session_id TEXT NOT NULL,
                  updated_at REAL NOT NULL
                )
                """,
                """
                CREATE TABLE IF NOT EXISTS leases(
                  name TEXT PRIMARY KEY,
                  holder_hmac TEXT NOT NULL,
                  expires_at REAL NOT NULL
                )
                """,
                """
                CREATE TABLE IF NOT EXISTS heartbeat(
                  singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                  lifecycle TEXT NOT NULL,
                  ready INTEGER NOT NULL,
                  updated_at REAL NOT NULL
                )
                """,
                """
                CREATE TABLE IF NOT EXISTS legacy_outbox_recovery(
                  row_sha256 TEXT PRIMARY KEY,
                  status TEXT NOT NULL CHECK(status='unknown'),
                  payload_json TEXT NOT NULL,
                  migrated_at REAL NOT NULL
                )
                """,
            )
            for statement in statements:
                self._db.execute(statement)
            inbox_columns = {
                str(row[1])
                for row in self._db.execute("PRAGMA table_info(inbox)")
            }
            additions = {
                "controller_idempotency_key": "TEXT",
                "route_request": "TEXT",
                "route_request_sha256": "TEXT",
                "in_flight": "INTEGER NOT NULL DEFAULT 0",
            }
            for column, declaration in additions.items():
                if column not in inbox_columns:
                    self._db.execute(
                        f"ALTER TABLE inbox ADD COLUMN {column} {declaration}"
                    )
            self._db.execute(
                """
                UPDATE inbox
                SET controller_idempotency_key='imessage-' || event_digest
                WHERE controller_idempotency_key IS NULL
                   OR controller_idempotency_key=''
                """
            )
            self._db.execute(
                "UPDATE inbox SET in_flight=0 WHERE in_flight IS NULL"
            )
            self._db.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_inbox_worker
                ON inbox(state,in_flight,next_retry,rowid_value)
                """
            )
            for row in legacy_outbox_rows:
                self._db.execute(
                    """
                    INSERT OR IGNORE INTO legacy_outbox_recovery(
                      row_sha256,status,payload_json,migrated_at
                    ) VALUES(?,?,?,?)
                    """,
                    row,
                )
            if legacy_cursor is not None:
                self._db.execute(
                    "INSERT INTO cursor(singleton,rowid_value) VALUES(1,?)",
                    (legacy_cursor,),
                )
            self._db.execute(f"PRAGMA user_version={STATE_SCHEMA_VERSION}")
            self._db.execute("COMMIT")
        except BaseException:
            self._db.execute("ROLLBACK")
            raise

    def _secure_sqlite_files(self) -> None:
        for path in (
            self.database_path,
            Path(str(self.database_path) + "-wal"),
            Path(str(self.database_path) + "-shm"),
        ):
            try:
                if path.exists() and not path.is_symlink():
                    os.chmod(path, 0o600)
            except OSError as error:
                raise StateError("private SQLite file mode cannot be secured") from error

    def _release_file_lease(self) -> None:
        descriptor = self._lock_descriptor
        self._lock_descriptor = None
        self._lease_holder_hmac = None
        if descriptor is not None:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
            except OSError:
                pass
            os.close(descriptor)
        registry_key = self._lease_registry_key
        self._lease_registry_key = None
        if registry_key is not None:
            with _IN_PROCESS_LEASES_LOCK:
                _IN_PROCESS_LEASES.discard(registry_key)

    def _require_open(self) -> None:
        if self._closed:
            raise StateError("iMessage state is closed")

    @staticmethod
    def _atomic_bytes(path: Path, payload: bytes, mode: int) -> None:
        temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.new")
        descriptor = -1
        try:
            descriptor = os.open(
                temporary,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                mode,
            )
            offset = 0
            while offset < len(payload):
                offset += os.write(descriptor, payload[offset:])
            os.fsync(descriptor)
            os.close(descriptor)
            descriptor = -1
            os.replace(temporary, path)
            os.chmod(path, mode)
            directory = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass

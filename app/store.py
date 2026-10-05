"""Idempotent verdict store with concurrent-submission coordination.

Maps a stable audit identifier to the digest of the submission and the
verdict it produced.  Retransmitting the same identifier with semantically
identical content replays the original verdict; the same identifier with
different content is an explicit conflict.

Concurrency model
-----------------
Two semantically identical submissions arriving while the first evaluation
is still in flight are *one* audit, not two: the first caller drives the
evaluation and every overlapping equivalent caller waits for its result and
receives a replay of the same verdict once it is available.  Overlapping
submissions whose content differs still get an immediate explicit conflict.

A pending reservation is persisted with no verdict; if the process dies
before the verdict is formed, a later retry with the same content adopts the
pending record and completes it rather than being refused forever.  A retry
with different content still conflicts (a different outcome may already have
been produced by the interrupted run).

Records live in memory; when ``AUDIT_STORE_FILE`` points at a path the store
is also persisted there (atomic rewrite) so a container restart keeps prior
verdicts.
"""

from __future__ import annotations

import json
import os
import threading

NEW = "new"
REPLAY = "replay"
CONFLICT = "conflict"
PENDING = "pending"


class AuditStore:
    def __init__(self, path: str | None = None):
        self._lock = threading.Lock()
        self._records: dict[str, dict] = {}
        # Condition per audit id with an in-flight evaluation; lets
        # overlapping equivalent callers block until the verdict lands.
        self._conditions: dict[str, threading.Condition] = {}
        self._path = path
        if path and os.path.exists(path):
            try:
                with open(path, "r", encoding="utf-8") as fh:
                    data = json.load(fh)
                if isinstance(data, dict) and isinstance(data.get("records"), dict):
                    records = data["records"]
                    # Pending records come from an interrupted run: nothing is
                    # evaluating them in this process, so they are safe to
                    # adopt or conflict against.
                    self._records = {
                        aid: {"digest": rec["digest"],
                              "verdict": rec.get("verdict")}
                        for aid, rec in records.items()
                        if isinstance(rec, dict) and "digest" in rec
                    }
            except (OSError, ValueError, KeyError):
                # A corrupt store must not take the service down; start empty.
                self._records = {}

    def check(self, audit_id: str, digest: str) -> str:
        """Classify a submission against any stored verdict for its id."""
        with self._lock:
            record = self._records.get(audit_id)
            if record is None:
                return NEW
            return REPLAY if record["digest"] == digest else CONFLICT

    def begin(self, audit_id: str, digest: str) -> str:
        """Reserve the audit for evaluation by this caller.

        ``NEW``     — this caller owns the (possibly adopted) pending
                      reservation and must run the audit, then call
                      :meth:`complete`;
        ``REPLAY``  — a completed verdict for identical content already
                      exists, fetchable via :meth:`get`;
        ``CONFLICT``— the id is bound to different content.
        """
        with self._lock:
            record = self._records.get(audit_id)
            if record is None:
                self._records[audit_id] = {"digest": digest, "verdict": None}
                self._conditions[audit_id] = threading.Condition(self._lock)
                self._persist_locked()
                return NEW
            if record["digest"] != digest:
                return CONFLICT
            if record["verdict"] is not None:
                return REPLAY
            # Same content, verdict not formed yet.  Either an evaluation is
            # genuinely in flight in this process, or the pending record was
            # adopted from disk after an interruption.  An in-flight owner
            # always owns a condition; absent one, adopt the reservation.
            cond = self._conditions.get(audit_id)
            if cond is None:
                self._conditions[audit_id] = threading.Condition(self._lock)
                return NEW
            return PENDING

    def await_verdict(self, audit_id: str, timeout: float | None = None):
        """Block until the in-flight evaluation of ``audit_id`` completes.

        Returns the verdict, or ``None`` on timeout.  Only call after
        :meth:`begin` returned ``PENDING``.
        """
        with self._lock:
            cond = self._conditions.get(audit_id)
            if cond is None:
                # Owner vanished without publishing (should not happen);
                # report whatever is stored.
                record = self._records.get(audit_id)
                return dict(record["verdict"]) if record and record["verdict"] else None
            if self._records[audit_id]["verdict"] is None:
                cond.wait(timeout)
            verdict = self._records[audit_id]["verdict"]
            return dict(verdict) if verdict is not None else None

    def complete(self, audit_id: str, digest: str, verdict: dict) -> None:
        """Publish the verdict produced by the caller that got ``NEW``."""
        with self._lock:
            record = self._records.get(audit_id)
            # A conflicting record can only have been written by another
            # process sharing the store file; never overwrite it.
            if record is not None and record["digest"] == digest:
                self._records[audit_id] = {"digest": digest, "verdict": verdict}
            self._persist_locked()
            cond = self._conditions.pop(audit_id, None)
            if cond is not None:
                cond.notify_all()

    def abandon(self, audit_id: str, digest: str) -> None:
        """Release a reservation the caller never completed.

        The pending record stays (and stays persisted): a later equivalent
        retry adopts it, preserving crash-safe completion.  In-process
        waiters are woken so they can retry rather than block forever.
        """
        with self._lock:
            cond = self._conditions.pop(audit_id, None)
            if cond is not None:
                cond.notify_all()

    def get(self, audit_id: str):
        with self._lock:
            record = self._records.get(audit_id)
            if record is None or record["verdict"] is None:
                return None
            return dict(record["verdict"])

    # Retained for backwards compatibility with older callers: reserve then
    # publish exactly like :meth:`begin`/:meth:`complete`.
    def reserve(self, audit_id: str, digest: str) -> str:
        return self.begin(audit_id, digest)

    def put(self, audit_id: str, digest: str, verdict: dict) -> None:
        self.complete(audit_id, digest, verdict)

    def _persist_locked(self) -> None:
        if not self._path:
            return
        tmp = self._path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump({"records": self._records}, fh, ensure_ascii=False)
        os.replace(tmp, self._path)

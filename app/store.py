"""Idempotent verdict store.

Maps a stable audit identifier to the digest of the submission and the
verdict it produced.  Retransmitting the same identifier with semantically
identical content replays the original verdict; the same identifier with
different content is an explicit conflict.

Concurrent submissions of *identical* content are coalesced: the first
caller wins the evaluation lease (``begin`` returns ``NEW``); every
overlapping equivalent caller parks on a condition variable (``begin``
returns ``PENDING`` and ``wait_for`` blocks) and replays the same verdict
once it is available.  Exactly one audit is ever evaluated for a given
identifier.  If the evaluating caller dies before completing the audit it
releases the lease with ``abort`` so a waiting or retrying caller can take
over; the identifier is never left permanently locked.

Records live in memory; when ``AUDIT_STORE_FILE`` points at a path the store
is also persisted there (atomic rewrite) so a container restart keeps prior
verdicts.  Leases are persisted while an evaluation is in flight; if the
process dies before the verdict forms, the orphaned lease is discarded on
load, so retrying the same content after the restart starts a fresh audit
instead of being refused forever.
"""

from __future__ import annotations

import json
import os
import threading
import time
from typing import Callable

NEW = "new"
REPLAY = "replay"
CONFLICT = "conflict"
PENDING = "pending"
ABORTED = "aborted"
TIMEOUT = "timeout"

# How long an equivalent overlapping submission waits for the in-flight
# evaluation before giving up.  A schema-valid trajectory replays in well
# under a second; this only guards against a wedged evaluator.
DEFAULT_WAIT_SECONDS = 30.0


class AuditStore:
    def __init__(self, path: str | None = None,
                 wait_hook: Callable[[str], None] | None = None):
        # One condition variable serializes all record transitions and lets
        # overlapping callers wait for an in-flight verdict.  ``wait_hook``
        # (optional) is invoked, without the lock held, when a caller starts
        # parking on an in-flight evaluation -- an observability seam.
        self._cond = threading.Condition()
        self._records: dict[str, dict] = {}
        self._path = path
        self._wait_hook = wait_hook
        if path and os.path.exists(path):
            try:
                with open(path, "r", encoding="utf-8") as fh:
                    data = json.load(fh)
                if isinstance(data, dict) and isinstance(data.get("records"), dict):
                    # Keep only completed verdicts: an orphaned lease left by a
                    # process that died mid-evaluation must not block retries.
                    self._records = {
                        audit_id: record
                        for audit_id, record in data["records"].items()
                        if self._is_complete(record)
                    }
            except (OSError, ValueError):
                # A corrupt store must not take the service down; start empty.
                self._records = {}

    @staticmethod
    def _is_complete(record) -> bool:
        return (isinstance(record, dict)
                and isinstance(record.get("digest"), str)
                and isinstance(record.get("verdict"), dict))

    def begin(self, audit_id: str, digest: str) -> str:
        """Claim ``audit_id`` for evaluation, or classify the submission.

        Returns ``NEW`` when the caller now owns the lease and must run the
        audit and call :meth:`finish`; ``PENDING`` when an identical-content
        evaluation is already under way (call :meth:`wait_for`); ``REPLAY``
        when a verdict for identical content already exists; ``CONFLICT``
        when the id is bound to different content.
        """
        with self._cond:
            record = self._records.get(audit_id)
            if record is None:
                self._records[audit_id] = {
                    "digest": digest,
                    "verdict": None,
                }
                self._persist_locked()
                return NEW
            if record["digest"] != digest:
                return CONFLICT
            return REPLAY if record["verdict"] is not None else PENDING

    def wait_for(self, audit_id: str, digest: str,
                 timeout: float | None = DEFAULT_WAIT_SECONDS) -> str:
        """Wait for an in-flight evaluation of identical content to finish.

        Returns ``REPLAY`` once the verdict is available (:meth:`get` then
        returns it), ``CONFLICT`` if the id became bound to other content,
        ``ABORTED`` if the lease was released without a verdict (the caller
        may race other retries by calling :meth:`begin` again), or
        ``TIMEOUT`` if ``timeout`` elapsed first.
        """
        deadline = None if timeout is None else time.monotonic() + timeout
        if self._wait_hook is not None:
            self._wait_hook(audit_id)
        with self._cond:
            while True:
                record = self._records.get(audit_id)
                if record is not None and record["digest"] != digest:
                    return CONFLICT
                if record is not None and record["verdict"] is not None:
                    return REPLAY
                if deadline is None:
                    remaining = None
                else:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        return TIMEOUT
                self._cond.wait_for(
                    lambda: self._wake_predicate(audit_id, digest),
                    remaining,
                )
                # A completed verdict / different digest is caught at the top
                # of the loop; a missing record means the owner aborted and no
                # retry has taken the lease over yet.
                if self._records.get(audit_id) is None:
                    return ABORTED

    def _wake_predicate(self, audit_id: str, digest: str) -> bool:
        record = self._records.get(audit_id)
        if record is None:
            return True  # owner aborted
        return (record["digest"] != digest
                or record["verdict"] is not None)

    def finish(self, audit_id: str, digest: str, verdict: dict) -> None:
        """Store the verdict produced by the lease holder and wake waiters."""
        with self._cond:
            record = self._records.get(audit_id)
            if (record is not None and record["digest"] == digest
                    and record["verdict"] is None):
                self._records[audit_id] = {"digest": digest, "verdict": verdict}
                self._persist_locked()
            self._cond.notify_all()

    def abort(self, audit_id: str, digest: str) -> None:
        """Release an unfinished lease (evaluator failed) and wake waiters."""
        with self._cond:
            record = self._records.get(audit_id)
            if (record is not None and record["digest"] == digest
                    and record["verdict"] is None):
                del self._records[audit_id]
                self._persist_locked()
            self._cond.notify_all()

    def get(self, audit_id: str):
        with self._cond:
            record = self._records.get(audit_id)
            if record is None or record["verdict"] is None:
                return None
            return dict(record["verdict"])

    def _persist_locked(self) -> None:
        if not self._path:
            return
        tmp = self._path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump({"records": self._records}, fh, ensure_ascii=False)
        os.replace(tmp, self._path)

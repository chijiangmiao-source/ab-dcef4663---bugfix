"""Concurrency and crash-recovery tests for the idempotent verdict store.

Covers the redundant-controller cutover boundary:

* semantically identical submissions overlapping in flight are evaluated
  exactly once — one new verdict, the rest replays of the same content;
* overlapping submissions that change an event, the validator set, or the
  genesis block are explicit conflicts, never "in progress" refusals;
* a pending reservation left by an interrupted process is adopted by a
  later identical retry instead of blocking it forever;
* completed-verdict retransmits keep their replay semantics.
"""

from __future__ import annotations

import copy
import json
import os
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request

from app import canonical, server, store, trajgen


def post(base: str, body: dict, timeout: float = 10.0):
    data = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(base + "/v1/audits", data=data,
                                 method="POST")
    req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read().decode("utf-8"))


class HttpConcurrencyTestCase(unittest.TestCase):
    """Runs a real (in-process, threaded) HTTP server with an evaluation
    delay so overlapping requests arrive deterministically mid-audit."""

    EVAL_DELAY = 0.4

    def setUp(self):
        self._orig_delay = server.AUDIT_EVAL_DELAY
        server.AUDIT_EVAL_DELAY = self.EVAL_DELAY
        self._orig_engine = server.consensus.Engine
        self.engine_calls: list[str] = []
        real_engine = self._orig_engine

        class CountingEngine(real_engine):
            def __init__(inner, submission):
                self.engine_calls.append(submission["audit_id"])
                super().__init__(submission)

        server.consensus.Engine = CountingEngine
        self.srv = server.make_server(0, store.AuditStore())
        self.port = self.srv.server_address[1]
        self.thread = threading.Thread(target=self.srv.serve_forever,
                                       daemon=True)
        self.thread.start()
        self.base = f"http://127.0.0.1:{self.port}"

    def tearDown(self):
        self.srv.shutdown()
        self.srv.server_close()
        server.AUDIT_EVAL_DELAY = self._orig_delay
        server.consensus.Engine = self._orig_engine

    def _post_concurrent(self, bodies):
        results = []
        barrier = threading.Barrier(len(bodies))

        def worker(body):
            barrier.wait()
            results.append(post(self.base, body))

        threads = [threading.Thread(target=worker, args=(b,)) for b in bodies]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10)
        return results

    def test_overlapping_identical_submissions_evaluated_once(self):
        builder, blocks = trajgen.build_commit_trajectory(
            "concurrency-identical", 4, 4)
        submission = builder.submission()

        statuses_bodies = self._post_concurrent([submission, submission])
        self.assertEqual(len(statuses_bodies), 2)
        statuses = sorted(s for s, _ in statuses_bodies)
        self.assertEqual(statuses, [200, 201],
                         f"expected one new verdict and one replay, got "
                         f"{[(s, b.get('error')) for s, b in statuses_bodies]}")

        created = next(b for s, b in statuses_bodies if s == 201)
        replayed = next(b for s, b in statuses_bodies if s == 200)
        self.assertFalse(created["replayed"])
        self.assertTrue(replayed["replayed"])
        self.assertEqual(created["status"], "accepted")
        self.assertEqual(created["committed"], blocks[:2])
        self.assertEqual({k: v for k, v in replayed.items() if k != "replayed"},
                         {k: v for k, v in created.items() if k != "replayed"})

        # the consensus engine ran exactly once for the audit id
        self.assertEqual(self.engine_calls, ["concurrency-identical"])

        # the verdict is observable by id afterwards
        with urllib.request.urlopen(
                self.base + "/v1/audits/concurrency-identical",
                timeout=5) as resp:
            fetched = json.loads(resp.read().decode("utf-8"))
        self.assertEqual(fetched["committed"], blocks[:2])

    def test_many_overlapping_identical_submissions(self):
        builder, _ = trajgen.build_commit_trajectory(
            "concurrency-many", 4, 4)
        submission = builder.submission()
        results = self._post_concurrent([submission] * 8)
        statuses = sorted(s for s, _ in results)
        self.assertEqual(statuses.count(201), 1)
        self.assertEqual(statuses.count(200), 7)
        self.assertEqual(self.engine_calls, ["concurrency-many"])
        verdicts = [b for _, b in results]
        self.assertEqual(len({json.dumps({k: v for k, v in v.items()
                                          if k != "replayed"},
                                         sort_keys=True)
                              for v in verdicts}), 1)

    def test_overlapping_conflicting_content_is_rejected(self):
        builder, blocks = trajgen.build_commit_trajectory(
            "concurrency-conflict", 4, 4)
        original = builder.submission()
        mutated = copy.deepcopy(original)
        mutated["events"] = mutated["events"][:-1]  # different business event

        first = {}

        def submit_original():
            first["result"] = post(self.base, original)

        t = threading.Thread(target=submit_original)
        t.start()
        # The first request reserves the id, then sleeps EVAL_DELAY before
        # evaluating; collide well inside that window.
        time.sleep(self.EVAL_DELAY / 4)
        status, conflict = post(self.base, mutated)
        self.assertEqual(status, 409)
        self.assertEqual(conflict["error"]["code"], "conflict")
        t.join(timeout=10)

        created_status, created = first["result"]
        self.assertEqual(created_status, 201)
        self.assertEqual(created["committed"], blocks[:2])
        # the consensus engine ran exactly once, on the winning content
        self.assertEqual(self.engine_calls, ["concurrency-conflict"])
        # a later identical retransmit of the winner replays, not a 409/400
        status, body = post(self.base, original)
        self.assertEqual(status, 200)
        self.assertTrue(body["replayed"])
        # different content keeps conflicting after completion
        status, body = post(self.base, mutated)
        self.assertEqual(status, 409)
        self.assertEqual(body["error"]["code"], "conflict")


class StoreCoordinationTestCase(unittest.TestCase):
    def setUp(self):
        self.audit_id = "store-coord"
        builder, _ = trajgen.build_commit_trajectory(self.audit_id, 4, 4)
        self.submission = builder.submission()
        self.digest = canonical.submission_digest(self.submission)
        self.verdict = {"audit_id": self.audit_id, "status": "accepted"}

    def test_waiter_blocks_then_gets_replay(self):
        audit_store = store.AuditStore()
        self.assertEqual(audit_store.begin(self.audit_id, self.digest),
                         store.NEW)
        outcome_box = []

        def waiter():
            outcome_box.append(audit_store.begin(self.audit_id, self.digest))
            outcome_box.append(
                audit_store.await_verdict(self.audit_id, timeout=5))

        t = threading.Thread(target=waiter)
        t.start()
        t.join(timeout=1)
        self.assertEqual(outcome_box, [store.PENDING])  # still blocked
        audit_store.complete(self.audit_id, self.digest, self.verdict)
        t.join(timeout=2)
        self.assertFalse(t.is_alive())
        self.assertEqual(outcome_box[1], self.verdict)

    def test_content_mutations_conflict_while_pending(self):
        base = self.submission
        other_key = trajgen.ed25519.publickey(
            trajgen.validator_seed(99)).hex()
        mutations = {
            "business event": lambda s: s["events"].pop(),
            "validator set": lambda s: s["validators"].__setitem__(0, other_key),
            "genesis block": lambda s: s["genesis"].__setitem__(
                "id", "11" * 32),
        }
        for label, mutate in mutations.items():
            audit_store = store.AuditStore()
            self.assertEqual(audit_store.begin(self.audit_id, self.digest),
                             store.NEW)
            changed = copy.deepcopy(base)
            mutate(changed)
            with self.subTest(mutation=label):
                self.assertEqual(
                    audit_store.begin(
                        self.audit_id,
                        canonical.submission_digest(changed)),
                    store.CONFLICT)
            # while pending, no verdict was ever published
            self.assertIsNone(audit_store.get(self.audit_id))

    def test_abandoned_owner_allows_adoption(self):
        audit_store = store.AuditStore()
        self.assertEqual(audit_store.begin(self.audit_id, self.digest),
                         store.NEW)
        self.assertEqual(audit_store.begin(self.audit_id, self.digest),
                         store.PENDING)
        # owner thread dies before forming a verdict
        audit_store.abandon(self.audit_id, self.digest)
        self.assertIsNone(audit_store.await_verdict(self.audit_id, timeout=1))
        # next equivalent call adopts the pending reservation and completes
        self.assertEqual(audit_store.begin(self.audit_id, self.digest),
                         store.NEW)
        audit_store.complete(self.audit_id, self.digest, self.verdict)
        self.assertEqual(audit_store.get(self.audit_id), self.verdict)

    def test_completed_retransmit_replays(self):
        audit_store = store.AuditStore()
        audit_store.begin(self.audit_id, self.digest)
        audit_store.complete(self.audit_id, self.digest, self.verdict)
        self.assertEqual(audit_store.begin(self.audit_id, self.digest),
                         store.REPLAY)
        self.assertEqual(audit_store.get(self.audit_id), self.verdict)


class PersistedPendingAdoptionTestCase(unittest.TestCase):
    """The persistence service interrupting before the verdict exists must
    not make the audit id permanently refuse identical retries."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.tmp.name, "audits.json")
        builder, _ = trajgen.build_commit_trajectory("persisted-pending", 4, 4)
        self.submission = builder.submission()
        self.digest = canonical.submission_digest(self.submission)

    def tearDown(self):
        self.tmp.cleanup()

    def _persisted(self):
        with open(self.path, "r", encoding="utf-8") as fh:
            return json.load(fh)["records"]

    def test_pending_record_survives_and_identical_retry_completes(self):
        first = store.AuditStore(self.path)
        self.assertEqual(first.begin("persisted-pending", self.digest),
                         store.NEW)
        # process dies here: only the pending reservation reached disk
        record = self._persisted()["persisted-pending"]
        self.assertEqual(record["digest"], self.digest)
        self.assertIsNone(record["verdict"])

        restarted = store.AuditStore(self.path)
        self.assertEqual(restarted.begin("persisted-pending", self.digest),
                         store.NEW)  # adopted, not refused
        verdict = {"audit_id": "persisted-pending", "status": "accepted"}
        restarted.complete("persisted-pending", self.digest, verdict)

        again = store.AuditStore(self.path)
        self.assertEqual(again.get("persisted-pending"), verdict)
        self.assertEqual(again.begin("persisted-pending", self.digest),
                         store.REPLAY)

    def test_pending_record_conflicts_with_different_retry(self):
        first = store.AuditStore(self.path)
        first.begin("persisted-pending", self.digest)
        del first

        changed = copy.deepcopy(self.submission)
        changed["events"] = changed["events"][:-1]
        restarted = store.AuditStore(self.path)
        self.assertEqual(
            restarted.begin("persisted-pending",
                            canonical.submission_digest(changed)),
            store.CONFLICT)


if __name__ == "__main__":
    unittest.main()

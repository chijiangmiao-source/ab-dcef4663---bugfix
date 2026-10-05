"""Concurrent submission boundary tests.

The audit identifier is a stable id: any number of callers retransmitting
semantically identical captures at the same time must produce exactly one
reviewable verdict -- one ``201`` for the first caller and ``200`` replays
for every overlapping equivalent caller -- while concurrent submissions of
different content stay explicit ``409`` conflicts.  An evaluation that dies
before the verdict forms (process crash against the persistence file, or an
internal failure) must leave the id retryable, never permanently locked.
"""

from __future__ import annotations

import json
import os
import tempfile
import threading
import unittest
import urllib.error
import urllib.request

from app import canonical, consensus, server, store, trajgen


def http_post(base: str, results: dict, key, raw: bytes) -> None:
    req = urllib.request.Request(base + "/v1/audits", data=raw, method="POST")
    req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            results[key] = (resp.status,
                            json.loads(resp.read().decode("utf-8")))
    except urllib.error.HTTPError as exc:
        results[key] = (exc.code, json.loads(exc.read().decode("utf-8")))


def http_post_one(base: str, submission):
    raw = json.dumps(submission).encode("utf-8")
    req = urllib.request.Request(base + "/v1/audits", data=raw, method="POST")
    req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read().decode("utf-8"))


def http_get(base: str, audit_id: str):
    with urllib.request.urlopen(f"{base}/v1/audits/{audit_id}",
                                timeout=15) as resp:
        return resp.status, json.loads(resp.read().decode("utf-8"))


def start_server(audit_store):
    srv = server.make_server(0, audit_store)
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}"


class StoreCoalescingTests(unittest.TestCase):
    def test_overlapping_equivalent_callers_share_one_verdict(self):
        s = store.AuditStore()
        self.assertEqual(s.begin("cap", "digest-a"), store.NEW)
        self.assertEqual(s.begin("cap", "digest-a"), store.PENDING)

        results = []
        t = threading.Thread(
            target=lambda: results.append(s.wait_for("cap", "digest-a")))
        t.start()
        self.assertTrue(t.is_alive())
        self.assertIsNone(s.get("cap"))  # gated: nothing to read yet

        s.finish("cap", "digest-a", {"audit_id": "cap", "status": "accepted"})
        t.join(timeout=5)
        self.assertEqual(results, [store.REPLAY])

        # Exactly one audit happened; everyone afterwards just replays.
        self.assertEqual(s.begin("cap", "digest-a"), store.REPLAY)
        self.assertEqual(s.get("cap")["status"], "accepted")

    def test_different_content_conflicts_while_pending_and_after(self):
        s = store.AuditStore()
        self.assertEqual(s.begin("cap", "digest-a"), store.NEW)
        for digest in ("digest-b", "digest-c"):
            self.assertEqual(s.begin("cap", digest), store.CONFLICT)

        s.finish("cap", "digest-a", {"audit_id": "cap", "status": "accepted"})
        for digest in ("digest-b", "digest-c"):
            self.assertEqual(s.begin("cap", digest), store.CONFLICT)
        self.assertEqual(s.begin("cap", "digest-a"), store.REPLAY)

    def test_abort_releases_lease_and_retry_takes_over(self):
        parked = threading.Event()
        s = store.AuditStore(wait_hook=lambda _id: parked.set())
        self.assertEqual(s.begin("cap", "digest-a"), store.NEW)

        results = []
        t = threading.Thread(
            target=lambda: results.append(s.wait_for("cap", "digest-a")))
        t.start()
        self.assertTrue(parked.wait(2))

        s.abort("cap", "digest-a")  # evaluator died without a verdict
        t.join(timeout=5)
        self.assertEqual(results, [store.ABORTED])

        self.assertEqual(s.begin("cap", "digest-a"), store.NEW)
        s.finish("cap", "digest-a", {"audit_id": "cap", "status": "accepted"})
        self.assertEqual(s.begin("cap", "digest-a"), store.REPLAY)

    def test_wait_timeout_leaves_state_intact(self):
        s = store.AuditStore()
        self.assertEqual(s.begin("cap", "digest-a"), store.NEW)
        self.assertEqual(s.wait_for("cap", "digest-a", timeout=0.01),
                         store.TIMEOUT)
        s.abort("cap", "digest-a")
        self.assertEqual(s.begin("cap", "digest-a"), store.NEW)

    def test_persistent_store_keeps_completed_verdict_across_restart(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "audits.json")
            s1 = store.AuditStore(path)
            self.assertEqual(s1.begin("cap", "digest-a"), store.NEW)
            s1.finish("cap", "digest-a",
                      {"audit_id": "cap", "status": "accepted"})

            s2 = store.AuditStore(path)
            self.assertEqual(s2.begin("cap", "digest-a"), store.REPLAY)
            self.assertEqual(s2.get("cap")["status"], "accepted")

    def test_interrupted_evaluation_is_retryable_after_restart(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "audits.json")
            s1 = store.AuditStore(path)
            self.assertEqual(s1.begin("cap", "digest-a"), store.NEW)
            self.assertTrue(os.path.exists(path))
            # ... service dies here, before finish() could store the verdict.

            s2 = store.AuditStore(path)  # orphaned lease dropped on load
            self.assertIsNone(s2.get("cap"))
            self.assertEqual(s2.begin("cap", "digest-a"), store.NEW)
            s2.finish("cap", "digest-a",
                      {"audit_id": "cap", "status": "accepted"})

            s3 = store.AuditStore(path)  # the retry survives later restarts
            self.assertEqual(s3.begin("cap", "digest-a"), store.REPLAY)


class HttpConcurrentSubmissionTests(unittest.TestCase):
    """Real overlapping HTTP requests against the threading server."""

    @classmethod
    def setUpClass(cls):
        cls._real_engine = consensus.Engine
        cls.srv, cls.base = start_server(store.AuditStore())

    @classmethod
    def tearDownClass(cls):
        consensus.Engine = cls._real_engine
        cls.srv.shutdown()
        cls.srv.server_close()

    def setUp(self):
        consensus.Engine = self._real_engine

    def _gated_engine(self, entered: threading.Event):
        """Engine substitute that parks the single evaluator on a gate."""
        real = self._real_engine
        gate = threading.Event()
        created = {"n": 0}
        lock = threading.Lock()

        class GatedEngine:
            def __init__(self, submission):
                self._real = real(submission)
                with lock:
                    created["n"] += 1
                    if created["n"] == 1:
                        entered.set()
                if not gate.wait(timeout=10):
                    raise RuntimeError("test gate never opened")

            def run(self):
                return self._real.run()

        consensus.Engine = GatedEngine
        return gate, created

    def test_overlapping_identical_posts_one_new_one_replay(self):
        builder, blocks = trajgen.build_commit_trajectory(
            "concurrent-identical", 4, 4)
        raw = json.dumps(builder.submission()).encode("utf-8")

        entered = threading.Event()
        gate, created = self._gated_engine(entered)
        parked = threading.Event()
        hooked = store.AuditStore(wait_hook=lambda _id: parked.set())
        srv, base = start_server(hooked)
        self.addCleanup(srv.server_close)
        self.addCleanup(srv.shutdown)

        results: dict = {}
        t1 = threading.Thread(target=http_post,
                              args=(base, results, 0, raw))
        t1.start()
        self.assertTrue(entered.wait(5), "owner never entered the engine")

        t2 = threading.Thread(target=http_post,
                              args=(base, results, 1, raw))
        t2.start()
        self.assertTrue(parked.wait(5), "equivalent caller never parked")
        # Still gated: no in_progress refusal, no verdict, single evaluation.
        self.assertEqual(results, {})
        self.assertEqual(created["n"], 1)

        gate.set()
        t1.join(timeout=10)
        t2.join(timeout=10)
        self.assertEqual(set(results), {0, 1})
        self.assertEqual(sorted(code for code, _ in results.values()),
                         [200, 201])
        self.assertEqual(created["n"], 1)  # exactly one audit evaluated

        new = [body for code, body in results.values() if code == 201][0]
        replay = [body for code, body in results.values() if code == 200][0]
        self.assertFalse(new["replayed"])
        self.assertTrue(replay["replayed"])
        self.assertEqual(new["status"], "accepted")
        self.assertEqual(new["committed"], blocks[:2])
        self.assertEqual({k: v for k, v in replay.items() if k != "replayed"},
                         {k: v for k, v in new.items() if k != "replayed"})

        status, fetched = http_get(base, "concurrent-identical")
        self.assertEqual(status, 200)
        self.assertEqual(fetched["committed"], blocks[:2])

    def test_ungated_burst_coalesces(self):
        builder, blocks = trajgen.build_commit_trajectory(
            "concurrent-burst", 4, 4)
        raw = json.dumps(builder.submission()).encode("utf-8")

        results: dict = {}
        barrier = threading.Barrier(5)

        def fire(key):
            barrier.wait()
            http_post(self.base, results, key, raw)

        threads = [threading.Thread(target=fire, args=(i,)) for i in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=15)

        self.assertEqual(sorted(code for code, _ in results.values()),
                         [200, 200, 200, 200, 201])
        verdicts = [body for _, body in results.values()]
        self.assertEqual({v["status"] for v in verdicts}, {"accepted"})
        self.assertEqual(sum(1 for v in verdicts if v["replayed"]), 4)
        self.assertTrue(all(v["committed"] == blocks[:2] for v in verdicts))

    def test_concurrent_different_content_is_explicit_conflict(self):
        builder, blocks = trajgen.build_commit_trajectory(
            "concurrent-conflict", 4, 4)
        submission = builder.submission()
        raw_a = json.dumps(submission).encode("utf-8")
        mutated = json.loads(json.dumps(submission))
        mutated["events"] = mutated["events"][:-1]  # semantically different
        raw_b = json.dumps(mutated).encode("utf-8")

        entered = threading.Event()
        gate, created = self._gated_engine(entered)

        results: dict = {}
        t1 = threading.Thread(target=http_post,
                              args=(self.base, results, 0, raw_a))
        t1.start()
        self.assertTrue(entered.wait(5))

        # Different content for the same id mid-evaluation: refused at once,
        # never queued behind the in-flight audit.
        t2 = threading.Thread(target=http_post,
                              args=(self.base, results, 1, raw_b))
        t2.start()
        t2.join(timeout=10)
        self.assertEqual(results[1][0], 409)
        self.assertEqual(results[1][1]["error"]["code"], "conflict")
        self.assertEqual(created["n"], 1)

        gate.set()
        t1.join(timeout=10)
        self.assertEqual(results[0][0], 201)
        self.assertEqual(results[0][1]["committed"], blocks[:2])

        status, body = http_post_one(self.base, mutated)
        self.assertEqual(status, 409)
        self.assertEqual(body["error"]["code"], "conflict")

    def test_failed_evaluation_releases_id_and_retry_succeeds(self):
        real = self._real_engine
        state = {"n": 0}
        lock = threading.Lock()

        class FlakyEngine:
            def __init__(self, submission):
                self._real = real(submission)
                with lock:
                    state["n"] += 1
                    self._fail = state["n"] == 1

            def run(self):
                if self._fail:
                    raise RuntimeError("simulated evaluation crash")
                return self._real.run()

        consensus.Engine = FlakyEngine
        builder, blocks = trajgen.build_commit_trajectory(
            "concurrent-flaky", 4, 4)
        submission = builder.submission()

        # First attempt: the single evaluation crashes before a verdict forms.
        status, body = http_post_one(self.base, submission)
        self.assertEqual(status, 500)
        self.assertEqual(body["error"]["code"], "audit_failed")

        # Same content after the failure: the lease was released, retry wins.
        status, verdict = http_post_one(self.base, submission)
        self.assertEqual(status, 201, verdict)
        self.assertEqual(verdict["committed"], blocks[:2])
        self.assertFalse(verdict["replayed"])

        status, replay = http_post_one(self.base, submission)
        self.assertEqual(status, 200)
        self.assertTrue(replay["replayed"])

    def test_waiter_takes_over_after_owner_evaluation_fails(self):
        real = self._real_engine
        state = {"n": 0}
        lock = threading.Lock()

        class FailOnceEngine:
            def __init__(self, submission):
                self._real = real(submission)
                with lock:
                    state["n"] += 1
                    self._fail = state["n"] == 1

            def run(self):
                if self._fail:
                    raise RuntimeError("simulated evaluation crash")
                return self._real.run()

        consensus.Engine = FailOnceEngine
        builder, blocks = trajgen.build_commit_trajectory(
            "concurrent-takeover", 4, 4)
        raw = json.dumps(builder.submission()).encode("utf-8")

        # Two equivalent callers start together.  The lease owner's single
        # evaluation crashes; the parked equivalent caller must wake, take
        # over the released lease, and produce the verdict.
        results: dict = {}
        barrier = threading.Barrier(2)

        def fire(key):
            barrier.wait()
            http_post(self.base, results, key, raw)

        threads = [threading.Thread(target=fire, args=(i,)) for i in range(2)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=15)

        codes = sorted(code for code, _ in results.values())
        self.assertEqual(codes, [201, 500], results)
        ok = [body for code, body in results.values() if code == 201][0]
        bad = [body for code, body in results.values() if code == 500][0]
        self.assertEqual(ok["committed"], blocks[:2])
        self.assertEqual(bad["error"]["code"], "audit_failed")
        self.assertEqual(state["n"], 2)  # exactly one failed try, one takeover

    def test_replay_after_completion_unchanged(self):
        builder, blocks = trajgen.build_commit_trajectory(
            "concurrent-sequential", 4, 4)
        submission = builder.submission()

        status, verdict = http_post_one(self.base, submission)
        self.assertEqual(status, 201)
        self.assertEqual(verdict["committed"], blocks[:2])

        results: dict = {}
        threads = [
            threading.Thread(target=http_post,
                             args=(self.base, results, i,
                                   json.dumps(submission).encode("utf-8")))
            for i in range(3)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10)
        self.assertEqual([code for code, _ in results.values()],
                         [200, 200, 200])
        self.assertTrue(all(body["replayed"] for _, body in results.values()))


class PersistentRestartTests(unittest.TestCase):
    """Lease persisted, service interrupted: retrying the same content wins."""

    def test_retry_after_interruption_completes(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "audits.json")
            builder, blocks = trajgen.build_commit_trajectory(
                "concurrent-restart", 4, 4)
            submission = builder.submission()
            digest = canonical.submission_digest(submission)

            interrupted = store.AuditStore(path)
            self.assertEqual(
                interrupted.begin("concurrent-restart", digest), store.NEW)
            del interrupted  # service dies before the verdict forms

            restarted = store.AuditStore(path)  # orphaned lease discarded
            srv, base = start_server(restarted)
            try:
                status, verdict = http_post_one(base, submission)
                self.assertEqual(status, 201, verdict)
                self.assertEqual(verdict["status"], "accepted")
                self.assertEqual(verdict["committed"], blocks[:2])

                status, replay = http_post_one(base, submission)
                self.assertEqual(status, 200)
                self.assertTrue(replay["replayed"])

                status, fetched = http_get(base, "concurrent-restart")
                self.assertEqual(status, 200)
                self.assertEqual(fetched["committed"], blocks[:2])
            finally:
                srv.shutdown()
                srv.server_close()


if __name__ == "__main__":
    unittest.main()

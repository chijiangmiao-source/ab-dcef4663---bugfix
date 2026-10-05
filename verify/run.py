"""One-shot verification entry point used by Docker Compose.

A single run of ``python -m verify.run``:

1. executes the lock-rule unit tests (Ed25519 vectors, consensus rules,
   in-process API tests);
2. waits for the ``audit`` service to become healthy and runs HTTP smoke
   checks against it: a commit trajectory, reject trajectories, idempotent
   replay, and conflict handling;

then exits with status 0 on success and 1 on any failure.
"""

from __future__ import annotations

import copy
import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request

AUDIT_URL = os.environ.get("AUDIT_URL", "http://127.0.0.1:8080").rstrip("/")
WAIT_SECONDS = float(os.environ.get("AUDIT_WAIT_SECONDS", "60"))

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import trajgen  # noqa: E402

_FAILURES: list[str] = []


def check(name: str, condition: bool, detail: str = "") -> None:
    if condition:
        print(f"  PASS {name}")
    else:
        print(f"  FAIL {name} {detail}")
        _FAILURES.append(name)


def run_unit_tests() -> bool:
    print("== lock-rule unit tests ==")
    suite = unittest.TestLoader().discover("tests")
    result = unittest.TextTestRunner(verbosity=1).run(suite)
    return result.wasSuccessful()


def wait_for_service() -> bool:
    print(f"== waiting for audit service at {AUDIT_URL} ==")
    if wait_for_url(AUDIT_URL + "/health", timeout=WAIT_SECONDS):
        print("  service is healthy")
        return True
    print("  service did not become healthy in time")
    return False


def wait_for_url(url: str, timeout: float = 30.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=3) as r:
                if r.status == 200:
                    return True
        except Exception:
            pass
        time.sleep(0.25)
    return False


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def spawn_audit(store_file: str | None = None, eval_delay: float = 0.0,
                port: int | None = None):
    """Launch a short-lived audit service inside this container."""
    port = port or free_port()
    env = dict(os.environ)
    env["PORT"] = str(port)
    env["AUDIT_EVAL_DELAY"] = str(eval_delay)
    if store_file:
        env["AUDIT_STORE_FILE"] = store_file
    else:
        env.pop("AUDIT_STORE_FILE", None)
    proc = subprocess.Popen(
        [sys.executable, "-m", "app.server"],
        env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    base = f"http://127.0.0.1:{port}"
    if not wait_for_url(base + "/health", timeout=15):
        proc.kill()
        raise RuntimeError(f"side audit instance on port {port} never started")
    return proc, base


def http(method: str, path: str, body=None, base: str = AUDIT_URL,
         timeout: float = 10):
    data = None if body is None else json.dumps(body).encode("utf-8")
    req = urllib.request.Request(base + path, data=data, method=method)
    if data is not None:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read().decode("utf-8"))


def smoke() -> None:
    print("== HTTP smoke: health ==")
    status, body = http("GET", "/health")
    check("health 200", status == 200 and body.get("status") == "ok",
          f"got {status} {body}")

    print("== HTTP smoke: commit trajectory (n=4) ==")
    builder, blocks = trajgen.build_commit_trajectory("smoke-commit-4", 4, 4)
    submission = builder.submission()
    status, verdict = http("POST", "/v1/audits", submission)
    check("commit accepted", status == 201 and verdict.get("status") == "accepted",
          f"got {status} {verdict.get('violation')}")
    check("commit derives 3-chain commits",
          verdict.get("committed") == blocks[:2],
          f"got {verdict.get('committed')}")
    check("commit certificates have 2f+1 signers",
          all(len(c["signers"]) >= 3 for c in verdict.get("certificates", []))
          and len(verdict.get("certificates", [])) == 4)
    check("commit locks climbed to view 4",
          all(l["locked"]["view"] == 4 for l in verdict.get("locks", {}).values()))

    print("== HTTP smoke: commit trajectory (n=7) ==")
    builder7, blocks7 = trajgen.build_commit_trajectory("smoke-commit-7", 7, 3)
    status, verdict7 = http("POST", "/v1/audits", builder7.submission())
    check("n=7 accepted", status == 201 and verdict7.get("status") == "accepted",
          f"got {status} {verdict7.get('violation')}")
    check("n=7 quorum 5 and commit",
          verdict7.get("quorum") == 5 and verdict7.get("committed") == blocks7[:1])

    print("== HTTP smoke: idempotent replay and conflict ==")
    status, replay = http("POST", "/v1/audits", submission)
    check("replay returns original verdict",
          status == 200 and replay.get("replayed") is True
          and replay.get("committed") == blocks[:2],
          f"got {status}")
    mutated = json.loads(json.dumps(submission))
    mutated["events"] = mutated["events"][:-1]
    status, conflict = http("POST", "/v1/audits", mutated)
    check("conflicting content rejected with 409",
          status == 409 and conflict.get("error", {}).get("code") == "conflict",
          f"got {status} {conflict}")
    status, fetched = http("GET", "/v1/audits/smoke-commit-4")
    check("stored verdict fetchable",
          status == 200 and fetched.get("committed") == blocks[:2],
          f"got {status}")

    print("== HTTP smoke: reject trajectories ==")
    unsafe, offending = trajgen.build_unsafe_vote_trajectory("smoke-unsafe")
    status, verdict = http("POST", "/v1/audits", unsafe.submission())
    check("unsafe vote frozen at earliest event",
          status == 201 and verdict.get("status") == "rejected"
          and verdict.get("violation", {}).get("type") == "unsafe_vote"
          and verdict.get("violation", {}).get("event_index") == offending,
          f"got {status} {verdict.get('violation')}")
    check("frozen trajectory yields no commits",
          verdict.get("committed") == [])

    bad_sig = trajgen.TrajectoryBuilder("smoke-bad-signature", 4)
    block = bad_sig.propose(0, 1, (bad_sig.genesis_id, 0))
    bad_sig.vote(0, 1, block, sign=False)
    status, verdict = http("POST", "/v1/audits", bad_sig.submission())
    check("invalid signature frozen",
          status == 201 and verdict.get("status") == "rejected"
          and verdict.get("violation", {}).get("type") == "invalid_signature",
          f"got {status} {verdict.get('violation')}")

    missing = trajgen.TrajectoryBuilder("smoke-missing-qc", 4)
    block = missing.propose(0, 1, (missing.genesis_id, 0))
    missing.observe(0, block, 1)  # no certificate formed yet
    status, verdict = http("POST", "/v1/audits", missing.submission())
    check("missing certificate frozen",
          status == 201 and verdict.get("status") == "rejected"
          and verdict.get("violation", {}).get("type") == "missing_certificate",
          f"got {status} {verdict.get('violation')}")

    print("== HTTP smoke: envelope errors ==")
    status, body = http("GET", "/v1/audits/never-submitted")
    check("unknown audit id 404", status == 404, f"got {status}")
    dup = trajgen.TrajectoryBuilder("smoke-dup", 4).submission()
    dup["validators"][1] = dup["validators"][0]
    status, body = http("POST", "/v1/audits", dup)
    check("duplicate identity 400",
          status == 400 and body.get("error", {}).get("code") == "duplicate_identity",
          f"got {status} {body}")


def overlap_smoke() -> None:
    """Overlapping submissions over real HTTP: one new verdict, equivalent
    collisions replay the same content; altered content conflicts."""
    print("== HTTP smoke: overlapping submissions (side instance) ==")
    proc, base = spawn_audit(eval_delay=1.0)
    try:
        builder, blocks = trajgen.build_commit_trajectory(
            "overlap-identical", 4, 4)
        submission = builder.submission()

        results: list = []

        def submit(payload):
            results.append(http("POST", "/v1/audits", payload, base=base,
                                timeout=20))

        threads = [threading.Thread(target=submit, args=(submission,))
                   for _ in range(3)]
        for t in threads:
            t.start()
        time.sleep(0.3)  # all three requests are in flight during the delay
        for t in threads:
            t.join(timeout=20)

        statuses = sorted(s for s, _ in results)
        check("overlap: one new verdict and two replays",
              statuses == [200, 200, 201],
              f"got {statuses}")
        created = next(b for s, b in results if s == 201)
        replayed = [b for s, b in results if s == 200]
        check("overlap: new verdict accepted, replays flagged",
              created.get("replayed") is False
              and all(b.get("replayed") is True for b in replayed),
              f"got {created.get('replayed')}, "
              f"{[b.get('replayed') for b in replayed]}")
        check("overlap: replays carry identical verdict content",
              all({k: v for k, v in b.items() if k != "replayed"}
                  == {k: v for k, v in created.items() if k != "replayed"}
                  for b in replayed),
              "replay content diverged from the new verdict")
        check("overlap: 3-chain commits present exactly once",
              created.get("committed") == blocks[:2])

        # Alterations arriving while another audit is (still) pending must be
        # explicit conflicts, never "in progress".  Vote signatures cover the
        # audit id, so each mutation gets its own freshly signed trajectory.
        mutations = {
            "business event": lambda s: s["events"].pop(),
            "validator set": lambda s: s["validators"].__setitem__(
                0, trajgen.ed25519.publickey(
                    trajgen.validator_seed(99)).hex()),
            "genesis block": lambda s: s["genesis"].__setitem__(
                "id", "11" * 32),
        }
        for label, mutate in mutations.items():
            conf_builder, _ = trajgen.build_commit_trajectory(
                f"overlap-conflict-{label.replace(' ', '-')}", 4, 4)
            conf_original = conf_builder.submission()
            winner = {}

            def post_owner(payload=conf_original):
                winner["result"] = http("POST", "/v1/audits", payload,
                                        base=base, timeout=20)

            t = threading.Thread(target=post_owner)
            t.start()
            time.sleep(0.3)  # inside the pending window
            changed = copy.deepcopy(conf_original)
            mutate(changed)
            status, body = http("POST", "/v1/audits", changed, base=base,
                                timeout=20)
            t.join(timeout=20)
            owner_status, _ = winner["result"]
            check(f"overlap conflict via {label}",
                  status == 409
                  and body.get("error", {}).get("code") == "conflict"
                  and owner_status == 201,
                  f"got {status} {body.get('error')} / owner "
                  f"{owner_status}")

        # a rejected verdict (unsafe vote) also coalesces under overlap
        unsafe_builder, _ = trajgen.build_unsafe_vote_trajectory(
            "overlap-unsafe")
        unsafe = unsafe_builder.submission()
        results = []
        threads = [threading.Thread(
            target=lambda p: results.append(
                http("POST", "/v1/audits", p, base=base, timeout=20)),
            args=(unsafe,)) for _ in range(2)]
        for t in threads:
            t.start()
        time.sleep(0.3)
        for t in threads:
            t.join(timeout=20)
        statuses = sorted(s for s, _ in results)
        check("overlap: rejected verdict also coalesces",
              statuses == [200, 201]
              and all(b.get("status") == "rejected" for _, b in results)
              and all(b.get("violation", {}).get("type") == "unsafe_vote"
                      for _, b in results),
              f"got {statuses}")
    finally:
        proc.terminate()
        proc.wait(timeout=10)


def recovery_smoke() -> None:
    """A persisted pending reservation interrupted before the verdict forms
    must let an identical retry finish after restart."""
    print("== HTTP smoke: crash before verdict, safe retry after restart ==")
    with tempfile.TemporaryDirectory() as tmp:
        store_file = os.path.join(tmp, "audits.json")
        builder, blocks = trajgen.build_commit_trajectory(
            "recovery-pending", 4, 4)
        submission = builder.submission()

        proc, base = spawn_audit(store_file=store_file, eval_delay=3.0)
        try:
            def hold_request():
                # Expected to fail: this service is killed while evaluating.
                try:
                    http("POST", "/v1/audits", submission,
                         base=base, timeout=15)
                except Exception:
                    pass

            holder = threading.Thread(target=hold_request)
            holder.start()
            # wait for the pending reservation to reach disk, then kill the
            # service while its evaluation is still sleeping
            deadline = time.time() + 10
            while time.time() < deadline:
                try:
                    with open(store_file, encoding="utf-8") as fh:
                        records = json.load(fh).get("records", {})
                    if "recovery-pending" in records:
                        break
                except (OSError, ValueError):
                    pass
                time.sleep(0.1)
            with open(store_file, encoding="utf-8") as fh:
                persisted = json.load(fh)["records"]["recovery-pending"]
            check("pending reservation persisted before verdict",
                  persisted.get("verdict") is None)
        finally:
            proc.kill()
            proc.wait(timeout=10)
            holder.join(timeout=5)

        # restart with the same store file and retry identical content
        proc, base = spawn_audit(store_file=store_file, eval_delay=0.0)
        try:
            status, verdict = http("POST", "/v1/audits", submission,
                                   base=base, timeout=20)
            check("identical retry after crash completes as new verdict",
                  status == 201 and verdict.get("status") == "accepted"
                  and verdict.get("replayed") is False
                  and verdict.get("committed") == blocks[:2],
                  f"got {status} {verdict.get('error')}")
            status, replay = http("POST", "/v1/audits", submission,
                                  base=base, timeout=20)
            check("completed verdict replays after recovery",
                  status == 200 and replay.get("replayed") is True
                  and replay.get("committed") == blocks[:2],
                  f"got {status}")
            changed = copy.deepcopy(submission)
            changed["events"] = changed["events"][:-1]
            status, body = http("POST", "/v1/audits", changed, base=base)
            check("different content still conflicts after recovery",
                  status == 409
                  and body.get("error", {}).get("code") == "conflict",
                  f"got {status}")
        finally:
            proc.terminate()
            proc.wait(timeout=10)


def main() -> int:
    ok = run_unit_tests()
    if not ok:
        print("unit tests failed; skipping HTTP smoke")
        return 1
    if not wait_for_service():
        return 1
    # Each phase runs even if an earlier one failed, so a single report
    # covers the whole concurrency boundary; the exit code aggregates them.
    for phase in (smoke, overlap_smoke, recovery_smoke):
        try:
            phase()
        except Exception as exc:  # connection reset, JSON decode, ...
            print(f"  FAIL {phase.__name__} raised {exc!r}")
            _FAILURES.append(f"{phase.__name__}: {exc!r}")
    if _FAILURES:
        print(f"VERIFY FAILED: {len(_FAILURES)} check(s) failed: {_FAILURES}")
        return 1
    print("VERIFY OK: unit tests and HTTP smoke passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())

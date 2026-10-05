"""One-shot verification entry point used by Docker Compose.

A single run of ``python -m verify.run``:

1. executes the lock-rule unit tests (Ed25519 vectors, consensus rules,
   API and concurrent-submission boundary tests);
2. waits for the ``audit`` service to become healthy and runs HTTP smoke
   checks against it: a commit trajectory, reject trajectories, idempotent
   replay, conflict handling, and the concurrency boundary -- simultaneous
   identical captures coalesce into one new verdict plus replays, while
   simultaneous differing captures are explicit conflicts;

then exits with status 0 on success and 1 on any failure.
"""

from __future__ import annotations

import json
import os
import sys
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
    deadline = time.time() + WAIT_SECONDS
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(AUDIT_URL + "/health", timeout=3) as r:
                if r.status == 200:
                    print("  service is healthy")
                    return True
        except Exception:
            pass
        time.sleep(1)
    print("  service did not become healthy in time")
    return False


def http(method: str, path: str, body=None):
    data = None if body is None else json.dumps(body).encode("utf-8")
    req = urllib.request.Request(AUDIT_URL + path, data=data, method=method)
    if data is not None:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
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


def _post_raw(path: str, raw: bytes, results: dict, key: int) -> None:
    req = urllib.request.Request(AUDIT_URL + path, data=raw, method="POST")
    req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            results[key] = (resp.status, json.loads(resp.read().decode("utf-8")))
    except urllib.error.HTTPError as exc:
        results[key] = (exc.code, json.loads(exc.read().decode("utf-8")))


def _simultaneous(posts: list[tuple[bytes, str]]) -> dict:
    """Fire every (raw body, path) pair from threads released together."""
    results: dict = {}
    barrier = threading.Barrier(len(posts))

    def fire(key, raw, path):
        barrier.wait()
        _post_raw(path, raw, results, key)

    threads = [
        threading.Thread(target=fire, args=(i, raw, path))
        for i, (raw, path) in enumerate(posts)
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)
    return results


def concurrency_smoke() -> None:
    print("== HTTP smoke: concurrent identical submissions ==")
    # Several rounds of simultaneous equivalent captures of the same id:
    # the stable audit id must be evaluated exactly once per round (one 201);
    # every overlapping equivalent caller receives the same verdict as a
    # 200 replay rather than an "in progress" refusal.
    rounds = 5
    callers = 6
    for r in range(rounds):
        builder, blocks = trajgen.build_commit_trajectory(
            f"smoke-concurrent-{r}", 4, 4)
        raw = json.dumps(builder.submission()).encode("utf-8")
        results = _simultaneous([(raw, "/v1/audits")] * callers)

        statuses = sorted(code for code, _ in results.values())
        check(f"round {r}: one new verdict, {callers - 1} equivalent replays",
              len(results) == callers and statuses == [200] * (callers - 1) + [201],
              f"got {statuses}")
        verdicts = [body for _, body in results.values()]
        check(f"round {r}: all callers share the same verdict",
              all(v.get("status") == "accepted"
                  and v.get("committed") == blocks[:2]
                  for v in verdicts),
              f"got {[v.get('violation') for v in verdicts]}")
        created = [v for v in verdicts if not v.get("replayed")]
        check(f"round {r}: exactly one non-replayed verdict",
              len(created) == 1, f"got {len(created)}")

        status, fetched = http("GET", f"/v1/audits/smoke-concurrent-{r}")
        check(f"round {r}: single verdict readable by id",
              status == 200 and fetched.get("committed") == blocks[:2],
              f"got {status}")

    print("== HTTP smoke: concurrent conflicting submissions ==")
    # Simultaneous sends of semantically different captures under the same
    # id: exactly one caller may win the single evaluation (201); every
    # differing caller -- including ones that overlap the in-flight audit --
    # must be turned away with an explicit 409 conflict.  The three variants
    # alter one business event, the validator set ordering, and the genesis.
    audit_id = "smoke-concurrent-conflict"
    builder, _ = trajgen.build_commit_trajectory(audit_id, 7, 4)
    submission = builder.submission()
    variants = []
    changed_event = json.loads(json.dumps(submission))
    changed_event["events"] = changed_event["events"][:-1]
    variants.append(changed_event)
    changed_validators = json.loads(json.dumps(submission))
    changed_validators["validators"] = list(
        reversed(changed_validators["validators"]))
    variants.append(changed_validators)
    changed_genesis = json.loads(json.dumps(submission))
    changed_genesis["genesis"]["id"] = "ab" * 32
    variants.append(changed_genesis)

    raws = [json.dumps(submission).encode("utf-8")]
    raws += [json.dumps(v).encode("utf-8") for v in variants]
    results = _simultaneous([(raw, "/v1/audits") for raw in raws])

    codes = sorted(code for code, _ in results.values())
    check("one winner and three explicit conflicts under contention",
          codes == [201, 409, 409, 409], f"got {codes}")
    conflicts = [body for code, body in results.values() if code == 409]
    check("every refusal is a content conflict, never 'in progress'",
          all(b.get("error", {}).get("code") == "conflict" for b in conflicts)
          and len(conflicts) == 3,
          f"got {[b.get('error') for b in conflicts]}")

    winner_key = next(k for k, (code, _) in results.items() if code == 201)
    winner_body = results[winner_key][1]
    check("the winning verdict is well formed",
          winner_body.get("audit_id") == audit_id
          and winner_body.get("replayed") is False,
          f"got {winner_body}")

    # Whichever variant won: its content now replays; the other three
    # (including the canonical submission) stay explicit conflicts.
    status, replay = http("POST", "/v1/audits",
                          json.loads(raws[winner_key].decode("utf-8")))
    check("the winning capture replays after the burst",
          status == 200 and replay.get("replayed") is True
          and replay.get("committed") == winner_body.get("committed"),
          f"got {status}")
    losers_conflict = True
    for k, raw in enumerate(raws):
        if k == winner_key:
            continue
        status, body = http("POST", "/v1/audits",
                            json.loads(raw.decode("utf-8")))
        if status != 409 or body.get("error", {}).get("code") != "conflict":
            losers_conflict = False
    check("each differing capture is still an explicit conflict",
          losers_conflict, "")

    status, fetched = http("GET", f"/v1/audits/{audit_id}")
    check("the single winning verdict is readable by id",
          status == 200 and fetched.get("committed")
          == winner_body.get("committed"), f"got {status}")


def main() -> int:
    ok = run_unit_tests()
    if not ok:
        print("unit tests failed; skipping HTTP smoke")
        return 1
    if not wait_for_service():
        return 1
    try:
        smoke()
        concurrency_smoke()
    except Exception as exc:  # connection reset, JSON decode, ...
        print(f"  FAIL smoke raised {exc!r}")
        _FAILURES.append(str(exc))
    if _FAILURES:
        print(f"VERIFY FAILED: {len(_FAILURES)} check(s) failed: {_FAILURES}")
        return 1
    print("VERIFY OK: unit tests and HTTP smoke passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())

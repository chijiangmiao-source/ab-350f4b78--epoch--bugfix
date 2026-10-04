#!/usr/bin/env python3
"""Acceptance driver for the DTLS 1.3 audit service.

Runs, in order:
  1. build checks        — byte-compile the app, import it, sanity-check the page
  2. review-rule tests   — the unittest suite (replay window, KeyUpdate, vectors)
  3. HTTP smoke tests    — live API checks of the KeyUpdate ratchet and the
                           replay-window boundary against APP_BASE_URL

Exits 0 when every check passes, 1 otherwise, so `docker compose up
--exit-code-from verify` reports the acceptance result as its status code.
"""
import base64
import compileall
import json
import os
import sys
import unittest
import urllib.error
import urllib.request

APP_BASE = os.environ.get("APP_BASE_URL", "http://127.0.0.1:8000").rstrip("/")
FAILURES: list[str] = []


def check(name, cond, detail=""):
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}"
          + (f" — {detail}" if detail and not cond else ""))
    if not cond:
        FAILURES.append(f"{name}: {detail}")
    return cond


# ---------------------------------------------------------------- build checks
def build_checks():
    print("[verify] build checks")
    check("compileall server", compileall.compile_dir("server", quiet=1))
    check("compileall tests", compileall.compile_dir("tests", quiet=1))
    try:
        import server.main  # noqa: F401
        check("import server.main", True)
    except Exception as exc:  # pragma: no cover
        check("import server.main", False, repr(exc))
    try:
        with open("server/static/index.html", encoding="utf-8") as fh:
            html = fh.read()
        check("page contains audit form",
              all(token in html for token in ("audit_id", "traffic_secret", "records")))
    except OSError as exc:
        check("page contains audit form", False, repr(exc))


# ------------------------------------------------------------ review-rule tests
def review_rule_tests():
    print("[verify] review-rule tests")
    suite = unittest.TestLoader().discover("tests")
    result = unittest.TextTestRunner(verbosity=1).run(suite)
    check("review-rule test suite", result.wasSuccessful(),
          f"{len(result.failures)} failure(s), {len(result.errors)} error(s)")


# ---------------------------------------------------------------- HTTP helpers
def http(method, path, payload=None):
    data = headers = None
    if payload is not None:
        data = json.dumps(payload).encode()
        headers = {"Content-Type": "application/json"}
    req = urllib.request.Request(APP_BASE + path, data=data,
                                 headers=headers or {}, method=method)
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, _maybe_json(resp.read())
    except urllib.error.HTTPError as exc:
        return exc.code, _maybe_json(exc.read())


def _maybe_json(raw: bytes):
    try:
        return json.loads(raw.decode())
    except Exception:
        return raw.decode(errors="replace")


def b64(blob):
    return base64.b64encode(blob).decode()


def post_audit(audit_id, secret_hex, records, initial_epoch=3):
    return http("POST", "/api/audit", {
        "audit_id": audit_id,
        "initial_epoch": initial_epoch,
        "traffic_secret": secret_hex,
        "records": [b64(r) for r in records],
    })


def viol(row):
    return row.get("violation") or {}


# ------------------------------------------------------------------ smoke tests
def smoke_tests():
    from server.crypto import ratchet_secret
    from server.encode import key_update_record, seal_record

    print(f"[verify] HTTP smoke tests against {APP_BASE}")

    status, body = http("GET", "/healthz")
    check("health endpoint", status == 200 and body.get("status") == "ok",
          f"{status} {body}")
    status, _ = http("GET", "/")
    check("audit page served", status == 200, f"status {status}")

    secret3 = bytes(range(32))
    secret4 = ratchet_secret(secret3)
    secret_hex = secret3.hex()

    def app(seq, payload=b"m", secret=secret3, epoch=3, tamper=False):
        rec = bytearray(seal_record(secret, epoch, seq, payload, 23))
        if tamper:
            rec[-1] ^= 1
        return bytes(rec)

    # --- scenario A: legal KeyUpdate ratchets epoch and resets the window ---
    records = [
        app(0, b"ping-0"),
        app(1, b"ping-1"),
        key_update_record(secret3, 3, 2, request_update=0),
        seal_record(secret4, 4, 0, b"post-update", 23),
        app(1, b"ping-1"),  # late replay in the old epoch
    ]
    status, v = post_audit("smoke-keyupdate", secret_hex, records)
    ok = status == 200 and v.get("ok") is True
    check("keyupdate: submission accepted without violations", ok,
          f"{status} {json.dumps(v)[:300]}" if not ok else "")
    if status == 200:
        recs = v["records"]
        check("keyupdate: KeyUpdate processed after authentication",
              recs[2]["key_update"] == "processed" and recs[2]["auth"] == "ok")
        check("keyupdate: ratchet advanced to epoch 4",
              v["final_state"]["current_epoch"] == 4
              and v["final_state"]["ratchets"] == 1)
        check("keyupdate: next-epoch record adjudicated new",
              recs[3]["epoch"] == 4 and recs[3]["replay"] == "new")
        check("keyupdate: old-epoch replay adjudicated duplicate",
              recs[4]["replay"] == "duplicate" and recs[4]["epoch"] == 3)
        check("keyupdate: new epoch window reset then advanced",
              any(e["epoch"] == 4 and e["highest"] == 0
                  and e["bitmap"] == "0000000000000001"
                  for e in v["final_state"]["epochs"]))
    status, v2 = http("GET", "/api/audit/smoke-keyupdate")
    check("keyupdate: frozen verdict reopens",
          status == 200 and v2.get("ok") is True and v2.get("record_count") == 5,
          f"status {status}")

    # --- scenario B: replay-window boundary (64-bit bitmap) ---
    records = [
        app(0),                 # new
        app(0),                 # duplicate
        app(64),                # new, jumps the window
        app(0),                 # offset 64 -> too old
        app(1),                 # offset 63 -> new
        app(2, tamper=True),    # AEAD failure, must not advance the window
        app(2),                 # still new after the failed forgery
    ]
    status, v = post_audit("smoke-replay", secret_hex, records)
    if status != 200:
        check("replay: submission accepted", False, f"status {status}")
    else:
        recs = v["records"]
        check("replay: fresh record is new", recs[0]["replay"] == "new")
        check("replay: exact replay is duplicate", recs[1]["replay"] == "duplicate")
        check("replay: jump to 64 is new", recs[2]["replay"] == "new")
        check("replay: offset 64 is too old", recs[3]["replay"] == "too_old")
        check("replay: offset 63 is new", recs[4]["replay"] == "new")
        check("replay: tampered record fails authentication",
              viol(recs[5]).get("kind") == "authentication")
        check("replay: authentication failure offset points at the tag",
              viol(recs[5]).get("offset") == len(records[5]) - 16)
        check("replay: failed record did not advance the window",
              recs[5]["window_before"] == recs[5]["window_after"])
        check("replay: genuine seq 2 still new after the failure",
              recs[6]["replay"] == "new")
        fv = v.get("first_violation") or {}
        check("replay: first violation reported with raw offset",
              fv.get("record_index") == 5 and fv.get("kind") == "authentication"
              and fv.get("offset") == len(records[5]) - 16)

    # --- scenario C: forged KeyUpdate never ratchets; stale success cleared ---
    status, v = post_audit("smoke-forged-ku", secret_hex, [app(0), app(1)])
    check("forged-ku: clean submission succeeds first",
          status == 200 and v.get("ok") is True,
          f"{status} {json.dumps(v)[:200]}" if not (status == 200 and v.get("ok")) else "")
    forged = bytearray(key_update_record(secret3, 3, 1, request_update=1))
    forged[-1] ^= 0x80  # corrupt the tag: a forged KeyUpdate
    records = [app(0), bytes(forged), seal_record(secret4, 4, 0, b"next", 23)]
    status, v = post_audit("smoke-forged-ku", secret_hex, records)
    if status != 200:
        check("forged-ku: resubmission accepted", False, f"status {status}")
    else:
        recs = v["records"]
        check("forged-ku: verdict reports violations", v.get("ok") is False)
        check("forged-ku: forged KeyUpdate fails authentication",
              viol(recs[1]).get("kind") == "authentication")
        check("forged-ku: secret and window never advance",
              v["final_state"]["current_epoch"] == 3
              and v["final_state"]["ratchets"] == 0)
        check("forged-ku: next-epoch record rejected as state violation",
              viol(recs[2]).get("kind") == "state")
    status, v = http("GET", "/api/audit/smoke-forged-ku")
    check("forged-ku: stale success evidence cleared on resubmission",
          status == 200 and v.get("ok") is False, f"status {status}")

    # --- scenario D: truncation / length violations carry raw offsets ---
    status, v = post_audit("smoke-trunc", secret_hex, [bytes([0x2C, 0x00])])
    fv = (v or {}).get("first_violation") or {}
    check("truncation: kind and raw offset reported",
          status == 200 and fv.get("kind") == "truncation" and fv.get("offset") == 1,
          f"{status} {fv}")

    rec = bytearray(seal_record(secret3, 3, 0, b"xyz", 23))  # S=1,L=1: length @3
    declared = int.from_bytes(rec[3:5], "big")
    rec[3:5] = (declared - 1).to_bytes(2, "big")
    status, v = post_audit("smoke-length", secret_hex, [bytes(rec)])
    fv = (v or {}).get("first_violation") or {}
    check("length: kind and raw offset reported",
          status == 200 and fv.get("kind") == "length" and fv.get("offset") == 3,
          f"{status} {fv}")

    # --- scenario E: four continuous KeyUpdates; low epoch tag wraps ------
    # epochs 3 and 7 both carry E=3 in the unified header. The first
    # application-data record of epoch 7 must be attributed to epoch 7, not
    # dropped as a duplicate capture of the same-tag initial epoch.
    chain = [secret3]
    for _ in range(4):
        chain.append(ratchet_secret(chain[-1]))
    import hashlib as _hashlib
    telemetry = b"first-telemetry-after-rotation"
    telemetry_digest = _hashlib.sha256(telemetry).hexdigest()
    ku_initial = key_update_record(chain[0], 3, 0)
    forged = bytearray(seal_record(chain[4], 7, 1, b"forged", 23))
    forged[-1] ^= 0x01
    records = [
        ku_initial,                                  # epoch 3 seq 0 -> epoch 4
        key_update_record(chain[1], 4, 0),           # -> epoch 5
        key_update_record(chain[2], 5, 0),           # -> epoch 6
        key_update_record(chain[3], 6, 0),           # -> epoch 7
        seal_record(chain[4], 7, 0, telemetry, 23),  # tag 3 == epoch 3's tag
        bytes(ku_initial),                           # true replay, epoch 3
        seal_record(chain[0], 3, 7, b"late-e3", 23), # unseen straggler, epoch 3
        seal_record(chain[4], 7, 0, telemetry, 23),  # exact replay, epoch 7
        bytes(forged),                               # forged under the shared tag
    ]
    status, v = post_audit("smoke-rotation", secret_hex, records)
    ok = status == 200 and v.get("ok") is False  # the forged record is a violation
    check("rotation: submission adjudicated", ok,
          f"{status} {json.dumps(v)[:300]}" if not ok else "")
    if status == 200:
        recs = v["records"]
        check("rotation: four KeyUpdates processed in order",
              [recs[i]["key_update"] for i in range(4)] == ["processed"] * 4
              and all(recs[i]["auth"] == "ok" for i in range(4)))
        check("rotation: current epoch is 7 after four ratchets",
              v["final_state"]["current_epoch"] == 7
              and v["final_state"]["ratchets"] == 4)
        fresh = recs[4]
        check("rotation: first telemetry attributed to epoch 7",
              fresh["epoch"] == 7 and fresh["seq"] == 0,
              f"epoch={fresh['epoch']} seq={fresh['seq']}")
        check("rotation: telemetry is new and authenticated",
              fresh["replay"] == "new" and fresh["auth"] == "ok",
              f"replay={fresh['replay']} auth={fresh['auth']}")
        check("rotation: application-data digest returned",
              fresh["app_data_sha256"] == telemetry_digest
              and fresh["inner_type"] == "application_data",
              str(fresh.get("app_data_sha256")))
        win_after = fresh.get("window_after") or {}
        check("rotation: epoch 7 window advanced by the record",
              win_after.get("epoch") == 7 and win_after.get("highest") == 0
              and win_after.get("bitmap") == "0000000000000001",
              str(win_after))
        check("rotation: same-tag old capture stays an epoch-3 duplicate",
              recs[5]["epoch"] == 3 and recs[5]["replay"] == "duplicate")
        check("rotation: old-epoch straggler adjudicated on epoch 3",
              recs[6]["epoch"] == 3 and recs[6]["replay"] == "new"
              and recs[6]["auth"] == "ok")
        check("rotation: replay of the epoch-7 telemetry is a duplicate",
              recs[7]["epoch"] == 7 and recs[7]["replay"] == "duplicate")
        check("rotation: forged record fails authentication at the tag",
              viol(recs[8]).get("kind") == "authentication"
              and viol(recs[8]).get("offset") == len(records[8]) - 16)
        epoch_windows = {e["epoch"]: e for e in v["final_state"]["epochs"]}
        check("rotation: epoch 7 window records only the genuine telemetry",
              epoch_windows[7]["highest"] == 0
              and epoch_windows[7]["bitmap"] == "0000000000000001"
              and epoch_windows[3]["highest"] == 7,
              json.dumps(epoch_windows))
        fv = v.get("first_violation") or {}
        check("rotation: first violation is the forged record only",
              fv.get("record_index") == 8 and fv.get("kind") == "authentication")
    status, v2 = http("GET", "/api/audit/smoke-rotation")
    check("rotation: frozen verdict reopens with the same attribution",
          status == 200 and (v2 or {}).get("final_state", {})
          .get("current_epoch") == 7
          and v2["records"][4]["epoch"] == 7
          and v2["records"][4]["app_data_sha256"] == telemetry_digest,
          f"status {status}")


def main():
    print(f"[verify] acceptance run, target {APP_BASE}")
    build_checks()
    review_rule_tests()
    smoke_tests()
    if FAILURES:
        print("[verify] failures:")
        for failure in FAILURES:
            print("  -", failure)
    print("[verify] ACCEPTANCE:", "PASS" if not FAILURES else "FAIL")
    sys.exit(0 if not FAILURES else 1)


if __name__ == "__main__":
    main()

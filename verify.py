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
import hashlib
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

    # --- scenario E: four consecutive KeyUpdates wrap the 2-bit epoch label ---
    # Initial epoch 0: after four authenticated KeyUpdates the current epoch
    # is 4, whose header label E=00 repeats the initial epoch's label. The
    # first seq-0 application record of the new epoch must be attributed to
    # epoch 4, not dropped as a duplicate capture of epoch 0.
    wrap_secret = bytes(range(32))
    wrap_secrets = [wrap_secret]
    wrap_records = []
    for epoch in range(4):
        wrap_records.append(
            key_update_record(wrap_secrets[-1], epoch, 0, request_update=0))
        wrap_secrets.append(ratchet_secret(wrap_secrets[-1]))
    telemetry = b"first-telemetry-after-four-rotations"
    wrap_records.append(
        seal_record(wrap_secrets[4], 4, 0, telemetry, 23))
    status, v = post_audit("smoke-wrap-rotation", wrap_secret.hex(),
                           wrap_records, initial_epoch=0)
    ok = status == 200 and v.get("ok") is True
    check("wrap: submission accepted without violations", ok,
          f"{status} {json.dumps(v)[:300]}" if not ok else "")
    if status == 200:
        recs = v["records"]
        check("wrap: all four KeyUpdates processed",
              all(r["key_update"] == "processed" and r["auth"] == "ok"
                  for r in recs[:4]))
        check("wrap: current epoch advanced exactly four times",
              v["final_state"]["current_epoch"] == 4
              and v["final_state"]["ratchets"] == 4)
        last = recs[4]
        check("wrap: new record attributed to the newest epoch",
              last["epoch"] == 4 and last["seq"] == 0,
              json.dumps({"epoch": last["epoch"], "seq": last["seq"]}))
        check("wrap: new record adjudicated new and authenticated",
              last["replay"] == "new" and last["auth"] == "ok"
              and last["inner_type"] == "application_data")
        check("wrap: application data digest returned",
              last["app_data_sha256"] == hashlib.sha256(telemetry).hexdigest())
        check("wrap: newest epoch window advanced for seq 0",
              last["window_after"]["epoch"] == 4
              and last["window_after"]["highest"] == 0
              and last["window_after"]["bitmap"] == "0000000000000001")
        epochs = {e["epoch"]: e for e in v["final_state"]["epochs"]}
        check("wrap: initial epoch window untouched by the new record",
              epochs[0]["highest"] == 0 and epochs[0]["bitmap"]
              == "0000000000000001")
    status, v2 = http("GET", "/api/audit/smoke-wrap-rotation")
    check("wrap: frozen verdict reopens with correct attribution",
          status == 200 and v2.get("records", [{}])[-1].get("epoch") == 4
          and v2.get("records", [{}])[-1].get("replay") == "new",
          f"status {status}")

    # A genuine replay carrying the same low label but encrypted under the
    # initial epoch's keys must stay attributed to that epoch as a duplicate.
    historical_replay = seal_record(wrap_secrets[0], 0, 0,
                                    b"epoch-zero-capture", 23)
    status, v = post_audit("smoke-wrap-replay", wrap_secret.hex(),
                           wrap_records + [historical_replay], initial_epoch=0)
    if status != 200:
        check("wrap-replay: submission accepted", False, f"status {status}")
    else:
        recs = v["records"]
        check("wrap-replay: same-label historical capture stays in epoch 0",
              recs[5]["epoch"] == 0 and recs[5]["replay"] == "duplicate"
              and recs[5]["auth"] == "skipped")
        epochs = {e["epoch"]: e for e in v["final_state"]["epochs"]}
        check("wrap-replay: neither epoch window moved",
              epochs[0]["highest"] == 0 and epochs[4]["highest"] == 0
              and epochs[0]["bitmap"] == "0000000000000001"
              and epochs[4]["bitmap"] == "0000000000000001")
        check("wrap-replay: duplicates are not violations", v.get("ok") is True)


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

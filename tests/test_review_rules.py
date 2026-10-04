"""Review-rule tests: replay window adjudication, sequence recovery,
KeyUpdate ratchet discipline, and violation offsets."""
import hashlib
import unittest

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from server.crypto import derive_record_keys, ratchet_secret, record_nonce
from server.dtls import (
    Receiver,
    ReplayWindow,
    Violation,
    parse_unified_header,
    reconstruct_seq,
    run_audit,
)
from server.encode import key_update_record, seal_record

SECRET3 = bytes(range(32))  # arbitrary 32-byte initial traffic secret


def appdata(secret, epoch, seq, payload=b"x", **kw):
    return seal_record(secret, epoch, seq, payload, 23, **kw)


class WindowRuleTests(unittest.TestCase):
    def test_first_record_is_new(self):
        w = ReplayWindow()
        self.assertEqual(w.classify(0), "new")
        w.advance(0)
        self.assertEqual((w.highest, w.bitmap), (0, 1))

    def test_exact_replay_is_duplicate(self):
        w = ReplayWindow()
        w.advance(5)
        self.assertEqual(w.classify(5), "duplicate")

    def test_unseen_inside_window_is_new(self):
        w = ReplayWindow()
        w.advance(5)
        self.assertEqual(w.classify(4), "new")
        w.advance(4)
        self.assertEqual(w.classify(4), "duplicate")

    def test_boundary_offset_63_new_offset_64_too_old(self):
        w = ReplayWindow()
        w.advance(64)
        self.assertEqual(w.classify(1), "new")       # offset 63, inside window
        self.assertEqual(w.classify(0), "too_old")   # offset 64, expired
        w.advance(1)
        self.assertEqual(w.classify(1), "duplicate")

    def test_large_jump_resets_bitmap(self):
        w = ReplayWindow()
        w.advance(0)
        w.advance(3)
        w.advance(200)  # shift >= 64
        self.assertEqual((w.highest, w.bitmap), (200, 1))
        self.assertEqual(w.classify(199), "new")
        self.assertEqual(w.classify(136), "too_old")

    def test_duplicate_does_not_change_window(self):
        w = ReplayWindow()
        w.advance(7)
        before = (w.highest, w.bitmap)
        self.assertEqual(w.classify(7), "duplicate")
        self.assertEqual((w.highest, w.bitmap), before)


class SequenceRecoveryTests(unittest.TestCase):
    def test_8bit_wraparound(self):
        self.assertEqual(reconstruct_seq(255, 0, 8), 256)

    def test_8bit_late_record(self):
        self.assertEqual(reconstruct_seq(260, 2, 8), 258)

    def test_16bit_wraparound(self):
        self.assertEqual(reconstruct_seq(65535, 0, 16), 65536)

    def test_first_record(self):
        self.assertEqual(reconstruct_seq(-1, 5, 8), 5)
        self.assertEqual(reconstruct_seq(-1, 0, 16), 0)

    def test_reconstructed_seq_matches_header(self):
        rx = Receiver(3, SECRET3)
        rx.process_record(appdata(SECRET3, 3, 300, b"a"))
        row = rx.process_record(appdata(SECRET3, 3, 301, b"b"))
        self.assertEqual(row["seq"], 301)


class HeaderRuleTests(unittest.TestCase):
    def test_fixed_bits_enforced(self):
        with self.assertRaises(Violation) as ctx:
            parse_unified_header(b"\x40\x00")
        self.assertEqual((ctx.exception.kind, ctx.exception.offset), ("state", 0))

    def test_cid_bit_rejected(self):
        with self.assertRaises(Violation) as ctx:
            parse_unified_header(b"\x30\x00")  # 001 1 .... -> CID present
        self.assertEqual((ctx.exception.kind, ctx.exception.offset), ("state", 0))

    def test_truncated_sequence_number(self):
        with self.assertRaises(Violation) as ctx:
            parse_unified_header(b"\x2c\x00")  # S=1 needs 2 seq bytes
        self.assertEqual((ctx.exception.kind, ctx.exception.offset), ("truncation", 1))

    def test_truncated_length_field(self):
        with self.assertRaises(Violation) as ctx:
            parse_unified_header(b"\x2c\x00\x00\x01")  # L=1, only 1 length byte
        self.assertEqual((ctx.exception.kind, ctx.exception.offset), ("truncation", 3))

    def test_declared_length_mismatch(self):
        rec = bytearray(appdata(SECRET3, 3, 0, b"payload"))
        declared = int.from_bytes(rec[3:5], "big")  # S=1: length field at offset 3
        rec[3:5] = (declared - 1).to_bytes(2, "big")
        with self.assertRaises(Violation) as ctx:
            parse_unified_header(bytes(rec))
        self.assertEqual((ctx.exception.kind, ctx.exception.offset), ("length", 3))

    def test_empty_record(self):
        with self.assertRaises(Violation) as ctx:
            parse_unified_header(b"")
        self.assertEqual((ctx.exception.kind, ctx.exception.offset), ("truncation", 0))


class ReceiverRuleTests(unittest.TestCase):
    def test_roundtrip_appdata_and_digest(self):
        rx = Receiver(3, SECRET3)
        row = rx.process_record(appdata(SECRET3, 3, 0, b"hello"))
        self.assertEqual(row["auth"], "ok")
        self.assertEqual(row["replay"], "new")
        self.assertEqual(row["epoch"], 3)
        self.assertEqual(row["seq"], 0)
        self.assertEqual(row["inner_type"], "application_data")
        self.assertEqual(row["app_data_sha256"],
                         hashlib.sha256(b"hello").hexdigest())

    def test_8bit_and_no_length_headers(self):
        rx = Receiver(3, SECRET3)
        row = rx.process_record(appdata(SECRET3, 3, 7, b"a", s_bit=False, l_bit=False))
        self.assertEqual((row["auth"], row["seq"]), ("ok", 7))
        self.assertIsNone(row["header"]["declared_length"])

    def test_failed_auth_never_advances_window(self):
        rx = Receiver(3, SECRET3)
        bad = bytearray(appdata(SECRET3, 3, 0, b"hello"))
        bad[-1] ^= 1
        row = rx.process_record(bytes(bad))
        self.assertEqual(row["violation"]["kind"], "authentication")
        self.assertEqual(row["violation"]["offset"], len(bad) - 16)
        self.assertEqual(rx.current.window.highest, -1)
        self.assertEqual(row["window_before"], row["window_after"])
        # the genuine record is still accepted afterwards
        row2 = rx.process_record(appdata(SECRET3, 3, 0, b"hello"))
        self.assertEqual((row2["replay"], row2["auth"]), ("new", "ok"))

    def test_duplicate_dropped_before_decryption(self):
        rx = Receiver(3, SECRET3)
        rec = appdata(SECRET3, 3, 0, b"hello")
        rx.process_record(rec)
        row = rx.process_record(rec)
        self.assertEqual(row["replay"], "duplicate")
        self.assertEqual(row["auth"], "skipped")
        self.assertEqual(rx.current.window.highest, 0)

    def test_expired_sequence_is_too_old(self):
        rx = Receiver(3, SECRET3)
        rx.process_record(appdata(SECRET3, 3, 64, b"hi"))
        row = rx.process_record(appdata(SECRET3, 3, 0, b"hi"))
        self.assertEqual(row["replay"], "too_old")
        self.assertEqual(row["auth"], "skipped")

    def test_key_update_ratchets_and_resets_window(self):
        rx = Receiver(3, SECRET3)
        rx.process_record(appdata(SECRET3, 3, 0, b"a"))
        row = rx.process_record(key_update_record(SECRET3, 3, 1, request_update=0))
        self.assertEqual(row["key_update"], "processed")
        self.assertEqual(row["auth"], "ok")
        self.assertEqual(rx.current.epoch, 4)
        self.assertEqual(rx.ratchets, 1)
        self.assertEqual(rx.current.window.highest, -1)  # window reset
        self.assertEqual(rx.previous.epoch, 3)           # old keys retained
        secret4 = ratchet_secret(SECRET3)
        row2 = rx.process_record(appdata(secret4, 4, 0, b"post"))
        self.assertEqual((row2["epoch"], row2["replay"], row2["auth"]),
                         (4, "new", "ok"))

    def test_forged_key_update_never_ratchets(self):
        rx = Receiver(3, SECRET3)
        forged = bytearray(key_update_record(SECRET3, 3, 0, request_update=1))
        forged[-1] ^= 0xFF  # corrupt the AEAD tag
        row = rx.process_record(bytes(forged))
        self.assertEqual(row["violation"]["kind"], "authentication")
        self.assertEqual(rx.current.epoch, 3)
        self.assertEqual(rx.ratchets, 0)
        self.assertIsNone(rx.previous)

    def test_duplicate_key_update_does_not_ratchet_twice(self):
        rx = Receiver(3, SECRET3)
        ku = key_update_record(SECRET3, 3, 0)
        rx.process_record(ku)
        row = rx.process_record(ku)  # replayed capture of the same KeyUpdate
        self.assertEqual(row["replay"], "duplicate")
        self.assertEqual(rx.current.epoch, 4)
        self.assertEqual(rx.ratchets, 1)

    def test_old_epoch_key_update_ignored(self):
        rx = Receiver(3, SECRET3)
        rx.process_record(key_update_record(SECRET3, 3, 0))  # -> epoch 4
        late = key_update_record(SECRET3, 3, 5)              # straggler in epoch 3
        row = rx.process_record(late)
        self.assertEqual(row["epoch"], 3)
        self.assertEqual(row["auth"], "ok")
        self.assertEqual(row["key_update"], "ignored_old_epoch")
        self.assertEqual(rx.current.epoch, 4)
        self.assertEqual(rx.ratchets, 1)

    def test_old_epoch_record_never_slides_current_window(self):
        rx = Receiver(3, SECRET3)
        rx.process_record(key_update_record(SECRET3, 3, 0))  # -> epoch 4
        before = rx.current.window.snapshot()
        row = rx.process_record(appdata(SECRET3, 3, 1, b"late"))
        self.assertEqual((row["epoch"], row["replay"]), (3, "new"))
        self.assertEqual(rx.current.window.snapshot(), before)
        self.assertEqual(rx.previous.window.highest, 1)  # own epoch window only

    def test_old_epoch_replay_still_detected(self):
        rx = Receiver(3, SECRET3)
        rec = appdata(SECRET3, 3, 0, b"a")
        rx.process_record(rec)
        rx.process_record(key_update_record(SECRET3, 3, 1))  # -> epoch 4
        row = rx.process_record(rec)  # replayed old-epoch capture
        self.assertEqual(row["replay"], "duplicate")


class EpochLabelWrapTests(unittest.TestCase):
    """After >= 4 ratchets the 2-bit epoch label repeats (e.g. epochs 0 and 4
    both carry E=00); the receiving epoch is then identified cryptographically.
    """

    def _rotate(self, n, initial_epoch=0, secret=SECRET3):
        secrets = [secret]
        records = []
        for epoch in range(initial_epoch, initial_epoch + n):
            records.append(key_update_record(secrets[-1], epoch, 0))
            secrets.append(ratchet_secret(secrets[-1]))
        return secrets, records

    def test_four_ratchets_then_seq_zero_belongs_to_newest_epoch(self):
        secrets, records = self._rotate(4)
        payload = b"first-telemetry-after-rotation"
        records.append(appdata(secrets[4], 4, 0, payload))
        verdict = run_audit(0, SECRET3, records)
        self.assertTrue(verdict["ok"], verdict.get("first_violation"))
        last = verdict["records"][-1]
        self.assertEqual(last["epoch"], 4)
        self.assertEqual(last["seq"], 0)
        self.assertEqual(last["replay"], "new")
        self.assertEqual(last["auth"], "ok")
        self.assertEqual(last["inner_type"], "application_data")
        self.assertEqual(last["app_data_sha256"],
                         hashlib.sha256(payload).hexdigest())
        window = {e["epoch"]: e for e in verdict["final_state"]["epochs"]}
        self.assertEqual((window[4]["highest"], window[4]["bitmap"]), (0, "0000000000000001"))
        self.assertEqual(verdict["final_state"]["current_epoch"], 4)
        self.assertEqual(verdict["final_state"]["ratchets"], 4)

    def test_wrapped_label_record_is_not_misread_as_old_epoch_duplicate(self):
        secrets, records = self._rotate(4)
        # epoch 0 saw seq 0 (its KeyUpdate); the epoch-4 seq 0 record shares
        # the same truncated label E=00 and truncated seq 0, yet must arrive.
        records.append(appdata(secrets[4], 4, 0, b"new"))
        rows = run_audit(0, SECRET3, records)["records"]
        self.assertNotEqual(rows[-1]["replay"], "duplicate")
        self.assertIsNotNone(rows[-1]["auth"], "ok")

    def test_same_label_historical_replay_stays_in_old_epoch(self):
        secrets, records = self._rotate(4)
        historical = appdata(secrets[0], 0, 5, b"late-capture")  # new, epoch 0
        records.append(historical)
        verdict = run_audit(0, SECRET3, records)
        self.assertEqual(verdict["records"][-1]["epoch"], 0)
        # replaying the very same capture after the label has wrapped
        verdict = run_audit(0, SECRET3, records + [historical])
        last = verdict["records"][-1]
        self.assertEqual((last["epoch"], last["replay"], last["auth"]),
                         (0, "duplicate", "skipped"))

    def test_same_label_old_epoch_straggler_updates_only_its_own_window(self):
        secrets, records = self._rotate(4)
        records.append(appdata(secrets[4], 4, 0, b"e4"))   # newest epoch first
        verdict = run_audit(0, SECRET3,
                            records + [appdata(secrets[0], 0, 9, b"e0-late")])
        last = verdict["records"][-1]
        self.assertEqual((last["epoch"], last["replay"], last["auth"]),
                         (0, "new", "ok"))
        window = {e["epoch"]: e for e in verdict["final_state"]["epochs"]}
        self.assertEqual(window[0]["highest"], 9)
        self.assertEqual(window[4]["highest"], 0)

    def test_same_label_old_epoch_key_update_ignored(self):
        secrets, records = self._rotate(4)
        late_ku = key_update_record(secrets[0], 0, 3)
        verdict = run_audit(0, SECRET3, records + [late_ku])
        last = verdict["records"][-1]
        self.assertEqual(last["epoch"], 0)
        self.assertEqual(last["key_update"], "ignored_old_epoch")
        self.assertEqual(verdict["final_state"]["current_epoch"], 4)
        self.assertEqual(verdict["final_state"]["ratchets"], 4)

    def test_authentication_failure_on_ambiguous_label_advances_nothing(self):
        secrets, records = self._rotate(4)
        forged = bytearray(appdata(secrets[4], 4, 0, b"e4"))
        forged[-1] ^= 0x01
        verdict = run_audit(0, SECRET3, records + [bytes(forged)])
        last = verdict["records"][-1]
        self.assertEqual(last["violation"]["kind"], "authentication")
        self.assertEqual(last["violation"]["offset"], len(forged) - 16)
        self.assertEqual(last["window_before"], last["window_after"])
        self.assertEqual(verdict["final_state"]["current_epoch"], 4)
        # the genuine record still arrives afterwards
        verdict = run_audit(0, SECRET3,
                            records + [appdata(secrets[4], 4, 0, b"e4")])
        self.assertTrue(verdict["ok"])

    def test_forged_key_update_after_wrap_never_ratchets(self):
        secrets, records = self._rotate(4)
        forged = bytearray(key_update_record(secrets[4], 4, 0))
        forged[-1] ^= 0xAA
        verdict = run_audit(0, SECRET3, records + [bytes(forged)])
        self.assertEqual(verdict["records"][-1]["violation"]["kind"],
                         "authentication")
        self.assertEqual(verdict["final_state"]["current_epoch"], 4)
        self.assertEqual(verdict["final_state"]["ratchets"], 4)

    def test_too_old_record_under_wrapped_label(self):
        secrets, records = self._rotate(4)
        records.append(appdata(secrets[4], 4, 0, b"e4-0"))
        records.append(appdata(secrets[4], 4, 64, b"e4-64"))
        replay0 = appdata(secrets[4], 4, 0, b"e4-0")
        verdict = run_audit(0, SECRET3, records + [replay0])
        self.assertEqual((verdict["records"][-1]["epoch"],
                          verdict["records"][-1]["replay"]), (4, "too_old"))

    def test_longer_rotation_twice_wrapped_label(self):
        secrets, records = self._rotate(8)  # epoch 8 shares E=00 with 0 and 4
        records.append(appdata(secrets[8], 8, 0, b"e8"))
        verdict = run_audit(0, SECRET3, records)
        self.assertTrue(verdict["ok"])
        last = verdict["records"][-1]
        self.assertEqual((last["epoch"], last["replay"], last["auth"]),
                         (8, "new", "ok"))
        self.assertEqual(verdict["final_state"]["current_epoch"], 8)
        self.assertEqual(verdict["final_state"]["ratchets"], 8)

    def test_four_ratchets_from_nonzero_initial_epoch(self):
        # initial epoch 3 -> current epoch 7; both carry the label E=11.
        secrets, records = self._rotate(4, initial_epoch=3)
        records.append(appdata(secrets[4], 7, 0, b"e7"))
        verdict = run_audit(3, SECRET3, records)
        self.assertTrue(verdict["ok"])
        last = verdict["records"][-1]
        self.assertEqual((last["epoch"], last["replay"], last["auth"]),
                         (7, "new", "ok"))

    def test_future_epoch_rejected_as_state_violation(self):
        rx = Receiver(3, SECRET3)
        secret4 = ratchet_secret(SECRET3)
        row = rx.process_record(appdata(secret4, 4, 0, b"x"))
        self.assertEqual(row["violation"]["kind"], "state")
        self.assertEqual(row["violation"]["offset"], 0)
        self.assertEqual(rx.ratchets, 0)

    def test_short_ciphertext_is_length_violation(self):
        rx = Receiver(3, SECRET3)
        rec = bytes([0x2B, 0x00, 0x00]) + b"\x00" * 5  # S=1, L=0, E=3, 5 < 16
        row = rx.process_record(rec)
        self.assertEqual(row["violation"]["kind"], "length")
        self.assertEqual(row["violation"]["offset"], 3)

    def test_empty_inner_plaintext_is_length_violation(self):
        key, iv = derive_record_keys(SECRET3)
        hdr = bytes([0x2F, 0x00, 0x00, 0x00, 0x10])  # S=1, L=1, E=3, len=16
        ct = AESGCM(key).encrypt(record_nonce(iv, 0), b"", hdr)
        row = Receiver(3, SECRET3).process_record(hdr + ct)
        self.assertEqual(row["violation"]["kind"], "length")

    def test_malformed_key_update_body_no_ratchet(self):
        from server.encode import handshake_message
        bad_hs = handshake_message(24, b"\x07\x08")  # invalid request_update
        rec = seal_record(SECRET3, 3, 0, bad_hs, 22)
        rx = Receiver(3, SECRET3)
        row = rx.process_record(rec)
        self.assertEqual(row["violation"]["kind"], "state")
        self.assertEqual(rx.ratchets, 0)
        # record was authenticated, so its sequence is marked received
        self.assertEqual(rx.current.window.highest, 0)

    def test_inner_type_unwrapped_only_after_auth(self):
        # a record with a valid header but garbage ciphertext must not
        # reveal any inner content type
        rx = Receiver(3, SECRET3)
        rec = bytes([0x2F, 0x00, 0x00, 0x00, 0x14]) + b"\xaa" * 20
        row = rx.process_record(rec)
        self.assertEqual(row["violation"]["kind"], "authentication")
        self.assertIsNone(row["inner_type"])


if __name__ == "__main__":
    unittest.main()

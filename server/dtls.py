"""DTLS 1.3 (RFC 9147) receive-path auditor.

Scope: unified record header without CID, TLS_AES_128_GCM_SHA256, single
direction. The full sequence number is recovered from the truncated value in
the transmitted header, record keys/IVs are derived from the traffic secret
with the TLS 1.3 HKDF labels, and the inner content type is unwrapped only
after AEAD authentication succeeds.

Receive state is kept per epoch (highest sequence number + 64-bit bitmap) and
adjudicates every record as new / duplicate / too_old. A legal KeyUpdate is
authenticated first and only then ratchets the secret into the next epoch and
resets the receive window. Failed, duplicate, or old-epoch records never
advance secrets or the current window.
"""
from __future__ import annotations

import hashlib

from .crypto import TAG_LEN, aead_open, derive_record_keys, ratchet_secret

# Content types (RFC 8446 §5, RFC 9147 §4.5.2).
CT_ALERT = 21
CT_HANDSHAKE = 22
CT_APPDATA = 23
CT_ACK = 25
CT_NAMES = {
    CT_ALERT: "alert",
    CT_HANDSHAKE: "handshake",
    CT_APPDATA: "application_data",
    CT_ACK: "ack",
}

# Handshake message types (RFC 8446 §4, RFC 9147 §5).
HS_KEY_UPDATE = 24
HS_NAMES = {
    0: "hello_request",
    1: "client_hello",
    2: "server_hello",
    4: "new_session_ticket",
    5: "end_of_early_data",
    8: "encrypted_extensions",
    11: "certificate",
    13: "certificate_request",
    15: "certificate_verify",
    20: "finished",
    HS_KEY_UPDATE: "key_update",
}

WINDOW_BITS = 64
MAX_EPOCH = 0xFFFF

KIND_TRUNCATION = "truncation"
KIND_LENGTH = "length"
KIND_AUTHENTICATION = "authentication"
KIND_STATE = "state"


class Violation(Exception):
    """A record-level violation; offset is the raw byte offset in the record."""

    def __init__(self, kind: str, offset: int, message: str):
        super().__init__(message)
        self.kind = kind
        self.offset = offset
        self.message = message

    def as_dict(self) -> dict:
        return {"kind": self.kind, "offset": self.offset, "message": self.message}


class UnifiedHeader:
    """RFC 9147 §4.1 unified header (no-CID form): 001C SLEE."""

    __slots__ = (
        "s_bit",
        "l_bit",
        "epoch_bits",
        "seq_truncated",
        "seq_nbits",
        "declared_length",
        "header_len",
    )

    def __init__(self, s_bit, l_bit, epoch_bits, seq_truncated, seq_nbits,
                 declared_length, header_len):
        self.s_bit = s_bit
        self.l_bit = l_bit
        self.epoch_bits = epoch_bits
        self.seq_truncated = seq_truncated
        self.seq_nbits = seq_nbits
        self.declared_length = declared_length
        self.header_len = header_len


def parse_unified_header(data: bytes) -> UnifiedHeader:
    if len(data) < 1:
        raise Violation(KIND_TRUNCATION, 0, "empty record: no header byte")
    b0 = data[0]
    if (b0 >> 5) != 0b001:
        raise Violation(
            KIND_STATE, 0,
            f"fixed header bits {(b0 >> 5):03b} != 001: not a DTLS 1.3 unified header",
        )
    if b0 & 0x10:
        raise Violation(KIND_STATE, 0, "CID bit set: only no-CID records are in scope")
    s_bit = bool(b0 & 0x08)
    l_bit = bool(b0 & 0x04)
    epoch_bits = b0 & 0x03
    seq_len = 2 if s_bit else 1
    seq_nbits = 16 if s_bit else 8
    if len(data) < 1 + seq_len:
        raise Violation(
            KIND_TRUNCATION, 1,
            f"record ends inside the {seq_len}-byte sequence number field",
        )
    seq_truncated = int.from_bytes(data[1:1 + seq_len], "big")
    header_len = 1 + seq_len
    declared = None
    if l_bit:
        if len(data) < header_len + 2:
            raise Violation(
                KIND_TRUNCATION, header_len,
                "record ends inside the 2-byte length field",
            )
        declared = int.from_bytes(data[header_len:header_len + 2], "big")
        length_offset = header_len
        header_len += 2
        remaining = len(data) - header_len
        if declared > remaining:
            raise Violation(
                KIND_TRUNCATION, len(data),
                f"declared length {declared} but only {remaining} byte(s) follow",
            )
        if declared < remaining:
            raise Violation(
                KIND_LENGTH, length_offset,
                f"declared length {declared} but {remaining} byte(s) follow",
            )
    return UnifiedHeader(s_bit, l_bit, epoch_bits, seq_truncated, seq_nbits,
                         declared, header_len)


def reconstruct_seq(highest: int, truncated: int, nbits: int) -> int:
    """Recover the full sequence number from the truncated header value.

    RFC 9147 §4.2.2, using the RFC 9000 §A.3 algorithm relative to the
    highest sequence number received so far in this epoch.
    """
    expected = highest + 1
    window = 1 << nbits
    half = window >> 1
    mask = window - 1
    candidate = (expected & ~mask) | truncated
    if candidate <= expected - half and candidate < (1 << 64) - window:
        return candidate + window
    if candidate > expected + half and candidate >= window:
        return candidate - window
    return candidate


class ReplayWindow:
    """Per-epoch anti-replay state: highest sequence number + 64-bit bitmap.

    Bit i of the bitmap corresponds to sequence number (highest - i);
    bit 0 therefore always tracks the highest sequence number itself.
    """

    def __init__(self):
        self.highest = -1
        self.bitmap = 0

    def classify(self, seq: int) -> str:
        """Adjudicate a sequence number without mutating the window."""
        if seq > self.highest:
            return "new"
        offset = self.highest - seq
        if offset >= WINDOW_BITS:
            return "too_old"
        if (self.bitmap >> offset) & 1:
            return "duplicate"
        return "new"

    def advance(self, seq: int) -> None:
        """Mark a sequence number as received (only after authentication)."""
        if self.highest < 0:
            self.highest = seq
            self.bitmap = 1
            return
        if seq > self.highest:
            shift = seq - self.highest
            self.bitmap = ((self.bitmap << shift) | 1) & ((1 << WINDOW_BITS) - 1) \
                if shift < WINDOW_BITS else 1
            self.highest = seq
        else:
            self.bitmap |= 1 << (self.highest - seq)

    def snapshot(self, epoch: int | None = None) -> dict:
        snap = {"highest": self.highest, "bitmap": f"{self.bitmap:016x}"}
        if epoch is not None:
            return {"epoch": epoch, **snap}
        return snap


class EpochState:
    """Keys and replay window for one epoch."""

    def __init__(self, epoch: int, traffic_secret: bytes):
        self.epoch = epoch
        self.secret = traffic_secret
        self.key, self.iv = derive_record_keys(traffic_secret)
        self.window = ReplayWindow()


def parse_handshake_messages(content: bytes, offset_base: int) -> list[tuple[int, bytes, int]]:
    """Split DTLS handshake bodies; returns (msg_type, body, content_offset)."""
    messages = []
    pos = 0
    while pos < len(content):
        if len(content) - pos < 12:
            raise Violation(
                KIND_STATE, offset_base + pos,
                "trailing bytes too short for a DTLS handshake header",
            )
        msg_type = content[pos]
        length = int.from_bytes(content[pos + 1:pos + 4], "big")
        frag_off = int.from_bytes(content[pos + 6:pos + 9], "big")
        frag_len = int.from_bytes(content[pos + 9:pos + 12], "big")
        if frag_off != 0 or frag_len != length:
            raise Violation(
                KIND_STATE, offset_base + pos,
                "fragmented post-handshake message is out of scope",
            )
        if len(content) - pos - 12 < length:
            raise Violation(
                KIND_STATE, offset_base + pos,
                "handshake message body is truncated",
            )
        messages.append((msg_type, content[pos + 12:pos + 12 + length], pos))
        pos += 12 + length
    return messages


class Receiver:
    """Single-direction DTLS 1.3 receive state machine."""

    def __init__(self, initial_epoch: int, traffic_secret: bytes):
        if not 0 <= initial_epoch <= MAX_EPOCH:
            raise ValueError("initial epoch out of range")
        self.current = EpochState(initial_epoch, traffic_secret)
        self.previous: EpochState | None = None
        self.epoch_history: list[EpochState] = [self.current]
        self.ratchets = 0

    def _epoch_for_bits(self, bits: int) -> EpochState | None:
        for state in self.epoch_history:
            if bits == (state.epoch & 0x03):
                return state
        if bits == (self.current.epoch & 0x03):
            return self.current
        if self.previous is not None and bits == (self.previous.epoch & 0x03):
            return self.previous
        return None

    def _ratchet(self) -> None:
        """Derive the next epoch's keys and reset its receive window."""
        next_state = EpochState(self.current.epoch + 1, ratchet_secret(self.current.secret))
        self.previous = self.current
        self.current = next_state
        self.epoch_history.append(next_state)
        self.ratchets += 1

    def process_record(self, data: bytes) -> dict:
        row = {
            "raw_length": len(data),
            "header": None,
            "epoch": None,
            "seq": None,
            "replay": None,
            "auth": None,
            "inner_type": None,
            "inner_length": None,
            "app_data_sha256": None,
            "handshake_messages": None,
            "key_update": None,
            "window_before": None,
            "window_after": None,
            "violation": None,
        }
        state: EpochState | None = None
        try:
            hdr = parse_unified_header(data)
            row["header"] = {
                "s_bit": hdr.s_bit,
                "l_bit": hdr.l_bit,
                "epoch_bits": hdr.epoch_bits,
                "seq_truncated": hdr.seq_truncated,
                "seq_nbits": hdr.seq_nbits,
                "declared_length": hdr.declared_length,
                "header_length": hdr.header_len,
            }
            state = self._epoch_for_bits(hdr.epoch_bits)
            if state is None:
                raise Violation(
                    KIND_STATE, 0,
                    f"epoch bits {hdr.epoch_bits} match neither current epoch "
                    f"{self.current.epoch} nor a retained previous epoch",
                )
            row["epoch"] = state.epoch
            seq = reconstruct_seq(state.window.highest, hdr.seq_truncated, hdr.seq_nbits)
            row["seq"] = seq
            replay = state.window.classify(seq)
            row["replay"] = replay
            row["window_before"] = state.window.snapshot(state.epoch)
            if replay != "new":
                # Duplicate / expired records are dropped before decryption and
                # never advance secrets or windows.
                row["auth"] = "skipped"
                return row
            ciphertext = data[hdr.header_len:]
            if len(ciphertext) < TAG_LEN:
                raise Violation(
                    KIND_LENGTH, hdr.header_len,
                    f"ciphertext of {len(ciphertext)} byte(s) cannot hold a "
                    f"16-byte AEAD tag",
                )
            plaintext = aead_open(state.key, state.iv, seq,
                                  data[:hdr.header_len], ciphertext)
            if plaintext is None:
                raise Violation(KIND_AUTHENTICATION, len(data) - TAG_LEN,
                                "AEAD tag verification failed")
            row["auth"] = "ok"
            # Authenticated: mark the replay window, then unwrap the inner type.
            state.window.advance(seq)
            row["window_after"] = state.window.snapshot(state.epoch)
            self._unwrap_inner(row, state, hdr, plaintext)
        except Violation as v:
            row["violation"] = v.as_dict()
        finally:
            if (state is not None and row["window_before"] is not None
                    and row["window_after"] is None):
                row["window_after"] = state.window.snapshot(state.epoch)
        return row

    def _unwrap_inner(self, row: dict, state: EpochState,
                      hdr: UnifiedHeader, plaintext: bytes) -> None:
        """Unwrap DTLSInnerPlaintext; only called after AEAD authentication."""
        if not plaintext:
            raise Violation(KIND_LENGTH, hdr.header_len,
                            "inner plaintext is empty: no content type byte")
        end = len(plaintext) - 1
        while end > 0 and plaintext[end] == 0:
            end -= 1
        if plaintext[end] == 0:
            raise Violation(KIND_LENGTH, hdr.header_len,
                            "inner plaintext is all padding: no content type byte")
        real_type = plaintext[end]
        content = plaintext[:end]
        row["inner_type"] = CT_NAMES.get(real_type, f"unknown({real_type})")
        row["inner_length"] = len(content)
        if real_type == CT_APPDATA:
            row["app_data_sha256"] = hashlib.sha256(content).hexdigest()
        elif real_type == CT_HANDSHAKE:
            messages = parse_handshake_messages(content, hdr.header_len)
            row["handshake_messages"] = [
                {"type": HS_NAMES.get(t, f"unknown({t})"), "length": len(b)}
                for t, b, _ in messages
            ]
            key_updates = [(b, p) for t, b, p in messages if t == HS_KEY_UPDATE]
            for body, pos in key_updates:
                if len(body) != 1 or body[0] not in (0, 1):
                    raise Violation(KIND_STATE, hdr.header_len + pos,
                                    "malformed KeyUpdate body")
            if key_updates:
                if state is self.current:
                    if self.current.epoch + len(key_updates) - 1 >= MAX_EPOCH:
                        raise Violation(KIND_STATE, hdr.header_len,
                                        "epoch overflow on KeyUpdate")
                    # Legal KeyUpdate: authenticated above, so now ratchet the
                    # secret into the next epoch and reset the receive window.
                    for _ in key_updates:
                        self._ratchet()
                    row["key_update"] = "processed"
                else:
                    # Old-epoch records never advance secrets or windows.
                    row["key_update"] = "ignored_old_epoch"

    def final_state(self) -> dict:
        epochs = [
            {
                "role": (
                    "current" if state is self.current else
                    "previous" if state is self.previous else "retained"
                ),
                **state.window.snapshot(state.epoch),
            }
            for state in self.epoch_history
        ]
        return {
            "current_epoch": self.current.epoch,
            "ratchets": self.ratchets,
            "epochs": epochs,
        }


def run_audit(initial_epoch: int, traffic_secret: bytes,
              record_blobs: list[bytes]) -> dict:
    """Adjudicate a captured record sequence and produce the frozen verdict."""
    receiver = Receiver(initial_epoch, traffic_secret)
    rows = []
    first_violation = None
    for index, blob in enumerate(record_blobs):
        row = receiver.process_record(blob)
        row["index"] = index
        rows.append(row)
        if row["violation"] is not None and first_violation is None:
            first_violation = {"record_index": index, **row["violation"]}
    return {
        "ok": first_violation is None,
        "first_violation": first_violation,
        "records": rows,
        "final_state": receiver.final_state(),
    }

"""DTLS 1.3 record encoder — the sender side.

Used by the review-rule tests and by the verify container to manufacture
well-formed (or deliberately corrupted) captures. The audited receive path
in server.dtls never calls into this module.
"""
from __future__ import annotations

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .crypto import TAG_LEN, derive_record_keys, record_nonce
from .dtls import CT_HANDSHAKE, HS_KEY_UPDATE


def seal_record(traffic_secret: bytes, epoch: int, seq: int, content: bytes,
                content_type: int, *, s_bit: bool = True, l_bit: bool = True,
                zero_pad: int = 0) -> bytes:
    """Build a unified-header record: header || AEAD(content || type || pad)."""
    key, iv = derive_record_keys(traffic_secret)
    b0 = 0x20 | (0x08 if s_bit else 0) | (0x04 if l_bit else 0) | (epoch & 0x03)
    seq_len = 2 if s_bit else 1
    header = bytes([b0]) + (seq & ((1 << (8 * seq_len)) - 1)).to_bytes(seq_len, "big")
    inner = content + bytes([content_type]) + b"\x00" * zero_pad
    if l_bit:
        header += (len(inner) + TAG_LEN).to_bytes(2, "big")
    return header + AESGCM(key).encrypt(record_nonce(iv, seq), inner, header)


def handshake_message(msg_type: int, body: bytes, message_seq: int = 0) -> bytes:
    """Unfragmented DTLS handshake message (12-byte header)."""
    return (
        bytes([msg_type])
        + len(body).to_bytes(3, "big")
        + message_seq.to_bytes(2, "big")
        + (0).to_bytes(3, "big")
        + len(body).to_bytes(3, "big")
        + body
    )


def key_update_record(traffic_secret: bytes, epoch: int, seq: int,
                      request_update: int = 0, message_seq: int = 0,
                      **kwargs) -> bytes:
    """A handshake record carrying a KeyUpdate message."""
    hs = handshake_message(HS_KEY_UPDATE, bytes([request_update]), message_seq)
    return seal_record(traffic_secret, epoch, seq, hs, CT_HANDSHAKE, **kwargs)

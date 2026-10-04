"""TLS 1.3 / DTLS 1.3 key schedule primitives (RFC 8446 §7, RFC 9147 §4).

Scope is fixed to TLS_AES_128_GCM_SHA256: SHA-256 HKDF, 16-byte AEAD key,
12-byte static IV, 16-byte GCM tag.
"""
from __future__ import annotations

import hashlib
import hmac

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

HASH_LEN = 32
KEY_LEN = 16
IV_LEN = 12
TAG_LEN = 16


def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    """RFC 5869 HKDF-Extract with SHA-256."""
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    """RFC 5869 HKDF-Expand with SHA-256."""
    out = b""
    block = b""
    counter = 1
    while len(out) < length:
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha256).digest()
        out += block
        counter += 1
    return out[:length]


def hkdf_expand_label(secret: bytes, label: str, context: bytes, length: int) -> bytes:
    """RFC 8446 §7.1 HKDF-Expand-Label ("tls13 " prefix, as reused by DTLS 1.3)."""
    full_label = b"tls13 " + label.encode("ascii")
    hkdf_label = (
        length.to_bytes(2, "big")
        + bytes([len(full_label)])
        + full_label
        + bytes([len(context)])
        + context
    )
    return hkdf_expand(secret, hkdf_label, length)


def derive_record_keys(traffic_secret: bytes) -> tuple[bytes, bytes]:
    """RFC 8446 §7.3: (key, iv) from a traffic secret via the "key"/"iv" labels."""
    if len(traffic_secret) != HASH_LEN:
        raise ValueError("traffic secret must be 32 bytes")
    key = hkdf_expand_label(traffic_secret, "key", b"", KEY_LEN)
    iv = hkdf_expand_label(traffic_secret, "iv", b"", IV_LEN)
    return key, iv


def ratchet_secret(traffic_secret: bytes) -> bytes:
    """RFC 8446 §7.2: next-generation traffic secret ("traffic upd")."""
    return hkdf_expand_label(traffic_secret, "traffic upd", b"", HASH_LEN)


def record_nonce(iv: bytes, seq: int) -> bytes:
    """RFC 8446 §5.3: static IV XOR the 64-bit record sequence number."""
    padded = b"\x00" * (IV_LEN - 8) + seq.to_bytes(8, "big")
    return bytes(a ^ b for a, b in zip(iv, padded))


def aead_open(key: bytes, iv: bytes, seq: int, aad: bytes, ciphertext: bytes) -> bytes | None:
    """AES-128-GCM open; returns None instead of raising on tag mismatch."""
    try:
        return AESGCM(key).decrypt(record_nonce(iv, seq), ciphertext, aad)
    except Exception:
        return None

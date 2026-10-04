"""Cryptographic primitive tests: RFC 5869 HKDF, AES-GCM, key schedule."""
import unittest

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from server.crypto import (
    derive_record_keys,
    hkdf_expand,
    hkdf_expand_label,
    hkdf_extract,
    ratchet_secret,
    record_nonce,
)


class HkdfVectorTests(unittest.TestCase):
    def test_rfc5869_test_case_1(self):
        ikm = bytes.fromhex("0b" * 22)
        salt = bytes.fromhex("000102030405060708090a0b0c")
        info = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9")
        prk = hkdf_extract(salt, ikm)
        self.assertEqual(
            prk.hex(),
            "077709362c2e32df0ddc3f0dc47bba63"
            "90b6c73bb50f9c3122ec844ad7c2b3e5",
        )
        okm = hkdf_expand(prk, info, 42)
        self.assertEqual(
            okm.hex(),
            "3cb25f25faacd57a90434f64d0362f2a"
            "2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
            "34007208d5b887185865",
        )


class AesGcmVectorTests(unittest.TestCase):
    def test_zero_key_zero_iv_empty_plaintext(self):
        # NIST GCM test vector: 128-bit zero key, 96-bit zero IV, empty PT
        tag = AESGCM(b"\x00" * 16).encrypt(b"\x00" * 12, b"", b"")
        self.assertEqual(tag.hex(), "58e2fccefa7e3061367f1d57a4e7455a")


class KeyScheduleTests(unittest.TestCase):
    def test_expand_label_encoding(self):
        # recompute the HkdfLabel structure independently
        secret = bytes(range(32))
        full_label = b"tls13 key"
        info = (16).to_bytes(2, "big") + bytes([len(full_label)]) + full_label + b"\x00"
        self.assertEqual(
            hkdf_expand_label(secret, "key", b"", 16),
            hkdf_expand(secret, info, 16),
        )

    def test_key_iv_lengths(self):
        key, iv = derive_record_keys(bytes(32))
        self.assertEqual((len(key), len(iv)), (16, 12))

    def test_secret_length_enforced(self):
        with self.assertRaises(ValueError):
            derive_record_keys(b"\x00" * 31)

    def test_ratchet_deterministic_and_distinct(self):
        s0 = bytes(range(32))
        s1 = ratchet_secret(s0)
        self.assertEqual(ratchet_secret(s0), s1)
        self.assertNotEqual(s0, s1)
        self.assertEqual(len(s1), 32)
        # chain: s2 derived from s1 differs from s1 derived keys
        self.assertNotEqual(ratchet_secret(s1), s1)

    def test_nonce_xor_layout(self):
        iv = bytes(range(12))
        nonce = record_nonce(iv, 0x0102)
        expect = bytearray(iv)
        expect[10] ^= 0x01
        expect[11] ^= 0x02
        self.assertEqual(nonce, bytes(expect))

    def test_nonce_zero_seq_equals_iv(self):
        iv = bytes(range(12))
        self.assertEqual(record_nonce(iv, 0), iv)


if __name__ == "__main__":
    unittest.main()

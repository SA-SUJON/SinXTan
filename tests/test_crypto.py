"""
Cryptographic Engine and Key Derivation Automated Tests for SinXTan.
"""

from __future__ import annotations

import os
import pytest

from app.core.crypto_engine import (
    AuthenticationError,
    CryptoEngine,
    DecryptionError,
)
from app.core.key_derivation import (
    KDFParams,
    KeyDerivationEngine,
)


def test_key_derivation_produces_32_byte_key() -> None:
    salt = KeyDerivationEngine.generate_salt()
    assert len(salt) == 32

    params = KDFParams(salt=salt, time_cost=1, memory_cost=16384, parallelism=1)
    enc_key, embed_key = KeyDerivationEngine.derive_keys("correct-password-123", salt, params)

    assert isinstance(enc_key, bytes)
    assert len(enc_key) == 32
    assert isinstance(embed_key, bytes)
    assert len(embed_key) == 32


def test_key_derivation_different_passwords_produce_different_keys() -> None:
    salt = KeyDerivationEngine.generate_salt()
    params = KDFParams(salt=salt, time_cost=1, memory_cost=16384, parallelism=1)

    k1, _ = KeyDerivationEngine.derive_keys("Password-A", salt, params)
    k2, _ = KeyDerivationEngine.derive_keys("Password-B", salt, params)

    assert k1 != k2


def test_key_derivation_same_password_and_salt_reproducible() -> None:
    salt = KeyDerivationEngine.generate_salt()
    params = KDFParams(salt=salt, time_cost=1, memory_cost=16384, parallelism=1)

    k1_enc, k1_emb = KeyDerivationEngine.derive_keys("IdenticalPassword", salt, params)
    k2_enc, k2_emb = KeyDerivationEngine.derive_keys("IdenticalPassword", salt, params)

    assert k1_enc == k2_enc
    assert k1_emb == k2_emb


def test_key_derivation_different_salts_produce_different_keys() -> None:
    salt1 = KeyDerivationEngine.generate_salt()
    salt2 = KeyDerivationEngine.generate_salt()
    assert salt1 != salt2

    params1 = KDFParams(salt=salt1, time_cost=1, memory_cost=16384, parallelism=1)
    params2 = KDFParams(salt=salt2, time_cost=1, memory_cost=16384, parallelism=1)

    k1, _ = KeyDerivationEngine.derive_keys("SamePassword", salt1, params1)
    k2, _ = KeyDerivationEngine.derive_keys("SamePassword", salt2, params2)

    assert k1 != k2


def test_domain_separation_produces_distinct_keys() -> None:
    salt = KeyDerivationEngine.generate_salt()
    params = KDFParams(salt=salt, time_cost=1, memory_cost=16384, parallelism=1)

    enc_key, embed_key = KeyDerivationEngine.derive_keys("MasterPassword", salt, params)
    assert enc_key != embed_key


def test_encrypt_decrypt_roundtrip() -> None:
    key = os.urandom(32)
    plaintext = b"Top secret classified content in stego container"

    nonce, ct, tag = CryptoEngine.encrypt(key, plaintext)
    assert len(nonce) == 12
    assert len(tag) == 16

    decrypted = CryptoEngine.decrypt(key, nonce, ct, tag)
    assert decrypted == plaintext


def test_wrong_key_fails_authentication() -> None:
    key1 = os.urandom(32)
    key2 = os.urandom(32)
    plaintext = b"Payload with authentic tag"

    nonce, ct, tag = CryptoEngine.encrypt(key1, plaintext)

    with pytest.raises(AuthenticationError):
        CryptoEngine.decrypt(key2, nonce, ct, tag)


def test_tampered_ciphertext_fails_authentication() -> None:
    key = os.urandom(32)
    plaintext = b"Critical configuration data"

    nonce, ct, tag = CryptoEngine.encrypt(key, plaintext)

    # Flip one byte in ciphertext
    tampered_ct = bytearray(ct)
    tampered_ct[0] ^= 0xFF

    with pytest.raises(AuthenticationError):
        CryptoEngine.decrypt(key, nonce, bytes(tampered_ct), tag)


def test_tampered_tag_fails_authentication() -> None:
    key = os.urandom(32)
    plaintext = b"Critical data"

    nonce, ct, tag = CryptoEngine.encrypt(key, plaintext)

    tampered_tag = bytearray(tag)
    tampered_tag[0] ^= 0x01

    with pytest.raises(AuthenticationError):
        CryptoEngine.decrypt(key, nonce, ct, bytes(tampered_tag))


def test_empty_plaintext_roundtrip() -> None:
    key = os.urandom(32)
    plaintext = b""

    nonce, ct, tag = CryptoEngine.encrypt(key, plaintext)
    decrypted = CryptoEngine.decrypt(key, nonce, ct, tag)
    assert decrypted == b""


def test_large_plaintext_roundtrip() -> None:
    key = os.urandom(32)
    plaintext = os.urandom(512 * 1024)  # 512 KiB

    nonce, ct, tag = CryptoEngine.encrypt(key, plaintext)
    decrypted = CryptoEngine.decrypt(key, nonce, ct, tag)
    assert decrypted == plaintext


def test_nonce_uniqueness() -> None:
    nonces = {CryptoEngine.generate_nonce() for _ in range(1000)}
    assert len(nonces) == 1000

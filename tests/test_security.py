"""
Security-Focused Tests for SinXTan.
"""

from __future__ import annotations

import os
from pathlib import Path
import pytest

from app.core.container_format import (
    CONTAINER_VERSION,
    ENCRYPTION_ALGO_AES256GCM,
    KDF_ALGO_ARGON2ID,
    STEGO_ALGO_LSB,
    COMPRESSION_NONE,
    ContainerFormat,
    ContainerHeader,
)
from app.core.crypto_engine import AuthenticationError, CryptoEngine
from app.core.key_derivation import KDFParams, KeyDerivationEngine
from app.core.payload_manager import PayloadManager, PayloadPathError


def test_salt_uniqueness() -> None:
    salts = {KeyDerivationEngine.generate_salt() for _ in range(100)}
    assert len(salts) == 100


def test_nonce_uniqueness() -> None:
    nonces = {CryptoEngine.generate_nonce() for _ in range(100)}
    assert len(nonces) == 100


def test_password_not_in_container_bytes() -> None:
    secret_password = "SuperUnusualPasswordString9876543210XYZ"
    salt = KeyDerivationEngine.generate_salt()
    params = KDFParams(salt=salt, time_cost=1, memory_cost=16384, parallelism=1)
    enc_key, _ = KeyDerivationEngine.derive_keys(secret_password, salt, params)

    plaintext = b"Payload data"
    nonce, ct, tag = CryptoEngine.encrypt(enc_key, plaintext)

    header = ContainerHeader(
        version=CONTAINER_VERSION,
        stego_algo_id=STEGO_ALGO_LSB,
        encryption_algo_id=ENCRYPTION_ALGO_AES256GCM,
        kdf_id=KDF_ALGO_ARGON2ID,
        kdf_time_cost=1,
        kdf_memory_cost=16384,
        kdf_parallelism=1,
        compression_id=COMPRESSION_NONE,
        salt=salt,
        nonce=nonce,
        payload_length=len(ct + tag),
        metadata_length=0,
    )
    container_bytes = ContainerFormat.build_container(header, {}, ct + tag)

    assert secret_password.encode("utf-8") not in container_bytes


def test_path_traversal_extraction_blocked(tmp_path: Path) -> None:
    with pytest.raises(PayloadPathError):
        from app.core.payload_manager import _validate_relative_path
        _validate_relative_path("subdir/../../etc/shadow")


def test_null_byte_in_path_rejected() -> None:
    with pytest.raises(PayloadPathError):
        from app.core.payload_manager import _validate_relative_path
        _validate_relative_path("safe_dir/test\x00_file.txt")


def test_empty_password_raises() -> None:
    salt = KeyDerivationEngine.generate_salt()
    params = KDFParams(salt=salt, time_cost=1, memory_cost=16384, parallelism=1)

    with pytest.raises(ValueError):
        KeyDerivationEngine.derive_keys("", salt, params)


def test_unicode_password_roundtrip() -> None:
    unicode_pw = "パスワード🔐Üñîçødé_Password_123!"
    salt = KeyDerivationEngine.generate_salt()
    params = KDFParams(salt=salt, time_cost=1, memory_cost=16384, parallelism=1)

    k1, _ = KeyDerivationEngine.derive_keys(unicode_pw, salt, params)
    k2, _ = KeyDerivationEngine.derive_keys(unicode_pw, salt, params)

    assert k1 == k2
    assert len(k1) == 32


def test_long_password_handling() -> None:
    long_pw = "A" * 1000
    salt = KeyDerivationEngine.generate_salt()
    params = KDFParams(salt=salt, time_cost=1, memory_cost=16384, parallelism=1)

    key, _ = KeyDerivationEngine.derive_keys(long_pw, salt, params)
    assert len(key) == 32

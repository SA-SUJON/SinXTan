"""
Container Format, Payload Manager, and Integrity Tests for SinXTan.
"""

from __future__ import annotations

import os
from pathlib import Path
import pytest

from app.core.compression import CompressionEngine, DecompressionError
from app.core.container_format import (
    CONTAINER_VERSION,
    ENCRYPTION_ALGO_AES256GCM,
    KDF_ALGO_ARGON2ID,
    STEGO_ALGO_LSB,
    COMPRESSION_ZLIB,
    ContainerFormat,
    ContainerHeader,
    CorruptedContainerError,
    InvalidContainerError,
    UnsupportedVersionError,
)
from app.core.integrity import IntegrityEngine
from app.core.payload_manager import (
    FileEntry,
    PayloadCorruptedError,
    PayloadManager,
    PayloadPathError,
)


def test_container_build_parse_roundtrip() -> None:
    salt = os.urandom(32)
    nonce = os.urandom(12)
    payload = os.urandom(128)
    metadata = {"files": ["doc.pdf", "img.png"], "count": 2}

    header = ContainerHeader(
        version=CONTAINER_VERSION,
        stego_algo_id=STEGO_ALGO_LSB,
        encryption_algo_id=ENCRYPTION_ALGO_AES256GCM,
        kdf_id=KDF_ALGO_ARGON2ID,
        kdf_time_cost=3,
        kdf_memory_cost=65536,
        kdf_parallelism=4,
        compression_id=COMPRESSION_ZLIB,
        salt=salt,
        nonce=nonce,
        payload_length=len(payload),
        metadata_length=0,
    )

    container_bytes = ContainerFormat.build_container(header, metadata, payload)
    parsed_header, parsed_meta, parsed_payload = ContainerFormat.parse_container(container_bytes)

    assert parsed_header.salt == salt
    assert parsed_header.nonce == nonce
    assert parsed_header.payload_length == len(payload)
    assert parsed_meta == metadata
    assert parsed_payload == payload


def test_invalid_magic_raises() -> None:
    data = b"FAKE" + os.urandom(100)
    with pytest.raises(InvalidContainerError):
        ContainerFormat.parse_container(data)


def test_truncated_container_raises() -> None:
    data = b"SXT1" + os.urandom(20)  # Shorter than 78-byte fixed header
    with pytest.raises(InvalidContainerError):
        ContainerFormat.parse_container(data)


def test_payload_single_file_roundtrip(tmp_path: Path) -> None:
    f1 = tmp_path / "hello.txt"
    f1.write_text("Hello, SinXTan Payload!", encoding="utf-8")

    payload_bytes = PayloadManager.serialize_files([f1])
    entries = PayloadManager.deserialize(payload_bytes)

    assert len(entries) == 1
    assert entries[0].relative_path == "hello.txt"
    assert entries[0].content == b"Hello, SinXTan Payload!"
    assert entries[0].verify_checksum() is True


def test_payload_multiple_files_roundtrip(tmp_path: Path) -> None:
    files = []
    for i in range(5):
        f = tmp_path / f"test_{i}.dat"
        f.write_bytes(f"Content {i}".encode("utf-8"))
        files.append(f)

    payload_bytes = PayloadManager.serialize_files(files)
    entries = PayloadManager.deserialize(payload_bytes)

    assert len(entries) == 5
    for i, e in enumerate(entries):
        assert e.content == f"Content {i}".encode("utf-8")
        assert e.verify_checksum() is True


def test_payload_directory_recursive_roundtrip(tmp_path: Path) -> None:
    src_dir = tmp_path / "my_project"
    sub_dir = src_dir / "src" / "deep"
    sub_dir.mkdir(parents=True)

    (src_dir / "README.md").write_text("Root doc", encoding="utf-8")
    (sub_dir / "module.py").write_text("print('Deep file')", encoding="utf-8")

    payload_bytes = PayloadManager.serialize_directory(src_dir)

    out_dir = tmp_path / "extracted"
    extracted_paths = PayloadManager.extract_to(payload_bytes, out_dir)

    assert len(extracted_paths) == 2
    assert (out_dir / "README.md").read_text(encoding="utf-8") == "Root doc"
    assert (out_dir / "src" / "deep" / "module.py").read_text(encoding="utf-8") == "print('Deep file')"


def test_path_traversal_rejected() -> None:
    # Attempt to serialize entry with traversal
    with pytest.raises(PayloadPathError):
        from app.core.payload_manager import _validate_relative_path
        _validate_relative_path("../../../etc/passwd")


def test_compression_roundtrip() -> None:
    data = b"Repeated pattern " * 500
    compressed = CompressionEngine.compress(data)
    assert len(compressed) < len(data)

    decompressed = CompressionEngine.decompress(compressed)
    assert decompressed == data


def test_integrity_sha256(tmp_path: Path) -> None:
    data = b"Deterministic payload to verify hash"
    h = IntegrityEngine.compute_sha256(data)
    assert len(h) == 32
    assert IntegrityEngine.verify_sha256(data, h) is True

    f = tmp_path / "hash_test.bin"
    f.write_bytes(data)
    assert IntegrityEngine.verify_file_sha256(f, h) is True

"""
End-to-End Integration Tests for the SinXTan Application Pipeline.
"""

from __future__ import annotations

import os
from pathlib import Path
import pytest
from PIL import Image

from app.core.compression import COMPRESSION_NONE, COMPRESSION_ZLIB, CompressionEngine
from app.core.container_format import (
    CONTAINER_VERSION,
    ENCRYPTION_ALGO_AES256GCM,
    KDF_ALGO_ARGON2ID,
    STEGO_ALGO_LSB,
    ContainerHeader,
)
from app.core.crypto_engine import AuthenticationError, CryptoEngine
from app.core.key_derivation import KDFParams, KeyDerivationEngine
from app.core.payload_manager import PayloadManager
from app.core.stego_engine import StegoEngine


@pytest.fixture
def carrier_image(tmp_path: Path) -> Path:
    p = tmp_path / "carrier.png"
    img = Image.new("RGB", (250, 250), color=(100, 140, 180))
    img.save(p)
    return p


def test_full_pipeline_single_file(carrier_image: Path, tmp_path: Path) -> None:
    # 1. Source file
    doc_path = tmp_path / "confidential.pdf"
    doc_content = b"%PDF-1.4 ... Fake confidential document content ..." * 10
    doc_path.write_bytes(doc_content)

    password = "CorrectStrongPassphrase!2026"

    # 2. Pipeline: Serialize -> Compress -> Derive Keys -> Encrypt -> Build Container -> Embed
    payload = PayloadManager.serialize_files([doc_path])
    compressed = CompressionEngine.compress(payload)

    salt = KeyDerivationEngine.generate_salt()
    kdf_params = KDFParams(salt=salt, time_cost=1, memory_cost=16384, parallelism=2)
    enc_key, embed_key = KeyDerivationEngine.derive_keys(password, salt, kdf_params)

    nonce, ct, tag = CryptoEngine.encrypt(enc_key, compressed)
    enc_payload = ct + tag

    header = ContainerHeader(
        version=CONTAINER_VERSION,
        stego_algo_id=STEGO_ALGO_LSB,
        encryption_algo_id=ENCRYPTION_ALGO_AES256GCM,
        kdf_id=KDF_ALGO_ARGON2ID,
        kdf_time_cost=kdf_params.time_cost,
        kdf_memory_cost=kdf_params.memory_cost,
        kdf_parallelism=kdf_params.parallelism,
        compression_id=COMPRESSION_ZLIB,
        salt=salt,
        nonce=nonce,
        payload_length=len(enc_payload),
        metadata_length=0,
    )
    metadata = {"files": ["confidential.pdf"], "count": 1}

    stego_out = tmp_path / "stego_output.png"
    StegoEngine.embed_container(
        image_path=carrier_image,
        header=header,
        metadata=metadata,
        encrypted_payload=enc_payload,
        embedding_key=embed_key,
        bits_per_channel=1,
        output_path=stego_out,
    )

    # 3. Reverse Pipeline: Detect -> Derive Keys -> Extract Payload -> Decrypt -> Decompress -> Extract Files
    det = StegoEngine.detect_container(stego_out, bits_per_channel=1)
    assert det is not None
    det_header, det_meta = det

    rec_enc_key, rec_embed_key = KeyDerivationEngine.derive_keys(
        password,
        det_header.salt,
        KDFParams(salt=det_header.salt, time_cost=det_header.kdf_time_cost, memory_cost=det_header.kdf_memory_cost, parallelism=det_header.kdf_parallelism),
    )

    extracted_payload = StegoEngine.extract_container_payload(stego_out, det_header, rec_embed_key, bits_per_channel=1)
    decrypted_bytes = CryptoEngine.decrypt(rec_enc_key, det_header.nonce, extracted_payload[:-16], extracted_payload[-16:])

    decompressed = CompressionEngine.decompress(decrypted_bytes)
    assert decompressed == payload

    dest_dir = tmp_path / "extracted_files"
    extracted_paths = PayloadManager.extract_to(decompressed, dest_dir)
    assert len(extracted_paths) == 1
    assert extracted_paths[0].read_bytes() == doc_content


def test_full_pipeline_wrong_password_fails(carrier_image: Path, tmp_path: Path) -> None:
    doc_path = tmp_path / "secret.txt"
    doc_path.write_text("Secret text data", encoding="utf-8")

    password = "CorrectPassword123"
    wrong_password = "IncorrectPassword999"

    payload = PayloadManager.serialize_files([doc_path])
    salt = KeyDerivationEngine.generate_salt()
    kdf_params = KDFParams(salt=salt, time_cost=1, memory_cost=16384, parallelism=1)
    enc_key, embed_key = KeyDerivationEngine.derive_keys(password, salt, kdf_params)

    nonce, ct, tag = CryptoEngine.encrypt(enc_key, payload)
    enc_payload = ct + tag

    header = ContainerHeader(
        version=CONTAINER_VERSION,
        stego_algo_id=STEGO_ALGO_LSB,
        encryption_algo_id=ENCRYPTION_ALGO_AES256GCM,
        kdf_id=KDF_ALGO_ARGON2ID,
        kdf_time_cost=kdf_params.time_cost,
        kdf_memory_cost=kdf_params.memory_cost,
        kdf_parallelism=kdf_params.parallelism,
        compression_id=COMPRESSION_NONE,
        salt=salt,
        nonce=nonce,
        payload_length=len(enc_payload),
        metadata_length=0,
    )

    stego_out = tmp_path / "stego_wrong_pw.png"
    StegoEngine.embed_container(
        carrier_image,
        header,
        {},
        enc_payload,
        embed_key,
        output_path=stego_out,
    )

    det = StegoEngine.detect_container(stego_out)
    assert det is not None
    det_header, _ = det

    wrong_enc_key, wrong_embed_key = KeyDerivationEngine.derive_keys(
        wrong_password,
        det_header.salt,
        KDFParams(salt=det_header.salt, time_cost=det_header.kdf_time_cost, memory_cost=det_header.kdf_memory_cost, parallelism=det_header.kdf_parallelism),
    )

    extracted_payload = StegoEngine.extract_container_payload(stego_out, det_header, wrong_embed_key)

    with pytest.raises(AuthenticationError):
        CryptoEngine.decrypt(wrong_enc_key, det_header.nonce, extracted_payload[:-16], extracted_payload[-16:])


def test_binary_file_exact_roundtrip(carrier_image: Path, tmp_path: Path) -> None:
    # All 256 byte values repeated
    all_bytes = bytes(range(256)) * 4
    bin_file = tmp_path / "all_bytes.bin"
    bin_file.write_bytes(all_bytes)

    password = "ByteIntegrityPassword!"

    payload = PayloadManager.serialize_files([bin_file])
    salt = KeyDerivationEngine.generate_salt()
    kdf_params = KDFParams(salt=salt, time_cost=1, memory_cost=16384, parallelism=1)
    enc_key, embed_key = KeyDerivationEngine.derive_keys(password, salt, kdf_params)

    nonce, ct, tag = CryptoEngine.encrypt(enc_key, payload)
    enc_payload = ct + tag

    header = ContainerHeader(
        version=CONTAINER_VERSION,
        stego_algo_id=STEGO_ALGO_LSB,
        encryption_algo_id=ENCRYPTION_ALGO_AES256GCM,
        kdf_id=KDF_ALGO_ARGON2ID,
        kdf_time_cost=kdf_params.time_cost,
        kdf_memory_cost=kdf_params.memory_cost,
        kdf_parallelism=kdf_params.parallelism,
        compression_id=COMPRESSION_NONE,
        salt=salt,
        nonce=nonce,
        payload_length=len(enc_payload),
        metadata_length=0,
    )

    stego_out = tmp_path / "binary_stego.png"
    StegoEngine.embed_container(carrier_image, header, {}, enc_payload, embed_key, output_path=stego_out)

    det = StegoEngine.detect_container(stego_out)
    assert det is not None
    det_hdr, _ = det

    rec_enc, rec_emb = KeyDerivationEngine.derive_keys(password, det_hdr.salt, kdf_params)
    ext_payload = StegoEngine.extract_container_payload(stego_out, det_hdr, rec_emb)
    decrypted = CryptoEngine.decrypt(rec_enc, det_hdr.nonce, ext_payload[:-16], ext_payload[-16:])

    dest = tmp_path / "extracted_binary"
    out_paths = PayloadManager.extract_to(decrypted, dest)

    assert out_paths[0].read_bytes() == all_bytes

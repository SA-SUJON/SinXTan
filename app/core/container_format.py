"""
Container Format for SinXTan Cryptographic Steganography Application.

Defines the binary container format for embedding and extracting encrypted data.
Includes strict validation, versioning, metadata serialization, and authenticated
additional data (AAD) construction for AES-GCM.

Header Format Layout (78 bytes fixed, Little-Endian):
    - Magic:                4 bytes  (b'SXT1')
    - Version:              2 bytes  (uint16)
    - Stego Algo ID:        1 byte   (uint8,  0x01 = LSB)
    - Encryption Algo ID:   1 byte   (uint8,  0x01 = AES-256-GCM)
    - KDF ID:               1 byte   (uint8,  0x01 = Argon2id)
    - KDF Time Cost:        4 bytes  (uint32)
    - KDF Memory Cost:      4 bytes  (uint32, KiB)
    - KDF Parallelism:      4 bytes  (uint32)
    - Compression ID:       1 byte   (uint8,  0x00 = None, 0x01 = zlib)
    - Salt:                32 bytes  (raw bytes)
    - Nonce:               12 bytes  (raw bytes)
    - Payload Length:       8 bytes  (uint64)
    - Metadata Length:      4 bytes  (uint32)
Followed by:
    - Metadata:             variable (UTF-8 encoded JSON bytes)
    - Encrypted Payload:    variable (ciphertext + 16-byte authentication tag)
"""

from __future__ import annotations

import json
import struct
from dataclasses import dataclass
from typing import Any, Final

__all__ = [
    "CONTAINER_MAGIC",
    "CONTAINER_VERSION",
    "STEGO_ALGO_LSB",
    "ENCRYPTION_ALGO_AES256GCM",
    "KDF_ALGO_ARGON2ID",
    "COMPRESSION_NONE",
    "COMPRESSION_ZLIB",
    "ContainerHeader",
    "ContainerFormat",
    "InvalidContainerError",
    "UnsupportedVersionError",
    "CorruptedContainerError",
]

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

CONTAINER_MAGIC: Final[bytes] = b"SXT1"
CONTAINER_VERSION: Final[int] = 1

STEGO_ALGO_LSB: Final[int] = 0x01
ENCRYPTION_ALGO_AES256GCM: Final[int] = 0x01
KDF_ALGO_ARGON2ID: Final[int] = 0x01
COMPRESSION_NONE: Final[int] = 0x00
COMPRESSION_ZLIB: Final[int] = 0x01

# Fixed header struct: <4sHBBBIIIB32s12sQI
# 4s (magic), H (version), B (stego), B (enc), B (kdf),
# I (time_cost), I (mem_cost), I (parallelism), B (comp),
# 32s (salt), 12s (nonce), Q (payload_len), I (meta_len)
_FIXED_HEADER_FORMAT: Final[str] = "<4sHBBBIIIB32s12sQI"
_FIXED_HEADER_SIZE: Final[int] = struct.calcsize(_FIXED_HEADER_FORMAT)  # 78 bytes
assert _FIXED_HEADER_SIZE == 78, f"Header size mismatch: {_FIXED_HEADER_SIZE} != 78"

_MAX_METADATA_SIZE: Final[int] = 10 * 1024 * 1024  # 10 MB limit on metadata JSON


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class InvalidContainerError(Exception):
    """Raised when data does not match the SinXTan container signature or format."""


class UnsupportedVersionError(Exception):
    """Raised when container version is not supported by this version of SinXTan."""


class CorruptedContainerError(Exception):
    """Raised when container header or metadata fields are invalid, truncated, or inconsistent."""


# ---------------------------------------------------------------------------
# Data Structures
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ContainerHeader:
    """Header information for a SinXTan secure container."""

    version: int
    stego_algo_id: int
    encryption_algo_id: int
    kdf_id: int
    kdf_time_cost: int
    kdf_memory_cost: int
    kdf_parallelism: int
    compression_id: int
    salt: bytes
    nonce: bytes
    payload_length: int
    metadata_length: int

    def __post_init__(self) -> None:
        if len(self.salt) != 32:
            raise ValueError(f"Salt must be 32 bytes, got {len(self.salt)}")
        if len(self.nonce) != 12:
            raise ValueError(f"Nonce must be 12 bytes, got {len(self.nonce)}")
        if self.payload_length < 16:  # At least 16 bytes for GCM tag
            raise ValueError(f"Payload length must be at least 16 bytes for auth tag, got {self.payload_length}")


# ---------------------------------------------------------------------------
# ContainerFormat
# ---------------------------------------------------------------------------


class ContainerFormat:
    """Parser and builder for the SinXTan binary container."""

    @staticmethod
    def get_header_size() -> int:
        """Return the fixed header size in bytes (78)."""
        return _FIXED_HEADER_SIZE

    @staticmethod
    def build_container(
        header: ContainerHeader,
        metadata: dict[str, Any],
        encrypted_payload: bytes,
    ) -> bytes:
        """Serialize a full container from header, metadata, and encrypted payload.

        Parameters
        ----------
        header:
            ContainerHeader with populated parameters.
        metadata:
            Dictionary of metadata to authenticate (JSON-serializable).
        encrypted_payload:
            Ciphertext including authentication tag.

        Returns
        -------
        bytes
            Complete serialized container bytes.
        """
        metadata_bytes = json.dumps(metadata, separators=(",", ":"), sort_keys=True).encode("utf-8")
        if len(metadata_bytes) > _MAX_METADATA_SIZE:
            raise ValueError(f"Metadata exceeds max allowed size of {_MAX_METADATA_SIZE} bytes")

        if len(encrypted_payload) != header.payload_length:
            raise ValueError(
                f"Payload length mismatch: expected {header.payload_length}, got {len(encrypted_payload)}"
            )

        fixed_header = struct.pack(
            _FIXED_HEADER_FORMAT,
            CONTAINER_MAGIC,
            header.version,
            header.stego_algo_id,
            header.encryption_algo_id,
            header.kdf_id,
            header.kdf_time_cost,
            header.kdf_memory_cost,
            header.kdf_parallelism,
            header.compression_id,
            header.salt,
            header.nonce,
            header.payload_length,
            len(metadata_bytes),
        )

        return fixed_header + metadata_bytes + encrypted_payload

    @staticmethod
    def parse_header(data: bytes) -> tuple[ContainerHeader, bytes]:
        """Parse only the fixed header from binary data.

        Returns (header, remaining_data).
        """
        if len(data) < _FIXED_HEADER_SIZE:
            raise InvalidContainerError(
                f"Data too short for container header: {len(data)} < {_FIXED_HEADER_SIZE} bytes"
            )

        (
            magic,
            version,
            stego_algo_id,
            encryption_algo_id,
            kdf_id,
            kdf_time_cost,
            kdf_memory_cost,
            kdf_parallelism,
            compression_id,
            salt,
            nonce,
            payload_length,
            metadata_length,
        ) = struct.unpack(_FIXED_HEADER_FORMAT, data[:_FIXED_HEADER_SIZE])

        if magic != CONTAINER_MAGIC:
            raise InvalidContainerError(
                f"Invalid container magic: expected {CONTAINER_MAGIC!r}, got {magic!r}"
            )

        if version != CONTAINER_VERSION:
            raise UnsupportedVersionError(
                f"Unsupported container version: {version} (expected {CONTAINER_VERSION})"
            )

        if metadata_length > _MAX_METADATA_SIZE:
            raise CorruptedContainerError(
                f"Metadata length {metadata_length} exceeds limit {_MAX_METADATA_SIZE}"
            )

        header = ContainerHeader(
            version=version,
            stego_algo_id=stego_algo_id,
            encryption_algo_id=encryption_algo_id,
            kdf_id=kdf_id,
            kdf_time_cost=kdf_time_cost,
            kdf_memory_cost=kdf_memory_cost,
            kdf_parallelism=kdf_parallelism,
            compression_id=compression_id,
            salt=salt,
            nonce=nonce,
            payload_length=payload_length,
            metadata_length=metadata_length,
        )

        return header, data[_FIXED_HEADER_SIZE:]

    @staticmethod
    def parse_container(data: bytes) -> tuple[ContainerHeader, dict[str, Any], bytes]:
        """Parse full container binary.

        Parameters
        ----------
        data:
            Container byte stream.

        Returns
        -------
        tuple[ContainerHeader, dict, bytes]
            (header, metadata_dict, encrypted_payload)
        """
        header, rest = ContainerFormat.parse_header(data)

        if len(rest) < header.metadata_length + header.payload_length:
            raise CorruptedContainerError(
                f"Truncated container: expected {header.metadata_length + header.payload_length} bytes after header, got {len(rest)}"
            )

        metadata_bytes = rest[: header.metadata_length]
        encrypted_payload = rest[
            header.metadata_length : header.metadata_length + header.payload_length
        ]

        try:
            metadata: dict[str, Any] = json.loads(metadata_bytes.decode("utf-8")) if metadata_bytes else {}
        except Exception as exc:
            raise CorruptedContainerError(f"Failed to decode container metadata JSON: {exc}") from exc

        return header, metadata, encrypted_payload

    @staticmethod
    def build_aad(header: ContainerHeader, metadata_bytes: bytes) -> bytes:
        """Construct Authenticated Additional Data (AAD) for AES-GCM.

        The AAD binds the fixed header and raw metadata bytes to the encryption
        tag, preventing any undetected modification of salt, iteration counts,
        algorithms, or file lists.
        """
        fixed_header = struct.pack(
            _FIXED_HEADER_FORMAT,
            CONTAINER_MAGIC,
            header.version,
            header.stego_algo_id,
            header.encryption_algo_id,
            header.kdf_id,
            header.kdf_time_cost,
            header.kdf_memory_cost,
            header.kdf_parallelism,
            header.compression_id,
            header.salt,
            header.nonce,
            header.payload_length,
            header.metadata_length,
        )
        return fixed_header + metadata_bytes

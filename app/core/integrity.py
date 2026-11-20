"""
Data integrity verification utilities for SinXTan.

Provides SHA-256 hashing, HMAC-SHA256 computation and verification,
and integrity reporting for extracted steganographic payloads.
"""

from __future__ import annotations

import hashlib
import hmac as _hmac
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Union

logger = logging.getLogger(__name__)

_CHUNK_SIZE: int = 65_536  # 64 KiB


class IntegrityError(Exception):
    """Raised when an integrity check fails unexpectedly."""


class IntegrityEngine:
    """Stateless engine for cryptographic integrity operations.

    All methods are intentionally class-level (could be static) but are kept
    as regular methods so the engine can be sub-classed or wrapped with
    additional state (e.g. audit logging) in the future.
    """

    # ------------------------------------------------------------------
    # SHA-256
    # ------------------------------------------------------------------

    @staticmethod
    def compute_sha256(data: bytes) -> bytes:
        """Return the SHA-256 digest of *data*.

        Args:
            data: Arbitrary byte string to hash.

        Returns:
            32-byte SHA-256 digest.

        Raises:
            TypeError: If *data* is not ``bytes``.
        """
        if not isinstance(data, bytes):
            raise TypeError(f"Expected bytes, got {type(data).__name__}")
        return hashlib.sha256(data).digest()

    @staticmethod
    def compute_file_sha256(file_path: Union[str, Path]) -> bytes:
        """Return the SHA-256 digest of a file, reading in 64 KiB chunks.

        Args:
            file_path: Path to the target file.

        Returns:
            32-byte SHA-256 digest.

        Raises:
            FileNotFoundError: If the file does not exist.
            PermissionError: If the file cannot be read.
            OSError: On other I/O failures.
        """
        path = Path(file_path)
        if not path.is_file():
            raise FileNotFoundError(f"File not found: {path}")

        sha = hashlib.sha256()
        with path.open("rb") as fh:
            while True:
                chunk = fh.read(_CHUNK_SIZE)
                if not chunk:
                    break
                sha.update(chunk)
        return sha.digest()

    @staticmethod
    def verify_sha256(data: bytes, expected_hash: bytes) -> bool:
        """Verify that the SHA-256 of *data* matches *expected_hash*.

        Uses ``hmac.compare_digest`` for constant-time comparison to
        prevent timing side-channels.

        Args:
            data: Byte string whose hash is to be verified.
            expected_hash: Expected 32-byte SHA-256 digest.

        Returns:
            ``True`` if the digests match, ``False`` otherwise.

        Raises:
            TypeError: If either argument is not ``bytes``.
        """
        if not isinstance(data, bytes):
            raise TypeError(f"Expected bytes for data, got {type(data).__name__}")
        if not isinstance(expected_hash, bytes):
            raise TypeError(
                f"Expected bytes for expected_hash, got {type(expected_hash).__name__}"
            )
        actual = hashlib.sha256(data).digest()
        return _hmac.compare_digest(actual, expected_hash)

    @staticmethod
    def verify_file_sha256(
        file_path: Union[str, Path], expected_hash: bytes
    ) -> bool:
        """Verify that the SHA-256 of a file matches *expected_hash*.

        Uses ``hmac.compare_digest`` for constant-time comparison.

        Args:
            file_path: Path to the target file.
            expected_hash: Expected 32-byte SHA-256 digest.

        Returns:
            ``True`` if the digests match, ``False`` otherwise.

        Raises:
            FileNotFoundError: If the file does not exist.
            TypeError: If *expected_hash* is not ``bytes``.
        """
        if not isinstance(expected_hash, bytes):
            raise TypeError(
                f"Expected bytes for expected_hash, got {type(expected_hash).__name__}"
            )
        actual = IntegrityEngine.compute_file_sha256(file_path)
        return _hmac.compare_digest(actual, expected_hash)

    # ------------------------------------------------------------------
    # HMAC-SHA256
    # ------------------------------------------------------------------

    @staticmethod
    def compute_hmac(key: bytes, data: bytes) -> bytes:
        """Compute an HMAC-SHA256 tag over *data* using *key*.

        Args:
            key: Secret key (arbitrary length; ≥32 bytes recommended).
            data: Message to authenticate.

        Returns:
            32-byte HMAC-SHA256 tag.

        Raises:
            TypeError: If *key* or *data* is not ``bytes``.
        """
        if not isinstance(key, bytes):
            raise TypeError(f"Expected bytes for key, got {type(key).__name__}")
        if not isinstance(data, bytes):
            raise TypeError(f"Expected bytes for data, got {type(data).__name__}")
        return _hmac.new(key, data, hashlib.sha256).digest()

    @staticmethod
    def verify_hmac(key: bytes, data: bytes, expected_mac: bytes) -> bool:
        """Verify an HMAC-SHA256 tag using constant-time comparison.

        Args:
            key: Secret key used to generate the original tag.
            data: Message that was authenticated.
            expected_mac: Expected 32-byte HMAC-SHA256 tag.

        Returns:
            ``True`` if the tag is valid, ``False`` otherwise.

        Raises:
            TypeError: If any argument is not ``bytes``.
        """
        if not isinstance(key, bytes):
            raise TypeError(f"Expected bytes for key, got {type(key).__name__}")
        if not isinstance(data, bytes):
            raise TypeError(f"Expected bytes for data, got {type(data).__name__}")
        if not isinstance(expected_mac, bytes):
            raise TypeError(
                f"Expected bytes for expected_mac, got {type(expected_mac).__name__}"
            )
        actual = _hmac.new(key, data, hashlib.sha256).digest()
        return _hmac.compare_digest(actual, expected_mac)


# ----------------------------------------------------------------------
# Integrity report
# ----------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class IntegrityReport:
    """Immutable record describing the outcome of a single file-integrity check.

    Attributes:
        file_path: Absolute or relative path of the checked file.
        expected_hash: Hex-encoded expected SHA-256 digest.
        actual_hash: Hex-encoded actual SHA-256 digest (empty string on error).
        verified: Whether the hashes matched.
        error: Human-readable error description, or ``None`` on success.
    """

    file_path: str
    expected_hash: str
    actual_hash: str
    verified: bool
    error: Optional[str] = field(default=None)


def generate_integrity_report(
    extracted_files: List[str],
    original_checksums: Dict[str, str],
) -> List[IntegrityReport]:
    """Compare extracted files against their original SHA-256 checksums.

    For each path in *extracted_files* the function:

    1. Looks up the expected hex-encoded SHA-256 in *original_checksums*.
    2. Computes the actual SHA-256 of the file on disk.
    3. Records the result in an :class:`IntegrityReport`.

    Files missing from *original_checksums* are reported as an error.
    I/O errors (missing file, permission denied, …) are caught and stored in
    the report's ``error`` field rather than propagated, so the caller always
    receives a complete list of reports.

    Args:
        extracted_files: Iterable of file-path strings to verify.
        original_checksums: Mapping of ``file_path → hex_sha256``.

    Returns:
        A list of :class:`IntegrityReport` instances, one per input file,
        in the same order as *extracted_files*.
    """
    engine = IntegrityEngine()
    reports: List[IntegrityReport] = []

    for file_path in extracted_files:
        expected_hex: Optional[str] = original_checksums.get(file_path)

        # No reference checksum available
        if expected_hex is None:
            reports.append(
                IntegrityReport(
                    file_path=file_path,
                    expected_hash="",
                    actual_hash="",
                    verified=False,
                    error=f"No checksum recorded for '{file_path}'",
                )
            )
            logger.warning("No checksum recorded for '%s'", file_path)
            continue

        try:
            expected_bytes = bytes.fromhex(expected_hex)
        except ValueError as exc:
            reports.append(
                IntegrityReport(
                    file_path=file_path,
                    expected_hash=expected_hex,
                    actual_hash="",
                    verified=False,
                    error=f"Malformed expected checksum: {exc}",
                )
            )
            logger.error("Malformed checksum for '%s': %s", file_path, exc)
            continue

        try:
            actual_bytes = engine.compute_file_sha256(file_path)
        except (FileNotFoundError, PermissionError, OSError) as exc:
            reports.append(
                IntegrityReport(
                    file_path=file_path,
                    expected_hash=expected_hex,
                    actual_hash="",
                    verified=False,
                    error=str(exc),
                )
            )
            logger.error("Cannot hash '%s': %s", file_path, exc)
            continue

        actual_hex = actual_bytes.hex()
        verified = _hmac.compare_digest(actual_bytes, expected_bytes)

        reports.append(
            IntegrityReport(
                file_path=file_path,
                expected_hash=expected_hex,
                actual_hash=actual_hex,
                verified=verified,
                error=None,
            )
        )

        if verified:
            logger.debug("Integrity OK: %s", file_path)
        else:
            logger.warning(
                "Integrity FAILED for '%s': expected %s, got %s",
                file_path,
                expected_hex,
                actual_hex,
            )

    return reports

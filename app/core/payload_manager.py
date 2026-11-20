"""
Payload Manager for SinXTan Cryptographic Steganography Application.

Serializes files and directories into a structured binary payload format
with integrity verification, path validation, and versioned headers.

Binary Format Layout:
    Header (12 bytes):
        - Magic:       4 bytes  (b'SXTP')
        - Version:     2 bytes  (uint16, little-endian)
        - Entry Count: 4 bytes  (uint32, little-endian)
        - Flags:       2 bytes  (uint16, little-endian, reserved)

    File Entry (variable length, sequential):
        - Path Length: 2 bytes  (uint16, little-endian)
        - Path:        variable (UTF-8 encoded relative path)
        - File Size:   8 bytes  (uint64, little-endian)
        - Checksum:    32 bytes (SHA-256 digest)
        - Timestamp:   8 bytes  (uint64, little-endian, Unix epoch seconds)
        - Content:     variable (raw file bytes, length == File Size)
"""

from __future__ import annotations

import hashlib
import os
import struct
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

__all__ = [
    "PayloadManager",
    "FileEntry",
    "PayloadError",
    "PayloadCorruptedError",
    "PayloadPathError",
    "PayloadVersionError",
    "PAYLOAD_MAGIC",
    "PAYLOAD_VERSION",
]

# ── Constants ───────────────────────────────────────────────────────────────────

PAYLOAD_MAGIC: bytes = b"SXTP"
PAYLOAD_VERSION: int = 1

_HEADER_FORMAT: str = "<4sHIH"  # magic(4s) version(H) entry_count(I) flags(H)
_HEADER_SIZE: int = struct.calcsize(_HEADER_FORMAT)  # 12 bytes

_PATH_LEN_FORMAT: str = "<H"  # path_length(H)
_PATH_LEN_SIZE: int = struct.calcsize(_PATH_LEN_FORMAT)  # 2 bytes

_ENTRY_META_FORMAT: str = "<Q32sQ"  # size(Q) checksum(32s) timestamp(Q)
_ENTRY_META_SIZE: int = struct.calcsize(_ENTRY_META_FORMAT)  # 48 bytes

_MAX_PATH_BYTES: int = 4096
_MAX_FILENAME_BYTES: int = 255
_MAX_UINT16: int = (1 << 16) - 1
_MAX_UINT32: int = (1 << 32) - 1
_MAX_UINT64: int = (1 << 64) - 1


# ── Exceptions ──────────────────────────────────────────────────────────────────


class PayloadError(Exception):
    """Base exception for all payload-related errors."""


class PayloadCorruptedError(PayloadError):
    """Raised when payload data fails integrity checks."""


class PayloadPathError(PayloadError):
    """Raised when a path fails security validation."""


class PayloadVersionError(PayloadError):
    """Raised when the payload version is unsupported."""


# ── Data Classes ────────────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class FileEntry:
    """Represents a single file entry within a serialized payload."""

    relative_path: str
    size: int
    checksum: bytes
    timestamp: int
    content: bytes

    def verify_checksum(self) -> bool:
        """Return True if the stored checksum matches the SHA-256 of content."""
        return hashlib.sha256(self.content).digest() == self.checksum

    def verify_size(self) -> bool:
        """Return True if the stored size matches the actual content length."""
        return self.size == len(self.content)


# ── Path Validation ─────────────────────────────────────────────────────────────


def _validate_relative_path(path_str: str) -> None:
    """Validate that *path_str* is a safe, relative path.

    Raises:
        PayloadPathError: If the path is absolute, contains traversal
            components, null bytes, or exceeds length limits.
    """
    if "\x00" in path_str:
        raise PayloadPathError(
            f"Path contains null byte: {path_str!r}"
        )

    if not path_str:
        raise PayloadPathError("Path must not be empty")

    path_bytes: bytes = path_str.encode("utf-8")
    if len(path_bytes) > _MAX_PATH_BYTES:
        raise PayloadPathError(
            f"Path exceeds maximum length of {_MAX_PATH_BYTES} bytes: "
            f"{len(path_bytes)} bytes"
        )

    # Use PurePosixPath for platform-independent analysis of the stored path.
    pure = PurePosixPath(path_str)

    if pure.is_absolute():
        raise PayloadPathError(f"Absolute paths are not allowed: {path_str!r}")

    # Also reject Windows-style absolute paths (e.g. C:\...).
    if Path(path_str).is_absolute():
        raise PayloadPathError(f"Absolute paths are not allowed: {path_str!r}")

    for part in pure.parts:
        if part == "..":
            raise PayloadPathError(
                f"Path traversal component '..' is not allowed: {path_str!r}"
            )
        part_bytes: bytes = part.encode("utf-8")
        if len(part_bytes) > _MAX_FILENAME_BYTES:
            raise PayloadPathError(
                f"Filename component exceeds {_MAX_FILENAME_BYTES} bytes: "
                f"{part!r} ({len(part_bytes)} bytes)"
            )


def _normalize_relative_path(file_path: Path, base_dir: Path) -> str:
    """Compute a normalised POSIX-style relative path from *base_dir*.

    Raises:
        PayloadPathError: If the result is unsafe.
    """
    try:
        rel = file_path.resolve().relative_to(base_dir.resolve())
    except ValueError as exc:
        raise PayloadPathError(
            f"File {file_path} is not inside base directory {base_dir}"
        ) from exc

    # Always store with forward slashes regardless of OS.
    posix_str: str = rel.as_posix()
    _validate_relative_path(posix_str)
    return posix_str


# ── Payload Manager ─────────────────────────────────────────────────────────────


class PayloadManager:
    """Serializes and deserializes files using the SinXTan binary payload
    format (``SXTP``).

    Thread-safety: instances are stateless and therefore safe to share
    across threads.
    """

    # ── Serialization ───────────────────────────────────────────────────

    @classmethod
    def serialize_files(
        cls,
        file_paths: list[str | Path],
        base_dir: str | Path | None = None,
    ) -> bytes:
        """Serialize multiple files into a single binary payload.

        Args:
            file_paths: Paths to individual files to include.
            base_dir: Optional base directory used to compute relative paths.
                If ``None``, the parent of each file is used as its base.

        Returns:
            The serialized payload as ``bytes``.

        Raises:
            FileNotFoundError: If a file does not exist.
            IsADirectoryError: If a path points to a directory.
            PayloadPathError: If a computed relative path is unsafe.
            PayloadError: If there are too many entries.
        """
        resolved_base: Path | None = Path(base_dir).resolve() if base_dir is not None else None

        entries: list[tuple[str, bytes, int]] = []  # (rel_path, content, mtime)

        for fp in file_paths:
            file_path = Path(fp)

            if not file_path.exists():
                raise FileNotFoundError(f"File not found: {file_path}")
            if file_path.is_dir():
                raise IsADirectoryError(
                    f"Expected a file, got a directory: {file_path}"
                )

            effective_base: Path = resolved_base if resolved_base is not None else file_path.resolve().parent
            rel_path_str: str = _normalize_relative_path(file_path, effective_base)

            content: bytes = file_path.read_bytes()
            mtime: int = int(file_path.stat().st_mtime)
            entries.append((rel_path_str, content, mtime))

        return cls._pack(entries)

    @classmethod
    def serialize_directory(cls, dir_path: str | Path) -> bytes:
        """Recursively serialize an entire directory into a binary payload.

        Args:
            dir_path: Path to the directory to serialize.

        Returns:
            The serialized payload as ``bytes``.

        Raises:
            NotADirectoryError: If *dir_path* is not a directory.
            PayloadPathError: If a computed relative path is unsafe.
            PayloadError: If there are too many entries.
        """
        root = Path(dir_path).resolve()

        if not root.is_dir():
            raise NotADirectoryError(f"Not a directory: {root}")

        entries: list[tuple[str, bytes, int]] = []

        # Sorted walk for deterministic output.
        for current_dir, dirnames, filenames in os.walk(root):
            dirnames.sort()
            for fname in sorted(filenames):
                full_path = Path(current_dir) / fname
                rel_path_str: str = _normalize_relative_path(full_path, root)
                content: bytes = full_path.read_bytes()
                mtime: int = int(full_path.stat().st_mtime)
                entries.append((rel_path_str, content, mtime))

        return cls._pack(entries)

    # ── Deserialization ─────────────────────────────────────────────────

    @classmethod
    def deserialize(cls, data: bytes) -> list[FileEntry]:
        """Parse a binary payload and return a list of :class:`FileEntry`.

        Args:
            data: Raw payload bytes.

        Returns:
            List of parsed file entries.

        Raises:
            PayloadCorruptedError: On magic mismatch, truncated data, size
                mismatch, or checksum failure.
            PayloadVersionError: If the payload version is unsupported.
            PayloadPathError: If a stored path is unsafe.
        """
        entries, _ = cls._unpack(data, verify_content=True)
        return entries

    @classmethod
    def extract_to(
        cls,
        data: bytes,
        destination: str | Path,
    ) -> list[Path]:
        """Deserialize a payload and write its files to *destination*.

        Parent directories are created automatically.  Existing files are
        overwritten.

        Args:
            data: Raw payload bytes.
            destination: Root directory to extract into.

        Returns:
            Sorted list of :class:`Path` objects for each extracted file.

        Raises:
            PayloadCorruptedError: On integrity failures.
            PayloadVersionError: If the payload version is unsupported.
            PayloadPathError: If a stored path would escape *destination*.
        """
        dest = Path(destination).resolve()
        dest.mkdir(parents=True, exist_ok=True)

        entries: list[FileEntry] = cls.deserialize(data)
        extracted: list[Path] = []

        for entry in entries:
            target = (dest / entry.relative_path).resolve()

            # Defence-in-depth: ensure the resolved target is under dest.
            try:
                target.relative_to(dest)
            except ValueError as exc:
                raise PayloadPathError(
                    f"Extracted path escapes destination: {entry.relative_path!r}"
                ) from exc

            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(entry.content)

            # Restore modification time (access time set to now).
            os.utime(target, (target.stat().st_atime, entry.timestamp))

            extracted.append(target)

        extracted.sort()
        return extracted

    # ── Internal Helpers ────────────────────────────────────────────────

    @staticmethod
    def _pack(entries: list[tuple[str, bytes, int]]) -> bytes:
        """Build the binary payload from pre-validated entries.

        Each element of *entries* is ``(relative_path, content, mtime)``.
        """
        entry_count: int = len(entries)
        if entry_count > _MAX_UINT32:
            raise PayloadError(
                f"Too many entries ({entry_count}); maximum is {_MAX_UINT32}"
            )

        parts: list[bytes] = []

        # ── Header ──────────────────────────────────────────────────────
        flags: int = 0  # Reserved for future use.
        header: bytes = struct.pack(
            _HEADER_FORMAT,
            PAYLOAD_MAGIC,
            PAYLOAD_VERSION,
            entry_count,
            flags,
        )
        parts.append(header)

        # ── Entries ─────────────────────────────────────────────────────
        for rel_path, content, mtime in entries:
            path_bytes: bytes = rel_path.encode("utf-8")
            path_len: int = len(path_bytes)

            if path_len > _MAX_UINT16:
                raise PayloadError(
                    f"Encoded path length ({path_len}) exceeds uint16 max"
                )

            size: int = len(content)
            if size > _MAX_UINT64:
                raise PayloadError(
                    f"File size ({size}) exceeds uint64 max"
                )

            checksum: bytes = hashlib.sha256(content).digest()

            timestamp: int = mtime
            if timestamp < 0:
                timestamp = 0
            if timestamp > _MAX_UINT64:
                raise PayloadError(
                    f"Timestamp ({timestamp}) exceeds uint64 max"
                )

            parts.append(struct.pack(_PATH_LEN_FORMAT, path_len))
            parts.append(path_bytes)
            parts.append(struct.pack(_ENTRY_META_FORMAT, size, checksum, timestamp))
            parts.append(content)

        return b"".join(parts)

    @staticmethod
    def _unpack(
        data: bytes,
        *,
        verify_content: bool = True,
    ) -> tuple[list[FileEntry], int]:
        """Parse raw bytes into ``FileEntry`` objects.

        Returns:
            A tuple of (entries, flags).
        """
        data_len: int = len(data)

        # ── Header ──────────────────────────────────────────────────────
        if data_len < _HEADER_SIZE:
            raise PayloadCorruptedError(
                f"Data too short for header: expected at least {_HEADER_SIZE} "
                f"bytes, got {data_len}"
            )

        magic, version, entry_count, flags = struct.unpack_from(
            _HEADER_FORMAT, data, 0
        )

        if magic != PAYLOAD_MAGIC:
            raise PayloadCorruptedError(
                f"Invalid magic bytes: expected {PAYLOAD_MAGIC!r}, got {magic!r}"
            )

        if version != PAYLOAD_VERSION:
            raise PayloadVersionError(
                f"Unsupported payload version {version}; "
                f"expected {PAYLOAD_VERSION}"
            )

        # ── Entries ─────────────────────────────────────────────────────
        offset: int = _HEADER_SIZE
        entries: list[FileEntry] = []

        for idx in range(entry_count):
            # Path length
            if offset + _PATH_LEN_SIZE > data_len:
                raise PayloadCorruptedError(
                    f"Truncated data at entry {idx}: cannot read path length "
                    f"(offset {offset})"
                )
            (path_len,) = struct.unpack_from(_PATH_LEN_FORMAT, data, offset)
            offset += _PATH_LEN_SIZE

            # Path bytes
            if offset + path_len > data_len:
                raise PayloadCorruptedError(
                    f"Truncated data at entry {idx}: cannot read path "
                    f"({path_len} bytes at offset {offset})"
                )
            try:
                rel_path: str = data[offset : offset + path_len].decode("utf-8")
            except UnicodeDecodeError as exc:
                raise PayloadCorruptedError(
                    f"Invalid UTF-8 in path at entry {idx}"
                ) from exc
            offset += path_len

            _validate_relative_path(rel_path)

            # Entry metadata (size, checksum, timestamp)
            if offset + _ENTRY_META_SIZE > data_len:
                raise PayloadCorruptedError(
                    f"Truncated data at entry {idx}: cannot read metadata "
                    f"(offset {offset})"
                )
            size, checksum, timestamp = struct.unpack_from(
                _ENTRY_META_FORMAT, data, offset
            )
            offset += _ENTRY_META_SIZE

            # Content
            if offset + size > data_len:
                raise PayloadCorruptedError(
                    f"Truncated data at entry {idx}: expected {size} content "
                    f"bytes at offset {offset}, but only "
                    f"{data_len - offset} bytes remain"
                )
            content: bytes = data[offset : offset + size]
            offset += size

            # Size verification (defence-in-depth; guaranteed by slice but
            # protects against future refactors).
            if len(content) != size:
                raise PayloadCorruptedError(
                    f"Size mismatch at entry {idx} ({rel_path!r}): header "
                    f"says {size}, got {len(content)}"
                )

            # Checksum verification
            if verify_content:
                actual_checksum: bytes = hashlib.sha256(content).digest()
                if actual_checksum != checksum:
                    raise PayloadCorruptedError(
                        f"Checksum mismatch at entry {idx} ({rel_path!r}): "
                        f"expected {checksum.hex()}, got {actual_checksum.hex()}"
                    )

            entries.append(
                FileEntry(
                    relative_path=rel_path,
                    size=size,
                    checksum=checksum,
                    timestamp=timestamp,
                    content=content,
                )
            )

        # Warn-level: trailing bytes are silently ignored. This is
        # intentional so that future versions may append data after the
        # entries without breaking older readers.

        return entries, flags

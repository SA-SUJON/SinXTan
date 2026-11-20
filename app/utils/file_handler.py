"""
Safe File Handler for SinXTan Cryptographic Steganography.

Provides robust file I/O operations including atomic writes, safe deletion,
temporary file management, and directory traversal utilities.
"""

from __future__ import annotations

import atexit
import os
import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Final

__all__ = [
    "FileHandler",
    "FileInfo",
]

_CHUNK_SIZE: Final[int] = 64 * 1024  # 64 KiB


@dataclass(frozen=True, slots=True)
class FileInfo:
    """Metadata container for a filesystem object."""

    path: Path
    name: str
    extension: str
    size: int
    modified_time: float
    is_file: bool
    is_dir: bool


class FileHandler:
    """Manages secure file reading, writing, and temporary resources."""

    _tracked_temp_files: set[Path] = set()
    _registered_atexit: bool = False

    @classmethod
    def _ensure_atexit_registered(cls) -> None:
        if not cls._registered_atexit:
            atexit.register(cls.cleanup_temp_files)
            cls._registered_atexit = True

    @staticmethod
    def read_file(path: str | Path) -> bytes:
        """Read and return full binary contents of a file."""
        p = Path(path).resolve()
        if not p.is_file():
            raise FileNotFoundError(f"File not found: {p}")
        with open(p, "rb") as f:
            return f.read()

    @classmethod
    def write_file(cls, path: str | Path, data: bytes, atomic: bool = True) -> Path:
        """Write data to destination path.

        If *atomic* is True, data is written to a temporary file in the same
        directory and then renamed via ``os.replace`` to ensure no partial
        files are ever left if the operation is interrupted.
        """
        dest = Path(path).resolve()
        dest.parent.mkdir(parents=True, exist_ok=True)

        if not atomic:
            with open(dest, "wb") as f:
                f.write(data)
            return dest

        temp_file = None
        try:
            with tempfile.NamedTemporaryFile(
                dir=dest.parent,
                prefix=".sxt_tmp_",
                delete=False,
            ) as tf:
                temp_file = Path(tf.name)
                tf.write(data)
                tf.flush()
                os.fsync(tf.fileno())

            os.replace(temp_file, dest)
            return dest
        except Exception:
            if temp_file and temp_file.exists():
                try:
                    temp_file.unlink()
                except OSError:
                    pass
            raise

    @classmethod
    def read_files(cls, paths: list[str | Path]) -> list[tuple[Path, bytes]]:
        """Read multiple files and return list of (Path, bytes)."""
        results: list[tuple[Path, bytes]] = []
        for p in paths:
            path_obj = Path(p).resolve()
            results.append((path_obj, cls.read_file(path_obj)))
        return results

    @staticmethod
    def get_file_info(path: str | Path) -> FileInfo:
        """Query and return detailed metadata for a path."""
        p = Path(path).resolve()
        stat = p.stat()
        return FileInfo(
            path=p,
            name=p.name,
            extension=p.suffix.lower(),
            size=stat.st_size if p.is_file() else 0,
            modified_time=stat.st_mtime,
            is_file=p.is_file(),
            is_dir=p.is_dir(),
        )

    @staticmethod
    def list_directory(path: str | Path, recursive: bool = True) -> list[Path]:
        """List files in directory."""
        root = Path(path).resolve()
        if not root.is_dir():
            raise NotADirectoryError(f"Directory not found: {root}")

        if recursive:
            return [p for p in root.rglob("*") if p.is_file()]
        return [p for p in root.glob("*") if p.is_file()]

    @classmethod
    def safe_delete(cls, path: str | Path) -> bool:
        """Securely overwrite file with random bytes before unlinking."""
        p = Path(path).resolve()
        if not p.exists():
            return False

        if p.is_file():
            try:
                size = p.stat().st_size
                if size > 0:
                    with open(p, "r+b") as f:
                        f.write(os.urandom(size))
                        f.flush()
                        os.fsync(f.fileno())
                p.unlink()
                return True
            except Exception:
                try:
                    p.unlink()
                    return True
                except Exception:
                    return False
        elif p.is_dir():
            shutil.rmtree(p, ignore_errors=True)
            return True
        return False

    @classmethod
    def create_temp_file(cls, suffix: str = ".tmp") -> Path:
        """Create a tracked temporary file cleaned up upon process exit."""
        cls._ensure_atexit_registered()
        fd, name = tempfile.mkstemp(prefix="sxt_", suffix=suffix)
        os.close(fd)
        p = Path(name).resolve()
        cls._tracked_temp_files.add(p)
        return p

    @classmethod
    def cleanup_temp_files(cls) -> None:
        """Clean up all tracked temporary files."""
        for p in list(cls._tracked_temp_files):
            try:
                if p.exists():
                    p.unlink()
            except OSError:
                pass
            cls._tracked_temp_files.discard(p)

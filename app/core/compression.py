"""
Payload compression engine for SinXTan steganography application.

Provides zlib-based compression and decompression with zip-bomb protection,
ratio estimation, and adaptive compression decisions.
"""

from __future__ import annotations

import zlib
from typing import Final

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

COMPRESSION_NONE_ID: Final[int] = 0x00
COMPRESSION_ZLIB_ID: Final[int] = 0x01
COMPRESSION_NONE: Final[int] = COMPRESSION_NONE_ID
COMPRESSION_ZLIB: Final[int] = COMPRESSION_ZLIB_ID

#: Hard ceiling on decompressed output to mitigate zip-bomb attacks (2 GiB).
DEFAULT_MAX_DECOMPRESSED_SIZE: Final[int] = 2 * 1024 * 1024 * 1024  # 2 GB

_MIN_COMPRESSION_LEVEL: Final[int] = 1
_MAX_COMPRESSION_LEVEL: Final[int] = 9
_DEFAULT_COMPRESSION_LEVEL: Final[int] = 6
_DEFAULT_SAMPLE_SIZE: Final[int] = 65_536
_DEFAULT_THRESHOLD: Final[float] = 0.9

# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class CompressionError(Exception):
    """Raised when compression of payload data fails."""


class DecompressionError(Exception):
    """Raised when decompression of payload data fails."""


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------


class CompressionEngine:
    """Zlib-based compression engine with zip-bomb protection.

    Parameters
    ----------
    max_decompressed_size:
        Upper bound (in bytes) on the size of decompressed output.  Any
        decompression that would exceed this limit raises
        :class:`DecompressionError`.  Defaults to 2 GiB.
    """

    __slots__ = ("_max_decompressed_size",)

    def __init__(
        self,
        max_decompressed_size: int = DEFAULT_MAX_DECOMPRESSED_SIZE,
    ) -> None:
        if max_decompressed_size <= 0:
            raise ValueError(
                f"max_decompressed_size must be positive, got {max_decompressed_size}"
            )
        self._max_decompressed_size: int = max_decompressed_size

    # -- public properties --------------------------------------------------

    @property
    def max_decompressed_size(self) -> int:
        """Maximum allowed size of decompressed output in bytes."""
        return self._max_decompressed_size

    # -- compression --------------------------------------------------------

    @classmethod
    def compress(
        cls_or_self,
        data: bytes,
        level: int = _DEFAULT_COMPRESSION_LEVEL,
    ) -> bytes:
        """Compress *data* using zlib at the specified *level*.

        Parameters
        ----------
        data:
            Raw bytes to compress.
        level:
            Compression level in the range 1 (fastest) to 9 (smallest).

        Returns
        -------
        bytes
            Zlib-compressed payload.

        Raises
        ------
        CompressionError
            If *level* is out of range or the zlib compressor fails.
        """
        if not isinstance(data, (bytes, bytearray, memoryview)):
            raise CompressionError(
                f"Expected bytes-like object, got {type(data).__name__}"
            )

        if not (_MIN_COMPRESSION_LEVEL <= level <= _MAX_COMPRESSION_LEVEL):
            raise CompressionError(
                f"Compression level must be between {_MIN_COMPRESSION_LEVEL} "
                f"and {_MAX_COMPRESSION_LEVEL}, got {level}"
            )

        # Empty data is a valid edge case — return the zlib representation of
        # an empty stream so that round-tripping works correctly.
        if len(data) == 0:
            return zlib.compress(b"", level)

        try:
            return zlib.compress(data, level)
        except zlib.error as exc:
            raise CompressionError(f"zlib compression failed: {exc}") from exc

    # -- decompression ------------------------------------------------------

    @classmethod
    def decompress(cls_or_self, data: bytes, max_size: int | None = None) -> bytes:
        """Decompress a zlib-compressed payload with zip-bomb protection.

        Decompression is performed incrementally so that output exceeding
        :pyattr:`max_decompressed_size` is detected *before* allocating the
        full buffer.

        Parameters
        ----------
        data:
            Zlib-compressed bytes.

        Returns
        -------
        bytes
            Original uncompressed payload.

        Raises
        ------
        DecompressionError
            If *data* is not valid zlib, the stream is truncated, or the
            decompressed output would exceed :pyattr:`max_decompressed_size`.
        """
        if not isinstance(data, (bytes, bytearray, memoryview)):
            raise DecompressionError(
                f"Expected bytes-like object, got {type(data).__name__}"
            )

        if len(data) == 0:
            raise DecompressionError("Cannot decompress empty data")

        if max_size is not None:
            limit = max_size
        elif isinstance(cls_or_self, type):
            limit = DEFAULT_MAX_DECOMPRESSED_SIZE
        else:
            limit = cls_or_self._max_decompressed_size

        try:
            return cls_or_self._safe_decompress(bytes(data), limit)
        except DecompressionError:
            raise
        except zlib.error as exc:
            raise DecompressionError(
                f"zlib decompression failed: {exc}"
            ) from exc
        except Exception as exc:
            raise DecompressionError(
                f"Unexpected decompression error: {exc}"
            ) from exc

    @classmethod
    def _safe_decompress(cls_or_self, data: bytes, limit: int) -> bytes:
        """Incrementally decompress *data* while enforcing the size limit.

        Uses :class:`zlib.decompressobj` to stream chunks so that a
        maliciously crafted archive (zip bomb) is caught early without
        exhausting memory.
        """
        decompressor = zlib.decompressobj()
        chunks: list[bytes] = []
        total_size: int = 0

        # Feed data in a single pass; decompressobj handles internal
        # buffering and will yield output in chunks.
        chunk = decompressor.decompress(data, limit + 1)
        total_size += len(chunk)
        if total_size > limit:
            raise DecompressionError(
                f"Decompressed output exceeds maximum allowed size of "
                f"{limit:,} bytes — potential zip bomb"
            )
        chunks.append(chunk)

        # Drain any remaining buffered output.
        while decompressor.unconsumed_tail:
            chunk = decompressor.decompress(
                decompressor.unconsumed_tail,
                limit + 1 - total_size,
            )
            total_size += len(chunk)
            if total_size > limit:
                raise DecompressionError(
                    f"Decompressed output exceeds maximum allowed size of "
                    f"{limit:,} bytes — potential zip bomb"
                )
            chunks.append(chunk)

        # Flush any data held in internal buffers.
        remaining = decompressor.flush()
        total_size += len(remaining)
        if total_size > limit:
            raise DecompressionError(
                f"Decompressed output exceeds maximum allowed size of "
                f"{limit:,} bytes — potential zip bomb"
            )
        chunks.append(remaining)

        return b"".join(chunks)

    # -- ratio estimation ---------------------------------------------------

    def estimate_ratio(
        self,
        data: bytes,
        sample_size: int = _DEFAULT_SAMPLE_SIZE,
    ) -> float:
        """Estimate the compression ratio for *data*.

        A sample of up to *sample_size* bytes from the start of *data* is
        compressed, and the ratio ``compressed_size / original_size`` is
        returned.  Values < 1.0 mean the data compresses well.

        Parameters
        ----------
        data:
            Raw bytes to evaluate.
        sample_size:
            Maximum number of bytes to sample (default 64 KiB).

        Returns
        -------
        float
            Estimated compression ratio.  Returns ``1.0`` for empty data
            (compression would not help).

        Raises
        ------
        CompressionError
            If the internal compression call fails.
        """
        if not isinstance(data, (bytes, bytearray, memoryview)):
            raise CompressionError(
                f"Expected bytes-like object, got {type(data).__name__}"
            )

        if sample_size <= 0:
            raise CompressionError(
                f"sample_size must be positive, got {sample_size}"
            )

        if len(data) == 0:
            return 1.0

        sample: bytes = bytes(data[:sample_size])
        try:
            compressed_sample: bytes = zlib.compress(
                sample, _DEFAULT_COMPRESSION_LEVEL
            )
        except zlib.error as exc:
            raise CompressionError(
                f"Ratio estimation failed: {exc}"
            ) from exc

        return len(compressed_sample) / len(sample)

    # -- adaptive decision --------------------------------------------------

    def is_worth_compressing(
        self,
        data: bytes,
        threshold: float = _DEFAULT_THRESHOLD,
    ) -> bool:
        """Decide whether compressing *data* is worthwhile.

        Returns ``True`` when the estimated compression ratio is strictly
        below *threshold* (i.e. the compressed output is at least
        ``(1 - threshold) * 100 %`` smaller).

        Parameters
        ----------
        data:
            Raw bytes to evaluate.
        threshold:
            Ratio ceiling below which compression is considered beneficial.
            The default ``0.9`` means compression must save at least 10 %.

        Returns
        -------
        bool
        """
        if not isinstance(data, (bytes, bytearray, memoryview)):
            raise CompressionError(
                f"Expected bytes-like object, got {type(data).__name__}"
            )

        if not (0.0 < threshold <= 1.0):
            raise CompressionError(
                f"threshold must be in (0.0, 1.0], got {threshold}"
            )

        if len(data) == 0:
            return False

        ratio: float = self.estimate_ratio(data)
        return ratio < threshold

"""
LSB Steganography Engine for SinXTan.

Implements Least Significant Bit (LSB) embedding and extraction for lossless
image formats (PNG, BMP, TIFF) with cryptographically keyed pseudorandom
pixel permutation, configurable bit depth (1-4 bits per channel), and strict
capacity and format validation.
"""

from __future__ import annotations

import hashlib
import os
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

import numpy as np
from PIL import Image

from app.core.container_format import (
    ContainerFormat,
    ContainerHeader,
    InvalidContainerError,
)

__all__ = [
    "StegoEngine",
    "CarrierInfo",
    "StegoError",
    "InsufficientCapacityError",
    "UnsupportedFormatError",
    "EmbeddingError",
    "ExtractionError",
    "STEGO_ALGO_LSB_ID",
    "SUPPORTED_FORMATS",
]

STEGO_ALGO_LSB_ID: Final[int] = 0x01
SUPPORTED_FORMATS: Final[frozenset[str]] = frozenset({"PNG", "BMP", "TIFF"})
_OUTPUT_FORMATS_BY_SUFFIX: Final[dict[str, str]] = {
    ".png": "PNG",
    ".bmp": "BMP",
    ".tif": "TIFF",
    ".tiff": "TIFF",
}

_LENGTH_HEADER_BYTES: Final[int] = 4  # uint32 little-endian length prefix
_HEADER_SEED_INT: Final[int] = int.from_bytes(
    hashlib.sha256(b"SinXTan-Container-Header-v1-Seed").digest()[:16], "little"
)


def _save_lossless_image(image: Image.Image, output_path: str | Path) -> Path:
    """Save a stego image using the lossless format selected by its extension."""
    out = Path(output_path).resolve()
    image_format = _OUTPUT_FORMATS_BY_SUFFIX.get(out.suffix.lower())
    if image_format is None:
        out = out.with_suffix(".png")
        image_format = "PNG"

    out.parent.mkdir(parents=True, exist_ok=True)
    if image_format == "PNG":
        image.save(out, format=image_format, compress_level=6)
    else:
        image.save(out, format=image_format)
    return out


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class StegoError(Exception):
    """Base exception for steganography engine errors."""


class InsufficientCapacityError(StegoError):
    """Raised when the carrier image cannot hold the requested payload."""


class UnsupportedFormatError(StegoError):
    """Raised when an image format is unsupported or lossy (e.g., JPEG)."""


class EmbeddingError(StegoError):
    """Raised when an error occurs during embedding."""


class ExtractionError(StegoError):
    """Raised when payload extraction fails."""


# ---------------------------------------------------------------------------
# Data Structures
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class CarrierInfo:
    """Detailed metadata and capacity analysis for a carrier image."""

    path: Path
    format: str
    width: int
    height: int
    channels: int
    mode: str
    max_capacity_bytes: int  # at bits_per_channel = 1
    is_supported: bool


# ---------------------------------------------------------------------------
# StegoEngine
# ---------------------------------------------------------------------------


class StegoEngine:
    """LSB Steganography engine with keyed pseudorandom permutation."""

    @staticmethod
    def _validate_image_file(image_path: str | Path) -> tuple[Path, Image.Image]:
        path = Path(image_path).resolve()
        if not path.is_file():
            raise FileNotFoundError(f"Carrier image file does not exist: {path}")

        try:
            img = Image.open(path)
        except Exception as exc:
            raise UnsupportedFormatError(f"Unable to read image file: {exc}") from exc

        fmt = (img.format or "").upper()
        if fmt not in SUPPORTED_FORMATS:
            # Check file extension as fallback for formats like BMP or TIFF
            ext = path.suffix.lower().lstrip(".")
            if ext == "png":
                fmt = "PNG"
            elif ext in ("bmp", "dib"):
                fmt = "BMP"
            elif ext in ("tiff", "tif"):
                fmt = "TIFF"
            else:
                raise UnsupportedFormatError(
                    f"Unsupported or lossy image format: '{fmt or ext}'. "
                    f"Supported lossless formats: {', '.join(sorted(SUPPORTED_FORMATS))}"
                )

        return path, img

    @classmethod
    def validate_carrier(cls, image_path: str | Path) -> CarrierInfo:
        """Inspect and return carrier image properties and capacity."""
        path, img = cls._validate_image_file(image_path)
        width, height = img.size
        mode = img.mode

        if mode == "RGB":
            channels = 3
        elif mode == "RGBA":
            channels = 3  # Alpha is preserved untouched
        elif mode in ("L", "1", "P"):
            channels = 1
        else:
            channels = len(mode)

        total_samples = width * height * channels
        max_bytes = max(0, (total_samples - (_LENGTH_HEADER_BYTES * 8)) // 8)

        return CarrierInfo(
            path=path,
            format=(img.format or path.suffix.upper().lstrip(".")),
            width=width,
            height=height,
            channels=channels,
            mode=mode,
            max_capacity_bytes=max_bytes,
            is_supported=True,
        )

    @classmethod
    def estimate_capacity(cls, image_path: str | Path, bits_per_channel: int = 1) -> int:
        """Calculate maximum payload size (in bytes) that can fit in the image.

        Parameters
        ----------
        image_path:
            Path to the carrier image.
        bits_per_channel:
            Number of least significant bits used per channel (1 to 4).
        """
        if not 1 <= bits_per_channel <= 4:
            raise ValueError(f"bits_per_channel must be between 1 and 4, got {bits_per_channel}")

        info = cls.validate_carrier(image_path)
        total_slots = info.width * info.height * info.channels * bits_per_channel
        return max(0, (total_slots - (_LENGTH_HEADER_BYTES * 8)) // 8)

    @staticmethod
    def _derive_rng(embedding_key: bytes) -> np.random.Generator:
        """Derive a reproducible CSPRNG generator from the embedding key."""
        if len(embedding_key) != 32:
            raise ValueError(f"Embedding key must be 32 bytes, got {len(embedding_key)}")

        # Use SHA-256 of the key as seed sequence entropy
        seed_bytes = hashlib.sha256(b"SinXTan-LSB-Permutation-v1:" + embedding_key).digest()
        seed_int = int.from_bytes(seed_bytes[:16], "little")
        return np.random.default_rng(seed_int)

    @classmethod
    def embed(
        cls,
        image_path: str | Path,
        data: bytes,
        embedding_key: bytes,
        bits_per_channel: int = 1,
        output_path: str | Path | None = None,
    ) -> Path:
        """Embed data into carrier image using keyed pseudorandom LSB steganography.

        Parameters
        ----------
        image_path:
            Source image path.
        data:
            Binary payload to embed.
        embedding_key:
            32-byte embedding key for pixel permutation.
        bits_per_channel:
            Number of LSBs per channel (1-4).
        output_path:
            Destination image path (default: creates PNG adjacent to source).

        Returns
        -------
        Path
            Path to the generated steganographic image.
        """
        if not 1 <= bits_per_channel <= 4:
            raise ValueError("bits_per_channel must be between 1 and 4")

        path, img = cls._validate_image_file(image_path)
        b = bits_per_channel

        # Convert image to standard RGB / RGBA / L if indexed or unsupported mode
        orig_mode = img.mode
        if orig_mode not in ("RGB", "RGBA", "L"):
            img = img.convert("RGBA" if "A" in orig_mode else "RGB")

        mode = img.mode
        img_array = np.array(img, dtype=np.uint8)

        # Separate channels if RGBA to preserve alpha transparency untouched
        has_alpha = mode == "RGBA"
        if has_alpha:
            active_channels = img_array[:, :, :3]
            alpha_channel = img_array[:, :, 3]
        elif mode == "RGB":
            active_channels = img_array
            alpha_channel = None
        elif mode == "L":
            active_channels = img_array
            alpha_channel = None
        else:
            active_channels = img_array
            alpha_channel = None

        orig_shape = active_channels.shape
        flat_pixels = active_channels.reshape(-1)
        total_samples = len(flat_pixels)

        # Prepare payload: 4-byte uint32 LE length prefix + data
        payload_len = len(data)
        prefix = struct.pack("<I", payload_len)
        full_payload = prefix + data

        # Convert bytes to bits
        raw_bits = np.unpackbits(np.frombuffer(full_payload, dtype=np.uint8))

        # Pad to multiple of b
        pad_len = (b - (len(raw_bits) % b)) % b
        if pad_len > 0:
            raw_bits = np.pad(raw_bits, (0, pad_len), mode="constant")

        # Convert each group of b bits into an integer in [0, 2^b - 1]
        num_chunks = len(raw_bits) // b
        if num_chunks > total_samples:
            max_bytes = max(0, (total_samples * b - (_LENGTH_HEADER_BYTES * 8)) // 8)
            raise InsufficientCapacityError(
                f"Payload size ({payload_len} bytes) exceeds carrier capacity ({max_bytes} bytes)."
            )

        chunks = np.zeros(num_chunks, dtype=np.uint8)
        for i in range(b):
            chunks = (chunks << 1) | raw_bits[i::b]

        # Generate keyed pseudorandom permutation of sample indices
        rng = cls._derive_rng(embedding_key)
        perm = rng.permutation(total_samples)
        chosen_indices = perm[:num_chunks]

        # Embed bits into chosen channel samples
        mask = np.uint8(~((1 << b) - 1) & 0xFF)
        flat_pixels[chosen_indices] = (flat_pixels[chosen_indices] & mask) | chunks

        # Reconstruct image array
        modified_active = flat_pixels.reshape(orig_shape)
        if has_alpha:
            final_array = np.dstack((modified_active, alpha_channel))
        else:
            final_array = modified_active

        stego_img = Image.fromarray(final_array, mode=mode)

        # Keep PNG as the default while honoring explicitly selected lossless formats.
        if output_path is None:
            out = path.with_name(f"{path.stem}_stego.png")
        else:
            out = Path(output_path).resolve()
        return _save_lossless_image(stego_img, out)

    @classmethod
    def extract(
        cls,
        image_path: str | Path,
        embedding_key: bytes,
        bits_per_channel: int = 1,
    ) -> bytes:
        """Extract embedded data from a steganographic image using the embedding key.

        Parameters
        ----------
        image_path:
            Path to the steganographic image.
        embedding_key:
            32-byte embedding key used during embedding.
        bits_per_channel:
            Number of LSBs per channel (1-4).

        Returns
        -------
        bytes
            The extracted payload data.
        """
        if not 1 <= bits_per_channel <= 4:
            raise ValueError("bits_per_channel must be between 1 and 4")

        path, img = cls._validate_image_file(image_path)
        b = bits_per_channel
        mode = img.mode

        img_array = np.array(img, dtype=np.uint8)
        if mode == "RGBA":
            active_channels = img_array[:, :, :3]
        else:
            active_channels = img_array

        flat_pixels = active_channels.reshape(-1)
        total_samples = len(flat_pixels)

        # Generate the keyed permutation
        rng = cls._derive_rng(embedding_key)
        perm = rng.permutation(total_samples)

        # First extract the 4-byte (32-bit) length header
        num_header_chunks = (32 + b - 1) // b
        if num_header_chunks > total_samples:
            raise ExtractionError("Image too small to contain length header.")

        header_indices = perm[:num_header_chunks]
        header_chunks = flat_pixels[header_indices] & np.uint8((1 << b) - 1)

        # Reconstruct header bits
        header_bits = np.zeros(num_header_chunks * b, dtype=np.uint8)
        for i in range(b):
            header_bits[i::b] = (header_chunks >> (b - 1 - i)) & 1

        header_bytes = np.packbits(header_bits)[:_LENGTH_HEADER_BYTES].tobytes()
        payload_len = struct.unpack("<I", header_bytes)[0]

        # Sanity check payload length
        max_possible_bytes = (total_samples * b - 32) // 8
        if payload_len <= 0 or payload_len > max_possible_bytes:
            raise ExtractionError(
                f"Invalid or corrupted payload length header: {payload_len} bytes "
                f"(max possible: {max_possible_bytes} bytes). Check password or embedding depth."
            )

        # Extract full payload (header + data)
        total_bits_needed = 32 + payload_len * 8
        total_chunks_needed = (total_bits_needed + b - 1) // b

        data_indices = perm[:total_chunks_needed]
        data_chunks = flat_pixels[data_indices] & np.uint8((1 << b) - 1)

        data_bits = np.zeros(total_chunks_needed * b, dtype=np.uint8)
        for i in range(b):
            data_bits[i::b] = (data_chunks >> (b - 1 - i)) & 1

        all_bytes = np.packbits(data_bits)[: _LENGTH_HEADER_BYTES + payload_len].tobytes()
        return all_bytes[_LENGTH_HEADER_BYTES:]

    # -- High-level container integration methods ---------------------------

    @classmethod
    def embed_container(
        cls,
        image_path: str | Path,
        header: ContainerHeader,
        metadata: dict[str, Any],
        encrypted_payload: bytes,
        embedding_key: bytes,
        bits_per_channel: int = 1,
        output_path: str | Path | None = None,
    ) -> Path:
        """Embed a complete SinXTan container into an image.

        The container header and metadata are placed at deterministic pseudo-random
        positions seeded by a known protocol anchor so they can be independently
        inspected without the password. The encrypted payload is placed at keyed
        positions permuted by the derived embedding key.
        """
        import json

        if not 1 <= bits_per_channel <= 4:
            raise ValueError("bits_per_channel must be between 1 and 4")

        path, img = cls._validate_image_file(image_path)
        b = bits_per_channel

        orig_mode = img.mode
        if orig_mode not in ("RGB", "RGBA", "L"):
            img = img.convert("RGBA" if "A" in orig_mode else "RGB")

        mode = img.mode
        img_array = np.array(img, dtype=np.uint8)

        has_alpha = mode == "RGBA"
        if has_alpha:
            active_channels = img_array[:, :, :3]
            alpha_channel = img_array[:, :, 3]
        else:
            active_channels = img_array
            alpha_channel = None

        orig_shape = active_channels.shape
        flat_pixels = active_channels.reshape(-1)
        total_samples = len(flat_pixels)

        # 1. Prepare Header + Metadata bytes
        metadata_bytes = json.dumps(metadata, separators=(",", ":"), sort_keys=True).encode("utf-8")
        header_obj = ContainerHeader(
            version=header.version,
            stego_algo_id=header.stego_algo_id,
            encryption_algo_id=header.encryption_algo_id,
            kdf_id=header.kdf_id,
            kdf_time_cost=header.kdf_time_cost,
            kdf_memory_cost=header.kdf_memory_cost,
            kdf_parallelism=header.kdf_parallelism,
            compression_id=header.compression_id,
            salt=header.salt,
            nonce=header.nonce,
            payload_length=header.payload_length,
            metadata_length=len(metadata_bytes),
        )

        fixed_header = struct.pack(
            "<4sHBBBIIIB32s12sQI",
            b"SXT1",
            header_obj.version,
            header_obj.stego_algo_id,
            header_obj.encryption_algo_id,
            header_obj.kdf_id,
            header_obj.kdf_time_cost,
            header_obj.kdf_memory_cost,
            header_obj.kdf_parallelism,
            header_obj.compression_id,
            header_obj.salt,
            header_obj.nonce,
            header_obj.payload_length,
            len(metadata_bytes),
        )
        full_header_bytes = fixed_header + metadata_bytes

        # Convert header to chunks
        hdr_raw_bits = np.unpackbits(np.frombuffer(full_header_bytes, dtype=np.uint8))
        pad_len_hdr = (b - (len(hdr_raw_bits) % b)) % b
        if pad_len_hdr > 0:
            hdr_raw_bits = np.pad(hdr_raw_bits, (0, pad_len_hdr), mode="constant")
        num_hdr_chunks = len(hdr_raw_bits) // b

        if num_hdr_chunks > total_samples:
            raise InsufficientCapacityError("Carrier image too small to hold container header.")

        hdr_chunks = np.zeros(num_hdr_chunks, dtype=np.uint8)
        for i in range(b):
            hdr_chunks = (hdr_chunks << 1) | hdr_raw_bits[i::b]

        # Header positions from protocol seed
        rng_hdr = np.random.default_rng(_HEADER_SEED_INT)
        hdr_perm = rng_hdr.permutation(total_samples)
        chosen_hdr_indices = hdr_perm[:num_hdr_chunks]

        # Embed header
        mask = np.uint8(~((1 << b) - 1) & 0xFF)
        flat_pixels[chosen_hdr_indices] = (flat_pixels[chosen_hdr_indices] & mask) | hdr_chunks

        # 2. Prepare Encrypted Payload
        payload_raw_bits = np.unpackbits(np.frombuffer(encrypted_payload, dtype=np.uint8))
        pad_len_pay = (b - (len(payload_raw_bits) % b)) % b
        if pad_len_pay > 0:
            payload_raw_bits = np.pad(payload_raw_bits, (0, pad_len_pay), mode="constant")
        num_payload_chunks = len(payload_raw_bits) // b

        # Available slots = all slots except those occupied by header
        mask_available = np.ones(total_samples, dtype=bool)
        mask_available[chosen_hdr_indices] = False
        available_indices = np.arange(total_samples, dtype=np.int32)[mask_available]

        if num_payload_chunks > len(available_indices):
            max_payload_bytes = max(0, (len(available_indices) * b) // 8)
            raise InsufficientCapacityError(
                f"Payload size ({len(encrypted_payload)} bytes) exceeds available carrier capacity ({max_payload_bytes} bytes)."
            )

        payload_chunks = np.zeros(num_payload_chunks, dtype=np.uint8)
        for i in range(b):
            payload_chunks = (payload_chunks << 1) | payload_raw_bits[i::b]

        # Permute available slots with embedding_key
        rng_payload = cls._derive_rng(embedding_key)
        payload_perm = rng_payload.permutation(len(available_indices))
        chosen_payload_indices = available_indices[payload_perm[:num_payload_chunks]]

        # Embed payload
        flat_pixels[chosen_payload_indices] = (flat_pixels[chosen_payload_indices] & mask) | payload_chunks

        # Reconstruct image
        modified_active = flat_pixels.reshape(orig_shape)
        if has_alpha:
            final_array = np.dstack((modified_active, alpha_channel))
        else:
            final_array = modified_active

        stego_img = Image.fromarray(final_array, mode=mode)

        if output_path is None:
            out = path.with_name(f"{path.stem}_secure.png")
        else:
            out = Path(output_path).resolve()
        return _save_lossless_image(stego_img, out)

    @classmethod
    def detect_container(
        cls,
        image_path: str | Path,
        bits_per_channel: int = 1,
    ) -> tuple[ContainerHeader, dict[str, Any]] | None:
        """Inspect an image and attempt to detect and parse a SinXTan container header and metadata.

        Returns (ContainerHeader, metadata_dict) if valid container found, else None.
        """
        import json

        try:
            path, img = cls._validate_image_file(image_path)
        except Exception:
            return None

        # Check all possible bit depths (1 to 4) starting with requested
        depths_to_check = [bits_per_channel] + [d for d in [1, 2, 3, 4] if d != bits_per_channel]

        for b in depths_to_check:
            try:
                img_array = np.array(img, dtype=np.uint8)
                if img.mode == "RGBA":
                    active_channels = img_array[:, :, :3]
                else:
                    active_channels = img_array

                flat_pixels = active_channels.reshape(-1)
                total_samples = len(flat_pixels)

                fixed_size = ContainerFormat.get_header_size()  # 78
                num_fixed_chunks = (fixed_size * 8 + b - 1) // b
                if num_fixed_chunks > total_samples:
                    continue

                rng_hdr = np.random.default_rng(_HEADER_SEED_INT)
                hdr_perm = rng_hdr.permutation(total_samples)

                fixed_indices = hdr_perm[:num_fixed_chunks]
                fixed_chunks = flat_pixels[fixed_indices] & np.uint8((1 << b) - 1)

                fixed_bits = np.zeros(num_fixed_chunks * b, dtype=np.uint8)
                for i in range(b):
                    fixed_bits[i::b] = (fixed_chunks >> (b - 1 - i)) & 1

                fixed_bytes = np.packbits(fixed_bits)[:fixed_size].tobytes()
                if fixed_bytes[:4] != b"SXT1":
                    continue

                header, _ = ContainerFormat.parse_header(fixed_bytes)

                # Extract metadata
                meta_len = header.metadata_length
                if meta_len > 0:
                    num_meta_chunks = (meta_len * 8 + b - 1) // b
                    if num_fixed_chunks + num_meta_chunks > total_samples:
                        continue
                    meta_indices = hdr_perm[num_fixed_chunks : num_fixed_chunks + num_meta_chunks]
                    meta_chunks = flat_pixels[meta_indices] & np.uint8((1 << b) - 1)

                    meta_bits = np.zeros(num_meta_chunks * b, dtype=np.uint8)
                    for i in range(b):
                        meta_bits[i::b] = (meta_chunks >> (b - 1 - i)) & 1

                    meta_bytes = np.packbits(meta_bits)[:meta_len].tobytes()
                    metadata = json.loads(meta_bytes.decode("utf-8"))
                else:
                    metadata = {}

                return header, metadata
            except Exception:
                continue

        return None

    @classmethod
    def extract_container_payload(
        cls,
        image_path: str | Path,
        header: ContainerHeader,
        embedding_key: bytes,
        bits_per_channel: int = 1,
    ) -> bytes:
        """Extract the encrypted payload from a container image using the derived embedding key."""
        if not 1 <= bits_per_channel <= 4:
            raise ValueError("bits_per_channel must be between 1 and 4")

        path, img = cls._validate_image_file(image_path)
        b = bits_per_channel

        img_array = np.array(img, dtype=np.uint8)
        if img.mode == "RGBA":
            active_channels = img_array[:, :, :3]
        else:
            active_channels = img_array

        flat_pixels = active_channels.reshape(-1)
        total_samples = len(flat_pixels)

        # Reconstruct header positions
        fixed_size = ContainerFormat.get_header_size()
        total_hdr_bytes = fixed_size + header.metadata_length
        num_hdr_chunks = (total_hdr_bytes * 8 + b - 1) // b

        rng_hdr = np.random.default_rng(_HEADER_SEED_INT)
        hdr_perm = rng_hdr.permutation(total_samples)
        chosen_hdr_indices = hdr_perm[:num_hdr_chunks]

        # Available slots
        mask_available = np.ones(total_samples, dtype=bool)
        mask_available[chosen_hdr_indices] = False
        available_indices = np.arange(total_samples, dtype=np.int32)[mask_available]

        num_payload_chunks = (header.payload_length * 8 + b - 1) // b
        if num_payload_chunks > len(available_indices):
            raise ExtractionError("Corrupted container: payload exceeds available space.")

        # Permute available slots with embedding_key
        rng_payload = cls._derive_rng(embedding_key)
        payload_perm = rng_payload.permutation(len(available_indices))
        chosen_payload_indices = available_indices[payload_perm[:num_payload_chunks]]

        payload_chunks = flat_pixels[chosen_payload_indices] & np.uint8((1 << b) - 1)

        payload_bits = np.zeros(num_payload_chunks * b, dtype=np.uint8)
        for i in range(b):
            payload_bits[i::b] = (payload_chunks >> (b - 1 - i)) & 1

        return np.packbits(payload_bits)[: header.payload_length].tobytes()

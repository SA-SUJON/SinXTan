"""
Steganography Engine Automated Tests for SinXTan.
"""

from __future__ import annotations

import os
from pathlib import Path
import pytest
from PIL import Image

from app.core.stego_engine import (
    CarrierInfo,
    EmbeddingError,
    ExtractionError,
    InsufficientCapacityError,
    StegoEngine,
    UnsupportedFormatError,
)


@pytest.fixture
def test_png_image(tmp_path: Path) -> Path:
    p = tmp_path / "carrier.png"
    img = Image.new("RGB", (150, 150), color=(80, 120, 160))
    img.save(p)
    return p


@pytest.fixture
def test_rgba_image(tmp_path: Path) -> Path:
    p = tmp_path / "carrier_rgba.png"
    img = Image.new("RGBA", (100, 100), color=(100, 150, 200, 220))
    img.save(p)
    return p


@pytest.fixture
def test_bmp_image(tmp_path: Path) -> Path:
    p = tmp_path / "carrier.bmp"
    img = Image.new("RGB", (100, 100), color=(200, 100, 50))
    img.save(p)
    return p


@pytest.fixture
def test_grayscale_image(tmp_path: Path) -> Path:
    p = tmp_path / "carrier_gray.png"
    img = Image.new("L", (100, 100), color=128)
    img.save(p)
    return p


def test_capacity_estimation(test_png_image: Path) -> None:
    # 150 x 150 x 3 channels = 67,500 samples
    # minus 32 bits (4 bytes) header = 67,468 bits // 8 = 8,433 bytes
    cap = StegoEngine.estimate_capacity(test_png_image, bits_per_channel=1)
    assert cap > 8000
    assert cap < 8500


def test_carrier_validation(test_png_image: Path) -> None:
    info = StegoEngine.validate_carrier(test_png_image)
    assert isinstance(info, CarrierInfo)
    assert info.width == 150
    assert info.height == 150
    assert info.channels == 3
    assert info.format == "PNG"
    assert info.is_supported is True


def test_embed_extract_roundtrip_small(test_png_image: Path, tmp_path: Path) -> None:
    key = os.urandom(32)
    data = b"Small Secret Payload 12345"

    out_path = tmp_path / "out_small.png"
    saved = StegoEngine.embed(test_png_image, data, key, bits_per_channel=1, output_path=out_path)

    extracted = StegoEngine.extract(saved, key, bits_per_channel=1)
    assert extracted == data


def test_embed_extract_roundtrip_medium_binary(test_png_image: Path, tmp_path: Path) -> None:
    key = os.urandom(32)
    data = os.urandom(3000)  # 3 KiB binary

    out_path = tmp_path / "out_binary.png"
    saved = StegoEngine.embed(test_png_image, data, key, bits_per_channel=1, output_path=out_path)

    extracted = StegoEngine.extract(saved, key, bits_per_channel=1)
    assert extracted == data


def test_different_keys_fail_extraction(test_png_image: Path, tmp_path: Path) -> None:
    key1 = os.urandom(32)
    key2 = os.urandom(32)
    data = b"Highly confidential data"

    out_path = tmp_path / "out_diff_key.png"
    saved = StegoEngine.embed(test_png_image, data, key1, bits_per_channel=1, output_path=out_path)

    with pytest.raises(ExtractionError):
        StegoEngine.extract(saved, key2, bits_per_channel=1)


def test_insufficient_capacity_raises(test_png_image: Path) -> None:
    key = os.urandom(32)
    huge_data = os.urandom(50_000)  # Exceeds ~8.4 KiB capacity

    with pytest.raises(InsufficientCapacityError):
        StegoEngine.embed(test_png_image, huge_data, key, bits_per_channel=1)


def test_rgba_image_preserves_alpha(test_rgba_image: Path, tmp_path: Path) -> None:
    key = os.urandom(32)
    data = b"RGBA Carrier Test Data"

    out = tmp_path / "rgba_stego.png"
    saved = StegoEngine.embed(test_rgba_image, data, key, bits_per_channel=1, output_path=out)

    extracted = StegoEngine.extract(saved, key, bits_per_channel=1)
    assert extracted == data

    # Check alpha channel is preserved
    orig_img = Image.open(test_rgba_image)
    saved_img = Image.open(saved)
    assert saved_img.mode == "RGBA"
    assert orig_img.getchannel("A").tobytes() == saved_img.getchannel("A").tobytes()


def test_bmp_carrier_works(test_bmp_image: Path, tmp_path: Path) -> None:
    key = os.urandom(32)
    data = b"BMP Carrier Test Data"

    out = tmp_path / "bmp_stego.png"
    saved = StegoEngine.embed(test_bmp_image, data, key, bits_per_channel=1, output_path=out)

    extracted = StegoEngine.extract(saved, key, bits_per_channel=1)
    assert extracted == data


def test_grayscale_image_works(test_grayscale_image: Path, tmp_path: Path) -> None:
    key = os.urandom(32)
    data = b"Grayscale Carrier Test Data"

    out = tmp_path / "gray_stego.png"
    saved = StegoEngine.embed(test_grayscale_image, data, key, bits_per_channel=1, output_path=out)

    extracted = StegoEngine.extract(saved, key, bits_per_channel=1)
    assert extracted == data


def test_bits_per_channel_2(test_png_image: Path, tmp_path: Path) -> None:
    key = os.urandom(32)
    data = os.urandom(5000)

    out = tmp_path / "b2_stego.png"
    saved = StegoEngine.embed(test_png_image, data, key, bits_per_channel=2, output_path=out)

    extracted = StegoEngine.extract(saved, key, bits_per_channel=2)
    assert extracted == data


def test_unsupported_jpeg_raises(tmp_path: Path) -> None:
    jpg_path = tmp_path / "fake.jpg"
    img = Image.new("RGB", (50, 50), color=(255, 0, 0))
    img.save(jpg_path, format="JPEG")

    key = os.urandom(32)
    with pytest.raises(UnsupportedFormatError):
        StegoEngine.embed(jpg_path, b"test", key)

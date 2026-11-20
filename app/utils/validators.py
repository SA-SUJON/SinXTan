"""
Input and Security Validators for SinXTan.

Provides validation functions for passwords, file paths, image formats,
traversal prevention, and extraction destinations.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Final

__all__ = [
    "PasswordStrength",
    "validate_password_strength",
    "validate_file_path",
    "validate_image_path",
    "validate_output_path",
    "sanitize_filename",
    "check_path_traversal",
    "validate_extraction_destination",
    "SUPPORTED_IMAGE_EXTENSIONS",
]

SUPPORTED_IMAGE_EXTENSIONS: Final[frozenset[str]] = frozenset({".png", ".bmp", ".tiff", ".tif"})
_UNSAFE_CHARS_PATTERN: Final[re.Pattern] = re.compile(r'[<>:"/\\|?*\x00-\x1f]')


@dataclass(frozen=True, slots=True)
class PasswordStrength:
    """Represents the evaluated strength of a user password."""

    score: int  # 0 to 4
    label: str  # Weak, Fair, Good, Strong, Very Strong
    feedback: list[str]
    has_uppercase: bool
    has_lowercase: bool
    has_digits: bool
    has_special: bool
    length: int


def validate_password_strength(password: str) -> PasswordStrength:
    """Evaluate password strength based on entropy, length, and character variety."""
    if not password:
        return PasswordStrength(
            score=0,
            label="Empty",
            feedback=["Password cannot be empty."],
            has_uppercase=False,
            has_lowercase=False,
            has_digits=False,
            has_special=False,
            length=0,
        )

    length = len(password)
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(not c.isalnum() for c in password)

    feedback: list[str] = []
    score = 0

    if length >= 8:
        score += 1
    else:
        feedback.append("Password should be at least 8 characters long.")

    if length >= 14:
        score += 1

    variety_count = sum([has_upper, has_lower, has_digit, has_special])
    if variety_count >= 3:
        score += 1
    else:
        feedback.append("Use a mix of uppercase, lowercase, numbers, and symbols.")

    if length >= 16 and variety_count >= 4:
        score += 1

    # Clamp score to 0..4
    score = max(0, min(4, score))

    labels = {
        0: "Very Weak",
        1: "Weak",
        2: "Fair",
        3: "Strong",
        4: "Very Strong",
    }

    return PasswordStrength(
        score=score,
        label=labels[score],
        feedback=feedback,
        has_uppercase=has_upper,
        has_lowercase=has_lower,
        has_digits=has_digit,
        has_special=has_special,
        length=length,
    )


def validate_file_path(path: str | Path) -> bool:
    """Check if file exists and is readable."""
    try:
        p = Path(path)
        return p.is_file() and os.access(p, os.R_OK)
    except Exception:
        return False


def validate_image_path(path: str | Path) -> bool:
    """Check if file exists, is readable, and has a supported lossless extension."""
    try:
        p = Path(path)
        if not (p.is_file() and os.access(p, os.R_OK)):
            return False
        return p.suffix.lower() in SUPPORTED_IMAGE_EXTENSIONS
    except Exception:
        return False


def validate_output_path(path: str | Path) -> bool:
    """Check if destination directory exists and is writable."""
    try:
        p = Path(path)
        parent = p.parent if p.suffix else p
        return parent.is_dir() and os.access(parent, os.W_OK)
    except Exception:
        return False


def sanitize_filename(name: str) -> str:
    """Sanitize a filename by stripping invalid filesystem characters."""
    sanitized = _UNSAFE_CHARS_PATTERN.sub("_", name)
    sanitized = sanitized.strip(". ")
    return sanitized if sanitized else "extracted_file"


def check_path_traversal(path: str) -> bool:
    """Return True if path contains directory traversal sequences or absolute paths."""
    if not path or "\x00" in path:
        return True

    # Check for absolute path
    if os.path.isabs(path) or path.startswith("/") or path.startswith("\\"):
        return True

    # Check for drive letters (e.g. C:)
    if len(path) >= 2 and path[1] == ":":
        return True

    # Normalize parts
    parts = Path(path).parts
    for part in parts:
        if part in ("..", ".", ""):
            return True

    return False


def validate_extraction_destination(destination: str | Path) -> bool:
    """Verify destination directory exists, is a directory, and is writable."""
    try:
        dest = Path(destination).resolve()
        return dest.is_dir() and os.access(dest, os.W_OK)
    except Exception:
        return False

"""
Key derivation module for SinXTan cryptographic steganography.

Implements Argon2id password-based key derivation with HKDF domain-separated
subkeys for encryption (AES-256-GCM) and embedding (pixel permutation).

Security notes:
    - Passwords and derived keys are never stored or logged.
    - Salts are generated from os.urandom (CSPRNG).
    - Domain separation via HKDF guarantees that compromising one subkey
      does not reveal the other.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Final

import argon2
from argon2.low_level import Type as Argon2Type, hash_secret_raw
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

KDF_ID: Final[int] = 0x01
"""Identifier for Argon2id inside serialised headers."""

_SALT_LENGTH: Final[int] = 32
"""Length of randomly generated salts in bytes."""

_MASTER_KEY_LENGTH: Final[int] = 32
"""Length of the Argon2id-derived master key in bytes."""

_SUBKEY_LENGTH: Final[int] = 32
"""Length of each HKDF-derived subkey in bytes."""

_HKDF_INFO_ENCRYPTION: Final[bytes] = b"SinXTan-v1-encryption-aes256gcm"
"""HKDF info string for the AES-256-GCM encryption subkey."""

_HKDF_INFO_EMBEDDING: Final[bytes] = b"SinXTan-v1-embedding-pixelperm"
"""HKDF info string for the pixel-position permutation subkey."""

# Default Argon2id parameters (OWASP recommended minimum for interactive use)
_DEFAULT_TIME_COST: Final[int] = 3
_DEFAULT_MEMORY_COST: Final[int] = 65_536  # 64 MiB
_DEFAULT_PARALLELISM: Final[int] = 4


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class KDFParams:
    """Immutable container for Argon2id parameters persisted alongside the
    ciphertext so that the same key can be re-derived during extraction.

    Attributes:
        salt: Cryptographically random salt (must be ``_SALT_LENGTH`` bytes).
        time_cost: Number of Argon2id iterations.
        memory_cost: Memory usage in KiB (65 536 = 64 MiB).
        parallelism: Degree of parallelism (threads / lanes).
    """

    salt: bytes
    time_cost: int = _DEFAULT_TIME_COST
    memory_cost: int = _DEFAULT_MEMORY_COST
    parallelism: int = _DEFAULT_PARALLELISM

    def __post_init__(self) -> None:
        if not isinstance(self.salt, bytes) or len(self.salt) < 16:
            raise ValueError(
                f"Salt must be at least 16 bytes, got {len(self.salt) if isinstance(self.salt, bytes) else type(self.salt)}"
            )
        if self.time_cost < 1:
            raise ValueError(f"time_cost must be >= 1, got {self.time_cost}")
        if self.memory_cost < 8:
            raise ValueError(f"memory_cost must be >= 8 KiB, got {self.memory_cost}")
        if self.parallelism < 1:
            raise ValueError(f"parallelism must be >= 1, got {self.parallelism}")


# ---------------------------------------------------------------------------
# Key derivation engine
# ---------------------------------------------------------------------------


class KeyDerivationEngine:
    """Stateless engine for password-based key derivation.

    All public methods are pure functions (no internal state is mutated).
    Passwords and keys are intentionally *not* stored as instance attributes.

    Typical usage::

        engine = KeyDerivationEngine()
        salt = engine.generate_salt()
        params = KDFParams(salt=salt)
        enc_key, emb_key = engine.derive_keys("correct horse battery staple", salt, params)
    """

    # -- salt generation ----------------------------------------------------

    @staticmethod
    def generate_salt() -> bytes:
        """Return a cryptographically secure random 32-byte salt.

        Returns:
            A ``_SALT_LENGTH``-byte random value sourced from :func:`os.urandom`.
        """
        return os.urandom(_SALT_LENGTH)

    # -- master key ---------------------------------------------------------

    @staticmethod
    def derive_master_key(password: str, salt: bytes, params: KDFParams) -> bytes:
        """Derive a 32-byte master key from *password* using Argon2id.

        Args:
            password: User-supplied passphrase (UTF-8 encoded internally).
            salt: Random salt (should come from :meth:`generate_salt`).
            params: Argon2id tuning parameters.

        Returns:
            A ``_MASTER_KEY_LENGTH``-byte master key.

        Raises:
            ValueError: If *password* is empty or *salt* length is incorrect.
            argon2.exceptions.HashingError: On low-level Argon2 failure.
        """
        if not password:
            raise ValueError("Password must not be empty")
        if not isinstance(salt, bytes) or len(salt) < 16:
            raise ValueError(
                f"Salt must be at least 16 bytes, got "
                f"{len(salt) if isinstance(salt, bytes) else type(salt)}"
            )

        master_key: bytes = hash_secret_raw(
            secret=password.encode("utf-8"),
            salt=salt,
            time_cost=params.time_cost,
            memory_cost=params.memory_cost,
            parallelism=params.parallelism,
            hash_len=_MASTER_KEY_LENGTH,
            type=Argon2Type.ID,
        )
        return master_key

    # -- domain-separated subkeys -------------------------------------------

    @staticmethod
    def derive_encryption_key(master_key: bytes) -> bytes:
        """Derive a 32-byte AES-256-GCM encryption subkey via HKDF-SHA256.

        Args:
            master_key: The master key produced by :meth:`derive_master_key`.

        Returns:
            A ``_SUBKEY_LENGTH``-byte encryption key.

        Raises:
            ValueError: If *master_key* is not 32 bytes.
        """
        if not isinstance(master_key, bytes) or len(master_key) != _MASTER_KEY_LENGTH:
            raise ValueError(
                f"master_key must be exactly {_MASTER_KEY_LENGTH} bytes"
            )

        hkdf = HKDF(
            algorithm=SHA256(),
            length=_SUBKEY_LENGTH,
            salt=None,  # salt already incorporated by Argon2id
            info=_HKDF_INFO_ENCRYPTION,
        )
        return hkdf.derive(master_key)

    @staticmethod
    def derive_embedding_key(master_key: bytes) -> bytes:
        """Derive a 32-byte pixel-permutation embedding subkey via HKDF-SHA256.

        Args:
            master_key: The master key produced by :meth:`derive_master_key`.

        Returns:
            A ``_SUBKEY_LENGTH``-byte embedding key.

        Raises:
            ValueError: If *master_key* is not 32 bytes.
        """
        if not isinstance(master_key, bytes) or len(master_key) != _MASTER_KEY_LENGTH:
            raise ValueError(
                f"master_key must be exactly {_MASTER_KEY_LENGTH} bytes"
            )

        hkdf = HKDF(
            algorithm=SHA256(),
            length=_SUBKEY_LENGTH,
            salt=None,
            info=_HKDF_INFO_EMBEDDING,
        )
        return hkdf.derive(master_key)

    # -- convenience --------------------------------------------------------

    @classmethod
    def derive_keys(
        cls_or_self,
        password: str,
        salt: bytes,
        params: KDFParams,
    ) -> tuple[bytes, bytes]:
        """One-shot helper: derive both subkeys from a password.

        Args:
            password: User-supplied passphrase.
            salt: Random salt.
            params: Argon2id tuning parameters.

        Returns:
            A ``(encryption_key, embedding_key)`` tuple, each 32 bytes.
        """
        master_key = cls_or_self.derive_master_key(password, salt, params)
        try:
            encryption_key = cls_or_self.derive_encryption_key(master_key)
            embedding_key = cls_or_self.derive_embedding_key(master_key)
        finally:
            # Best-effort: overwrite the master key in local memory once the
            # subkeys have been derived.  Python does not guarantee immediate
            # deallocation, but we clear the reference as early as possible.
            del master_key

        return encryption_key, embedding_key

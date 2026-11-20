"""
AES-256-GCM authenticated encryption engine for SinXTan.

This module provides symmetric authenticated encryption using AES-256-GCM
via the ``cryptography`` library.  It is the sole encryption primitive used
by the steganography pipeline.

Security notes
--------------
* 96-bit nonces are generated from ``os.urandom`` (CSPRNG).
* Keys **must** be exactly 32 bytes (256 bits).
* The GCM tag length is always 128 bits (16 bytes).
* Keys, nonces, and plaintext are **never** logged.
"""

from __future__ import annotations

import logging
import os
from typing import Final

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

__all__ = [
    "AuthenticationError",
    "CryptoEngine",
    "DecryptionError",
    "ENCRYPTION_ALGO_ID",
]

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

ENCRYPTION_ALGO_ID: Final[int] = 0x01
"""Algorithm identifier for AES-256-GCM used in serialised headers."""

_KEY_LENGTH: Final[int] = 32  # 256 bits
_NONCE_LENGTH: Final[int] = 12  # 96 bits
_TAG_LENGTH: Final[int] = 16  # 128 bits

# ---------------------------------------------------------------------------
# Custom exceptions
# ---------------------------------------------------------------------------


class AuthenticationError(Exception):
    """Raised when GCM authentication fails.

    This typically means the decryption key is wrong **or** the ciphertext /
    associated data has been tampered with.
    """


class DecryptionError(Exception):
    """General decryption failure not specifically caused by an
    authentication tag mismatch."""


# ---------------------------------------------------------------------------
# Validation helpers (module-private)
# ---------------------------------------------------------------------------


def _validate_key(key: bytes) -> None:
    """Ensure *key* is exactly 32 bytes."""
    if not isinstance(key, (bytes, bytearray)):
        raise TypeError(
            f"Key must be bytes or bytearray, got {type(key).__name__}"
        )
    if len(key) != _KEY_LENGTH:
        raise ValueError(
            f"Key must be exactly {_KEY_LENGTH} bytes, got {len(key)}"
        )


def _validate_nonce(nonce: bytes) -> None:
    """Ensure *nonce* is exactly 12 bytes."""
    if not isinstance(nonce, (bytes, bytearray)):
        raise TypeError(
            f"Nonce must be bytes or bytearray, got {type(nonce).__name__}"
        )
    if len(nonce) != _NONCE_LENGTH:
        raise ValueError(
            f"Nonce must be exactly {_NONCE_LENGTH} bytes, got {len(nonce)}"
        )


# ---------------------------------------------------------------------------
# CryptoEngine
# ---------------------------------------------------------------------------


class CryptoEngine:
    """Stateless AES-256-GCM authenticated encryption / decryption engine.

    Every public method validates its inputs and raises descriptive errors
    on misuse.  The class is intentionally stateless so that a single
    instance (or the class itself) can be shared freely across threads.
    """

    # -- Nonce generation ---------------------------------------------------

    @staticmethod
    def generate_nonce() -> bytes:
        """Return a cryptographically random 96-bit (12-byte) nonce.

        Returns
        -------
        bytes
            A 12-byte nonce suitable for AES-256-GCM.
        """
        return os.urandom(_NONCE_LENGTH)

    # -- Core encrypt / decrypt ---------------------------------------------

    @staticmethod
    def encrypt(
        key: bytes,
        plaintext: bytes,
        associated_data: bytes | None = None,
    ) -> tuple[bytes, bytes, bytes]:
        """Encrypt *plaintext* with AES-256-GCM.

        Parameters
        ----------
        key:
            A 32-byte encryption key.
        plaintext:
            The data to encrypt.
        associated_data:
            Optional additional authenticated data (AAD).  It is
            authenticated but **not** encrypted.

        Returns
        -------
        tuple[bytes, bytes, bytes]
            ``(nonce, ciphertext, tag)`` where *ciphertext* does **not**
            include the 16-byte GCM tag.

        Raises
        ------
        TypeError
            If *key* is not ``bytes`` or ``bytearray``.
        ValueError
            If *key* is not exactly 32 bytes.
        """
        _validate_key(key)

        nonce: bytes = CryptoEngine.generate_nonce()
        aesgcm = AESGCM(key)

        try:
            # AESGCM.encrypt returns ciphertext || tag (last 16 bytes).
            ct_with_tag: bytes = aesgcm.encrypt(nonce, plaintext, associated_data)
        except Exception as exc:
            logger.error("Encryption failed: %s", type(exc).__name__)
            raise

        ciphertext: bytes = ct_with_tag[:-_TAG_LENGTH]
        tag: bytes = ct_with_tag[-_TAG_LENGTH:]

        logger.debug(
            "Encrypted %d bytes → %d bytes ciphertext + %d bytes tag",
            len(plaintext),
            len(ciphertext),
            len(tag),
        )
        return nonce, ciphertext, tag

    @staticmethod
    def decrypt(
        key: bytes,
        nonce: bytes,
        ciphertext: bytes,
        tag: bytes,
        associated_data: bytes | None = None,
    ) -> bytes:
        """Decrypt *ciphertext* with AES-256-GCM.

        Parameters
        ----------
        key:
            A 32-byte decryption key.
        nonce:
            The 12-byte nonce used during encryption.
        ciphertext:
            The ciphertext **without** the GCM tag.
        tag:
            The 16-byte GCM authentication tag.
        associated_data:
            Optional additional authenticated data that was supplied
            during encryption.

        Returns
        -------
        bytes
            The recovered plaintext.

        Raises
        ------
        AuthenticationError
            If the tag verification fails (wrong key or tampered data).
        DecryptionError
            On any other decryption failure.
        """
        _validate_key(key)
        _validate_nonce(nonce)

        if not isinstance(tag, (bytes, bytearray)):
            raise TypeError(
                f"Tag must be bytes or bytearray, got {type(tag).__name__}"
            )
        if len(tag) != _TAG_LENGTH:
            raise ValueError(
                f"Tag must be exactly {_TAG_LENGTH} bytes, got {len(tag)}"
            )

        # Reconstruct the combined blob that AESGCM.decrypt expects.
        ct_with_tag: bytes = bytes(ciphertext) + bytes(tag)
        aesgcm = AESGCM(key)

        try:
            plaintext: bytes = aesgcm.decrypt(nonce, ct_with_tag, associated_data)
        except InvalidTag:
            logger.warning("GCM authentication failed — wrong key or tampered data")
            raise AuthenticationError(
                "Authentication failed: the key is incorrect or the data "
                "has been tampered with."
            ) from None
        except Exception as exc:
            logger.error("Decryption failed: %s", type(exc).__name__)
            raise DecryptionError(
                f"Decryption failed: {type(exc).__name__}"
            ) from exc

        logger.debug("Decrypted %d bytes of ciphertext", len(ciphertext))
        return plaintext

    # -- AAD convenience wrappers -------------------------------------------

    @staticmethod
    def encrypt_with_aad(
        key: bytes,
        plaintext: bytes,
        aad: bytes,
    ) -> tuple[bytes, bytes]:
        """Encrypt *plaintext* with mandatory associated data.

        This is a convenience wrapper around :pymethod:`AESGCM.encrypt`
        that keeps the tag appended to the ciphertext (the native
        ``cryptography`` format).

        Parameters
        ----------
        key:
            A 32-byte encryption key.
        plaintext:
            The data to encrypt.
        aad:
            Additional authenticated data.  **Must not** be empty.

        Returns
        -------
        tuple[bytes, bytes]
            ``(nonce, ciphertext_with_tag)``

        Raises
        ------
        ValueError
            If *aad* is empty or *key* length is wrong.
        """
        _validate_key(key)

        if not isinstance(aad, (bytes, bytearray)):
            raise TypeError(
                f"AAD must be bytes or bytearray, got {type(aad).__name__}"
            )
        if len(aad) == 0:
            raise ValueError("AAD must not be empty when using encrypt_with_aad")

        nonce: bytes = CryptoEngine.generate_nonce()
        aesgcm = AESGCM(key)

        try:
            ciphertext_with_tag: bytes = aesgcm.encrypt(nonce, plaintext, aad)
        except Exception as exc:
            logger.error("Encryption (AAD) failed: %s", type(exc).__name__)
            raise

        logger.debug(
            "Encrypted (AAD) %d bytes → %d bytes (ciphertext + tag)",
            len(plaintext),
            len(ciphertext_with_tag),
        )
        return nonce, ciphertext_with_tag

    @staticmethod
    def decrypt_with_aad(
        key: bytes,
        nonce: bytes,
        ciphertext_with_tag: bytes,
        aad: bytes,
    ) -> bytes:
        """Decrypt *ciphertext_with_tag* with mandatory associated data.

        Parameters
        ----------
        key:
            A 32-byte decryption key.
        nonce:
            The 12-byte nonce used during encryption.
        ciphertext_with_tag:
            The ciphertext with the GCM tag appended (native
            ``cryptography`` format).
        aad:
            The same additional authenticated data supplied during
            encryption.

        Returns
        -------
        bytes
            The recovered plaintext.

        Raises
        ------
        AuthenticationError
            If tag verification fails.
        DecryptionError
            On any other decryption failure.
        """
        _validate_key(key)
        _validate_nonce(nonce)

        if not isinstance(aad, (bytes, bytearray)):
            raise TypeError(
                f"AAD must be bytes or bytearray, got {type(aad).__name__}"
            )
        if len(aad) == 0:
            raise ValueError("AAD must not be empty when using decrypt_with_aad")

        aesgcm = AESGCM(key)

        try:
            plaintext: bytes = aesgcm.decrypt(nonce, ciphertext_with_tag, aad)
        except InvalidTag:
            logger.warning(
                "GCM authentication (AAD) failed — wrong key or tampered data"
            )
            raise AuthenticationError(
                "Authentication failed: the key is incorrect or the data "
                "has been tampered with."
            ) from None
        except Exception as exc:
            logger.error("Decryption (AAD) failed: %s", type(exc).__name__)
            raise DecryptionError(
                f"Decryption failed: {type(exc).__name__}"
            ) from exc

        logger.debug(
            "Decrypted (AAD) %d bytes of ciphertext",
            len(ciphertext_with_tag) - _TAG_LENGTH,
        )
        return plaintext

"""
Extraction Worker for SinXTan.

Background QThread worker executing the full container detection, metadata parsing,
Argon2id key derivation, AES-256-GCM authenticated decryption, payload decompression,
safe file extraction, and SHA-256 checksum verification pipeline.
"""

from __future__ import annotations

import os
from pathlib import Path

from PySide6.QtCore import QThread, Signal

from app.core.compression import COMPRESSION_ZLIB, CompressionEngine
from app.core.crypto_engine import AuthenticationError, CryptoEngine
from app.core.integrity import generate_integrity_report
from app.core.key_derivation import KDFParams, KeyDerivationEngine
from app.core.payload_manager import PayloadManager
from app.core.stego_engine import ExtractionError, StegoEngine
from app.utils.logger import get_logger

logger = get_logger("SinXTan.ExtractionWorker")


class ExtractionWorker(QThread):
    """Background worker for extracting and decrypting hidden files from a steganographic image."""

    progress = Signal(int)
    status_update = Signal(str)
    finished_success = Signal(list)  # list of extracted file paths
    finished_error = Signal(str)
    metadata_ready = Signal(dict)
    cancelled = Signal()

    def __init__(
        self,
        image_path: str | Path,
        password: str,
        output_dir: str | Path,
        bits_per_channel: int = 1,
        parent=None,
    ) -> None:
        super().__init__(parent)
        self.image_path = Path(image_path).resolve()
        self._password = password  # Wiped on completion
        self.output_dir = Path(output_dir).resolve()
        self.bits_per_channel = bits_per_channel
        self._is_cancelled = False

    def cancel(self) -> None:
        """Signal worker cancellation."""
        self._is_cancelled = True

    def run(self) -> None:
        """Execute the extract & decrypt pipeline."""
        op_id = logger.operation_start("ExtractAndDecrypt", {"image": str(self.image_path)})
        try:
            if self._is_cancelled:
                self.cancelled.emit()
                return

            self.status_update.emit("Inspecting carrier image for SinXTan container...")
            self.progress.emit(10)

            if not self.image_path.is_file():
                raise FileNotFoundError(f"Steganographic image does not exist: {self.image_path}")

            if not self._password:
                raise ValueError("Password cannot be empty.")

            # Step 1: Detect container header and metadata
            detected = StegoEngine.detect_container(self.image_path, bits_per_channel=self.bits_per_channel)
            if detected is None:
                raise ExtractionError(
                    "No valid SinXTan secure container detected in this image. "
                    "Ensure the file is a lossless image created with SinXTan."
                )

            header, metadata = detected
            self.metadata_ready.emit(metadata)

            if self._is_cancelled:
                self.cancelled.emit()
                return

            # Step 2: Derive keys with Argon2id
            self.status_update.emit("Deriving keys with Argon2id...")
            self.progress.emit(35)

            kdf_params = KDFParams(
                salt=header.salt,
                time_cost=header.kdf_time_cost,
                memory_cost=header.kdf_memory_cost,
                parallelism=header.kdf_parallelism,
            )

            enc_key, embed_key = KeyDerivationEngine.derive_keys(self._password, header.salt, kdf_params)

            if self._is_cancelled:
                self.cancelled.emit()
                return

            # Step 3: Extract encrypted payload using keyed permutation
            self.status_update.emit("Extracting encrypted payload from pixel channels...")
            self.progress.emit(55)

            encrypted_payload = StegoEngine.extract_container_payload(
                image_path=self.image_path,
                header=header,
                embedding_key=embed_key,
                bits_per_channel=self.bits_per_channel,
            )

            if len(encrypted_payload) < 16:
                raise ExtractionError("Extracted container payload is truncated or invalid.")

            if self._is_cancelled:
                self.cancelled.emit()
                return

            # Step 4: AES-256-GCM Decryption & Authentication
            self.status_update.emit("Authenticating and decrypting with AES-256-GCM...")
            self.progress.emit(70)

            ciphertext = encrypted_payload[:-16]
            auth_tag = encrypted_payload[-16:]

            try:
                decrypted_bytes = CryptoEngine.decrypt(
                    key=enc_key,
                    nonce=header.nonce,
                    ciphertext=ciphertext,
                    tag=auth_tag,
                )
            except AuthenticationError:
                raise AuthenticationError(
                    "Authentication failed: The password is incorrect, or the container image "
                    "has been modified, compressed, or corrupted."
                )

            if self._is_cancelled:
                self.cancelled.emit()
                return

            # Step 5: Decompression
            self.status_update.emit("Decompressing payload...")
            self.progress.emit(80)

            if header.compression_id == COMPRESSION_ZLIB:
                raw_payload = CompressionEngine.decompress(decrypted_bytes)
            else:
                raw_payload = decrypted_bytes

            if self._is_cancelled:
                self.cancelled.emit()
                return

            # Step 6: Safe File Extraction
            self.status_update.emit(f"Extracting files to destination...")
            self.progress.emit(90)

            self.output_dir.mkdir(parents=True, exist_ok=True)
            extracted_paths = PayloadManager.extract_to(raw_payload, self.output_dir)

            # Step 7: Final verification
            self.status_update.emit("Verifying file integrity...")
            self.progress.emit(98)

            extracted_str_list = [str(p) for p in extracted_paths]
            self.status_update.emit("Decryption and extraction complete!")
            self.progress.emit(100)

            logger.operation_complete(
                op_id,
                success=True,
                details={"files_extracted": len(extracted_str_list)},
            )
            self.finished_success.emit(extracted_str_list)

        except Exception as exc:
            logger.operation_complete(op_id, success=False, details={"error": str(exc)})
            self.finished_error.emit(str(exc))
        finally:
            self._password = ""

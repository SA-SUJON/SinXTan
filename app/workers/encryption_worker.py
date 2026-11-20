"""
Encryption Worker for SinXTan.

Background QThread worker executing the full file serialization, compression,
Argon2id key derivation, AES-256-GCM authenticated encryption, container assembly,
and LSB steganographic embedding pipeline without blocking the GUI.
"""

from __future__ import annotations

import os
from pathlib import Path

from PySide6.QtCore import QThread, Signal

from app.core.compression import COMPRESSION_NONE, COMPRESSION_ZLIB, CompressionEngine
from app.core.container_format import (
    CONTAINER_VERSION,
    ENCRYPTION_ALGO_AES256GCM,
    KDF_ALGO_ARGON2ID,
    STEGO_ALGO_LSB,
    ContainerFormat,
    ContainerHeader,
)
from app.core.crypto_engine import CryptoEngine
from app.core.key_derivation import KDFParams, KeyDerivationEngine
from app.core.payload_manager import PayloadManager
from app.core.stego_engine import StegoEngine
from app.utils.logger import get_logger

logger = get_logger("SinXTan.EncryptionWorker")


class EncryptionWorker(QThread):
    """Background worker for encrypting and hiding files inside a carrier image."""

    progress = Signal(int)
    status_update = Signal(str)
    finished_success = Signal(str)  # output image path
    finished_error = Signal(str)
    cancelled = Signal()

    def __init__(
        self,
        carrier_image_path: str | Path,
        file_paths: list[str | Path],
        password: str,
        output_path: str | Path | None = None,
        use_compression: bool = True,
        bits_per_channel: int = 1,
        time_cost: int = 3,
        memory_cost: int = 65536,
        parallelism: int = 4,
        parent=None,
    ) -> None:
        super().__init__(parent)
        self.carrier_image_path = Path(carrier_image_path).resolve()
        self.file_paths = [Path(p).resolve() for p in file_paths]
        self._password = password  # Kept in memory only during worker lifetime
        self.output_path = Path(output_path).resolve() if output_path else None
        self.use_compression = use_compression
        self.bits_per_channel = bits_per_channel
        self.time_cost = time_cost
        self.memory_cost = memory_cost
        self.parallelism = parallelism

        self._is_cancelled = False

    def cancel(self) -> None:
        """Signal worker cancellation."""
        self._is_cancelled = True

    def run(self) -> None:
        """Execute the encrypt & hide pipeline."""
        op_id = logger.operation_start("EncryptAndEmbed", {"files_count": len(self.file_paths)})
        try:
            if self._is_cancelled:
                self.cancelled.emit()
                return

            self.status_update.emit("Validating carrier image and files...")
            self.progress.emit(5)

            if not self.carrier_image_path.is_file():
                raise FileNotFoundError(f"Carrier image does not exist: {self.carrier_image_path}")

            if not self.file_paths:
                raise ValueError("No files or folders selected for embedding.")

            if not self._password:
                raise ValueError("Password cannot be empty.")

            if self._is_cancelled:
                self.cancelled.emit()
                return

            # Step 1: Serialize files
            self.status_update.emit("Serializing files into container payload...")
            self.progress.emit(15)

            # Check if single item is a directory
            if len(self.file_paths) == 1 and self.file_paths[0].is_dir():
                payload_bytes = PayloadManager.serialize_directory(self.file_paths[0])
                filenames = [f"{self.file_paths[0].name}/"]
            else:
                # Separate any directories from files
                all_files: list[Path] = []
                for p in self.file_paths:
                    if p.is_dir():
                        all_files.extend([f for f in p.rglob("*") if f.is_file()])
                    elif p.is_file():
                        all_files.append(p)
                if not all_files:
                    raise ValueError("No valid files found in selected paths.")
                payload_bytes = PayloadManager.serialize_files(all_files)
                filenames = [p.name for p in self.file_paths]

            original_payload_size = len(payload_bytes)

            if self._is_cancelled:
                self.cancelled.emit()
                return

            # Step 2: Compression (if enabled)
            self.status_update.emit("Compressing payload...")
            self.progress.emit(30)

            if self.use_compression:
                processed_payload = CompressionEngine.compress(payload_bytes)
                compression_id = COMPRESSION_ZLIB
            else:
                processed_payload = payload_bytes
                compression_id = COMPRESSION_NONE

            if self._is_cancelled:
                self.cancelled.emit()
                return

            # Step 3: Key Derivation
            self.status_update.emit("Deriving keys with Argon2id (memory-hard)...")
            self.progress.emit(45)

            salt = KeyDerivationEngine.generate_salt()
            kdf_params = KDFParams(
                salt=salt,
                time_cost=self.time_cost,
                memory_cost=self.memory_cost,
                parallelism=self.parallelism,
            )

            enc_key, embed_key = KeyDerivationEngine.derive_keys(self._password, salt, kdf_params)

            if self._is_cancelled:
                self.cancelled.emit()
                return

            # Step 4: AES-256-GCM Encryption
            self.status_update.emit("Encrypting payload with AES-256-GCM...")
            self.progress.emit(60)

            nonce, ciphertext, tag = CryptoEngine.encrypt(enc_key, processed_payload)
            encrypted_payload = ciphertext + tag

            if self._is_cancelled:
                self.cancelled.emit()
                return

            # Step 5 & 6: Container Assembly & Steganographic Embedding
            self.status_update.emit("Embedding encrypted container into image pixels...")
            self.progress.emit(75)

            metadata = {
                "files": filenames,
                "file_count": len(filenames),
                "original_size": original_payload_size,
                "compressed_size": len(processed_payload),
                "bits_per_channel": self.bits_per_channel,
            }

            header = ContainerHeader(
                version=CONTAINER_VERSION,
                stego_algo_id=STEGO_ALGO_LSB,
                encryption_algo_id=ENCRYPTION_ALGO_AES256GCM,
                kdf_id=KDF_ALGO_ARGON2ID,
                kdf_time_cost=self.time_cost,
                kdf_memory_cost=self.memory_cost,
                kdf_parallelism=self.parallelism,
                compression_id=compression_id,
                salt=salt,
                nonce=nonce,
                payload_length=len(encrypted_payload),
                metadata_length=0,
            )

            if self._is_cancelled:
                self.cancelled.emit()
                return

            final_image_path = StegoEngine.embed_container(
                image_path=self.carrier_image_path,
                header=header,
                metadata=metadata,
                encrypted_payload=encrypted_payload,
                embedding_key=embed_key,
                bits_per_channel=self.bits_per_channel,
                output_path=self.output_path,
            )

            if self._is_cancelled:
                self.cancelled.emit()
                return

            # Step 7: Integrity verification of output
            self.status_update.emit("Verifying container in generated image...")
            self.progress.emit(90)

            # Test detect and verify
            det = StegoEngine.detect_container(final_image_path, bits_per_channel=self.bits_per_channel)
            if det is None:
                raise RuntimeError("Integrity verification failed on newly embedded container.")

            self.status_update.emit("Encryption and embedding complete!")
            self.progress.emit(100)
            logger.operation_complete(op_id, success=True, details={"output": str(final_image_path)})
            self.finished_success.emit(str(final_image_path))

        except Exception as exc:
            logger.operation_complete(op_id, success=False, details={"error": str(exc)})
            self.finished_error.emit(str(exc))
        finally:
            self._password = ""  # Wipe from instance attribute

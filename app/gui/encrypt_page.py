"""
Encrypt & Hide Page for SinXTan.
"""

from __future__ import annotations

import os
from pathlib import Path

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
)

from app.core.stego_engine import StegoEngine
from app.gui.components.file_drop_zone import FileDropZone
from app.gui.components.image_preview import ImagePreviewWidget
from app.gui.components.password_input import PasswordInputWidget
from app.gui.components.progress_card import ProgressCard
from app.gui.page_header import add_page_header
from app.workers.encryption_worker import EncryptionWorker


class EncryptPage(QWidget):
    """Encrypt & Hide interface allowing users to select carrier images and files,
    configure security parameters, and run the embedding pipeline."""

    operation_completed = Signal(str)

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._worker: EncryptionWorker | None = None

        self._setup_ui()

    def _setup_ui(self) -> None:
        outer_layout = QVBoxLayout(self)
        outer_layout.setContentsMargins(0, 0, 0, 0)

        # Scroll area container for small screens
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        scroll.setFrameShape(QFrame.Shape.NoFrame)

        container = QWidget()
        container.setObjectName("scrollContent")
        layout = QVBoxLayout(container)
        layout.setContentsMargins(36, 28, 36, 28)
        layout.setSpacing(18)

        add_page_header(
            layout,
            "ENCRYPT & HIDE",
            "Create a secure image container",
            "Choose a lossless carrier, add files, and protect the container with a passphrase.",
        )

        # 2. Main Content Two-Column or Horizontal Layout
        content_row = QHBoxLayout()
        content_row.setSpacing(18)

        # Left Column: Carrier Image & Files
        left_col = QVBoxLayout()
        left_col.setSpacing(16)

        self.carrier_widget = ImagePreviewWidget(title="Carrier image")
        self.carrier_widget.image_selected.connect(self._update_capacity_check)
        left_col.addWidget(self.carrier_widget)

        files_label = QLabel("Files to conceal")
        files_label.setObjectName("formSectionTitle")
        left_col.addWidget(files_label)

        self.drop_zone = FileDropZone()
        self.drop_zone.files_changed.connect(self._update_capacity_check)
        left_col.addWidget(self.drop_zone)

        content_row.addLayout(left_col, stretch=1)

        # Right Column: Security, Output & Parameters
        right_col = QVBoxLayout()
        right_col.setSpacing(16)

        # Security Card
        sec_card = QFrame()
        sec_card.setObjectName("surfaceCard")
        sec_layout = QVBoxLayout(sec_card)
        sec_layout.setContentsMargins(18, 18, 18, 18)
        sec_layout.setSpacing(12)

        sec_title = QLabel("Security & output settings")
        sec_title.setObjectName("formSectionTitle")
        sec_layout.addWidget(sec_title)

        self.pw_widget = PasswordInputWidget(require_confirmation=True)
        sec_layout.addWidget(self.pw_widget)

        # Embedding Options
        opt_label = QLabel("Advanced Parameters")
        opt_label.setObjectName("formLabel")
        sec_layout.addWidget(opt_label)

        opts_row = QHBoxLayout()
        b_label = QLabel("Bits per Channel:")
        b_label.setObjectName("formLabel")
        opts_row.addWidget(b_label)

        self.bits_combo = QComboBox()
        self.bits_combo.addItems(["1 bit (Maximum Stealth)", "2 bits (Balanced)", "3 bits (Higher Capacity)", "4 bits (Maximum Capacity)"])
        self.bits_combo.currentIndexChanged.connect(self._update_capacity_check)
        opts_row.addWidget(self.bits_combo)
        sec_layout.addLayout(opts_row)

        self.compress_chk = QCheckBox("Enable zlib Payload Compression")
        self.compress_chk.setChecked(True)
        sec_layout.addWidget(self.compress_chk)

        # Output Destination Row
        dest_label = QLabel("Output Steganographic Image")
        dest_label.setObjectName("formLabel")
        sec_layout.addWidget(dest_label)

        dest_row = QHBoxLayout()
        self.dest_edit = QLineEdit()
        self.dest_edit.setPlaceholderText("Auto-generated (adjacent to carrier)...")
        dest_row.addWidget(self.dest_edit)

        self.browse_dest_btn = QPushButton("Browse")
        self.browse_dest_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.browse_dest_btn.clicked.connect(self._browse_destination)
        dest_row.addWidget(self.browse_dest_btn)

        sec_layout.addLayout(dest_row)
        right_col.addWidget(sec_card)

        # Capacity Status Indicator Card
        self.cap_card = QFrame()
        self.cap_card.setObjectName("statusCardNeutral")
        self.cap_card.setMaximumHeight(96)
        self.cap_card.setSizePolicy(QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Maximum)
        cap_layout = QHBoxLayout(self.cap_card)
        cap_layout.setContentsMargins(14, 12, 14, 12)
        self.cap_status_label = QLabel("Select a carrier image and files to check capacity.")
        self.cap_status_label.setObjectName("capacityStatus")
        self.cap_status_label.setWordWrap(True)
        cap_layout.addWidget(self.cap_status_label)
        right_col.addWidget(self.cap_card)

        # Start Button
        self.start_btn = QPushButton("Start Encryption & Embedding")
        self.start_btn.setObjectName("primaryButton")
        self.start_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.start_btn.setFixedHeight(48)
        self.start_btn.clicked.connect(self._start_operation)
        right_col.addWidget(self.start_btn)

        # Progress Monitor (hidden by default)
        self.progress_card = ProgressCard()
        self.progress_card.cancel_requested.connect(self._cancel_operation)
        self.progress_card.hide()
        right_col.addWidget(self.progress_card)

        content_row.addLayout(right_col, stretch=1)
        layout.addLayout(content_row)

        scroll.setWidget(container)
        outer_layout.addWidget(scroll)

    def _browse_destination(self) -> None:
        image_filters = "PNG Image (*.png);;BMP Image (*.bmp);;TIFF Image (*.tif *.tiff)"
        file_path, selected_filter = QFileDialog.getSaveFileName(
            self,
            "Save Encrypted Image As",
            "",
            image_filters,
            "PNG Image (*.png)",
        )
        if not file_path:
            return

        destination = Path(file_path)
        supported_suffixes = {".png", ".bmp", ".tif", ".tiff"}
        if destination.suffix.lower() not in supported_suffixes:
            if destination.suffix:
                QMessageBox.warning(
                    self,
                    "Unsupported Image Format",
                    "Choose a PNG, BMP, or TIFF output image.",
                )
                return

            extension_by_filter = {
                "PNG Image (*.png)": ".png",
                "BMP Image (*.bmp)": ".bmp",
                "TIFF Image (*.tif *.tiff)": ".tiff",
            }
            extension = extension_by_filter.get(selected_filter, ".png")
            destination = destination.with_suffix(extension)

        self.dest_edit.setText(str(destination))

    def _get_bits_per_channel(self) -> int:
        return self.bits_combo.currentIndex() + 1

    def _update_capacity_check(self) -> None:
        carrier_path = self.carrier_widget.get_image_path()
        selected_files = self.drop_zone.get_files()
        b = self._get_bits_per_channel()

        if not carrier_path or not selected_files:
            self.cap_card.setObjectName("statusCardNeutral")
            self.cap_status_label.setObjectName("capacityStatus")
            self.cap_status_label.setText("Select a carrier image and files to evaluate capacity.")
            return

        total_file_bytes = self.drop_zone.get_total_size()
        capacity_bytes = StegoEngine.estimate_capacity(carrier_path, bits_per_channel=b)

        needed_mb = total_file_bytes / (1024 * 1024)
        cap_mb = capacity_bytes / (1024 * 1024)

        if total_file_bytes <= capacity_bytes:
            self.cap_card.setObjectName("statusCardSuccess")
            self.cap_status_label.setObjectName("capacityStatusSuccess")
            self.cap_status_label.setText(
                f"✓ Capacity OK: Need {needed_mb:.2f} MB / Carrier holds {cap_mb:.2f} MB"
            )
        else:
            self.cap_card.setObjectName("statusCardError")
            self.cap_status_label.setObjectName("capacityStatusError")
            self.cap_status_label.setText(
                f"✕ Insufficient Capacity: Need {needed_mb:.2f} MB, but image holds only {cap_mb:.2f} MB. Choose a larger image or increase bits per channel."
            )

    def _start_operation(self) -> None:
        carrier = self.carrier_widget.get_image_path()
        if not carrier:
            QMessageBox.warning(self, "Carrier Required", "Please select a carrier image.")
            return

        files = self.drop_zone.get_files()
        if not files:
            QMessageBox.warning(self, "Files Required", "Please add at least one file or folder to conceal.")
            return

        if not self.pw_widget.is_valid():
            QMessageBox.warning(
                self,
                "Password Required",
                "Please enter a valid master password and ensure confirmation matches.",
            )
            return

        password = self.pw_widget.get_password()
        output_path = self.dest_edit.text().strip() or None
        b = self._get_bits_per_channel()

        # UI State transition
        self.start_btn.setEnabled(False)
        self.progress_card.reset()
        self.progress_card.show()

        # Instantiate background worker
        self._worker = EncryptionWorker(
            carrier_image_path=carrier,
            file_paths=files,
            password=password,
            output_path=output_path,
            use_compression=self.compress_chk.isChecked(),
            bits_per_channel=b,
        )

        self._worker.progress.connect(self.progress_card.set_progress)
        self._worker.status_update.connect(self.progress_card.set_status)
        self._worker.finished_success.connect(self._on_success)
        self._worker.finished_error.connect(self._on_error)
        self._worker.cancelled.connect(self._on_cancelled)

        self._worker.start()

    def _cancel_operation(self) -> None:
        if self._worker and self._worker.isRunning():
            self._worker.cancel()
            self.progress_card.set_status("Cancelling operation...")

    def _on_success(self, output_path: str) -> None:
        self.progress_card.set_complete(
            True,
            f"Image saved successfully to:\n{output_path}",
        )
        self.start_btn.setEnabled(True)
        self.operation_completed.emit(output_path)
        QMessageBox.information(
            self,
            "Operation Successful",
            f"Files have been encrypted and concealed!\n\nOutput image:\n{output_path}",
        )

    def _on_error(self, err_msg: str) -> None:
        self.progress_card.set_error(err_msg)
        self.start_btn.setEnabled(True)
        QMessageBox.critical(self, "Encryption Error", f"Operation failed:\n{err_msg}")

    def _on_cancelled(self) -> None:
        self.progress_card.set_status("Operation was cancelled.")
        self.start_btn.setEnabled(True)

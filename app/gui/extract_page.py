"""
Extract & Decrypt Page for SinXTan.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMessageBox,
    QPushButton,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)

from app.core.stego_engine import StegoEngine
from app.gui.components.image_preview import ImagePreviewWidget
from app.gui.components.password_input import PasswordInputWidget
from app.gui.components.progress_card import ProgressCard
from app.gui.page_header import add_page_header
from app.workers.extraction_worker import ExtractionWorker


class ExtractPage(QWidget):
    """Extract & Decrypt interface allowing users to inspect carrier images,
    enter master passwords, and extract authenticated digital payloads."""

    operation_completed = Signal(list)

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._worker: ExtractionWorker | None = None
        self._last_output_dir: Path | None = None

        self._setup_ui()

    def _setup_ui(self) -> None:
        outer_layout = QVBoxLayout(self)
        outer_layout.setContentsMargins(0, 0, 0, 0)

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
            "EXTRACT & RECOVER",
            "Recover files from a container",
            "Inspect a lossless image, enter its passphrase, and choose where recovered files should go.",
        )

        # 2. Main Two-Column Layout
        content_row = QHBoxLayout()
        content_row.setSpacing(18)

        # Left Column: Image Selection & Container Detection Inspection
        left_col = QVBoxLayout()
        left_col.setSpacing(16)

        self.image_widget = ImagePreviewWidget(title="Container image")
        self.image_widget.image_selected.connect(self._on_image_selected)
        left_col.addWidget(self.image_widget)

        # Container Inspection Info Card
        self.info_card = QFrame()
        self.info_card.setObjectName("statusCardNeutral")
        info_layout = QVBoxLayout(self.info_card)
        info_layout.setContentsMargins(18, 18, 18, 18)
        info_layout.setSpacing(8)

        card_title = QLabel("Container Metadata Inspection")
        card_title.setObjectName("formSectionTitle")
        info_layout.addWidget(card_title)

        self.detect_status_label = QLabel("No image selected. Choose an image to inspect container.")
        self.detect_status_label.setObjectName("detectStatus")
        self.detect_status_label.setWordWrap(True)
        info_layout.addWidget(self.detect_status_label)

        self.details_label = QLabel("")
        self.details_label.setObjectName("statusDetails")
        self.details_label.setWordWrap(True)
        info_layout.addWidget(self.details_label)

        left_col.addWidget(self.info_card)
        content_row.addLayout(left_col, stretch=1)

        # Right Column: Decryption, Destination, Progress & Extracted Files
        right_col = QVBoxLayout()
        right_col.setSpacing(16)

        dec_card = QFrame()
        dec_card.setObjectName("surfaceCard")
        dec_layout = QVBoxLayout(dec_card)
        dec_layout.setContentsMargins(18, 18, 18, 18)
        dec_layout.setSpacing(12)

        dec_title = QLabel("Decryption & destination")
        dec_title.setObjectName("formSectionTitle")
        dec_layout.addWidget(dec_title)

        self.pw_widget = PasswordInputWidget(require_confirmation=False)
        dec_layout.addWidget(self.pw_widget)

        dest_label = QLabel("Destination Directory")
        dest_label.setObjectName("formLabel")
        dec_layout.addWidget(dest_label)

        dest_row = QHBoxLayout()
        self.dest_edit = QLineEdit()
        self.dest_edit.setPlaceholderText("Extraction folder destination...")
        dest_row.addWidget(self.dest_edit)

        self.browse_dest_btn = QPushButton("Browse")
        self.browse_dest_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.browse_dest_btn.clicked.connect(self._browse_destination)
        dest_row.addWidget(self.browse_dest_btn)

        dec_layout.addLayout(dest_row)
        right_col.addWidget(dec_card)

        # Action Button
        self.start_btn = QPushButton("Extract & Decrypt Container")
        self.start_btn.setObjectName("primaryButton")
        self.start_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.start_btn.setFixedHeight(48)
        self.start_btn.clicked.connect(self._start_operation)
        right_col.addWidget(self.start_btn)

        # Progress Monitor
        self.progress_card = ProgressCard()
        self.progress_card.cancel_requested.connect(self._cancel_operation)
        self.progress_card.hide()
        right_col.addWidget(self.progress_card)

        # Results Card
        self.results_card = QFrame()
        self.results_card.setObjectName("surfaceCard")
        results_layout = QVBoxLayout(self.results_card)
        results_layout.setContentsMargins(18, 18, 18, 18)
        results_layout.setSpacing(10)

        res_hdr = QHBoxLayout()
        res_title = QLabel("Extracted Files & Integrity Status")
        res_title.setObjectName("formSectionTitle")
        res_hdr.addWidget(res_title)
        res_hdr.addStretch()

        self.open_folder_btn = QPushButton("Open Output Folder")
        self.open_folder_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.open_folder_btn.clicked.connect(self._open_output_folder)
        self.open_folder_btn.setEnabled(False)
        res_hdr.addWidget(self.open_folder_btn)

        results_layout.addLayout(res_hdr)

        self.extracted_list = QListWidget()
        self.extracted_list.setMinimumHeight(104)
        self.extracted_list.setMaximumHeight(160)
        results_layout.addWidget(self.extracted_list)

        self.results_card.hide()
        right_col.addWidget(self.results_card)

        content_row.addLayout(right_col, stretch=1)
        layout.addLayout(content_row)

        scroll.setWidget(container)
        outer_layout.addWidget(scroll)

    def _browse_destination(self) -> None:
        folder = QFileDialog.getExistingDirectory(
            self,
            "Select Extraction Destination Directory",
            "",
        )
        if folder:
            self.dest_edit.setText(folder)

    def _on_image_selected(self, image_path: str) -> None:
        p = Path(image_path)
        # Default destination folder adjacent to image
        default_out = p.parent / f"extracted_{p.stem}"
        self.dest_edit.setText(str(default_out))

        # Inspect container
        det = StegoEngine.detect_container(p)
        if det is not None:
            header, meta = det
            self.info_card.setObjectName("statusCardSuccess")
            self.detect_status_label.setText("✓ SinXTan Secure Container Detected")
            self.detect_status_label.setStyleSheet("font-size: 12px; font-weight: 700; color: #187050;")

            files_info = meta.get("files", [])
            file_count = meta.get("file_count", len(files_info))
            orig_size = meta.get("original_size", 0)
            orig_mb = orig_size / (1024 * 1024)

            details_text = (
                f"• Container Version: {header.version}\n"
                f"• Encryption: AES-256-GCM (Authenticated)\n"
                f"• Key Derivation: Argon2id (Cost: {header.kdf_time_cost}, Mem: {header.kdf_memory_cost // 1024} MB)\n"
                f"• Compression: {'zlib' if header.compression_id == 1 else 'None'}\n"
                f"• Enclosed Files: {file_count} item(s) (~{orig_mb:.2f} MB)"
            )
            self.details_label.setText(details_text)
        else:
            self.info_card.setObjectName("statusCardNeutral")
            self.detect_status_label.setText("No SinXTan container signature detected in this image.")
            self.detect_status_label.setStyleSheet("font-size: 11px; font-weight: 500; color: #718095;")
            self.details_label.setText("If the container uses custom depth, you can still attempt decryption.")

    def _start_operation(self) -> None:
        img_path = self.image_widget.get_image_path()
        if not img_path:
            QMessageBox.warning(self, "Image Required", "Please select a steganographic image.")
            return

        password = self.pw_widget.get_password()
        if not password:
            QMessageBox.warning(self, "Password Required", "Please enter the decryption password.")
            return

        out_dir = self.dest_edit.text().strip()
        if not out_dir:
            out_dir = str(Path(img_path).parent / f"extracted_{Path(img_path).stem}")
            self.dest_edit.setText(out_dir)

        self._last_output_dir = Path(out_dir)

        self.start_btn.setEnabled(False)
        self.progress_card.reset()
        self.progress_card.show()
        self.results_card.hide()
        self.extracted_list.clear()

        self._worker = ExtractionWorker(
            image_path=img_path,
            password=password,
            output_dir=out_dir,
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

    def _on_success(self, file_paths: list) -> None:
        self.progress_card.set_complete(
            True,
            f"Successfully extracted {len(file_paths)} file(s) with verified SHA-256 integrity.",
        )
        self.start_btn.setEnabled(True)

        self.extracted_list.clear()
        for p in file_paths:
            path_obj = Path(p)
            item = QListWidgetItem(f"✓  {path_obj.name}  [Authenticated]")
            item.setForeground(Qt.GlobalColor.darkGreen)
            self.extracted_list.addItem(item)

        self.open_folder_btn.setEnabled(True)
        self.results_card.show()
        self.operation_completed.emit(file_paths)

        QMessageBox.information(
            self,
            "Extraction Complete",
            f"Successfully authenticated and extracted {len(file_paths)} item(s) to:\n{self._last_output_dir}",
        )

    def _on_error(self, err_msg: str) -> None:
        self.progress_card.set_error(err_msg)
        self.start_btn.setEnabled(True)
        QMessageBox.critical(
            self,
            "Decryption Failed",
            f"Extraction failed:\n\n{err_msg}\n\n"
            "Please verify that the password is correct and that the image has not been compressed or altered.",
        )

    def _on_cancelled(self) -> None:
        self.progress_card.set_status("Operation was cancelled.")
        self.start_btn.setEnabled(True)

    def _open_output_folder(self) -> None:
        if self._last_output_dir and self._last_output_dir.is_dir():
            if os.name == "nt":
                os.startfile(str(self._last_output_dir))
            else:
                subprocess.Popen(["xdg-open", str(self._last_output_dir)])

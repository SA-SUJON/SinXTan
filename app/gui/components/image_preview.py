"""
Carrier Image Preview and Capacity Analysis Widget for SinXTan.
"""

from __future__ import annotations

import os
from pathlib import Path

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QDragEnterEvent, QDropEvent, QPixmap
from PySide6.QtWidgets import (
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from app.core.stego_engine import StegoEngine


class ImagePreviewWidget(QWidget):
    """Visual preview and capacity inspector for carrier and steganographic images."""

    image_selected = Signal(str)

    def __init__(self, title: str = "Carrier Image", parent=None) -> None:
        super().__init__(parent)
        self.setAcceptDrops(True)
        self.setObjectName("surfaceCard")
        self._title = title
        self._image_path: Path | None = None

        self._setup_ui()

    def _setup_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(18, 18, 18, 18)
        layout.setSpacing(11)

        # Header row
        hdr_row = QHBoxLayout()
        title_label = QLabel(self._title)
        title_label.setObjectName("formSectionTitle")
        hdr_row.addWidget(title_label)
        hdr_row.addStretch()

        self.browse_btn = QPushButton("Select Image")
        self.browse_btn.setObjectName("secondaryButton")
        self.browse_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.browse_btn.clicked.connect(self._browse)
        hdr_row.addWidget(self.browse_btn)

        layout.addLayout(hdr_row)

        # Thumbnail area
        self.thumb_label = QLabel("No image selected\n(Drag & drop PNG, BMP, or TIFF here)")
        self.thumb_label.setObjectName("thumbBox")
        self.thumb_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.thumb_label.setFixedSize(284, 152)
        layout.addWidget(self.thumb_label, alignment=Qt.AlignmentFlag.AlignCenter)

        # Info metadata labels
        self.info_label = QLabel("Dimensions: --  |  Format: --  |  Size: --")
        self.info_label.setObjectName("imageMetadata")
        self.info_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self.info_label)

        self.capacity_label = QLabel("Max Storage Capacity: 0 B")
        self.capacity_label.setObjectName("imageCapacity")
        self.capacity_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self.capacity_label)

    def dragEnterEvent(self, event: QDragEnterEvent) -> None:
        if event.mimeData().hasUrls():
            event.acceptProposedAction()

    def dropEvent(self, event: QDropEvent) -> None:
        urls = event.mimeData().urls()
        if urls:
            path = Path(urls[0].toLocalFile()).resolve()
            if path.suffix.lower() in (".png", ".bmp", ".tiff", ".tif"):
                self.set_image(path)

    def _browse(self) -> None:
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            f"Select {self._title}",
            "",
            "Lossless Images (*.png *.bmp *.tiff *.tif)",
        )
        if file_path:
            self.set_image(file_path)

    def set_image(self, path: str | Path) -> None:
        p = Path(path).resolve()
        if not p.is_file():
            return

        try:
            info = StegoEngine.validate_carrier(p)
            self._image_path = p

            # Display scaled pixmap
            pixmap = QPixmap(str(p))
            scaled = pixmap.scaled(
                264, 140,
                Qt.AspectRatioMode.KeepAspectRatio,
                Qt.TransformationMode.SmoothTransformation,
            )
            self.thumb_label.setPixmap(scaled)

            file_size_mb = p.stat().st_size / (1024 * 1024)
            self.info_label.setText(
                f"{info.width} × {info.height}  |  {info.format} ({info.mode})  |  {file_size_mb:.2f} MB"
            )

            cap_mb = info.max_capacity_bytes / (1024 * 1024)
            self.capacity_label.setText(
                f"Max Storage Capacity: {cap_mb:.2f} MB ({info.max_capacity_bytes:,} B)"
            )

            self.image_selected.emit(str(p))

        except Exception as exc:
            self.thumb_label.setText(f"Error loading image:\n{exc}")
            self.info_label.setText("Invalid or unsupported format.")
            self.capacity_label.setText("Max Storage Capacity: 0 B")

    def get_image_path(self) -> str:
        return str(self._image_path) if self._image_path else ""

    def clear(self) -> None:
        self._image_path = None
        self.thumb_label.clear()
        self.thumb_label.setText("No image selected\n(Drag & drop PNG, BMP, or TIFF here)")
        self.info_label.setText("Dimensions: --  |  Format: --  |  Size: --")
        self.capacity_label.setText("Max Storage Capacity: 0 B")

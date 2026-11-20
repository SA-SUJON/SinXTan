"""
Drag-and-Drop File and Folder Selection Zone for SinXTan.
"""

from __future__ import annotations

import os
from pathlib import Path

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QDragEnterEvent, QDropEvent
from PySide6.QtWidgets import (
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QPushButton,
    QVBoxLayout,
    QWidget,
)


class FileDropZone(QWidget):
    """Interactive drag & drop area for adding files and directories to the container."""

    files_changed = Signal(list)

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setAcceptDrops(True)
        self._files: list[Path] = []

        self._setup_ui()
        self._apply_styles()

    def _setup_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(10)

        # 1. Drop area box
        self.drop_box = QWidget()
        self.drop_box.setObjectName("dropBox")
        self.drop_box.setMinimumHeight(156)
        box_layout = QVBoxLayout(self.drop_box)
        box_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        box_layout.setContentsMargins(20, 24, 20, 24)
        box_layout.setSpacing(8)

        icon_label = QLabel("📂")
        icon_label.setStyleSheet("font-size: 32px;")
        icon_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        box_layout.addWidget(icon_label)

        title_label = QLabel("Drag & Drop Files or Folders Here")
        title_label.setStyleSheet("font-weight: 600; font-size: 14px; color: #1E293B;")
        title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        box_layout.addWidget(title_label)

        hint_label = QLabel("Supports documents, archives, videos, code, or entire directories")
        hint_label.setStyleSheet("font-size: 12px; color: #64748B;")
        hint_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        box_layout.addWidget(hint_label)

        # Buttons row
        btn_row = QHBoxLayout()
        btn_row.setSpacing(10)
        btn_row.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self.add_file_btn = QPushButton("+ Add Files")
        self.add_file_btn.setObjectName("secondaryButton")
        self.add_file_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.add_file_btn.clicked.connect(self._browse_files)
        btn_row.addWidget(self.add_file_btn)

        self.add_folder_btn = QPushButton("+ Add Folder")
        self.add_folder_btn.setObjectName("secondaryButton")
        self.add_folder_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.add_folder_btn.clicked.connect(self._browse_folder)
        btn_row.addWidget(self.add_folder_btn)

        box_layout.addLayout(btn_row)
        layout.addWidget(self.drop_box)

        # 2. File list view
        self.file_list = QListWidget()
        self.file_list.setMinimumHeight(106)
        self.file_list.setMaximumHeight(148)
        layout.addWidget(self.file_list)

        # 3. Summary row
        summary_row = QHBoxLayout()
        summary_row.setContentsMargins(2, 0, 2, 0)
        self.summary_label = QLabel("No files selected (0 B)")
        summary_row.addWidget(self.summary_label)

        self.clear_btn = QPushButton("Clear All")
        self.clear_btn.setObjectName("dangerText")
        self.clear_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.clear_btn.clicked.connect(self.clear)
        summary_row.addWidget(self.clear_btn)

        layout.addLayout(summary_row)

    def _apply_styles(self) -> None:
        self.setStyleSheet("""
            #dropBox {
                background-color: #F8F9FC;
                border: 1px dashed #CCD4E1;
                border-radius: 12px;
            }
            #dropBox:hover {
                border-color: #8796E2;
                background-color: #F2F4FF;
            }
        """)

    def dragEnterEvent(self, event: QDragEnterEvent) -> None:
        if event.mimeData().hasUrls():
            event.acceptProposedAction()
            self.drop_box.setStyleSheet("#dropBox { background-color: #EEF1FF; border: 2px dashed #7B8AE0; border-radius: 12px; }")

    def dragLeaveEvent(self, event) -> None:
        self.drop_box.setStyleSheet("")
        self._apply_styles()

    def dropEvent(self, event: QDropEvent) -> None:
        self._apply_styles()
        urls = event.mimeData().urls()
        new_paths: list[Path] = []
        for url in urls:
            path = Path(url.toLocalFile()).resolve()
            if path.exists() and path not in self._files:
                new_paths.append(path)

        if new_paths:
            self._files.extend(new_paths)
            self._refresh_list()

    def _browse_files(self) -> None:
        files, _ = QFileDialog.getOpenFileNames(
            self,
            "Select Files to Hide",
            "",
            "All Files (*.*)",
        )
        if files:
            for f in files:
                p = Path(f).resolve()
                if p not in self._files:
                    self._files.append(p)
            self._refresh_list()

    def _browse_folder(self) -> None:
        folder = QFileDialog.getExistingDirectory(
            self,
            "Select Folder to Hide",
            "",
        )
        if folder:
            p = Path(folder).resolve()
            if p not in self._files:
                self._files.append(p)
            self._refresh_list()

    def _refresh_list(self) -> None:
        self.file_list.clear()
        total_bytes = 0

        for p in self._files:
            if p.is_file():
                size = p.stat().st_size
                total_bytes += size
                item = QListWidgetItem(f"📄  {p.name}  ({self._format_size(size)})")
            elif p.is_dir():
                dir_size = sum(f.stat().st_size for f in p.rglob("*") if f.is_file())
                total_bytes += dir_size
                item = QListWidgetItem(f"📁  {p.name}/  ({self._format_size(dir_size)})")
            else:
                continue
            self.file_list.addItem(item)

        count = len(self._files)
        self.summary_label.setText(f"{count} item{'s' if count != 1 else ''} selected ({self._format_size(total_bytes)})")
        self.files_changed.emit([str(p) for p in self._files])

    @staticmethod
    def _format_size(size_bytes: int) -> str:
        for unit in ["B", "KB", "MB", "GB"]:
            if size_bytes < 1024:
                return f"{size_bytes:.1f} {unit}" if unit != "B" else f"{size_bytes} B"
            size_bytes /= 1024
        return f"{size_bytes:.1f} TB"

    def get_files(self) -> list[str]:
        return [str(p) for p in self._files]

    def get_total_size(self) -> int:
        total = 0
        for p in self._files:
            if p.is_file():
                total += p.stat().st_size
            elif p.is_dir():
                total += sum(f.stat().st_size for f in p.rglob("*") if f.is_file())
        return total

    def clear(self) -> None:
        self._files.clear()
        self._refresh_list()

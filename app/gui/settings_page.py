"""
Settings and Configuration Page for SinXTan.
"""

from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import QSettings, Qt, Signal
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
    QSpinBox,
    QVBoxLayout,
    QWidget,
)

from app.gui.page_header import add_page_header


class SettingsPage(QWidget):
    """Application preferences and cryptographic parameter configuration page."""

    settings_changed = Signal()

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._settings = QSettings("SinXTan", "SinXTan")
        self._setup_ui()
        self._load_settings()

    def _setup_ui(self) -> None:
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)

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
            "PREFERENCES",
            "Settings",
            "Tune key derivation, embedding defaults, and where new output files are saved.",
        )

        # 1. Argon2id Configuration Card
        kdf_card = QFrame()
        kdf_card.setObjectName("surfaceCard")
        kdf_layout = QVBoxLayout(kdf_card)
        kdf_layout.setContentsMargins(18, 18, 18, 18)
        kdf_layout.setSpacing(12)

        kdf_title = QLabel("Argon2id Key Derivation Tuning")
        kdf_title.setObjectName("formSectionTitle")
        kdf_layout.addWidget(kdf_title)

        kdf_desc = QLabel("Adjust memory hardness and iteration cost. Higher values increase protection against brute-force attacks at the expense of processing time.")
        kdf_desc.setObjectName("pageDescription")
        kdf_desc.setWordWrap(True)
        kdf_layout.addWidget(kdf_desc)

        # Time cost
        t_row = QHBoxLayout()
        t_label = QLabel("Time Cost (Iterations):")
        t_row.addWidget(t_label)
        t_row.addStretch()
        self.time_spin = QSpinBox()
        self.time_spin.setRange(1, 10)
        self.time_spin.setValue(3)
        self.time_spin.setFixedWidth(160)
        t_row.addWidget(self.time_spin)
        kdf_layout.addLayout(t_row)

        # Memory cost
        m_row = QHBoxLayout()
        m_label = QLabel("Memory Cost (KiB):")
        m_row.addWidget(m_label)
        m_row.addStretch()
        self.mem_spin = QSpinBox()
        self.mem_spin.setRange(8192, 262144)  # 8 MB to 256 MB
        self.mem_spin.setSingleStep(8192)
        self.mem_spin.setValue(65536)  # 64 MB
        self.mem_spin.setFixedWidth(160)
        m_row.addWidget(self.mem_spin)
        kdf_layout.addLayout(m_row)

        # Parallelism
        p_row = QHBoxLayout()
        p_label = QLabel("Parallelism (Threads):")
        p_row.addWidget(p_label)
        p_row.addStretch()
        self.par_spin = QSpinBox()
        self.par_spin.setRange(1, 16)
        self.par_spin.setValue(4)
        self.par_spin.setFixedWidth(160)
        p_row.addWidget(self.par_spin)
        kdf_layout.addLayout(p_row)

        layout.addWidget(kdf_card)

        # 2. Steganography Defaults Card
        stego_card = QFrame()
        stego_card.setObjectName("surfaceCard")
        stego_layout = QVBoxLayout(stego_card)
        stego_layout.setContentsMargins(18, 18, 18, 18)
        stego_layout.setSpacing(12)

        stego_title = QLabel("Steganography Defaults")
        stego_title.setObjectName("formSectionTitle")
        stego_layout.addWidget(stego_title)

        depth_row = QHBoxLayout()
        d_label = QLabel("Default Embedding Depth:")
        depth_row.addWidget(d_label)
        depth_row.addStretch()
        self.default_depth_combo = QComboBox()
        self.default_depth_combo.addItems(["1 bit per channel (Recommended)", "2 bits per channel", "3 bits per channel", "4 bits per channel"])
        self.default_depth_combo.setFixedWidth(310)
        depth_row.addWidget(self.default_depth_combo)
        stego_layout.addLayout(depth_row)

        self.default_compress_chk = QCheckBox("Enable Payload Compression by Default")
        self.default_compress_chk.setChecked(True)
        stego_layout.addWidget(self.default_compress_chk)

        layout.addWidget(stego_card)

        # 3. Output Destination Default
        out_card = QFrame()
        out_card.setObjectName("surfaceCard")
        out_layout = QVBoxLayout(out_card)
        out_layout.setContentsMargins(18, 18, 18, 18)
        out_layout.setSpacing(12)

        out_title = QLabel("Default Output Directory")
        out_title.setObjectName("formSectionTitle")
        out_layout.addWidget(out_title)

        dest_row = QHBoxLayout()
        self.dest_edit = QLineEdit()
        self.dest_edit.setPlaceholderText("Adjacent to carrier image (Default)")
        dest_row.addWidget(self.dest_edit)

        browse_btn = QPushButton("Browse")
        browse_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        browse_btn.clicked.connect(self._browse_default_dest)
        dest_row.addWidget(browse_btn)

        out_layout.addLayout(dest_row)
        layout.addWidget(out_card)

        # Action Buttons
        btn_row = QHBoxLayout()
        btn_row.setSpacing(12)

        self.reset_btn = QPushButton("Reset to Recommended Defaults")
        self.reset_btn.setObjectName("secondaryButton")
        self.reset_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.reset_btn.clicked.connect(self._reset_defaults)
        btn_row.addWidget(self.reset_btn)

        btn_row.addStretch()

        self.save_btn = QPushButton("Save Settings")
        self.save_btn.setObjectName("primaryButton")
        self.save_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.save_btn.clicked.connect(self._save_settings)
        btn_row.addWidget(self.save_btn)

        layout.addLayout(btn_row)

        scroll.setWidget(container)
        outer.addWidget(scroll)

    def _browse_default_dest(self) -> None:
        folder = QFileDialog.getExistingDirectory(self, "Select Default Output Folder", "")
        if folder:
            self.dest_edit.setText(folder)

    def _load_settings(self) -> None:
        self.time_spin.setValue(int(self._settings.value("kdf/time_cost", 3)))
        self.mem_spin.setValue(int(self._settings.value("kdf/memory_cost", 65536)))
        self.par_spin.setValue(int(self._settings.value("kdf/parallelism", 4)))
        self.default_depth_combo.setCurrentIndex(int(self._settings.value("stego/depth", 0)))
        self.default_compress_chk.setChecked(self._settings.value("stego/compress", "true") == "true")
        self.dest_edit.setText(self._settings.value("output/default_dir", ""))

    def _save_settings(self) -> None:
        self._settings.setValue("kdf/time_cost", self.time_spin.value())
        self._settings.setValue("kdf/memory_cost", self.mem_spin.value())
        self._settings.setValue("kdf/parallelism", self.par_spin.value())
        self._settings.setValue("stego/depth", self.default_depth_combo.currentIndex())
        self._settings.setValue("stego/compress", "true" if self.default_compress_chk.isChecked() else "false")
        self._settings.setValue("output/default_dir", self.dest_edit.text().strip())
        self.settings_changed.emit()
        QMessageBox.information(self, "Settings Saved", "Your preferences have been saved successfully.")

    def _reset_defaults(self) -> None:
        self.time_spin.setValue(3)
        self.mem_spin.setValue(65536)
        self.par_spin.setValue(4)
        self.default_depth_combo.setCurrentIndex(0)
        self.default_compress_chk.setChecked(True)
        self.dest_edit.clear()

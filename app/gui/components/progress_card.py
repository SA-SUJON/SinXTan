"""
Operation Progress and Status Card Widget for SinXTan.
"""

from __future__ import annotations

from PySide6.QtCore import QEasingCurve, QPropertyAnimation, Qt, Signal
from PySide6.QtWidgets import (
    QHBoxLayout,
    QLabel,
    QProgressBar,
    QPushButton,
    QVBoxLayout,
    QWidget,
)


class ProgressCard(QWidget):
    """Visual progress monitor with cancel capability and operation feedback."""

    cancel_requested = Signal()

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setObjectName("surfaceCard")
        self._setup_ui()
        self._progress_animation = QPropertyAnimation(self.bar, b"value", self)
        self._progress_animation.setDuration(220)
        self._progress_animation.setEasingCurve(QEasingCurve.Type.OutCubic)

    def _setup_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(18, 16, 18, 16)
        layout.setSpacing(11)

        # Header: status text + cancel button
        header_row = QHBoxLayout()
        self.status_label = QLabel("Ready")
        self.status_label.setObjectName("progressStatus")
        header_row.addWidget(self.status_label)

        self.percent_label = QLabel("0%")
        self.percent_label.setObjectName("progressPercent")
        header_row.addWidget(self.percent_label)

        header_row.addStretch()

        self.cancel_btn = QPushButton("Cancel")
        self.cancel_btn.setObjectName("dangerAction")
        self.cancel_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.cancel_btn.clicked.connect(self.cancel_requested.emit)
        header_row.addWidget(self.cancel_btn)

        layout.addLayout(header_row)

        # Progress bar
        self.bar = QProgressBar()
        self.bar.setRange(0, 100)
        self.bar.setValue(0)
        self.bar.setTextVisible(False)
        self.bar.setFixedHeight(8)
        layout.addWidget(self.bar)

        # Message / Details label
        self.detail_label = QLabel("")
        self.detail_label.setObjectName("progressDetail")
        self.detail_label.setWordWrap(True)
        layout.addWidget(self.detail_label)

    def set_progress(self, value: int) -> None:
        val = max(0, min(100, value))
        self._progress_animation.stop()
        self._progress_animation.setStartValue(self.bar.value())
        self._progress_animation.setEndValue(val)
        self._progress_animation.start()
        self.percent_label.setText(f"{val}%")

    def set_status(self, text: str) -> None:
        self.status_label.setText(text)

    def set_detail(self, text: str) -> None:
        self.detail_label.setText(text)

    def set_complete(self, success: bool, message: str = "") -> None:
        self.cancel_btn.setEnabled(False)
        if success:
            self.set_progress(100)
            self.status_label.setText("✓ Completed Successfully")
            self.status_label.setStyleSheet("font-weight: 700; color: #138B72;")
            self.bar.setStyleSheet("""
                QProgressBar { background-color: #E9EDF4; border: none; border-radius: 4px; }
                QProgressBar::chunk { background-color: #138B72; border-radius: 4px; }
            """)
        else:
            self.status_label.setText("✕ Operation Failed")
            self.status_label.setStyleSheet("font-weight: 700; color: #D8485A;")
            self.bar.setStyleSheet("""
                QProgressBar { background-color: #E9EDF4; border: none; border-radius: 4px; }
                QProgressBar::chunk { background-color: #D8485A; border-radius: 4px; }
            """)
        if message:
            self.detail_label.setText(message)

    def set_error(self, error_message: str) -> None:
        self.set_complete(False, error_message)

    def reset(self) -> None:
        self._progress_animation.stop()
        self.cancel_btn.setEnabled(True)
        self.bar.setValue(0)
        self.percent_label.setText("0%")
        self.status_label.setText("Ready")
        self.status_label.setStyleSheet("")
        self.detail_label.setText("")
        self.bar.setStyleSheet("")

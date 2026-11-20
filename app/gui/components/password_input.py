"""
Password Input Widget with Real-time Strength Meter for SinXTan.
"""

from __future__ import annotations

from PySide6.QtCore import QEasingCurve, QPropertyAnimation, Qt, Signal
from PySide6.QtWidgets import (
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QProgressBar,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from app.utils.validators import validate_password_strength


class PasswordInputWidget(QWidget):
    """Modern password input widget with show/hide toggle and strength feedback."""

    password_changed = Signal(str)
    strength_changed = Signal(int)

    def __init__(self, require_confirmation: bool = True, parent=None) -> None:
        super().__init__(parent)
        self.require_confirmation = require_confirmation

        self._setup_ui()
        self._strength_animation = QPropertyAnimation(self.strength_bar, b"value", self)
        self._strength_animation.setDuration(180)
        self._strength_animation.setEasingCurve(QEasingCurve.Type.OutCubic)
        self._apply_styles()

    def _setup_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(8)

        # 1. Main password row
        pw_label = QLabel("Master Password")
        pw_label.setStyleSheet("font-weight: 600; color: #1E293B; font-size: 13px;")
        layout.addWidget(pw_label)

        pw_row = QHBoxLayout()
        pw_row.setSpacing(6)

        self.password_edit = QLineEdit()
        self.password_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.password_edit.setPlaceholderText("Enter a strong encryption passphrase...")
        self.password_edit.textChanged.connect(self._on_password_changed)
        pw_row.addWidget(self.password_edit)

        self.toggle_btn = QPushButton("Show")
        self.toggle_btn.setObjectName("passwordToggle")
        self.toggle_btn.setToolTip("Show / Hide password")
        self.toggle_btn.setFixedSize(52, 36)
        self.toggle_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.toggle_btn.clicked.connect(self._toggle_visibility)
        pw_row.addWidget(self.toggle_btn)

        layout.addLayout(pw_row)

        # 2. Strength Meter Bar
        meter_row = QHBoxLayout()
        meter_row.setSpacing(8)

        self.strength_bar = QProgressBar()
        self.strength_bar.setRange(0, 4)
        self.strength_bar.setValue(0)
        self.strength_bar.setTextVisible(False)
        self.strength_bar.setFixedHeight(6)
        meter_row.addWidget(self.strength_bar)

        self.strength_label = QLabel("Empty")
        self.strength_label.setStyleSheet("font-size: 11px; font-weight: 600; color: #64748B;")
        self.strength_label.setFixedWidth(72)
        meter_row.addWidget(self.strength_label)

        layout.addLayout(meter_row)

        # 3. Optional Confirmation Row
        if self.require_confirmation:
            confirm_label = QLabel("Confirm Password")
            confirm_label.setStyleSheet("font-weight: 600; color: #1E293B; font-size: 13px; margin-top: 4px;")
            layout.addWidget(confirm_label)

            self.confirm_edit = QLineEdit()
            self.confirm_edit.setEchoMode(QLineEdit.EchoMode.Password)
            self.confirm_edit.setPlaceholderText("Re-enter master password...")
            self.confirm_edit.textChanged.connect(self._on_confirm_changed)
            layout.addWidget(self.confirm_edit)

            self.match_label = QLabel("")
            self.match_label.setStyleSheet("font-size: 11px; font-weight: 500;")
            layout.addWidget(self.match_label)

    def _apply_styles(self) -> None:
        self.setStyleSheet("""
            QLineEdit {
                background-color: #FFFFFF;
                border: 1px solid #DCE2EB;
                border-radius: 9px;
                padding: 9px 12px;
                font-size: 13px;
                color: #253146;
            }
            QLineEdit:focus {
                border: 1px solid #7185E7;
            }
            QPushButton {
                background-color: #F5F7FA;
                border: 1px solid #DCE2EB;
                border-radius: 8px;
                font-size: 15px;
            }
            QPushButton:hover {
                background-color: #EBEEF4;
            }
            QProgressBar {
                background-color: #E9EDF4;
                border: none;
                border-radius: 3px;
            }
        """)

    def _toggle_visibility(self) -> None:
        if self.password_edit.echoMode() == QLineEdit.EchoMode.Password:
            self.password_edit.setEchoMode(QLineEdit.EchoMode.Normal)
            if self.require_confirmation:
                self.confirm_edit.setEchoMode(QLineEdit.EchoMode.Normal)
            self.toggle_btn.setText("Hide")
        else:
            self.password_edit.setEchoMode(QLineEdit.EchoMode.Password)
            if self.require_confirmation:
                self.confirm_edit.setEchoMode(QLineEdit.EchoMode.Password)
            self.toggle_btn.setText("Show")

    def _on_password_changed(self, text: str) -> None:
        eval_res = validate_password_strength(text)
        self._strength_animation.stop()
        self._strength_animation.setStartValue(self.strength_bar.value())
        self._strength_animation.setEndValue(eval_res.score)
        self._strength_animation.start()
        self.strength_label.setText(eval_res.label)

        # Style strength bar color
        colors = {
            0: "#D5DCE7",
            1: "#D8485A",
            2: "#D29135",
            3: "#219171",
            4: "#138B72",
        }
        color = colors.get(eval_res.score, "#D5DCE7")
        self.strength_bar.setStyleSheet(f"""
            QProgressBar {{
                background-color: #E9EDF4;
                border: none;
                border-radius: 3px;
            }}
            QProgressBar::chunk {{
                background-color: {color};
                border-radius: 3px;
            }}
        """)
        self.strength_label.setStyleSheet(f"font-size: 11px; font-weight: 600; color: {color};")

        if self.require_confirmation:
            self._check_match()

        self.password_changed.emit(text)
        self.strength_changed.emit(eval_res.score)

    def _on_confirm_changed(self, _text: str) -> None:
        self._check_match()

    def _check_match(self) -> bool:
        if not self.require_confirmation:
            return True
        pw = self.password_edit.text()
        cpw = self.confirm_edit.text()

        if not cpw:
            self.match_label.setText("")
            return False
        elif pw == cpw:
            self.match_label.setText("✓ Passwords match")
            self.match_label.setStyleSheet("font-size: 11px; font-weight: 600; color: #138B72;")
            return True
        else:
            self.match_label.setText("✕ Passwords do not match")
            self.match_label.setStyleSheet("font-size: 11px; font-weight: 600; color: #D8485A;")
            return False

    def get_password(self) -> str:
        """Return the entered password if valid, else empty string."""
        pw = self.password_edit.text()
        if self.require_confirmation and pw != self.confirm_edit.text():
            return ""
        return pw

    def is_valid(self) -> bool:
        """Check if password is entered and matches confirmation."""
        pw = self.password_edit.text()
        if not pw:
            return False
        if self.require_confirmation:
            return pw == self.confirm_edit.text()
        return True

    def clear(self) -> None:
        self.password_edit.clear()
        if self.require_confirmation:
            self.confirm_edit.clear()
            self.match_label.setText("")

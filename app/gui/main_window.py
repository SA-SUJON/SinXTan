"""Main application shell and persistent navigation for SinXTan."""

from __future__ import annotations

from PySide6.QtCore import QEasingCurve, QPropertyAnimation, Qt
from PySide6.QtWidgets import (
    QApplication,
    QButtonGroup,
    QFrame,
    QHBoxLayout,
    QLabel,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QStackedWidget,
    QStatusBar,
    QVBoxLayout,
    QWidget,
    QGraphicsOpacityEffect,
)

from app.gui.dashboard import DashboardPage
from app.gui.encrypt_page import EncryptPage
from app.gui.extract_page import ExtractPage
from app.gui.security_center import SecurityCenterPage
from app.gui.settings_page import SettingsPage
from app.gui.theme import apply_theme


class MainWindow(QMainWindow):
    """Primary window with a stable sidebar and animated workspace pages."""

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setWindowTitle("SinXTan")
        self.resize(1220, 820)
        self.setMinimumSize(1000, 680)

        self._navigation_buttons: dict[str, QPushButton] = {}
        self._setup_ui()
        app = QApplication.instance()
        if app is not None:
            apply_theme(app)

    def _setup_ui(self) -> None:
        root = QWidget(self)
        root.setObjectName("appSurface")
        root_layout = QHBoxLayout(root)
        root_layout.setContentsMargins(0, 0, 0, 0)
        root_layout.setSpacing(0)

        sidebar = QFrame(root)
        sidebar.setObjectName("sidebar")
        sidebar.setFixedWidth(224)
        sidebar_layout = QVBoxLayout(sidebar)
        sidebar_layout.setContentsMargins(18, 23, 18, 18)
        sidebar_layout.setSpacing(0)

        brand_row = QHBoxLayout()
        brand_row.setSpacing(11)
        brand_mark = QFrame()
        brand_mark.setObjectName("brandMark")
        brand_mark.setFixedSize(40, 40)
        mark_layout = QVBoxLayout(brand_mark)
        mark_layout.setContentsMargins(0, 0, 0, 0)
        mark = QLabel("ST")
        mark.setObjectName("brandMarkText")
        mark.setAlignment(Qt.AlignmentFlag.AlignCenter)
        mark_layout.addWidget(mark)
        brand_row.addWidget(brand_mark)

        brand_copy = QVBoxLayout()
        brand_copy.setSpacing(1)
        brand_name = QLabel("SinXTan")
        brand_name.setObjectName("brandName")
        brand_copy.addWidget(brand_name)
        brand_subtitle = QLabel("PRIVATE FILE WORKSPACE")
        brand_subtitle.setObjectName("brandSubtitle")
        brand_copy.addWidget(brand_subtitle)
        brand_row.addLayout(brand_copy)
        brand_row.addStretch()
        sidebar_layout.addLayout(brand_row)

        sidebar_layout.addSpacing(27)
        sidebar_layout.addWidget(self._section_label("WORKSPACE"))
        sidebar_layout.addSpacing(9)

        self._nav_group = QButtonGroup(self)
        self._nav_group.setExclusive(True)
        self._add_nav_button(sidebar_layout, "home", "⌂", "Overview")
        self._add_nav_button(sidebar_layout, "encrypt", "↗", "Encrypt & hide")
        self._add_nav_button(sidebar_layout, "extract", "↙", "Extract & recover")

        sidebar_layout.addSpacing(22)
        sidebar_layout.addWidget(self._section_label("PREFERENCES"))
        sidebar_layout.addSpacing(9)
        self._add_nav_button(sidebar_layout, "security", "◇", "Security center")
        self._add_nav_button(sidebar_layout, "settings", "⚙", "Settings")

        sidebar_layout.addStretch(1)

        note = QFrame()
        note.setObjectName("sidebarNote")
        note_layout = QVBoxLayout(note)
        note_layout.setContentsMargins(12, 12, 12, 12)
        note_layout.setSpacing(4)
        note_title = QLabel("Lossless carriers")
        note_title.setObjectName("sidebarNoteTitle")
        note_layout.addWidget(note_title)
        note_text = QLabel("PNG  ·  BMP  ·  TIFF")
        note_text.setObjectName("sidebarNoteText")
        note_layout.addWidget(note_text)
        sidebar_layout.addWidget(note)

        root_layout.addWidget(sidebar)

        self.stack = QStackedWidget(root)
        self.stack.setObjectName("pageStack")
        self.dashboard_page = DashboardPage()
        self.encrypt_page = EncryptPage()
        self.extract_page = ExtractPage()
        self.security_page = SecurityCenterPage()
        self.settings_page = SettingsPage()

        self.stack.addWidget(self.dashboard_page)
        self.stack.addWidget(self.encrypt_page)
        self.stack.addWidget(self.extract_page)
        self.stack.addWidget(self.security_page)
        self.stack.addWidget(self.settings_page)

        self.dashboard_page.navigate_to.connect(self._navigate_to)
        self.encrypt_page.operation_completed.connect(
            lambda path: self.dashboard_page.add_recent_operation(
                f"Encrypted and concealed in: {path}", "Success"
            )
        )
        self.extract_page.operation_completed.connect(
            lambda files: self.dashboard_page.add_recent_operation(
                f"Extracted {len(files)} file(s)", "Success"
            )
        )

        self._stack_opacity = QGraphicsOpacityEffect(self.stack)
        self._stack_opacity.setOpacity(1.0)
        self.stack.setGraphicsEffect(self._stack_opacity)
        self._page_animation = QPropertyAnimation(self._stack_opacity, b"opacity", self)
        self._page_animation.setDuration(180)
        self._page_animation.setEasingCurve(QEasingCurve.Type.OutCubic)
        root_layout.addWidget(self.stack, 1)
        self.setCentralWidget(root)

        self._navigation_buttons["home"].setChecked(True)

        self.status_bar = QStatusBar()
        self.status_bar.showMessage("Ready  ·  AES-256-GCM  ·  Argon2id")
        self.setStatusBar(self.status_bar)

    @staticmethod
    def _section_label(text: str) -> QLabel:
        label = QLabel(text)
        label.setObjectName("sidebarSection")
        return label

    def _add_nav_button(
        self,
        layout: QVBoxLayout,
        route: str,
        icon: str,
        label: str,
    ) -> None:
        button = QPushButton(f"{icon}     {label}")
        button.setObjectName("navItem")
        button.setCheckable(True)
        button.setCursor(Qt.CursorShape.PointingHandCursor)
        self._nav_group.addButton(button)
        button.clicked.connect(lambda _checked=False, page=route: self._navigate_to(page))
        self._navigation_buttons[route] = button
        layout.addWidget(button)
        layout.addSpacing(3)

    def _navigate_to(self, page_name: str) -> None:
        mapping = {"home": 0, "dashboard": 0, "encrypt": 1, "extract": 2, "security": 3, "settings": 4}
        page_index = mapping.get(page_name, 0)
        route = page_name if page_name in self._navigation_buttons else "home"
        if self.stack.currentIndex() == page_index:
            self._navigation_buttons[route].setChecked(True)
            return

        self._navigation_buttons[route].setChecked(True)
        self.stack.setCurrentIndex(page_index)
        self._page_animation.stop()
        self._stack_opacity.setOpacity(0.72)
        self._page_animation.setStartValue(0.72)
        self._page_animation.setEndValue(1.0)
        self._page_animation.start()

    def closeEvent(self, event) -> None:
        """Ask before leaving while a cryptographic worker is running."""
        enc_running = (
            self.encrypt_page._worker is not None and self.encrypt_page._worker.isRunning()
        )
        ext_running = (
            self.extract_page._worker is not None and self.extract_page._worker.isRunning()
        )

        if enc_running or ext_running:
            reply = QMessageBox.question(
                self,
                "Operation in Progress",
                "A cryptographic operation is currently in progress. Are you sure you want to cancel and exit?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No,
            )
            if reply == QMessageBox.StandardButton.Yes:
                if enc_running:
                    self.encrypt_page._worker.cancel()
                    self.encrypt_page._worker.wait(1000)
                if ext_running:
                    self.extract_page._worker.cancel()
                    self.extract_page._worker.wait(1000)
                event.accept()
            else:
                event.ignore()
        else:
            event.accept()

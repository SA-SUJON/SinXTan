"""Overview page for SinXTan's secure file workflows."""

from __future__ import annotations

import datetime

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QPushButton,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)


class ActionCard(QPushButton):
    """Large, keyboard-accessible card for a primary workspace action."""

    def __init__(
        self,
        title: str,
        description: str,
        icon: str,
        number: str,
        parent=None,
    ) -> None:
        super().__init__(parent)
        self.setObjectName("actionCard")
        self.setAccessibleName(title)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setMinimumHeight(146)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(18, 15, 18, 16)
        layout.setSpacing(10)

        top_row = QHBoxLayout()
        icon_label = QLabel(icon)
        icon_label.setObjectName("actionIcon")
        icon_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        icon_label.setFixedSize(36, 36)
        top_row.addWidget(icon_label)
        top_row.addStretch()
        number_label = QLabel(number)
        number_label.setObjectName("actionNumber")
        top_row.addWidget(number_label)
        layout.addLayout(top_row)

        title_label = QLabel(title)
        title_label.setObjectName("actionTitle")
        layout.addWidget(title_label)

        description_label = QLabel(description)
        description_label.setObjectName("actionDescription")
        description_label.setWordWrap(True)
        layout.addWidget(description_label)


class DashboardPage(QWidget):
    """Home page with primary actions, security summary, and recent activity."""

    navigate_to = Signal(str)

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._setup_ui()

    def _setup_ui(self) -> None:
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        scroll.setFrameShape(QFrame.Shape.NoFrame)

        content = QWidget()
        content.setObjectName("scrollContent")
        layout = QVBoxLayout(content)
        layout.setContentsMargins(36, 28, 36, 26)
        layout.setSpacing(17)

        page_heading = QVBoxLayout()
        page_heading.setSpacing(5)
        eyebrow = QLabel("WORKSPACE OVERVIEW")
        eyebrow.setObjectName("pageEyebrow")
        page_heading.addWidget(eyebrow)
        title = QLabel("Your private workspace")
        title.setObjectName("pageTitle")
        page_heading.addWidget(title)
        description = QLabel(
            "Hide files inside a lossless image or recover an existing container."
        )
        description.setObjectName("pageDescription")
        description.setWordWrap(True)
        page_heading.addWidget(description)
        layout.addLayout(page_heading)

        layout.addWidget(self._build_hero())

        action_header = QHBoxLayout()
        action_heading = QVBoxLayout()
        action_heading.setSpacing(4)
        action_eyebrow = QLabel("GET STARTED")
        action_eyebrow.setObjectName("sectionEyebrow")
        action_heading.addWidget(action_eyebrow)
        action_title = QLabel("Choose a task")
        action_title.setObjectName("sectionTitle")
        action_heading.addWidget(action_title)
        action_header.addLayout(action_heading)
        action_header.addStretch()
        layout.addLayout(action_header)

        action_grid = QGridLayout()
        action_grid.setHorizontalSpacing(14)
        action_grid.setVerticalSpacing(14)

        encrypt_card = ActionCard(
            "Encrypt & hide",
            "Protect files and conceal them in a PNG, BMP, or TIFF image.",
            "↗",
            "01",
        )
        encrypt_card.clicked.connect(lambda: self.navigate_to.emit("encrypt"))
        action_grid.addWidget(encrypt_card, 0, 0)

        extract_card = ActionCard(
            "Extract & recover",
            "Verify a protected image and restore its files to a folder.",
            "↙",
            "02",
        )
        extract_card.clicked.connect(lambda: self.navigate_to.emit("extract"))
        action_grid.addWidget(extract_card, 0, 1)
        action_grid.setColumnStretch(0, 1)
        action_grid.setColumnStretch(1, 1)
        layout.addLayout(action_grid)

        layout.addWidget(self._build_security_summary())
        layout.addWidget(self._build_activity_panel())
        layout.addStretch(1)

        scroll.setWidget(content)
        outer.addWidget(scroll)

    @staticmethod
    def _build_hero() -> QFrame:
        panel = QFrame()
        panel.setObjectName("heroPanel")
        hero = QHBoxLayout(panel)
        hero.setContentsMargins(23, 20, 23, 20)
        hero.setSpacing(18)

        copy = QVBoxLayout()
        copy.setSpacing(7)
        eyebrow = QLabel("SECURE CONTAINERS")
        eyebrow.setObjectName("heroEyebrow")
        copy.addWidget(eyebrow)

        title = QLabel("Encryption before concealment.")
        title.setObjectName("heroTitle")
        title.setWordWrap(True)
        copy.addWidget(title)

        description = QLabel(
            "Files are authenticated with AES-256-GCM before they are embedded in a lossless image."
        )
        description.setObjectName("heroDescription")
        description.setWordWrap(True)
        description.setMaximumWidth(420)
        copy.addWidget(description)
        hero.addLayout(copy, 1)

        flow = QHBoxLayout()
        flow.setSpacing(7)
        for index, (label, detail) in enumerate(
            (("FILES", "Your payload"), ("AES", "Encrypted"), ("IMAGE", "Lossless"))
        ):
            step = QVBoxLayout()
            step.setSpacing(5)
            token = QLabel(label)
            token.setObjectName("heroFlowToken")
            token.setAlignment(Qt.AlignmentFlag.AlignCenter)
            token.setFixedSize(58, 40)
            step.addWidget(token, alignment=Qt.AlignmentFlag.AlignCenter)
            caption = QLabel(detail)
            caption.setObjectName("heroFlowCaption")
            caption.setAlignment(Qt.AlignmentFlag.AlignCenter)
            step.addWidget(caption)
            flow.addLayout(step)
            if index < 2:
                arrow = QLabel("›")
                arrow.setObjectName("heroFlowArrow")
                arrow.setAlignment(Qt.AlignmentFlag.AlignCenter)
                flow.addWidget(arrow)
        hero.addLayout(flow)
        return panel

    @staticmethod
    def _build_security_summary() -> QFrame:
        panel = QFrame()
        panel.setObjectName("summaryPanel")
        grid = QGridLayout(panel)
        grid.setContentsMargins(17, 12, 17, 12)
        grid.setHorizontalSpacing(14)
        grid.setVerticalSpacing(8)

        specs = (
            ("ENCRYPTION", "AES-256-GCM"),
            ("KEY DERIVATION", "Argon2id"),
            ("CARRIERS", "PNG · BMP · TIFF"),
            ("INTEGRITY", "SHA-256"),
        )
        for index, (label, value) in enumerate(specs):
            item = QVBoxLayout()
            item.setSpacing(4)
            name = QLabel(label)
            name.setObjectName("summaryLabel")
            value_label = QLabel(value)
            value_label.setObjectName("summaryValue")
            item.addWidget(name)
            item.addWidget(value_label)
            grid.addLayout(item, 0, index)
            grid.setColumnStretch(index, 1)
        return panel

    def _build_activity_panel(self) -> QFrame:
        panel = QFrame()
        panel.setObjectName("activityPanel")
        activity_layout = QVBoxLayout(panel)
        activity_layout.setContentsMargins(17, 14, 17, 15)
        activity_layout.setSpacing(9)

        header = QHBoxLayout()
        heading = QVBoxLayout()
        heading.setSpacing(3)
        eyebrow = QLabel("ACTIVITY")
        eyebrow.setObjectName("sectionEyebrow")
        heading.addWidget(eyebrow)
        title = QLabel("Recent operations")
        title.setObjectName("sectionTitle")
        heading.addWidget(title)
        header.addLayout(heading)
        header.addStretch()
        scope = QLabel("This session")
        scope.setObjectName("activityScope")
        header.addWidget(scope, alignment=Qt.AlignmentFlag.AlignTop)
        activity_layout.addLayout(header)

        self.recent_list = QListWidget()
        self.recent_list.setFixedHeight(104)
        self.recent_list.setAlternatingRowColors(False)
        activity_layout.addWidget(self.recent_list)

        self.add_recent_operation("Cryptographic subsystem ready", "Success")
        return panel

    def add_recent_operation(self, description: str, status: str = "Success") -> None:
        """Log a completed operation in the current session."""
        now = datetime.datetime.now().strftime("%H:%M")
        status_icon = "✓" if status == "Success" else "!"
        item = QListWidgetItem(f"{status_icon}   {description}   ·   {now}")
        if status != "Success":
            item.setForeground(Qt.GlobalColor.darkRed)
        self.recent_list.insertItem(0, item)
        if self.recent_list.count() > 10:
            self.recent_list.takeItem(self.recent_list.count() - 1)

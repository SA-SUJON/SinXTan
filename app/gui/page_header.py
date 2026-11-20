"""Shared page-heading layout for SinXTan workspace views."""

from __future__ import annotations

from PySide6.QtWidgets import QLabel, QSizePolicy, QVBoxLayout, QWidget


def add_page_header(
    layout: QVBoxLayout,
    section: str,
    title: str,
    description: str,
) -> None:
    """Add a consistent eyebrow, title, and supporting description."""
    header = QWidget()
    header.setSizePolicy(QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Maximum)
    heading = QVBoxLayout(header)
    heading.setContentsMargins(0, 0, 0, 2)
    heading.setSpacing(5)

    eyebrow = QLabel(section.upper())
    eyebrow.setObjectName("pageEyebrow")
    heading.addWidget(eyebrow)

    title_label = QLabel(title)
    title_label.setObjectName("pageTitle")
    heading.addWidget(title_label)

    description_label = QLabel(description)
    description_label.setObjectName("pageDescription")
    description_label.setWordWrap(True)
    heading.addWidget(description_label)

    layout.addWidget(header)

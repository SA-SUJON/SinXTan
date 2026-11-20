"""
SinXTan - Advanced Cryptographic Steganography & Secure File Container Application.
Main entry point.
"""

from __future__ import annotations

import sys
from pathlib import Path

# Add project root to sys.path so package imports resolve correctly
project_root = Path(__file__).resolve().parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from PySide6.QtCore import Qt
from PySide6.QtGui import QFont, QIcon
from PySide6.QtWidgets import QApplication

from app.gui.main_window import MainWindow


def main() -> int:
    """Launch the SinXTan desktop GUI application."""
    app = QApplication(sys.argv)
    app.setApplicationName("SinXTan")
    app.setApplicationDisplayName("SinXTan")
    app.setOrganizationName("SinXTan")
    app.setApplicationVersion("1.0.0")
    app.setWindowIcon(QIcon(str(project_root / "assets" / "icons" / "icon.png")))

    # Set default clean modern font
    font = QFont("Segoe UI", 10)
    font.setStyleHint(QFont.StyleHint.SansSerif)
    app.setFont(font)

    window = MainWindow()
    window.show()

    return app.exec()


if __name__ == "__main__":
    sys.exit(main())

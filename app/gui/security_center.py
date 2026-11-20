"""
Security Center Page for SinXTan.
"""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)

from app.gui.page_header import add_page_header


class SecuritySpecCard(QFrame):
    """Card displaying a specific cryptographic subsystem specification."""

    def __init__(self, title: str, icon: str, details: list[tuple[str, str]], parent=None) -> None:
        super().__init__(parent)
        self.setObjectName("surfaceCard")

        layout = QVBoxLayout(self)
        layout.setContentsMargins(18, 18, 18, 18)
        layout.setSpacing(11)

        # Title
        hdr = QHBoxLayout()
        icon_lbl = QLabel(icon)
        icon_lbl.setObjectName("securityIcon")
        hdr.addWidget(icon_lbl)

        title_lbl = QLabel(title)
        title_lbl.setObjectName("formSectionTitle")
        hdr.addWidget(title_lbl)
        hdr.addStretch()
        layout.addLayout(hdr)

        # Table of specs
        for label, val in details:
            row = QHBoxLayout()
            row.setSpacing(12)
            k = QLabel(label)
            k.setObjectName("specLabel")
            v = QLabel(val)
            v.setObjectName("specValue")
            v.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
            v.setWordWrap(True)
            row.addWidget(k)
            row.addWidget(v, 1)
            layout.addLayout(row)


class SecurityCenterPage(QWidget):
    """Cryptographic specification and audit overview page."""

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

        container = QWidget()
        container.setObjectName("scrollContent")
        layout = QVBoxLayout(container)
        layout.setContentsMargins(36, 28, 36, 28)
        layout.setSpacing(18)

        add_page_header(
            layout,
            "SECURITY CENTER",
            "Cryptographic details",
            "Review the algorithms, key derivation settings, and limits of image steganography.",
        )

        # Grid of Cards
        grid = QGridLayout()
        grid.setHorizontalSpacing(16)
        grid.setVerticalSpacing(16)

        c1 = SecuritySpecCard(
            title="Authenticated Encryption",
            icon="🔐",
            details=[
                ("Algorithm", "AES-256-GCM"),
                ("Key Length", "256 bits (32 bytes)"),
                ("Nonce Generation", "CSPRNG (os.urandom)"),
                ("Nonce Length", "96 bits (12 bytes)"),
                ("Authentication Tag", "128 bits (16 bytes)"),
                ("AAD Binding", "Header + Container Metadata"),
            ],
        )
        grid.addWidget(c1, 0, 0)

        c2 = SecuritySpecCard(
            title="Password Key Derivation",
            icon="🔑",
            details=[
                ("KDF Primitive", "Argon2id (RFC 9106)"),
                ("Salt Entropy", "256 bits (CSPRNG generated)"),
                ("Memory Cost", "65,536 KiB (64 MiB)"),
                ("Time Cost", "3 iterations"),
                ("Parallelism", "4 threads / lanes"),
                ("Subkey Derivation", "HKDF-SHA256 (Domain separated)"),
            ],
        )
        grid.addWidget(c2, 0, 1)

        c3 = SecuritySpecCard(
            title="Steganography Engine",
            icon="🖼️",
            details=[
                ("Embedding Technique", "Keyed Permuted LSB"),
                ("Pixel Selection", "Fisher-Yates Permutation"),
                ("Permutation Key", "HKDF embedding subkey"),
                ("Color Channels", "RGB (Alpha channel preserved)"),
                ("Lossless Carriers", "PNG, BMP, TIFF"),
                ("Embedding Depth", "1 - 4 bits per channel"),
            ],
        )
        grid.addWidget(c3, 1, 0)

        c4 = SecuritySpecCard(
            title="Data Integrity & Safety",
            icon="🛡️",
            details=[
                ("File Checksums", "SHA-256 per enclosed file"),
                ("Container Auth", "GCM Tag validation"),
                ("Path Traversal", "Strict POSIX relative verification"),
                ("Temp File Safety", "CSPRNG wipe before deletion"),
                ("Atomic Operations", "Safe atomic file replacement"),
                ("Memory Hygiene", "Zero master keys in instances"),
            ],
        )
        grid.addWidget(c4, 1, 1)

        grid.setColumnStretch(0, 1)
        grid.setColumnStretch(1, 1)

        layout.addLayout(grid)

        # Technical Disclaimer & Threat Model Card
        disc_card = QFrame()
        disc_card.setObjectName("warningCard")
        disc_layout = QVBoxLayout(disc_card)
        disc_layout.setContentsMargins(18, 18, 18, 18)
        disc_layout.setSpacing(8)

        disc_title = QLabel("⚠️ Cryptographic & Steganographic Threat Model & Limitations")
        disc_title.setObjectName("warningTitle")
        disc_layout.addWidget(disc_title)

        disc_text = QLabel(
            "• Confidentiality: Guaranteed by AES-256-GCM. Without the correct password, "
            "it is computationally infeasible to decrypt or tamper with the payload.\n"
            "• Steganography Limitations: LSB steganography subtly alters pixel color values. "
            "While visually imperceptible to the human eye, statistical steganalysis tools "
            "(e.g., Chi-Squared test, Sample Pairs Analysis) can detect anomalies in modified lossless images.\n"
            "• Compression Resistance: Steganographic images MUST be stored and transmitted using lossless "
            "channels. Social media platforms or messaging apps that recompress images to JPEG will destroy the hidden payload.\n"
            "• No Backdoors: SinXTan contains zero backdoors, master passwords, or key-escrow mechanisms. "
            "Lost passwords cannot be recovered under any circumstances."
        )
        disc_text.setObjectName("warningBody")
        disc_text.setWordWrap(True)
        disc_layout.addWidget(disc_text)

        layout.addWidget(disc_card)

        scroll.setWidget(container)
        outer.addWidget(scroll)

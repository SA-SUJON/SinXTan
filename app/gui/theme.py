"""Shared visual theme for the SinXTan desktop application."""

from __future__ import annotations

from PySide6.QtWidgets import QApplication


APP_STYLESHEET = """
QMainWindow, QWidget#appSurface {
    background-color: #F5F7FB;
    color: #202B3C;
    font-family: "Segoe UI";
    font-size: 12px;
}

QLabel {
    background: transparent;
    color: #202B3C;
}

QFrame#sidebar {
    background-color: #FFFFFF;
    border-right: 1px solid #E6EAF1;
}
QFrame#brandMark {
    background-color: #435FE0;
    border: none;
    border-radius: 12px;
}
QLabel#brandMarkText {
    color: #FFFFFF;
    font-size: 14px;
    font-weight: 800;
}
QLabel#brandName {
    color: #1C2637;
    font-size: 16px;
    font-weight: 700;
}
QLabel#brandSubtitle {
    color: #7B8798;
    font-size: 10px;
}
QLabel#sidebarSection {
    color: #9AA4B2;
    font-size: 9px;
    font-weight: 700;
    letter-spacing: 1px;
}
QFrame#sidebarDivider {
    background-color: #EEF0F5;
    border: none;
    max-height: 1px;
}
QPushButton#navItem {
    background: transparent;
    color: #677387;
    border: none;
    border-radius: 9px;
    padding: 10px 12px;
    text-align: left;
    font-size: 12px;
    font-weight: 600;
}
QPushButton#navItem:hover {
    background-color: #F4F6FA;
    color: #26334A;
}
QPushButton#navItem:checked {
    background-color: #EEF1FF;
    color: #3D58D1;
    font-weight: 700;
}
QFrame#sidebarNote {
    background-color: #F6F8FC;
    border: 1px solid #E9EDF4;
    border-radius: 12px;
}
QLabel#sidebarNoteTitle {
    color: #37445A;
    font-size: 11px;
    font-weight: 700;
}
QLabel#sidebarNoteText {
    color: #7A8798;
    font-size: 10px;
}

QFrame#surfaceCard, QWidget#surfaceCard {
    background-color: #FFFFFF;
    border: 1px solid #E6EAF1;
    border-radius: 14px;
}
QWidget#scrollContent {
    background-color: #F5F7FB;
}
QFrame#heroPanel {
    background-color: #EEF2FF;
    border: 1px solid #DFE5FA;
    border-radius: 16px;
}
QLabel#heroEyebrow {
    color: #566DD5;
    font-size: 9px;
    font-weight: 700;
    letter-spacing: 1px;
}
QLabel#heroTitle {
    color: #202B40;
    font-size: 18px;
    font-weight: 700;
}
QLabel#heroDescription {
    color: #66748D;
    font-size: 11px;
}
QLabel#heroFlowToken {
    background-color: #FFFFFF;
    border: 1px solid #E0E5F2;
    border-radius: 10px;
    color: #465FDB;
    font-size: 10px;
    font-weight: 700;
}
QLabel#heroFlowCaption {
    color: #758198;
    font-size: 9px;
}
QLabel#heroFlowArrow {
    color: #9AA7C2;
    font-size: 22px;
}
QPushButton#actionCard {
    background-color: #FFFFFF;
    border: 1px solid #E5E9F0;
    border-radius: 14px;
    text-align: left;
    min-height: 146px;
}
QPushButton#actionCard:hover {
    background-color: #FFFFFF;
    border-color: #C6D0F4;
}
QPushButton#actionCard:pressed {
    background-color: #F8F9FE;
}
QLabel#actionIcon {
    background-color: #EEF1FF;
    border-radius: 10px;
    color: #4962D7;
    font-size: 17px;
    font-weight: 700;
}
QLabel#actionNumber {
    color: #A1AABB;
    font-size: 10px;
    font-weight: 700;
}
QLabel#actionTitle {
    color: #273349;
    font-size: 14px;
    font-weight: 700;
}
QLabel#actionDescription {
    color: #758196;
    font-size: 10px;
}
QLabel#sectionTitle {
    color: #29354A;
    font-size: 15px;
    font-weight: 700;
}
QFrame#summaryPanel, QFrame#activityPanel {
    background-color: #FFFFFF;
    border: 1px solid #E6EAF1;
    border-radius: 13px;
}
QLabel#summaryLabel {
    color: #929DAE;
    font-size: 8px;
    font-weight: 700;
    letter-spacing: 0.7px;
}
QLabel#summaryValue {
    color: #37445A;
    font-size: 11px;
    font-weight: 600;
}
QLabel#activityScope {
    color: #909BAC;
    font-size: 10px;
}
QLabel#pageEyebrow, QLabel#sectionEyebrow {
    color: #576DDB;
    font-size: 9px;
    font-weight: 700;
    letter-spacing: 1.1px;
}
QLabel#pageTitle {
    color: #1D2839;
    font-size: 25px;
    font-weight: 700;
}
QLabel#pageDescription {
    color: #748094;
    font-size: 12px;
}
QLabel#formSectionTitle {
    color: #2B384D;
    font-size: 13px;
    font-weight: 700;
}
QLabel#specLabel {
    color: #748094;
    font-size: 11px;
    font-weight: 600;
}
QLabel#specValue {
    color: #334158;
    font-size: 11px;
    font-weight: 600;
}
QLabel#formLabel {
    color: #566477;
    font-size: 11px;
    font-weight: 600;
}
QLabel#statusDetails {
    color: #64738A;
    font-size: 10px;
}
QLabel#detectStatus {
    color: #718095;
    font-size: 11px;
}
QFrame#statusCardNeutral {
    background-color: #FFFFFF;
    border: 1px solid #E6EAF1;
    border-radius: 14px;
}
QFrame#statusCardSuccess {
    background-color: #EFF8F3;
    border: 1px solid #C8E6D5;
    border-radius: 14px;
}
QFrame#statusCardError {
    background-color: #FFF2F3;
    border: 1px solid #F0D0D3;
    border-radius: 14px;
}
QLabel#capacityStatus {
    color: #718095;
    font-size: 10px;
    font-weight: 500;
}
QLabel#capacityStatusSuccess {
    color: #187050;
    font-size: 10px;
    font-weight: 700;
}
QLabel#capacityStatusError {
    color: #B83345;
    font-size: 10px;
    font-weight: 700;
}
QLabel#securityIcon {
    font-size: 19px;
}
QFrame#warningCard {
    background-color: #FFF9EC;
    border: 1px solid #F1E1B8;
    border-radius: 14px;
}
QLabel#warningTitle {
    color: #795A1C;
    font-size: 13px;
    font-weight: 700;
}
QLabel#warningBody {
    color: #796842;
    font-size: 11px;
}
QLabel#thumbBox {
    background-color: #F8F9FC;
    border: 1px dashed #CCD4E1;
    border-radius: 11px;
    color: #778398;
    font-size: 11px;
}
QLabel#thumbBox:hover {
    background-color: #F1F4FF;
    border-color: #8493E1;
}
QLabel#imageMetadata {
    color: #7A8799;
    font-size: 10px;
}
QLabel#imageCapacity {
    color: #4961D0;
    font-size: 11px;
    font-weight: 700;
}
QLabel#progressStatus {
    color: #334158;
    font-size: 12px;
    font-weight: 600;
}
QLabel#progressPercent {
    color: #4961D0;
    font-size: 12px;
    font-weight: 700;
}
QLabel#progressDetail {
    color: #758196;
    font-size: 10px;
}
QPushButton#dangerAction {
    background-color: #FFF3F3;
    border: 1px solid #F2D8D8;
    color: #B84950;
    padding: 5px 11px;
}
QPushButton#dangerAction:hover {
    background-color: #FCE8E8;
    border-color: #E9C2C4;
}
QPushButton#passwordToggle {
    background-color: #F5F7FA;
    border: 1px solid #DCE2EB;
    color: #5E6C82;
    padding: 4px 8px;
    font-size: 10px;
}
QPushButton#passwordToggle:hover {
    background-color: #EBEEF4;
}

QPushButton {
    background-color: #FFFFFF;
    color: #354258;
    border: 1px solid #DDE3EC;
    border-radius: 9px;
    padding: 7px 13px;
    min-height: 20px;
    font-size: 12px;
    font-weight: 600;
}
QPushButton:hover {
    background-color: #F7F8FC;
    border-color: #C8D1E0;
}
QPushButton:pressed {
    background-color: #EEF1F7;
}
QPushButton:disabled {
    background-color: #E8EBF1;
    border-color: #E8EBF1;
    color: #929BAB;
}
QPushButton#primaryButton {
    background-color: #435FE0;
    border: none;
    color: #FFFFFF;
    font-size: 13px;
    font-weight: 700;
}
QPushButton#primaryButton:hover {
    background-color: #354FC9;
}
QPushButton#primaryButton:pressed {
    background-color: #2D43AE;
}
QPushButton#primaryButton:disabled {
    background-color: #B9C2E8;
    color: #FFFFFF;
}
QPushButton#dangerText {
    background: transparent;
    border: none;
    color: #C5525A;
}
QPushButton#dangerText:hover {
    background: transparent;
    color: #A73942;
}

QLineEdit, QComboBox, QSpinBox {
    background-color: #FBFCFE;
    color: #253146;
    border: 1px solid #DCE2EB;
    border-radius: 8px;
    padding: 7px 10px;
    min-height: 20px;
    selection-background-color: #435FE0;
}
QLineEdit:focus, QComboBox:focus, QSpinBox:focus {
    background-color: #FFFFFF;
    border: 1px solid #7185E7;
}
QComboBox::drop-down {
    border: none;
    width: 24px;
}
QCheckBox {
    spacing: 8px;
    color: #3C485D;
}
QCheckBox::indicator {
    width: 16px;
    height: 16px;
}

QListWidget {
    background-color: #FFFFFF;
    color: #39465B;
    border: 1px solid #E6EAF1;
    border-radius: 10px;
    padding: 6px;
    outline: none;
}
QListWidget::item {
    padding: 8px 9px;
    border-bottom: 1px solid #F0F2F6;
}
QListWidget::item:hover {
    background-color: #F7F8FC;
}
QListWidget::item:selected {
    background-color: #EEF1FF;
    color: #344FC7;
}

QProgressBar {
    background-color: #E9EDF4;
    border: none;
    border-radius: 4px;
}
QProgressBar::chunk {
    background-color: #5069DE;
    border-radius: 4px;
}
QScrollArea {
    background: transparent;
    border: none;
}
QScrollBar:vertical {
    background: #F5F7FB;
    border: none;
    width: 9px;
    margin: 2px;
}
QScrollBar::handle:vertical {
    background: #D4DAE5;
    border-radius: 4px;
    min-height: 28px;
}
QScrollBar::handle:vertical:hover {
    background: #B8C1D0;
}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
    height: 0;
}
QStatusBar {
    background-color: #FFFFFF;
    border-top: 1px solid #E6EAF1;
    color: #788496;
    font-size: 10px;
}
"""


def apply_theme(app: QApplication) -> None:
    """Apply the shared light theme to the full application."""
    app.setStyleSheet(APP_STYLESHEET)


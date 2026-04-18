from __future__ import annotations

import platform

from PySide6.QtGui import QFont
from PySide6.QtWidgets import QApplication


def _preferred_font_family() -> str:
    system = platform.system()
    if system == "Windows":
        return "Segoe UI"
    if system == "Darwin":
        return "SF Pro Text"
    return "Noto Sans"


def apply_application_style(app: QApplication) -> None:
    app.setStyle("Fusion")

    font = QFont(_preferred_font_family(), 10)
    font.setStyleStrategy(QFont.StyleStrategy.PreferAntialias)
    font.setHintingPreference(QFont.HintingPreference.PreferFullHinting)
    app.setFont(font)

    app.setStyleSheet(
        """
        QMainWindow, QWidget {
            color: #eef2ff;
            background: #0b1020;
        }

        QWidget#RootWindow {
            background: qradialgradient(
                cx: 0.18, cy: 0.08, radius: 1.15,
                fx: 0.18, fy: 0.08,
                stop: 0 #17203a,
                stop: 0.45 #0e1529,
                stop: 1 #070b15
            );
        }

        QFrame#Card {
            background: rgba(13, 19, 34, 0.94);
            border: 1px solid rgba(113, 132, 184, 0.20);
            border-radius: 22px;
        }

        QLabel#HeroTitle {
            font-size: 30px;
            font-weight: 700;
            color: #f8fbff;
            letter-spacing: 0.02em;
        }

        QLabel#HeroSubtitle {
            font-size: 13px;
            color: #8d9bb8;
        }

        QLabel#SectionTitle {
            font-size: 18px;
            font-weight: 650;
            color: #f4f7ff;
        }

        QLabel#MutedLabel {
            color: #8b99b5;
        }

        QLineEdit, QTextEdit, QSpinBox {
            background: rgba(10, 16, 31, 0.88);
            color: #f4f8ff;
            border: 1px solid rgba(103, 121, 171, 0.30);
            border-radius: 14px;
            padding: 11px 14px;
            selection-background-color: #3a7afe;
            selection-color: #f8fbff;
        }

        QLineEdit:hover, QTextEdit:hover, QSpinBox:hover {
            border: 1px solid rgba(123, 148, 214, 0.44);
            background: rgba(12, 19, 37, 0.94);
        }

        QLineEdit:focus, QTextEdit:focus, QSpinBox:focus {
            border: 1px solid rgba(83, 138, 255, 0.95);
            background: rgba(13, 20, 38, 1.0);
        }

        QLineEdit[readOnly="true"] {
            color: #dce5ff;
            background: rgba(15, 21, 38, 0.82);
        }

        QPushButton {
            background: rgba(16, 24, 43, 0.96);
            color: #edf2ff;
            border: 1px solid rgba(112, 131, 179, 0.28);
            border-radius: 14px;
            padding: 11px 18px;
            font-weight: 600;
        }

        QPushButton:hover {
            background: rgba(27, 39, 70, 0.98);
            border: 1px solid rgba(141, 168, 226, 0.44);
        }

        QPushButton:pressed {
            background: rgba(12, 19, 36, 0.98);
        }

        QPushButton#PrimaryButton {
            background: qlineargradient(
                x1: 0, y1: 0, x2: 1, y2: 1,
                stop: 0 #2e6cff,
                stop: 1 #4a8bff
            );
            color: #f7faff;
            border: 1px solid rgba(115, 155, 255, 0.70);
        }

        QPushButton#PrimaryButton:hover {
            background: qlineargradient(
                x1: 0, y1: 0, x2: 1, y2: 1,
                stop: 0 #3a7afe,
                stop: 1 #5c98ff
            );
        }

        QPushButton#DangerButton {
            background: rgba(56, 23, 31, 0.96);
            color: #ffcad5;
            border: 1px solid rgba(214, 98, 121, 0.34);
        }

        QPushButton#DangerButton:hover {
            background: rgba(76, 29, 41, 1.0);
            border: 1px solid rgba(235, 116, 140, 0.48);
        }

        QPushButton[feedbackState="success"] {
            background: qlineargradient(
                x1: 0, y1: 0, x2: 1, y2: 1,
                stop: 0 #17b978,
                stop: 1 #23d18b
            );
            color: #07120d;
            border: 1px solid rgba(81, 238, 172, 0.85);
        }

        QTabWidget::pane {
            border: 1px solid rgba(102, 120, 164, 0.20);
            border-radius: 16px;
            top: -1px;
            background: rgba(12, 18, 33, 0.68);
        }

        QTabBar::tab {
            background: rgba(13, 20, 38, 0.62);
            color: #8092b4;
            border-top-left-radius: 12px;
            border-top-right-radius: 12px;
            padding: 11px 18px;
            margin-right: 6px;
        }

        QTabBar::tab:hover {
            color: #dbe6ff;
            background: rgba(23, 33, 59, 0.88);
        }

        QTabBar::tab:selected {
            background: rgba(20, 29, 53, 1.0);
            color: #f4f8ff;
        }

        QTableWidget {
            background: rgba(11, 17, 31, 0.92);
            alternate-background-color: rgba(14, 22, 41, 0.96);
            border: 1px solid rgba(102, 119, 165, 0.22);
            border-radius: 18px;
            color: #edf3ff;
            gridline-color: transparent;
            outline: none;
        }

        QTableWidget::item {
            padding: 12px 10px;
            border-bottom: 1px solid rgba(97, 114, 158, 0.08);
        }

        QTableWidget::item:hover {
            background: rgba(38, 54, 93, 0.72);
        }

        QTableWidget::item:selected {
            background: rgba(51, 94, 196, 0.84);
            color: #f8fbff;
        }

        QHeaderView::section {
            background: rgba(16, 24, 43, 0.96);
            color: #9fb0d1;
            border: none;
            border-bottom: 1px solid rgba(98, 116, 160, 0.18);
            padding: 13px 12px;
            font-weight: 700;
        }

        QScrollBar:vertical {
            background: transparent;
            width: 12px;
            margin: 10px 2px 10px 2px;
        }

        QScrollBar::handle:vertical {
            background: rgba(99, 123, 183, 0.48);
            min-height: 38px;
            border-radius: 6px;
        }

        QScrollBar::handle:vertical:hover {
            background: rgba(127, 155, 226, 0.72);
        }

        QScrollBar:horizontal {
            background: transparent;
            height: 12px;
            margin: 2px 10px 2px 10px;
        }

        QScrollBar::handle:horizontal {
            background: rgba(99, 123, 183, 0.48);
            min-width: 38px;
            border-radius: 6px;
        }

        QScrollBar::handle:horizontal:hover {
            background: rgba(127, 155, 226, 0.72);
        }

        QScrollBar::add-line, QScrollBar::sub-line,
        QScrollBar::add-page, QScrollBar::sub-page {
            background: transparent;
            border: none;
        }

        QStatusBar {
            color: #d9e4ff;
            background: rgba(8, 13, 24, 0.92);
            border-top: 1px solid rgba(96, 113, 159, 0.16);
        }

        QCheckBox {
            spacing: 8px;
            color: #b0bedb;
        }

        QCheckBox::indicator {
            width: 18px;
            height: 18px;
            border-radius: 5px;
            border: 1px solid rgba(117, 137, 187, 0.42);
            background: rgba(11, 17, 31, 0.94);
        }

        QCheckBox::indicator:checked {
            background: #3a7afe;
            border: 1px solid rgba(122, 162, 255, 0.95);
        }
        """
    )

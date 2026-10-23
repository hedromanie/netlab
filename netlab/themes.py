"""Built-in and user-editable color themes for the desktop GUI."""

from __future__ import annotations

from typing import Any

# Semantic color tokens → QSS is built from these so users can edit without QSS knowledge.
DEFAULT_THEMES: dict[str, dict[str, str]] = {
    "dark": {
        "bg": "#0f1115",
        "panel": "#161a21",
        "border": "#2a3140",
        "text": "#e6eaf0",
        "muted": "#8b95a8",
        "accent": "#3b82f6",
        "accent_text": "#ffffff",
        "disabled": "#2a3140",
        "disabled_text": "#8b95a8",
        "selection": "#1c212b",
        "danger": "#ef4444",
        "ok": "#22c55e",
    },
    "light": {
        "bg": "#f4f6f8",
        "panel": "#ffffff",
        "border": "#d5dbe3",
        "text": "#1b1f24",
        "muted": "#526072",
        "accent": "#1d4ed8",
        "accent_text": "#ffffff",
        "disabled": "#d5dbe3",
        "disabled_text": "#64748b",
        "selection": "#dbeafe",
        "danger": "#dc2626",
        "ok": "#16a34a",
    },
    "nord": {
        "bg": "#2e3440",
        "panel": "#3b4252",
        "border": "#4c566a",
        "text": "#eceff4",
        "muted": "#d8dee9",
        "accent": "#5e81ac",
        "accent_text": "#eceff4",
        "disabled": "#4c566a",
        "disabled_text": "#d8dee9",
        "selection": "#434c5e",
        "danger": "#bf616a",
        "ok": "#a3be8c",
    },
}

THEME_LABELS = {
    "en": {
        "bg": "Background",
        "panel": "Panels / inputs",
        "border": "Borders",
        "text": "Text",
        "muted": "Secondary text",
        "accent": "Accent (buttons)",
        "accent_text": "Button text",
        "disabled": "Disabled button",
        "disabled_text": "Disabled text",
        "selection": "Selection",
        "danger": "Error / stop",
        "ok": "Success",
    },
    "ru": {
        "bg": "Фон окна",
        "panel": "Панели / поля",
        "border": "Рамки",
        "text": "Текст",
        "muted": "Вторичный текст",
        "accent": "Акцент (кнопки)",
        "accent_text": "Текст на кнопке",
        "disabled": "Неактивная кнопка",
        "disabled_text": "Неактивный текст",
        "selection": "Выделение",
        "danger": "Ошибка / стоп",
        "ok": "Успех",
    },
}


def merge_themes(user_themes: dict[str, Any] | None) -> dict[str, dict[str, str]]:
    """Built-ins + user overrides (user wins per key)."""
    out: dict[str, dict[str, str]] = {k: dict(v) for k, v in DEFAULT_THEMES.items()}
    if not user_themes:
        return out
    for name, colors in user_themes.items():
        if not isinstance(colors, dict):
            continue
        base = dict(out.get(name, DEFAULT_THEMES["dark"]))
        for key, value in colors.items():
            if isinstance(value, str) and value.strip():
                base[str(key)] = value.strip()
        out[str(name)] = base
    return out


def build_qss(colors: dict[str, str]) -> str:
    c = {**DEFAULT_THEMES["dark"], **colors}
    return f"""
        QWidget {{ background: {c['bg']}; color: {c['text']}; }}
        QMainWindow, QDialog {{ background: {c['bg']}; }}
        QTreeWidget, QLineEdit, QTextEdit, QPlainTextEdit, QComboBox, QSpinBox, QTextBrowser {{
            background: {c['panel']}; border: 1px solid {c['border']};
            border-radius: 6px; padding: 6px; color: {c['text']};
            selection-background-color: {c['selection']};
        }}
        QTreeWidget::item {{ padding: 6px 4px; }}
        QTreeWidget::item:selected {{ background: {c['selection']}; color: {c['text']}; }}
        QTreeWidget::item:hover {{ background: {c['selection']}; }}
        QPushButton {{
            background: {c['accent']}; color: {c['accent_text']};
            border: none; padding: 9px 18px; border-radius: 6px; font-weight: 600;
        }}
        QPushButton:hover {{ opacity: 0.92; }}
        QPushButton:disabled {{ background: {c['disabled']}; color: {c['disabled_text']}; }}
        QPushButton#danger {{ background: {c['danger']}; color: #ffffff; }}
        QPushButton#secondary {{
            background: {c['panel']}; color: {c['text']};
            border: 1px solid {c['border']};
        }}
        QLabel#title {{ font-size: 18px; font-weight: 600; color: {c['text']}; }}
        QLabel#desc, QLabel#muted {{ color: {c['muted']}; }}
        QStatusBar {{ background: {c['panel']}; color: {c['muted']}; border-top: 1px solid {c['border']}; }}
        QCheckBox {{ spacing: 8px; }}
        QGroupBox {{
            border: 1px solid {c['border']}; border-radius: 6px;
            margin-top: 10px; padding-top: 8px; color: {c['text']};
        }}
        QGroupBox::title {{ subcontrol-origin: margin; left: 10px; padding: 0 4px; }}
        QTextEdit#output, QTextBrowser {{
            font-family: "Cascadia Mono", "Consolas", "JetBrains Mono", monospace;
            font-size: 12px;
        }}
        QSplitter::handle {{ background: {c['border']}; width: 2px; }}
        QScrollBar:vertical {{ background: {c['bg']}; width: 10px; }}
        QScrollBar::handle:vertical {{ background: {c['border']}; border-radius: 4px; min-height: 24px; }}
    """

"""Desktop GUI for NetForge — categories, session form cache, themes, help."""

from __future__ import annotations

import sys
import traceback
from typing import Any

from netlab.core import Engine, is_admin, load_gui_settings, save_gui_settings
from netlab.i18n import CATEGORIES, HELP, UI, param_label
from netlab.output import MODULE_TITLE, STATUS_RU, _fmt_bytes
from netlab.themes import DEFAULT_THEMES, THEME_LABELS, build_qss, merge_themes


def main() -> None:
    try:
        from PySide6.QtCore import QObject, Qt, QThread, Signal
        from PySide6.QtGui import QColor, QFont
        from PySide6.QtWidgets import (
            QApplication,
            QCheckBox,
            QColorDialog,
            QComboBox,
            QDialog,
            QFormLayout,
            QGroupBox,
            QHBoxLayout,
            QLabel,
            QLineEdit,
            QMainWindow,
            QMessageBox,
            QPushButton,
            QScrollArea,
            QSplitter,
            QStatusBar,
            QTextBrowser,
            QTextEdit,
            QTreeWidget,
            QTreeWidgetItem,
            QVBoxLayout,
            QWidget,
        )
    except ImportError:
        sys.stderr.write(
            "PySide6 is not installed.\nInstall with: pip install -e .\n"
        )
        raise SystemExit(1)

    # ------------------------------------------------------------------ runners
    class Runner(QObject):
        log = Signal(str)
        finished = Signal(dict)

        def __init__(self, engine: Engine, name: str, params: dict[str, Any]) -> None:
            super().__init__()
            self.engine = engine
            self.name = name
            self.params = params
            self.instance = None

        def stop(self) -> None:
            if self.instance is not None:
                self.instance.request_stop()

        def run(self) -> None:
            import io
            from contextlib import redirect_stdout

            class _Writer(io.TextIOBase):
                def write(self, s: str) -> int:  # type: ignore[override]
                    if s:
                        outer.log.emit(s)
                    return len(s)

                def flush(self) -> None:
                    return None

            outer = self

            def on_start(instance) -> None:
                self.instance = instance

            try:
                with redirect_stdout(_Writer()):
                    logger = self.engine.run_module(
                        self.name, self.params, on_start=on_start
                    )
                self.finished.emit(
                    {
                        "ok": True,
                        "status": logger.status,
                        "packets": logger.packets_sent,
                        "bytes": logger.bytes_sent,
                        "path": str(logger.path) if logger.path else "",
                        "module": self.name,
                    }
                )
            except Exception as exc:  # noqa: BLE001
                self.log.emit(traceback.format_exc())
                self.finished.emit({"ok": False, "status": "error", "error": str(exc)})

    # ------------------------------------------------------------------ theme editor
    class ThemeEditorDialog(QDialog):
        def __init__(self, parent, settings: dict[str, Any], lang: str) -> None:
            super().__init__(parent)
            self.settings = settings
            self.lang = lang
            self.setWindowTitle("Theme editor" if lang == "en" else "Редактор темы")
            self.resize(480, 560)
            themes = merge_themes(settings.get("custom_themes"))
            self.theme_name = settings.get("theme") or "dark"
            if self.theme_name not in themes:
                self.theme_name = "dark"
            self.colors = dict(themes[self.theme_name])

            layout = QVBoxLayout(self)
            row = QHBoxLayout()
            row.addWidget(QLabel("Theme:" if lang == "en" else "Тема:"))
            self.name_combo = QComboBox()
            for name in themes:
                self.name_combo.addItem(name, name)
            idx = self.name_combo.findData(self.theme_name)
            if idx >= 0:
                self.name_combo.setCurrentIndex(idx)
            self.name_combo.currentIndexChanged.connect(self._load_selected)
            row.addWidget(self.name_combo, 1)
            layout.addLayout(row)

            self.form = QFormLayout()
            self.editors: dict[str, QLineEdit] = {}
            labels = THEME_LABELS.get(lang, THEME_LABELS["en"])
            for key in DEFAULT_THEMES["dark"]:
                edit = QLineEdit(self.colors.get(key, ""))
                btn = QPushButton("…")
                btn.setFixedWidth(36)
                btn.clicked.connect(lambda _=False, k=key: self._pick(k))
                cell = QWidget()
                hl = QHBoxLayout(cell)
                hl.setContentsMargins(0, 0, 0, 0)
                hl.addWidget(edit, 1)
                hl.addWidget(btn)
                self.editors[key] = edit
                self.form.addRow(labels.get(key, key), cell)
            layout.addLayout(self.form)

            tip = QLabel(
                "Save as custom name to keep built-ins intact."
                if lang == "en"
                else "Сохраните под именем custom (или своим), чтобы не затирать built-in."
            )
            tip.setObjectName("muted")
            tip.setWordWrap(True)
            layout.addWidget(tip)

            self.save_name = QLineEdit(self.theme_name if self.theme_name not in DEFAULT_THEMES or self.theme_name == "custom" else "custom")
            layout.addWidget(QLabel("Save as:" if lang == "en" else "Сохранить как:"))
            layout.addWidget(self.save_name)

            buttons = QHBoxLayout()
            save_btn = QPushButton(UI[lang]["apply"])
            close_btn = QPushButton(UI[lang]["close"])
            close_btn.setObjectName("secondary")
            save_btn.clicked.connect(self._save)
            close_btn.clicked.connect(self.reject)
            buttons.addWidget(save_btn)
            buttons.addWidget(close_btn)
            layout.addLayout(buttons)

        def _load_selected(self) -> None:
            name = self.name_combo.currentData()
            themes = merge_themes(self.settings.get("custom_themes"))
            self.colors = dict(themes.get(name, DEFAULT_THEMES["dark"]))
            for key, edit in self.editors.items():
                edit.setText(self.colors.get(key, ""))

        def _pick(self, key: str) -> None:
            current = QColor(self.editors[key].text() or "#ffffff")
            color = QColorDialog.getColor(current, self)
            if color.isValid():
                self.editors[key].setText(color.name())

        def _save(self) -> None:
            name = (self.save_name.text() or "custom").strip()
            colors = {k: e.text().strip() for k, e in self.editors.items() if e.text().strip()}
            customs = dict(self.settings.get("custom_themes") or {})
            customs[name] = colors
            self.settings["custom_themes"] = customs
            self.settings["theme"] = name
            self.accept()

    # ------------------------------------------------------------------ settings
    class SettingsDialog(QDialog):
        def __init__(self, parent, settings: dict[str, Any]) -> None:
            super().__init__(parent)
            self.settings = dict(settings)
            lang = self.settings["language"]
            text = UI[lang]
            self.setWindowTitle(text["settings"])
            self.setMinimumWidth(400)
            form = QFormLayout(self)

            self.language = QComboBox()
            self.language.addItem("Русский", "ru")
            self.language.addItem("English", "en")
            self.language.setCurrentIndex(0 if lang == "ru" else 1)

            themes = merge_themes(self.settings.get("custom_themes"))
            self.theme = QComboBox()
            for key in themes:
                label = text["themes"].get(key, key)
                self.theme.addItem(label, key)
            idx = self.theme.findData(self.settings.get("theme", "dark"))
            if idx >= 0:
                self.theme.setCurrentIndex(idx)

            self.save_logs = QCheckBox(text["save_logs"])
            self.save_logs.setChecked(bool(self.settings["save_logs"]))

            form.addRow(text["language"], self.language)
            form.addRow(text["theme"], self.theme)
            form.addRow(self.save_logs)

            edit_theme = QPushButton(
                "Edit theme colors…" if lang == "en" else "Редактировать цвета темы…"
            )
            edit_theme.setObjectName("secondary")
            edit_theme.clicked.connect(self._edit_theme)
            form.addRow(edit_theme)

            buttons = QHBoxLayout()
            apply_btn = QPushButton(text["apply"])
            close_btn = QPushButton(text["close"])
            close_btn.setObjectName("secondary")
            apply_btn.clicked.connect(self._apply)
            close_btn.clicked.connect(self.reject)
            buttons.addWidget(apply_btn)
            buttons.addWidget(close_btn)
            form.addRow(buttons)

        def _edit_theme(self) -> None:
            self._apply_to_dict()
            dlg = ThemeEditorDialog(self, self.settings, self.settings["language"])
            if dlg.exec() == QDialog.DialogCode.Accepted:
                self.settings = dlg.settings
                # refresh theme combo
                self.theme.clear()
                text = UI[self.settings["language"]]
                for key in merge_themes(self.settings.get("custom_themes")):
                    self.theme.addItem(text["themes"].get(key, key), key)
                idx = self.theme.findData(self.settings["theme"])
                if idx >= 0:
                    self.theme.setCurrentIndex(idx)

        def _apply_to_dict(self) -> None:
            self.settings["language"] = self.language.currentData()
            self.settings["theme"] = self.theme.currentData()
            self.settings["save_logs"] = self.save_logs.isChecked()

        def _apply(self) -> None:
            self._apply_to_dict()
            self.accept()

    class HelpDialog(QDialog):
        def __init__(self, parent, lang: str) -> None:
            super().__init__(parent)
            self.setWindowTitle(UI[lang]["help"])
            self.resize(760, 600)
            layout = QVBoxLayout(self)
            browser = QTextBrowser()
            browser.setHtml(HELP[lang])
            layout.addWidget(browser)
            close_btn = QPushButton(UI[lang]["close"])
            close_btn.setObjectName("secondary")
            close_btn.clicked.connect(self.accept)
            layout.addWidget(close_btn)

    # ------------------------------------------------------------------ main window
    class MainWindow(QMainWindow):
        def __init__(self) -> None:
            super().__init__()
            self.settings = load_gui_settings()
            # session cache of form values (also persisted to gui.yaml)
            self.param_cache: dict[str, dict[str, Any]] = dict(
                self.settings.get("module_params") or {}
            )
            self.engine = Engine()
            self.engine.config.save_logs = bool(self.settings["save_logs"])
            self.modules = {m["name"]: m for m in self.engine.list_modules()}
            self.fields: dict[str, QWidget] = {}
            self.thread: QThread | None = None
            self.runner: Runner | None = None
            self.current_name: str | None = None

            self.resize(
                int(self.settings.get("window_width", 1120)),
                int(self.settings.get("window_height", 740)),
            )

            root = QWidget()
            outer = QVBoxLayout(root)
            outer.setContentsMargins(10, 10, 10, 8)
            outer.setSpacing(8)

            bar = QHBoxLayout()
            self.settings_btn = QPushButton()
            self.help_btn = QPushButton()
            self.clear_log_btn = QPushButton()
            self.settings_btn.setObjectName("secondary")
            self.help_btn.setObjectName("secondary")
            self.clear_log_btn.setObjectName("secondary")
            self.settings_btn.clicked.connect(self._open_settings)
            self.help_btn.clicked.connect(self._open_help)
            self.clear_log_btn.clicked.connect(lambda: self.output.clear())
            bar.addWidget(self.settings_btn)
            bar.addWidget(self.help_btn)
            bar.addStretch(1)
            bar.addWidget(self.clear_log_btn)
            outer.addLayout(bar)

            splitter = QSplitter()
            left = QWidget()
            left_l = QVBoxLayout(left)
            left_l.setContentsMargins(0, 0, 0, 0)
            self.tree_label = QLabel()
            self.tree_label.setObjectName("muted")
            left_l.addWidget(self.tree_label)
            self.tree = QTreeWidget()
            self.tree.setHeaderHidden(True)
            self.tree.setMinimumWidth(220)
            self.tree.itemSelectionChanged.connect(self._select)
            left_l.addWidget(self.tree, 1)
            splitter.addWidget(left)

            right = QWidget()
            layout = QVBoxLayout(right)
            layout.setContentsMargins(4, 0, 0, 0)
            self.title = QLabel()
            self.title.setObjectName("title")
            self.desc = QLabel()
            self.desc.setWordWrap(True)
            self.desc.setObjectName("desc")
            layout.addWidget(self.title)
            layout.addWidget(self.desc)

            scroll = QScrollArea()
            scroll.setWidgetResizable(True)
            scroll.setFrameShape(scroll.Shape.NoFrame)
            self.form_host = QWidget()
            self.form = QFormLayout(self.form_host)
            self.form.setSpacing(8)
            scroll.setWidget(self.form_host)
            scroll.setMinimumHeight(160)
            layout.addWidget(scroll, 2)

            buttons = QHBoxLayout()
            self.run_btn = QPushButton()
            self.stop_btn = QPushButton()
            self.stop_btn.setObjectName("danger")
            self.stop_btn.setEnabled(False)
            self.run_btn.clicked.connect(self._run)
            self.stop_btn.clicked.connect(self._stop)
            buttons.addWidget(self.run_btn)
            buttons.addWidget(self.stop_btn)
            buttons.addStretch(1)
            layout.addLayout(buttons)

            self.log_label = QLabel()
            self.log_label.setObjectName("muted")
            layout.addWidget(self.log_label)
            self.output = QTextEdit()
            self.output.setReadOnly(True)
            self.output.setObjectName("output")
            layout.addWidget(self.output, 3)

            splitter.addWidget(right)
            splitter.setStretchFactor(0, 0)
            splitter.setStretchFactor(1, 1)
            splitter.setSizes([240, 880])
            outer.addWidget(splitter, 1)
            self.setCentralWidget(root)

            self.status = QStatusBar()
            self.setStatusBar(self.status)

            self._apply_chrome()
            self._restore_last_module()

            if not is_admin():
                self.output.append(
                    UI[self.settings["language"]]["not_admin"]
                )
                self.status.showMessage(
                    "No admin/root — packet modules will fail"
                    if self.settings["language"] == "en"
                    else "Нет прав администратора — модули с пакетами не заработают"
                )

        def _t(self) -> dict[str, Any]:
            return UI[self.settings["language"]]

        def _themes(self) -> dict[str, dict[str, str]]:
            return merge_themes(self.settings.get("custom_themes"))

        def _apply_chrome(self) -> None:
            text = self._t()
            self.setWindowTitle("NetForge")
            self.settings_btn.setText(text["settings"])
            self.help_btn.setText(text["help"])
            self.clear_log_btn.setText(
                "Clear log" if self.settings["language"] == "en" else "Очистить лог"
            )
            self.run_btn.setText(text["run"])
            self.stop_btn.setText(text["stop"])
            self.tree_label.setText(
                "Modules" if self.settings["language"] == "en" else "Модули"
            )
            self.log_label.setText(
                "Output" if self.settings["language"] == "en" else "Вывод"
            )
            if self.current_name is None:
                self.title.setText(text["select"])
                self.desc.setText("")
            theme = self.settings.get("theme", "dark")
            colors = self._themes().get(theme, DEFAULT_THEMES["dark"])
            QApplication.instance().setStyleSheet(build_qss(colors))
            self._fill_tree()

        def _fill_tree(self) -> None:
            current = self.current_name
            self.tree.blockSignals(True)
            self.tree.clear()
            lang = self.settings["language"]
            groups: dict[str, list[dict]] = {}
            for mod in self.modules.values():
                groups.setdefault(mod["category"], []).append(mod)
            order = ["recon", "l2", "l3_l4", "app", "misc"]
            select_item = None
            for category in order:
                items = groups.get(category)
                if not items:
                    continue
                parent = QTreeWidgetItem([CATEGORIES[lang].get(category, category)])
                parent.setFlags(parent.flags() & ~Qt.ItemFlag.ItemIsSelectable)
                for mod in sorted(items, key=lambda m: m["name"]):
                    title = MODULE_TITLE.get(mod["name"], mod["name"])
                    child = QTreeWidgetItem([f"{mod['name']}"])
                    child.setToolTip(0, f"{title}\n{mod['description']}")
                    child.setData(0, Qt.ItemDataRole.UserRole, mod["name"])
                    parent.addChild(child)
                    if current and mod["name"] == current:
                        select_item = child
                self.tree.addTopLevelItem(parent)
                parent.setExpanded(True)
            self.tree.blockSignals(False)
            if select_item is not None:
                self.tree.setCurrentItem(select_item)

        def _restore_last_module(self) -> None:
            last = self.settings.get("last_module")
            if not last or last not in self.modules:
                return
            for i in range(self.tree.topLevelItemCount()):
                parent = self.tree.topLevelItem(i)
                for j in range(parent.childCount()):
                    child = parent.child(j)
                    if child.data(0, Qt.ItemDataRole.UserRole) == last:
                        self.tree.setCurrentItem(child)
                        return

        def _selected_module(self) -> dict | None:
            item = self.tree.currentItem()
            if item is None:
                return None
            name = item.data(0, Qt.ItemDataRole.UserRole)
            if not name:
                return None
            return self.modules.get(name)

        def _clear_form(self) -> None:
            while self.form.rowCount():
                self.form.removeRow(0)
            self.fields.clear()

        def _save_current_form(self) -> None:
            """Keep user inputs when switching modules (session + disk)."""
            if not self.current_name or not self.fields:
                return
            try:
                self.param_cache[self.current_name] = self._collect_raw()
                self.settings["module_params"] = self.param_cache
                self.settings["last_module"] = self.current_name
            except Exception:
                pass

        def _collect_raw(self) -> dict[str, Any]:
            mod = self.modules.get(self.current_name or "")
            if not mod:
                return {}
            params: dict[str, Any] = {}
            for param in mod["parameters"]:
                if param["name"] not in self.fields:
                    continue
                widget = self.fields[param["name"]]
                if isinstance(widget, QCheckBox):
                    params[param["name"]] = widget.isChecked()
                else:
                    params[param["name"]] = widget.text().strip()
            return params

        def _select(self) -> None:
            self._save_current_form()
            mod = self._selected_module()
            if mod is None:
                return
            self.current_name = mod["name"]
            self._clear_form()
            title = MODULE_TITLE.get(mod["name"], mod["name"])
            self.title.setText(f"{title}  ({mod['name']})")
            self.desc.setText(mod["description"])
            lang = self.settings["language"]
            cached = self.param_cache.get(mod["name"], {})
            for param in mod["parameters"]:
                if param["type"] == "interface":
                    continue
                name = param["name"]
                if param["type"] == "bool":
                    widget: QWidget = QCheckBox(param_label(lang, name, param["label"]))
                    default = cached.get(name, param.get("default"))
                    widget.setChecked(bool(default))
                    self.form.addRow(widget)
                else:
                    edit = QLineEdit()
                    if name in cached and cached[name] not in (None, ""):
                        edit.setText(str(cached[name]))
                    elif param.get("default") is not None:
                        edit.setText(str(param["default"]))
                    hint = param.get("description") or ""
                    if hint:
                        edit.setPlaceholderText(hint)
                    widget = edit
                    label = param_label(lang, name, param["label"])
                    if param["required"]:
                        label += " *"
                    self.form.addRow(label, widget)
                self.fields[name] = widget
            self.settings["last_module"] = mod["name"]
            self.status.showMessage(
                f"{title}" if lang == "en" else f"Модуль: {title}"
            )

        def _collect(self) -> dict[str, Any]:
            return self._collect_raw()

        def _run(self) -> None:
            mod = self._selected_module()
            if mod is None or self.thread is not None:
                return
            self._save_current_form()
            save_gui_settings(self.settings)
            params = self._collect()
            self.param_cache[mod["name"]] = params
            self.output.clear()
            title = MODULE_TITLE.get(mod["name"], mod["name"])
            self.output.append(f"── {title} ──\n")
            self.run_btn.setEnabled(False)
            self.stop_btn.setEnabled(True)
            self.status.showMessage(
                "Running…" if self.settings["language"] == "en" else "Выполняется…"
            )
            self.thread = QThread()
            self.runner = Runner(self.engine, mod["name"], params)
            self.runner.moveToThread(self.thread)
            self.thread.started.connect(self.runner.run)
            self.runner.log.connect(self.output.insertPlainText)
            self.runner.finished.connect(self._finished)
            self.runner.finished.connect(self.thread.quit)
            self.thread.finished.connect(self._thread_done)
            self.thread.start()

        def _stop(self) -> None:
            if self.runner is not None:
                self.runner.stop()
                self.output.append(self._t()["stop_req"])
                self.status.showMessage(
                    "Stopping…" if self.settings["language"] == "en" else "Остановка…"
                )

        def _finished(self, result: dict) -> None:
            text = self._t()
            if result.get("ok"):
                st = STATUS_RU.get(result["status"], result["status"])
                log_line = result["path"] or text["logs_off"]
                self.output.append(
                    f"\n── Итог ──\n"
                    f"  Статус     {st}\n"
                    f"  Пакетов    {result['packets']}\n"
                    f"  Объём      {_fmt_bytes(int(result['bytes']))}\n"
                    f"  Лог        {log_line}\n"
                )
                self.status.showMessage(st)
            else:
                QMessageBox.warning(self, "NetForge", result.get("error", "error"))
                self.status.showMessage(
                    "Error" if self.settings["language"] == "en" else "Ошибка"
                )

        def _thread_done(self) -> None:
            self.run_btn.setEnabled(True)
            self.stop_btn.setEnabled(False)
            self.thread = None
            self.runner = None

        def _open_settings(self) -> None:
            self._save_current_form()
            dialog = SettingsDialog(self, self.settings)
            if dialog.exec() != QDialog.DialogCode.Accepted:
                return
            self.settings = dialog.settings
            self.settings["module_params"] = self.param_cache
            save_gui_settings(self.settings)
            self.engine.config.save_logs = bool(self.settings["save_logs"])
            self._apply_chrome()
            if self.current_name:
                # rebuild form with new language labels but keep values
                for i in range(self.tree.topLevelItemCount()):
                    parent = self.tree.topLevelItem(i)
                    for j in range(parent.childCount()):
                        child = parent.child(j)
                        if child.data(0, Qt.ItemDataRole.UserRole) == self.current_name:
                            self.tree.setCurrentItem(child)
                            return

        def _open_help(self) -> None:
            HelpDialog(self, self.settings["language"]).exec()

        def closeEvent(self, event) -> None:  # noqa: N802
            self._save_current_form()
            self.settings["module_params"] = self.param_cache
            self.settings["window_width"] = self.width()
            self.settings["window_height"] = self.height()
            save_gui_settings(self.settings)
            super().closeEvent(event)

    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    app.setFont(QFont("Segoe UI", 10))
    window = MainWindow()
    window.show()
    raise SystemExit(app.exec())


if __name__ == "__main__":
    main()

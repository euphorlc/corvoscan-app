from PyQt6.QtWidgets import (
    QDialog,
    QVBoxLayout,
    QLabel,
    QPushButton,
    QLineEdit,
    QHBoxLayout,
)


def show_error_popup(parent, message):
    dlg = QDialog(parent)
    dlg.setWindowTitle("Error")
    dlg.setModal(True)
    dlg.setFixedSize(500, 220)

    layout = QVBoxLayout(dlg)
    label = QLabel(message)
    label.setStyleSheet(
        """
        QLabel {
            font-size: 18px;
            color: #222;
            padding: 16px;
        }
    """
    )
    layout.addWidget(label)

    btn = QPushButton("OK")
    btn.setStyleSheet(
        """
        QPushButton {
            background-color: #1976d2;
            color: #fff;
            border-radius: 8px;
            padding: 8px 24px;
            font-size: 16px;
        }
        QPushButton:hover {
            background-color: #1565c0;
        }
    """
    )
    btn.clicked.connect(dlg.accept)
    layout.addWidget(btn)

    dlg.setStyleSheet(
        """
        QDialog {
            background-color: #fff;
            border-radius: 16px;
            border: 1px solid #90caf9;
        }
    """
    )

    # Position: center horizontally, lower vertically
    if parent:
        parent_geom = parent.geometry()
        x = parent_geom.x() + (parent_geom.width() - dlg.width()) // 2
        y = (
            parent_geom.y() + (parent_geom.height() - dlg.height()) // 2 + 100
        )  # Shift down by 100 pixels
        dlg.move(x, y)
    dlg.exec()


def show_info_popup(parent, message, title="Info"):
    dlg = QDialog(parent)
    dlg.setWindowTitle(title)
    dlg.setModal(True)
    dlg.setFixedSize(480, 160)
    layout = QVBoxLayout(dlg)
    label = QLabel(message)
    label.setStyleSheet("QLabel { font-size: 16px; color: #222; padding: 12px; }")
    layout.addWidget(label)
    btn = QPushButton("OK")
    btn.setStyleSheet(
        """
        QPushButton { background-color: #1976d2; color: #fff; border-radius:8px; padding:8px 20px; font-size:14px; }
        QPushButton:hover { background-color: #1565c0; }
    """
    )
    btn.clicked.connect(dlg.accept)
    btn_row = QHBoxLayout()
    btn_row.addStretch()
    btn_row.addWidget(btn)
    layout.addLayout(btn_row)
    dlg.setStyleSheet(
        "QDialog { background-color: #fff; border-radius: 12px; border: 1px solid #90caf9; }"
    )
    if parent:
        pg = parent.geometry()
        dlg.move(
            pg.x() + (pg.width() - dlg.width()) // 2,
            pg.y() + (pg.height() - dlg.height()) // 2 + 60,
        )
    dlg.exec()


def show_warning_popup(parent, message, title="Warning"):
    dlg = QDialog(parent)
    dlg.setWindowTitle(title)
    dlg.setModal(True)
    dlg.setFixedSize(480, 160)
    layout = QVBoxLayout(dlg)
    label = QLabel(message)
    label.setStyleSheet("QLabel { font-size: 16px; color: #222; padding: 12px; }")
    layout.addWidget(label)
    btn = QPushButton("OK")
    btn.setStyleSheet(
        """
        QPushButton { background-color: #f57c00; color: #fff; border-radius:8px; padding:8px 20px; font-size:14px; }
        QPushButton:hover { background-color: #ef6c00; }
    """
    )
    btn.clicked.connect(dlg.accept)
    btn_row = QHBoxLayout()
    btn_row.addStretch()
    btn_row.addWidget(btn)
    layout.addLayout(btn_row)
    dlg.setStyleSheet(
        "QDialog { background-color: #fff; border-radius: 12px; border: 1px solid #ffcc80; }"
    )
    if parent:
        pg = parent.geometry()
        dlg.move(
            pg.x() + (pg.width() - dlg.width()) // 2,
            pg.y() + (pg.height() - dlg.height()) // 2 + 60,
        )
    dlg.exec()


def show_question_popup(parent, message, title="Confirm"):
    dlg = QDialog(parent)
    dlg.setWindowTitle(title)
    dlg.setModal(True)
    dlg.setFixedSize(520, 160)
    layout = QVBoxLayout(dlg)
    label = QLabel(message)
    label.setStyleSheet("QLabel { font-size: 16px; color: #222; padding: 12px; }")
    layout.addWidget(label)
    btn_row = QHBoxLayout()
    btn_row.addStretch()
    btn_yes = QPushButton("Yes")
    btn_no = QPushButton("No")
    btn_yes.setStyleSheet(
        """QPushButton { background-color: #1976d2; color:#fff; border-radius:8px; padding:8px 18px; font-size:14px;} QPushButton:hover{background:#1565c0;}"""
    )
    btn_no.setStyleSheet(
        """QPushButton { background-color: #757575; color:#fff; border-radius:8px; padding:8px 18px; font-size:14px;} QPushButton:hover{background:#616161;}"""
    )
    btn_no.clicked.connect(dlg.reject)
    btn_yes.clicked.connect(dlg.accept)
    btn_no.setFocus()
    btn_row.addWidget(btn_yes)
    btn_row.addSpacing(8)
    btn_row.addWidget(btn_no)
    layout.addLayout(btn_row)
    dlg.setStyleSheet(
        "QDialog { background-color: #fff; border-radius: 12px; border: 1px solid #90caf9; }"
    )
    if parent:
        pg = parent.geometry()
        dlg.move(
            pg.x() + (pg.width() - dlg.width()) // 2,
            pg.y() + (pg.height() - dlg.height()) // 2 + 60,
        )
    return dlg.exec() == QDialog.DialogCode.Accepted


def show_terminal_clear_choice(parent):
    """Show a dialog with three choices:
    - Clear All
    - Clear This Terminal Only
    - Cancel
    Returns:
      "all"  -> user chose Clear All
      "this" -> user chose Clear This Terminal Only
      None   -> user cancelled
    """
    dlg = QDialog(parent)
    dlg.setWindowTitle("Clear Terminal")
    dlg.setModal(True)
    dlg.setFixedSize(520, 180)

    layout = QVBoxLayout(dlg)
    label = QLabel("Choose how you want to clear the terminal output:")
    label.setStyleSheet("QLabel { font-size: 16px; color: #222; padding: 12px; }")
    layout.addWidget(label)

    # Primary / secondary button styles (match other popups)
    btn_primary = """
        QPushButton {
            background-color: #1976d2;
            color: #fff;
            border-radius: 8px;
            padding: 8px 18px;
            font-size: 14px;
        }
        QPushButton:hover {
            background-color: #1565c0;
        }
    """
    btn_secondary = """
        QPushButton {
            background-color: #757575;
            color: #fff;
            border-radius: 8px;
            padding: 8px 18px;
            font-size: 14px;
        }
        QPushButton:hover {
            background-color: #616161;
        }
    """

    btn_row = QHBoxLayout()
    btn_row.addStretch()

    btn_all = QPushButton("Clear All")
    btn_this = QPushButton("Clear This Terminal Only")
    btn_cancel = QPushButton("Cancel")

    btn_all.setStyleSheet(btn_primary)
    btn_this.setStyleSheet(btn_secondary)
    btn_cancel.setStyleSheet(btn_secondary)

    # Wire up actions using distinct result codes
    def _accept_all():
        dlg.done(1)

    def _accept_this():
        dlg.done(2)

    def _cancel():
        dlg.reject()

    btn_all.clicked.connect(_accept_all)
    btn_this.clicked.connect(_accept_this)
    btn_cancel.clicked.connect(_cancel)

    # Default focus to Cancel to avoid accidental clears
    btn_cancel.setFocus()

    btn_row.addWidget(btn_all)
    btn_row.addSpacing(8)
    btn_row.addWidget(btn_this)
    btn_row.addSpacing(8)
    btn_row.addWidget(btn_cancel)
    layout.addLayout(btn_row)

    # Unified dialog chrome
    dlg.setStyleSheet(
        "QDialog { background-color: #fff; border-radius: 12px; border: 1px solid #90caf9; }"
    )

    # Center relative to parent (slightly lower)
    if parent:
        pg = parent.geometry()
        dlg.move(
            pg.x() + (pg.width() - dlg.width()) // 2,
            pg.y() + (pg.height() - dlg.height()) // 2 + 60,
        )

    res = dlg.exec()
    if res == 1:
        return "all"
    if res == 2:
        return "this"
    return None


def show_critical_popup(parent, message, title="Error"):
    dlg = QDialog(parent)
    dlg.setWindowTitle(title)
    dlg.setModal(True)
    dlg.setFixedSize(520, 180)

    layout = QVBoxLayout(dlg)
    label = QLabel(message)
    # keep message text emphasized (red) but use the same dialog/button chrome as show_error_popup
    label.setStyleSheet(
        """
        QLabel {
            font-size: 16px;
            color: #b71c1c;
            padding: 12px;
        }
    """
    )
    layout.addWidget(label)

    btn = QPushButton("OK")
    # reuse the same primary button styling used by show_error_popup
    btn.setStyleSheet(
        """
        QPushButton {
            background-color: #1976d2;
            color: #fff;
            border-radius: 8px;
            padding: 8px 24px;
            font-size: 16px;
        }
        QPushButton:hover {
            background-color: #1565c0;
        }
    """
    )
    btn.clicked.connect(dlg.accept)
    btn_row = QHBoxLayout()
    btn_row.addStretch()
    btn_row.addWidget(btn)
    layout.addLayout(btn_row)

    dlg.setStyleSheet(
        """
        QDialog {
            background-color: #fff;
            border-radius: 12px;
            border: 1px solid #90caf9;
        }
    """
    )

    if parent:
        pg = parent.geometry()
        dlg.move(
            pg.x() + (pg.width() - dlg.width()) // 2,
            pg.y() + (pg.height() - dlg.height()) // 2 + 60,
        )
    dlg.exec()


def show_confirm_clear(parent, area_name):
    """Show a confirmation dialog asking to clear the given area name.
    Returns True if the user confirms, False otherwise.
    """
    dlg = QDialog(parent)
    dlg.setWindowTitle("Confirm Clear")
    dlg.setModal(True)
    dlg.setFixedSize(480, 160)

    layout = QVBoxLayout(dlg)
    label = QLabel(f"Are you sure you want to clear {area_name}?")
    label.setStyleSheet("QLabel { font-size: 16px; color: #222; padding: 12px; }")
    layout.addWidget(label)

    # Primary / secondary button styles (match other popups)
    btn_primary = """
        QPushButton {
            background-color: #1976d2;
            color: #fff;
            border-radius: 8px;
            padding: 8px 20px;
            font-size: 14px;
        }
        QPushButton:hover {
            background-color: #1565c0;
        }
    """
    btn_secondary = """
        QPushButton {
            background-color: #757575;
            color: #fff;
            border-radius: 8px;
            padding: 8px 20px;
            font-size: 14px;
        }
        QPushButton:hover {
            background-color: #616161;
        }
    """

    btn_row = QHBoxLayout()
    btn_row.addStretch()

    btn_yes = QPushButton("Yes")
    btn_no = QPushButton("No")
    btn_yes.setStyleSheet(btn_primary)
    btn_no.setStyleSheet(btn_secondary)

    btn_no.clicked.connect(dlg.reject)
    btn_yes.clicked.connect(dlg.accept)

    # Default focus to No to avoid accidental clears
    btn_no.setFocus()

    btn_row.addWidget(btn_yes)
    btn_row.addSpacing(8)
    btn_row.addWidget(btn_no)
    layout.addLayout(btn_row)

    # Unified dialog chrome
    dlg.setStyleSheet(
        "QDialog { background-color: #fff; border-radius: 12px; border: 1px solid #90caf9; }"
    )

    # Center relative to parent (slightly lower)
    if parent:
        pg = parent.geometry()
        dlg.move(
            pg.x() + (pg.width() - dlg.width()) // 2,
            pg.y() + (pg.height() - dlg.height()) // 2 + 60,
        )

    return dlg.exec() == QDialog.DialogCode.Accepted

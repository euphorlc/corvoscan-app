from PyQt6.QtWidgets import QDialog, QVBoxLayout, QLabel, QPushButton, QMessageBox

def show_error_popup(parent, message):
    dlg = QDialog(parent)
    dlg.setWindowTitle("Error")
    dlg.setModal(True)
    dlg.setFixedSize(500, 220)

    layout = QVBoxLayout(dlg)
    label = QLabel(message)
    label.setStyleSheet("""
        QLabel {
            font-size: 18px;
            color: #222;
            padding: 16px;
        }
    """)
    layout.addWidget(label)

    btn = QPushButton("OK")
    btn.setStyleSheet("""
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
    """)
    btn.clicked.connect(dlg.accept)
    layout.addWidget(btn)

    dlg.setStyleSheet("""
        QDialog {
            background-color: #fff;
            border-radius: 16px;
            border: 1px solid #90caf9;
        }
    """)

    # Position: center horizontally, lower vertically
    if parent:
        parent_geom = parent.geometry()
        x = parent_geom.x() + (parent_geom.width() - dlg.width()) // 2
        y = parent_geom.y() + (parent_geom.height() - dlg.height()) // 2 + 100  # Shift down by 100 pixels
        dlg.move(x, y)
    dlg.exec()

def show_info_popup(parent, message, title="Info"):
    msg = QMessageBox(parent)
    msg.setIcon(QMessageBox.Icon.Information)
    msg.setWindowTitle(title)
    msg.setText(message)
    msg.exec()

def show_warning_popup(parent, message, title="Warning"):
    msg = QMessageBox(parent)
    msg.setIcon(QMessageBox.Icon.Warning)
    msg.setWindowTitle(title)
    msg.setText(message)
    msg.exec()

def show_question_popup(parent, message, title="Confirm"):
    msg = QMessageBox(parent)
    msg.setIcon(QMessageBox.Icon.Question)
    msg.setWindowTitle(title)
    msg.setText(message)
    msg.setStandardButtons(QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
    return msg.exec() == QMessageBox.StandardButton.Yes

def show_confirm_clear(parent, area_name):
    """Show a confirmation dialog asking to clear the given area name.
    Returns True if the user confirms, False otherwise.
    """
    resp = QMessageBox.question(parent, "Confirm Clear",
                                f"Are you sure you want to clear {area_name}?",
                                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                                QMessageBox.StandardButton.No)
    return resp == QMessageBox.StandardButton.Yes

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
    dlg = QMessageBox(parent)
    dlg.setWindowTitle("Clear Terminal")
    dlg.setText("Choose how you want to clear the terminal output:")
    dlg.setIcon(QMessageBox.Icon.Question)

    # Custom buttons
    btn_all = dlg.addButton("Clear All", QMessageBox.ButtonRole.AcceptRole)
    btn_this = dlg.addButton("Clear This Terminal Only", QMessageBox.ButtonRole.DestructiveRole)
    btn_cancel = dlg.addButton("Cancel", QMessageBox.ButtonRole.RejectRole)

    # Set default focus on Cancel to avoid accidental clears
    dlg.setDefaultButton(btn_cancel)

    dlg.exec()

    clicked = dlg.clickedButton()
    if clicked is btn_all:
        return "all"
    if clicked is btn_this:
        return "this"
    return None
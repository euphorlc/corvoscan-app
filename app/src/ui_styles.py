from PyQt6.QtWidgets import QFrame, QLabel, QSizePolicy, QListView
from PyQt6.QtCore import Qt


def rounded_frame():
    """Return a QFrame with the app's rounded background style applied."""
    frame = QFrame()
    frame.setStyleSheet(
        """
        QFrame {
            background: #f5f5f5;
            border-radius: 20px;
            /* subtle faint border for every main "div" */
            border: 1px solid rgba(0,0,0,0.06);
        }
    """
    )
    return frame


def create_division_title(text: str):
    """Return a styled QLabel for section titles."""
    label = QLabel(text)
    label.setStyleSheet("font-size: 18px; font-weight: bold; border: none;")
    label.setSizePolicy(QSizePolicy.Policy.Minimum, QSizePolicy.Policy.Minimum)
    label.setAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignTop)
    return label


def limit_combo_popup(combo, max_items: int = 10):
    """Ensure a QComboBox popup shows at most max_items visually by using a QListView
    and constraining its height based on font metrics."""
    try:
        combo.setMaxVisibleItems(max_items)
        view = QListView()
        combo.setView(view)
        fm = combo.fontMetrics()
        row_h = fm.height() + 6
        visible = min(max_items, combo.count() if combo.count() > 0 else max_items)
        height = max(24, int(row_h * visible + 4))
        view.setMaximumHeight(height)
        view.setMinimumHeight(0)
        view.setUniformItemSizes(True)
        view.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        try:
            popup = view.window()
            if popup is not None:
                popup.setMaximumHeight(height)
                popup.setMinimumHeight(0)
        except Exception:
            pass
        view.setStyleSheet(f"QListView {{ max-height: {height}px; }}")
    except Exception:
        pass


# Button styles used by CollapsibleCategory and elsewhere
DEFAULT_BTN_STYLE = """
    QPushButton {
        background: #e0e0e0;
        color: #222;
        border-radius: 8px;
        padding: 4px 16px;
        font-size: 16px;
        border: none;
        min-width: 80px;
    }
    QPushButton:hover {
        background: #cccccc;
    }
"""

ACTIVE_BTN_STYLE = """
    QPushButton {
        background: #a3d8f4;
        color: #222;
        border-radius: 8px;
        padding: 4px 16px;
        font-size: 16px;
        border: none;
        min-width: 80px;
    }
    QPushButton:hover {
        background: #90caf9;
    }
"""

# Application tooltip + combobox popup styling applied at startup (via app.setStyleSheet)
TOOLTIP_APP_STYLE = """
/* Tooltip styling (slightly dark so text is readable) */
QToolTip {
    background-color: #ffffff;
    color: #2b2b2b;
    font-weight: normal;
    border: 1px solid #444;
    padding: 8px;
    border-radius: 8px;
}

/* Ensure combobox popup (the dropdown list) has a dark background and readable text */
QComboBox QAbstractItemView {
    background-color: #2b2b2b;
    color: #f5f5f5;
    selection-background-color: #1976d2;
    selection-color: #ffffff;
    outline: 0;
}
QComboBox QAbstractItemView::item:hover {
    background-color: #155fa0;
    color: #ffffff;
}

/* Make the combobox text itself readable */
QComboBox {
    color: #222222;
}
"""

# Parameter panel / QScrollArea styling (used by ToolNameBox)
PARAMETER_SCROLL_STYLE = """
QScrollArea {
    border: none;
    background: transparent;
}
QScrollBar:vertical {
    background: #f0f0f0;
    width: 8px;
    margin: 2px 0 2px 0;
    border-radius: 4px;
}
QScrollBar::handle:vertical {
    background: #bdbdbd;
    min-height: 24px;
    border-radius: 4px;
}
QScrollBar::handle:vertical:hover {
    background: #90caf9;
}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
    height: 0px;
    background: none;
    border: none;
}
QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical {
    background: none;
}
"""

# Results/Diagnostics QTextEdit styling (shared)
RESULTS_SCROLLBAR_STYLE = """
QTextEdit {
    background: #fff;
    color: #222;
    border-radius: 8px;
}
/* vertical scrollbar styling to match parameters/results pane */
QTextEdit QScrollBar:vertical {
    background: #f0f0f0;
    width: 8px;
    margin: 2px 0 2px 0;
    border-radius: 4px;
}
QTextEdit QScrollBar::handle:vertical {
    background: #bdbdbd;
    min-height: 24px;
    border-radius: 4px;
}
QTextEdit QScrollBar::handle:vertical:hover {
    background: #90caf9;
}
QTextEdit QScrollBar::add-line:vertical, QTextEdit QScrollBar::sub-line:vertical {
    height: 0px;
    background: none;
    border: none;
}
QTextEdit QScrollBar::add-page:vertical, QTextEdit QScrollBar::sub-page:vertical {
    background: none;
}
"""

# Document-level CSS used to make tables not wrap (applied via QTextDocument.setDefaultStyleSheet)
RESULTS_CSS = """
    table { table-layout: fixed; width: 100%; border-collapse: collapse; }
    th, td { white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
    /* keep other block content normal-wrapping */
    div, p, span { white-space: normal; }
    pre { white-space: pre-wrap; word-wrap: break-word; }
"""

# Scan button styles (Start/Stop and selected variants)
SCAN_START_STYLE = """
    QPushButton {
        font-size: 22px;
        border-radius: 14px;
        background: #4caf50;
        color: white;
        font-weight: bold;
    }
    QPushButton:pressed {
        background: #388e3c;
    }
"""
SCAN_STOP_STYLE = """
    QPushButton {
        font-size: 22px;
        border-radius: 14px;
        background: #f44336;
        color: white;
        font-weight: bold;
    }
    QPushButton:pressed {
        background: #b71c1c;
    }
"""
SCAN_SELECTED_START_STYLE = """
    QPushButton {
        font-size: 18px;
        border-radius: 14px;
        background: #4caf50;
        color: white;
        font-weight: bold;
    }
    QPushButton:pressed {
        background: #388e3c;
    }
"""
SCAN_SELECTED_STOP_STYLE = """
    QPushButton {
        font-size: 18px;
        border-radius: 14px;
        background: #f44336;
        color: white;
        font-weight: bold;
    }
    QPushButton:pressed {
        background: #b71c1c;
    }
"""

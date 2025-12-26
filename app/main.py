# --- Imports ---
import sys
import os
import re
import json
import time
from PyQt6.QtCore import pyqtSignal
from unittest import result
from PyQt6.QtCore import pyqtSignal, QRegularExpression
from PyQt6.QtWidgets import (
    QApplication,
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QLabel,
    QFrame,
    QLineEdit,
    QSizePolicy,
    QPushButton,
    QCheckBox,
    QTextEdit,
    QScrollArea,
    QPlainTextEdit,
    QFileDialog,
    QInputDialog,
    QComboBox,
    QListView,
    QTabWidget,
    QRadioButton,
    QButtonGroup,
    QMessageBox,
)
from PyQt6.QtWidgets import QToolTip
from PyQt6.QtWebEngineWidgets import QWebEngineView
from PyQt6.QtCore import QUrl
from PyQt6.QtGui import QGuiApplication
from PyQt6.QtGui import QFont
from PyQt6.QtCore import Qt, QTimer, QEvent, QObject
from PyQt6.QtGui import QCursor, QTextDocument, QRegularExpressionValidator
from PyQt6.QtPrintSupport import QPrinter

from src.scan_handler import ScanHandler
from src.popup_utils import (
    show_error_popup,
    show_confirm_clear,
    show_terminal_clear_choice,
    show_info_popup,
    show_critical_popup,
    show_confirm_new_scan,
)
from src.results_parser import ResultsManager
from src.parsers.nmap_parser import NmapResultsParser
from src.parsers.nslookup_parser import NSLookupParser
from src.parsers.theharvester_parser import TheHarvesterParser
from src.parsers.dnsenum_parser import DNSEnumResultsParser
from src.parsers.whois_parser import WhoisParser
from src.parsers.whatweb_parser import WhatWebParser
from src.parsers.ffuf_parser import FFUFParser

from src.scanners.nmap_tools import value_required as nmap_value_required
from src.scanners.whatweb_tool import value_required as whatweb_value_required
from src.scanners.whois_tool import (
    value_required as whois_value_required,
    value_optional as whois_value_optional,
)
from src.scanners.ffuf_tool import value_required as ffuf_value_required
from src.scanners.theharvester_tool import value_required as theharvester_value_required
from src.scanners.dnsenum_tool import value_required as dnsenum_value_required
from src.scanners import (
    nmap_tools,
    whatweb_tool,
    whois_tool,
    ffuf_tool,
    theharvester_tool,
    nslookup_tool,
    dnsenum_tool,
)


# add import for styling helpers/constants
from src.ui_styles import (
    rounded_frame,
    create_division_title,
    limit_combo_popup,
    DEFAULT_BTN_STYLE,
    ACTIVE_BTN_STYLE,
    TOOLTIP_APP_STYLE,
    PARAMETER_SCROLL_STYLE,
    RESULTS_SCROLLBAR_STYLE,
    RESULTS_CSS,
    SCAN_START_STYLE,
    SCAN_STOP_STYLE,
    SCAN_SELECTED_START_STYLE,
    SCAN_SELECTED_STOP_STYLE,
)


ANSI_RESET = "\x1b[0m"

# --- Helper Functions: UI Styling ---


# Returns a QFrame with rounded corners and background color
def rounded_frame():
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


# Returns a styled QLabel for section titles
def create_division_title(text):
    label = QLabel(text)
    label.setStyleSheet("font-size: 18px; font-weight: bold; border: none;")
    label.setSizePolicy(QSizePolicy.Policy.Minimum, QSizePolicy.Policy.Minimum)
    label.setAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignTop)
    return label


# New helper: limit combo popup height/visible items
def limit_combo_popup(combo: QComboBox, max_items: int = 10):
    """Ensure a QComboBox popup shows at most max_items visually by using a QListView
    and constraining its height based on font metrics."""
    try:
        combo.setMaxVisibleItems(max_items)
        # Force QListView so we can control its height precisely
        view = QListView()
        combo.setView(view)
        # Estimate row height from font metrics (safe fallback)
        fm = combo.fontMetrics()
        row_h = fm.height() + 6  # small padding to match item spacing
        visible = min(max_items, combo.count() if combo.count() > 0 else max_items)
        height = max(24, int(row_h * visible + 4))  # minimal height guard

        # Constrain the list view and its popup window
        view.setMaximumHeight(height)
        view.setMinimumHeight(0)
        view.setUniformItemSizes(True)
        view.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)

        # The view's window is the actual popup — constrain it as well so native popups obey the limit
        try:
            popup = view.window()
            if popup is not None:
                popup.setMaximumHeight(height)
                popup.setMinimumHeight(0)
        except Exception:
            pass

        # also set a stylesheet hint to help platforms obey the limit
        view.setStyleSheet(f"QListView {{ max-height: {height}px; }}")
    except Exception:
        pass


# Small helper widget: a horizontal group of radio buttons that provides
# currentText()/setCurrentText() (QComboBox-like API) so existing save/restore
# code works without further changes.
class RadioChoiceWidget(QWidget):
    def __init__(self, choices, default=None, parent=None):
        super().__init__(parent)
        # use an internal horizontal layout for buttons
        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(8)
        self._buttons = []
        self._group = QButtonGroup(self)
        for i, choice in enumerate(list(choices)):
            rb = QRadioButton(str(choice))
            layout.addWidget(rb)
            self._group.addButton(rb, i)
            self._buttons.append(rb)
        # select default if provided, otherwise first
        if default is not None:
            self.setCurrentText(default)
        elif self._buttons:
            self._buttons[0].setChecked(True)

    def currentText(self):
        btn = self._group.checkedButton()
        return btn.text() if btn else ""

    def setCurrentText(self, text):
        if text is None:
            return
        txt = str(text).lower()
        for rb in self._buttons:
            try:
                if rb.text().lower() == txt:
                    rb.setChecked(True)
                    return
            except Exception:
                pass


# --- CollapsibleCategory: Tool Category Widget ---


class CollapsibleCategory(QWidget):
    def __init__(self, title, tools, callback, highlight_callback):
        super().__init__()
        self.tools = tools
        self.callback = callback
        self.highlight_callback = highlight_callback
        # Define tool descriptions (short and concise)
        self.tool_descriptions = {
            "Whois": "Query domain registration info",
            "NSLookup": "Query DNS records",
            "theHarvester": "Gather emails & subdomains",
            "DNSEnum": "Enumerate DNS records",
            "NMAP": "Network & port scanning",
            "WhatWeb": "Fingerprint web tech",
            "FFUF": "Directory & file fuzzing",
        }
        self.main_layout = QVBoxLayout(self)
        self.main_layout.setSpacing(0)
        self.main_layout.setContentsMargins(0, 0, 0, 0)

        # show a collapse/expand symbol so users know this is a dropdown
        # use a simple unicode triangle: right-pointing when closed, down-pointing when open
        self._raw_title = title
        self.header = QPushButton(f"› {title}")
        # Disable any tooltip on the header so div1 never shows hover popups
        self.header.setToolTip("")
        # Ensure the category header button won't be clipped horizontally
        # by allowing it to expand horizontally and enforcing a modest
        # minimum height so the label is always fully visible.
        try:
            self.header.setSizePolicy(
                QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed
            )
            self.header.setMinimumHeight(40)
        except Exception:
            pass
        try:
            self.header.setAttribute(Qt.WidgetAttribute.WA_HasToolTip, False)
        except Exception:
            pass
        self.header.setCheckable(True)
        self.header.setChecked(False)
        self.header.setStyleSheet(
            """
            QPushButton {
                text-align: left;
                font-size: 16px;
                background: #fafafa;
                border: none;
                border-radius: 12px;
                padding: 8px 12px;
            }
            QPushButton:checked {
                background: #e0e0e0;
            }
        """
        )
        self.main_layout.addWidget(self.header)

        content_frame = QFrame()
        # ensure content_frame cannot show tooltips either
        content_frame.setToolTip("")
        try:
            content_frame.setAttribute(Qt.WidgetAttribute.WA_HasToolTip, False)
        except Exception:
            pass
        # keep content_frame visually clean (no extra borders — main divs use rounded_frame)
        content_frame.setStyleSheet(
            """
            QFrame {
                background: #ffffff;
                border-radius: 10px;
                border: none;
            }
        """
        )
        content_layout = QVBoxLayout(content_frame)
        content_layout.setContentsMargins(8, 8, 8, 8)
        content_layout.setSpacing(8)
        content_layout.setAlignment(Qt.AlignmentFlag.AlignLeft)

        self.tool_buttons = []
        self.default_style = DEFAULT_BTN_STYLE
        self.active_style = ACTIVE_BTN_STYLE

        for tool_name in tools:
            row = QHBoxLayout()
            row.setSpacing(8)
            checkbox = QCheckBox()
            # ensure no hover tooltip appears for the category checkboxes
            checkbox.setToolTip("")
            try:
                checkbox.setAttribute(Qt.WidgetAttribute.WA_HasToolTip, False)
            except Exception:
                pass
            button = QPushButton(tool_name)
            # ensure no hover tooltip appears for the category buttons (div1)
            button.setToolTip("")
            try:
                button.setAttribute(Qt.WidgetAttribute.WA_HasToolTip, False)
            except Exception:
                pass
            button.setStyleSheet(self.default_style)
            button.clicked.connect(
                lambda checked, t=tool_name, cb=checkbox: self.on_button_clicked(t)
                or cb.setChecked(True)
            )
            checkbox.stateChanged.connect(
                lambda state, t=tool_name, btn=button: (
                    btn.click() if state == 2 else None
                )
            )

            # Add description label
            desc_label = QLabel(self.tool_descriptions.get(tool_name, ""))
            desc_label.setStyleSheet(
                "font-size: 11px; color: #666; font-style: italic;"
            )
            desc_label.setWordWrap(True)
            desc_label.setSizePolicy(
                QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Minimum
            )

            row.addWidget(checkbox)
            row.addWidget(button)
            row.addWidget(desc_label, stretch=1)
            content_layout.addLayout(row)
            self.tool_buttons.append((checkbox, button))

        self.scroll_area = QScrollArea()
        # Ensure the scroll area in div1 cannot show tooltips
        self.scroll_area.setToolTip("")
        try:
            self.scroll_area.setAttribute(Qt.WidgetAttribute.WA_HasToolTip, False)
        except Exception:
            pass
        self.scroll_area.setWidgetResizable(True)
        self.scroll_area.setWidget(content_frame)
        # Keep collapsible scroll area borderless (main frames already have faint border)
        self.scroll_area.setStyleSheet(
            """
            QScrollArea { border: none; background: transparent; }
        """
        )
        # Keep the scroll area constrained so expanding the category only reveals
        # the tool container instead of enlarging the parent layout.
        self.scroll_area.setHorizontalScrollBarPolicy(
            Qt.ScrollBarPolicy.ScrollBarAlwaysOff
        )
        # allow vertical scrollbar when needed but constrain height
        self.scroll_area.setVerticalScrollBarPolicy(
            Qt.ScrollBarPolicy.ScrollBarAsNeeded
        )
        self.scroll_area.setSizePolicy(
            QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed
        )
        self.scroll_area.setFixedHeight(
            100
        )  # adjust this value if you want a different visible height
        self.scroll_area.setVisible(False)
        self.main_layout.addWidget(self.scroll_area)

        # update the arrow and visibility when toggled
        def _on_header_toggled(checked: bool):
            try:
                self.scroll_area.setVisible(checked)
                # update symbol: down when open, right when closed
                sym = "⌄" if checked else "›"
                self.header.setText(f"{sym} {self._raw_title}")
            except Exception:
                pass

        self.header.toggled.connect(_on_header_toggled)

    # ... Handles tool button click ...
    def on_button_clicked(self, tool_name):
        self.highlight_callback(tool_name)
        self.callback(tool_name)

    # ... Highlights the active tool button ...
    def set_highlight(self, active_tool):
        for _, button in self.tool_buttons:
            button.setStyleSheet(
                self.active_style
                if button.text() == active_tool
                else self.default_style
            )

    # ... Checks if a tool's checkbox is checked ...
    def is_tool_checked(self, tool_name=None):
        if tool_name is None and self.tools:
            tool_name = self.tools[0]
        for checkbox, button in self.tool_buttons:
            if button.text() == tool_name:
                return checkbox.isChecked()
        return False


# --- ToolNameBox: Tool Details and Parameter Selection ---


class ToolNameBox(QFrame):
    # ... Displays tool name, description, and parameter checkboxes ...
    def __init__(self, tool_name, description, parameters, checked_params):
        super().__init__()
        # Keep the right-side tool box visually clean — no extra border (main divs use rounded_frame)
        self.setStyleSheet(
            """
            QFrame {
                background: #fafafa;
                border-radius: 12px;
                border: none;
            }
        """
        )
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        layout = QVBoxLayout(self)
        layout.setSpacing(8)
        layout.setContentsMargins(16, 12, 16, 12)
        self.tool_name_label = QLabel(f"(i){tool_name}")
        # slightly smaller tool title to free space for terminal
        self.tool_name_label.setStyleSheet("font-size: 16px; font-weight: bold;")
        self.tool_name_label.setSizePolicy(
            QSizePolicy.Policy.Minimum, QSizePolicy.Policy.Minimum
        )
        layout.addWidget(
            self.tool_name_label,
            alignment=Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignTop,
        )

        # show tool description as a tooltip on the tool name instead of a side panel
        self.tool_name_label.setToolTip("")  # default empty, updated in set_tool()

        info_params_layout = QHBoxLayout()
        info_params_layout.setSpacing(8)
        info_params_layout.setContentsMargins(0, 0, 0, 0)
        info_params_layout.setAlignment(Qt.AlignmentFlag.AlignTop)
        params_box = QFrame()
        # Keep parameter container borderless (parameters area should remain visually minimal)
        params_box.setStyleSheet(
            """
            QFrame {
                background: #f5f5f5;
                border-radius: 8px;
                border: none;
            }
        """
        )
        params_box.setSizePolicy(
            QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding
        )
        self.params_widget = QWidget()
        self.params_layout = QVBoxLayout(self.params_widget)
        self.params_layout.setContentsMargins(12, 12, 12, 12)
        self.params_layout.setAlignment(Qt.AlignmentFlag.AlignTop)
        self.param_checks = []
        self.params_title = QLabel("Parameters")
        self.params_title.setStyleSheet(
            "font-size: 16px; font-weight: bold; margin-bottom: 8px;"
        )
        self.params_layout.addWidget(
            self.params_title,
            alignment=Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignTop,
        )
        for i, param in enumerate(parameters):
            cb = QCheckBox(param)
            cb.setChecked(checked_params[i] if i < len(checked_params) else False)
            # slightly smaller checkbox text
            cb.setStyleSheet("font-size: 14px; font-weight: normal; padding: 4px 0;")
            self.param_checks.append(cb)
            self.params_layout.addWidget(cb)
            # If this param needs a value, add a QLineEdit
            if param in nmap_value_required:
                le = QLineEdit()
                # Set specific placeholder text based on parameter type
                # support both "Timing template (-T0-5)" and variants by substring matching
                if "Timing template" in param:
                    le.setPlaceholderText("0-5 (e.g., 4 for aggressive)")
                    le.setToolTip(
                        "Timing templates:\nT0=Paranoid (very slow)\nT1=Sneaky (slow)\nT2=Polite (slow)\nT3=Normal (default)\nT4=Aggressive (fast, recommended)\nT5=Insane (very fast)"
                    )
                elif "Custom port range" in param:
                    le.setPlaceholderText("e.g., 80,443 or 1-1000")
                    le.setToolTip(
                        "Specify ports: single (80), multiple (80,443,8080), or range (1-1000)"
                    )
                elif param == "Host Timeout":
                    le.setPlaceholderText("e.g., 30s, 2m, 1h")
                    le.setToolTip(
                        "Timeout for each host: seconds (30s), minutes (2m), hours (1h)"
                    )
                elif "XML Output" in param:
                    le.setPlaceholderText("filename.xml")
                    le.setToolTip("Output file name for XML results")
                # DNSEnum-specific placeholders/tooltips
                elif param == "DNS server (--dnsserver <IP>)":
                    le.setPlaceholderText("e.g., 8.8.8.8")
                    le.setToolTip(
                        "IP address of the DNS server to query (IPv4 or IPv6)."
                    )
                elif param == "Concurrency (-p <n>)":
                    le.setPlaceholderText("e.g., 10")
                    le.setToolTip("Limit number of concurrent DNS queries (integer).")
                else:
                    le.setPlaceholderText("Enter value")
                self.params_layout.addWidget(le)
                cb.value_input = le  # Attach for later retrieval
            else:
                cb.value_input = None
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setWidget(self.params_widget)
        # use centralized parameter scroll style
        scroll.setStyleSheet(PARAMETER_SCROLL_STYLE)
        scroll.setMinimumHeight(200)

        self.params_widget.setStyleSheet("background: #f5f5f5;")
        params_box_layout = QVBoxLayout(params_box)
        params_box_layout.setContentsMargins(0, 0, 0, 0)
        params_box_layout.addWidget(scroll)
        info_params_layout.addWidget(params_box, stretch=3)
        layout.addLayout(info_params_layout)

    # ... Updates the box with new tool info ...
    def set_tool(self, tool_name, description, parameters, checked_params):
        self.tool_name_label.setText(tool_name)
        # show the description as a hover tooltip on the tool name (keeps UI compact)
        self.tool_name_label.setToolTip(description)

        # Remove all widgets from params_layout
        while self.params_layout.count():
            item = self.params_layout.takeAt(0)
            widget = item.widget()
            if widget is not None:
                widget.setParent(None)
                widget.deleteLater()
        self.param_checks.clear()

        # Add new "Parameters" title
        self.params_title = QLabel("Parameters")
        self.params_title.setStyleSheet(
            "font-size: 16px; font-weight: bold; margin-bottom: 8px;"
        )
        self.params_layout.addWidget(
            self.params_title,
            alignment=Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignTop,
        )

        # Choose the correct value_required list based on tool
        tool_key = tool_name.lower()
        if tool_key == "whois":
            current_value_required = whois_value_required
            current_value_optional = whois_value_optional
        elif tool_key == "whatweb":
            current_value_required = whatweb_value_required
            current_value_optional = []
        elif tool_key == "nmap":
            current_value_required = nmap_value_required
            current_value_optional = []
        elif tool_key == "ffuf":
            current_value_required = ffuf_value_required
            current_value_optional = []
        elif tool_key == "theharvester":
            current_value_required = theharvester_value_required
            current_value_optional = []
        elif tool_key == "dnsenum":
            current_value_required = dnsenum_value_required
            current_value_optional = []
        else:
            current_value_required = []
            current_value_optional = []

        # Use per-module standalone/modifier lists when available
        TOOL_MODULES = {
            "whois": whois_tool,
            "whatweb": whatweb_tool,
            "nmap": nmap_tools,
            "ffuf": ffuf_tool,
            "theharvester": theharvester_tool,
            "nslookup": nslookup_tool,
            "dnsenum": dnsenum_tool,
        }
        module = TOOL_MODULES.get(tool_key)

        def _extract_flags(mod, name):
            if not mod:
                return []
            val = getattr(mod, name, None)
            if val is not None:
                return val
            # fallback: search for class attributes (ToolProcess classes)
            for attr in dir(mod):
                obj = getattr(mod, attr)
                if isinstance(obj, type):
                    val = getattr(obj, name, None)
                    if val is not None:
                        return val
            return []

        current_standalone = _extract_flags(module, "standalone_flags")
        current_modifiers = _extract_flags(module, "modifier_flags")

        # If this tool is FFUF, add the static textbox at the top of the parameters section
        if tool_name.upper() == "FFUF":
            # Add Protocol radio control (required, no checkbox / no big "[REQUIRED]" label)
            # Make font-size match checkbox labels (16px) so it visually aligns with other parameter controls.
            self.protocol_label = QLabel("Protocol:")
            self.protocol_label.setStyleSheet(
                "font-size:16px; color: #444; margin-top:6px;"
            )
            self.protocol_widget = RadioChoiceWidget(["https", "http"], default="https")
            self.protocol_widget.setMinimumWidth(140)
            # Increase radio text size to match checkboxes
            self.protocol_widget.setStyleSheet("QRadioButton { font-size:16px; }")
            self.params_layout.addWidget(
                self.protocol_label, alignment=Qt.AlignmentFlag.AlignLeft
            )
            self.params_layout.addWidget(
                self.protocol_widget, alignment=Qt.AlignmentFlag.AlignLeft
            )

            self.ffuf_static_label = QLabel("FFUF wordlist:")
            # Make wordlist label/input visually consistent with checkboxes (slightly larger font)
            self.ffuf_static_label.setStyleSheet(
                "font-size:16px; color: #444; margin-top:8px;"
            )
            self.ffuf_top_input = QLineEdit()
            self.ffuf_top_input.setPlaceholderText("Select wordlist file path")
            self.ffuf_top_input.setMaximumHeight(30)
            # Larger input font for readability
            self.ffuf_top_input.setStyleSheet("font-size:16px; padding:6px;")
            self.params_layout.addWidget(
                self.ffuf_static_label, alignment=Qt.AlignmentFlag.AlignLeft
            )
            self.params_layout.addWidget(
                self.ffuf_top_input, alignment=Qt.AlignmentFlag.AlignLeft
            )

            select_btn = QPushButton("Select...")
            select_btn.setMaximumWidth(140)
            # Make Select button font similar to other buttons/controls
            select_btn.setStyleSheet("font-size:16px; padding:6px 12px;")

            # open file dialog and set selected path into the textbox
            def _choose_wordlist():
                path, _ = QFileDialog.getOpenFileName(
                    self, "Select wordlist", os.path.expanduser("~"), "All Files (*)"
                )
                if path:
                    self.ffuf_top_input.setText(path)

            select_btn.clicked.connect(_choose_wordlist)
            self.params_layout.addWidget(
                select_btn, alignment=Qt.AlignmentFlag.AlignLeft
            )
        else:
            self.ffuf_top_input = None

        # Insert visual section headers only when needed, keep param_checks order matching [parameters](http://_vscodecontentref_/2)
        orig_params = list(parameters)
        required_fields = [p for p in orig_params if "[REQUIRED]" in p]
        # preserve first-appearance order for groups
        used = set()
        standalone_group = []
        modifier_group = []
        other_group = []
        for p in orig_params:
            if "[REQUIRED]" in p:
                used.add(p)
                continue
            if current_standalone and p in current_standalone:
                if p not in standalone_group:
                    standalone_group.append(p)
                used.add(p)
            elif current_modifiers and p in current_modifiers:
                if p not in modifier_group:
                    modifier_group.append(p)
                used.add(p)
            else:
                if p not in other_group:
                    other_group.append(p)
                # don't mark used here to allow duplicates to be matched by index mapping below

        ordered_params = (
            required_fields + standalone_group + modifier_group + other_group
        )
        # expose the final rendered parameter order so callers (HelloWindow) can map
        # saved checked-flag lists back to the correct parameter names.
        try:
            self._rendered_param_order = list(ordered_params)
        except Exception:
            self._rendered_param_order = list(parameters)

        # helper to find the original index for a parameter (handles duplicates by tracking used indices)
        used_indices = set()

        def find_orig_index(param_name):
            for idx, orig in enumerate(orig_params):
                if idx in used_indices:
                    continue
                if orig == param_name:
                    used_indices.add(idx)
                    return idx
            return None

        # Now iterate ordered_params and render; insert headers only when group appears
        inserted_standalone_section = False
        inserted_modifier_section = False
        for param in ordered_params:
            # For FFUF, Protocol is rendered above as a radio widget — skip creating a checkbox/required label for it.
            if tool_key == "ffuf" and param == "Protocol (http/https)":
                continue
            # Required-style parameters (theHarvester uses "[REQUIRED]" marker)
            is_required_field = "[REQUIRED]" in param
            orig_index = find_orig_index(param)

            if is_required_field:
                param_label = QLabel(param)
                param_label.setStyleSheet(
                    "font-size: 16px; font-weight: bold; padding: 4px 0; color: #d32f2f;"
                )
                self.params_layout.addWidget(param_label)
                cb = QCheckBox(param)
                # Do NOT auto-check the WHOIS server hidden checkbox so it remains optional.
                # The combo can be left blank to indicate "no specific server selected".
                cb.setChecked(False)
                cb.setVisible(False)
                self.param_checks.append(cb)
                # Always show WHOIS server dropdown for -h as a combobox (even if not listed in value_required)
                if param == "WHOIS server (-h)":
                    combo = QComboBox()
                    whois_servers = [
                        # RIRs / general
                        "whois.iana.org",
                        "whois.arin.net",
                        "whois.ripe.net",
                        "whois.apnic.net",
                        "whois.lacnic.net",
                        "whois.afrinic.net",
                        # gTLD / popular registries
                        "whois.verisign-grs.com",
                        "whois.crsnic.net",
                        "whois.godaddy.com",
                        # country and ccTLD examples
                        "whois.nic.uk",
                        "whois.auda.org.au",
                        "whois.cira.ca",
                        "whois.denic.de",
                        "whois.nic.fr",
                        "whois.nic.it",
                        "whois.jprs.jp",
                        "whois.cnnic.cn",
                        "whois.inregistry.net",
                        "whois.registro.br",
                        "whois.tcinet.ru",
                        "whois.mx",
                        "whois.nic.co",
                        "whois.srs.net.nz",
                        "whois.dns.be",
                        "whois.sidn.nl",
                        "whois.iis.se",
                        "whois.norid.no",
                        "whois.nic.es",
                    ]
                    # DO NOT insert a blank option; show only real servers
                    combo.addItems(whois_servers)
                    combo.setMaxVisibleItems(10)
                    combo.setEditable(False)
                    try:
                        combo.setCurrentIndex(0)
                    except Exception:
                        pass
                    combo.setToolTip(
                        "Select WHOIS server for -h flag (editable to paste a custom server)."
                    )
                    combo.setMinimumWidth(300)
                    # ensure popup uses light background + dark text so items are readable
                    try:
                        combo.setStyleSheet(
                            """
                            QComboBox { color: black; background: white; }
                            QComboBox QAbstractItemView {
                                background-color: #ffffff;
                                color: black;
                                selection-background-color: #ff7043;
                                selection-color: black;
                            }
                        """
                        )
                    except Exception:
                        pass
                    # enforce visual max items
                    limit_combo_popup(combo, 10)
                    self.params_layout.addWidget(combo)
                    cb.value_input = combo
                    continue
                # REPLACE: Protocol (was a QComboBox here) -> RadioChoiceWidget
                if param == "Protocol (http/https)":
                    # In the rare fallback path where protocol radio gets created here, ensure consistent styling.
                    radio = RadioChoiceWidget(["https", "http"], default="https")
                    radio.setToolTip(
                        "Choose protocol to use when constructing the target URL for ffuf (https default)."
                    )
                    radio.setMinimumWidth(140)
                    radio.setStyleSheet("QRadioButton { font-size:16px; }")
                    self.params_layout.addWidget(radio)
                    cb.value_input = radio
                    continue
                if param in current_value_required:
                    # For theHarvester source selection show a combobox limited to ~7 visible items
                    if param == "[REQUIRED] Source (-b, --source)":
                        combo = QComboBox()
                        # Common sources — add or adjust as desired
                        sources = [
                            "baidu",
                            # "bevigil",
                            "bing",
                            "bingapi",
                            "brave",
                            # "bufferoverun",
                            # "builtwith",
                            # "censys",
                            "certspotter",
                            # "criminalip",
                            "crtsh",
                            # "dehashed",
                            # "dnsdumpster",
                            "duckduckgo",
                            # "fullhunt",
                            # "github-code",
                            "hackertarget",
                            # "haveibeenpwned",
                            # "hunter",
                            # "hunterhow",
                            # "intelx",
                            # "leaklookup",
                            # "netlas",
                            # "onyphe",
                            "otx",
                            # "pentesttools",
                            # "projectdiscovery",
                            "rapiddns",
                            # "rocketreach",
                            # "securityscorecard",
                            # "securityTrails",
                            # "shodan",
                            "sitedossier",
                            #  "subdomaincenter",
                            #  "subdomainfinderc99",
                            #  "threatminer",
                            #  "tomba",
                            "urlscan",
                            #  "venacus",
                            #  "virustotal",
                            # "whoisxml",
                            "yahoo",
                            # "zoomeye",
                        ]
                        # Insert explicit blank first option (WHOIS-style) and do NOT allow typing
                        combo.insertItem(0, "")
                        combo.addItems(sources)
                        combo.setMaxVisibleItems(10)
                        combo.setEditable(False)
                        try:
                            combo.setCurrentIndex(0)
                        except Exception:
                            pass
                        combo.setToolTip(
                            "Select a source for theHarvester (choose from list)."
                        )
                        combo.setMinimumWidth(220)
                        # Style: displayed text black, popup white, orange hover/selection with black text
                        try:
                            combo.setStyleSheet(
                                """
                                QComboBox { color: black; background: white; }
                                QComboBox QAbstractItemView {
                                    background-color: #ffffff;
                                    color: black;
                                    selection-background-color: #ff7043;
                                    selection-color: black;
                                }
                            """
                            )
                            view = combo.view()
                            view.setMouseTracking(True)
                            view.setStyleSheet(
                                """
                                QAbstractItemView { background-color: #ffffff; color: black; }
                                QListView::item:hover { background-color: #ff7043; color: black; }
                                QListView::item:selected { background-color: #ff7043; color: black; }
                            """
                            )
                            # Add per-item tooltips (show item text on hover)
                            for i in range(combo.count()):
                                combo.setItemData(
                                    i, combo.itemText(i), Qt.ItemDataRole.ToolTipRole
                                )
                            # enforce visual max items
                            limit_combo_popup(combo, 10)
                        except Exception:
                            pass
                        self.params_layout.addWidget(combo)
                        cb.value_input = combo
                    # WHOIS server dropdown
                    elif param == "WHOIS server (-h)":
                        combo = QComboBox()
                        whois_servers = [
                            # RIRs / general
                            "whois.iana.org",
                            "whois.arin.net",
                            "whois.ripe.net",
                            "whois.apnic.net",
                            "whois.lacnic.net",
                            "whois.afrinic.net",
                            # gTLD / popular registries
                            "whois.verisign-grs.com",
                            "whois.crsnic.net",
                            "whois.godaddy.com",
                            # country and ccTLD examples
                            "whois.nic.uk",
                            "whois.auda.org.au",
                            "whois.cira.ca",
                            "whois.denic.de",
                            "whois.nic.fr",
                            "whois.nic.it",
                            "whois.jprs.jp",
                            "whois.cnnic.cn",
                            "whois.inregistry.net",
                            "whois.registro.br",
                            "whois.tcinet.ru",
                            "whois.mx",
                            "whois.nic.co",
                            "whois.srs.net.nz",
                            "whois.dns.be",
                            "whois.sidn.nl",
                            "whois.iis.se",
                            "whois.norid.no",
                            "whois.nic.es",
                        ]
                        # Present only the real servers (no blank first choice)
                        combo.addItems([s for s in whois_servers if s and s.strip()])
                        combo.setMaxVisibleItems(10)
                        combo.setEditable(False)
                        try:
                            combo.setCurrentIndex(0)
                        except Exception:
                            pass
                        combo.setToolTip(
                            "Select WHOIS server for -h flag (editable to paste a custom server)."
                        )
                        combo.setMinimumWidth(300)
                        # ensure popup uses light background + dark text so items are readable
                        try:
                            combo.setStyleSheet(
                                """
                                QComboBox { color: black; background: white; }
                                QComboBox QAbstractItemView {
                                    background-color: #ffffff;
                                    color: black;
                                    selection-background-color: #ff7043;
                                    selection-color: black;
                                }
                            """
                            )
                        except Exception:
                            pass
                        # enforce visual max items
                        limit_combo_popup(combo, 10)
                        self.params_layout.addWidget(combo)
                        cb.value_input = combo
                    else:
                        le = QLineEdit()
                        # reuse previous placeholders/tooltips logic
                        le.setPlaceholderText("Enter value")
                        self.params_layout.addWidget(le)
                        cb.value_input = le
                else:
                    cb.value_input = None
                continue

            # Determine group membership
            is_standalone = bool(current_standalone and param in current_standalone)
            is_modifier = bool(current_modifiers and param in current_modifiers)

            if is_standalone and not inserted_standalone_section:
                hdr = QLabel("Standalone Flags")
                hdr.setStyleSheet(
                    "font-size: 16px; font-weight: bold; margin-top:8px; color:#333;"
                )
                self.params_layout.addWidget(hdr, alignment=Qt.AlignmentFlag.AlignLeft)
                inserted_standalone_section = True
            if is_modifier and not inserted_modifier_section:
                hdr = QLabel("Modifiers")
                hdr.setStyleSheet(
                    "font-size: 16px; font-weight: bold; margin-top:8px; color:#333;"
                )
                self.params_layout.addWidget(hdr, alignment=Qt.AlignmentFlag.AlignLeft)
                inserted_modifier_section = True

            # Create checkbox for this parameter (use original checked state by orig_index)
            cb = QCheckBox(param)
            checked_state = False
            if orig_index is not None and orig_index < len(checked_params):
                checked_state = checked_params[orig_index]
            cb.setChecked(checked_state)
            cb.setStyleSheet("font-size: 16px; font-weight: normal; padding: 4px 0;")
            self.param_checks.append(cb)
            self.params_layout.addWidget(cb)

            # If this param needs a value (either required or optional), add a QLineEdit and attach it to the checkbox
            needs_value = (param in current_value_required) or (
                param in current_value_optional
            )
            if needs_value:
                # WHOIS server dropdown for -h flag (ensure dropdown appears even when not marked as [REQUIRED])
                if param == "WHOIS server (-h)":
                    combo = QComboBox()
                    whois_servers = [
                        # RIRs / general
                        "whois.iana.org",
                        "whois.arin.net",
                        "whois.ripe.net",
                        "whois.apnic.net",
                        "whois.lacnic.net",
                        "whois.afrinic.net",
                        # gTLD / popular registries
                        "whois.verisign-grs.com",
                        "whois.crsnic.net",
                        "whois.godaddy.com",
                        # country and ccTLD examples
                        "whois.nic.uk",
                        "whois.auda.org.au",
                        "whois.cira.ca",
                        "whois.denic.de",
                        "whois.nic.fr",
                        "whois.nic.it",
                        "whois.jprs.jp",
                        "whois.cnnic.cn",
                        "whois.inregistry.net",
                        "whois.registro.br",
                        "whois.tcinet.ru",
                        "whois.mx",
                        "whois.nic.co",
                        "whois.srs.net.nz",
                        "whois.dns.be",
                        "whois.sidn.nl",
                        "whois.iis.se",
                        "whois.norid.no",
                        "whois.nic.es",
                    ]
                    # Present only the real servers (no blank first choice)
                    combo.addItems([s for s in whois_servers if s and s.strip()])
                    combo.setMaxVisibleItems(10)
                    combo.setEditable(False)
                    try:
                        combo.setCurrentIndex(0)
                    except Exception:
                        pass
                    combo.setToolTip(
                        "Select WHOIS server for -h flag (editable to paste a custom server)."
                    )
                    combo.setMinimumWidth(300)
                    # ensure popup uses light background + dark text so items are readable
                    try:
                        combo.setStyleSheet(
                            """
                            QComboBox { color: black; background: white; }
                            QComboBox QAbstractItemView {
                                background-color: #ffffff;
                                color: black;
                                selection-background-color: #ff7043;
                                selection-color: black;
                            }
                        """
                        )
                    except Exception:
                        pass
                    # enforce visual max items
                    limit_combo_popup(combo, 10)
                    self.params_layout.addWidget(combo)
                    cb.value_input = combo
                # NEW: Protocol should be radio buttons (not a textbox) — but we created a dedicated widget above;
                # ensure any accidental matches are ignored here.
                elif param == "Protocol (http/https)":
                    # already created at top of FFUF params; attach no checkbox widget here
                    cb.value_input = None
                    # continue so we don't add another input widget
                    continue
                else:
                    le = QLineEdit()
                    # Preserve helpful placeholders/tooltips from previous logic
                    if "Timing template" in param:
                        le.setPlaceholderText("0-5 (e.g., 4 for aggressive)")
                        #   le.setToolTip("Timing templates:\nT0=Paranoid (very slow)\nT1=Sneaky (slow)\nT2=Polite (slow)\nT3=Normal (default)\nT4=Aggressive (fast, recommended)\nT5=Insane (very fast)")
                        try:
                            rx = QRegularExpression(r"^[0-9]*$")
                            le.setValidator(QRegularExpressionValidator(rx))
                        except Exception:
                            pass
                    elif "Custom port range" in param:
                        le.setPlaceholderText("e.g., 80,443 or 1-1000")
                        #   le.setToolTip("Specify ports: single (80), multiple (80,443,8080), or range (1-1000)")
                        try:
                            rx = QRegularExpression(r"^[0-9,-]*$")
                            le.setValidator(QRegularExpressionValidator(rx))
                        except Exception:
                            pass
                    elif param == "Host Timeout":
                        le.setPlaceholderText("e.g., 30s, 2m, 1h")
                        #   le.setToolTip("Timeout for each host: seconds (30s), minutes (2m), hours (1h)")
                        try:
                            rx = QRegularExpression(r"^[0-9smh]*$")
                            le.setValidator(QRegularExpressionValidator(rx))
                        except Exception:
                            pass
                    elif "XML Output" in param:
                        le.setPlaceholderText("filename.xml")
                    #    le.setToolTip("Output file name for XML results")
                    elif param == "WHOIS server (-h)":
                        le.setPlaceholderText(
                            "whois.verisign-grs.com (leave blank for auto-detect)"
                        )
                    #    le.setToolTip("Custom whois server hostname. Leave blank to automatically detect the appropriate server.")
                    elif param == "Port (-p)":
                        le.setPlaceholderText("43 (leave blank for default)")
                        #   le.setToolTip("Whois server port number. Leave blank to use default port 43.")
                        try:
                            rx = QRegularExpression(r"^[0-9.,-]*$")
                            le.setValidator(QRegularExpressionValidator(rx))
                        except Exception:
                            pass
                    elif param == "Inverse attribute search (-i ATTR)":
                        le.setPlaceholderText("e.g., email or nic-hdl")
                    #    le.setToolTip("Inverse attribute to search for (attribute name or value). Example: 'email' or 'nic-hdl'.")
                    elif param == "Object type (-T TYPE)":
                        le.setPlaceholderText("e.g., domain, person, role")
                    #   le.setToolTip("Restrict query to a specific object type (domain, person, role, etc.).")
                    # DNSEnum-specific placeholders/tooltips
                    elif param == "DNS server (--dnsserver <IP>)":
                        le.setPlaceholderText("e.g., 8.8.8.8")
                        #   le.setToolTip("IP address of the DNS server to query (IPv4 or IPv6).")
                        try:
                            rx = QRegularExpression(r"^[0-9.]*$")
                            le.setValidator(QRegularExpressionValidator(rx))
                        except Exception:
                            pass
                    elif param == "Concurrency (-p <n>)":
                        le.setPlaceholderText("e.g., 10")
                        #   le.setToolTip("Limit number of concurrent DNS queries (integer).")
                        try:
                            rx = QRegularExpression(r"^[0-9]*$")
                            le.setValidator(QRegularExpressionValidator(rx))
                        except Exception:
                            pass
                    # Harvester-specific placeholders/tooltips
                    elif param == "Limit (-l, --limit)":
                        le.setPlaceholderText("e.g., 100")
                        #   le.setToolTip("Maximum number of results to return from the selected source (integer).")
                        try:
                            rx = QRegularExpression(r"^[0-9]*$")
                            le.setValidator(QRegularExpressionValidator(rx))
                        except Exception:
                            pass
                    elif param == "Start result (-S, --start)":
                        le.setPlaceholderText("e.g., 0")
                        #   le.setToolTip("Result offset (zero-based) to start returning results from.")
                        try:
                            rx = QRegularExpression(r"^[0-9-]*$")
                            le.setValidator(QRegularExpressionValidator(rx))
                        except Exception:
                            pass
                    elif param == "DNS server (-e, --dns-server)":
                        le.setPlaceholderText("e.g., 8.8.8.8")
                        #   le.setToolTip("DNS server IP address to use for DNS queries (optional).")
                        try:
                            rx = QRegularExpression(r"^[0-9.]*$")
                            le.setValidator(QRegularExpressionValidator(rx))
                        except Exception:
                            pass
                    # WhatWeb-specific placeholders/tooltips (match whatweb_tool.py labels)
                    elif param == "User-Agent (--user-agent)":
                        le.setPlaceholderText("Custom User-Agent string")
                    #    le.setToolTip("Set the User-Agent header for requests (helps evade basic blocks).")
                    elif param == "Follow redirects (--follow-redirect)":
                        le.setPlaceholderText("always | same-origin | never")
                    #    le.setToolTip("Follows redirects — may increase number of requests.")
                    elif param == "Max redirects (--max-redirects)":
                        le.setPlaceholderText("e.g., 5")
                        #    le.setToolTip("Maximum number of redirects to follow when following redirects.")
                        try:
                            rx = QRegularExpression(r"^[0-9]*$")
                            le.setValidator(QRegularExpressionValidator(rx))
                        except Exception:
                            pass
                    elif param == "Wait (--wait)":
                        le.setPlaceholderText("0.5 (seconds) — conservative default")
                        #    le.setToolTip("Delay between requests in seconds. Larger waits reduce detection risk.")
                        try:
                            rx = QRegularExpression(r"^[0-9.]*$")
                            le.setValidator(QRegularExpressionValidator(rx))
                        except Exception:
                            pass
                    elif param == "Max threads (--max-threads)":
                        le.setPlaceholderText("4 (recommended conservative default)")
                        # le.setToolTip("Max concurrent threads. Higher values are faster but increase chance of detection.")
                        try:
                            rx = QRegularExpression(r"^[0-9]*$")
                            le.setValidator(QRegularExpressionValidator(rx))
                        except Exception:
                            pass
                    elif param == "Aggressiveness (1-4)":
                        le.setPlaceholderText("1-4 (1=passive, 4=aggressive)")
                        le.setToolTip(
                            "Aggression level: 1=passive, 2=polite, 3=normal, 4=aggressive"
                        )
                    elif param == "Custom matcher":
                        le.setPlaceholderText("e.g., status:403")
                        #    le.setToolTip("Custom matching rules for responses")
                        try:
                            rx = QRegularExpression(r"^[0-9,]*$")
                            le.setValidator(QRegularExpressionValidator(rx))
                        except Exception:
                            pass
                    elif param == "Size filter":
                        le.setPlaceholderText("e.g., 100,200-400")
                        #  le.setToolTip("Filter by response size")
                        try:
                            rx = QRegularExpression(r"^[0-9,-]*$")
                            le.setValidator(QRegularExpressionValidator(rx))
                        except Exception:
                            pass
                    elif param == "Time filter":
                        le.setPlaceholderText("e.g., 1s, 2m")
                        # le.setToolTip("Filter by response time")
                        try:
                            rx = QRegularExpression(r"^[0-9smh]*$")
                            le.setValidator(QRegularExpressionValidator(rx))
                        except Exception:
                            pass
                    # FFUF-specific placeholders/tooltips (new additions)
                    elif param == "Status codes":
                        le.setPlaceholderText("e.g., 200,301,302")
                        # le.setToolTip("Comma-separated HTTP status codes to match (e.g., 200,301).")
                        try:
                            rx = QRegularExpression(r"^[0-9,]*$")
                            le.setValidator(QRegularExpressionValidator(rx))
                        except Exception:
                            pass
                    elif param == "Extension fuzz":
                        le.setPlaceholderText("e.g., .php,.html or php,html")
                        # le.setToolTip("Comma-separated file extensions to try (e.g., .php,.html).")
                        try:
                            rx = QRegularExpression(r"^[.a-zA-Z]*$")
                            le.setValidator(QRegularExpressionValidator(rx))
                        except Exception:
                            pass
                    elif param == "Depth limit":
                        le.setPlaceholderText("e.g., 3")
                        # le.setToolTip("Maximum recursion depth for fuzzing (integer).")
                        try:
                            rx = QRegularExpression(r"^[0-9]*$")
                            le.setValidator(QRegularExpressionValidator(rx))
                        except Exception:
                            pass
                    elif param == "Rate limit":
                        le.setPlaceholderText("e.g., 100")
                        # le.setToolTip("Limit request rate (requests per second or as supported by ffuf).")
                        try:
                            rx = QRegularExpression(r"^[0-9]*$")
                            le.setValidator(QRegularExpressionValidator(rx))
                        except Exception:
                            pass
                    else:
                        le.setPlaceholderText("Enter value")
                    self.params_layout.addWidget(le)
                    cb.value_input = le
            else:
                cb.value_input = None

    # ... Returns which parameters are checked ...
    def get_checked(self):
        return [cb.isChecked() for cb in self.param_checks]


# --- HelloWindow: Main Application Window ---


class HelloWindow(QWidget):
    # signal carries (tool_name, text) so writes can be routed to the proper tab on the main thread
    append_line_signal = pyqtSignal(str, str)
    parse_results_signal = pyqtSignal(str)
    request_debounced_parse = pyqtSignal(
        str
    )  # new signal to request debounced parse on main thread

    def _confirm_new_scan_and_clear(self) -> bool:
        """Ask the user to confirm starting a new scan and clear all previous scans if confirmed."""
        try:
            # Only show dialog if terminals have content
            if not self._any_terminal_has_content():
                self._clear_all_previous_scans()
                return True

            # Use the styled confirmation popup
            if show_confirm_new_scan(self):
                self._clear_all_previous_scans()
                return True
        except Exception as e:
            # Print error for debugging
            print(f"Error in confirmation dialog: {e}")
            return False
        return False

    def _any_terminal_has_content(self) -> bool:
        """Return True if any terminal tab has visible content."""
        try:
            return any(
                bool(v) for v in getattr(self, "_terminal_has_content", {}).values()
            )
        except Exception:
            return False

    def _mark_terminal_has_content(self, key: str, text: str):
        """Mark the terminal tab identified by key as having visible content if text is not just ANSI/whitespace."""
        try:
            if not key:
                return
            # Strip ANSI escape sequences
            try:
                ansi_re = re.compile(r"\x1B[@-_][0-?]*[ -/]*[@-~]|\x1b\][^\x07]*\x07")
                stripped = ansi_re.sub("", text or "")
            except Exception:
                stripped = str(text or "")
            # Remove CR/LF and check if any non-whitespace remains
            stripped = stripped.replace("\r", "").replace("\n", "")
            has_visible = bool(stripped.strip())
            if has_visible:
                self._terminal_has_content[key] = True
        except Exception:
            pass

    def _clear_all_previous_scans(self):
        """Clear terminal tabs, results/diagnostics UI, and reset stored results/state."""
        try:
            # Clear all terminal tabs
            for view in list(self.terminal_views.values()):
                try:
                    if view and hasattr(view, "page") and view.page():
                        view.page().runJavaScript("window.term.clear()")
                except Exception:
                    pass

            # Clear Results and Diagnostics panes
            try:
                self.results_textbox.clear()
            except Exception:
                pass
            try:
                self.diagnostics_textbox.clear()
            except Exception:
                pass

            # Reset duplicate tracking and parser results
            try:
                self.displayed_results.clear()
            except Exception:
                pass
            try:
                self.results_manager.clear_results()
            except Exception:
                pass

            # Stop and clear any pending parse timers/failure timers
            try:
                for t in list(self._parse_timers.values()):
                    try:
                        t.stop()
                        t.deleteLater()
                    except Exception:
                        pass
                self._parse_timers.clear()
            except Exception:
                pass
            try:
                for t in list(self._parse_failure_timers.values()):
                    try:
                        t.stop()
                        t.deleteLater()
                    except Exception:
                        pass
                self._parse_failure_timers.clear()
            except Exception:
                pass

            # Reset scan state trackers
            try:
                self._scan_start_times.clear()
            except Exception:
                pass
            try:
                self._scan_complete_sent.clear()
            except Exception:
                pass
            try:
                self._last_progress_len.clear()
            except Exception:
                pass
        except Exception:
            pass

    def __init__(self):
        super().__init__()
        self.setWindowTitle("CorvoScan")
        # Set darker background for the main window
        self.setStyleSheet("QWidget#MainWindow { background-color: #e6e6e6; }")
        self.setObjectName("MainWindow")
        # create the quick tooltip filter instance
        self._tooltip_filter = QuickTooltipFilter(self)
        screen = QGuiApplication.primaryScreen()
        rect = screen.availableGeometry()
        # Use a slightly larger default window size so the left category
        # panel and other UI columns are more likely to be fully visible
        # on startup (95% of available screen instead of 90%).
        self.resize(int(rect.width() * 0.95), int(rect.height() * 0.95))
        # Modern tooltip styling (dark, rounded, padded)
        try:
            QToolTip.setFont(QFont("Segoe UI", 10))
            app = QApplication.instance()
            if app:
                # apply centralized app tooltip / combobox stylesheet
                app.setStyleSheet(TOOLTIP_APP_STYLE)
        except Exception:
            pass

        # Track displayed results to prevent duplicates
        self.displayed_results = set()

        main_layout = QVBoxLayout()
        main_layout.setContentsMargins(20, 20, 20, 20)
        main_layout.setSpacing(20)
        top_layout = QHBoxLayout()
        top_layout.setSpacing(20)
        self.tools_data = {
            "Whois": {
                "description": "Whois queries domain registration databases to retrieve detailed ownership and administrative information about domains and IP addresses. Use it to discover registrar details, registration/expiration dates, nameservers, administrative contacts, and network allocation data. Essential for identifying domain ownership, investigating suspicious domains, and gathering intelligence about network infrastructure.",
                "parameters": [
                    "Default scan",
                    "WHOIS server (-h)",
                    "Port (-p)",
                    "Display referral chain (-I)",
                    "Verbose output (--verbose)",
                    "Suppress legal disclaimers (-H)",
                ],
            },
            "NSLookup": {
                "description": "NSLookup (Name Server Lookup) queries DNS servers to resolve domain names to IP addresses and retrieve various DNS record types. Use it to discover mail servers (MX), nameservers (NS), IPv4/IPv6 addresses, TXT records (SPF, DKIM, DMARC), canonical names (CNAME), and authoritative DNS information. Critical for DNS troubleshooting, email security verification, and discovering infrastructure details.",
                "parameters": [
                    "IPv4 addresses (A)",
                    "IPv6 addresses (AAAA)",
                    "Mail servers (MX)",
                    "Nameservers (NS)",
                    "Start of Authority (SOA)",
                    "TXT records (TXT)",
                    "Canonical names (CNAME)",
                ],
            },
            "theHarvester": {
                "description": "theHarvester is an OSINT (Open Source Intelligence) tool that aggregates data from multiple public sources to discover email addresses, subdomains, employee names, open ports, and banners. It queries search engines, certificate transparency logs, public databases, and social media to gather reconnaissance data. Ideal for penetration testing reconnaissance, attack surface mapping, and social engineering preparation.",
                "parameters": [
                    "[REQUIRED] Source (-b, --source)",
                    "Limit (-l, --limit)",
                    "Start result (-S, --start)",
                    "DNS server (-e, --dns-server)",
                    "DNS resolve (-r, --dns-resolve)",
                    "DNS lookup (-n, --dns-lookup)",
                    "Quiet mode (-q, --quiet)",
                    "API scan (-a, --api-scan)",
                ],
            },
            "DNSEnum": {
                "description": "DNSEnum performs comprehensive DNS enumeration by gathering nameservers, mail servers, zone transfers, subdomain brute-forcing, reverse lookups, and WHOIS queries. It automatically discovers network ranges and performs targeted DNS reconnaissance to map out an organization's DNS infrastructure. Perfect for thorough DNS auditing, discovering hidden subdomains, and identifying misconfigurations in DNS security.",
                "parameters": [
                    "Basic run",
                    "Verbose output (-v)",
                    "Skip PTR (--noreverse)",
                    "Enable brute force",
                    "DNS server (--dnsserver <IP>)",
                ],
            },
            "NMAP": {
                "description": "Nmap (Network Mapper) is the industry-standard network scanning and security auditing tool. It discovers live hosts, open ports, running services, operating systems, and potential vulnerabilities. Use it for network inventory, security audits, penetration testing, and compliance verification. Supports advanced techniques like stealth scanning, service version detection, OS fingerprinting, and NSE scripting for vulnerability detection.",
                "parameters": [
                    "Fast scan (-F)",
                    "Service detection (-sV)",
                    "OS detection (-O)",
                    "UDP scan (-sU)",
                    "SYN (Stealth) scan (-sS)",
                    "Ping scan (-sn)",
                    "Script scan (-sC)",
                    "Traceroute (--traceroute)",
                    "Custom port range (-p)",
                ],
            },
            "WhatWeb": {
                "description": "WhatWeb identifies web technologies, content management systems (WordPress, Joomla, Drupal), frameworks (Angular, React, Vue), server software (Apache, Nginx, IIS), analytics platforms, and security headers. It detects over 1800+ plugins to fingerprint websites and reveal their technology stack. Essential for web application reconnaissance, vulnerability research, and security assessments of web infrastructure.",
                "parameters": [
                    "Default scan",
                    "Verbose (-v)",
                    "Follow redirects (--follow-redirect)",
                    "Max redirects (--max-redirects)",
                    "User-Agent (--user-agent)",
                    "Header (--header)",
                    "Wait (--wait)",
                    "Max threads (--max-threads)",
                ],
            },
            "FFUF": {
                "description": "FFUF (Fuzz Faster U Fool) is a high-performance web fuzzer for discovering hidden directories, files, subdomains, parameters, and virtual hosts. It uses wordlists to rapidly brute-force URLs and supports recursive fuzzing, custom headers, POST data, and advanced filtering by status codes, response size, or content patterns. Crucial for web application penetration testing, API endpoint discovery, and finding exposed sensitive files.",
                "parameters": [
                    "Protocol (http/https)",
                    "Default scan",
                    "Recursion",
                    "Status codes",
                    "Filter code",
                    "Extension fuzz",
                    "Depth limit",
                    "Rate limit",
                    "Time filter",
                    "Follow redirects",
                    "Ignore SSL",
                ],
            },
        }

        self.checked_params = {
            tool: [False] * len(data["parameters"])
            for tool, data in self.tools_data.items()
        }
        # Persist per-tool parameter values (param_name -> value) so inputs survive tool switches
        self.stored_param_values = {tool: {} for tool in self.tools_data.keys()}
        self.collapsible_widgets = {}
        div1 = rounded_frame()
        div1_layout = QVBoxLayout()
        div1_layout.setSpacing(8)
        div1_layout.setContentsMargins(10, 8, 10, 10)
        corvoscan_label = QLabel("CorvoScan")
        corvoscan_label.setStyleSheet(
            "font-size: 28px; font-weight: bold; color: #222;"
        )
        corvoscan_label.setAlignment(
            Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignTop
        )
        div1_layout.addWidget(
            corvoscan_label,
            alignment=Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignTop,
        )
        self.target_box = QLineEdit()
        self.target_box.setPlaceholderText("target.com")
        self.target_box.setStyleSheet(
            "font-size: 20px; padding: 8px; border-radius: 10px;"
        )
        self.target_box.setMaximumHeight(40)
        div1_layout.addWidget(self.target_box)
        categories_widget = QWidget()
        # Keep categories container borderless (main divs already provide separation)
        categories_widget.setStyleSheet("background: #ffffff;")
        categories_layout = QVBoxLayout(categories_widget)
        categories_layout.setSpacing(8)
        categories_layout.setContentsMargins(0, 0, 0, 0)
        categories = {
            "WHOIS and ASN lookups": ["Whois", "NSLookup"],
            "OSINT": ["theHarvester"],
            "Domain and subdomain enumeration": ["DNSEnum"],
            "Network and IP mapping": ["NMAP"],
            "Webserver and technology fingerprinting": ["WhatWeb"],
            "Directory and file enumeration": ["FFUF"],
        }
        for category, tools in categories.items():
            collapsible = CollapsibleCategory(
                category, tools, self.update_tool, self.highlight_button
            )
            categories_layout.addWidget(collapsible)
            for tool in tools:
                self.collapsible_widgets[tool] = collapsible
        categories_scroll = QScrollArea()
        categories_scroll.setWidgetResizable(True)
        categories_scroll.setWidget(categories_widget)
        categories_scroll.setStyleSheet(
            """
            QScrollArea { border: none; background: transparent; }
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
        )
        categories_scroll.setHorizontalScrollBarPolicy(
            Qt.ScrollBarPolicy.ScrollBarAlwaysOff
        )

        categories_scroll.setVerticalScrollBarPolicy(
            Qt.ScrollBarPolicy.ScrollBarAsNeeded
        )
        # Allow the categories area to shrink more gracefully when window height
        # is reduced to avoid clipping left-panel content on small windows.
        # Keeping a modest minimum ensures it's still usable on very small screens.
        categories_scroll.setMinimumHeight(120)
        div1_layout.addWidget(categories_scroll)
        div1.setLayout(div1_layout)
        # Let the left panel expand/contract vertically with the main window
        # so its contents won't be clipped when the window is resized.
        # Ensure the left panel holds a minimum width so category labels
        # and buttons are not truncated when the main window is made narrow.
        try:
            # Increase left panel minimum width so category labels/buttons
            # are visible on typical window sizes without requiring fullscreen.
            div1.setMinimumWidth(360)
        except Exception:
            pass
        div1.setSizePolicy(QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Expanding)
        top_layout.addWidget(div1, stretch=2)
        div2 = rounded_frame()
        div2_layout = QVBoxLayout()
        div2_layout.setSpacing(8)
        div2_layout.setContentsMargins(10, 8, 10, 10)
        self.tool_name_box = ToolNameBox("Tool Name", "", [], [])
        self.current_tool = None
        # increase fixed height so parameters area extends vertically toward the buttons
        self.tool_name_box.setFixedHeight(420)
        div2_layout.addWidget(self.tool_name_box)
        button_row = QHBoxLayout()
        button_row.addStretch()
        # styles used for Start / Stop states
        self._scan_start_style = SCAN_START_STYLE
        self._scan_stop_style = SCAN_STOP_STYLE

        # Scan Selected styles — slightly smaller font so text fits comfortably
        self._scan_selected_start_style = SCAN_SELECTED_START_STYLE
        self._scan_selected_stop_style = SCAN_SELECTED_STOP_STYLE

        # single toggle button
        self.scan_button = QPushButton("Start Tool")
        self.scan_button.setFixedSize(160, 56)
        self.scan_button.setStyleSheet(self._scan_start_style)
        # on click, decide start or stop based on running state
        self.scan_button.clicked.connect(self.handle_scan_toggle)

        button_row.addWidget(self.scan_button)
        # place unified Scan Selected to the right of the Start/Stop button using slightly smaller-font styles
        self.scan_selected_btn = QPushButton("Start Selected")
        self.scan_selected_btn.setFixedSize(160, 56)
        self.scan_selected_btn.setStyleSheet(self._scan_selected_start_style)
        self.scan_selected_btn.clicked.connect(self.handle_scan_selected_toggle)
        # small spacer between buttons
        button_row.addSpacing(8)
        button_row.addWidget(self.scan_selected_btn)
        div2_layout.addSpacing(6)
        div2_layout.addLayout(button_row)
        div2.setLayout(div2_layout)
        div2.setSizePolicy(QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Minimum)
        top_layout.addWidget(div2, stretch=2)
        div3 = rounded_frame()
        div3_layout = QVBoxLayout()
        div3_layout.setSpacing(10)
        div3_layout.setContentsMargins(10, 10, 10, 10)
        div3_layout.addWidget(
            create_division_title("Terminal View"),
            0,
            alignment=Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignTop,
        )

        # Create exactly one terminal tab per tool (show all 7 tabs at startup)
        self.terminal_tabs = QTabWidget()
        self.terminal_tabs.setTabsClosable(False)
        self.terminal_views = {}
        self._terminal_has_content = {}

        project_root = os.path.dirname(os.path.abspath(__file__))
        xterm_path = os.path.join(project_root, "xterm.html")
        fallback_html = """
           <html><body style="font-family: sans-serif; padding: 20px;">
               <h2>Terminal preview unavailable</h2>
               <p><code>xterm.html</code> not found in the project root:</p>
               <pre>{}</pre>
               <p>The terminal preview has been disabled. Raw output will still appear in the terminal view.</p>
           </body></html>
        """.format(xterm_path)

        # Pre-create one tab per tool in self.tools_data (preserves insertion order)
        for tool_label in self.tools_data.keys():
            view = QWebEngineView()
            if os.path.exists(xterm_path):
                view.setUrl(QUrl.fromLocalFile(xterm_path))
            else:
                view.setHtml(fallback_html)
            # label the tab with the human-readable tool name
            self.terminal_tabs.addTab(view, tool_label)
            # map by lowercase key for routing (e.g., "nmap" -> view)
            tool_key = tool_label.lower()
            self.terminal_views[tool_key] = view
            # initialize content marker for this tab
            self._terminal_has_content[tool_key] = False
            # connect readiness (safe to connect for every view)
            try:
                view.loadFinished.connect(self.on_terminal_ready)
            except Exception:
                pass

        # show the first tab by default
        try:
            self.terminal_tabs.setCurrentIndex(0)
        except Exception:
            pass

        div3_layout.addWidget(self.terminal_tabs)
        # marshal writes from workers to the UI thread: (tool_name, text)
        self.append_line_signal.connect(self.send_to_terminal)
        self.parse_results_signal.connect(self.parse_and_display_results)

        # helper to lazily ensure a terminal tab exists for a tool (keeps ability to add new tabs if needed)
        def ensure_tab(tool_name):
            key = (tool_name or "").lower()
            if key in self.terminal_views:
                return self.terminal_views[key]
            # fallback creation (shouldn't be needed with pre-created tabs)
            view = QWebEngineView()
            if os.path.exists(xterm_path):
                view.setUrl(QUrl.fromLocalFile(xterm_path))
            else:
                view.setHtml(fallback_html)
            self.terminal_views[key] = view
            self.terminal_tabs.addTab(view, tool_name or key)
            try:
                view.loadFinished.connect(self.on_terminal_ready)
            except Exception:
                pass
            return view

        self.ensure_terminal_for_tool = ensure_tab

        # initialize parse timers dict and connect debounced parse request signal
        self._parse_timers = {}
        self.request_debounced_parse.connect(self._handle_request_debounced_parse)
        # timers used to debounce showing failed parse results
        self._parse_failure_timers = {}
        # track last progress length per tool so we can overwrite progress line cleanly
        self._last_progress_len = {}
        # track scan start times (tool_key -> epoch seconds)
        self._scan_start_times = {}
        # track whether we've already emitted a scan-complete terminal message per tool
        self._scan_complete_sent = set()
        # track which tools are currently running (lowercase keys)
        self._scan_running_tools = set()

        clear_terminal_button = QPushButton("Clear")
        clear_terminal_button.setStyleSheet(
            "font-size: 16px; border-radius: 8px; background: #757575; color: white; font-weight: bold; padding: 8px 24px;"
        )
        # Place "Scan All" on the same row as "Clear", with Scan All on the left and Clear on the right.
        terminal_btn_row = QHBoxLayout()
        # terminal row: only keep Clear / layout controls here (Scan Selected moved to middle controls)
        terminal_btn_row.addStretch()
        terminal_btn_row.addWidget(
            clear_terminal_button, alignment=Qt.AlignmentFlag.AlignRight
        )
        div3_layout.addLayout(terminal_btn_row)

        def clear_xterm():
            choice = show_terminal_clear_choice(self)
            if choice is None:
                return  # Cancelled
            try:
                if choice == "this":
                    cur = self.terminal_tabs.currentWidget()
                    if cur and hasattr(cur, "page"):
                        cur.page().runJavaScript("window.term.clear()")
                elif choice == "all":
                    # iterate all created terminal views and clear each one
                    for view in list(self.terminal_views.values()):
                        try:
                            if view and hasattr(view, "page"):
                                view.page().runJavaScript("window.term.clear()")
                        except Exception:
                            # ignore per-view failures and continue
                            pass
            except Exception:
                pass

        clear_terminal_button.clicked.connect(clear_xterm)

        # connect the unified scan-selected toggle
        self.scan_selected_btn.clicked.connect(self.handle_scan_selected_toggle)

        # (removed duplicate connections above to avoid invoking handlers twice)
        div3.setLayout(div3_layout)
        div3.setSizePolicy(QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Minimum)
        top_layout.addWidget(div3, stretch=5)
        main_layout.addLayout(top_layout, stretch=1)
        bottom_layout = QHBoxLayout()
        bottom_layout.setSpacing(20)
        results = rounded_frame()
        results_layout = QVBoxLayout()
        results_layout.setSpacing(10)
        results_layout.setContentsMargins(10, 10, 10, 10)
        results_layout.addWidget(
            create_division_title("Results"),
            0,
            alignment=Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignTop,
        )
        self.results_textbox = QTextEdit()
        self.results_textbox.setReadOnly(True)
        self.results_textbox.setPlaceholderText("Results will appear here.")
        # Match the parameters scrollbar styling: light track, narrow width, rounded thumb and hover color
        # replace inline CSS with centralized constant
        self.results_textbox.setStyleSheet(RESULTS_SCROLLBAR_STYLE)

        # Keep results visually constrained to the widget width, avoid horizontal scrollbar,
        # and prevent table cells from wrapping (truncate with ellipsis instead of wrapping or expanding).
        try:
            # Do not show horizontal scroll bar (user requested no horizontal scroll)
            self.results_textbox.setHorizontalScrollBarPolicy(
                Qt.ScrollBarPolicy.ScrollBarAlwaysOff
            )
            # Wrap non-tabular text to the widget width so the widget doesn't expand
            self.results_textbox.setLineWrapMode(QTextEdit.LineWrapMode.WidgetWidth)
            # Provide a document-level stylesheet so generated HTML tables/cells won't wrap.
            # This makes table cells use nowrap + overflow:hidden + text-overflow:ellipsis
            # so long cells are truncated rather than wrapping or forcing horizontal scroll.
            results_css = RESULTS_CSS
            try:
                self.results_textbox.document().setDefaultStyleSheet(results_css)
            except Exception:
                pass

            # Ensure the QTextDocument text width matches the visible viewport so HTML tables expand to full width.
            # Use a small margin to account for internal padding.
            try:
                vw = self.results_textbox.viewport().width()
                self.results_textbox.document().setTextWidth(max(0, vw - 8))
            except Exception:
                pass
            # Update document width on viewport / widget resize by installing an event filter
            # on both the QTextEdit and its viewport so we catch all resize scenarios.
            try:
                self.results_textbox.installEventFilter(self)
            except Exception:
                pass
            try:
                self.results_textbox.viewport().installEventFilter(self)
            except Exception:
                pass
        except Exception:
            pass
        self.results_textbox.setSizePolicy(
            QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding
        )
        results_layout.addWidget(self.results_textbox, stretch=1)
        export_row = QHBoxLayout()
        export_row.addStretch()
        self.export_button = QPushButton("Export")
        self.export_button.setStyleSheet(
            "font-size: 16px; border-radius: 8px; background: #1976d2; color: white; font-weight: bold; padding: 8px 24px;"
        )
        export_row.addWidget(self.export_button)
        # Clear results button
        self.clear_results_button = QPushButton("Clear Results")
        self.clear_results_button.setStyleSheet(
            "font-size: 16px; border-radius: 8px; background: #757575; color: white; font-weight: bold; padding: 8px 24px;"
        )
        export_row.addWidget(self.clear_results_button)
        results_layout.addLayout(export_row)
        results.setLayout(results_layout)
        results.setSizePolicy(
            QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding
        )
        bottom_layout.addWidget(results, stretch=1)
        diagnostics = rounded_frame()
        diagnostics_layout = QVBoxLayout()
        diagnostics_layout.setSpacing(10)
        diagnostics_layout.setContentsMargins(10, 10, 10, 10)
        diagnostics_layout.addWidget(
            create_division_title("Insights"),
            0,
            alignment=Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignTop,
        )
        self.diagnostics_textbox = QTextEdit()
        self.diagnostics_textbox.setReadOnly(True)
        self.diagnostics_textbox.setPlaceholderText("Insights will appear here.")
        # diagnostics styling: reuse results scroll CSS
        self.diagnostics_textbox.setStyleSheet(RESULTS_SCROLLBAR_STYLE)
        diagnostics_layout.addWidget(self.diagnostics_textbox, stretch=1)
        diag_export_row = QHBoxLayout()
        diag_export_row.addStretch()
        self.diag_export_button = QPushButton("Export")
        self.diag_export_button.setStyleSheet(
            "font-size: 16px; border-radius: 8px; background: #1976d2; color: white; font-weight: bold; padding: 8px 24px;"
        )
        diag_export_row.addWidget(self.diag_export_button)
        # Clear insights button
        self.clear_diag_button = QPushButton("Clear Insights")
        self.clear_diag_button.setStyleSheet(
            "font-size: 16px; border-radius: 8px; background: #757575; color: white; font-weight: bold; padding: 8px 24px;"
        )
        diag_export_row.addWidget(self.clear_diag_button)
        diagnostics_layout.addLayout(diag_export_row)
        diagnostics.setLayout(diagnostics_layout)
        diagnostics.setSizePolicy(
            QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding
        )
        bottom_layout.addWidget(diagnostics, stretch=1)
        main_layout.addLayout(bottom_layout, stretch=1)
        self.setLayout(main_layout)
        # Prevent the window from being made narrower than a width that
        # would clip the left category panel or its buttons. This ensures
        # the category bar is fully visible at startup and during resize.
        try:
            # Choose a conservative minimum width that fits the three
            # columns (left categories, middle parameters, right terminal/results).
            self.setMinimumWidth(1200)
        except Exception:
            pass

        self.scan_handler = ScanHandler()

        # Initialize results management system
        self.results_manager = ResultsManager()
        self.results_manager.register_parser("nmap", NmapResultsParser())
        self.results_manager.register_parser("nslookup", NSLookupParser())
        self.results_manager.register_parser("theharvester", TheHarvesterParser())
        self.results_manager.register_parser("dnsenum", DNSEnumResultsParser())
        self.results_manager.register_parser("whois", WhoisParser())
        self.results_manager.register_parser("whatweb", WhatWebParser())
        self.results_manager.register_parser("ffuf", FFUFParser())

        # Connect buttons
        # scan_button is already connected above; keep other button connections unchanged
        self.export_button.clicked.connect(self.handle_export_results)
        self.clear_results_button.clicked.connect(self.handle_clear_results)
        self.diag_export_button.clicked.connect(self.handle_export_diagnostics)

        self.clear_diag_button.clicked.connect(self.handle_clear_diagnostics)

        # install quick tooltip filter on the right-side label so tooltip appears immediately
        try:
            self.tool_name_box.tool_name_label.installEventFilter(self._tooltip_filter)
        except Exception:
            pass

        # Network monitor removed per user request

    def on_terminal_ready(self):
        # Suppress the automatic "terminal ready" message.
        # No action required when the embedded terminal finishes loading.
        return

    def eventFilter(self, obj, event):
        """Update document text width when the results QTextEdit or its viewport is resized."""
        try:
            # Ensure results_textbox exists
            rt = getattr(self, "results_textbox", None)
            if rt is None:
                return False

            # If the event comes from either the QTextEdit or its viewport and is a resize,
            # update the document text width to match the visible viewport width.
            viewport = rt.viewport()
            if obj is rt or obj is viewport:
                if event.type() == QEvent.Type.Resize:
                    try:
                        w = viewport.width()
                        # Subtract a small margin for padding/borders so 100% table width fills the visible area.
                        rt.document().setTextWidth(max(0, w - 6))
                    except Exception:
                        pass
        except Exception:
            pass
        return False

    # ... Highlights the selected tool in the UI ...
    def highlight_button(self, tool_name):
        for widget in self.collapsible_widgets.values():
            widget.set_highlight(tool_name)

    # ... Updates ToolNameBox when a tool is selected ...
    def update_tool(self, tool_name):
        # clear any lingering terminal SGR attributes to avoid color bleed
        # send only the SGR reset sequence (no newline) so toggling a checkbox
        # doesn't emit a new line in the terminal view.
        # route UI-originated control output to the selected tool's tab (create it if missing)
        try:
            self.send_to_terminal(tool_name.lower(), ANSI_RESET)
        except Exception:
            # fallback to general if something goes wrong
            self.send_to_terminal("general", ANSI_RESET)
        if hasattr(self, "current_tool") and self.current_tool in self.tools_data:
            # save checked flags
            self.checked_params[self.current_tool] = self.tool_name_box.get_checked()
            # save any values the user entered for the current tool
            try:
                self._save_current_tool_values()
            except Exception:
                pass
        data = self.tools_data.get(tool_name, {})
        description = data.get("description", "")
        parameters = data.get("parameters", [])
        checked = self.checked_params.get(tool_name, [False] * len(parameters))
        self.tool_name_box.set_tool(tool_name, description, parameters, checked)
        self.current_tool = tool_name
        # restore previously saved values (if any) into the newly rendered widgets
        try:
            self._restore_tool_values(tool_name)
        except Exception:
            pass

        # install quick tooltip filter on the right-side label so tooltip appears immediately
        try:
            self.tool_name_box.tool_name_label.installEventFilter(self._tooltip_filter)
        except Exception:
            pass

        # IMPORTANT: Do NOT set tooltips or install the quick tooltip event filter on any
        # widgets that live in the left-side categories (div1). The left-side UI must not
        # show hover popups. Previously we copied the right-side tooltip to the div1 buttons

        # and installed the event filter here which produced hover tooltips in div1.
        # Leave div1 buttons/checks with no tooltip and no event filter to ensure hover
        # popups only appear when hovering the tool name in div2.

        # Ensure the scan button reflects whether the newly-selected tool is running.
        try:
            if self.current_tool:
                self._set_scan_button_state(
                    self.current_tool.lower(),
                    (self.current_tool.lower() in self._scan_running_tools),
                )
        except Exception:
            pass

        # Switch the terminal tab to the selected tool (create the tab if it does not exist)
        try:
            tab_view = self.ensure_terminal_for_tool(tool_name)
            self.terminal_tabs.setCurrentWidget(tab_view)
        except Exception:
            pass

    def _save_current_tool_values(self):
        """Save values from the currently-displayed ToolNameBox into stored_param_values."""
        try:
            if not getattr(self, "current_tool", None):
                return
            storage = self.stored_param_values.setdefault(self.current_tool, {})
            # iterate current param widgets and persist any value_input content
            for cb in getattr(self.tool_name_box, "param_checks", []):
                name = cb.text()
                widget = getattr(cb, "value_input", None)
                if widget is None:
                    continue
                try:
                    if hasattr(widget, "currentText"):  # QComboBox-like
                        val = widget.currentText().strip()
                    else:
                        val = widget.text().strip()
                except Exception:
                    val = ""
                storage[name] = val
            # Also persist FFUF top input if present
            ffuf_in = getattr(self.tool_name_box, "ffuf_top_input", None)
            if ffuf_in is not None:
                storage["__ffuf_top_input__"] = ffuf_in.text().strip()
            # Persist FFUF protocol selection if present
            proto_w = getattr(self.tool_name_box, "protocol_widget", None)
            if proto_w is not None:
                try:
                    storage["Protocol (http/https)"] = proto_w.currentText().strip()
                except Exception:
                    pass
            # Persist the rendered parameter order (so multi-run builds map checked flags by name)
            try:
                storage["__param_order__"] = [
                    cb.text() for cb in getattr(self.tool_name_box, "param_checks", [])
                ]
            except Exception:
                pass
        except Exception:
            pass

    def _restore_tool_values(self, tool_name):
        """Restore previously-saved parameter values for tool_name into the currently-rendered widgets."""
        try:
            if not tool_name:
                return
            saved = self.stored_param_values.get(tool_name, {}) or {}
            for cb in getattr(self.tool_name_box, "param_checks", []):
                name = cb.text()
                widget = getattr(cb, "value_input", None)
                if widget is None:
                    continue
                val = saved.get(name, "") or ""
                try:
                    if hasattr(widget, "setCurrentText"):
                        # prefer setCurrentText for editable combo boxes, otherwise try to find the item
                        try:
                            widget.setCurrentText(val)
                        except Exception:
                            idx = (
                                widget.findText(val)
                                if hasattr(widget, "findText")
                                else -1
                            )
                            if idx >= 0:
                                widget.setCurrentIndex(idx)
                            elif val and hasattr(widget, "addItem"):
                                widget.insertItem(0, val)
                                widget.setCurrentIndex(0)
                    elif hasattr(widget, "setText"):
                        widget.setText(val)
                except Exception:
                    pass
            # restore ffuf top input if present
            ffuf_in = getattr(self.tool_name_box, "ffuf_top_input", None)
            if ffuf_in is not None:
                ffuf_val = saved.get("__ffuf_top_input__", "") or ""
                try:
                    ffuf_in.setText(ffuf_val)
                except Exception:
                    pass
            # restore FFUF protocol if present
            proto_w = getattr(self.tool_name_box, "protocol_widget", None)
            if proto_w is not None:
                try:
                    proto_val = saved.get("Protocol (http/https)", "") or ""
                    if proto_val:
                        proto_w.setCurrentText(proto_val)
                except Exception:
                    pass
        except Exception:
            pass

    def output_callback(self, tool_name, line):
        # Always record raw output for parsers/records
        try:
            self.results_manager.add_output_line(tool_name, line)
        except Exception:
            pass

        # If this is the explicit completion sentinel from ToolProcessBase, always show it
        # and notify parsers. Format from base: "[scan complete] <ToolName>\n"
        if isinstance(line, str) and line.startswith("[scan complete]"):
            # make a friendly message and display it regardless of ffuf/progress filtering
            try:
                # compute optional duration string (do not remove stored start time here)
                dur_str = ""
                try:
                    start = self._scan_start_times.get(tool_name.lower(), None)
                except Exception:
                    start = None
                if start is not None:
                    try:
                        dur = time.time() - float(start)
                        if dur >= 3600:
                            hrs = int(dur // 3600)
                            mins = int((dur % 3600) // 60)
                            secs = int(dur % 60)
                            dur_str = f"{hrs}h{mins:02d}m{secs:02d}s"
                        elif dur >= 60:
                            mins = int(dur // 60)
                            secs = int(dur % 60)
                            dur_str = f"{mins}m{secs:02d}s"
                        else:
                            dur_str = f"{dur:.2f}s"
                    except Exception:
                        dur_str = ""

                msg = f"[scan complete] {tool_name} finished."
                if dur_str:
                    msg += f" ({dur_str})"
                # ensure an extra blank line after completion for readability
                self.append_line_signal.emit(tool_name.lower(), msg + "\n\n")
                try:
                    self._scan_complete_sent.add(tool_name.lower())
                except Exception:
                    pass
            except Exception:
                self.append_line_signal.emit(tool_name.lower(), line)
            # trigger parsing/other completion handlers
            try:
                self.parse_results_signal.emit(tool_name)
            except Exception:
                pass
            return

        # small helper to emit progress that pads previous content so overwritten cleanly
        def _emit_progress(tn: str, text: str):
            last = self._last_progress_len.get(tn, 0)
            pad = max(0, last - len(text))
            out = text + (" " * pad) + "\r"
            self._last_progress_len[tn] = len(text)
            try:
                self.append_line_signal.emit(tn.lower(), out)
            except Exception:
                pass

        # For ffuf: keep progress updates from producing new terminal lines.

        if tool_name.lower() == "ffuf":
            import re

            # If it's a mixed CR+LF chunk but looks like a progress update, convert to a lone CR
            if "\r" in line and "\n" in line:
                prog = line.replace("\n", "").strip()
                if prog and (
                    re.fullmatch(r"[\d\s/]+", prog)
                    or re.fullmatch(r"\d+(\.\d+)?%$", prog)
                    or re.fullmatch(r"[\.\-\\|/]+", prog)
                ):
                    _emit_progress(tool_name, prog)
                    return
            # If the chunk contains no newline but contains a '\r', it's likely a progress update.
            if "\n" not in line and "\r" in line:
                prog = line.strip()
                if not prog:
                    return
                if (
                    re.fullmatch(r"[\d\s/]+", prog)
                    or re.fullmatch(r"\d+(\.\d+)?%$", prog)
                    or re.fullmatch(r"[\.\-\\|/]+", prog)
                ):
                    _emit_progress(tool_name, prog)
                    return
            # Otherwise fall through and display (this includes real ffuf output lines that end with '\n').

        # Send visible output to the terminal view
        try:
            self.append_line_signal.emit(tool_name.lower(), line)
        except Exception:
            pass
        # If a real newline was emitted, reset progress padding tracker so future shorter lines don't leave garbage
        if "\n" in line:
            self._last_progress_len[tool_name] = 0

        if tool_name.lower() == "nslookup":
            self.request_debounced_parse.emit(tool_name)
            return

        # For nslookup use only the debounced parse path to avoid duplicate parsers
        if tool_name.lower() == "nslookup":
            self.request_debounced_parse.emit(tool_name)
            self.request_debounced_parse.emit(tool_name)
            return

        # If the line indicates completion, request parsing
        if (
            "done:" in line.lower()
            or "finished" in line.lower()
            or "completed" in line.lower()
            or ("[*] searching" in line.lower() and "finished" in line.lower())
        ):
            # Try to show a scan-complete message with duration if we recorded a start time.
            try:
                # Peek at recorded start time for terminal-friendly duration text
                # but do NOT remove it here so the GUI display can still show Duration.
                start = self._scan_start_times.get(tool_name.lower(), None)
            except Exception:
                start = None
            if start is not None:
                try:
                    dur = time.time() - float(start)
                    if dur >= 3600:
                        hrs = int(dur // 3600)
                        mins = int((dur % 3600) // 60)
                        secs = int(dur % 60)
                        dur_str = f"{hrs}h{mins:02d}m{secs:02d}s"
                    elif dur >= 60:
                        mins = int(dur // 60)
                        secs = int(dur % 60)
                        dur_str = f"{mins}m{secs:02d}s"
                    else:
                        dur_str = f"{dur:.2f}s"
                except Exception:
                    dur_str = ""

                try:
                    msg = f"[scan complete] {tool_name} finished."
                    if dur_str:
                        msg += f" ({dur_str})"
                    self.append_line_signal.emit(tool_name.lower(), msg + "\n\n")
                    try:
                        self._scan_complete_sent.add(tool_name.lower())
                    except Exception:
                        pass
                except Exception:
                    pass
            self.parse_results_signal.emit(tool_name)

        # Specific completion detection for theHarvester
        elif (
            tool_name.lower() == "theharvester"
            and "[scan completed]" in line.lower()
            and "theharvester scan finished" in line.lower()
        ):
            try:
                # Peek at recorded start time for terminal-friendly duration text
                # but do NOT remove it here so the GUI display can still show Duration.
                start = self._scan_start_times.get(tool_name.lower(), None)
            except Exception:
                start = None
            if start is not None:
                try:
                    dur = time.time() - float(start)
                    if dur >= 3600:
                        hrs = int(dur // 3600)
                        mins = int((dur % 3600) // 60)
                        secs = int(dur % 60)
                        dur_str = f"{hrs}h{mins:02d}m{secs:02d}s"
                    elif dur >= 60:
                        mins = int(dur // 60)
                        secs = int(dur % 60)
                        dur_str = f"{mins}m{secs:02d}s"
                    else:
                        dur_str = f"{dur:.2f}s"
                except Exception:
                    dur_str = ""
                try:
                    msg = f"[scan complete] {tool_name} finished."
                    if dur_str:
                        msg += f" ({dur_str})"
                    self.append_line_signal.emit(tool_name.lower(), msg + "\n\n")
                    try:
                        self._scan_complete_sent.add(tool_name.lower())
                    except Exception:
                        pass
                except Exception:
                    pass
            self.parse_results_signal.emit(tool_name)

        # Request debounced parse on main thread for nslookup
        # nslookup needs debounced parsing because it doesn't send completion signals
        if tool_name.lower() in ("nslookup",):
            self.request_debounced_parse.emit(tool_name)

    def _handle_request_debounced_parse(self, tool_name):
        """Run in main thread: debounce parse requests per tool using QTimer."""
        t = self._parse_timers.get(tool_name)
        if t:
            t.stop()
        timer = QTimer(self)
        timer.setSingleShot(True)
        timer.timeout.connect(lambda tn=tool_name: self.parse_results_signal.emit(tn))
        timer.start(300)
        self._parse_timers[tool_name] = timer

    # --- Start Scan Logic ---
    # ... Collects user input, validates, and starts scan via ScanHandler ...
    def handle_start_scan(self):
        if not self.current_tool or self.current_tool not in self.tools_data:
            show_error_popup(self, "Please select a tool before scanning.")
            return
        collapsible = self.collapsible_widgets.get(self.current_tool)
        if collapsible and not collapsible.is_tool_checked(self.current_tool):
            show_error_popup(
                self, f"Please check the '{self.current_tool}' tool before scanning."
            )
            return
        domain = self.target_box.text().strip()
        if not domain:
            show_error_popup(self, "Please enter a domain before scanning.")
            return
        checked = self.tool_name_box.get_checked()

        # set tool_key from current tool early so validation below can reference it
        tool_key = self.current_tool.lower()

        # Allow theHarvester to run when only the source (-b) is provided.
        # The source control is implemented as a hidden checkbox with an attached QComboBox (value_input).
        if not any(checked):
            if tool_key == "theharvester":
                source_present = False
                for cb in self.tool_name_box.param_checks:
                    if (
                        cb.text() == "[REQUIRED] Source (-b, --source)"
                        and getattr(cb, "value_input", None) is not None
                    ):
                        try:
                            # Support both QComboBox and QLineEdit APIs safely
                            val = (
                                cb.value_input.currentText().strip()
                                if hasattr(cb.value_input, "currentText")
                                else cb.value_input.text().strip()
                            )
                        except Exception:
                            val = ""
                        if val:
                            source_present = True
                            break
                if not source_present:
                    show_error_popup(
                        self, "Please select at least one parameter before scanning."
                    )
                    return
            else:
                show_error_popup(
                    self, "Please select at least one parameter before scanning."
                )
                return

        # Get the correct value_required and value_optional lists for validation
        current_value_required = []
        current_value_optional = []
        if tool_key == "whois":
            current_value_required = whois_value_required
            current_value_optional = whois_value_optional
        elif tool_key == "whatweb":
            current_value_required = whatweb_value_required
            current_value_optional = []
        elif tool_key == "nmap":
            current_value_required = nmap_value_required
            current_value_optional = []
        elif tool_key == "ffuf":
            current_value_required = ffuf_value_required
            current_value_optional = []
        elif tool_key == "theharvester":
            current_value_required = theharvester_value_required
            current_value_optional = []
        elif tool_key == "dnsenum":
            current_value_required = dnsenum_value_required
            current_value_optional = []

        parameters = {tool_key: []}
        # Build parameters from the rendered checkboxes (checkbox text reflects reordered UI)
        for cb in self.tool_name_box.param_checks:
            name = cb.text()
            # Normally we only include checked boxes. For theHarvester, allow the hidden source combobox
            # to be included even if its checkbox is invisible/unchecked.
            if not cb.isChecked():
                if not (
                    tool_key == "theharvester"
                    and name == "[REQUIRED] Source (-b, --source)"
                    and getattr(cb, "value_input", None) is not None
                ):
                    continue

            # Extract value if present (supports QComboBox or QLineEdit)
            if getattr(cb, "value_input", None) is not None:
                val_widget = cb.value_input
                try:
                    is_combo = hasattr(val_widget, "currentText")
                except Exception:
                    is_combo = False
                try:
                    val = (
                        val_widget.currentText().strip()
                        if is_combo
                        else val_widget.text().strip()
                    )
                except Exception:
                    val = ""

                # Validate required parameters are not empty
                if name in current_value_required and not val:
                    show_error_popup(self, f"Please provide a value for {name}")
                    return

                # For optional parameters, only include if value is provided
                if name in current_value_optional:
                    if val:  # Only add if user provided a value
                        parameters[tool_key].append((name, val))
                else:
                    # For required parameters or non-optional parameters, always add the tuple
                    parameters[tool_key].append((name, val))
            else:
                parameters[tool_key].append(name)

        # --- auto-insert FFUF wordlist (-w <path>) from the static textbox ---
        if tool_key == "ffuf":
            ffuf_input = getattr(self.tool_name_box, "ffuf_top_input", None)
            if ffuf_input:
                ffuf_path = ffuf_input.text().strip()
                if ffuf_path:
                    params_list = parameters.setdefault(tool_key, [])
                    # remove any existing Wordlist tuple to avoid duplicates
                    params_list = [
                        p
                        for p in params_list
                        if not (isinstance(p, tuple) and p[0] == "Wordlist")
                    ]
                    # insert at front so FFUFToolProcess will place -w right after -u <target>
                    params_list.insert(0, ("Wordlist", ffuf_path))
                    parameters[tool_key] = params_list
        # --------------------------------------------------------------------

        # If WhatWeb "Default scan" was selected, ignore other flags so the command is just: whatweb <target>
        if tool_key == "whatweb":
            params_list = parameters.get(tool_key, [])
            has_default = any(
                (
                    (p == "Default scan")
                    if not isinstance(p, tuple)
                    else (p[0] == "Default scan")
                )
                for p in params_list
            )
            if has_default:
                parameters[tool_key] = []

        # For nslookup: if user requested CNAME or Nameservers and target is a bare domain (example.com),
        # prefer querying the www. subdomain automatically.
        domain_for_scan = domain
        if tool_key == "nslookup":
            params_list = parameters.get(tool_key, [])

            # parameters may be tuples (name, val) or plain strings
            def _param_matches(p, text):
                if isinstance(p, tuple):
                    return p[0] == text
                return p == text

            wants_cname = any(
                _param_matches(p, "Canonical names (CNAME)") for p in params_list
            )
            wants_ns = any(_param_matches(p, "Nameservers (NS)") for p in params_list)
            if wants_cname or wants_ns:
                labels = domain.split(".")
                if len(labels) == 2 and not domain.startswith("www."):
                    domain_for_scan = f"www.{domain}"
                    self.send_to_terminal(
                        f"[Info] Using {domain_for_scan} for nslookup because Canonical names/Nameservers was selected.\r\n"
                    )
        # Ensure FFUF protocol selection is included (visible radio or previously stored value)
        if tool_key == "ffuf":
            try:
                proto_val = ""
                # prefer visible widget
                try:
                    proto_w = getattr(self.tool_name_box, "protocol_widget", None)
                    if proto_w:
                        proto_val = proto_w.currentText().strip()
                except Exception:
                    proto_val = ""
                # fallback to stored value
                if not proto_val:
                    proto_val = (
                        (self.stored_param_values.get(self.current_tool, {}) or {})
                        .get("Protocol (http/https)", "")
                        .strip()
                    )
                if proto_val:
                    params_list = parameters.setdefault(tool_key, [])
                    # avoid duplicates
                    if not any(
                        isinstance(p, tuple) and p[0] == "Protocol (http/https)"
                        for p in params_list
                    ):
                        params_list.insert(0, ("Protocol (http/https)", proto_val))
            except Exception:
                pass

        # Confirm and clear before starting a new scan (clears terminals & previous results)
        try:
            if not self._confirm_new_scan_and_clear():
                return
        except Exception:
            return

        # build preview after injection
        command_preview = self.scan_handler.build_command_preview(
            domain_for_scan, tool_key, parameters[tool_key]
        )
        # route preview to the tool tab
        self.send_to_terminal(tool_key, f"$ {command_preview}\r\n")

        # Start scan with the final parameters (includes Wordlist tuple if provided)
        # Clear the parser state for this tool to prevent accumulation from previous scans
        if tool_key in self.results_manager.parsers:
            self.results_manager.parsers[tool_key].clear()

        try:
            # record start time BEFORE starting the worker to avoid races for very-fast scans
            self._scan_start_times[tool_key] = time.time()
            # start time recorded
        except Exception:
            pass
        try:
            # reset any previously-emitted complete flag for this tool
            self._scan_complete_sent.discard(tool_key)
        except Exception:
            pass

        self.scan_handler.start_scan(
            domain_for_scan,
            [tool_key],
            parameters,
            self.output_callback,
        )
        self.send_to_terminal(
            tool_key,
            f"Started scan for {domain_for_scan} with {self.current_tool}.\r\n",
        )
        # mark tool as running and update toggle button
        try:
            self._set_scan_button_state(tool_key, True)
        except Exception:
            pass

    def handle_scan_all(self):
        """Start scans for all left-side checked tools concurrently."""
        try:
            domain = self.target_box.text().strip()
            if not domain:
                show_error_popup(self, "Please enter a domain before scanning.")
                return

            # Persist any changes the user made in the currently-visible tool
            # so Scan All uses the up-to-date checkboxes and input values.
            try:
                # Save the checked flags from the visible ToolNameBox
                if getattr(self, "current_tool", None) and getattr(
                    self, "tool_name_box", None
                ):
                    try:
                        self.checked_params[self.current_tool] = (
                            self.tool_name_box.get_checked()
                        )
                    except Exception:
                        pass
                    # Persist any widget values (FFUF textbox, combos, line edits, etc.)
                    try:
                        self._save_current_tool_values()
                    except Exception:
                        pass
            except Exception:
                pass

            # collect checked tools from the left-side categories
            selected = [
                tool
                for tool, widget in self.collapsible_widgets.items()
                if widget.is_tool_checked(tool)
            ]
            if not selected:
                show_error_popup(
                    self,
                    "No tools checked on the left. Check tools you want to run with 'Scan All'.",
                )
                return

            # Build parameters for each tool using currently stored checked param flags and stored input values.
            parameters = {}
            missing_required = []
            tools_with_no_params = []  # collect tools that would run with zero parameters
            previews = {}
            for tool_label in selected:
                tool_key = tool_label.lower()
                # original parameters as defined in the data model
                params_defs = self.tools_data.get(tool_label, {}).get("parameters", [])
                checked_flags = self.checked_params.get(
                    tool_label, [False] * len(params_defs)
                )
                params_list = []

                # choose required/optional lists for validation (mirror handle_start_scan)
                current_value_required = []
                current_value_optional = []
                if tool_key == "whois":
                    current_value_required = whois_value_required
                    current_value_optional = whois_value_optional
                elif tool_key == "whatweb":
                    current_value_required = whatweb_value_required
                    current_value_optional = []
                elif tool_key == "nmap":
                    current_value_required = nmap_value_required
                    current_value_optional = []
                elif tool_key == "ffuf":
                    current_value_required = ffuf_value_required
                    current_value_optional = []
                elif tool_key == "theharvester":
                    current_value_required = theharvester_value_required
                    current_value_optional = []
                elif tool_key == "dnsenum":
                    current_value_required = dnsenum_value_required
                    current_value_optional = []

                # retrieve previously-saved user-entered values for this tool (including current tool just saved above)
                saved_vals = self.stored_param_values.get(tool_label, {}) or {}

                # Map checked flags by the rendered right-side order (saved in __param_order__) to avoid index mismatch
                saved_order = saved_vals.get("__param_order__")
                checked_by_name = {}
                try:
                    if (
                        saved_order
                        and isinstance(saved_order, list)
                        and len(checked_flags) == len(saved_order)
                    ):
                        checked_by_name = {
                            saved_order[i]: bool(checked_flags[i])
                            for i in range(len(saved_order))
                        }
                    elif len(checked_flags) == len(params_defs):
                        checked_by_name = {
                            params_defs[i]: bool(checked_flags[i])
                            for i in range(len(params_defs))
                        }
                    else:
                        checked_by_name = {}
                except Exception:
                    checked_by_name = {}

                # Build params_list consulting checked_by_name (name-based) to match UI ordering
                for name in params_defs:
                    if not checked_by_name.get(name, False):
                        continue

                    # If this parameter accepts a value, attempt to include stored value
                    if name in current_value_required or name in current_value_optional:
                        # saved_vals holds previously persisted widget values for this tool
                        val = saved_vals.get(name, "") or ""
                        if val:
                            params_list.append((name, val))
                        else:
                            # required and missing -> cannot proceed
                            if name in current_value_required:
                                missing_required.append(f"{tool_label}: {name}")
                            # optional & missing -> skip it
                    else:
                        # plain flag (no value) -> include label name
                        params_list.append(name)

                # If ffuf has a stored top input and current tool is FFUF and textbox exists in UI, include it
                if tool_key == "ffuf":
                    ffuf_val = ""
                    # visible widget wins (only present when FFUF is the current tool)
                    try:
                        ffuf_input = getattr(self.tool_name_box, "ffuf_top_input", None)
                        if ffuf_input and ffuf_input.text().strip():
                            ffuf_val = ffuf_input.text().strip()
                    except Exception:
                        ffuf_val = ""
                    # fallback to stored values (persisted earlier via _save_current_tool_values)
                    if not ffuf_val:
                        saved = self.stored_param_values.get(tool_label) or {}
                        ffuf_val = (saved.get("__ffuf_top_input__", "") or "").strip()
                    if ffuf_val:
                        params_list.insert(0, ("Wordlist", ffuf_val))
                # Ensure FFUF protocol from stored values (or visible widget) is included in Scan All parameters
                if tool_key == "ffuf":
                    try:
                        sv = ""
                        # if this tool_label is the currently rendered tool, prefer visible widget
                        try:
                            if self.current_tool == tool_label and getattr(
                                self.tool_name_box, "protocol_widget", None
                            ):
                                sv = self.tool_name_box.protocol_widget.currentText().strip()
                        except Exception:
                            sv = ""
                        if not sv:
                            sv = (saved_vals.get("Protocol (http/https)") or "").strip()
                        if sv:
                            if not any(
                                isinstance(p, tuple) and p[0] == "Protocol (http/https)"
                                for p in params_list
                            ):
                                params_list.insert(0, ("Protocol (http/https)", sv))
                    except Exception:
                        pass
                parameters[tool_key] = params_list

                # create preview to check sudo hints
                try:
                    previews[tool_key] = self.scan_handler.build_command_preview(
                        domain, tool_key, params_list
                    )
                except Exception:
                    previews[tool_key] = ""

            if missing_required:
                msg = "Scan All cannot run because some selected parameters require explicit values. Open each tool and set the required values or uncheck the parameter:\n\n"
                msg += "\n".join(missing_required)
                show_error_popup(self, msg)
                return

            # Block Scan All if any selected tools have no parameters checked.
            if tools_with_no_params:
                msg = "Scan All will not start because some selected tools have no parameters selected. Open each tool and select parameters or uncheck the tool:\n\n"
                msg += "\n".join(tools_with_no_params)
                show_error_popup(self, msg)
                return

            # Confirm and clear before starting a new scan (clears terminals & previous results)
            try:
                if not self._confirm_new_scan_and_clear():
                    return
            except Exception:
                return

            # Clear parser state for each tool and start them all concurrently
            tool_keys = list(parameters.keys())
            for tk in tool_keys:
                if tk in self.results_manager.parsers:
                    try:
                        self.results_manager.parsers[tk].clear()
                    except Exception:
                        pass

            # Start the scans in one call (ScanHandler supports multiple tools)
            try:
                # record start times for each tool so we can show durations on completion
                for tk in tool_keys:
                    try:
                        self._scan_start_times[tk] = time.time()
                    except Exception:
                        pass
                    try:
                        self._scan_complete_sent.discard(tk)
                    except Exception:
                        pass
            except Exception:
                pass
            self.scan_handler.start_scan(
                domain,
                tool_keys,
                parameters,
                self.output_callback,
            )

            # Mark each started tool as running and update UI state so switching to any of them
            # shows the correct Start/Stop appearance immediately.
            for tk in tool_keys:
                try:
                    # ensure we use the lowercase tool key expected by _set_scan_button_state
                    self._set_scan_button_state(tk, True)
                except Exception:
                    pass

            # User feedback per-tab
            for tk in tool_keys:
                self.send_to_terminal(
                    tk, f"Started scan for {domain} with {tk} (Scan All).\r\n"
                )
            # Update unified Scan Selected toggle appearance to reflect running selected tools
            try:
                self.update_scan_selected_button_state()
            except Exception:
                pass
        except Exception as e:
            show_error_popup(self, f"Failed to start Scan All:\n{str(e)}")

    def handle_scan_selected_toggle(self):
        """Toggle Start/Stop for checked left-side tools. If any selected tool is running, stop them; otherwise start them."""
        try:
            # Collect which tools are currently checked on the left
            selected = [
                tool
                for tool, widget in self.collapsible_widgets.items()
                if widget.is_tool_checked(tool)
            ]
            if not selected:
                show_error_popup(
                    self,
                    "No tools checked on the left. Check tools you want to run with 'Scan Selected'.",
                )
                return
            # If any of the selected tools are running, treat this as a Stop action
            any_running = any(
                (tool.lower() in self._scan_running_tools) for tool in selected
            )
            if any_running:
                # stop all selected
                self.handle_stop_selected()
            else:
                # start selected (reuse existing logic)
                self.handle_scan_all()
        except Exception:
            pass

    def handle_stop_selected(self):
        """Stop selected scans (stop tools checked on the left that may still be running)."""
        try:
            # collect checked tools from the left-side categories
            selected = [
                tool
                for tool, widget in self.collapsible_widgets.items()
                if widget.is_tool_checked(tool)
            ]
            if not selected:
                show_error_popup(
                    self,
                    "No tools checked on the left. Check tools you want to stop with 'Stop Selected'.",
                )
                return

            # Attempt to stop each selected tool (ScanHandler.stop_tool expects tool key)
            for tool_label in selected:
                tk = tool_label.lower()
                try:
                    self.scan_handler.stop_tool(tk)
                except Exception:
                    # ignore per-tool stop failures and continue
                    pass
                # user-visible per-tab notice
                try:
                    self.send_to_terminal(
                        tk, f"Stopping selected scan: {tool_label}.\r\n"
                    )
                except Exception:
                    pass
            # Refresh unified toggle appearance after stop attempts
            try:
                self.update_scan_selected_button_state()
            except Exception:
                pass
        except Exception as e:
            show_error_popup(self, f"Failed to stop selected scans:\n{str(e)}")

    # --- Stop Scan Logic ---
    # ... Stops the running scan via ScanHandler ...
    def handle_stop_scan(self):
        tool_key = self.current_tool.lower() if self.current_tool else None
        if tool_key:
            # request worker to terminate the running tool
            self.scan_handler.stop_tool(tool_key)
            # update running state for this tool
            try:
                self._set_scan_button_state(tool_key, False)
            except Exception:
                pass
        # user-visible notice (single line)
        self.send_to_terminal(
            tool_key or "general", f"Stopping Scan: {self.current_tool or 'tool'}.\r\n"
        )
        # clear SGR without adding a newline
        self.send_to_terminal(tool_key or "general", ANSI_RESET)
        # DO NOT auto-parse on manual stop; ToolProcessBase will emit a cancelled sentinel.

    def parse_and_display_results(self, tool_name):
        """Parse the results and update the results display.
        Failures are debounced briefly so transient/partial parses don't display
        before a subsequent successful parse arrives.
        """
        try:
            target = self.target_box.text().strip()
            result = self.results_manager.parse_results(tool_name, target)
            if not result:
                return

            key = f"{tool_name}:{target}"

            # If parser reported failure, debounce showing the failure so transient partial parses don't flash
            if not getattr(result, "success", False):
                # If already scheduled, don't schedule another
                if key in self._parse_failure_timers:
                    return
                timer = QTimer(self)
                timer.setSingleShot(True)

                def _on_timeout(r=result, k=key):
                    # remove timer reference and show the (failed) result
                    self._parse_failure_timers.pop(k, None)
                    self.display_parsed_results(r)
                    self.update_diagnostics(r)
                    try:
                        timer.deleteLater()
                    except Exception:
                        pass

                timer.timeout.connect(_on_timeout)
                timer.start(1200)  # 1.2s debounce window
                self._parse_failure_timers[key] = timer
                return

            # Success path: cancel any pending failure timer and display immediately
            pending = self._parse_failure_timers.pop(key, None)
            if pending:
                try:
                    pending.stop()
                    pending.deleteLater()
                except Exception:
                    pass

            # Immediately show successful parse
            self.display_parsed_results(result)
            self.update_diagnostics(result)
            # mark tool as not running (scan complete) and update toggle button if it matches current tool
            try:
                self._set_scan_button_state(tool_name.lower(), False)
            except Exception:
                pass
        except Exception as e:
            self.send_to_terminal("general", f"Error parsing results: {str(e)}\r\n")

    def display_parsed_results(self, result):
        """Display structured results in the results textbox"""
        if not result.success:
            # Bold, 11pt, dark red failure message (matches completed styling but red)
            self.results_textbox.append(
                f'<span style="color:#D41A1A; font-weight:bold;"><span style="font-size:11pt;">{result.tool_name.upper()} scan failed for {result.target}</span></span>'
            )
            if getattr(result, "error_message", None):
                self.results_textbox.append(
                    f'<div style="font-size:10pt; color:#d32f2f;"><b>Error:</b> {result.error_message}</div>'
                )
            return

        # Create a unique key for this result to prevent duplicates based on content
        # Use raw output hash instead of timestamp to catch true duplicates
        import hashlib

        content_hash = hashlib.md5(result.raw_output.encode()).hexdigest()[:8]
        result_key = f"{result.tool_name}:{result.target}:{content_hash}"
        if result_key in self.displayed_results:
            return  # Skip duplicate
        self.displayed_results.add(result_key)

        self.results_textbox.append(
            f'<span style="color: darkgreen; font-weight: bold;"><span style="font-size:11pt;">{result.tool_name.upper()} scan completed for {result.target}</span></span>'
        )

        import html as _html

        ts = _html.escape(str(getattr(result, "timestamp", "") or ""))
        self.results_textbox.append(
            f'<div style="font-size:10pt; color:#222; margin-bottom:6px;"><b>Timestamp:</b> {ts}</div>'
        )
        # show duration if we recorded a start time for this tool
        try:
            start = self._scan_start_times.pop(result.tool_name.lower(), None)
        except Exception:
            start = None
        if start is not None:
            try:
                dur = time.time() - float(start)
                if dur >= 3600:
                    hrs = int(dur // 3600)
                    mins = int((dur % 3600) // 60)
                    secs = int(dur % 60)
                    dur_str = f"{hrs}h{mins:02d}m{secs:02d}s"
                elif dur >= 60:
                    mins = int(dur // 60)
                    secs = int(dur % 60)
                    dur_str = f"{mins}m{secs:02d}s"
                else:
                    dur_str = f"{dur:.2f}s"
            except Exception:
                dur_str = ""
            # Also emit a terminal-visible scan-complete message with duration (if not already emitted)
            try:
                term_msg = f"(Duration: {dur_str})\r\n"
                # add an extra CRLF so the terminal receives a blank line after completion
                term_msg = f"(Duration: {dur_str})\r\n\r\n"
                tk = result.tool_name.lower()
                if tk not in self._scan_complete_sent:
                    self.send_to_terminal(tk, term_msg)
                    try:
                        self._scan_complete_sent.add(tk)
                    except Exception:
                        pass
            except Exception:
                pass
        self.results_textbox.append("-" * 80)
        # Display tool-specific results
        if result.tool_name == "nmap":
            self.display_nmap_results(result)
        elif result.tool_name == "nslookup":
            self.display_nslookup_results(result)
        elif result.tool_name == "whatweb":
            self.display_whatweb_results(result)
        elif result.tool_name == "ffuf":
            self.display_ffuf_results(result)
        elif result.tool_name == "theharvester":
            self.display_theharvester_results(result)
        elif result.tool_name == "dnsenum":
            self.display_dnsenum_results(result)
        elif result.tool_name == "whois":
            self.display_whois_results(result)

        self.results_textbox.append("")

    # #============================================================================================= START RESULTS
    # #=============================================================================================
    # #=============================================================================================\

    def display_nmap_results(self, result):
        """Display nmap-specific results"""
        self.results_textbox.append(
            f'<span style="font-size:10pt;"><b>Scan Type:</b> {result.scan_type}</span>'
        )

        if result.hosts:
            count = len(result.hosts)
            label = f"Hosts Discovered ({count} host{'s' if count != 1 else ''}):"
            self.results_textbox.append(
                f'<span style="font-size:10pt;"><b>{label}</b</span>'
            )
            for host in result.hosts:
                # IP (first-level indent)
                self.results_textbox.append(
                    '<div style="margin-left:12px; font-size:10pt;"><b>IP:</b> '
                    + str(host.ip)
                    + "</div>"
                )
                # Hostname, rDNS, Status, MAC (second-level indent)
                if host.hostname:
                    self.results_textbox.append(
                        '<div style="margin-left:24px; font-size:10pt;"><b>Hostname:</b> '
                        + str(host.hostname)
                        + "</div>"
                    )
                if getattr(host, "rdns", None):
                    self.results_textbox.append(
                        '<div style="margin-left:24px; font-size:10pt;"><b>rDNS:</b> '
                        + str(host.rdns)
                        + "</div>"
                    )
                if host.status:
                    self.results_textbox.append(
                        '<div style="margin-left:24px; font-size:10pt;"><b>Status:</b> '
                        + str(host.status)
                        + "</div>"
                    )
                if host.mac_address:
                    self.results_textbox.append(
                        '<div style="margin-left:24px; font-size:10pt;"><b>MAC:</b> '
                        + str(host.mac_address)
                        + "</div>"
                    )
                    if host.vendor:
                        # Vendor (third-level indent)
                        self.results_textbox.append(
                            '<div style="margin-left:36px; font-size:10pt;"><b>Vendor:</b> '
                            + str(host.vendor)
                            + "</div>"
                        )
                # Other addresses (if parsed by nmap parser)
                if getattr(host, "other_addresses", None):
                    other = ", ".join(host.other_addresses)
                    self.results_textbox.append(
                        '<div style="margin-left:24px; font-size:10pt;"><b>Other Addresses:</b> '
                        + other
                        + "</div>"
                    )

        if result.ports:
            # Determine if we need a separate "Version" column.
            # Show Version column when either:
            #  - parser populated port.version, or
            #     - extra_info contains additional tokens after the service token (e.g. "http Varnish")
            has_version_col = False
            for p in result.ports:
                ver = str(getattr(p, "version", "") or "").strip()
                extra_info = str(getattr(p, "extra_info", "") or "").strip()
                tokens = extra_info.split()

                rest_after_service = (
                    " ".join(tokens[1:]).strip() if len(tokens) > 1 else ""
                )
                if ver or rest_after_service:
                    has_version_col = True
                    break

            parts = []
            parts.append(
                f'<div style="font-weight:bold; font-size:10pt; margin-top:6px;">Port Discovery ({len(result.ports)} found):</div>'
            )
            parts.append(
                '<div style="display:block; width:100%; overflow:auto; box-sizing:border-box; padding:0; margin:0; box-shadow: 0 2px 8px rgba(0,0,0,0.15); border-radius: 4px;">'
            )
            parts.append(
                '<table width="100%" cellpadding="0" cellspacing="0" style="border-collapse:collapse; table-layout:fixed; width:100%;">'
            )
            parts.append(
                "<colgroup>"
                '<col style="width:12%;">'
                '<col style="width:18%;">'
                '<col style="width:12%;">'
                '<col style="width:48%;">'
                '<col style="width:10%;">'
                "</colgroup>"
            )
            parts.append(
                "<thead>"
                '<tr style="background:#f0f0f0;">'
                '<th style="text-align:left; padding:6px; border:1px solid #ddd; white-space:nowrap; font-size:10pt;">Port</th>'
                '<th style="text-align:left; padding:6px; border:1px solid #ddd; white-space:nowrap; font-size:10pt;">Protocol</th>'
                '<th style="text-align:left; padding:6px; border:1px solid #ddd; white-space:nowrap; font-size:10pt;">State</th>'
                '<th style="text-align:left; padding:6px; border:1px solid #ddd; font-size:10pt;">Service</th>'
                '<th style="text-align:left; padding:6px; border:1px solid #ddd; white-space:nowrap; font-size:10pt;">Version</th>'
                "</tr>"
                "</thead>"
                "<tbody>"
            )
            for port in result.ports:
                # Use extra_info to recover original service token (e.g. "http Varnish")
                extra_info = str(getattr(port, "extra_info", "") or "").strip()
                tokens = extra_info.split()
                original_service_token = (
                    tokens[0]
                    if tokens
                    else (str(getattr(port, "service", "") or "").strip())
                )
                rest_after_service = (
                    " ".join(tokens[1:]).strip() if len(tokens) > 1 else ""
                )

                prod = str(getattr(port, "service", "") or "").strip()
                ver = str(getattr(port, "version", "") or "").strip()

                if has_version_col:
                    # Service should be the original protocol/service token (e.g. "http")
                    service_text = original_service_token or prod or ""
                    # Version prefers explicit parsed version, otherwise whatever follows the service token
                    version_text = ver or rest_after_service or ""
                else:
                    # No separate version column — combine intelligently
                    extra = rest_after_service or ""
                    if ver:
                        if prod and prod not in extra:
                            service_text = f"{prod} {ver}"
                        elif extra:
                            service_text = f"{extra} {ver}"
                        else:
                            service_text = f"{prod} {ver}".strip()
                    else:
                        if extra and extra != prod and extra != "":
                            if prod:
                                service_text = f"{prod} — {extra}"
                            else:
                                service_text = extra
                        else:
                            service_text = prod or extra or ""
                        version_text = ""
                width1 = "12%" if has_version_col else "15%"
                width2 = "18%" if has_version_col else "20%"
                width3 = "12%" if has_version_col else "15%"
                width4 = "48%" if has_version_col else "50%"

                row_cells = [
                    f'<td style="padding:6px; border:1px solid #ddd; word-break:break-word; width:{width1}; font-size:10pt;">{port.port}</td>',
                    f'<td style="padding:6px; border:1px solid #ddd; word-break:break-word; width:{width2}; font-size:10pt;">{port.protocol}</td>',
                    f'<td style="padding:6px; border:1px solid #ddd; word-break:break-word; width:{width3}; font-size:10pt;">{port.state}</td>',
                    f'<td style="padding:6px; border:1px solid #ddd; font-weight:normal; word-break:break-word; width:{width4}; font-size:10pt;">{service_text}</td>',
                ]
                if has_version_col:
                    row_cells.append(
                        f'<td style="padding:6px; border:1px solid #ddd; word-break:break-word; width:10%; font-size:10pt;">{version_text}</td>'
                    )

                parts.append("<tr>" + "".join(row_cells) + "</tr>")
            parts.append("</tbody></table>")
            parts.append("</div>")  # close wrapper
            self.results_textbox.append("".join(parts))

            # Per-port details (SSH hostkeys, scripts, per-request rows) shown below the table
            for port in result.ports:
                # existing scripts block left unchanged (shows scripts as before)
                if getattr(port, "scripts", None):
                    self.results_textbox.append(
                        f'<div style="margin-top:8px; margin-left:12px; font-size:10pt;"><b>Scripts ({port.port}/{port.protocol}):</b></div>'
                    )
                    for name, val in (port.scripts or {}).items():
                        if val is None:
                            continue
                        if "\n" in val:
                            self.results_textbox.append(
                                f'<div style="margin-left:24px; font-size:10pt;"><b>{name}:</b></div>'
                            )
                            for sub in val.splitlines():
                                self.results_textbox.append(
                                    f'<div style="margin-left:36px; font-size:10pt;">{sub}</div>'
                                )
                        else:
                            self.results_textbox.append(
                                f'<div style="margin-left:24px; font-size:10pt;"><b>{name}:</b> {val}</div>'
                            )

                # --- Render per-request rows parsed by nmap_parser (one row per Request Type) ---
                if getattr(port, "requests", None):
                    reqs = port.requests or []
                    if reqs:
                        parts = []
                        parts.append(
                            f'<div style="margin-top:8px; margin-left:12px; font-size:10pt;"><b>Per-request details ({port.port}/{port.protocol}):</b></div>'
                        )
                        parts.append(
                            '<div style="display:block; width:100%; overflow:auto; box-sizing:border-box; margin-top:6px; margin-left:12px; box-shadow: 0 2px 6px rgba(0,0,0,0.12); border-radius: 4px;">'
                        )
                        parts.append(
                            '<table width="98%" cellpadding="6" cellspacing="0" style="border-collapse:collapse; border:1px solid #ddd;">'
                        )
                        parts.append(
                            '<thead><tr style="background:#f6f6f6;">'
                            '<th style="text-align:left; border:1px solid #ddd; font-size:10pt;">Port / Protocol</th>'
                            '<th style="text-align:left; border:1px solid #ddd; font-size:10pt;">State</th>'
                            '<th style="text-align:left; border:1px solid #ddd; font-size:10pt;">Service</th>'
                            '<th style="text-align:left; border:1px solid #ddd; font-size:10pt;">Version</th>'
                            '<th style="text-align:left; border:1px solid #ddd; font-size:10pt;">Request Type</th>'
                            '<th style="text-align:left; border:1px solid #ddd; font-size:10pt;">Status Code</th>'
                            '<th style="text-align:left; border:1px solid #ddd; font-size:10pt;">Message</th>'
                            '<th style="text-align:left; border:1px solid #ddd; font-size:10pt;">Server</th>'
                            '<th style="text-align:left; border:1px solid #ddd; font-size:10pt;">X-Served-By</th>'
                            '<th style="text-align:left; border:1px solid #ddd; font-size:10pt;">Notes</th>'
                            "</tr></thead><tbody>"
                        )
                        for r in reqs:
                            p_proto = (
                                f"{r.get('port', '')}/{r.get('protocol', '')}".strip(
                                    "/"
                                )
                            )
                            state = r.get("state", "") or "N/A"
                            service = r.get("service", "") or ""
                            # prefer explicit parsed version, fallback to extra_info if available
                            version = (
                                r.get("version", "")
                                or getattr(r, "extra_info", "")
                                or ""
                            )
                            # request_type may be comma-separated; render one table row per entry
                            raw_req_types = (r.get("request_type") or "") or ""
                            req_type_list = [
                                t.strip()
                                for t in re.split(r",\s*", raw_req_types)
                                if t.strip()
                            ] or [""]
                            # explicit parser fields (prefer these)
                            base_status_code = (r.get("status_code") or "").strip()
                            base_message = (r.get("message") or "").strip()
                            base_server = (r.get("server") or "").strip()
                            base_x_served_by = (r.get("x_served_by") or "").strip()
                            notes_raw = (r.get("notes", "") or "").strip()

                            # Augment notes from other script outputs on the same port (http-title, http-server-header, ssl-cert, tls warnings)
                            scripts = getattr(port, "scripts", {}) or {}
                            script_notes = []
                            # include http-title / redirect hints
                            http_title = scripts.get("http-title") or scripts.get(
                                "http-title:"
                            )
                            if http_title:
                                script_notes.append(f"Title: {http_title}")
                                # if title mentions redirect, prefer to keep it prominent
                            # include http-server-header if present (already applied to server if missing)
                            http_srv = scripts.get("http-server-header") or scripts.get(
                                "http-server-header:"
                            )
                            if http_srv and not base_server:
                                base_server = http_srv.strip()
                            # include ssl-cert summary when present
                            ssl_cert = scripts.get("ssl-cert") or scripts.get(
                                "ssl-cert:"
                            )
                            if ssl_cert:
                                # extract CN and SAN summary
                                cn_m = re.search(
                                    r"commonName=([^/,\n\r]+)", ssl_cert, re.IGNORECASE
                                )
                                san_m = re.search(
                                    r"Subject Alternative Name:\s*(.*)",
                                    ssl_cert,
                                    re.IGNORECASE,
                                )
                                if cn_m:
                                    script_notes.append(
                                        f"Cert CN: {cn_m.group(1).strip()}"
                                    )
                                if san_m:
                                    san = san_m.group(1).strip()
                                    # shorten long SAN lists
                                    script_notes.append(f"SANs: {san}")
                                # include validity window if present
                                nb = re.search(
                                    r"Not valid before[:\s]*(.*)",
                                    ssl_cert,
                                    re.IGNORECASE,
                                )
                                na = re.search(
                                    r"Not valid after[:\s]*(.*)",
                                    ssl_cert,
                                    re.IGNORECASE,
                                )
                                if nb:
                                    script_notes.append(
                                        f"Not valid before: {nb.group(1).strip()}"
                                    )
                                if na:
                                    script_notes.append(
                                        f"Not valid after: {na.group(1).strip()}"
                                    )

                            # combine parser notes and script_notes preserving order (script notes first)
                            combined_notes = []
                            for s in script_notes:
                                if s and s not in combined_notes:
                                    combined_notes.append(s)
                            if notes_raw:
                                for line in notes_raw.splitlines():
                                    ln = line.strip()
                                    if ln and ln not in combined_notes:
                                        combined_notes.append(ln)

                            # If status/message missing, try to extract from combined_notes text
                            combined_text = "\n".join(combined_notes)
                            if not base_status_code:
                                m = re.search(
                                    r"HTTP/\d+\.\d+\s+(\d{3})\s*(.*)",
                                    combined_text,
                                    re.IGNORECASE,
                                )
                                if m:
                                    base_status_code = m.group(1).strip()
                                    if not base_message:
                                        base_message = (m.group(2) or "").strip()
                            # try alternate shorter patterns
                            if not base_status_code:
                                m2 = re.search(
                                    r"\b(\d{3})\b\s*[-–:]\s*([A-Za-z ].+)",
                                    combined_text,
                                )
                                if m2:
                                    base_status_code = m2.group(1).strip()
                                    if not base_message:
                                        base_message = m2.group(2).strip()

                            # If x-served-by missing, try to extract from combined_notes
                            if not base_x_served_by:
                                xs = re.findall(
                                    r"X-Served-By[:\s]*([^\r\n,;]+)",
                                    combined_text,
                                    re.IGNORECASE,
                                )
                                if xs:
                                    seen = set()
                                    xs_clean = []
                                    for v in xs:
                                        v = v.strip()
                                        if v and v not in seen:
                                            xs_clean.append(v)
                                            seen.add(v)
                                    base_x_served_by = "; ".join(xs_clean)

                            # If server still missing, try to extract from combined_notes
                            if not base_server:
                                m3 = re.search(
                                    r"Server[:\s]*([^\r\n]+)",
                                    combined_text,
                                    re.IGNORECASE,
                                )
                                if m3:
                                    base_server = m3.group(1).strip()

                            # Build final notes HTML: include redirect/title/fastly/cache info and remaining notes
                            notes_parts = []
                            # make redirect/title prominent
                            for note in combined_notes:
                                # normalize common long lines (strip repetitive fragments)
                                n = note.strip()
                                if n:
                                    notes_parts.append(n)
                            notes_html = "<br>".join(notes_parts)

                            # produce one row per request-type found
                            for single_req in req_type_list:
                                parts.append(
                                    "<tr>"
                                    f'<td style="padding:6px; border:1px solid #ddd; font-size:10pt; vertical-align:top;">{p_proto}</td>'
                                    f'<td style="padding:6px; border:1px solid #ddd; font-size:10pt; vertical-align:top;">{state}</td>'
                                    f'<td style="padding:6px; border:1px solid #ddd; font-size:10pt; vertical-align:top;">{service}</td>'
                                    f'<td style="padding:6px; border:1px solid #ddd; font-size:10pt; vertical-align:top;">{version}</td>'
                                    f'<td style="padding:6px; border:1px solid #ddd; font-size:10pt; vertical-align:top;">{single_req}</td>'
                                    f'<td style="padding:6px; border:1px solid #ddd; font-size:10pt; vertical-align:top;">{base_status_code or ""}</td>'
                                    f'<td style="padding:6px; border:1px solid #ddd; font-size:10pt; vertical-align:top;">{base_message or ""}</td>'
                                    f'<td style="padding:6px; border:1px solid #ddd; font-size:10pt; vertical-align:top;">{base_server or ""}</td>'
                                    f'<td style="padding:6px; border:1px solid #ddd; font-size:10pt; vertical-align:top;">{base_x_served_by or ""}</td>'
                                    f'<td style="padding:6px; border:1px solid #ddd; font-size:10pt; vertical-align:top;">{notes_html or ""}</td>'
                                    "</tr>"
                                )
                        parts.append("</tbody></table></div>")
                        self.results_textbox.append("".join(parts))

                # Guarded traceroute render (place in both spots that currently render traceroute)
                if not getattr(result, "_traceroute_rendered", False):
                    traceroute = getattr(result, "traceroute", None) or []
                    if traceroute:
                        tr_parts = []
                        tr_parts.append(
                            '<div style="font-size:10pt; font-weight:bold; margin-top:12px;">Traceroute</div>'
                        )
                        tr_parts.append(
                            '<div style="display:block; width:100%; overflow:auto; box-sizing:border-box; margin-top:6px; margin-left:12px;">'
                        )
                        tr_parts.append(
                            '<table width="98%" cellpadding="6" cellspacing="0" style="border-collapse:collapse; border:1px solid #ddd;">'
                        )
                        tr_parts.append(
                            '<thead><tr style="background:#f6f6f6;">'
                            '<th style="text-align:left; border:1px solid #ddd; font-size:10pt; width:8%;">Hop</th>'
                            '<th style="text-align:left; border:1px solid #ddd; font-size:10pt; width:12%;">RTT (ms)</th>'
                            '<th style="text-align:left; border:1px solid #ddd; font-size:10pt; width:20%;">Address</th>'
                            '<th style="text-align:left; border:1px solid #ddd; font-size:10pt; width:30%;">Hostname</th>'
                            '<th style="text-align:left; border:1px solid #ddd; font-size:10pt;">Notes</th>'
                            "</tr></thead><tbody>"
                        )
                        for hop in traceroute:
                            hop_num = hop.get("Hop", "")
                            rtt = hop.get("RTT (ms)", "") or ""
                            address = hop.get("Address", "") or ""
                            hostname = hop.get("Hostname", "") or ""
                            notes = hop.get("Notes", "") or ""
                            notes_html = str(notes).replace("\n", "<br>")

                            hop_disp = hop_num if hop_num != "" else "---"
                            rtt_disp = rtt if str(rtt).strip() != "" else "---"
                            addr_disp = address if address.strip() != "" else "---"
                            host_disp = hostname if hostname.strip() != "" else "---"
                            notes_disp = (
                                notes_html if str(notes_html).strip() != "" else "---"
                            )

                            tr_parts.append(
                                "<tr>"
                                f'<td style="padding:6px; border:1px solid #ddd; font-size:10pt; vertical-align:top;">{hop_disp}</td>'
                                f'<td style="padding:6px; border:1px solid #ddd; font-size:10pt; vertical-align:top;">{rtt_disp}</td>'
                                f'<td style="padding:6px; border:1px solid #ddd; font-size:10pt; vertical-align:top;">{addr_disp}</td>'
                                f'<td style="padding:6px; border:1px solid #ddd; font-size:10pt; vertical-align:top;">{host_disp}</td>'
                                f'<td style="padding:6px; border:1px solid #ddd; font-size:10pt; vertical-align:top;">{notes_disp}</td>'
                                "</tr>"
                            )
                        tr_parts.append("</tbody></table></div>")
                        self.results_textbox.append("".join(tr_parts))
                        setattr(result, "_traceroute_rendered", True)

    # =============================================================================================
    # =============================================================================================
    # =============================================================================================
    # #=============================================================================================
    #
    # #=============================================================================================
    # #=============================================================================================
    # #=============================================================================================\

    def display_nslookup_results(self, result):
        """Display nslookup results using consistent 10pt font and bold labels."""
        try:
            # Header / basic info
            if getattr(result, "server", None):
                self.results_textbox.append(
                    f'<div style="font-size:10pt; margin-bottom:6px;"><b>DNS Server:</b> {result.server}</div>'
                )
            if getattr(result, "address", None):
                self.results_textbox.append(
                    f'<div style="font-size:10pt; margin-bottom:6px;"><b>Server Address:</b> {result.address}</div>'
                )

            self.results_textbox.append(
                f'<div style="font-size:10pt; margin-bottom:6px;"><b>Domain:</b> {result.domain}</div>'
            )
            scan_type = getattr(result, "scan_type", None) or "Standard Query"
            self.results_textbox.append(
                f'<div style="font-size:10pt; margin-bottom:6px;"><b>Query Type(s):</b> {scan_type}</div>'
            )

            # A (IPv4) Records
            if result.a_records:
                self.results_textbox.append(
                    f'<div style="font-size:10pt; margin-top:8px; margin-bottom:4px;"><b>IPv4 Address Records (A):</b></div>'
                )
                for record in result.a_records:
                    self.results_textbox.append(
                        f'<div style="margin-left:12px; font-size:10pt; margin-bottom:4px;">• <b>{record.name}</b> → {record.ipv4}</div>'
                    )

            # AAAA (IPv6) Records
            if result.aaaa_records:
                self.results_textbox.append(
                    f'<div style="font-size:10pt; margin-top:8px; margin-bottom:4px;"><b>IPv6 Address Records (AAAA):</b></div>'
                )
                for record in result.aaaa_records:
                    self.results_textbox.append(
                        f'<div style="margin-left:12px; font-size:10pt; margin-bottom:4px;">• <b>{record.name}</b> → {record.ipv6}</div>'
                    )

            # MX Records
            if result.mx_records:
                parts = []
                parts.append(
                    '<div style="font-size:10pt; font-weight:bold; margin-top:8px; margin-bottom:6px;"><b>Mail Exchange (MX) Records:</b></div>'
                )
                parts.append(
                    '<div style="display:block; width:100%; overflow:auto; box-sizing:border-box; padding:0; margin:0; box-shadow: 0 2px 8px rgba(0,0,0,0.15); border-radius: 4px;">'
                )
                parts.append(
                    '<table width="100%" cellpadding="0" cellspacing="0" style="border-collapse:collapse; table-layout:fixed; width:100%;">'
                )
                parts.append(
                    '<colgroup><col style="width:35%;"><col style="width:45%;"><col style="width:10%;"><col style="width:10%;"></colgroup>'
                )
                parts.append(
                    '<thead><tr style="background:#f0f0f0;">'
                    '<th style="text-align:left; padding:6px; border:1px solid #ddd; font-size:10pt;">Domain</th>'
                    '<th style="text-align:left; padding:6px; border:1px solid #ddd; font-size:10pt;">Mail Server</th>'
                    '<th style="text-align:left; padding:6px; border:1px solid #ddd; font-size:10pt;">Priority</th>'
                    '<th style="text-align:left; padding:6px; border:1px solid #ddd; font-size:10pt;">TTL</th>'
                    "</tr></thead><tbody>"
                )
                for record in result.mx_records:
                    domain_display = (
                        getattr(record, "domain", "")
                        or getattr(record, "name", "")
                        or ""
                    )
                    mail_server_display = (
                        getattr(record, "mail_server", "")
                        or getattr(record, "value", "")
                        or ""
                    )
                    priority_display = getattr(record, "priority", None)
                    priority_display = (
                        str(priority_display) if priority_display is not None else "N/A"
                    )
                    ttl_display = getattr(record, "ttl", None)
                    ttl_display = str(ttl_display) if ttl_display is not None else "N/A"
                    parts.append(
                        "<tr>"
                        f'<td style="padding:6px; border:1px solid #ddd; word-break:break-word; width:35%; font-size:10pt;"><b>{domain_display}</b></td>'
                        f'<td style="padding:6px; border:1px solid #ddd; word-break:break-word; width:45%; font-size:10pt;">{mail_server_display}</td>'
                        f'<td style="padding:6px; border:1px solid #ddd; text-align:left; font-size:10pt;">{priority_display}</td>'
                        f'<td style="padding:6px; border:1px solid #ddd; text-align:left; font-size:10pt;">{ttl_display}</td>'
                        "</tr>"
                    )
                parts.append("</tbody></table></div>")
                self.results_textbox.append("".join(parts))
            # NS Records
            if result.ns_records:
                self.results_textbox.append(
                    f'<div style="font-size:10pt; margin-top:8px; margin-bottom:4px;"><b>Name Server (NS) Records:</b></div>'
                )
                for record in result.ns_records:
                    self.results_textbox.append(
                        f'<div style="margin-left:12px; font-size:10pt; margin-bottom:4px;">• <b>{record.domain}</b> → {record.nameserver}</div>'
                    )

            # CNAME Records
            if result.cname_records:
                self.results_textbox.append(
                    f'<div style="font-size:10pt; margin-top:8px; margin-bottom:4px;"><b>Canonical Name (CNAME) Records:</b></div>'
                )
                for record in result.cname_records:
                    self.results_textbox.append(
                        f'<div style="margin-left:12px; font-size:10pt; margin-bottom:4px;">• <b>{record.alias}</b> → {record.canonical}</div>'
                    )

            # TXT Records
            if result.txt_records:
                self.results_textbox.append(
                    f'<div style="font-size:10pt; margin-top:8px; margin-bottom:4px;"><b>Text (TXT) Records:</b></div>'
                )
                for record in result.txt_records:
                    self.results_textbox.append(
                        f'<div style="margin-left:12px; font-size:10pt; margin-bottom:2px;">• <b>{record.domain}</b></div>'
                    )
                    for text in record.texts:
                        self.results_textbox.append(
                            f'<div style="margin-left:24px; font-size:10pt; margin-bottom:4px;">"{text}"</div>'
                        )

            # SOA Record
            if result.soa_record:
                soa = result.soa_record
                self.results_textbox.append(
                    f'<div style="font-size:10pt; margin-top:8px; margin-bottom:4px;"><b>Start of Authority (SOA) Record:</b></div>'
                )
                domain = getattr(soa, "domain", None) or getattr(result, "domain", "")
                self.results_textbox.append(
                    f'<div style="margin-left:12px; font-size:10pt; margin-bottom:4px;">• <b>Domain:</b> {domain}</div>'
                )
                primary = (
                    getattr(soa, "primary_ns", None)
                    or getattr(soa, "primary", None)
                    or getattr(soa, "origin", None)
                )
                if primary:
                    self.results_textbox.append(
                        f'<div style="margin-left:24px; font-size:10pt; margin-bottom:4px;"><b>Primary NS:</b> {primary}</div>'
                    )
                responsible = (
                    getattr(soa, "responsible_email", None)
                    or getattr(soa, "contact", None)
                    or getattr(soa, "mail_addr", None)
                )
                if responsible:
                    self.results_textbox.append(
                        f'<div style="margin-left:24px; font-size:10pt; margin-bottom:4px;"><b>Responsible Email:</b> {responsible}</div>'
                    )
                if getattr(soa, "serial", None):
                    self.results_textbox.append(
                        f'<div style="margin-left:24px; font-size:10pt; margin-bottom:2px;"><b>Serial:</b> {soa.serial}</div>'
                    )
                if getattr(soa, "refresh", None):
                    self.results_textbox.append(
                        f'<div style="margin-left:24px; font-size:10pt; margin-bottom:2px;"><b>Refresh:</b> {soa.refresh}</div>'
                    )
                if getattr(soa, "retry", None):
                    self.results_textbox.append(
                        f'<div style="margin-left:24px; font-size:10pt; margin-bottom:2px;"><b>Retry:</b> {soa.retry}</div>'
                    )
                if getattr(soa, "expire", None):
                    self.results_textbox.append(
                        f'<div style="margin-left:24px; font-size:10pt; margin-bottom:2px;"><b>Expire:</b> {soa.expire}</div>'
                    )
                ttl_val = getattr(soa, "ttl", None) or getattr(soa, "minimum", None)
                if ttl_val:
                    self.results_textbox.append(
                        f'<div style="margin-left:24px; font-size:10pt; margin-bottom:4px;"><b>TTL:</b> {ttl_val}</div>'
                    )
                # other SOA attributes
                shown = {
                    "domain",
                    "primary_ns",
                    "primary",
                    "origin",
                    "responsible_email",
                    "contact",
                    "mail_addr",
                    "serial",
                    "refresh",
                    "retry",
                    "expire",
                    "ttl",
                    "minimum",
                }
                for k, v in vars(soa).items() if hasattr(soa, "__dict__") else []:
                    if k in shown or v is None or v == "":
                        continue
                    self.results_textbox.append(
                        f'<div style="margin-left:24px; font-size:10pt; margin-bottom:4px;"><b>{k}:</b> {v}</div>'
                    )

            # If no records at all
            if not any(
                [
                    result.a_records,
                    result.aaaa_records,
                    result.mx_records,
                    result.ns_records,
                    result.txt_records,
                    result.cname_records,
                    result.soa_record,
                ]
            ):
                self.results_textbox.append(
                    f'<div style="font-size:10pt; margin-top:8px; color:#d32f2f;">No DNS records found or lookup failed.</div>'
                )

            # Error message if lookup failed
            if not result.success and getattr(result, "error_message", None):
                self.results_textbox.append(
                    f'<div style="font-size:10pt; margin-top:8px; color:#d32f2f;"><b>Lookup Error:</b> {result.error_message}</div>'
                )
        except Exception:
            # fall back to simple text output on failure
            try:
                self.results_textbox.append(f"Domain: {result.domain}")
            except Exception:
                pass

    # =============================================================================================
    # =============================================================================================
    # =============================================================================================
    # #=============================================================================================
    #
    # #=============================================================================================
    # #=============================================================================================
    # #=============================================================================================\

    def display_whatweb_results(self, result):
        """Display whatweb-specific results with HTML formatting"""
        # Use the parser's format_results method to generate HTML
        parser = self.results_manager.get_parser("whatweb")
        if parser and hasattr(parser, "format_results"):
            html_output = parser.format_results(result)
            self.results_textbox.insertHtml(html_output)
        else:
            # Fallback to basic display if parser doesn't have format_results
            self.results_textbox.append(f"🌍 URL: {result.get('target', 'N/A')}")
            if result.get("success"):
                self.results_textbox.append(f"✅ Scan completed successfully")

                # Display based on format type
                if result.get("format") == "verbose" and result.get("reports"):
                    for report in result.get("reports", []):
                        self.results_textbox.append(f"\n� {report.get('url', 'N/A')}")
                        if report.get("status_code"):
                            self.results_textbox.append(
                                f"  Status: [{report['status_code']}] {report.get('status', '')}"
                            )
                        if report.get("title"):
                            self.results_textbox.append(f"  Title: {report['title']}")
                        if report.get("ip"):
                            self.results_textbox.append(f"  IP: {report['ip']}")

                elif result.get("urls_scanned"):
                    for url_data in result.get("urls_scanned", []):
                        self.results_textbox.append(
                            f"\n📊 {url_data.get('url', 'N/A')}"
                        )
                        self.results_textbox.append(
                            f"  Status: [{url_data.get('status_code', 'N/A')}]"
                        )
            else:
                self.results_textbox.append(
                    f"❌ Scan failed: {result.get('error_message', 'Unknown error')}"
                )

    # =============================================================================================
    # =============================================================================================
    # =============================================================================================
    # #=============================================================================================
    #
    # #=============================================================================================
    # #=============================================================================================
    # #=============================================================================================\

    def display_ffuf_results(self, result):
        """Display ffuf-specific results"""
        # Base URL always shown

        # --- robust metadata extraction (handles nested metadata and varied key spellings) ---
        try:
            progress_info = (
                result.progress_info if isinstance(result.progress_info, dict) else {}
            )
            nested_meta = {}
            if isinstance(progress_info.get("metadata"), dict) and progress_info.get(
                "metadata"
            ):
                nested_meta = progress_info.get("metadata")
            elif isinstance(progress_info.get("meta"), dict) and progress_info.get(
                "meta"
            ):
                nested_meta = progress_info.get("meta")
        except Exception:
            progress_info = {}
            nested_meta = {}

        # Helper: produce likely variants for a key (space/underscore/dash)
        def _key_variants(k: str):
            k = k or ""
            low = k.lower()
            return {
                low,
                low.replace("_", " "),
                low.replace("-", " "),
                low.replace(" ", "_"),
                low.replace(" ", "-"),
                low.replace("_", "-"),
            }

        # quick ANSI stripper for raw_output scanning
        _ansi_re_local = re.compile(r"\x1B[@-_][0-?]*[ -/]*[@-~]|\x1b\][^\x07]*\x07")

        # Lookup function: search nested_meta first, then progress_info, then result attributes.
        def _lookup(*keys):
            candidates = []
            if nested_meta:
                candidates.append(nested_meta)
            if progress_info:
                candidates.append(progress_info)
            for cd in candidates:
                for key in keys:
                    if key in cd and cd.get(key) not in (None, ""):
                        return cd.get(key)
                    kvals = _key_variants(key)
                    for mk, mv in cd.items() if isinstance(cd, dict) else []:
                        if mv in (None, ""):
                            continue
                        if mk.lower() in kvals:
                            return mv
                    for var in kvals:
                        if var in cd and cd.get(var) not in (None, ""):
                            return cd.get(var)
            # fallback to attributes on the parsed result object
            for key in keys:
                try:
                    if hasattr(result, key) and getattr(result, key) not in (None, ""):
                        return getattr(result, key)
                except Exception:
                    pass
            return ""

        # Fallback: scan raw output (plain text) for "Key: Value" headers or JSON 'config' block
        def _scan_raw_for_key(*keys):
            # Try JSON config first
            try:
                j = json.loads(result.raw_output or "")
                if isinstance(j, dict):
                    cfg = (
                        j.get("config")
                        or j.get("Config")
                        or j.get("meta")
                        or j.get("metadata")
                    )
                    if isinstance(cfg, dict):
                        for k in keys:
                            for kk, vv in cfg.items():
                                if (
                                    kk
                                    and kk.lower() == k.lower()
                                    and vv not in (None, "")
                                ):
                                    return vv
                            # try variants
                            kvals = _key_variants(k)
                            for kk, vv in cfg.items():
                                if kk and kk.lower() in kvals and vv not in (None, ""):
                                    return vv
            except Exception:
                pass

            # Plain text header scan: look for "Key: Value" lines
            re_header_local = re.compile(
                r"^(?:\s*::\s*)?(?P<key>[^:]+?)\s*:\s*(?P<val>.+)$"
            )
            for ln in (result.raw_output or "").splitlines():
                try:
                    line = _ansi_re_local.sub("", ln).strip()
                except Exception:
                    line = ln.strip()
                if not line:
                    continue
                m = re_header_local.match(line)
                if not m:
                    continue
                k = re.sub(r"\s+", " ", m.group("key")).strip().lower()
                v = m.group("val").strip()
                for target in keys:
                    if k == target.lower() or k in _key_variants(target):
                        if v:
                            return v
            return ""

        # requested fields (preserve order requested)
        fields = [
            ("Method", ("method", "http_method", "http-method", "Method")),
            ("URL", ("url", "base_url", "target_url", "URL")),
            (
                "Wordlist",
                (
                    "wordlist_raw",
                    "wordlist",
                    "wordlist_path",
                    "wordlistfile",
                    "wordlistfile_path",
                    "Wordlist",
                ),
            ),
            (
                "Follow redirects",
                (
                    "follow_redirects",
                    "follow_redirect",
                    "follow-redirect",
                    "followredirects",
                    "follow redirects",
                ),
            ),
            ("Calibration", ("calibration", "calibrate", "Calibration")),
            ("Timeout", ("timeout", "maxtime", "max-time", "Timeout")),
            (
                "Threads",
                ("threads", "maxthreads", "max-threads", "threads_count", "Threads"),
            ),
            ("Matcher", ("matcher", "matchers", "m", "Matcher")),
        ]

        # Build and always render metadata lines (show "N/A" when missing)
        meta_lines = []
        import os

        for label, keys in fields:
            val = _lookup(*keys)
            if not val:
                # fallback to raw text/JSON scan
                val = _scan_raw_for_key(*keys)
            if val is None:
                val = ""
            # Convert lists/dicts to concise strings
            try:
                if isinstance(val, (list, dict)):
                    s = (
                        ", ".join(str(x) for x in val)
                        if isinstance(val, list)
                        else str(val)
                    )
                else:
                    s = str(val).strip()
            except Exception:
                s = str(val)
            # For wordlist, show just the filename portion if it looks like a path
            if label == "Wordlist" and s and "/" in s:
                try:
                    s = os.path.basename(s) or s
                except Exception:
                    pass
            display_val = s if s else "N/A"
            meta_lines.append(f":: {label.ljust(16)} {display_val}")

        # --- summary + entries (render entries in an HTML table like Nmap ports) ---
        if result.total_requests:
            self.results_textbox.append(f"📊 Total Requests: {result.total_requests}")

        if result.entries_found:
            parts = []
            parts.append(
                f'<div style="font-weight:bold; font-size:10pt; margin-top:6px;">Directories/Files Found ({len(result.entries_found)}):</div>'
            )
            parts.append(
                '<div style="display:block; width:100%; overflow:auto; box-sizing:border-box; padding:0; margin:0; box-shadow: 0 2px 8px rgba(0,0,0,0.15); border-radius: 4px;">'
            )
            parts.append(
                '<table width="100%" cellpadding="0" cellspacing="0" style="border-collapse:collapse; table-layout:fixed; width:100%;">'
            )
            parts.append(
                "<colgroup>"
                '<col style="width:48%;">'
                '<col style="width:12%;">'
                '<col style="width:12%;">'
                '<col style="width:8%;">'
                '<col style="width:10%;">'
                "</colgroup>"
            )
            parts.append(
                "<thead>"
                '<tr style="background:#f0f0f0;">'
                '<th style="text-align:left; padding:6px; border:1px solid #ddd; white-space:nowrap; font-size:10pt;">Path</th>'
                '<th style="text-align:left; padding:6px; border:1px solid #ddd; white-space:nowrap; font-size:10pt;">Status</th>'
                '<th style="text-align:left; padding:6px; border:1px solid #ddd; white-space:nowrap; font-size:10pt;">Size</th>'
                '<th style="text-align:left; padding:6px; border:1px solid #ddd; width:8%; font-size:10pt;">Words</th>'
                '<th style="text-align:left; padding:6px; border:1px solid #ddd; font-size:10pt;">Duration</th>'
                "</tr>"
                "</thead>"
                "<tbody>"
            )

            for entry in result.entries_found:
                path = getattr(entry, "path", "") or getattr(entry, "url", "") or ""
                status = getattr(entry, "status_code", "")
                size = getattr(entry, "size", "")
                words = getattr(entry, "words", "")
                lines_cnt = getattr(entry, "lines", "")
                dur_ms = getattr(entry, "duration_ms", None)
                dur_fmt = ""
                if dur_ms is not None:
                    try:
                        d = int(dur_ms)
                        dur_fmt = f"{d / 1000:.2f}s" if d >= 1000 else f"{d}ms"
                    except Exception:
                        dur_fmt = str(dur_ms)
                # prefer showing words if available, otherwise lines (kept small column)
                words_display = (
                    words
                    if words not in (None, 0, "")
                    else (lines_cnt if lines_cnt not in (None, 0, "") else "")
                )

                parts.append(
                    "<tr>"
                    f'<td style="padding:6px; border:1px solid #ddd; word-break:break-word; width:48%; font-size:10pt;">{path}</td>'
                    f'<td style="padding:6px; border:1px solid #ddd; width:12%; font-size:10pt;">{status}</td>'
                    f'<td style="padding:6px; border:1px solid #ddd; width:12%; font-size:10pt;">{size}</td>'
                    f'<td style="padding:6px; border:1px solid #ddd; width:8%; font-size:10pt;">{words_display}</td>'
                    f'<td style="padding:6px; border:1px solid #ddd; width:10%; font-size:10pt;">{dur_fmt}</td>'
                    "</tr>"
                )

            parts.append("</tbody></table>")
            parts.append("</div>")  # close wrapper
            self.results_textbox.append("".join(parts))
        else:
            self.results_textbox.append("\n No directories/files found.")

        self.results_textbox.append("")  # extra space after FFUF results

        # =============================================================================================

    # =============================================================================================
    # =============================================================================================
    # #=============================================================================================
    #
    # #=============================================================================================
    # #=============================================================================================
    # #=============================================================================================\

    def display_theharvester_results(self, result):
        """Display theHarvester-specific results in professional format"""
        # Display summary information with consistent styling
        self.results_textbox.append(
            f'<span style="font-size:10pt;"><b>Target Domain:</b> {result.target}</span>'
        )
        if hasattr(result, "source_engine") and result.source_engine:
            self.results_textbox.append(
                f'<span style="font-size:10pt;"><b>Source Engine:</b> {result.source_engine}</span>'
            )
        if hasattr(result, "total_results"):
            self.results_textbox.append(
                f'<span style="font-size:10pt;"><b>Total Results:</b> {result.total_results}</span>'
            )

        # Display email addresses found in table format
        if hasattr(result, "emails") and result.emails:
            count = len(result.emails)
            label = (
                f"📧 Email Addresses Found ({count} email{'s' if count != 1 else ''}):"
            )
            self.results_textbox.append(
                f'<span style="font-size:10pt;"><b>{label}</b></span>'
            )

            parts = []
            parts.append(
                '<div style="display:block; width:100%; overflow:auto; box-sizing:border-box; padding:0; margin:0; box-shadow: 0 2px 8px rgba(0,0,0,0.15); border-radius: 4px;">'
            )
            parts.append(
                '<table width="100%" cellpadding="0" cellspacing="0" style="border-collapse:collapse; table-layout:fixed; width:100%;">'
            )
            parts.append(
                '<colgroup><col style="width:70%;"><col style="width:30%;"></colgroup>'
            )
            parts.append(
                "<thead>"
                '<tr style="background:#f0f0f0;">'
                '<th style="text-align:left; padding:6px; border:1px solid #ddd; white-space:nowrap; font-size:10pt;">Email Address</th>'
                '<th style="text-align:left; padding:6px; border:1px solid #ddd; white-space:nowrap; font-size:10pt;">Source</th>'
                "</tr>"
                "</thead>"
                "<tbody>"
            )

            # Add email rows
            for email in result.emails:
                source_display = email.source if email.source else "N/A"
                parts.append(
                    "<tr>"
                    f'<td style="padding:6px; border:1px solid #ddd; word-break:break-word; width:70%; font-size:10pt;"><b>{email.email}</b></td>'
                    f'<td style="padding:6px; border:1px solid #ddd; word-break:break-word; width:30%; font-size:10pt;">{source_display}</td>'
                    "</tr>"
                )

            parts.append("</tbody></table></div>")
            self.results_textbox.append("".join(parts))

        # Display hosts/subdomains found in table format
        if hasattr(result, "hosts") and result.hosts:
            count = len(result.hosts)
            label = (
                f"🌐 Hosts/Subdomains Found ({count} host{'s' if count != 1 else ''}):"
            )
            self.results_textbox.append(
                f'<span style="font-size:10pt;"><b>{label}</b></span>'
            )

            parts = []
            parts.append(
                '<div style="display:block; width:100%; overflow:auto; box-sizing:border-box; padding:0; margin:0; box-shadow: 0 2px 8px rgba(0,0,0,0.15); border-radius: 4px;">'
            )
            parts.append(
                '<table width="100%" cellpadding="0" cellspacing="0" style="border-collapse:collapse; table-layout:fixed; width:100%;">'
            )
            parts.append(
                '<colgroup><col style="width:50%;"><col style="width:30%;"><col style="width:20%;"></colgroup>'
            )
            parts.append(
                "<thead>"
                '<tr style="background:#f0f0f0;">'
                '<th style="text-align:left; padding:6px; border:1px solid #ddd; white-space:nowrap; font-size:10pt;">Name</th>'
                '<th style="text-align:left; padding:6px; border:1px solid #ddd; white-space:nowrap; font-size:10pt;">IP Address</th>'
                '<th style="text-align:left; padding:6px; border:1px solid #ddd; white-space:nowrap; font-size:10pt;">Source</th>'
                "</tr>"
                "</thead>"
                "<tbody>"
            )

            for host in result.hosts:
                ip_display = host.ip if host.ip else "N/A"
                source_display = host.source if host.source else "N/A"
                parts.append(
                    "<tr>"
                    f'<td style="padding:6px; border:1px solid #ddd; word-break:break-word; width:50%; font-size:10pt;"><b>{host.hostname}</b></td>'
                    f'<td style="padding:6px; border:1px solid #ddd; word-break:break-word; width:30%; font-size:10pt;">{ip_display}</td>'
                    f'<td style="padding:6px; border:1px solid #ddd; word-break:break-word; width:20%; font-size:10pt;">{source_display}</td>'
                    "</tr>"
                )

            parts.append("</tbody></table></div>")
            self.results_textbox.append("".join(parts))

        # Display URLs found in table format
        if hasattr(result, "urls") and result.urls:
            count = len(result.urls)
            label = f"🔗 URLs Found ({count} URL{'s' if count != 1 else ''}):"
            self.results_textbox.append(
                f'<span style="font-size:10pt;"><b>{label}</b></span>'
            )

            parts = []
            parts.append(
                '<div style="display:block; width:100%; overflow:auto; box-sizing:border-box; padding:0; margin:0; box-shadow: 0 2px 8px rgba(0,0,0,0.15); border-radius: 4px;">'
            )
            parts.append(
                '<table width="100%" cellpadding="0" cellspacing="0" style="border-collapse:collapse; table-layout:fixed; width:100%;">'
            )
            parts.append(
                '<colgroup><col style="width:80%;"><col style="width:20%;"></colgroup>'
            )
            parts.append(
                "<thead>"
                '<tr style="background:#f0f0f0;">'
                '<th style="text-align:left; padding:6px; border:1px solid #ddd; white-space:nowrap; font-size:10pt;">URL</th>'
                '<th style="text-align:left; padding:6px; border:1px solid #ddd; white-space:nowrap; font-size:10pt;">Source</th>'
                "</tr>"
                "</thead>"
                "<tbody>"
            )

            for url in result.urls:
                source_display = url.source if url.source else "N/A"
                parts.append(
                    "<tr>"
                    f'<td style="padding:6px; border:1px solid #ddd; word-break:break-all; width:80%; font-size:10pt;"><b>{url.url}</b></td>'
                    f'<td style="padding:6px; border:1px solid #ddd; word-break:break-word; width:20%; font-size:10pt;">{source_display}</td>'
                    "</tr>"
                )

            parts.append("</tbody></table></div>")
            self.results_textbox.append("".join(parts))

        # Display people found in table format
        if hasattr(result, "people") and result.people:
            count = len(result.people)
            label = f"👥 People Found ({count} person/people):"
            self.results_textbox.append(
                f'<span style="font-size:10pt;"><b>{label}</b></span>'
            )

            parts = []
            parts.append(
                '<div style="display:block; width:100%; overflow:auto; box-sizing:border-box; padding:0; margin:0; box-shadow: 0 2px 8px rgba(0,0,0,0.15); border-radius: 4px;">'
            )
            parts.append(
                '<table width="100%" cellpadding="0" cellspacing="0" style="border-collapse:collapse; table-layout:fixed; width:100%;">'
            )
            parts.append(
                '<colgroup><col style="width:40%;"><col style="width:30%;"><col style="width:30%;"></colgroup>'
            )
            parts.append(
                "<thead>"
                '<tr style="background:#f0f0f0;">'
                '<th style="text-align:left; padding:6px; border:1px solid #ddd; white-space:nowrap; font-size:10pt;">Name</th>'
                '<th style="text-align:left; padding:6px; border:1px solid #ddd; white-space:nowrap; font-size:10pt;">Platform</th>'
                '<th style="text-align:left; padding:6px; border:1px solid #ddd; white-space:nowrap; font-size:10pt;">Source</th>'
                "</tr>"
                "</thead>"
                "<tbody>"
            )

            for person in result.people:
                platform_display = person.platform if person.platform else "N/A"
                source_display = person.source if person.source else "N/A"
                parts.append(
                    "<tr>"
                    f'<td style="padding:6px; border:1px solid #ddd; word-break:break-word; width:40%; font-size:10pt;"><b>{person.name}</b></td>'
                    f'<td style="padding:6px; border:1px solid #ddd; word-break:break-word; width:30%; font-size:10pt;">{platform_display}</td>'
                    f'<td style="padding:6px; border:1px solid #ddd; word-break:break-word; width:30%; font-size:10pt;">{source_display}</td>'
                    "</tr>"
                )

            parts.append("</tbody></table></div>")
            self.results_textbox.append("".join(parts))

    def display_dnsenum_results(self, result):
        """Display DNSEnum-specific results following NMAP display pattern"""
        # Display summary information with consistent styling
        self.results_textbox.append(
            f'<span style="font-size:10pt;"><b>Target Domain:</b> {result.target}</span>'
        )

        # Display host addresses in professional table format
        if hasattr(result, "host_addresses") and result.host_addresses:
            count = len(result.host_addresses)
            label = f"Host Addresses ({count} address{'es' if count != 1 else ''}):"

            parts = []
            parts.append(
                f'<div style="font-size:10pt; margin-bottom:6px;"><b>{label}</b></div>'
            )
            parts.append(
                '<div style="display:block; width:100%; overflow:auto; box-sizing:border-box; padding:0; margin:0;">'
            )
            parts.append(
                '<table width="100%" cellpadding="0" cellspacing="0" style="border-collapse:collapse; table-layout:fixed; width:100%;">'
            )
            parts.append(
                "<colgroup>"
                '<col style="width:35%;">'
                '<col style="width:15%;">'
                '<col style="width:15%;">'
                '<col style="width:35%;">'
                "</colgroup>"
            )
            parts.append(
                "<thead>"
                '<tr style="background:#f0f0f0;">'
                '<th style="text-align:left; padding:6px; border:1px solid #ddd; white-space:nowrap; font-size:10pt;">Host</th>'
                '<th style="text-align:left; padding:6px; border:1px solid #ddd; white-space:nowrap; font-size:10pt;">TTL</th>'
                '<th style="text-align:left; padding:6px; border:1px solid #ddd; white-space:nowrap; font-size:10pt;">Type</th>'
                '<th style="text-align:left; padding:6px; border:1px solid #ddd; white-space:nowrap; font-size:10pt;">IP Address</th>'
                "</tr>"
                "</thead>"
                "<tbody>"
            )

            # Add host address rows
            for host in result.host_addresses:
                ttl_display = (
                    str(host.ttl) if getattr(host, "ttl", None) is not None else "N/A"
                )
                host_name = getattr(host, "name", "") or ""
                host_type = getattr(host, "record_type", "") or ""
                host_ip = getattr(host, "value", "") or ""

                parts.append(
                    "<tr>"
                    f'<td style="padding:6px; border:1px solid #ddd; word-break:break-word; width:35%; font-size:10pt;"><b>{host_name}</b></td>'
                    f'<td style="padding:6px; border:1px solid #ddd; text-align:left; width:15%; font-size:10pt;">{ttl_display}</td>'
                    f'<td style="padding:6px; border:1px solid #ddd; text-align:left; width:15%; font-size:10pt;">{host_type}</td>'
                    f'<td style="padding:6px; border:1px solid #ddd; word-break:break-word; width:35%; font-size:10pt;"><b>{host_ip}</b></td>'
                    "</tr>"
                )

            parts.append("</tbody></table>")
            parts.append("</div>")
            self.results_textbox.append("".join(parts))

        # Display name servers in professional table format
        if hasattr(result, "name_servers") and result.name_servers:
            count = len(result.name_servers)
            label = f"Name Servers ({count} server{'s' if count != 1 else ''}):"
            self.results_textbox.append(
                f'<span style="font-size:10pt;"><b>{label}</b></span>'
            )

            parts = []
            parts.append(
                '<div style="display:block; width:100%; overflow:auto; box-sizing:border-box; padding:0; margin:0;">'
            )
            parts.append(
                '<table width="100%" cellpadding="0" cellspacing="0" style="border-collapse:collapse; table-layout:fixed; width:100%;">'
            )
            parts.append(
                "<colgroup>"
                '<col style="width:35%;">'
                '<col style="width:25%;">'
                '<col style="width:20%;">'
                '<col style="width:20%;">'
                "</colgroup>"
            )
            parts.append(
                "<thead>"
                '<tr style="background:#f0f0f0;">'
                '<th style="text-align:left; padding:6px; border:1px solid #ddd; white-space:nowrap; font-size:10pt;">Name Server</th>'
                '<th style="text-align:left; padding:6px; border:1px solid #ddd; white-space:nowrap; font-size:10pt;">IP Address</th>'
                '<th style="text-align:left; padding:6px; border:1px solid #ddd; white-space:nowrap; font-size:10pt;">Zone Transfer</th>'
                '<th style="text-align:left; padding:6px; border:1px solid #ddd; white-space:nowrap; font-size:10pt;">BIND Version</th>'
                "</tr>"
                "</thead>"
                "<tbody>"
            )

            for ns in result.name_servers:
                zone_status = (
                    "❌ Blocked"
                    if hasattr(ns, "zone_transfer_possible")
                    and ns.zone_transfer_possible is False
                    else "⚠️ Unknown"
                )
                bind_version = ns.bind_version if ns.bind_version else "N/A"

                parts.append(
                    "<tr>"
                    f'<td style="padding:6px; border:1px solid #ddd; word-break:break-word; width:35%; font-size:10pt;"><b>{ns.nameserver}</b></td>'
                    f'<td style="padding:6px; border:1px solid #ddd; word-break:break-word; width:40%; font-size:10pt;">{ns.ip_address}</td>'
                    f'<td style="padding:6px; border:1px solid #ddd; word-break:break-word; width:20%; font-size:10pt;">{zone_status}</td>'
                    f'<td style="padding:6px; border:1px solid #ddd; word-break:break-word; width:20%; font-size:10pt;">{bind_version}</td>'
                    "</tr>"
                )

            parts.append("</tbody></table>")
            parts.append("</div>")
            self.results_textbox.append("".join(parts))

        # Display mail servers if found
        if hasattr(result, "mail_servers") and result.mail_servers:
            count = len(result.mail_servers)

            label = f"Mail Servers ({count} server{'s' if count != 1 else ''}):"
            self.results_textbox.append(
                f'<span style="font-size:10pt;"><b>{label}</b></span>'
            )

            parts = []
            parts.append(
                '<div style="display:block; width:100%; overflow:auto; box-sizing:border-box; padding:0; margin:0;">'
            )
            parts.append(
                '<table width="100%" cellpadding="0" cellspacing="0" style="border-collapse:collapse; table-layout:fixed; width:100%;">'
            )
            parts.append(
                "<colgroup>"
                '<col style="width:25%;">'
                '<col style="width:40%;">'
                '<col style="width:15%;">'
                '<col style="width:20%;">'
                "</colgroup>"
            )
            parts.append(
                "<thead>"
                '<tr style="background:#f0f0f0;">'
                '<th style="text-align:left; padding:6px; border:1px solid #ddd; white-space:nowrap; font-size:10pt;">Domain</th>'
                '<th style="text-align:left; padding:6px; border:1px solid #ddd; white-space:nowrap; font-size:10pt;">Mail Server</th>'
                '<th style="text-align:left; padding:6px; border:1px solid #ddd; white-space:nowrap; font-size:10pt;">Priority</th>'
                '<th style="text-align:left; padding:6px; border:1px solid #ddd; white-space:nowrap; font-size:10pt;">TTL</th>'
                "</tr>"
                "</thead>"
                "<tbody>"
            )

            for mx in result.mail_servers:
                ttl_display = str(mx.ttl) if mx.ttl is not None else "N/A"

                priority_display = (
                    str(mx.priority) if mx.priority is not None else "N/A"
                )
                parts.append(
                    "<tr>"
                    f'<td style="padding:6px; border:1px solid #ddd; word-break:break-word; width:25%; font-size:10pt;">{mx.name}</td>'
                    f'<td style="padding:6px; border:1px solid #ddd; word-break:break-word; width:40%; font-size:10pt;"><b>{mx.value}</b></td>'
                    f'<td style="padding:6px; border:1px solid #ddd; word-break:break-word; width:15%; font-size:10pt;">{priority_display}</td>'
                    f'<td style="padding:6px; border:1px solid #ddd; word-break:break-word; width:20%; font-size:10pt;">{ttl_display}</td>'
                    "</tr>"
                )

            parts.append("</tbody></table>")
            parts.append("</div>")
            self.results_textbox.append("".join(parts))

        # Display subdomains found
        if hasattr(result, "subdomains") and result.subdomains:
            count = len(result.subdomains)
            label = f"Subdomains Found ({count} subdomain{'s' if count != 1 else ''}):"
            self.results_textbox.append(
                f'<span style="font-size:10pt;"><b>{label}</b></span>'
            )

            parts = []
            parts.append(
                '<div style="display:block; width:100%; overflow:auto; box-sizing:border-box; padding:0; margin:0;">'
            )
            parts.append(
                '<table width="100%" cellpadding="0" cellspacing="0" style="border-collapse:collapse; table-layout:fixed; width:100%;">'
            )
            parts.append(
                "<colgroup>"
                '<col style="width:30%;">'
                '<col style="width:40%;">'
                '<col style="width:15%;">'
                '<col style="width:15%;">'
                "</colgroup>"
            )
            parts.append(
                "<thead>"
                '<tr style="background:#f0f0f0;">'
                '<th style="text-align:left; padding:6px; border:1px solid #ddd; white-space:nowrap; font-size:10pt;">Subdomain</th>'
                '<th style="text-align:left; padding:6px; border:1px solid #ddd; white-space:nowrap; font-size:10pt;">IP Address(es)</th>'
                '<th style="text-align:left; padding:6px; border:1px solid #ddd; white-space:nowrap; font-size:10pt;">Type</th>'
                '<th style="text-align:left; padding:6px; border:1px solid #ddd; white-space:nowrap; font-size:10pt;">Source</th>'
                "</tr>"
                "</thead>"
                "<tbody>"
            )

            for sub in result.subdomains:
                ip_list = ", ".join(sub.ip_addresses) if sub.ip_addresses else "N/A"
                source_display = sub.source if sub.source else "Unknown"
                parts.append(
                    "<tr>"
                    f'<td style="padding:6px; border:1px solid #ddd; word-break:break-word; width:30%; font-size:10pt;"><b>{sub.subdomain}</b></td>'
                    f'<td style="padding:6px; border:1px solid #ddd; word-break:break-word; width:40%; font-size:10pt;">{ip_list}</td>'
                    f'<td style="padding:6px; border:1px solid #ddd; word-break:break-word; width:15%; font-size:10pt;">{sub.record_type}</td>'
                    f'<td style="padding:6px; border:1px solid #ddd; word-break:break-word; width:15%; font-size:10pt;">{source_display}</td>'
                    "</tr>"
                )

            parts.append("</tbody></table></div>")
            self.results_textbox.append("".join(parts))

        # Display network information
        if hasattr(result, "network_info") and result.network_info:
            count = len(result.network_info)
            label = f"Network Information ({count} range{'s' if count != 1 else ''}):"
            self.results_textbox.append(
                f'<span style="font-size:10pt;"><b>{label}</b></span>'
            )

            parts = []
            parts.append(
                '<div style="display:block; width:100%; overflow:auto; box-sizing:border-box; padding:0; margin:0;">'
            )
            parts.append(
                '<table width="100%" cellpadding="0" cellspacing="0" style="border-collapse:collapse; table-layout:fixed; width:100%;">'
            )
            parts.append(
                "<colgroup>"
                '<col style="width:40%;">'
                '<col style="width:30%;">'
                '<col style="width:30%;">'
                "</colgroup>"
            )
            parts.append(
                "<thead>"
                '<tr style="background:#f0f0f0;">'
                '<th style="text-align:left; padding:6px; border:1px solid #ddd; white-space:nowrap; font-size:10pt;">Network Range</th>'
                '<th style="text-align:left; padding:6px; border:1px solid #ddd; white-space:nowrap; font-size:10pt;">Type</th>'
                '<th style="text-align:left; padding:6px; border:1px solid #ddd; white-space:nowrap; font-size:10pt;">Organization</th>'
                "</tr>"
                "</thead>"
                "<tbody>"
            )

            for net in result.network_info:
                netblock_type = (
                    net.nettype
                    if (hasattr(net, "netblock") and net.netblock)
                    else "Network"
                )
                organization = (
                    net.organization
                    if (hasattr(net, "organization") and net.organization)
                    else "N/A"
                )
                parts.append(
                    "<tr>"
                    f'<td style="padding:6px; border:1px solid #ddd; word-break:break-word; width:40%; font-size:10pt;"><b>{net.ip_range}</b></td>'
                    f'<td style="padding:6px; border:1px solid #ddd; text-align:left; width:30%; font-size:10pt;">{netblock_type}</td>'
                    f'<td style="padding:6px; border:1px solid #ddd; text-align:left; width:30%; font-size:10pt;">{organization}</td>'
                    "</tr>"
                )

            parts.append("</tbody></table>")
            parts.append("</div>")
            self.results_textbox.append("".join(parts))

        # Display contact information
        if hasattr(result, "contacts") and result.contacts:
            count = len(result.contacts)
            label = f"Contacts ({count} contact{'s' if count != 1 else ''}):"
            self.results_textbox.append(
                f'<span style="font-size:10pt;"><b>{label}</b></span>'
            )

            for contact in result.contacts:
                self.results_textbox.append(
                    f'<div style="margin-left:12px; font-size:10pt;">• {contact}</div>'
                )

        # Display additional DNS records if found
        if hasattr(result, "dns_records") and result.dns_records:
            count = len(result.dns_records)
            label = (
                f"Additional DNS Records ({count} record{'s' if count != 1 else ''}):"
            )
            self.results_textbox.append(
                f'<span style="font-size:10pt;"><b>{label}</b></span>'
            )

            for record in result.dns_records:
                value_display = (
                    record.value[:80] + "..."
                    if len(record.value) > 80
                    else record.value
                )
                ttl_display = f" [TTL: {record.ttl}]" if record.ttl is not None else ""
                self.results_textbox.append(
                    f'<div style="margin-left:12px; font-size:10pt;"><b>{record.record_type}:</b> {record.name} → {value_display}{ttl_display}</div>'
                )

        # Display reverse DNS results with indentation
        if hasattr(result, "reverse_dns") and result.reverse_dns:
            self.results_textbox.append(
                f'<span style="font-size:10pt;"><b>Reverse DNS ({len(result.reverse_dns)}):</b></span>'
            )
            for reverse in result.reverse_dns:
                self.results_textbox.append(
                    f'<div style="margin-left:12px; font-size:10pt;">• {reverse}</div>'
                )

        # Display zone transfer summary with indentation
        if hasattr(result, "zone_transfers") and result.zone_transfers:
            transfer_attempts = len(
                [zt for zt in result.zone_transfers if "Trying Zone Transfer" in zt]
            )
            self.results_textbox.append(
                f'<span style="font-size:10pt;"><b>Zone Transfer Summary:</b></span>'
            )
            self.results_textbox.append(
                f'<div style="margin-left:12px; font-size:10pt;">Attempted transfers on {transfer_attempts} name servers</div>'
            )
            self.results_textbox.append(
                f'<div style="margin-left:12px; font-size:10pt;">All zone transfers were blocked (expected behavior)</div>'
            )

        # Display scan statistics following NMAP pattern
        if hasattr(result, "scan_stats") and result.scan_stats:
            self.results_textbox.append(
                f'<span style="font-size:10pt;"><b>Scan Statistics:</b></span>'
            )

            if result.scan_stats.get("dnsenum_version"):
                self.results_textbox.append(
                    f'<div style="margin-left:12px; font-size:10pt;"><b>DNSEnum Version:</b> {result.scan_stats["dnsenum_version"]}</div>'
                )
            if result.scan_stats.get("wordlist_used"):
                wordlist = result.scan_stats["wordlist_used"].split("/")[
                    -1
                ]  # Show just filename
                self.results_textbox.append(
                    f'<div style="margin-left:12px; font-size:10pt;"><b>Wordlist Used:</b> {wordlist}</div>'
                )
            if result.scan_stats.get("reverse_lookup_count"):
                self.results_textbox.append(
                    f'<div style="margin-left:12px; font-size:10pt;"><b>Reverse Lookups:</b> {result.scan_stats["reverse_lookup_count"]}</div>'
                )

            # Add summary statistics
            if hasattr(result, "total_subdomains"):
                self.results_textbox.append(
                    f'<div style="margin-left:12px; font-size:10pt;"><b>Total Subdomains:</b> {result.total_subdomains}</div>'
                )
            self.results_textbox.append(
                f'<div style="margin-left:12px; font-size:10pt;"><b>Total Name Servers:</b> {len(result.name_servers) if result.name_servers else 0}</div>'
            )
            self.results_textbox.append(
                f'<div style="margin-left:12px; font-size:10pt;"><b>Total Host IPs:</b> {len(result.host_addresses) if result.host_addresses else 0}</div>'
            )
            self.results_textbox.append(
                f'<div style="margin-left:12px; font-size:10pt;"><b>Network Ranges:</b> {len(result.network_info) if result.network_info else 0}</div>'
            )

    def display_whois_results(self, result):
        """Display Whois-specific results following NMAP display pattern"""
        # Display summary information with consistent styling
        self.results_textbox.append(
            f'<span style="font-size:10pt;"><b>Target:</b> {result.target}</span>'
        )
        self.results_textbox.append(
            f'<span style="font-size:10pt;"><b>Query Type:</b> {result.query_type.upper()}</span>'
        )

        if result.query_type == "domain" and result.domain_info:
            domain = result.domain_info

            # Display basic domain information
            if domain.domain_name:
                self.results_textbox.append(
                    f'<span style="font-size:10pt;"><b>Domain Information:</b></span>'
                )

                parts = []
                parts.append(
                    '<div style="display:block; width:100%; overflow:auto; box-sizing:border-box; padding:0; margin:0;">'
                )
                parts.append(
                    '<table width="100%" cellpadding="0" cellspacing="0" style="border-collapse:collapse; table-layout:fixed; width:100%;">'
                )
                parts.append(
                    "<colgroup>"
                    '<col style="width:25%;">'
                    '<col style="width:75%;">'
                    "</colgroup>"
                )
                parts.append(
                    "<thead>"
                    '<tr style="background:#f0f0f0;">'
                    '<th style="text-align:left; padding:6px; border:1px solid #ddd; white-space:nowrap; font-size:10pt;">Field</th>'
                    '<th style="text-align:left; padding:6px; border:1px solid #ddd; white-space:nowrap; font-size:10pt;">Value</th>'
                    "</tr>"
                    "</thead>"
                    "<tbody>"
                )

                # Add domain information rows
                if domain.domain_name:
                    parts.append(
                        f'<tr><td style="padding:6px; border:1px solid #ddd; font-size:10pt;"><b>Domain Name</b></td>'
                        f'<td style="padding:6px; border:1px solid #ddd; font-size:10pt;">{domain.domain_name}</td></tr>'
                    )

                if domain.registrar and domain.registrar.strip():
                    parts.append(
                        f'<tr><td style="padding:6px; border:1px solid #ddd; font-size:10pt;"><b>Registrar</b></td>'
                        f'<td style="padding:6px; border:1px solid #ddd; font-size:10pt;">{domain.registrar}</td></tr>'
                    )
                if domain.creation_date and domain.creation_date.strip():
                    parts.append(
                        f'<tr><td style="padding:6px; border:1px solid #ddd; font-size:10pt;"><b>Creation Date</b></td>'
                        f'<td style="padding:6px; border:1px solid #ddd; font-size:10pt;">{domain.creation_date}</td></tr>'
                    )
                if domain.updated_date and domain.updated_date.strip():
                    parts.append(
                        f'<tr><td style="padding:6px; border:1px solid #ddd; font-size:10pt;"><b>Updated Date</b></td>'
                        f'<td style="padding:6px; border:1px solid #ddd; font-size:10pt;">{domain.updated_date}</td></tr>'
                    )
                if domain.expiry_date and domain.expiry_date.strip():
                    parts.append(
                        f'<tr><td style="padding:6px; border:1px solid #ddd; font-size:10pt;"><b>Expiry Date</b></td>'
                        f'<td style="padding:6px; border:1px solid #ddd; font-size:10pt;">{domain.expiry_date}</td></tr>'
                    )
                if domain.dnssec and domain.dnssec.strip():
                    parts.append(
                        f'<tr><td style="padding:6px; border:1px solid #ddd; font-size:10pt;"><b>DNSSEC</b></td>'
                        f'<td style="padding:6px; border:1px solid #ddd; font-size:10pt;">{domain.dnssec}</td></tr>'
                    )

                # Domain status list
                if domain.domain_status and len(domain.domain_status) > 0:
                    status_list = ", ".join(domain.domain_status)
                    parts.append(
                        f'<tr><td style="padding:6px; border:1px solid #ddd; font-size:10pt;"><b>Domain Status</b></td>'
                        f'<td style="padding:6px; border:1px solid #ddd; font-size:10pt;">{status_list}</td></tr>'
                    )

                # Name servers list
                if domain.name_servers and len(domain.name_servers) > 0:
                    servers_list = ", ".join(domain.name_servers)
                    parts.append(
                        f'<tr><td style="padding:6px; border:1px solid #ddd; font-size:10pt;"><b>Name Servers</b></td>'
                        f'<td style="padding:6px; border:1px solid #ddd; font-size:10pt;">{servers_list}</td></tr>'
                    )

                parts.append("</tbody></table>")
                parts.append("</div>")
                self.results_textbox.append("".join(parts))

            # Display domain status
            if domain.domain_status:
                count = len(domain.domain_status)
                label = f"Domain Status ({count} status{'es' if count != 1 else ''}):"
                self.results_textbox.append(
                    f'<span style="font-size:10pt;"><b>{label}</b></span>'
                )

                for status in domain.domain_status:
                    self.results_textbox.append(
                        f'<div style="margin-left:12px; font-size:10pt;">• {status}</div>'
                    )

            # Display name servers
            if domain.name_servers:
                count = len(domain.name_servers)
                label = f"Name Servers ({count} server{'s' if count != 1 else ''}):"
                self.results_textbox.append(
                    f'<span style="font-size:10pt;"><b>{label}</b></span>'
                )

                for ns in domain.name_servers:
                    self.results_textbox.append(
                        f'<div style="margin-left:12px; font-size:10pt;">• {ns}</div>'
                    )

            # Display registrant contact information if available
            if domain.registrant_contact and (
                domain.registrant_contact.name
                or domain.registrant_contact.organization
                or domain.registrant_contact.email
            ):
                self.results_textbox.append(
                    f'<span style="font-size:10pt;"><b>Registrant Contact:</b></span>'
                )
                contact = domain.registrant_contact
                if contact.name:
                    self.results_textbox.append(
                        f'<div style="margin-left:12px; font-size:10pt;"><b>Name:</b> {contact.name}</div>'
                    )
                if contact.organization:
                    self.results_textbox.append(
                        f'<div style="margin-left:12px; font-size:10pt;"><b>Organization:</b> {contact.organization}</div>'
                    )
                if contact.email:
                    self.results_textbox.append(
                        f'<div style="margin-left:12px; font-size:10pt;"><b>Email:</b> {contact.email}</div>'
                    )
                if contact.address:
                    self.results_textbox.append(
                        f'<div style="margin-left:12px; font-size:10pt;"><b>Address:</b> {contact.address}</div>'
                    )

            # Display admin contact if available
            if domain.admin_contact and (
                domain.admin_contact.name or domain.admin_contact.email
            ):
                self.results_textbox.append(
                    f'<span style="font-size:10pt;"><b>Admin Contact:</b></span>'
                )
                contact = domain.admin_contact
                if contact.name:
                    self.results_textbox.append(
                        f'<div style="margin-left:12px; font-size:10pt;"><b>Name:</b> {contact.name}</div>'
                    )
                if contact.email:
                    self.results_textbox.append(
                        f'<div style="margin-left:12px; font-size:10pt;"><b>Email:</b> {contact.email}</div>'
                    )

            # Display technical contact if available
            if domain.tech_contact and (
                domain.tech_contact.name or domain.tech_contact.email
            ):
                self.results_textbox.append(
                    f'<span style="font-size:10pt;"><b>Technical Contact:</b></span>'
                )
                contact = domain.tech_contact
                if contact.name:
                    self.results_textbox.append(
                        f'<div style="margin-left:12px; font-size:10pt;"><b>Name:</b> {contact.name}</div>'
                    )
                if contact.email:
                    self.results_textbox.append(
                        f'<div style="margin-left:12px; font-size:10pt;"><b>Email:</b> {contact.email}</div>'
                    )

            # Display additional info if available (e.g., AS number for RPSL format)
            if hasattr(domain, "additional_info") and domain.additional_info:
                self.results_textbox.append(
                    f'<span style="font-size:10pt;"><b>Additional Information:</b></span>'
                )
                for key, value in domain.additional_info.items():
                    display_key = key.replace("_", " ").title()
                    self.results_textbox.append(
                        f'<div style="margin-left:12px; font-size:10pt;"><b>{display_key}:</b> {value}</div>'
                    )

        elif result.query_type == "ip" and result.network_info:
            # Iterate through all networks in the list
            for network in result.network_info:
                # Display network information
                self.results_textbox.append(
                    f'<span style="font-size:10pt;"><b>Network Information:</b></span>'
                )

                parts = []
                parts.append(
                    '<div style="display:block; width:100%; overflow:auto; box-sizing:border-box; padding:0; margin:0;">'
                )
                parts.append(
                    '<table width="100%" cellpadding="0" cellspacing="0" style="border-collapse:collapse; table-layout:fixed; width:100%;">'
                )
                parts.append(
                    "<colgroup>"
                    '<col style="width:25%;">'
                    '<col style="width:75%;">'
                    "</colgroup>"
                )
                parts.append(
                    "<thead>"
                    '<tr style="background:#f0f0f0;">'
                    '<th style="text-align:left; padding:6px; border:1px solid #ddd; white-space:nowrap; font-size:10pt;">Field</th>'
                    '<th style="text-align:left; padding:6px; border:1px solid #ddd; white-space:nowrap; font-size:10pt;">Value</th>'
                    "</tr>"
                    "</thead>"
                    "<tbody>"
                )
                if hasattr(network, "net_range") and network.net_range:
                    parts.append(
                        f'<tr><td style="padding:6px; border:1px solid #ddd; font-size:10pt;"><b>IP Range</b></td>'
                        f'<td style="padding:6px; border:1px solid #ddd; font-size:10pt;">{network.net_range}</td></tr>'
                    )
                if hasattr(network, "cidr") and network.cidr:
                    parts.append(
                        f'<tr><td style="padding:6px; border:1px solid #ddd; font-size:10pt;"><b>CIDR</b></td>'
                        f'<td style="padding:6px; border:1px solid #ddd; font-size:10pt;">{network.cidr}</td></tr>'
                    )
                if hasattr(network, "net_name") and network.net_name:
                    parts.append(
                        f'<tr><td style="padding:6px; border:1px solid #ddd; font-size:10pt;"><b>Network Name</b></td>'
                        f'<td style="padding:6px; border:1px solid #ddd; font-size:10pt;">{network.net_name}</td></tr>'
                    )
                if hasattr(network, "organization") and network.organization:
                    parts.append(
                        f'<tr><td style="padding:6px; border:1px solid #ddd; font-size:10pt;"><b>Organization</b></td>'
                        f'<td style="padding:6px; border:1px solid #ddd; font-size:10pt;">{network.organization}</td></tr>'
                    )
                if hasattr(network, "net_type") and network.net_type:
                    parts.append(
                        f'<tr><td style="padding:6px; border:1px solid #ddd; font-size:10pt;"><b>Type</b></td>'
                        f'<td style="padding:6px; border:1px solid #ddd; font-size:10pt;">{network.net_type}</td></tr>'
                    )
                if hasattr(network, "origin_as") and network.origin_as:
                    parts.append(
                        f'<tr><td style="padding:6px; border:1px solid #ddd; font-size:10pt;"><b>Origin AS</b></td>'
                        f'<td style="padding:6px; border:1px solid #ddd; font-size:10pt;">{network.origin_as}</td></tr>'
                    )
                if hasattr(network, "reg_date") and network.reg_date:
                    parts.append(
                        f'<tr><td style="padding:6px; border:1px solid #ddd; font-size:10pt;"><b>Registered</b></td>'
                        f'<td style="padding:6px; border:1px solid #ddd; font-size:10pt;">{network.reg_date}</td></tr>'
                    )
                if hasattr(network, "updated") and network.updated:
                    parts.append(
                        f'<tr><td style="padding:6px; border:1px solid #ddd; font-size:10pt;"><b>Updated</b></td>'
                        f'<td style="padding:6px; border:1px solid #ddd; font-size:10pt;">{network.updated}</td></tr>'
                    )
                    parts.append("</tbody></table>")
                    parts.append("</div>")
                    self.results_textbox.append("".join(parts))

                # Display organization address if available
                if (
                    (hasattr(network, "address") and network.address)
                    or (hasattr(network, "city") and network.city)
                    or (hasattr(network, "state") and network.state)
                    or (hasattr(network, "country") and network.country)
                ):
                    self.results_textbox.append(
                        f'<span style="font-size:10pt;"><b>Organization Address:</b></span>'
                    )
                    address_parts = []
                    if hasattr(network, "address") and network.address:
                        address_parts.append(network.address)
                    if hasattr(network, "city") and network.city:
                        address_parts.append(network.city)
                    if hasattr(network, "state") and network.state:
                        address_parts.append(network.state)
                    if hasattr(network, "postal_code") and network.postal_code:
                        address_parts.append(network.postal_code)
                    if hasattr(network, "country") and network.country:
                        address_parts.append(network.country)

                    full_address = ", ".join(address_parts)
                    self.results_textbox.append(
                        f'<div style="margin-left:12px; font-size:10pt;">{full_address}</div>'
                    )

                # Display contact information
                if hasattr(network, "abuse_contacts") and network.abuse_contacts:
                    self.results_textbox.append(
                        f'<span style="font-size:10pt;"><b>Abuse Contacts:</b></span>'
                    )

                for contact in network.abuse_contacts:
                    self.results_textbox.append(
                        f'<div style="margin-left:12px; font-size:10pt;">• {contact}</div>'
                    )

                if hasattr(network, "tech_contacts") and network.tech_contacts:
                    self.results_textbox.append(
                        f'<span style="font-size:10pt;"><b>Technical Contacts:</b></span>'
                    )
                    for contact in network.tech_contacts:
                        self.results_textbox.append(
                            f'<div style="margin-left:12px; font-size:10pt;">• {contact}</div>'
                        )
        else:
            # Fallback display if parsing failed
            print(f"DEBUG: No proper domain_info or network_info, showing raw output")
            self.results_textbox.append(
                f'<span style="font-size:10pt;"><b>Raw Whois Output:</b></span>'
            )
            self.results_textbox.append(
                f'<pre style="font-size:9pt;">{result.raw_output[:1000]}...</pre>'
            )

    def update_diagnostics(self, result):
        """Update diagnostics with result information (rich HTML formatting)."""
        try:
            import html as _html

            parts = []
            # Header lines (10pt, spaced)
            parts.append(
                f'<div style="font-size:10pt; margin-bottom:6px;"><b>[{_html.escape(result.timestamp)}] {_html.escape(result.tool_name.upper())}</b></div>'
            )
            if getattr(result, "error_message", None):
                parts.append(
                    f'<div style="font-size:10pt; margin-bottom:6px; color:#d32f2f;">Error: {_html.escape(str(result.error_message))}</div>'
                )

            # Diagnostics list (severity bold + color, message, optional context)
            diags = getattr(result, "diagnostics", None) or []

            if not diags:
                # show a default "no diagnostics" info entry using same formatting
                sev = "Info"
                color = "#90CAF9"  # light blue
                sev_html = f'<span style="font-weight:bold; color:{color}; margin-right:6px;">[{_html.escape(sev.upper())}]</span>'
                msg_html = f'<span style="font-size:10pt; color:#222;">No diagnostics found</span>'
                parts.append(
                    f'<div style="font-size:10pt; margin-bottom:8px;">{sev_html}{msg_html}</div>'
                )
            else:
                for d in diags:
                    sev_raw = str(d.get("severity", "Info") or "Info")
                    sev = sev_raw.strip()
                    msg = str(d.get("message", "") or "")
                    ctx = d.get("context") or d.get("context", "") or ""

                    # normalize severity -> color
                    s = sev.lower()
                    if s == "info":
                        color = "#90CAF9"  # light blue
                    elif s == "low":
                        color = "#FBC02D"  # yellow/amber
                    elif s == "medium":
                        color = "#FF9800"  # orange
                    elif s == "high":
                        color = "#E53935"  # red
                    else:
                        color = "#90CAF9"  # default to info blue

                    sev_html = f'<span style="font-weight:bold; color:{color}; margin-right:6px;">[{_html.escape(sev.upper())}]</span>'
                    msg_html = f'<span style="font-size:10pt; color:#222;">{_html.escape(msg)}</span>'
                    ctx_html = (
                        f' <span style="font-size:10pt; color:#666;">({_html.escape(str(ctx))})</span>'
                        if ctx
                        else ""
                    )
                    parts.append(
                        f'<div style="font-size:10pt; margin-bottom:8px;">{sev_html}{msg_html}{ctx_html}</div>'
                    )

            # Separator with spacing
            parts.append(
                '<div style="font-size:10pt; color:#888; margin-top:6px; margin-bottom:12px;">'
                + ("—" * 30)
                + "</div>"
            )

            # Insert as HTML block (preserves styling and spacing)
            html_block = "".join(parts)
            try:
                # insertHtml appends without converting newlines; use it for reliable HTML rendering
                self.diagnostics_textbox.insertHtml(html_block)
                # move to new paragraph so future inserts are clean
                self.diagnostics_textbox.insertPlainText("\n")
            except Exception:
                # fallback: plain append with minimal formatting
                for line in _html.escape("\n".join(parts)).splitlines():
                    self.diagnostics_textbox.append(line)
        except Exception:
            # don't let diagnostics errors crash the UI
            pass

    def handle_export_results(self):
        """Export parsed results to file"""
        try:
            results = self.results_manager.get_all_results()
            if not results:
                # Use centralized popup helper
                show_info_popup(
                    self, "No results to export. Run a scan first.", "Export Results"
                )
                return

            # Offer PDF as an export target in addition to JSON/CSV
            filename, _ = QFileDialog.getSaveFileName(
                self,
                "Export Results",
                f"corvoscan_results_{results[0].target}_{len(results)}_scans.json",
                "PDF Files (*.pdf);;JSON Files (*.json);;CSV Files (*.csv);;All Files (*)",
            )

            if filename:
                lf = filename.lower()
                if lf.endswith(".csv"):
                    exported_file = self.results_manager.export_to_csv(filename)
                    show_info_popup(
                        self,
                        f"Results exported to:\n{exported_file}",
                        "Export Complete",
                    )
                elif lf.endswith(".json"):
                    exported_file = self.results_manager.export_to_json(filename)
                    show_info_popup(
                        self,
                        f"Results exported to:\n{exported_file}",
                        "Export Complete",
                    )
                elif lf.endswith(".pdf"):
                    # Build minimal HTML representation of parsed results and print to PDF
                    try:
                        import html as _html

                        html_parts = [
                            '<html><head><meta charset="utf-8"><style>body{font-family:Arial,Helvetica,sans-serif;} pre{white-space:pre-wrap; font-family:monospace; background:#f9f9f9; padding:8px; border-radius:6px;} h2{margin-bottom:4px;} hr{border:none;border-top:1px solid #ddd;margin:12px 0;} </style></head><body>'
                        ]
                        for r in results:
                            tool = getattr(r, "tool_name", "N/A")
                            target = getattr(r, "target", "")
                            timestamp = getattr(r, "timestamp", "")
                            raw = getattr(r, "raw_output", "") or ""
                            html_parts.append(
                                f"<h2>{_html.escape(str(tool).upper())} — {_html.escape(str(target))}</h2>"
                            )
                            html_parts.append(
                                f"<div><b>Timestamp:</b> {_html.escape(str(timestamp))}</div>"
                            )
                            html_parts.append(f"<pre>{_html.escape(raw)}</pre>")
                            html_parts.append("<hr>")
                        html_parts.append("</body></html>")

                        doc = QTextDocument()
                        doc.setHtml(html_parts)
                        printer = QPrinter()
                        printer.setOutputFormat(QPrinter.OutputFormat.PdfFormat)
                        printer.setOutputFileName(filename)
                        doc.print(printer)
                        show_info_popup(
                            self, f"Results exported to:\n{filename}", "Export Complete"
                        )
                    except Exception as e:
                        show_critical_popup(
                            self, f"Failed to export PDF:\n{str(e)}", "Export Error"
                        )
                else:
                    show_info_popup(
                        self,
                        "Unknown export type selected. Use .json, .csv or .pdf",
                        "Export Results",
                    )
        except Exception as e:
            show_critical_popup(
                self, f"Failed to export results:\n{str(e)}", "Export Error"
            )

    def handle_export_diagnostics(self):
        """Export diagnostics to file (supports .txt and .pdf)"""
        try:
            diagnostics_text = self.diagnostics_textbox.toPlainText()
            if not diagnostics_text.strip():
                show_info_popup(self, "No diagnostics to export.", "Export Diagnostics")
                return

            # Offer PDF as an export option in addition to plain text
            filename, _ = QFileDialog.getSaveFileName(
                self,
                "Export Diagnostics",
                "corvoscan_diagnostics.txt",
                "PDF Files (*.pdf);;Text Files (*.txt);;All Files (*)",
            )
            if not filename:
                return
            lf = filename.lower()
            if lf.endswith(".pdf"):
                try:
                    import html as _html

                    # Simple HTML: preserve newlines inside <pre> for monospace display
                    safe = _html.escape(diagnostics_text)
                    html_doc = f"<html><head><meta charset='utf-8'><style>body{{font-family:Arial,Helvetica,sans-serif;}} pre{{white-space:pre-wrap; font-family:monospace;}}</style></head><body><h2>Diagnostics</h2><pre>{safe}</pre></body></html>"
                    doc = QTextDocument()
                    doc.setHtml(html_doc)
                    printer = QPrinter()
                    printer.setOutputFormat(QPrinter.OutputFormat.PdfFormat)
                    printer.setOutputFileName(filename)
                    doc.print(printer)
                    show_info_popup(
                        self, f"Diagnostics exported to:\n{filename}", "Export Complete"
                    )
                except Exception as e:
                    show_critical_popup(
                        self,
                        f"Failed to export diagnostics to PDF:\n{str(e)}",
                        "Export Error",
                    )
            else:
                # Fallback: write plain text file
                try:
                    with open(filename, "w", encoding="utf-8") as f:
                        f.write(diagnostics_text)
                    show_info_popup(
                        self, f"Diagnostics exported to:\n{filename}", "Export Complete"
                    )
                except Exception as e:
                    show_critical_popup(
                        self, f"Failed to export diagnostics:\n{str(e)}", "Export Error"
                    )
        except Exception as e:
            show_critical_popup(
                self, f"Failed to export diagnostics:\n{str(e)}", "Export Error"
            )

    def handle_clear_results(self):
        """Clear the results textbox (and optionally internal stored parsed results display)."""
        try:
            if not show_confirm_clear(self, "results"):
                return
            self.results_textbox.clear()
            self.displayed_results.clear()  # Clear duplicate tracking
            try:
                self.results_manager.clear_results()  # Clear all parser states and results
            except Exception:
                pass
        except Exception:
            pass

    def handle_clear_diagnostics(self):
        """Clear diagnostics textbox."""
        try:
            if not show_confirm_clear(self, "diagnostics"):
                return
            self.diagnostics_textbox.clear()
        except Exception:
            pass

    def send_to_terminal(self, tool_name, text=None):
        """Route text to the appropriate terminal tab.
        Usage:
          send_to_terminal("nmap", "line...\n")  -> send to nmap tab
          send_to_terminal("some text")         -> send to currently selected tab
        """
        try:
            import json

            # Keep original text for content-marking
            orig_text = text if text is not None else tool_name
            key_for_mark = None

            # If called with a single argument, treat it as the text and use current tab
            if text is None:
                text = tool_name or ""
                target_view = self.terminal_tabs.currentWidget()
            else:
                # tool_name provided explicitly; route by lowercase key if available
                key = (tool_name or "").lower()
                target_view = (
                    self.terminal_views.get(key) or self.terminal_tabs.currentWidget()
                )
                key_for_mark = key if key in self.terminal_views else None

            # Mark content visibility (ignore pure ANSI/whitespace)
            try:
                if key_for_mark:
                    self._mark_terminal_has_content(key_for_mark, orig_text or "")
            except Exception:
                pass

            if not target_view:
                return

            # Normalize and pretty-print JSON if appropriate
            text = text.replace("\t", "    ")
            text = text.replace("\r\n", "\n")
            text = text.replace("\n", "\r\n")
            try:
                j = json.loads(text)
                text = f"\x1b[32m{json.dumps(j, indent=4, sort_keys=True)}\x1b[0m"
            except Exception:
                pass

            try:
                # Safely write to the tab's embedded terminal (if present)
                page = target_view.page()
                if page:
                    page.runJavaScript(f"window.term.write({json.dumps(text)})")
            except Exception:
                pass
        except Exception:
            pass

    # --- New helpers for scan button state ---
    def handle_scan_toggle(self):
        """Called when the single scan_button is clicked — start or stop current tool."""
        try:
            if not self.current_tool:
                show_error_popup(self, "Please select a tool before scanning.")
                return
            tk = (self.current_tool or "").lower()
            if tk in self._scan_running_tools:
                # currently running -> stop
                self.handle_stop_scan()
            else:
                # currently not running -> start
                self.handle_start_scan()
        except Exception:
            pass

    def update_scan_selected_button_state(self):
        """Set unified Scan Selected button appearance based on whether any left-checked tools are running."""
        try:
            # Determine currently-checked left-side tools
            selected = [
                tool
                for tool, widget in self.collapsible_widgets.items()
                if widget.is_tool_checked(tool)
            ]
            any_running = any(
                (tool.lower() in self._scan_running_tools) for tool in selected
            )
            if any_running:
                self.scan_selected_btn.setText("Stop Selected")
                self.scan_selected_btn.setStyleSheet(self._scan_selected_stop_style)
            else:
                self.scan_selected_btn.setText("Scan Selected")
                self.scan_selected_btn.setStyleSheet(self._scan_selected_start_style)
        except Exception:
            pass

    def _set_scan_button_state(self, tool_key, running: bool):
        """Update internal running set and the toggle button appearance.
        tool_key should be lowercase. Only update the visible button if it refers to the current tool.
        """
        try:
            if not tool_key:
                return
            key = tool_key.lower()
            if running:
                self._scan_running_tools.add(key)
            else:
                self._scan_running_tools.discard(key)

            # If the button exists and the tool matches the currently selected tool, update appearance
            if getattr(self, "scan_button", None):
                cur = (
                    (self.current_tool or "").lower()
                    if getattr(self, "current_tool", None)
                    else ""
                )
                if cur and cur == key:
                    if running:
                        self.scan_button.setText("Stop Tool")
                        self.scan_button.setStyleSheet(self._scan_stop_style)
                    else:
                        self.scan_button.setText("Start Tool")
                        self.scan_button.setStyleSheet(self._scan_start_style)
                else:
                    # if current tool not running, ensure button shows Start for the UI's selected tool
                    if cur and cur not in self._scan_running_tools:
                        self.scan_button.setText("Start Tool")
                        self.scan_button.setStyleSheet(self._scan_start_style)

            # Ensure unified "Scan Selected" toggle reflects current running state of checked tools
            try:
                if getattr(self, "scan_selected_btn", None):
                    self.update_scan_selected_button_state()
            except Exception:
                pass
        except Exception:
            pass


# --- Quick tooltip filter: show tooltip immediately on hover (Enter), hide on Leave.
class QuickTooltipFilter(QObject):
    def __init__(self, parent=None):
        super().__init__(parent)

    def eventFilter(self, obj, event):
        try:
            # Only show the quick tooltip for the main tool name label on the right side.
            # Guard if parent or tool_name_box isn't available.
            parent = self.parent()
            target_label = None
            try:
                target_label = (
                    getattr(parent, "tool_name_box", None).tool_name_label
                    if parent and getattr(parent, "tool_name_box", None)
                    else None
                )
            except Exception:
                target_label = None

            if obj is not target_label:
                # ignore events from other widgets (prevents left-side buttons from triggering)
                return False

            if event.type() == QEvent.Type.Enter:
                txt = obj.toolTip() or ""
                if txt:
                    QToolTip.showText(QCursor.pos(), txt, obj)
                return False
            if event.type() == QEvent.Type.Leave:
                QToolTip.hideText()
                return False
        except Exception:
            pass
        return False


# --- Main Application Entry Point ---
if __name__ == "__main__":
    # --- Application Startup ---
    app = QApplication(sys.argv)
    window = HelloWindow()
    window.show()
    app.exec()

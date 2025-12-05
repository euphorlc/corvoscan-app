from .tool_process_base import ToolProcessBase
import os
import re

# parameters that require a user-supplied value (UI should show QLineEdit / combobox)
value_required = [
    "Status codes",  # -mc  (e.g. 200,301)
    "Extension fuzz",  # -e   (e.g. .php,.html)
    "Depth limit",  # -recursion-depth (number)
    "Rate limit",  # -rate (number)
    "Time filter",  # -maxtime (seconds)
    "Filter code",  # -fc  (filter by HTTP response code)
    "Protocol (http/https)",  # UI-controlled protocol selection; default: https
]


class FFUFToolProcess(ToolProcessBase):
    # remove automatic "-w" entry from param_map; wordlist is provided separately
    param_map = {
        "Show help": "-h",  # help flag (no input required)
        "Recursion": "-recursion",
        "Filter code": "-fc",  # Filter by HTTP response code (value)
        "Status codes": "-mc",  # Requires a code list (value)
        "Extension fuzz": "-e",  # Requires extension(s) (value)
        "Depth limit": "-recursion-depth",  # Requires a number (value)
        "Rate limit": "-rate",  # Requires a number (value)
        "Time filter": "-maxtime",  # Requires time (value)
        "Follow redirects": "-r",
        "Ignore SSL": "-k",
        # removed "Size filter" (-fs) and "Custom matcher" (-m)
    }

    # optional fallback defaults if UI path not provided
    DEFAULT_WORDLISTS = [
        os.path.expanduser("~/wordlists/rockyou.txt"),
        "/usr/share/wordlists/rockyou.txt",
        os.path.expanduser("~/wordlists/common.txt"),
    ]

    def __init__(self, target, params):
        super().__init__("ffuf", target, params)

    def _get_ui_wordlist(self):
        """
        Try to obtain the wordlist path from multiple sources, in order:
          1) explicit ("Wordlist", path) tuple in params (handled in build_command)
          2) environment variable CORVOSCAN_FFUFWL
          3) a QLineEdit in the running QApplication that looks like the FFUF textbox
          4) fallback default files if "Default scan" is checked
        This allows the GUI textbox to be read by ffuf_tool without main injecting -w.
        """
        # 2) env var
        env_path = os.getenv("CORVOSCAN_FFUFWL")
        if env_path:
            return env_path

        # 3) try to find a QLineEdit that looks like the FFUF wordlist textbox
        try:
            from PyQt6.QtWidgets import QApplication, QLineEdit

            app = QApplication.instance()
            if app:
                for top in app.topLevelWidgets():
                    # find children QLineEdit widgets
                    for le in top.findChildren(QLineEdit):
                        try:
                            ph = le.placeholderText().lower()
                        except Exception:
                            ph = ""
                        name = (le.objectName() or "").lower()
                        tip = (le.toolTip() or "").lower()
                        # heuristic: placeholder/objectName/tooltip contains 'wordlist' or 'ffuf'
                        if (
                            "wordlist" in ph
                            or "wordlist" in name
                            or "wordlist" in tip
                            or "ffuf" in ph
                        ):
                            val = le.text().strip()
                            if val:
                                return val
        except Exception:
            # don't crash if PyQt not available in this context
            pass

        # 4) fallback default files if "Default scan" present in params
        if "Default scan" in [
            p if not isinstance(p, tuple) else p[0] for p in self.params
        ]:
            for path in self.DEFAULT_WORDLISTS:
                if os.path.isfile(path):
                    return path

        return None

    def build_command(self):
        """
        Two syntaxes:
          - help requested: ffuf <target> -h
          - normal: ffuf -u <target_with_/FUZZ> -w <wordlist> [flags and flag values...]
        The UI may provide ("Wordlist", path) but if not, this function will try to read
        the textbox (or env/defaults) automatically via _get_ui_wordlist().
        """

        # detect explicit help flag (-h) requested by any parameter
        for p in self.params:
            name = p[0] if isinstance(p, tuple) else p
            flag = self.param_map.get(name)
            if flag == "-h":
                # ffuf <target> -h (leave target as provided)
                return ["ffuf", self.target, "-h"]

        # Respect explicit scheme in the provided target. If missing, use chosen protocol (default https).
        target = self.target.strip()

        # Determine protocol selection from params (default to https)
        protocol = "https"
        for p in self.params:
            if isinstance(p, tuple):
                name, value = p
                if name == "Protocol (http/https)":
                    v = (value or "").strip().lower()
                    if v in ("http", "https"):
                        protocol = v
                    break

        # Only prefix protocol if target has no scheme already
        if not re.match(r"^[a-zA-Z][a-zA-Z0-9+\-.]*://", target):
            target = f"{protocol}://{target}"

        # ensure target contains /FUZZ
        fuzz_target = target
        if "FUZZ" not in fuzz_target:
            fuzz_target = fuzz_target.rstrip("/") + "/FUZZ"

        # start command with -u <fuzz_target>
        cmd = ["ffuf", "-u", fuzz_target]

        # collect wordlist from params first (explicit tuple), else try UI/env/defaults
        wordlist = None
        other_flags = []
        for p in self.params:
            if isinstance(p, tuple):
                name, value = p
                if name == "Wordlist":
                    wordlist = value
                else:
                    flag = self.param_map.get(name)
                    if flag:
                        other_flags.extend([flag, value])
            else:
                flag = self.param_map.get(p)
                if flag:
                    other_flags.append(flag)

        if not wordlist:
            wordlist = self._get_ui_wordlist()

        # insert -w immediately after -u <target_with_/FUZZ> if provided
        if wordlist:
            cmd.extend(["-w", wordlist])

        # then append other flags/flag-values
        cmd.extend(other_flags)

        return cmd

import os
from .tool_process_base import ToolProcessBase

value_required = [
    "Domain (-d, --domain) [REQUIRED]",
    "[REQUIRED] Source (-b, --source)",
    "Limit (-l, --limit)",
    "Start result (-S, --start)",
    "DNS server (-e, --dns-server)",
    # removed: "Output filename (-f, --filename)"
    # "Wordlist (-w, --wordlist)"  # removed / commented out per request
]

# theHarvester: standalone flags (meaningful operations)
standalone_flags = [
    "Domain (-d, --domain) [REQUIRED]",
    "[REQUIRED] Source (-b, --source)",
    # "Take screenshots (--screenshot)",
    #
    "Object type (-T TYPE)", # note: kept for consistency if present elsewhere
    # "Takeover check (-t, --take-over)",
    "Query all objects (-a)",
    "Exact match only (-x)",
    "DNS resolve (-r, --dns-resolve)",
    "DNS lookup (-n, --dns-lookup)",
    # "DNS brute force (-c, --dns-brute)"  # removed / commented out per request
]

# Modifiers for theHarvester (adjust behavior/output)
modifier_flags = [
    "Limit (-l, --limit)",
    "Start result (-S, --start)",
    # removed: "Use proxies (-p, --proxies)",
    # removed: "Use Shodan (-s, --shodan)",
    # removed: "Virtual host verification (-v, --virtual-host)",
    "DNS server (-e, --dns-server)",
    # removed: "Output filename (-f, --filename)",
    # "Wordlist (-w, --wordlist)"  # removed / commented out per request
    "Quiet mode (-q, --quiet)"
]

param_map = {
    "Domain (-d, --domain) [REQUIRED]": "-d",
    "[REQUIRED] Source (-b, --source)": "-b",
    "Limit (-l, --limit)": "-l",
    "Start result (-S, --start)": "-S",
    # removed: "Use proxies (-p, --proxies)"
    # removed: "Use Shodan (-s, --shodan)"
    # "Take screenshots (--screenshot)": "--screenshot",
    # removed: "Virtual host verification (-v, --virtual-host)"
    "DNS server (-e, --dns-server)": "-e",
    # "Takeover check (-t, --take-over)": "-t",
    "DNS resolve (-r, --dns-resolve)": "-r",
    "DNS lookup (-n, --dns-lookup)": "-n",
    # "DNS brute force (-c, --dns-brute)": "-c",
    # removed: "Output filename (-f, --filename)"
    # "Wordlist (-w, --wordlist)": "-w",
    "API scan (-a, --api-scan)": "-a",
    "Quiet mode (-q, --quiet)": "-q"
}

# NOTE: The UI's Domain (-d) is provided via the main target field (not a right-side checkbox),
# so Domain appears in param_map/value_required but is intentionally not rendered as a normal
# parameter checkbox in the right-side parameter list.

# --- New: validation to ensure param_map covers UI labels ---
# Keep a small copy of the theHarvester parameter labels as they appear in the UI (main.py).
# This helps catch accidental renames/typos between UI and mapping.
UI_PARAMS_EXPECTED = [
    "[REQUIRED] Source (-b, --source)",
    "Limit (-l, --limit)",
    "Start result (-S, --start)",
    "DNS server (-e, --dns-server)",
    "DNS resolve (-r, --dns-resolve)",
    "DNS lookup (-n, --dns-lookup)",
    "Quiet mode (-q, --quiet)",
    "API scan (-a, --api-scan)"
]

# perform a lightweight set comparison at import time and print actionable warnings if mismatched.
try:
    missing_in_map = [p for p in UI_PARAMS_EXPECTED if p not in param_map]
    extra_in_map = [k for k in param_map.keys() if (k not in UI_PARAMS_EXPECTED and k != "Domain (-d, --domain) [REQUIRED]")]
    if missing_in_map or extra_in_map:
        # Use simple prints so this is visible in console; do not raise to avoid breaking runtime.
        print("theHarvester parameter mapping check:")
        if missing_in_map:
            print(f"  WARNING: UI parameters missing from param_map: {missing_in_map}")
        if extra_in_map:
            print(f"  NOTE: param_map contains extra keys not present in the UI (ignoring domain): {extra_in_map}")
        print("  Tip: keep UI labels in main.py and keys in param_map identical so flags map correctly.")
except Exception:
    # Don't fail import if validation code encounters unexpected data
    pass
# --- end validation ---

class TheHarvesterToolProcess(ToolProcessBase):
    # basic mapping for building command from selected UI parameters
    param_map = {
        "Domain (-d, --domain) [REQUIRED]": "-d",
        "[REQUIRED] Source (-b, --source)": "-b",
        "Limit (-l, --limit)": "-l",
        "Start result (-S, --start)": "-S",
        # removed: "Use proxies (-p, --proxies)"
        # removed: "Use Shodan (-s, --shodan)"
        # "Take screenshots (--screenshot)": "--screenshot",
        # removed: "Virtual host verification (-v, --virtual-host)"
        "DNS server (-e, --dns-server)": "-e",
        # "Takeover check (-t, --take-over)": "-t",
        "DNS resolve (-r, --dns-resolve)": "-r",
        "DNS lookup (-n, --dns-lookup)": "-n",
        # "DNS brute force (-c, --dns-brute)": "-c",
        # removed: "Output filename (-f, --filename)"
        # "Wordlist (-w, --wordlist)": "-w",
        "API scan (-a, --api-scan)": "-a",
        "Quiet mode (-q, --quiet)": "-q"
    }

    def __init__(self, target, params):
        super().__init__("theharvester", target, params)

    def build_command(self):
        # Get the absolute path to theHarvester
        current_dir = os.path.dirname(os.path.abspath(__file__))
        project_root = os.path.dirname(os.path.dirname(current_dir))
        theharvester_path = os.path.join(project_root, "tools", "theHarvester", "theHarvester.py")
        
        # Use the virtual environment's Python interpreter
        venv_python = os.path.join(project_root, "venv", "bin", "python")
        if not os.path.exists(venv_python):
            venv_python = "python3"  # Fallback to system python
        
        # Ensure -b <source> is placed before -d <domain>
        cmd = [venv_python, theharvester_path]

        # Look for the source tuple (expected from the UI as a required field)
        source_val = None
        remaining_params = []
        for p in self.params:
            if isinstance(p, tuple) and p[0] == "[REQUIRED] Source (-b, --source)":
                # keep the chosen source value (only first occurrence)
                if p[1]:
                    source_val = p[1]
                # do not add this tuple to remaining_params to avoid duplication
                continue
            remaining_params.append(p)

        # Insert -b <source> first if present (required field ensures it should exist)
        if source_val:
            cmd.extend(["-b", source_val])

        # Then always add -d <domain> directly after -b
        cmd.extend(["-d", self.target])

        # Process the remaining params (skip the source which we already handled)
        for p in remaining_params:
            if isinstance(p, tuple):
                name, value = p
                flag = self.param_map.get(name)
                if flag and value:  # Only add if value is not empty
                    cmd.extend([flag, value])
            else:
                flag = self.param_map.get(p)
                if flag:
                    cmd.append(flag)

        return cmd
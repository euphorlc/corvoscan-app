from .tool_process_base import ToolProcessBase
import os

# Parameters that require values (UI will show input fields)
value_required = [
    "DNS server (--dnsserver <IP>)",     # UI label -> maps to --dnsserver
    # "Concurrency (-p <n>)"               # COMMENTED OUT: removed from UI options
]

# Standalone vs modifier lists must match the UI strings in main.py
standalone_flags = [
    "Basic run",            # shortened label for default/basic run
    "Verbose output (-v)"   # normalized label (match main.py)
]

modifier_flags = [
    "Skip PTR (--noreverse)",          # descriptive label for --noreverse
    "DNS server (--dnsserver <IP>)",   # shortened/descriptive
    "Enable brute force",              # NEW: when enabled, do not pass automatic -f empty wordlist
    #"-o <output.xml> (save results in XML)",
    # "Concurrency (-p <n>)",            # COMMENTED OUT: removed from UI options
    # "-h (help)"
]

class DNSEnumToolProcess(ToolProcessBase):
    param_map = {
        "Basic run": "",                          # no extra flag; run default
        "Skip PTR (--noreverse)": "--noreverse",
        "DNS server (--dnsserver <IP>)": "--dnsserver",       # maps UI label to actual flag
        "Enable brute force": "",                 # recognized but has no direct CLI token here
        #"-o <output.xml> (save results in XML)": "-o",
        # "Concurrency (-p <n>)": "-p",            # COMMENTED OUT: keep mapping in source but disabled
        "Verbose output (-v)": "-v",
        #"-h (help)": "-h"
    }

    def __init__(self, target, params):
        super().__init__("dnsenum", target, params)

    def build_command(self):
        flags = []
        brute_enabled = False
        for p in self.params:
            # parameter with value passed as tuple (name, value)
            if isinstance(p, tuple):
                name, value = p
                if name == "Enable brute force":
                    brute_enabled = True
                flag = self.param_map.get(name)
                if flag:
                    # some flags expect their value as a separate token
                    flags.extend([flag, value])
            else:
                if p == "Enable brute force":
                    brute_enabled = True
                flag = self.param_map.get(p)
                if flag:
                    # empty string means "no flag" (default run)
                    if flag != "":
                        flags.append(flag)

        # Ensure an empty wordlist exists in the project root and only pass it via -f when brute is NOT enabled
        try:
            project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
            empty_path = os.path.join(project_root, "emptywordlist.txt")
            if not os.path.exists(empty_path):
                # create an empty file to disable brute-force wordlist usage
                with open(empty_path, "w", encoding="utf-8"):
                    pass
            # append the flag to bypass brute force (dnsenum -f <wordlist>)
            # only append when brute force is NOT enabled by the user
            if not brute_enabled:
                flags.extend(["-f", empty_path])
        except Exception:
            # best-effort: if anything fails, continue without raising
            pass

        return ["dnsenum"] + flags + [self.target]

from .tool_process_base import ToolProcessBase

# Parameters that require values and cannot be blank
value_required = []

# Parameters that can have values but are optional (can be left blank)
value_optional = [
    "WHOIS server (-h)",           # Optional - leave blank for auto-detect
    "Port (-p)",                   # Optional - leave blank for default port 43
    # "Inverse attribute search (-i ATTR)",  # commented out: hide from UI but kept for reference
    # "Object type (-T TYPE)"        # commented out: hide from UI but kept for reference
]

class WhoisToolProcess(ToolProcessBase):
    # Flags that represent standalone query options (can be used by themselves with a target)
    # Moved -I, -r, -B here so they act as standalone flags (presence toggles behavior).
    # Verbose (--verbose) is intentionally a standalone toggle as requested.
    standalone_flags = [
        "Default scan",                # no-op default; checking this adds no flag to the command
        "WHOIS server (-h)",
        "Port (-p)",
        # "Inverse attribute search (-i ATTR)", # commented out: hide from UI but keep reference
        # "Object type (-T TYPE)", # commented out: hide from UI but keep reference
        # "Exact match only (-x)",     # commented out per request
        "Display referral chain (-I)",
        # "Query all objects (-a)",    # commented out per request
        # "Disable recursion (-r)",              # commented out: hide from UI but keep reference
        # "Disable contact data filtering (-B)", # commented out: hide from UI but keep reference
        "Verbose output (--verbose)",
        # "Show client version (-V)"  # deprecated/commented out per request
    ]

    # Modifier flags that only change behavior/output
    # Keep only true modifiers here (e.g. -H)
    modifier_flags = {
        "Suppress legal disclaimers (-H)": "-H",
    }

    # Flags that require a user-supplied value (kept for UI validation)
    value_required_flags = {
        "WHOIS server (-h)": "-h",
        "Port (-p)": "-p",
        # "Inverse attribute search (-i ATTR)": "-i",  # commented out: hide but keep reference
        # "Object type (-T TYPE)": "-T",               # commented out: hide but keep reference
    }

    # Combined mapping used when building commands
    param_map = {
        "Default scan": "",                            # explicit no-op mapping
        "WHOIS server (-h)": "-h",                      # requires user input (server host/IP)
        "Port (-p)": "-p",                              # requires user input (port number)
        "Display referral chain (-I)": "-I",
        # "Query all objects (-a)": "-a",                 # commented out per request
        # "Disable recursion (-r)": "-r",                # commented out: hide from UI but keep reference
        # "Inverse attribute search (-i ATTR)": "-i",    # commented out: hide from UI but keep reference
        # "Object type (-T TYPE)": "-T",                 # commented out: hide from UI but keep reference
        # "Disable contact data filtering (-B)": "-B",   # commented out: hide from UI but keep reference
        # "Exact match only (-x)": "-x",                 # commented out per request

        "Verbose output (--verbose)": "--verbose",
        "Suppress legal disclaimers (-H)": "-H",
        # "Show client version (-V)": "-V"  # commented/deprecated
    }

    def __init__(self, target, params):
        # use exact tool name without trailing spaces
        super().__init__("whois", target, params)

    def build_command(self):
        flags = []
        for p in self.params:
            if isinstance(p, tuple):
                name, value = p
                flag = self.param_map.get(name)
                if flag:
                    flags.extend([flag, value])
            else:
                flag = self.param_map.get(p)
                if flag:
                    flags.append(flag)
        return ["whois"] + flags + [self.target]

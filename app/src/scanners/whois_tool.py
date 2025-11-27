from .tool_process_base import ToolProcessBase

# Parameters that require values and cannot be blank
# value_required: parameters that must have a value when selected (empty here)
value_required = []

# Parameters that can have values but are optional (can be left blank)
# value_optional: parameters that accept a value but can be left blank (UI will show input)
value_optional = [
    "WHOIS server (-h)",  # optional: leave blank to auto-detect
    "Port (-p)",  # optional: leave blank to use default port 43
]

# Flags that represent standalone query options (can be used by themselves with a target)
# Standalone flags (presence only) — keys must match UI labels
standalone_flags = [
    "Default scan",  # no-op option
    "WHOIS server (-h)",
    "Port (-p)",
    "Display referral chain (-I)",
    "Suppress legal disclaimers (-H)",
    "Verbose output (--verbose)",
]

# Modifier flags that only change behavior/output
# Modifier flags (toggle-like) mapping to actual short flags
modifier_flags = {"Suppress legal disclaimers (-H)": "-H"}

# Combined mapping used when building commands
# Mapping from UI label -> actual whois flag (used by ToolProcessBase/build)
param_map = {
    "Default scan": "",  # explicit no-op
    "WHOIS server (-h)": "-h",
    "Port (-p)": "-p",
    "Display referral chain (-I)": "-I",
    "Suppress legal disclaimers (-H)": "-H",
    "Verbose output (--verbose)": "--verbose",
}


class WhoisToolProcess(ToolProcessBase):
    def __init__(self, target, params):
        # use exact tool name without trailing spaces
        super().__init__("whois", target, params)

    def build_command(self):
        flags = []
        for p in self.params:
            if isinstance(p, tuple):
                name, value = p
                flag = param_map.get(name)
                if flag:
                    flags.extend([flag, value])
            else:
                flag = param_map.get(p)
                if flag:
                    flags.append(flag)
        return ["whois"] + flags + [self.target]

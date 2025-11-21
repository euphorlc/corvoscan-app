from .tool_process_base import ToolProcessBase

# module-level lists (must match UI parameter strings exactly)
standalone_flags = [
    "IPv4 addresses (A)",
    "IPv6 addresses (AAAA)",
    "Mail servers (MX)",
    "Nameservers (NS)",
    "Start of Authority (SOA)",
    "TXT records (TXT)",
    "Canonical names (CNAME)"
]

# NSLookup has no modifiers; keep empty list exported at module level for clarity
modifier_flags = []

class NSLookupToolProcess(ToolProcessBase):
    # These NSLookup query types are standalone (each is a complete query type)
    standalone_flags = [
        "IPv4 addresses (A)",
        "IPv6 addresses (AAAA)",
        "Mail servers (MX)",
        "Nameservers (NS)",
        "Start of Authority (SOA)",
        "TXT records (TXT)",
        "Canonical names (CNAME)"
    ]

    # NSLookup has few modifiers; keep empty list for clarity
    modifier_flags = []

    param_map = {
        "IPv4 addresses (A)": "-type=A",
        "IPv6 addresses (AAAA)": "-type=AAAA",
        "Mail servers (MX)": "-type=MX",
        "Nameservers (NS)": "-type=NS",
        "Start of Authority (SOA)": "-type=SOA",
        "TXT records (TXT)": "-type=TXT",
        "Canonical names (CNAME)": "-type=CNAME"
    }

    def __init__(self, target, params):
        super().__init__("nslookup", target, params)

    def build_command(self):
        flags = [self.param_map[p] for p in self.params if p in self.param_map]
        return ["nslookup"] + flags + [self.target]
from .tool_process_base import ToolProcessBase

# Parameters that require values (UI will show input fields)
value_required = [
    "User-Agent (--user-agent)",      # requires a User-Agent string
    "Header (--header)",              # requires a header value like "Name: Value"
    "Max threads (--max-threads)",    # requires a numeric thread count
    "Wait (--wait)",                  # requires seconds (delay between requests)
    "Max redirects (--max-redirects)",# numeric redirects limit
    "Follow redirects (--follow-redirect)"  # requires WHEN value (e.g., always/same-origin)
]

# WhatWeb standalone flags (exact strings must match main.py)
standalone_flags = [
    "Default scan",             # UI option: run whatweb with no flags (whatweb <target>)
    "Verbose (-v)"               # use short verbose label to save horizontal space
]

# WhatWeb modifier flags (exact strings must match main.py)
modifier_flags = [
    "Max threads (--max-threads)",    # concurrency control
    "Follow redirects (--follow-redirect)", # follow redirects (value)
    "Max redirects (--max-redirects)",      # numeric redirect cap
    "Wait (--wait)",                  # wait between requests
    "Header (--header)",              # custom HTTP header to include
    "User-Agent (--user-agent)"       # user agent value
]

class WhatWebToolProcess(ToolProcessBase):
    # map UI parameter labels to actual CLI flags; comments explain each mapping
    param_map = {
        "Verbose (-v)": "-v",
        # these flags require an '=' directly after the flag (e.g. --wait=0.5)
        "Follow redirects (--follow-redirect)": "--follow-redirect=",
        "Max redirects (--max-redirects)": "--max-redirects=",       
        "User-Agent (--user-agent)": "--user-agent=",   # requires a string and passed as --user-agent=VALUE
        "Header (--header)": "--header",                      
        "Max threads (--max-threads)": "--max-threads=",       # requires integer
        "Wait (--wait)": "--wait="                             # requires float/seconds, use '='
    }

    def __init__(self, target, params):
        super().__init__("whatweb", target, params)

    def build_command(self):
        flags = []
        for p in self.params:
            if isinstance(p, tuple):
                param_name, value = p
                if param_name in self.param_map:
                    flag = self.param_map[param_name]
                    # If the mapped flag ends with '=', join without a space: --flag=value
                    if flag.endswith('='):
                        flags.append(f"{flag}{value}")
                    else:
                        # otherwise use a space between flag and value
                        flags.append(f"{flag} {value}")
            else:
                if p in self.param_map:
                    flags.append(self.param_map[p])
        # Put flags before the target; WhatWeb typically accepts flags then target URL
        return ["whatweb"] + flags + [self.target]

def set_tool(tool_name):
    global value_required
    # kept for compatibility with existing import patterns (no further logic required)
    if tool_name.lower() == "whatweb":
        value_required = value_required
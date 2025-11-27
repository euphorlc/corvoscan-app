from src.scanners.dnsenum_tool import DNSEnumToolProcess
from src.scanners.ffuf_tool import FFUFToolProcess
from src.scanners.nmap_tools import NmapToolProcess
from src.scanners.nslookup_tool import NSLookupToolProcess
from src.scanners.theharvester_tool import TheHarvesterToolProcess
from src.scanners.whatweb_tool import WhatWebToolProcess
from src.scanners.whois_tool import WhoisToolProcess


# ensure your ScanHandler keeps active_scans mapping (tool_key -> process instance)
class ScanHandler:
    def __init__(self):
        self.active_scans = {}

    def start_scan(self, target, tools, parameters, output_callback):
        for tool in tools:
            tool_lc = tool.lower()
            params = parameters.get(tool, []) or parameters.get(tool_lc, [])
            if tool_lc == "whois":
                proc = WhoisToolProcess(target, params)
            elif tool_lc == "theharvester":
                proc = TheHarvesterToolProcess(target, params)
            elif tool_lc == "dnsenum":
                proc = DNSEnumToolProcess(target, params)
            elif tool_lc == "nmap":
                proc = NmapToolProcess(target, params)
                self.active_scans[tool_lc] = proc
                proc.start(
                    lambda t, line, tool_lc=tool_lc: output_callback(tool_lc, line)
                )
                continue
            elif tool_lc == "whatweb":
                proc = WhatWebToolProcess(target, params)
            elif tool_lc == "ffuf":
                proc = FFUFToolProcess(target, params)
            elif tool_lc == "nslookup":
                proc = NSLookupToolProcess(target, params)
            else:
                continue
            self.active_scans[tool_lc] = proc
            # debug: send exact argv to the GUI terminal via the output callback
            output_callback(
                tool_lc, f"DEBUG start command: {' '.join(proc.build_command())}\r\n"
            )
            proc.start(lambda t, line, tool_lc=tool_lc: output_callback(tool_lc, line))

    def stop_tool(self, tool_name):
        tool_lc = tool_name.lower()
        proc = self.active_scans.get(tool_lc)
        if proc:
            proc.terminate()

    def build_command_preview(self, target, tool_key, params):
        # use already-imported tool classes to avoid repeated dynamic imports
        mapping = {
            "nslookup": NSLookupToolProcess,
            "dnsenum": DNSEnumToolProcess,
            "nmap": NmapToolProcess,
            "whois": WhoisToolProcess,
            "whatweb": WhatWebToolProcess,
            "ffuf": FFUFToolProcess,
            "theharvester": TheHarvesterToolProcess,
        }
        cls = mapping.get(tool_key)
        if not cls:
            return "<command preview unavailable>"
        proc = cls(target, params)
        return " ".join(proc.build_command())

    def set_pty_size(self, tool_key, rows, cols):
        proc = self.active_scans.get(tool_key)
        if proc:
            try:
                proc.set_window_size(rows, cols)
            except Exception:
                pass

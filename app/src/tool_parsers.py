import re
from dataclasses import dataclass
from typing import List, Dict, Optional, Any
from datetime import datetime
from .results_parser import ToolResultsParser, ParsedResult

@dataclass
class DNSRecord:
    """DNS record information"""
    name: str
    record_type: str
    value: str
    ttl: Optional[int] = None

@dataclass
class NSLookupResult(ParsedResult):
    """Structured NSLookup results"""
    dns_records: List[DNSRecord] = None
    server_used: str = ""

    def __post_init__(self):
        if self.dns_records is None:
            self.dns_records = []

    def to_dict(self) -> Dict[str, Any]:
        result = super().to_dict()
        result['dns_records'] = [record.__dict__ for record in self.dns_records]
        return result

@dataclass
class DirectoryEntry:
    """Directory/file fuzzing result"""
    path: str
    status_code: int
    size: int
    words: int = 0
    lines: int = 0
    redirect_location: str = ""
    duration_ms: Optional[int] = None  # optional, parsed from "Duration: 30ms" tokens

@dataclass
class FFUFResult(ParsedResult):
    """Structured FFUF results"""
    base_url: str = ""
    entries_found: List[DirectoryEntry] = None
    total_requests: int = 0
    filter_criteria: str = ""
    # Progress / runtime stats
    progress_processed: int = 0
    progress_total: int = 0
    requests_per_sec: float = 0.0
    progress_duration: str = ""   # human readable like "0:00:33"
    errors_count: int = 0
    progress_info: Dict[str, Any] = None

    def __post_init__(self):
        if self.entries_found is None:
            self.entries_found = []
        if self.progress_info is None:
            self.progress_info = {}

    def to_dict(self) -> Dict[str, Any]:
        result = super().to_dict()
        result['entries_found'] = [entry.__dict__ for entry in self.entries_found]
        result['progress_processed'] = self.progress_processed
        result['progress_total'] = self.progress_total
        result['requests_per_sec'] = self.requests_per_sec
        result['progress_duration'] = self.progress_duration
        result['errors_count'] = self.errors_count
        result['progress_info'] = self.progress_info
        return result

class NSLookupParser(ToolResultsParser):
    """Parser for NSLookup output"""

    def __init__(self):
        super().__init__("nslookup")

    def parse(self, target: str) -> NSLookupResult:
        raw_output = self.get_raw_output()
        dns_records = []
        server_used = ""

        current_record_type = ""

        for line in self.raw_lines:
            line = line.strip()

            # Extract DNS server
            if line.startswith("Server:"):
                server_match = re.search(r'Server:\s+(.+)', line)
                if server_match:
                    server_used = server_match.group(1)

            # Record type headers
            if "IPv4 addresses" in line or line.endswith("A records"):
                current_record_type = "A"
            elif "IPv6 addresses" in line or line.endswith("AAAA records"):
                current_record_type = "AAAA"
            elif "Mail servers" in line or line.endswith("MX records"):
                current_record_type = "MX"
            elif "Nameservers" in line or line.endswith("NS records"):
                current_record_type = "NS"
            elif "TXT records" in line:
                current_record_type = "TXT"
            elif "CNAME" in line:
                current_record_type = "CNAME"
            elif "SOA" in line:
                current_record_type = "SOA"

            # Parse record values
            if current_record_type and line and not line.startswith(("Server:", "Address:", "Non-authoritative")):
                # Skip lines that are headers or separators
                if "records" not in line and "addresses" not in line and "servers" not in line:
                    # Clean up the line to extract the actual record value
                    value = line.strip()
                    if value and not value.startswith("Name:"):
                        dns_records.append(DNSRecord(
                            name=target,
                            record_type=current_record_type,
                            value=value
                        ))

        success = len(dns_records) > 0 and not self._has_errors()
        error_message = self._extract_error_message() if not success else None

        return NSLookupResult(
            tool_name="nslookup",
            target=target,
            timestamp=datetime.now().isoformat(),
            raw_output=raw_output,
            success=success,
            error_message=error_message,
            dns_records=dns_records,
            server_used=server_used
        )

    def _has_errors(self) -> bool:
        """Check for DNS resolution errors"""
        error_indicators = [
            "can't find",
            "NXDOMAIN",
            "SERVFAIL",
            "No answer",
            "connection timed out",
            "no servers could be reached"
        ]
        output = self.get_raw_output()
        return any(indicator in output for indicator in error_indicators)

    def _extract_error_message(self) -> Optional[str]:
        for line in self.raw_lines:
            if any(error in line for error in ["can't find", "NXDOMAIN", "SERVFAIL"]):
                return line.strip()
        return None

# The local WhatWebParser implementation below has been commented out because
# a dedicated parser now exists in src/whatweb_parser.py.  Keep the original
# code here (disabled) in case you want to re-enable or reference it later.

# class WhatWebParser(ToolResultsParser):
#     """Parser for WhatWeb output"""
#
#     def __init__(self):
#         super().__init__("whatweb")
#
#     def parse(self, target: str) -> WhatWebResult:
#         raw_output = self.get_raw_output()
#         technologies = []
#         status_code = 0
#         server = ""
#         ip_address = ""
#         url = target
#
#         # Parse WhatWeb output (assuming standard format)
#         for line in self.raw_lines:
#             line = line.strip()
#
#             # Extract status code
#             status_match = re.search(r'\[(\d{3})\]', line)
#             if status_match:
#                 status_code = int(status_match.group(1))
#
#             # Extract technologies (format: Name[Version])
#             tech_matches = re.findall(r'([A-Za-z0-9_-]+)(?:\[([^\]]*)\])?', line)
#             for name, version in tech_matches:
#                 if name and not name.isdigit():  # Skip status codes
#                     technologies.append(WebTechnology(
#                         name=name,
#                         version=version or ""
#                     ))
#
#             # Extract server information
#             if "Server:" in line:
#                 server_match = re.search(r'Server:\s*([^\s,]+)', line)
#                 if server_match:
#                     server = server_match.group(1)
#
#             # Extract IP address
#             ip_match = re.search(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', line)
#             if ip_match:
#                 ip_address = ip_match.group(1)
#
#         success = status_code > 0 and not self._has_errors()
#         error_message = self._extract_error_message() if not success else None
#
#         return WhatWebResult(
#             tool_name="whatweb",
#             target=target,
#             timestamp=datetime.now().isoformat(),
#             raw_output=raw_output,
#             success=success,
#             error_message=error_message,
#             url=url,
#             status_code=status_code,
#             technologies=technologies,
#             server=server,
#             ip_address=ip_address
#         )
#
#     def _has_errors(self) -> bool:
#         error_indicators = ["ERROR", "failed", "timeout", "unable to connect"]
#         output = self.get_raw_output().lower()
#         return any(indicator in output for indicator in error_indicators)
#
#     def _extract_error_message(self) -> Optional[str]:
#         for line in self.raw_lines:
#             if any(error in line.lower() for error in ["error", "failed", "timeout"]):
#                 return line.strip()
#         return None

# NOTE: FFUFParser implementation moved to src/ffuf_parser.py to mirror other tool-specific parsers.
# The FFUFResult and DirectoryEntry dataclasses remain in this module for reuse by the new parser.

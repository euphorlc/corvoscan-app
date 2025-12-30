import re
import json
import os
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any
from datetime import datetime
from src.results_parser import ToolResultsParser, ParsedResult


@dataclass
class PortInfo:
    port: int
    protocol: str
    state: str
    service: str = ""
    version: str = ""
    extra_info: str = ""
    ssh_hostkeys: Optional[List[Dict[str, str]]] = None
    # NSE script outputs attached to this port (key -> value)
    scripts: Optional[Dict[str, str]] = None
    # Parsed per-request rows (one dict per Request Type, ready for display)
    requests: Optional[List[Dict[str, str]]] = None


@dataclass
class HostInfo:
    """Information about a discovered host"""

    ip: str
    hostname: str = ""
    status: str = ""
    mac_address: str = ""
    vendor: str = ""
    rdns: str = ""
    other_addresses: List[str] = field(default_factory=list)


@dataclass
class OSInfo:
    """Operating system detection information"""

    name: str = ""
    accuracy: int = 0
    type: str = ""
    vendor: str = ""
    family: str = ""
    generation: str = ""
    version: str = ""  # parsed OS version (e.g. "4.0", "8.2-RELEASE", "4.X")
    cpe: str = ""


@dataclass
class SSLInfo:
    port: int = 0
    common_name: str = ""
    issuer: str = ""
    valid_from: str = ""
    valid_to: str = ""
    protocols: Optional[List[str]] = None
    ciphers: Optional[List[str]] = None
    tls_versions: Optional[List[str]] = None
    issues: Optional[List[str]] = None  # e.g., weak ciphers, expired certs


@dataclass
class NmapResult(ParsedResult):
    """Structured nmap scan results"""

    hosts: List[HostInfo] = None
    ports: List[PortInfo] = None
    os_info: List[OSInfo] = None
    ssl_info: List[SSLInfo] = None
    scan_type: str = ""
    scan_stats: Dict[str, Any] = None
    # Add fields for parsed OS detection summary lines
    device_type: str = ""
    os_running_just_guessing: str = ""
    os_aggressive_guesses: str = ""
    # Traceroute hops (list of dicts with Hop/RTT/Address/Hostname/Notes)
    traceroute: List[Dict[str, Any]] = None
    # Diagnostics computed by parser from ruleset
    diagnostics: List[Dict[str, Any]] = None

    def __post_init__(self):
        if self.hosts is None:
            self.hosts = []
        if self.ports is None:
            self.ports = []
        if self.os_info is None:
            self.os_info = []
        if self.ssl_info is None:
            self.ssl_info = []
        if self.scan_stats is None:
            self.scan_stats = {}
        if self.traceroute is None:
            self.traceroute = []
        if self.diagnostics is None:
            self.diagnostics = []

    def to_dict(self) -> Dict[str, Any]:
        result = super().to_dict()
        result["hosts"] = [host.__dict__ for host in self.hosts]
        result["ports"] = [port.__dict__ for port in self.ports]
        result["os_info"] = [os.__dict__ for os in self.os_info]
        result["ssl_info"] = [s.__dict__ for s in self.ssl_info]
        result["device_type"] = self.device_type
        result["os_running_just_guessing"] = self.os_running_just_guessing
        result["os_aggressive_guesses"] = self.os_aggressive_guesses
        result["traceroute"] = self.traceroute
        result["diagnostics"] = self.diagnostics
        return result


class NmapResultsParser(ToolResultsParser):
    def __init__(self):
        super().__init__("nmap")
        # fields populated by _parse_os_detection for consumption by caller
        self._device_type = ""
        self._os_running_just_guessing = ""
        self._os_aggressive_guesses = ""
        # load ruleset (optional) from same src folder
        self.ruleset: Dict[str, Any] = {}
        try:
            candidates = []
            here = os.path.dirname(__file__) if "__file__" in globals() else os.getcwd()
            candidates.append(os.path.join(here, "nmap_ruleset.json"))
            candidates.append(os.path.join(here, "rulesets", "nmap_ruleset.json"))
            candidates.append(os.path.join(here, "..", "nmap_ruleset.json"))
            candidates.append(os.path.join(here, "..", "rulesets", "nmap_ruleset.json"))
            candidates.append(
                os.path.join(os.getcwd(), "src", "rulesets", "nmap_ruleset.json")
            )
            candidates.append(
                os.path.join(os.getcwd(), "rulesets", "nmap_ruleset.json")
            )
            candidates.append(os.path.join(os.getcwd(), "src", "nmap_ruleset.json"))
            candidates.append(os.path.join(os.getcwd(), "nmap_ruleset.json"))
            env_path = os.environ.get("NMAP_RULESET_PATH")
            if env_path:
                candidates.insert(0, env_path)
            for p in candidates:
                try:
                    p = os.path.abspath(p)
                    if os.path.exists(p):
                        with open(p, "r", encoding="utf-8") as fh:
                            self.ruleset = json.load(fh) or {}
                            break
                except Exception:
                    continue
        except Exception:
            self.ruleset = {}

        # compile optional service_map from ruleset (treat keys as regex)
        self.compiled_service_map = []
        try:
            svc_map = (
                (self.ruleset or {}).get("service_map", {})
                if isinstance(self.ruleset, dict)
                else {}
            )
            for k, v in (svc_map or {}).items():
                try:
                    self.compiled_service_map.append((re.compile(k, re.IGNORECASE), v))
                except Exception:
                    # fall back to substring matcher by compiling escaped pattern
                    try:
                        self.compiled_service_map.append(
                            (re.compile(re.escape(k), re.IGNORECASE), v)
                        )
                    except Exception:
                        continue
        except Exception:
            self.compiled_service_map = []

    def parse(self, target: str) -> NmapResult:
        raw_output = self.get_raw_output()
        hosts = []
        ports = []
        os_info = []
        ssl_info: List[SSLInfo] = []  # ensure initialized
        scan_stats = {}
        scan_type = self._extract_scan_type()

        self._parse_hosts_and_ports(hosts, ports)
        self._parse_os_detection(os_info)
        self._parse_scan_statistics(scan_stats)
        self._parse_ssl_info(ssl_info)
        traceroute = self._parse_traceroute()  # <-- new traceroute parsing

        # compute diagnostics based on loaded ruleset and parsed artifacts
        diagnostics = self._compute_diagnostics(
            hosts, ports, os_info, ssl_info, scan_stats
        )

        success = self._is_scan_successful(hosts, ports, os_info, ssl_info)
        error_message = self._extract_error_message() if not success else None

        return NmapResult(
            tool_name="nmap",
            target=target,
            timestamp=datetime.now().isoformat(),
            raw_output=raw_output,
            success=success,
            error_message=error_message,
            hosts=hosts,
            ports=ports,
            os_info=os_info,
            ssl_info=ssl_info,
            scan_type=scan_type,
            scan_stats=scan_stats,
            device_type=self._device_type,
            os_running_just_guessing=self._os_running_just_guessing,
            os_aggressive_guesses=self._os_aggressive_guesses,
            traceroute=traceroute,
            diagnostics=diagnostics,
        )

    def _extract_scan_type(self) -> str:
        """Extract scan type(s) performed in the Nmap output and return a comma-separated string."""
        output = self.get_raw_output() or ""

        # Mapping of indicators to scan type names
        scan_map = {
            ("SYN Stealth Scan", "-sS"): "SYN Stealth Scan",
            ("UDP Scan", "-sU"): "UDP Scan",
            ("Connect() scan", "-sT"): "TCP Connect Scan",
            ("Ping Scan", "-sn"): "Ping Scan",
            ("Service scan", "-sV"): "Service Version Scan",
            ("OS detection", "-O"): "OS Detection Scan",
            ("Script scan", "-sC"): "Script Scan",
            ("-A",): "Aggressive Scan",
        }

        detected_scans = []
        for indicators, scan_name in scan_map.items():
            if any(indicator in output for indicator in indicators):
                detected_scans.append(scan_name)

        # If no scan types matched, return a default
        if not detected_scans:
            return "Standard Scan"

        # Return as a single, stable comma-separated string
        # (NmapResult.scan_type is declared as str)
        return ", ".join(sorted(dict.fromkeys(detected_scans)))

    def _parse_hosts_and_ports(self, hosts: List[HostInfo], ports: List[PortInfo]):
        """Parse host and port information"""
        current_host = None

        for idx, raw_line in enumerate(self.raw_lines):
            line = raw_line.strip()

            # Host discovery
            host_match = re.search(
                r"Nmap scan report for ([^\s]+)(?:\s+\(([^)]+)\))?", line
            )
            if host_match:
                hostname = host_match.group(1)
                ip = host_match.group(2) if host_match.group(2) else hostname

                # If hostname looks like an IP, swap them
                if self._is_ip_address(hostname) and host_match.group(2):
                    ip, hostname = hostname, host_match.group(2)
                elif self._is_ip_address(hostname):
                    ip, hostname = hostname, ""

                current_host = HostInfo(ip=ip, hostname=hostname)
                hosts.append(current_host)
                continue

            # Other addresses line (e.g. "Other addresses for example.com (not scanned): 1.2.3.4 2.3.4.5")
            m_other = re.match(
                r"Other addresses for\s+([^\s]+)(?:\s*\([^)]+\))?:\s*(.*)",
                line,
                re.IGNORECASE,
            )
            if m_other:
                addrs = m_other.group(2).strip()
                if addrs:
                    addr_list = re.split(r"[\s,]+", addrs)
                    # attach to current host if present, otherwise try to find matching host by name
                    target_host = current_host
                    if not target_host:
                        name = m_other.group(1).strip()
                        for h in hosts[::-1]:
                            if h.hostname == name or h.ip == name:
                                target_host = h
                                break
                    if target_host:
                        target_host.other_addresses = addr_list
                continue

            # Host status
            if current_host and "Host is" in line:
                status_match = re.search(r"Host is (\w+)", line)
                if status_match:
                    current_host.status = status_match.group(1)
                continue

            # MAC Address
            if current_host and "MAC Address:" in line:
                mac_match = re.search(
                    r"MAC Address: ([A-Fa-f0-9:]{17})(?: \(([^)]+)\))?", line
                )
                if mac_match:
                    current_host.mac_address = mac_match.group(1)
                    if mac_match.group(2):
                        current_host.vendor = mac_match.group(2)
                continue

            # Port information (supports "PORT STATE SERVICE [VERSION]" output from -sV)
            port_match = re.match(
                r"^(\d+)\/(tcp|udp)\s+(\w+)\s+(\S+)(?:\s+(.+))?$", line
            )
            if port_match:
                port_num = int(port_match.group(1))
                protocol = port_match.group(2)
                state = port_match.group(3)
                service_token = port_match.group(
                    4
                )  # original SERVICE token (e.g. "http", "ssl/https")
                extra = (
                    port_match.group(5) or ""
                ).strip()  # may contain product/version info (sV)

                # default: keep original service token, no version
                service_field = service_token
                version_field = ""

                if extra:
                    # Keep the full extra string as the version field so we capture
                    # product + revision + distro qualifiers and parentheses.
                    # Examples:
                    #  "OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.13 (Ubuntu Linux; protocol 2.0)"
                    #  "Apache httpd 2.4.7 ((Ubuntu))"
                    version_field = extra

                service_info = (service_token + (" " + extra if extra else "")).strip()
                port_info = PortInfo(
                    port=port_num,
                    protocol=protocol,
                    state=state,
                    service=service_field,
                    version=version_field,
                    extra_info=service_info,
                )
                ports.append(port_info)
                # --- NSE script output parsing (lines starting with '|' or '|_') ---
                # Collect script outputs like "|_http-title: ..." and attach as a dict to port_info.scripts
                scripts = {}
                last_key = None
                for j in range(idx + 1, min(len(self.raw_lines), idx + 40)):
                    l = (self.raw_lines[j] or "").rstrip()
                    # stop when script block ends (no leading pipe)
                    if not l.lstrip().startswith("|"):
                        break
                    body = re.sub(r"^\|_?\s*", "", l).rstrip()
                    m = re.match(r"([^:]+):\s*(.*)", body)
                    if m:
                        key = m.group(1).strip()
                        val = m.group(2).strip()
                        if key in scripts:
                            scripts[key] += "\n" + val
                        else:
                            scripts[key] = val
                        last_key = key
                    else:
                        # continuation line -> append to last key
                        if last_key:
                            scripts[last_key] += "\n" + body
                if scripts:
                    port_info.scripts = scripts

                    # Parse fingerprint-strings (and related script fields) into per-request rows.
                    # Each request type (FourOhFourRequest, GetRequest, etc.) becomes its own row.
                    request_rows: List[Dict[str, str]] = []

                    # Helper: ingest a block of lines for a request type and extract status/header/notes
                    def _ingest_request_block(req_name: str, lines: List[str]):
                        status_code = ""
                        message = ""
                        server = ""
                        x_served_by = ""
                        notes_lines: List[str] = []

                        # Normalize: strip leading pipe chars and trailing whitespace
                        norm_lines = [
                            re.sub(r"^\s*\|\s*", "", (ln or "")).rstrip()
                            for ln in lines
                        ]
                        # remove empty and consecutive-duplicate lines
                        cleaned = []
                        last = None
                        for ln in norm_lines:
                            if not ln:
                                continue
                            if last is not None and ln == last:
                                continue
                            cleaned.append(ln)
                            last = ln

                        i = 0
                        while i < len(cleaned):
                            s = cleaned[i].strip()
                            i += 1
                            if not s:
                                continue

                            # Status line: HTTP/1.1 500 Domain Not Found
                            m_status = re.match(
                                r"^HTTP/\d+\.\d+\s+(\d{3})\s*(.*)$", s, re.IGNORECASE
                            )
                            if m_status and not status_code:
                                status_code = m_status.group(1).strip()
                                message = (m_status.group(2) or "").strip()
                                continue

                            # Header form: "Header: value" OR "Header:" then next line is value
                            m_header = re.match(r"^(?P<h>[^:]+):\s*(?P<v>.*)$", s)
                            if m_header:
                                h = m_header.group("h").strip()
                                v = m_header.group("v").strip()
                                # if empty value, try next line as value (if it's not another header)
                                if not v and i < len(cleaned):
                                    nxt = cleaned[i].strip()
                                    if ":" not in nxt:
                                        v = nxt
                                        i += 1
                                lh = h.lower()
                                if lh == "server" and not server:
                                    server = v
                                    continue
                                if (
                                    lh in ("x-served-by", "x-served-by:")
                                    and not x_served_by
                                ):
                                    x_served_by = v
                                    continue
                                # otherwise keep as note
                                notes_lines.append(f"{h}: {v}" if v else h)
                                continue

                            # If line looks like just a status code and message without HTTP/1.1
                            m_alt_status = re.match(r"^(\d{3})\s+(.+)$", s)
                            if m_alt_status and not status_code:
                                status_code = m_alt_status.group(1).strip()
                                message = m_alt_status.group(2).strip()
                                continue

                            # Otherwise append to notes
                            notes_lines.append(s)

                        # Final attempt: if no explicit status_code found, search notes for status pattern
                        if not status_code:
                            for idx_n, nl in enumerate(list(notes_lines)):
                                m2 = re.search(
                                    r"HTTP/\d+\.\d+\s+(\d{3})\s*(.*)$",
                                    nl,
                                    re.IGNORECASE,
                                )
                                if m2:
                                    status_code = m2.group(1).strip()
                                    message = (m2.group(2) or "").strip()
                                    notes_lines.pop(idx_n)
                                    break
                                m3 = re.match(r"^(\d{3})\s+(.+)$", nl)
                                if m3:
                                    status_code = m3.group(1).strip()
                                    message = m3.group(2).strip()
                                    notes_lines.pop(idx_n)
                                    break

                        # Extract HTML title / meaningful paragraph snippets from notes (if present)
                        combined = "\n".join(notes_lines)
                        title_m = re.search(
                            r"<title[^>]*>(.*?)</title>",
                            combined,
                            re.IGNORECASE | re.DOTALL,
                        )
                        if title_m:
                            title_txt = re.sub(r"\s+", " ", title_m.group(1).strip())
                            # ensure title appears first in notes
                            notes_lines.insert(0, f"Title: {title_txt}")

                        # Try to find short Fastly/Varnish message fragments in notes
                        fastly_m = re.search(
                            r"(Fastly error:[^\n\r]+)", combined, re.IGNORECASE
                        )
                        if fastly_m:
                            notes_lines.insert(0, fastly_m.group(1).strip())

                        # dedupe and trim notes_lines
                        cleaned_notes = []
                        seen = set()
                        for n in notes_lines:
                            n_s = n.strip()
                            if not n_s or n_s in seen:
                                continue
                            cleaned_notes.append(n_s)
                            seen.add(n_s)

                        request_rows.append(
                            {
                                "request_type": req_name.strip(),
                                "status_code": status_code.strip(),
                                "message": message.strip(),
                                "server": server.strip(),
                                "x_served_by": x_served_by.strip(),
                                "notes": "\n".join(cleaned_notes).strip(),
                            }
                        )

                    # Parse fingerprint-strings blocks if present
                    fs_raw = (
                        scripts.get("fingerprint-strings")
                        or scripts.get("fingerprint-strings:")
                        or ""
                    )
                    if fs_raw:
                        # Split into lines, normalize leading pipe chars
                        raw_lines = [
                            re.sub(r"^\s*\|\s*", "", (ln or "")).rstrip()
                            for ln in fs_raw.splitlines()
                        ]
                        # remove empty and consecutive duplicates
                        cleaned = []
                        last = None
                        for ln in raw_lines:
                            if not ln:
                                continue
                            if last is not None and ln == last:
                                continue
                            cleaned.append(ln)
                            last = ln

                        cur_names: List[str] = []
                        cur_block: List[str] = []
                        for line_fs in cleaned:
                            # header lines end with ":" (e.g. "FourOhFourRequest:" or "GetRequest, HTTPOptions:")
                            m_hdr = re.match(r"^\s*([^:]+):\s*$", line_fs)
                            if m_hdr:
                                # flush previous
                                if cur_names and cur_block:
                                    for nm in cur_names:
                                        _ingest_request_block(nm, cur_block)
                                # start new block, allow comma-separated names
                                name_field = m_hdr.group(1).strip()
                                cur_names = [
                                    n.strip()
                                    for n in re.split(r",\s*", name_field)
                                    if n.strip()
                                ]
                                cur_block = []
                                continue
                            # continuation lines for current block
                            if cur_names:
                                cur_block.append(line_fs)
                        # flush last
                        if cur_names and cur_block:
                            for nm in cur_names:
                                _ingest_request_block(nm, cur_block)

                    # If no fingerprint-strings rows were captured, build generic rows from other scripts
                    if not request_rows:
                        # create rows for common probes if we can detect responses
                        # prefer http-title and http-server-header presence to create a 'probe' row
                        generic_notes: List[str] = []
                        title_val = (
                            scripts.get("http-title")
                            or scripts.get("http-title:")
                            or ""
                        )
                        server_val = (
                            scripts.get("http-server-header")
                            or scripts.get("http-server-header:")
                            or ""
                        )
                        if title_val:
                            generic_notes.append(f"Title: {title_val}")
                        if server_val:
                            generic_notes.append(f"Server header: {server_val}")
                        # also include ssl-cert summary for HTTPS
                        ssl_cert_val = scripts.get("ssl-cert") or scripts.get(
                            "ssl-cert:"
                        )
                        if ssl_cert_val:
                            # include CN and notable SAN/cert lines
                            cn_m = re.search(
                                r"commonName=([^/,\n\r]+)", ssl_cert_val, re.IGNORECASE
                            )
                            if cn_m:
                                generic_notes.append(
                                    f"Cert CN: {cn_m.group(1).strip()}"
                                )
                        if generic_notes:
                            request_rows.append(
                                {
                                    "request_type": "probe",
                                    "status_code": "",
                                    "message": "",
                                    "server": (server_val or "").strip(),
                                    "x_served_by": "",
                                    "notes": "\n".join(generic_notes),
                                }
                            )

                    # Ensure http-server-header populates any empty server fields
                    http_server = scripts.get("http-server-header") or scripts.get(
                        "http-server-header:"
                    )
                    if http_server:
                        for rr in request_rows:
                            if not rr.get("server"):
                                rr["server"] = http_server.strip()

                    # Attach port-level fields to each request row (port/proto/state/service/version)
                    if request_rows:
                        enriched_rows: List[Dict[str, str]] = []
                        for rr in request_rows:
                            enriched = {
                                "port": str(port_num),
                                "protocol": protocol,
                                "state": state,
                                "service": service_field,
                                "version": version_field,
                                "request_type": rr.get("request_type", ""),
                                "status_code": rr.get("status_code", ""),
                                "message": rr.get("message", ""),
                                "server": rr.get("server", ""),
                                "x_served_by": rr.get("x_served_by", ""),
                                "notes": rr.get("notes", ""),
                            }
                            enriched_rows.append(enriched)
                        port_info.requests = enriched_rows

                    # continue parsing other lines after attaching scripts
                    # (do not `continue` here; allow other parsers like ssh-hostkey to run)

            # rDNS information
            rdns_match = re.search(
                r"rDNS record for\s+([\d\.]+):\s*(\S+)", line, re.IGNORECASE
            )
            if not rdns_match:
                rdns_match = re.search(
                    r"reverse\s*dns\s*(?:record)?\s*for\s+([\d\.]+):\s*(\S+)",
                    line,
                    re.IGNORECASE,
                )
            if rdns_match:
                ip_address = rdns_match.group(1).strip()
                rdns_full = rdns_match.group(2).strip()
                # If multiple hostnames are present, split by comma or whitespace
                rdns_list = re.split(r"[\s,]+", rdns_full)
                primary_rdns = rdns_list[0] if rdns_list else rdns_full

                # Attach rdns to current_host when IP matches, otherwise try to find the host
                target_host = current_host
                if not target_host or getattr(target_host, "ip", None) != ip_address:
                    for h in hosts:
                        if getattr(h, "ip", None) == ip_address:
                            target_host = h
                            break
                if target_host:
                    target_host.rdns = primary_rdns

                # keep local rdns_info for potential future use / debugging
                rdns_info = {
                    "ip": ip_address,
                    "hostname": primary_rdns,
                    "all_hostnames": rdns_list,
                    "raw": rdns_full,
                }

    def _parse_os_detection(self, os_info: List[OSInfo]):
        """Parse OS detection results, including device type, 'Running (JUST GUESSING)', and aggressive guesses."""
        # reset temp fields
        self._device_type = ""
        self._os_running_just_guessing = ""
        self._os_aggressive_guesses = ""

        # collect parsed CPE entries here for later association
        cpe_entries: List[Dict[str, str]] = []

        def _parse_guess_list(text: str) -> List[OSInfo]:
            items: List[OSInfo] = []
            if not text:
                return items
            # split on commas that are not inside parentheses
            parts = [
                p.strip() for p in re.split(r",\s*(?![^()]*\))", text) if p.strip()
            ]
            for part in parts:
                # Try: "Name Version (NN%)"
                m_full = re.match(
                    r"^(?P<name>.+?)\s+(?P<version>[0-9A-Za-z\.\-X]+)\s*\((?P<acc>\d+)%\)\s*$",
                    part,
                )
                if m_full:
                    name = m_full.group("name").strip()
                    version = m_full.group("version").strip()
                    acc = int(m_full.group("acc"))
                    items.append(OSInfo(name=name, version=version, accuracy=acc))
                    continue

                # Try: "Name (NN%)"
                m_acc = re.match(r"^(?P<name>.+?)\s*\((?P<acc>\d+)%\)\s*$", part)
                if m_acc:
                    name = m_acc.group("name").strip()
                    acc = int(m_acc.group("acc"))
                    # attempt to separate trailing version tokens from the name if present (e.g. "OpenBSD 4.X")
                    m_nv = re.match(r"^(?P<n>.*\D)\s+(?P<v>[0-9A-Za-z\.\-X]+)$", name)
                    if m_nv:
                        items.append(
                            OSInfo(
                                name=m_nv.group("n").strip(),
                                version=m_nv.group("v").strip(),
                                accuracy=acc,
                            )
                        )
                    else:
                        items.append(OSInfo(name=name, accuracy=acc))
                    continue

                # Try: "Name Version" (no accuracy)
                m_nv2 = re.match(
                    r"^(?P<name>.+?)\s+(?P<version>[0-9A-Za-z\.\-X]+)\s*$", part
                )
                if m_nv2:
                    items.append(
                        OSInfo(
                            name=m_nv2.group("name").strip(),
                            version=m_nv2.group("version").strip(),
                            accuracy=0,
                        )
                    )
                    continue

                # fallback: the whole part is a name without accuracy/version
                items.append(OSInfo(name=part.strip(), accuracy=0))
            return items

        in_os_section = False
        # we will also collect any standalone "Running:" lines and accuracy lines
        for raw_line in self.raw_lines:
            line = (raw_line or "").strip()
            if not line:
                # do not necessarily break; keep scanning for OS lines
                continue

            # Device type
            m_dev = re.match(r"^\s*Device type:\s*(.+)$", line, re.IGNORECASE)
            if m_dev:
                self._device_type = m_dev.group(1).strip()
                continue

            # Running (JUST GUESSING) or Running:
            m_running_guess = re.match(
                r"^\s*Running\s*\(.*JUST\s*GUESSING.*\)\s*:\s*(.+)$",
                line,
                re.IGNORECASE,
            )
            if m_running_guess:
                val = m_running_guess.group(1).strip()
                self._os_running_just_guessing = val
                os_info.extend(_parse_guess_list(val))
                continue

            m_running = re.match(r"^\s*Running:\s*(.+)$", line, re.IGNORECASE)
            if m_running:
                val = m_running.group(1).strip()
                self._os_running_just_guessing = self._os_running_just_guessing or val
                os_info.extend(_parse_guess_list(val))
                continue

            # Aggressive guesses
            m_aggr = re.match(
                r"^\s*Aggressive OS guesses\s*:\s*(.+)$", line, re.IGNORECASE
            )
            if m_aggr:
                val = m_aggr.group(1).strip()
                self._os_aggressive_guesses = val
                os_info.extend(_parse_guess_list(val))
                continue

            # OS CPE: parse and store entries for later association
            m_cpe = re.match(r"^\s*OS CPE:\s*(.+)$", line, re.IGNORECASE)
            if m_cpe:
                cpe_text = m_cpe.group(1).strip()
                # split on whitespace; each token should be a cpe string like cpe:/o:vendor:product:version
                tokens = [t.strip() for t in re.split(r"\s+", cpe_text) if t.strip()]
                for t in tokens:
                    # parse cpe:/o:vendor:product:version...
                    parts = t.split(":")
                    vendor = parts[2] if len(parts) > 2 else ""
                    product = parts[3] if len(parts) > 3 else ""
                    ver = parts[4] if len(parts) > 4 else ""
                    cpe_entries.append(
                        {"raw": t, "vendor": vendor, "product": product, "version": ver}
                    )
                continue

            # Parse lines which look like 'Name (NN% accuracy)' appearing anywhere
            m_acc_any = re.match(
                r"^\s*(.+?)\s*\((\d+)%\s*accuracy\)\s*$", line, re.IGNORECASE
            )
            if m_acc_any:
                name = m_acc_any.group(1).strip()
                acc = int(m_acc_any.group(2))
                # attempt to split name/version if present
                m_nv = re.match(r"^(?P<n>.*\D)\s+(?P<v>[0-9A-Za-z\.\-X]+)$", name)
                if m_nv:
                    os_info.append(
                        OSInfo(
                            name=m_nv.group("n").strip(),
                            version=m_nv.group("v").strip(),
                            accuracy=acc,
                        )
                    )
                else:
                    os_info.append(OSInfo(name=name, accuracy=acc))
                continue

            # If we hit a line that indicates OS detection finished, skip further parsing
            if (
                line.lower().startswith("no exact os matches")
                or line.lower().startswith("os cpe:")
                or line.lower().startswith("nmap done:")
            ):
                # don't break immediately; allow other patterns above to be matched earlier
                continue

        # After scanning all lines, try to associate CPE entries with parsed OSInfo entries.
        if cpe_entries:
            # First try direct matching by product/vendor in the os_info names
            for os_entry in os_info:
                name_l = (os_entry.name or "").lower()
                matched = False
                for c in cpe_entries:
                    prod_l = (c.get("product") or "").lower()
                    vend_l = (c.get("vendor") or "").lower()
                    cver = c.get("version") or ""
                    if (
                        (prod_l and prod_l in name_l)
                        or (vend_l and vend_l in name_l)
                        or (cver and cver in (os_entry.version or ""))
                    ):
                        os_entry.cpe = c.get("raw", "")
                        if not os_entry.version and cver:
                            os_entry.version = cver
                        matched = True
                        break
                # if not matched, leave for the generic pass below
            # If some CPE entries remain unassociated, create OSInfo entries from them
            for c in cpe_entries:
                already = any(
                    (getattr(o, "cpe", "") or "") == c.get("raw", "") for o in os_info
                )
                if not already:
                    name_guess = c.get("product") or c.get("vendor") or ""
                    os_info.append(
                        OSInfo(
                            name=name_guess,
                            version=c.get("version", ""),
                            accuracy=0,
                            cpe=c.get("raw", ""),
                        )
                    )

    def _parse_scan_statistics(self, scan_stats: Dict[str, Any]):
        """Parse scan timing and statistics"""
        for line in self.raw_lines:
            line = line.strip()

            # Scan timing
            if "done:" in line and "scanned" in line:
                timing_match = re.search(
                    r"done: (\d+) IP address(?:es)? \((\d+) host(?:s)? up\) scanned in ([\d.]+) seconds",
                    line,
                )
                if timing_match:
                    scan_stats["total_ips"] = int(timing_match.group(1))
                    scan_stats["hosts_up"] = int(timing_match.group(2))
                    scan_stats["scan_time"] = float(timing_match.group(3))

            # Ports scanned
            ports_match = re.search(r"(\d+) ports scanned", line)
            if ports_match:
                scan_stats["ports_scanned"] = int(ports_match.group(1))

            # "Not shown:" lines — support variants like:
            #   Not shown: 98 filtered tcp ports (no-response)
            #   Not shown: 98 filtered ports (no-response)
            #   Not shown: 98 closed tcp ports
            m_not_shown = re.match(
                r"^\s*Not shown:\s*(\d+)\s+(.+?)\s+ports(?:\s*\(([^)]+)\))?\s*$",
                line,
                re.IGNORECASE,
            )
            if m_not_shown:
                # count
                try:
                    scan_stats["not_shown_count"] = int(m_not_shown.group(1))
                except Exception:
                    scan_stats["not_shown_count"] = m_not_shown.group(1)

                desc = (m_not_shown.group(2) or "").strip()
                # attempt to detect protocol token (tcp/udp) at the end of the descriptor
                parts = desc.split()
                proto = None
                reason_desc = None
                if parts:
                    last = parts[-1].lower()
                    if last in ("tcp", "udp"):
                        proto = last
                        reason_desc = " ".join(parts[:-1]).strip() or None
                    else:
                        reason_desc = desc

                scan_stats["not_shown_proto"] = proto
                paren_reason = (m_not_shown.group(3) or "").strip()
                scan_stats["not_shown_reason"] = paren_reason or (reason_desc or "")
                # friendly summary for UI
                proto_part = f" {proto}" if proto else ""
                scan_stats["not_shown_display"] = (
                    f"{scan_stats.get('not_shown_count', '?')}{proto_part} ports ({scan_stats.get('not_shown_reason', '').strip()})"
                )
                continue

    def _parse_ssl_info(self, ssl_info: List[SSLInfo]):
        lines = self.raw_lines or []
        for idx, line in enumerate(lines):
            l = line.strip()
            if not any(
                token in l.lower()
                for token in (
                    "ssl",
                    "tls",
                    "certificate",
                    "subject",
                    "issuer",
                    "cipher",
                )
            ):
                continue

            # find nearest preceding port line
            port_num = None
            for j in range(max(0, idx - 8), idx + 1)[::-1]:
                m = re.match(r"(\d+)/(tcp|udp)\s+(\w+)\s+(.+)", lines[j].strip())
                if m:
                    try:
                        port_num = int(m.group(1))
                    except Exception:
                        port_num = None
                    break
                pm = re.search(r"(\d+)/(tcp|udp)", lines[j])
                if pm:
                    try:
                        port_num = int(pm.group(1))
                    except Exception:
                        port_num = None
                    break

            if port_num is None:
                continue

            si = SSLInfo(port=port_num)
            # scan a small window forward for certificate fields
            for k in range(idx, min(len(lines), idx + 14)):
                t = lines[k].strip()
                sub_m = re.search(r"Subject[:\s]*(.*)", t, re.IGNORECASE)
                if sub_m:
                    subj = sub_m.group(1).strip()
                    cn_m = re.search(r"CN=([^,;/]+)", subj)
                    si.common_name = cn_m.group(1).strip() if cn_m else subj
                    continue
                iss_m = re.search(r"Issuer[:\s]*(.*)", t, re.IGNORECASE)
                if iss_m:
                    si.issuer = iss_m.group(1).strip()
                    continue
                nb_m = re.search(r"Not valid before[:\s]*(.*)", t, re.IGNORECASE)
                if nb_m:
                    si.valid_from = nb_m.group(1).strip()
                    continue
                na_m = re.search(r"Not valid after[:\s]*(.*)", t, re.IGNORECASE)
                if na_m:
                    si.valid_to = na_m.group(1).strip()
                    continue
                tv = re.findall(r"(TLSv?\d+(?:\.\d+)?)", t, re.IGNORECASE)
                if tv:
                    si.tls_versions = list(dict.fromkeys((si.tls_versions or []) + tv))
                c_m = re.search(r"Cipher[:\s]*(.*)", t, re.IGNORECASE)
                if c_m:
                    val = c_m.group(1).strip()
                    si.ciphers = list(dict.fromkeys((si.ciphers or []) + [val]))
                if re.search(r"(weak|insecure|deprecated|expired)", t, re.IGNORECASE):
                    si.issues = list(dict.fromkeys((si.issues or []) + [t]))

            ssl_info.append(si)

    def _is_scan_successful(self, *args, **kwargs):
        """
        Backwards-compatible wrapper for nmap scan-success checks.

        Accepts either:
          - (parsed, scan_stats)  (legacy)
          - (hosts, open_ports, services, scan_stats?)  (caller-specific)
        Heuristic: if any meaningful parsed result/list is non-empty -> success.
        If scan_stats indicates an explicit failure token, return False.
        """
        # Legacy two-arg form: (parsed, scan_stats)
        if len(args) == 2 and isinstance(args[1], dict):
            parsed, scan_stats = args
            # quick checks for common parsed structures
            try:
                if isinstance(parsed, dict) and parsed:
                    return True
                if hasattr(parsed, "hosts") and getattr(parsed, "hosts"):
                    return True
                if isinstance(parsed, (list, tuple)) and parsed:
                    return True
            except Exception:
                pass
            # inspect scan_stats for explicit failure markers
            stats = scan_stats or {}
            if isinstance(stats, dict):
                status = str(stats.get("status", "")).lower()
                if any(
                    tok in status for tok in ("error", "failed", "timeout", "refused")
                ):
                    return False
            return bool(parsed)

        # Multi-arg form: consider any non-empty meaningful arg a success
        # Skip self if accidentally passed; check positional args
        meaningful = [a for a in args if a is not None]
        for a in meaningful:
            if isinstance(a, (list, tuple, dict, set)) and len(a) > 0:
                return True
            if not isinstance(a, (list, tuple, dict, set)) and bool(a):
                return True

        # Check kwargs scan_stats for failure indicators
        stats = kwargs.get("scan_stats") or {}
        if isinstance(stats, dict):
            status_text = " ".join(
                str(stats.get(k, "")) for k in ("status", "status_lines") if k in stats
            ).lower()
            if any(
                tok in status_text
                for tok in ("error", "failed", "timed out", "timeout", "refused")
            ):
                return False

        # Default to success to avoid spurious failures when unsure
        return True

    def _has_critical_errors(self) -> bool:
        """Check if the scan output contains critical errors (excluding sudo prompts)"""
        critical_error_indicators = [
            "QUITTING!",
            "ERROR:",
            "Permission denied",
            "Operation not permitted",
            "No route to host",
            "Network is unreachable",
        ]

        # Sudo-related messages that should NOT be considered errors
        sudo_indicators = ["[sudo]", "password for", "Password:"]

        output = self.get_raw_output()
        lines = output.split("\n")

        for line in lines:
            line_upper = line.upper()

            # Skip lines that contain sudo prompts
            if any(
                sudo_indicator.upper() in line_upper
                for sudo_indicator in sudo_indicators
            ):
                continue

            # Check for critical errors
            if any(error.upper() in line_upper for error in critical_error_indicators):
                return True

        return False

    def _extract_error_message(self) -> Optional[str]:
        """Extract error message from output, ignoring sudo prompts"""
        sudo_indicators = ["[sudo]", "password for", "Password:"]

        for line in self.raw_lines:
            line = line.strip()
            line_upper = line.upper()

            # Skip sudo-related lines
            if any(
                sudo_indicator.upper() in line_upper
                for sudo_indicator in sudo_indicators
            ):
                continue

            # Look for actual error messages
            if any(
                keyword in line_upper
                for keyword in [
                    "ERROR",
                    "QUITTING",
                    "PERMISSION DENIED",
                    "OPERATION NOT PERMITTED",
                ]
            ):
                return line
        return None

    def _is_ip_address(self, text: str) -> bool:
        """Check if text is an IP address"""
        ip_pattern = r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
        return bool(re.match(ip_pattern, text))

    def _parse_traceroute(self) -> List[Dict[str, Any]]:
        """Parse traceroute section into list of hops with fields:
        Hop | RTT (ms) | Address | Hostname | Notes
        """
        lines = self.raw_lines or []
        hops: List[Dict[str, Any]] = []
        in_tr = False

        # IPv4 private ranges check helper
        def _is_private_ip(ip: str) -> bool:
            try:
                parts = [int(p) for p in ip.split(".") if p != ""]
                if len(parts) != 4:
                    return False
                a, b, c, d = parts
                if a == 10:
                    return True
                if a == 192 and b == 168:
                    return True
                if a == 172 and 16 <= b <= 31:
                    return True
                return False
            except Exception:
                return False

        for idx, raw in enumerate(lines):
            line = (raw or "").rstrip()
            if not in_tr:
                # Detect traceroute header (various forms)
                if (
                    re.search(r"^\s*TRACEROUTE\b", line, re.IGNORECASE)
                    or re.search(r"\btraceroute\b", line, re.IGNORECASE)
                    and "hop" in line.lower()
                ):
                    in_tr = True
                    continue
                # sometimes a header line "HOP RTT ADDRESS" appears next - treat start when we see first numbered hop
            else:
                # stop when we reach an empty line followed by a non-hop section, but allow some blanks
                if not line:
                    # lookahead to decide stop: if next non-empty line is not a hop, end
                    lookahead = ""
                    for j in range(idx + 1, min(len(lines), idx + 6)):
                        if lines[j].strip():
                            lookahead = lines[j].strip()
                            break
                    if lookahead and not re.match(r"^\d+\s+", lookahead):
                        break
                    # otherwise continue scanning
                    continue

            # If not yet flagged as traceroute but we encounter a hop-like line, start capturing
            if not in_tr:
                # Only start traceroute capture on lines that resemble real traceroute hops:
                #  - a '*' or '...' no-response hop
                #  - contain an RTT token like 'ms'
                #  - contain an IP address (with or without parentheses)
                # This avoids false positives on lines like "2 services unrecognized ..." which also start with a number.
                hop_like = re.match(
                    r"^\s*\d+\s+(?:\*|\.\.\.|\S.*\bms\b|\S.*\(\d{1,3}(?:\.\d{1,3}){3}\)|.*\d{1,3}(?:\.\d{1,3}){3})",
                    line,
                    re.IGNORECASE,
                )
                if hop_like:
                    in_tr = True
                else:
                    # not a traceroute hop-looking line -> continue
                    continue

            if not in_tr:
                continue

            # Hop lines typically start with hop number
            m = re.match(r"^\s*(\d+)\s+(.*)$", line)
            if not m:
                # handle '*' or '...' lines or other noisy lines
                if line.strip() in ("...", "*", "* * *"):
                    # unknown hop index - append a no-response placeholder without hop number
                    hops.append(
                        {
                            "Hop": "",
                            "RTT (ms)": "",
                            "Address": "",
                            "Hostname": "",
                            "Notes": "no response",
                        }
                    )
                continue

            hop_num = int(m.group(1))
            rest = m.group(2).strip()

            # if rest is '...' or '*' => no response
            if rest.startswith("...") or rest.startswith("*") or rest == "":
                hops.append(
                    {
                        "Hop": hop_num,
                        "RTT (ms)": "",
                        "Address": "",
                        "Hostname": "",
                        "Notes": "no response",
                    }
                )
                continue

            # Extract first RTT value (e.g., "0.33 ms" or "1 ms")
            rtt = ""
            m_rtt = re.search(r"(\d+(?:\.\d+)?)\s*ms", rest, re.IGNORECASE)
            if m_rtt:
                rtt = m_rtt.group(1).strip()
                # remove that RTT occurrence from rest for easier address parsing
                rest = re.sub(re.escape(m_rtt.group(0)), "", rest, count=1).strip()

            # Sometimes multiple RTTs are present; keep first only per rules.

            # Now parse address/hostname
            address = ""
            hostname = ""
            notes_list: List[str] = []

            # If rest like "name (ip)"
            m_host_ip = re.match(r"^(?P<h>.+?)\s*\((?P<ip>[\d\.]+)\)\s*$", rest)
            if m_host_ip:
                hostname = m_host_ip.group("h").strip()
                address = m_host_ip.group("ip").strip()
            else:
                # rest may be only an IP or a name without ().
                # Take the last token if it matches IP pattern
                toks = rest.split()
                last_tok = toks[-1] if toks else ""
                if re.match(r"^\d+\.\d+\.\d+\.\d+$", last_tok):
                    address = last_tok
                    hostname = " ".join(toks[:-1]).strip() if len(toks) > 1 else ""
                    # if hostname equals address, clear hostname
                    if hostname == address:
                        hostname = ""
                else:
                    # no explicit paren IP and last token not IP -> treat entire rest as hostname
                    hostname = rest
                    address = ""

            # Notes: mark private network if address is private
            if address and _is_private_ip(address):
                notes_list.append("private network")

            # If hostname present and looks like an IP written without parens, handle
            if hostname and re.match(r"^\d+\.\d+\.\d+\.\d+$", hostname):
                address = hostname
                hostname = ""

            # If remaining tokens include words like "no reply" or "*", mark no response
            if (
                re.search(r"\b(no reply|no response)\b", rest, re.IGNORECASE)
                or "*" in rest
            ):
                if not notes_list:
                    notes_list.append("no response")

            # Additional content (sometimes provider names) — include in notes if not duplicate
            # If there is still extra text beyond hostname/ip and RTT, include it as a note
            # Compute what's left after removing hostname and address from rest
            residual = rest
            # remove hostname (if present) and address token
            if hostname:
                residual = re.sub(re.escape(hostname), "", residual, count=1).strip()
            if address:
                residual = re.sub(re.escape(address), "", residual, count=1).strip()
            # strip leftover parentheses and separators
            residual = residual.strip(" ,;()")

            if residual:
                # avoid repeating 'ms' fragments etc.
                if not re.match(r"^\d+(\.\d+)?\s*ms$", residual):
                    notes_list.append(residual)

            notes = "; ".join(notes_list) if notes_list else ""

            hops.append(
                {
                    "Hop": hop_num,
                    "RTT (ms)": rtt,
                    "Address": address,
                    "Hostname": hostname,
                    "Notes": notes,
                }
            )

        return hops

    def _compute_diagnostics(
        self,
        hosts: List[HostInfo],
        ports: List[PortInfo],
        os_info: List[OSInfo],
        ssl_info: List[SSLInfo],
        scan_stats: Dict[str, Any],
    ) -> List[Dict[str, Any]]:
        """Produce diagnostics by comparing parsed results to the loaded ruleset."""
        diags: List[Dict[str, Any]] = []
        try:
            rules = (
                (self.ruleset or {}).get("rules", [])
                if isinstance(self.ruleset, dict)
                else []
            )
        except Exception:
            rules = []
        defaults = (
            (self.ruleset or {}).get("defaults", {})
            if isinstance(self.ruleset, dict)
            else {}
        )
        version_rules = (
            (self.ruleset or {}).get("version_rules", [])
            if isinstance(self.ruleset, dict)
            else []
        )

        def add(sev, msg, ctx=None, insight=None, remediation=None):
            entry = {
                "severity": sev or defaults.get("severity", "Info"),
                "message": msg,
            }
            if ctx:
                entry["context"] = ctx
            if insight:
                entry["insight"] = insight
            if remediation:
                entry["remediation"] = remediation
            if entry not in diags:
                diags.append(entry)

        # helpers for version extraction & compare
        def _extract_version_token(text: str) -> Optional[str]:
            if not text:
                return None
            s = str(text)
            # Try prioritized patterns:
            # 1) dotted versions with common suffixes (e.g. 6.6.1p1, 2.4.7-rc1, 2022.83)
            # 2) dotted versions without suffix (e.g. 6.6.1, 2.4.7)
            # 3) numeric + alpha suffix (e.g. 6p1, 6a1)
            # 4) single integer fallback
            patterns = [
                r"(\d+(?:\.\d+)+(?:[A-Za-z0-9_\-\.]*\d)?)",
                r"(\d+(?:\.\d+)+)",
                r"(\d+[A-Za-z0-9_\-\.]+)",
                r"(\d+)",
            ]
            for pat in patterns:
                m = re.search(pat, s)
                if m:
                    return m.group(1)
            return None

        def _version_to_list(v: str) -> List[int]:
            parts = re.findall(r"\d+", v or "")
            return [int(p) for p in parts] if parts else []

        def _cmp_versions(a: str, b: str) -> int:
            """Return -1 if a<b, 0 if equal, 1 if a>b"""
            if not a or not b:
                return 0
            A = _version_to_list(a)
            B = _version_to_list(b)
            # compare padded
            L = max(len(A), len(B))
            for i in range(L):
                ai = A[i] if i < len(A) else 0
                bi = B[i] if i < len(B) else 0
                if ai < bi:
                    return -1
                if ai > bi:
                    return 1
            return 0

        # Port/service rules
        for p in ports or []:
            p_svc = (p.service or "").lower()
            p_extra = (p.extra_info or "").lower()
            p_proto = (p.protocol or "").lower()
            matched = False
            for r in rules:
                r_ports = r.get("ports") or r.get("port") or []
                if isinstance(r_ports, int):
                    r_ports = [r_ports]
                proto_rule = r.get("protocol") or r.get("protocols")
                proto_ok = True
                if proto_rule:
                    if isinstance(proto_rule, (list, tuple)):
                        proto_ok = p_proto in [x.lower() for x in proto_rule]
                    else:
                        proto_ok = p_proto == str(proto_rule).lower()

                port_match = bool(r_ports and p.port in r_ports)
                svc = (r.get("service") or "").lower()
                svc_contains = (r.get("service_contains") or "").lower()
                service_match = bool(svc and svc == p_svc)
                contains_match = bool(
                    svc_contains and (svc_contains in p_svc or svc_contains in p_extra)
                )

                if proto_ok and (port_match or service_match or contains_match):
                    add(
                        r.get("severity"),
                        r.get("message", "Matched rule"),
                        f"port {p.port}/{p.protocol} service={p.service}",
                        insight=r.get("insight"),
                        remediation=r.get("remediation"),
                    )
                    matched = True

            # simple fallback heuristics if nothing matched
            if not matched:
                heuristics = {
                    "ftp": (
                        "High",
                        "FTP transmits credentials in clear text; secure with TLS or disable.",
                    ),
                    "telnet": ("High", "Telnet is unencrypted; avoid."),
                    "mysql": ("High", "Public MySQL access can expose data."),
                    "redis": (
                        "High",
                        "Unprotected Redis can allow remote writes/execution.",
                    ),
                    "mongodb": ("High", "Open MongoDB instances may leak data."),
                    "rdp": ("High", "RDP exposed — brute-force / remote exploit risk."),
                }
                for tok, info in heuristics.items():
                    if tok in p_svc or tok in p_extra:
                        add(
                            info[0],
                            info[1],
                            f"port {p.port}/{p.protocol} service={p.service}",
                        )

        # --- version rules checks ---
        for vr in version_rules or []:
            vr_ports = vr.get("ports") or vr.get("port") or []
            if isinstance(vr_ports, int):
                vr_ports = [vr_ports]
            vr_min = str(vr.get("min_version") or "").strip()
            if not vr_min and not vr.get("pattern"):
                continue
            vr_service = (
                (vr.get("service") or "").lower() if vr.get("service") else None
            )
            vr_contains = (
                (vr.get("service_contains") or "").lower()
                if vr.get("service_contains")
                else None
            )
            vr_pattern = vr.get("pattern")

            for p in ports or []:
                # build searchable text from multiple fields (service token, extra_info, version, script outputs)
                scripts_text = ""
                if p.scripts:
                    try:
                        scripts_text = " ".join(
                            [f"{k} {v}" for k, v in p.scripts.items()]
                        )
                    except Exception:
                        scripts_text = " ".join(
                            [
                                str(k)
                                for k in (
                                    p.scripts.keys()
                                    if hasattr(p.scripts, "keys")
                                    else []
                                )
                            ]
                        )
                combined = " ".join(
                    filter(
                        None,
                        [
                            (p.service or ""),
                            (p.version or ""),
                            (p.extra_info or ""),
                            scripts_text,
                        ],
                    )
                ).lower()

                # basic matching: by port or by service token presence in combined text
                match = False
                if vr_ports and p.port in vr_ports:
                    match = True
                svc_lower = (p.service or "").lower()
                if vr_service and (vr_service == svc_lower or vr_service in combined):
                    match = True
                if vr_contains and (vr_contains in combined):
                    match = True
                if vr_pattern and re.search(vr_pattern, combined, re.IGNORECASE):
                    match = True
                if not match:
                    continue

                # Attempt to extract a version in several ways:
                actual_ver = None
                # 1) service-name followed by version, e.g. "OpenSSH 6.6.1p1"
                if vr_service:
                    msv = re.search(
                        r"%s[\s/:-]*([0-9A-Za-z\.\-p_]+)" % re.escape(vr_service),
                        combined,
                        re.IGNORECASE,
                    )
                    if msv:
                        actual_ver = msv.group(1)
                # 2) try explicit version field or extra_info
                if not actual_ver:
                    actual_ver = _extract_version_token(
                        (p.version or "") or (p.extra_info or "") or combined
                    )
                # 3) scan scripts values one-by-one
                if not actual_ver and p.scripts:
                    for sval in p.scripts.values():
                        av = _extract_version_token(str(sval))
                        if av:
                            actual_ver = av
                            break

                if not actual_ver and not vr_pattern:
                    # add a lightweight Info diag so you can see why a rule didn't match
                    add(
                        "Info",
                        f"version not detected for {vr.get('service') or vr.get('service_contains') or 'rule'}",
                        f"port {p.port}/{p.protocol}",
                    )
                    continue

                # normalize version for comparison (strip trailing letters/punctuation)
                if actual_ver:
                    actual_ver_cmp = re.sub(r"[^0-9\.]", "", actual_ver)
                else:
                    actual_ver_cmp = None

                # version comparison
                if (
                    actual_ver_cmp
                    and vr_min
                    and _cmp_versions(actual_ver_cmp, vr_min) < 0
                ):
                    sev = vr.get("severity") or "High"
                    msg = (
                        vr.get("message")
                        or f"{p.service or 'service'} version {actual_ver} is older than required {vr_min}"
                    )
                    add(
                        sev,
                        msg,
                        f"port {p.port}/{p.protocol} (detected {actual_ver})",
                        insight=vr.get("insight"),
                        remediation=vr.get("remediation"),
                    )
                elif vr_pattern and re.search(vr_pattern, combined, re.IGNORECASE):
                    # if only pattern matched, report it
                    sev = vr.get("severity") or "High"
                    msg = (
                        vr.get("message")
                        or f"{p.service or 'service'} matches pattern {vr_pattern}"
                    )
                    add(
                        sev,
                        msg,
                        f"port {p.port}/{p.protocol} (detected {actual_ver or 'unknown'})",
                        insight=vr.get("insight"),
                        remediation=vr.get("remediation"),
                    )

        # SSL observations
        for si in ssl_info or []:
            if si.issues:
                for issue in si.issues:
                    add("High", f"SSL issue: {issue}", f"port {si.port}")
            if si.valid_to and "expired" in si.valid_to.lower():
                add(
                    "Medium",
                    f"Certificate validity ends: {si.valid_to}",
                    f"port {si.port}",
                )

        # OS rules
        for r in rules:
            r_os = (r.get("os") or "").lower() if r.get("os") else None
            if not r_os:
                continue
            for o in os_info or []:
                if r_os in (o.name or "").lower() or r_os in (o.cpe or "").lower():
                    add(
                        r.get("severity"),
                        r.get("message", "OS rule matched"),
                        f"os: {o.name}",
                        insight=r.get("insight"),
                        remediation=r.get("remediation"),
                    )

        # scan_stats hints
        if scan_stats.get("not_shown_display"):
            add(
                "Info",
                f"Not shown ports: {scan_stats.get('not_shown_display')}",
                "scan_stats",
            )

        return diags

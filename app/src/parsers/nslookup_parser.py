from dataclasses import dataclass, field
import re
from typing import Optional, List, Dict, Any
from datetime import datetime
from src.results_parser import ToolResultsParser, ParsedResult

@dataclass
class ARecord:
    """IPv4 Address Record"""
    name: str                    # Queried domain
    ipv4: str                    # IPv4 address result

@dataclass
class AAAARecord:
    """IPv6 Address Record"""
    name: str                    # Queried domain
    ipv6: str                    # IPv6 address result

@dataclass
class MXRecord:
    """Mail Exchange Record"""
    domain: str                  # Domain the MX applies to
    priority: int                # MX preference value
    mail_server: str             # Mail server hostname

@dataclass
class NSRecord:
    """Authoritative Name Server Record"""
    domain: str                  # Domain the NS applies to
    nameserver: str              # NS hostname

@dataclass
class SOARecord:
    domain: str
    primary_ns: Optional[str] = None
    contact: Optional[str] = None
    serial: Optional[str] = None
    refresh: Optional[str] = None
    retry: Optional[str] = None
    expire: Optional[str] = None
    minimum: Optional[str] = None

@dataclass
class TXTRecord:
    """Text Record (SPF, DKIM, etc.)"""
    domain: str
    texts: List[str]             # May contain multiple strings for one domain

@dataclass
class CNAMERecord:
    """Canonical Name Record"""
    alias: str                   # Alias (queried name)
    canonical: str               # Canonical name target

@dataclass
class NSLookupResult(ParsedResult):
    domain: str = ""
    scan_type: str = ""     # add this line
    a_records: List[ARecord] = field(default_factory=list)
    aaaa_records: List[AAAARecord] = field(default_factory=list)
    mx_records: List[MXRecord] = field(default_factory=list)
    ns_records: List[NSRecord] = field(default_factory=list)
    soa_record: Optional[SOARecord] = None
    txt_records: List[TXTRecord] = field(default_factory=list)
    cname_records: List[CNAMERecord] = field(default_factory=list)
    diagnostics: List[Dict[str, Any]] = field(default_factory=list)

    def __post_init__(self):
        if self.a_records is None:
            self.a_records = []
        if self.aaaa_records is None:
            self.aaaa_records = []
        if self.mx_records is None:
            self.mx_records = []
        if self.ns_records is None:
            self.ns_records = []
        if self.txt_records is None:
            self.txt_records = []
        if self.cname_records is None:
            self.cname_records = []

    def to_dict(self) -> Dict[str, Any]:
        result = super().to_dict()
        result.update({
            "domain": self.domain,
            "a_records": [a.__dict__ for a in self.a_records],
            "aaaa_records": [aaaa.__dict__ for aaaa in self.aaaa_records],
            "mx_records": [mx.__dict__ for mx in self.mx_records],
            "ns_records": [ns.__dict__ for ns in self.ns_records],
            "soa_record": self.soa_record.__dict__ if self.soa_record else {},
            "txt_records": [txt.__dict__ for txt in self.txt_records],
            "cname_records": [cn.__dict__ for cn in self.cname_records],
        })
        return result


class NSLookupParser(ToolResultsParser):
    def __init__(self):
        super().__init__("nslookup")


    def parse(self, target: str) -> NSLookupResult:
        """
        Robust parse: search raw output for IPv4/IPv6 addresses and associate them
        with the nearest preceding Name: entry, or use target as fallback.
        Only record address lines that are part of the answer section and skip
        server header lines (e.g. "Address: 10.0.0.1#53").
        """
        raw_output = self.get_raw_output() or ""
        lines = (raw_output or "").splitlines()

        a_records: List[ARecord] = []
        aaaa_records: List[AAAARecord] = []
        mx_records: List[MXRecord] = []
        ns_records: List[NSRecord] = []
        txt_records: List[TXTRecord] = []
        cname_records: List[CNAMERecord] = []
        soa_record: Optional[SOARecord] = None

        last_name = None
        in_answer = False

        for i, ln in enumerate(lines):
            if not ln:
                continue
            s = ln.strip()

            # mark start of the answer section when seen
            if re.search(r'^(Non-authoritative answer:|Authoritative answers can be found|Authoritative answer:)', s, re.IGNORECASE):
                in_answer = True
                continue

            # Skip server header lines like:
            #   Server:         10.255.255.254
            #   Address:        10.255.255.254#53
            if s.lower().startswith("server:"):
                continue
            if re.match(r'^Address:\s*.+#\d+', s):
                # server address with a port/hash — not a query answer
                continue

            # Capture "Name: <domain>" lines -> enables subsequent Address lines to be recorded
            m_name = re.match(r'Name:\s*(\S+)', s, re.IGNORECASE)
            if m_name:
                last_name = m_name.group(1).rstrip('.')
                in_answer = True
                continue

            # Some nslookup variants place the domain on a plain line before Address lines
            m_plain = re.match(r'^([A-Za-z0-9\.-]+)$', s)
            if m_plain and not re.match(r'^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$', s):
                # treat this as candidate name only if we're likely in the answer section
                if in_answer:
                    last_name = m_plain.group(1).rstrip('.')

            # Match IPv4 addresses introduced by "Address:" or bare IP lines.
            # Only record A records if we are in the answer section OR we already saw a Name.
            m_addr = re.search(r'Address:\s*([0-9]{1,3}(?:\.[0-9]{1,3}){3})', s, re.IGNORECASE)
            if m_addr:
                # ignore server Address lines containing '#', handled above
                ip = m_addr.group(1)
                if in_answer or last_name:
                    name = last_name or target
                    a_records.append(ARecord(name=name, ipv4=ip))
                continue

            # IPv4 on a line by itself (rare). Only accept if in answer or have name.
            m_ip_only = re.match(r'^([0-9]{1,3}(?:\.[0-9]{1,3}){3})$', s)
            if m_ip_only:
                if in_answer or last_name:
                    ip = m_ip_only.group(1)
                    name = last_name or target
                    a_records.append(ARecord(name=name, ipv4=ip))
                continue

            # Match IPv6 Address lines (AAAA). Record even without '#' but respect answer context.
            m_aaaa = re.search(r'Address:\s*([0-9a-fA-F:]+)', s)
            if m_aaaa:
                addr = m_aaaa.group(1)
                # if this is the server IPv6 with "#", skip (handled above)
                if in_answer or last_name:
                    name = last_name or target
                    aaaa_records.append(AAAARecord(name=name, ipv6=addr))
                continue

        # ensure names for any records without a name are set to target only if they belong to answer
        for rec in a_records + aaaa_records:
            if not getattr(rec, "name", None):
                rec.name = target

        # attempt to parse other record types but don't let them break A/AAAA extraction
        try:
            self._parse_mx_records(mx_records, lines)
            self._parse_ns_records(ns_records, lines)
            self._parse_txt_records(txt_records, lines)
            self._parse_cname_records(cname_records, lines)
            soa_record = self._parse_soa_record(lines)
        except Exception:
            pass

        # Build and return result
        # Determine success tolerantly:
        # - any parsed A/AAAA/MX/NS/TXT/CNAME/SOA => success
        # - ignore transient "No answer" / server header messages if usable records exist
        parsed_found = bool(a_records or aaaa_records or mx_records or ns_records or txt_records or cname_records or soa_record)
        raw_lower = (raw_output or "").lower()
        # If parser found meaningful records treat as success regardless of error lines
        success = parsed_found
        # If nothing parsed, still treat SOA or CNAME in raw text as success (fallback)
        if not success:
            if soa_record or cname_records:
                success = True

        # Extract error only when we consider the scan failed
        error_message = None if success else self._extract_error_message()

        # Decide scan_type from parsed data (prefer explicit query type)
        if soa_record and not (a_records or aaaa_records or cname_records):
            scan_type = "SOA"
        elif a_records:
            scan_type = "A"
        elif aaaa_records:
            scan_type = "AAAA"
        elif cname_records:
            scan_type = "CNAME"
        else:
            scan_type = self._extract_scan_type() or "Standard Query"

        result = NSLookupResult(
            tool_name="nslookup",
            target=target,
            timestamp=datetime.now().isoformat(),
            raw_output=raw_output,
            success=success,
            error_message=error_message,
            a_records=a_records,
            aaaa_records=aaaa_records,
            mx_records=mx_records,
            ns_records=ns_records,
            soa_record=soa_record,
            txt_records=txt_records,
            cname_records=cname_records,
        )
        result.domain = target
        result.scan_type = scan_type

        # build simple record list for diagnostics and attach diagnostics to result
        records_for_diag: List[Dict[str, Any]] = []
        for a in a_records:
            records_for_diag.append({"name": getattr(a, "name", ""), "type": "A", "value": getattr(a, "ipv4", "")})
        for aaaa in aaaa_records:
            records_for_diag.append({"name": getattr(aaaa, "name", ""), "type": "AAAA", "value": getattr(aaaa, "ipv6", "")})
        for ns in ns_records:
            records_for_diag.append({"name": getattr(ns, "domain", ""), "type": "NS", "value": getattr(ns, "nameserver", "")})
        # include MX records so MX diagnostics can detect presence/priorities
        for mx in mx_records:
            try:
                mx_raw = mx.__dict__ if hasattr(mx, "__dict__") else (mx if isinstance(mx, dict) else {})
                name = getattr(mx, "domain", "") or mx_raw.get("domain", "") or ""
                priority = getattr(mx, "priority", None)
                if priority is None:
                    # try common raw keys
                    for k in ("preference", "pref"):
                        if isinstance(mx_raw, dict) and k in mx_raw:
                            try:
                                priority = int(mx_raw.get(k))
                                break
                            except Exception:
                                priority = None
                server = getattr(mx, "mail_server", None) or mx_raw.get("mailserver") or mx_raw.get("exchange") or ""
                value = f"{priority} {server}".strip() if priority is not None else str(server or "")
                records_for_diag.append({"name": name, "type": "MX", "value": value, "raw": mx_raw})
            except Exception:
                continue
        # include TXT records for third-party integration checks
        for txt in txt_records:
            try:
                txt_raw = txt.__dict__ if hasattr(txt, "__dict__") else (txt if isinstance(txt, dict) else {})
                name = getattr(txt, "domain", "") or txt_raw.get("domain", "")
                texts = getattr(txt, "texts", None) or txt_raw.get("texts") or txt_raw.get("text") or txt_raw.get("values") or []
                if isinstance(texts, (list, tuple)):
                    value = " ".join([str(x) for x in texts])
                else:
                    value = str(texts or "")
                records_for_diag.append({"name": name, "type": "TXT", "value": value, "raw": txt_raw})
            except Exception:
                continue

        # include SOA so soa_rule checks can evaluate refresh/retry/expire/ttl
        if soa_record:
            try:
                # build a minimal raw dict with canonical keys (strings)
                soa_raw = {}
                # many libraries use different attr names; guard for both
                for k in ("refresh", "retry", "expire", "minimum", "ttl", "serial", "primary_ns", "contact", "origin"):
                    v = getattr(soa_record, k, None)
                    if v is None and isinstance(soa_record, dict):
                        v = soa_record.get(k)
                    if v is not None:
                        soa_raw[k] = str(v)
                # ensure we have a name
                name = getattr(soa_record, "domain", None) or soa_raw.get("origin") or target
                records_for_diag.append({"name": name, "type": "SOA", "value": "", "raw": soa_raw})
            except Exception:
                pass
        try:
            # pass scan_type so diagnostics can be selective (eg. only warn about missing MX for MX scans)
            result.diagnostics = self._compute_diagnostics(records_for_diag, {"scan_type": scan_type})
        except Exception:
            result.diagnostics = []

        return result

    def _extract_scan_type(self) -> str:
        """Extract scan type(s) performed in the Nmap output and return a comma-separated string."""
        output = self.get_raw_output() or ""

        # Mapping of indicators to scan type names
        scan_map = {
            ("-type=A",): "IPv4 Address (A Record)",
            ("-type=AAAA",): "IPv6 Address (AAAA Record)",
            ("-type=MX",): "Mail Exchange (MX Record)",
            ("-type=NS",): "Name Server (NS Record)",
            ("-type=SOA",): "Start of Authority (SOA Record)",
            ("-type=TXT",): "Text (TXT Record)",
            ("-type=CNAME",): "Canonical Name (CNAME Record)",
        }

        detected_scans = []
        for indicators, scan_name in scan_map.items():
            if any(indicator in output for indicator in indicators):
                detected_scans.append(scan_name)

        if not detected_scans:
            return "Standard Scan"

        return ", ".join(sorted(dict.fromkeys(detected_scans)))

    def _parse_a_records(self, a_records: List[ARecord], lines: List[str]):
        """
        Robustly parse A records from nslookup output.

        Handles:
         - Lines like "Name:   target.com"
         - Lines like "Address: 151.101.194.187"
         - Repeated Name/Address pairs
         - Cases where Address appears but Name was on a previous line
        """
        if not lines:
            return

        current_name = None
        # Precompute stripped lines for easier backward search
        stripped_lines = [(i, (ln or "").strip()) for i, ln in enumerate(lines)]

        for idx, raw in stripped_lines:
            if not raw:
                continue

            # Match "Name:  target.com" (case-insensitive)
            m_name = re.match(r'Name:\s*(\S+)', raw, re.IGNORECASE)
            if m_name:
                current_name = m_name.group(1).rstrip('.')
                continue

            # Match IPv4 Address lines like "Address: 151.101.194.187"
            m_addr = re.match(r'Address:\s*([0-9]{1,3}(?:\.[0-9]{1,3}){3})', raw)
            if m_addr:
                ip = m_addr.group(1)
                if current_name:
                    a_records.append(ARecord(name=current_name, ipv4=ip))
                else:
                    # fallback: search backwards for the nearest Name: line
                    for j in range(idx - 1, -1, -1):
                        prev = stripped_lines[j][1]
                        if not prev:
                            continue
                        pm = re.match(r'Name:\s*(\S+)', prev, re.IGNORECASE)
                        if pm:
                            name = pm.group(1).rstrip('.')
                            a_records.append(ARecord(name=name, ipv4=ip))
                            break
                    else:
                        # final fallback: use target-like token if present
                        # (do not fail parsing just because we couldn't find a name)
                        a_records.append(ARecord(name="", ipv4=ip))
                continue

            # Sometimes nslookup prints "target.com" on a line by itself before Address
            # capture that as a candidate name
            m_plain = re.match(r'^([A-Za-z0-9\.-]+)$', raw)
            if m_plain and not re.match(r'^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$', raw):
                current_name = m_plain.group(1).rstrip('.')
                continue

        return

    def _parse_aaaa_records(self, aaaa_records: List[AAAARecord], lines: List[str]):
        current_name = None
        for line in lines:
            line = line.strip()
            if m := re.match(r"Name:\s*(\S+)", line):
                current_name = m.group(1)
            elif m := re.match(r"Address:\s*([0-9a-fA-F:]+)", line):
                if ":" in m.group(1) and current_name:
                    aaaa_records.append(AAAARecord(name=current_name, ipv6=m.group(1)))

    def _parse_mx_records(self, mx_records: List[MXRecord], lines: List[str]):
        """Parse MX (Mail Exchange) records from nslookup output."""
        for line in lines:
            line = line.strip()
            matches = re.findall(r"([a-zA-Z0-9.-]+)\s+mail exchanger\s*=\s*(\d+)\s+([a-zA-Z0-9.-]+)", line)
            for m in matches:
                domain, priority, mail_server = m
                mx_records.append(
                    MXRecord(
                        domain=domain,
                        priority=int(priority),
                        mail_server=mail_server.rstrip(".")
                    )
                )
    def _parse_ns_records(self, ns_records: List[NSRecord], lines: List[str]):
        for line in lines:
            line = line.strip()
            if m := re.match(r"(\S+)\s+nameserver = (\S+)", line):
                ns_records.append(NSRecord(domain=m.group(1), nameserver=m.group(2)))

    def _parse_txt_records(self, txt_records: List[TXTRecord], lines: List[str]):
        for line in lines:
            line = line.strip()
            if m := re.match(r"(\S+)\s+text = \"(.*)\"", line):
                txt_records.append(TXTRecord(domain=m.group(1), texts=[m.group(2)]))

    def _parse_cname_records(self, cname_records: List[CNAMERecord], lines: List[str]):
        for line in lines:
            line = line.strip()
            if m := re.match(r"(\S+)\s+canonical name = (\S+)", line):
                cname_records.append(CNAMERecord(alias=m.group(1), canonical=m.group(2)))

    def _parse_soa_record(self, lines: List[str]) -> Optional[SOARecord]:
        """
        Robustly parse SOA output blocks like the one produced by nslookup -type=SOA.
        Handles variants where the queried domain appears on its own line followed by
        indented 'origin = ...', 'mail addr = ...', 'serial = ...' lines.
        """
        if not lines:
            return None

        # join for quick NXDOMAIN detection
        joined = "\n".join(lines)
        if re.search(r"can't find|no such|server can't find|not found|NXDOMAIN", joined, re.IGNORECASE):
            return None

        domain = None
        primary = None
        contact = None
        serial = None
        refresh = None
        retry = None
        expire = None
        minimum = None

        # Find a line that is just the queried domain (common nslookup SOA format)
        # and then parse the following indented key = value lines.
        for i, ln in enumerate(lines):
            if not ln:
                continue
            s = ln.rstrip()

            # A plain domain line (no colon, not an ip, contains a dot)
            if re.match(r'^[A-Za-z0-9\.-]+\.[A-Za-z]{2,}$', s.strip()) and ':' not in s:
                # candidate domain line
                domain_candidate = s.strip().rstrip('.')
                # look ahead for SOA key/value lines in the next several lines
                j = i + 1
                saw_soa_field = False
                while j < len(lines) and j <= i + 12:  # limit lookahead
                    ln2 = lines[j].strip()
                    if not ln2:
                        j += 1
                        continue
                    m_origin = re.match(r'origin\s*=\s*(\S+)', ln2, re.IGNORECASE)
                    if m_origin:
                        primary = m_origin.group(1).rstrip('.')
                        saw_soa_field = True
                    m_mail = re.match(r'(mail addr|responsible mail addr)\s*=\s*(\S+)', ln2, re.IGNORECASE)
                    if m_mail:
                        contact = m_mail.group(2).rstrip('.')
                        saw_soa_field = True
                    m_serial = re.match(r'serial\s*=\s*(\S+)', ln2, re.IGNORECASE)
                    if m_serial:
                        serial = m_serial.group(1)
                        saw_soa_field = True
                    m_refresh = re.match(r'refresh\s*=\s*(\S+)', ln2, re.IGNORECASE)
                    if m_refresh:
                        refresh = m_refresh.group(1)
                        saw_soa_field = True
                    m_retry = re.match(r'retry\s*=\s*(\S+)', ln2, re.IGNORECASE)
                    if m_retry:
                        retry = m_retry.group(1)
                        saw_soa_field = True
                    m_expire = re.match(r'expire\s*=\s*(\S+)', ln2, re.IGNORECASE)
                    if m_expire:
                        expire = m_expire.group(1)
                        saw_soa_field = True
                    m_min = re.match(r'minimum\s*=\s*(\S+)', ln2, re.IGNORECASE)
                    if m_min:
                        minimum = m_min.group(1)
                        saw_soa_field = True
                    j += 1

                if saw_soa_field:
                    domain = domain_candidate
                    break

        # Fallback: attempt to parse compact SOA lines if the above didn't find anything
        if not domain:
            for ln in lines:
                s = ln.strip()
                # compact SOA token line might include 'origin' or 'SOA'
                m_origin = re.search(r'origin\s*=\s*(\S+)', s, re.IGNORECASE)
                if m_origin and not primary:
                    primary = m_origin.group(1).rstrip('.')
                    # try to get domain from nearby Name: or plain domain lines
                m_mail = re.search(r'(mail addr|responsible mail addr)\s*=\s*(\S+)', s, re.IGNORECASE)
                if m_mail and not contact:
                    contact = m_mail.group(2).rstrip('.')
                m_serial = re.search(r'serial\s*=\s*(\S+)', s, re.IGNORECASE)
                if m_serial and not serial:
                    serial = m_serial.group(1)

        # If we found at least one meaningful SOA piece, return a record
        if primary or serial or contact or refresh or retry or expire or minimum:
            return SOARecord(
                domain = domain or "",
                primary_ns = primary,
                contact = contact,
                serial = serial,
                refresh = refresh,
                retry = retry,
                expire = expire,
                minimum = minimum
            )

        return None

    def _extract_error_message(self) -> Optional[str]:
        for line in self.raw_lines:
            line = (line or "").strip()
            low = line.lower()
            if any(x in low for x in ["can't find", "non-existent domain", "refused", "timed out", "server failed", "servfail", "nxdomain"]):
                return line
        return None


    def _is_scan_successful(
        self,
        a_records: List[ARecord],
        aaaa_records: List[AAAARecord],
        mx_records: List[MXRecord],
        ns_records: List[NSRecord],
        txt_records: List[TXTRecord],
        cname_records: List[CNAMERecord],
        soa_record: Optional[SOARecord],
        scan_stats: Optional[Dict[str, Any]] = None
    ) -> bool:
        scan_stats = scan_stats or {}  # <── ADD THIS LINE

        """
        Determine if the nslookup query was successful:
        - If there are parsed records, consider it successful.
        - If there are no records, but there is an explicit NXDOMAIN / can't find error, it's not successful.
        - If there are server/timeout issues in scan_stats, treat as failure.
        """
        # If we found any records -> success
        if any([a_records, aaaa_records, mx_records, ns_records, txt_records, cname_records, soa_record]):
            return True

        # If scan_stats include explicit failure indicators -> not successful
        status = (scan_stats.get('status') or "").lower()
        status_lines = " ".join(scan_stats.get('status_lines', [])).lower()
        if any(token in status for token in ["nxdomain", "refused", "servfail", "notfound", "timed out"]) or any(token in status_lines for token in ["nxdomain", "refused", "servfail", "notfound", "timed out"]):
            return False

        # Check raw output for known fatal messages
        raw = (self.get_raw_output() or "").lower()
        if any(x in raw for x in ["no answer", "connection timed out", "timed out", "refused", "server failed", "can't find"]):
            # If it's one of the above but we still have records, we already returned True earlier.
            return False

        # Default: treat as success if no explicit errors were found (nslookup sometimes returns nothing for legitimate reasons)
        return True

    def _compute_diagnostics(self,
                             records: List[Dict[str, Any]],
                             scan_stats: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """Produce diagnostics for nslookup output using src/nslookup_ruleset.json.

        Expects records as list of dicts/objects with keys like 'name','type','value' (best-effort).
        """
        import os, json, re

        scan_stats = scan_stats or {}
        diags: List[Dict[str, Any]] = []

        # load ruleset (reuse cached self.ruleset if present)
        ruleset = getattr(self, "ruleset", None) or {}
        if not ruleset:
            try:
                candidates = []
                here = os.path.dirname(__file__) if '__file__' in globals() else os.getcwd()
                # try parser dir and rulesets/ subdir nearby
                candidates.append(os.path.join(here, "nslookup_ruleset.json"))
                candidates.append(os.path.join(here, "rulesets", "nslookup_ruleset.json"))
                # parent locations
                candidates.append(os.path.join(here, "..", "nslookup_ruleset.json"))
                candidates.append(os.path.join(here, "..", "rulesets", "nslookup_ruleset.json"))
                # project-level common places
                candidates.append(os.path.join(os.getcwd(), "src", "rulesets", "nslookup_ruleset.json"))
                candidates.append(os.path.join(os.getcwd(), "rulesets", "nslookup_ruleset.json"))
                candidates.append(os.path.join(os.getcwd(), "src", "nslookup_ruleset.json"))
                candidates.append(os.path.join(os.getcwd(), "nslookup_ruleset.json"))
                # environment override
                env_path = os.environ.get("NSLOOKUP_RULESET_PATH") or os.environ.get("DNS_RULESET_PATH")
                if env_path:
                    candidates.insert(0, env_path)
                for p in candidates:
                    try:
                        p = os.path.abspath(p)
                        if os.path.exists(p):
                            with open(p, "r", encoding="utf-8") as fh:
                                ruleset = json.load(fh) or {}
                                self.ruleset = ruleset
                                break
                    except Exception:
                        continue
            except Exception:
                ruleset = {}
        defaults = ruleset.get("defaults", {}) if isinstance(ruleset, dict) else {}

        def add(sev, msg, ctx=None):
            entry = {"severity": sev or defaults.get("severity", "Info"), "message": msg}
            if ctx:
                entry["context"] = ctx
            if entry not in diags:
                diags.append(entry)

        # determine A-record rules (support both "a_rule" and generic "rules")
        a_rules = []
        if isinstance(ruleset, dict):
            a_rules = ruleset.get("a_rule") or []
            # also accept generic rules that target A
            for r in ruleset.get("rules", []) or []:
                if (r.get("record_type") or "").upper() == "A":
                    a_rules.append(r)

        # default A-rule: RFC1918 -> Medium
        if not a_rules:
            a_rules = [{
                "record_type": "A",
                "pattern": r"^(?:10\.|192\.168\.|172\.(?:1[6-9]|2[0-9]|3[0-1])\.)",
                "severity": "Medium",
                "message": "A record resolves to a private IP (RFC1918) — likely internal host leaked or misconfiguration."
            }]

        # normalize records
        normalized: List[Dict[str, str]] = []
        for r in (records or []):
            try:
                rec = {}
                if isinstance(r, dict):
                    rec = r.copy()
                elif hasattr(r, "__dict__"):
                    rec = {k: v for k, v in r.__dict__.items()}
                else:
                    continue
                name = str(rec.get("name") or rec.get("host") or "").rstrip('.').lower()
                rtype = str(rec.get("type") or rec.get("record_type") or "").upper()
                value = str(rec.get("value") or rec.get("rdata") or rec.get("address") or "").strip()
                normalized.append({"name": name, "type": rtype, "value": value, "raw": rec})
            except Exception:
                continue

        # apply A-record rules
        for rule in a_rules:
            rtype_cfg = (rule.get("record_type") or rule.get("type") or "").upper() or "A"
            pattern = rule.get("pattern")
            severity = rule.get("severity") or "Medium"
            message = rule.get("message") or "A record rule matched"
            hosts_filter = [h.lower() for h in (rule.get("hosts") or [])] if rule.get("hosts") else []

            for rec in normalized:
                if rtype_cfg and rtype_cfg != rec["type"]:
                    continue
                if hosts_filter and not any(hf in rec["name"] for hf in hosts_filter):
                    continue
                if pattern:
                    try:
                        if not re.search(pattern, rec["value"], re.IGNORECASE):
                            continue
                    except re.error:
                        # fallback to substring
                        if pattern.lower() not in rec["value"].lower():
                            continue
                # use a shorter context (no leading "record ")
                add(severity, message, f"{rec['name']} -> {rec['value']}")

        # --- MX priority checks using mx_rule from nslookup_ruleset.json ---
        try:
            mx_recs = [r for r in normalized if (r.get("type") or "").upper() == "MX"]
            mx_rules = ruleset.get("mx_rule") if isinstance(ruleset, dict) else []

            same_rule = next((r for r in (mx_rules or []) if (r.get("type") or "").lower() == "same_priority"), None)
            diff_rule = next((r for r in (mx_rules or []) if (r.get("type") or "").lower() == "diff_priority"), None)
            no_mx_rule = next((r for r in (mx_rules or []) if (r.get("type") or "").lower() == "no_mx"), None)

            # Only emit "no mx" diagnostic when the scan was for MX records (or ruleset explicitly allows it).
            scan_type_flag = (scan_stats or {}).get("scan_type", "") or ""
            scan_type_flag = str(scan_type_flag).upper()
            apply_no_mx_globally = bool(ruleset.get("apply_no_mx_for_all", False))

            if not mx_recs:
                if no_mx_rule and (("MX" in scan_type_flag) or apply_no_mx_globally):
                    add(no_mx_rule.get("severity") or "Medium",
                        no_mx_rule.get("message") or "No MX records found — domain may not be configured to receive email.",
                        None)
            elif len(mx_recs) > 1:
                # build mapping: priority (int or None) -> [hosts]
                mx_map: Dict[Optional[int], List[str]] = {}
                for r in mx_recs:
                    raw = r.get("raw") or {}
                    pr = None
                    # try common numeric keys
                    for k in ("priority", "preference", "pref"):
                        try:
                            if isinstance(raw, dict) and k in raw:
                                pr = int(raw.get(k))
                                break
                        except Exception:
                            pr = None
                    # try parse leading number in value like "10 mail.example.com"
                    if pr is None:
                        m = re.match(r'\s*(\d+)\s+(.+)$', r.get("value") or "")
                        if m:
                            try:
                                pr = int(m.group(1))
                            except Exception:
                                pr = None

                    # extract host string
                    host = ""
                    if isinstance(raw, dict):
                        host = (raw.get("exchange") or raw.get("mailserver") or raw.get("host")
                                or raw.get("value") or raw.get("nameserver") or "")
                    if not host:
                        m2 = re.match(r'\s*(?:\d+\s+)?(.+)$', r.get("value") or "")
                        host = m2.group(1).strip() if m2 and m2.group(1) else host
                    host = (host or "<unknown>").strip()

                    mx_map.setdefault(pr, []).append(host)

                unique_priorities = set(mx_map.keys())
                if len(unique_priorities) == 1:
                    # all same priority => load-balanced
                    hosts = [h for hosts in mx_map.values() for h in hosts]
                    sev = (same_rule.get("severity") if same_rule else None) or "Info"
                    msg = (same_rule.get("message") if same_rule else None) or "Emails may be delivered to any of these servers for load balancing."
                    add(sev, msg, ", ".join(hosts))
                else:
                    # different priorities => delivery ordering; lowest numeric value is preferred
                    ordered = sorted(mx_map.items(), key=lambda kv: (kv[0] if kv[0] is not None else 999999))
                    ctx_parts = [f"{p}:{','.join(hosts)}" if p is not None else f"?:{','.join(hosts)}" for p, hosts in ordered]
                    sev = (diff_rule.get("severity") if diff_rule else None) or "Info"
                    msg = (diff_rule.get("message") if diff_rule else None) or "Multiple MX records with different priorities. Emails will be delivered to the lowest-priority server first."
                    add(sev, msg, "; ".join(ctx_parts))
        except Exception:
            # don't let diagnostics parsing break the whole parser
            pass

        # --- TXT rules: detect third-party integrations from TXT values ---
        try:
            txt_rules = ruleset.get("txt_rule", []) if isinstance(ruleset, dict) else []
            if txt_rules:
                for rec in (normalized or []):
                    if (rec.get("type") or "").upper() != "TXT":
                        continue
                    txt_val = str(rec.get("value") or "")
                    if not txt_val:
                        # sometimes raw may contain list of texts
                        raw = rec.get("raw") or {}
                        if isinstance(raw, dict):
                            cand = raw.get("texts") or raw.get("text") or raw.get("values") or raw.get("strings")
                            if isinstance(cand, (list, tuple)):
                                txt_val = " ".join([str(x) for x in cand])
                            elif cand:
                                txt_val = str(cand)
                    for rule in txt_rules:
                        pattern = rule.get("pattern") or rule.get("regex") or rule.get("match")
                        if not pattern:
                            continue
                        try:
                            if re.search(pattern, txt_val, re.IGNORECASE):
                                provider = rule.get("provider") or rule.get("name") or pattern
                                sev = rule.get("severity") or rule.get("level") or "Info"
                                msg = rule.get("message") or f"Third-party integration detected: {provider}"
                                # short context: show domain and provider only
                                ctx = f"{rec.get('name') or '<root>'}, {provider}"
                                add(sev, msg, ctx)
                                # break so same TXT value isn't duplicated by other rules for same provider
                                break
                        except re.error:
                            # fallback to simple substring check
                            try:
                                if pattern.lower() in txt_val.lower():
                                    provider = rule.get("provider") or rule.get("name") or pattern
                                    sev = rule.get("severity") or "Info"
                                    msg = rule.get("message") or f"Third-party integration detected: {provider}"
                                    ctx = f"{rec.get('name') or '<root>'} -> {txt_val[:60].replace('\\n',' ')}"
                                    add(sev, msg, ctx)
                                    break
                            except Exception:
                                continue
        except Exception:
            # non-fatal: do not break diagnostics on TXT scanning errors
            pass

        # --- NS rules: detect common hosting / DNS providers (emit one diag per provider only) ---
        try:
            ns_rules = ruleset.get("ns_rule", []) if isinstance(ruleset, dict) else []
            if ns_rules:
                provider_hosts: Dict[str, set] = {}
                provider_rule_map: Dict[str, Dict[str, Any]] = {}

                for rec in normalized:
                    if (rec.get("type") or "").upper() != "NS":
                        continue
                    ns_val = str(rec.get("value") or "").rstrip('.').lower()
                    if not ns_val:
                        continue
                    for rule in ns_rules:
                        pattern = rule.get("pattern")
                        if not pattern:
                            continue
                        try:
                            if re.search(pattern, ns_val, re.IGNORECASE):
                                provider = rule.get("provider") or rule.get("name") or pattern
                                provider_hosts.setdefault(provider, set()).add(ns_val)
                                # keep a reference to the rule for severity/message
                                provider_rule_map.setdefault(provider, rule)
                                break
                        except re.error:
                            if pattern.lower() in ns_val.lower():
                                provider = rule.get("provider") or rule.get("name") or pattern
                                provider_hosts.setdefault(provider, set()).add(ns_val)
                                provider_rule_map.setdefault(provider, rule)
                                break

                # Emit one diagnostic per matched provider (no duplicates)
                for provider, hosts in provider_hosts.items():
                    rule = provider_rule_map.get(provider, {})
                    sev = rule.get("severity") or "Info"
                    msg = rule.get("message") or f"DNS is hosted by {provider}"
                    # Do not include host list in the diagnostic context — only severity/message
                    add(sev, msg)
        except Exception:
            # non-fatal
            pass

        # --- SOA rules: check refresh/retry/expire/ttl (minimum) against soa_rule entries ---
        try:
            soa_rules = ruleset.get("soa_rule", []) if isinstance(ruleset, dict) else []
            if soa_rules:
                soa_recs = [r for r in normalized if (r.get("type") or "").upper() == "SOA"]
                for rec in soa_recs:
                    raw = rec.get("raw") or {}
                    # get a short identifier for context (avoid dumping full raw record)
                    short_name = rec.get("name") or (raw.get("domain") or raw.get("origin") or "<soa>")
                    for rule in soa_rules:
                        try:
                            field = (rule.get("field") or "").strip().lower()
                            if not field:
                                continue
                            key = "minimum" if field == "ttl" else field
                            # obtain the field value from known keys without exposing full raw
                            val_raw = raw.get(key) or raw.get(field) or raw.get(field.lower())
                            if val_raw is None:
                                continue
                            # parse integer seconds
                            try:
                                val = int(str(val_raw).strip())
                            except Exception:
                                m = re.search(r'(\d+)', str(val_raw))
                                if not m:
                                    continue
                                val = int(m.group(1))
                            thresh = int(rule.get("threshold_seconds") or rule.get("threshold") or 0)
                            cond = (rule.get("condition") or "<").strip()
                            sev = rule.get("severity") or "Medium"
                            msg = rule.get("message") or f"SOA {field} rule matched"
                            # use very short context (field=value) to avoid dumping whole SOA
                            ctx = f"{short_name}: {field}={val}s"
                            if cond == "<" and val < thresh:
                                add(sev, msg, ctx)
                            elif cond == ">" and val > thresh:
                                add(sev, msg, ctx)
                        except Exception:
                            continue
        except Exception:
            pass

        # --- AAAA (IPv6) rules: mirror A-record logic, use "aaaa_rule" or generic rules
        aaaa_rules = []
        if isinstance(ruleset, dict):
            aaaa_rules = ruleset.get("aaaa_rule") or []
            for r in ruleset.get("rules", []) or []:
                if (r.get("record_type") or "").upper() == "AAAA":
                    aaaa_rules.append(r)

        # default AAAA-rule: ULA / link-local / loopback -> Medium
        if not aaaa_rules:
            aaaa_rules = [{
                "record_type": "AAAA",
                "pattern": r"^(?:fc00:|fd00:|fe80:|::1$)",
                "severity": "Medium",
                "message": "AAAA record resolves to a private IPv6 address (ULA/link-local/loopback)."
            }]

        for rule in aaaa_rules:
            rtype_cfg = (rule.get("record_type") or rule.get("type") or "").upper() or "AAAA"
            pattern = rule.get("pattern")
            severity = rule.get("severity") or "Medium"
            message = rule.get("message") or "AAAA record rule matched"
            hosts_filter = [h.lower() for h in (rule.get("hosts") or [])] if rule.get("hosts") else []

            for rec in normalized:
                if rtype_cfg and rtype_cfg != rec["type"]:
                    continue
                if hosts_filter and not any(hf in rec["name"] for hf in hosts_filter):
                    continue
                if pattern:
                    try:
                        if not re.search(pattern, rec["value"], re.IGNORECASE):
                            continue
                    except re.error:
                        if pattern.lower() not in rec["value"].lower():
                            continue
                add(severity, message, f"{rec['name']} -> {rec['value']}")

        return diags

import re
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any
from datetime import datetime
from src.results_parser import ToolResultsParser, ParsedResult

def strip_ansi_codes(text: str) -> str:
    """Remove ANSI color codes and escape sequences from text"""
    if not text:
        return text
    # Remove ANSI escape sequences
    ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
    return ansi_escape.sub('', text)

@dataclass
class DNSRecord:
    """DNS record information"""
    name: str
    record_type: str  # A, AAAA, MX, NS, CNAME, TXT, SOA
    value: str
    ttl: Optional[int] = None
    priority: Optional[int] = None  # For MX records

@dataclass
class SubdomainInfo:
    """Subdomain discovery information"""
    subdomain: str
    ip_addresses: List[str] = field(default_factory=list)
    record_type: str = "A"
    source: str = ""  # brute_force, zone_transfer, reverse_lookup

@dataclass
class NameServerInfo:
    """Name server information"""
    nameserver: str
    ip_address: str = ""
    zone_transfer_possible: bool = False
    bind_version: str = ""

@dataclass
class NetworkInfo:
    """Network and IP range information"""
    ip_range: str
    netblock: str = ""
    asn: str = ""
    organization: str = ""

@dataclass
class DNSEnumResult(ParsedResult):
    """Structured DNSEnum results"""
    target_domain: str = ""
    host_addresses: List[DNSRecord] = field(default_factory=list)
    name_servers: List[NameServerInfo] = field(default_factory=list)
    mail_servers: List[DNSRecord] = field(default_factory=list)
    subdomains: List[SubdomainInfo] = field(default_factory=list)
    dns_records: List[DNSRecord] = field(default_factory=list)  # All other DNS records
    zone_transfers: List[str] = field(default_factory=list)
    reverse_dns: List[str] = field(default_factory=list)
    network_info: List[NetworkInfo] = field(default_factory=list)
    wildcard_info: List[str] = field(default_factory=list)
    total_subdomains: int = 0
    scan_stats: Dict[str, Any] = field(default_factory=dict)
    diagnostics: List[Dict[str, Any]] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        result = super().to_dict()
        result.update({
            "target_domain": self.target_domain,
            "host_addresses": [record.__dict__ for record in self.host_addresses],
            "name_servers": [ns.__dict__ for ns in self.name_servers],
            "mail_servers": [record.__dict__ for record in self.mail_servers],
            "subdomains": [sub.__dict__ for sub in self.subdomains],
            "dns_records": [record.__dict__ for record in self.dns_records],
            "zone_transfers": self.zone_transfers,
            "reverse_dns": self.reverse_dns,
            "network_info": [net.__dict__ for net in self.network_info],
            "wildcard_info": self.wildcard_info,
            "total_subdomains": self.total_subdomains,
            "scan_stats": self.scan_stats
        })
        return result

class DNSEnumResultsParser(ToolResultsParser):
    def __init__(self):
        super().__init__("dnsenum")
        
    def parse(self, target: str) -> DNSEnumResult:
        raw_output = self.get_raw_output()
        # Strip ANSI color codes from the output
        cleaned_output = strip_ansi_codes(raw_output)
        
        host_addresses = []
        name_servers = []
        mail_servers = []
        subdomains = []
        dns_records = []
        zone_transfers = []
        reverse_dns = []
        network_info = []
        wildcard_info = []
        scan_stats = {}
        
        self._parse_host_addresses(host_addresses, cleaned_output)
        self._parse_name_servers(name_servers, cleaned_output)
        self._parse_mail_servers(mail_servers, cleaned_output)
        self._parse_subdomains(subdomains, cleaned_output)
        self._parse_dns_records(dns_records, cleaned_output)
        self._parse_zone_transfers(zone_transfers, name_servers, cleaned_output)
        self._parse_reverse_dns(reverse_dns, cleaned_output)
        self._parse_network_info(network_info, cleaned_output)
        self._parse_wildcard_info(wildcard_info, cleaned_output)
        self._parse_scan_stats(scan_stats, cleaned_output)
        
        total_subdomains = len(subdomains)

        diagnostics = self._compute_diagnostics(host_addresses, name_servers, mail_servers, subdomains, dns_records, zone_transfers, reverse_dns, network_info, wildcard_info, scan_stats)
        
        self._update_scan_stats(scan_stats, diagnostics)
        success = self._is_scan_successful(host_addresses, name_servers, subdomains, scan_stats)
        error_message = self._extract_error_message() if not success else None
        
        return DNSEnumResult(
            tool_name="dnsenum",
            target=target,
            timestamp=datetime.now().isoformat(),
            raw_output=raw_output,
            success=success,
            error_message=error_message,
            target_domain=target,
            host_addresses=host_addresses,
            name_servers=name_servers,
            mail_servers=mail_servers,
            subdomains=subdomains,
            dns_records=dns_records,
            zone_transfers=zone_transfers,
            reverse_dns=reverse_dns,
            network_info=network_info,
            wildcard_info=wildcard_info,
            total_subdomains=total_subdomains,
            scan_stats=scan_stats,
            diagnostics=diagnostics
        )
    
    def _parse_host_addresses(self, host_addresses: List[DNSRecord], raw_output: str):
        """Parse main host addresses (A/AAAA records)"""
        if not raw_output:
            return
            
        lines = raw_output.strip().split('\n')
        in_hosts_section = False
        
        for line in lines:
            line = line.strip()
            
            # Look for "Host's addresses:" section
            if "Host's addresses:" in line or "Host addresses:" in line:
                in_hosts_section = True
                continue
            elif line.startswith("Name Servers:") or line.startswith("Mail (MX) Servers:"):
                in_hosts_section = False
                continue
            
            if in_hosts_section and line:
                # Parse DNS record format: domain.com. 300 IN A 1.2.3.4
                dns_match = re.match(r'^([^\s]+)\.\s+(\d+)?\s*IN\s+([A-Z]+)\s+(.+)$', line)
                if dns_match:
                    domain = dns_match.group(1)
                    ttl = int(dns_match.group(2)) if dns_match.group(2) else None
                    record_type = dns_match.group(3)
                    value = dns_match.group(4).strip()
                    
                    if record_type in ['A', 'AAAA']:
                        host_addresses.append(DNSRecord(
                            name=domain,
                            record_type=record_type,
                            value=value,
                            ttl=ttl
                        ))
    
    def _parse_name_servers(self, name_servers: List[NameServerInfo], raw_output: str):
        """Parse name servers"""
        if not raw_output:
            return
            
        lines = raw_output.strip().split('\n')
        in_ns_section = False
        
        for line in lines:
            line = line.strip()
            
            if "Name Servers:" in line:
                in_ns_section = True
                continue
            elif line.startswith("Mail (MX) Servers:") or "Trying Zone Transfers" in line:
                in_ns_section = False
                continue
            
            if in_ns_section and line:
                # Parse: ns1.example.com. 172800 IN A 1.2.3.4
                dns_match = re.match(r'^([^\s]+)\.\s+(\d+)?\s*IN\s+A\s+(.+)$', line)
                if dns_match:
                    nameserver = dns_match.group(1)
                    ip_address = dns_match.group(3).strip()
                    
                    name_servers.append(NameServerInfo(
                        nameserver=nameserver,
                        ip_address=ip_address
                    ))
    
    def _parse_mail_servers(self, mail_servers: List[DNSRecord], raw_output: str):
        """Parse mail servers (MX records)"""
        if not raw_output:
            return
            
        lines = raw_output.strip().split('\n')
        in_mx_section = False
        
        for line in lines:
            line = line.strip()
            
            if "Mail (MX) Servers:" in line:
                in_mx_section = True
                continue
            elif "Trying Zone Transfers" in line or line.startswith("Brute forcing"):
                in_mx_section = False
                continue
            
            if in_mx_section and line:
                # Check for "No MX records found"
                if "No MX records found" in line:
                    continue
                
                # Parse: domain.com. 300 IN MX 10 mail.example.com
                mx_match = re.match(r'^([^\s]+)\.\s+(\d+)?\s*IN\s+MX\s+(\d+)\s+(.+)$', line)
                if mx_match:
                    domain = mx_match.group(1)
                    ttl = int(mx_match.group(2)) if mx_match.group(2) else None
                    priority = int(mx_match.group(3))
                    value = mx_match.group(4).strip()
                    
                    mail_servers.append(DNSRecord(
                        name=domain,
                        record_type="MX",
                        value=value,
                        ttl=ttl,
                        priority=priority
                    ))
                    continue
                
                # Also parse A records for mail servers (common format)
                # Parse: mx1.hostinger.com. 0 IN A 172.65.182.103
                a_match = re.match(r'^([^\s]+)\.\s+(\d+)?\s*IN\s+A\s+([^\s]+)$', line)
                if a_match:
                    domain = a_match.group(1)
                    ttl = int(a_match.group(2)) if a_match.group(2) else 0
                    ip_address = a_match.group(3).strip()
                    
                    mail_servers.append(DNSRecord(
                        name=domain,
                        record_type="A",
                        value=ip_address,
                        ttl=ttl
                    ))
    
    def _parse_subdomains(self, subdomains: List[SubdomainInfo], raw_output: str):
        """Parse discovered subdomains from brute forcing"""
        if not raw_output:
            return
            
        lines = raw_output.strip().split('\n')
        in_brute_section = False
        
        for line in lines:
            line = line.strip()
            
            # Look for brute force section
            if "Brute forcing with" in line:
                in_brute_section = True
                continue
            elif "Performing reverse lookup" in line or "dnsenum.pl done" in line:
                in_brute_section = False
                continue
            
            if in_brute_section and line:
                # Parse: www.example.com. 300 IN A 1.2.3.4
                subdomain_match = re.match(r'^([^\s]+)\.\s+(\d+)?\s*IN\s+([A-Z]+)\s+(.+)$', line)
                if subdomain_match:
                    subdomain = subdomain_match.group(1)
                    record_type = subdomain_match.group(3)
                    ip_address = subdomain_match.group(4).strip()
                    
                    # Check if subdomain already exists
                    existing = next((s for s in subdomains if s.subdomain == subdomain), None)
                    if existing:
                        if ip_address not in existing.ip_addresses:
                            existing.ip_addresses.append(ip_address)
                    else:
                        subdomains.append(SubdomainInfo(
                            subdomain=subdomain,
                            ip_addresses=[ip_address],
                            record_type=record_type,
                            source="brute_force"
                        ))
    
    def _parse_dns_records(self, dns_records: List[DNSRecord], raw_output: str):
        """Parse additional DNS records (CNAME, TXT, SOA, etc.)"""
        if not raw_output:
            return
            
        lines = raw_output.strip().split('\n')
        
        for line in lines:
            line = line.strip()
            
            # Parse any DNS record format not caught by other methods
            dns_match = re.match(r'^([^\s]+)\.\s+(\d+)?\s*IN\s+([A-Z]+)\s+(.+)$', line)
            if dns_match:
                domain = dns_match.group(1)
                ttl = int(dns_match.group(2)) if dns_match.group(2) else None
                record_type = dns_match.group(3)
                value = dns_match.group(4).strip()
                
                # Only capture records not handled by other methods
                if record_type in ['CNAME', 'TXT', 'SOA', 'PTR', 'SRV']:
                    dns_records.append(DNSRecord(
                        name=domain,
                        record_type=record_type,
                        value=value,
                        ttl=ttl
                    ))
    
    def _parse_zone_transfers(self, zone_transfers: List[str], name_servers: List[NameServerInfo], raw_output: str):
        """Parse zone transfer attempts and results"""
        if not raw_output:
            return
            
        lines = raw_output.strip().split('\n')
        current_ns = None
        
        for line in lines:
            line = line.strip()
            
            # Look for zone transfer attempts
            if "Trying Zone Transfer" in line:
                zone_transfers.append(line)
                # Extract nameserver from line for zone transfer tracking
                for ns in name_servers:
                    if ns.nameserver in line:
                        current_ns = ns
                        if "connection refused" in line or "failed" in line:
                            ns.zone_transfer_possible = False
                        elif "succeeded" in line or "AXFR" in line:
                            ns.zone_transfer_possible = True
            
            # Look for BIND version detection lines
            if "Bind Version for" in line:
                # Extract nameserver from "Bind Version for nameserver:"
                ns_match = re.search(r'Bind Version for ([^:]+):', line)
                if ns_match:
                    ns_name = ns_match.group(1).strip()
                    for ns in name_servers:
                        if ns.nameserver == ns_name:
                            current_ns = ns
                            break
            elif "version.bind:" in line and current_ns:
                # Extract version from "version.bind: version_info"
                version_match = re.search(r'version\.bind:\s*(.+)', line)
                if version_match:
                    current_ns.bind_version = version_match.group(1).strip()
    
    def _parse_reverse_dns(self, reverse_dns: List[str], raw_output: str):
        """Parse reverse DNS lookup results"""
        if not raw_output:
            return
            
        lines = raw_output.strip().split('\n')
        in_reverse_section = False
        
        for line in lines:
            line = line.strip()
            
            if "Performing reverse lookup" in line:
                in_reverse_section = True
                continue
            elif "dnsenum.pl done" in line or line.startswith("Trying to get"):
                in_reverse_section = False
                continue
            
            if in_reverse_section and line:
                # Parse: 1.2.3.4 example.com
                reverse_match = re.match(r'^(\d+\.\d+\.\d+\.\d+)\s+(.+)$', line)
                if reverse_match:
                    ip = reverse_match.group(1)
                    hostname = reverse_match.group(2).strip()
                    reverse_dns.append(f"{ip} -> {hostname}")
    
    def _parse_network_info(self, network_info: List[NetworkInfo], raw_output: str):
        """Parse network and netblock information"""
        if not raw_output:
            return
            
        lines = raw_output.strip().split('\n')
        in_netranges_section = False
        in_ipblocks_section = False
        
        for line in lines:
            line = line.strip()
            
            # Look for class C netranges section
            if "class C netranges:" in line:
                in_netranges_section = True
                in_ipblocks_section = False
                continue
            elif "ip blocks:" in line:
                in_netranges_section = False
                in_ipblocks_section = True
                continue
            elif line.startswith("done."):
                in_netranges_section = False
                in_ipblocks_section = False
                continue
            elif not line or line.startswith("_"):
                # Skip empty lines and underline separators but don't reset flags
                continue
            
            # Parse network ranges and IP blocks
            if (in_netranges_section or in_ipblocks_section) and line:
                # Extract network CIDR (e.g., "18.140.25.0/24" or "18.140.25.243/32")
                network_match = re.search(r'(\d+\.\d+\.\d+\.\d+/\d+)', line)
                if network_match:
                    ip_range = network_match.group(1)
                    netblock_type = "Class C Range" if in_netranges_section else "IP Block"
                    
                    network_info.append(NetworkInfo(
                        ip_range=ip_range,
                        netblock=netblock_type
                    ))
    
    def _parse_wildcard_info(self, wildcard_info: List[str], raw_output: str):
        """Parse wildcard DNS information"""
        if not raw_output:
            return
            
        lines = raw_output.strip().split('\n')
        
        for line in lines:
            line = line.strip()
            
            if "wildcard" in line.lower():
                wildcard_info.append(line)
    
    def _parse_scan_stats(self, scan_stats: Dict[str, Any], raw_output: str):
        """Parse scan statistics and metadata"""
        if not raw_output:
            return
            
        lines = raw_output.strip().split('\n')
        
        for line in lines:
            line = line.strip()
            
            # Extract DNSEnum version
            if "dnsenum VERSION" in line:
                version_match = re.search(r'VERSION:([^\s]+)', line)
                if version_match:
                    scan_stats['dnsenum_version'] = version_match.group(1)
            
            # Extract completion status
            if "dnsenum.pl done" in line or line == "done.":
                scan_stats['scan_completed'] = True
            
            # Extract brute force wordlist info
            if "Brute forcing with" in line:
                wordlist_match = re.search(r'with\s+([^\s:]+)', line)
                if wordlist_match:
                    scan_stats['wordlist_used'] = wordlist_match.group(1)
            
            # Count reverse lookup attempts
            if "reverse lookup on" in line:
                count_match = re.search(r'on\s+(\d+)\s+ip', line)
                if count_match:
                    scan_stats['reverse_lookup_count'] = int(count_match.group(1))
    
    def _compute_diagnostics(
        self,
        host_addresses: List[DNSRecord],
        name_servers: List[NameServerInfo],
        mail_servers: List[DNSRecord],
        subdomains: List[SubdomainInfo],
        dns_records: List[DNSRecord],
        zone_transfers: List[str],
        reverse_dns: List[str],
        network_info: List[NetworkInfo],
        wildcard_info: List[str],
        scan_stats: Optional[Dict[str, Any]] = None,
    ) -> List[Dict[str, Any]]:
        import os, json, re

        scan_stats = scan_stats or {}
        diags: List[Dict[str, Any]] = []

        # load ruleset (try multiple locations and cache on self.ruleset)
        ruleset = getattr(self, "ruleset", None) or {}
        if not ruleset:
            try:
                candidates = []
                here = os.path.dirname(__file__) if '__file__' in globals() else os.getcwd()
                # same directory as parser
                candidates.append(os.path.join(here, "dnsenum_ruleset.json"))
                # rulesets subdir next to parser
                candidates.append(os.path.join(here, "rulesets", "dnsenum_ruleset.json"))
                # parent directory and its rulesets/
                candidates.append(os.path.join(here, "..", "dnsenum_ruleset.json"))
                candidates.append(os.path.join(here, "..", "rulesets", "dnsenum_ruleset.json"))
                # project-level locations
                candidates.append(os.path.join(os.getcwd(), "src", "rulesets", "dnsenum_ruleset.json"))
                candidates.append(os.path.join(os.getcwd(), "rulesets", "dnsenum_ruleset.json"))
                candidates.append(os.path.join(os.getcwd(), "src", "dnsenum_ruleset.json"))
                candidates.append(os.path.join(os.getcwd(), "dnsenum_ruleset.json"))
                # environment override
                env_path = os.environ.get("DNSENUM_RULESET_PATH")
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

        # --- host addresses aggregation (hostname -> set(IPs)) ---
        by_name: Dict[str, set] = {}
        for h in (host_addresses or []):
            try:
                rec = h if isinstance(h, dict) else (h.__dict__ if hasattr(h, "__dict__") else {})
                name = (rec.get("name") or rec.get("host") or rec.get("hostname") or "").rstrip('.').lower()
                ip = rec.get("ip") or rec.get("address") or rec.get("value") or rec.get("target") or ""
                ip = str(ip).strip()
                if not name or not ip:
                    continue
                by_name.setdefault(name, set()).add(ip)
            except Exception:
                continue

        # host_addresses_rule (existing default behavior)
        host_rules = ruleset.get("host_addresses_rule", []) if isinstance(ruleset, dict) else []
        if not host_rules:
            host_rules = [{"type": "multiple_a", "min_count": 2, "hosts": [], "severity": "Info",
                           "message": "Traffic may be spread across servers or through a content delivery network"}]
        for rule in host_rules:
            rtype = (rule.get("type") or "").lower()
            if rtype != "multiple_a":
                continue
            min_count = int(rule.get("min_count") or 2)
            hosts_filter = [h.lower() for h in (rule.get("hosts") or [])]
            severity = rule.get("severity") or "Info"
            message = rule.get("message") or "Multiple addresses detected for host"
            for name, ips in by_name.items():
                if hosts_filter and not any(f in name for f in hosts_filter):
                    continue
                if len(ips) >= max(2, min_count):
                    add(severity, message, f"host {name} (IPs: {', '.join(sorted(ips))})")

        # --- name server checks ---
        ns_rules = ruleset.get("name_servers_rule", []) if isinstance(ruleset, dict) else []

        # Collect IPv6 addresses from name_servers entries (best-effort)
        ipv6_addrs = set()
        normalized_ns_names = []
        for ns in (name_servers or []):
            try:
                rec = ns if isinstance(ns, dict) else (ns.__dict__ if hasattr(ns, "__dict__") else {})
                ns_name = (rec.get("name") or rec.get("host") or rec.get("hostname") or rec.get("ns") or "").rstrip('.').lower()
                normalized_ns_names.append(ns_name)
                # common fields that may contain addresses
                vals = []
                for k in ("ip", "address", "value", "target", "ipv6", "aaaa", "addresses"):
                    v = rec.get(k) if isinstance(rec, dict) else None
                    if v:
                        if isinstance(v, (list, tuple, set)):
                            vals.extend([str(x) for x in v])
                        else:
                            vals.append(str(v))
                # also consider 'type' == 'AAAA' with 'value'
                if rec.get("type", "").upper() == "AAAA" and rec.get("value"):
                    vals.append(str(rec.get("value")))
                for vv in vals:
                    if ":" in vv:  # crude IPv6 detection
                        ipv6_addrs.add(vv)
            except Exception:
                continue

        # Apply ipv6_missing rule: trigger if no ipv6 addresses observed among name servers
        for rule in ns_rules:
            rtype = (rule.get("type") or "").lower()
            if rtype == "ipv6_missing":
                severity = rule.get("severity") or "Medium"
                message = rule.get("message") or "No IPv6 name server records found"
                if not ipv6_addrs:
                    add(severity, message, f"name_servers: {', '.join([n for n in normalized_ns_names if n]) or 'none'}")
            elif rtype in ("zone_transfer_open", "zone_transfer_blocked"):
                # zone transfer rules handled below
                continue

        # --- zone transfer checks ---
        zt_rule_open = next((r for r in ns_rules if (r.get("type") or "").lower() == "zone_transfer_open"), None)
        zt_rule_blocked = next((r for r in ns_rules if (r.get("type") or "").lower() == "zone_transfer_blocked"), None)

        # build short context from normalized name-server names (used inside parentheses)
        ns_list = [n for n in normalized_ns_names if n]
        ns_ctx = ", ".join(ns_list) if ns_list else None

        # Determine zone transfer outcome:
        # - treat as OPEN only if at least one name-server was marked as zone_transfer_possible == True
        # - if attempts were made but none succeeded -> "attempted but blocked"
        # - if no attempts observed -> informational "no attempts"
        any_open = any(getattr(ns, "zone_transfer_possible", False) for ns in (name_servers or []))
        any_attempts = bool(zone_transfers and len(zone_transfers) > 0)

        if any_open:
            # at least one NS reported AXFR / success
            if zt_rule_open:
                add(zt_rule_open.get("severity") or "High",
                    zt_rule_open.get("message") or "Zone transfer open",
                    ns_ctx)
            else:
                add("High",
                    "Zone transfer open — allows anyone to view full DNS zone; should be restricted to trusted servers only.",
                    ns_ctx)
        elif any_attempts:
            # attempts were made but no successful AXFR observed
            if zt_rule_blocked:
                add(zt_rule_blocked.get("severity") or "Info",
                    zt_rule_blocked.get("message") or "Zone transfer appears blocked",
                    ns_ctx)
            else:
                add("Info", "Zone transfer attempted but no AXFR results (blocked or restricted)", ns_ctx)
        else:
            # no zone transfer attempts detected in output
            add("Info", "No zone transfer attempts observed", ns_ctx)

        # --- (existing) optional checks can follow: AXFR detection in dns_records, wildcard, version rules etc. ---
        return diags

    def _update_scan_stats(self, scan_stats: Dict[str, Any], diagnostics: Optional[List[Dict[str, Any]]]) -> None:
        """Update scan_stats with a minimal diagnostics summary to avoid AttributeError from callers."""
        try:
            if scan_stats is None:
                return
            diagnostics = diagnostics or []
            scan_stats.setdefault("meta", {})
            scan_stats["meta"]["diagnostics_count"] = len(diagnostics)
            # counts by severity
            sev_counts: Dict[str, int] = {}
            for d in diagnostics:
                sev = (d.get("severity") or "Info")
                sev_norm = str(sev).title()
                sev_counts[sev_norm] = sev_counts.get(sev_norm, 0) + 1
            scan_stats["meta"]["diagnostics_by_severity"] = sev_counts
        except Exception:
            # Don't raise from this helper; it's observational only.
            pass

    def _is_scan_successful(
        self,
        host_addresses: List[DNSRecord],
        name_servers: List[NameServerInfo],
        subdomains: List[SubdomainInfo],
        scan_stats: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """Heuristic: consider the scan successful if it completed or returned any findings."""
        try:
            scan_stats = scan_stats or {}
            # If scan explicitly marked incomplete, treat as failure
            if isinstance(scan_stats, dict) and scan_stats.get("scan_completed") is False:
                return False
            # If we discovered anything, treat as success
            if host_addresses or name_servers or subdomains:
                return True
            # Fallback: if scan reports completion flag, treat as success even if empty
            if isinstance(scan_stats, dict) and scan_stats.get("scan_completed") is True:
                return True
        except Exception:
            pass
        return False

    def _extract_error_message(self) -> Optional[str]:
        """Best-effort extraction of a failure message from raw output (non-fatal)."""
        try:
            raw = self.get_raw_output() or ""
            if not raw:
                return None
            # look for obvious error lines
            for line in (raw.splitlines() or []):
                l = line.strip()
                if not l:
                    continue
                if l.lower().startswith("error") or "failed" in l.lower() or "exception" in l.lower():
                    return l
            return None
        except Exception:
            return None
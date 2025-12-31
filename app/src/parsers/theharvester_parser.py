import re
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any
from datetime import datetime
from src.results_parser import ToolResultsParser, ParsedResult


@dataclass
class EmailInfo:
    """Email address information"""

    email: str
    source: str = ""
    confidence: str = ""


@dataclass
class HostInfo:
    """Host/subdomain information"""

    hostname: str
    ip: str = ""
    source: str = ""


@dataclass
class URLInfo:
    """URL information"""

    url: str
    source: str = ""


@dataclass
class PersonInfo:
    """Person/social media information"""

    name: str
    platform: str = ""
    profile_url: str = ""
    source: str = ""


@dataclass
class TheHarvesterResult(ParsedResult):
    """Structured theHarvester results"""

    domain: str = ""
    source_engine: str = ""
    emails: List[EmailInfo] = field(default_factory=list)
    hosts: List[HostInfo] = field(default_factory=list)
    urls: List[URLInfo] = field(default_factory=list)
    people: List[PersonInfo] = field(default_factory=list)
    total_results: int = 0
    scan_stats: Dict[str, Any] = field(default_factory=dict)
    diagnostics: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        result = super().to_dict()
        result.update(
            {
                "domain": self.domain,
                "source_engine": self.source_engine,
                "emails": [email.__dict__ for email in self.emails],
                "hosts": [host.__dict__ for host in self.hosts],
                "urls": [url.__dict__ for url in self.urls],
                "people": [person.__dict__ for person in self.people],
                "total_results": self.total_results,
                "scan_stats": self.scan_stats,
            }
        )
        result["diagnostics"] = [d.copy() for d in (self.diagnostics or [])]
        return result


class TheHarvesterParser(ToolResultsParser):
    """Parser for theHarvester output"""

    def __init__(self):
        super().__init__("theharvester")

    def parse(self, target: str) -> TheHarvesterResult:
        raw_output = self.get_raw_output()
        emails = []
        hosts = []
        urls = []
        people = []
        scan_stats = {}
        source_engine = ""

        # Extract source engine from command or output
        source_engine = self._extract_source_engine()

        # Parse different sections of theHarvester output
        self._parse_emails(emails, raw_output)
        self._parse_hosts(hosts, raw_output)
        self._parse_urls(urls, raw_output)
        self._parse_people(people, raw_output)
        self._parse_scan_stats(scan_stats, raw_output)

        total_results = len(emails) + len(hosts) + len(urls) + len(people)

        success = self._is_scan_successful(emails, hosts, urls, people, scan_stats)
        error_message = self._extract_error_message() if not success else None

        result = TheHarvesterResult(
            tool_name="theharvester",
            target=target,
            timestamp=datetime.now().isoformat(),
            raw_output=raw_output,
            success=success,
            error_message=error_message,
            domain=target,
            source_engine=source_engine,
            emails=emails,
            hosts=hosts,
            urls=urls,
            people=people,
            total_results=total_results,
            scan_stats=scan_stats,
        )
        # attach diagnostics computed from discovered hosts vs hostname_rule
        try:
            result.diagnostics = self._compute_diagnostics(
                result.hosts, {"raw_output": raw_output}
            )
        except Exception:
            result.diagnostics = []

        return result

    def _extract_source_engine(self) -> str:
        """Extract the source engine used for the scan"""
        raw_output = self.get_raw_output()
        if not raw_output:
            return ""

        lines = raw_output.strip().split("\n")

        for line in lines:
            # Look for command line or source indication
            if "-b" in line and "python" in line:
                # Extract from command line
                match = re.search(r"-b\s+(\w+)", line)
                if match:
                    return match.group(1)

            # Look for source mentions in output
            if "Searching" in line and "results" in line:
                # Format: "Searching 100 results from bing"
                match = re.search(r"from\s+(\w+)", line)
                if match:
                    return match.group(1)

        return "unknown"

    def _parse_emails(self, emails: List[EmailInfo], raw_output: str):
        """Parse email addresses from theHarvester output"""
        if not raw_output:
            return

        lines = raw_output.strip().split("\n")
        in_emails_section = False

        for line in lines:
            line = line.strip()

            # Section headers for emails (case insensitive)
            if "[*] emails found:" in line.lower():
                in_emails_section = True
                continue
            elif line.startswith("[*]") and "emails found:" not in line.lower():
                in_emails_section = False
                continue

            # Parse email addresses only in emails section
            if in_emails_section and "@" in line and not line.startswith("*"):
                # Extract email addresses from the line, but skip banner/header content
                if not any(
                    skip in line.lower()
                    for skip in ["coded by", "edge-security", "theharvester", "*"]
                ):
                    email_pattern = (
                        r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"
                    )
                    matches = re.findall(email_pattern, line)

                    for email in matches:
                        # Skip if already found
                        if not any(e.email == email for e in emails):
                            emails.append(
                                EmailInfo(
                                    email=email,
                                    source=self._extract_source_from_line(line),
                                )
                            )

    def _parse_hosts(self, hosts: List[HostInfo], raw_output: str):
        """Parse hostnames/subdomains from theHarvester output"""
        if not raw_output:
            return

        lines = raw_output.strip().split("\n")
        in_hosts_section = False

        for line in lines:
            line = line.strip()

            # Section headers - look for "Hosts found:" with count (case insensitive)
            if "[*] hosts found:" in line.lower():
                in_hosts_section = True
                continue
            elif line.startswith("[*]") and not any(
                host_keyword in line.lower() for host_keyword in ["hosts", "virtual"]
            ):
                in_hosts_section = False
                continue

            # Parse hostnames only in hosts section
            if in_hosts_section and line:
                # Skip separator lines like "---------------------"
                if "-" in line and len(set(line)) <= 2:
                    continue

                # Skip non-hostname lines (banner, messages, etc.)
                if any(
                    skip in line.lower()
                    for skip in [
                        "read ",
                        "searching",
                        "theharvester",
                        "coded by",
                        "edge-security",
                        "*",
                        "scan completed",
                        "api-keys",
                        "proxies",
                        "results",
                    ]
                ):
                    continue

                # Handle format: "subdomain.example.com" or "subdomain.example.com:192.168.1.1"
                if ":" in line:
                    # Format: hostname:ip
                    parts = line.split(":")
                    hostname = parts[0].strip()
                    ip = parts[1].strip() if len(parts) > 1 else ""
                else:
                    # Format: just hostname
                    hostname = line.strip()
                    ip = ""

                # Validate it's a proper hostname (must have domain extension and no spaces)
                if (
                    "." in hostname
                    and len(hostname) > 3
                    and " " not in hostname
                    and not hostname.startswith(".")
                    and not hostname.endswith(".")
                    and hostname.count(".") >= 1
                    and not any(
                        char in hostname for char in ["*", "/", "\\", " ", "\t"]
                    )
                ):
                    # Must end with a valid TLD-like extension
                    parts = hostname.split(".")
                    if len(parts) >= 2 and len(parts[-1]) >= 2 and parts[-1].isalpha():
                        # Skip if already found
                        if not any(h.hostname == hostname for h in hosts):
                            hosts.append(
                                HostInfo(
                                    hostname=hostname,
                                    ip=ip,
                                    source=self._extract_source_from_line(line),
                                )
                            )

    def _parse_urls(self, urls: List[URLInfo], raw_output: str):
        """Parse URLs from theHarvester output"""
        if not raw_output:
            return

        lines = raw_output.strip().split("\n")
        in_urls_section = False

        for line in lines:
            line = line.strip()

            # Section headers
            if (
                "[*] urls found:" in line.lower()
                or "[*] interesting urls found:" in line.lower()
            ):
                in_urls_section = True
                continue
            elif line.startswith("[*]") and "url" not in line.lower():
                in_urls_section = False
                continue

            # Parse URLs
            if in_urls_section or line.startswith("http"):
                # Extract URLs
                url_pattern = r'https?://[^\s<>"]+|www\.[^\s<>"]+'
                matches = re.findall(url_pattern, line)

                for url in matches:
                    # Skip if already found
                    if not any(u.url == url for u in urls):
                        urls.append(
                            URLInfo(
                                url=url, source=self._extract_source_from_line(line)
                            )
                        )

    def _parse_people(self, people: List[PersonInfo], raw_output: str):
        """Parse people/contacts from theHarvester output"""
        if not raw_output:
            return

        lines = raw_output.strip().split("\n")
        in_people_section = False

        for line in lines:
            line = line.strip()

            # Section headers
            if any(
                header in line.lower()
                for header in [
                    "[*] people found:",
                    "[*] users found:",
                    "[*] profiles found:",
                ]
            ):
                in_people_section = True
                continue
            elif line.startswith("[*]") and not any(
                word in line.lower() for word in ["people", "user", "profile"]
            ):
                in_people_section = False
                continue

            # Parse people information
            if (
                in_people_section
                and line
                and not line.startswith("-")
                and not line.startswith("[*]")
            ):
                # Clean the line
                cleaned_line = line.strip()

                if cleaned_line:
                    # Try to extract proper names (e.g., "John Doe")
                    name_pattern = r"([A-Z][a-z]+\s+[A-Z][a-z]+)"
                    name_matches = re.findall(name_pattern, line)

                    for name in name_matches:
                        if not any(p.name == name for p in people):
                            people.append(
                                PersonInfo(
                                    name=name,
                                    source=self._extract_source_from_line(line),
                                )
                            )

                    # If no proper names found, treat the whole line as a username/handle
                    if (
                        not name_matches
                        and len(cleaned_line) > 2
                        and " " not in cleaned_line
                    ):
                        # Skip if already found
                        if not any(p.name == cleaned_line for p in people):
                            people.append(
                                PersonInfo(
                                    name=cleaned_line,
                                    source=self._extract_source_from_line(line),
                                )
                            )

    def _parse_scan_stats(self, scan_stats: Dict[str, Any], raw_output: str):
        """Parse scan statistics from theHarvester output"""
        if not raw_output:
            return

        lines = raw_output.strip().split("\n")

        for line in lines:
            line = line.strip()

            # Extract search limits
            if "Searching" in line and "results" in line:
                # Format: "Searching 100 results from bing"
                limit_match = re.search(r"Searching\s+(\d+)\s+results", line)
                if limit_match:
                    scan_stats["search_limit"] = int(limit_match.group(1))

                source_match = re.search(r"from\s+(\w+)", line)
                if source_match:
                    scan_stats["source_engine"] = source_match.group(1)

            # Extract timing information
            if "done:" in line.lower() or "finished" in line.lower():
                # Try to extract timing info if present
                time_match = re.search(r"(\d+(?:\.\d+)?)\s*(?:seconds?|s)\b", line)
                if time_match:
                    scan_stats["scan_time"] = float(time_match.group(1))

            # Extract error information
            if "error" in line.lower() or "failed" in line.lower():
                scan_stats["errors"] = scan_stats.get("errors", []) + [line]

    def _extract_source_from_line(self, line: str) -> str:
        """Extract source information from a result line"""
        # theHarvester might include source information in the line
        # This is a placeholder - adjust based on actual theHarvester output format
        return ""

    def _is_scan_successful(
        self,
        emails: List[EmailInfo],
        hosts: List[HostInfo],
        urls: List[URLInfo],
        people: List[PersonInfo],
        scan_stats: Dict[str, Any],
    ) -> bool:
        """Determine if the theHarvester scan was successful"""

        # If we found any results, consider it successful
        if emails or hosts or urls or people:
            return True

        # Check for explicit errors
        if scan_stats.get("errors"):
            return False

        # Check for common error patterns in raw output
        raw_output = self.get_raw_output().lower()
        error_indicators = [
            "invalid source",
            "connection failed",
            "timeout",
            "error:",
            "failed to",
            "permission denied",
            "not supported",
        ]

        if any(indicator in raw_output for indicator in error_indicators):
            return False

        # If no results but no explicit errors, consider it a successful scan with no results
        return True

    def _extract_error_message(self) -> Optional[str]:
        """Extract error message from theHarvester output"""
        raw_output = self.get_raw_output()
        if not raw_output:
            return None

        lines = raw_output.strip().split("\n")

        for line in lines:
            line = line.strip()

            # Look for explicit error messages
            if any(
                keyword in line.lower()
                for keyword in ["error:", "[!]", "invalid", "failed", "timeout"]
            ):
                return line

            # Look for theHarvester-specific errors
            if "not supported" in line.lower() or "source" in line.lower():
                return line

        return None

    def _compute_diagnostics(
        self, findings: List[HostInfo], scan_stats: Optional[Dict[str, Any]] = None
    ) -> List[Dict[str, Any]]:
        """
        Compare discovered hosts (HostInfo list) against hostname_rule entries in
        rulesets/theharvester_ruleset.json and return diagnostics.
        """
        import os, json, re

        scan_stats = scan_stats or {}
        diags: List[Dict[str, Any]] = []

        # load/cached ruleset
        ruleset = getattr(self, "theharvester_ruleset", None) or {}
        if not ruleset:
            try:
                here = (
                    os.path.dirname(__file__)
                    if "__file__" in globals()
                    else os.getcwd()
                )
                candidates = [
                    os.path.join(here, "theharvester_ruleset.json"),
                    os.path.join(here, "rulesets", "theharvester_ruleset.json"),
                    os.path.join(os.getcwd(), "rulesets", "theharvester_ruleset.json"),
                ]
                for p in candidates:
                    try:
                        p = os.path.abspath(p)
                        if os.path.exists(p):
                            with open(p, "r", encoding="utf-8") as fh:
                                ruleset = json.load(fh) or {}
                                self.theharvester_ruleset = ruleset
                                break
                    except Exception:
                        continue
            except Exception:
                ruleset = {}
        defaults = ruleset.get("defaults", {}) if isinstance(ruleset, dict) else {}

        def add(sev, msg, ctx=None, insight=None, remediation=None):
            entry = {
                "severity": sev or defaults.get("severity", "Info"),
                "message": msg,
            }
            if ctx:
                entry["context"] = ctx
            # support rule-specific insight/remediation with fallback to defaults
            ins = insight if insight is not None else defaults.get("insight")
            rem = (
                remediation if remediation is not None else defaults.get("remediation")
            )
            if ins:
                entry["insight"] = ins
            if rem:
                entry["remediation"] = rem
            if entry not in diags:
                diags.append(entry)

        def matches(pattern: str, text: str) -> bool:
            try:
                return bool(re.search(pattern, text or "", re.IGNORECASE))
            except re.error:
                return pattern.lower() in (text or "").lower()

        hostname_rules = []
        if isinstance(ruleset, dict):
            hostname_rules = ruleset.get("hostname_rule") or []

        # normalize hostnames from findings
        hostnames = []
        for h in findings or []:
            try:
                hn = (
                    h.hostname
                    if hasattr(h, "hostname")
                    else (h.get("hostname") if isinstance(h, dict) else None)
                )
                if hn:
                    hostnames.append(str(hn).strip())
            except Exception:
                continue

        if not hostnames or not hostname_rules:
            return diags

        # evaluate each rule against hostnames
        for rule in hostname_rules:
            pattern = (
                rule.get("pattern") or rule.get("regex") or rule.get("match") or ""
            )
            if not pattern:
                continue
            severity = rule.get("severity") or defaults.get("severity") or "Info"
            message = rule.get("message") or f"Hostname rule matched: {pattern}"
            insight = rule.get("insight")
            remediation = rule.get("remediation")
            for hn in hostnames:
                try:
                    if matches(pattern, hn):
                        add(severity, message, f"host: {hn}", insight, remediation)
                except Exception:
                    continue

        return diags

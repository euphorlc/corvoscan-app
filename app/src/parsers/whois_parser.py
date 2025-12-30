import re
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any
from datetime import datetime
from src.results_parser import ToolResultsParser, ParsedResult


@dataclass
class ContactInfo:
    """Contact information from Whois data"""

    name: str = ""
    organization: str = ""
    address: str = ""
    city: str = ""
    state: str = ""
    postal_code: str = ""
    country: str = ""
    phone: str = ""
    email: str = ""


@dataclass
class DomainInfo:
    """Domain-specific Whois information"""

    domain_name: str = ""
    registry_domain_id: str = ""
    registrar: str = ""
    registrar_whois_server: str = ""
    registrar_url: str = ""
    creation_date: str = ""
    updated_date: str = ""
    expiry_date: str = ""
    domain_status: List[str] = None
    name_servers: List[str] = None
    dnssec: str = ""
    registrant_contact: ContactInfo = None
    admin_contact: ContactInfo = None
    tech_contact: ContactInfo = None
    additional_info: Dict[str, str] = None

    def __post_init__(self):
        if self.domain_status is None:
            self.domain_status = []
        if self.name_servers is None:
            self.name_servers = []
        if self.registrant_contact is None:
            self.registrant_contact = ContactInfo()
        if self.admin_contact is None:
            self.admin_contact = ContactInfo()
        if self.tech_contact is None:
            self.tech_contact = ContactInfo()
        if self.additional_info is None:
            self.additional_info = {}


@dataclass
class NetworkInfo:
    """Network/IP-specific Whois information"""

    net_range: str = ""
    cidr: str = ""
    net_name: str = ""
    net_handle: str = ""
    parent: str = ""
    net_type: str = ""
    origin_as: str = ""
    organization: str = ""
    reg_date: str = ""
    updated: str = ""
    address: str = ""
    city: str = ""
    state: str = ""
    postal_code: str = ""
    country: str = ""
    abuse_contacts: List[str] = None
    tech_contacts: List[str] = None

    def __post_init__(self):
        if self.abuse_contacts is None:
            self.abuse_contacts = []
        if self.tech_contacts is None:
            self.tech_contacts = []


@dataclass
class WhoisResult(ParsedResult):
    """Structured Whois results"""

    query_type: str = ""  # "domain" or "ip"
    domain_info: Optional[DomainInfo] = None
    network_info: Optional[NetworkInfo] = None
    raw_registrar_data: str = ""
    additional_info: Dict[str, str] = None
    diagnostics: List[Dict[str, Any]] = field(default_factory=list)

    def __post_init__(self):
        if self.additional_info is None:
            self.additional_info = {}

    def to_dict(self) -> Dict[str, Any]:
        result = super().to_dict()
        if self.domain_info:
            result["domain_info"] = self.domain_info.__dict__.copy()
            result["domain_info"]["registrant_contact"] = (
                self.domain_info.registrant_contact.__dict__
            )
            result["domain_info"]["admin_contact"] = (
                self.domain_info.admin_contact.__dict__
            )
            result["domain_info"]["tech_contact"] = (
                self.domain_info.tech_contact.__dict__
            )
        if self.network_info:
            result["network_info"] = self.network_info.__dict__
        result["diagnostics"] = [d.copy() for d in (self.diagnostics or [])]
        return result


class WhoisParser(ToolResultsParser):
    """Parser for Whois output"""

    def __init__(self):
        super().__init__("whois")

    def parse(self, target: str) -> WhoisResult:
        """Parse Whois output for domain or IP"""
        raw_output = self.get_raw_output()

        # Skip parsing if we have no meaningful content
        if not raw_output.strip() or len(self.raw_lines) < 3:
            return WhoisResult(
                tool_name=self.tool_name,
                target=target,
                timestamp=datetime.now().isoformat(),
                raw_output=raw_output,
                query_type="unknown",
                success=False,
                error_message="No whois data available",
            )

        # Check if this is RPSL format (RIPE database)
        is_rpsl = (
            "% This is the RIPE Database" in raw_output
            or "inet-rtr:" in raw_output
            or "inetnum:" in raw_output
            or "organisation:" in raw_output
            or "% [whois.apnic.net]" in raw_output
            or "% IANA WHOIS server" in raw_output
        )

        # Determine if target is IP or domain
        is_ip = self._is_ip_address(target)
        query_type = "ip" if is_ip else "domain"

        if self._has_errors():
            return WhoisResult(
                tool_name=self.tool_name,
                target=target,
                timestamp=datetime.now().isoformat(),
                raw_output=raw_output,
                query_type=query_type,
                success=False,
                error_message=self._extract_error_message(),
            )

        # Handle RPSL format (from -B or -r flags)
        if is_rpsl:
            domain_info = self._parse_rpsl_format()
            result = WhoisResult(
                tool_name=self.tool_name,
                target=target,
                timestamp=datetime.now().isoformat(),
                raw_output=raw_output,
                query_type=query_type,
                domain_info=domain_info,
                success=True,
            )
            try:
                result.diagnostics = self._compute_diagnostics(
                    {"registrar": getattr(domain_info, "registrar", "")},
                    {"raw_output": raw_output},
                )
            except Exception:
                result.diagnostics = []
            return result

        if is_ip:
            network_info = self._parse_ip_whois()
            result = WhoisResult(
                tool_name=self.tool_name,
                target=target,
                timestamp=datetime.now().isoformat(),
                raw_output=raw_output,
                query_type=query_type,
                network_info=network_info,
                success=True,
            )
            # no registrar for IP lookups but still allow ruleset fallbacks if needed
            try:
                result.diagnostics = self._compute_diagnostics(
                    None, {"raw_output": raw_output}
                )
            except Exception:
                result.diagnostics = []
            return result
        else:
            domain_info = self._parse_domain_whois()
            result = WhoisResult(
                tool_name=self.tool_name,
                target=target,
                timestamp=datetime.now().isoformat(),
                raw_output=raw_output,
                query_type=query_type,
                domain_info=domain_info,
                success=True,
            )
            try:
                result.diagnostics = self._compute_diagnostics(
                    {"registrar": getattr(domain_info, "registrar", "")},
                    {"raw_output": raw_output},
                )
            except Exception:
                result.diagnostics = []
            return result

    def _is_ip_address(self, target: str) -> bool:
        """Check if target is an IP address"""
        ip_pattern = r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
        return bool(re.match(ip_pattern, target))

    def _has_errors(self) -> bool:
        """Check for Whois errors"""
        error_indicators = [
            "No whois server is known",
            "No entries found",
            "No match for",
            "Not found",
            "No data found",
            "connection timed out",
            "ERROR:",
            "WHOIS LIMIT EXCEEDED",
            "No such domain",
            "Domain not found",
            "This query looks like a domain name",  # ARIN specific
        ]
        output = self.get_raw_output().lower()

        # Don't treat RIPE/RPSL format as error
        if "% This is the RIPE Database" in self.get_raw_output():
            return False

        return any(indicator.lower() in output for indicator in error_indicators)

    def _extract_error_message(self) -> Optional[str]:
        """Extract error message from output and provide user-friendly message"""
        output = self.get_raw_output()

        # Check for specific error patterns and return cleaner messages
        if (
            "%ERROR:101: no entries found" in output
            or "no entries found" in output.lower()
        ):
            # Extract which sources were searched
            if "source APNIC" in output:
                return "No records found in APNIC database (Asia Pacific region). This target may not be registered in this region."
            elif "source AFRINIC" in output:
                return "No records found in AFRINIC database (Africa region). This target may not be registered in this region."
            elif "source LACNIC" in output:
                return "No records found in LACNIC database (Latin America region). This target may not be registered in this region."
            elif "source RIPE" in output:
                return "No records found in RIPE database (Europe region). This target may not be registered in this region."
            else:
                return "No records found in whois database for this query."

        if "No match for" in output or "No match found for" in output:
            # ARIN and LACNIC style
            if "ARIN WHOIS" in output:
                return "No match found in ARIN database. Note: ARIN handles IP addresses/networks, not domain names. Try querying with an IP address instead."
            else:
                return "No matching records found for this query in the selected whois server."

        if "% This query looks like a domain name" in output:
            return "The whois server expects an IP address or network, not a domain name. Please resolve the domain to an IP first or use a different whois server."

        # Extract first actual error line for other cases
        for line in self.raw_lines:
            line = line.strip()
            if any(
                error in line.lower()
                for error in [
                    "no whois server",
                    "connection timed out",
                    "error:",
                    "whois limit exceeded",
                    "no such domain",
                    "domain not found",
                ]
            ):
                return line

        return "Whois lookup failed - no data returned from server."

    def _parse_domain_whois(self) -> DomainInfo:
        """Parse domain Whois information - handles multi-section whois output"""
        domain_info = DomainInfo()
        current_contact = None

        # Process all lines and take the most recent/complete information
        # Handle cases where multiple fields are concatenated in single lines
        all_field_lines = []

        for line in self.raw_lines:
            # Skip debug and completion messages
            if line.strip().startswith("DEBUG") or "[SCAN COMPLETED]" in line:
                continue

            # Split lines that contain multiple whois fields (separated by newlines)
            if "\n" in line:
                sub_lines = line.split("\n")
                all_field_lines.extend(sub_lines)
            else:
                all_field_lines.append(line)

        # Handle UK-style indented format where value is on next line
        # Example:
        #     Domain name:
        #         google.co.uk
        processed_lines = []
        i = 0
        while i < len(all_field_lines):
            line = all_field_lines[i].strip()

            # Check if this is a label line ending with colon but no value
            if (
                line
                and ":" in line
                and not line.startswith("#")
                and not line.startswith("%")
            ):
                parts = line.split(":", 1)
                if len(parts) == 2 and not parts[1].strip():
                    # Label with no value - check next line
                    if i + 1 < len(all_field_lines):
                        next_line = all_field_lines[i + 1].strip()
                        if (
                            next_line
                            and not next_line.startswith("#")
                            and ":" not in next_line
                        ):
                            # Combine label and value
                            processed_lines.append(f"{parts[0]}: {next_line}")
                            i += 2  # Skip next line as we've processed it
                            continue

            processed_lines.append(all_field_lines[i])
            i += 1

        for line in processed_lines:
            line = line.strip()
            if (
                not line
                or line.startswith("#")
                or line.startswith("%")
                or line.startswith(">>>")
            ):
                continue

            # Skip common footer text that appears in whois output
            if any(
                footer in line.lower()
                for footer in [
                    "for more information",
                    "terms of use",
                    "notice:",
                    "the data in",
                    "by submitting",
                    "web-based whois:",
                    "if you wish to contact",
                    "the registry database contains",
                    "markmonitor domain management",
                    "protecting companies",
                    "visit markmonitor",
                    "contact us at",
                ]
            ):
                continue

            # Basic domain information
            if ":" in line:
                key, value = line.split(":", 1)
                key = key.strip().lower().replace(" ", "_")
                value = value.strip()

                # Skip empty values
                if not value:
                    continue

                # Domain name (prefer lowercase clean version)
                if "domain_name" in key or key == "domain":
                    # Only take the first word/line for domain name, clean up any extra data
                    clean_domain = (
                        value.split()[0].lower() if value.split() else value.lower()
                    )
                    clean_domain = clean_domain.split("\n")[0]  # Take only first line
                    if not domain_info.domain_name or len(clean_domain) < len(
                        domain_info.domain_name
                    ):
                        domain_info.domain_name = clean_domain

                # Registry information (prefer more detailed registrar info)
                elif "registry_domain_id" in key:
                    domain_info.registry_domain_id = value
                elif "registrar_whois_server" in key:
                    domain_info.registrar_whois_server = value
                elif "registrar_url" in key:
                    domain_info.registrar_url = value
                elif key == "registrar" or "registrar_name" in key:
                    # Only accept if it looks like a registrar name (not an email or date)
                    if (
                        "@" not in value
                        and "T" not in value
                        and not re.match(r"\d{4}-\d{2}-\d{2}", value)
                    ):
                        domain_info.registrar = value

                # Dates (prefer the more recent/detailed format)
                elif any(
                    date_key in key
                    for date_key in ["creation_date", "created", "registered_on"]
                ):
                    normalized_date = self._normalize_date(value)
                    if normalized_date and (
                        not domain_info.creation_date
                        or len(normalized_date) > len(domain_info.creation_date)
                    ):
                        domain_info.creation_date = normalized_date
                elif any(
                    date_key in key
                    for date_key in [
                        "updated_date",
                        "updated",
                        "last_modified",
                        "changed",
                        "last_updated",
                    ]
                ):
                    normalized_date = self._normalize_date(value)
                    if normalized_date and (
                        not domain_info.updated_date
                        or len(normalized_date) > len(domain_info.updated_date)
                    ):
                        domain_info.updated_date = normalized_date
                elif any(
                    date_key in key
                    for date_key in [
                        "expiry_date",
                        "expires",
                        "expiration",
                        "registry_expiry_date",
                    ]
                ):
                    normalized_date = self._normalize_date(value)
                    if normalized_date and (
                        not domain_info.expiry_date
                        or len(normalized_date) > len(domain_info.expiry_date)
                    ):
                        domain_info.expiry_date = normalized_date

                # Domain status (collect all unique statuses)
                elif "domain_status" in key or (
                    key == "status" and "domain" not in line.lower()
                ):
                    # Clean status (remove URLs in parentheses and after spaces)
                    clean_status = re.sub(r"\s*\(.*?\)", "", value).strip()
                    clean_status = re.sub(r"\s+https?://.*$", "", clean_status).strip()
                    if clean_status and clean_status not in domain_info.domain_status:
                        domain_info.domain_status.append(clean_status)

                # Name servers (collect all unique servers)
                elif "name_server" in key or "nserver" in key:
                    clean_ns = value.lower().strip()
                    if clean_ns and clean_ns not in domain_info.name_servers:
                        domain_info.name_servers.append(clean_ns)

                # DNSSEC
                elif "dnssec" in key:
                    domain_info.dnssec = value

                # Contact information detection
                elif any(
                    contact_type in key
                    for contact_type in ["registrant", "admin", "tech"]
                ):
                    if "registrant" in key:
                        current_contact = domain_info.registrant_contact
                    elif "admin" in key:
                        current_contact = domain_info.admin_contact
                    elif "tech" in key:
                        current_contact = domain_info.tech_contact

                    if current_contact:
                        self._parse_contact_field(current_contact, key, value)

        return domain_info

    def _parse_ip_whois(self) -> NetworkInfo:
        """Parse IP/Network Whois information"""
        network_info = NetworkInfo()

        for line in self.raw_lines:
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            if ":" in line:
                key, value = line.split(":", 1)
                key = key.strip().lower().replace(" ", "")
                value = value.strip()

                # Network information
                if key == "netrange":
                    network_info.net_range = value
                elif key == "cidr":
                    network_info.cidr = value
                elif key == "netname":
                    network_info.net_name = value
                elif key == "nethandle":
                    network_info.net_handle = value
                elif key == "parent":
                    network_info.parent = value
                elif key == "nettype":
                    network_info.net_type = value
                elif key == "originas":
                    network_info.origin_as = value

                # Organization information
                elif key == "orgname" or key == "organization":
                    network_info.organization = value
                elif key == "address":
                    if network_info.address:
                        network_info.address += f", {value}"
                    else:
                        network_info.address = value
                elif key == "city":
                    network_info.city = value
                elif key == "stateprov" or key == "state":
                    network_info.state = value
                elif key == "postalcode":
                    network_info.postal_code = value
                elif key == "country":
                    network_info.country = value

                # Dates
                elif key == "regdate":
                    network_info.reg_date = self._normalize_date(value)
                elif key == "updated":
                    network_info.updated = self._normalize_date(value)

                # Contacts
                elif "abuse" in key and "email" in key:
                    if value not in network_info.abuse_contacts:
                        network_info.abuse_contacts.append(value)
                elif "tech" in key and "email" in key:
                    if value not in network_info.tech_contacts:
                        network_info.tech_contacts.append(value)

        return network_info

    def _parse_rpsl_format(self) -> DomainInfo:
        """Parse RPSL format (RIPE/APNIC/IANA databases) - used with -B, -r flags or specific servers"""
        domain_info = DomainInfo()
        org_name = ""
        org_email = ""
        admin_contact = ""
        admin_email = ""
        netname = ""
        descr_parts = []

        # Handle cases where multiple fields are concatenated in single lines
        all_field_lines = []

        for line in self.raw_lines:
            # Skip debug and completion messages
            if line.strip().startswith("DEBUG") or "[SCAN COMPLETED]" in line:
                continue

            # Split lines that contain multiple whois fields (separated by newlines)
            if "\n" in line:
                sub_lines = line.split("\n")
                all_field_lines.extend(sub_lines)
            else:
                all_field_lines.append(line)

        for line in all_field_lines:
            line = line.strip()

            # Skip comments and empty lines
            if not line or line.startswith("%") or line.startswith("#"):
                continue

            if ":" in line:
                key, value = line.split(":", 1)
                key = key.strip().lower()
                value = value.strip()

                if not value:
                    continue

                # Domain/network name - multiple possible fields
                if key == "inet-rtr":
                    domain_info.domain_name = value.lower()
                elif key == "domain":
                    # IANA format - domain: COM
                    domain_info.domain_name = value.lower()
                elif key == "inetnum":
                    # RIPE/APNIC format - inetnum: 1.1.1.0 - 1.1.1.255
                    domain_info.domain_name = value  # Store IP range as "domain"
                elif key == "netname":
                    # Network name from RIR databases
                    netname = value
                    if not domain_info.domain_name:
                        domain_info.domain_name = value.lower()

                # Description (useful for network blocks)
                elif key == "descr":
                    descr_parts.append(value)

                # Organization information
                elif key == "org-name":
                    org_name = value
                    domain_info.registrant_contact.organization = value
                elif key == "organisation":
                    # IANA/RIPE format
                    if not org_name:
                        org_name = value
                        domain_info.registrant_contact.organization = value
                elif key == "org":
                    domain_info.registry_domain_id = value

                # Country
                elif key == "country":
                    domain_info.registrant_contact.country = value

                # Contact information
                elif key == "e-mail":
                    if not org_email:
                        org_email = value
                        domain_info.registrant_contact.email = value
                    elif not admin_email:
                        admin_email = value
                        domain_info.admin_contact.email = value
                elif key == "abuse-mailbox":
                    # APNIC abuse contact
                    if not domain_info.admin_contact.email:
                        domain_info.admin_contact.email = value

                # Address information
                elif key == "address":
                    if domain_info.registrant_contact.address:
                        domain_info.registrant_contact.address += f", {value}"
                    else:
                        domain_info.registrant_contact.address = value

                # Contact names
                elif key == "name":
                    # Usually appears under contact: sections
                    if not domain_info.registrant_contact.name:
                        domain_info.registrant_contact.name = value

                # Phone/Fax
                elif key == "phone":
                    domain_info.registrant_contact.phone = value
                elif key == "fax-no":
                    if not domain_info.additional_info:
                        domain_info.additional_info = {}
                    domain_info.additional_info["fax"] = value

                # Technical/admin contacts
                elif key == "admin-c" or key == "tech-c":
                    admin_contact = value
                    if key == "admin-c":
                        domain_info.admin_contact.name = value
                    else:
                        domain_info.tech_contact.name = value

                # Role name (RIPE format - describes the contact role)
                elif key == "role":
                    # Store role as the admin contact name if we don't have a better name
                    # The nic-hdl will still be there as a reference
                    if value and value != admin_contact:
                        # Prefer descriptive role name over NIC handle
                        if domain_info.admin_contact.name == admin_contact:
                            domain_info.admin_contact.name = (
                                f"{value} ({admin_contact})"
                            )

                # NIC handle (network information center handle)
                elif key == "nic-hdl":
                    # This is a reference ID, store it in additional info
                    if not domain_info.additional_info:
                        domain_info.additional_info = {}
                    if "nic_handles" not in domain_info.additional_info:
                        domain_info.additional_info["nic_handles"] = []
                    if value not in domain_info.additional_info["nic_handles"]:
                        domain_info.additional_info["nic_handles"].append(value)

                # Organization type (RIPE)
                elif key == "org-type":
                    if not domain_info.additional_info:
                        domain_info.additional_info = {}
                    domain_info.additional_info["org_type"] = value

                # Maintainer (RIPE)
                elif key == "mnt-by":
                    if not domain_info.additional_info:
                        domain_info.additional_info = {}
                    if "maintainers" not in domain_info.additional_info:
                        domain_info.additional_info["maintainers"] = []
                    if value not in domain_info.additional_info["maintainers"]:
                        domain_info.additional_info["maintainers"].append(value)

                # Dates
                elif key == "created":
                    domain_info.creation_date = self._normalize_date(value)
                elif key == "last-modified":
                    domain_info.updated_date = self._normalize_date(value)
                elif key == "changed":
                    # IANA uses 'changed' instead of 'updated' or 'last-modified'
                    domain_info.updated_date = self._normalize_date(value)

                # AS information
                elif key == "local-as":
                    if not domain_info.additional_info:
                        domain_info.additional_info = {}
                    domain_info.additional_info["as_number"] = value

                # Name servers (IANA format: nserver)
                elif key == "nserver":
                    # Format: A.GTLD-SERVERS.NET 192.5.6.30 2001:503:a83e:0:0:0:2:30
                    parts = value.split()
                    if parts:
                        ns_name = parts[0].lower()
                        if ns_name not in domain_info.name_servers:
                            domain_info.name_servers.append(ns_name)

                # IP addresses (store as name servers for display purposes)
                elif key == "ifaddr":
                    ip_addr = value.split()[0]  # Get just the IP, ignore masklen
                    if ip_addr and ip_addr not in domain_info.name_servers:
                        domain_info.name_servers.append(ip_addr)

                # Status
                elif key == "status":
                    # Clean status - take only the first word/value before any other fields
                    clean_status = value.split()[0] if value.split() else value
                    # Also handle case where "remarks:" or other fields got concatenated
                    clean_status = clean_status.split("remarks:")[0].strip()
                    clean_status = clean_status.split("created:")[0].strip()
                    clean_status = clean_status.split("changed:")[0].strip()
                    if clean_status and clean_status not in domain_info.domain_status:
                        domain_info.domain_status.append(clean_status)

                    # Extract embedded fields from aggregated status line
                    # Check for created: in the value
                    if "created:" in value:
                        created_match = re.search(r"created:\s*(\S+)", value)
                        if created_match and not domain_info.creation_date:
                            domain_info.creation_date = self._normalize_date(
                                created_match.group(1)
                            )

                    # Check for changed: in the value
                    if "changed:" in value:
                        changed_match = re.search(r"changed:\s*(\S+)", value)
                        if changed_match and not domain_info.updated_date:
                            domain_info.updated_date = self._normalize_date(
                                changed_match.group(1)
                            )

                    # Check for remarks: in the value
                    if "remarks:" in value:
                        remarks_match = re.search(
                            r"remarks:\s*(.+?)(?:created:|changed:|source:|$)", value
                        )
                        if remarks_match:
                            if not domain_info.additional_info:
                                domain_info.additional_info = {}
                            domain_info.additional_info["remarks"] = (
                                remarks_match.group(1).strip()
                            )

                    # Check for source: in the value
                    if "source:" in value:
                        source_match = re.search(r"source:\s*(\S+)", value)
                        if source_match:
                            if not domain_info.additional_info:
                                domain_info.additional_info = {}
                            domain_info.additional_info["source"] = source_match.group(
                                1
                            )

                # Remarks (IANA format)
                elif key == "remarks":
                    if not domain_info.additional_info:
                        domain_info.additional_info = {}
                    domain_info.additional_info["remarks"] = value

                # Source (IANA/RIPE format)
                elif key == "source":
                    if not domain_info.additional_info:
                        domain_info.additional_info = {}
                    domain_info.additional_info["source"] = value

                # WHOIS server reference (IANA)
                elif key == "whois":
                    domain_info.registrar_whois_server = value

                # DS record data (DNSSEC)
                elif key == "ds-rdata":
                    domain_info.dnssec = f"Signed (DS record present)"
                    if not domain_info.additional_info:
                        domain_info.additional_info = {}
                    domain_info.additional_info["ds_record"] = value

        # If we found organization info, set it as registrar
        if org_name:
            domain_info.registrar = org_name

        # If we have descriptions, add them to additional info
        if descr_parts and not domain_info.registrar:
            # Use first description as registrar if we don't have one
            domain_info.registrar = descr_parts[0]
            if len(descr_parts) > 1:
                if not domain_info.additional_info:
                    domain_info.additional_info = {}
                domain_info.additional_info["description"] = "; ".join(descr_parts[1:])

        # If netname exists and domain_name is IP range, add netname as registrar
        if netname and "-" in str(domain_info.domain_name):
            if not domain_info.registrar:
                domain_info.registrar = netname

        return domain_info

    def _parse_contact_field(self, contact: ContactInfo, key: str, value: str):
        """Parse contact information fields"""
        key = key.lower()

        if "name" in key:
            contact.name = value
        elif "organization" in key or "org" in key:
            contact.organization = value
        elif "address" in key:
            if contact.address:
                contact.address += f", {value}"
            else:
                contact.address = value
        elif "city" in key:
            contact.city = value
        elif "state" in key or "province" in key:
            contact.state = value
        elif "postal" in key or "zip" in key:
            contact.postal_code = value
        elif "country" in key:
            contact.country = value
        elif "phone" in key:
            contact.phone = value
        elif "email" in key:
            contact.email = value

    def _normalize_date(self, date_str: str) -> str:
        """Normalize date format from various Whois formats"""
        if not date_str:
            return ""

        # Remove common suffixes and clean up
        date_str = re.sub(r"\s*\(.*?\)", "", date_str)  # Remove parentheses content
        date_str = re.sub(r"\s*Z$", "", date_str)  # Remove Z timezone
        date_str = re.sub(
            r"\+\d{2}:\d{2}$", "", date_str
        )  # Remove timezone offset like +01:00
        date_str = re.sub(
            r"\+\d{4}$", "", date_str
        )  # Remove timezone offset like +0100
        date_str = date_str.strip()

        # Try to parse common formats
        date_patterns = [
            r"(\d{4}-\d{2}-\d{2})",  # YYYY-MM-DD (ISO)
            r"(\d{2}/\d{2}/\d{4})",  # MM/DD/YYYY or DD/MM/YYYY
            r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})",  # ISO format with time
            r"(\d{2}-[A-Za-z]{3}-\d{4})",  # DD-Mon-YYYY (e.g., 14-Feb-1999 UK format)
        ]

        for pattern in date_patterns:
            match = re.search(pattern, date_str)
            if match:
                return match.group(1)

        return date_str  # Return as-is if no pattern matches

    def _compute_diagnostics(
        self,
        findings: Optional[Any] = None,
        scan_stats: Optional[Dict[str, Any]] = None,
    ) -> List[Dict[str, Any]]:
        """
        Produce diagnostics for WHOIS output:
        - compare registrar against registrar_rules (registrar_rules in whois_ruleset.json)
        - compare creation/update dates against age_rules (age_rules in whois_ruleset.json)
        """
        import os, json, re
        from datetime import datetime

        scan_stats = scan_stats or {}
        diags: List[Dict[str, Any]] = []

        # load/cached ruleset
        ruleset = getattr(self, "whois_ruleset", None) or {}
        if not ruleset:
            try:
                here = (
                    os.path.dirname(__file__)
                    if "__file__" in globals()
                    else os.getcwd()
                )
                candidates = [
                    os.path.join(here, "whois_ruleset.json"),
                    os.path.join(here, "rulesets", "whois_ruleset.json"),
                    os.path.join(os.getcwd(), "rulesets", "whois_ruleset.json"),
                    os.path.join(os.getcwd(), "src", "rulesets", "whois_ruleset.json"),
                    os.path.join(os.getcwd(), "src", "whois_ruleset.json"),
                ]
                env_path = os.environ.get("WHOIS_RULESET_PATH") or os.environ.get(
                    "WHOIS_RULES"
                )
                if env_path:
                    candidates.insert(0, env_path)
                for p in candidates:
                    try:
                        p = os.path.abspath(p)
                        if os.path.exists(p):
                            with open(p, "r", encoding="utf-8") as fh:
                                ruleset = json.load(fh) or {}
                                self.whois_ruleset = ruleset
                                break
                    except Exception:
                        continue
            except Exception:
                ruleset = {}
        defaults = ruleset.get("defaults", {}) if isinstance(ruleset, dict) else {}

        def add(sev, msg, ctx=None):
            entry = {
                "severity": sev or defaults.get("severity", "Info"),
                "message": msg,
            }
            if ctx:
                entry["context"] = ctx
            if entry not in diags:
                diags.append(entry)

        def matches(pattern, text):
            try:
                return bool(re.search(pattern, text or "", re.IGNORECASE))
            except re.error:
                return pattern.lower() in (text or "").lower()

        # --- gather registrar candidates ---
        registrar_candidates: List[str] = []
        if isinstance(findings, dict) and findings.get("registrar"):
            registrar_candidates.append(str(findings.get("registrar")))
        elif isinstance(findings, (list, tuple)):
            for it in findings:
                if isinstance(it, dict) and it.get("registrar"):
                    registrar_candidates.append(str(it.get("registrar")))

        raw = (
            scan_stats.get("raw_output")
            or getattr(self, "get_raw_output", lambda: "")()
            or ""
        ).strip()

        # try extract Registrar lines from raw
        for m in re.finditer(
            r"^\s*Registrar:\s*(.+)$", raw, re.IGNORECASE | re.MULTILINE
        ):
            registrar_candidates.append(m.group(1).strip())
        for m in re.finditer(
            r"^\s*Registrar Name:\s*(.+)$", raw, re.IGNORECASE | re.MULTILINE
        ):
            registrar_candidates.append(m.group(1).strip())

        # normalize registrar list
        registrar_candidates = [
            r.rstrip(".").strip() for r in registrar_candidates if r and str(r).strip()
        ]
        seen = set()
        regs = []
        for r in registrar_candidates:
            low = r.lower()
            if low not in seen:
                seen.add(low)
                regs.append(r)

        # apply registrar rules
        registrar_rules = (
            ruleset.get("registrar_rules") if isinstance(ruleset, dict) else []
        )
        for reg in regs:
            for rule in registrar_rules or []:
                pattern = rule.get("pattern") or rule.get("regex") or ""
                if not pattern:
                    continue
                try:
                    if matches(pattern, reg):
                        sev = rule.get("severity") or "Info"
                        msg = (
                            rule.get("message") or f"Registrar rule matched: {pattern}"
                        )
                        add(sev, msg, f"registrar: {reg}")
                except Exception:
                    continue

        # --- AGE RULES: extract creation & update dates and evaluate conditions ---
        # try common WHOIS date formats (YYYY-MM-DD) for Creation and Updated fields
        creation_year: Optional[int] = None
        updated_year: Optional[int] = None
        creation_full = None
        updated_full = None

        m = re.search(
            r"Creation Date:\s*([0-9]{4})-([0-9]{2})-([0-9]{2})", raw, re.IGNORECASE
        )
        if not m:
            m = re.search(
                r"Created On:\s*([0-9]{4})-([0-9]{2})-([0-9]{2})", raw, re.IGNORECASE
            )
        if m:
            try:
                creation_year = int(m.group(1))
                creation_full = f"{m.group(1)}-{m.group(2)}-{m.group(3)}"
            except Exception:
                creation_year = None

        m2 = re.search(
            r"(Updated Date|Updated):\s*([0-9]{4})-([0-9]{2})-([0-9]{2})",
            raw,
            re.IGNORECASE,
        )
        if m2:
            try:
                updated_year = int(m2.group(2))
                updated_full = (
                    f"{m2.group(2)}-{m2.group(3)}-{m2.group(4)}"
                    if False
                    else f"{m2.group(2)}-{m2.group(3)}-{m2.group(4)}"
                )
            except Exception:
                updated_year = None

        # alternative Updated patterns (some WHOIS outputs use "Updated Date: YYYY-MM-DD")
        if updated_year is None:
            m3 = re.search(
                r"Updated Date:\s*([0-9]{4})-([0-9]{2})-([0-9]{2})", raw, re.IGNORECASE
            )
            if m3:
                try:
                    updated_year = int(m3.group(1))
                    updated_full = f"{m3.group(1)}-{m3.group(2)}-{m3.group(3)}"
                except Exception:
                    updated_year = None

        current_year = datetime.now().year

        age_rules = ruleset.get("age_rules") if isinstance(ruleset, dict) else []
        for rule in age_rules or []:
            pattern = rule.get("pattern") or ""
            if not pattern:
                continue
            # attempt to find a year capture using regex on raw text first (some rules include groups)
            year_val = None
            g = None
            try:
                gm = re.search(pattern, raw, re.IGNORECASE)
                if gm and gm.groups():
                    # use first capture as year when it looks like YYYY
                    g = gm.group(1)
                    if g and re.match(r"^\d{4}$", str(g)):
                        year_val = int(g)
                # if pattern specifically mentions Creation Date (common), prefer extracted creation_year
                if (
                    year_val is None
                    and re.search(r"creation", pattern, re.IGNORECASE)
                    and creation_year
                ):
                    year_val = creation_year
                if (
                    year_val is None
                    and re.search(r"update|updated", pattern, re.IGNORECASE)
                    and updated_year
                ):
                    year_val = updated_year
                # fallback: if we have creation_year use it
                if year_val is None and creation_year:
                    year_val = creation_year
            except Exception:
                year_val = None

            if year_val is None:
                # cannot evaluate condition without a year — skip
                continue

            age = current_year - int(year_val)
            condition = rule.get("condition") or ""
            matched = False
            try:
                if condition:
                    # allow conditions referencing \1 or \\1 — substitute with captured year and provide locals
                    expr = condition.replace("\\1", str(year_val)).replace(
                        "\\\\1", str(year_val)
                    )
                    # expose age, current_year, year for expression
                    local_vars = {
                        "age": age,
                        "current_year": current_year,
                        "year": year_val,
                    }
                    # safe-ish eval: no builtins
                    try:
                        res = eval(expr, {"__builtins__": {}}, local_vars)
                    except Exception:
                        # as fallback, try simple comparisons replacing common tokens
                        res = False
                    if res:
                        matched = True
                else:
                    # no condition provided, apply default heuristics (example thresholds)
                    if age < 1 and rule.get("message"):
                        matched = True
                    elif 1 <= age <= 3 and rule.get("message"):
                        matched = True
                    elif age > 3 and rule.get("message"):
                        matched = True
            except Exception:
                matched = False

            if matched:
                sev = rule.get("severity") or "Medium"
                msg = rule.get("message") or f"Age rule matched (year={year_val})"
                ctx = (
                    f"creation_year={creation_year}"
                    if creation_year
                    else f"year={year_val}"
                )
                add(sev, msg, ctx)

        return diags

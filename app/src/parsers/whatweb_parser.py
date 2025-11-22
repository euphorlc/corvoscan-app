"""
WhatWeb Parser - Comprehensive parser for WhatWeb web technology fingerprinting output.

Supports both standard and verbose (-v) output formats.
"""

import re
from typing import Dict, List, Tuple, Optional, Any
from datetime import datetime


class WhatWebResult:
    """Result object for WhatWeb scans - compatible with CorvoScan's result handling"""

    def __init__(self, tool_name, target, timestamp, raw_output, success, error_message=None, **kwargs):
        self.tool_name = tool_name
        self.target = target
        self.timestamp = timestamp
        self.raw_output = raw_output
        self.success = success
        self.error_message = error_message

        # Store additional data as attributes
        for key, value in kwargs.items():
            setattr(self, key, value)

    def to_dict(self):
        """Convert to dictionary"""
        result = {
            'tool_name': self.tool_name,
            'target': self.target,
            'timestamp': self.timestamp,
            'raw_output': self.raw_output,
            'success': self.success,
            'error_message': self.error_message
        }
        # Add any extra attributes
        for key, value in self.__dict__.items():
            if key not in result:
                result[key] = value
        return result


class WhatWebParser:
    """Parser for WhatWeb output"""

    def __init__(self):
        self.tool_name = "whatweb"
        self.raw_lines = []

    def add_output_line(self, line: str):
        """Add a line of output from the tool"""
        self.raw_lines.append(line.rstrip())

    def get_raw_output(self) -> str:
        """Get the complete raw output"""
        return "\n".join(self.raw_lines)

    def clear(self):
        """Clear accumulated output"""
        self.raw_lines.clear()

    def parse(self, target: str) -> WhatWebResult:
        """
        Parse WhatWeb output and return structured results.

        Args:
            target: Target URL that was scanned

        Returns:
            WhatWebResult object with parsed results
        """
        raw_output = self.get_raw_output()
        lines = raw_output.strip().split('\n')

        # Detect output format
        is_verbose = any('WhatWeb report for' in line for line in lines)

        if is_verbose:
            parsed_data = self._parse_verbose(lines, target, raw_output)
        else:
            parsed_data = self._parse_standard(lines, target, raw_output)

        # compute diagnostics and attach (reports for verbose, urls_scanned for standard)
        try:
            if parsed_data.get("format") == "verbose":
                findings = parsed_data.get("reports") or []
            else:
                findings = parsed_data.get("urls_scanned") or []
            parsed_data["diagnostics"] = self._compute_diagnostics(findings, {"raw_output": raw_output})
        except Exception:
            parsed_data["diagnostics"] = []

        # Convert dict to WhatWebResult object
        return WhatWebResult(**parsed_data)

    def _parse_standard(self, lines: List[str], target: str, raw_output: str) -> Dict:
        """Parse standard (non-verbose) WhatWeb output"""

        urls_scanned = []

        # ANSI color code regex
        ansi_escape = re.compile(r'\x1b\[[0-9;]*m')

        for line in lines:
            # Skip empty lines
            if not line.strip():
                continue

            # Skip debug/status lines
            if line.startswith('DEBUG') or line.startswith('Started scan') or line.startswith('[SCAN COMPLETED]'):
                continue

            # Strip ANSI color codes
            line = ansi_escape.sub('', line)

            # Each line is typically: URL [STATUS] Technologies, Info
            url_match = re.match(r'^(https?://[^\s\[]+)', line)
            if url_match:
                url = url_match.group(1)
                rest = line[len(url):].strip()

                # Extract status code
                status_code = None
                status_match = re.search(r'\[(\d{3})\s+([^\]]+)\]', rest)
                if status_match:
                    status_code = int(status_match.group(1))
                    status_text = status_match.group(2)

                # Extract all technology/plugin mentions: Name[Version/Info]
                technologies = []
                tech_pattern = r'([A-Za-z0-9_-]+)\[([^\]]+)\]'
                for match in re.finditer(tech_pattern, rest):
                    name = match.group(1)
                    info = match.group(2)

                    # Skip status codes
                    if name.isdigit():
                        continue

                    # Check if it looks like a technology
                    if len(name) > 1 and not name.startswith('http'):
                        technologies.append({
                            'name': name,
                            'info': info
                        })

                urls_scanned.append({
                    'url': url,
                    'status_code': status_code,
                    'status_text': status_text if status_match else None,
                    'technologies': technologies
                })

        success = len(urls_scanned) > 0

        return {
            'tool_name': 'whatweb',
            'target': target,
            'timestamp': datetime.now().isoformat(),
            'raw_output': raw_output,
            'success': success,
            'error_message': None if success else "No results found",
            'urls_scanned': urls_scanned,
            'format': 'standard'
        }

    def _parse_verbose(self, lines: List[str], target: str, raw_output: str) -> Dict:
        """Parse verbose (-v) WhatWeb output"""

        reports = []
        current_report = None
        current_plugin = None
        in_http_headers = False
        http_headers = []

        # ANSI color code regex
        ansi_escape = re.compile(r'\x1b\[[0-9;]*m')

        i = 0
        while i < len(lines):
            line = lines[i]

            # Strip ANSI color codes
            line = ansi_escape.sub('', line)

            # Start of a new report
            if line.startswith('WhatWeb report for'):
                if current_report:
                    reports.append(current_report)

                url_match = re.search(r'WhatWeb report for (.+)', line)
                current_report = {
                    'url': url_match.group(1) if url_match else target,
                    'status': None,
                    'status_code': None,
                    'title': None,
                    'ip': None,
                    'country': None,
                    'country_code': None,
                    'summary': None,
                    'plugins': [],
                    'http_headers': []
                }
                in_http_headers = False
                http_headers = []

            # Status line
            elif line.startswith('Status'):
                status_match = re.search(r'Status\s*:\s*(\d+)\s*(.+)?', line)
                if status_match and current_report:
                    current_report['status_code'] = int(status_match.group(1))
                    current_report['status'] = status_match.group(2).strip() if status_match.group(2) else None

            # Title
            elif line.startswith('Title'):
                title_match = re.search(r'Title\s*:\s*(.+)', line)
                if title_match and current_report:
                    current_report['title'] = title_match.group(1).strip()

            # IP Address
            elif line.startswith('IP'):
                ip_match = re.search(r'IP\s*:\s*([0-9.]+)', line)
                if ip_match and current_report:
                    current_report['ip'] = ip_match.group(1)

            # Country
            elif line.startswith('Country'):
                country_match = re.search(r'Country\s*:\s*([^,]+),\s*(.+)', line)
                if country_match and current_report:
                    current_report['country'] = country_match.group(1).strip()
                    current_report['country_code'] = country_match.group(2).strip()

            # Summary
            elif line.startswith('Summary'):
                summary_match = re.search(r'Summary\s*:\s*(.+)', line)
                if summary_match and current_report:
                    current_report['summary'] = summary_match.group(1).strip()

            # Detected Plugins section
            elif line.startswith('Detected Plugins:'):
                # Start parsing plugins
                pass

            # Plugin name (starts with [)
            elif re.match(r'^\[\s*([^\]]+)\s*\]', line):
                plugin_match = re.match(r'^\[\s*([^\]]+)\s*\]', line)
                if plugin_match and current_report is not None:
                    current_plugin = {
                        'name': plugin_match.group(1).strip(),
                        'description': '',
                        'strings': []
                    }
                    current_report['plugins'].append(current_plugin)

            # Plugin description or string value
            elif current_plugin is not None and line.strip():
                # Check if it's a String line
                if line.strip().startswith('String'):
                    string_match = re.search(r'String\s*:\s*(.+)', line)
                    if string_match:
                        current_plugin['strings'].append(string_match.group(1).strip())
                # Otherwise it's part of the description
                elif not line.startswith('HTTP Headers:') and not in_http_headers:
                    if current_plugin['description']:
                        current_plugin['description'] += ' ' + line.strip()
                    else:
                        current_plugin['description'] = line.strip()

            # HTTP Headers section
            elif line.startswith('HTTP Headers:'):
                in_http_headers = True
                current_plugin = None  # Stop parsing plugins

            # Collect HTTP headers
            elif in_http_headers and line.strip():
                # Check if we've reached the next report or end
                if line.startswith('WhatWeb report for'):
                    i -= 1  # Reprocess this line
                    in_http_headers = False
                    if current_report:
                        current_report['http_headers'] = http_headers
                else:
                    http_headers.append(line.strip())

            i += 1

        # Add the last report
        if current_report:
            if http_headers:
                current_report['http_headers'] = http_headers
            reports.append(current_report)

        success = len(reports) > 0

        return {
            'tool_name': 'whatweb',
            'target': target,
            'timestamp': datetime.now().isoformat(),
            'raw_output': raw_output,
            'success': success,
            'error_message': None if success else "No results found",
            'reports': reports,
            'format': 'verbose'
        }

    def format_results(self, result: WhatWebResult) -> str:
        """Format parsed results as HTML for display"""

        if not result.success:
            return f"""
            <div style='color: #d32f2f; font-family: monospace; padding: 10px;'>
                ❌ WhatWeb scan failed
                <br>Error: {result.error_message or 'Unknown error'}
            </div>
            """

        # Convert result object to dict for easier access
        parsed = result.to_dict()
        format_type = parsed.get('format', 'standard')

        if format_type == 'verbose':
            return self._format_verbose_results(parsed)
        else:
            return self._format_standard_results(parsed)

    def _format_standard_results(self, parsed: Dict) -> str:
        """Format standard output as HTML"""

        html = f"""
        <div style='padding: 10px; background: #ffffff; color: #000000;'>
            <p><strong>URLs Scanned:</strong> {len(parsed.get('urls_scanned', []))}</p>
        """

        for url_data in parsed.get('urls_scanned', []):
            status_code = url_data.get('status_code', 0)
            if status_code == 200:
                status_color = '#2e7d32'  # Green
            elif 300 <= status_code < 400:
                status_color = '#f57c00'  # Orange
            else:
                status_color = '#c62828'  # Red

            html += f"""
            <div style='margin: 15px 0; padding: 12px; background: #ffffff; border-left: 4px solid {status_color}; border-radius: 3px; color: #000000;'>
                <h4 style='color: #000000; margin-top: 0; margin-bottom: 8px;'>{url_data['url']}</h4>
                <p style='margin: 5px 0;'><strong style='color: {status_color};'>[{url_data.get('status_code', 'N/A')} {url_data.get('status_text', '')}]</strong></p>
            """

            if url_data.get('technologies'):
                html += "<h5 style='color: #000000; margin-top: 10px; margin-bottom: 8px;'>Detected Technologies:</h5><ul style='list-style: none; padding-left: 0; margin: 0;'>"
                for tech in url_data['technologies']:
                    html += f"<li style='margin: 4px 0; color: #000000;'>• <strong>{tech['name']}:</strong> {tech['info']}</li>"
                html += "</ul>"

            html += "</div>"

        html += "</div>"
        return html

    def _format_verbose_results(self, parsed: Dict) -> str:
        """Format verbose output as HTML"""

        html = f"""
        <div style='padding: 10px; background: #ffffff; color: #000000;'>
            <p><strong>Reports Generated:</strong> {len(parsed.get('reports', []))}</p>
        """

        for report in parsed.get('reports', []):
            status_code = report.get('status_code', 0)
            if status_code == 200:
                status_color = '#2e7d32'  # Green
            elif 300 <= status_code < 400:
                status_color = '#f57c00'  # Orange
            else:
                status_color = '#c62828'  # Red

            html += f"""
            <div style='margin: 15px 0; padding: 15px; background: #ffffff; border-left: 4px solid {status_color}; border-radius: 3px; color: #000000;'>
                <h4 style='color: #000000; margin-top: 0;'>{report['url']}</h4>

                <table style='width: 100%; border-collapse: collapse; margin: 10px 0;'>
                    <tr>
                        <td style='padding: 8px; color: #000000; width: 120px;'><strong>Status:</strong></td>
                        <td style='padding: 8px; color: {status_color};'>[{status_code}] {report.get('status', 'N/A')}</td>
                    </tr>
            """

            if report.get('title'):
                html += f"""
                    <tr>
                        <td style='padding: 8px; color: #000000;'><strong>Title:</strong></td>
                        <td style='padding: 8px; color: #000000;'>{report['title']}</td>
                    </tr>
                """

            if report.get('ip'):
                html += f"""
                    <tr>
                        <td style='padding: 8px; color: #000000;'><strong>IP Address:</strong></td>
                        <td style='padding: 8px; color: #000000;'>{report['ip']}</td>
                    </tr>
                """

            if report.get('country'):
                html += f"""
                    <tr>
                        <td style='padding: 8px; color: #000000;'><strong>Country:</strong></td>
                        <td style='padding: 8px; color: #000000;'>{report['country']} ({report.get('country_code', 'N/A')})</td>
                    </tr>
                """

            html += "</table>"

            # Summary
            if report.get('summary'):
                html += f"""
                <div style='margin: 15px 0; padding: 10px; background: #ffffff; border: 1px solid #e0e0e0; border-radius: 3px; color: #000000;'>
                    <strong>Summary:</strong><br>
                    <span>{report['summary']}</span>
                </div>
                """

            # Detected Plugins
            if report.get('plugins'):
                html += "<h5 style='color: #000000; margin-top: 15px;'>🔌 Detected Plugins & Technologies:</h5>"

                for plugin in report['plugins']:
                    html += f"""
                    <div style='margin: 10px 0; padding: 12px; background: #ffffff; border: 1px solid #e0e0e0; border-left: 3px solid #1565c0; border-radius: 3px; color: #000000;'>
                        <strong>{plugin['name']}</strong><br>
                    """

                    if plugin.get('description'):
                        desc = plugin['description'][:200] + ('...' if len(plugin['description']) > 200 else '')
                        html += f"<span style='font-size: 0.9em;'>{desc}</span><br>"

                    if plugin.get('strings'):
                        html += "<ul style='margin: 5px 0; padding-left: 20px; color: #000000;'>"
                        for string in plugin['strings']:
                            html += f"<li>{string}</li>"
                        html += "</ul>"

                    html += "</div>"

            # HTTP Headers (collapsible or limited)
            if report.get('http_headers'):
                header_count = len(report['http_headers'])
                html += f"""
                <details style='margin: 15px 0;'>
                    <summary style='color: #81c784; cursor: pointer;'>📋 HTTP Headers ({header_count} headers)</summary>
                    <div style='margin: 10px 0; padding: 10px; background: #1e1e1e; border-radius: 3px; font-family: monospace; font-size: 0.85em;'>
                """
                for header in report['http_headers'][:20]:  # Limit to first 20
                    html += f"<div style='color: #b0bec5; padding: 2px 0;'>{header}</div>"

                if header_count > 20:
                    html += f"<div style='color: #757575; padding: 5px 0;'><em>... and {header_count - 20} more headers</em></div>"

                html += "</div></details>"

            html += "</div>"

        html += "</div>"
        return html

    def _compute_diagnostics(self,
                             findings: List[Dict[str, Any]],
                             scan_stats: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """
        Produce diagnostics for WhatWeb-style findings using rules in rulesets/whatweb_ruleset.json.

        Evaluates all rule groups (server_rule, security_header_rule, tls_ssl_rule,
        cookie_rule, uncommon_header_rule, redirect_rule, cdn_rule, cms_plugin_rule,
        exposed_file_rule, directory_listing_rule, etc.) against parsed findings.

        This version is tolerant of invalid/malformed ruleset JSON and provides a small
        fallback server_rule (matches "varnish") so quick tests show diagnostics.
        """
        import os, json, re

        scan_stats = scan_stats or {}
        diags: List[Dict[str, Any]] = []

        # load/cached ruleset (robust: allow // comments and fallbacks)
        ruleset = getattr(self, "whatweb_ruleset", None) or {}
        if not ruleset:
            try:
                here = os.path.dirname(__file__) if '__file__' in globals() else os.getcwd()
                candidates = [
                    os.path.join(here, "whatweb_ruleset.json"),
                    os.path.join(here, "rulesets", "whatweb_ruleset.json"),
                    os.path.join(os.getcwd(), "rulesets", "whatweb_ruleset.json"),
                    os.path.join(os.getcwd(), "src", "rulesets", "whatweb_ruleset.json"),
                    os.path.join(os.getcwd(), "src", "whatweb_ruleset.json"),
                ]
                env_path = os.environ.get("WHATWEB_RULESET_PATH") or os.environ.get("WEB_RULESET_PATH")
                if env_path:
                    candidates.insert(0, env_path)
                loaded = {}
                for p in candidates:
                    try:
                        p = os.path.abspath(p)
                        if not os.path.exists(p):
                            continue
                        try:
                            with open(p, "r", encoding="utf-8") as fh:
                                loaded = json.load(fh) or {}
                                break
                        except Exception:
                            # try tolerant parse: strip // and /* */ comments then json.loads
                            try:
                                with open(p, "r", encoding="utf-8") as fh:
                                    txt = fh.read()
                                # remove // comments
                                txt = re.sub(r'//.*?(\r?\n)', r'\1', txt)
                                # remove /* */ comments
                                txt = re.sub(r'/\*.*?\*/', '', txt, flags=re.S)
                                # remove trailing commas before } or ]
                                txt = re.sub(r',\s*([\}\]])', r'\1', txt)
                                loaded = json.loads(txt) or {}
                                break
                            except Exception:
                                continue
                    except Exception:
                        continue
                ruleset = loaded or {}
                self.whatweb_ruleset = ruleset
            except Exception:
                ruleset = {}
        defaults = ruleset.get("defaults", {}) if isinstance(ruleset, dict) else {}

        def add(sev, msg, ctx=None):
            entry = {"severity": sev or defaults.get("severity", "Info"), "message": msg}
            if ctx:
                entry["context"] = ctx
            if entry not in diags:
                diags.append(entry)

        def matches(pattern, text):
            try:
                return bool(re.search(pattern, text or "", re.IGNORECASE))
            except re.error:
                return pattern.lower() in (text or "").lower()

        # --- Flatten findings into searchable buckets ---
        raw_output = ""
        reports = []
        urls_scanned = []
        for f in (findings or []):
            if not isinstance(f, dict):
                continue
            if f.get("url") and ("plugins" in f or "http_headers" in f or "technologies" in f):
                reports.append(f)
            elif f.get("url"):
                urls_scanned.append(f)
            raw_output = raw_output + " " + (f.get("raw_output") or "") if f.get("raw_output") else raw_output

        raw_text = (scan_stats.get("raw_output") or raw_output or self.get_raw_output() or "").strip()

        server_header = ""
        headers_map: Dict[str, str] = {}
        tls_list: List[str] = []
        cookies_list: List[str] = []
        plugins_list: List[str] = []
        technologies_list: List[str] = []
        found_files: List[str] = []
        redirects: List[str] = []

        if reports:
            first = reports[0]
            for h in first.get("http_headers") or []:
                if isinstance(h, str) and ":" in h:
                    k, v = h.split(":", 1)
                    headers_map[k.strip().lower()] = v.strip()
            for p in first.get("plugins") or []:
                if isinstance(p, dict):
                    name = p.get("name") or p.get("plugin") or ""
                    plugins_list.append(str(name).lower())
                    for s in p.get("strings") or []:
                        if isinstance(s, str):
                            if s.lower().startswith("set-cookie") or "cookie" in s.lower():
                                cookies_list.append(s)
                            found_files.append(s)
                else:
                    plugins_list.append(str(p).lower())
            for t in first.get("technologies") or []:
                if isinstance(t, dict):
                    technologies_list.append((t.get("name") or "").lower())
                else:
                    technologies_list.append(str(t).lower())
            server_header = headers_map.get("server", "") or first.get("server", "") or first.get("title", "") or ""
            if first.get("status_code") and 300 <= int(first.get("status_code") or 0) < 400:
                redirects.append(first.get("url") or "")
        else:
            if urls_scanned:
                for u in urls_scanned:
                    for t in u.get("technologies") or []:
                        if isinstance(t, dict):
                            technologies_list.append((t.get("name") or "").lower())
                        else:
                            technologies_list.append(str(t).lower())

        if raw_text:
            tls_list.extend(re.findall(r"(tls|ssl|https|x509|certificate|cipher|openssl)[^ \n,;]{0,30}", raw_text, re.IGNORECASE))
            found_files.extend(re.findall(r'(?:/[\w\-/]+(?:robots\.txt|sitemap\.xml|backup|\.env|\.git|README\.md|composer\.json))', raw_text, re.IGNORECASE))
            cookies_list.extend(re.findall(r'Set-Cookie:\s*([^;\n\r]+)', raw_text, re.IGNORECASE))
            redirects.extend(re.findall(r'Location:\s*([^\s]+)', raw_text, re.IGNORECASE))

        server_header = (server_header or "").lower()
        hdrs = {k.lower(): v for k, v in (headers_map or {}).items()}
        tls_list = [str(x).lower() for x in tls_list]
        cookies_list = [str(x).lower() for x in cookies_list]
        plugins_list = [str(x).lower() for x in plugins_list]
        technologies_list = [str(x).lower() for x in technologies_list]
        found_files = [str(x).lower() for x in found_files]
        redirects = [str(x).lower() for x in redirects]
        raw_text_lower = (raw_text or "").lower()

        group_sources = {
            "server_rule": lambda rule: server_header + " " + raw_text_lower,
            "security_header_rule": lambda rule: " ".join([f"{k}:{v}" for k, v in hdrs.items()]) + " " + raw_text_lower,
            "tls_ssl_rule": lambda rule: " ".join(tls_list) + " " + raw_text_lower,
            "cookie_rule": lambda rule: " ".join(cookies_list) + " " + raw_text_lower,
            "uncommon_header_rule": lambda rule: " ".join([f"{k}:{v}" for k, v in hdrs.items()]) + " " + raw_text_lower,
            "redirect_rule": lambda rule: " ".join(redirects) + " " + raw_text_lower,
            "cdn_rule": lambda rule: " ".join(technologies_list) + " " + raw_text_lower,
            "cms_plugin_rule": lambda rule: " ".join(plugins_list) + " " + raw_text_lower,
            "exposed_file_rule": lambda rule: " ".join(found_files) + " " + raw_text_lower,
            "directory_listing_rule": lambda rule: raw_text_lower,
        }

        # If no rules loaded, provide a minimal server_rule fallback (helps quick testing)
        if not isinstance(ruleset, dict) or not ruleset:
            ruleset = {"server_rule": [
                {"pattern": "varnish", "severity": "Info", "message": "Server header indicates Varnish (fallback test rule)"}
            ]}
            self.whatweb_ruleset = ruleset

        # --- Ensure server_rule checks headers/raw/plugins/techs first and then remove it from ruleset to avoid duplicate checks ---
        try:
            server_rules = ruleset.get("server_rule", []) if isinstance(ruleset, dict) else []
            if server_rules:
                hay_sources: List[str] = []
                if server_header:
                    hay_sources.append(server_header)
                hay_sources.append(raw_text_lower)
                hay_sources.extend([f"{k}:{v}".lower() for k, v in hdrs.items()])
                hay_sources.extend(plugins_list or [])
                hay_sources.extend(technologies_list or [])
                for r in reports:
                    for h in r.get("http_headers") or []:
                        if isinstance(h, str):
                            hay_sources.append(h.lower())

                for rule in server_rules:
                    pattern = rule.get("pattern") or ""
                    if not pattern:
                        continue
                    sev = rule.get("severity") or defaults.get("severity") or "Info"
                    msg = rule.get("message") or defaults.get("message") or "Server rule matched"
                    for hay in hay_sources:
                        try:
                            if re.search(pattern, hay or "", re.IGNORECASE):
                                add(sev, msg, f"server:{pattern}")
                                break
                        except re.error:
                            if pattern.lower() in (hay or ""):
                                add(sev, msg, f"server:{pattern}")
                                break
                try:
                    ruleset.pop("server_rule", None)
                except Exception:
                    pass
        except Exception:
            pass

        # Iterate remaining rule groups in ruleset
        for group_name, rules in (ruleset or {}).items():
            if group_name == "defaults":
                continue
            if not isinstance(rules, list):
                continue
            for rule in rules:
                try:
                    pattern = rule.get("pattern") or rule.get("regex") or rule.get("match") or ""
                    if not pattern:
                        continue
                    severity = rule.get("severity") or defaults.get("severity") or "Info"
                    message = rule.get("message") or defaults.get("message") or f"{group_name} matched"
                    matched = False

                    if group_name in ("security_header_rule", "uncommon_header_rule"):
                        for hn, hv in hdrs.items():
                            hay = f"{hn}:{hv}"
                            if matches(pattern, hay):
                                add(severity, message, f"header {hn}")
                                matched = True
                                break
                        if matched:
                            continue

                    if group_name == "cookie_rule" and cookies_list:
                        for ck in cookies_list:
                            if matches(pattern, ck):
                                add(severity, message, f"cookie {ck}")
                                matched = True
                                break
                        if matched:
                            continue

                    if group_name == "exposed_file_rule" and found_files:
                        for fn in found_files:
                            if matches(pattern, fn):
                                add(severity, message, f"file {fn}")
                                matched = True
                                break
                        if matched:
                            continue

                    if group_name == "cms_plugin_rule" and plugins_list:
                        for p in plugins_list:
                            if matches(pattern, p):
                                add(severity, message, f"plugin {p}")
                                matched = True
                                break
                        if matched:
                            continue

                    if group_name == "redirect_rule" and redirects:
                        for r in redirects:
                            if matches(pattern, r):
                                add(severity, message, f"redirect {r}")
                                matched = True
                                break
                        if matched:
                            continue

                    getter = group_sources.get(group_name, lambda r: raw_text_lower)
                    try:
                        src = getter(rule) or raw_text_lower
                    except Exception:
                        src = raw_text_lower

                    if matches(pattern, src):
                        ctx = group_name
                        add(severity, message, ctx)
                except Exception:
                    continue

        # Heuristic: directory listing detection even if no explicit rule exists
        if ("directory_listing_rule" not in ruleset or not ruleset.get("directory_listing_rule")) and re.search(r'Index of /|<title>\s*Index of', raw_text, re.IGNORECASE):
            add("High", "Directory listing detected (heuristic)", "raw_output")

        return diags

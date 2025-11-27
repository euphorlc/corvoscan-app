import re
import json
from datetime import datetime
from typing import List, Optional, Dict, Any
from src.results_parser import ToolResultsParser
from src.tool_parsers import FFUFResult, DirectoryEntry


class FFUFParser(ToolResultsParser):
    """Parser for FFUF output — captures header metadata, matched entries and progress stats."""

    def __init__(self):
        super().__init__("ffuf")

    def parse(self, target: str) -> FFUFResult:
        raw_output = self.get_raw_output() or ""
        entries_found: List[DirectoryEntry] = []
        seen_paths = set()
        total_requests = 0
        base_url = target
        filter_criteria = ""

        # progress related
        progress_processed = 0
        progress_total = 0
        requests_per_sec = 0.0
        progress_duration = ""
        errors_count = 0
        progress_info: Dict[str, Any] = {}

        # header metadata (Method, URL, Wordlist, Follow redirects, ...)
        metadata: Dict[str, str] = {}

        in_results_table = False
        # Robust ANSI escape stripper (covers common CSI/OSC sequences)
        _ansi_re = re.compile(r"\x1B[@-_][0-?]*[ -/]*[@-~]|\x1b\][^\x07]*\x07")

        # --- Helper utilities and flags to avoid multiple-parsing and normalize entries ---
        def _canon_path(p: Optional[str]) -> str:
            """Return a normalized path key used for deduplication (no leading/trailing slashes).
            Converts full URLs to path component when possible."""
            if not p:
                return ""
            s = str(p).strip().strip('"').strip("'")
            # try to extract path from full URL
            try:
                from urllib.parse import urlparse

                u = urlparse(s)
                if u.scheme and (u.path is not None):
                    # if path is just '/', treat as empty to avoid duplicates for root
                    if u.path and u.path != "/":
                        s = u.path
                    else:
                        s = ""
            except Exception:
                # ignore parse errors
                pass
            s = s.strip()
            # canonicalize by removing leading/trailing slashes
            if s.startswith("/"):
                s = s.lstrip("/")
            if s.endswith("/"):
                s = s.rstrip("/")
            return s

        def _add_entry(
            path: Optional[str],
            status: int = 0,
            size: int = 0,
            words: int = 0,
            lines_cnt: int = 0,
            dur_ms: Optional[int] = None,
        ) -> bool:
            """Add a DirectoryEntry only if its canonical path wasn't seen before.
            Returns True if the entry was added."""
            canon = _canon_path(path)
            if not canon:
                # if path canonicalizes to empty, skip (avoid ambiguous duplicates)
                return False
            if canon in seen_paths:
                return False
            seen_paths.add(canon)
            entries_found.append(
                DirectoryEntry(
                    path=canon,
                    status_code=status,
                    size=size,
                    words=words,
                    lines=lines_cnt,
                    duration_ms=dur_ms,
                )
            )
            return True

        parsed_from_json = False  # mark if JSON results produced entries so we minimize re-parsing same info from text
        # --- Try to parse JSON/NDJSON output first (ffuf -j / --json) ---
        parsed = None
        try:
            parsed = json.loads(raw_output)
        except Exception:
            # Try NDJSON (one JSON object per line)
            objs = []
            for ln in raw_output.splitlines() or []:
                ln = ln.strip()
                if not ln:
                    continue
                try:
                    objs.append(json.loads(ln))
                except Exception:
                    # ignore non-json lines
                    pass
            if objs:
                if len(objs) == 1:
                    parsed = objs[0]
                else:
                    comb = {"results": []}
                    for o in objs:
                        if (
                            isinstance(o, dict)
                            and "results" in o
                            and isinstance(o["results"], list)
                        ):
                            comb["results"].extend(o["results"])
                        elif isinstance(o, dict) and "result" in o:
                            comb["results"].append(o["result"])
                    if comb["results"]:
                        parsed = comb

        if isinstance(parsed, dict) and parsed.get("results"):
            # JSON-based results — prefer these as they are authoritative
            try:
                before = len(entries_found)
                for r in parsed.get("results", []):
                    # path/input detection (ffuf uses 'input' or nested 'input' dict)
                    path = ""
                    if isinstance(r.get("input"), dict):
                        path = (
                            r.get("input", {}).get("url")
                            or r.get("input", {}).get("path")
                            or r.get("input", {}).get("value")
                            or ""
                        )
                    else:
                        path = (
                            r.get("input")
                            or r.get("uri")
                            or r.get("url")
                            or r.get("path")
                            or ""
                        )
                    try:
                        status = int(r.get("status", 0) or 0)
                    except Exception:
                        status = 0
                    try:
                        size = int(r.get("length", 0) or r.get("size", 0) or 0)
                    except Exception:
                        size = 0
                    try:
                        words = int(r.get("wordcount", 0) or r.get("words", 0) or 0)
                    except Exception:
                        words = 0
                    try:
                        lines_cnt = int(r.get("lines", 0) or 0)
                    except Exception:
                        lines_cnt = 0
                    dur_ms = None
                    dur = r.get("time") or r.get("duration")
                    if isinstance(dur, (int, float)):
                        dur_ms = int(float(dur) * 1000)
                    elif isinstance(dur, str):
                        m = re.search(r"(\d+(?:\.\d+)?)", dur)
                        if m:
                            dur_ms = int(float(m.group(1)) * 1000)
                    # use centralized add (handles canonicalization and dedupe)
                    _add_entry(
                        path,
                        status=status,
                        size=size,
                        words=words,
                        lines_cnt=lines_cnt,
                        dur_ms=dur_ms,
                    )
                after = len(entries_found)
                if after > before:
                    parsed_from_json = True
                # attach some top-level metadata if present
                if isinstance(parsed.get("config"), dict):
                    # Normalize known config keys into canonical metadata names
                    cfg = parsed.get("config", {})
                    if "wordlist" in cfg:
                        metadata["wordlist_raw"] = str(cfg.get("wordlist") or "")
                    for k in (
                        "method",
                        "url",
                        "follow",
                        "timeout",
                        "threads",
                        "matcher",
                        "calibration",
                    ):
                        if k in cfg and cfg.get(k) not in (None, ""):
                            metadata[k if k != "follow" else "follow_redirects"] = str(
                                cfg.get(k)
                            )
            except Exception:
                # if JSON parsing unexpectedly fails, fall back to text heuristics below
                pass

        # --- Try to extract progress/stats from JSON/NDJSON if available (common keys) ---
        if isinstance(parsed, dict):
            p = parsed.get("progress") or parsed.get("stats") or parsed.get("summary")
            if isinstance(p, dict):
                try:
                    progress_processed = int(
                        p.get("processed")
                        or p.get("current")
                        or p.get("count")
                        or progress_processed
                    )
                except Exception:
                    pass
                try:
                    progress_total = int(
                        p.get("total")
                        or p.get("max")
                        or p.get("total_requests")
                        or progress_total
                    )
                except Exception:
                    pass
                try:
                    requests_per_sec = float(
                        str(
                            p.get("rps")
                            or p.get("requests_per_sec")
                            or p.get("req_per_sec")
                            or requests_per_sec
                        ).replace(",", "")
                    )
                except Exception:
                    pass
                if p.get("duration") is not None:
                    progress_duration = str(p.get("duration"))
                try:
                    errors_count = int(
                        p.get("errors") or p.get("errs") or errors_count or 0
                    )
                except Exception:
                    pass
                # keep raw JSON progress for debug
                progress_info.setdefault("metadata", {})["json_progress"] = p

        # regex patterns (text fallback)
        re_header = re.compile(r"^(?:\s*::\s*)?(?P<key>[^:]+?)\s*:\s*(?P<val>.+)$")
        re_separator = re.compile(r"^[\s_\-]{3,}$")
        re_old = re.compile(
            r"\[Status:\s*(?P<status>\d+),\s*Size:\s*(?P<size>\d+)(?:,\s*Words:\s*(?P<words>\d+))?(?:,\s*Lines:\s*(?P<lines>\d+))?(?:,\s*Duration:\s*(?P<dur>\d+)ms)?\]\s*::\s*(?P<path>.+)$"
        )
        re_path_before_bracket = re.compile(
            r"^(?P<path>\S(?:.*?\S)?)\s*\[\s*Status:\s*(?P<status>\d+),\s*Size:\s*(?P<size>\d+)(?:,\s*Words:\s*(?P<words>\d+))?(?:,\s*Lines:\s*(?P<lines>\d+))?(?:,\s*Duration:\s*(?P<dur>\d+)ms)?\s*\]"
        )
        # permissive/simple match for lines like:
        # uploads           [Status: 301, Size: 169, Words: 5, Lines: 8, Duration: 30ms]
        re_simple = re.compile(
            r"^\s*(?P<path>[^\[\n]+?)\s*\[\s*Status:\s*(?P<status>\d+),\s*Size:\s*(?P<size>\d+)(?:,\s*Words:\s*(?P<words>\d+))?(?:,\s*Lines:\s*(?P<lines>\d+))?(?:,\s*Duration:\s*(?P<dur>\d+)ms)?\s*\]",
            re.IGNORECASE,
        )
        re_tokens = re.compile(
            r"Status:\s*(?P<status>\d+).*?Size:\s*(?P<size>\d+)", re.IGNORECASE
        )
        re_progress = re.compile(
            r"Progress:\s*\[\s*(?P<processed>\d+)\s*/\s*(?P<total>\d+)\s*\].*?(?P<rps>[\d,]+(?:\.\d+)?)\s*req/sec.*?Duration:\s*\[(?P<dur>[^\]]+)\].*?Errors:\s*(?P<errs>\d+)",
            re.IGNORECASE,
        )

        # If JSON already gave entries, we can still inspect headers/progress from raw lines.
        # fallback to raw_output lines when self.raw_lines is empty (ensures we parse progress lines)
        for raw_line in self.raw_lines or raw_output.splitlines():
            line = (raw_line or "").rstrip()
            if not line:
                continue

            # strip common ANSI escapes for parsing
            try:
                line = _ansi_re.sub("", line)
            except Exception:
                pass

            # QUICK: permissive parse for bracketed-status rows (covers your sample)
            try:
                m_simple = re_simple.match(line)
                if m_simple:
                    # use the centralized add function which prevents duplicates
                    path = m_simple.group("path").strip()
                    status = int(m_simple.group("status") or 0)
                    size = int(m_simple.group("size") or 0)
                    words = (
                        int(m_simple.group("words") or 0)
                        if m_simple.group("words")
                        else 0
                    )
                    lines_cnt = (
                        int(m_simple.group("lines") or 0)
                        if m_simple.group("lines")
                        else 0
                    )
                    dur_ms = (
                        int(m_simple.group("dur")) if m_simple.group("dur") else None
                    )
                    _add_entry(
                        path,
                        status=status,
                        size=size,
                        words=words,
                        lines_cnt=lines_cnt,
                        dur_ms=dur_ms,
                    )
                    in_results_table = True
                    continue
            except Exception:
                pass

            # detect a pipe-separated table header like: Path | Status | Size | Words | Lines | Duration
            if (not in_results_table) and (
                "|" in line and "Path" in line and "Status" in line
            ):
                in_results_table = True
                continue

            # header metadata lines appear before the separator
            if not in_results_table:
                m_header = re_header.match(line)
                if m_header:
                    key = m_header.group("key").strip()
                    val = m_header.group("val").strip()
                    # Normalize key for checks (lowercase, single spaces)
                    k_norm = re.sub(r"\s+", " ", key).lower()

                    # Skip noisy debug/progress headers that we don't want in metadata
                    # e.g. "DEBUG start command: ..." or "Progress: [...]"
                    if (
                        "debug" in k_norm
                        or k_norm == "progress"
                        or k_norm.startswith("progress ")
                    ):
                        continue

                    # Heuristic canonicalization mapping
                    canonical = None
                    if "method" in k_norm:
                        canonical = "method"
                    elif "url" in k_norm:
                        canonical = "url"
                    elif "wordlist" in k_norm:
                        # preserve raw textual value
                        canonical = "wordlist_raw"
                    elif "follow" in k_norm:
                        canonical = "follow_redirects"
                    elif "calibr" in k_norm:
                        canonical = "calibration"
                    elif (
                        "timeout" in k_norm
                        or "maxtime" in k_norm
                        or "max-time" in k_norm
                    ):
                        canonical = "timeout"
                    elif "thread" in k_norm:
                        canonical = "threads"
                    elif "matcher" in k_norm or "match" in k_norm:
                        canonical = "matcher"
                    else:
                        # fallback: accept some other useful tokens
                        if any(
                            tok in k_norm
                            for tok in ("filter", "requests", "duration", "errors")
                        ):
                            canonical = k_norm  # keep original-ish key

                    # Heuristic to detect ASCII banners / art lines so we don't record them as metadata.
                    def _looks_like_ascii_art(s: str) -> bool:
                        if not s:
                            return False
                        non_alnum = sum(
                            1 for ch in s if not ch.isalnum() and not ch.isspace()
                        )
                        ratio = non_alnum / max(1, len(s))
                        if ratio > 0.40:
                            return True
                        if re.search(r"[^A-Za-z0-9\s]{6,}", s):
                            return True
                        if re.search(r"[_\-\|\\/]{6,}", s):
                            return True
                        return False

                    # Accept header if canonical or if it looks like a useful hint and not ASCII art
                    if canonical or not (
                        _looks_like_ascii_art(key) or _looks_like_ascii_art(val)
                    ):
                        store_key = canonical or k_norm
                        # preserve original header key too (exact casing) so we can expose the block later
                        if key not in metadata:
                            metadata[key] = val
                        # do not overwrite canonicalized metadata keys repeatedly with identical values
                        if store_key not in metadata:
                            metadata[store_key] = val
                        # update some derived fields
                        if store_key in ("url", "url "):
                            base_url = val
                        if store_key in ("wordlist_raw", "wordlist"):
                            metadata["wordlist_raw"] = val
                        continue

                    # else: skip noisy/banner header line
                    continue

            # detect separator (start of results table)
            if not in_results_table and re_separator.match(line):
                in_results_table = True
                continue

            # If we're in the results table, parse match rows
            if in_results_table:
                # try parsing pipe-separated rows (Path | Status | Size | Words | Lines | Duration)
                if "|" in line:
                    cols = [c.strip() for c in line.split("|")]
                    # skip the header row if present
                    if cols and cols[0].lower().startswith("path"):
                        continue
                    try:
                        if len(cols) >= 2:
                            path = cols[0]
                            status_str = re.sub(r"[^\d]", "", cols[1]) or "0"
                            status = int(status_str)
                            size = (
                                int(re.sub(r"[^\d]", "", cols[2]))
                                if len(cols) > 2 and re.search(r"\d", cols[2])
                                else 0
                            )
                            words = (
                                int(re.sub(r"[^\d]", "", cols[3]))
                                if len(cols) > 3 and re.search(r"\d", cols[3])
                                else 0
                            )
                            lines_cnt = (
                                int(re.sub(r"[^\d]", "", cols[4]))
                                if len(cols) > 4 and re.search(r"\d", cols[4])
                                else 0
                            )
                            dur_ms = None
                            if len(cols) > 5 and cols[5]:
                                mdur = re.search(r"(\d+)\s*ms", cols[5])
                                if mdur:
                                    dur_ms = int(mdur.group(1))
                            _add_entry(
                                path,
                                status=status,
                                size=size,
                                words=words,
                                lines_cnt=lines_cnt,
                                dur_ms=dur_ms,
                            )
                            continue
                    except Exception:
                        # fall through to other heuristics
                        pass

                # try old-style [Status:...] :: /path
                m_old = re_old.search(line)
                if m_old:
                    try:
                        path = m_old.group("path").strip()
                        if path and path not in seen_paths:
                            seen_paths.add(path)
                            status = int(m_old.group("status"))
                            size = int(m_old.group("size"))
                            words = (
                                int(m_old.group("words")) if m_old.group("words") else 0
                            )
                            lines_cnt = (
                                int(m_old.group("lines")) if m_old.group("lines") else 0
                            )
                            duration_ms = (
                                int(m_old.group("dur")) if m_old.group("dur") else None
                            )
                            entries_found.append(
                                DirectoryEntry(
                                    path=path,
                                    status_code=status,
                                    size=size,
                                    words=words,
                                    lines=lines_cnt,
                                    duration_ms=duration_ms,
                                )
                            )
                        continue
                    except Exception:
                        pass

                # try "path [Status: ...]" style (common)
                m_pb = re_path_before_bracket.search(line)
                if m_pb:
                    try:
                        path = m_pb.group("path").strip()
                        if path and path not in seen_paths:
                            seen_paths.add(path)
                            status = int(m_pb.group("status"))
                            size = int(m_pb.group("size"))
                            words = (
                                int(m_pb.group("words")) if m_pb.group("words") else 0
                            )
                            lines_cnt = (
                                int(m_pb.group("lines")) if m_pb.group("lines") else 0
                            )
                            duration_ms = (
                                int(m_pb.group("dur")) if m_pb.group("dur") else None
                            )
                            entries_found.append(
                                DirectoryEntry(
                                    path=path,
                                    status_code=status,
                                    size=size,
                                    words=words,
                                    lines=lines_cnt,
                                    duration_ms=duration_ms,
                                )
                            )
                        continue
                    except Exception:
                        pass

                # permissive fallback: look for tokens and infer path
                mt = re_tokens.search(line)
                if mt:
                    try:
                        status = int(mt.group("status"))
                        size = int(mt.group("size"))
                        path_candidate = ""
                        br_idx = line.find("[")
                        if br_idx > 0:
                            left = line[:br_idx].strip()
                            toks = re.split(r"\s{2,}|\s+\|\s+|\s+", left)
                            if toks:
                                path_candidate = toks[-1].strip()
                        if not path_candidate:
                            t = re.search(r"::\s*(.+)$", line)
                            if t:
                                path_candidate = t.group(1).strip()
                        if not path_candidate:
                            toks2 = line.strip().split()
                            if toks2:
                                path_candidate = toks2[0].strip()
                        _add_entry(path_candidate, status=status, size=size)
                        continue
                    except Exception:
                        pass

                # plain path fallback
                plain_path = re.match(r"^\s*/\S+", line)
                if plain_path:
                    path = line.strip().split()[0]
                    _add_entry(path, status=0, size=0)
                    continue

                # non-entry table line — skip
                continue

            # not yet in table: capture progress / summary info and filters
            if "Progress:" in line:
                mprog = re_progress.search(line)
                if mprog:
                    try:
                        progress_processed = int(mprog.group("processed"))
                        progress_total = int(mprog.group("total"))
                        requests_per_sec = float(mprog.group("rps").replace(",", ""))
                        progress_duration = mprog.group("dur").strip()
                        errors_count = int(mprog.group("errs"))
                        total_requests = progress_total or total_requests
                    except Exception:
                        pass
                else:
                    p = re.search(r"Progress:\s*\[\s*(\d+)\s*/\s*(\d+)\s*\]", line)
                    if p:
                        try:
                            progress_processed = int(p.group(1))
                            progress_total = int(p.group(2))
                            total_requests = progress_total or total_requests
                        except Exception:
                            pass
                    rps = re.search(r"([\d,]+(?:\.\d+)?)\s*req/sec", line)
                    if rps:
                        try:
                            requests_per_sec = float(rps.group(1).replace(",", ""))
                        except Exception:
                            pass
                    dur = re.search(r"Duration:\s*\[([^\]]+)\]", line)
                    if dur:
                        progress_duration = dur.group(1).strip()
                    err = re.search(r"Errors:\s*(\d+)", line)
                    if err:
                        try:
                            errors_count = int(err.group(1))
                        except Exception:
                            pass
                # merge progress info without overwriting existing metadata block
                progress_info.setdefault("metadata", {})
                progress_info.update(
                    {
                        "processed": progress_processed,
                        "total": progress_total,
                        "requests_per_sec": requests_per_sec,
                        "duration": progress_duration,
                        "errors": errors_count,
                    }
                )
                # keep a small debug field of the last progress line
                progress_info["metadata"].setdefault(
                    "last_progress_line", line.strip()[:200]
                )
                continue

            # capture "87664 requests"
            mreqs = re.search(r"(\d+)\s+requests", line, re.IGNORECASE)
            if mreqs:
                try:
                    total_requests = int(mreqs.group(1))
                except Exception:
                    pass

            # capture filter lines
            # Conservative capture for explicit ffuf "Filter" headers or short filter lines.
            # Avoid capturing large ASCII-art banners or noisy header blocks.
            def _looks_like_ascii_art_line(s: str) -> bool:
                if not s:
                    return False
                # high ratio of non-alnum characters -> art
                non_alnum = sum(1 for ch in s if not ch.isalnum() and not ch.isspace())
                ratio = non_alnum / max(1, len(s))
                if ratio > 0.40:
                    return True
                # long runs of punctuation/slashes/backslashes are typical art
                if re.search(r"[^A-Za-z0-9\s]{6,}", s):
                    return True
                if re.search(r"[_\-\|\\/]{6,}", s):
                    return True
                return False

            if not filter_criteria and re.search(r"\bfilter\b", line, re.IGNORECASE):
                # only accept when it looks like an explicit header or a short filter description
                if _looks_like_ascii_art_line(line):
                    # skip obvious banner/noise
                    pass
                else:
                    # match patterns like:
                    # " :: Filter           : Response status: 200"
                    # "Filter: ...", "Response filter: ..."
                    m = re.search(
                        r"(?:\:\:\s*)?Filter\b\s*[:\-]?\s*(?P<val>.+)$",
                        line,
                        re.IGNORECASE,
                    )
                    if not m:
                        # fallback: sometimes shown as "Response filter: ..." or "Filter <something>"
                        m = re.search(
                            r"Response\s+filter\b\s*[:\-]?\s*(?P<val>.+)$",
                            line,
                            re.IGNORECASE,
                        )
                    if m:
                        val = m.group("val").strip()
                        # avoid capturing massive blocks — require reasonable length
                        if 0 < len(val) <= 300:
                            filter_criteria = val
                    else:
                        # as a last resort accept short single-line mentions that look legit
                        s = line.strip()
                        if len(s) <= 200:
                            filter_criteria = s

        # augment progress_info
        progress_info.setdefault("total_requests", total_requests)
        progress_info.setdefault("errors_count", errors_count)
        # Robust post-scan pass: extract final progress/summary values from the raw output
        try:
            cleaned = _ansi_re.sub("", raw_output or "")
            # last seen Progress: [processed/total]
            m = None
            for mm in re.finditer(r"Progress:\s*\[\s*(\d+)\s*/\s*(\d+)\s*\]", cleaned):
                m = mm
            if m:
                try:
                    progress_processed = int(m.group(1))
                    progress_total = int(m.group(2))
                    total_requests = progress_total or total_requests
                except Exception:
                    pass

            # last seen req/sec
            m = None
            for mm in re.finditer(r"([\d,]+(?:\.\d+)?)\s*req/sec", cleaned):
                m = mm
            if m:
                try:
                    requests_per_sec = float(m.group(1).replace(",", ""))
                except Exception:
                    pass

            # last seen Duration: [..]
            m = None
            for mm in re.finditer(r"Duration:\s*\[([^\]]+)\]", cleaned):
                m = mm
            if m:
                progress_duration = m.group(1).strip()

            # last seen Errors: N
            m = None
            for mm in re.finditer(r"Errors:\s*(\d+)", cleaned):
                m = mm
            if m:
                try:
                    errors_count = int(m.group(1))
                except Exception:
                    pass

            # fallback: explicit '<N> requests' anywhere
            m = re.search(r"\b(\d{2,})\s+requests\b", cleaned, re.IGNORECASE)
            if m:
                try:
                    total_requests = int(m.group(1))
                except Exception:
                    pass

            # update progress_info with discovered values (do not overwrite existing metadata block)
            progress_info.setdefault("total_requests", total_requests)
            progress_info.setdefault("processed", progress_processed)
            progress_info.setdefault("total", progress_total)
            progress_info.setdefault("requests_per_sec", requests_per_sec)
            progress_info.setdefault("duration", progress_duration)
            progress_info.setdefault("errors_count", errors_count)
        except Exception:
            # best-effort: ignore failures in the post-scan pass
            pass

        # ensure wordlist present at top-level if we found it
        if progress_info.get("metadata", {}).get("wordlist_raw"):
            progress_info.setdefault(
                "wordlist", progress_info["metadata"].get("wordlist_raw")
            )
        elif metadata.get("wordlist_raw"):
            progress_info.setdefault("wordlist", metadata.get("wordlist_raw"))

        # Canonicalize progress_info keys so there is only one canonical representation
        try:
            # preferred keys (match FFUFResult naming)
            prog_processed = progress_info.pop(
                "processed", progress_info.pop("progress_processed", progress_processed)
            )
            prog_total = progress_info.pop(
                "total", progress_info.pop("progress_total", progress_total)
            )
            prog_rps = progress_info.pop(
                "requests_per_sec", progress_info.pop("rps", requests_per_sec)
            )
            prog_dur = progress_info.pop(
                "duration", progress_info.pop("progress_duration", progress_duration)
            )
            prog_errors = progress_info.pop("errors_count", errors_count)
            prog_total_requests = progress_info.pop("total_requests", total_requests)

            # remove any legacy aliases that might remain
            for alias in ("processed", "total", "duration", "rps"):
                if alias in progress_info:
                    try:
                        del progress_info[alias]
                    except Exception:
                        pass

            # set canonical keys
            progress_info["progress_processed"] = (
                int(prog_processed) if prog_processed is not None else 0
            )
            progress_info["progress_total"] = (
                int(prog_total) if prog_total is not None else 0
            )
            # requests per sec can be float
            try:
                progress_info["requests_per_sec"] = (
                    float(prog_rps) if prog_rps is not None else 0.0
                )
            except Exception:
                progress_info["requests_per_sec"] = 0.0
            progress_info["progress_duration"] = (
                str(prog_dur) if prog_dur is not None else ""
            )
            progress_info["errors_count"] = (
                int(prog_errors) if prog_errors is not None else 0
            )
            progress_info["total_requests"] = (
                int(prog_total_requests) if prog_total_requests is not None else 0
            )
        except Exception:
            # don't fail parsing on canonicalization issues
            pass

        # Finalize metadata as the LAST block in progress_info:
        # Build a canonicalized metadata block and place it at the end by popping any
        # earlier 'metadata' key and reassigning it (preserves canonical keys and original headers).
        if metadata:
            canonical_map = {}
            for k, v in metadata.items():
                k_lower = k.lower()
                if k_lower in ("method", "method "):
                    canonical_map["method"] = v
                elif k_lower in ("url",):
                    canonical_map["url"] = v
                elif k_lower in ("wordlist_raw", "wordlist", "wordlist raw"):
                    canonical_map["wordlist_raw"] = v
                    canonical_map["wordlist"] = v
                elif k_lower in (
                    "follow_redirects",
                    "follow redirects",
                    "follow-redirect",
                    "follow",
                ):
                    canonical_map["follow_redirects"] = v
                elif "calibr" in k_lower:
                    canonical_map["calibration"] = v
                elif k_lower in ("timeout", "maxtime", "max-time"):
                    canonical_map["timeout"] = v
                elif "thread" in k_lower:
                    canonical_map["threads"] = v
                elif "matcher" in k_lower:
                    canonical_map["matcher"] = v
                else:
                    canonical_map[k_lower] = v

            final_meta = {}
            final_meta.update(canonical_map)
            for orig_k, orig_v in metadata.items():
                if orig_k not in final_meta:
                    final_meta[orig_k] = orig_v
            if canonical_map.get("url"):
                base_url = canonical_map.get("url")

            # Do not include the metadata block in the final output (user requested it removed)
            progress_info.pop("metadata", None)

        # success logic (was missing) — determine if parse considered successful and extract error_message when not
        def _has_errors_simple() -> bool:
            # If explicit error count tracked, treat as error
            try:
                if errors_count and errors_count > 0:
                    return True
            except Exception:
                pass
            # look for common error/fatal markers in raw output
            if re.search(
                r"^\s*(error|fatal|failed|ffuf:)",
                raw_output,
                re.IGNORECASE | re.MULTILINE,
            ):
                return True
            if re.search(
                r"connection refused|no such file|no such host|permission denied",
                raw_output,
                re.IGNORECASE,
            ):
                return True
            return False

        has_errors = _has_errors_simple()
        success = (len(entries_found) > 0) or (not has_errors)
        error_message = None if success else self._extract_error_message()

        # augment progress_info
        progress_info.setdefault("total_requests", total_requests)
        progress_info.setdefault("errors_count", errors_count)
        # ensure wordlist present at top-level if we found it
        if progress_info.get("metadata", {}).get("wordlist_raw"):
            progress_info.setdefault(
                "wordlist", progress_info["metadata"].get("wordlist_raw")
            )
        elif metadata.get("wordlist_raw"):
            progress_info.setdefault("wordlist", metadata.get("wordlist_raw"))

        # build result, compute diagnostics and attach them
        result = FFUFResult(
            tool_name="ffuf",
            target=target,
            timestamp=datetime.now().isoformat(),
            raw_output=raw_output,
            success=success,
            error_message=error_message,
            base_url=base_url,
            entries_found=entries_found,
            total_requests=total_requests,
            filter_criteria=filter_criteria,
            progress_processed=progress_processed,
            progress_total=progress_total,
            requests_per_sec=requests_per_sec,
            progress_duration=progress_duration,
            errors_count=errors_count,
            progress_info=progress_info,
        )
        try:
            result.diagnostics = self._compute_diagnostics(
                entries_found, {"raw_output": raw_output}
            )
        except Exception:
            result.diagnostics = []
        return result

    def _extract_error_message(self) -> Optional[str]:
        for line in self.raw_lines or []:
            if not line:
                continue
            s = line.strip()
            if re.match(r"^(error|error:|failed to|fatal|ffuf:)", s, re.IGNORECASE):
                return s
            m = re.search(r"Errors:\s*(\d+)", s, re.IGNORECASE)
            if m and int(m.group(1)) > 0:
                return s
            if re.search(
                r"connection refused|no such file|no such host|permission denied",
                s,
                re.IGNORECASE,
            ):
                return s
        return None

    def _compute_diagnostics(
        self,
        findings: List[DirectoryEntry],
        scan_stats: Optional[Dict[str, Any]] = None,
    ) -> List[Dict[str, Any]]:
        """
        Compare discovered paths (DirectoryEntry list) against rules in rulesets/ffuf_ruleset.json
        and return diagnostics: list of {"severity","message","context"}.
        """
        import os, json, re

        scan_stats = scan_stats or {}
        diags: List[Dict[str, Any]] = []

        # load/cached ruleset
        ruleset = getattr(self, "ffuf_ruleset", None) or {}
        if not ruleset:
            try:
                here = (
                    os.path.dirname(__file__)
                    if "__file__" in globals()
                    else os.getcwd()
                )
                candidates = [
                    os.path.join(here, "ffuf_ruleset.json"),
                    os.path.join(here, "rulesets", "ffuf_ruleset.json"),
                    os.path.join(os.getcwd(), "rulesets", "ffuf_ruleset.json"),
                ]
                env_path = os.environ.get("FFUF_RULESET_PATH")
                if env_path:
                    candidates.insert(0, env_path)
                for p in candidates:
                    try:
                        p = os.path.abspath(p)
                        if os.path.exists(p):
                            with open(p, "r", encoding="utf-8") as fh:
                                ruleset = json.load(fh) or {}
                                self.ffuf_ruleset = ruleset
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

        def matches(pattern: str, text: str) -> bool:
            try:
                return bool(re.search(pattern, text or "", re.IGNORECASE))
            except re.error:
                return pattern.lower() in (text or "").lower()

        path_rules = []
        if isinstance(ruleset, dict):
            path_rules = ruleset.get("path_rules") or []

        if not path_rules or not findings:
            return diags

        # Normalize each finding path and compare
        for ent in findings or []:
            try:
                if isinstance(ent, dict):
                    p = ent.get("path") or ent.get("url") or ""
                    status = int(ent.get("status") or ent.get("status_code") or 0)
                else:
                    p = getattr(ent, "path", "") or getattr(ent, "url", "") or ""
                    status = int(getattr(ent, "status_code", 0) or 0)
                # strip query string and leading slash for rule matching
                hay = str(p).split("?", 1)[0].lstrip("/")
                hay = hay.strip()
                if not hay:
                    continue

                for rule in path_rules or []:
                    try:
                        rule_path = rule.get("path") or ""
                        if not rule_path:
                            continue
                        rule_status = rule.get("status", None)
                        # status can be single int or list
                        if rule_status is not None:
                            try:
                                if isinstance(rule_status, list):
                                    if status not in [int(x) for x in rule_status]:
                                        continue
                                else:
                                    if int(rule_status) != int(status):
                                        continue
                            except Exception:
                                # if status comparison fails, skip status check
                                pass

                        if matches(rule_path, hay):
                            sev = (
                                rule.get("severity")
                                or defaults.get("severity")
                                or "Info"
                            )
                            msg = (
                                rule.get("message") or f"Path rule matched: {rule_path}"
                            )
                            ctx = f"{hay} (status:{status})"
                            add(sev, msg, ctx)
                    except Exception:
                        continue
            except Exception:
                continue

        return diags

    def _maybe_int(v):
        try:
            if v is None or v == "":
                return None
            return int(v)
        except Exception:
            try:
                return int(str(v).strip())
            except Exception:
                return None

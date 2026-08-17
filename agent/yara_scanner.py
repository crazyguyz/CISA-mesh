"""
YARA/Pattern Scanner for GIAM-SAT Agent v1.6.0
Scans for malware patterns using YARA rules (if available) or regex-based fallback.

v1.6.0: Adaptive file size scanning (defeats binary padding evasion)
  - ≤10MB:  Scan toàn bộ file
  - 10-50MB:  5MB đầu + 5MB cuối + PE header
  - 50-200MB: 2MB đầu + 2MB cuối + PE overlay
  - >200MB:   1MB đầu + 1MB cuối (chỉ signature)
  - PE-aware: Parse PE structure, scan .text section + overlay
"""

import os
import re
import time
import threading
import subprocess
import json
import math
from collections import Counter
from datetime import datetime

try:
    import yara
    HAS_YARA = True
except ImportError:
    HAS_YARA = False

# Built-in suspicious pattern rules (fallback when yara not available)
SUSPICIOUS_PATTERNS = [
    {"name": "Mimikatz_Strings", "pattern": rb"mimikatz|mimilib|sekurlsa|wdigest", "desc": "Mimikatz credential dumping tool"},
    {"name": "PowerShell_WebClient", "pattern": rb"Net\.WebClient|DownloadFile|DownloadString|Invoke-WebRequest.*-OutFile", "desc": "PowerShell download cradle"},
    {"name": "Reverse_Shell", "pattern": rb"cmd\.exe.*\/c.*nc\s|powershell.*-e\s|bash -i >&", "desc": "Reverse shell command"},
    {"name": "Ransomware_Note", "pattern": rb"YOUR_FILES_ARE_ENCRYPTED|ransom|bitcoin|decrypt.*files", "desc": "Ransomware note strings"},
    {"name": "Encoded_PS", "pattern": rb"-e(nc|ncodedCommand)?\s+[A-Za-z0-9+/=]{100,}", "desc": "Base64 encoded PowerShell command"},
    {"name": "CobaltStrike_Beacon", "pattern": rb"MSSE-%d|beacon.dll|ReflectiveLoader|cobaltstrike", "desc": "Cobalt Strike beacon"},
    {"name": "WMI_Persistence", "pattern": rb"__EventFilter|__EventConsumer|CommandLineEventConsumer|ActiveScriptEventConsumer", "desc": "WMI persistence"},
    {"name": "Schtasks_Persist", "pattern": rb"schtasks.*\/create.*\/sc\s+onlogon|schtasks.*\/create.*\/sc\s+minute", "desc": "Scheduled task persistence"},
    {"name": "Reg_Persistence", "pattern": rb"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run|HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "desc": "Registry run key persistence"},
    {"name": "Process_Injection", "pattern": rb"VirtualAllocEx|WriteProcessMemory|CreateRemoteThread|NtCreateThreadEx", "desc": "Process injection API calls"},
]


class YaraScanner:
    def __init__(self, callback=None):
        self.callback = callback
        self.running = True
        self.last_scan = 0
        self.scan_interval = 86400  # Daily
        self.rules = None
        if HAS_YARA:
            self._compile_yara_rules()

    def _compile_yara_rules(self):
        try:
            rules = []
            for p in SUSPICIOUS_PATTERNS:
                pattern_hex = ' '.join(f'{b:02x}' for b in p['pattern'][:20])
                rule = f"""
rule {p['name']} {{
    meta:
        description = "{p['desc']}"
    strings:
        $s = {{{pattern_hex}}}
    condition:
        $s
}}
"""
                rules.append(rule)
            self.rules = yara.compile(sources={p['name']: rules[i] for i, p in enumerate(SUSPICIOUS_PATTERNS)})
        except Exception:
            self.rules = None

    def _read_adaptive_content(self, filepath, file_size):
        """v1.6.0: Read file content adaptively based on size to defeat binary padding.
        Returns (content_bytes, scan_description)
        """
        try:
            with open(filepath, 'rb') as f:
                if file_size <= 10 * 1024 * 1024:
                    # Full scan for small files
                    return f.read(), "full"

                elif file_size <= 50 * 1024 * 1024:
                    # Medium: 5MB head + 5MB tail
                    head = f.read(5 * 1024 * 1024)
                    f.seek(-5 * 1024 * 1024, os.SEEK_END)
                    tail = f.read(5 * 1024 * 1024)
                    return head + tail, "head5MB+tail5MB"

                elif file_size <= 200 * 1024 * 1024:
                    # Large: 2MB head + 2MB tail
                    head = f.read(2 * 1024 * 1024)
                    f.seek(-2 * 1024 * 1024, os.SEEK_END)
                    tail = f.read(2 * 1024 * 1024)
                    return head + tail, "head2MB+tail2MB"

                else:
                    # Huge: 1MB head + 1MB tail
                    head = f.read(1 * 1024 * 1024)
                    f.seek(-1 * 1024 * 1024, os.SEEK_END)
                    tail = f.read(1 * 1024 * 1024)
                    return head + tail, "head1MB+tail1MB"
        except Exception:
            return b"", "error"

    def _detect_pe_sections(self, filepath):
        """v1.6.0: Parse PE header to find important sections for scanning.
        Returns (code_section_data, overlay_data)
        """
        try:
            with open(filepath, 'rb') as f:
                # Read DOS header
                dos_header = f.read(64)
                if dos_header[:2] != b'MZ':
                    return b"", b""

                # Get PE offset
                pe_offset = int.from_bytes(dos_header[60:64], 'little')
                f.seek(pe_offset)

                # Read PE signature
                pe_sig = f.read(4)
                if pe_sig != b'PE\x00\x00':
                    return b"", b""

                # Read COFF header
                coff = f.read(20)
                num_sections = int.from_bytes(coff[2:4], 'little')
                opt_header_size = int.from_bytes(coff[16:18], 'little')

                # Skip optional header to get to section table
                f.seek(pe_offset + 24 + opt_header_size)

                # Find .text section
                code_data = b""
                section_end = 0
                for i in range(min(num_sections, 20)):
                    section = f.read(40)
                    name = section[:8].rstrip(b'\x00').decode('ascii', errors='ignore')
                    virtual_size = int.from_bytes(section[8:12], 'little')
                    raw_offset = int.from_bytes(section[20:24], 'little')
                    raw_size = int.from_bytes(section[16:20], 'little')

                    section_end = max(section_end, raw_offset + raw_size)

                    if name in ('.text', 'CODE'):
                        # Read code section
                        current_pos = f.tell()
                        f.seek(raw_offset)
                        code_data = f.read(min(raw_size, 2 * 1024 * 1024))  # Max 2MB of code
                        f.seek(current_pos)

                # Read overlay (data after PE)
                f.seek(0, os.SEEK_END)
                file_size = f.tell()
                if file_size > section_end + 512:
                    f.seek(section_end)
                    overlay_data = f.read(min(file_size - section_end, 1 * 1024 * 1024))
                    return code_data, overlay_data
                return code_data, b""
        except Exception:
            return b"", b""

    @staticmethod
    def _calculate_entropy(data):
        """v2.6.5: Calculate Shannon entropy of byte data.
        Returns float 0.0-8.0 where very low (<0.2) suggests binary padding (all zeros/repeating).
        """
        if not data:
            return 0.0
        byte_counts = Counter(data)
        total = len(data)
        entropy = 0.0
        for count in byte_counts.values():
            if count > 0:
                p = count / total
                entropy -= p * math.log2(p)
        return entropy

    def _check_binary_padding(self, filepath, file_size):
        """v2.6.5: Check if a large file (>100MB) might be binary padded to evade scanning.
        Reads a sample from the middle of the file and calculates entropy.
        Very low entropy mid-section → probable padding with repeating bytes.
        Returns alert dict or None.
        """
        try:
            with open(filepath, 'rb') as f:
                # Read 10KB sample from the middle of the file
                f.seek(file_size // 2)
                mid_sample = f.read(10 * 1024)  # 10KB
                if len(mid_sample) < 1024:  # Too small to analyze
                    return None
                entropy = self._calculate_entropy(mid_sample)
                if entropy < 0.2:
                    return {
                        "rule_name": "Binary_Padding_Evasion",
                        "description": f"File {os.path.basename(filepath)} ({file_size/1024/1024:.0f}MB) has very low mid-section entropy ({entropy:.3f}): possible binary padding evasion",
                        "file": filepath,
                        "file_size": file_size,
                        "scan_mode": f"entropy_check(mid_entropy={entropy:.3f})",
                    }
        except Exception:
            pass
        return None

    def _scan_with_patterns(self, filepath):
        """v2.6.5: Adaptive pattern-based scan with binary padding detection."""
        results = []
        try:
            file_size = os.path.getsize(filepath)
            content, scan_mode = self._read_adaptive_content(filepath, file_size)

            if not content:
                return results

            # v2.6.5: Entropy check for large files (>100MB) to detect binary padding evasion
            if file_size > 100 * 1024 * 1024:
                padding_alert = self._check_binary_padding(filepath, file_size)
                if padding_alert:
                    results.append(padding_alert)

            # Also get PE-specific data for better coverage
            code_data, overlay_data = self._detect_pe_sections(filepath)
            if code_data:
                content += code_data
            if overlay_data:
                content += overlay_data

            for rule in SUSPICIOUS_PATTERNS:
                if re.search(rule['pattern'], content, re.IGNORECASE):
                    results.append({
                        "rule_name": rule['name'],
                        "description": rule['desc'],
                        "file": filepath,
                        "file_size": file_size,
                        "scan_mode": scan_mode,
                    })
        except Exception:
            pass
        return results

    def _scan_with_yara(self, filepath):
        """v1.6.0: YARA-based scan (YARA handles file access internally)."""
        results = []
        try:
            if self.rules:
                file_size = os.path.getsize(filepath)
                matches = self.rules.match(filepath)
                for match in matches:
                    results.append({
                        "rule_name": match.rule,
                        "description": match.meta.get('description', ''),
                        "file": filepath,
                        "file_size": file_size,
                        "scan_mode": "yara_engine",
                    })
        except Exception:
            pass
        return results

    def scan_directory(self, directory, max_files=100):
        """Scan a directory for suspicious files."""
        results = []
        count = 0
        try:
            for root, dirs, files in os.walk(directory):
                for f in files:
                    if count >= max_files:
                        return results
                    fp = os.path.join(root, f)
                    if any(fp.lower().endswith(ext) for ext in ('.exe', '.dll', '.ps1', '.vbs', '.bat', '.js', '.hta', '.scr', '.sys')):
                        scan_results = self._scan_with_yara(fp) if HAS_YARA and self.rules else self._scan_with_patterns(fp)
                        results.extend(scan_results)
                        count += 1
        except Exception:
            pass
        return results

    def run_scan(self):
        """Perform a full YARA/pattern scan."""
        now = time.time()
        if now - self.last_scan < self.scan_interval:
            return []
        self.last_scan = now

        # Scan common malware locations
        scan_dirs = [
            os.environ.get("TEMP", "C:\\Windows\\Temp"),
            os.path.join(os.environ.get("APPDATA", "C:\\"), "..", "Local", "Temp"),
            "C:\\Windows\\Temp",
            os.path.join(os.environ.get("USERPROFILE", "C:\\Users\\Public"), "Downloads"),
        ]
        scan_dirs = [d for d in scan_dirs if os.path.exists(d)]

        all_results = []
        for d in scan_dirs:
            all_results.extend(self.scan_directory(d, max_files=50))

        results = []
        for r in all_results:
            event = {
                "type": "yara_alert",
                "rule_name": r["rule_name"],
                "description": r["description"],
                "file": r["file"],
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
            results.append(event)
            if self.callback:
                self.callback(event)

        return results
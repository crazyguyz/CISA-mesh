"""
Vulnerability Scanner for GIAM-SAT Agent v1.8.0
v1.8.0: Major accuracy overhaul - 3-step verification pipeline:
  Step 1: OS Fingerprinting - xac dinh chinh xac OS (ten, version, build, arch)
  Step 2: Service Verification - chi scan CVE cho service DANG CHAY + LISTEN port
  Step 3: Exact Version Check - doc binary file header, khong chi dung registry
Plus: CISA KEV filter, token-based name matching, semantic version comparison
"""
import os
import sys
import json
import time
import threading
import subprocess
import urllib.request
import urllib.error
import re
import socket
from datetime import datetime, timedelta

IS_WINDOWS = os.name == "nt"
CREATE_NO_WINDOW = 0x08000000 if IS_WINDOWS else 0

# Cache paths
CACHE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
CVE_CACHE_FILE = os.path.join(CACHE_DIR, "nvd_cve_cache.json")
CVE_LAST_UPDATE_FILE = os.path.join(CACHE_DIR, "nvd_last_update.txt")
CISA_KEV_CACHE = os.path.join(CACHE_DIR, "cisa_kev_cache.json")
CISA_KEV_LAST_UPDATE = os.path.join(CACHE_DIR, "cisa_kev_last_update.txt")

# NVD API configuration
NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_CACHE_DURATION_HOURS = 24
NVD_MAX_RESULTS_PER_REQUEST = 2000
NVD_RATE_LIMIT_SLEEP = 6

# CISA KEV URL
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

# v1.8.0: Severity thresholds with CISA KEV boost
SEVERITY_THRESHOLDS = {
    "cisa_kev": "CRITICAL",       # CVE in CISA KEV = always CRITICAL
    "cvss_critical": 9.0,          # CVSS >= 9.0 without KEV = HIGH
    "cvss_high": 7.0,              # CVSS >= 7.0 without KEV = MEDIUM (informational)
    "cvss_medium": 5.0,            # CVSS >= 5.0 without KEV = LOW (informational only)
    # Below 5.0: skip entirely
}

# v1.8.0: Token-based matching stop words
STOP_WORDS = {
    "microsoft", "inc", "llc", "ltd", "corp", "corporation", "software",
    "version", "edition", "for", "the", "and", "or", "a", "an", "with",
    "windows", "linux", "mac", "server", "client", "professional", "enterprise",
}

# Hardcoded fallback CVE database
_FALLBACK_CVE_DB = [
    {"cve": "CVE-2023-21716", "software": "Microsoft Office", "product": "Microsoft Word",
     "versions_affected": ["<=16.0.16026.20214"], "severity": "CRITICAL", "cvss": 9.8,
     "description": "Microsoft Word Remote Code Execution Vulnerability"},
    {"cve": "CVE-2023-23397", "software": "Microsoft Office", "product": "Microsoft Outlook",
     "versions_affected": ["<=16.0.16130.20218"], "severity": "CRITICAL", "cvss": 9.8,
     "description": "Microsoft Outlook Elevation of Privilege Vulnerability (EoP via NTLM relay)"},
    {"cve": "CVE-2023-29336", "software": "Windows", "product": "Win32k",
     "versions_affected": ["<=10.0.19045.3086"], "severity": "HIGH", "cvss": 7.8,
     "description": "Win32k Elevation of Privilege Vulnerability"},
    {"cve": "CVE-2021-44228", "software": "Apache", "product": "Log4j",
     "versions_affected": ["2.0-beta9 - 2.14.1"], "severity": "CRITICAL", "cvss": 10.0,
     "description": "Log4j Remote Code Execution (Log4Shell)"},
    {"cve": "CVE-2022-22965", "software": "Spring", "product": "Spring Framework",
     "versions_affected": ["<=5.3.18, <=5.2.20"], "severity": "CRITICAL", "cvss": 9.8,
     "description": "Spring Framework Remote Code Execution (Spring4Shell)"},
    {"cve": "CVE-2022-3786", "software": "OpenSSL", "product": "OpenSSL",
     "versions_affected": ["3.0.0 - 3.0.6"], "severity": "HIGH", "cvss": 7.5,
     "description": "OpenSSL X.509 Email Address Buffer Overflow"},
    {"cve": "CVE-2021-34523", "software": "Microsoft", "product": "Exchange Server",
     "versions_affected": ["<=15.2.858.12"], "severity": "CRITICAL", "cvss": 9.8,
     "description": "Microsoft Exchange Server Privilege Escalation (ProxyShell)"},
    {"cve": "CVE-2023-4863", "software": "Google", "product": "Chrome",
     "versions_affected": ["<=116.0.5845.187"], "severity": "HIGH", "cvss": 8.8,
     "description": "Google Chrome libwebp heap buffer overflow"},
    {"cve": "CVE-2023-34048", "software": "VMware", "product": "vCenter Server",
     "versions_affected": ["<=8.0U1"], "severity": "CRITICAL", "cvss": 9.8,
     "description": "VMware vCenter Server Out-of-Bounds Write Vulnerability"},
    {"cve": "CVE-2023-20198", "software": "Cisco", "product": "IOS XE",
     "versions_affected": ["<=17.9.4a"], "severity": "CRITICAL", "cvss": 10.0,
     "description": "Cisco IOS XE Web UI Privilege Escalation"},
    {"cve": "CVE-2023-27997", "software": "Fortinet", "product": "FortiOS",
     "versions_affected": ["<=7.2.5"], "severity": "CRITICAL", "cvss": 9.8,
     "description": "FortiOS SSL-VPN Heap-Based Buffer Overflow (RCE)"},
    {"cve": "CVE-2023-38545", "software": "cURL", "product": "libcurl",
     "versions_affected": ["7.69.0 - 8.3.0"], "severity": "HIGH", "cvss": 7.5,
     "description": "cURL SOCKS5 heap buffer overflow"},
    {"cve": "CVE-2023-36704", "software": "7-Zip", "product": "7-Zip",
     "versions_affected": ["<=23.00"], "severity": "HIGH", "cvss": 7.8,
     "description": "7-Zip SquashFS File Parsing Out-of-Bounds Write"},
    {"cve": "CVE-2024-20669", "software": "Windows", "product": "Windows Kernel",
     "versions_affected": ["<=10.0.19045.4046"], "severity": "HIGH", "cvss": 7.8,
     "description": "Windows Kernel Elevation of Privilege Vulnerability"},
    {"cve": "CVE-2024-21410", "software": "Microsoft", "product": "Exchange Server",
     "versions_affected": ["<=15.2.1544.11"], "severity": "CRITICAL", "cvss": 9.8,
     "description": "Microsoft Exchange Server Privilege Escalation (NTLM relay)"},
    {"cve": "CVE-2024-3400", "software": "PAN", "product": "PAN-OS",
     "versions_affected": ["<=11.1.0-h3"], "severity": "CRITICAL", "cvss": 10.0,
     "description": "PAN-OS GlobalProtect Command Injection (CVE-2024-3400)"},
    {"cve": "CVE-2024-4577", "software": "PHP", "product": "PHP",
     "versions_affected": ["<=8.3.8, <=8.2.20, <=8.1.29"], "severity": "CRITICAL", "cvss": 9.8,
     "description": "PHP CGI Windows Argument Injection leading to RCE (CVE-2024-4577)"},
    {"cve": "CVE-2024-6387", "software": "OpenSSH", "product": "OpenSSH",
     "versions_affected": ["8.5p1 - 9.7p1"], "severity": "HIGH", "cvss": 8.1,
     "description": "OpenSSH signal handler race condition (regreSSHion)"},
    {"cve": "CVE-2021-34527", "software": "Windows", "product": "Print Spooler",
     "versions_affected": ["<=10.0.19043.1110"], "severity": "CRITICAL", "cvss": 8.8,
     "description": "Windows Print Spooler Remote Code Execution (PrintNightmare)"},
    {"cve": "CVE-2020-1472", "software": "Windows", "product": "Netlogon",
     "versions_affected": ["<=10.0.19041"], "severity": "CRITICAL", "cvss": 10.0,
     "description": "Windows Netlogon Elevation of Privilege (Zerologon)"},
    {"cve": "CVE-2024-1086", "software": "Linux", "product": "Linux Kernel",
     "versions_affected": ["3.15 - 6.7"], "severity": "HIGH", "cvss": 7.8,
     "description": "Linux Kernel nf_tables use-after-free (CVE-2024-1086)"},
    {"cve": "CVE-2024-27198", "software": "JetBrains", "product": "TeamCity",
     "versions_affected": ["<=2023.11.3"], "severity": "CRITICAL", "cvss": 9.8,
     "description": "JetBrains TeamCity Authentication Bypass leading to RCE"},
    {"cve": "CVE-2023-34362", "software": "Progress", "product": "MOVEit Transfer",
     "versions_affected": ["<=2023.0.1"], "severity": "CRITICAL", "cvss": 9.8,
     "description": "MOVEit Transfer SQL Injection leading to RCE (CL0P exploitation)"},
]


def _run_hidden(cmd, **kwargs):
    kwargs.setdefault("timeout", 15)
    if IS_WINDOWS:
        kwargs.setdefault("creationflags", CREATE_NO_WINDOW)
    return subprocess.run(cmd, capture_output=True, text=True, **kwargs)


# =============================================================================
# STEP 1: OS FINGERPRINTING
# =============================================================================

def get_os_info():
    """Xac dinh chinh xac he dieu hanh.
    Returns dict with: name, version, build, arch, edition, kernel, type (windows/linux/macos)
    """
    info = {"type": "", "name": "", "version": "", "build": "", "arch": "", "edition": "", "kernel": ""}

    if IS_WINDOWS:
        info["type"] = "windows"
        try:
            # wmic is deprecated/removed on Windows 11 24H2+; use PowerShell CIM instead.
            ps = ("$o=Get-CimInstance Win32_OperatingSystem; "
                  "'{0}|{1}|{2}|{3}' -f $o.Caption,$o.Version,$o.BuildNumber,$o.OSArchitecture")
            r = _run_hidden(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps], timeout=15)
            if r.stdout:
                parts = r.stdout.strip().split("|")
                if len(parts) >= 4:
                    info["name"] = parts[0].strip()  # e.g., "Microsoft Windows 11 Pro"
                    info["version"] = parts[1].strip()  # e.g., "10.0.22631"
                    info["build"] = parts[2].strip()  # e.g., "22631"
                    info["arch"] = parts[3].strip()  # e.g., "64-bit"
            # Try to get edition
            if "Pro" in info.get("name", "") or "Professional" in info.get("name", ""):
                info["edition"] = "Professional"
            elif "Enterprise" in info.get("name", ""):
                info["edition"] = "Enterprise"
            elif "Home" in info.get("name", ""):
                info["edition"] = "Home"
            # Kernel version = build
            info["kernel"] = info.get("build", "")
        except Exception as e:
            info["name"] = "Windows"
            print(f"[-] OS fingerprint error: {e}")

    elif sys.platform == "darwin":
        info["type"] = "macos"
        try:
            r = _run_hidden(["sw_vers"], timeout=5)
            for line in r.stdout.split("\n"):
                if "ProductName:" in line:
                    info["name"] = line.split(":")[-1].strip()
                elif "ProductVersion:" in line:
                    info["version"] = line.split(":")[-1].strip()
                elif "BuildVersion:" in line:
                    info["build"] = line.split(":")[-1].strip()
            ur = _run_hidden(["uname", "-a"], timeout=5)
            if ur.stdout:
                parts = ur.stdout.strip().split()
                info["kernel"] = parts[2] if len(parts) > 2 else ""
                info["arch"] = parts[-1] if parts else ""
        except Exception:
            info["name"] = "macOS"

    else:
        info["type"] = "linux"
        try:
            r = _run_hidden(["cat", "/etc/os-release"], timeout=5)
            for line in r.stdout.split("\n"):
                if line.startswith("NAME="):
                    info["name"] = line.split("=")[1].strip().strip('"')
                elif line.startswith("VERSION_ID="):
                    info["version"] = line.split("=")[1].strip().strip('"')
                elif line.startswith("VERSION="):
                    if not info.get("version"):
                        info["version"] = line.split("=")[1].strip().strip('"')
            ur = _run_hidden(["uname", "-a"], timeout=5)
            if ur.stdout:
                parts = ur.stdout.strip().split()
                info["kernel"] = parts[2] if len(parts) > 2 else ""
                info["arch"] = parts[-1] if parts else ""
        except Exception:
            info["name"] = "Linux"

    return info


def _is_windows_server(os_info):
    """Check if Windows OS is a Server edition."""
    name = os_info.get("name", "").lower()
    return any(x in name for x in ["server", "datacenter", "standard"])


# =============================================================================
# STEP 2: SERVICE VERIFICATION
# =============================================================================

def get_running_services():
    """Liet ke cac service dang LISTEN + binary path cua chung.
    Returns list of dicts: {service_name, pid, port, proto, binary_path, display_name}
    """
    services = []

    if IS_WINDOWS:
        try:
            # Get all listening TCP/UDP ports with PID
            r = _run_hidden(["netstat", "-ano"], timeout=10)
            listening = []
            for line in r.stdout.split("\n"):
                if "LISTENING" in line.upper() or "ESTABLISHED" in line.upper():
                    parts = line.split()
                    if len(parts) >= 5:
                        addr = parts[1]
                        pid = parts[-1]
                        try:
                            proto = "TCP" if "TCP" in line.upper() else "UDP"
                            port = addr.split(":")[-1] if ":" in addr else addr
                            listening.append({"pid": pid, "port": port, "proto": proto, "address": addr})
                        except (ValueError, IndexError):
                            pass

            # Map PID to process name + binary path
            if listening:
                pids = set(item["pid"] for item in listening)
                pid_map = {}
                for pid in pids:
                    try:
                        pr = _run_hidden(["wmic", "process", "where", f"ProcessId={pid}", "get", "Name,ExecutablePath", "/format:csv"], timeout=5)
                        if pr.stdout:
                            lines = [l.strip() for l in pr.stdout.strip().split("\n") if l.strip()]
                            if len(lines) >= 2:
                                pp = lines[1].split(",")
                                if len(pp) >= 3:
                                    pid_map[pid] = {"name": pp[1].strip(), "binary_path": pp[2].strip()}
                    except Exception:
                        pass

                # Also try tasklist for services
                try:
                    tr = _run_hidden(["tasklist", "/SVC", "/FO", "CSV"], timeout=10)
                    svc_map = {}
                    for line in tr.stdout.strip().split("\n")[1:]:
                        parts = line.strip().strip('"').split('","')
                        if len(parts) >= 2:
                            svc_map[parts[0]] = parts[1] if len(parts) > 1 else ""
                except Exception:
                    svc_map = {}

                for item in listening:
                    pid = item["pid"]
                    pinfo = pid_map.get(pid, {})
                    svc_name = svc_map.get(pinfo.get("name", ""), "")
                    services.append({
                        "service_name": pinfo.get("name", f"PID:{pid}"),
                        "display_name": svc_name,
                        "pid": pid,
                        "port": item["port"],
                        "proto": item["proto"],
                        "address": item["address"],
                        "binary_path": pinfo.get("binary_path", ""),
                    })
        except Exception as e:
            print(f"[-] Service verification error: {e}")

    else:
        try:
            # Linux: ss -tlnp
            r = _run_hidden(["ss", "-tlnp"], timeout=10)
            for line in r.stdout.split("\n")[1:]:
                parts = line.split()
                if len(parts) >= 6:
                    addr = parts[4]
                    port = addr.split(":")[-1] if ":" in addr else addr
                    proc_info = parts[-1] if len(parts) > 5 else ""
                    # Extract PID from users:(("process",pid,fd))
                    pid_match = re.search(r'pid=(\d+)', proc_info)
                    pid = pid_match.group(1) if pid_match else ""
                    pname_match = re.search(r'users:\(\(\"([^\"]+)\"', proc_info)
                    pname = pname_match.group(1) if pname_match else ""
                    binary_path = ""
                    if pid:
                        try:
                            br = _run_hidden(["readlink", "-f", f"/proc/{pid}/exe"], timeout=3)
                            binary_path = br.stdout.strip()
                        except Exception:
                            pass
                    services.append({
                        "service_name": pname,
                        "display_name": pname,
                        "pid": pid,
                        "port": port,
                        "proto": "TCP",
                        "address": addr,
                        "binary_path": binary_path,
                    })
        except Exception as e:
            print(f"[-] Linux service verification error: {e}")

    # Deduplicate by service_name + port
    seen = set()
    unique = []
    for s in services:
        key = f"{s['service_name']}:{s['port']}"
        if key not in seen:
            seen.add(key)
            unique.append(s)
    return unique


# =============================================================================
# STEP 3: EXACT VERSION CHECK
# =============================================================================

def get_exact_version(binary_path):
    """Doc version chinh xac tu binary file header.
    Returns dict: {version, source, confidence}
    Source priorities: binary_header > package_manager > registry (fallback)
    """
    if not binary_path or not os.path.exists(binary_path):
        return {"version": "", "source": "unknown", "confidence": 0}

    result = {"version": "", "source": "unknown", "confidence": 0}

    # Method 1: Read binary file header (Windows)
    if IS_WINDOWS and binary_path.lower().endswith(('.exe', '.dll', '.sys')):
        try:
            # Use wmic to get exact file version
            escaped = binary_path.replace("\\", "\\\\")
            r = _run_hidden(["wmic", "datafile", "where", f"name='{escaped}'", "get", "Version", "/format:csv"], timeout=10)
            if r.stdout:
                lines = [l.strip() for l in r.stdout.strip().split("\n") if l.strip()]
                if len(lines) >= 2:
                    parts = lines[1].split(",")
                    if len(parts) >= 2 and parts[1].strip():
                        result["version"] = parts[1].strip()
                        result["source"] = "binary_header"
                        result["confidence"] = 95
        except Exception:
            pass

    # Method 2: PowerShell FileVersionInfo (Windows)
    if IS_WINDOWS and result["confidence"] == 0:
        try:
            r = _run_hidden(["powershell", "-NoProfile", "-NonInteractive",
                             f"(Get-Item '{binary_path}').VersionInfo.FileVersion"], timeout=10)
            ver = r.stdout.strip()
            if ver and ver != "" and "error" not in ver.lower():
                result["version"] = ver
                result["source"] = "powershell_fileversion"
                result["confidence"] = 90
        except Exception:
            pass

    # Method 3: Package manager (Linux)
    if not IS_WINDOWS and result["confidence"] == 0:
        pkg_name = os.path.basename(binary_path)
        try:
            r = _run_hidden(["dpkg", "-S", binary_path], timeout=5)
            if r.returncode == 0 and r.stdout:
                pkg = r.stdout.strip().split(":")[0]
                r2 = _run_hidden(["dpkg", "-l", pkg], timeout=5)
                for line in r2.stdout.split("\n"):
                    if pkg in line:
                        parts = line.split()
                        if len(parts) >= 3:
                            ver = parts[2]
                            if re.match(r'\d', ver):
                                result["version"] = ver
                                result["source"] = "dpkg"
                                result["confidence"] = 85
                                break
        except Exception:
            pass

    return result


def get_installed_software_with_exact_versions():
    """Get installed software with version from multiple sources, prioritized by confidence.
    Returns list of {name, version, publisher, version_source, confidence}
    """
    software = []

    if IS_WINDOWS:
        # Method 1: Registry (fast, but lower confidence)
        reg_sw = _get_installed_software_windows()

        # Method 2: Cross-reference with binary files for high-value targets
        high_value_paths = [
            r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE",
            r"C:\Program Files (x86)\Microsoft Office\root\Office16\WINWORD.EXE",
            r"C:\Program Files\Mozilla Firefox\firefox.exe",
            r"C:\Program Files (x86)\Mozilla Firefox\firefox.exe",
            r"C:\Program Files\Google\Chrome\Application\chrome.exe",
            r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
            r"C:\Program Files\OpenSSH\sshd.exe",
            r"C:\Program Files\Apache Software Foundation\Apache2.4\bin\httpd.exe",
            r"C:\Program Files\7-Zip\7z.exe",
            r"C:\Program Files\Python*\python.exe",
            r"C:\Program Files\Java\jre*\bin\java.exe",
        ]

        # First, add all registry entries
        for sw in reg_sw:
            software.append({
                "name": sw["name"],
                "version": sw["version"],
                "publisher": sw.get("publisher", ""),
                "version_source": "registry",
                "confidence": 60,
                "binary_path": "",
            })

        # Then cross-reference high-value targets to improve confidence
        import glob
        for sw_entry in software:
            name_lower = sw_entry["name"].lower()
            # Try to find binary path for known software
            for pattern in high_value_paths:
                try:
                    for path in glob.glob(pattern):
                        fname = os.path.basename(path).lower()
                        if any(kw in fname for kw in ["chrome", "firefox", "word", "outlook", "sshd", "httpd", "7z", "python", "java"]):
                            if any(kw in name_lower for kw in ["chrome", "firefox", "office", "openssh", "apache", "7-zip", "python", "java"]):
                                exact = get_exact_version(path)
                                if exact["confidence"] >= 90:
                                    sw_entry["version"] = exact["version"]
                                    sw_entry["version_source"] = exact["source"]
                                    sw_entry["confidence"] = exact["confidence"]
                                    sw_entry["binary_path"] = path
                                    break
                except Exception:
                    pass
    else:
        software = _get_installed_software_linux()

    return software


def _get_installed_software_windows():
    """Get installed software list on Windows via WMI/registry."""
    software = []
    try:
        r = _run_hidden(["powershell", "-NoProfile", "-NonInteractive",
            "Get-ItemProperty HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*," +
            "HKLM:\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*," +
            "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* 2>$null",
            "| Where-Object { $_.DisplayName -and $_.DisplayVersion }",
            "| Select-Object DisplayName, DisplayVersion, Publisher",
            "| Sort-Object DisplayName -Unique",
            "| ConvertTo-Json -Compress -Depth 1"], timeout=30)
        if r.stdout:
            data = json.loads(r.stdout)
            if isinstance(data, dict):
                data = [data]
            for item in data:
                if item.get("DisplayName") and item.get("DisplayVersion"):
                    software.append({
                        "name": item["DisplayName"],
                        "version": item["DisplayVersion"],
                        "publisher": item.get("Publisher", ""),
                    })
    except Exception:
        pass
    return software


def _get_installed_software_linux():
    """Get installed packages on Linux."""
    software = []
    try:
        r = _run_hidden(["dpkg-query", "-W", "-f=${Package}\t${Version}\t${Maintainer}\n"], timeout=15)
        if r.returncode == 0 and r.stdout:
            for line in r.stdout.strip().split("\n"):
                parts = line.split("\t")
                if len(parts) >= 2:
                    software.append({"name": parts[0], "version": parts[1], "publisher": parts[2] if len(parts) > 2 else ""})
            return software
    except Exception:
        pass
    try:
        r = _run_hidden(["rpm", "-qa", "--queryformat=%{NAME}\t%{VERSION}-%{RELEASE}\t%{VENDOR}\n"], timeout=15)
        if r.returncode == 0 and r.stdout:
            for line in r.stdout.strip().split("\n"):
                parts = line.split("\t")
                if len(parts) >= 2:
                    software.append({"name": parts[0], "version": parts[1], "publisher": parts[2] if len(parts) > 2 else ""})
    except Exception:
        pass
    return software


# =============================================================================
# TOKEN-BASED NAME MATCHING
# =============================================================================

def _tokenize(name):
    """Tach ten thanh tokens, bo stop words, lowercase."""
    tokens = re.split(r'[\s\-_.,;:/\\()\[\]{}]+', name.lower())
    return [t for t in tokens if t and t not in STOP_WORDS and len(t) > 1]


def match_software_name(cve_sw, cve_product, target_name, target_publisher=""):
    """Token-based software name matching.
    Returns confidence score 0-100.
    - 100: exact match on both software + product
    - 80+: high token overlap (>=80%)
    - 50-79: partial overlap
    - <50: low confidence (likely false positive)
    """
    cve_tokens = set(_tokenize(cve_sw))
    cve_prod_tokens = set(_tokenize(cve_product))
    cve_all = cve_tokens | cve_prod_tokens

    target_tokens = set(_tokenize(target_name))
    target_pub_tokens = set(_tokenize(target_publisher))
    target_all = target_tokens | target_pub_tokens

    if not cve_all or not target_all:
        return 0

    # Exact match on full name
    cve_sw_clean = cve_sw.lower().strip()
    target_clean = target_name.lower().strip()
    if cve_sw_clean == target_clean:
        return 100
    if cve_product.lower().strip() == target_clean:
        return 95

    # Jaccard similarity on tokens
    intersection = cve_all & target_all
    union = cve_all | target_all
    jaccard = len(intersection) / len(union) * 100

    # Bonus for product name match
    product_match = cve_prod_tokens & target_tokens
    if product_match and len(product_match) >= min(len(cve_prod_tokens), len(target_tokens)):
        jaccard = min(100, jaccard + 20)

    # Penalty for big size difference (e.g., "Microsoft Office" vs "Microsoft Office Click-to-Run Proofing Tools 2016")
    if len(target_tokens) > len(cve_tokens) * 2:
        jaccard = max(0, jaccard - 25)

    return round(jaccard)


# =============================================================================
# CISA KEV INTEGRATION
# =============================================================================

class CISAKevCache:
    """Manages CISA Known Exploited Vulnerabilities catalog."""

    def __init__(self):
        os.makedirs(CACHE_DIR, exist_ok=True)
        self.kev_set = set()  # Set of CVE IDs in KEV
        self.kev_data = {}    # CVE ID -> full KEV entry
        self._load_cache()

    def _load_cache(self):
        if os.path.exists(CISA_KEV_CACHE):
            try:
                with open(CISA_KEV_CACHE, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    if data and "vulnerabilities" in data:
                        for vuln in data["vulnerabilities"]:
                            cve_id = vuln.get("cveID", "")
                            if cve_id:
                                self.kev_set.add(cve_id)
                                self.kev_data[cve_id] = vuln
                print(f"[*] CISA KEV: loaded {len(self.kev_set)} known exploited CVEs from cache")
                return
            except Exception:
                pass
        self._fetch_kev()

    def _fetch_kev(self):
        """Download CISA KEV catalog."""
        try:
            req = urllib.request.Request(CISA_KEV_URL, headers={"User-Agent": "GIAM-SAT/1.8.0"})
            resp = urllib.request.urlopen(req, timeout=30)
            data = json.loads(resp.read().decode("utf-8"))
            if data and "vulnerabilities" in data:
                for vuln in data["vulnerabilities"]:
                    cve_id = vuln.get("cveID", "")
                    if cve_id:
                        self.kev_set.add(cve_id)
                        self.kev_data[cve_id] = vuln
                # Save cache
                try:
                    with open(CISA_KEV_CACHE, "w", encoding="utf-8") as f:
                        json.dump(data, f, indent=2, ensure_ascii=False)
                    with open(CISA_KEV_LAST_UPDATE, "w") as f:
                        f.write(str(time.time()))
                except Exception:
                    pass
                print(f"[*] CISA KEV: downloaded {len(self.kev_set)} known exploited CVEs")
        except Exception as e:
            print(f"[-] CISA KEV fetch error: {e}")

    def needs_update(self):
        if not os.path.exists(CISA_KEV_LAST_UPDATE):
            return True
        try:
            with open(CISA_KEV_LAST_UPDATE, "r") as f:
                last = float(f.read().strip())
            return (time.time() - last) > (24 * 3600)
        except Exception:
            return True

    def is_kev(self, cve_id):
        """Check if CVE is in CISA KEV (known exploited)."""
        return cve_id in self.kev_set

    def get_kev_info(self, cve_id):
        """Get full KEV entry for a CVE."""
        return self.kev_data.get(cve_id, {})


# =============================================================================
# SEMANTIC VERSION COMPARISON
# =============================================================================

def _parse_version(v):
    """Parse version string into list of comparable segments (ints where possible)."""
    if not v:
        return []
    # Split on common separators
    parts = re.split(r'[.\-_]', str(v))
    result = []
    for p in parts:
        # Extract leading number
        m = re.match(r'(\d+)', p)
        if m:
            result.append(int(m.group(1)))
            # Keep suffix as string for comparison
            suffix = p[m.end():].lower()
            if suffix:
                result.append(suffix)
        else:
            # Non-numeric part (e.g., "beta", "rc")
            result.append(p.lower())
    return result


def version_compare(v1, v2):
    """Compare two version strings. Returns -1, 0, or 1."""
    p1 = _parse_version(v1)
    p2 = _parse_version(v2)
    for i in range(max(len(p1), len(p2))):
        a = p1[i] if i < len(p1) else (0 if isinstance(p2[i], int) else "")
        b = p2[i] if i < len(p2) else (0 if isinstance(p1[i], int) else "")
        # Numeric comparison
        if isinstance(a, int) and isinstance(b, int):
            if a < b: return -1
            if a > b: return 1
        else:
            # String comparison
            a_str = str(a)
            b_str = str(b)
            if a_str < b_str: return -1
            if a_str > b_str: return 1
    return 0


def version_le(v1, v2):
    """v1 <= v2"""
    return version_compare(v1, v2) <= 0


def version_lt(v1, v2):
    """v1 < v2"""
    return version_compare(v1, v2) < 0


def version_ge(v1, v2):
    """v1 >= v2"""
    return version_compare(v1, v2) >= 0


# =============================================================================
# CVE CACHE
# =============================================================================

class CVECache:
    """Manages CVE database cache with NVD API auto-update and CISA KEV integration."""

    def __init__(self):
        os.makedirs(CACHE_DIR, exist_ok=True)
        self.cve_data = []
        self.cisa_kev = CISAKevCache()
        self._load_cache()

    def _load_cache(self):
        if os.path.exists(CVE_CACHE_FILE):
            try:
                with open(CVE_CACHE_FILE, "r", encoding="utf-8") as f:
                    self.cve_data = json.load(f)
                if self.cve_data:
                    print(f"[*] CVE Cache: loaded {len(self.cve_data)} CVEs from cache")
                    return
            except Exception:
                pass
        self.cve_data = list(_FALLBACK_CVE_DB)
        print(f"[*] CVE Cache: using {len(self.cve_data)} fallback CVEs")

    def save_cache(self):
        try:
            with open(CVE_CACHE_FILE, "w", encoding="utf-8") as f:
                json.dump(self.cve_data, f, indent=2, ensure_ascii=False)
        except Exception as e:
            print(f"[-] Failed to save CVE cache: {e}")

    def needs_update(self):
        if not os.path.exists(CVE_LAST_UPDATE_FILE):
            return True
        try:
            with open(CVE_LAST_UPDATE_FILE, "r") as f:
                last = float(f.read().strip())
            return (time.time() - last) > (NVD_CACHE_DURATION_HOURS * 3600)
        except Exception:
            return True

    def mark_updated(self):
        try:
            with open(CVE_LAST_UPDATE_FILE, "w") as f:
                f.write(str(time.time()))
        except Exception:
            pass

    def fetch_nvd_recent(self, hours_back=48):
        """Fetch recently published CVEs from NVD API."""
        try:
            now = datetime.utcnow()
            start_date = (now - timedelta(hours=hours_back)).strftime("%Y-%m-%dT%H:%M:%S.000")
            end_date = now.strftime("%Y-%m-%dT%H:%M:%S.000")

            url = (f"{NVD_API_BASE}?pubStartDate={start_date}&pubEndDate={end_date}"
                   f"&resultsPerPage={NVD_MAX_RESULTS_PER_REQUEST}")

            req = urllib.request.Request(url, headers={"User-Agent": "GIAM-SAT/1.8.0"})
            resp = urllib.request.urlopen(req, timeout=30)
            data = json.loads(resp.read().decode("utf-8"))

            vulnerabilities = data.get("vulnerabilities", [])
            new_count = 0
            existing_cve_ids = {c["cve"] for c in self.cve_data}

            for vuln_item in vulnerabilities:
                cve_info = vuln_item.get("cve", {})
                cve_id = cve_info.get("id", "")
                if cve_id in existing_cve_ids:
                    continue

                descriptions = cve_info.get("descriptions", [])
                desc = next((d.get("value", "") for d in descriptions if d.get("lang") == "en"), "")

                metrics = cve_info.get("metrics", {})
                cvss_v31 = metrics.get("cvssMetricV31", [{}])[0]
                cvss_v30 = metrics.get("cvssMetricV30", [{}])[0]
                cvss_data = cvss_v31.get("cvssData", {}) or cvss_v30.get("cvssData", {})
                base_score = cvss_data.get("baseScore", 5.0)
                base_severity = cvss_data.get("baseSeverity", "MEDIUM")

                # v1.8.0: Only include CVEs above medium threshold OR in CISA KEV
                is_kev = self.cisa_kev.is_kev(cve_id)
                if base_score < SEVERITY_THRESHOLDS["cvss_medium"] and not is_kev:
                    continue

                configurations = cve_info.get("configurations", [])
                products = []
                for config in configurations:
                    for node in config.get("nodes", []):
                        for cpe in node.get("cpeMatch", []):
                            criteria = cpe.get("criteria", "")
                            parts = criteria.split(":")
                            if len(parts) >= 5:
                                vendor = parts[3]
                                product = parts[4]
                                products.append({"vendor": vendor, "product": product, "version": parts[5] if len(parts) > 5 else "*"})

                # v1.8.0: Adjust severity based on CISA KEV
                if is_kev:
                    final_severity = "CRITICAL"
                elif base_score >= SEVERITY_THRESHOLDS["cvss_critical"]:
                    final_severity = "HIGH"
                elif base_score >= SEVERITY_THRESHOLDS["cvss_high"]:
                    final_severity = "MEDIUM"
                else:
                    final_severity = "LOW"

                entry = {
                    "cve": cve_id,
                    "software": products[0]["vendor"].title() if products else "Unknown",
                    "product": products[0]["product"] if products else "Unknown",
                    "versions_affected": [f"<={products[0]['version']}" for p in products[:3]] if products else ["*"],
                    "severity": final_severity,
                    "cvss": base_score,
                    "description": desc[:300],
                    "source": "NVD",
                    "published": cve_info.get("published", ""),
                    "in_cisa_kev": is_kev,
                }
                self.cve_data.append(entry)
                existing_cve_ids.add(cve_id)
                new_count += 1

            if new_count > 0:
                self.save_cache()
                self.mark_updated()

            return new_count
        except urllib.error.HTTPError as e:
            print(f"[-] NVD API HTTP error: {e.code}")
        except Exception as e:
            print(f"[-] NVD API fetch error: {e}")

        return 0

    def check_software(self, software_name, software_version, publisher="", os_info=None):
        """v1.8.0: Check software against CVE database with:
        - Token-based name matching (confidence threshold)
        - Semantic version comparison
        - CISA KEV priority
        - OS filtering (skip Linux CVEs on Windows, Windows CVEs on Linux)
        Returns list of matching CVEs with confidence metadata.
        """
        matches = []
        name_lower = software_name.lower()
        pub_lower = publisher.lower()
        os_type = os_info.get("type", "") if os_info else ""

        for cve in self.cve_data:
            cve_sw = cve.get("software", "")
            cve_product = cve.get("product", "")

            # v1.8.0: OS filtering - skip clearly wrong OS matches
            cve_sw_lower = cve_sw.lower()
            if os_type == "windows":
                # Skip Linux-only CVEs on Windows
                linux_keywords = ["linux kernel", "ubuntu", "debian", "centos", "rhel", "red hat", "fedora"]
                if any(kw in cve_sw_lower or kw in cve_product.lower() for kw in linux_keywords):
                    continue
                # Skip macOS-only CVEs
                macos_keywords = ["macos", "mac os", "ios"]
                if any(kw in cve_sw_lower or kw in cve_product.lower() for kw in macos_keywords):
                    continue
            elif os_type == "linux":
                # Skip Windows-only CVEs on Linux
                if "windows" in cve_sw_lower and "linux" not in cve_sw_lower:
                    if not any(kw in cve_product.lower() for kw in ["python", "curl", "openssl", "apache", "nginx", "ssh"]):
                        continue

            # v1.8.0: Token-based name matching with confidence threshold
            confidence = match_software_name(cve_sw, cve_product, software_name, publisher)
            if confidence < 50:
                continue  # Below threshold = likely false positive, skip

            # Version comparison
            affected = False
            try:
                for ver_str in cve.get("versions_affected", []):
                    ver_str = ver_str.strip().replace(" ", "")
                    if "<=" in ver_str:
                        max_ver = ver_str.replace("<=", "").strip()
                        if max_ver and version_le(software_version, max_ver):
                            affected = True
                            break
                    elif "<" in ver_str:
                        max_ver = ver_str.replace("<", "").strip()
                        if max_ver and version_lt(software_version, max_ver):
                            affected = True
                            break
                    elif " - " in ver_str:
                        parts = ver_str.split(" - ")
                        if len(parts) == 2:
                            lo, hi = parts[0].strip(), parts[1].strip()
                            if lo and hi and version_ge(software_version, lo) and version_le(software_version, hi):
                                affected = True
                                break
                    elif ver_str == "*":
                        affected = True
                        break
                    else:
                        if software_version == ver_str:
                            affected = True
                            break
            except Exception:
                # If version parsing fails, mark as affected only if confidence is high
                if confidence >= 80:
                    affected = True

            if not affected:
                continue

            # v1.8.0: CISA KEV boost
            is_kev = cve.get("in_cisa_kev", False) or self.cisa_kev.is_kev(cve["cve"])
            if is_kev:
                severity = "CRITICAL"
                cisa_info = self.cisa_kev.get_kev_info(cve["cve"])
                cve["severity"] = "CRITICAL"
                cve["cisa_kev"] = {
                    "date_added": cisa_info.get("dateAdded", ""),
                    "due_date": cisa_info.get("dueDate", ""),
                    "required_action": cisa_info.get("requiredAction", ""),
                    "notes": cisa_info.get("notes", ""),
                }

            match_entry = dict(cve)
            match_entry["match_confidence"] = confidence
            match_entry["in_cisa_kev"] = is_kev
            matches.append(match_entry)

        # Sort: CISA KEV first, then by CVSS, then by confidence
        matches.sort(key=lambda m: (
            0 if m.get("in_cisa_kev") else 1,
            -(m.get("cvss", 0)),
            -(m.get("match_confidence", 0)),
        ))

        return matches


# =============================================================================
# VULN SCANNER
# =============================================================================

class VulnScanner:
    """Vulnerability Scanner v1.8.0 - 3-step verification pipeline."""

    def __init__(self, callback=None):
        self.callback = callback
        self.results = []
        self.cve_cache = CVECache()
        self._update_thread = None
        self._os_info = None
        self._running_services = None

    def get_os_info(self):
        """Get cached OS fingerprint."""
        if not self._os_info:
            self._os_info = get_os_info()
        return self._os_info

    def get_running_services(self):
        """Get cached running services."""
        if not self._running_services:
            self._running_services = get_running_services()
        return self._running_services

    def run_scan(self):
        """v1.8.0: Run vulnerability scan with 3-step verification pipeline.
        
        Step 1: OS Fingerprinting
        Step 2: Service Verification (only scan CVE for running services)
        Step 3: Exact Version Check (read binary headers, not just registry)
        """
        self.results = []

        # Step 1: OS Fingerprinting
        os_info = self.get_os_info()
        print(f"[*] Vuln Scanner v1.8.0: OS = {os_info['name']} {os_info['version']} (build {os_info['build']}) {os_info['arch']}")
        print(f"[*] Vuln Scanner: Checking {len(self.cve_cache.cve_data)} CVEs")

        # Update CISA KEV if needed
        if self.cve_cache.cisa_kev.needs_update():
            t = threading.Thread(target=self.cve_cache.cisa_kev._fetch_kev, daemon=True)
            t.start()

        # Auto-update NVD CVE database
        if self.cve_cache.needs_update():
            self._start_auto_update()

        # Step 2: Get installed software & running services
        installed = get_installed_software_with_exact_versions()
        running_svcs = self.get_running_services()
        running_names = set()
        running_binaries = {}
        for svc in running_svcs:
            name = svc.get("service_name", "").lower().replace(".exe", "")
            running_names.add(name)
            if svc.get("binary_path"):
                running_binaries[name] = svc["binary_path"]

        print(f"[*] Vuln Scanner: Found {len(installed)} installed packages, {len(running_svcs)} listening services")

        # Step 3: Filter installed software to only running services (if we have service data)
        # If we couldn't get running services, fall back to all installed
        scan_targets = []
        if running_svcs:
            for sw in installed:
                name_lower = sw["name"].lower()
                # Check if this software is running
                is_running = False
                for rname in running_names:
                    if rname and (rname in name_lower or name_lower in rname):
                        is_running = True
                        # Cross-reference binary version
                        if rname in running_binaries and sw.get("confidence", 60) < 85:
                            exact = get_exact_version(running_binaries[rname])
                            if exact["confidence"] >= 80:
                                sw["version"] = exact["version"]
                                sw["version_source"] = exact["source"]
                                sw["confidence"] = exact["confidence"]
                        break
                # Also include if software is critical infrastructure (even if not on LISTEN)
                critical_keywords = ["windows", "kernel", "openssl", "libcurl", "apache", "nginx",
                                     "exchange", "defender", "active directory", "dns", "dhcp"]
                if not is_running:
                    is_running = any(kw in name_lower for kw in critical_keywords)
                if is_running:
                    scan_targets.append(sw)
        else:
            scan_targets = installed

        # v3.6: Fallback - if filter is too aggressive (scan_targets < installed/4), scan all installed
        if not scan_targets or len(scan_targets) < max(3, len(installed) // 4):
            print(f"[*] Vuln Scanner: Filter too restrictive ({len(scan_targets)} filtered from {len(installed)}), scanning all installed")
            # Merge: keep filtered targets + add all installed (dedup by name)
            seen_names = {sw["name"].lower() for sw in scan_targets}
            for sw in installed:
                if sw["name"].lower() not in seen_names:
                    scan_targets.append(sw)
                    seen_names.add(sw["name"].lower())

        print(f"[*] Vuln Scanner: Scanning {len(scan_targets)} relevant targets (filtered from {len(installed)})")

        # Check each target against CVE DB
        for sw in scan_targets:
            matches = self.cve_cache.check_software(
                sw["name"], sw["version"], sw.get("publisher", ""), os_info
            )
            for cve in matches:
                # v3.6: Keep original severity from CVE DB (don't downgrade)
                severity = cve.get("severity", "MEDIUM")

                finding = {
                    "type": "vulnerability_alert",
                    "software": sw["name"],
                    "version": sw["version"],
                    "version_source": sw.get("version_source", "unknown"),
                    "version_confidence": sw.get("confidence", 0),
                    "publisher": sw.get("publisher", ""),
                    "cve": cve["cve"],
                    "severity": severity,
                    "cvss": cve.get("cvss", 0),
                    "description": cve.get("description", ""),
                    "match_confidence": cve.get("match_confidence", 0),
                    "in_cisa_kev": cve.get("in_cisa_kev", False),
                    "os_type": os_info.get("type", ""),
                    "os_name": os_info.get("name", ""),
                    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                }
                if cve.get("cisa_kev"):
                    finding["cisa_kev"] = cve["cisa_kev"]

                self.results.append(finding)
                if self.callback:
                    self.callback(finding)

        # Scan OS-level vulnerabilities
        self._scan_os_vulnerabilities(os_info)

        print(f"[*] Vuln Scanner: Found {len(self.results)} vulnerabilities ({sum(1 for r in self.results if r['severity'] == 'CRITICAL')} CRITICAL, {sum(1 for r in self.results if r.get('in_cisa_kev'))} in CISA KEV)")
        return self.results

    def _scan_os_vulnerabilities(self, os_info):
        """Check OS-level vulnerabilities (kernel, built-in components)."""
        if not os_info or not os_info.get("version"):
            return

        os_name = os_info.get("name", "")
        os_version = os_info.get("version", "")

        # Check OS against CVE DB
        matches = self.cve_cache.check_software(os_name, os_version, "", os_info)
        for cve in matches:
            severity = cve.get("severity", "MEDIUM")
            if severity in ("MEDIUM", "LOW"):
                severity = "INFO"

            finding = {
                "type": "vulnerability_alert",
                "software": os_name,
                "version": os_version,
                "version_source": "os_fingerprint",
                "version_confidence": 95,
                "publisher": "Microsoft" if "windows" in os_name.lower() else "",
                "cve": cve["cve"],
                "severity": severity,
                "cvss": cve.get("cvss", 0),
                "description": cve.get("description", ""),
                "match_confidence": cve.get("match_confidence", 0),
                "in_cisa_kev": cve.get("in_cisa_kev", False),
                "os_type": os_info.get("type", ""),
                "os_name": os_info.get("name", ""),
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            }
            if cve.get("cisa_kev"):
                finding["cisa_kev"] = cve["cisa_kev"]

            # Avoid duplicates
            existing_cves = {r["cve"] for r in self.results if r["software"] == os_name}
            if cve["cve"] not in existing_cves:
                self.results.append(finding)
                if self.callback:
                    self.callback(finding)

    def _start_auto_update(self):
        if self._update_thread and self._update_thread.is_alive():
            return

        def _update():
            print("[*] Vuln Scanner: Auto-updating CVE database from NVD...")
            new = self.cve_cache.fetch_nvd_recent(hours_back=48)
            if new > 0:
                print(f"[*] Vuln Scanner: Added {new} new CVEs from NVD")
            else:
                print("[*] Vuln Scanner: No new CVEs or NVD API unavailable")

        self._update_thread = threading.Thread(target=_update, daemon=True)
        self._update_thread.start()
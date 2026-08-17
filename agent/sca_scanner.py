"""
SCA (Security Configuration Assessment) Scanner for GIAM-SAT Agent v1.7.0
Reads checks from sca_policy.yaml - YAML-based, easily extensible.
New v1.7.0: BitLocker, screensaver, NTLM, SMB signing, PowerShell logging, AppLocker, Windows Update, LSASS PPL, and more.
"""
import os
import sys
import json
import subprocess
import re
from datetime import datetime

IS_WINDOWS = os.name == "nt"
CREATE_NO_WINDOW = 0x08000000 if IS_WINDOWS else 0

# Try importing yaml, fall back to basic parsing if not available
try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False

POLICY_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "sca_policy.yaml")


def _run_hidden(cmd, **kwargs):
    """Run a subprocess with hidden window on Windows."""
    if IS_WINDOWS:
        kwargs.setdefault("creationflags", CREATE_NO_WINDOW)
    return subprocess.run(cmd, capture_output=True, text=True,
                          timeout=kwargs.pop("timeout", 15), **kwargs)


# Multi-policy support v1.13.0
POLICY_FILES = {
    "cis": "sca_policy.yaml",
    "pci_dss": "sca_pci_dss_policy.yaml",
    "gdpr": "sca_gdpr_policy.yaml",
    "hipaa": "sca_hipaa_policy.yaml",
    "iso27001": "sca_iso27001_policy.yaml",
}


def _load_policy(policy_name="cis"):
    """Load SCA policy from YAML file. Supports multiple compliance standards.
    
    Args:
        policy_name: One of 'cis', 'pci_dss', 'gdpr', 'hipaa', 'iso27001'
    
    Returns:
        dict with windows_checks and linux_checks, or None for fallback
    """
    base_dir = os.path.dirname(os.path.abspath(__file__))
    filename = POLICY_FILES.get(policy_name, POLICY_FILES["cis"])
    policy_path = os.path.join(base_dir, filename)

    if not os.path.exists(policy_path):
        return None

    if HAS_YAML:
        try:
            with open(policy_path, "r", encoding="utf-8") as f:
                return yaml.safe_load(f) or {}
        except Exception:
            return None
    else:
        return None


def get_available_policies():
    """Return list of available compliance policies with metadata."""
    base_dir = os.path.dirname(os.path.abspath(__file__))
    available = []
    for name, filename in POLICY_FILES.items():
        path = os.path.join(base_dir, filename)
        if os.path.exists(path) and HAS_YAML:
            try:
                with open(path, "r", encoding="utf-8") as f:
                    data = yaml.safe_load(f)
                    if data and "metadata" in data:
                        meta = data["metadata"]
                        available.append({
                            "id": name,
                            "standard": meta.get("standard", name.upper()),
                            "description": meta.get("description", ""),
                            "checks": len(data.get("windows_checks", [])) + len(data.get("linux_checks", [])),
                        })
            except Exception:
                pass
    return available


# =============================================================================
# Parser Functions - extract structured data from command/PS outputs
# These are referenced by 'parser' field in sca_policy.yaml
# =============================================================================

class Parsers:
    """Collection of parser functions for SCA checks."""

    @staticmethod
    def parse_net_accounts_password_length(check, output, stderr):
        try:
            match = re.search(r'Minimum password length\s*[:\s]+(\d+)', output, re.IGNORECASE)
            return {"min_length": int(match.group(1))} if match else {"min_length": 0}
        except Exception:
            return {"min_length": 0}

    @staticmethod
    def parse_net_accounts_lockout(check, output, stderr):
        try:
            match = re.search(r'Lockout threshold\s*[:\s]+(\d+)', output, re.IGNORECASE)
            return {"lockout": int(match.group(1))} if match else {"lockout": 0}
        except Exception:
            return {"lockout": 0}

    @staticmethod
    def parse_net_accounts_max_age(check, output, stderr):
        try:
            match = re.search(r'Maximum password age.*?(\d+)', output, re.IGNORECASE)
            return {"max_age": int(match.group(1))} if match else {"max_age": 0}
        except Exception:
            return {"max_age": 0}

    @staticmethod
    def parse_firewall_state(check, output, stderr):
        return {"on_count": output.count("ON")}

    @staticmethod
    def parse_defender_status(check, output, stderr):
        try:
            data = json.loads(output)
            parts = {}
            if isinstance(data, dict):
                parts["antivirus_enabled"] = data.get("AntivirusEnabled", False)
                parts["realtime_enabled"] = data.get("RealTimeProtectionEnabled", False)
            elif isinstance(data, list) and data:
                parts["antivirus_enabled"] = data[0].get("AntivirusEnabled", False)
                parts["realtime_enabled"] = data[0].get("RealTimeProtectionEnabled", False)
            else:
                parts["antivirus_enabled"] = "True" in output
                parts["realtime_enabled"] = "True" in output
            return parts
        except Exception:
            return {"antivirus_enabled": False, "realtime_enabled": False}

    @staticmethod
    def parse_audit_policy(check, output, stderr):
        required = check.get("required_categories", [])
        failed = []
        for cat in required:
            found = False
            for line in output.split("\n"):
                if cat in line and "Success and Failure" in line:
                    found = True
                    break
            if not found:
                failed.append(cat)
        return {"failed_categories": failed, "all_pass": len(failed) == 0}

    @staticmethod
    def parse_uac_status(check, output, stderr):
        return {"uac_enabled": "1" in output.strip()}

    @staticmethod
    def parse_insecure_services(check, output, stderr):
        insecure_services = check.get("insecure_services", [])
        running = []
        for svc in insecure_services:
            try:
                r = _run_hidden(["sc", "query", svc])
                if "RUNNING" in r.stdout:
                    running.append(svc)
            except Exception:
                pass
        return {"running_insecure": running, "all_pass": len(running) == 0}

    @staticmethod
    def parse_smbv1_status(check, output, stderr):
        return {"smbv1_disabled": "False" in output or "false" in output.lower()}

    @staticmethod
    def parse_autologon_status(check, output, stderr):
        return {"autologon_disabled": "0x1" not in output}

    @staticmethod
    def parse_rdp_status(check, output, stderr):
        return {"rdp_disabled": "1" in output.strip()}

    @staticmethod
    def parse_rdp_nla_status(check, output, stderr):
        return {"nla_enabled": "1" in output.strip()}

    # ---- NEW v1.7.0 parsers ----

    @staticmethod
    def parse_bitlocker_status(check, output, stderr):
        try:
            if output.strip():
                data = json.loads(output)
                if isinstance(data, dict):
                    ps = data.get("ProtectionStatus", 0)
                elif isinstance(data, list) and data:
                    ps = data[0].get("ProtectionStatus", 0) if isinstance(data[0], dict) else 0
                else:
                    ps = 0
                # ProtectionStatus: 0=Off, 1=On, 2=Unknown
                return {"bitlocker_on": ps == 1}
            return {"bitlocker_on": False}
        except Exception:
            return {"bitlocker_on": False}

    @staticmethod
    def parse_screensaver_timeout(check, output, stderr):
        try:
            val = int(output.strip())
            return {"timeout": val}
        except Exception:
            return {"timeout": 0}

    @staticmethod
    def parse_screensaver_password(check, output, stderr):
        try:
            val = output.strip()
            return {"password_protected": val == "1"}
        except Exception:
            return {"password_protected": False}

    @staticmethod
    def parse_registry_dword_enabled(check, output, stderr):
        """Generic parser for registry DWORD values: 1 = enabled."""
        try:
            val = output.strip()
            # Handle both "0x1" (hex) and "1" (decimal) formats
            if "0x" in val.lower():
                return {"enabled": int(val, 16) == 1}
            return {"enabled": val == "1"}
        except Exception:
            return {"enabled": False}

    @staticmethod
    def parse_ntlm_level(check, output, stderr):
        try:
            val = output.strip()
            if "0x" in val.lower():
                lm_compat = int(val, 16)
            else:
                lm_compat = int(val)
            return {"lm_compat": lm_compat}
        except Exception:
            return {"lm_compat": 0}

    @staticmethod
    def parse_smb_signing_server(check, output, stderr):
        try:
            val = output.strip()
            enabled = val == "1" or "0x1" in val.lower()
            return {"signing_enabled": enabled}
        except Exception:
            return {"signing_enabled": False}

    @staticmethod
    def parse_smb_signing_client(check, output, stderr):
        try:
            val = output.strip()
            enabled = val == "1" or "0x1" in val.lower()
            return {"signing_enabled": enabled}
        except Exception:
            return {"signing_enabled": False}

    @staticmethod
    def parse_windows_update(check, output, stderr):
        try:
            val = int(output.strip())
            # AUOptions: 2=Notify, 3=Auto download, 4=Auto install, 5=Allow local admin
            return {"au_options": val, "auto_update_enabled": val >= 3}
        except Exception:
            return {"au_options": -1, "auto_update_enabled": False}

    @staticmethod
    def parse_applocker_status(check, output, stderr):
        try:
            if output.strip():
                data = json.loads(output)
                if isinstance(data, dict):
                    rules = data.get("RuleCollection", data.get("ruleCollection", []))
                elif isinstance(data, list):
                    rules = data
                else:
                    rules = []
                return {"applocker_enabled": len(rules) > 0, "rule_count": len(rules)}
        except Exception:
            pass
        return {"applocker_enabled": False, "rule_count": 0}

    @staticmethod
    def parse_applocker_dll_status(check, output, stderr):
        try:
            if output.strip():
                data = json.loads(output)
                if isinstance(data, dict):
                    rules = data.get("RuleCollection", data.get("ruleCollection", []))
                elif isinstance(data, list):
                    rules = data
                else:
                    rules = []
                return {"applocker_dll_enabled": len(rules) > 0, "rule_count": len(rules)}
        except Exception:
            pass
        return {"applocker_dll_enabled": False, "rule_count": 0}

    @staticmethod
    def parse_network_protection(check, output, stderr):
        try:
            data = json.loads(output)
            if isinstance(data, dict):
                val = data.get("EnableNetworkProtection", 0)
            elif isinstance(data, list) and data:
                val = data[0].get("EnableNetworkProtection", 0) if isinstance(data[0], dict) else 0
            else:
                val = 0
            return {"network_protection_enabled": val == 1}
        except Exception:
            return {"network_protection_enabled": False}

    @staticmethod
    def parse_maps_reporting(check, output, stderr):
        try:
            data = json.loads(output)
            if isinstance(data, dict):
                val = data.get("MAPSReporting", 0)
            elif isinstance(data, list) and data:
                val = data[0].get("MAPSReporting", 0) if isinstance(data[0], dict) else 0
            else:
                val = 0
            return {"maps_enabled": val == 2}  # 2 = Advanced
        except Exception:
            return {"maps_enabled": False}

    @staticmethod
    def parse_sample_submission(check, output, stderr):
        try:
            data = json.loads(output)
            if isinstance(data, dict):
                val = data.get("SubmitSamplesConsent", 0)
            elif isinstance(data, list) and data:
                val = data[0].get("SubmitSamplesConsent", 0) if isinstance(data[0], dict) else 0
            else:
                val = 0
            return {"sample_submission_enabled": val == 1}
        except Exception:
            return {"sample_submission_enabled": False}

    @staticmethod
    def parse_local_admin_members(check, output, stderr):
        try:
            if output.strip():
                data = json.loads(output)
                if isinstance(data, list):
                    members = data
                elif isinstance(data, dict):
                    members = [data]
                else:
                    members = []
            else:
                members = []
            return {"admin_count": len(members), "admins": members}
        except Exception:
            return {"admin_count": -1, "admins": []}

    @staticmethod
    def parse_guest_account(check, output, stderr):
        try:
            data = json.loads(output)
            if isinstance(data, dict):
                enabled = data.get("Enabled", True)
            elif isinstance(data, list) and data:
                enabled = data[0].get("Enabled", True) if isinstance(data[0], dict) else True
            else:
                enabled = True
            return {"guest_disabled": not enabled}
        except Exception:
            return {"guest_disabled": True}  # Assume OK if can't read

    @staticmethod
    def parse_signature_age(check, output, stderr):
        try:
            data = json.loads(output)
            if isinstance(data, dict):
                age = data.get("AntivirusSignatureAge", 999)
            elif isinstance(data, list) and data:
                age = data[0].get("AntivirusSignatureAge", 999) if isinstance(data[0], dict) else 999
            else:
                age = 999
            return {"signature_age_days": age}
        except Exception:
            return {"signature_age_days": 999}

    # ---- Linux parsers ----

    @staticmethod
    def parse_login_defs_minlen(check, output, stderr):
        try:
            match = re.search(r'PASS_MIN_LEN\s+(\d+)', output)
            return {"min_len": int(match.group(1))} if match else {"min_len": 0}
        except Exception:
            return {"min_len": 0}

    @staticmethod
    def parse_login_defs_maxdays(check, output, stderr):
        try:
            match = re.search(r'PASS_MAX_DAYS\s+(\d+)', output)
            return {"max_days": int(match.group(1))} if match else {"max_days": 9999}
        except Exception:
            return {"max_days": 9999}

    @staticmethod
    def parse_linux_firewall(check, output, stderr):
        has_drop = "DROP" in output or "REJECT" in output
        has_ufw = "active" in output.lower()
        return {"firewall_rules": has_drop or has_ufw}

    @staticmethod
    def parse_auditd_rules(check, output, stderr):
        rules = [l for l in output.split("\n") if l.strip()]
        return {"rule_count": len(rules)}

    @staticmethod
    def parse_ssh_permit_root(check, output, stderr):
        try:
            lines = output.strip().split("\n")
            for line in lines:
                parts = line.split()
                if len(parts) >= 2:
                    val = parts[-1].strip().strip('"')
                    return {"PermitRootLogin": val}
        except Exception:
            pass
        return {"PermitRootLogin": "yes"}

    @staticmethod
    def parse_ssh_password_auth(check, output, stderr):
        try:
            lines = output.strip().split("\n")
            for line in lines:
                parts = line.split()
                if len(parts) >= 2:
                    val = parts[-1].strip().strip('"')
                    return {"PasswordAuthentication": val}
        except Exception:
            pass
        return {"PasswordAuthentication": "yes"}

    @staticmethod
    def parse_ssh_protocol(check, output, stderr):
        try:
            match = re.search(r'Protocol\s+(\d+)', output)
            return {"protocol": int(match.group(1))} if match else {"protocol": 0}
        except Exception:
            return {"protocol": 0}

    @staticmethod
    def parse_ssh_max_auth_tries(check, output, stderr):
        try:
            match = re.search(r'MaxAuthTries\s+(\d+)', output)
            return {"max_tries": int(match.group(1))} if match else {"max_tries": 6}
        except Exception:
            return {"max_tries": 6}

    @staticmethod
    def parse_sysctl_enabled(check, output, stderr):
        try:
            val = int(output.strip().split("=")[-1].strip())
            return {"enabled": val != 0}
        except Exception:
            return {"enabled": False}

    @staticmethod
    def parse_kernel_module_loaded(check, output, stderr):
        return {"loaded": bool(output.strip())}

    @staticmethod
    def parse_ssh_allow(check, output, stderr):
        return {"restricted": bool(output.strip())}

    @staticmethod
    def parse_mac_status(check, output, stderr):
        has_selinux = "enabled" in output.lower() or "enforcing" in output.lower()
        has_apparmor = "enabled" in output.lower() or "enforce" in output.lower()
        return {"mac_enabled": has_selinux or has_apparmor}

    @staticmethod
    def parse_systemctl_enabled(check, output, stderr):
        return {"enabled": "enabled" in output.strip()}

    @staticmethod
    def parse_service_active(check, output, stderr):
        return {"active": output.strip() == "active"}

    @staticmethod
    def parse_grub_password(check, output, stderr):
        return {"has_password": bool(output.strip())}

    # ---- v1.13.0 NEW parsers for multi-compliance policies ----

    @staticmethod
    def parse_simple_pass_fail(check, output, stderr):
        """Parse PASS:msg / FAIL:msg / WARN:msg format output."""
        try:
            line = output.strip().split("\n")[0]
            if line.startswith("PASS:"):
                return {"status": "PASS", "message": line[5:].strip()}
            elif line.startswith("FAIL:"):
                return {"status": "FAIL", "message": line[5:].strip()}
            elif line.startswith("WARN:"):
                return {"status": "WARN", "message": line[5:].strip()}
            elif line.strip() == "PASS":
                return {"status": "PASS", "message": ""}
            elif line.strip() == "FAIL":
                return {"status": "FAIL", "message": ""}
            elif line.strip() == "WARN":
                return {"status": "WARN", "message": ""}
            else:
                return {"status": "UNKNOWN", "message": line}
        except Exception:
            return {"status": "UNKNOWN", "message": str(output)}

    @staticmethod
    def parse_registry_int(check, output, stderr):
        """Parse registry DWORD value as integer."""
        try:
            val = output.strip()
            if not val or val == "0":
                return {"value": 0}
            if "0x" in val.lower():
                return {"value": int(val, 16)}
            return {"value": int(val)}
        except Exception:
            return {"value": 0}

    @staticmethod
    def parse_registry_hex_int(check, output, stderr):
        """Parse registry hex value (alias for parse_registry_int)."""
        return Parsers.parse_registry_int(check, output, stderr)

    @staticmethod
    def parse_firewall_status(check, output, stderr):
        """Count firewall ON states across profiles."""
        try:
            on_count = output.count("ON")
            return {"firewall_on_count": on_count}
        except Exception:
            return {"firewall_on_count": 0}

    @staticmethod
    def parse_audit_policy_pci(check, output, stderr):
        """Parse auditpol output, count categories missing Success+Failure."""
        try:
            required = ["Logon/Logoff", "Account Logon", "Account Management",
                        "Policy Change", "Privilege Use", "Process Creation",
                        "Object Access", "System"]
            failed = []
            for cat in required:
                found = False
                for line in output.split("\n"):
                    if cat in line and "Success and Failure" in line:
                        found = True
                        break
                if not found:
                    failed.append(cat)
            return {"failed_categories": len(failed), "missing_categories": failed}
        except Exception:
            return {"failed_categories": 99, "missing_categories": ["parse_error"]}

    @staticmethod
    def parse_firewall_linux(check, output, stderr):
        """Check if iptables or ufw has active rules."""
        try:
            has_rules = "DROP" in output or "REJECT" in output or "ACCEPT" in output
            return {"firewall_active": has_rules}
        except Exception:
            return {"firewall_active": False}

    @staticmethod
    def parse_ssh_config(check, output, stderr):
        """Parse SSH config grep output for key-value pairs."""
        try:
            result = {}
            for line in output.strip().split("\n"):
                if not line.strip() or line.startswith("#"):
                    continue
                parts = line.split()
                if len(parts) >= 2:
                    result[parts[0].strip()] = parts[1].strip()
            if "PermitRootLogin" not in result:
                result["PermitRootLogin"] = "yes"  # Default
            if "PasswordAuthentication" not in result:
                result["PasswordAuthentication"] = "yes"
            return result
        except Exception:
            return {"PermitRootLogin": "yes", "PasswordAuthentication": "yes"}

    @staticmethod
    def parse_file_perms(check, output, stderr):
        """Parse stat output for file permissions."""
        try:
            passwd_perm = "999"
            shadow_perm = "999"
            for line in output.strip().split("\n"):
                parts = line.split()
                if len(parts) >= 2:
                    perm = parts[0]
                    name = parts[1]
                    if "passwd" in name and "shadow" not in name:
                        passwd_perm = perm
                    elif "shadow" in name:
                        shadow_perm = perm
            passwd_ok = int(passwd_perm, 8) <= 0o644
            shadow_ok = int(shadow_perm, 8) <= 0o400  # 000 or 400 is acceptable
            return {
                "passwd_perm": passwd_perm,
                "shadow_perm": shadow_perm,
                "passwd_ok": passwd_ok,
                "shadow_ok": shadow_ok,
            }
        except Exception:
            return {"passwd_perm": "???", "shadow_perm": "???", "passwd_ok": False, "shadow_ok": False}

    @staticmethod
    def parse_audit_rules(check, output, stderr):
        """Count auditd rules."""
        try:
            rules = [l for l in output.split("\n") if l.strip() and not l.startswith("#")]
            return {"rule_count": len(rules)}
        except Exception:
            return {"rule_count": 0}

    @staticmethod
    def parse_encryption_status(check, output, stderr):
        """Check if LUKS/crypt volumes exist."""
        try:
            has_encryption = bool(output.strip())
            lines = [l for l in output.split("\n") if l.strip()]
            return {"encryption_found": has_encryption, "volume_count": len(lines)}
        except Exception:
            return {"encryption_found": False, "volume_count": 0}

    @staticmethod
    def parse_pass_min_len(check, output, stderr):
        """Parse PASS_MIN_LEN from login.defs."""
        try:
            match = re.search(r'(\d+)', output)
            return {"min_length": int(match.group(1))} if match else {"min_length": 0}
        except Exception:
            return {"min_length": 0}


# =============================================================================
# SCAScanner Class
# =============================================================================

class SCAScanner:
    def __init__(self, callback=None, policy_name="cis"):
        self.callback = callback
        self.results = []
        self.policy_name = policy_name
        self.policy = _load_policy(policy_name)
        self.parsers = Parsers()

    def run_scan(self):
        """Run all SCA checks from the YAML policy."""
        self.results = []

        if self.policy is None:
            # Fallback: run old hardcoded checks
            self._run_legacy_checks()
            return self.results

        # Windows checks
        if IS_WINDOWS:
            for check in self.policy.get("windows_checks", []):
                self._execute_check(check)

        # Linux checks
        if not IS_WINDOWS:
            for check in self.policy.get("linux_checks", []):
                self._execute_check(check)

        return self.results

    def _execute_check(self, check):
        """Execute a single SCA check from the policy."""
        try:
            method = check.get("method", "")
            parser_name = check.get("parser", "")
            command = check.get("command", "")
            registry_key = check.get("registry_key", "")
            registry_value = check.get("registry_value", "")
            file_path = check.get("file_path", "")

            output = ""
            stderr = ""

            if method == "command":
                r = _run_hidden(command.split())
                output = r.stdout
                stderr = r.stderr

            elif method == "powershell":
                r = _run_hidden(["powershell", "-NoProfile", "-NonInteractive",
                                 "-Command", command])
                output = r.stdout.strip()
                stderr = r.stderr

            elif method == "registry":
                r = _run_hidden(["reg", "query", registry_key, "/v", registry_value])
                output = r.stdout
                stderr = r.stderr
                # Extract value from reg output
                for line in output.split("\n"):
                    if registry_value in line:
                        parts = line.split()
                        if len(parts) >= 3:
                            output = parts[-1].strip()
                            break
                if registry_value not in output:
                    output = "0"  # Default: not found = disabled

            elif method == "file_stat":
                if os.path.exists(file_path):
                    mode = oct(os.stat(file_path).st_mode)[-3:]
                    output = mode
                else:
                    output = "missing"

            # Parse the output
            parsed = {}
            if parser_name and hasattr(self.parsers, parser_name):
                parser_func = getattr(self.parsers, parser_name)
                parsed = parser_func(check, output, stderr)
            else:
                parsed = {"raw": output.strip()}

            # Evaluate expected condition
            expected = check.get("expected", "")
            status = self._evaluate_status(expected, parsed, check)

            # Build description message
            if status == "PASS":
                msg_tpl = check.get("pass_message", check.get("description", ""))
            elif status == "WARN":
                msg_tpl = check.get("warn_message", check.get("description", ""))
            else:
                msg_tpl = check.get("fail_message", check.get("description", ""))

            try:
                description = msg_tpl.format(**parsed)
            except (KeyError, ValueError):
                description = msg_tpl

            # Determine severity for WARN
            severity = check.get("severity", "MEDIUM")

            self._add_finding(
                check.get("id", "UNKNOWN"),
                check.get("title", "Unknown Check"),
                status,
                severity,
                description,
                check.get("remediation", ""),
            )

        except subprocess.TimeoutExpired:
            self._add_finding(
                check.get("id", "UNKNOWN"),
                check.get("title", "Unknown Check"),
                "WARN", "LOW",
                f"Check timed out: {check.get('title', '')}",
                check.get("remediation", "")
            )
        except Exception as e:
            self._add_finding(
                check.get("id", "UNKNOWN"),
                check.get("title", "Unknown Check"),
                "WARN", "LOW",
                f"Check failed: {str(e)[:100]}",
                check.get("remediation", "")
            )

    def _evaluate_status(self, expected, parsed, check):
        """Evaluate expected condition against parsed data. Returns PASS/FAIL/WARN."""
        if not expected:
            # No expected condition - use presence/absence-based logic
            return "PASS"

        try:
            # Simple expression evaluation (safer than eval)
            # Supports: variable comparisons, 'and', basic arithmetic
            result = self._safe_eval(expected, parsed)
            if result:
                return "PASS"
            else:
                return "FAIL"
        except Exception:
            return "FAIL"

    def _safe_eval(self, expr, context):
        """Safely evaluate a simple boolean expression with context variables."""
        # Replace variable names with their values
        expr_lower = expr.lower()
        for var, val in context.items():
            if isinstance(val, str):
                expr_lower = expr_lower.replace(var.lower(), f"'{val}'")
            elif isinstance(val, bool):
                expr_lower = expr_lower.replace(var.lower(), str(val))
            else:
                expr_lower = expr_lower.replace(var.lower(), str(val))

        # Restrict eval to simple comparisons
        # Only allow: numbers, strings, True/False, comparisons, and/or, not
        allowed = set('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_ .\'"<>=!()-+*/%:')
        cleaned = ''.join(c for c in expr_lower if c in allowed)

        # Dangerous keywords blacklist
        dangerous = ['__', 'import', 'exec', 'eval', 'open', 'file', 'os', 'sys',
                      'subprocess', 'compile', 'globals', 'locals']
        for d in dangerous:
            if d in cleaned:
                return False

        # Use simple eval with restricted context
        safe_builtins = {"True": True, "False": False, "None": None}
        result = eval(cleaned, {"__builtins__": safe_builtins}, context)
        return bool(result)

    def _add_finding(self, check_id, title, status, severity, description, remediation=""):
        finding = {
            "type": "sca_event",
            "check_id": check_id,
            "title": title,
            "status": status,
            "severity": severity,
            "description": description,
            "remediation": remediation,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        }
        self.results.append(finding)
        if self.callback:
            self.callback(finding)

    # ---- Legacy fallback for when pyyaml is not available ----
    def _run_legacy_checks(self):
        """Fallback to old hardcoded checks when policy YAML can't be loaded."""
        self._check_password_policy()
        self._check_firewall()
        self._check_defender()
        self._check_audit_policy()
        self._check_uac()
        self._check_services()
        self._check_network_settings()
        if not IS_WINDOWS:
            self._check_ssh_config()
            self._check_file_permissions()
        self._check_autologon()
        self._check_rdp_settings()
        # New v1.7.0 legacy checks
        self._check_bitlocker_legacy()
        self._check_ntlm_legacy()
        self._check_smb_signing_legacy()
        self._check_powershell_logging_legacy()
        self._check_windows_update_legacy()

    def _check_password_policy(self):
        if IS_WINDOWS:
            try:
                r = _run_hidden(["net", "accounts"])
                output = r.stdout.lower()
                min_len = max_age = lockout = 0
                for line in output.split("\n"):
                    if "minimum password length" in line:
                        try: min_len = int(line.split(":")[-1].strip().split()[0])
                        except Exception: pass
                    if "maximum password age" in line:
                        try: max_age = int(line.split(":")[-1].strip().split()[0])
                        except Exception: pass
                    if "lockout threshold" in line:
                        try: lockout = int(line.split(":")[-1].strip().split()[0])
                        except Exception: pass
                if min_len >= 14:
                    self._add_finding("CIS-1.1.1", "Password Length", "PASS", "LOW", f"Min password length: {min_len}")
                else:
                    self._add_finding("CIS-1.1.1", "Password Length", "FAIL", "HIGH",
                                      f"Min password length: {min_len} (14+ required)", "net accounts /minpwlen:14")
                if lockout >= 5:
                    self._add_finding("CIS-1.2.1", "Lockout Threshold", "PASS", "LOW", f"Threshold: {lockout}")
                else:
                    self._add_finding("CIS-1.2.1", "Lockout Threshold", "FAIL", "MEDIUM",
                                      f"Threshold: {lockout} (5+ required)", "net accounts /lockoutthreshold:5")
                if 30 <= max_age <= 90:
                    self._add_finding("CIS-1.1.2", "Password Max Age", "PASS", "LOW", f"Max age: {max_age}d")
                elif max_age > 0:
                    self._add_finding("CIS-1.1.2", "Password Max Age", "WARN", "MEDIUM",
                                      f"Max age: {max_age}d (30-90 recommended)", "net accounts /maxpwage:60")
                else:
                    self._add_finding("CIS-1.1.2", "Password Max Age", "FAIL", "HIGH",
                                      "Password never expires", "net accounts /maxpwage:60")
            except Exception as e:
                self._add_finding("CIS-1.0", "Password Policy", "WARN", "LOW", f"Check failed: {e}")
        else:
            try:
                r = _run_hidden(["grep", "-E", "^PASS_MAX_DAYS|^PASS_MIN_LEN", "/etc/login.defs"])
                for line in r.stdout.split("\n"):
                    if "PASS_MAX_DAYS" in line:
                        v = int(line.split()[-1])
                        if 30 <= v <= 90:
                            self._add_finding("CIS-5.4.1.2", "Password Max Days", "PASS", "LOW", f"PASS_MAX_DAYS: {v}")
                        else:
                            self._add_finding("CIS-5.4.1.2", "Password Max Days", "FAIL", "MEDIUM", f"PASS_MAX_DAYS: {v}")
                    if "PASS_MIN_LEN" in line:
                        v = int(line.split()[-1])
                        if v >= 14:
                            self._add_finding("CIS-5.4.1.1", "Password Min Length", "PASS", "LOW", f"PASS_MIN_LEN: {v}")
                        else:
                            self._add_finding("CIS-5.4.1.1", "Password Min Length", "FAIL", "HIGH", f"PASS_MIN_LEN: {v}")
            except Exception:
                pass

    def _check_firewall(self):
        if IS_WINDOWS:
            try:
                r = _run_hidden(["netsh", "advfirewall", "show", "allprofiles", "state"])
                if "ON" in r.stdout:
                    on_count = r.stdout.count("ON")
                    if on_count >= 3:
                        self._add_finding("CIS-9.1.1", "Windows Firewall", "PASS", "LOW", "Firewall ON all profiles")
                    else:
                        self._add_finding("CIS-9.1.1", "Windows Firewall", "WARN", "HIGH",
                                          f"Firewall ON {on_count}/3 profiles", "netsh advfirewall set allprofiles state on")
                else:
                    self._add_finding("CIS-9.1.1", "Windows Firewall", "FAIL", "CRITICAL",
                                      "Firewall OFF", "netsh advfirewall set allprofiles state on")
            except Exception:
                self._add_finding("CIS-9.1.1", "Windows Firewall", "WARN", "HIGH", "Could not check")
        else:
            try:
                r = _run_hidden(["iptables", "-L", "-n"])
                if "DROP" in r.stdout or "REJECT" in r.stdout:
                    self._add_finding("CIS-3.5.1.1", "iptables", "PASS", "LOW", "Restrictive policy")
                else:
                    self._add_finding("CIS-3.5.1.1", "iptables", "FAIL", "CRITICAL", "No restrictive policy")
            except Exception:
                try:
                    r = _run_hidden(["ufw", "status"])
                    if "active" in r.stdout.lower():
                        self._add_finding("CIS-3.5.1.1", "UFW", "PASS", "LOW", "UFW active")
                    else:
                        self._add_finding("CIS-3.5.1.1", "UFW", "FAIL", "CRITICAL", "UFW inactive")
                except Exception:
                    self._add_finding("CIS-3.5.1.1", "Firewall", "WARN", "CRITICAL", "No firewall detected")

    def _check_defender(self):
        if not IS_WINDOWS: return
        try:
            r = _run_hidden(["powershell", "-Command",
                "Get-MpComputerStatus | Select-Object AntivirusEnabled,RealTimeProtectionEnabled | ConvertTo-Json"], timeout=15)
            data = json.loads(r.stdout) if r.stdout else {}
            if isinstance(data, list): data = data[0] if data else {}
            if data.get("AntivirusEnabled") and data.get("RealTimeProtectionEnabled"):
                self._add_finding("CIS-18.9.44.1", "Windows Defender", "PASS", "LOW", "AV + Real-time ON")
            else:
                issues = []
                if not data.get("AntivirusEnabled"): issues.append("AV disabled")
                if not data.get("RealTimeProtectionEnabled"): issues.append("Real-time disabled")
                self._add_finding("CIS-18.9.44.1", "Windows Defender", "FAIL", "CRITICAL",
                                  ", ".join(issues), "Set-MpPreference -DisableRealtimeMonitoring $false")
        except Exception:
            self._add_finding("CIS-18.9.44.1", "Windows Defender", "WARN", "HIGH", "Could not check")

    def _check_audit_policy(self):
        if IS_WINDOWS:
            try:
                r = _run_hidden(["auditpol", "/get", "/category:*"])
                failed = []
                for line in r.stdout.split("\n"):
                    if "Success and Failure" not in line and any(
                            x in line for x in ["Logon/Logoff", "Account Logon", "Account Management",
                                                "Policy Change", "Privilege Use"]):
                        failed.append(line.split(",")[0].strip() if "," in line else line[:40])
                if not failed:
                    self._add_finding("CIS-17.1.1", "Audit Policy", "PASS", "LOW", "Key categories configured")
                else:
                    self._add_finding("CIS-17.1.1", "Audit Policy", "FAIL", "HIGH",
                                      f"Missing: {', '.join(failed[:5])}",
                                      "auditpol /set /category:* /success:enable /failure:enable")
            except Exception:
                self._add_finding("CIS-17.1.1", "Audit Policy", "WARN", "MEDIUM", "Could not check")
        else:
            try:
                r = _run_hidden(["auditctl", "-l"])
                if r.stdout.strip():
                    self._add_finding("CIS-4.1.1", "auditd", "PASS", "LOW",
                                      f"{len(r.stdout.split(chr(10)))} rules configured")
                else:
                    self._add_finding("CIS-4.1.1", "auditd", "FAIL", "CRITICAL", "No rules")
            except Exception:
                self._add_finding("CIS-4.1.1", "auditd", "WARN", "HIGH", "Not available")

    def _check_uac(self):
        if not IS_WINDOWS: return
        try:
            r = _run_hidden(["powershell", "-Command",
                "Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -Name EnableLUA | Select-Object -ExpandProperty EnableLUA"])
            if "1" in r.stdout:
                self._add_finding("CIS-2.3.17.1", "UAC", "PASS", "LOW", "UAC enabled")
            else:
                self._add_finding("CIS-2.3.17.1", "UAC", "FAIL", "CRITICAL", "UAC disabled")
        except Exception:
            self._add_finding("CIS-2.3.17.1", "UAC", "WARN", "HIGH", "Could not check")

    def _check_services(self):
        if IS_WINDOWS:
            insecure = []
            for svc in ["RemoteRegistry", "TlntSvr", "SNMP"]:
                try:
                    r = _run_hidden(["sc", "query", svc])
                    if "RUNNING" in r.stdout: insecure.append(svc)
                except Exception: pass
            if insecure:
                self._add_finding("CIS-18.2", "Insecure Services", "FAIL", "CRITICAL",
                                  f"Running: {', '.join(insecure)}", f"sc config {insecure[0]} start= disabled")
            else:
                self._add_finding("CIS-18.2", "Insecure Services", "PASS", "LOW", "No insecure services")

    def _check_network_settings(self):
        if IS_WINDOWS:
            try:
                r = _run_hidden(["powershell", "-Command", "(Get-SmbServerConfiguration).EnableSMB1Protocol"])
                if "False" in r.stdout:
                    self._add_finding("CIS-18.3.10", "SMBv1", "PASS", "LOW", "SMBv1 disabled")
                else:
                    self._add_finding("CIS-18.3.10", "SMBv1", "FAIL", "CRITICAL",
                                      "SMBv1 enabled!", "Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol")
            except Exception: pass

    def _check_ssh_config(self):
        if IS_WINDOWS: return
        try:
            r = _run_hidden(["grep", "-E", "^(PermitRootLogin|PasswordAuthentication)", "/etc/ssh/sshd_config"])
            found = {}
            for line in r.stdout.split("\n"):
                if " " in line:
                    k, v = line.split(None, 1)
                    found[k.strip()] = v.strip()
            status_r = "PASS" if found.get("PermitRootLogin") in ("no", "prohibit-password") else "FAIL"
            self._add_finding("CIS-5.2.3", "SSH Root Login", status_r, "HIGH",
                              f"PermitRootLogin: {found.get('PermitRootLogin', 'not set')}",
                              "Set PermitRootLogin no")
            status_p = "PASS" if found.get("PasswordAuthentication") == "no" else "WARN"
            self._add_finding("CIS-5.2.4", "SSH Password Auth", status_p, "MEDIUM",
                              f"PasswordAuth: {found.get('PasswordAuthentication', 'not set')}",
                              "Set PasswordAuthentication no")
        except Exception: pass

    def _check_file_permissions(self):
        if IS_WINDOWS: return
        for fpath, expected in [("/etc/passwd", "0644"), ("/etc/shadow", "0000"), ("/etc/ssh/sshd_config", "0600")]:
            if os.path.exists(fpath):
                try:
                    mode = oct(os.stat(fpath).st_mode)[-3:]
                    if mode == expected or (expected == "0000" and int(mode, 8) < 0o644):
                        self._add_finding("CIS-6.1", f"Perm: {fpath}", "PASS", "LOW", f"Mode: {mode}")
                    else:
                        self._add_finding("CIS-6.1", f"Perm: {fpath}", "FAIL", "HIGH",
                                          f"Mode: {mode} (expected {expected})", f"chmod {expected} {fpath}")
                except Exception: pass

    def _check_autologon(self):
        if not IS_WINDOWS: return
        try:
            r = _run_hidden(["reg", "query",
                "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", "/v", "AutoAdminLogon"])
            if "0x1" in r.stdout:
                self._add_finding("CIS-18.2.6", "AutoAdminLogon", "FAIL", "CRITICAL",
                                  "AutoAdminLogon enabled!", "Set AutoAdminLogon to 0")
            else:
                self._add_finding("CIS-18.2.6", "AutoAdminLogon", "PASS", "LOW", "Disabled")
        except Exception: pass

    def _check_rdp_settings(self):
        if not IS_WINDOWS: return
        try:
            r = _run_hidden(["powershell", "-Command",
                "(Get-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server' -Name fDenyTSConnections).fDenyTSConnections"])
            if "1" in r.stdout:
                self._add_finding("CIS-18.8.1", "RDP Access", "PASS", "LOW", "RDP disabled")
            else:
                self._add_finding("CIS-18.8.1", "RDP Access", "WARN", "MEDIUM",
                                  "RDP enabled - ensure NLA enforced")
        except Exception: pass

    # ---- NEW v1.7.0 legacy fallback checks ----
    def _check_bitlocker_legacy(self):
        if not IS_WINDOWS: return
        try:
            r = _run_hidden(["powershell", "-Command",
                "Get-BitLockerVolume -MountPoint $env:SystemDrive | Select-Object ProtectionStatus | ConvertTo-Json"], timeout=15)
            data = json.loads(r.stdout) if r.stdout else {}
            if isinstance(data, list): data = data[0] if data else {}
            ps = data.get("ProtectionStatus", 0)
            if ps == 1:
                self._add_finding("CIS-18.9.65.1", "BitLocker", "PASS", "LOW", "BitLocker enabled")
            else:
                self._add_finding("CIS-18.9.65.1", "BitLocker", "FAIL", "HIGH",
                                  "BitLocker not enabled", "Enable-BitLocker -MountPoint C:")
        except Exception: pass

    def _check_ntlm_legacy(self):
        if not IS_WINDOWS: return
        try:
            r = _run_hidden(["reg", "query",
                "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa", "/v", "LmCompatibilityLevel"])
            for line in r.stdout.split("\n"):
                if "LmCompatibilityLevel" in line:
                    parts = line.split()
                    if len(parts) >= 3:
                        val = parts[-1].strip()
                        level = int(val, 16) if "0x" in val.lower() else int(val)
                        if level >= 4:
                            self._add_finding("CIS-2.3.11.11", "NTLM Level", "PASS", "LOW",
                                              f"NTLM Level: {level}")
                        else:
                            self._add_finding("CIS-2.3.11.11", "NTLM Level", "FAIL", "HIGH",
                                              f"NTLM Level: {level} (4+ required)",
                                              "Set LmCompatibilityLevel=5")
        except Exception: pass

    def _check_smb_signing_legacy(self):
        if not IS_WINDOWS: return
        for key, title in [
            ("HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters", "SMB Server Signing"),
            ("HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters", "SMB Client Signing")
        ]:
            try:
                r = _run_hidden(["reg", "query", key, "/v", "RequireSecuritySignature"])
                for line in r.stdout.split("\n"):
                    if "RequireSecuritySignature" in line:
                        parts = line.split()
                        if len(parts) >= 3:
                            val = parts[-1].strip()
                            enabled = int(val, 16) == 1 if "0x" in val.lower() else val == "1"
                            if enabled:
                                self._add_finding("CIS-18.3.11", title, "PASS", "LOW", "SMB signing enabled")
                            else:
                                self._add_finding("CIS-18.3.11", title, "FAIL", "HIGH",
                                                  "SMB signing disabled", "Set RequireSecuritySignature=1")
            except Exception: pass

    def _check_powershell_logging_legacy(self):
        if not IS_WINDOWS: return
        checks = [
            ("ScriptBlockLogging", "EnableScriptBlockLogging", "PowerShell ScriptBlock Logging"),
            ("ModuleLogging", "EnableModuleLogging", "PowerShell Module Logging"),
            ("Transcription", "EnableTranscripting", "PowerShell Transcription"),
        ]
        for subkey, value, title in checks:
            try:
                key = f"HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\{subkey}"
                r = _run_hidden(["reg", "query", key, "/v", value])
                enabled = "0x1" in r.stdout or "1" in r.stdout.split("\n")[-1] if r.stdout else False
                if enabled:
                    self._add_finding("CIS-18.9.100", title, "PASS", "LOW", f"{title} enabled")
                else:
                    self._add_finding("CIS-18.9.100", title, "FAIL", "HIGH",
                                      f"{title} not enabled", "Enable via GPO")
            except Exception: pass

    def _check_windows_update_legacy(self):
        if not IS_WINDOWS: return
        try:
            r = _run_hidden(["reg", "query",
                "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU", "/v", "AUOptions"])
            for line in r.stdout.split("\n"):
                if "AUOptions" in line:
                    parts = line.split()
                    if len(parts) >= 3:
                        val = parts[-1].strip()
                        opt = int(val, 16) if "0x" in val.lower() else int(val)
                        if opt >= 3:
                            self._add_finding("CIS-18.9.85.1", "Windows Update", "PASS", "LOW",
                                              f"Auto update configured (AUOptions={opt})")
                        else:
                            self._add_finding("CIS-18.9.85.1", "Windows Update", "FAIL", "HIGH",
                                              f"Auto update not configured (AUOptions={opt})",
                                              "Set AUOptions=4 via GPO")
        except Exception:
            self._add_finding("CIS-18.9.85.1", "Windows Update", "WARN", "MEDIUM",
                              "Windows Update policy not configured")
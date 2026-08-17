"""
MITRE ATT&CK Mapper for GIAM-SAT Agent
Maps Windows Event IDs and Sysmon events to MITRE ATT&CK tactics/techniques.
"""

# MITRE ATT&CK Mapping: Windows Event ID -> {tactic, technique_id, technique_name, severity}
MITRE_MAP_WINDOWS = {
    # Account Management
    4720: {"tactic": "Persistence", "technique_id": "T1136", "technique_name": "Create Account", "severity": "MEDIUM"},
    4722: {"tactic": "Persistence", "technique_id": "T1098", "technique_name": "Account Manipulation", "severity": "HIGH"},
    4724: {"tactic": "Persistence", "technique_id": "T1098", "technique_name": "Account Manipulation", "severity": "HIGH"},
    4738: {"tactic": "Persistence", "technique_id": "T1098", "technique_name": "Account Manipulation", "severity": "MEDIUM"},
    
    # Logon Events
    4624: {"tactic": "Initial Access", "technique_id": "T1078", "technique_name": "Valid Accounts", "severity": "INFO"},
    4625: {"tactic": "Credential Access", "technique_id": "T1110", "technique_name": "Brute Force", "severity": "LOW"},
    4648: {"tactic": "Lateral Movement", "technique_id": "T1021", "technique_name": "Remote Services", "severity": "MEDIUM"},
    
    # Process Creation
    4688: {"tactic": "Execution", "technique_id": "T1059", "technique_name": "Command and Scripting Interpreter", "severity": "INFO"},
    
    # Scheduled Tasks
    4698: {"tactic": "Persistence", "technique_id": "T1053", "technique_name": "Scheduled Task/Job", "severity": "MEDIUM"},
    4699: {"tactic": "Persistence", "technique_id": "T1053", "technique_name": "Scheduled Task/Job", "severity": "MEDIUM"},
    4702: {"tactic": "Persistence", "technique_id": "T1053", "technique_name": "Scheduled Task/Job", "severity": "MEDIUM"},
    
    # Service Management
    4697: {"tactic": "Persistence", "technique_id": "T1543", "technique_name": "Create or Modify System Process", "severity": "HIGH"},
    7045: {"tactic": "Persistence", "technique_id": "T1543", "technique_name": "Create or Modify System Process (Service)", "severity": "HIGH"},
    
    # Firewall Changes
    4946: {"tactic": "Defense Evasion", "technique_id": "T1562", "technique_name": "Impair Defenses - Firewall", "severity": "HIGH"},
    4947: {"tactic": "Defense Evasion", "technique_id": "T1562", "technique_name": "Impair Defenses - Firewall", "severity": "HIGH"},
    4948: {"tactic": "Defense Evasion", "technique_id": "T1562", "technique_name": "Impair Defenses - Firewall", "severity": "HIGH"},
    
    # Audit Policy
    4719: {"tactic": "Defense Evasion", "technique_id": "T1562", "technique_name": "Impair Defenses - Audit Policy", "severity": "HIGH"},
    
    # Security Group
    4728: {"tactic": "Persistence", "technique_id": "T1098", "technique_name": "Account Manipulation - Group", "severity": "HIGH"},
    4732: {"tactic": "Persistence", "technique_id": "T1098", "technique_name": "Account Manipulation - Group", "severity": "HIGH"},
    4756: {"tactic": "Persistence", "technique_id": "T1098", "technique_name": "Account Manipulation - Group", "severity": "HIGH"},
    
    # Network
    5140: {"tactic": "Discovery", "technique_id": "T1135", "technique_name": "Network Share Discovery", "severity": "INFO"},
    5156: {"tactic": "Command and Control", "technique_id": "T1571", "technique_name": "Non-Standard Port", "severity": "LOW"},
    
    # Special Logon
    4672: {"tactic": "Privilege Escalation", "technique_id": "T1068", "technique_name": "Exploitation for Privilege Escalation", "severity": "MEDIUM"},
    
    # DLL Load
    4664: {"tactic": "Execution", "technique_id": "T1055", "technique_name": "Process Injection", "severity": "MEDIUM"},
    
    # Windows Defender
    5001: {"tactic": "Defense Evasion", "technique_id": "T1562", "technique_name": "Impair Defenses - AV Disabled", "severity": "CRITICAL"},
    5013: {"tactic": "Defense Evasion", "technique_id": "T1562", "technique_name": "Impair Defenses - AV", "severity": "HIGH"},
    
    # WMI
    5858: {"tactic": "Execution", "technique_id": "T1047", "technique_name": "Windows Management Instrumentation", "severity": "MEDIUM"},
    5860: {"tactic": "Execution", "technique_id": "T1047", "technique_name": "Windows Management Instrumentation", "severity": "MEDIUM"},
    5861: {"tactic": "Persistence", "technique_id": "T1546", "technique_name": "Event Triggered Execution - WMI", "severity": "HIGH"},
}

# Sysmon Event ID -> MITRE Mapping
MITRE_MAP_SYSMON = {
    1: {"tactic": "Execution", "technique_id": "T1059", "technique_name": "Process Creation", "severity": "INFO"},
    2: {"tactic": "Persistence", "technique_id": "T1547", "technique_name": "Boot or Logon Autostart - Registry", "severity": "MEDIUM"},
    3: {"tactic": "Discovery", "technique_id": "T1049", "technique_name": "System Network Connections Discovery", "severity": "INFO"},
    7: {"tactic": "Defense Evasion", "technique_id": "T1562", "technique_name": "Impair Defenses - Sysmon Disabled", "severity": "HIGH"},
    8: {"tactic": "Privilege Escalation", "technique_id": "T1055", "technique_name": "Process Injection", "severity": "CRITICAL"},
    10: {"tactic": "Defense Evasion", "technique_id": "T1070", "technique_name": "Indicator Removal - Event Logs", "severity": "HIGH"},
    11: {"tactic": "Persistence", "technique_id": "T1546", "technique_name": "Event Triggered Execution", "severity": "MEDIUM"},
    12: {"tactic": "Discovery", "technique_id": "T1083", "technique_name": "File and Directory Discovery", "severity": "INFO"},
    13: {"tactic": "Discovery", "technique_id": "T1012", "technique_name": "Query Registry", "severity": "INFO"},
    14: {"tactic": "Persistence", "technique_id": "T1546", "technique_name": "Event Triggered Execution", "severity": "MEDIUM"},
    22: {"tactic": "Discovery", "technique_id": "T1135", "technique_name": "Network Share Discovery - DNS", "severity": "LOW"},
}

# Network traffic -> MITRE Mapping
MITRE_MAP_NETWORK = {
    # Suspicious ports mapped to MITRE techniques
    4444: {"tactic": "Command and Control", "technique_id": "T1571", "technique_name": "Metasploit/Meterpreter C2", "severity": "CRITICAL"},
    1337: {"tactic": "Command and Control", "technique_id": "T1571", "technique_name": "Custom C2 Channel", "severity": "CRITICAL"},
    8080: {"tactic": "Command and Control", "technique_id": "T1571", "technique_name": "HTTP Alternate Port C2", "severity": "MEDIUM"},
    3389: {"tactic": "Lateral Movement", "technique_id": "T1021", "technique_name": "Remote Desktop Protocol", "severity": "LOW"},
    22:   {"tactic": "Lateral Movement", "technique_id": "T1021", "technique_name": "SSH Remote Services", "severity": "LOW"},
    23:   {"tactic": "Lateral Movement", "technique_id": "T1021", "technique_name": "Telnet Remote Services", "severity": "MEDIUM"},
    445:  {"tactic": "Lateral Movement", "technique_id": "T1021", "technique_name": "SMB/Windows Admin Shares", "severity": "MEDIUM"},
    135:  {"tactic": "Lateral Movement", "technique_id": "T1021", "technique_name": "RPC/DCOM Remote Services", "severity": "MEDIUM"},
    389:  {"tactic": "Discovery", "technique_id": "T1018", "technique_name": "Remote System Discovery - LDAP", "severity": "LOW"},
    53:   {"tactic": "Command and Control", "technique_id": "T1571", "technique_name": "DNS Tunneling", "severity": "HIGH"},
}

# FIM events -> MITRE Mapping
MITRE_MAP_FIM = {
    "FILE_CREATED": {"tactic": "Execution", "technique_id": "T1204", "technique_name": "User Execution - Malicious File", "severity": "MEDIUM"},
    "FILE_MODIFIED": {"tactic": "Defense Evasion", "technique_id": "T1562", "technique_name": "Impair Defenses - File Modification", "severity": "HIGH"},
    "FILE_DELETED": {"tactic": "Defense Evasion", "technique_id": "T1070", "technique_name": "Indicator Removal on Host", "severity": "HIGH"},
}

SEVERITY_ORDER = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}


def get_mitre_info(event_data):
    """
    Map a GIAM-SAT event to MITRE ATT&CK framework.
    Returns dict with tactic, technique_id, technique_name, severity or None.
    """
    event_type = event_data.get("type", "")
    event_id = str(event_data.get("event_id", ""))
    subtype = event_data.get("subtype", "")

    # Check Windows Event IDs
    if event_type == "windows_event":
        eid = int(event_id) if event_id.isdigit() else 0
        if subtype in ("Microsoft-Windows-Sysmon/Operational", "Sysmon"):
            return MITRE_MAP_SYSMON.get(eid)
        return MITRE_MAP_WINDOWS.get(eid)

    # Check FIM events
    if event_type == "fim":
        action = event_data.get("action", "")
        return MITRE_MAP_FIM.get(action)

    # Check Network traffic
    if event_type == "network_traffic":
        dst_port = int(event_data.get("dst_port", 0))
        return MITRE_MAP_NETWORK.get(dst_port)

    return None


def get_mitre_description(mitre_info):
    """Format MITRE info as a readable string."""
    if not mitre_info:
        return None
    return f"[{mitre_info['tactic']}] {mitre_info['technique_id']} - {mitre_info['technique_name']}"


def get_severity_score(mitre_info):
    """Convert MITRE severity to numeric score."""
    if not mitre_info:
        return 0
    return SEVERITY_ORDER.get(mitre_info.get("severity", "INFO"), 0)
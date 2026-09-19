"""Static mapping from each detector module to its MITRE ATT&CK technique.

Real SOC reports live or die by this mapping - it's what lets an analyst
(or a CISO reading the exec summary) instantly see *which stage of the kill
chain* each alert represents.
"""

DETECTOR_MITRE_MAP = {
    "phishing_detector": {
        "technique": "T1566",
        "name": "Phishing",
        "tactic": "Initial Access",
    },
    "virustotal_checker": {
        "technique": "T1204",
        "name": "User Execution (Malicious File/Link)",
        "tactic": "Execution",
    },
    "brute_force": {
        "technique": "T1110",
        "name": "Brute Force",
        "tactic": "Credential Access",
    },
    "lsass_mimikatz": {
        "technique": "T1003.001",
        "name": "OS Credential Dumping: LSASS Memory",
        "tactic": "Credential Access",
    },
    "powershell_analyzer": {
        "technique": "T1059.001",
        "name": "Command and Scripting Interpreter: PowerShell",
        "tactic": "Execution",
    },
    "ransomware": {
        "technique": "T1486",
        "name": "Data Encrypted for Impact",
        "tactic": "Impact",
    },
    "ransomware_shadow_copy": {
        "technique": "T1490",
        "name": "Inhibit System Recovery",
        "tactic": "Impact",
    },
    "persistence": {
        "technique": "T1053.005",
        "name": "Scheduled Task/Job: Scheduled Task",
        "tactic": "Persistence",
    },
    "persistence_run_key": {
        "technique": "T1547.001",
        "name": "Registry Run Keys / Startup Folder",
        "tactic": "Persistence",
    },
    "lateral_movement": {
        "technique": "T1021.002",
        "name": "Remote Services: SMB/Windows Admin Shares",
        "tactic": "Lateral Movement",
    },
    "lateral_movement_rdp": {
        "technique": "T1021.001",
        "name": "Remote Services: RDP",
        "tactic": "Lateral Movement",
    },
    "impossible_travel": {
        "technique": "T1078",
        "name": "Valid Accounts",
        "tactic": "Initial Access / Defense Evasion",
    },
}


def get_mitre(detector_key: str) -> dict:
    return DETECTOR_MITRE_MAP.get(
        detector_key,
        {"technique": "N/A", "name": "Unmapped", "tactic": "N/A"},
    )

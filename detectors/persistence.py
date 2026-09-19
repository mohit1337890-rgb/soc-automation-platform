"""Item 7: Persistence Detection.

Two mechanisms attackers use to survive a reboot:
  1. Scheduled Task creation (EID 4698) whose action runs from a
     user-writable path (AppData/Temp/ProgramData) or invokes PowerShell.
  2. Registry Run key modification (Sysmon EID 13) pointing at a binary
     in a user-writable path.
"""
from core.models import Alert
from core.mitre_mapper import get_mitre


def run(events: dict, config: dict, db) -> list[Alert]:
    cfg = config["persistence"]
    mitre_task = get_mitre("persistence")
    mitre_run = get_mitre("persistence_run_key")
    alerts = []

    for e in events.get("windows_security", []):
        if e.get("event_id") != 4698:
            continue
        action = e.get("task_action", "").lower()
        suspicious = any(p in action for p in cfg["suspicious_task_paths"]) or "powershell" in action

        if not suspicious:
            continue

        alert = Alert(
            detector="persistence",
            severity="high",
            title=f"Suspicious scheduled task created on {e.get('host')}",
            description=(
                f"Scheduled task '{e.get('task_name')}' was created on '{e.get('host')}' by "
                f"user '{e.get('user')}' with action: {e.get('task_action')}. Running from a "
                f"user-writable path and/or invoking PowerShell is a common persistence pattern."
            ),
            mitre_technique=mitre_task["technique"],
            mitre_tactic=mitre_task["tactic"],
            timestamp=e.get("timestamp"),
            entity_user=e.get("user"),
            entity_host=e.get("host"),
            iocs=[e.get("task_action", "")],
            raw_event=e,
        )
        alerts.append(alert)
        db.insert_alert(alert)

    for e in events.get("sysmon", []):
        if e.get("event_id") != 13:
            continue
        target = e.get("target_object", "").lower()
        if "\\run\\" not in target and "\\currentversion\\run" not in target:
            continue

        details = e.get("details", "").lower()
        suspicious = any(p in details for p in cfg["suspicious_run_key_paths"])
        if not suspicious:
            continue

        alert = Alert(
            detector="persistence",
            severity="high",
            title=f"Suspicious registry Run key added on {e.get('host')}",
            description=(
                f"Registry value '{e.get('target_object')}' was set to '{e.get('details')}' on "
                f"host '{e.get('host')}' by user '{e.get('user')}'. This causes the referenced "
                f"program to auto-start at every logon."
            ),
            mitre_technique=mitre_run["technique"],
            mitre_tactic=mitre_run["tactic"],
            timestamp=e.get("timestamp"),
            entity_user=e.get("user"),
            entity_host=e.get("host"),
            iocs=[e.get("details", "")],
            raw_event=e,
        )
        alerts.append(alert)
        db.insert_alert(alert)

    return alerts

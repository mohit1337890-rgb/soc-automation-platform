"""Item 4: LSASS Access / Mimikatz-style Credential Dumping (Sysmon EID 10).

Logic: Sysmon EID 10 (ProcessAccess) where the target is lsass.exe and the
granted access mask matches one known to be used by credential dumpers
(full/read access), or the source process name matches a known dumping
tool - either signal alone is enough here because this technique has very
few legitimate reasons to occur outside of EDR/AV agents (which should be
whitelisted by image path in a real deployment).
"""
from core.models import Alert
from core.mitre_mapper import get_mitre


def run(events: dict, config: dict, db) -> list[Alert]:
    cfg = config["lsass_mimikatz"]
    mitre = get_mitre("lsass_mimikatz")
    alerts = []

    for e in events.get("sysmon", []):
        if e.get("event_id") != 10:
            continue
        target = e.get("target_image", "").lower()
        if "lsass.exe" not in target:
            continue

        access = e.get("granted_access", "").lower()
        source_image = e.get("source_image", "")
        source_name = source_image.split("\\")[-1].lower()

        suspicious_access = access in [m.lower() for m in cfg["suspicious_access_masks"]]
        known_tool = source_name in [t.lower() for t in cfg["known_dump_tools"]]

        if not (suspicious_access or known_tool):
            continue

        alert = Alert(
            detector="lsass_mimikatz",
            severity="critical",
            title=f"Credential dumping attempt: {source_name} accessed LSASS on {e.get('host')}",
            description=(
                f"Process '{source_image}' opened LSASS.exe with access mask '{access}' "
                f"on host '{e.get('host')}'. This is a strong indicator of a credential "
                f"dumping tool (e.g. Mimikatz) attempting to extract passwords/hashes "
                f"from memory."
            ),
            mitre_technique=mitre["technique"],
            mitre_tactic=mitre["tactic"],
            timestamp=e.get("timestamp"),
            entity_user=e.get("user"),
            entity_host=e.get("host"),
            iocs=[source_image],
            raw_event=e,
        )
        alerts.append(alert)
        db.insert_alert(alert)

    return alerts

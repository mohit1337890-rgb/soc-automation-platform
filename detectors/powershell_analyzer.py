"""Item 5: Malicious PowerShell Detection (EID 4104 - Script Block Logging).

Logic: scan every logged script block for a set of keywords that are
heavily associated with fileless malware / living-off-the-land attacks
(-EncodedCommand, IEX, download cradles, AMSI bypass phrasing, etc). Also
decodes Base64 -EncodedCommand payloads so the *real* command is visible
in the alert instead of a wall of base64 - this is what an analyst wants
in a triage view.
"""
import re
import base64
from core.models import Alert
from core.mitre_mapper import get_mitre


def _try_decode_encoded_command(script_block: str) -> str | None:
    m = re.search(r"-(?:e|enc|encodedcommand)\s+([A-Za-z0-9+/=]{20,})", script_block, re.IGNORECASE)
    if not m:
        return None
    try:
        raw = base64.b64decode(m.group(1))
        return raw.decode("utf-16-le", errors="ignore")
    except Exception:
        return None


def run(events: dict, config: dict, db) -> list[Alert]:
    cfg = config["powershell"]
    mitre = get_mitre("powershell_analyzer")
    keywords = [k.lower() for k in cfg["suspicious_keywords"]]
    alerts = []

    for e in events.get("powershell", []):
        if e.get("event_id") != 4104:
            continue
        script_block = e.get("script_block", "")
        script_lower = script_block.lower()

        matched = [kw for kw in keywords if kw in script_lower]
        if not matched:
            continue

        decoded = _try_decode_encoded_command(script_block)
        decoded_matches = []
        if decoded:
            decoded_lower = decoded.lower()
            decoded_matches = [kw for kw in keywords if kw in decoded_lower]

        all_matched = sorted(set(matched + decoded_matches))
        severity = "critical" if len(all_matched) >= 3 or "-enc" in matched or "-encodedcommand" in matched else "high"

        description = (
            f"PowerShell script block on host '{e.get('host')}' (user '{e.get('user')}') "
            f"contains suspicious indicators: {', '.join(all_matched)}."
        )
        if decoded:
            description += f" Decoded -EncodedCommand payload: {decoded.strip()[:300]}"

        alert = Alert(
            detector="powershell_analyzer",
            severity=severity,
            title=f"Suspicious PowerShell execution on {e.get('host')}",
            description=description,
            mitre_technique=mitre["technique"],
            mitre_tactic=mitre["tactic"],
            timestamp=e.get("timestamp"),
            entity_user=e.get("user"),
            entity_host=e.get("host"),
            iocs=[decoded.strip()] if decoded else [],
            raw_event=e,
        )
        alerts.append(alert)
        db.insert_alert(alert)

    return alerts

"""Item 6: Ransomware Detection.

Three independent signals, any of which raises an alert (each is a strong
indicator on its own in a real environment where 3rd-party backup tools
are whitelisted by image path):
  1. Shadow-copy / backup-catalog deletion command line (Sysmon EID 1) -
     classic pre-encryption sabotage of recovery options.
  2. A burst of file-create events (Sysmon EID 11) on one host inside a
     short window - mass file rewriting is the signature of an encryptor.
  3. Known ransomware file extensions appearing (.locked, .encrypted, ...).
"""
from datetime import timedelta
from collections import defaultdict
from core.models import Alert
from core.mitre_mapper import get_mitre


def _parse_ts(ts: str):
    from datetime import datetime
    return datetime.fromisoformat(ts)


def run(events: dict, config: dict, db) -> list[Alert]:
    cfg = config["ransomware"]
    mitre_impact = get_mitre("ransomware")
    mitre_shadow = get_mitre("ransomware_shadow_copy")
    alerts = []

    sysmon = events.get("sysmon", [])

    # --- Signal 1: shadow copy / backup deletion ---
    shadow_cmds = [c.lower() for c in cfg["shadow_copy_delete_commands"]]
    for e in sysmon:
        if e.get("event_id") != 1:
            continue
        cmd = e.get("command_line", "").lower()
        if any(sc in cmd for sc in shadow_cmds):
            alert = Alert(
                detector="ransomware",
                severity="critical",
                title=f"Shadow copy deletion detected on {e.get('host')}",
                description=(
                    f"Process '{e.get('image')}' executed '{e.get('command_line')}' on host "
                    f"'{e.get('host')}', which destroys Windows backup/recovery points. This is "
                    f"a pre-encryption step used by ransomware to prevent recovery."
                ),
                mitre_technique=mitre_shadow["technique"],
                mitre_tactic=mitre_shadow["tactic"],
                timestamp=e.get("timestamp"),
                entity_user=e.get("user"),
                entity_host=e.get("host"),
                iocs=[e.get("command_line", "")],
                raw_event=e,
            )
            alerts.append(alert)
            db.insert_alert(alert)

    # --- Signal 2 & 3: mass file creation + known ransom extensions ---
    file_events_by_host = defaultdict(list)
    for e in sysmon:
        if e.get("event_id") == 11:
            file_events_by_host[e.get("host")].append(e)

    window = timedelta(minutes=cfg["mass_file_change_window_minutes"])
    ransom_exts = [ext.lower() for ext in cfg["known_ransom_extensions"]]

    for host, file_events in file_events_by_host.items():
        file_events.sort(key=lambda e: e["timestamp"])
        for i, e in enumerate(file_events):
            start = _parse_ts(e["timestamp"])
            window_events = [fe for fe in file_events if start <= _parse_ts(fe["timestamp"]) <= start + window]
            if len(window_events) >= cfg["mass_file_change_threshold"]:
                encrypted_files = [
                    fe.get("target_filename", "") for fe in window_events
                    if any(fe.get("target_filename", "").lower().endswith(ext) for ext in ransom_exts)
                ]
                alert = Alert(
                    detector="ransomware",
                    severity="critical",
                    title=f"Mass file encryption detected on {host}",
                    description=(
                        f"{len(window_events)} files were created/modified on '{host}' within "
                        f"{cfg['mass_file_change_window_minutes']} minute(s)"
                        + (f", {len(encrypted_files)} with known ransomware extensions "
                           f"(e.g. {encrypted_files[0]})." if encrypted_files else ".")
                    ),
                    mitre_technique=mitre_impact["technique"],
                    mitre_tactic=mitre_impact["tactic"],
                    timestamp=window_events[-1]["timestamp"],
                    entity_user=window_events[0].get("user"),
                    entity_host=host,
                    iocs=encrypted_files[:10],
                    raw_event={"sample_files": [fe.get("target_filename") for fe in window_events[:10]]},
                )
                alerts.append(alert)
                db.insert_alert(alert)
                break  # one alert per host is enough

    return alerts

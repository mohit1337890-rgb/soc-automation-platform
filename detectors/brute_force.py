"""Item 3: Brute Force Detection (Windows Event ID 4625 / 4624).

Logic: count failed logons (4625) per (user, host) inside a sliding
window. Crossing the threshold raises an alert; if a successful logon
(4624) for the same account/host follows shortly after, severity is
escalated to critical - that's the "attacker got in" case.
"""
from datetime import datetime, timedelta
from collections import defaultdict
from core.models import Alert
from core.mitre_mapper import get_mitre


def _parse_ts(ts: str) -> datetime:
    return datetime.fromisoformat(ts)


def run(events: dict, config: dict, db) -> list[Alert]:
    cfg = config["brute_force"]
    mitre = get_mitre("brute_force")
    window = timedelta(minutes=cfg["window_minutes"])
    threshold = cfg["failed_attempts_threshold"]

    winsec = sorted(events.get("windows_security", []), key=lambda e: e["timestamp"])
    failures_by_key = defaultdict(list)   # (user, host) -> [timestamps]
    successes_by_key = defaultdict(list)

    for e in winsec:
        if e.get("event_id") == 4625:
            failures_by_key[(e["user"], e["host"])].append(e)
        elif e.get("event_id") == 4624:
            successes_by_key[(e["user"], e["host"])].append(e)

    alerts = []
    flagged_keys = set()

    for key, fail_events in failures_by_key.items():
        fail_events.sort(key=lambda e: e["timestamp"])
        for i, e in enumerate(fail_events):
            start = _parse_ts(e["timestamp"])
            window_events = [
                fe for fe in fail_events
                if start <= _parse_ts(fe["timestamp"]) <= start + window
            ]
            if len(window_events) >= threshold and key not in flagged_keys:
                flagged_keys.add(key)
                user, host = key
                last_fail_ts = _parse_ts(window_events[-1]["timestamp"])

                # was there a successful logon for the same account/host shortly after?
                escalated = False
                for se in successes_by_key.get(key, []):
                    se_ts = _parse_ts(se["timestamp"])
                    if last_fail_ts <= se_ts <= last_fail_ts + timedelta(minutes=5):
                        escalated = True
                        break

                severity = "critical" if (escalated and cfg["success_after_failures_is_critical"]) else "high"
                title = f"Brute force against '{user}' on {host}"
                if escalated:
                    title += " - FOLLOWED BY SUCCESSFUL LOGON"

                alert = Alert(
                    detector="brute_force",
                    severity=severity,
                    title=title,
                    description=(
                        f"{len(window_events)} failed logon attempts for user '{user}' on host "
                        f"'{host}' within {cfg['window_minutes']} minute(s) from IP "
                        f"{window_events[0].get('src_ip')}."
                        + (" A successful logon followed - credentials were likely compromised." if escalated else "")
                    ),
                    mitre_technique=mitre["technique"],
                    mitre_tactic=mitre["tactic"],
                    timestamp=window_events[-1]["timestamp"],
                    entity_user=user,
                    entity_host=host,
                    entity_ip=window_events[0].get("src_ip"),
                    iocs=[window_events[0].get("src_ip")],
                    raw_event={"failed_attempts": window_events, "successful_logon": escalated},
                )
                alerts.append(alert)
                db.insert_alert(alert)
                break  # one alert per key is enough

    return alerts

"""Item 8: Lateral Movement Detection.

Two signals:
  1. PsExec-style remote execution: admin share access (EID 5140 to
     ADMIN$/C$/IPC$) followed by a PSEXESVC.exe process creation on the
     target host - the textbook PsExec fingerprint.
  2. Same account touching admin shares on >= N distinct hosts within a
     short window - even without PsExec, this is abnormal for a human
     user and typical of an attacker/worm hopping across the network.
"""
from datetime import timedelta, datetime
from collections import defaultdict
from core.models import Alert
from core.mitre_mapper import get_mitre


def run(events: dict, config: dict, db) -> list[Alert]:
    cfg = config["lateral_movement"]
    mitre = get_mitre("lateral_movement")
    alerts = []

    admin_shares = [s.upper() for s in cfg["admin_shares"]]
    psexec_names = [p.lower() for p in cfg["psexec_indicators"]]

    share_events = [
        e for e in events.get("windows_security", [])
        if e.get("event_id") == 5140 and any(s in e.get("share_name", "").upper() for s in admin_shares)
    ]

    # --- Signal 1: PsExec fingerprint (share access + PSEXESVC on same host shortly after) ---
    psexec_procs = [
        e for e in events.get("sysmon", [])
        if e.get("event_id") == 1 and e.get("image", "").split("\\")[-1].lower() in psexec_names
    ]
    for se in share_events:
        for pe in psexec_procs:
            if pe.get("host") != se.get("host"):
                continue
            dt = abs((datetime.fromisoformat(pe["timestamp"]) - datetime.fromisoformat(se["timestamp"])).total_seconds())
            if dt <= 120:
                alert = Alert(
                    detector="lateral_movement",
                    severity="critical",
                    title=f"PsExec-style lateral movement to {se.get('host')}",
                    description=(
                        f"User '{se.get('user')}' accessed admin share '{se.get('share_name')}' on "
                        f"'{se.get('host')}' and a PsExec service process was created moments later "
                        f"from IP {se.get('src_ip')}. This is the classic remote-execution fingerprint "
                        f"used to hop between machines."
                    ),
                    mitre_technique=mitre["technique"],
                    mitre_tactic=mitre["tactic"],
                    timestamp=pe["timestamp"],
                    entity_user=se.get("user"),
                    entity_host=se.get("host"),
                    entity_ip=se.get("src_ip"),
                    iocs=[se.get("src_ip", "")],
                    raw_event={"share_event": se, "process_event": pe},
                )
                alerts.append(alert)
                db.insert_alert(alert)

    # --- Signal 2: same account hitting admin shares on many hosts fast ---
    by_user = defaultdict(list)
    for e in share_events:
        by_user[e["user"]].append(e)

    window = timedelta(minutes=cfg["multi_host_window_minutes"])
    for user, ev_list in by_user.items():
        ev_list.sort(key=lambda e: e["timestamp"])
        for e in ev_list:
            start = datetime.fromisoformat(e["timestamp"])
            in_window = [x for x in ev_list if start <= datetime.fromisoformat(x["timestamp"]) <= start + window]
            hosts = {x["host"] for x in in_window}
            if len(hosts) >= cfg["multi_host_logon_threshold"]:
                alert = Alert(
                    detector="lateral_movement",
                    severity="high",
                    title=f"Account '{user}' accessed admin shares on {len(hosts)} hosts rapidly",
                    description=(
                        f"User '{user}' accessed administrative shares on {len(hosts)} distinct hosts "
                        f"({', '.join(sorted(hosts))}) within {cfg['multi_host_window_minutes']} minutes. "
                        f"This pattern is unusual for normal user/admin activity and typically indicates "
                        f"an attacker moving laterally with compromised credentials."
                    ),
                    mitre_technique=mitre["technique"],
                    mitre_tactic=mitre["tactic"],
                    timestamp=in_window[-1]["timestamp"],
                    entity_user=user,
                    entity_ip=in_window[0].get("src_ip"),
                    iocs=[in_window[0].get("src_ip", "")],
                    raw_event={"hosts": sorted(hosts)},
                )
                alerts.append(alert)
                db.insert_alert(alert)
                break

    return alerts

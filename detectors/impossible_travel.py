"""Item 9: Impossible Travel Detection (Cloud/AD sign-in logs + real Windows
remote logons).

Logic: for each user, look at consecutive sign-ins ordered by time, compute
the great-circle distance (haversine) between the two source locations, and
divide by the elapsed time to get an implied travel speed. If that speed
exceeds what's physically plausible (faster than a commercial flight), the
two logons can't both be genuine -> alert.

Two sources feed this, normalized into the same shape:
  1. `cloud_auth` events - the sample data already carries city/lat/lon, so
     this works fully offline for the demo (real Azure AD/Okta/Google
     Workspace sign-in-log ingestion isn't wired up yet).
  2. Real Windows Security EID 4624 (successful logon) events with a public
     source IP and a remote logon type (3=Network, 10=RemoteInteractive/RDP)
     - these DO exist in live mode today. When an IPinfo API key is
     configured (dashboard Settings, or impossible_travel.ipinfo_api_key),
     each IP is resolved to a real city/lat/lon via ingestion/geoip_lookup.py
     so this detector can fire on genuine live data even before a real
     cloud/AD integration exists.
"""
import math
from datetime import datetime
from core.models import Alert
from core.mitre_mapper import get_mitre
from ingestion.geoip_lookup import resolve_ip, is_private_ip

REMOTE_LOGON_TYPES = {"3", "10"}


def _haversine_km(lat1, lon1, lat2, lon2) -> float:
    R = 6371.0
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dphi = math.radians(lat2 - lat1)
    dlambda = math.radians(lon2 - lon1)
    a = math.sin(dphi / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dlambda / 2) ** 2
    return 2 * R * math.asin(math.sqrt(a))


def _collect_cloud_auth_logons(events: dict) -> dict:
    by_user = {}
    for e in events.get("cloud_auth", []):
        by_user.setdefault(e["user"], []).append({
            "timestamp": e["timestamp"], "city": e["city"], "country": e["country"],
            "lat": e["lat"], "lon": e["lon"], "src_ip": e.get("src_ip"),
        })
    return by_user


def _collect_live_windows_logons(events: dict, ipinfo_key: str) -> dict:
    by_user = {}
    if not ipinfo_key:
        return by_user
    for e in events.get("windows_security", []):
        if e.get("event_id") != 4624 or str(e.get("logon_type", "")) not in REMOTE_LOGON_TYPES:
            continue
        ip = e.get("src_ip")
        if is_private_ip(ip):
            continue
        geo = resolve_ip(ip, ipinfo_key)
        if not geo:
            continue
        by_user.setdefault(e["user"], []).append({
            "timestamp": e["timestamp"], "city": geo["city"], "country": geo["country"],
            "lat": geo["lat"], "lon": geo["lon"], "src_ip": ip,
        })
    return by_user


def run(events: dict, config: dict, db) -> list[Alert]:
    cfg = config["impossible_travel"]
    mitre = get_mitre("impossible_travel")
    alerts = []

    by_user: dict = {}
    for source in (_collect_cloud_auth_logons(events), _collect_live_windows_logons(events, cfg.get("ipinfo_api_key", ""))):
        for user, logons in source.items():
            by_user.setdefault(user, []).extend(logons)

    for user, logons in by_user.items():
        logons.sort(key=lambda x: x["timestamp"])
        for prev, curr in zip(logons, logons[1:]):
            hours = (datetime.fromisoformat(curr["timestamp"]) - datetime.fromisoformat(prev["timestamp"])).total_seconds() / 3600.0
            if hours <= 0:
                continue
            distance_km = _haversine_km(prev["lat"], prev["lon"], curr["lat"], curr["lon"])
            if distance_km < 50:
                continue  # same metro area, ignore
            speed_kmh = distance_km / hours

            if speed_kmh > cfg["max_plausible_speed_kmh"]:
                alert = Alert(
                    detector="impossible_travel",
                    severity="critical",
                    title=f"Impossible travel for '{user}': {prev['city']} -> {curr['city']}",
                    description=(
                        f"User '{user}' logged in from {prev['city']}, {prev['country']} at "
                        f"{prev['timestamp']} and then from {curr['city']}, {curr['country']} at "
                        f"{curr['timestamp']} - a distance of {distance_km:.0f} km in {hours:.2f} "
                        f"hour(s), implying a travel speed of {speed_kmh:.0f} km/h. This exceeds "
                        f"plausible travel speed and indicates the account credentials are likely "
                        f"compromised and being used from two locations."
                    ),
                    mitre_technique=mitre["technique"],
                    mitre_tactic=mitre["tactic"],
                    timestamp=curr["timestamp"],
                    entity_user=user,
                    entity_ip=curr.get("src_ip"),
                    iocs=[prev.get("src_ip", ""), curr.get("src_ip", "")],
                    raw_event={"previous_logon": prev, "current_logon": curr, "speed_kmh": speed_kmh},
                )
                alerts.append(alert)
                db.insert_alert(alert)

    return alerts

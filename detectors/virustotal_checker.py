"""Item 2: VirusTotal Reputation Checker.

Pulls every hash/domain/URL IOC out of the already-ingested events, checks
each one's reputation, and raises an alert for anything malicious/suspicious.

Two modes, chosen automatically:
  - ONLINE  (config.virustotal.api_key or env VT_API_KEY is set): calls the
    real VirusTotal v3 API, respecting the free-tier rate limit, and caches
    every verdict in SQLite (vt_cache table) so re-runs don't burn quota.
  - OFFLINE (no key configured): falls back to a small local blocklist so
    the module - and everything downstream of it - still works in a demo/
    CI environment with no internet access or paid API key.
"""
import os
import re
import time
import requests
from datetime import datetime, timezone
from core.models import Alert
from core.mitre_mapper import get_mitre

VT_URL_FILE = "https://www.virustotal.com/api/v3/files/{}"
VT_URL_DOMAIN = "https://www.virustotal.com/api/v3/domains/{}"


def _extract_indicators(events: dict) -> list[dict]:
    """Returns [{"type": "hash"|"domain", "value": ..., "source_event": {...}}]"""
    indicators = []

    for e in events.get("sysmon", []):
        hashes = e.get("hashes", "")
        m = re.search(r"MD5=([A-Fa-f0-9]{32})", hashes)
        if m:
            indicators.append({"type": "hash", "value": m.group(1).lower(), "source_event": e})

    for e in events.get("emails", []):
        sender_domain = e.get("from", "").split("@")[-1] if "@" in e.get("from", "") else None
        if sender_domain:
            indicators.append({"type": "domain", "value": sender_domain.lower(), "source_event": e})
        for url in e.get("urls", []):
            m = re.search(r"https?://([^/]+)/?", url)
            if m:
                indicators.append({"type": "domain", "value": m.group(1).lower(), "source_event": e})

    return indicators


def _check_offline(indicator: dict, cfg: dict) -> str:
    if indicator["type"] == "hash" and indicator["value"] in [h.lower() for h in cfg["offline_blocklist_hashes"]]:
        return "malicious"
    if indicator["type"] == "domain" and indicator["value"] in [d.lower() for d in cfg["offline_blocklist_domains"]]:
        return "malicious"
    return "clean"


def _check_online(indicator: dict, api_key: str) -> str:
    headers = {"x-apikey": api_key}
    try:
        if indicator["type"] == "hash":
            resp = requests.get(VT_URL_FILE.format(indicator["value"]), headers=headers, timeout=10)
        else:
            resp = requests.get(VT_URL_DOMAIN.format(indicator["value"]), headers=headers, timeout=10)
        if resp.status_code != 200:
            return "unknown"
        stats = resp.json()["data"]["attributes"]["last_analysis_stats"]
        if stats.get("malicious", 0) > 0:
            return "malicious"
        if stats.get("suspicious", 0) > 0:
            return "suspicious"
        return "clean"
    except (requests.RequestException, KeyError, ValueError):
        return "unknown"


def run(events: dict, config: dict, db) -> list[Alert]:
    cfg = config["virustotal"]
    # Tenant setting (entered via the dashboard) wins; env var / config.yaml
    # are the fallback for CLI/Docker use.
    api_key = cfg.get("api_key", "") or os.environ.get("VT_API_KEY", "")
    mitre = get_mitre("virustotal_checker")
    alerts = []

    indicators = _extract_indicators(events)
    min_interval = 60.0 / max(cfg.get("requests_per_minute", 4), 1)
    last_call = 0.0

    for ind in indicators:
        cached = db.vt_cache_get(ind["value"])
        if cached is not None:
            verdict = cached
        elif api_key:
            elapsed = time.monotonic() - last_call
            if elapsed < min_interval:
                time.sleep(min_interval - elapsed)
            verdict = _check_online(ind, api_key)
            last_call = time.monotonic()
            db.vt_cache_set(ind["value"], verdict, datetime.now(timezone.utc).isoformat())
        else:
            verdict = _check_offline(ind, cfg)
            db.vt_cache_set(ind["value"], verdict, datetime.now(timezone.utc).isoformat())

        if verdict in ("malicious", "suspicious"):
            src = ind["source_event"]
            alert = Alert(
                detector="virustotal_checker",
                severity="critical" if verdict == "malicious" else "medium",
                title=f"VirusTotal flagged {ind['type']} as {verdict}: {ind['value']}",
                description=(
                    f"Indicator '{ind['value']}' ({ind['type']}) extracted from "
                    f"a {src.get('source')} event was rated '{verdict}' by VirusTotal."
                ),
                mitre_technique=mitre["technique"],
                mitre_tactic=mitre["tactic"],
                timestamp=src.get("timestamp"),
                entity_user=src.get("user") or (src.get("to", "").split("@")[0] if src.get("to") else None),
                entity_host=src.get("host"),
                iocs=[ind["value"]],
                raw_event=src,
            )
            alerts.append(alert)
            db.insert_alert(alert)

    return alerts

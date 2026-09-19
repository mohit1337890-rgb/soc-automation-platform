"""The Orchestrator - runs Ingestion -> Detection -> Correlation -> Reporting
for one tenant. Shared by main.py (CLI), dashboard/app.py (the "Run Now"
button), and scheduler.py (unattended periodic runs) so every entry point
behaves identically.
"""
import os
import yaml
from datetime import datetime, timezone
from core.database import SOCDatabase
from core.tenants import TenantRegistry, tenant_paths, ensure_tenant_dirs
from core.correlation import build_incidents
from ingestion.sample_data_generator import generate_all
from ingestion.log_loader import load_events
from ingestion.windows_event_log_reader import read_live_windows_events
from ingestion.email_ingestion import read_live_inbox
from ingestion.cloud_auth_ingestion import read_live_cloud_auth
from reporting.report_generator import generate_report
from notifications.notifier import notify_new_alerts

from detectors import (
    phishing_detector, virustotal_checker, brute_force, lsass_mimikatz,
    powershell_analyzer, ransomware, persistence, lateral_movement, impossible_travel,
)

DETECTOR_MODULES = [
    phishing_detector, virustotal_checker, brute_force, lsass_mimikatz,
    powershell_analyzer, ransomware, persistence, lateral_movement, impossible_travel,
]


def load_config(config_path: str = "config.yaml") -> dict:
    with open(config_path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def _apply_tenant_settings(config: dict, settings: dict) -> None:
    """Settings entered in the dashboard's Settings tab override config.yaml
    defaults / environment variables for this tenant's runs only.
    """
    if settings.get("vt_api_key"):
        config["virustotal"]["api_key"] = settings["vt_api_key"]
    if settings.get("anthropic_api_key"):
        config["genai"]["api_key"] = settings["anthropic_api_key"]
    if settings.get("ipinfo_api_key"):
        config["impossible_travel"]["ipinfo_api_key"] = settings["ipinfo_api_key"]


def _collect_live_events(settings: dict, lookback_hours: int = 24) -> tuple[dict, list[str]]:
    warnings = []

    win_events = read_live_windows_events(lookback_hours=lookback_hours)
    warnings.extend(win_events.pop("warnings", []))

    email_result = read_live_inbox(
        email_address=settings.get("email_address", ""),
        app_password=settings.get("email_app_password", ""),
        provider=settings.get("email_provider", "gmail"),
        custom_server=settings.get("email_imap_server", ""),
        lookback_days=int(settings.get("email_lookback_days", 3) or 3),
    )
    warnings.extend(email_result.pop("warnings", []))

    cloud_events, cloud_warnings = read_live_cloud_auth(settings, lookback_hours=lookback_hours)
    warnings.extend(cloud_warnings)

    events = {
        "emails": email_result.get("emails", []),
        "windows_security": win_events.get("windows_security", []),
        "sysmon": win_events.get("sysmon", []),
        "powershell": win_events.get("powershell", []),
        "cloud_auth": cloud_events,
    }
    return events, warnings


def run_pipeline(tenant_id: str, generate_sample_data: bool = True,
                  genai_override: bool | None = None, seed: int = 42,
                  source: str = "sample") -> dict:
    """Runs the full pipeline for one tenant. `source` is "sample" (bundled
    synthetic demo data) or "live" (real Windows Event Logs + real email
    inbox, using this tenant's Settings). Returns a summary dict with counts,
    warnings, and the generated report path.

    Alert history persists across runs - each Alert has a deterministic id
    (core/models.py) so re-seeing the same real-world event overwrites its
    own row instead of duplicating, while a genuinely new event is added
    without disturbing anything already triaged. Nothing is wiped.
    """
    config = load_config()
    if genai_override is not None:
        config["genai"]["enabled"] = genai_override

    registry = TenantRegistry()
    tenant = registry.get(tenant_id)
    if tenant is None:
        raise ValueError(f"Unknown tenant '{tenant_id}'. Check config/tenants.yaml")

    paths = ensure_tenant_dirs(tenant_id)
    # tenant-specific paths override the global defaults in config.yaml
    config["paths"]["database_file"] = paths["database_file"]
    config["paths"]["reports_dir"] = paths["reports_dir"]

    db = SOCDatabase(paths["database_file"])
    settings = db.get_settings()
    _apply_tenant_settings(config, settings)

    ids_before = db.get_alert_ids()

    warnings = []
    if source == "live":
        events, warnings = _collect_live_events(settings)
    else:
        if generate_sample_data or not os.path.exists(os.path.join(paths["sample_data_dir"], "emails.jsonl")):
            generate_all(paths["sample_data_dir"], seed=seed)
        events = load_events(paths["sample_data_dir"])

    total_alerts = 0
    per_detector_counts = {}
    for module in DETECTOR_MODULES:
        name = module.__name__.split(".")[-1]
        alerts = module.run(events, config, db)
        per_detector_counts[name] = len(alerts)
        total_alerts += len(alerts)

    all_alerts = db.get_all_alerts()
    new_alerts = [a for a in all_alerts if a["id"] not in ids_before]

    incidents = build_incidents(all_alerts, config)
    db.clear_incidents()
    for inc in incidents:
        db.insert_incident(inc)

    report_path = generate_report(db, config, tenant_id, tenant.name)

    warnings.extend(notify_new_alerts(settings, new_alerts, tenant.name))

    db.set_setting("last_scan_at", datetime.now(timezone.utc).isoformat())
    db.set_setting("last_scan_source", source)
    db.close()

    return {
        "tenant_id": tenant_id,
        "tenant_name": tenant.name,
        "source": source,
        "events_loaded": {k: len(v) for k, v in events.items()},
        "alerts_by_detector": per_detector_counts,
        # len(all_alerts), not the raw sum of what detectors returned this run,
        # since two detector hits can legitimately dedupe to one stored alert
        # (core/models.py's deterministic id) - this reflects what's actually stored.
        "total_alerts": len(all_alerts),
        "new_alerts": len(new_alerts),
        "incidents": len(incidents),
        "report_path": report_path,
        "database_file": paths["database_file"],
        "warnings": warnings,
    }

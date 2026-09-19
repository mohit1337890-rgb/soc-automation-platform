"""Standalone always-on scheduler - the piece that makes scanning happen
automatically instead of a human clicking "Run detection pipeline now"
every time.

Usage:
    python scheduler.py                 # runs forever in the foreground
    docker compose up -d scheduler      # or as a long-running Docker service

Design: every CHECK_INTERVAL_SECONDS, re-read the tenant registry (so
adding a tenant to config/tenants.yaml doesn't require a restart) and each
tenant's Settings (scheduling_enabled / scheduling_interval_minutes /
scheduling_source, all configured from the dashboard's Settings panel).
Any tenant whose interval has elapsed since its last scan gets one -
`core/pipeline.py` already tracks `last_scan_at` after every run (CLI,
dashboard, or scheduler), so all three stay in sync automatically.

One tenant's failure (bad credentials, a transient network error, an
unexpected exception in a detector) is caught and logged, never allowed to
take down scanning for every other tenant - that would defeat the entire
point of an unattended scheduler.
"""
import sys
import time
import traceback
from datetime import datetime, timezone

from core.tenants import TenantRegistry, tenant_paths
from core.database import SOCDatabase
from core.pipeline import run_pipeline

CHECK_INTERVAL_SECONDS = 30


def _log(msg: str):
    print(f"[{datetime.now(timezone.utc).isoformat()}] [scheduler] {msg}", flush=True)


def _is_due(settings: dict) -> bool:
    if settings.get("scheduling_enabled") != "true":
        return False
    last_scan_at = settings.get("last_scan_at")
    interval_minutes = int(settings.get("scheduling_interval_minutes", 30) or 30)
    if not last_scan_at:
        return True
    try:
        last = datetime.fromisoformat(last_scan_at)
    except ValueError:
        return True
    elapsed_minutes = (datetime.now(timezone.utc) - last).total_seconds() / 60
    return elapsed_minutes >= interval_minutes


def run_forever():
    _log(f"started - checking every {CHECK_INTERVAL_SECONDS}s for tenants with scheduling enabled")
    while True:
        registry = TenantRegistry()
        for tenant in registry.list_tenants():
            paths = tenant_paths(tenant.id)
            try:
                db = SOCDatabase(paths["database_file"])
                settings = db.get_settings()
                db.close()
            except Exception as e:
                _log(f"{tenant.id}: could not read settings ({e}) - skipping this tick")
                continue

            if not _is_due(settings):
                continue

            source = settings.get("scheduling_source", "live")
            _log(f"{tenant.id}: due - running (source={source})")
            try:
                result = run_pipeline(tenant.id, generate_sample_data=False, source=source)
                _log(f"{tenant.id}: {result['total_alerts']} total alerts "
                     f"({result['new_alerts']} new), {result['incidents']} incident(s)")
                for w in result.get("warnings", []):
                    _log(f"{tenant.id}: warning - {w}")
            except Exception:
                _log(f"{tenant.id}: run FAILED, see traceback below - continuing with other tenants")
                traceback.print_exc()

        time.sleep(CHECK_INTERVAL_SECONDS)


if __name__ == "__main__":
    try:
        run_forever()
    except KeyboardInterrupt:
        _log("stopped")
        sys.exit(0)

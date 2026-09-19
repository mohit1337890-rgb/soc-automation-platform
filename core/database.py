"""SQLite-backed storage for alerts and incidents.

Every detector calls db.insert_alert(alert) as soon as it fires. The
correlation engine then reads everything back out to build incidents.
One SOCDatabase instance == one tenant's data (see core/tenants.py).
"""
import sqlite3
import json
import os
from datetime import datetime, timezone
from typing import Optional
from core.models import Alert, Incident


class SOCDatabase:
    def __init__(self, db_path: str):
        os.makedirs(os.path.dirname(db_path) or ".", exist_ok=True)
        self.db_path = db_path
        self.conn = sqlite3.connect(db_path)
        self.conn.row_factory = sqlite3.Row
        self._init_schema()

    def _init_schema(self):
        self.conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS alerts (
                id TEXT PRIMARY KEY,
                timestamp TEXT,
                detector TEXT,
                severity TEXT,
                title TEXT,
                description TEXT,
                mitre_technique TEXT,
                mitre_tactic TEXT,
                entity_user TEXT,
                entity_host TEXT,
                entity_ip TEXT,
                iocs TEXT,
                raw_event TEXT,
                status TEXT DEFAULT 'new',
                status_note TEXT DEFAULT '',
                status_updated_at TEXT
            );

            CREATE TABLE IF NOT EXISTS incidents (
                id TEXT PRIMARY KEY,
                timestamp TEXT,
                title TEXT,
                narrative TEXT,
                severity TEXT,
                entity TEXT,
                alert_ids TEXT,
                mitre_chain TEXT
            );

            CREATE TABLE IF NOT EXISTS vt_cache (
                indicator TEXT PRIMARY KEY,
                verdict TEXT,
                checked_at TEXT
            );

            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT
            );

            CREATE INDEX IF NOT EXISTS idx_alerts_entity_host ON alerts(entity_host);
            CREATE INDEX IF NOT EXISTS idx_alerts_entity_user ON alerts(entity_user);
            CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp);
            """
        )
        self.conn.commit()
        self._migrate_schema()

    def _migrate_schema(self):
        """Adds columns introduced after a tenant's database already existed.
        CREATE TABLE IF NOT EXISTS doesn't retrofit new columns onto an
        existing table, so older per-tenant databases need this once.
        """
        existing_cols = {row["name"] for row in self.conn.execute("PRAGMA table_info(alerts)")}
        for col, ddl in [
            ("status", "ALTER TABLE alerts ADD COLUMN status TEXT DEFAULT 'new'"),
            ("status_note", "ALTER TABLE alerts ADD COLUMN status_note TEXT DEFAULT ''"),
            ("status_updated_at", "ALTER TABLE alerts ADD COLUMN status_updated_at TEXT"),
        ]:
            if col not in existing_cols:
                self.conn.execute(ddl)
        self.conn.commit()

    # ---------- Alerts ----------
    def insert_alert(self, alert: Alert):
        """Upserts by the alert's deterministic id (core/models.py). If this
        exact alert already exists (same detector/entity/title/timestamp -
        i.e. the same real-world event seen again in an overlapping scan
        window), its factual fields are refreshed but an analyst's triage
        status is deliberately left untouched - re-detecting an event must
        never silently un-resolve it.
        """
        self.conn.execute(
            """INSERT INTO alerts
               (id, timestamp, detector, severity, title, description,
                mitre_technique, mitre_tactic, entity_user, entity_host,
                entity_ip, iocs, raw_event, status, status_note, status_updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'new', '', NULL)
               ON CONFLICT(id) DO UPDATE SET
                   timestamp=excluded.timestamp, detector=excluded.detector,
                   severity=excluded.severity, title=excluded.title,
                   description=excluded.description, mitre_technique=excluded.mitre_technique,
                   mitre_tactic=excluded.mitre_tactic, entity_user=excluded.entity_user,
                   entity_host=excluded.entity_host, entity_ip=excluded.entity_ip,
                   iocs=excluded.iocs, raw_event=excluded.raw_event""",
            (
                alert.id, alert.timestamp, alert.detector, alert.severity,
                alert.title, alert.description, alert.mitre_technique,
                alert.mitre_tactic, alert.entity_user, alert.entity_host,
                alert.entity_ip, json.dumps(alert.iocs), json.dumps(alert.raw_event),
            ),
        )
        self.conn.commit()

    def get_all_alerts(self) -> list[dict]:
        rows = self.conn.execute("SELECT * FROM alerts ORDER BY timestamp ASC").fetchall()
        return [self._row_to_alert_dict(r) for r in rows]

    def get_alert_ids(self) -> set:
        return {r["id"] for r in self.conn.execute("SELECT id FROM alerts")}

    def update_alert_status(self, alert_id: str, status: str, note: str = ""):
        self.conn.execute(
            "UPDATE alerts SET status = ?, status_note = ?, status_updated_at = ? WHERE id = ?",
            (status, note, datetime.now(timezone.utc).isoformat(), alert_id),
        )
        self.conn.commit()

    def _row_to_alert_dict(self, row: sqlite3.Row) -> dict:
        d = dict(row)
        d["iocs"] = json.loads(d["iocs"] or "[]")
        d["raw_event"] = json.loads(d["raw_event"] or "{}")
        return d

    # ---------- Incidents ----------
    def insert_incident(self, incident: Incident):
        self.conn.execute(
            """INSERT OR REPLACE INTO incidents
               (id, timestamp, title, narrative, severity, entity, alert_ids, mitre_chain)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                incident.id, incident.timestamp, incident.title, incident.narrative,
                incident.severity, incident.entity, json.dumps(incident.alert_ids),
                json.dumps(incident.mitre_chain),
            ),
        )
        self.conn.commit()

    def get_all_incidents(self) -> list[dict]:
        rows = self.conn.execute("SELECT * FROM incidents ORDER BY timestamp ASC").fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["alert_ids"] = json.loads(d["alert_ids"] or "[]")
            d["mitre_chain"] = json.loads(d["mitre_chain"] or "[]")
            out.append(d)
        return out

    def clear_incidents(self):
        self.conn.execute("DELETE FROM incidents")
        self.conn.commit()

    def clear_alerts(self):
        self.conn.execute("DELETE FROM alerts")
        self.conn.commit()

    # ---------- VirusTotal cache (respects free-tier rate limits) ----------
    def vt_cache_get(self, indicator: str) -> Optional[str]:
        row = self.conn.execute(
            "SELECT verdict FROM vt_cache WHERE indicator = ?", (indicator,)
        ).fetchone()
        return row["verdict"] if row else None

    def vt_cache_set(self, indicator: str, verdict: str, checked_at: str):
        self.conn.execute(
            "INSERT OR REPLACE INTO vt_cache (indicator, verdict, checked_at) VALUES (?, ?, ?)",
            (indicator, verdict, checked_at),
        )
        self.conn.commit()

    # ---------- Settings (per-tenant API keys / email credentials) ----------
    # Stored as plaintext in this tenant's own isolated SQLite file - fine for
    # local/demo use, but NOT a secrets vault. For real production, prefer
    # environment variables injected by your deployment platform, or a proper
    # secrets manager, instead of typing long-lived credentials into a UI.
    def get_settings(self) -> dict:
        rows = self.conn.execute("SELECT key, value FROM settings").fetchall()
        return {r["key"]: r["value"] for r in rows}

    def get_setting(self, key: str, default: str = "") -> str:
        row = self.conn.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
        return row["value"] if row else default

    def set_setting(self, key: str, value: str):
        self.conn.execute(
            "INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", (key, value)
        )
        self.conn.commit()

    def set_settings(self, values: dict):
        for key, value in values.items():
            self.set_setting(key, value)

    def close(self):
        self.conn.close()

"""Item 10: Executive Reporting.

Pulls every alert + correlated incident for a tenant out of the database,
builds a MITRE ATT&CK coverage table and IOC list, gets the executive
summary (GenAI or template - see genai_summary.py), and renders it all
into a single self-contained HTML report a client can open in any browser.
"""
import os
from collections import Counter
from datetime import datetime, timezone
from jinja2 import Environment, FileSystemLoader
from core.mitre_mapper import DETECTOR_MITRE_MAP
from reporting.genai_summary import generate_executive_summary

TEMPLATE_DIR = os.path.join(os.path.dirname(__file__), "templates")


def _mitre_table(alerts: list[dict]) -> list[dict]:
    counts = Counter((a["mitre_technique"], a["mitre_tactic"]) for a in alerts)
    # reverse-lookup technique -> human name from the static map
    name_by_technique = {v["technique"]: v["name"] for v in DETECTOR_MITRE_MAP.values()}
    rows = []
    for (technique, tactic), count in sorted(counts.items(), key=lambda x: -x[1]):
        rows.append({
            "technique": technique,
            "name": name_by_technique.get(technique, "Unknown"),
            "tactic": tactic,
            "count": count,
        })
    return rows


def generate_report(db, config: dict, tenant_id: str, tenant_name: str) -> str:
    alerts = db.get_all_alerts()
    incidents_raw = db.get_all_incidents()

    # dashboard/report both need .severity/.title/etc as attributes for the
    # incident objects passed into the template - wrap dicts minimally.
    class _Inc:
        def __init__(self, d):
            self.__dict__.update(d)

    incidents = [_Inc(i) for i in incidents_raw]

    severity_counts = Counter(a["severity"] for a in alerts)
    all_iocs = sorted({str(ioc) for a in alerts for ioc in a.get("iocs", []) if ioc})

    exec_summary, source = generate_executive_summary(alerts, incidents, tenant_name, config)

    env = Environment(loader=FileSystemLoader(TEMPLATE_DIR), autoescape=True)
    template = env.get_template("report.html.j2")
    html = template.render(
        tenant_name=tenant_name,
        tenant_id=tenant_id,
        generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        alerts=alerts,
        incidents=incidents,
        severity_counts=severity_counts,
        mitre_table=_mitre_table(alerts),
        iocs=all_iocs,
        executive_summary=exec_summary,
        summary_source=source,
    )

    reports_dir = config["paths"]["reports_dir"]
    os.makedirs(reports_dir, exist_ok=True)
    out_path = os.path.join(reports_dir, f"soc_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html")
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(html)

    return out_path

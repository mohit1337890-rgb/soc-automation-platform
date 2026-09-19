"""The Correlation Engine ("The Brain").

Individually, "5 failed logons" or "a scheduled task was created" are low/
medium-value alerts an analyst might dismiss. The point of this layer is
to notice that the SAME account, host, IP or IOC keeps reappearing across
DIFFERENT detectors within a short time span - which is exactly what a
real intrusion looks like (Initial Access -> Credential Access ->
Persistence -> Lateral Movement -> Impact) - and stitch those alerts into
one Incident with a single story instead of ten disconnected rows.

Algorithm: Union-Find over alerts. Two alerts are linked if they share a
non-null entity_user, entity_host, entity_ip, or IOC value AND occurred
within `correlation.max_gap_minutes` of each other. Every connected
component that contains alerts from 2+ distinct detectors becomes an
Incident; everything else stays a standalone alert in the report.
"""
from datetime import datetime, timedelta
from collections import defaultdict
from core.models import Incident

SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}


class _UnionFind:
    def __init__(self, ids):
        self.parent = {i: i for i in ids}

    def find(self, x):
        while self.parent[x] != x:
            self.parent[x] = self.parent[self.parent[x]]
            x = self.parent[x]
        return x

    def union(self, a, b):
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.parent[ra] = rb


def _group_and_link(alerts: list[dict], key_fn, uf: _UnionFind, max_gap: timedelta):
    groups = defaultdict(list)
    for a in alerts:
        key = key_fn(a)
        if key:
            groups[key].append(a)
    for _, group in groups.items():
        group.sort(key=lambda a: a["timestamp"])
        for prev, curr in zip(group, group[1:]):
            gap = abs(datetime.fromisoformat(curr["timestamp"]) - datetime.fromisoformat(prev["timestamp"]))
            if gap <= max_gap:
                uf.union(prev["id"], curr["id"])


def build_incidents(alerts: list[dict], config: dict) -> list[Incident]:
    if not alerts:
        return []

    max_gap = timedelta(minutes=config["correlation"]["max_gap_minutes"])
    uf = _UnionFind([a["id"] for a in alerts])

    _group_and_link(alerts, lambda a: a.get("entity_user"), uf, max_gap)
    _group_and_link(alerts, lambda a: a.get("entity_host"), uf, max_gap)
    _group_and_link(alerts, lambda a: a.get("entity_ip"), uf, max_gap)

    # IOC-based linking (e.g. a dropped file's hash tying VirusTotal's
    # verdict back to the Sysmon process-creation event that dropped it).
    ioc_index = defaultdict(list)
    for a in alerts:
        for ioc in a.get("iocs", []):
            if ioc and len(str(ioc)) > 4:   # skip empty/trivial values
                ioc_index[ioc].append(a)
    for _, group in ioc_index.items():
        group.sort(key=lambda a: a["timestamp"])
        for prev, curr in zip(group, group[1:]):
            gap = abs(datetime.fromisoformat(curr["timestamp"]) - datetime.fromisoformat(prev["timestamp"]))
            if gap <= max_gap:
                uf.union(prev["id"], curr["id"])

    components = defaultdict(list)
    for a in alerts:
        components[uf.find(a["id"])].append(a)

    incidents = []
    for _, group in components.items():
        detectors = {a["detector"] for a in group}
        if len(detectors) < 2:
            continue  # not a correlation, just one detector repeating itself

        group.sort(key=lambda a: a["timestamp"])
        users = [a["entity_user"] for a in group if a.get("entity_user")]
        hosts = sorted({a["entity_host"] for a in group if a.get("entity_host")})
        primary_user = max(set(users), key=users.count) if users else None
        entity_label = primary_user or (hosts[0] if hosts else "unknown")
        if hosts:
            entity_label += f" (hosts: {', '.join(hosts)})"

        severity = max((a["severity"] for a in group), key=lambda s: SEVERITY_RANK.get(s, 0))
        mitre_chain = []
        steps = []
        for i, a in enumerate(group, 1):
            if a["mitre_technique"] not in mitre_chain:
                mitre_chain.append(a["mitre_technique"])
            steps.append(f"({i}) [{a['mitre_tactic']}] {a['title']} [{a['mitre_technique']}]")

        narrative = (
            f"Correlated attack chain spanning {len(group)} alerts across {len(detectors)} "
            f"detection modules, tied together by {entity_label}, from {group[0]['timestamp']} "
            f"to {group[-1]['timestamp']}:\n" + "\n".join(steps)
        )

        incident = Incident(
            title=f"Multi-stage attack chain involving {entity_label}",
            narrative=narrative,
            severity=severity,
            entity=entity_label,
            alert_ids=[a["id"] for a in group],
            mitre_chain=mitre_chain,
            timestamp=group[-1]["timestamp"],
        )
        incidents.append(incident)

    incidents.sort(key=lambda i: SEVERITY_RANK.get(i.severity, 0), reverse=True)
    return incidents

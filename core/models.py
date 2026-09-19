"""Common data structures shared by every detector, the correlation engine,
and the reporting layer. Keeping one Alert schema is what lets 10 independent
detectors feed a single database and a single report.
"""
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Optional
import hashlib
import uuid


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _stable_id(*parts) -> str:
    """A deterministic id derived from an alert's identifying fields.

    This is what lets alert history survive across pipeline runs: two scans
    that both see the SAME underlying event (same detector/entity/title/
    timestamp) produce the same id, so re-inserting it just overwrites
    itself instead of piling up as a duplicate row - and a genuinely new
    event (different timestamp/content) gets a new id and is added, not
    dropped. This is what makes it safe to stop wiping the alerts table on
    every run (see core/pipeline.py).
    """
    raw = "|".join(str(p) for p in parts)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]


@dataclass
class Alert:
    detector: str                     # e.g. "brute_force"
    severity: str                     # low | medium | high | critical
    title: str
    description: str
    mitre_technique: str              # e.g. "T1110"
    mitre_tactic: str                 # e.g. "Credential Access"
    timestamp: str = field(default_factory=now_iso)
    entity_user: Optional[str] = None
    entity_host: Optional[str] = None
    entity_ip: Optional[str] = None
    iocs: list = field(default_factory=list)     # hashes, ips, urls, domains
    raw_event: dict = field(default_factory=dict)
    id: str = ""
    status: str = "new"                # new | acknowledged | resolved | false_positive
    status_note: str = ""
    status_updated_at: Optional[str] = None

    def __post_init__(self):
        if not self.id:
            self.id = _stable_id(self.detector, self.entity_user, self.entity_host,
                                  self.entity_ip, self.title, self.timestamp)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Incident:
    """A correlation-layer finding: multiple alerts stitched into one story."""
    title: str
    narrative: str
    severity: str
    entity: str                       # the user/host that ties the chain together
    alert_ids: list
    mitre_chain: list                 # ordered list of technique IDs
    timestamp: str = field(default_factory=now_iso)
    id: str = field(default_factory=lambda: str(uuid.uuid4()))

    def to_dict(self) -> dict:
        return asdict(self)

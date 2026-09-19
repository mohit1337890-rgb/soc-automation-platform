"""Real Windows Event Log ingestion (replaces the synthetic sysmon.jsonl /
windows_security.jsonl / powershell.jsonl files for a "live" pipeline run).

Uses the modern Windows Eventing API (EvtQuery/EvtNext/EvtRender, exposed by
pywin32 as win32evtlog.Evt*) so both classic channels (Security) and
manifest-based channels (Sysmon, PowerShell operational) are read the same
way, as structured XML with named fields - no legacy positional
StringInserts parsing required.

IMPORTANT: reading the Security channel requires the calling process to run
elevated (Administrator) - regular users cannot read it even if they are a
local admin account, unless the process itself was launched "Run as
Administrator". Sysmon/PowerShell-Operational channels do NOT require
elevation. Every function here degrades gracefully: a missing channel or an
access-denied error is returned as a `warning` string instead of raising, so
one missing log source never kills the whole pipeline run.
"""
import re
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

try:
    import win32evtlog
    import win32security
    import pywintypes
    PYWIN32_AVAILABLE = True
except ImportError:
    PYWIN32_AVAILABLE = False

NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
_SID_CACHE: dict[str, str] = {}


def _resolve_sid(sid_str: str) -> str:
    """4104 PowerShell events carry the user only as a SID (System/Security/
    @UserID), not a named field - resolve it to a plain username so it can
    still be linked to other alerts (e.g. brute_force on the same account)
    by the correlation engine.
    """
    if not sid_str:
        return "unknown"
    if sid_str in _SID_CACHE:
        return _SID_CACHE[sid_str]
    try:
        sid = win32security.ConvertStringSidToSid(sid_str)
        name, _domain, _type = win32security.LookupAccountSid(None, sid)
        _SID_CACHE[sid_str] = name
        return name
    except pywintypes.error:
        _SID_CACHE[sid_str] = sid_str
        return sid_str

SECURITY_EVENT_IDS = [4625, 4624, 4698, 5140]
SYSMON_EVENT_IDS = [1, 10, 11, 13]
POWERSHELL_EVENT_IDS = [4104]


def _xpath_query(event_ids: list[int], lookback_hours: int) -> str:
    id_clause = " or ".join(f"EventID={eid}" for eid in event_ids)
    ms = int(lookback_hours * 3600 * 1000)
    return f"*[System[({id_clause}) and TimeCreated[timediff(@SystemTime) <= {ms}]]]"


def _query_channel(channel: str, event_ids: list[int], lookback_hours: int, max_events: int = 2000):
    """Returns (list_of_xml_strings, warning_or_none)."""
    if not PYWIN32_AVAILABLE:
        return [], "pywin32 is not installed - run: pip install pywin32"

    query = _xpath_query(event_ids, lookback_hours)
    try:
        handle = win32evtlog.EvtQuery(
            channel, win32evtlog.EvtQueryChannelPath | win32evtlog.EvtQueryReverseDirection, query
        )
    except pywintypes.error as e:
        if e.winerror == 5:
            return [], (f"Access denied reading '{channel}'. Re-launch the dashboard/CLI "
                         f"from an elevated (Administrator) terminal to read this channel.")
        if e.winerror in (15007, 2):
            return [], f"Channel '{channel}' was not found on this machine (is it installed/enabled?)."
        return [], f"Could not open '{channel}': {e}"

    xml_events = []
    while len(xml_events) < max_events:
        try:
            batch = win32evtlog.EvtNext(handle, 100)
        except pywintypes.error:
            break
        if not batch:
            break
        for h in batch:
            try:
                xml_events.append(win32evtlog.EvtRender(h, win32evtlog.EvtRenderEventXml))
            except pywintypes.error:
                continue
    return xml_events, None


def _parse_event(xml_str: str) -> dict:
    root = ET.fromstring(xml_str)
    system = root.find("e:System", NS)
    event_id = int(system.find("e:EventID", NS).text)
    computer = system.find("e:Computer", NS).text
    time_created = system.find("e:TimeCreated", NS).get("SystemTime")
    ts = datetime.fromisoformat(time_created.replace("Z", "+00:00")).astimezone(timezone.utc).isoformat()

    fields = {}
    event_data = root.find("e:EventData", NS)
    if event_data is not None:
        for data in event_data.findall("e:Data", NS):
            name = data.get("Name")
            if name:
                fields[name] = (data.text or "").strip()

    security = system.find("e:Security", NS)
    user_sid = security.get("UserID") if security is not None else None

    return {"event_id": event_id, "host": computer, "timestamp": ts, "fields": fields, "user_sid": user_sid}


def _short_user(raw: str) -> str:
    """Sysmon's User field is DOMAIN\\user - keep just the username part."""
    if not raw:
        return raw
    return raw.split("\\")[-1]


def _map_security_event(e: dict) -> dict | None:
    f, eid = e["fields"], e["event_id"]
    base = {"source": "windows_security", "timestamp": e["timestamp"], "event_id": eid, "host": e["host"]}
    if eid in (4625, 4624):
        base.update({
            "user": f.get("TargetUserName"), "src_ip": f.get("IpAddress"),
            "logon_type": f.get("LogonType"), "failure_reason": f.get("FailureReason") or f.get("Status"),
        })
        return base
    if eid == 4698:
        task_content = f.get("TaskContent", "")
        cmd_match = re.search(r"<Command>(.*?)</Command>", task_content)
        args_match = re.search(r"<Arguments>(.*?)</Arguments>", task_content)
        action = f"{cmd_match.group(1) if cmd_match else ''} {args_match.group(1) if args_match else ''}".strip()
        base.update({
            "user": f.get("SubjectUserName"), "task_name": f.get("TaskName"),
            "task_action": action or task_content[:300],
        })
        return base
    if eid == 5140:
        base.update({
            "user": f.get("SubjectUserName"), "src_ip": f.get("IpAddress"),
            "share_name": f.get("ShareName"),
        })
        return base
    return None


def _map_sysmon_event(e: dict) -> dict | None:
    f, eid = e["fields"], e["event_id"]
    base = {"source": "sysmon", "timestamp": e["timestamp"], "event_id": eid, "host": e["host"]}
    if eid == 1:
        base.update({
            "user": _short_user(f.get("User")), "image": f.get("Image"),
            "command_line": f.get("CommandLine"), "hashes": f.get("Hashes", ""),
            "parent_image": f.get("ParentImage"),
        })
        return base
    if eid == 10:
        base.update({
            "user": _short_user(f.get("User") or f.get("SourceUser")),
            "source_image": f.get("SourceImage"), "target_image": f.get("TargetImage"),
            "granted_access": f.get("GrantedAccess", "").lower(),
        })
        return base
    if eid == 11:
        base.update({"user": _short_user(f.get("User")), "target_filename": f.get("TargetFilename")})
        return base
    if eid == 13:
        base.update({
            "user": _short_user(f.get("User")), "target_object": f.get("TargetObject"),
            "details": f.get("Details"),
        })
        return base
    return None


def _map_powershell_event(e: dict) -> dict | None:
    f = e["fields"]
    return {
        "source": "powershell", "timestamp": e["timestamp"], "event_id": e["event_id"],
        "host": e["host"], "user": _resolve_sid(e.get("user_sid")),
        "script_block": f.get("ScriptBlockText", ""),
    }


def read_live_windows_events(lookback_hours: int = 24) -> dict:
    """Returns {"windows_security": [...], "sysmon": [...], "powershell": [...],
    "warnings": [...]} using the exact same event schema the detectors expect
    from the synthetic sample data.
    """
    result = {"windows_security": [], "sysmon": [], "powershell": [], "warnings": []}

    sources = [
        ("Security", SECURITY_EVENT_IDS, _map_security_event, "windows_security"),
        ("Microsoft-Windows-Sysmon/Operational", SYSMON_EVENT_IDS, _map_sysmon_event, "sysmon"),
        ("Microsoft-Windows-PowerShell/Operational", POWERSHELL_EVENT_IDS, _map_powershell_event, "powershell"),
    ]

    for channel, event_ids, mapper, out_key in sources:
        xml_events, warning = _query_channel(channel, event_ids, lookback_hours)
        if warning:
            result["warnings"].append(f"[{channel}] {warning}")
            continue
        for xml_str in xml_events:
            try:
                parsed = _parse_event(xml_str)
                mapped = mapper(parsed)
                if mapped:
                    result[out_key].append(mapped)
            except (ET.ParseError, AttributeError, ValueError):
                continue

    return result

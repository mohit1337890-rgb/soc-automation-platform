"""Loads normalized JSONL events off disk into per-source lists in memory.

This is the seam where real collectors plug in later: as long as a real
win32evtlog/IMAP/Azure-AD collector emits the same JSON shape as
sample_data_generator.py, every detector below keeps working unchanged.
"""
import json
import os


def _read_jsonl(path: str) -> list[dict]:
    if not os.path.exists(path):
        return []
    events = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                events.append(json.loads(line))
    return events


def load_events(sample_data_dir: str) -> dict:
    """Returns {"emails": [...], "windows_security": [...], "sysmon": [...],
    "powershell": [...], "cloud_auth": [...]}"""
    return {
        "emails": _read_jsonl(os.path.join(sample_data_dir, "emails.jsonl")),
        "windows_security": _read_jsonl(os.path.join(sample_data_dir, "windows_security.jsonl")),
        "sysmon": _read_jsonl(os.path.join(sample_data_dir, "sysmon.jsonl")),
        "powershell": _read_jsonl(os.path.join(sample_data_dir, "powershell.jsonl")),
        "cloud_auth": _read_jsonl(os.path.join(sample_data_dir, "cloud_auth.jsonl")),
    }

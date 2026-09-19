"""Item 1: Phishing Email Detection.

Logic: an email is suspicious if authentication fails (SPF/DKIM/DMARC)
AND it carries a risky payload (executable-type attachment, a URL on a
shortener/suspicious TLD, or a mismatched sender domain). Either signal
alone is common and noisy; requiring both cuts false positives sharply.
"""
from core.models import Alert
from core.mitre_mapper import get_mitre


def _url_is_suspicious(url: str, cfg: dict) -> bool:
    url_l = url.lower()
    if any(short in url_l for short in cfg["url_shorteners"]):
        return True
    if any(url_l.split("?")[0].endswith(tld) or tld in url_l for tld in cfg["suspicious_tlds"]):
        return True
    return False


def _attachment_is_suspicious(name: str, cfg: dict) -> bool:
    name_l = name.lower()
    return any(name_l.endswith(ext) for ext in cfg["suspicious_attachment_ext"])


def run(events: dict, config: dict, db) -> list[Alert]:
    cfg = config["phishing"]
    alerts = []
    mitre = get_mitre("phishing_detector")

    for email in events.get("emails", []):
        auth_failed = email.get("spf") == "fail" or email.get("dkim") == "fail" or email.get("dmarc") == "fail"
        if not auth_failed:
            continue

        risky_urls = [u for u in email.get("urls", []) if _url_is_suspicious(u, cfg)]
        risky_attachments = [a for a in email.get("attachments", []) if _attachment_is_suspicious(a, cfg)]

        if not risky_urls and not risky_attachments:
            continue

        severity = "high" if risky_attachments else "medium"
        reasons = []
        if auth_failed:
            reasons.append("SPF/DKIM/DMARC authentication failed")
        if risky_urls:
            reasons.append(f"suspicious URL(s): {', '.join(risky_urls)}")
        if risky_attachments:
            reasons.append(f"risky attachment(s): {', '.join(risky_attachments)}")

        alert = Alert(
            detector="phishing_detector",
            severity=severity,
            title=f"Phishing email delivered to {email.get('to')}",
            description=(
                f"Email from '{email.get('from')}' failed authentication checks and "
                f"contains risky content: {'; '.join(reasons)}."
            ),
            mitre_technique=mitre["technique"],
            mitre_tactic=mitre["tactic"],
            timestamp=email.get("timestamp"),
            entity_user=email.get("to", "").split("@")[0],
            iocs=risky_urls + risky_attachments + [email.get("from", "")],
            raw_event=email,
        )
        alerts.append(alert)
        db.insert_alert(alert)

    return alerts

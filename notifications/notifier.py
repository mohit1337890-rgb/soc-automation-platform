"""Pushes a notification the moment a new critical/high alert appears,
instead of leaving it sitting silently in the dashboard until someone
happens to open it. Two channels, both optional and configured per-tenant
via the dashboard's Settings panel:

  - Slack, via an Incoming Webhook URL (no OAuth app needed).
  - Email, via the same Gmail/Outlook account already configured for
    live phishing scanning (SMTP instead of IMAP).

Both fail soft: a notification failure is reported as a pipeline warning,
never an exception that could take down the run.
"""
import smtplib
from email.mime.text import MIMEText
import requests

SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}
SMTP_SERVERS = {"gmail": ("smtp.gmail.com", 587), "outlook": ("smtp.office365.com", 587)}


def send_slack(webhook_url: str, text: str) -> tuple[bool, str | None]:
    try:
        resp = requests.post(webhook_url, json={"text": text}, timeout=10)
        if resp.status_code == 200:
            return True, None
        return False, f"Slack returned HTTP {resp.status_code}"
    except requests.RequestException as e:
        return False, str(e)


def send_email(email_address: str, app_password: str, provider: str,
               to_address: str, subject: str, body: str) -> tuple[bool, str | None]:
    if provider not in SMTP_SERVERS:
        return False, "Email notifications currently only support Gmail/Outlook - use Slack for a custom provider."
    server, port = SMTP_SERVERS[provider]
    try:
        msg = MIMEText(body)
        msg["Subject"] = subject
        msg["From"] = email_address
        msg["To"] = to_address
        with smtplib.SMTP(server, port, timeout=15) as conn:
            conn.starttls()
            conn.login(email_address, app_password)
            conn.sendmail(email_address, [to_address], msg.as_string())
        return True, None
    except (smtplib.SMTPException, OSError) as e:
        return False, str(e)


def notify_new_alerts(settings: dict, new_alerts: list[dict], tenant_name: str) -> list[str]:
    """Sends Slack/email notifications for newly-appeared alerts at or above
    the configured minimum severity. Returns a list of warning strings for
    anything that failed to send (empty list if nothing to notify or
    everything succeeded).
    """
    warnings = []
    if not new_alerts:
        return warnings

    min_severity = settings.get("notify_min_severity", "critical")
    threshold = SEVERITY_RANK.get(min_severity, 3)
    to_notify = [a for a in new_alerts if SEVERITY_RANK.get(a.get("severity", "low"), 0) >= threshold]
    if not to_notify:
        return warnings

    to_notify.sort(key=lambda a: SEVERITY_RANK.get(a.get("severity", "low"), 0), reverse=True)
    lines = [f"[{a['severity'].upper()}] {a['title']}" for a in to_notify[:20]]
    text = (
        f"SOC Automation - {tenant_name}: {len(to_notify)} new alert(s) at/above "
        f"'{min_severity}' severity\n" + "\n".join(lines)
    )
    if len(to_notify) > 20:
        text += f"\n... and {len(to_notify) - 20} more"

    webhook = settings.get("slack_webhook_url", "")
    if webhook:
        ok, err = send_slack(webhook, text)
        if not ok:
            warnings.append(f"Slack notification failed: {err}")

    if settings.get("notify_email_enabled") == "true":
        email_address = settings.get("email_address", "")
        app_password = settings.get("email_app_password", "")
        provider = settings.get("email_provider", "gmail")
        to_address = settings.get("notify_email_to") or email_address
        if email_address and app_password:
            ok, err = send_email(email_address, app_password, provider, to_address,
                                  f"SOC Alert - {tenant_name}: {len(to_notify)} new finding(s)", text)
            if not ok:
                warnings.append(f"Email notification failed: {err}")
        else:
            warnings.append("Email notifications enabled but email address/app password not configured.")

    return warnings

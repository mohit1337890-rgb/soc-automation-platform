"""Real email ingestion via IMAP (replaces the synthetic emails.jsonl for a
"live" pipeline run). Works with Gmail and Outlook/Microsoft 365 personal
mailboxes using an **App Password**, not the account's real password.

Gmail app password: Google Account -> Security -> 2-Step Verification (must
be ON) -> App passwords -> generate one for "Mail".
Outlook.com app password: account.live.com/proofs/AppPassword (also
requires 2-step verification to be enabled).

Credentials are read from the tenant's Settings (dashboard) or, for
CLI/Docker use, from EMAIL_ADDRESS / EMAIL_APP_PASSWORD environment
variables. Nothing is ever logged or written back out except the derived
alert fields (from/to/subject/urls/attachment names) - message bodies are
parsed in memory only, never persisted.
"""
import email
import imaplib
import re
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime

IMAP_SERVERS = {
    "gmail": "imap.gmail.com",
    "outlook": "outlook.office365.com",
}

URL_RE = re.compile(r'https?://[^\s"\'<>\)\]]+')


def _auth_result(headers_value: str, mechanism: str) -> str:
    m = re.search(rf"{mechanism}=(\w+)", headers_value or "", re.IGNORECASE)
    return m.group(1).lower() if m else "none"


def _extract_urls(msg) -> list[str]:
    urls = set()
    for part in msg.walk():
        content_type = part.get_content_type()
        if content_type in ("text/plain", "text/html"):
            try:
                payload = part.get_payload(decode=True)
                if payload:
                    text = payload.decode(part.get_content_charset() or "utf-8", errors="ignore")
                    urls.update(URL_RE.findall(text))
            except (LookupError, ValueError):
                continue
    return sorted(urls)[:20]


def _extract_attachments(msg) -> list[str]:
    names = []
    for part in msg.walk():
        disposition = str(part.get("Content-Disposition", ""))
        if "attachment" in disposition.lower():
            filename = part.get_filename()
            if filename:
                names.append(filename)
    return names


def read_live_inbox(email_address: str, app_password: str, provider: str = "gmail",
                     custom_server: str = "", lookback_days: int = 3,
                     max_messages: int = 100) -> dict:
    """Returns {"emails": [...], "warnings": [...]}"""
    result = {"emails": [], "warnings": []}

    if not email_address or not app_password:
        result["warnings"].append("Email address / app password not configured - skipping live email ingestion.")
        return result

    server = custom_server.strip() or IMAP_SERVERS.get(provider, IMAP_SERVERS["gmail"])

    try:
        conn = imaplib.IMAP4_SSL(server, 993, timeout=20)
        conn.login(email_address, app_password)
        conn.select("INBOX")
    except imaplib.IMAP4.error as e:
        result["warnings"].append(f"IMAP login failed for {email_address} on {server}: {e}")
        return result
    except OSError as e:
        result["warnings"].append(f"Could not connect to {server}: {e}")
        return result

    try:
        since = (datetime.now() - timedelta(days=lookback_days)).strftime("%d-%b-%Y")
        status, data = conn.search(None, f'(SINCE "{since}")')
        if status != "OK":
            result["warnings"].append("IMAP search returned no results.")
            return result

        message_ids = data[0].split()[-max_messages:]
        for msg_id in message_ids:
            status, msg_data = conn.fetch(msg_id, "(RFC822)")
            if status != "OK" or not msg_data or not msg_data[0]:
                continue
            raw = msg_data[0][1]
            msg = email.message_from_bytes(raw)

            auth_header = msg.get("Authentication-Results", "")
            try:
                ts = parsedate_to_datetime(msg.get("Date")).astimezone(timezone.utc).isoformat()
            except (TypeError, ValueError):
                ts = datetime.now(timezone.utc).isoformat()

            result["emails"].append({
                "source": "email",
                "timestamp": ts,
                "from": msg.get("From", ""),
                "to": msg.get("To", email_address),
                "subject": msg.get("Subject", ""),
                "spf": _auth_result(auth_header, "spf"),
                "dkim": _auth_result(auth_header, "dkim"),
                "dmarc": _auth_result(auth_header, "dmarc"),
                "urls": _extract_urls(msg),
                "attachments": _extract_attachments(msg),
            })
    finally:
        try:
            conn.close()
            conn.logout()
        except imaplib.IMAP4.error:
            pass

    return result

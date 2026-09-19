"""Real cloud/AD sign-in log ingestion - Azure AD (Microsoft Entra ID),
Okta, and Google Workspace. Every provider is mapped into the exact same
`cloud_auth` event shape the synthetic sample data already uses:

    {"source": "cloud_auth", "timestamp", "user", "src_ip",
     "city", "country", "lat", "lon", "app"}

...which is why `detectors/impossible_travel.py` needs ZERO changes to work
against real sign-in logs from any of these providers - it already just
reads `events["cloud_auth"]`.

None of these providers hand back a ready-to-use city/lat/lon for an IP, so
every sign-in's source IP is resolved via `ingestion/geoip_lookup.py`
(IPinfo) - the same helper the live Windows remote-logon path uses. A
sign-in whose IP can't be resolved (private/internal IP, no IPinfo key
configured, or an API error) is skipped rather than passed through with
missing fields.

Setup for each provider is genuinely different - see README's
"Real cloud/AD sign-in logs" section for exact steps.
"""
from datetime import datetime, timedelta, timezone
import requests
from ingestion.geoip_lookup import resolve_ip, is_private_ip


def _since_iso(lookback_hours: int) -> str:
    return (datetime.now(timezone.utc) - timedelta(hours=lookback_hours)).strftime("%Y-%m-%dT%H:%M:%SZ")


def _to_cloud_auth_event(user: str, ip: str, timestamp: str, app: str, ipinfo_key: str) -> dict | None:
    if not user or is_private_ip(ip):
        return None
    geo = resolve_ip(ip, ipinfo_key)
    if not geo:
        return None
    return {
        "source": "cloud_auth", "timestamp": timestamp, "user": user, "src_ip": ip,
        "city": geo["city"], "country": geo["country"], "lat": geo["lat"], "lon": geo["lon"], "app": app,
    }


# ---------------------------------------------------------------------
# Azure AD / Microsoft Entra ID - Microsoft Graph API
#
# Setup: Azure Portal -> Microsoft Entra ID -> App registrations -> New
# registration -> note the Application (client) ID and Directory (tenant)
# ID -> Certificates & secrets -> new client secret -> API permissions ->
# add "AuditLog.Read.All" (Application permission) -> Grant admin consent.
#
# IMPORTANT: reading /auditLogs/signIns requires an Azure AD Premium P1 or
# P2 license on the tenant - this is a Microsoft licensing requirement, not
# something this code can work around. Without it, Graph returns a 403.
# ---------------------------------------------------------------------
def read_azure_ad_signins(tenant_id: str, client_id: str, client_secret: str,
                           lookback_hours: int, ipinfo_key: str) -> tuple[list[dict], list[str]]:
    if not (tenant_id and client_id and client_secret):
        return [], ["[Azure AD] tenant_id/client_id/client_secret not configured - skipping."]

    token_url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
    try:
        token_resp = requests.post(token_url, data={
            "client_id": client_id, "client_secret": client_secret,
            "scope": "https://graph.microsoft.com/.default", "grant_type": "client_credentials",
        }, timeout=15)
        if token_resp.status_code != 200:
            return [], [f"[Azure AD] auth failed: HTTP {token_resp.status_code} - {token_resp.text[:200]}"]
        access_token = token_resp.json()["access_token"]
    except (requests.RequestException, KeyError) as e:
        return [], [f"[Azure AD] auth request failed: {e}"]

    since = _since_iso(lookback_hours)
    url = "https://graph.microsoft.com/v1.0/auditLogs/signIns"
    params = {"$filter": f"createdDateTime ge {since}", "$top": "500"}
    headers = {"Authorization": f"Bearer {access_token}"}

    events, warnings = [], []
    try:
        while url:
            resp = requests.get(url, params=params, headers=headers, timeout=20)
            if resp.status_code == 403:
                return [], ["[Azure AD] HTTP 403 - most likely this tenant lacks Azure AD Premium P1/P2 "
                            "(required by Microsoft for the sign-ins API), or AuditLog.Read.All wasn't "
                            "granted admin consent."]
            if resp.status_code != 200:
                warnings.append(f"[Azure AD] HTTP {resp.status_code}: {resp.text[:200]}")
                break
            data = resp.json()
            for item in data.get("value", []):
                if item.get("status", {}).get("errorCode", 1) != 0:
                    continue  # only successful sign-ins are meaningful for impossible travel
                event = _to_cloud_auth_event(
                    user=item.get("userPrincipalName"), ip=item.get("ipAddress"),
                    timestamp=item.get("createdDateTime"), app=item.get("appDisplayName", "Azure AD"),
                    ipinfo_key=ipinfo_key,
                )
                if event:
                    events.append(event)
            url = data.get("@odata.nextLink")
            params = None  # nextLink already includes query params
    except requests.RequestException as e:
        warnings.append(f"[Azure AD] request failed: {e}")

    if not ipinfo_key:
        warnings.append("[Azure AD] IPinfo API key not configured - sign-ins were fetched but none could "
                         "be geo-resolved, so impossible_travel will not fire on them.")
    return events, warnings


# ---------------------------------------------------------------------
# Okta - System Log API
#
# Setup: sign up for a free developer org at developer.okta.com -> Security
# -> API -> Tokens -> Create Token. okta_domain is your org's base URL,
# e.g. "dev-12345678.okta.com" (no https://).
# ---------------------------------------------------------------------
def read_okta_signins(okta_domain: str, api_token: str,
                       lookback_hours: int, ipinfo_key: str) -> tuple[list[dict], list[str]]:
    if not (okta_domain and api_token):
        return [], ["[Okta] okta_domain/api_token not configured - skipping."]

    domain = okta_domain.replace("https://", "").rstrip("/")
    since = _since_iso(lookback_hours)
    url = f"https://{domain}/api/v1/logs"
    params = {"since": since, "filter": 'eventType eq "user.session.start"'}
    headers = {"Authorization": f"SSWS {api_token}", "Accept": "application/json"}

    events, warnings = [], []
    try:
        while url:
            resp = requests.get(url, params=params, headers=headers, timeout=20)
            if resp.status_code == 401:
                return [], ["[Okta] HTTP 401 - invalid or expired API token."]
            if resp.status_code != 200:
                warnings.append(f"[Okta] HTTP {resp.status_code}: {resp.text[:200]}")
                break
            for item in resp.json():
                if item.get("outcome", {}).get("result") != "SUCCESS":
                    continue
                actor = item.get("actor", {})
                client = item.get("client", {})
                event = _to_cloud_auth_event(
                    user=actor.get("alternateId"), ip=client.get("ipAddress"),
                    timestamp=item.get("published"), app="Okta",
                    ipinfo_key=ipinfo_key,
                )
                if event:
                    events.append(event)
            # Okta paginates via a Link header, not a body field
            next_url = resp.links.get("next", {}).get("url")
            url, params = next_url, None
    except requests.RequestException as e:
        warnings.append(f"[Okta] request failed: {e}")

    if not ipinfo_key:
        warnings.append("[Okta] IPinfo API key not configured - sign-ins were fetched but none could "
                         "be geo-resolved, so impossible_travel will not fire on them.")
    return events, warnings


# ---------------------------------------------------------------------
# Google Workspace - Admin SDK Reports API
#
# Setup: Google Cloud Console -> create/select a project -> enable "Admin
# SDK API" -> IAM & Admin -> Service Accounts -> create one -> Keys -> Add
# key (JSON) -> download it. Then, in Google Workspace Admin console ->
# Security -> API controls -> Domain-wide delegation -> add the service
# account's Client ID with scope:
#   https://www.googleapis.com/auth/admin.reports.audit.readonly
# Only a Workspace (business) domain has this - a personal @gmail.com
# account cannot be the target of this integration, only the admin who
# authorizes access to read the *organization's* sign-in log.
# ---------------------------------------------------------------------
SCOPES = ["https://www.googleapis.com/auth/admin.reports.audit.readonly"]


def read_google_workspace_signins(service_account_json: dict, delegated_admin_email: str,
                                   lookback_hours: int, ipinfo_key: str) -> tuple[list[dict], list[str]]:
    if not (service_account_json and delegated_admin_email):
        return [], ["[Google Workspace] service account JSON / delegated admin email not configured - skipping."]

    try:
        from google.oauth2 import service_account
        from google.auth.transport.requests import AuthorizedSession
    except ImportError:
        return [], ["[Google Workspace] the 'google-auth' package isn't installed - "
                     "run: pip install google-auth"]

    try:
        creds = service_account.Credentials.from_service_account_info(
            service_account_json, scopes=SCOPES, subject=delegated_admin_email
        )
        session = AuthorizedSession(creds)
    except (ValueError, KeyError) as e:
        return [], [f"[Google Workspace] invalid service account JSON: {e}"]

    since = _since_iso(lookback_hours)
    url = "https://admin.googleapis.com/admin/reports/v1/activity/users/all/applications/login"
    params = {"startTime": since, "eventName": "login_success", "maxResults": "500"}

    events, warnings = [], []
    try:
        while url:
            resp = session.get(url, params=params, timeout=20)
            if resp.status_code == 403:
                return [], ["[Google Workspace] HTTP 403 - check domain-wide delegation is authorized "
                             "for this scope and the delegated admin email is correct."]
            if resp.status_code != 200:
                warnings.append(f"[Google Workspace] HTTP {resp.status_code}: {resp.text[:200]}")
                break
            data = resp.json()
            for item in data.get("items", []):
                actor_email = item.get("actor", {}).get("email")
                ip = item.get("ipAddress")
                timestamp = item.get("id", {}).get("time")
                event = _to_cloud_auth_event(actor_email, ip, timestamp, "Google Workspace", ipinfo_key)
                if event:
                    events.append(event)
            next_token = data.get("nextPageToken")
            if next_token:
                params = {"startTime": since, "eventName": "login_success", "maxResults": "500",
                          "pageToken": next_token}
            else:
                url = None
    except requests.RequestException as e:
        warnings.append(f"[Google Workspace] request failed: {e}")

    if not ipinfo_key:
        warnings.append("[Google Workspace] IPinfo API key not configured - sign-ins were fetched but "
                         "none could be geo-resolved, so impossible_travel will not fire on them.")
    return events, warnings


def read_live_cloud_auth(settings: dict, lookback_hours: int = 24) -> tuple[list[dict], list[str]]:
    """Dispatches to whichever provider is configured in this tenant's
    Settings (cloud_provider: "azure_ad" | "okta" | "google_workspace" | "").
    """
    provider = settings.get("cloud_provider", "")
    ipinfo_key = settings.get("ipinfo_api_key", "")

    if provider == "azure_ad":
        return read_azure_ad_signins(
            settings.get("azure_tenant_id", ""), settings.get("azure_client_id", ""),
            settings.get("azure_client_secret", ""), lookback_hours, ipinfo_key,
        )
    if provider == "okta":
        return read_okta_signins(
            settings.get("okta_domain", ""), settings.get("okta_api_token", ""), lookback_hours, ipinfo_key,
        )
    if provider == "google_workspace":
        raw_json = settings.get("google_service_account_json", "")
        if not raw_json:
            return [], ["[Google Workspace] service account JSON not uploaded - skipping."]
        import json
        try:
            parsed = json.loads(raw_json)
        except ValueError:
            return [], ["[Google Workspace] stored service account JSON is invalid - re-upload it in Settings."]
        return read_google_workspace_signins(
            parsed, settings.get("google_delegated_admin", ""), lookback_hours, ipinfo_key,
        )

    return [], []   # no cloud provider configured - not an error, just nothing to do

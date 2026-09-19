"""SOC Automation - Multi-Tenant Web Dashboard.

Run with: streamlit run dashboard/app.py

This is the "product" a client actually uses day to day: sign in as your
organization, see your alerts/incidents/reports, optionally trigger a new
detection run. Every read in this file is scoped to the signed-in tenant's
own SQLite file (core/tenants.py) - there is no code path that can load
another tenant's data into this session.

NOTE on auth: tenant selection + access code below is a *demo-grade* gate,
not enterprise authentication. For real multi-client production use,
replace this with Streamlit's native st.login()/OIDC (see
https://docs.streamlit.io/develop/api-reference/user/st.login) backed by
your identity provider, and use the authenticated user's org claim to pick
the tenant instead of a shared code.
"""
import os
import sys
import glob

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import altair as alt
import pandas as pd
import streamlit as st

from core.database import SOCDatabase
from core.tenants import TenantRegistry, tenant_paths
from core.pipeline import run_pipeline

SEVERITY_ORDER = ["critical", "high", "medium", "low"]
SEVERITY_COLOR = {
    "critical": "#ff4d5e",
    "high": "#ff9f45",
    "medium": "#ffd23f",
    "low": "#4fd1a5",
}

st.set_page_config(page_title="SOC Automation Dashboard", page_icon=":material/shield:", layout="wide")


# --------------------------------------------------------------------------
# Authentication (tenant gate)
# --------------------------------------------------------------------------
def login_screen(registry: TenantRegistry):
    st.title("SOC Automation Dashboard")
    st.caption("Sign in to view your organization's security findings.")
    with st.container(border=True, width="content"):
        tenants = registry.list_tenants()
        tenant_choice = st.selectbox("Organization", options=[t.id for t in tenants],
                                      format_func=lambda tid: registry.get(tid).name)
        access_code = st.text_input("Access code", type="password",
                                     help="Leave blank if your organization has no code configured.")
        if st.button("Sign in", type="primary"):
            if registry.verify(tenant_choice, access_code):
                st.session_state["tenant_id"] = tenant_choice
                st.rerun()
            else:
                st.error("Invalid access code for this organization.")


# --------------------------------------------------------------------------
# Data loading (always scoped to the signed-in tenant)
# --------------------------------------------------------------------------
def load_tenant_data(tenant_id: str):
    paths = tenant_paths(tenant_id)
    if not os.path.exists(paths["database_file"]):
        return None, None, paths
    db = SOCDatabase(paths["database_file"])
    alerts = db.get_all_alerts()
    incidents = db.get_all_incidents()
    db.close()
    return alerts, incidents, paths


def severity_sort_key(sev: str) -> int:
    return SEVERITY_ORDER.index(sev) if sev in SEVERITY_ORDER else len(SEVERITY_ORDER)


# --------------------------------------------------------------------------
# Settings (per-tenant API keys + email credentials, entered from the UI -
# no config file editing required). Stored in this tenant's own isolated
# SQLite database (see core/database.py's settings table).
# --------------------------------------------------------------------------
def settings_panel(tenant_id: str):
    db = SOCDatabase(tenant_paths(tenant_id)["database_file"])
    current = db.get_settings()

    st.caption("Saved locally in this organization's own database. Not an encrypted "
               "vault - for real production, prefer environment variables or a secrets manager.")

    st.markdown("**Threat intelligence & AI**")
    vt_key = st.text_input("VirusTotal API key", value=current.get("vt_api_key", ""), type="password",
                            help="Optional. Without it, only the offline blocklist in config.yaml is used.")
    anthropic_key = st.text_input("Anthropic (Claude) API key", value=current.get("anthropic_api_key", ""),
                                   type="password",
                                   help="Optional. Without it, the report uses a template-based executive summary.")
    ipinfo_key = st.text_input("IPinfo API key", value=current.get("ipinfo_api_key", ""), type="password",
                                help="Optional. Real GeoIP for impossible-travel - needed for both real Windows "
                                     "remote logons and any cloud/AD provider configured below.")

    st.markdown("**Email inbox (for live phishing detection)**")
    provider = st.selectbox("Provider", ["gmail", "outlook", "custom"],
                             index=["gmail", "outlook", "custom"].index(current.get("email_provider", "gmail")))
    custom_server = ""
    if provider == "custom":
        custom_server = st.text_input("IMAP server", value=current.get("email_imap_server", ""))
    email_address = st.text_input("Email address", value=current.get("email_address", ""))
    app_password = st.text_input(
        "App password", value=current.get("email_app_password", ""), type="password",
        help="Use an App Password, never your real account password. Gmail: Google Account -> "
             "Security -> 2-Step Verification -> App passwords. Outlook: account.live.com/proofs/AppPassword."
    )
    lookback_days = st.number_input(
        "Scan emails from the last N days", min_value=1, max_value=30,
        value=max(1, min(30, int(current.get("email_lookback_days", 3) or 3))),
    )

    st.caption("Note: reading real Windows Security event logs also requires launching this "
               "dashboard from an elevated (Administrator) terminal - that's an OS-level "
               "requirement no web setting can grant.")

    st.markdown("**Cloud/AD sign-in logs (for impossible travel)**")
    cloud_options = ["none", "azure_ad", "okta", "google_workspace"]
    cloud_provider = st.selectbox(
        "Provider", cloud_options, index=cloud_options.index(current.get("cloud_provider", "none")),
        format_func=lambda p: {"none": "None", "azure_ad": "Azure AD / Microsoft Entra ID",
                                "okta": "Okta", "google_workspace": "Google Workspace"}[p],
    )
    azure_tenant_id = azure_client_id = azure_client_secret = ""
    okta_domain = okta_api_token = ""
    google_service_account_json = current.get("google_service_account_json", "")
    google_delegated_admin = ""

    if cloud_provider == "azure_ad":
        st.caption("Requires Azure AD Premium P1/P2 on the tenant (Microsoft's requirement for the "
                   "sign-ins API), an app registration with AuditLog.Read.All (admin-consented).")
        azure_tenant_id = st.text_input("Azure Tenant ID", value=current.get("azure_tenant_id", ""))
        azure_client_id = st.text_input("Azure Client (Application) ID", value=current.get("azure_client_id", ""))
        azure_client_secret = st.text_input("Azure Client Secret", value=current.get("azure_client_secret", ""),
                                             type="password")
    elif cloud_provider == "okta":
        st.caption("Free to test: sign up at developer.okta.com -> Security -> API -> Tokens -> Create Token.")
        okta_domain = st.text_input("Okta domain", value=current.get("okta_domain", ""),
                                     placeholder="dev-12345678.okta.com")
        okta_api_token = st.text_input("Okta API token", value=current.get("okta_api_token", ""), type="password")
    elif cloud_provider == "google_workspace":
        st.caption("Requires a Google Workspace (business) domain - a personal @gmail.com account cannot "
                   "be delegated this way. Needs a service account with domain-wide delegation for scope "
                   "admin.reports.audit.readonly (see ingestion/cloud_auth_ingestion.py for exact steps).")
        uploaded = st.file_uploader("Service account JSON key file", type=["json"])
        if uploaded is not None:
            google_service_account_json = uploaded.read().decode("utf-8")
        elif current.get("google_service_account_json"):
            st.caption("A service account JSON is already saved for this organization.")
        google_delegated_admin = st.text_input(
            "Delegated Workspace admin email", value=current.get("google_delegated_admin", ""),
            help="The service account impersonates this admin to read the org's sign-in log."
        )

    st.markdown("**Notifications** — pushed the moment a new alert appears, instead of "
                "waiting for someone to open this dashboard")
    slack_webhook = st.text_input(
        "Slack Incoming Webhook URL", value=current.get("slack_webhook_url", ""), type="password",
        help="Slack -> your workspace -> Apps -> Incoming Webhooks -> Add to Slack -> copy the URL."
    )
    notify_email_enabled = st.checkbox("Also notify by email", value=current.get("notify_email_enabled") == "true")
    notify_email_to = ""
    if notify_email_enabled:
        notify_email_to = st.text_input(
            "Send notification emails to", value=current.get("notify_email_to", email_address),
            help="Uses the Gmail/Outlook credentials above to send - only Gmail/Outlook are supported for sending."
        )
    notify_min_severity = st.selectbox(
        "Minimum severity to notify on", ["critical", "high", "medium", "low"],
        index=["critical", "high", "medium", "low"].index(current.get("notify_min_severity", "critical")),
    )

    st.markdown("**Scheduling** — run automatically instead of clicking the button every time")
    scheduling_enabled = st.checkbox("Enable scheduled scanning for this organization",
                                      value=current.get("scheduling_enabled") == "true",
                                      help="Requires scheduler.py to be running separately (see README) - "
                                           "this checkbox alone doesn't start a background process.")
    scheduling_interval = st.number_input(
        "Scan every N minutes", min_value=5, max_value=1440,
        value=max(5, min(1440, int(current.get("scheduling_interval_minutes", 30) or 30))),
    )
    scheduling_source = st.selectbox("Scheduled scan source", ["live", "sample"],
                                      index=["live", "sample"].index(current.get("scheduling_source", "live")))

    if st.button("Save settings", type="primary", width="stretch"):
        db.set_settings({
            "vt_api_key": vt_key,
            "anthropic_api_key": anthropic_key,
            "ipinfo_api_key": ipinfo_key,
            "email_provider": provider,
            "email_imap_server": custom_server,
            "email_address": email_address,
            "email_app_password": app_password,
            "email_lookback_days": str(lookback_days),
            "cloud_provider": cloud_provider,
            "azure_tenant_id": azure_tenant_id,
            "azure_client_id": azure_client_id,
            "azure_client_secret": azure_client_secret,
            "okta_domain": okta_domain,
            "okta_api_token": okta_api_token,
            "google_service_account_json": google_service_account_json,
            "google_delegated_admin": google_delegated_admin,
            "slack_webhook_url": slack_webhook,
            "notify_email_enabled": "true" if notify_email_enabled else "false",
            "notify_email_to": notify_email_to,
            "notify_min_severity": notify_min_severity,
            "scheduling_enabled": "true" if scheduling_enabled else "false",
            "scheduling_interval_minutes": str(scheduling_interval),
            "scheduling_source": scheduling_source,
        })
        st.success("Settings saved for this organization.")
    db.close()


# --------------------------------------------------------------------------
# Main dashboard (only reached once signed in)
# --------------------------------------------------------------------------
def dashboard(registry: TenantRegistry, tenant_id: str):
    tenant = registry.get(tenant_id)

    with st.sidebar:
        st.markdown(f"**Signed in as**  \n{tenant.name} (`{tenant.id}`)")
        if st.button("Sign out", width="stretch"):
            del st.session_state["tenant_id"]
            st.rerun()

        st.divider()
        with st.expander("Settings (API keys & email)"):
            settings_panel(tenant_id)

        st.divider()
        st.subheader("Run pipeline")
        source_choice = st.radio("Data source", ["Demo sample data", "Live (real Windows logs + email)"])
        regen = False
        if source_choice == "Demo sample data":
            regen = st.checkbox("Regenerate sample data", value=False,
                                 help="Untick to reuse previously ingested logs for this organization.")
        else:
            st.caption("Uses the Settings above. Security-log access needs an elevated terminal.")
        use_genai = st.checkbox("Use AI-generated executive summary", value=True,
                                 help="Requires an Anthropic API key (Settings above, or ANTHROPIC_API_KEY env var). Falls back automatically if not.")
        if st.button("Run detection pipeline now", type="primary", width="stretch"):
            source_arg = "sample" if source_choice == "Demo sample data" else "live"
            with st.spinner("Ingesting logs, running detectors, correlating, generating report..."):
                result = run_pipeline(tenant_id, generate_sample_data=regen, genai_override=use_genai, source=source_arg)
            st.session_state["last_run_result"] = result
            st.rerun()

    alerts, incidents, paths = load_tenant_data(tenant_id)

    st.title("Security Operations Overview")
    settings_db = SOCDatabase(paths["database_file"])
    last_scan_at = settings_db.get_setting("last_scan_at", "")
    last_scan_source = settings_db.get_setting("last_scan_source", "")
    settings_db.close()
    if last_scan_at:
        st.caption(f"{tenant.name}  ·  Last scan: {last_scan_at} ({last_scan_source})")
    else:
        st.caption(tenant.name)

    if "last_run_result" in st.session_state:
        r = st.session_state.pop("last_run_result")
        st.success(f"Pipeline run complete ({r['source']} source): {r['total_alerts']} alerts, {r['incidents']} incident(s).")
        for w in r.get("warnings", []):
            st.warning(w)

    if not alerts:
        st.info("No data yet for this organization. Click **Run detection pipeline now** in the sidebar to get started.")
        return

    df = pd.DataFrame(alerts)
    df["severity"] = pd.Categorical(df["severity"], categories=SEVERITY_ORDER, ordered=True)

    # ---- KPI row ----
    counts = df["severity"].value_counts()
    with st.container(horizontal=True):
        st.metric("Total alerts", len(df), border=True)
        st.metric("Critical", int(counts.get("critical", 0)), border=True)
        st.metric("High", int(counts.get("high", 0)), border=True)
        st.metric("Medium", int(counts.get("medium", 0)), border=True)
        st.metric("Low", int(counts.get("low", 0)), border=True)
        st.metric("Correlated incidents", len(incidents), border=True)

    tab_overview, tab_incidents, tab_alerts, tab_iocs, tab_reports = st.tabs(
        ["Overview", "Incidents", "Alerts", "IOCs", "Reports"]
    )

    # ---- Overview ----
    with tab_overview:
        col1, col2 = st.columns(2)
        with col1:
            with st.container(border=True):
                st.subheader("Alerts by severity")
                sev_counts_df = df["severity"].value_counts().reindex(SEVERITY_ORDER).fillna(0).reset_index()
                sev_counts_df.columns = ["severity", "count"]
                chart = (
                    alt.Chart(sev_counts_df)
                    .mark_bar(cornerRadius=4)
                    .encode(
                        x=alt.X("severity:N", sort=SEVERITY_ORDER, title="Severity"),
                        y=alt.Y("count:Q", title="Alerts"),
                        color=alt.Color("severity:N",
                                        scale=alt.Scale(domain=SEVERITY_ORDER,
                                                         range=[SEVERITY_COLOR[s] for s in SEVERITY_ORDER]),
                                        legend=None),
                        tooltip=["severity", "count"],
                    )
                )
                st.altair_chart(chart)

        with col2:
            with st.container(border=True):
                st.subheader("Alerts by detector module")
                det_counts = df["detector"].value_counts().reset_index()
                det_counts.columns = ["detector", "count"]
                chart2 = (
                    alt.Chart(det_counts)
                    .mark_bar(cornerRadius=4, color="#5b8cff")
                    .encode(
                        x=alt.X("count:Q", title="Alerts"),
                        y=alt.Y("detector:N", sort="-x", title=""),
                        tooltip=["detector", "count"],
                    )
                )
                st.altair_chart(chart2)

        with st.container(border=True):
            st.subheader("Alert timeline")
            timeline_df = df.copy()
            timeline_df["timestamp"] = pd.to_datetime(timeline_df["timestamp"])
            timeline_chart = (
                alt.Chart(timeline_df)
                .mark_circle(size=90, opacity=0.85)
                .encode(
                    x=alt.X("timestamp:T", title="Time"),
                    y=alt.Y("detector:N", title=""),
                    color=alt.Color("severity:N",
                                    scale=alt.Scale(domain=SEVERITY_ORDER,
                                                     range=[SEVERITY_COLOR[s] for s in SEVERITY_ORDER]),
                                    legend=alt.Legend(title="Severity")),
                    tooltip=["timestamp:T", "detector", "title", "severity"],
                )
            )
            st.altair_chart(timeline_chart)

    # ---- Incidents (correlated attack chains) ----
    with tab_incidents:
        if not incidents:
            st.info("No multi-stage attack chains have been correlated yet.")
        for inc in sorted(incidents, key=lambda i: severity_sort_key(i["severity"])):
            with st.container(border=True):
                badge_color = {"critical": "red", "high": "orange", "medium": "yellow", "low": "green"}.get(inc["severity"], "gray")
                st.markdown(f":{badge_color}-badge[{inc['severity'].upper()}]  **{inc['title']}**")
                st.caption(f"Entity: {inc['entity']}  ·  {len(inc['alert_ids'])} alerts  ·  MITRE chain: {' → '.join(inc['mitre_chain'])}")
                with st.expander("Full narrative"):
                    st.text(inc["narrative"])

    # ---- Alerts (filterable, triage-able table) ----
    with tab_alerts:
        show_closed = st.checkbox("Show resolved / false-positive alerts", value=False)
        with st.container(horizontal=True):
            sev_filter = st.multiselect("Severity", SEVERITY_ORDER, default=SEVERITY_ORDER)
            det_filter = st.multiselect("Detector", sorted(df["detector"].unique()), default=sorted(df["detector"].unique()))

        filtered = df[df["severity"].isin(sev_filter) & df["detector"].isin(det_filter)].copy()
        if not show_closed:
            filtered = filtered[~filtered["status"].isin(["resolved", "false_positive"])]

        st.caption("Edit the Status column to triage alerts, then click Save below.")
        edited = st.data_editor(
            filtered[["id", "timestamp", "severity", "detector", "title", "entity_user",
                      "entity_host", "entity_ip", "mitre_technique", "status"]],
            hide_index=True,
            disabled=["timestamp", "severity", "detector", "title", "entity_user",
                      "entity_host", "entity_ip", "mitre_technique"],
            column_config={
                "id": None,
                "timestamp": st.column_config.DatetimeColumn("Time", format="YYYY-MM-DD HH:mm"),
                "mitre_technique": st.column_config.TextColumn("MITRE"),
                "status": st.column_config.SelectboxColumn(
                    "Status", options=["new", "acknowledged", "resolved", "false_positive"]
                ),
            },
            key="alerts_editor",
        )

        if st.button("Save status changes"):
            original_status = filtered.set_index("id")["status"].to_dict()
            status_db = SOCDatabase(paths["database_file"])
            changed = 0
            for _, row in edited.iterrows():
                if row["status"] != original_status.get(row["id"]):
                    status_db.update_alert_status(row["id"], row["status"])
                    changed += 1
            status_db.close()
            st.success(f"Updated {changed} alert(s).")
            st.rerun()

    # ---- IOCs ----
    with tab_iocs:
        all_iocs = sorted({str(ioc) for a in alerts for ioc in a.get("iocs", []) if ioc})
        st.subheader(f"{len(all_iocs)} indicators of compromise")
        if all_iocs:
            st.dataframe(pd.DataFrame({"indicator": all_iocs}), hide_index=True)
        else:
            st.info("No IOCs extracted yet.")

    # ---- Reports ----
    with tab_reports:
        report_files = sorted(glob.glob(os.path.join(paths["reports_dir"], "*.html")), reverse=True)
        if not report_files:
            st.info("No reports generated yet. Run the pipeline from the sidebar.")
        for rf in report_files:
            with st.container(border=True):
                st.markdown(f"**{os.path.basename(rf)}**")
                with open(rf, "rb") as f:
                    st.download_button("Download report", data=f.read(), file_name=os.path.basename(rf),
                                        mime="text/html", key=rf)


# --------------------------------------------------------------------------
def main():
    registry = TenantRegistry()
    if "tenant_id" not in st.session_state:
        login_screen(registry)
    else:
        dashboard(registry, st.session_state["tenant_id"])


main()

"""GenAI-powered Executive Summary.

This is the "GenAI engineer" piece of Item 10: instead of a purely
templated report, we hand Claude the *structured* findings (counts,
incidents, MITRE techniques, IOCs - never raw logs, to keep the prompt
small and avoid leaking unnecessary data) and ask it to write the kind of
plain-English narrative a CISO/leadership audience actually reads.

Fully optional and fails soft: if ANTHROPIC_API_KEY isn't set, the
Anthropic SDK isn't installed, or the API call fails for any reason
(network, rate limit, bad key), we fall back to a deterministic
template-based summary so report generation NEVER breaks the pipeline.
"""
import os
from collections import Counter

SYSTEM_PROMPT = (
    "You are a senior SOC (Security Operations Center) analyst writing the executive "
    "summary section of an incident report for a non-technical leadership audience "
    "(CISO, CIO, board members). Be concise, factual, and avoid jargon. Only use the "
    "facts given to you - never invent hosts, users, timestamps or numbers. Structure "
    "your answer as:\n"
    "1. A short paragraph (3-5 sentences) summarizing what happened and the business risk.\n"
    "2. A 'Recommended Immediate Actions' section with 3-6 bullet points.\n"
    "Keep the whole answer under 300 words. Do not use markdown headers, plain text and "
    "bullet dashes only."
)


def _build_findings_context(alerts: list[dict], incidents, tenant_name: str) -> str:
    severity_counts = Counter(a["severity"] for a in alerts)
    detector_counts = Counter(a["detector"] for a in alerts)
    mitre_techniques = sorted({a["mitre_technique"] for a in alerts})
    all_iocs = sorted({ioc for a in alerts for ioc in a.get("iocs", []) if ioc})[:25]

    lines = [
        f"Organization: {tenant_name}",
        f"Total alerts: {len(alerts)}",
        f"Alerts by severity: {dict(severity_counts)}",
        f"Alerts by detector module: {dict(detector_counts)}",
        f"MITRE ATT&CK techniques observed: {', '.join(mitre_techniques) if mitre_techniques else 'none'}",
        f"Correlated multi-stage incidents: {len(incidents)}",
    ]
    for i, inc in enumerate(incidents, 1):
        lines.append(f"\nIncident {i} [{inc.severity.upper()}] - {inc.title}:")
        lines.append(inc.narrative)
    if all_iocs:
        lines.append(f"\nKey Indicators of Compromise (IOCs): {', '.join(str(x) for x in all_iocs)}")
    return "\n".join(lines)


def _fallback_summary(alerts: list[dict], incidents, tenant_name: str) -> str:
    severity_counts = Counter(a["severity"] for a in alerts)
    crit = severity_counts.get("critical", 0)
    high = severity_counts.get("high", 0)

    if incidents:
        top = incidents[0]
        headline = (
            f"During this reporting period, {tenant_name}'s environment triggered {len(alerts)} "
            f"security alert(s), including {crit} critical and {high} high severity finding(s). "
            f"The correlation engine identified {len(incidents)} multi-stage attack incident(s), "
            f"the most severe being: {top.title}. This chain involved {len(top.mitre_chain)} distinct "
            f"MITRE ATT&CK technique(s), indicating a coordinated intrusion rather than isolated noise."
        )
    else:
        headline = (
            f"During this reporting period, {tenant_name}'s environment triggered {len(alerts)} "
            f"security alert(s), including {crit} critical and {high} high severity finding(s). "
            f"No alerts correlated into a multi-stage attack chain; findings currently appear isolated."
        )

    actions = [
        "- Prioritize triage of all CRITICAL severity alerts within 1 hour.",
        "- Force a credential reset for every account involved in a correlated incident.",
        "- Isolate affected hosts from the network pending forensic review.",
        "- Validate backups are intact and offline if ransomware indicators were present.",
        "- Block IOCs (IPs, domains, hashes) listed in this report at the firewall/EDR.",
        "- Review MITRE ATT&CK coverage gaps against current detection rules.",
    ]
    return headline + "\n\nRecommended Immediate Actions:\n" + "\n".join(actions)


def generate_executive_summary(alerts: list[dict], incidents, tenant_name: str, config: dict) -> tuple[str, str]:
    """Returns (summary_text, source) where source is 'genai' or 'template'."""
    genai_cfg = config.get("genai", {})
    # Tenant setting (entered via the dashboard) wins; env var is the fallback
    # for CLI/Docker use where nobody has filled in the Settings tab yet.
    api_key = genai_cfg.get("api_key") or os.environ.get("ANTHROPIC_API_KEY")

    if not genai_cfg.get("enabled") or not api_key:
        return _fallback_summary(alerts, incidents, tenant_name), "template"

    try:
        from anthropic import Anthropic
        client = Anthropic(api_key=api_key)
        context = _build_findings_context(alerts, incidents, tenant_name)
        response = client.messages.create(
            model=genai_cfg.get("model", "claude-sonnet-5"),
            max_tokens=genai_cfg.get("max_tokens", 1200),
            system=SYSTEM_PROMPT,
            messages=[{"role": "user", "content": f"Here are this period's SOC findings:\n\n{context}"}],
        )
        text = "".join(block.text for block in response.content if hasattr(block, "text")).strip()
        if text:
            return text, "genai"
        return _fallback_summary(alerts, incidents, tenant_name), "template"
    except Exception:
        # Never let a GenAI/network failure break report generation.
        return _fallback_summary(alerts, incidents, tenant_name), "template"

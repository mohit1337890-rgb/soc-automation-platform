"""Builds docs/SOC_Automation_Manual.pdf - the client-facing installation
and usage manual, requested alongside the dashboard/Docker/multi-tenancy
work. Pure-Python (fpdf2, no system dependencies like wkhtmltopdf/Cairo),
so it builds identically on Windows, Linux, and inside the Docker image.

Run with: python docs/generate_manual.py
"""
import os
from fpdf import FPDF

NAVY = (15, 20, 32)
ACCENT = (91, 140, 255)
TEXT = (30, 34, 44)
MUTED = (100, 108, 128)
LIGHT_BG = (240, 243, 250)


class Manual(FPDF):
    def header(self):
        if self.page_no() == 1:
            return
        self.set_font("Helvetica", "", 8)
        self.set_text_color(*MUTED)
        self.cell(0, 8, "SOC Automation Project - Installation & User Manual", align="L")
        self.cell(0, 8, f"Page {self.page_no()}", align="R", new_x="LMARGIN", new_y="NEXT")
        self.set_draw_color(*LIGHT_BG)
        self.line(10, 18, 200, 18)
        self.ln(4)

    def footer(self):
        pass

    def h1(self, text):
        self.add_page()
        self.set_font("Helvetica", "B", 20)
        self.set_text_color(*ACCENT)
        self.cell(0, 14, text, new_x="LMARGIN", new_y="NEXT")
        self.set_draw_color(*ACCENT)
        self.set_line_width(0.8)
        self.line(10, self.get_y(), 60, self.get_y())
        self.ln(8)
        self.set_text_color(*TEXT)

    def h2(self, text):
        self.ln(3)
        self.set_font("Helvetica", "B", 13)
        self.set_text_color(*ACCENT)
        self.cell(0, 9, text, new_x="LMARGIN", new_y="NEXT")
        self.set_text_color(*TEXT)
        self.ln(1)

    def body(self, text):
        self.set_font("Helvetica", "", 10.5)
        self.set_text_color(*TEXT)
        self.multi_cell(0, 6, text)
        self.ln(1)

    def bullets(self, items):
        self.set_font("Helvetica", "", 10.5)
        self.set_text_color(*TEXT)
        for item in items:
            self.set_x(14)
            self.multi_cell(0, 6, f"-  {item}")
        self.ln(1)

    def code(self, text):
        self.set_fill_color(*LIGHT_BG)
        self.set_font("Courier", "", 9.5)
        self.set_text_color(20, 20, 20)
        x, y = self.get_x(), self.get_y()
        lines = text.strip("\n").split("\n")
        height = 6 * len(lines) + 6
        self.rect(10, y, 190, height, style="F")
        self.set_xy(14, y + 3)
        for line in lines:
            self.set_x(14)
            self.cell(0, 6, line, new_x="LEFT", new_y="NEXT")
        self.set_xy(x, y + height + 4)
        self.set_text_color(*TEXT)

    def note(self, label, text):
        self.set_fill_color(255, 247, 224)
        self.set_font("Helvetica", "B", 10)
        self.set_text_color(150, 110, 0)
        self.multi_cell(0, 6, label, fill=True, new_x="LMARGIN", new_y="NEXT")
        self.set_font("Helvetica", "", 10)
        self.set_text_color(*TEXT)
        self.multi_cell(0, 6, text, fill=True, new_x="LMARGIN", new_y="NEXT")
        self.ln(2)


def build():
    pdf = Manual()
    pdf.set_auto_page_break(auto=True, margin=20)
    pdf.set_margins(10, 12, 10)

    # ---------------- Cover page ----------------
    pdf.add_page()
    pdf.set_fill_color(*NAVY)
    pdf.rect(0, 0, 210, 297, style="F")
    pdf.set_y(110)
    pdf.set_text_color(255, 255, 255)
    pdf.set_font("Helvetica", "B", 30)
    pdf.cell(0, 16, "SOC Automation Project", align="C", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "", 15)
    pdf.set_text_color(180, 195, 230)
    pdf.cell(0, 10, "Installation, Configuration & User Manual", align="C", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(10)
    pdf.set_font("Helvetica", "", 11)
    pdf.set_text_color(140, 155, 190)
    pdf.cell(0, 8, "Multi-tenant threat detection, correlation & AI-assisted reporting", align="C",
             new_x="LMARGIN", new_y="NEXT")
    pdf.ln(6)
    pdf.set_font("Helvetica", "I", 11)
    pdf.set_text_color(180, 195, 230)
    pdf.cell(0, 8, "Built by Mohit", align="C", new_x="LMARGIN", new_y="NEXT")

    # ---------------- 1. Overview ----------------
    pdf.h1("1. Overview & Architecture")
    pdf.body(
        "The SOC Automation Project ingests security logs (email, Windows Security/Sysmon "
        "events, PowerShell script-block logs, and cloud/AD sign-in logs), runs them through "
        "9 independent detection modules, correlates related alerts into multi-stage incidents, "
        "and produces an executive report with an AI-generated summary and MITRE ATT&CK mapping."
    )
    pdf.h2("Four layers")
    pdf.bullets([
        "Ingestion - reads/normalizes logs from every source into one JSON event schema.",
        "Detection - 9 modules, each independently flags one class of threat.",
        "Correlation ('The Brain') - links alerts across modules that share a user/host/IP/IOC "
        "within a time window into one incident.",
        "Reporting - builds the HTML report and the AI executive summary (Item 10).",
    ])
    pdf.h2("Detection modules")
    pdf.bullets([
        "Phishing email detection (SPF/DKIM/DMARC + risky URLs/attachments)",
        "VirusTotal reputation checking (hashes/domains, cached, rate-limited)",
        "Brute force detection (EID 4625/4624)",
        "LSASS / Mimikatz credential dumping (Sysmon EID 10)",
        "Malicious PowerShell detection (EID 4104, -EncodedCommand decoding)",
        "Ransomware detection (shadow-copy deletion, mass file encryption)",
        "Persistence detection (scheduled tasks EID 4698, registry Run keys)",
        "Lateral movement detection (admin shares, PsExec, multi-host logons)",
        "Impossible travel detection (GeoIP + travel-speed physics)",
    ])
    pdf.h2("Multi-tenancy")
    pdf.body(
        "Every client (\"tenant\") gets a physically separate SQLite database, sample-data "
        "folder, and reports folder. There is no shared table and no tenant_id column to get "
        "wrong - Client A's data cannot leak into Client B's dashboard because it is never "
        "loaded into the same file."
    )

    # ---------------- 2. Installation ----------------
    pdf.h1("2. Installation")
    pdf.h2("Option A - Docker (recommended)")
    pdf.body("This is the fastest path for a client machine. Requires Docker Desktop.")
    pdf.code("docker compose up -d --build")
    pdf.body("The web dashboard is then available at:")
    pdf.code("http://localhost:8501")
    pdf.body("To run the detection pipeline for a specific tenant from the command line instead:")
    pdf.code("docker compose run --rm pipeline --tenant acme_corp")

    pdf.h2("Option B - Local Python install")
    pdf.code(
        "python -m venv .venv\n"
        ".venv\\Scripts\\activate        (Windows)\n"
        "source .venv/bin/activate       (Linux/Mac)\n"
        "pip install -r requirements.txt streamlit fpdf2"
    )
    pdf.body("Run the pipeline once, then launch the dashboard:")
    pdf.code(
        "python main.py --tenant demo\n"
        "streamlit run dashboard/app.py"
    )

    # ---------------- 3. API keys ----------------
    pdf.h1("3. Configuring API Keys")
    pdf.body(
        "All keys are optional - every module has an offline fallback so the system is fully "
        "usable for a demo or evaluation with zero paid API access. Set keys as environment "
        "variables (recommended) or in config.yaml."
    )
    pdf.h2("VirusTotal (hash/domain reputation)")
    pdf.bullets([
        "Get a free API key at virustotal.com (4 requests/minute on the free tier).",
        "Set environment variable VT_API_KEY, or edit virustotal.api_key in config.yaml.",
        "Without a key: the module uses a small offline blocklist so it still runs end-to-end.",
    ])
    pdf.h2("Anthropic / Claude (AI-generated executive summary)")
    pdf.bullets([
        "Get an API key from console.anthropic.com.",
        "Set environment variable ANTHROPIC_API_KEY.",
        "Without a key: the report falls back automatically to a clear template-based summary - "
        "report generation never fails because of this.",
    ])
    pdf.h2("IPinfo (optional, real GeoIP for Impossible Travel)")
    pdf.bullets([
        "Only needed to resolve real source IPs to city/lat/lon in production.",
        "Set impossible_travel.ipinfo_api_key in config.yaml.",
        "The bundled sample data already carries city/lat/lon, so this module works fully "
        "offline for demos.",
    ])
    pdf.note("Security note", "Never commit real API keys to source control. Use environment "
             "variables or a secrets manager in production.")

    # ---------------- 4. Multi-tenancy ----------------
    pdf.h1("4. Multi-Tenancy - Onboarding a New Client")
    pdf.body("Add one entry to config/tenants.yaml:")
    pdf.code(
        "tenants:\n"
        "  - id: \"new_client\"\n"
        "    name: \"New Client Ltd\"\n"
        "    access_code: \"choose-a-code\""
    )
    pdf.body(
        "That's it. The next pipeline run or dashboard login for 'new_client' automatically "
        "creates its own isolated database at data/new_client/soc.db, its own sample-data "
        "folder, and its own reports folder. No other configuration file needs to change."
    )
    pdf.note("Production note", "The dashboard's tenant + access-code screen is a demo-grade "
             "gate, not enterprise authentication. For real multi-client production use, wire "
             "up Streamlit's native st.login() with your identity provider (SSO/OIDC) and map "
             "the authenticated user's organization claim to the tenant ID.")

    # ---------------- 5. CLI ----------------
    pdf.h1("5. Running the Detection Pipeline (CLI)")
    pdf.code(
        "python main.py --tenant acme_corp\n"
        "python main.py --tenant acme_corp --no-sample-data   # reuse existing logs\n"
        "python main.py --tenant acme_corp --no-genai         # force template summary\n"
        "python main.py --list-tenants"
    )
    pdf.body(
        "Each run: ingests logs -> runs all 9 detectors -> stores alerts in that tenant's "
        "database -> re-runs correlation -> writes a fresh HTML report to reports/<tenant>/."
    )

    # ---------------- 6. Dashboard ----------------
    pdf.h1("6. Using the Web Dashboard")
    pdf.bullets([
        "Sign in by choosing your organization and entering its access code.",
        "Sidebar: 'Run detection pipeline now' re-runs ingestion + detection + correlation + "
        "reporting for your organization on demand.",
        "Overview tab: KPI counts, severity distribution, alerts-by-module, and a timeline.",
        "Incidents tab: correlated multi-stage attack chains with a step-by-step narrative.",
        "Alerts tab: every individual alert, filterable by severity and detector.",
        "IOCs tab: every indicator of compromise (IP, domain, hash, URL) extracted so far.",
        "Reports tab: download any previously generated HTML report.",
    ])

    # ---------------- 7. Reading reports ----------------
    pdf.h1("7. Reading the Report")
    pdf.h2("Severity levels")
    pdf.bullets([
        "Critical - confirmed or near-certain compromise; act immediately.",
        "High - strong indicator of malicious activity; triage same day.",
        "Medium - suspicious but not conclusive; review during normal triage.",
        "Low - informational; monitor for recurrence.",
    ])
    pdf.h2("Correlated incidents vs. standalone alerts")
    pdf.body(
        "An 'incident' means 2 or more different detectors fired on the same user, host, IP, "
        "or IOC within the configured time window - this is much higher-confidence evidence of "
        "a real, active intrusion than any single alert, because it shows a pattern across "
        "multiple independent detection methods."
    )
    pdf.h2("MITRE ATT&CK mapping")
    pdf.body(
        "Every alert carries a MITRE ATT&CK technique ID and tactic (e.g. T1110 / Credential "
        "Access). The report's MITRE table shows which stages of a real attack lifecycle "
        "(Initial Access, Execution, Persistence, Lateral Movement, Impact, etc.) were observed."
    )
    pdf.h2("IOCs (Indicators of Compromise)")
    pdf.body(
        "IPs, domains, file hashes and URLs extracted from alerts - use these to block at your "
        "firewall/EDR/email gateway."
    )

    # ---------------- 8. Troubleshooting ----------------
    pdf.h1("8. Troubleshooting / FAQ")
    pdf.h2("The AI executive summary says 'Template-Based' instead of 'AI-Generated'")
    pdf.body("ANTHROPIC_API_KEY is not set in the environment, or the API call failed. Check "
              "the key and your network access; the report still generates correctly either way.")
    pdf.h2("VirusTotal alerts aren't appearing")
    pdf.body("Without VT_API_KEY set, only indicators in the offline blocklist (config.yaml -> "
              "virustotal.offline_blocklist_hashes/domains) will be flagged. This is expected "
              "in demo mode.")
    pdf.h2("I ran the pipeline twice and got duplicate-looking alerts")
    pdf.body("Each run re-ingests the sample data and re-inserts alerts by their unique ID; "
              "use --no-sample-data to reuse the same logs instead of regenerating new random "
              "background noise each time.")
    pdf.h2("Docker: dashboard container can't see my data after a restart")
    pdf.body("Confirm the data/, sample_data/, reports/, and config/ folders are mounted as "
              "volumes in docker-compose.yml (they are, by default) - this is what makes data "
              "persist across container rebuilds.")

    out_dir = os.path.dirname(os.path.abspath(__file__))
    out_path = os.path.join(out_dir, "SOC_Automation_Manual.pdf")
    pdf.output(out_path)
    return out_path


if __name__ == "__main__":
    path = build()
    print(f"Manual written to: {path}")

"""SOC Automation Project - CLI Orchestrator.

Usage:
    python main.py --tenant demo
    python main.py --tenant acme_corp --no-sample-data
    python main.py --tenant acme_corp --no-genai
    python main.py --tenant acme_corp --source live
    python main.py --list-tenants
"""
import argparse
from core.pipeline import run_pipeline
from core.tenants import TenantRegistry


def main():
    parser = argparse.ArgumentParser(description="Run the SOC detection + correlation + reporting pipeline.")
    parser.add_argument("--tenant", default="demo", help="Tenant ID from config/tenants.yaml (default: demo)")
    parser.add_argument("--source", choices=["sample", "live"], default="sample",
                         help="'sample' = bundled synthetic demo data (default). "
                              "'live' = real Windows Event Logs + real email inbox, using this "
                              "tenant's Settings (configure via the dashboard's Settings tab first).")
    parser.add_argument("--no-sample-data", action="store_true",
                         help="With --source sample: skip regenerating synthetic logs (reuse existing ones)")
    parser.add_argument("--no-genai", action="store_true",
                         help="Force the template-based executive summary, skip Claude API call")
    parser.add_argument("--list-tenants", action="store_true", help="List configured tenants and exit")
    args = parser.parse_args()

    if args.list_tenants:
        for t in TenantRegistry().list_tenants():
            print(f"  - {t.id:15s} {t.name}")
        return

    result = run_pipeline(
        tenant_id=args.tenant,
        generate_sample_data=not args.no_sample_data,
        genai_override=False if args.no_genai else None,
        source=args.source,
    )

    print(f"\n{'=' * 60}")
    print(f"  SOC PIPELINE COMPLETE - {result['tenant_name']} ({result['tenant_id']})  [source: {result['source']}]")
    print(f"{'=' * 60}")
    print(f"Events ingested : {result['events_loaded']}")
    if result["warnings"]:
        print("\nWarnings:")
        for w in result["warnings"]:
            print(f"  ! {w}")
    print(f"\nAlerts by detector:")
    for name, count in result["alerts_by_detector"].items():
        print(f"  - {name:22s} {count}")
    print(f"\nTotal alerts        : {result['total_alerts']}")
    print(f"Correlated incidents: {result['incidents']}")
    print(f"Database            : {result['database_file']}")
    print(f"Report              : {result['report_path']}")
    print(f"{'=' * 60}\n")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
Auto-Investigate Driver — Non-interactive end-to-end KQL investigation.

Given a single entity (UPN, IP, device hostname, or incident ID), runs the
3-phase workflow defined in .github/skills/kql-auto-investigate/SKILL.md:

  Phase 1 — Triage (parallel KQL via Data Lake REST API)
  Phase 2 — Deep Dive (conditional on Phase 1 findings)
  Phase 3 — Correlation + IP enrichment

Outputs:
  reports/investigation_<entity_prefix>_YYYY-MM-DD.json

This driver intentionally performs ONLY the deterministic parts (query
execution + enrichment). The interactive skill (SKILL.md) handles narrative
analysis and HTML report generation via the `report-generation` skill.

Usage:
  python scripts/auto_investigate.py --entity user@contoso.com
  python scripts/auto_investigate.py --entity 203.0.113.42 --days 14
  python scripts/auto_investigate.py --entity WORKSTATION-01 --output reports/custom.json

Prerequisites:
  - enrichment/config.json populated (workspace name + ID, API keys)
  - az login completed (for Sentinel Data Lake KQL API)
  - Python deps: requests (already in enrichment/requirements.txt)
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
CONFIG_PATH = REPO_ROOT / "enrichment" / "config.json"
REPORTS_DIR = REPO_ROOT / "reports"
QUERY_DATALAKE = REPO_ROOT / "scripts" / "query_datalake.py"
ENRICH_IPS = REPO_ROOT / "enrichment" / "enrich_ips.py"


# --------------------------------------------------------------------------- #
# Entity classification
# --------------------------------------------------------------------------- #

IPV4_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
INCIDENT_RE = re.compile(r"^(INC-?)?\d+$", re.IGNORECASE)


def classify(entity: str) -> str:
    """Return one of: upn | ip | device | incident."""
    if "@" in entity:
        return "upn"
    if IPV4_RE.match(entity) or ":" in entity:
        return "ip"
    if INCIDENT_RE.match(entity):
        return "incident"
    return "device"


def entity_prefix(entity: str, entity_type: str) -> str:
    """Short prefix used in report filenames."""
    if entity_type == "upn":
        return entity.split("@", 1)[0].lower()
    if entity_type == "ip":
        return entity.replace(".", "-").replace(":", "-")
    return entity.lower().replace(" ", "_")


# --------------------------------------------------------------------------- #
# Query templates per entity type
# --------------------------------------------------------------------------- #

def triage_queries(entity: str, entity_type: str, days: int) -> dict[str, str]:
    """Phase 1 triage queries scoped to entity type."""
    window = f"ago({days}d)"

    if entity_type == "upn":
        return {
            "signins": f"""
                SigninLogs
                | where TimeGenerated > {window}
                | where UserPrincipalName =~ '{entity}'
                | summarize count() by ResultType, bin(TimeGenerated, 1d)
                | order by TimeGenerated desc
            """,
            "alerts": f"""
                SecurityAlert
                | where TimeGenerated > {window}
                | where Entities has '{entity}'
                | summarize arg_max(TimeGenerated, *) by SystemAlertId
                | project TimeGenerated, AlertName, AlertSeverity, ProductName, Tactics
            """,
            "audit": f"""
                AuditLogs
                | where TimeGenerated > {window}
                | where tostring(InitiatedBy) has '{entity}' or tostring(TargetResources) has '{entity}'
                | summarize count() by OperationName
                | top 20 by count_
            """,
            "office": f"""
                OfficeActivity
                | where TimeGenerated > {window}
                | where UserId =~ '{entity}'
                | summarize count() by Operation, OfficeWorkload
                | top 20 by count_
            """,
        }

    if entity_type == "ip":
        return {
            "signins": f"""
                SigninLogs
                | where TimeGenerated > {window}
                | where IPAddress == '{entity}'
                | summarize count(), dcount(UserPrincipalName) by ResultType
            """,
            "alerts": f"""
                SecurityAlert
                | where TimeGenerated > {window}
                | where Entities has '{entity}'
                | summarize arg_max(TimeGenerated, *) by SystemAlertId
                | project TimeGenerated, AlertName, AlertSeverity, ProductName
            """,
        }

    if entity_type == "device":
        return {
            "alerts": f"""
                SecurityAlert
                | where TimeGenerated > {window}
                | where Entities has '{entity}'
                | summarize arg_max(TimeGenerated, *) by SystemAlertId
            """,
        }

    # incident
    return {
        "incident": f"""
            SecurityIncident
            | where TimeGenerated > {window}
            | where IncidentNumber == tolong('{entity.lstrip('INC-').lstrip('inc-')}')
               or ProviderIncidentId == '{entity}'
            | summarize arg_max(TimeGenerated, *) by IncidentNumber
        """,
    }


# --------------------------------------------------------------------------- #
# Query execution
# --------------------------------------------------------------------------- #

def run_query(name: str, kql: str) -> dict[str, Any]:
    """Run a single KQL query via the Data Lake REST API wrapper."""
    try:
        result = subprocess.run(
            ["python", str(QUERY_DATALAKE), "--json", kql.strip()],
            capture_output=True,
            text=True,
            timeout=120,
            cwd=str(REPO_ROOT),
        )
        if result.returncode != 0:
            return {"name": name, "status": "error", "error": result.stderr.strip()}
        return {"name": name, "status": "ok", "rows": json.loads(result.stdout or "[]")}
    except subprocess.TimeoutExpired:
        return {"name": name, "status": "timeout"}
    except Exception as exc:  # noqa: BLE001
        return {"name": name, "status": "error", "error": str(exc)}


def run_parallel(queries: dict[str, str]) -> dict[str, Any]:
    results: dict[str, Any] = {}
    with ThreadPoolExecutor(max_workers=min(len(queries), 4)) as pool:
        futures = {pool.submit(run_query, name, kql): name for name, kql in queries.items()}
        for fut in as_completed(futures):
            out = fut.result()
            results[out["name"]] = out
    return results


# --------------------------------------------------------------------------- #
# IP extraction + enrichment
# --------------------------------------------------------------------------- #

IP_IN_ROW = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def extract_ips(phase1: dict[str, Any]) -> list[str]:
    ips: set[str] = set()
    for q in phase1.values():
        for row in q.get("rows", []) or []:
            ips.update(IP_IN_ROW.findall(json.dumps(row)))
    # Filter private + loopback
    public = [
        ip for ip in ips
        if not (
            ip.startswith(("10.", "127.", "169.254.", "192.168."))
            or ip.startswith("172.") and 16 <= int(ip.split(".")[1]) <= 31
        )
    ]
    return sorted(public)


def enrich_ips(ips: list[str]) -> dict[str, Any]:
    if not ips:
        return {"status": "skipped", "reason": "no public IPs extracted"}
    try:
        result = subprocess.run(
            ["python", str(ENRICH_IPS), *ips],
            capture_output=True,
            text=True,
            timeout=600,
            cwd=str(REPO_ROOT),
        )
        return {
            "status": "ok" if result.returncode == 0 else "error",
            "ips": ips,
            "stderr": result.stderr[-500:] if result.stderr else "",
        }
    except Exception as exc:  # noqa: BLE001
        return {"status": "error", "error": str(exc), "ips": ips}


# --------------------------------------------------------------------------- #
# Driver
# --------------------------------------------------------------------------- #

def main() -> int:
    parser = argparse.ArgumentParser(description="Auto-investigate a single entity end-to-end.")
    parser.add_argument("--entity", required=True, help="UPN, IP, device hostname, or incident ID")
    parser.add_argument("--days", type=int, default=7, help="Lookback window (default: 7)")
    parser.add_argument("--output", type=Path, default=None, help="Output JSON path (default: reports/investigation_<prefix>_<date>.json)")
    args = parser.parse_args()

    if not CONFIG_PATH.exists():
        print(f"ERROR: {CONFIG_PATH} not found. Copy enrichment/config.json.template and fill it in.", file=sys.stderr)
        return 2

    entity_type = classify(args.entity)
    prefix = entity_prefix(args.entity, entity_type)
    date_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    output = args.output or REPORTS_DIR / f"investigation_{prefix}_{date_str}.json"
    output.parent.mkdir(parents=True, exist_ok=True)

    print(f"[auto-investigate] entity={args.entity} type={entity_type} window={args.days}d")
    print(f"[auto-investigate] output={output}")

    # Phase 1 — Triage
    print("[phase 1] triage queries (parallel)...")
    queries = triage_queries(args.entity, entity_type, args.days)
    phase1 = run_parallel(queries)

    total_rows = sum(len(q.get("rows", []) or []) for q in phase1.values())
    print(f"[phase 1] {total_rows} total rows across {len(phase1)} queries")

    report: dict[str, Any] = {
        "metadata": {
            "entity": args.entity,
            "entity_type": entity_type,
            "window_days": args.days,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "driver": "scripts/auto_investigate.py",
            "skill": ".github/skills/kql-auto-investigate/SKILL.md",
        },
        "phase1_triage": phase1,
    }

    if total_rows == 0:
        report["status"] = "clean"
        report["summary"] = f"No activity found for {args.entity} in the last {args.days} days."
        output.write_text(json.dumps(report, indent=2))
        print(f"[done] clean result written to {output}")
        return 0

    # Phase 2 — IP enrichment (simplest deterministic deep-dive)
    print("[phase 2] extracting + enriching IPs...")
    ips = extract_ips(phase1)
    print(f"[phase 2] {len(ips)} public IPs found")
    report["phase2_enrichment"] = enrich_ips(ips)

    # Phase 3 — Correlation (baseline diff placeholder; full logic lives in the skill)
    report["phase3_correlation"] = {
        "status": "deferred-to-skill",
        "note": "Narrative correlation + MITRE mapping handled by the interactive skill.",
    }

    report["status"] = "findings"
    output.write_text(json.dumps(report, indent=2))
    print(f"[done] report written to {output}")
    print("[next] invoke the report-generation skill to produce the HTML report.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

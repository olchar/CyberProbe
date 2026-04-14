#!/usr/bin/env python3
"""
Sentinel Data Lake KQL REST API Query Utility

Direct KQL query execution against the Microsoft Sentinel data lake using the
native REST API endpoint. Use this as a fallback when the MCP Data Lake tool
(query_lake) is unavailable, or for automation/scripting.

API Endpoint: POST https://api.securityplatform.microsoft.com/lake/kql/v2/rest/query
Auth scope:   4500ebfb-89b6-4b14-a480-7f749797bfcd/.default

References:
  - https://learn.microsoft.com/en-us/azure/sentinel/datalake/kql-queries-api
  - https://techcommunity.microsoft.com/blog/MicrosoftSentinelBlog/running-kql-queries-on-microsoft-sentinel-data-lake-using-api/4503128

Usage:
  # Interactive query (reads config.json for workspace):
  python scripts/query_datalake.py "SigninLogs | where TimeGenerated > ago(1d) | take 10"

  # With explicit workspace:
  python scripts/query_datalake.py --workspace-name "CyberSOC-Lake" --workspace-id "e34d562e-..." "SigninLogs | take 5"

  # Read query from file:
  python scripts/query_datalake.py --file queries/identity/multi_stage_identity_compromise_detection.kql

  # Output as JSON:
  python scripts/query_datalake.py --json "SigninLogs | take 10"

  # With optional query settings:
  python scripts/query_datalake.py --timeout "00:04:00" --consistency strong "SigninLogs | take 10"

Authentication:
  Uses `az account get-access-token` for the Data Lake API resource.
  Ensure you are logged in: az login --tenant <tenant-id>
  Required RBAC: Log Analytics Reader or Contributor on the Sentinel workspace.
"""

import argparse
import json
import os
import subprocess
import sys
import textwrap

# Sentinel Data Lake KQL API constants
DATALAKE_API_URL = "https://api.securityplatform.microsoft.com/lake/kql/v2/rest/query"
DATALAKE_AUTH_RESOURCE = "4500ebfb-89b6-4b14-a480-7f749797bfcd"

CONFIG_PATH = os.path.join(os.path.dirname(__file__), "..", "enrichment", "config.json")


def load_config():
    """Load workspace config from enrichment/config.json."""
    config_path = os.path.normpath(CONFIG_PATH)
    if not os.path.exists(config_path):
        return None
    with open(config_path, "r", encoding="utf-8") as f:
        return json.load(f)


def get_access_token():
    """Acquire an access token for the Data Lake KQL API via az CLI."""
    try:
        result = subprocess.run(
            [
                "az", "account", "get-access-token",
                "--resource", DATALAKE_AUTH_RESOURCE,
                "--query", "accessToken",
                "-o", "tsv"
            ],
            capture_output=True, text=True, check=True, timeout=30
        )
        token = result.stdout.strip()
        if not token:
            print("ERROR: Empty token returned. Ensure you are logged in:", file=sys.stderr)
            print("  az login --tenant <tenant-id>", file=sys.stderr)
            sys.exit(1)
        return token
    except subprocess.CalledProcessError as e:
        print(f"ERROR: Failed to acquire token: {e.stderr.strip()}", file=sys.stderr)
        print("Ensure Azure CLI is installed and you are logged in:", file=sys.stderr)
        print("  az login --tenant <tenant-id>", file=sys.stderr)
        sys.exit(1)
    except FileNotFoundError:
        print("ERROR: Azure CLI (az) not found. Install from:", file=sys.stderr)
        print("  https://learn.microsoft.com/cli/azure/install-azure-cli", file=sys.stderr)
        sys.exit(1)


def execute_query(query, workspace_db, token, timeout=None, consistency=None):
    """Execute a KQL query against the Sentinel Data Lake API."""
    import urllib.request
    import urllib.error

    # Build payload
    payload = {
        "csl": query.replace("\n", " ").strip(),
        "db": workspace_db
    }

    # Add optional properties
    if timeout or consistency:
        options = {"query_language": "kql"}
        if timeout:
            options["servertimeout"] = timeout
        if consistency:
            options["queryconsistency"] = consistency
        payload["properties"] = {"Options": options}

    data = json.dumps(payload).encode("utf-8")

    req = urllib.request.Request(
        DATALAKE_API_URL,
        data=data,
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json"
        },
        method="POST"
    )

    try:
        with urllib.request.urlopen(req, timeout=300) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")
        print(f"ERROR: HTTP {e.code} — {e.reason}", file=sys.stderr)
        print(f"Response: {body}", file=sys.stderr)
        sys.exit(1)
    except urllib.error.URLError as e:
        print(f"ERROR: Connection failed — {e.reason}", file=sys.stderr)
        sys.exit(1)


def format_table(result):
    """Format API response as a readable table."""
    tables = result.get("Tables", result.get("tables", []))
    if not tables:
        print("No results returned.")
        return

    table = tables[0]
    columns = [col.get("ColumnName", col.get("columnName", f"col{i}"))
                for i, col in enumerate(table.get("Columns", table.get("columns", [])))]
    rows = table.get("Rows", table.get("rows", []))

    if not rows:
        print(f"Query returned 0 rows. Columns: {', '.join(columns)}")
        return

    print(f"Rows: {len(rows)} | Columns: {len(columns)}")
    print("-" * 80)

    # Calculate column widths (cap at 40 chars)
    widths = [min(max(len(str(col)), max((len(str(row[i])) for row in rows), default=0)), 40)
              for i, col in enumerate(columns)]

    # Header
    header = " | ".join(str(col).ljust(widths[i]) for i, col in enumerate(columns))
    print(header)
    print("-+-".join("-" * w for w in widths))

    # Rows
    for row in rows:
        line = " | ".join(str(val)[:40].ljust(widths[i]) for i, val in enumerate(row))
        print(line)


def main():
    parser = argparse.ArgumentParser(
        description="Query Sentinel Data Lake via the native KQL REST API.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            Examples:
              %(prog)s "SigninLogs | take 10"
              %(prog)s --file queries/identity/failed_signin_analysis.kql
              %(prog)s --json "AuditLogs | where TimeGenerated > ago(1d) | take 5"
              %(prog)s --timeout "00:04:00" "SecurityAlert | take 20"
        """)
    )
    parser.add_argument("query", nargs="?", help="KQL query string to execute")
    parser.add_argument("--file", "-f", help="Read KQL query from a file")
    parser.add_argument("--workspace-name", help="Sentinel workspace name (default: from config.json)")
    parser.add_argument("--workspace-id", help="Sentinel workspace ID (default: from config.json)")
    parser.add_argument("--json", action="store_true", help="Output raw JSON response")
    parser.add_argument("--timeout", help="Server timeout (e.g., '00:04:00')")
    parser.add_argument("--consistency", choices=["strongconsistency", "weakconsistency", "strong", "weak"],
                        help="Query consistency level")

    args = parser.parse_args()

    # Resolve query
    if args.file:
        if not os.path.exists(args.file):
            print(f"ERROR: File not found: {args.file}", file=sys.stderr)
            sys.exit(1)
        with open(args.file, "r", encoding="utf-8") as f:
            query = f.read()
    elif args.query:
        query = args.query
    else:
        parser.print_help()
        sys.exit(1)

    # Strip KQL comments for the API (single-line JSON requirement)
    query_lines = []
    for line in query.split("\n"):
        stripped = line.strip()
        if stripped.startswith("//") or stripped.startswith("#"):
            continue
        query_lines.append(line)
    query = " ".join(query_lines)

    # Resolve workspace
    config = load_config()
    workspace_name = args.workspace_name
    workspace_id = args.workspace_id or (config.get("sentinel_workspace_id") if config else None)

    if not workspace_id:
        print("ERROR: No workspace ID. Provide --workspace-id or set sentinel_workspace_id in config.json",
              file=sys.stderr)
        sys.exit(1)

    if not workspace_name:
        workspace_name = config.get("sentinel_workspace_name", "Workspace") if config else "Workspace"

    workspace_db = f"{workspace_name}-{workspace_id}"

    # Normalize consistency
    consistency = args.consistency
    if consistency == "strong":
        consistency = "strongconsistency"
    elif consistency == "weak":
        consistency = "weakconsistency"

    # Execute
    print(f"Workspace: {workspace_db}", file=sys.stderr)
    print(f"Query: {query[:120]}{'...' if len(query) > 120 else ''}", file=sys.stderr)
    print(file=sys.stderr)

    token = get_access_token()
    result = execute_query(query, workspace_db, token, timeout=args.timeout, consistency=consistency)

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        format_table(result)


if __name__ == "__main__":
    main()

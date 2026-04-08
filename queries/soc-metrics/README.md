# SOC Metrics — KQL Query Library

Parameterized KQL queries for SOC operational metrics, KPIs, and analyst performance tracking. All queries target the **Microsoft Sentinel Data Lake** (`SecurityIncident`, `SecurityAlert` tables).

## Source Attribution

These queries were adapted from [stefanpems/ai-powered-soc](https://github.com/stefanpems/ai-powered-soc) (SOC-HighView-Agent/MCP-toolset), originally designed for a Copilot Studio MCP server. They have been reformatted for CyberProbe's standardized header convention and converted from parameterized templates (`{start_date}`) to standalone KQL with configurable `let` variables.

## Queries

| File | Description | Key Output |
|------|-------------|------------|
| [mean_time_to_acknowledge.kql](mean_time_to_acknowledge.kql) | MTTA: average minutes from creation to first modification | MTTA + MoM % change |
| [mean_time_to_resolve.kql](mean_time_to_resolve.kql) | MTTR: average minutes from creation to closure | MTTR + MoM % change |
| [incident_count_stats.kql](incident_count_stats.kql) | Incident breakdown by type with status, classification, MITRE mapping | Top N incident types |
| [top_impacted_users.kql](top_impacted_users.kql) | Users with the most alerts/incidents (entity extraction) | Top N users by alert count |
| [top_impacted_devices.kql](top_impacted_devices.kql) | Devices with the most alerts/incidents (entity extraction) | Top N hosts by alert count |
| [top_incident_owners.kql](top_incident_owners.kql) | Analyst workload distribution by incident assignment | Top N owners by count |

## Usage

All queries use `let` variables at the top for easy customization:

```kql
let start_time = ago(7d);     // Adjust lookback period
let end_time = now();          // Or use a fixed datetime
let severities = dynamic([]);  // Set to dynamic(["High"]) to filter
```

Run via Sentinel Data Lake (`query_lake` MCP tool) or Log Analytics workspace.

# Data Sources

Tools and guides for connecting, generating, and ingesting data into Microsoft Sentinel.

---

## 📁 Contents

| File | Description |
|------|-------------|
| `generate_csl_sample_data.py` | Generate realistic `CommonSecurityLog` events (5 vendors, 6 attack scenarios) |
| `deploy-csl-ingestion.json` | ARM template — deploys DCE and DCR for an existing `CommonSecurityLog_CL` table |
| `deploy-csl-ingestion.parameters.json` | ARM template parameters file (edit before deploying) |
| `LOGS_INGESTION_SETUP.md` | Step-by-step guide to set up DCE/DCR for the Azure Monitor Logs Ingestion API |
| `sample_csl_events.json` | Pre-generated 100-event sample output |

---

## 🔧 Quick Start

### Generate sample data (file only)

```powershell
cd data-sources
python generate_csl_sample_data.py --output sample_csl_events.json --count 200 --days 7
```

### Send to Sentinel via Logs Ingestion API

```powershell
python generate_csl_sample_data.py --send \
  --dce-url "https://<DCE_NAME>.<REGION>.ingest.monitor.azure.com" \
  --dcr-id "dcr-<IMMUTABLE_ID>" \
  --count 200 --days 7
```

See [LOGS_INGESTION_SETUP.md](LOGS_INGESTION_SETUP.md) for Azure resource setup, or use the ARM template below.

### Deploy Azure infrastructure (ARM template)

```powershell
# 1. Edit parameters file with your workspace name, resource group, and region
notepad deploy-csl-ingestion.parameters.json

# 2. Deploy DCE + DCR + custom table in one command
az deployment group create `
  --resource-group "<YOUR_RG>" `
  --template-file deploy-csl-ingestion.json `
  --parameters @deploy-csl-ingestion.parameters.json

# 3. Note the outputs: dceLogsIngestionUrl, dcrImmutableId, dcrStreamName
```

---

## 📊 Supported Vendors / Scenarios

### Vendors
Palo Alto (PAN-OS), Fortinet (FortiGate), Check Point (VPN-1), Zscaler (ZIA), Cisco (ASA)

### Attack Scenarios
| Scenario | Distribution | Severity |
|----------|-------------|----------|
| Normal traffic | 60% | Low (1) |
| Port scan | 10% | Medium (5) |
| Brute force | 10% | High (7) |
| Data exfiltration | 10% | High (8) |
| Malware download | 5% | Critical (9) |
| C2 communication | 5% | Critical (10) |

---

## 🗺️ Roadmap

Future data source generators planned:

| Data Source | Table | Status |
|-------------|-------|--------|
| CommonSecurityLog (CEF) | `CommonSecurityLog` | ✅ Available |
| Syslog (Linux) | `Syslog` | 🔜 Planned |
| Windows Security Events | `SecurityEvent` | 🔜 Planned |
| Custom Log (JSON) | `CustomTable_CL` | 🔜 Planned |
| Threat Intelligence | `ThreatIntelligenceIndicator` | 🔜 Planned |

---

## 📚 References

- [Logs Ingestion API overview](https://learn.microsoft.com/azure/azure-monitor/logs/logs-ingestion-api-overview)
- [CommonSecurityLog schema](https://learn.microsoft.com/azure/azure-monitor/reference/tables/commonsecuritylog)
- [CEF format specification](https://www.microfocus.com/documentation/arcsight/arcsight-smartconnectors/pdfdoc/common-event-format-v25/common-event-format-v25.pdf)

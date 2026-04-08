# Logs Ingestion API Setup — CommonSecurityLog

Step-by-step guide to send sample CEF data to `CommonSecurityLog` in Microsoft Sentinel via the [Azure Monitor Logs Ingestion API](https://learn.microsoft.com/azure/azure-monitor/logs/logs-ingestion-api-overview).

---

## Architecture

```
generate_csl_sample_data.py
        │
        ▼
Data Collection Endpoint (DCE)
        │
        ▼
Data Collection Rule (DCR)
   ┌────┴────┐
   │ Transform│  ← KQL transformation (optional)
   └────┬────┘
        ▼
CommonSecurityLog (Log Analytics / Sentinel)
```

---

## Option A: Deploy with ARM Template (Recommended)

The ARM template `deploy-csl-ingestion.json` creates all three resources in one deployment:
- **Custom table** (`CommonSecurityLog_CL`) with full 155-column schema
- **Data Collection Endpoint** (DCE)
- **Data Collection Rule** (DCR) with stream declarations and data flow

```powershell
# 1. Edit the parameters file
notepad deploy-csl-ingestion.parameters.json

# 2. Deploy
az deployment group create `
  --resource-group "<YOUR_RG>" `
  --template-file deploy-csl-ingestion.json `
  --parameters @deploy-csl-ingestion.parameters.json

# 3. Capture outputs
$outputs = az deployment group show `
  --resource-group "<YOUR_RG>" `
  --name deploy-csl-ingestion `
  --query properties.outputs -o json | ConvertFrom-Json

$dceUrl = $outputs.dceLogsIngestionUrl.value
$dcrId  = $outputs.dcrImmutableId.value
Write-Host "DCE URL: $dceUrl"
Write-Host "DCR ID:  $dcrId"
```

After deployment, skip to **Step 3** (permissions) and then **Step 4** (run the script).

---

## Option B: Manual Setup (CLI / Portal)

## Prerequisites

| Requirement | Details |
|-------------|---------|
| Azure Subscription | With a Log Analytics workspace connected to Sentinel |
| Permissions | `Owner` or `Contributor` on the resource group |
| Azure CLI | `az` CLI installed and authenticated (`az login`) |
| Python packages | `azure-identity`, `azure-monitor-ingestion` |

```bash
pip install azure-identity azure-monitor-ingestion
```

---

## Step 1: Create a Data Collection Endpoint (DCE)

```bash
az monitor data-collection endpoint create \
  --name "dce-cyberprobe-csl" \
  --resource-group "<YOUR_RG>" \
  --location "<YOUR_REGION>" \
  --kind "Linux"
```

Note the **`logsIngestion.endpoint`** URL from the output — you'll need it as `--dce-url`.

Or via Azure Portal:
1. Go to **Monitor** → **Data Collection Endpoints**
2. Click **+ Create**
3. Name: `dce-cyberprobe-csl`, Region: same as your workspace
4. Copy the **Logs Ingestion URI** from the overview page

---

## Step 2: Create a Data Collection Rule (DCR)

### Option A: Azure CLI (recommended)

Create a DCR JSON definition file:

```json
{
  "location": "<YOUR_REGION>",
  "properties": {
    "dataCollectionEndpointId": "/subscriptions/<SUB_ID>/resourceGroups/<RG>/providers/Microsoft.Insights/dataCollectionEndpoints/dce-cyberprobe-csl",
    "streamDeclarations": {
      "Custom-CommonSecurityLog": {
        "columns": [
          { "name": "TimeGenerated", "type": "datetime" },
          { "name": "DeviceVendor", "type": "string" },
          { "name": "DeviceProduct", "type": "string" },
          { "name": "DeviceVersion", "type": "string" },
          { "name": "DeviceEventClassID", "type": "string" },
          { "name": "Activity", "type": "string" },
          { "name": "LogSeverity", "type": "string" },
          { "name": "SourceIP", "type": "string" },
          { "name": "SourcePort", "type": "int" },
          { "name": "DestinationIP", "type": "string" },
          { "name": "DestinationPort", "type": "int" },
          { "name": "Protocol", "type": "string" },
          { "name": "DeviceAction", "type": "string" },
          { "name": "SentBytes", "type": "long" },
          { "name": "ReceivedBytes", "type": "long" },
          { "name": "Message", "type": "string" },
          { "name": "DeviceName", "type": "string" },
          { "name": "Computer", "type": "string" },
          { "name": "SourceUserName", "type": "string" },
          { "name": "DestinationUserName", "type": "string" },
          { "name": "RequestURL", "type": "string" },
          { "name": "DeviceEventCategory", "type": "string" },
          { "name": "MaliciousIP", "type": "string" },
          { "name": "ThreatSeverity", "type": "int" },
          { "name": "IndicatorThreatType", "type": "string" },
          { "name": "ThreatDescription", "type": "string" },
          { "name": "DeviceCustomString1", "type": "string" },
          { "name": "DeviceCustomString1Label", "type": "string" },
          { "name": "DeviceCustomString2", "type": "string" },
          { "name": "DeviceCustomString2Label", "type": "string" }
        ]
      }
    },
    "destinations": {
      "logAnalytics": [
        {
          "workspaceResourceId": "/subscriptions/<SUB_ID>/resourceGroups/<RG>/providers/Microsoft.OperationalInsights/workspaces/<WORKSPACE_NAME>",
          "name": "sentinel-workspace"
        }
      ]
    },
    "dataFlows": [
      {
        "streams": ["Custom-CommonSecurityLog"],
        "destinations": ["sentinel-workspace"],
        "transformKql": "source",
        "outputStream": "Microsoft-CommonSecurityLog"
      }
    ]
  }
}
```

Deploy:

```bash
az monitor data-collection rule create \
  --name "dcr-cyberprobe-csl" \
  --resource-group "<YOUR_RG>" \
  --location "<YOUR_REGION>" \
  --rule-file dcr-csl-definition.json
```

Note the **`immutableId`** from the output — you'll need it as `--dcr-id`.

### Option B: Azure Portal

1. Go to **Monitor** → **Data Collection Rules** → **+ Create**
2. Name: `dcr-cyberprobe-csl`
3. Platform: **Custom**
4. Add Data Source: **Custom** → stream name `Custom-CommonSecurityLog`
5. Add Destination: your Log Analytics workspace
6. Set output stream: `Microsoft-CommonSecurityLog`
7. Transform: `source` (passthrough)

---

## Step 3: Assign Permissions

The identity running the script needs **Monitoring Metrics Publisher** role on the DCR:

```bash
# Get the DCR resource ID
DCR_ID=$(az monitor data-collection rule show \
  --name "dcr-cyberprobe-csl" \
  --resource-group "<YOUR_RG>" \
  --query "id" -o tsv)

# Assign role to your user or service principal
az role assignment create \
  --assignee "<YOUR_USER_OR_SP_OBJECT_ID>" \
  --role "Monitoring Metrics Publisher" \
  --scope "$DCR_ID"
```

---

## Step 4: Run the Script

### Generate file only (no Azure required)

```powershell
cd enrichment
python generate_csl_sample_data.py --output ../labs/sample-data/sample_csl_events.json --count 200 --days 7
```

### Send directly to Sentinel

```powershell
cd enrichment

# Authenticate (if not using managed identity)
az login

# Send 200 events
python generate_csl_sample_data.py --send \
  --dce-url "https://dce-cyberprobe-csl-XXXX.eastus-1.ingest.monitor.azure.com" \
  --dcr-id "dcr-XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX" \
  --stream "Custom-CommonSecurityLog" \
  --count 200 --days 7
```

### Both: save file AND send

```powershell
python generate_csl_sample_data.py \
  --output ../labs/sample-data/sample_csl_events.json \
  --send \
  --dce-url "https://dce-cyberprobe-csl-XXXX.eastus-1.ingest.monitor.azure.com" \
  --dcr-id "dcr-XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX" \
  --count 500 --days 14
```

---

## Step 5: Verify Data in Sentinel

After sending, wait 5-10 minutes for ingestion, then run:

```kql
CommonSecurityLog
| where TimeGenerated > ago(1h)
| summarize EventCount = count() by DeviceVendor, DeviceProduct, DeviceEventCategory
| order by EventCount desc
```

### Verify attack scenarios:

```kql
CommonSecurityLog
| where TimeGenerated > ago(1d)
| where DeviceCustomString1Label == "AttackScenario"
| summarize Count = count() by Scenario = DeviceCustomString1
| order by Count desc
```

---

## Troubleshooting

| Issue | Fix |
|-------|-----|
| `403 Forbidden` | Assign **Monitoring Metrics Publisher** role on the DCR |
| `404 Not Found` | Verify DCE URL and DCR immutable ID |
| `Stream not found` | Stream name in script must match DCR stream declaration exactly |
| `Schema mismatch` | DCR column types must match the JSON payload types |
| Data not appearing | Wait 5-10 min. Check DCR metrics in portal for ingestion errors |
| `azure.identity` error | Run `az login` or set `AZURE_CLIENT_ID` / `AZURE_TENANT_ID` / `AZURE_CLIENT_SECRET` |

---

## Cost Considerations

| Component | Cost |
|-----------|------|
| Data Collection Endpoint | Free |
| Data Collection Rule | Free |
| Log Analytics ingestion | ~$2.76/GB (pay-as-you-go) |
| 100 events (~50KB) | ~$0.0001 |
| 10,000 events (~5MB) | ~$0.014 |

For lab purposes, the cost is negligible.

---

## References

- [Logs Ingestion API overview](https://learn.microsoft.com/azure/azure-monitor/logs/logs-ingestion-api-overview)
- [Tutorial: Send data using Logs Ingestion API](https://learn.microsoft.com/azure/azure-monitor/logs/tutorial-logs-ingestion-portal)
- [DCR data sources](https://learn.microsoft.com/azure/azure-monitor/essentials/data-collection-rule-structure)
- [CommonSecurityLog schema reference](https://learn.microsoft.com/azure/azure-monitor/reference/tables/commonsecuritylog)

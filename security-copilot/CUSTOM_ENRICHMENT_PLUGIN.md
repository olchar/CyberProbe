# CyberProbe IP Enrichment Plugin for Security Copilot

## Overview
This document outlines how to create a custom Security Copilot plugin to integrate CyberProbe's IP enrichment capabilities (AbuseIPDB, IPInfo.io, VPNapi.io) with Security Copilot agents.

## Architecture

```
Security Copilot Agent
    ↓
Custom Plugin (CyberProbe.IPEnrichment)
    ↓
Azure Function / Logic App
    ↓
Python Enrichment Script (enrich_ips.py)
    ↓
External APIs (AbuseIPDB, IPInfo, VPNapi)
    ↓
Enriched Results → Agent
```

## Step 1: Create Azure Function Wrapper

### Azure Function (Python)
```python
# function_app.py
import azure.functions as func
import json
import subprocess
import os

app = func.FunctionApp()

@app.route(route="enrich-ip", methods=["POST"], auth_level=func.AuthLevel.FUNCTION)
def enrich_ip(req: func.HttpRequest) -> func.HttpResponse:
    """
    Enriches IP addresses using CyberProbe enrichment script
    """
    try:
        # Parse request
        req_body = req.get_json()
        ip_addresses = req_body.get('ipAddresses', [])
        
        if not ip_addresses:
            return func.HttpResponse(
                json.dumps({"error": "No IP addresses provided"}),
                status_code=400,
                mimetype="application/json"
            )
        
        # Run enrichment script
        script_path = os.path.join(os.path.dirname(__file__), 'enrich_ips.py')
        result = subprocess.run(
            ['python', script_path] + ip_addresses,
            capture_output=True,
            text=True
        )
        
        # Parse output
        enrichment_data = json.loads(result.stdout)
        
        return func.HttpResponse(
            json.dumps(enrichment_data),
            status_code=200,
            mimetype="application/json"
        )
        
    except Exception as e:
        return func.HttpResponse(
            json.dumps({"error": str(e)}),
            status_code=500,
            mimetype="application/json"
        )
```

### Environment Variables (local.settings.json)
```json
{
  "IsEncrypted": false,
  "Values": {
    "AzureWebJobsStorage": "",
    "FUNCTIONS_WORKER_RUNTIME": "python",
    "ABUSEIPDB_API_KEY": "your-abuseipdb-key",
    "IPINFO_TOKEN": "your-ipinfo-token",
    "VPNAPI_KEY": "your-vpnapi-key"
  }
}
```

## Step 2: Create OpenAPI Specification

```yaml
# openapi.yaml
openapi: 3.0.0
info:
  title: CyberProbe IP Enrichment API
  version: 1.0.0
  description: Enriches IP addresses with threat intelligence from AbuseIPDB, IPInfo, and VPNapi

servers:
  - url: https://your-function-app.azurewebsites.net/api
    description: Production Azure Function

paths:
  /enrich-ip:
    post:
      operationId: enrichIPAddress
      summary: Enrich IP addresses with threat intelligence
      description: |
        Enriches one or more IP addresses with:
        - AbuseIPDB abuse confidence score and report count
        - IPInfo.io geolocation, ISP, and organization details
        - VPNapi.io VPN/proxy/Tor detection
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              required:
                - ipAddresses
              properties:
                ipAddresses:
                  type: array
                  items:
                    type: string
                    format: ipv4
                  description: List of IPv4 addresses to enrich
                  example: ["213.209.159.181", "64.112.126.83"]
      responses:
        '200':
          description: Successfully enriched IP addresses
          content:
            application/json:
              schema:
                type: object
                properties:
                  results:
                    type: array
                    items:
                      type: object
                      properties:
                        ip:
                          type: string
                          description: IP address
                        abuseConfidence:
                          type: integer
                          description: AbuseIPDB confidence score (0-100)
                        totalReports:
                          type: integer
                          description: Total abuse reports
                        country:
                          type: string
                          description: Country code
                        city:
                          type: string
                          description: City name
                        isp:
                          type: string
                          description: ISP/Organization
                        isVpn:
                          type: boolean
                          description: VPN detected
                        isProxy:
                          type: boolean
                          description: Proxy detected
                        isTor:
                          type: boolean
                          description: Tor exit node
                        riskLevel:
                          type: string
                          enum: [CRITICAL, HIGH, MEDIUM, LOW, INFO]
                          description: Calculated risk level
        '400':
          description: Invalid request
        '500':
          description: Server error

security:
  - apiKey: []

components:
  securitySchemes:
    apiKey:
      type: apiKey
      in: header
      name: x-functions-key
```

## Step 3: Register Custom Plugin in Security Copilot

### Plugin Manifest (YAML)
```yaml
Descriptor:
  Name: CyberProbe.IPEnrichment
  DisplayName: CyberProbe IP Enrichment
  Description: Enriches IP addresses with AbuseIPDB, IPInfo.io, and VPNapi threat intelligence

SkillGroups:
  - Format: API
    Skills:
      - Name: EnrichIPAddresses
        DisplayName: Enrich IP Addresses with Threat Intelligence
        Description: |
          Enriches IP addresses using CyberProbe's multi-source threat intelligence:
          - AbuseIPDB: Abuse confidence score, total reports
          - IPInfo.io: Geolocation, ISP, organization
          - VPNapi.io: VPN/proxy/Tor detection
        Settings:
          OpenApiSpecUrl: https://your-function-app.azurewebsites.net/api/openapi.yaml
          AuthType: ApiKey
          AuthHeaderName: x-functions-key
```

## Step 4: Update Network Device Investigation Agent

Add the custom enrichment skill to the agent:

```yaml
# Updated agent with custom enrichment
SkillGroups:
  - Format: Agent
    Skills:
      - Name: NetworkDeviceInvestigationAgent
        DisplayName: Network Device Compromise Investigation Agent
        # ... existing config ...
        
        Settings:
          Instructions: |
            # Overall Mission & Persona
            You are a SOC investigation agent specializing in network device compromise.

            # Data Handling
            1. Use GetIncident and GetIncidentEntities to retrieve incident details.
            2. Extract all malicious IP addresses using ExtractIndicatorsOfCompromise.
            3. **Enrich IPs with CyberProbe enrichment (EnrichIPAddresses from CyberProbe.IPEnrichment)**
               - Provides AbuseIPDB confidence scores and report counts
               - Includes geolocation and ISP details from IPInfo.io
               - Detects VPN/proxy/Tor usage via VPNapi.io
            4. Map each IOC to MITRE ATT&CK techniques (T1071, T1204).
            5. Query Sentinel using NL2KQLDefenderSentinel for device correlation.
            # ... rest of instructions ...

        ChildSkills:
          - GetIncident
          - GetIncidentEntities
          - ExtractIndicatorsOfCompromise
          - CyberProbe.IPEnrichment/EnrichIPAddresses  # ← Custom enrichment
          - GetSummaryForIndicators  # ← Fallback to Microsoft TI
          - NL2KQLDefenderSentinel
          - SummarizeData
          - GenerateReportFromTemplate
```

## Step 5: Deployment Steps

### 1. Deploy Azure Function
```bash
# Install Azure Functions Core Tools
npm install -g azure-functions-core-tools@4

# Create function app
cd security-copilot/plugins/ip-enrichment
func init --python

# Deploy to Azure
func azure functionapp publish cyberprobe-enrichment
```

### 2. Configure API Keys
```bash
# Set environment variables in Azure
az functionapp config appsettings set \
  --name cyberprobe-enrichment \
  --resource-group cyberprobe-rg \
  --settings \
    ABUSEIPDB_API_KEY="your-key" \
    IPINFO_TOKEN="your-token" \
    VPNAPI_KEY="your-key"
```

### 3. Upload Plugin to Security Copilot
1. Navigate to **Security Copilot** → **Plugins**
2. Click **Upload custom plugin**
3. Upload `cyberprobe-ip-enrichment-plugin.yaml`
4. Configure authentication (provide Function Key)
5. Test plugin with sample IP

### 4. Update Agent Definition
1. Navigate to **Agents** → **Network Device Investigation Agent**
2. Edit agent definition
3. Add `CyberProbe.IPEnrichment/EnrichIPAddresses` to ChildSkills
4. Update instructions to use custom enrichment
5. Save and test

## Example Agent Execution Flow

```
User: "Investigate incident 42918"
   ↓
Agent: NetworkDeviceInvestigationAgent
   ↓
Step 1: GetIncident(42918)
   → Returns: TI Map IP Entity to DeviceNetworkEvents
   ↓
Step 2: ExtractIndicatorsOfCompromise
   → Finds: 213.209.159.181
   ↓
Step 3: CyberProbe.IPEnrichment/EnrichIPAddresses
   → Calls: Azure Function → enrich_ips.py → AbuseIPDB/IPInfo/VPNapi
   → Returns:
     {
       "ip": "213.209.159.181",
       "abuseConfidence": 100,
       "totalReports": 1955,
       "country": "DE",
       "city": "Aachen",
       "isp": "AS208137 Feo Prest SRL",
       "isVpn": false,
       "isProxy": false,
       "isTor": false,
       "riskLevel": "CRITICAL"
     }
   ↓
Step 4: NL2KQLDefenderSentinel
   → Query: DeviceNetworkEvents for 213.209.159.181
   → Finds: mb-wap.internal.niseko.alpineskihouse.co
   ↓
Step 5: GenerateReportFromTemplate
   → Produces: Executive report with enriched IOC data
```

## Benefits of Custom Plugin

✅ **Native Integration**
- Agent automatically calls CyberProbe enrichment
- No manual script execution required

✅ **Rich Threat Intelligence**
- AbuseIPDB: 100% confidence scores, historical reports
- IPInfo: Accurate geolocation, ISP/ASN details
- VPNapi: Anonymization detection

✅ **Consistent Workflow**
- Same enrichment data in automated and manual investigations
- Standardized JSON output format

✅ **Scalable**
- Azure Functions auto-scale for high-volume investigations
- Cached results reduce API costs

## Cost Considerations

### API Rate Limits
- **AbuseIPDB Free:** 1,000 requests/day
- **IPInfo Free:** 50,000 requests/month
- **VPNapi Free:** 1,000 requests/day

### Azure Function Costs
- **Consumption Plan:** ~$0.20 per million executions
- **First 1 million executions free** monthly

### Recommendation
For production, upgrade to paid API tiers:
- AbuseIPDB Pro: 100,000 requests/day ($20/month)
- IPInfo Business: Unlimited requests ($249/month)

## Testing the Plugin

### Test Request
```bash
curl -X POST https://cyberprobe-enrichment.azurewebsites.net/api/enrich-ip \
  -H "Content-Type: application/json" \
  -H "x-functions-key: YOUR_FUNCTION_KEY" \
  -d '{
    "ipAddresses": ["213.209.159.181", "64.112.126.83"]
  }'
```

### Expected Response
```json
{
  "results": [
    {
      "ip": "213.209.159.181",
      "abuseConfidence": 100,
      "totalReports": 1955,
      "country": "DE",
      "city": "Aachen",
      "isp": "AS208137 Feo Prest SRL",
      "isVpn": false,
      "isProxy": false,
      "isTor": false,
      "riskLevel": "CRITICAL"
    }
  ]
}
```

## Alternative: Logic Apps Implementation

If you prefer no-code, use Azure Logic Apps:

1. **Trigger:** HTTP Request (from Security Copilot)
2. **Action:** Run Python enrichment in Azure Container Instance
3. **Action:** Parse JSON results
4. **Action:** Return HTTP Response

## Next Steps

1. **Immediate:** Use hybrid approach (agent + manual scripts)
2. **Short-term:** Deploy Azure Function wrapper
3. **Long-term:** Create full custom plugin with OpenAPI spec

---

**Files to Create:**
- `security-copilot/plugins/ip-enrichment/function_app.py`
- `security-copilot/plugins/ip-enrichment/openapi.yaml`
- `security-copilot/plugins/cyberprobe-ip-enrichment-plugin.yaml`

**Updated Agent:**
- `security-copilot/agents/network-device-investigation-agent.yaml` (add custom skill)

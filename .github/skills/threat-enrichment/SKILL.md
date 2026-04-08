---
name: threat-enrichment
description: Enrich IP addresses with multi-source threat intelligence including AbuseIPDB, IPInfo, and VPNapi. Use when analyzing suspicious IPs, IOCs, or network indicators. Returns abuse confidence scores, geolocation, ISP details, and VPN detection.
---

# Threat Intelligence Enrichment Skill

This skill enriches IP addresses with threat intelligence from multiple external sources to assess risk and detect malicious infrastructure.

## When to Use This Skill

Use this skill when:
- Analyzing suspicious IP addresses from investigations
- Enriching IOCs (Indicators of Compromise)
- Assessing risk of external network connections
- Detecting VPN/proxy/anonymization services
- Validating geographic anomalies in authentication logs
- Investigating C2 (Command & Control) infrastructure

## Prerequisites

1. **API Keys Configured**: Verify `enrichment/config.json` contains valid API keys:
   - `abuseipdb_key` - AbuseIPDB API token
   - `ipinfo_key` - IPInfo.io API token
   - `vpnapi_key` - VPNapi.io API token

2. **Python Environment**: Virtual environment configured at `.venv/Scripts/python.exe`

3. **Script Location**: `enrichment/enrich_ips.py` exists and is executable

## Enrichment Workflow

### Basic Enrichment (Single IP)
```powershell
python enrichment/enrich_ips.py <IP_ADDRESS>
```

**Example:**
```powershell
python enrichment/enrich_ips.py 206.168.34.210
```

**Expected Output:**
```json
{
  "ip": "206.168.34.210",
  "abuse_confidence_score": 100,
  "total_reports": 1363,
  "country_code": "US",
  "city": "Chicago",
  "region": "Illinois",
  "is_public": true,
  "isp": "Censys Inc.",
  "usage_type": "Data Center/Web Hosting/Transit",
  "domain": null,
  "is_vpn": false,
  "is_tor": false,
  "is_proxy": false,
  "last_checked": "2026-01-14T21:30:45Z"
}
```

### Batch Enrichment (Multiple IPs)
```powershell
python enrichment/enrich_ips.py 206.168.34.210 45.155.205.233 192.0.2.1
```

**Processing:**
- Uses ThreadPoolExecutor with 3 concurrent workers
- Queries all 3 APIs in parallel per IP
- Merges results into unified JSON
- Exports to `enrichment/ip_enrichment_results.json`

### Investigation-Based Enrichment
When enriching IPs from an investigation JSON:

```powershell
python enrichment/enrich_ips.py --from-investigation reports/investigation_user_2026-01-15.json
```

**Process:**
1. Reads investigation JSON file
2. Extracts all unique IPs from `signInsByLocation`, `threatIntelligence`, `anomalies`
3. Enriches each IP
4. Merges results back into investigation JSON
5. Exports enriched data to `reports/ip_enrichment_<count>_ips_YYYY-MM-DD.json`

## Threat Intelligence Sources

### 1. AbuseIPDB
**Purpose**: Abuse confidence and reporting history

**Key Fields:**
- `abuseConfidenceScore` (0-100): Likelihood of malicious activity
- `totalReports`: Number of abuse reports
- `lastReportedAt`: Most recent report timestamp
- `categories`: Types of abuse (port scan, DDoS, brute force, etc.)

**Risk Levels:**
- **0-25**: Low risk (likely legitimate)
- **26-75**: Medium risk (investigate further)
- **76-100**: High risk (likely malicious)

**API Rate Limits:** 1,000 requests/day (free tier)

### 2. IPInfo
**Purpose**: Geolocation, ISP, and network details

**Key Fields:**
- `country`, `region`, `city`: Geographic location
- `loc`: Latitude/longitude coordinates
- `org`: Organization/ISP name
- `postal`: ZIP/postal code
- `timezone`: Local timezone

**Use Cases:**
- Validate geographic anomalies
- Detect impossible travel scenarios
- Identify hosting providers vs residential IPs
- Cross-reference with user's expected location

**API Rate Limits:** 50,000 requests/month (free tier)

### 3. VPNapi
**Purpose**: VPN/proxy/Tor detection

**Key Fields:**
- `security.vpn` (boolean): Is VPN endpoint
- `security.proxy` (boolean): Is proxy server
- `security.tor` (boolean): Is Tor exit node
- `security.relay` (boolean): Is relay server

**Risk Assessment:**
- VPN/Proxy detected + High abuse score = High risk
- VPN/Proxy detected + Low abuse score = Privacy user
- Tor detected = Always investigate (anonymization)

**API Rate Limits:** 1,000 requests/month (free tier)

## Risk Assessment Rules

Use this decision matrix to assess enrichment results:

| Abuse Score | VPN/Tor | ISP Type | Risk Level | Action |
|-------------|---------|----------|------------|--------|
| 90-100 | Any | Any | **Critical** | Block immediately, investigate |
| 75-89 | Yes | Datacenter | **High** | Investigate SessionId chain |
| 75-89 | No | Residential | **Medium** | Check user location history |
| 50-74 | Yes | Any | **Medium** | Review authentication pattern |
| 50-74 | No | Residential | **Low** | Monitor only |
| 0-49 | Yes | Any | **Low** | Likely privacy user |
| 0-49 | No | Residential | **Very Low** | Legitimate |

## Integration with Investigations

### After Phase 2 (Parallel Data Collection)
Extract priority IPs from investigation results:

```python
priority_ips = []
# From anomalies
priority_ips.extend([a['ipAddress'] for a in anomalies if a.get('ipAddress')])
# From risky sign-ins
priority_ips.extend([s['ipAddress'] for s in signIns if s.get('riskLevel') == 'high'])
# From threat intelligence
priority_ips.extend([t['networkIPv4'] for t in threatIntel if t.get('networkIPv4')])

unique_ips = list(set(priority_ips))
```

### Enrichment Execution
```powershell
python enrichment/enrich_ips.py {" ".join(unique_ips[:15])}
```

**Limit to 15 IPs** to avoid API rate limits and reduce processing time.

### Merge Results
```python
enrichment_results = read_file("enrichment/ip_enrichment_results.json")
investigation_data['ipEnrichment'] = enrichment_results
```

## Output Format

### Individual IP Result
```json
{
  "ip": "206.168.34.210",
  "abuse_confidence_score": 100,
  "total_reports": 1363,
  "country_code": "US",
  "city": "Chicago",
  "region": "Illinois",
  "is_public": true,
  "isp": "Censys Inc.",
  "usage_type": "Data Center/Web Hosting/Transit",
  "domain": null,
  "is_vpn": false,
  "is_tor": false,
  "is_proxy": false,
  "threat_categories": ["Port Scan", "Brute Force"],
  "last_reported": "2026-01-10T14:23:11Z",
  "last_checked": "2026-01-15T09:15:32Z"
}
```

### Batch Results File
```json
{
  "enrichment_date": "2026-01-15T09:15:32Z",
  "total_ips": 3,
  "high_risk_count": 1,
  "medium_risk_count": 1,
  "low_risk_count": 1,
  "results": [
    { /* IP 1 data */ },
    { /* IP 2 data */ },
    { /* IP 3 data */ }
  ]
}
```

## Error Handling

| Error | Cause | Action |
|-------|-------|--------|
| `API key missing` | config.json missing key | Add key to `enrichment/config.json` |
| `Rate limit exceeded` | Too many requests | Wait 24 hours or upgrade API tier |
| `Invalid IP format` | Malformed IP address | Validate IP format before enrichment |
| `API timeout` | Network/service issue | Retry with exponential backoff |
| `Partial enrichment` | One API failed | Export with available data, note error |

**Graceful Degradation:**
If one API fails, continue with other sources:
```json
{
  "ip": "1.2.3.4",
  "abuse_confidence_score": 50,
  "abuseipdb_error": "Rate limit exceeded",
  "country_code": "US",
  "is_vpn": false
}
```

## Performance Expectations

| Operation | IPs | Time | API Calls |
|-----------|-----|------|-----------|
| Single IP | 1 | ~2-3 sec | 3 |
| Batch (5 IPs) | 5 | ~5-8 sec | 15 |
| Batch (15 IPs) | 15 | ~15-25 sec | 45 |
| Investigation | 10-15 | ~20-30 sec | 30-45 |

**Concurrency**: 3 workers via ThreadPoolExecutor (configurable)

## Example Scenarios

### Scenario 1: Critical Incident Response
```
User: "Enrich IPs from incident #41272"

Response:
1. Get incident details (mcp_triage_GetIncidentById)
2. Extract IPs from alerts/entities
3. Run enrichment: python enrichment/enrich_ips.py <IP1> <IP2> <IP3>
4. Analyze results:
   - IP1: 100% abuse = CRITICAL, block immediately
   - IP2: 25% abuse + VPN = Privacy user, low risk
   - IP3: 0% abuse = Legitimate
5. Include in incident report with risk assessment
```

### Scenario 2: Geographic Anomaly Validation
```
User: "User logged in from Chicago then Paris 10 minutes later - investigate"

Response:
1. Extract both IPs from sign-in logs
2. Enrich both IPs
3. Check results:
   - Chicago IP: VPN=false, ISP=residential → Legitimate
   - Paris IP: VPN=true, ISP=datacenter → VPN session
4. Conclusion: SessionId-based forwarding, not impossible travel
```

### Scenario 3: Proactive Threat Hunting
```
User: "Find and enrich all high-risk IPs from last 24 hours"

Response:
1. Query Sentinel: SigninLogs | where RiskLevel == "high"
2. Extract unique IPs
3. Batch enrich (limit to 15 IPs)
4. Filter abuse_confidence_score >= 75
5. Generate summary report with recommendations
```

## Configuration Reference

### enrichment/config.json
```json
{
  "sentinel_workspace_id": "00000000-...",
  "tenant_id": "00000000-...",
  "api_keys": {
    "abuseipdb": "6a1efcd9bd...",
    "ipinfo": "a4a8be9afcba56",
    "vpnapi": "d520e365f..."
  },
  "settings": {
    "output_dir": "enrichment",
    "max_workers": 3,
    "timeout_seconds": 10
  }
}
```

## Resources

- [enrich_ips.py](../../../enrichment/enrich_ips.py) - Enrichment script source
- [config.json](../../../enrichment/config.json) - API configuration
- [AbuseIPDB Documentation](https://docs.abuseipdb.com/)
- [IPInfo Documentation](https://ipinfo.io/developers)
- [VPNapi Documentation](https://vpnapi.io/docs)

## Important Notes

⚠️ **Rate Limits**: Free tier limits = 1,000 AbuseIPDB/day, 50,000 IPInfo/month, 1,000 VPNapi/month
⚠️ **Privacy**: IP enrichment logs are stored locally, ensure compliance with data retention policies
⚠️ **False Positives**: VPN detection doesn't always indicate malicious activity - consider context
⚠️ **API Keys**: Store in config.json, NEVER commit to Git (use .gitignore)
⚠️ **Batch Limits**: Recommend max 15 IPs per enrichment to preserve API quotas

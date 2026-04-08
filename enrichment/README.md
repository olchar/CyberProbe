# Enrichment Scripts and Configuration

This directory contains threat intelligence enrichment scripts, configuration files, and integration tools for CyberProbe.

## Contents

### Scripts

| File | Description | Usage |
|------|-------------|-------|
| [enrich_ips.py](enrich_ips.py) | IP address enrichment with AbuseIPDB, IPInfo, VPNapi, Shodan | `python enrich_ips.py <ip1> <ip2> ...` |
| [enrich_iocs.py](enrich_iocs.py) | IOC enrichment for IPs, domains, hashes | `python enrich_iocs.py <ioc1> <ioc2> ...` |
| [powerbi_data_export.py](powerbi_data_export.py) | Export enrichment data for Power BI | `python powerbi_data_export.py` |
| [test_config.py](test_config.py) | Validate configuration file | `python test_config.py` |

### Configuration

| File | Description |
|------|-------------|
| [config.json](config.json) | Main configuration file — API keys, settings (gitignored) |
| [config.json.template](config.json.template) | Configuration template with placeholders for onboarding |
| [CONFIG.md](CONFIG.md) | Complete configuration documentation |

### Output

| Directory | Description |
|-----------|-------------|
| [reports/](reports/) | Enrichment JSON output files |

## Quick Start

### 1. Configure API Keys

Copy the template and fill in your keys:

```powershell
Copy-Item config.json.template config.json
```

Edit [config.json](config.json) and add your API keys:

```json
{
  "api_keys": {
    "abuseipdb": "YOUR_API_KEY",
    "ipinfo": "YOUR_TOKEN",
    "vpnapi": "YOUR_KEY",
    "shodan": "YOUR_KEY"
  }
}
```

See [CONFIG.md](CONFIG.md) for complete configuration guide.

### 2. Test Configuration

```powershell
.venv\Scripts\python.exe enrichment/test_config.py
```

### 3. Enrich IP Addresses

```powershell
# Single IP
.venv\Scripts\python.exe enrichment/enrich_ips.py 8.8.8.8

# Multiple IPs
.venv\Scripts\python.exe enrichment/enrich_ips.py 213.209.159.181 64.112.126.83 150.40.179.15
```

### 4. View Results

```powershell
# View JSON output
Get-Content reports/ip_enrichment_3_ips.json | ConvertFrom-Json | Format-List

# View in browser (HTML reports in ../reports/)
```

## Enrichment Sources

### Currently Active (6 sources)

| Source | Cost | Rate Limit | Purpose |
|--------|------|------------|---------|
| **AbuseIPDB** | FREE | 1,000/day | IP abuse confidence scoring |
| **IPInfo** | FREE | 50,000/month | Geolocation, ASN data |
| **VPNapi** | FREE | 1,000/day | VPN/Proxy/Tor detection |
| **VirusTotal** | FREE | 4 req/min | Multi-engine malware scanning |
| **GreyNoise** | FREE | 10,000/month | Internet scanner classification |
| **Shodan** | PAID | Unlimited | Internet device scanning ($59/month) |

### Recommended FREE Additions

See [CONFIG.md](CONFIG.md#recommended-free-sources-to-add) for:
- **AlienVault OTX** (Community threat intel, MITRE ATT&CK)
- **ThreatFox** (Recent C2 servers, no API key)
- **MalwareBazaar** (Malware hash repository, no API key)
- **URLhaus** (Malware distribution URLs, no API key)

## Output Format

Enrichment results are saved as JSON files in `reports/` directory:

```json
{
  "value": [
    {
      "ip": "213.209.159.181",
      "city": "Aachen",
      "country": "DE",
      "org": "AS208137 Feo Prest SRL",
      "abuse_confidence_score": 100,
      "total_reports": 1981,
      "is_vpn": false,
      "is_whitelisted": false,
      "shodan_ports": [22, 80, 443],
      "shodan_vulns": ["CVE-2023-1234"],
      "shodan_tags": ["cloud"]
    }
  ]
}
```

## Script Details

### enrich_ips.py

**Purpose:** Enrich IP addresses with threat intelligence from multiple sources.

**Features:**
- Multi-source aggregation (AbuseIPDB, IPInfo, VPNapi, Shodan)
- Shodan integration: open ports, CVEs, service tags (with free InternetDB fallback)
- Abuse confidence scoring
- VPN/Proxy/Tor detection
- Geolocation with city-level accuracy
- ASN and ISP identification
- Whitelisting support

**Output:** JSON file in `reports/ip_enrichment_N_ips.json`

**Example:**
```powershell
.venv\Scripts\python.exe enrichment/enrich_ips.py 213.209.159.181
```

### enrich_iocs.py

**Purpose:** Enrich indicators of compromise (IPs, domains, file hashes).

**Supported IOC Types:**
- IP addresses (IPv4)
- Domains
- File hashes (MD5, SHA1, SHA256)
- URLs

**Output:** JSON file in `reports/ioc_enrichment_YYYYMMDD_HHMMSS.json`

### powerbi_data_export.py

**Purpose:** Export enrichment data in Power BI compatible format.

**Features:**
- Aggregates multiple enrichment results
- Formats data for Power BI ingestion
- Generates CSV and JSON outputs

**Output:** `../powerbi/data/enrichment_export.csv`

### test_config.py

**Purpose:** Validate configuration file and display settings.

**Output:**
- JSON validation status
- Active API keys count
- Recommended sources to add
- Risk scoring weights verification
- Workspace configuration

## Integration

### Security Copilot

Enrichment can be integrated with Security Copilot agents via custom plugin. See:
- [../security-copilot/CUSTOM_ENRICHMENT_PLUGIN.md](../security-copilot/CUSTOM_ENRICHMENT_PLUGIN.md)

### Power BI

Export enrichment data for visualization:
```powershell
.venv\Scripts\python.exe enrichment/powerbi_data_export.py
```

See [../powerbi/POWERBI_DASHBOARD_SETUP.md](../powerbi/POWERBI_DASHBOARD_SETUP.md)

### Microsoft Sentinel

Enrichment results can be ingested into Sentinel via:
1. **Logic Apps** - Automated enrichment playbooks
2. **Custom Logs** - Upload JSON to Log Analytics
3. **Sentinel Playbooks** - Trigger enrichment from alerts

## Troubleshooting

### "API key invalid"

**Solution:** Verify API key in config.json and test directly:
```powershell
curl "https://api.abuseipdb.com/api/v2/check?ipAddress=8.8.8.8" `
  -H "Key: YOUR_API_KEY"
```

### "Rate limit exceeded"

**Solutions:**
- Enable caching: `"cache_enabled": true` in config.json
- Increase cache TTL: `"cache_ttl_hours": 48`
- Upgrade to paid tier

### "No module named 'requests'"

**Solution:** Install dependencies:
```powershell
.venv\Scripts\pip install -r requirements.txt
```

### "JSON parsing error"

**Solution:** Validate config.json:
```powershell
python -c "import json; json.load(open('enrichment/config.json', encoding='utf-8'))"
```

## Best Practices

### 1. Use Caching

Enable caching to avoid hitting rate limits:
```json
{
  "settings": {
    "cache_enabled": true,
    "cache_ttl_hours": 24
  }
}
```

### 2. Batch Processing

Process multiple IPs in one command:
```powershell
.venv\Scripts\python.exe enrichment/enrich_ips.py $(Get-Content ips.txt)
```

### 3. Secure API Keys

- Never commit config.json to Git
- Use environment variables for production
- Rotate keys every 90 days

### 4. Monitor Rate Limits

Check API usage:
- AbuseIPDB: [abuseipdb.com/account](https://www.abuseipdb.com/account)
- IPInfo: [ipinfo.io/account](https://ipinfo.io/account)
- GreyNoise: [greynoise.io/account](https://www.greynoise.io/account)

## Related Documentation

- **Configuration Guide:** [CONFIG.md](CONFIG.md)
- **Investigation Guide:** [../Investigation-Guide.md](../Investigation-Guide.md)
- **Security Copilot Plugin:** [../security-copilot/CUSTOM_ENRICHMENT_PLUGIN.md](../security-copilot/CUSTOM_ENRICHMENT_PLUGIN.md)
- **Power BI Integration:** [../powerbi/POWERBI_DASHBOARD_SETUP.md](../powerbi/POWERBI_DASHBOARD_SETUP.md)

## Examples

### Example 1: Single IP Enrichment

```powershell
.venv\Scripts\python.exe enrichment/enrich_ips.py 213.209.159.181
```

**Output:**
```
Enriching 1 IPs using ipinfo.io, vpnapi.io, AbuseIPDB, Shodan...
  OK 213.209.159.181   [Abuse:100%]

IP: 213.209.159.181
City: Aachen
Country: DE
ISP/Org: AS208137 Feo Prest SRL
Abuse Confidence: 100%
Total Reports: 1,981
Risk: CRITICAL

Results saved to: reports\ip_enrichment_1_ips.json
```

### Example 2: Batch Enrichment

```powershell
# Create IP list
@"
213.209.159.181
64.112.126.83
150.40.179.15
"@ | Out-File -Encoding utf8 ips.txt

# Enrich all IPs
.venv\Scripts\python.exe enrichment/enrich_ips.py $(Get-Content ips.txt)
```

### Example 3: Automated Investigation

```powershell
# Extract IPs from Defender incident, enrich, and generate report
$ips = Get-DefenderIncidentIPs -IncidentId 42918
.venv\Scripts\python.exe enrichment/enrich_ips.py $ips
```

---

**Last Updated:** February 18, 2026  
**Maintainer:** CyberProbe Security Team

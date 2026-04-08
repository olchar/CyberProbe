# CyberProbe Configuration Guide

## Overview

The `config.json` file is the central configuration file for CyberProbe's threat intelligence enrichment system. It manages API credentials, enrichment sources, risk scoring weights, and operational settings.

**Location:** `enrichment/config.json` (gitignored — never committed)

**Template:** `enrichment/config.json.template` (committed with placeholder values)

**Quick Start:** Copy the template and fill in your keys:
```powershell
Copy-Item enrichment/config.json.template enrichment/config.json
```

## File Structure

```json
{
  "sentinel_workspace_id": "...",
  "tenant_id": "...",
  "domain": "...",
  "api_keys": { ... },
  "settings": { ... },
  "_integration_urls": { ... }
}
```

## Configuration Sections

### 1. Workspace Configuration

```json
{
  "sentinel_workspace_id": "YOUR_SENTINEL_WORKSPACE_GUID",
  "tenant_id": "YOUR_ENTRA_TENANT_GUID",
  "domain": "YOUR_DOMAIN.COM"
}
```

| Field | Description | Required | How to Find |
|-------|-------------|----------|-------------|
| `sentinel_workspace_id` | Microsoft Sentinel Log Analytics Workspace GUID | Yes | Azure Portal → Log Analytics workspace → Properties → Workspace ID |
| `tenant_id` | Microsoft Entra ID Tenant GUID | Yes | Azure Portal → Entra ID → Overview → Tenant ID |
| `domain` | Your organization’s primary Entra domain | Yes | Azure Portal → Entra ID → Overview → Primary domain (e.g., `contoso.com`) |

---

### 2. API Keys Section

The `api_keys` section contains credentials for all threat intelligence sources. Keys starting with underscore (`_`) are comments/documentation and are ignored by the enrichment scripts.

#### Currently Active Sources (6)

```json
{
  "api_keys": {
    "virustotal": "YOUR_VT_API_KEY",
    "abuseipdb": "YOUR_ABUSEIPDB_API_KEY",
    "shodan": "YOUR_SHODAN_API_KEY",
    "greynoise": "YOUR_GREYNOISE_API_KEY",
    "ipinfo": "YOUR_IPINFO_TOKEN",
    "vpnapi": "YOUR_VPNAPI_KEY"
  }
}
```

| Source | Cost | Rate Limit | Purpose | Signup |
|--------|------|------------|---------|--------|
| **virustotal** | FREE | 4 req/min | Multi-engine malware scanning | [virustotal.com/gui/join-us](https://www.virustotal.com/gui/join-us) |
| **abuseipdb** | FREE | 1,000/day | IP abuse confidence scoring | [abuseipdb.com/register](https://www.abuseipdb.com/register) |
| **shodan** | PAID | Unlimited | Internet device scanning | [account.shodan.io](https://account.shodan.io/billing) ($59/month) |
| **greynoise** | FREE | 10,000/month | Internet scanner classification | [greynoise.io/plans/free](https://www.greynoise.io/plans/free) |
| **ipinfo** | FREE | 50,000/month | IP geolocation & ASN data | [ipinfo.io/signup](https://ipinfo.io/signup) |
| **vpnapi** | FREE | 1,000/day | VPN/Proxy/Tor detection | [vpnapi.io/pricing](https://vpnapi.io/pricing) |

#### Recommended FREE Sources to Add

These sources provide high-value threat intelligence at no cost:

##### No API Key Required (4 sources)

```json
{
  "_threatfox": "NO_KEY_NEEDED",
  "_malwarebazaar": "NO_KEY_NEEDED",
  "_urlhaus": "NO_KEY_NEEDED",
  "_spamhaus_zen": "NO_KEY_NEEDED"
}
```

| Source | Purpose | API Endpoint |
|--------|---------|-------------|
| **threatfox** | Recent C2 servers, malware families | [threatfox-api.abuse.ch/api/v1/](https://threatfox-api.abuse.ch/api/v1/) |
| **malwarebazaar** | Malware hash repository, Yara rules | [mb-api.abuse.ch/api/v1/](https://mb-api.abuse.ch/api/v1/) |
| **urlhaus** | Malware distribution URLs | [urlhaus-api.abuse.ch/v1/](https://urlhaus-api.abuse.ch/v1/) |
| **spamhaus_zen** | Spam/malware IP reputation (DNS) | zen.spamhaus.org |

##### Free API Key Required (5 sources)

```json
{
  "_alienvault_otx": "YOUR_OTX_API_KEY_HERE",
  "_hybrid_analysis": "YOUR_HYBRID_ANALYSIS_KEY",
  "_urlscan": "YOUR_URLSCAN_KEY",
  "_censys": "YOUR_CENSYS_API_ID:YOUR_CENSYS_SECRET",
  "_phishtank": "YOUR_PHISHTANK_KEY"
}
```

| Source | Free Tier | Paid Tier | Purpose | Signup |
|--------|-----------|-----------|---------|--------|
| **alienvault_otx** ⭐ | Unlimited | N/A | Community threat intel, MITRE ATT&CK | [otx.alienvault.com/api](https://otx.alienvault.com/api) |
| **hybrid_analysis** | 200 scans/month | $99/month | Malware sandbox, behavior analysis | [hybrid-analysis.com](https://hybrid-analysis.com/apikeys/info) |
| **urlscan** | 100 scans/day | $50/month | Website analysis, phishing detection | [urlscan.io](https://urlscan.io/user/profile/) |
| **censys** | 250 queries/month | $99/month | Internet-wide device scanning | [censys.io](https://censys.io/account/api) |
| **phishtank** | Basic access | Enhanced | Phishing URL validation | [phishtank.com](https://www.phishtank.com/api_info.php) |

⭐ **Highly Recommended** - AlienVault OTX provides 80M+ IOCs with MITRE ATT&CK mapping at no cost.

#### Enterprise Sources

```json
{
  "_recorded_future": "YOUR_RECORDED_FUTURE_TOKEN",
  "_crowdstrike_intel": "YOUR_CROWDSTRIKE_CLIENT_ID:YOUR_CROWDSTRIKE_SECRET",
  "_anomali": "YOUR_ANOMALI_API_KEY"
}
```

These require enterprise contracts with custom pricing ($3,000+/month).

---

### 3. Settings Section

```json
{
  "settings": {
    "timeout": 30,
    "max_retries": 3,
    "cache_enabled": true,
    "cache_ttl_hours": 24,
    "output_dir": "reports",
    "enabled_sources": [
      "abuseipdb",
      "ipinfo",
      "vpnapi",
      "virustotal",
      "greynoise",
      "shodan"
    ]
  }
}
```

| Setting | Default | Description |
|---------|---------|-------------|
| `timeout` | 30 | API request timeout in seconds |
| `max_retries` | 3 | Number of retry attempts for failed API calls |
| `cache_enabled` | true | Enable caching of enrichment results |
| `cache_ttl_hours` | 24 | Cache time-to-live in hours |
| `output_dir` | "reports" | Directory for enrichment output files |
| `enabled_sources` | Array | List of active enrichment sources |

#### Risk Scoring Weights

```json
{
  "_risk_scoring_weights": {
    "abuseipdb": 0.35,
    "alienvault_otx": 0.20,
    "threatfox": 0.20,
    "greynoise": 0.15,
    "virustotal": 0.10
  }
}
```

Weights determine how each source contributes to the aggregate risk score. **Must sum to 1.0 (100%)**.

| Source | Weight | Contribution |
|--------|--------|--------------|
| AbuseIPDB | 35% | Primary IP reputation source |
| AlienVault OTX | 20% | Community threat intelligence |
| ThreatFox | 20% | Recent C2 infrastructure |
| GreyNoise | 15% | Internet scanner classification |
| VirusTotal | 10% | Multi-engine validation |

**Example Calculation:**
- IP has AbuseIPDB confidence: 100%
- IP found in ThreatFox: Yes (100%)
- Aggregate Risk = (100 × 0.35) + (100 × 0.20) = 55% risk score

---

### 4. Integration URLs Section

Contains documentation links and signup information for all supported sources.

```json
{
  "_integration_urls": {
    "alienvault_otx": {
      "signup": "https://otx.alienvault.com/api",
      "docs": "https://otx.alienvault.com/api",
      "cost": "FREE - Unlimited",
      "value": "Community threat intel, 80M+ IOCs, MITRE ATT&CK mapping"
    }
  }
}
```

**Purpose:** Quick reference for API documentation and registration during setup.

---

## Usage Guide

### Adding a New Free Source

**Example: Adding AlienVault OTX**

1. **Sign up:** Visit [otx.alienvault.com/api](https://otx.alienvault.com/api)
2. **Get API Key:** Navigate to Settings → API Integration
3. **Update config.json:**
   ```json
   {
     "api_keys": {
       "alienvault_otx": "YOUR_ACTUAL_API_KEY_HERE"
     }
   }
   ```
   (Remove the leading underscore from `_alienvault_otx`)

4. **Enable in settings:**
   ```json
   {
     "settings": {
       "enabled_sources": [
         "abuseipdb",
         "ipinfo",
         "vpnapi",
         "alienvault_otx"  // Add here
       ]
     }
   }
   ```

5. **Test configuration:**
   ```powershell
   .venv\Scripts\python.exe enrichment/test_config.py
   ```

### Removing a Paid Source

**Example: Removing Shodan**

1. **Remove from enabled sources:**
   ```json
   {
     "settings": {
       "enabled_sources": [
         "abuseipdb",
         "ipinfo",
         "vpnapi",
         // "shodan"  // Commented out or removed
       ]
     }
   }
   ```

2. **Optional:** Comment out the API key to preserve it:
   ```json
   {
     "api_keys": {
       "_shodan_backup": "YOUR_SHODAN_API_KEY_BACKUP"
---

## Comment Conventions

Keys starting with underscore (`_`) are comments and ignored by scripts:

```json
{
  "_comment_section": "This is a documentation comment",
  "actual_setting": "This is used by scripts"
}
```

**Common comment prefixes:**
- `_comment_`: General documentation
- `_comment_free_`: Free tier sources
- `_comment_paid_`: Paid sources
- `_recommended_`: Recommended additions

---

## Security Best Practices

### 1. **Never Commit API Keys to Git**

Add to `.gitignore` (already configured):
```gitignore
enrichment/config.json
enrichment/config.local.json
```

### 2. **Use Environment Variables (Alternative)**

```bash
export ABUSEIPDB_API_KEY="your_key_here"
export IPINFO_TOKEN="your_token_here"
```

Update enrichment scripts to read from environment:
```python
import os
api_key = os.getenv('ABUSEIPDB_API_KEY') or config['api_keys']['abuseipdb']
```

### 3. **Use Azure Key Vault (Production)**

For enterprise deployments, store API keys in Azure Key Vault:

```python
from azure.keyvault.secrets import SecretClient
from azure.identity import DefaultAzureCredential

vault_url = "https://cyberprobe-keyvault.vault.azure.net/"
client = SecretClient(vault_url=vault_url, credential=DefaultAzureCredential())
abuseipdb_key = client.get_secret("abuseipdb-api-key").value
```

### 4. **Rotate Keys Regularly**

- Rotate API keys every 90 days
- Document rotation dates in comments:
  ```json
  {
    "_abuseipdb_rotated": "2026-01-28",
    "abuseipdb": "new_key_here"
  }
  ```

---

## Troubleshooting

### Issue: "JSON parsing error"

**Solution:** Validate JSON syntax
```powershell
python -c "import json; json.load(open('enrichment/config.json', encoding='utf-8'))"
```

Common causes:
- Missing commas between elements
- Trailing commas in arrays/objects
- Unescaped quotes in strings
- Unicode characters (use UTF-8 encoding)

### Issue: "API key invalid"

**Solution:** Verify key format and test directly
```powershell
# Test AbuseIPDB key
curl "https://api.abuseipdb.com/api/v2/check?ipAddress=8.8.8.8" `
  -H "Key: YOUR_API_KEY" -H "Accept: application/json"
```

### Issue: "Rate limit exceeded"

**Solutions:**
1. Enable caching: `"cache_enabled": true`
2. Increase cache TTL: `"cache_ttl_hours": 48`
3. Reduce enabled sources temporarily
4. Upgrade to paid tier for higher limits

### Issue: "Source not enriching"

**Check:**
1. Source is in `enabled_sources` array
2. API key is correct (no leading/trailing spaces)
3. API key doesn't have underscore prefix
4. Network connectivity to API endpoint

---

## Configuration Templates

### Minimal Configuration (Free Only)

```json
{
  "sentinel_workspace_id": "YOUR_WORKSPACE_ID",
  "tenant_id": "YOUR_TENANT_ID",
  "api_keys": {
    "abuseipdb": "YOUR_ABUSEIPDB_KEY",
    "ipinfo": "YOUR_IPINFO_TOKEN",
    "vpnapi": "YOUR_VPNAPI_KEY"
  },
  "settings": {
    "timeout": 30,
    "max_retries": 3,
    "cache_enabled": true,
    "cache_ttl_hours": 24,
    "output_dir": "reports",
    "enabled_sources": ["abuseipdb", "ipinfo", "vpnapi"]
  }
}
```

### Recommended Configuration (Free + No-Key Sources)

Add ThreatFox, MalwareBazaar, URLhaus to enrichment script logic (no config changes needed since they don't require keys).

### Enterprise Configuration

```json
{
  "enabled_sources": [
    "abuseipdb",
    "ipinfo",
    "virustotal",
    "greynoise",
    "shodan",
    "alienvault_otx",
    "threatfox",
    "recorded_future",
    "crowdstrike_intel"
  ],
  "_risk_scoring_weights": {
    "abuseipdb": 0.25,
    "alienvault_otx": 0.15,
    "threatfox": 0.15,
    "recorded_future": 0.20,
    "crowdstrike_intel": 0.15,
    "virustotal": 0.10
  }
}
```

---

## Related Files

| File | Purpose |
|------|---------|
| `enrichment/config.json` | Main configuration file (this document) |
| `enrichment/test_config.py` | Configuration validation script |
| `enrichment/enrich_ips.py` | IP enrichment script |
| `enrichment/enrich_iocs.py` | IOC enrichment script |
| `enrichment/mcp.json` | MCP server configuration |
| `reports/` | Enrichment output directory |

---

## Version History

| Date | Version | Changes |
|------|---------|---------|| 2026-02-18 | 1.2 | Added config.json.template, removed PII, Shodan InternetDB fallback || 2026-01-28 | 1.1 | Added free source recommendations, risk scoring weights |
| 2026-01-27 | 1.0 | Initial configuration with 6 active sources |

---

## Support & Documentation

- **CyberProbe Documentation:** [Investigation-Guide.md](../Investigation-Guide.md)
- **Enrichment Setup:** [Custom Enrichment Plugin Guide](../security-copilot/CUSTOM_ENRICHMENT_PLUGIN.md)
- **Report Issues:** Create issue in project repository

---

**Last Updated:** February 18, 2026  
**Maintainer:** CyberProbe Security Team

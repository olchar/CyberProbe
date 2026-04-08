---
name: ioc-management
description: Extract, enrich, deduplicate, and track indicators of compromise (IOCs) across investigations. Manage watchlists, correlate IOCs across incidents, and automate threat intelligence workflows. Use for building threat intel feeds, tracking threat actor infrastructure, and IOC lifecycle management.
---

# IOC Management Skill

This skill enables comprehensive management of Indicators of Compromise (IOCs) including extraction, enrichment, correlation, and lifecycle tracking.

## Time Window Strategy for IOC Operations

**Active Incident Response (Use 24 hours):**
- Extract IOCs from ongoing incidents
- Quick threat validation
- Immediate watchlist updates
- Query time: ~5-15 seconds

**Campaign Investigation (Use 7 days):**
- IOC correlation across multiple incidents
- Pattern-based IOC discovery
- Threat actor infrastructure mapping
- Query time: ~30-60 seconds

**Threat Intelligence Building (Use 30 days):**
- Historical IOC tracking
- Confidence decay calculations
- Long-term watchlist management
- Query time: ~2-5 minutes

**APT Tracking (Use 90+ days):**
- Complete infrastructure timeline
- Advanced persistent threat analysis
- Domain registration correlation
- Query time: ~5-15 minutes

## When to Use This Skill

Use this skill when:
- Extracting IOCs from security incidents and alerts
- Building threat intelligence feeds
- Creating and maintaining watchlists (known-bad, known-good)
- Correlating IOCs across multiple investigations
- Tracking threat actor infrastructure over time
- Automating bulk enrichment workflows
- Managing IOC expiration and aging
- Creating block lists for automated response
- Identifying IOC patterns and relationships
- Exporting IOCs for SIEM/SOAR integration

## Prerequisites

1. **Enrichment Environment**: Python virtual environment with threat intelligence APIs configured
2. **API Keys**: AbuseIPDB, IPInfo, VPNapi, VirusTotal tokens in `enrichment/config.json`
3. **Storage**: Directory structure for IOC storage (`enrichment/ioc-database/`)
4. **MCP Tools**: Access to Defender XDR tools for IOC queries

## IOC Types Supported

- **IP Addresses** (IPv4, IPv6)
- **Domains** (FQDNs, subdomains)
- **URLs** (HTTP/HTTPS endpoints)
- **File Hashes** (MD5, SHA1, SHA256)
- **Email Addresses** (attacker infrastructure)
- **User Agents** (malicious browser strings)
- **Registry Keys** (persistence mechanisms)
- **Certificates** (malicious SSL/TLS certs)

---

## IOC Extraction Workflows

### Phase 1: Extract IOCs from Incidents

#### Step 1.1: Extract IPs from Incident
```kql
let incidentNumber = "<INCIDENT_NUMBER>";

SecurityIncident
| where IncidentNumber == incidentNumber
| extend AlertIds = parse_json(AlertIds)
| mv-expand AlertId = AlertIds
| join kind=inner (
    SecurityAlert
    | extend Entities = parse_json(Entities)
    | mv-expand Entity = Entities
    | where Entity.Type == "ip"
    | project 
        SystemAlertId,
        IP = tostring(Entity.Address),
        EntityType = "IP"
) on $left.AlertId == $right.SystemAlertId
| distinct IP
| project IOC = IP, IOCType = "IP", Source = strcat("Incident #", incidentNumber)
```

#### Step 1.2: Extract File Hashes from Incident
```kql
SecurityIncident
| where IncidentNumber == "<INCIDENT_NUMBER>"
| extend AlertIds = parse_json(AlertIds)
| mv-expand AlertId = AlertIds
| join kind=inner (
    SecurityAlert
    | extend Entities = parse_json(Entities)
    | mv-expand Entity = Entities
    | where Entity.Type == "file"
    | extend FileHashes = Entity.FileHashes
    | mv-expand Hash = FileHashes
    | project 
        SystemAlertId,
        FileHash = tostring(Hash.Value),
        HashAlgorithm = tostring(Hash.Algorithm),
        FileName = tostring(Entity.Name)
) on $left.AlertId == $right.SystemAlertId
| where HashAlgorithm == "SHA256"
| distinct FileHash, FileName
| project IOC = FileHash, IOCType = "FileHash", FileName
```

#### Step 1.3: Extract Domains and URLs
```kql
SecurityAlert
| where TimeGenerated > ago(7d)
| extend Entities = parse_json(Entities)
| mv-expand Entity = Entities
| where Entity.Type in ("url", "dns")
| project 
    AlertName,
    IOC = tostring(coalesce(Entity.Url, Entity.DomainName)),
    IOCType = case(Entity.Type == "url", "URL", "Domain"),
    TimeGenerated
| distinct IOC, IOCType, AlertName
```

#### Step 1.4: Automated IOC Extraction from Multiple Incidents
```kql
let startDate = datetime(<StartDate>);
let endDate = datetime(<EndDate>);

SecurityIncident
| where CreatedTime between (startDate .. endDate)
| extend AlertIds = parse_json(AlertIds)
| mv-expand AlertId = AlertIds
| join kind=inner (
    SecurityAlert
    | extend Entities = parse_json(Entities)
    | mv-expand Entity = Entities
    | where Entity.Type in ("ip", "file", "url", "dns")
    | project 
        SystemAlertId,
        EntityType = tostring(Entity.Type),
        IOC_Value = coalesce(
            tostring(Entity.Address),           // IP
            tostring(Entity.FileHashes[0].Value), // File hash
            tostring(Entity.Url),                 // URL
            tostring(Entity.DomainName)           // Domain
        )
) on $left.AlertId == $right.SystemAlertId
| where isnotempty(IOC_Value)
| summarize 
    IncidentCount = dcount(IncidentNumber),
    Incidents = make_set(IncidentNumber),
    FirstSeen = min(CreatedTime),
    LastSeen = max(CreatedTime)
    by IOC_Value, EntityType
| project 
    IOC = IOC_Value,
    Type = EntityType,
    Incidents = array_length(Incidents),
    IncidentNumbers = Incidents,
    FirstSeen,
    LastSeen
| order by Incidents desc
```

**Export to JSON for enrichment:**
```python
# Save extracted IOCs to JSON for bulk enrichment
import json

iocs = {
    "ips": ["109.70.100.7", "176.65.134.8"],
    "domains": ["malicious.example.com"],
    "file_hashes": ["abc123..."],
    "urls": ["http://evil.com/payload.exe"]
}

with open('enrichment/ioc-database/extracted_iocs.json', 'w') as f:
    json.dump(iocs, f, indent=2)
```

---

### Phase 2: Bulk IOC Enrichment

#### Step 2.1: Enrich Extracted IPs
```powershell
# Using the wrapper script for IP enrichment
$ips = Get-Content enrichment/ioc-database/extracted_ips.txt
.\run-enrichment.ps1 @ips
```

**Alternative - Python script:**
```python
# enrichment/enrich_iocs.py
import json
from enrich_ips import enrich_single_ip

with open('enrichment/ioc-database/extracted_iocs.json', 'r') as f:
    iocs = json.load(f)

enriched_data = {
    "timestamp": datetime.now().isoformat(),
    "ips": []
}

for ip in iocs.get('ips', []):
    result = enrich_single_ip(ip)
    enriched_data['ips'].append(result)

# Save enriched results
with open('enrichment/ioc-database/enriched_iocs.json', 'w') as f:
    json.dump(enriched_data, f, indent=2)
```

#### Step 2.2: Get File Reputation from Defender
```
mcp_triage_GetDefenderFileInfo(fileHash="<SHA256>")
```

**Returns:**
- File name and size
- Digital signature information
- Global prevalence (how many organizations seen)
- First/last seen dates
- Threat classification

#### Step 2.3: Domain/URL Analysis
```kql
// Query Sentinel threat intelligence
ThreatIntelligenceIndicator
| where TimeGenerated > ago(30d)
| where DomainName in ("<DOMAIN1>", "<DOMAIN2>")
| project 
    DomainName,
    ThreatType,
    Confidence,
    Description,
    ThreatSeverity,
    FirstSeen = TimeGenerated,
    ExpirationDateTime
```

---

### Phase 3: IOC Deduplication & Normalization

#### Step 3.1: IP Address Normalization
```python
import ipaddress

def normalize_ip(ip_str):
    """Convert IP to canonical format"""
    try:
        ip = ipaddress.ip_address(ip_str.strip())
        return str(ip)  # Removes leading zeros, standardizes format
    except ValueError:
        return None

# Example usage
raw_ips = ["192.168.001.001", "192.168.1.1", "::1"]
normalized = [normalize_ip(ip) for ip in raw_ips]
unique_ips = list(set(filter(None, normalized)))
```

#### Step 3.2: Domain Normalization
```python
def normalize_domain(domain):
    """Standardize domain format"""
    domain = domain.lower().strip()
    domain = domain.removeprefix('http://').removeprefix('https://')
    domain = domain.removeprefix('www.')
    domain = domain.split('/')[0]  # Remove path
    domain = domain.split(':')[0]  # Remove port
    return domain

# Example
normalize_domain("HTTP://WWW.EXAMPLE.COM:443/path") # -> "example.com"
```

#### Step 3.3: Hash Normalization
```python
def normalize_hash(hash_str, hash_type="sha256"):
    """Standardize file hash format"""
    hash_str = hash_str.upper().strip()
    
    expected_lengths = {
        "md5": 32,
        "sha1": 40,
        "sha256": 64
    }
    
    if len(hash_str) != expected_lengths.get(hash_type.lower()):
        return None
    
    return hash_str
```

#### Step 3.4: Remove Duplicates Across Sources
```python
import json
from datetime import datetime

def deduplicate_iocs(ioc_files):
    """Merge and deduplicate IOCs from multiple investigations"""
    all_iocs = {}
    
    for file_path in ioc_files:
        with open(file_path, 'r') as f:
            data = json.load(f)
            
        for ioc_type in ['ips', 'domains', 'file_hashes']:
            if ioc_type not in all_iocs:
                all_iocs[ioc_type] = {}
            
            for ioc in data.get(ioc_type, []):
                ioc_value = ioc if isinstance(ioc, str) else ioc.get('value')
                
                if ioc_value not in all_iocs[ioc_type]:
                    all_iocs[ioc_type][ioc_value] = {
                        'value': ioc_value,
                        'first_seen': datetime.now().isoformat(),
                        'sources': []
                    }
                
                all_iocs[ioc_type][ioc_value]['sources'].append(file_path)
    
    return all_iocs

# Usage
ioc_files = [
    'enrichment/ioc-database/incident_42001_iocs.json',
    'enrichment/ioc-database/incident_42005_iocs.json'
]
merged_iocs = deduplicate_iocs(ioc_files)
```

---

### Phase 4: Watchlist Management

#### Step 4.1: Create Known-Bad IOC Watchlist
```python
# enrichment/ioc-database/watchlist_malicious.json
{
  "watchlist_name": "Known Malicious IOCs",
  "created_date": "2026-01-30",
  "last_updated": "2026-01-30",
  "auto_block": true,
  "ips": [
    {
      "value": "109.70.100.7",
      "added_date": "2026-01-20",
      "reason": "C2 infrastructure - Incident #42001",
      "threat_actor": "APT-Unknown",
      "confidence": "High",
      "expires": "2026-07-30"
    }
  ],
  "domains": [
    {
      "value": "malicious-domain.com",
      "added_date": "2026-01-22",
      "reason": "Phishing campaign",
      "confidence": "High",
      "expires": "2026-07-30"
    }
  ]
}
```

#### Step 4.2: Create Known-Good IOC Whitelist
```python
# enrichment/ioc-database/watchlist_benign.json
{
  "watchlist_name": "Approved Corporate Infrastructure",
  "ips": [
    {
      "value": "8.8.8.8",
      "reason": "Google Public DNS",
      "added_by": "security@company.com"
    },
    {
      "value": "13.107.42.14",
      "reason": "Microsoft Office 365",
      "added_by": "security@company.com"
    }
  ],
  "domains": [
    {
      "value": "login.microsoftonline.com",
      "reason": "Microsoft authentication"
    }
  ]
}
```

#### Step 4.3: Query Watchlist in KQL
```kql
let malicious_ips = dynamic([
    "109.70.100.7",
    "176.65.134.8",
    "206.168.34.210"
]);

DeviceNetworkEvents
| where TimeGenerated > ago(7d)
| where RemoteIP in (malicious_ips)
| summarize 
    ConnectionCount = count(),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated),
    Devices = make_set(DeviceName)
    by RemoteIP, InitiatingProcessFileName
| order by ConnectionCount desc
```

---

### Phase 5: IOC Correlation Analysis

#### Step 5.1: Cross-Incident IOC Analysis
```python
def correlate_iocs_across_incidents(incident_ids):
    """Find IOCs shared across multiple incidents"""
    ioc_incident_map = {}
    
    for incident_id in incident_ids:
        ioc_file = f'enrichment/ioc-database/incident_{incident_id}_iocs.json'
        with open(ioc_file, 'r') as f:
            data = json.load(f)
        
        for ip in data.get('ips', []):
            if ip not in ioc_incident_map:
                ioc_incident_map[ip] = []
            ioc_incident_map[ip].append(incident_id)
    
    # Find IOCs in 2+ incidents
    shared_iocs = {
        ioc: incidents 
        for ioc, incidents in ioc_incident_map.items() 
        if len(incidents) >= 2
    }
    
    return shared_iocs

# Example
incident_ids = [42001, 42005, 42012, 42018]
shared = correlate_iocs_across_incidents(incident_ids)

# Output: {"109.70.100.7": [42001, 42012, 42018]}
```

#### Step 5.2: Temporal IOC Clustering
```kql
// Find IPs that appear together in time windows
let timeWindow = 6h;
let target_ips = dynamic(["109.70.100.7", "176.65.134.8"]);

DeviceNetworkEvents
| where TimeGenerated > ago(7d)
| where RemoteIP in (target_ips)
| extend TimeWindow = bin(TimeGenerated, timeWindow)
| summarize IPs = make_set(RemoteIP) by TimeWindow, DeviceName
| where array_length(IPs) > 1  // Multiple IOCs in same window
| project TimeWindow, DeviceName, IPs
```

**Analysis:** IPs appearing together suggest coordinated attack or shared infrastructure

#### Step 5.3: Infrastructure Mapping
```kql
// Map relationships between domains and IPs
let target_domain = "malicious-domain.com";

DnsEvents
| where TimeGenerated > ago(30d)
| where Name =~ target_domain
| extend QueryResult = parse_json(QueryResult)
| mv-expand IP = QueryResult
| summarize 
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated),
    QueryCount = count()
    by Domain = Name, IP = tostring(IP)
```

---

### Phase 6: IOC Lifecycle Management

#### Step 6.1: IOC Aging and Expiration
```python
from datetime import datetime, timedelta

def check_ioc_expiration(ioc_database):
    """Identify expired IOCs for removal"""
    now = datetime.now()
    expired = []
    active = []
    
    for ioc in ioc_database.get('ips', []):
        expires = datetime.fromisoformat(ioc.get('expires'))
        
        if expires < now:
            expired.append(ioc)
        else:
            active.append(ioc)
    
    return {
        'expired': expired,
        'active': active,
        'expiring_soon': [
            ioc for ioc in active 
            if datetime.fromisoformat(ioc.get('expires')) < now + timedelta(days=7)
        ]
    }
```

#### Step 6.2: IOC Confidence Decay
```python
def update_ioc_confidence(ioc, days_since_last_seen):
    """Reduce confidence score as IOC ages without new sightings"""
    initial_confidence = ioc.get('confidence_score', 100)
    
    # Decay 5% per week of inactivity
    decay_rate = 0.05
    weeks_inactive = days_since_last_seen / 7
    
    new_confidence = initial_confidence * ((1 - decay_rate) ** weeks_inactive)
    
    # Minimum threshold
    return max(new_confidence, 20)
```

#### Step 6.3: IOC Revalidation
```kql
// Check if previously malicious IP still shows activity
let old_malicious_ips = dynamic(["109.70.100.7", "176.65.134.8"]);

DeviceNetworkEvents
| where TimeGenerated > ago(30d)
| where RemoteIP in (old_malicious_ips)
| summarize 
    RecentConnections = count(),
    LastSeen = max(TimeGenerated),
    DevicesAffected = dcount(DeviceName)
    by RemoteIP
| extend StillActive = iff(RecentConnections > 0, true, false)
```

---

### Phase 7: Export & Integration

#### Step 7.1: Export to STIX Format
```python
# STIX 2.1 indicator export
import json

def export_to_stix(iocs, output_file):
    """Export IOCs in STIX 2.1 format for SIEM integration"""
    stix_bundle = {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "objects": []
    }
    
    for ip in iocs.get('ips', []):
        indicator = {
            "type": "indicator",
            "spec_version": "2.1",
            "id": f"indicator--{uuid.uuid4()}",
            "created": datetime.now().isoformat() + "Z",
            "modified": datetime.now().isoformat() + "Z",
            "name": f"Malicious IP: {ip['value']}",
            "description": ip.get('reason', 'No description'),
            "pattern": f"[ipv4-addr:value = '{ip['value']}']",
            "pattern_type": "stix",
            "valid_from": datetime.now().isoformat() + "Z",
            "labels": ["malicious-activity", "c2"]
        }
        stix_bundle['objects'].append(indicator)
    
    with open(output_file, 'w') as f:
        json.dump(stix_bundle, f, indent=2)
```

#### Step 7.2: Export to CSV for Firewall Rules
```python
import csv

def export_blocklist_csv(iocs, output_file):
    """Export IPs to CSV for firewall import"""
    with open(output_file, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(['IP Address', 'Threat Type', 'Confidence', 'Added Date', 'Source'])
        
        for ip in iocs.get('ips', []):
            writer.writerow([
                ip['value'],
                ip.get('threat_type', 'Malicious'),
                ip.get('confidence', 'High'),
                ip.get('added_date'),
                ip.get('reason', 'Unknown')
            ])
```

#### Step 7.3: Create Defender IOC Indicators
```
mcp_triage_CreateDefenderIndicator(
    indicatorValue="109.70.100.7",
    indicatorType="IpAddress",
    action="Block",
    title="C2 Infrastructure - Incident #42001",
    description="Known malicious IP from APT campaign",
    severity="High",
    expirationDateTime="2026-07-30T00:00:00Z"
)
```

---

## Automated Workflows

### Workflow 1: Daily IOC Extraction & Enrichment

**Schedule:** Run daily at 2 AM

```powershell
# automated_ioc_workflow.ps1

# Step 1: Extract IOCs from last 24 hours
$yesterday = (Get-Date).AddDays(-1).ToString("yyyy-MM-dd")
$today = (Get-Date).ToString("yyyy-MM-dd")

# Run KQL query (save results to JSON)
# ... query logic ...

# Step 2: Deduplicate and normalize
python enrichment/normalize_iocs.py

# Step 3: Enrich new IPs
.\run-enrichment.ps1 @(Get-Content enrichment/ioc-database/new_ips.txt)

# Step 4: Update watchlist
python enrichment/update_watchlist.py

# Step 5: Export to SIEM
python enrichment/export_to_stix.py
```

### Workflow 2: Threat Actor Infrastructure Tracking

**Use case:** Track all IOCs associated with specific threat actor over time

```python
# track_threat_actor.py
class ThreatActorProfile:
    def __init__(self, actor_name):
        self.actor_name = actor_name
        self.ips = set()
        self.domains = set()
        self.file_hashes = set()
        self.first_seen = None
        self.last_seen = None
        self.incidents = []
    
    def add_iocs_from_incident(self, incident_id, ioc_data):
        self.ips.update(ioc_data.get('ips', []))
        self.domains.update(ioc_data.get('domains', []))
        self.file_hashes.update(ioc_data.get('file_hashes', []))
        self.incidents.append(incident_id)
    
    def export_profile(self):
        return {
            'actor_name': self.actor_name,
            'total_ips': len(self.ips),
            'total_domains': len(self.domains),
            'total_hashes': len(self.file_hashes),
            'incidents': self.incidents,
            'first_seen': self.first_seen,
            'last_seen': self.last_seen
        }
```

---

## Best Practices

1. **Normalize Before Deduplication**: Always standardize IOC format before comparing
2. **Track Provenance**: Record where each IOC came from (incident, TI feed, manual entry)
3. **Set Expiration Dates**: Don't keep IOCs indefinitely (90-180 day default)
4. **Confidence Scoring**: Assign confidence levels (High/Medium/Low) based on source
5. **Whitelist Management**: Maintain known-good list to prevent false positives
6. **Regular Revalidation**: Check if old IOCs still active monthly
7. **Context Preservation**: Keep incident context with IOCs for future reference
8. **Bulk Operations**: Use batch enrichment for 10+ IOCs to save API calls
9. **Version Control**: Track changes to watchlists over time
10. **Integration Testing**: Validate exports work with your SIEM/firewall before production

---

## IOC Database Structure

```
enrichment/ioc-database/
├── watchlist_malicious.json       # Known-bad IOCs for auto-blocking
├── watchlist_benign.json          # Known-good whitelist
├── threat_actors/                 # Threat actor profiles
│   ├── apt28_profile.json
│   └── apt29_profile.json
├── incidents/                     # Per-incident IOC extractions
│   ├── incident_42001_iocs.json
│   ├── incident_42005_iocs.json
│   └── ...
├── enriched/                      # Enrichment results
│   ├── enriched_ips_2026-01-30.json
│   └── enriched_domains_2026-01-30.json
├── exports/                       # SIEM/firewall exports
│   ├── stix_export_2026-01-30.json
│   ├── blocklist_2026-01-30.csv
│   └── ...
└── archive/                       # Expired/historical IOCs
    └── expired_2025_q4.json
```

---

## Related Skills

- **threat-enrichment** - IP, domain, and file hash enrichment APIs
- **incident-investigation** - Extract IOCs from investigation workflow
- **incident-correlation-analytics** - Cross-incident IOC correlation
- **endpoint-device-investigation** - Extract IOCs from device events

---

## References

- [Threat Enrichment Skill](../threat-enrichment/SKILL.md)
- [STIX 2.1 Specification](https://docs.oasis-open.org/cti/stix/v2.1/stix-v2.1.html)
- [Defender Threat Intelligence API](https://learn.microsoft.com/graph/api/resources/tiindicator)
- [AbuseIPDB API Documentation](https://docs.abuseipdb.com/)

# Network Device Investigation Agent

## Overview
This Security Copilot agent automates the investigation of compromised network devices flagged by threat intelligence feeds. It was created based on the investigation of device `mb-wap.internal.niseko.alpineskihouse.co` on January 27, 2026.

## Use Case
**Target Scenario:** SOC analysts investigating network infrastructure compromise alerts from Sentinel threat intelligence rules, specifically when:
- Devices are flagged for communicating with known malicious IP addresses
- Multiple Command & Control (C2) connections are detected
- Threat intelligence feeds identify IOC matches
- Network infrastructure devices require rapid triage and remediation

## Investigation Workflow

The agent automates the following investigation steps based on the real-world incident:

### 1. **Incident Context Gathering**
- Retrieves incident details from Microsoft Defender XDR or Sentinel
- Extracts associated entities (devices, IP addresses, users)
- Identifies threat intelligence indicators and alert timeline

### 2. **IOC Extraction & Enrichment**
- Extracts all malicious IP addresses from incident evidence
- Enriches each IP with:
  - **AbuseIPDB reputation** (confidence score, total reports)
  - **Geolocation data** (country, city, ISP)
  - **VPN/Proxy/Tor detection**
  - **Threat intelligence context**

### 3. **MITRE ATT&CK Mapping**
The agent automatically maps detected activities to MITRE ATT&CK techniques:
- **T1071** - Application Layer Protocol (Command & Control)
- **T1204** - User Execution
- Additional techniques detected in the incident

### 4. **Device & Network Correlation**
- Executes KQL queries against Sentinel and Defender XDR
- Correlates device network events with flagged IOCs
- Identifies communication patterns and C2 beaconing
- Discovers lateral movement indicators

### 5. **User Impact Analysis**
- Identifies users authenticated through compromised infrastructure
- Correlates user activity with threat timeline
- Detects insider risk management alerts
- Assesses scope of credential exposure

### 6. **Executive Reporting**
Generates comprehensive reports including:
- Executive summary with threat confidence scoring
- Attack timeline with IOC details
- MITRE ATT&CK technique breakdown
- Affected assets and users
- Prioritized remediation recommendations
- Detection queries for threat hunting

## Real-World Investigation Example

**Incident:** mb-wap.internal.niseko.alpineskihouse.co Compromise (Jan 27, 2026)

### Findings
- **7 malicious IPs** flagged by threat intelligence
- **Primary threat:** 213.209.159.181 (100% abuse confidence, 1,955 reports)
- **Attack duration:** 12 hours (03:43 - 15:05 UTC)
- **Incidents:** 5 Defender XDR incidents (42910, 42913, 42914, 42918, 42955)
- **Risk:** 34 users flagged in concurrent alerts

### MITRE ATT&CK Techniques Detected
- **T1071** (Application Layer Protocol) - C2 communications via standard protocols
- **T1204** (User Execution) - Social engineering for malicious file execution

### Remediation Actions
1. Network isolation of compromised device
2. Firewall blocking of all 7 flagged IPs
3. Forensic evidence preservation
4. Network-wide threat hunt for additional compromised systems
5. User credential reset for affected accounts

## Agent Configuration

### Required Inputs
- **IncidentId**: Sentinel or Defender XDR incident identifier (GUID, number, or URL)

### Required Skillsets
- **Fusion** - Incident and entity management
- **Generic** - IOC extraction, summarization, reporting
- **NL2KQLDefenderSentinel** - KQL query generation and execution
- **ThreatIntelligence.DTI** - Threat intelligence enrichment

### Child Skills
The agent orchestrates the following skills:
- `GetIncident` - Retrieve incident details
- `GetIncidentEntities` - Extract associated entities
- `ExtractIndicatorsOfCompromise` - IOC extraction
- `EntityExtraction` - Entity parsing
- `GetSummaryForIndicators` - Threat intelligence summary
- `GetReputationsForIndicators` - Reputation scoring
- `NL2KQLDefenderSentinel` - KQL correlation queries
- `SummarizeData` - Investigation summarization
- `AnalyzeSecurityData` - Security analysis
- `GenerateReportFromTemplate` - Executive reporting

## Deployment

### 1. Upload Agent to Security Copilot
```powershell
# Using the Security Copilot portal
# Navigate to: Agents > Upload Agent Definition
# Select: network-device-investigation-agent.yaml
```

### 2. Test Agent
```
Investigate incident 42918 for network device compromise
```

### 3. Expected Output
- **Executive Summary** with threat confidence
- **Timeline** of malicious communications
- **Enriched IOC Details** (7 IPs with AbuseIPDB scores)
- **MITRE ATT&CK Mapping** (T1071, T1204)
- **Affected Assets** (devices, users)
- **Remediation Recommendations** (prioritized by severity)

## Integration with CyberProbe Workflow

This agent complements the existing CyberProbe investigation toolkit:

### Manual Investigation (CyberProbe)
1. Run Python enrichment scripts: `enrich_ips.py`
2. Execute KQL queries manually in Sentinel
3. Generate HTML reports: `executive_report_threat_intel_2026-01-27.html`

### Automated Investigation (Security Copilot Agent)
1. Provide incident ID to agent
2. Agent automatically:
   - Extracts IOCs
   - Enriches with threat intelligence
   - Correlates with network events
   - Maps to MITRE ATT&CK
   - Generates executive report

### Best Practice Workflow
1. **Triage:** Use agent for rapid initial assessment
2. **Deep Dive:** Use CyberProbe Python scripts for custom enrichment
3. **Reporting:** Combine agent findings with CyberProbe HTML reports
4. **Threat Hunting:** Execute agent-provided KQL queries in Sentinel

## Files Generated During Investigation

- **Agent Definition:** `network-device-investigation-agent.yaml`
- **Executive Report:** `reports/executive_report_threat_intel_2026-01-27.html`
- **IP Enrichment:** `reports/ip_enrichment_1_ips.json`
- **Incident Reports:** `reports/incident_report_42953_2026-01-27.html`

## MITRE ATT&CK Coverage

### T1071 - Application Layer Protocol (Command & Control)
**Description:** Adversaries communicate using application layer protocols to avoid detection.

**Detection in Incident:**
- DeviceNetworkEvents correlated with Threat Intelligence Indicators
- Connections to known C2 IP 213.209.159.181
- Incidents: 42918, 42914, 42910

### T1204 - User Execution (Execution)
**Description:** Adversaries rely on user actions to execute malicious code.

**Detection in Incident:**
- Insider Risk Management alerts (34 users flagged)
- File sharing to unauthorized domain
- Incident: 42955

## Threat Hunting Queries

The agent generates these KQL queries for ongoing monitoring:

### Find Devices Communicating with Flagged IPs
```kql
let flaggedIPs = dynamic([
    "213.209.159.181", "64.112.126.83", "150.40.179.15", 
    "205.210.31.133", "192.42.116.215", "102.33.32.29", "45.84.107.97"
]);
DeviceNetworkEvents
| where TimeGenerated > ago(30d)
| where RemoteIP in (flaggedIPs)
| summarize ConnectionCount = count() by DeviceName
```

### Check for Persistence Mechanisms
```kql
union DeviceRegistryEvents, DeviceProcessEvents, DeviceFileEvents
| where DeviceName == "mb-wap.internal.niseko.alpineskihouse.co"
| where ActionType in ("RegistryValueSet", "ScheduledTaskCreated", "ServiceInstalled")
```

## Support & Documentation

- **Agent File:** `security-copilot/agents/network-device-investigation-agent.yaml`
- **Documentation:** `security-copilot/agents/NETWORK_DEVICE_INVESTIGATION_AGENT.md` (this file)
- **Investigation Guide:** `Investigation-Guide.md`
- **Security Copilot Setup:** `security-copilot/SECURITY_COPILOT_QUICKSTART.md`

## Version History

- **v1.0** (2026-01-27): Initial agent created from mb-wap.internal.niseko.alpineskihouse.co investigation
  - Based on 5 Defender XDR incidents
  - 7 malicious IPs enriched
  - MITRE ATT&CK mapping (T1071, T1204)
  - Executive reporting with remediation

---

**Created:** January 27, 2026  
**Based on:** mb-wap.internal.niseko.alpineskihouse.co incident investigation  
**Author:** CyberProbe Threat Intelligence Platform

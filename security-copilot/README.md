# Security Copilot Integration

This directory contains Security Copilot agent definitions, custom plugins, and integration documentation for CyberProbe.

## Contents

### Agent Definitions

| Directory/File | Description |
|----------------|-------------|
| [agents/](agents/) | Security Copilot agent YAML definitions |
| [agents/network-device-investigation-agent.yaml](agents/network-device-investigation-agent.yaml) | Network device compromise investigation agent |
| [agents/NETWORK_DEVICE_INVESTIGATION_AGENT.md](agents/NETWORK_DEVICE_INVESTIGATION_AGENT.md) | Agent documentation and usage guide |

### Documentation

| File | Description |
|------|-------------|
| [SECURITY_COPILOT_AGENT.md](SECURITY_COPILOT_AGENT.md) | Overview of Security Copilot agents |
| [SECURITY_COPILOT_QUICKSTART.md](SECURITY_COPILOT_QUICKSTART.md) | Quick start guide for Security Copilot |
| [CUSTOM_ENRICHMENT_PLUGIN.md](CUSTOM_ENRICHMENT_PLUGIN.md) | Guide for creating custom enrichment plugins |

### Plugin Development

| Directory | Description |
|-----------|-------------|
| [plugins/](plugins/) | Custom Security Copilot plugins (planned) |

## Quick Start

### 1. Import Network Device Investigation Agent

```powershell
# Navigate to Security Copilot
# https://securitycopilot.microsoft.com

# Upload agent definition
# Agents → Upload Agent Definition → Select file
agents/network-device-investigation-agent.yaml
```

### 2. Test Agent

```
Investigate incident 42918 for network device compromise
```

**Expected Output:**
- Executive summary with threat confidence
- Timeline of malicious communications
- Enriched IOC details (IPs with AbuseIPDB scores)
- MITRE ATT&CK mapping (T1071, T1204)
- Affected assets and users
- Prioritized remediation recommendations

### 3. Configure Agent Settings

1. **Security Copilot** → **Agents** → **Network Device Investigation Agent**
2. **Settings** → **Instructions Optimization**
3. Paste Expected Output template from [agents/NETWORK_DEVICE_INVESTIGATION_AGENT.md](agents/NETWORK_DEVICE_INVESTIGATION_AGENT.md)

## Available Agents

### Network Device Compromise Investigation Agent

**Purpose:** Automates investigation of compromised network devices flagged by threat intelligence feeds.

**Use Cases:**
- Devices communicating with known malicious IPs
- Command & Control (C2) connection detection
- Network infrastructure compromise alerts
- Threat intelligence IOC matches

**Key Features:**
- Automatic IOC extraction from incidents
- Multi-source threat intelligence enrichment
- MITRE ATT&CK technique mapping
- User and lateral movement analysis
- Executive report generation
- Prioritized remediation recommendations

**Input Required:**
- Incident ID (Sentinel or Defender XDR GUID, number, or URL)

**Documentation:** [agents/NETWORK_DEVICE_INVESTIGATION_AGENT.md](agents/NETWORK_DEVICE_INVESTIGATION_AGENT.md)

## Agent Workflow

### Investigation Process

```
1. GetIncident(IncidentId)
   ↓
2. GetIncidentEntities()
   ↓
3. ExtractIndicatorsOfCompromise()
   ↓
4. GetSummaryForIndicators() [Microsoft Threat Intelligence]
   ↓
5. NL2KQLDefenderSentinel() [Correlate device events]
   ↓
6. SummarizeData() [MITRE ATT&CK mapping]
   ↓
7. GenerateReportFromTemplate()
```

### Skills Used

| Skill | Skillset | Purpose |
|-------|----------|---------|
| GetIncident | Fusion | Retrieve incident details |
| GetIncidentEntities | Fusion | Extract entities (devices, IPs, users) |
| ExtractIndicatorsOfCompromise | Generic | IOC extraction |
| GetSummaryForIndicators | ThreatIntelligence.DTI | Threat intelligence enrichment |
| GetReputationsForIndicators | ThreatIntelligence.DTI | Reputation scoring |
| NL2KQLDefenderSentinel | NL2KQLDefenderSentinel | Generate and execute KQL queries |
| SummarizeData | Generic | Investigation summarization |
| AnalyzeSecurityData | Generic | Security analysis |

## Custom Plugin Development

### CyberProbe IP Enrichment Plugin (Planned)

**Purpose:** Integrate CyberProbe's custom enrichment sources (AbuseIPDB, IPInfo, VPNapi, AlienVault OTX, ThreatFox) with Security Copilot.

**Architecture:**
```
Security Copilot
    ↓
Custom Plugin (CyberProbe.IPEnrichment)
    ↓
Azure Function
    ↓
Python Enrichment Script (enrich_ips.py)
    ↓
External APIs (AbuseIPDB, IPInfo, etc.)
```

**Status:** Planning phase

**Documentation:** [CUSTOM_ENRICHMENT_PLUGIN.md](CUSTOM_ENRICHMENT_PLUGIN.md)

### Development Steps

1. **Create Azure Function wrapper** for enrichment scripts
2. **Generate OpenAPI specification** for plugin interface
3. **Register plugin** in Security Copilot
4. **Update agent** to use custom enrichment skill
5. **Test and validate** enrichment integration

## Integration with CyberProbe

### Current Integration (Agent)

**How Agent Uses CyberProbe Workflow:**

The Network Device Investigation Agent automates the manual investigation process documented in CyberProbe:

| Manual Step (CyberProbe) | Automated (Agent) |
|--------------------------|-------------------|
| List Defender incidents | GetIncident() |
| Identify affected device | GetIncidentEntities() |
| Extract malicious IPs | ExtractIndicatorsOfCompromise() |
| Run `enrich_ips.py` | GetSummaryForIndicators() (MS TI) |
| Execute KQL queries | NL2KQLDefenderSentinel() |
| Generate HTML report | GenerateReportFromTemplate() |

### Future Integration (Custom Plugin)

**When custom plugin is deployed:**

```
Agent Skill: CyberProbe.IPEnrichment/EnrichIPAddresses
    ↓
Returns: AbuseIPDB confidence (100%), 1,955 reports, Aachen Germany
```

This will provide the same enrichment quality as manual CyberProbe scripts within the automated agent workflow.

## Configuration

### Agent Configuration Files

**Location:** `agents/network-device-investigation-agent.yaml`

**Key Sections:**
```yaml
Descriptor:
  Name: NetworkDeviceCompromiseInvestigationAgent
  DisplayName: Network Device Compromise Investigation Agent
  Prerequisites:
    - Fusion
    - Sentinel
    - ThreatIntelligence.DTI
    - NL2KQLDefenderSentinel

SkillGroups:
  - Format: Agent
    Skills:
      - Name: NetworkDeviceCompromiseInvestigationAgent
        Inputs:
          - Name: IncidentId
            Required: true
```

### Expected Output Template

Configure in Security Copilot UI or YAML:

```yaml
Settings:
  ExpectedOutput: |
    # Executive Investigation Report
    
    ## 1. EXECUTIVE SUMMARY
    [3-4 sentence summary with risk score]
    
    ## 2. INCIDENT OVERVIEW
    [Incident metadata]
    
    ## 3. THREAT INTELLIGENCE - ENRICHED IOCs
    [IP enrichment table]
    
    ## 4. MITRE ATT&CK FRAMEWORK MAPPING
    [T1071, T1204, others]
    
    ...
```

See [agents/NETWORK_DEVICE_INVESTIGATION_AGENT.md](agents/NETWORK_DEVICE_INVESTIGATION_AGENT.md) for complete template.

## Usage Examples

### Example 1: Investigate Network Device Compromise

```
Investigate incident 42918
```

**Agent performs:**
1. Retrieves incident 42918 from Defender XDR
2. Extracts device: mb-wap.internal.niseko.alpineskihouse.co
3. Finds 7 malicious IPs
4. Enriches IPs with Microsoft Threat Intelligence
5. Maps to MITRE ATT&CK (T1071 - C2, T1204 - Execution)
6. Generates executive report with remediation recommendations

### Example 2: Analyze User Activity

```
Investigate suspicious activity for user u4116@int.zava-corp.com
```

**Agent performs:**
1. Searches for incidents involving user
2. Analyzes sign-in logs and DLP alerts
3. Identifies email exfiltration patterns
4. Provides user risk assessment
5. Recommends credential reset and MFA enforcement

### Example 3: Threat Hunt for IOCs

```
Search for devices communicating with IP 213.209.159.181
```

**Agent performs:**
1. Executes KQL query across DeviceNetworkEvents
2. Identifies all devices with connections to IP
3. Enriches IP with threat intelligence (100% abuse confidence)
4. Lists affected devices and users
5. Provides containment recommendations

## Troubleshooting

### Issue: "Agent not finding incidents"

**Solution:**
- Verify incident ID format (GUID, number, or URL)
- Check Sentinel/Defender XDR workspace permissions
- Ensure incident exists in specified timeframe

### Issue: "No enrichment data in report"

**Current Limitation:**
- Agent uses Microsoft's built-in threat intelligence
- Custom enrichment (AbuseIPDB, IPInfo) requires custom plugin (not yet deployed)

**Workaround:**
1. Use agent for investigation automation
2. Manually run CyberProbe enrichment scripts
3. Combine findings in final report

**Future:** Deploy custom enrichment plugin

### Issue: "MITRE ATT&CK mapping missing"

**Solution:**
- Verify incident has associated alert rules
- Check if detection rules include ATT&CK mapping
- Update agent instructions to emphasize MITRE mapping

## Best Practices

### 1. Use Descriptive Prompts

**Good:**
```
Investigate network device compromise for incident 42918, 
include MITRE ATT&CK mapping and remediation steps
```

**Poor:**
```
Check incident 42918
```

### 2. Verify Agent Output

Always review:
- IOC enrichment accuracy
- MITRE ATT&CK technique applicability
- Remediation recommendation feasibility
- Timeline chronology

### 3. Supplement with Manual Tools

For high-severity incidents:
1. Run agent for initial triage
2. Use CyberProbe enrichment for detailed IOC analysis
3. Execute custom KQL queries for deep investigation
4. Generate comprehensive HTML report

### 4. Provide Feedback

Help improve the agent:
- Report inaccurate findings
- Suggest new detection scenarios
- Share successful investigation workflows
- Document edge cases

## Related Documentation

- **Agent Documentation:** [agents/NETWORK_DEVICE_INVESTIGATION_AGENT.md](agents/NETWORK_DEVICE_INVESTIGATION_AGENT.md)
- **Quick Start Guide:** [SECURITY_COPILOT_QUICKSTART.md](SECURITY_COPILOT_QUICKSTART.md)
- **Plugin Development:** [CUSTOM_ENRICHMENT_PLUGIN.md](CUSTOM_ENRICHMENT_PLUGIN.md)
- **Investigation Guide:** [../Investigation-Guide.md](../Investigation-Guide.md)
- **Enrichment Tools:** [../enrichment/README.md](../enrichment/README.md)

## Support

- **Microsoft Security Copilot Documentation:** [learn.microsoft.com/security-copilot](https://learn.microsoft.com/security-copilot)
- **Agent Development:** [learn.microsoft.com/security-copilot/agent-build](https://learn.microsoft.com/security-copilot/agent-build)
- **CyberProbe Issues:** Create issue in project repository

---

**Last Updated:** January 28, 2026  
**Maintainer:** CyberProbe Security Team

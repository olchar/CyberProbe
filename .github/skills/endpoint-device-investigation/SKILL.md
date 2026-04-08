---
name: endpoint-device-investigation
description: Investigate endpoint devices using Microsoft Defender for Endpoint. Analyze device information, process execution, network connections, file operations, software vulnerabilities, and lateral movement. Use when investigating compromised endpoints, malware infections, or device security posture.
---

# Endpoint Device Investigation Skill

This skill enables comprehensive endpoint device investigation using Microsoft Defender for Endpoint data sources and MCP tools.

## When to Use This Skill

Use this skill when:
- Investigating compromised or suspicious endpoints
- Analyzing malware execution and persistence mechanisms
- Detecting lateral movement across devices
- Assessing software vulnerabilities on specific devices
- Tracking file distribution across the environment
- Investigating process execution chains and parent-child relationships
- Analyzing network connections from devices
- Investigating suspicious logon events or credential access

## Prerequisites

1. **Defender for Endpoint**: Devices onboarded to Microsoft Defender for Endpoint
2. **MCP Tools**: Defender XDR MCP tools available (`mcp_triage_*` functions)
3. **Sentinel Access**: Access to Advanced Hunting tables (Device* tables)
4. **Permissions**: Read access to Defender XDR and Sentinel workspaces

## KQL Query Optimization Best Practices

### Time Window Selection Strategy

**Initial Triage (Fast - Use 1-24 hours):**
- Active incident response
- Immediate threat assessment
- Quick IoC validation
- Real-time compromise detection

**Standard Investigation (Moderate - Use 7 days):**
- Persistence mechanism discovery
- Lateral movement tracking
- Campaign pattern analysis
- Malware behavior profiling

**Deep Dive / Forensics (Slow - Use 30+ days):**
- Long-term persistence detection
- Insider threat investigations
- Advanced threat actor tracking
- Complete attack timeline reconstruction

### Performance Optimization Rules

1. **Filter Order (CRITICAL):**
   ```kql
   // CORRECT: Fastest filters first
   | where DeviceId == "<ID>"        // ← Indexed column FIRST
   | where TimeGenerated > ago(24h)  // ← Time filter SECOND
   | where ActionType != "Failure"   // ← Other filters THIRD
   ```

2. **Use Single-Pass Filters:**
   ```kql
   // SLOW (two passes):
   | extend isPrivate = ipv4_is_private(RemoteIP)
   | where isPrivate != true
   
   // FAST (single pass):
   | where not(ipv4_is_private(RemoteIP))
   ```

3. **Limit Result Sets:**
   ```kql
   | take 10  // Initial triage
   | take 50  // Standard investigation
   ```

4. **Use make_set with limits:**
   ```kql
   | summarize Ports = make_set(RemotePort, 10)  // Limit to 10 items
   ```

5. **Pre-filter with let statements:**
   ```kql
   let suspiciousIPs = dynamic(["1.2.3.4", "5.6.7.8"]);
   DeviceNetworkEvents
   | where RemoteIP in (suspiciousIPs)  // Early filtering
   ```

## Investigation Workflow

### Phase 1: Device Identification & Baseline

#### Step 1.1: Get Device Information
```
mcp_triage_GetDefenderMachineById(deviceId="<DEVICE_ID>")
```

**Alternative - Find device by name:**
```kql
DeviceInfo
| where TimeGenerated > ago(7d)
| where DeviceName =~ "<DEVICE_NAME>"
| summarize arg_max(TimeGenerated, *) by DeviceId
| project DeviceId, DeviceName, OSPlatform, OSVersion, PublicIP, MachineGroup, OnboardingStatus
```

#### Step 1.2: Get Device Baseline Profile
Query last 30 days of normal activity:

```kql
let deviceId = "<DEVICE_ID>";
let lookback = 30d;

DeviceInfo
| where TimeGenerated > ago(lookback)
| where DeviceId == deviceId
| summarize 
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated),
    OSVersions = make_set(OSVersion),
    PublicIPs = make_set(PublicIP),
    DeviceTypes = make_set(DeviceType),
    MachineGroups = make_set(MachineGroup)
    by DeviceId, DeviceName, OSPlatform
| extend DaysOnline = datetime_diff('day', LastSeen, FirstSeen)
```

**Expected output:**
- Device join date
- OS versions seen (should be consistent)
- Public IPs used (check for geographic anomalies)
- Device type (Workstation, Server, etc.)
- Security groups assigned

---

### Phase 2: Process Execution Analysis

#### Step 2.1: Recent Process Activity
```kql
let deviceId = "<DEVICE_ID>";
let start = datetime(<StartDate>);
let end = datetime(<EndDate>);

DeviceProcessEvents
| where TimeGenerated between (start .. end)
| where DeviceId == deviceId
| where InitiatingProcessFileName !in ("svchost.exe", "explorer.exe")  // Filter noise
| project 
    TimeGenerated,
    FileName,
    ProcessCommandLine,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    AccountName,
    SHA256
| order by TimeGenerated desc
| take 100
```

#### Step 2.2: Suspicious Process Patterns

**Time Window Guidance:**
- **Active Incident:** Use `ago(1h)` or `ago(24h)` for immediate threats
- **Persistence Hunt:** Use `ago(7d)` to find scheduled tasks, registry modifications
- **Forensic Analysis:** Use `ago(30d)` for complete attack chain reconstruction

**Encoded PowerShell (OPTIMIZED):**
```kql
let deviceId = "<DEVICE_ID>";
let timeWindow = 24h;  // ← Adjust: 1h (fast), 24h (standard), 7d (deep dive)

DeviceProcessEvents
| where DeviceId == deviceId                    // ← Filter 1: Device (indexed)
| where TimeGenerated > ago(timeWindow)         // ← Filter 2: Time
| where ProcessCommandLine has_any ("encodedcommand", "-enc", "-e ", "FromBase64String")
| project TimeGenerated, FileName, ProcessCommandLine, AccountName, SHA256
| take 50
```

**Living-off-the-Land Binaries (LOLBins - OPTIMIZED):**
```kql
let deviceId = "<DEVICE_ID>";
let timeWindow = 24h;  // ← Adjust based on investigation scope
let suspiciousLOLBins = dynamic([
    "certutil.exe", "regsvr32.exe", "mshta.exe", "rundll32.exe",
    "wmic.exe", "powershell.exe", "cmd.exe", "cscript.exe", "wscript.exe"
]);

DeviceProcessEvents
| where DeviceId == deviceId                    // ← Filter 1: Device
| where TimeGenerated > ago(timeWindow)         // ← Filter 2: Time  
| where FileName in~ (suspiciousLOLBins)        // ← Filter 3: Process
| where ProcessCommandLine has_any ("download", "http", "ftp", "invoke", "iex")
| project TimeGenerated, FileName, ProcessCommandLine, InitiatingProcessFileName
| take 50
```

**Persistence Mechanisms (OPTIMIZED):**
```kql
let deviceId = "<DEVICE_ID>";
let timeWindow = 7d;  // ← Use 7d for persistence (runs periodically)

DeviceProcessEvents
| where DeviceId == deviceId
| where TimeGenerated > ago(timeWindow)
| where ProcessCommandLine has_any (
    "schtasks", "at.exe", "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "startup"
)
| project TimeGenerated, FileName, ProcessCommandLine, AccountName
| take 50
```

---

### Phase 3: Network Connections Analysis

**Time Window Strategy:**
- **Active C2 Detection:** `ago(1h)` - Detect live command & control
- **Standard Analysis:** `ago(24h)` - Recent external connections
- **Beaconing Patterns:** `ago(7d)` - Identify periodic C2 communication
- **Infrastructure Mapping:** `ago(30d)` - Full threat actor infrastructure

#### Step 3.1: External Network Connections (OPTIMIZED)
```kql
let deviceId = "<DEVICE_ID>";
let timeWindow = 24h;  // ← Adjust: 1h (active), 24h (standard), 7d (patterns)

DeviceNetworkEvents
| where DeviceId == deviceId                    // ← Filter 1: Device (indexed)
| where TimeGenerated > ago(timeWindow)         // ← Filter 2: Time
| where ActionType !has "ConnectionFailed"      // ← Filter 3: Exclude failures
| where not(ipv4_is_private(RemoteIP))          // ← Filter 4: External IPs only (single-pass)
| summarize 
    ConnectionCount = count(),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated),
    Ports = make_set(RemotePort, 10),            // ← Limit set size
    Protocols = make_set(Protocol, 5)
    by RemoteIP, InitiatingProcessFileName
| order by ConnectionCount desc
| take 15  // ← Reduced from 50 for faster results
```

**Extract IPs for enrichment (OPTIMIZED):**
```kql
let deviceId = "<DEVICE_ID>";
let timeWindow = 24h;  // ← Use 24h for recent threats, 7d for campaign analysis

DeviceNetworkEvents
| where DeviceId == deviceId                    // ← Filter order optimized
| where TimeGenerated > ago(timeWindow)
| where not(ipv4_is_private(RemoteIP))          // ← Single-pass filter
| summarize ConnectionCount = count() by RemoteIP
| order by ConnectionCount desc
| take 15
| project RemoteIP
```

#### Step 3.2: Suspicious Network Patterns

**Command & Control Indicators (OPTIMIZED - 7 days for beaconing):**
```kql
let deviceId = "<DEVICE_ID>";
let timeWindow = 7d;  // ← Need 7d minimum to detect beaconing patterns

DeviceNetworkEvents
| where DeviceId == deviceId
| where TimeGenerated > ago(timeWindow)
| where not(ipv4_is_private(RemoteIP))
| where ActionType !has "ConnectionFailed"
| summarize 
    Count = count(),
    AvgInterval = avg(datetime_diff('second', TimeGenerated, prev(TimeGenerated))),
    Ports = make_set(RemotePort, 5)
    by RemoteIP, InitiatingProcessFileName, bin(TimeGenerated, 1h)
| where Count > 10 and AvgInterval between (30 .. 3600)  // 30 sec to 1 hour intervals
| project RemoteIP, InitiatingProcessFileName, Count, AvgInterval, Ports
| take 20
```

**Data Exfiltration Indicators (OPTIMIZED):**
```kql
let deviceId = "<DEVICE_ID>";
let timeWindow = 24h;  // ← Use 24h for active exfiltration, 7d for patterns

DeviceNetworkEvents
| where DeviceId == deviceId
| where TimeGenerated > ago(timeWindow)
| where ActionType !has "ConnectionFailed"
| where RemoteIPType == "Public"
| where RemotePort !in (80, 443, 53)  // Exclude common ports
| summarize TotalBytes = sum(ReceivedBytes + SentBytes) by RemoteIP, RemotePort
| where TotalBytes > 10485760  // > 10 MB
| order by TotalBytes desc
```

---

### Phase 4: File Operations & Malware Analysis

#### Step 4.1: File Creations & Modifications
```kql
let deviceId = "<DEVICE_ID>";
let start = datetime(<StartDate>);
let end = datetime(<EndDate>);

DeviceFileEvents
| where TimeGenerated between (start .. end)
| where DeviceId == deviceId
| where ActionType in ("FileCreated", "FileModified", "FileRenamed")
| where FolderPath !startswith "C:\\Windows\\System32"  // Filter system files
| project 
    TimeGenerated,
    ActionType,
    FileName,
    FolderPath,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    SHA256
| order by TimeGenerated desc
| take 100
```

#### Step 4.2: Suspicious File Locations
```kql
DeviceFileEvents
| where TimeGenerated > ago(7d)
| where DeviceId == "<DEVICE_ID>"
| where FolderPath has_any (
    "\\Temp\\", "\\AppData\\Roaming\\", "\\AppData\\Local\\Temp\\",
    "\\Downloads\\", "\\Users\\Public\\", "\\ProgramData\\"
)
| where FileName endswith_any (".exe", ".dll", ".ps1", ".vbs", ".bat", ".cmd", ".scr")
| where ActionType == "FileCreated"
| project TimeGenerated, FileName, FolderPath, SHA256, InitiatingProcessFileName
```

#### Step 4.3: Get File Threat Intelligence
```
mcp_triage_GetDefenderFileInfo(fileHash="<SHA256>")
```

**Returns:**
- File reputation (known malware, clean, unknown)
- Global prevalence (how many devices have seen this file)
- Signer information
- First/last seen timestamps
- Associated threats

#### Step 4.4: Track File Distribution
```
mcp_triage_GetDefenderFileRelatedMachines(fileHash="<SHA256>")
```

**Use case:** Determine if malware spread to other devices

---

### Phase 5: Vulnerability Assessment

#### Step 5.1: Get Device Vulnerabilities
```
mcp_triage_GetDefenderMachineVulnerabilities(deviceId="<DEVICE_ID>")
```

**Returns:**
- CVE IDs with CVSS scores
- Affected software
- Exploit availability
- Remediation recommendations

#### Step 5.2: Vulnerable Software Analysis
```kql
DeviceTvmSoftwareInventory
| where DeviceId == "<DEVICE_ID>"
| where isnotempty(SoftwareVendor)
| summarize by DeviceName, SoftwareName, SoftwareVersion, SoftwareVendor
| order by SoftwareName asc
```

#### Step 5.3: Critical Vulnerabilities by Software
```
mcp_triage_ListDefenderVulnerabilitiesBySoftware(
    deviceId="<DEVICE_ID>",
    softwareId="<SOFTWARE_ID>"
)
```

**Workflow:**
1. Get software inventory
2. Identify critical software (domain controllers, servers, admin workstations)
3. Query vulnerabilities for each critical software
4. Prioritize patching based on CVSS score + device criticality

---

### Phase 6: Lateral Movement Detection

#### Step 6.1: Logon Events
```kql
let deviceId = "<DEVICE_ID>";
let start = datetime(<StartDate>);
let end = datetime(<EndDate>);

DeviceLogonEvents
| where TimeGenerated between (start .. end)
| where DeviceId == deviceId
| where ActionType in ("LogonSuccess", "LogonFailed")
| extend LogonType = case(
    LogonType == "2", "Interactive",
    LogonType == "3", "Network",
    LogonType == "10", "RemoteInteractive",
    LogonType == "4", "Batch",
    LogonType == "5", "Service",
    strcat("Type ", LogonType)
)
| project 
    TimeGenerated,
    AccountName,
    AccountDomain,
    LogonType,
    ActionType,
    RemoteIP,
    RemoteDeviceName,
    InitiatingProcessFileName
| order by TimeGenerated desc
```

#### Step 6.2: Remote Desktop Connections
```kql
DeviceLogonEvents
| where TimeGenerated > ago(7d)
| where DeviceId == "<DEVICE_ID>"
| where LogonType == "10"  // Remote Interactive (RDP)
| where ActionType == "LogonSuccess"
| project TimeGenerated, AccountName, RemoteIP, RemoteDeviceName
```

#### Step 6.3: Credential Access Attempts
```kql
DeviceEvents
| where TimeGenerated > ago(7d)
| where DeviceId == "<DEVICE_ID>"
| where ActionType in (
    "LsassMemoryDump", "CredentialDumping", "SuspiciousSAMActivity",
    "SuspiciousLsassProcessAccess", "AsepRegistryPersistence"
)
| project TimeGenerated, ActionType, FileName, ProcessCommandLine, AccountName
```

---

### Phase 7: Registry Modifications

#### Step 7.1: Recent Registry Changes
```kql
let deviceId = "<DEVICE_ID>";
let start = datetime(<StartDate>);
let end = datetime(<EndDate>);

DeviceRegistryEvents
| where TimeGenerated between (start .. end)
| where DeviceId == deviceId
| where RegistryKey has_any ("Run", "RunOnce", "Services", "Policies")
| project 
    TimeGenerated,
    ActionType,
    RegistryKey,
    RegistryValueName,
    RegistryValueData,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine
| order by TimeGenerated desc
| take 100
```

#### Step 7.2: Persistence Registry Keys
```kql
DeviceRegistryEvents
| where TimeGenerated > ago(7d)
| where DeviceId == "<DEVICE_ID>"
| where RegistryKey has_any (
    "\\Run", "\\RunOnce", "\\RunServices", "\\RunServicesOnce",
    "\\Winlogon\\Shell", "\\Winlogon\\Userinit"
)
| where ActionType in ("RegistryValueSet", "RegistryKeyCreated")
| project TimeGenerated, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessFileName
```

---

## Investigation Templates

### Template 1: Malware Infection Analysis

**Scenario:** Defender alert for malware execution on device

**Workflow:**
1. Get device baseline (Phase 1)
2. Identify malicious process (Phase 2.2)
3. Extract file hash from process events
4. Get file threat intelligence (Phase 4.3)
5. Check file distribution (Phase 4.4)
6. Analyze network connections from process (Phase 3)
7. Check for persistence (Phase 2.2 - persistence queries)
8. Identify lateral movement (Phase 6)

### Template 2: Lateral Movement Investigation

**Scenario:** Suspicious RDP connection to server

**Workflow:**
1. Query logon events (Phase 6.1)
2. Identify source device from RemoteDeviceName
3. Repeat investigation for source device
4. Track credential usage across multiple devices
5. Identify initial compromise point
6. Map attack path through environment

### Template 3: Data Exfiltration Investigation

**Scenario:** High data transfer to external IP

**Workflow:**
1. Get network connections (Phase 3.1)
2. Identify process responsible for connections
3. Get process execution timeline (Phase 2.1)
4. Check file access events around same time
5. Enrich external IPs with threat intelligence
6. Determine data accessed and exfiltrated

---

## MCP Tools Reference

### Device Information
- `mcp_triage_GetDefenderMachineById` - Get detailed device information
- `mcp_triage_ListDefenderMachines` - List all devices (filter by health, risk, etc.)

### File Analysis
- `mcp_triage_GetDefenderFileInfo` - Get file reputation and threat intelligence
- `mcp_triage_GetDefenderFileRelatedMachines` - Find all devices with specific file
- `mcp_triage_GetDefenderFileAlerts` - Get alerts related to file hash

### Vulnerabilities
- `mcp_triage_GetDefenderMachineVulnerabilities` - List CVEs affecting device
- `mcp_triage_ListDefenderVulnerabilitiesBySoftware` - CVEs for specific software on device
- `mcp_triage_ListDefenderMachinesByCVE` - Find all devices affected by CVE

### Network & IP
- `mcp_triage_GetDefenderIpStatistics` - Get statistics for IP (device count, etc.)
- `mcp_triage_FindDefenderMachinesByIp` - Find devices that communicated with IP

### Investigations & Remediation
- `mcp_triage_ListDefenderInvestigations` - List automated investigations
- `mcp_triage_GetDefenderRemediationActivity` - Check remediation status

---

## Key Defender for Endpoint Tables

All queries use Sentinel-synced tables:

- **DeviceInfo** - Device inventory, OS, IP addresses
- **DeviceProcessEvents** - Process creation, command lines, parent-child relationships
- **DeviceNetworkEvents** - Network connections, remote IPs, ports, protocols
- **DeviceFileEvents** - File creation, modification, deletion, access
- **DeviceLogonEvents** - Interactive, network, and remote logons
- **DeviceRegistryEvents** - Registry modifications (Run keys, services, policies)
- **DeviceEvents** - Miscellaneous security events (credential access, privilege escalation)
- **DeviceImageLoadEvents** - DLL and driver loading
- **DeviceFileCertificateInfo** - Digital signature information
- **DeviceTvmSoftwareInventory** - Installed software
- **DeviceTvmSoftwareVulnerabilities** - CVE mappings

---

## Common Investigation Patterns

### Pattern 1: Process Tree Reconstruction
```kql
let suspiciousProcessId = "<PROCESS_ID>";
DeviceProcessEvents
| where InitiatingProcessId == suspiciousProcessId
| project TimeGenerated, FileName, ProcessCommandLine, ProcessId
| order by TimeGenerated asc
```

### Pattern 2: Timeline Correlation
Correlate events across multiple tables:

```kql
let deviceId = "<DEVICE_ID>";
let timeWindow = 5m;
let suspiciousTime = datetime(<EVENT_TIME>);

union 
    (DeviceProcessEvents | where DeviceId == deviceId | project TimeGenerated, EventType = "Process", Details = ProcessCommandLine),
    (DeviceNetworkEvents | where DeviceId == deviceId | project TimeGenerated, EventType = "Network", Details = strcat(RemoteIP, ":", RemotePort)),
    (DeviceFileEvents | where DeviceId == deviceId | project TimeGenerated, EventType = "File", Details = FolderPath)
| where TimeGenerated between ((suspiciousTime - timeWindow) .. (suspiciousTime + timeWindow))
| order by TimeGenerated asc
```

### Pattern 3: User Activity Tracking
```kql
let username = "<USERNAME>";
union DeviceProcessEvents, DeviceLogonEvents, DeviceFileEvents
| where AccountName =~ username
| where TimeGenerated > ago(7d)
| summarize EventCount = count() by DeviceName, ActionType
| order by EventCount desc
```

---

## Best Practices

1. **Start Broad, Narrow Down**: Begin with device baseline, then focus on suspicious timeframes
2. **Follow the Process Chain**: Use InitiatingProcessFileName to reconstruct attack paths
3. **Correlate Data Sources**: Combine process, network, and file events for complete picture
4. **Enrich Early**: Get threat intelligence for IPs and file hashes as soon as extracted
5. **Document Timeline**: Maintain chronological event log with timestamps
6. **Check Prevalence**: Use file distribution and IP statistics to gauge threat scope
7. **Automate Repetitive Queries**: Create investigation templates for common scenarios

---

## Related Skills

- **threat-enrichment** - Enrich IPs and file hashes extracted from device events
- **incident-investigation** - Full incident workflow including device investigation
- **kql-sentinel-queries** - Additional KQL patterns and query optimization

---

## References

- [Microsoft Defender for Endpoint Documentation](https://learn.microsoft.com/defender-endpoint/)
- [Advanced Hunting Schema](https://learn.microsoft.com/defender-xdr/advanced-hunting-schema-tables)
- [Investigation Guide Section 2](../../../Investigation-Guide.md#2-data-sources) - Data source overview
- [MITRE ATT&CK Framework](https://attack.mitre.org/) - Technique mapping

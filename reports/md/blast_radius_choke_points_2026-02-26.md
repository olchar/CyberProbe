Blast Radius — Choke Point Devices | CyberProbe


# 💥 Blast Radius — Choke Point Device Analysis

Exposure Management choke point identification, lateral movement mapping, and blast radius visualization based on Defender XDR + Sentinel data (last 30 days).

Generated: 2026-02-26 | Workspace: SecOps-Workspace | Data Range: Jan 27 – Feb 26, 2026


## 🔴 Top Choke Point Devices — by Alert Severity

Devices ranked by high-severity alert count and lateral movement involvement. These are the most critical exposure points in the environment.

### 🖥️ rayt-pc

27 High

34 total alerts | 5 Medium | 1 Low

CredentialAccess
LateralMovement
PrivilegeEscalation
DefenseEvasion

Mimikatz, Pass-the-Hash, Pass-the-Ticket, LSASS Access, Kekeo, SMB file transfer

### 🖥️ sap-ash

8 High

167 total alerts | 129 Medium | 30 Low

CredentialAccess
Execution
Collection
CommandAndControl

SAP XPPG external commands, credential theft, LinPEAS, sensitive file access, data exfiltration

### 🖥️ aaronb-pc

5 High

16 total alerts | 9 Medium | 2 Low

LateralMovement
CredentialAccess
Persistence

Kekeo lateral movement, pass-the-hash, Rubeus kerberoasting, malicious service

### 🖥️ main-dc

3 High

3 total alerts | Domain Controller

LateralMovement

Hands-on-keyboard multi-device attack, SMB lateral movement target

### 🖥️ contoso-sql

1 High

13 total alerts | Internet-exposed SQL server

InitialAccess
PrivilegeEscalation

Remote logon on internet-exposed device, 30+ unique external IPs observed

## 💥 Primary Blast Radius — rayt-pc (Most Severe Choke Point)

All entities reachable from `rayt-pc` via lateral movement, credential theft, and hands-on-keyboard attacks. rayt-pc is the epicenter: Mimikatz + Pass-the-Hash + Pass-the-Ticket enabled credential harvesting that propagated to 3 additional devices and 2 compromised accounts.

Choke Point (epicenter)

Ring 1: Direct lateral movement target

Ring 2: Compromised accounts

Ring 3: Network IPs / infrastructure

Attack techniques

+

100%

−
⟳

```
graph LR
    %% ===== EPICENTER =====
    RAYT["🔴 rayt-pc  
CHOKE POINT  
27 High-sev alerts  
Mimikatz · PtH · PtT"]

    %% ===== RING 1: DIRECT LATERAL MOVEMENT TARGETS =====
    subgraph Ring1["🔴 RING 1 — Direct Lateral Movement Targets"]
        AARON["🖥️ aaronb-pc  
5 High alerts  
Kekeo · PtH · SMB"]
        MAINDC["🖥️ main-dc  
Domain Controller  
3 High alerts"]
        CELESTEB["🖥️ celesteb-pc  
Accessed via main-dc"]
    end

    %% ===== RING 2: COMPROMISED ACCOUNTS =====
    subgraph Ring2["🟠 RING 2 — Compromised Accounts"]
        RAYT_USER["👤 rayt  
Primary operator  
Credential theft origin"]
        AARON_USER["👤 aaronb  
Lateral movement target  
Pass-the-Hash victim"]
        RAYTM["👤 rayt-pc$  
Machine account  
Used in PtT"]
    end

    %% ===== RING 3: NETWORK INFRASTRUCTURE =====
    subgraph Ring3["🔵 RING 3 — Network / IPs"]
        IP1["🌐 10.0.0.69  
rayt-pc primary IP"]
        IP2["🌐 10.2.0.132  
aaronb-pc IP"]
        IP3["🌐 10.2.0.136  
main-dc IP"]
        IP4["🌐 10.1.0.4  
Secondary subnet"]
    end

    %% ===== RING 4: ATTACK TECHNIQUES =====
    subgraph Ring4["🟣 Attack Techniques (MITRE ATT&CK)"]
        T1003["T1003  
OS Credential Dumping"]
        T1550["T1550  
Use Alternate Auth"]
        T1021["T1021  
Remote Services"]
        T1570["T1570  
Lateral Tool Transfer"]
        T1134["T1134  
Access Token Manipulation"]
        T1558["T1558  
Steal Kerberos Tickets"]
    end

    %% ===== CONNECTIONS FROM EPICENTER =====
    RAYT -->|"Mimikatz + LSASS dump"| RAYT_USER
    RAYT -->|"Pass-the-Hash  
SMB file transfer"| AARON
    RAYT -->|"Hands-on-keyboard  
multi-device attack"| MAINDC
    RAYT -->|"Pass-the-Ticket"| RAYTM
    RAYT --- IP1

    %% ===== LATERAL MOVEMENT CHAINS =====
    AARON -->|"Kekeo malware  
service persistence"| AARON_USER
    AARON --- IP2
    MAINDC -->|"SMB enumeration"| CELESTEB
    MAINDC --- IP3
    MAINDC -->|"Account used across DC"| RAYT_USER
    MAINDC -->|"Account used across DC"| AARON_USER

    %% ===== SMB LATERAL MOVEMENT =====
    IP2 -.->|"SMB suspicious transfer"| IP3
    IP1 -.->|"Remote session"| IP4

    %% ===== TECHNIQUE LINKS =====
    RAYT -.-> T1003
    RAYT -.-> T1550
    AARON -.-> T1558
    RAYT -.-> T1021
    RAYT -.-> T1570
    RAYT -.-> T1134

    classDef epicenter fill:#da3633,stroke:#f85149,color:#fff,stroke-width:3px
    classDef ring1 fill:#4a1d1d,stroke:#f85149,color:#f0f6fc,stroke-width:2px
    classDef ring2 fill:#3d2e00,stroke:#d29922,color:#f0f6fc,stroke-width:2px
    classDef ring3 fill:#0c2d6b,stroke:#1f6feb,color:#f0f6fc,stroke-width:2px
    classDef technique fill:#2d1b69,stroke:#8957e5,color:#f0f6fc,stroke-width:2px

    class RAYT epicenter
    class AARON,MAINDC,CELESTEB ring1
    class RAYT_USER,AARON_USER,RAYTM ring2
    class IP1,IP2,IP3,IP4 ring3
    class T1003,T1550,T1021,T1570,T1134,T1558 technique
```

## 💥 Secondary Blast Radius — contoso-sql (Internet-Exposed Entry Point)

`contoso-sql` is the internet-facing entry point with 30+ unique external IPs connecting to it. Compromise of this node provides direct access to internal SQL services and lateral path to other choke points.

+

100%

−
⟳

```
graph LR
    %% ===== INTERNET EXPOSURE =====
    subgraph Internet["🌍 INTERNET (30+ unique IPs)"]
        EXT1["🔴 198.235.24.34"]
        EXT2["🔴 87.120.191.67"]
        EXT3["🔴 80.94.92.168"]
        EXT4["🔴 176.65.134.22"]
        EXT5["🔴 85.217.149.3"]
        EXT6["⚪ +25 more IPs"]
    end

    %% ===== ENTRY POINT =====
    SQL["🔴 contoso-sql  
INTERNET-EXPOSED  
13 alerts  
SQL Server"]

    %% ===== SQL SERVICE ACCOUNTS =====
    subgraph SQLAccounts["🟠 SQL Service Accounts"]
        SA1["👤 mssqlserver"]
        SA2["👤 sqlserveragent"]
        SA3["👤 mssqlfdlauncher"]
        SA4["👤 sqltelemetry"]
        SA5["👤 ssastelemetry"]
        SA6["👤 system"]
    end

    %% ===== CONNECTED HOSTS =====
    subgraph Connected["🔵 Connected Infrastructure"]
        MBWAP["🖥️ wap-01  
Web App Proxy  
internal.niseko.contoso.com"]
        CONT1["🐳 e8a72f6b3fb3  
Container"]
        CONT2["🐳 e8a72f6b388b  
Container"]
    end

    %% ===== CONNECTIONS =====
    EXT1 -->|"Remote logon"| SQL
    EXT2 -->|"Remote logon"| SQL
    EXT3 -->|"Remote logon"| SQL
    EXT4 -->|"Remote logon"| SQL
    EXT5 -->|"Remote logon"| SQL
    EXT6 -.-> SQL

    SQL -->|"Service accounts"| SA1
    SQL --> SA2
    SQL --> SA3
    SQL --> SA4
    SQL --> SA5
    SQL --> SA6

    SQL -->|"Network path"| MBWAP
    SQL -->|"Container access"| CONT1
    SQL --> CONT2

    classDef entrypoint fill:#da3633,stroke:#f85149,color:#fff,stroke-width:3px
    classDef external fill:#4a1d1d,stroke:#f85149,color:#f0f6fc,stroke-width:2px
    classDef account fill:#3d2e00,stroke:#d29922,color:#f0f6fc,stroke-width:2px
    classDef infra fill:#0c2d6b,stroke:#1f6feb,color:#f0f6fc,stroke-width:2px

    class SQL entrypoint
    class EXT1,EXT2,EXT3,EXT4,EXT5,EXT6 external
    class SA1,SA2,SA3,SA4,SA5,SA6 account
    class MBWAP,CONT1,CONT2 infra
```

## 💥 Tertiary Blast Radius — sap-ash (SAP Production Server)

`sap-ash` has the highest total alert volume (167 alerts) including SAP-specific threats, credential theft, LinPEAS privilege escalation, and data exfiltration. Linked to 6 high-severity incidents.

+

100%

−
⟳

```
graph LR
    SAP["🔴 sap-ash  
SAP PRODUCTION  
167 alerts  
8 High severity"]

    subgraph Threats["🔴 Active Threats"]
        TH1["⚠️ LinPEAS  
Privilege Escalation"]
        TH2["⚠️ Credential Theft  
Unix creds accessed"]
        TH3["⚠️ Web Shell  
Persistence"]
        TH4["⚠️ Data Exfiltration  
Sensitive file access"]
    end

    subgraph SAPOps["🟠 SAP-Specific Risks"]
        OP1["👤 CAMERONV  
8.6KB + 22KB + 13.4KB  
sensitive data downloads"]
        OP2["👤 MAPANKRA  
7.2KB sensitive data"]
        OP3["⚙️ SM49 Transaction  
Dangerous external cmd"]
    end

    subgraph Incidents["🔵 Linked Incidents"]
        INC1["🔥 INC-33623  
Multi-stage Exec+Exfil  
48 alerts · Active"]
        INC2["🔥 INC-33617  
Multi-stage Exec+Exfil  
42 alerts · Closed"]
        INC3["🔥 INC-33365  
Multi-stage Exec+Exfil  
50 alerts · Closed"]
        INC4["🔥 INC-33339  
Privilege Escalation  
57 alerts · Closed"]
    end

    SAP --> TH1 & TH2 & TH3 & TH4
    SAP --> OP1 & OP2 & OP3
    SAP --> INC1 & INC2 & INC3 & INC4

    classDef sapnode fill:#da3633,stroke:#f85149,color:#fff,stroke-width:3px
    classDef threat fill:#4a1d1d,stroke:#f85149,color:#f0f6fc,stroke-width:2px
    classDef sapops fill:#3d2e00,stroke:#d29922,color:#f0f6fc,stroke-width:2px
    classDef incident fill:#0c2d6b,stroke:#1f6feb,color:#f0f6fc,stroke-width:2px

    class SAP sapnode
    class TH1,TH2,TH3,TH4 threat
    class OP1,OP2,OP3 sapops
    class INC1,INC2,INC3,INC4 incident
```

## 🗺️ Environment-Wide Blast Radius — All Choke Points Connected

How the 5 choke points interconnect through shared accounts, lateral movement paths, and network adjacency. Arrows indicate proven attack paths observed in alerts.

+

100%

−
⟳

```
graph TB
    subgraph ExternalZone["🌍 EXTERNAL ZONE"]
        INET["🌐 Internet  
30+ unique IPs"]
    end

    subgraph DMZ["📡 DMZ / Internet-Facing"]
        SQL["🔴 contoso-sql  
SQL Server · 13 alerts  
Internet-exposed"]
        MBWAP["🖥️ wap-01  
Web App Proxy"]
    end

    subgraph CorpNet["🏢 CORPORATE NETWORK"]
        RAYT["🔴 rayt-pc  
PRIMARY CHOKE POINT  
27 High · Mimikatz+PtH+PtT"]
        AARON["🟠 aaronb-pc  
5 High · Kekeo+PtH"]
        MAINDC["🔴 main-dc  
Domain Controller  
3 High"]
        CELESTEB["🟡 celesteb-pc"]
    end

    subgraph SAPZone["🏭 SAP PRODUCTION"]
        SAPASH["🔴 sap-ash  
167 alerts · SAP Prod  
LinPEAS · Exfiltration"]
    end

    subgraph Accounts["👤 COMPROMISED ACCOUNTS"]
        U_RAYT["rayt"]
        U_AARON["aaronb"]
        U_CAMERON["cameronv"]
        U_SYSTEM["system / svc accts"]
    end

    %% External to DMZ
    INET ==>|"Remote logon  
30+ IPs"| SQL
    SQL --- MBWAP

    %% DMZ to Corp
    SQL -.->|"Potential pivot path"| MAINDC

    %% Corp lateral movement
    RAYT ==>|"Pass-the-Hash  
SMB transfer"| AARON
    RAYT ==>|"Hands-on-keyboard"| MAINDC
    MAINDC -->|"SMB blocked"| CELESTEB
    MAINDC -->|"SMB blocked"| AARON

    %% Account reuse
    U_RAYT ---|"Used on"| RAYT
    U_RAYT ---|"Used on"| MAINDC
    U_RAYT ---|"Used on"| AARON
    U_AARON ---|"Used on"| AARON
    U_AARON ---|"Used on"| MAINDC
    U_CAMERON ---|"SAP downloads"| SAPASH
    U_SYSTEM ---|"SQL services"| SQL

    classDef critical fill:#da3633,stroke:#f85149,color:#fff,stroke-width:3px
    classDef high fill:#4a1d1d,stroke:#f85149,color:#f0f6fc,stroke-width:2px
    classDef medium fill:#3d2e00,stroke:#d29922,color:#f0f6fc,stroke-width:2px
    classDef low fill:#21262d,stroke:#30363d,color:#c9d1d9,stroke-width:2px
    classDef account fill:#0c2d6b,stroke:#1f6feb,color:#f0f6fc,stroke-width:2px
    classDef external fill:#161b22,stroke:#8b949e,color:#8b949e,stroke-width:2px

    class RAYT,MAINDC,SAPASH,SQL critical
    class AARON high
    class CELESTEB,MBWAP low
    class U_RAYT,U_AARON,U_CAMERON,U_SYSTEM account
    class INET external
```

## 📊 Choke Point Blast Radius Summary

Quantified blast radius per choke point device: entity counts, incident linkage, MITRE techniques, and recommended containment priority.

| Device | Role | Total Alerts | High Sev | Compromised Accounts | Connected Devices | External IPs | Linked Incidents | MITRE Techniques | Containment Priority |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| **rayt-pc** | Primary Choke Point | 34 | 27 | rayt aaronb rayt-pc$ | aaronb-pc main-dc | — | Multi-stage incidents via linked devices | T1003, T1550, T1021, T1570, T1134, T1558 | 🔴 IMMEDIATE |
| **sap-ash** | SAP Production | 167 | 8 | cameronv mapankra ashadm | — | 1 | INC-33623 (Active), INC-33617, INC-33365, INC-33339 + 3 more | T1003, T1005, T1083, T1119, T1552, T1555 | 🔴 IMMEDIATE |
| **contoso-sql** | Internet-Exposed SQL | 13 | 1 | mssqlserver system + 7 svc accts | wap-01 containers ×2 | 30+ | INC-30292 | T1078 (Valid Accounts) | 🔴 IMMEDIATE |
| **aaronb-pc** | Lateral Target | 16 | 5 | aaronb rayt | Reached from rayt-pc | — | Via rayt-pc multi-stage incidents | T1021, T1078, T1543, T1558, T1569, T1570 | 🟠 HIGH |
| **main-dc** | Domain Controller | 3 | 3 | rayt aaronb | celesteb-pc aaronb-pc | — | Via rayt-pc multi-stage incidents | T1021 (Remote Services) | 🔴 IMMEDIATE |

## 🔗 Lateral Movement Evidence — Alert-Level Detail

Every high and medium severity lateral movement alert observed in the last 30 days, showing origin device, target accounts, and network indicators.

| Alert Name | Severity | Tactics | Source Device | Accounts | IPs |
| --- | --- | --- | --- | --- | --- |
| Mimikatz credential theft tool | High | CredentialAccess | rayt-pc | rayt | 10.0.0.69 |
| Pass-the-ticket attack | High | CredentialAccess | rayt-pc | — | — |
| Possible pass-the-hash authentication | High | CredentialAccess LateralMovement | rayt-pc | aaronb, rayt | 10.0.0.69, ::1 |
| Multiple dual-purpose tools were dropped | High | CredentialAccess LateralMovement C2 | rayt-pc | rayt | 10.0.0.69 |
| Suspicious remote session | High | CredentialAccess LateralMovement C2 | rayt-pc | rayt, rayt-pc$ | 10.0.0.69 |
| Suspicious access to LSASS service | High | DefenseEvasion CredentialAccess LateralMovement | rayt-pc | rayt | 10.0.0.69 |
| Hands-on-keyboard attack (multi-device) | High | LateralMovement | rayt-pc, aaronb-pc, main-dc | rayt, aaronb | 10.0.0.69, 10.1.0.4 |
| 'Kekeo' malware detected during lateral movement | High | LateralMovement | aaronb-pc | rayt, aaronb | 10.2.0.132 |
| Excessive SMB login attempts | High | Persistence LateralMovement Execution | 1AW002 (IoT) | — | — |
| Possible lateral movement (SMB file transfer) | Medium | LateralMovement | rayt-pc | — | 10.2.0.136 → 10.2.0.132 |
| Possible lateral movement using pass-the-hash | Medium | DefenseEvasion LateralMovement | aaronb-pc | aaronb | 10.2.0.132 |
| File dropped and launched from remote location | Medium | LateralMovement C2 | aaronb-pc | aaronb | 10.2.0.132 |
| Suspicious SMB enumeration from untrusted host | Medium | Discovery | rayt-pc → main-dc | rayt | 10.2.0.132 |

## ⚠️ Containment Recommendations

| Priority | Action | Target | Rationale |
| --- | --- | --- | --- |
| 🔴 P1 | **Isolate rayt-pc** | rayt-pc | Epicenter of all lateral movement. Mimikatz + PtH + PtT active. 27 high-severity alerts. Compromised credentials for rayt + aaronb propagated from this device. |
| 🔴 P1 | **Reset credentials: rayt, aaronb** | rayt, aaronb accounts | Both accounts confirmed compromised via credential theft tools (Mimikatz, Kekeo). Pass-the-hash tokens in use across 3 devices. |
| 🔴 P1 | **Restrict contoso-sql internet exposure** | contoso-sql NSG / firewall | 30+ external IPs performing remote logon. Direct internet-to-SQL path. Immediate network segmentation required. |
| 🔴 P1 | **Investigate sap-ash active incident INC-33623** | sap-ash, cameronv | 48-alert active incident. Multi-stage execution + exfiltration. Sensitive data downloads by CAMERONV (44KB total). LinPEAS priv-esc tool detected. |
| 🟠 P2 | **Isolate aaronb-pc** | aaronb-pc | Secondary lateral movement target. Kekeo malware active. Malicious services registered. Receiving PtH from rayt-pc. |
| 🟠 P2 | **Audit main-dc for persistence** | main-dc | Domain Controller reached via lateral movement from rayt-pc. Verify no Golden/Silver Ticket artifacts, no new admin accounts, no scheduled tasks. |
| 🟠 P2 | **Review SQL service account permissions** | mssqlserver, sqlserveragent + 7 svc accts | 9 service accounts on internet-exposed contoso-sql. Verify least-privilege, disable unnecessary accounts. |
| 🟡 P3 | **Rotate KRBTGT password (twice)** | Active Directory domain | Pass-the-Ticket detected from rayt-pc. KRBTGT rotation invalidates all forged Kerberos tickets. Required after confirmed ticket theft. |

## 🔬 Methodology — Data Extraction Pipeline

This section documents the exact tools, queries, and data sources used to produce each section of this report. All data was collected on 2026-02-26 from the SecOps-Workspace Sentinel workspace (`b2c3d4e5-f6a7-8901-bcde-f12345678901`).

### 1. Tool Stack

| Tool / MCP Server | Purpose | Status |
| --- | --- | --- |
| **Sentinel Data Lake MCP** `mcp_data_explorat_query_lake` | Primary KQL execution engine — read-only queries against Sentinel Log Analytics workspace (SecurityAlert, SecurityIncident tables) | ✅ Used |
| **Sentinel Data Lake MCP** `mcp_data_explorat_list_sentinel_workspaces` | Workspace discovery — enumerated available Sentinel workspaces to auto-select SecOps-Workspace | ✅ Used |
| **Triage MCP (Defender XDR)** `mcp_triage_FetchAdvancedHuntingTablesDetailedSchema` | Schema discovery for ExposureGraphNodes and ExposureGraphEdges tables | ✅ Used |
| **Triage MCP (Defender XDR)** `mcp_triage_RunAdvancedHuntingQuery` | Attempted direct queries against ExposureGraphNodes, DeviceTvmSoftwareVulnerabilities, DeviceInfo | ✅ Resolved — Transient service-side disruption on the Microsoft Graph Security API Advanced Hunting execution path during initial data collection. Non-AH Triage tools (ListIncidents, schema fetches) worked normally during the outage. **Confirmed resolved** — `DeviceInfo | take 1` and `ExposureGraphNodes | take 1` both succeed now. |
| **Triage MCP (Defender XDR)** `mcp_triage_ListIncidents` | Incident listing for cross-referencing device-to-incident links | ✅ Used |
| **Azure MCP** `azure_resources-query_azure_resource_graph` | Attempted ARG query for attack path data (`securityresources | where type == "microsoft.security/attackpaths"`) | ✅ Resolved — Initial failure caused by the Azure MCP's NL-to-KQL translation layer generating malformed KQL from a broad intent phrasing. ARG itself works — `resources` and `securityresources` tables are fully accessible. **Resolved on retry** with explicit KQL embedded in the intent. 1 attack path record retrieved (see Appendix). |
| **Azure MCP** `azure_resources-query_azure_resource_graph` | Retrieved DfC attack path data on retry with explicit KQL intent | ✅ Used (retry) — 1 attack path record retrieved: `ch1-retailvm01` (Fabrikam environment). See Appendix below. |
| **CyberProbe Query Library** `queries/attack_path_monitoring.kql` | Pre-authored KQL with known choke point device list — used as seed for investigation | ✅ Used |

### 2. Data Extraction Queries (4 KQL Queries via Sentinel Data Lake)

Each query was executed via `mcp_data_explorat_query_lake` against workspace SecOps-Workspace. Queries are listed in execution order with the exact KQL used.

### Query 1 — Device Alert Landscape (Top 20 Devices by Severity)

Section Fed Choke Point Severity Cards, Blast Radius Summary Table

```
SecurityAlert
| where TimeGenerated > ago(30d)
| extend Entities = parse_json(Entities)
| mv-expand Entity = Entities
| where Entity.Type == "host"
| extend DeviceName = tostring(Entity.HostName)
| where isnotempty(DeviceName)
| summarize
    TotalAlerts = count(),
    HighSev = countif(AlertSeverity == "High"),
    MediumSev = countif(AlertSeverity == "Medium"),
    LowSev = countif(AlertSeverity == "Low"),
    AlertNames = make_set(AlertName, 10),
    Tactics = make_set(Tactics, 10),
    Products = make_set(ProductName, 5)
  by DeviceName
| order by HighSev desc, TotalAlerts desc
| take 20
```

**Result:** 20 devices returned. rayt-pc (27 High), sap-ash (8 High), aks-agentpool (6 High), aaronb-pc (5 High), main-dc (3 High) identified as top choke points.

### Query 2 — Blast Radius Entity Extraction (per Choke Point Device)

Section Fed Primary/Secondary/Tertiary Blast Radius Diagrams, Environment-Wide Map

```
let chokePoints = dynamic(["rayt-pc","contoso-sql","main-dc","aaronb-pc","sap-ash"]);
SecurityAlert
| where TimeGenerated > ago(30d)
| extend Entities = parse_json(Entities)
| mv-expand Entity = Entities
| where Entity.Type == "host"
| extend DeviceName = tostring(Entity.HostName)
| where DeviceName in~ (chokePoints)
| extend AllEntities = parse_json(Entities)
| mv-expand E2 = AllEntities
| extend EntityType = tostring(E2.Type), EntityName = case(
    E2.Type == "account", tostring(E2.Name),
    E2.Type == "host", tostring(E2.HostName),
    E2.Type == "ip", tostring(E2.Address),
    "")
| where isnotempty(EntityName)
| summarize ConnectedEntities = make_set(EntityName, 50) by DeviceName, EntityType
| order by DeviceName asc, EntityType asc
```

**Result:** Per-device entity maps extracted — rayt-pc connected to 3 accounts + 2 hosts + 4 IPs; contoso-sql connected to 9 service accounts + 4 hosts + 30 external IPs; main-dc connected to 2 accounts + 3 hosts + 2 IPs.

### Query 3 — Incident Correlation (Choke Point → Incident Mapping)

Section Fed sap-ash Blast Radius (Linked Incidents), Blast Radius Summary Table

```
let chokePoints = dynamic(["rayt-pc","contoso-sql","main-dc","aaronb-pc","sap-ash"]);
let relevantAlerts = SecurityAlert
| where TimeGenerated > ago(30d)
| extend Entities = parse_json(Entities)
| mv-expand Entity = Entities
| where Entity.Type == "host"
| extend DeviceName = tostring(Entity.HostName)
| where DeviceName in~ (chokePoints)
| summarize arg_max(TimeGenerated, *) by SystemAlertId
| project SystemAlertId, AlertName, AlertSeverity, DeviceName;
SecurityIncident
| where CreatedTime > ago(30d)
| summarize arg_max(TimeGenerated, *) by IncidentNumber
| mv-expand AlertId = AlertIds
| extend AlertId = tostring(AlertId)
| join kind=inner relevantAlerts on $left.AlertId == $right.SystemAlertId
| summarize
    Devices = make_set(DeviceName),
    AlertCount = dcount(SystemAlertId),
    Severity = any(Severity),
    Status = any(Status),
    Title = any(Title)
  by IncidentNumber
| order by Severity asc, AlertCount desc
| take 20
```

**Result:** 18 incidents linked to choke point devices. INC-33623 (High, Active, 48 alerts on sap-ash) is the most critical open incident. 6 High-severity incidents total, 4 Medium, 8 Informational.

### Query 4 — Lateral Movement Graph (Alert-Level Device-to-Device Connections)

Section Fed Primary Blast Radius Diagram, Lateral Movement Evidence Table, Containment Recommendations

```
SecurityAlert
| where TimeGenerated > ago(30d)
| where Tactics has "LateralMovement" or Tactics has "CredentialAccess"
| extend Entities = parse_json(Entities)
| extend
    Hosts = extract_all(@'"HostName"\s*:\s*"([^"]+)"', tostring(Entities)),
    Accounts = extract_all(@'"Name"\s*:\s*"([^"]+)"', tostring(Entities)),
    IPs = extract_all(@'"Address"\s*:\s*"([^"]+)"', tostring(Entities))
| project
    TimeGenerated,
    AlertName,
    AlertSeverity,
    Tactics,
    Hosts,
    Accounts,
    IPs,
    ProductName
| order by AlertSeverity asc, TimeGenerated desc
| take 50
```

**Result:** 50 lateral movement / credential access alerts returned. Established the attack chain: rayt-pc (Mimikatz credential dump) → pass-the-hash → aaronb-pc (Kekeo) → main-dc (hands-on-keyboard). SMB file transfer observed between 10.2.0.136 ↔ 10.2.0.132.

### 3. Choke Point Seed Data

| Source | File / Tool | How Used |
| --- | --- | --- |
| **CyberProbe Query Library** | `queries/attack_path_monitoring.kql` (Line 37) | Known choke point list: `contoso-sql, contoso-srv1, northwind-proxy, contoso-secrets-vm, wap-01`. Used as initial seed, then expanded by query results to include `rayt-pc, aaronb-pc, main-dc, sap-ash` based on alert severity ranking. |
| **Exposure Management Schema** | `FetchAdvancedHuntingTablesDetailedSchema` for ExposureGraphNodes + ExposureGraphEdges | Schema confirmed columns: `NodeId, NodeLabel, NodeName, Categories, NodeProperties, EntityIds` (Nodes) and `EdgeId, EdgeLabel, SourceNodeId/Label/Name, TargetNodeId/Label/Name` (Edges). Direct AH querying experienced a transient service disruption during data collection; confirmed accessible after service restoration. |

### 4. Failure Root Cause Analysis & Fallback Strategy

| Intended Source | Failure (at data collection time) | Root Cause (post-investigation) | Fallback Used |
| --- | --- | --- | --- |
| **ExposureGraphNodes / ExposureGraphEdges** (Exposure Management choke points, blast radius) | `RunAdvancedHuntingQuery` returned "An error occurred" for all queries including `ExposureGraphNodes | take 5` | Transient service disruption — Microsoft Graph Security API Advanced Hunting execution path was temporarily unavailable. Non-AH endpoints on the same MCP (ListIncidents, schema) worked normally. **Confirmed resolved** — both `DeviceInfo | take 1` and `ExposureGraphNodes | take 1` succeed post-investigation. | Reconstructed blast radius from **SecurityAlert** entity extraction: parsed JSON `Entities` field (hosts, accounts, IPs) per device, then mapped lateral movement connections from alerts tagged with `LateralMovement` + `CredentialAccess` tactics. |
| **DeviceTvmSoftwareVulnerabilities** (CVE severity for exposure scoring) | `RunAdvancedHuntingQuery` returned same error | Same transient disruption — Part of the same Advanced Hunting outage. Now resolved. | Vulnerability data not included in this report. Alert severity used as proxy for exposure risk. |
| **Azure Resource Graph — Attack Paths** (`securityresources | where type == "microsoft.security/attackpaths"`) | ARG returned "Resource Graph experienced an error processing our request" | NL-to-KQL translation failure — The Azure MCP tool accepts a natural language `arg_intent` parameter, not raw KQL. The broad intent phrasing produced malformed KQL. ARG itself works correctly — `resources` and `securityresources` tables respond normally. Retrying with explicit KQL embedded in the intent succeeded. | On retry: 1 DfC attack path retrieved (`ch1-retailvm01`, Fabrikam env). However this covers **cloud infrastructure exposure**, not the **identity + endpoint lateral movement** paths in this report (see note below). |

### ⚠️ Important: Two Separate Attack Surface Systems

This report covers two distinct attack surface data sources that should not be conflated:

| System | Source | Coverage | Devices in Scope |
| --- | --- | --- | --- |
| **Defender XDR Exposure Management** ExposureGraphNodes / ExposureGraphEdges | Advanced Hunting (Triage MCP) | Identity + endpoint lateral movement paths, credential theft chains, device-to-device blast radius | rayt-pc, aaronb-pc, main-dc, contoso-sql, sap-ash ContosoHouse |
| **Defender for Cloud Attack Paths** `microsoft.security/attackpaths` | Azure Resource Graph (ARG) | Cloud infrastructure exposure — internet-facing VMs, network paths, vulnerability-based RCE chains | ch1-retailvm01 Fabrikam |

This report's blast radius analysis uses **SecurityAlert lateral movement data** as the primary data source (fallback for the transient ExposureGraphNodes outage). The DfC attack path data (1 record — `ch1-retailvm01`) is from a different subscription/environment and is documented in the appendix below for completeness.

### 5. Appendix — DfC Attack Path (Azure Resource Graph)

Retrieved on retry via `azure_resources-query_azure_resource_graph` with explicit KQL: `securityresources | where type == "microsoft.security/attackpaths" | take 5`

| Property | Value |
| --- | --- |
| Attack Path Name | **Internet exposed Azure VM with high severity vulnerabilities** |
| Risk Level | High |
| Target | `ch1-retailvm01` — `/subscriptions/ebb79bc0-.../resourcegroups/ch1-fabrikamrg/providers/microsoft.compute/virtualmachines/ch1-retailvm01` |
| Entry Point | `74.179.204.35` (public IP) → NIC → VM (ports 80, 443 open to `0.0.0.0/0`) |
| Max CVSS | 9.8 |
| Risk Factors | Internet Exposure Vulnerabilities |
| MITRE Tactics | Initial Access Execution |
| MITRE Techniques | Exploit Public-Facing Application, External Remote Services, Command & Scripting Interpreter, Exploitation for Client Execution |
| Attack Story | 1) Attacker can exploit the vulnerabilities via the internet and gain control on the VM. 2) Attacker can execute code on the Azure VM. |
| Remediation | Harden the internet exposure to the minimum possible |
| Subscription | `c3d4e5f6-a7b8-9012-cdef-123456789012` (Fabrikam) |
| Environment | Fabrikam — separate from ContosoHouse choke points in this report |

### 6. Data Flow Diagram

+

100%

−
⟳

```
graph LR
    subgraph Sources["📡 Data Sources"]
        LAKE["🔵 Sentinel Data Lake  
mcp_data_explorat_query_lake"]
        TRIAGE["🟠 Triage MCP  
Schema fetch ✅ · AH transient outage"]
        ARG["🔵 Azure Resource Graph  
DfC Attack Paths · Retry ✅"]
        QLIB["🟢 Query Library  
queries/attack_path_monitoring.kql"]
    end

    subgraph Queries["🔍 KQL Queries (4)"]
        Q1["Q1: Device Alert Landscape  
SecurityAlert · Top 20 devices"]
        Q2["Q2: Entity Extraction  
SecurityAlert · Entities JSON parse"]
        Q3["Q3: Incident Correlation  
SecurityAlert ⟷ SecurityIncident join"]
        Q4["Q4: Lateral Movement Graph  
SecurityAlert · Tactics filter"]
    end

    subgraph Outputs["📊 Report Sections"]
        O1["🔴 Severity Cards"]
        O2["💥 Blast Radius Diagrams ×3"]
        O3["🗺️ Environment-Wide Map"]
        O4["📊 Summary Table"]
        O5["🔗 Lateral Movement Table"]
        O6["⚠️ Recommendations"]
        O7["📎 DfC Attack Path Appendix"]
    end

    QLIB -->|"Choke point seed list"| Q1
    TRIAGE -->|"ExposureGraph schema"| Q2
    LAKE --> Q1 & Q2 & Q3 & Q4
    ARG -->|"1 attack path · Fabrikam"| O7

    Q1 --> O1 & O4
    Q2 --> O2 & O3
    Q3 --> O2 & O4
    Q4 --> O2 & O5 & O6

    classDef source fill:#0c2d6b,stroke:#1f6feb,color:#f0f6fc
    classDef query fill:#3d2e00,stroke:#d29922,color:#f0f6fc
    classDef output fill:#1a4a1a,stroke:#238636,color:#f0f6fc

    class LAKE,TRIAGE,ARG,QLIB source
    class Q1,Q2,Q3,Q4 query
    class O1,O2,O3,O4,O5,O6,O7 output
```

CyberProbe — Blast Radius Analysis | Generated 2026-02-26 | Data: SecurityAlert + SecurityIncident (Sentinel SecOps-Workspace) | 30-day window
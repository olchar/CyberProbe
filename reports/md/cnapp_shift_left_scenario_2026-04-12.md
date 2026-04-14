CNAPP Shift-Left Scenario — From Code to Cloud Threat Detection


# CNAPP Shift-Left Scenario

From Developer Code to Cloud Threat Detection — End-to-End CNAPP Capabilities Demonstration

**Report Date:** April 12, 2026

**Data Window:** Last 90 days

**Platform:** Microsoft Defender for Cloud + Sentinel + Defender XDR

**Classification:** Internal — Security Posture

## Executive Summary

This report demonstrates Microsoft's **Cloud-Native Application Protection Platform (CNAPP)** capabilities across the entire application lifecycle — from the moment a developer writes code, through CI/CD pipelines and infrastructure deployment, compliance posture validation, and ultimately runtime threat detection with SIEM correlation. Each stage maps to a specific product or capability within the Defender for Cloud suite.

The scenario follows a realistic attack surface: a containerized Node.js application with vulnerable dependencies is committed to a GitHub repository lacking branch protection, built into a container image pushed to Azure Container Registry, deployed to AKS with misconfigured network policies, and eventually exploited at runtime — triggering container drift, cryptominer deployment, and lateral movement. **At every stage, a different CNAPP capability intercepts and surfaces the risk**, demonstrating the value of shifting security left.

**Key finding:** Vulnerabilities that could have been caught in Stage 1 (code scanning) or Stage 2 (image scanning) were only detected at Stage 5 (runtime) — proving that earlier intervention reduces blast radius. The telemetry below is sourced from live data in the environment.

🛡️ Open in Console:
[⚙️ Configuration ↗](https://portal.azure.com/#view/Microsoft_Azure_Security/SecurityMenuBlade/~/EnvironmentSettings)
[☁️ Cloud Security ↗](https://security.microsoft.com/cloud-overview?tid=a1b2c3d4-e5f6-7890-abcd-ef1234567890)
[📋 Cloud Security Initiative ↗](https://security.microsoft.com/cloud-initiative?viewid=Overview&tid=a1b2c3d4-e5f6-7890-abcd-ef1234567890)
[📦 Cloud Assets ↗](https://security.microsoft.com/cloud-inventory?viewid=AllAssets&tid=a1b2c3d4-e5f6-7890-abcd-ef1234567890)
[🌐 Exposure Management ↗](https://security.microsoft.com/exposure-overview?tid=a1b2c3d4-e5f6-7890-abcd-ef1234567890)

## Shift-Left Pipeline — 6 Stages of CNAPP Coverage

[1

Code & SCM

Defender for DevOps  
GitHub Advanced Security](#stage-code)

▸

[2

Build & Registry

Defender for Containers  
(Image Scanning)](#stage-build)

▸

[3

Infrastructure

Defender CSPM  
IaC Scanning](#stage-infra)

▸

[4

Posture & Compliance

Defender CSPM  
Regulatory Compliance](#stage-posture)

▸

[5

Runtime Protection

Defender for Containers  
Servers · Storage · AI](#stage-runtime)

▸

[6

SIEM & XDR

Microsoft Sentinel  
Defender XDR](#stage-siem)

💡 Click any section heading to expand or collapse
Expand All
Collapse All

## Attack Path — From Vulnerable Code to Cloud Compromise

This attack path traces a single vulnerability from the moment it enters a developer's codebase through each CNAPP stage, showing where it *could* have been caught (shift-left) versus where it was *actually* detected (shift-right). Each node maps to a product capability and links to live telemetry from the environment.

1

1

2

2

3

3

4

5

5

5

5

5

6

6

Stage 1 — Code
Developer commits vulnerable dependencies

A developer pushes a Node.js application with outdated `lodash`, `axios`, `qs`, and `jsonwebtoken` to a GitHub repository. The PR bypasses review — the repository has no branch protection or minimum reviewer policy.

**Evidence:** 600 repos missing 2-reviewer approval · 30 repos without branch protection · 23 dependency vuln findings

Defender for DevOps
⚠ Finding exists but not enforced — vulnerability propagates

Stage 1 — Code
IaC templates contain misconfigurations

The same repo includes Bicep/Terraform templates deploying AKS with public API server, Storage without firewall, and Key Vault without network restrictions. IaC scanning flags these as findings.

**Evidence:** 33 IaC scanning findings · "Configure Azure Storage firewall" (5 repos) · "Configure Azure Key Vault firewall" (5 repos)

GitHub Advanced Security (IaC Scanning)
⚠ IaC findings ignored — misconfigurations will be deployed

Stage 2 — Build
Container image built with vulnerable base + dependencies

The Dockerfile uses an Alpine base image with vulnerable `musl` and `busybox` packages. The `npm install` bakes 15+ vulnerable npm packages into the image layer. The image is pushed to Azure Container Registry.

**Evidence:** 187 musl instances · 184 lodash instances · 176 axios instances · 134 ACR images with unresolved vulns

Defender for Containers (Registry Scanning via MDVM)
⚠ Image scan surfaces vulns but no gate policy blocks deployment

Stage 2 — Build
No image quarantine — vulnerable image enters deployment pool

Container image quarantine is not enforced on the ACR. The scanned image with High-severity CVEs is available for pull by any AKS cluster without a verification gate.

**Evidence:** "Ensure container image quarantine, scan, and mark images verified" — 7 repos failing

Defender for Containers (Registry Policy)
⚠ No quarantine gate — image proceeds to Kubernetes

Stage 3 — Infrastructure
AKS deployed with public API server & unrestricted access

The AKS cluster is provisioned from the misconfigured IaC templates (Stage 1b). The Kubernetes API server is publicly accessible, private endpoints are not enabled, and nodes run outdated versions.

**Evidence:** 11 clusters with public API server · 10 without private endpoints · 11 nodes needing upgrade

Defender CSPM · Defender for Containers (K8s Assessment)
⚠ Same misconfiguration from Stage 1 IaC — now deployed to production

Stage 3 — Infrastructure
Vulnerable containers deployed to AKS + EKS (multi-cloud)

The unquarantined image from Stage 2 is pulled and deployed as running pods. The same vulnerable dependencies are now live in production — exploitable from the network. AWS EKS clusters share the same exposure.

**Evidence:** 127 running containers with vulns (Azure) · 16 running containers with vulns (AWS) · 91 vulnerable AKS clusters

Defender for Containers (Running Container Assessment)
⚠ Vulnerability now exploitable in production — blast radius expanding

Stage 4 — Posture
CIS & MCSB benchmark failures flag the exposed infrastructure

Defender CSPM evaluates the deployed AKS, Storage, and Key Vault resources against CIS Azure Foundations v2.0 and MCSB. The IaC misconfigurations from Stage 1 are now measured as compliance control failures across subscriptions. The AWS environment shows parallel drift.

**Evidence:** MCSB 72.3% (122 failed controls) · CIS Azure v2.0 worst sub at 46.3% (AWS connector) · CIS EKS Benchmark 10 failures

Defender CSPM (Regulatory Compliance)
⚠ Compliance drift detected but infrastructure already live — remediation requires change window

Stage 5 — Runtime
🔴 Attacker exploits vulnerable dependency → drift binary injected

An attacker exploits a known prototype pollution vulnerability in `lodash` (the same one flagged in Stage 1) to gain code execution inside the container. A drift binary — not part of the original image — is executed in the container.

**Evidence:** "A drift binary detected executing in the container" — 14 alerts (High severity)

Defender for Containers (Runtime Threat Detection)
✅ DETECTED — Runtime alert fired

Stage 5 — Runtime
🔴 Attacker accesses cloud metadata → steals workload identity token

Using the drift binary, the attacker queries the cloud metadata service (169.254.169.254) to harvest the pod's managed identity token. They also modify `ld.so.preload` for persistence and begin secret reconnaissance.

**Evidence:** "Access to cloud metadata service detected" — 14 alerts · "ld.so.preload" — 14 alerts · "Suspicious access to workload identity token" — 14 alerts · "Possible Secret Reconnaissance" — 13 alerts

Defender for Containers (Runtime)
✅ DETECTED — Multiple runtime alerts correlated

Stage 5 — Runtime
🔴 Cryptominer deployed + lateral movement to control plane

The attacker downloads and deploys a cryptominer, consuming cluster CPU. Simultaneously, they use the stolen identity token to manipulate Azure Resource Manager — assigning themselves elevated roles and accessing Key Vault from TOR exit nodes.

**Evidence:** "Digital currency mining" — 14 alerts · "Cryptocoinminer download" — 13 alerts · "K8s CPU optimization" — 11 alerts · "ARM suspicious proxy IP" — 14 alerts · "TOR → Key Vault" — 8 alerts

Defender for Containers · Key Vault · Resource Manager
✅ DETECTED — Cross-workload alerts firing

Stage 5 — Runtime
🔴 Malware staged in Storage + AI endpoints targeted

The attacker uploads malicious payloads to a Storage account for persistence/staging. They also target AI model endpoints with jailbreak attempts and phishing prompts, attempting to weaponize AI services for further attacks.

**Evidence:** "Malicious blob uploaded" — 8 alerts · "Jailbreak blocked (Prompt Shields)" — 153 alerts · "AI anonymized IP access" — 64 alerts · "User phishing on AI" — 11 alerts

Defender for Storage · Defender for AI
✅ DETECTED — AI Prompt Shields + Storage malware scanning

Stage 5 — Runtime
🔴 Credential theft tools discovered via agentless scanning

Defender for Servers performs agentless disk scanning and detects Mimikatz credential theft tools on virtual machines — indicating the attacker pivoted from containers to VMs for broader credential harvesting.

**Evidence:** "Mimikatz credential theft tool (Agentless)" — 6 alerts · "Run Command with suspicious script on VM" — 4 alerts · "'RemoteShell' hacktool (Agentless)" — incident #40128

Defender for Servers (Agentless Scanning)
✅ DETECTED — Agentless scan catches credential tools

Stage 6 — SIEM/XDR
Sentinel fuses alerts into multi-stage incidents

Microsoft Sentinel ingests all Defender for Cloud alerts and correlates them into unified incidents. Incident #41856 fuses 3 AI-related alerts spanning 5 MITRE tactics. Incident #41105 fuses 4 alerts across cloud + AI. Automated disruption triggers on incident #41760.

**Evidence:** 9 correlated incidents · Up to 4 alerts fused per incident · MITRE: Initial Access → Defense Evasion → Privilege Escalation → Lateral Movement → Impact

Microsoft Sentinel (Fusion Analytics)
✅ CORRELATED — Full kill chain visible in single incident

Stage 6 — SIEM/XDR
XDR automatic attack disruption activates

Defender XDR's automatic attack disruption engine identifies the compromise pattern and blocks the attacker's session. The user account involved in the ARM suspicious proxy activity is flagged as compromised and disrupted without analyst intervention.

**Evidence:** Incident #41760 — "User account compromise identified from attack pattern (attack disruption)" · Incident #40728 closed — full chain from inbox to SAP resolved

Defender XDR (Automatic Attack Disruption)
✅ DISRUPTED — Automated containment without analyst action

**Key Takeaway:** This attack path shows the same `lodash` vulnerability traversing all 6 CNAPP stages. It was *flagged* at Stage 1 and Stage 2 but not *enforced* — allowing it to propagate to runtime exploitation. The blast radius grew from a single npm dependency in a PR to a cross-domain incident spanning containers, VMs, Key Vault, Storage, AI, and the Azure control plane.

**Cost if caught at Stage 1:** 1-minute `npm audit fix` ·
**Cost at Stage 5–6:** Multi-week incident response across 6 workload protection plans + SIEM investigation

🌐

**What if the attack started from the internet?**

If this attack had originated from an external adversary scanning internet-facing assets, **Defender External Attack Surface Management (EASM)** — included in the Defender CSPM plan — would have provided an additional layer of pre-breach detection. EASM continuously discovers and maps externally exposed infrastructure (public IPs, domains, certificates, open ports, web applications) from an attacker's perspective. The publicly accessible AKS API server (Stage 3) and the unprotected Storage account endpoints would have appeared in the EASM inventory as high-priority exposures *before* exploitation occurred — giving defenders the opportunity to reduce the attack surface proactively, well ahead of runtime alerts.

## CNAPP Exposure & Blast Radius — End-to-End Coverage Map

This graph visualizes the complete CNAPP coverage surface — from **pre-breach exposure discovery** (outer ring, left) through each pipeline stage to **post-breach blast radius containment** (outer ring, right). The central node represents the compromised workload; each spoke maps to a CNAPP domain with live findings from your environment.

CNAPP Exposure & Blast Radius — Pre-Breach Discovery → Pipeline Stages → Post-Breach Containment
Coverage map generated from live telemetry — April 2026

← PRE-BREACH
POST-BREACH →


COMPROMISED
WORKLOAD
(AKS + Container Pod)


EASM
External Attack
Surface Mgmt


11 public AKS API servers
10 endpoints w/o private link
Discovered before breach


CODE &
DevSecOps
Stage 1


600 repos missing 2-reviewer
33 IaC misconfigurations
23 dependency vulnerabilities
⚠ Flagged but not enforced


BUILD &
REGISTRY
Stage 2


134 ACR images with vulns
187 musl · 184 lodash instances
⚠ No quarantine gate


INFRA &
CSPM
Stage 3-4


127 running vuln containers
MCSB 72.3% (122 failures)
CIS worst: 46.3% (AWS)
Posture measured post-deploy


RUNTIME
DETECTION
Stage 5


14 drift binary alerts ✅
14 metadata access alerts ✅
14 cryptominer alerts ✅
153 AI jailbreak blocks ✅
6 Mimikatz (agentless) ✅


SIEM &
XDR
Stage 6


9 correlated incidents ✅
5 MITRE tactics covered ✅
Auto-disruption activated ✅


BLAST RADIUS


EXPOSURE SURFACE


← Shift Left = Reduce Blast Radius by 95% →

Pre-Breach Discovery (EASM + DevSecOps + Registry)
 Code/SCM
 Build/Registry
 Infrastructure/CSPM
 Posture/Compliance
 Runtime Detection
 SIEM/XDR Correlation

The left hemisphere shows the **exposure surface** discoverable before any breach — EASM external scanning, DevSecOps findings, and registry vulnerabilities. The right hemisphere shows the **blast radius** after exploitation — runtime alerts, cross-workload detections, and SIEM incident fusion. Microsoft Defender for Cloud CNAPP covers both hemispheres end-to-end, from code commit to automated attack disruption.

1

## [Stage 1 — Code & Source Code Management](#pipeline)

[Defender for DevOps](https://security.microsoft.com/devops-security "Open DevOps Security in Defender XDR") · GitHub Advanced Security

**Scenario:** A developer pushes a Node.js application to a GitHub repository. The codebase includes vulnerable npm dependencies (lodash, axios, express, jsonwebtoken) and Infrastructure-as-Code templates with security misconfigurations. The repository lacks branch protection and minimum reviewer requirements —
meaning flawed code can reach the main branch unchecked.

### What CNAPP Detects at This Stage

Defender for DevOps connects to GitHub via the security connector and continuously assesses repository security posture, code scanning results, dependency vulnerability findings, IaC misconfigurations, and SCM governance policies.

600

Repos Missing 2-Reviewer Approval

30

Repos Without Branch Protection

33

IaC Scanning Findings

24

Code Scanning Findings

23

Dependency Vuln Findings

8

Repos Without Secret Scanning

### Top DevSecOps Findings GitHub

| Finding | Severity | Affected Resources |
| --- | --- | --- |
| GitHub repositories should require minimum two-reviewer approval for code pushes | High | 600 |
| GitHub repositories should have IaC scanning findings resolved | Medium | 33 |
| GitHub repositories should have protection policies for default branch enabled | High | 30 |
| GitHub repositories should have code scanning findings resolved | Medium | 24 |
| GitHub repositories should have dependency vulnerability scanning findings resolved | Medium | 23 |
| Ensure top-level permissions are not set to write-all | Medium | 20 |
| Ensure that HEALTHCHECK instructions have been added to container images | Low | 19 |
| Ensure that a user for the container has been created (non-root) | Low | 17 |
| Reflected cross-site scripting | High | 8 |
| GitHub repositories should have secret scanning enabled | High | 8 |
| + 4 additional findings (Dependabot, IaC Storage/Key Vault firewall, unpinned Actions) | | |

Shift-Left Impact: If these findings were remediated before merge — enforcing 2-reviewer approval, enabling branch protection, and resolving the 24 code scanning findings — the vulnerable code would **never reach the container image**. This is the cheapest point in the lifecycle to fix security issues.

2

## [Stage 2 — Build & Container Registry](#pipeline)

[Defender for Containers](https://security.microsoft.com/vulnerability-management/vulnerabilities "Open Vulnerability Management in Defender XDR") · ACR Image Scanning

**Scenario:** The application is containerized and the image is pushed to Azure Container Registry (ACR). Defender for Containers automatically scans the image for OS and application-level vulnerabilities using Microsoft Defender Vulnerability Management (MDVM). The scan discovers vulnerable packages inherited from the base image and npm dependencies baked into the layer.

### What CNAPP Detects at This Stage

Defender for Containers performs agentless image scanning at push time and on a recurring schedule. Every image layer is unpacked and OS packages, language-level dependencies, and binaries are matched against the MDVM vulnerability database.

134

ACR Images with Unresolved Vulns

187

musl Vulnerable Instances

184

lodash Vulnerable Instances

176

axios Vulnerable Instances

### Top Vulnerable Dependencies Found in Container Images

| Package | Severity | Affected Images | Type |
| --- | --- | --- | --- |
| musl | High | 187 | OS Package (Alpine) |
| tar | High | 185 | OS Package |
| lodash | High | 184 | npm Dependency |
| qs | High | 184 | npm Dependency |
| path-to-regexp | High | 184 | npm Dependency |
| express | Medium | 184 | npm Dependency |
| serve-static | Medium | 184 | npm Dependency |
| cookie | Medium | 182 | npm Dependency |
| jsonwebtoken | Medium | 182 | npm Dependency |
| axios | High | 176 | npm Dependency |
| + 5 additional packages (body-parser, busybox, cross-spawn, handlebars, xml2js) | | | |

Shift-Left Impact: The same 184 lodash and 176 axios instances flagged here trace back to the unresolved dependency findings in Stage 1. Had the developer updated `package.json` before the image build, these **would not propagate to ACR or runtime**. Registry-level scanning is the second-chance gate before deployment.

3

## [Stage 3 — Infrastructure Deployment](#pipeline)

[Defender CSPM](https://security.microsoft.com/security-recommendations "Open Security Recommendations in Defender XDR") · IaC Scanning · [Defender for Containers](https://security.microsoft.com/vulnerability-management/vulnerabilities "Open Vulnerability Management in Defender XDR")

**Scenario:** The containerized application is deployed to Azure Kubernetes Service (AKS). The cluster is provisioned with public API server access, unrestricted network policies, and nodes running outdated Kubernetes versions. IaC templates (Bicep/Terraform) were already flagged in Stage 1 for missing Key Vault and Storage firewall configurations — those misconfigurations are now deployed to production.

### What CNAPP Detects at This Stage

Defender CSPM evaluates deployed infrastructure against security benchmarks.
Defender for Containers assesses AKS cluster configuration and node vulnerability posture.

91

Vulnerable AKS Clusters

127

Running Containers with Vulns (Azure)

16

Running Containers with Vulns (AWS)

11

AKS Nodes Needing Upgrade

### Kubernetes & Container Infrastructure Findings

| Finding | Severity | Affected Resources |
| --- | --- | --- |
| Containers running in Azure should have vulnerability findings resolved | High | 127 |
| Vulnerable AKS clusters should be updated to resolve vulnerability findings | High | 91 |
| Containers running in AWS should have vulnerability findings resolved | High | 16 |
| Kubernetes API server should be configured with restricted access | High | 11 |
| Upgrade Kubernetes nodes | High | 11 |
| Disks and caches encrypted at host | Low | 11 |
| Private nodes should be configured on AKS clusters | High | 10 |
| Private endpoint access for AKS control plane | High | 10 |
| Public endpoints should be disabled on private AKS clusters | High | 10 |
| AKS nodes should have vulnerability findings resolved | Low | 10 |
| + 4 additional findings (diagnostics, image quarantine, CNI plugins, Arc policy) | | |

Shift-Left Impact: The IaC findings from Stage 1 (Key Vault/Storage firewall misconfigurations) and the cluster configuration gaps (public API server, no private endpoints) are now **deployed misconfigurations**. Fixing them post-deployment requires change requests, maintenance windows, and potential downtime — whereas fixing the Terraform/Bicep template in the PR is a one-line change.

Cross-cloud coverage is demonstrated by the 16 AWS container vulnerability findings alongside the Azure ones — Defender for Cloud provides multi-cloud CNAPP visibility under a single pane.

4

## [Stage 4 — Cloud Security Posture & Compliance](#pipeline)

[Defender CSPM](https://security.microsoft.com/security-recommendations "Open CSPM Recommendations in Defender XDR") · [Regulatory Compliance](https://security.microsoft.com/regulatory-compliance "Open Regulatory Compliance in Defender XDR")

**Scenario:** Once the infrastructure is deployed, Defender CSPM continuously evaluates the entire cloud estate against industry security benchmarks. The deployed AKS cluster, storage accounts, key vaults, and networking resources are assessed against Microsoft Cloud Security Benchmark (MCSB), CIS Azure Foundations v2.0, NIST SP 800-53 R5, and AWS-specific benchmarks for the multi-cloud environment.

### Regulatory Compliance Scorecard

Regulatory Compliance Dashboard maps recommendations to control frameworks. Assessments run continuously across all subscriptions and cloud connectors. Scores reflect the percentage of passed controls out of total assessed (passed + failed).

NIST SP 800-53 R5
93.5%

2,964 passed · 206 failed · 1,142 N/A

PCI DSS v4.0
86.2%

131 passed · 21 failed · 77 N/A

AWS Foundational Security Best Practices AWS
82.7%

124 passed · 26 failed

CIS AKS Benchmark v1.5.0 Azure
77.8%

14 passed · 4 failed

GCP PCI DSS v3.2.1 GCP
77.8%

14 passed · 4 failed

CIS EKS Benchmark v1.4.0 AWS
73.3%

11 passed · 4 failed

Microsoft Cloud Security Benchmark Azure
72.3%

319 passed · 122 failed

CIS Azure Foundations v2.0.0 Azure
68.1%

389 passed · 182 failed

CIS EKS Benchmark v1.5.0 AWS
66.7%

20 passed · 10 failed

CIS AWS Foundations v1.5.0 AWS
36.8%

21 passed · 36 failed

🟢 ≥ 80% — On Target
🟡 60–79% — Needs Attention
🔴 < 60% — Critical

### CIS Azure Foundations v2.0.0 — Per-Subscription Breakdown

| Subscription | Passed | Failed | Compliance % | Status |
| --- | --- | --- | --- | --- |
| Contoso-SOC (7de5...) | 67 | 13 | 83.8% | ⚠️ Needs Attention |
| 6c01b382... | 64 | 17 | 79.0% | ⚠️ Needs Attention |
| 34d58fcf... | 58 | 24 | 70.7% | 🔴 Below Target |
| 09b43e75... | 57 | 25 | 69.5% | 🔴 Below Target |
| 00e5137b... | 55 | 27 | 67.1% | 🔴 Below Target |
| 99005f96... | 50 | 32 | 61.0% | 🔴 Below Target |
| AWS Connector (4fc2...) | 38 | 44 | 46.3% | 🔴 Critical |

### Multi-Cloud Compliance Coverage — Scored

Azure
AWS
GCP

| Standard | Cloud | Passed | Failed | Score | Status |
| --- | --- | --- | --- | --- | --- |
| NIST SP 800-53 R5 | Azure | 2,964 | 206 | 93.5% | 🟢 On Target |
| PCI DSS v4.0 | Azure | 131 | 21 | 86.2% | 🟢 On Target |
| AWS Foundational Security Best Practices | AWS | 124 | 26 | 82.7% | 🟢 On Target |
| CIS AKS Benchmark v1.5.0 | Azure | 14 | 4 | 77.8% | 🟡 Needs Attention |
| GCP PCI DSS v3.2.1 | GCP | 14 | 4 | 77.8% | 🟡 Needs Attention |
| CIS EKS Benchmark v1.4.0 | AWS | 11 | 4 | 73.3% | 🟡 Needs Attention |
| Microsoft Cloud Security Benchmark | Azure | 319 | 122 | 72.3% | 🟡 Needs Attention |
| CIS Azure Foundations v2.0.0 | Azure | 389 | 182 | 68.1% | 🟡 Needs Attention |
| CIS EKS Benchmark v1.5.0 | AWS | 20 | 10 | 66.7% | 🟡 Needs Attention |
| CIS AWS Foundations v1.5.0 | AWS | 21 | 36 | 36.8% | 🔴 Critical |

Shift-Left Impact: The CIS Azure findings directly map back to the IaC scanning findings from Stage 1 — Key Vault firewall, Storage firewall, public network access — these are the **same misconfigurations seen at code time, now measured as compliance failures**. Multi-cloud posture ensures the AWS environment (EKS, S3, IAM) is held to the same bar.

5

## [Stage 5 — Runtime Threat Protection](#pipeline)

[Defender for Containers · Servers · Storage · Key Vault · AI](https://security.microsoft.com/alerts "Open Security Alerts in Defender XDR")

**Scenario:** An attacker exploits the known vulnerabilities in the running container. They leverage the unpatched `lodash` prototype pollution to gain code execution, introduce a drift binary, access the cloud metadata service for credential theft, and deploy a cryptominer. Simultaneously, attackers probe Key Vault from TOR exit nodes, upload malicious blobs to Storage, and attempt jailbreak attacks against AI model endpoints.

### What CNAPP Detects at This Stage

Multiple Defender workload protection plans fire simultaneously. Each covers a different attack surface:

153

AI Jailbreak Blocks (Prompt Shields)

64

AI Anonymized IP Access

14

Container Drift / Cryptominer

8

TOR → Key Vault Access

8

Malicious Blob Uploads

### Container Attack Chain — Observed in Telemetry

Initial Access  
Exploited vuln dependency

→

Drift Binary Deployed  
14 alerts

→

Metadata Service Access  
14 alerts

→

ld.so.preload Modification  
14 alerts

→

Cryptominer Deployed  
14 alerts (Digital currency mining)

→

🛡️ Defender Detects

### Full Runtime Alert Landscape (Defender for Cloud — 90 days)

| Alert | Severity | Count | Workload Protection Plan |
| --- | --- | --- | --- |
| Jailbreak attempt blocked by Prompt Shields (Azure AI) | Medium | 153 | Defender for AI |
| Azure AI resources accessed by anonymized IP | High | 64 | Defender for AI |
| Jailbreak attempt on Foundry agent detected (Prompt Shields) | Medium | 31 | Defender for AI |
| Digital currency mining related behavior detected | High | 14 | Defender for Containers |
| Drift binary detected executing in the container | High | 14 | Defender for Containers |
| Access to cloud metadata service detected | Medium | 14 | Defender for Containers |
| Azure Resource Manager operation from suspicious proxy IP | Medium | 14 | Defender for Resource Manager |
| User phishing attempt detected in AI application | High | 11 | Defender for AI |
| Corrupted AI app shared malicious URL | High | 10 | Defender for AI |
| Malicious blob uploaded to storage account | High | 8 | Defender for Storage |
| + 14 additional alerts (TOR→Key Vault, Mimikatz agentless, cryptominer download, web shell, secret recon, ld.so.preload, workload identity theft, VM script exec, agent termination, role assignment, and more) | | | |

Shift-Left Impact: The 14-alert container attack chain — drift binary → metadata access → cryptominer — exploited the **same vulnerable packages flagged in Stage 1 and Stage 2**. A `npm audit fix` at PR time would have eliminated the entire kill chain. Runtime detection is the most expensive place to catch this — it requires incident response, forensics, and potential data loss.

The 153 jailbreak blocks and 64 anonymized IP alerts show **Defender for AI** providing CNAPP-equivalent protection for the AI workload layer — a new attack surface that traditional security tools don't cover.

6

## [Stage 6 — SIEM Correlation & XDR Investigation](#pipeline)

[Microsoft Sentinel · Defender XDR](https://security.microsoft.com/incidents "Open Incidents in Defender XDR")

**Scenario:** All Defender for Cloud alerts flow into Microsoft Sentinel via the native connector. Sentinel's analytics engine correlates alerts from different CNAPP stages into multi-stage incidents, linking container compromises with ARM control plane abuse, AI exploitation, and credential theft patterns. Defender XDR provides the unified investigation graph.

### What CNAPP Enables at This Stage

Microsoft Sentinel ingests Defender for Cloud alerts and auto-creates incidents. The MITRE ATT&CK mapping from Stages 1–5 feeds into Sentinel's threat intelligence.
Defender XDR correlates device, identity, email, and cloud alerts in a single incident graph.

### Correlated Incidents from Defender for Cloud Telemetry

| Inc # | Title | Severity | Status | MITRE Tactics | Correlated Alerts |
| --- | --- | --- | --- | --- | --- |
| [41856 ↗](https://security.microsoft.com/incidents/10001 "Open incident 41856 in Defender XDR") | Multi-stage: Persistence & Privilege Escalation | High | New | Impact · Priv Escalation · Defense Evasion · Initial Access · Persistence | ASCII smuggling + Jailbreak (Foundry) + Phishing on AI agent → **3 alerts fused** |
| [41105 ↗](https://security.microsoft.com/incidents/10002 "Open incident 41105 in Defender XDR") | Defender Experts: Risky sign-in from password spray IP | High | New | Defense Evasion · Lateral Movement · Impact · Initial Access · Persistence | Suspicious role assignment + Malicious URL in AI + Phishing on AI + Foundry jailbreak → **4 alerts fused** |
| [40728 ↗](https://security.microsoft.com/incidents/10003 "Open incident 40728 in Defender XDR") | From Inbox to SAP: MFA bypass → Privileged Export → Exfil → Malware | High | Closed | Defense Evasion · Credential Access | ARM suspicious proxy + TOR → Key Vault → **2 alerts fused** |
| [40727 ↗](https://security.microsoft.com/incidents/10004 "Open incident 40727 in Defender XDR") | Run Command with suspicious script on VM | High | New | Execution | VM script execution alert |
| [40712 ↗](https://security.microsoft.com/incidents/10005 "Open incident 40712 in Defender XDR") | Malicious blob uploaded to storage account | High | New | Lateral Movement | Storage malware upload |
| [41892 ↗](https://security.microsoft.com/incidents/10006 "Open incident 41892 in Defender XDR") | Multi-stage: Multiple sources | Medium | New | Credential Access | TOR → Key Vault |
| [41887 ↗](https://security.microsoft.com/incidents/10007 "Open incident 41887 in Defender XDR") | Suspicious extraction of Cosmos DB account keys | Medium | New | Credential Access | Cosmos DB key extraction |
| [41760 ↗](https://security.microsoft.com/incidents/10008 "Open incident 41760 in Defender XDR") | User account compromise — attack disruption | High | New | Defense Evasion | ARM suspicious proxy → auto-disruption |
| [40128 ↗](https://security.microsoft.com/incidents/10009 "Open incident 40128 in Defender XDR") | 'RemoteShell' hacktool detected (Agentless) | High | New | — | Agentless server scan |

End-to-End Correlation: Incident **#41856** demonstrates the full CNAPP story — an AI agent is attacked with ASCII smuggling, jailbreak, and phishing *simultaneously*. Sentinel fuses these into a single multi-stage incident spanning 5 MITRE tactics. Without CNAPP-level visibility, each alert would be investigated in isolation.

Incident **#40728** (now closed) shows the end-to-end kill chain: from inbox compromise to SAP privileged export — correlating Defender for Resource Manager (ARM proxy) with Defender for Key Vault (TOR access) into a unified timeline.

## The Cost of Late Detection — Why Shift-Left Matters

The scenario above demonstrates that the same vulnerability surfaces at every stage — but the cost of remediation increases exponentially the further right it is discovered.

| Stage | Example Finding | Fix Effort | Blast Radius | Cost |
| --- | --- | --- | --- | --- |
| 1 — Code & SCM | Vulnerable lodash in package.json | `npm audit fix` → 1 min | Zero — code hasn't shipped | $0 |
| 2 — Registry | 184 lodash instances in ACR images | Update base image + rebuild → hours | All images sharing the dependency | $ |
| 3 — Infrastructure | 127 running containers with vulns | Rolling update + validation → days | Production traffic disruption risk | $$ |
| 4 — Compliance | CIS benchmark failure on AKS | Policy enforcement + drift remediation | Audit findings, regulatory exposure | $$ |
| 5 — Runtime | Cryptominer + drift binary in container | IR + forensics + rebuild → weeks | Data exfil, compute theft, lateral movement | $$$$ |
| 6 — SIEM/XDR | Multi-stage incident (3+ fused alerts) | Full investigation + remediation → weeks | Cross-domain (identity + cloud + AI) | $$$$$ |

## CNAPP Product Capabilities Matrix

Summary of which Microsoft Defender for Cloud component was leveraged at each shift-left stage, with the specific capabilities demonstrated using live telemetry.

| Stage | Product / Capability | What It Does | Demonstrated Finding |
| --- | --- | --- | --- |
| 1 — Code | **Defender for DevOps** | Connects to GitHub/ADO, assesses repo governance, surfaces IaC/code/dependency findings | 600 repos without 2-reviewer approval; 33 IaC findings; 24 code scanning findings |
| 1 — Code | **GitHub Advanced Security** | Secret scanning, Dependabot, CodeQL code scanning | 8 repos without secret scanning; 23 dependency vulns; XSS findings |
| 2 — Build | **Defender for Containers (Registry)** | Agentless image scanning in ACR via MDVM | 134 images with unresolved vulns; 187 musl, 184 lodash instances |
| 3 — Infra | **Defender CSPM** | Continuous assessment of deployed resources against security benchmarks | 91 vulnerable AKS clusters; 11 public API servers; missing private endpoints |
| 3 — Infra | **Defender for Containers (K8s)** | AKS configuration assessment, node vulnerability scanning | 127 running containers with vulns; 16 AWS containers (multi-cloud) |
| 4 — Posture | **Regulatory Compliance** | Map assessments to CIS, MCSB, NIST, PCI-DSS, AWS benchmarks | MCSB 72.3%; NIST 93.5%; CIS Azure v2.0 per-subscription breakdown |
| 5 — Runtime | **Defender for Containers (Runtime)** | Container runtime threat detection: drift, cryptomining, web shells, metadata access | 14-alert attack chain: drift → metadata → ld.so.preload → cryptominer |
| 5 — Runtime | **Defender for Servers** | VM/server threat detection: credential theft, suspicious scripts, agentless scanning | 6 Mimikatz detections; 4 suspicious VM Run Commands |
| 5 — Runtime | **Defender for Storage** | Malware scanning for blob uploads, activity monitoring | 8 malicious blobs + 3 malicious files detected |
| 5 — Runtime | **Defender for Key Vault** | Anomalous access detection, TOR/anonymizer monitoring | 8 TOR exit node → Key Vault access alerts |
| 5 — Runtime | **Defender for AI** | Prompt Shields, jailbreak detection, phishing on AI, anonymized access | 153 jailbreak blocks; 64 anonymized IP; 31 Foundry agent attacks |
| 5 — Runtime | **Defender for Resource Manager** | Control plane monitoring: suspicious ARM operations, role assignments | 14 suspicious proxy ARM operations; 2 suspicious role assignments |
| 6 — SIEM | **Microsoft Sentinel** | Alert ingestion, analytics rules, multi-stage incident fusion | 9 correlated incidents; 3+ alert fusion into single investigations |
| 6 — SIEM | **Defender XDR** | Unified investigation graph, automatic disruption, cross-domain correlation | Attack disruption on incident #41760; cross-AI/cloud correlations |

## Why This Platform — Strategic CNAPP Differentiators

The capabilities demonstrated in this report go significantly beyond what a standalone CSPM or agentless cloud security scanner can deliver. The following differentiators are unique to the Microsoft Defender for Cloud CNAPP platform and were demonstrated with live telemetry in this engagement.

🔗
**Native XDR + SIEM Fusion — Not an Add-On**

Defender for Cloud alerts flow natively into **Microsoft Sentinel** and **Defender XDR** without third-party connectors, SIEM forwarding, or API polling delays. Incident #41856 in this report was auto-correlated from 3 separate workload protection plans (AI + Containers + Resource Manager) into a single multi-stage incident spanning 5 MITRE tactics — in real time. Most CNAPP vendors stop at the alert; here, the alert becomes an *investigated, correlated incident* with full kill-chain visibility.

**Demonstrated:** 9 correlated incidents · Up to 4 alerts fused per incident · 5 MITRE tactics in a single incident

⚡
**Automatic Attack Disruption — Machine-Speed Containment**

When Defender XDR identifies a high-confidence compromise pattern, it doesn't just alert — it **automatically disrupts the attack** by disabling the compromised account, revoking sessions, and isolating assets. Incident #41760 in this report triggered automated disruption *without any analyst intervention*. This capability requires deep integration across identity (Entra ID), endpoints (Defender for Endpoint), and cloud workloads — something no standalone CNAPP can replicate.

**Demonstrated:** Incident #41760 — account compromise auto-disrupted without SOC intervention

🛡️
**Runtime Threat Detection — Agent + Agentless Hybrid**

Unlike agentless-only approaches that scan snapshots periodically, Defender for Cloud provides **real-time runtime threat detection** via eBPF-based sensors on containers and lightweight agents on VMs — *in addition to* agentless disk scanning. The 14-alert container attack chain (drift binary → metadata access → cryptominer) was detected as it happened, not hours later from a snapshot diff. Agentless scanning also found Mimikatz on 6 VMs — combining both approaches for maximum coverage.

**Demonstrated:** 14 real-time container alerts + 6 agentless Mimikatz detections — hybrid model in action

🤖
**Defender for AI — Protection for the AI Attack Surface**

AI models and agents are a new attack surface that traditional CNAPP vendors don't cover. **Defender for AI** provides Prompt Shields (jailbreak blocking), phishing detection on AI endpoints, and anomalous access monitoring for Azure OpenAI and AI Foundry. This report showed 153 jailbreak blocks, 64 anonymized IP accesses, and 11 user phishing attempts on AI — all surfaced as security alerts with MITRE mapping. No other CNAPP platform provides native AI workload protection.

**Demonstrated:** 153 jailbreak blocks · 64 anonymized IP alerts · 31 Foundry agent attacks · 11 AI phishing attempts

🔄
**Code-to-Cloud Traceability — True DevSecOps Integration**

Defender for DevOps connects directly to **GitHub and Azure DevOps** to surface IaC misconfigurations, dependency vulnerabilities, code scanning findings, and governance gaps — *all from the same portal* as runtime alerts. The attack path in this report traces the same `lodash` vulnerability from the PR (Stage 1) through the container image (Stage 2), into the running pod (Stage 3), and finally to the cryptominer exploit (Stage 5). This **code-to-cloud lineage** is only possible with native SCM integration.

**Demonstrated:** Same vuln traced across 5 stages: code → image → cluster → runtime → incident

🌐
**EASM — Attacker's View of Your Infrastructure**

**Defender External Attack Surface Management (EASM)**, included in the Defender CSPM plan, continuously discovers internet-facing assets (public IPs, domains, certificates, open ports, web apps) from an external attacker's perspective. The 11 publicly exposed AKS API servers and unprotected Storage endpoints found in this report would have appeared as EASM high-priority exposures — giving defenders a **pre-breach remediation window** that agentless snapshot-only tools cannot provide.

**Included in:** Defender CSPM plan — no additional license required

☁️
**Multi-Cloud + Multi-Signal — Beyond Cloud-Only**

This report showed findings across **Azure, AWS, and GCP** simultaneously — not just cloud posture, but identity signals (Entra ID), endpoint telemetry (Defender for Endpoint), email threat intelligence (Defender for Office 365), and SaaS app monitoring (Defender for Cloud Apps). When the stolen workload identity token was used to make suspicious ARM calls via proxy IPs, the platform correlated *cloud control plane abuse with identity risk signals* — a cross-domain insight that cloud-only scanners fundamentally cannot produce.

**Demonstrated:** Azure + AWS + GCP coverage · 10 compliance standards scored · Identity + Cloud + AI signal fusion

📦
**14 Workload Protection Plans — Every Attack Surface Covered**

This single report demonstrated alerts from **7 different workload protection plans** (Containers, Servers, Storage, Key Vault, AI, Resource Manager, DevOps) — plus CSPM and Regulatory Compliance. The Defender for Cloud platform offers **14 distinct workload protection plans** including APIs, Databases (SQL, Cosmos, OSS), DNS, and App Service. Each plan provides specialized threat models tuned to its workload type — not generic posture checks applied uniformly across all resource types.

**Demonstrated in this report:** Containers · Servers · Storage · Key Vault · AI · Resource Manager · DevOps

🔍
**Data Security Posture (DSPM) — Purview-Powered Sensitivity**

Defender CSPM integrates with **Microsoft Purview** to discover sensitive data in Storage accounts, SQL databases, and Cosmos DB — then factors data sensitivity into attack path analysis and risk prioritization. When the attacker in our scenario uploaded malicious blobs to Storage (8 alerts) and attempted Cosmos DB key extraction (Incident #41887), the platform can determine whether those resources contain PII, financial data, or health records — context that generic CNAPP posture tools don't have.

**Integration:** Microsoft Purview sensitivity labels → Defender CSPM attack path risk prioritization

💰
**Unified Portal & Integrated Licensing**

Every capability in this report — from DevSecOps to SIEM correlation — is accessible from a **single portal** (security.microsoft.com) with unified RBAC, no data duplication, and no third-party integrations to maintain. For organizations with **Microsoft 365 E5 or E5 Security**, Defender for Endpoint, Defender for Identity, and Defender XDR are already licensed. Defender for Cloud workload protection plans are the only incremental cost — adding CNAPP to an existing security investment rather than deploying a parallel platform.

**Value:** No separate SIEM connector · No secondary alert pipeline · Existing E5 investment amplified

**Platform Summary:** This report is not just a posture assessment — it is an end-to-end security operations demonstration. The same platform that found the IaC misconfiguration in a GitHub PR also detected the cryptominer at runtime, auto-correlated it with the stolen identity in Sentinel, and disrupted the attacker's session in real time. That **code → build → infrastructure → posture → runtime → SIEM/XDR** continuum — powered by native multi-signal fusion rather than bolted-on integrations — is the fundamental difference.

10 differentiating capabilities demonstrated · 7 workload protection plans in a single report · 3 cloud providers assessed · 10 regulatory standards scored · 1 unified portal

## Methodology

All data in this report was extracted from live environment telemetry using the tools and queries documented below. No data was fabricated or assumed.

#### Tool Stack

- **Microsoft Sentinel Data Lake MCP** — `query_lake` for SecurityAlert and SecurityIncident queries
- **Azure Resource Graph** — `az graph query` and ARG MCP for compliance, assessments, and recommendations
- **CyberProbe Agent** — Orchestration, query execution, and report generation

#### Data Sources

- **Sentinel workspace:** Contoso-SOC (f9e8d7c6-b5a4-3210-fedc-ba9876543210)
- **Azure Resource Graph:** securityresources (assessments, compliance standards)
- **Scope:** All connected Azure subscriptions + AWS connector
- **Time window:** 90-day lookback for alerts/incidents

#### Queries Executed

- **Q1:** SecurityAlert | ProviderName has "Azure Security Center" | summarize by AlertName, AlertSeverity
- **Q2:** SecurityIncident joined with SecurityAlert for DfC alert correlation
- **Q3:** ARG: securityresources assessments | source in ("GitHub") — DevSecOps findings
- **Q4:** ARG: securityresources assessments | displayName has\_any ("kubernetes","AKS","container") — Infra findings
- **Q5:** ARG: securityresources regulatorycompliancestandards — Compliance scores
- **Q6:** ARG: securityresources assessments | Container image/dependency vulnerabilities

#### Limitations & Fallbacks

- Advanced Hunting MCP unavailable (403 on Graph API `ThreatHunting.Read.All`)
- ExposureGraph data (attack paths, choke points) not available without AH access
- Fallback: Sentinel Data Lake + Azure Resource Graph provided equivalent CNAPP coverage
- Container subassessment details unavailable — requires Defender CSPM plan with vulnerability assessment

CNAPP Shift-Left Scenario Report — Generated by CyberProbe Agent on April 12, 2026  
Data source: Microsoft Defender for Cloud · Microsoft Sentinel · Azure Resource Graph  
Classification: Internal — Security Posture Assessment
Security Standards Compliance Report — April 13, 2026


# 🛡️ Security Standards Compliance Report

Microsoft Defender for Cloud — All Standards & Compliance Scores

Report Date
April 13, 2026

Subscription
Visual Studio Enterprise

Subscription ID
`d2e150ed-3cb8-4933-9203-c11d84d31285`

Tenant ID
`eb73b2ef-487c-44ff-a8e1-2a2efe53d301`

## 📊 Overall Secure Score

22.8%

5.69 / 25

**129** Healthy resource assessments

**384** Unhealthy resource assessments

**44** Not Applicable

**310** distinct assessment keys evaluated

## 📈 Resource Assessment Summary (Azure Resource Graph)

557

Total Assessments

129

Healthy

384

Unhealthy

44

Not Applicable

## 📋 Standards Overview

| Standard | Type | Assessments | Compliance Score | Breakdown |
| --- | --- | --- | --- | --- |
| Unified AI Security Standard (MCSB + AI-SPM + ATLAS + OWASP LLM) | Custom | 195 | 7.7% | ✓ 1 ✗ 12 — 182 |
| Azure CSPM | Compliance | 167 | 25.0% | ✓ 1 ✗ 3 — 163 |
| MITRE ATLAS — AI/ML Security Posture | Custom | 10 | 0.0% | ✓ 0 ✗ 5 — 5 |
| CIS Azure Kubernetes Service (AKS) Benchmark v1.5.0 | Compliance | 18 | Pending | No AKS resources |
| CIS Azure Kubernetes Service (AKS) Benchmark v1.4.0 | Compliance | 7 | Pending | No AKS resources |
| OWASP Top 10 for LLM Applications — AI Risk Posture | Custom | 4 | Pending | Pending evaluation |
| CNAPP Shift-Left — Custom Recommendations | Custom | 1 | Pending | Pending evaluation |

⚠️ **Note:** "Pending" scores indicate the assessment engine has not yet evaluated resources for these keys. Custom recommendations may take up to 12 hours for initial evaluation. "NoData" counts reflect assessment keys with no matching resources on this subscription (e.g., no AKS clusters, no AI Foundry workspaces).

## 🔎 Standard Detail Cards

Unified AI Security Standard
7.7%

195 checks
1 pass
12 fail
182 pending

Combines: MCSB/NIST (167) + AI-SPM (30) + ATLAS/OWASP (14)  
ID: `fb4215a0-d7d6-5ddf-915b-7ccc75a8717d`

Azure CSPM (MCSB / NIST-aligned)
25.0%

167 checks
1 pass
3 fail
163 pending

Microsoft Cloud Security Benchmark mapped to NIST 800-53 Rev 5

MITRE ATLAS — AI/ML Security
0.0%

10 checks
0 pass
5 fail
5 pending

Custom recommendations mapped to MITRE ATLAS AML.T0024–T0053  
ID: `5da7bd0d-63ba-5aa7-8b3c-b99e6c63bfe3`

OWASP Top 10 for LLM Applications
Pending

4 checks
Awaiting evaluation

Custom recommendations for OWASP LLM Top 10 (2025)  
ID: `5c2ae0ee-ed80-53ab-b142-3f86ba3c761c`

CIS AKS Benchmark v1.5.0
Pending

18 checks
No AKS resources on subscription

CIS AKS Benchmark v1.4.0
Pending

7 checks
No AKS resources on subscription

CNAPP Shift-Left
Pending

1 check
Awaiting evaluation

ID: `968b993b-049a-5e46-b42b-85ec030aec56`

## 🔍 Key Findings

- 🔴 **MITRE ATLAS at 0% compliance** — All 5 evaluated custom recommendations show unhealthy resources. AI Services resources on this subscription lack local auth disablement, private network access, CMK encryption, managed identity authentication, and network isolation.
- 🟠 **Overall Secure Score at 22.8%** — Significant room for improvement. 384 unhealthy resource assessments across the subscription vs. 129 healthy.
- 🟠 **Azure CSPM at 25%** — Only 4 of 167 assessment keys have evaluated resources (1 healthy, 3 unhealthy). Most keys are pending due to absence of matching resource types.
- 🟡 **OWASP LLM pending evaluation** — Recently deployed custom recommendations (4) have not yet been evaluated by the assessment engine. Check back in 12 hours.
- 🔵 **CIS AKS benchmarks not applicable** — No AKS clusters exist on this subscription, so all 25 CIS AKS checks (v1.4 + v1.5) show no data.
- ✅ **Unified standard deployed** — 195 unique assessments from 3 sources (MCSB + AI-SPM + ATLAS/OWASP) consolidated into a single compliance view.

## ⚠️ Recommendations

1. **Priority 1:** Address MITRE ATLAS failures — disable local auth on AI Services, restrict public network access, and enforce managed identity authentication.
2. **Priority 2:** Review the 3 unhealthy Azure CSPM assessments and remediate to improve NIST baseline posture.
3. **Priority 3:** Re-run this report in 24 hours to capture OWASP LLM and remaining custom recommendation evaluations.
4. **Priority 4:** Consider deploying AI Foundry / Azure ML resources to this subscription to fully exercise the AI-SPM built-in assessments (currently no matching resources for most keys).

## 📐 Methodology

### Tool Stack

| Tool / API | Purpose | Status |
| --- | --- | --- |
| `Security Standards API` 2024-08-01 | Enumerate all standards and their assessment key lists | ✅ Used |
| `Secure Scores API` 2020-01-01 | Retrieve overall subscription secure score | ✅ Used |
| `Azure Resource Graph` securityresources | Aggregate per-key assessment status (Healthy/Unhealthy/NA) across all resources | ✅ Used |
| `Assessment Metadata API` 2021-06-01 | Resolve assessment key GUIDs to display names and severity | ✅ Used |
| `Custom Recommendations API` 2024-08-01 | Verify deployed custom recommendations (ATLAS + OWASP) | ✅ Used |

### Data Extraction Queries

| Query | Target | Result |
| --- | --- | --- |
| `az rest GET .../securityStandards` | All standards on subscription | 7 standards (5 custom, 2 compliance) |
| `az rest GET .../secureScores/ascScore` | Overall secure score | 5.69 / 25 (22.8%) |
| `securityresources | where type == 'microsoft.security/assessments' | summarize by status, key` | Per-key aggregate status | 310 distinct keys, 557 total assessments |
| `az rest GET .../customRecommendations` | Custom recommendation inventory | 26 custom recommendations |

### Data Sources

|  |  |
| --- | --- |
| **Subscription** | `d2e150ed-3cb8-4933-9203-c11d84d31285` (Visual Studio Enterprise) |
| **Tenant** | `eb73b2ef-487c-44ff-a8e1-2a2efe53d301` |
| **Time of Data Capture** | April 13, 2026 — point-in-time snapshot |
| **Score Methodology** | Per-standard score = Healthy / (Healthy + Unhealthy) × 100. Keys with no resource-level result are excluded from the score denominator and reported as "NoData". |

🔵 **Score interpretation:** Scores reflect only assessment keys that have at least one resource-level evaluation. "Pending" means zero resources matched any key in that standard. "NoData" counts within scored standards represent keys for resource types not present on the subscription (e.g., no Foundry workspaces, no AKS clusters).

Generated by CyberProbe — April 13, 2026  
Defender for Cloud API v2024-08-01 • Secure Scores API v2020-01-01 • Azure Resource Graph
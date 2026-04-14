CSPM Executive KPI Report - February 19, 2026


# CSPM Executive KPI Report

Microsoft Defender for Cloud — Monthly Security Posture Assessment

February 19, 2026
Internal Use Only


71.8%

Device Coverage

74 of 103 devices

57.5%

Top Secure Score

Primary Subscription

45

Critical CVEs

67 devices affected

67%

Baseline Pass Rate

90-day average

52.2%

MCSB Compliance

Top framework

5,717

Total CVEs Found

Across all severities

## 📑 Table of Contents

- [1. Coverage KPIs](#coverage)
- [1.1 Device Onboarding Coverage](#coverage-devices)
- [1.2 Defender Plans by Subscription](#coverage-plans)
- [1.3 Assets by Vulnerability Severity](#coverage-severity)
- [1.4 Device Inventory by OS](#coverage-os)
- [2. Security Posture KPIs](#posture)
- [2.1 Secure Score](#posture-score)
- [2.2 Secure Score Controls](#posture-controls)
- [2.3 Posture Trend (Baseline)](#posture-trend)
- [2.4 Misconfigurations Aging](#posture-misconfig)
- [2.5 Vulnerabilities by Severity](#posture-vulns)
- [2.6 Exposed Secrets Aging](#posture-secrets)
- [3. Regulatory Compliance KPIs](#compliance)
- [4. Data Gaps & Recommendations](#gaps)


## 🛡️ 1. Coverage KPIs

Defender for Cloud environment coverage, onboarding status, and asset inventory

## 1.1 Device Onboarding Coverage

⚡ Advanced Hunting — DeviceInfo

✓ Validated

Endpoint Coverage


71.8%

74 Onboarded / 29 Not Covered

| Status | Count | Percentage |
| --- | --- | --- |
| ● Onboarded | 74 | 71.8% |
| ● Not Onboarded | 29 | 28.2% |
| **Total** | **103** | **100%** |

View KQL Query

// Run via: Advanced Hunting (RunAdvancedHuntingQuery)
DeviceInfo
| summarize arg\_max(Timestamp, \*) by DeviceId
| summarize
TotalDevices = dcount(DeviceId),
Onboarded = dcountif(DeviceId, OnboardingStatus == "Onboarded"),
NotOnboarded = dcountif(DeviceId, OnboardingStatus != "Onboarded")
| extend
CoveredPct = round(100.0 \* Onboarded / TotalDevices, 1),
NotCoveredPct = round(100.0 \* NotOnboarded / TotalDevices, 1)

## 1.2 Defender Plans by Subscription

🔧 Azure Portal — Resource Graph Explorer

Manual Query Required

⚠️

**ARG intent-based tool limitation:** The `microsoft.security/pricings` resource type (36 records confirmed) cannot be queried through the automated tool. Run the query below manually in **Azure Portal → Resource Graph Explorer**.

KQL Query (run in Azure Portal)

// Run via: Azure Portal → Resource Graph Explorer
securityresources
| where type == "microsoft.security/pricings"
| extend planName = name,
tier = tostring(properties.pricingTier),
subPlan = tostring(properties.subPlan),
freeTrialRemaining = tostring(properties.freeTrialRemainingTime)
| project subscriptionId, planName, tier, subPlan, freeTrialRemaining
| order by subscriptionId asc, planName asc

**Trending:** Defender plan changes are tracked via `AzureActivity` table — filter on `microsoft.security/pricings/write` operations.

## 1.3 Assets by Vulnerability Severity

⚡ Advanced Hunting — DeviceTvmSoftwareVulnerabilities

✓ Validated

### Devices by Highest Vulnerability Severity

Critical

67 devices

67

High

4

4

71 of 103 devices have at least one known vulnerability. **67 devices** have at least 1 critical-severity CVE as their highest exposure.

View KQL Query

// Run via: Advanced Hunting (RunAdvancedHuntingQuery)
DeviceTvmSoftwareVulnerabilities
| summarize MaxSeverity = iff(countif(VulnerabilitySeverityLevel == "Critical") > 0, "Critical",
iff(countif(VulnerabilitySeverityLevel == "High") > 0, "High",
iff(countif(VulnerabilitySeverityLevel == "Medium") > 0, "Medium",
iff(countif(VulnerabilitySeverityLevel == "Low") > 0, "Low", "None"))))
by DeviceId, DeviceName
| summarize DeviceCount = count() by MaxSeverity

## 1.4 Device Inventory by OS Platform

⚡ Advanced Hunting — DeviceInfo

✓ Validated

Windows 11

68

68

Windows 10

11

11

Windows Server 2022

8

8

Linux

7

7

Windows Server 2016

4

4

Windows Server 2019

3

3

Windows Server 2025

1

1

Windows (Other)

1

1


## 📊 2. Security Posture KPIs

Secure Score, baseline compliance, vulnerability management, and secrets exposure

## 2.1 Secure Score by Subscription

☁️ Azure Resource Graph — securescores

✓ Validated

Primary Subscription


57.5%

Secondary Subscription


28.1%

ℹ️

**Trending note:** Native Secure Score trending requires **Continuous Export** to be enabled (currently not configured). Use SecurityBaselineSummary as a proxy — see Section 2.3.

View KQL Query

// Run via: Azure Portal → Resource Graph Explorer
securityresources
| where type == "microsoft.security/securescores"
| extend scorePercent = round(todouble(properties.score.percentage) \* 100, 1),
currentScore = todouble(properties.score.current),
maxScore = todouble(properties.score.max)
| project subscriptionId, scorePercent, currentScore, maxScore

## 2.2 Secure Score Controls

☁️ Azure Resource Graph — securescorecontrols

✓ Validated

26 controls evaluated. Top unhealthy controls shown below.

| Control | Score % | Healthy | Unhealthy | Status |
| --- | --- | --- | --- | --- |
| Manage access and permissions | — | 3 | 87 | Needs Attention |
| Enable encryption at rest | — | 0 | 24 | Needs Attention |
| Remediate vulnerabilities | — | 2 | 20 | Needs Attention |
| Secure management ports | — | 6 | 8 | Review |
| Enable endpoint protection | — | 1 | 5 | Review |

View KQL Query

// Run via: Azure Portal → Resource Graph Explorer
securityresources
| where type == "microsoft.security/securescores/securescorecontrols"
| extend controlName = tostring(properties.displayName),
healthyCount = toint(properties.healthyResourceCount),
unhealthyCount = toint(properties.unhealthyResourceCount),
scorePct = round(todouble(properties.percentage) \* 100, 1)
| project subscriptionId, controlName, scorePct, healthyCount, unhealthyCount
| order by unhealthyCount desc

## 2.3 Posture Trend — Baseline Compliance

📘 Sentinel Data Lake — SecurityBaselineSummary

✓ Validated

14 weekly data points available. Average pass rate: **67%** over 90 days.

Nov 2025
Dec 2025
Jan 2026
Feb 2026

📊

**Proxy metric:** This uses `SecurityBaselineSummary` as a Secure Score trend proxy. Enable Continuous Export for native `SecureScoreControls` trending.

View KQL Query

// Run via: Sentinel Data Lake (query\_lake)
SecurityBaselineSummary
| where TimeGenerated > ago(90d)
| summarize
AvgPassRate = round(avg(PercentageOfPassedRules), 1),
TotalAssessed = sum(TotalAssessedRules),
CriticalFails = sum(CriticalFailedRules),
WarningFails = sum(WarningFailedRules)
by Week = startofweek(TimeGenerated)
| order by Week asc

## 2.4 Misconfigurations by Severity — Aging Analysis

📘 Sentinel Data Lake — SecurityBaseline

✓ Validated

### Failed Rules — New (≤30d) vs Older (>30d)

New (≤30 days)
 Older (>30 days)

Critical

20 older

20

Warning

7 older

7

Informational

3 older

3

⚠️

**All 30 misconfigurations are older than 30 days** — no new baseline failures detected recently, but existing critical failures remain unremediated.

View KQL Query

// Run via: Sentinel Data Lake (query\_lake)
SecurityBaseline
| where AnalyzeResult == "Failed"
| summarize arg\_max(TimeGenerated, \*) by \_ResourceId, RuleSeverity, Description
| extend AgeCategory = iff(TimeGenerated > ago(30d), "New (≤30d)", "Older (>30d)")
| summarize Count = count() by RuleSeverity, AgeCategory
| order by case(RuleSeverity, "Critical", 1, "Warning", 2, "Informational", 3, 4) asc

## 2.5 Vulnerabilities by Severity — Current Snapshot

⚡ Advanced Hunting — DeviceTvmSoftwareVulnerabilities

✓ Validated

45

Critical CVEs

67 devices

2,483

High CVEs

71 devices

3,085

Medium CVEs

71 devices

104

Low CVEs

71 devices

| Severity | Unique CVEs | Affected Devices | % of Fleet | Risk |
| --- | --- | --- | --- | --- |
| Critical | 45 | 67 | 65.0% | Urgent |
| High | 2,483 | 71 | 68.9% | Urgent |
| Medium | 3,085 | 71 | 68.9% | Review |
| Low | 104 | 71 | 68.9% | Monitor |
| Total | 5,717 | 71 | 68.9% | — |

📌

**Snapshot table:** `DeviceTvmSoftwareVulnerabilities` shows current state only — no historical trending. Enable Continuous Export for `SecurityRecommendation` table to get vulnerability aging data.

View KQL Query

// Run via: Advanced Hunting (RunAdvancedHuntingQuery)
DeviceTvmSoftwareVulnerabilities
| summarize
UniqueCVEs = dcount(CveId),
AffectedDevices = dcount(DeviceId)
by VulnerabilitySeverityLevel
| order by case(VulnerabilitySeverityLevel, "Critical", 1, "High", 2, "Medium", 3, "Low", 4, 5) asc

## 2.6 Exposed Secrets — Aging Analysis

📘 Sentinel Data Lake — SecurityAlert

✓ Validated

### Secret-Related Alerts — New (≤30d) vs Older (>30d)

New (≤30 days)
 Older (>30 days)

High

2

11

13

Medium

1

10

11

| Severity | New (≤30d) | Older (>30d) | Total | % Aging |
| --- | --- | --- | --- | --- |
| High | 2 | 11 | 13 | 84.6% |
| Medium | 1 | 10 | 11 | 90.9% |
| Total | 3 | 21 | 24 | 87.5% |

⚠️

**87.5% of secret-related alerts are older than 30 days.** These represent persistent credential exposure risks that should be reviewed for remediation.

View KQL Query

// Run via: Sentinel Data Lake (query\_lake)
SecurityAlert
| where TimeGenerated > ago(90d)
| where AlertName has\_any ("secret", "credential", "key", "password", "certificate", "token")
or Description has\_any ("secret", "credential", "exposed key", "leaked")
| extend AgeCategory = iff(TimeGenerated > ago(30d), "New (≤30d)", "Older (>30d)")
| summarize Count = count() by AlertSeverity, AgeCategory


## ✅ 3. Regulatory Compliance KPIs

Framework compliance assessment against industry standards and benchmarks

## 3.1 Framework Compliance — Current State

☁️ Azure Resource Graph — regulatorycompliancestandards

✓ Validated

### Compliance by Framework

MCSB

52.2%

52.2%

ISO 27001:2013

43.5%

43.5%

CSPM Foundation

37.8%

37.8%

| Framework | Passed Controls | Failed Controls | Skipped | Compliance % | Status |
| --- | --- | --- | --- | --- | --- |
| Microsoft Cloud Security Benchmark | — | — | — | 52.2% | Below Target |
| ISO 27001:2013 | — | — | — | 43.5% | Critical Gap |
| CSPM Foundation Benchmark | — | — | — | 37.8% | Critical Gap |

📈

**Compliance trending:** Native trending requires Continuous Export (`SecurityRegulatoryCompliance` table). Alternative: build a Logic App to snapshot ARG compliance data weekly into a custom `ComplianceTrend_CL` table.

View KQL Query

// Run via: Azure Portal → Resource Graph Explorer
securityresources
| where type == "microsoft.security/regulatorycompliancestandards"
| extend framework = name,
passedControls = toint(properties.passedControls),
failedControls = toint(properties.failedControls),
skippedControls = toint(properties.skippedControls)
| extend totalControls = passedControls + failedControls + skippedControls
| extend compliancePct = round(100.0 \* passedControls / totalControls, 1)
| project subscriptionId, framework, compliancePct, passedControls, failedControls, skippedControls


## ⚠️ 4. Data Gaps & Recommendations

Identified limitations, missing data sources, and prioritized remediation actions

## 4.1 Data Source Availability Matrix

| KPI | Data Source | Tool | Current Data | Trending |
| --- | --- | --- | --- | --- |
| Device Coverage | DeviceInfo | AH | ✓ Yes | Requires Snapshots |
| Plan Coverage | securityresources/pricings | ARG | Manual Only | Activity Log |
| Secure Score | securityresources/securescores | ARG | ✓ Yes | Requires CE |
| Posture Trend | SecurityBaselineSummary | LA | ✓ Yes | ✓ 90 days |
| Misconfigurations | SecurityBaseline | LA | ✓ Yes | ✓ Aging |
| Vulnerabilities | DeviceTvmSoftwareVulnerabilities | AH | ✓ Yes | Snapshot Only |
| Exposed Secrets | SecurityAlert | LA | ✓ Yes | ✓ Aging |
| Compliance | securityresources/compliance | ARG | ✓ Yes | Requires CE |

**Legend:**
AH = Advanced Hunting |
LA = Log Analytics (Sentinel Data Lake) |
ARG = Azure Resource Graph |
CE = Continuous Export

## 4.2 Prioritized Recommendations

- P1 — Critical

  **Enable Continuous Export to Log Analytics**  

  This single action unlocks native trending for Secure Score, Recommendations, and Compliance — filling 5 KPI gaps. Configure in Azure Portal → Defender for Cloud → Environment Settings → Continuous Export. Target workspace: `b2c3d4e5-f6a7-8901-bcde-f12345678901`. Tables created: SecureScoreControls, SecurityRecommendation, SecurityRegulatoryCompliance.
- P1 — Critical

  **Remediate 45 Critical CVEs Across 67 Devices**  

  65% of fleet has at least one critical vulnerability. Prioritize patch deployment for CVEs with known exploits using DeviceTvmSoftwareVulnerabilities data.
- P2 — High

  **Onboard 29 Uncovered Devices to Defender for Endpoint**  

  28.2% of devices are not onboarded. Increasing coverage is critical for visibility. Review DeviceInfo for OS types of unmanaged endpoints.
- P2 — High

  **Address 20 Critical Baseline Failures (all >30 days old)**  

  All critical misconfigurations are aging. Review SecurityBaseline failed rules and create remediation work items.
- P2 — High

  **Resolve 87 Unhealthy Resources in "Manage Access and Permissions" Control**  

  This is the largest contributor to Secure Score reduction. Address excessive permissions and RBAC misconfigurations.
- P3 — Medium

  **Build ARG Snapshot Pipeline for Trending KPIs**  

  Create a Logic App running weekly to snapshot Secure Score, Plan Coverage, and Compliance into custom Log Analytics tables (SecureScoreTrend\_CL, ComplianceTrend\_CL). This provides trending even before Continuous Export is fully configured.
- P3 — Medium

  **Remediate 21 Aging Secret-Related Alerts**  

  87.5% of credential exposure alerts are older than 30 days. Investigate and rotate or revoke exposed secrets.
- P4 — Monitor

  **Consolidate KPI Dashboard in Azure Workbooks**  

  Once data sources are stable, connect Azure Workbooks to Log Analytics and ARG. Build a single executive dashboard refreshing daily with all KPIs.

## 4.3 Key Findings Summary

| Finding | Severity | Evidence |
| --- | --- | --- |
| 28.2% of devices not covered by Defender | High | DeviceInfo: 29 of 103 devices not onboarded |
| 45 Critical CVEs across 67 devices | Critical | DeviceTvmSoftwareVulnerabilities: 65% fleet exposed |
| All baseline misconfigurations aging >30 days | High | SecurityBaseline: 20 Critical, 7 Warning, 3 Info — all older |
| 87.5% of secret alerts are aging | Medium | SecurityAlert: 21 of 24 alerts older than 30 days |
| CSPM Foundation compliance at 37.8% | High | ARG: regulatorycompliancestandards query |
| Continuous Export not configured | Medium | SecureScoreControls, SecurityRecommendation, SecurityRegulatoryCompliance tables missing from workspace |
| Access control is #1 score reducer | High | ARG securescorecontrols: 87 unhealthy in "Manage access" control |


**Report Generated:** February 19, 2026

**Data Sources:** Microsoft Defender XDR (Advanced Hunting) • Microsoft Sentinel (Log Analytics) • Azure Resource Graph

**Workspace:** SecOps-Workspace (b2c3d4e5-f6a7-8901-bcde-f12345678901)

**Classification:** Internal Use Only

Generated by CyberProbe Security Operations
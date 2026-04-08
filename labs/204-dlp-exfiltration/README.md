# Lab 204: DLP Policy Violation & Data Exfiltration

**Duration**: 90 minutes  
**Difficulty**: Advanced  
**Prerequisites**: Labs 101-106, Labs 201-203

---

## 🎯 Learning Objectives

- ✅ Investigate DLP policy violations using Query 10
- ✅ Trace multi-stage data exfiltration chains
- ✅ Identify sensitive information types (SITs)
- ✅ Analyze external sharing patterns
- ✅ Correlate DLP events with file/email activity
- ✅ Build timeline of data theft attempts
- ✅ Recommend DLP policy improvements

---

## 📖 Scenario: Financial Data Exfiltration

**DLP Alert**: January 15, 2026, 16:45 PST

```
════════════════════════════════════════════════════════════
MICROSOFT PURVIEW DLP ALERT
════════════════════════════════════════════════════════════
Policy: Protect Financial Data
Rule: Block External Sharing of Budget Files
Severity: High

Violation Details:
User: david.chen@contoso.com
Action: External file sharing via SharePoint
File: Q1_2026_Budget_FINAL.xlsx
Sensitive Info: 3 types detected
  - Credit Card Numbers (8 instances)
  - US Bank Account Numbers (15 instances)
  - Contoso Customer IDs (247 instances)

Destination: personal-storage@gmail.com
Result: BLOCKED (DLP prevented sharing)
════════════════════════════════════════════════════════════
```

**Your Mission**: Investigate this DLP violation and determine if this was malicious exfiltration attempt or accidental oversharing.

---

## 📝 Exercise 1: DLP Event Analysis (Query 10)

### Task 1.1: Get Full DLP Violation Details

Use **Query 10 from Investigation Guide**:

```kql
let upn = "david.chen@contoso.com";
let start = datetime(2026-01-15 16:00);
let end = datetime(2026-01-17);

CloudAppEvents
| where TimeGenerated between (start .. end)
| where AccountDisplayName has "david" or AccountObjectId has upn
| where ActionType in ("DLPRuleMatch", "DLPRuleUndo")
| extend DLPDetails = parse_json(RawEventData)
| extend 
    PolicyName = tostring(DLPDetails.PolicyName),
    RuleName = tostring(DLPDetails.RuleName),
    Sensitivity = tostring(DLPDetails.SensitivityLabelName),
    SensitiveTypes = tostring(DLPDetails.SensitiveInformationTypeData),
    DestinationUrl = tostring(DLPDetails.DestinationUrl),
    Blocked = tostring(DLPDetails.Blocked)
| project 
    TimeGenerated,
    ObjectName,
    PolicyName,
    RuleName,
    Sensitivity,
    SensitiveTypes,
    DestinationUrl,
    Blocked,
    IPAddress
| order by TimeGenerated desc
```

**Document findings**:
- Total DLP violations for this user: _____
- Files involved: _____
- Policies triggered: _____
- Violations blocked: _____ / Violations allowed: _____

### Task 1.2: Parse Sensitive Information Types

Extract detailed SIT (Sensitive Information Type) data:

```kql
let upn = "david.chen@contoso.com";
let start = datetime(2026-01-15);
let end = datetime(2026-01-17);

CloudAppEvents
| where TimeGenerated between (start .. end)
| where AccountDisplayName has "david"
| where ActionType == "DLPRuleMatch"
| extend DLPDetails = parse_json(RawEventData)
| extend SensitiveTypes = parse_json(tostring(DLPDetails.SensitiveInformationTypeData))
| mv-expand SensitiveType = SensitiveTypes
| extend 
    SITName = tostring(SensitiveType.Name),
    SITCount = toint(SensitiveType.Count),
    SITConfidence = tostring(SensitiveType.Confidence)
| summarize 
    TotalInstances = sum(SITCount),
    Files = make_set(ObjectName)
    by SITName, SITConfidence
| order by TotalInstances desc
```

**Sensitive Data Inventory**:

| SIT Name | Instance Count | Confidence | Files |
|----------|---------------|------------|-------|
| Credit Card Numbers | ___ | ___ | ___ |
| US Bank Account Numbers | ___ | ___ | ___ |
| Alpine Customer IDs | ___ | ___ | ___ |
| SSN | ___ | ___ | ___ |

---

## 📝 Exercise 2: Multi-Stage Exfiltration Detection

### Task 2.1: Timeline of File Activity

Trace what the user did BEFORE the DLP block:

```kql
let targetFile = "Q1_2026_Budget_FINAL.xlsx";
let upn = "david.chen@contoso.com";
let start = datetime(2026-01-15);
let end = datetime(2026-01-17);

CloudAppEvents
| where TimeGenerated between (start .. end)
| where AccountDisplayName has "david" or AccountObjectId has upn
| where ObjectName has targetFile
| extend RawData = parse_json(RawEventData)
| project 
    TimeGenerated,
    ActionType,
    ObjectName,
    SourceFileName = tostring(RawData.SourceFileName),
    DestinationFileName = tostring(RawData.DestinationFileName),
    IPAddress,
    Application
| order by TimeGenerated asc
```

**Reconstruct Timeline**:
```
[TIME] - FileAccessed - User opened file in SharePoint
[TIME] - FileDownloaded - User downloaded to local device
[TIME] - FileModified - User edited file (added/removed data?)
[TIME] - FileUploaded - User uploaded modified version
[TIME] - SharingSet - User attempted external share
[TIME] - DLPRuleMatch - DLP blocked share attempt
```

### Task 2.2: Check for Alternative Exfiltration Methods

After DLP block, did user try other methods?

**Email Attempts**:
```kql
let upn = "david.chen@contoso.com";
let targetFile = "Q1_2026_Budget_FINAL.xlsx";
let dlpBlockTime = datetime(2026-01-15 16:45:00);

EmailEvents
| where TimeGenerated > dlpBlockTime
| where SenderFromAddress =~ upn
| where AttachmentCount > 0
| extend Attachments = parse_json(AttachmentNames)
| mv-expand Attachment = Attachments
| where Attachment has "Budget" or Attachment has "Q1_2026"
| project 
    TimeGenerated,
    RecipientEmailAddress,
    Subject,
    Attachment = tostring(Attachment),
    DeliveryAction,
    ThreatTypes
```

**Personal OneDrive Upload**:
```kql
let upn = "david.chen@contoso.com";
let dlpBlockTime = datetime(2026-01-15 16:45:00);

CloudAppEvents
| where TimeGenerated > dlpBlockTime
| where AccountDisplayName has "david"
| where Application == "Microsoft OneDrive for Business"
| where ActionType in ("FileUploaded", "FileSyncUploadedFull")
| extend RawData = parse_json(RawEventData)
| extend Destination = tostring(RawData.DestinationFileName)
| where Destination has "personal" or Destination has "Personal"
| project TimeGenerated, ObjectName, ActionType, Destination, IPAddress
```

**USB Device Activity** (requires Defender for Endpoint):
```kql
DeviceEvents
| where TimeGenerated > datetime(2026-01-15 16:45)
| where InitiatingProcessAccountName has "david.chen"
| where ActionType in ("UsbDriveMounted", "UsbDriveUnmounted")
| project TimeGenerated, DeviceName, ActionType, AdditionalFields
```

**Alternative Exfiltration Attempts**:
- Email with attachments: [Yes/No] - [COUNT]
- Personal cloud upload: [Yes/No] - [FILES]
- USB device usage: [Yes/No] - [DEVICE INFO]

---

## 📝 Exercise 3: User Behavior Pattern Analysis

### Task 3.1: Historical DLP Violations

Is this user's first violation or repeat offender?

```kql
let upn = "david.chen@contoso.com";
let lookback = datetime(2025-10-01);  // 3 months
let end = datetime(2026-01-17);

CloudAppEvents
| where TimeGenerated between (lookback .. end)
| where AccountDisplayName has "david"
| where ActionType == "DLPRuleMatch"
| extend DLPDetails = parse_json(RawEventData)
| extend 
    PolicyName = tostring(DLPDetails.PolicyName),
    Blocked = tostring(DLPDetails.Blocked)
| summarize 
    ViolationCount = count(),
    BlockedCount = countif(Blocked == "true"),
    AllowedCount = countif(Blocked == "false"),
    FirstViolation = min(TimeGenerated),
    LastViolation = max(TimeGenerated),
    Policies = make_set(PolicyName)
| extend 
    Duration = datetime_diff('day', LastViolation, FirstViolation),
    Pattern = case(
        ViolationCount == 1, "First offense",
        ViolationCount < 5, "Occasional",
        ViolationCount >= 5, "Repeat offender",
        "Unknown")
```

**User DLP History**:
- Total violations (3 months): _____
- Pattern: [First offense / Occasional / Repeat offender]
- Prior violations blocked: _____ / allowed: _____

### Task 3.2: External Sharing Baseline

```kql
let upn = "david.chen@contoso.com";
let baselineStart = datetime(2025-12-15);
let baselineEnd = datetime(2026-01-15);

CloudAppEvents
| where TimeGenerated between (baselineStart .. baselineEnd)
| where AccountDisplayName has "david"
| where ActionType in ("SharingSet", "AnonymousLinkCreated", "AddedToSecureLink")
| extend RawData = parse_json(RawEventData)
| extend TargetUser = tostring(RawData.TargetUserOrGroupName)
| extend IsExternal = TargetUser !endswith "@contoso.com"
| summarize 
    TotalSharing = count(),
    ExternalSharing = countif(IsExternal),
    InternalSharing = countif(not(IsExternal))
| extend ExternalShareRate = round(100.0 * ExternalSharing / TotalSharing, 1)
```

**Sharing Behavior**:
- External sharing rate: _____% (baseline normal: <10%)
- Anomalous if >20%

---

## 📝 Exercise 4: Determine Intent (Malicious vs Accidental)

### Task 4.1: Apply Decision Framework

| Evidence | Malicious Indicator | Accidental Indicator | Your Finding |
|----------|-------------------|---------------------|--------------|
| **Timing** | After hours, weekend | During work hours | [TIME: ___] |
| **Recipient** | Personal email, unknown | Colleague, vendor | [RECIPIENT: ___] |
| **File Modification** | Removed sensitivity labels | No modifications | [MODIFIED: Y/N] |
| **Alternative Methods** | Tried email, USB after DLP block | No further attempts | [ALTERNATIVES: Y/N] |
| **User History** | Repeat DLP violator | First offense | [HISTORY: ___] |
| **File Sensitivity** | Top Secret / Confidential | Internal / Public | [LABEL: ___] |
| **Business Justification** | No valid reason | Legit business need | [REASON: ___] |

**Scoring**:
- 5-7 Malicious indicators = **MALICIOUS EXFILTRATION**
- 3-4 Mixed = **INVESTIGATION NEEDED**
- 0-2 Malicious indicators = **ACCIDENTAL OVERSHARING**

**Your Determination**: [MALICIOUS / INVESTIGATION NEEDED / ACCIDENTAL]

### Task 4.2: Interview User (if ambiguous)

**Questions to ask David**:
1. "Why did you need to share Q1_2026_Budget_FINAL.xlsx externally?"
2. "Who is personal-storage@gmail.com and why share with them?"
3. "Are you aware of the DLP policy regarding financial data?"
4. "Did you attempt any other methods to share this file after the DLP block?"

**User Response**: ___________________

---

## 📝 Exercise 5: DLP Policy Assessment

### Task 5.1: Evaluate Current DLP Policy

Review the policy that triggered:

**Policy Name**: Protect Financial Data  
**Current Rules**:
1. Block external sharing of files with >5 credit card numbers
2. Block email attachments with bank account numbers
3. Alert on SharePoint files labeled "Confidential - Finance"

**Questions**:
1. **Coverage**: Does policy cover all financial data sources?
   - SharePoint: ✓ Covered
   - OneDrive: [Covered / Gap]
   - Email: ✓ Covered
   - Teams Chat: [Covered / Gap]
   - USB Transfer: [Covered / Gap]

2. **Thresholds**: Are confidence/count thresholds appropriate?
   - Credit card: >5 instances (is 5 the right number?)
   - Bank account: >1 instance

3. **Actions**: Block vs Alert vs Warn user?
   - Current: Block external sharing
   - Alternative: Warn user first, allow business justification?

### Task 5.2: Recommend Policy Improvements

Based on this incident, recommend changes:

**Recommendations**:
1. [ ] Extend DLP to Teams chat file sharing
2. [ ] Add "Customer ID" as custom SIT (Alpine specific)
3. [ ] Lower threshold: >1 credit card (not >5)
4. [ ] Enable endpoint DLP for USB blocking
5. [ ] User training: Annual DLP awareness for Finance dept
6. [ ] Sensitivity labeling: Require labels on budget files
7. [ ] Conditional Access: Require managed device for Finance SharePoint

---

## ✅ Lab Validation Checklist

- [ ] Query DLP violations using Query 10
- [ ] Parse sensitive information types (SITs)
- [ ] Build file activity timeline
- [ ] Detect alternative exfiltration methods
- [ ] Analyze user DLP history
- [ ] Determine malicious vs accidental intent
- [ ] Evaluate DLP policy effectiveness
- [ ] Recommend policy improvements
- [ ] Document findings for compliance

---

## 🎓 Key Takeaways

**DLP Investigation Process**:
```
DLP Alert → Query 10 (Details) → Timeline Reconstruction → 
Alternative Methods Check → Intent Determination → Policy Assessment
```

**Critical SITs** (Sensitive Information Types):
- **Financial**: Credit cards, bank accounts, tax IDs
- **Personal**: SSN, driver's license, passport numbers
- **Healthcare**: Medical record numbers, DEA numbers
- **Custom**: Company-specific IDs, project code names

**Malicious Exfiltration Patterns**:
1. DLP block → Immediate retry via email
2. Remove sensitivity label → Re-share
3. Download → USB transfer (bypasses cloud DLP)
4. After-hours activity → Personal email

**Remediation by Risk**:
- **Malicious**: Disable account, legal investigation, HR discipline
- **Negligent**: User training, manager notification, monitoring
- **Accidental**: Warning, one-on-one training, no further action

---

## 🚀 Next Steps

**Practice with real DLP alerts**:
1. Review past 30 days of DLP violations in your environment
2. Categorize as malicious/negligent/accidental
3. Track repeat offenders
4. Measure policy effectiveness (block rate, false positives)

**Build DLP Dashboard**:
- Top violators (by user)
- Top policies triggered
- Block vs allow ratio
- Sensitive file inventory
- Trend analysis (violations increasing?)

---

## 📚 Resources

- [Investigation Guide - Query 10: DLP Policy Violations](../../Investigation-Guide.md#query-10-dlp-policy-violations-via-query-to-cloudappevents)
- [Microsoft Purview DLP Policies](https://learn.microsoft.com/en-us/purview/dlp-learn-about-dlp)
- [Sensitive Information Types Reference](https://learn.microsoft.com/en-us/purview/sensitive-information-type-entity-definitions)

---

**Congratulations!** You can now investigate DLP violations, determine user intent, and improve data protection policies.

**🎉 YOU'VE COMPLETED ALL LABS!** You're now a certified CyberProbe investigator.

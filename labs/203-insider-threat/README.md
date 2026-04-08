# Lab 203: Insider Threat Investigation

**Duration**: 90 minutes  
**Difficulty**: Advanced  
**Prerequisites**: Labs 101-106, Labs 201-202

---

## 🎯 Learning Objectives

- ✅ Establish behavioral baselines for insider threat detection
- ✅ Identify anomalous file access patterns
- ✅ Detect after-hours and off-pattern activity
- ✅ Correlate security events with HR indicators
- ✅ Assess insider risk using behavioral analytics
- ✅ Build evidence timeline for HR/Legal review

---

## 📖 Scenario: The Departing Employee

**HR Alert**: January 12, 2026

```
FROM: HR Director
TO: Security Operations
SUBJECT: Employee Resignation - Monitoring Request

Employee Jennifer Kim (jennifer.kim@alpineskihouse.co) submitted
resignation on January 10, 2026. Last day: January 24, 2026.

Role: Senior Financial Analyst (access to confidential financial data)
Destination: Competitor (SkiTech International)

Please monitor for data exfiltration attempts during notice period.
```

**Your Mission**: Monitor Jennifer's activity for signs of data theft before departure.

---

## 📝 Exercise 1: Establish Baseline Behavior (30-day lookback)

### Task 1.1: Historical File Access Pattern

```kql
let upn = "jennifer.kim@alpineskihouse.co";
let baselineStart = datetime(2025-12-10);
let baselineEnd = datetime(2026-01-10);

CloudAppEvents
| where TimeGenerated between (baselineStart .. baselineEnd)
| where AccountDisplayName has "jennifer" or AccountObjectId has upn
| where Application in ("Microsoft SharePoint Online", "Microsoft OneDrive for Business")
| where ActionType in ("FileAccessed", "FileDownloaded", "FileModified")
| summarize 
    DailyFileAccess = count(),
    UniqueFolders = dcount(ObjectId),
    FileTypes = make_set(ObjectName)
    by bin(TimeGenerated, 1d)
| summarize 
    AvgDailyAccess = avg(DailyFileAccess),
    MaxDailyAccess = max(DailyFileAccess),
    MinDailyAccess = min(DailyFileAccess),
    StdDev = stdev(DailyFileAccess)
```

**Baseline Metrics**:
- Average daily file access: _____ files
- Maximum daily access: _____ files
- Standard deviation: _____
- **Anomaly threshold**: Avg + (2 × StdDev) = _____ files/day

### Task 1.2: Typical Working Hours

```kql
let upn = "jennifer.kim@alpineskihouse.co";
let baselineStart = datetime(2025-12-10);
let baselineEnd = datetime(2026-01-10);

CloudAppEvents
| where TimeGenerated between (baselineStart .. baselineEnd)
| where AccountDisplayName has "jennifer" or AccountObjectId has upn
| extend Hour = hourofday(TimeGenerated)
| summarize ActivityCount = count() by Hour
| order by Hour asc
```

**Baseline Working Hours**:
- Typical start time: _____ (hour with activity spike)
- Typical end time: _____ (last hour of regular activity)
- After-hours activity (10 PM - 6 AM): _____ events

---

## 📝 Exercise 2: Detect Post-Resignation Anomalies

### Task 2.1: File Access Spike Detection

```kql
let upn = "jennifer.kim@alpineskihouse.co";
let resignationDate = datetime(2026-01-10);
let investigationEnd = datetime(2026-01-17);
let anomalyThreshold = 50;  // From baseline: Avg + 2×StdDev

CloudAppEvents
| where TimeGenerated between (resignationDate .. investigationEnd)
| where AccountDisplayName has "jennifer" or AccountObjectId has upn
| where Application in ("Microsoft SharePoint Online", "Microsoft OneDrive for Business")
| where ActionType in ("FileAccessed", "FileDownloaded")
| summarize 
    FileCount = count(),
    FileNames = make_set(ObjectName, 100),
    FirstAccess = min(TimeGenerated),
    LastAccess = max(TimeGenerated)
    by bin(TimeGenerated, 1d), IPAddress
| where FileCount > anomalyThreshold
| extend DeviationFromBaseline = FileCount - anomalyThreshold
| order by TimeGenerated desc
```

**Anomaly Findings**:
- Days with spike: _____
- Peak file access: _____ files (vs baseline avg: _____)
- Deviation: _____ % above baseline

### Task 2.2: After-Hours Activity

```kql
let upn = "jennifer.kim@alpineskihouse.co";
let resignationDate = datetime(2026-01-10);
let investigationEnd = datetime(2026-01-17);

CloudAppEvents
| where TimeGenerated between (resignationDate .. investigationEnd)
| where AccountDisplayName has "jennifer" or AccountObjectId has upn
| where Application in ("Microsoft SharePoint Online", "Microsoft OneDrive for Business", "Microsoft Exchange Online")
| extend Hour = hourofday(TimeGenerated)
| where Hour >= 22 or Hour <= 6  // 10 PM to 6 AM
| summarize 
    EventCount = count(),
    Actions = make_set(ActionType),
    Files = make_set(ObjectName, 20)
    by bin(TimeGenerated, 1h), IPAddress
| order by TimeGenerated asc
```

**After-Hours Activity**:
- Total after-hours events: _____
- Nights with activity: _____
- Actions performed: _____

---

## 📝 Exercise 3: Sensitive Data Access Analysis

### Task 3.1: Financial Documents Access

```kql
let upn = "jennifer.kim@alpineskihouse.co";
let resignationDate = datetime(2026-01-10);
let investigationEnd = datetime(2026-01-17);
let sensitiveKeywords = pack_array("Financial", "Confidential", "Budget", "Revenue", "Projection", "Strategy");

CloudAppEvents
| where TimeGenerated between (resignationDate .. investigationEnd)
| where AccountDisplayName has "jennifer" or AccountObjectId has upn
| where ActionType in ("FileDownloaded", "FileAccessed", "FileCopied")
| extend FileName = tostring(ObjectName)
| where FileName has_any (sensitiveKeywords)
| summarize 
    SensitiveFileCount = count(),
    FileList = make_set(FileName),
    FirstAccess = min(TimeGenerated),
    LastAccess = max(TimeGenerated)
    by ActionType, IPAddress
| order by SensitiveFileCount desc
```

**Sensitive File Access**:
- Total sensitive files accessed: _____
- Files downloaded: _____
- Most accessed file: _____

### Task 3.2: Personal Cloud Upload Detection

```kql
let upn = "jennifer.kim@alpineskihouse.co";
let resignationDate = datetime(2026-01-10);
let investigationEnd = datetime(2026-01-17);

CloudAppEvents
| where TimeGenerated between (resignationDate .. investigationEnd)
| where AccountDisplayName has "jennifer" or AccountObjectId has upn
| where Application == "Microsoft OneDrive for Business"
| where ActionType in ("FileSyncUploadedFull", "FileUploaded")
| extend RawData = parse_json(RawEventData)
| extend DestinationPath = tostring(RawData.DestinationFileName)
| where DestinationPath has "personal" or DestinationPath has "Personal"
| project 
    TimeGenerated,
    ObjectName,
    DestinationPath,
    IPAddress,
    DeviceId
```

**Exfiltration Indicators**:
- Files uploaded to personal OneDrive: _____
- External sharing events: _____

---

## 📝 Exercise 4: USB & Print Activity

### Task 4.1: USB Device Detection (requires Defender for Endpoint)

```kql
DeviceEvents
| where TimeGenerated between (datetime(2026-01-10) .. datetime(2026-01-17))
| where InitiatingProcessAccountName has "jennifer.kim"
| where ActionType in ("UsbDriveMounted", "UsbDriveUnmounted")
| extend DeviceInfo = parse_json(AdditionalFields)
| project 
    TimeGenerated,
    DeviceName,
    ActionType,
    DriveLetter = tostring(DeviceInfo.DriveLetter),
    VendorName = tostring(DeviceInfo.VendorName)
```

### Task 4.2: Print Activity Monitoring

```kql
CloudAppEvents
| where TimeGenerated between (datetime(2026-01-10) .. datetime(2026-01-17))
| where AccountDisplayName has "jennifer"
| where ActionType == "FilePrinted"
| summarize PrintCount = count(), FilesPrinted = make_set(ObjectName) by bin(TimeGenerated, 1d)
```

**Physical Exfiltration Risk**:
- USB devices connected: _____
- Documents printed: _____

---

## 📝 Exercise 5: Risk Scoring & Determination

### Task 5.1: Calculate Insider Risk Score

| Risk Factor | Finding | Points | Your Score |
|------------|---------|--------|------------|
| File access > 2×baseline | [Yes/No] | +5 | ___ |
| After-hours activity increase | [Yes/No] | +3 | ___ |
| Sensitive file downloads | [Yes/No] | +5 | ___ |
| Personal cloud uploads | [Yes/No] | +10 | ___ |
| USB device usage | [Yes/No] | +5 | ___ |
| Mass printing | [Yes/No] | +3 | ___ |
| External sharing | [Yes/No] | +10 | ___ |
| **Total Risk Score** | | | ___ |

**Risk Classification**:
- 0-5 = LOW - Normal departure activity
- 6-15 = MEDIUM - Monitor closely, interview user
- 16-25 = HIGH - Likely data theft, immediate action
- 26+ = CRITICAL - Active exfiltration, escalate to legal

**Your Assessment**: [LOW/MEDIUM/HIGH/CRITICAL]

### Task 5.2: HR Correlation

**Check for additional HR indicators**:
- [ ] Negative performance reviews
- [ ] Recent disciplinary action
- [ ] Salary negotiation failure
- [ ] Competing offer known
- [ ] Access to trade secrets
- [ ] Recent security training completion (knows what to avoid)

**Each "Yes" adds +2 to risk score**

---

## 📝 Exercise 6: Evidence Collection & Response

### Immediate Actions (if HIGH/CRITICAL risk)

1. **Preserve Evidence**:
```powershell
# Export all file activity to CSV
$data = Invoke-AzOperationalInsightsQuery -WorkspaceId $wsId -Query @"
CloudAppEvents
| where TimeGenerated between (datetime(2026-01-10) .. datetime(2026-01-17))
| where AccountDisplayName has 'jennifer'
| project TimeGenerated, ActionType, ObjectName, IPAddress, Application
"@
$data.Results | Export-Csv "evidence_jennifer_kim.csv"
```

2. **Restrict Access** (if CRITICAL):
- [ ] Disable OneDrive sync
- [ ] Block external sharing
- [ ] Revoke USB device permissions
- [ ] Disable printing to non-corporate printers
- [ ] Enable Purview IRM monitoring

3. **Interview User**:
```
Questions to ask:
- Why the spike in file access after resignation?
- Explain after-hours activity on [DATE]
- Purpose of accessing [SENSITIVE FILE] on [DATE]?
- Aware of data handling policies?
```

4. **Legal Coordination**:
- [ ] Notify Legal team if risk score >20
- [ ] Preserve all logs for 90 days minimum
- [ ] Prepare evidence timeline for potential litigation

---

## ✅ Lab Validation Checklist

- [ ] Establish 30-day behavioral baseline
- [ ] Calculate anomaly detection thresholds
- [ ] Detect file access spikes post-resignation
- [ ] Identify after-hours activity patterns
- [ ] Assess sensitive data access
- [ ] Check for exfiltration methods (USB, print, cloud)
- [ ] Calculate insider risk score
- [ ] Make evidence-based recommendation
- [ ] Document findings for HR/Legal

---

## 🎓 Key Takeaways

**Insider Threat Detection Process**:
```
HR Alert → Baseline (30d) → Anomaly Detection → Sensitive Data Check → 
Risk Scoring → Evidence Collection → HR/Legal Coordination
```

**Critical Metrics**:
- **File Access Spike**: >2× standard deviation
- **After-Hours**: 10 PM - 6 AM activity increase
- **Sensitive Keywords**: "Confidential", "Financial", "Strategy"
- **Exfiltration Channels**: Personal cloud, USB, email, print

**Legal Considerations**:
- All monitoring must comply with employment contracts
- Preserve evidence with chain of custody
- Involve Legal early (risk score >15)
- User privacy vs company protection balance

---

## 🚀 Next Steps

**Continue to [Lab 204: DLP Exfiltration Investigation](../204-dlp-exfiltration/)**

---

## 📚 Resources

- [Microsoft Purview Insider Risk Management](https://learn.microsoft.com/en-us/purview/insider-risk-management)
- [MITRE ATT&CK: Data Exfiltration](https://attack.mitre.org/tactics/TA0010/)

---

**Congratulations!** You can now detect and investigate insider threats using behavioral analytics and evidence-based risk scoring.

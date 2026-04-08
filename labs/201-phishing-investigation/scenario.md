# Phishing Campaign Scenario - Incident #41398

## Executive Summary

**Incident Classification**: Phishing with Credential Theft & Data Exfiltration  
**Attack Vector**: Spear-phishing email with malicious link  
**Impact**: 3 compromised accounts, 184 MB of financial data exfiltrated  
**Attacker Origin**: Lagos, Nigeria (IP: 41.58.XXX.XXX)  
**Timeline**: January 15, 2026, 08:32 - 10:42 PST (2h 10m)

---

## Attack Timeline

### 08:32 - 08:44 PST: Initial Compromise (Email Distribution)
- Attacker sends 47 phishing emails
- Sender spoofs Microsoft security notification
- Personalized URLs with pre-filled recipient emails
- 31 emails delivered, 12 quarantined, 4 blocked

### 08:47 - 09:02 PST: Credential Harvesting
- 3 users click malicious link:
  - violetm@contoso.com (Finance Manager)
  - u3498@contoso.com (HR Business Partner)
  - u11317@contoso.com (IT Help Desk)
  
- Users enter credentials on fake Microsoft login page
- MFA tokens stolen via real-time phishing proxy (Evilginx framework)

### 08:49 - 10:42 PST: Post-Compromise Activity
**violetm** (Primary Target - Finance Manager):
- 08:49 - First sign-in from Lagos, Nigeria
- 09:05 - Creates malicious inbox forwarding rule
- 09:12 - 09:35 - Accesses 47 files in "Finance" SharePoint folder
- 10:42 - Uploads "Q4_Financial_Projections.xlsx" to personal OneDrive (DLP triggered)

**u3498** (Secondary Target):
- 09:15 - Sign-in from Lagos
- 09:22 - Creates inbox rule forwarding to external email
- 09:30 - Accesses "Employee_Records" folder
- No DLP violations (HR data not classified)

**u11317** (Tertiary Target):
- 09:45 - Sign-in from Lagos
- 09:52 - Attempts to access Azure Portal (blocked by Conditional Access)
- 10:05 - Creates OAuth app delegation (Microsoft Graph Mail.Read)
- Account disabled by security team at 10:30

---

## Technical Details

### Phishing Email Analysis

**From**: security-noreply@micros0ft-verify.com  
**Subject**: Urgent: Verify Your Microsoft Account  
**Body**:
```
Dear [FirstName],

We've detected unusual activity on your Microsoft 365 account. 
For your security, please verify your identity immediately.

[Verify Account Now] <-- Malicious Link

If you don't verify within 24 hours, your account will be locked.

Microsoft Security Team
```

**Malicious URL Pattern**:
```
https://login-microsoftonline.verify-account[.]tk/auth?user={recipient_email}
```

**Infrastructure**:
- Domain: `verify-account[.]tk` (Tokelau TLD, registered Jan 13, 2026)
- Hosting: Cloudflare CDN (masking true origin)
- Certificate: Let's Encrypt (valid HTTPS to appear legitimate)
- Backend: Evilginx2 reverse proxy (captures MFA tokens in real-time)

### Attack Chain Visualization

```
[Attacker] --> [Email Campaign] --> [47 Recipients]
                                           |
                                           v
                                   [3 Users Click Link]
                                           |
                                           v
                               [Fake Microsoft Login Page]
                                           |
                                           v
                           [User Enters Credentials + MFA]
                                           |
                                           v
                          [Evilginx Proxies to Real Microsoft]
                                           |
                                           v
                            [Attacker Steals Session Token]
                                           |
                                           v
                        [Attacker Uses Token from Nigeria IP]
                                           |
                        +------------------+------------------+
                        |                  |                  |
                        v                  v                  v
                [Inbox Rule]      [File Access]      [Data Exfiltration]
```

---

## Indicators of Compromise (IOCs)

### Email Indicators
- **Sender Domain**: `micros0ft-verify.com`
- **Sender IP**: 185.220.101.XXX (Tor exit node)
- **Return-Path**: `bounce@micros0ft-verify.com`
- **Message-ID**: `<20260115083217.A4F2C@micros0ft-verify.com>`

### Network Indicators
- **Phishing URL**: `login-microsoftonline.verify-account[.]tk`
- **C2 Domain**: `verify-account[.]tk`
- **Attacker IP**: `41.58.XXX.XXX` (MainOne Cable, Lagos, Nigeria)
- **Exfiltration Target**: `external-collector@suspicious-domain.tk`
- **SSL Cert SHA-256**: `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`

### File Indicators
- **Exfiltrated Files**: 47 files from SharePoint "Finance" folder
- **DLP Violation File**: `Q4_Financial_Projections.xlsx` (SHA-256: `a1b2c3...`)
- **Total Size**: 184 MB

### User Account Indicators
- **Compromised Accounts**: 
  - violetm@contoso.com (Object ID: xxx-xxx-xxx)
  - u3498@contoso.com (Object ID: xxx-xxx-xxx)
  - u11317@contoso.com (Object ID: xxx-xxx-xxx)

### Persistence Mechanisms
- **Malicious Inbox Rules**:
  - violetm: "IT Security Update" → forwards to `external-collector@suspicious-domain.tk`
  - u3498: "System Notification" → forwards to `backup-mail@suspicious-domain.tk`
- **OAuth Delegations**:
  - u11317: Granted "Mail Exfiltrator" app (App ID: xxx) → Mail.Read permission

---

## Attacker Profile

### Attribution
- **Threat Actor**: Likely APT-C-36 (Blind Eagle) based on TTP overlap
- **Geography**: Lagos, Nigeria (known cybercrime hub)
- **Motivation**: Financial gain (targeting finance data)
- **Sophistication**: Medium (uses commodity phishing kit, no zero-days)

### Tactics, Techniques, and Procedures (MITRE ATT&CK)

| Tactic | Technique | ID | Evidence |
|--------|-----------|----|---------| 
| Initial Access | Phishing | T1566.002 | Spear-phishing link |
| Credential Access | Steal Web Session Cookie | T1539 | Evilginx token theft |
| Persistence | Email Forwarding Rule | T1114.003 | Inbox rules created |
| Persistence | Account Manipulation | T1098 | OAuth app delegation |
| Collection | Email Collection | T1114.002 | Forwarding rule exfiltration |
| Collection | Data from Information Repositories | T1213 | SharePoint file access |
| Exfiltration | Exfiltration Over Web Service | T1567.002 | OneDrive personal upload |

---

## Impact Assessment

### Immediate Impact
- **Compromised Accounts**: 3 user accounts (2 high-privilege: Finance, IT)
- **Data Loss**: 184 MB of sensitive financial data
- **Business Disruption**: Finance team unable to access Q4 planning documents
- **Regulatory Risk**: Potential SOX compliance violation (financial data exfiltration)

### Potential Impact (If Not Contained)
- **Follow-On Attacks**: Attacker could use Finance Manager account for BEC (Business Email Compromise)
- **Ransomware**: IT account could be used to deploy ransomware
- **Competitive Intelligence**: M&A pipeline exposed to competitors
- **Regulatory Fines**: GDPR/CCPA violations if customer data was in exfiltrated files

---

## Lessons Learned

### What Went Wrong
1. **SafeLinks Bypass**: 3 users clicked through SafeLinks warning (user training gap)
2. **Delayed Detection**: 2-hour window between click and containment
3. **Conditional Access Gap**: No geo-fencing for high-risk countries
4. **DLP Policy**: Only 1 file flagged, others not classified properly

### What Went Right
1. **Email Security**: 16 emails (34%) blocked/quarantined before delivery
2. **SafeLinks Telemetry**: All clicks tracked, enabling victim identification
3. **Identity Protection**: Nigerian IP flagged as risky sign-in
4. **DLP Detection**: Financial data upload caught in real-time
5. **Incident Response**: Security team disabled accounts within 30 minutes of DLP alert

---

## Recommendations (From Lab Exercise)

See **Task 5.2** in the lab for full remediation plan.

**Key Improvements**:
- Implement Conditional Access policy blocking sign-ins from Nigeria for privileged accounts
- Enable Continuous Access Evaluation (CAE) for real-time token revocation
- Retrain users on SafeLinks warnings and phishing recognition
- Re-classify SharePoint files with correct sensitivity labels
- Deploy automated response playbook for phishing click + risky sign-in correlation

---

## Related Incidents

This scenario is based on real-world incident #41398 from the January 15, 2026 executive report. For context, see:
- [Executive Report 2026-01-15](../../reports/executive_report_2026-01-15.html)
- Incident #41398: "Suspicious activity was identified" (3 users, phishing category)

The lab expands this incident into a full investigation workflow for training purposes.

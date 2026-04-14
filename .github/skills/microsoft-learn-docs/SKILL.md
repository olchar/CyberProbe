---
name: microsoft-learn-docs
description: Access official Microsoft Learn documentation for security remediation guidance, PowerShell code samples, KQL queries, and best practices during incident investigations. Integrates with Defender XDR, Entra ID, Sentinel, and Microsoft 365 security products.
---

# Microsoft Learn Documentation Integration Skill

## When to Use This Skill

This skill activates when you need **official Microsoft documentation** during security investigations:

### Trigger Scenarios

**✅ Activate this skill when:**
- User asks "How do I remediate [security issue]?"
- Investigation reveals attack technique requiring Microsoft guidance (OAuth attacks, TOR networks, compromised users)
- Need PowerShell commands for remediation actions
- Want validated KQL queries from Microsoft documentation
- Building incident report and need to cite official sources
- Unfamiliar with specific Microsoft security product feature
- Need to verify best practices against Microsoft recommendations

**❌ Do NOT activate for:**
- General web searches (use browser instead)
- Non-Microsoft products or third-party tools
- When Investigation-Guide.md already has the answer
- Basic questions answerable from existing CyberProbe documentation

### Common Investigation Integration Points

This skill integrates seamlessly with investigation workflows:

1. **After OAuth App Detection**: Automatically search for revocation procedures
2. **After TOR/VPN Detection**: Find Conditional Access blocking guidance
3. **After Account Compromise**: Retrieve user remediation playbooks
4. **Before Executing Remediation**: Validate procedures against Microsoft docs
5. **During Report Generation**: Include official Microsoft Learn citations

---

## Prerequisites

### Required MCP Tools

Verify these tools are available (VS Code Copilot includes them automatically):

- `mcp_microsoft_lea_microsoft_docs_search` - Search Microsoft Learn documentation
- `mcp_microsoft_lea_microsoft_code_sample_search` - Search code samples with language filtering
- `mcp_microsoft_lea_microsoft_docs_fetch` - Retrieve full documentation pages

### Authentication

**Microsoft Learn MCP Server is public - no API keys required.**

The server accesses publicly available Microsoft Learn documentation. No special credentials needed.

## Example Prompts

Type these in VS Code Copilot Chat to activate this skill:

**Remediation guidance:**
```
How do I remediate a compromised user account according to Microsoft docs?
```

**Security feature guidance:**
```
What's the official guidance for setting up Conditional Access to block TOR networks?
```

**Code samples:**
```
Show me the Microsoft docs for revoking malicious OAuth app permissions with PowerShell
```

**KQL reference:**
```
Find the official Microsoft KQL examples for detecting impossible travel
```

**Product documentation:**
```
What are the prerequisites for enabling Defender for Endpoint on Linux servers?
```

**Best practices:**
```
What does Microsoft recommend for securing privileged access in Entra ID?
```

---

## Workflow

### Phase 1: Identify Documentation Need

**From investigation context, determine what guidance is needed:**

```
Investigation finding: "Malicious OAuth application 'Micr0s0ft-App' detected"
→ Documentation need: "OAuth application revocation procedures"

Investigation finding: "User authenticated from TOR exit node 185.220.100.252"
→ Documentation need: "Block TOR networks with Conditional Access"

Investigation finding: "User account showing impossible travel alerts"
→ Documentation need: "Compromised user investigation playbook"
```

### Phase 2: Search Microsoft Learn Documentation

**Use `mcp_microsoft_lea_microsoft_docs_search` for quick guidance:**

```python
# Example: OAuth application remediation
query = "revoke malicious OAuth application Azure AD tenant remediation"
result = mcp_microsoft_lea_microsoft_docs_search(query)

# Returns: Up to 10 documentation articles with:
# - Title
# - URL (Microsoft Learn link)
# - Excerpt (relevant content snippet, max 500 tokens)
```

**Best practices for search queries:**
- ✅ Include product names: "Entra ID", "Defender XDR", "Sentinel"
- ✅ Use action verbs: "revoke", "block", "investigate", "remediate"
- ✅ Be specific: "TOR network" not just "anonymous proxy"
- ✅ Include scenario context: "compromised user account" not just "user"

**Common search patterns:**

```
# Remediation actions
"disable compromised user account Microsoft 365"
"revoke OAuth consent grants Entra ID"
"block anonymous networks Conditional Access"
"delete malicious mail forwarding rule Exchange Online"

# Investigation techniques
"trace authentication SessionId Entra ID sign-in logs"
"detect impossible travel KQL query SigninLogs"
"investigate suspicious inbox rule creation"
"find lateral movement Advanced Hunting query"

# Configuration guidance
"configure MFA enforcement policy Entra ID"
"setup identity protection risk policies"
"enable unified audit log Microsoft 365"
"deploy Conditional Access policies"
```

### Phase 3: Get Production-Ready Code Samples

**Use `mcp_microsoft_lea_microsoft_code_sample_search` when you need executable code:**

```python
# Example: PowerShell cmdlets for OAuth revocation
query = "Remove OAuth consent grants Microsoft Graph PowerShell"
language = "powershell"
result = mcp_microsoft_lea_microsoft_code_sample_search(query, language=language)

# Returns: Up to 20 code samples with:
# - Source code (syntax highlighted)
# - Context (what the code does)
# - Documentation link
```

**Supported languages:**
- `powershell` - Microsoft.Graph, Az, ExchangeOnlineManagement modules
- `kusto` - KQL queries for Sentinel/Advanced Hunting
- `python` - Microsoft Graph API, Azure SDK
- `csharp` - .NET Microsoft Graph SDK
- `javascript` / `typescript` - JavaScript/Node.js Microsoft Graph SDK
- `azurecli` - Azure CLI commands
- `java`, `cpp`, `go`, `rust`, `ruby`, `php` - Language-specific SDKs

**Example queries with language filtering:**

```python
# PowerShell for user remediation
mcp_microsoft_lea_microsoft_code_sample_search(
    "disable user account and revoke sessions Entra ID",
    language="powershell"
)

# KQL for threat hunting
mcp_microsoft_lea_microsoft_code_sample_search(
    "detect credential stuffing attacks SigninLogs",
    language="kusto"
)

# Python for Microsoft Graph automation
mcp_microsoft_lea_microsoft_code_sample_search(
    "list OAuth application permissions Microsoft Graph API",
    language="python"
)
```

### Phase 4: Fetch Full Documentation (When Needed)

**Use `mcp_microsoft_lea_microsoft_docs_fetch` for complete guides:**

```python
# When search results are incomplete, fetch the full page
url = "https://learn.microsoft.com/en-us/entra/identity/authentication/howto-authentication-temporary-access-pass"
content = mcp_microsoft_lea_microsoft_docs_fetch(url)

# Returns: Full page in markdown format with:
# - All headings and sections
# - Complete code blocks
# - Tables and lists
# - Preserved links
```

**When to fetch full documentation:**
- Search results show truncated content
- Need complete step-by-step procedures with prerequisites
- Building comprehensive investigation documentation
- Want full troubleshooting guide with multiple scenarios
- Require complete reference documentation (API endpoints, cmdlet parameters)

### Phase 5: Apply Documentation to Investigation

**Extract actionable guidance and include in investigation report:**

```markdown
## Remediation Actions (from Microsoft Learn)

Based on official Microsoft documentation:

### 1. Revoke Malicious OAuth Application
Source: https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/manage-consent-requests

**Steps:**
1. Disable the application (prevents re-consent):
   ```powershell
   Update-MgApplication -ApplicationId <app-id> -DisabledByMicrosoftStatus "DisabledDueToViolation"
   ```

2. Remove existing consent grants:
   ```powershell
   Get-MgOauth2PermissionGrant -Filter "clientId eq '<client-id>'" | 
       ForEach-Object { Remove-MgOauth2PermissionGrant -OAuth2PermissionGrantId $_.Id }
   ```

3. Revoke affected user sessions:
   ```powershell
   Revoke-MgUserSignInSession -UserId <user-object-id>
   ```

**Best Practice (from Microsoft):**
- Disable applications instead of deleting (soft delete allows 30-day recovery if needed)
- Monitor audit logs for "Update application" events where appEnabled changed to true
- Notify affected users and require password reset
```

---

## Complete Examples

### Example 1: OAuth Application Attack Remediation

**Investigation Context:**
- Incident #42281 detected malicious OAuth app "Micr0s0ft-App"
- App has consent grants from 5 users
- App created from TOR exit node 185.220.100.252

**Skill Workflow:**

**Step 1: Search for Remediation Guidance**
```python
result = mcp_microsoft_lea_microsoft_docs_search(
    "revoke malicious OAuth application consent grants Entra ID remediation"
)
```

**Result:**
```
Found 10 articles including:
1. "Detect and Remediate Illicit Consent Grants"
   URL: https://learn.microsoft.com/en-us/entra/identity/...
   Key Steps: Identify → Disable → Revoke grants → Monitor

2. "Review permissions granted to enterprise applications"
   URL: https://learn.microsoft.com/en-us/entra/identity/...
   Prerequisites: Cloud Application Administrator role
```

**Step 2: Get PowerShell Code**
```python
code = mcp_microsoft_lea_microsoft_code_sample_search(
    "Remove-MgOauth2PermissionGrant revoke consent",
    language="powershell"
)
```

**Result:**
```powershell
# Official Microsoft Graph PowerShell
Connect-MgGraph -Scopes "Application.ReadWrite.All"

# List consent grants for app
$grants = Get-MgOauth2PermissionGrant -Filter "clientId eq '<YOUR_APP_CLIENT_ID>'"

# Revoke each grant
$grants | ForEach-Object {
    Remove-MgOauth2PermissionGrant -OAuth2PermissionGrantId $_.Id
    Write-Host "Revoked grant: $($_.Id)"
}
```

**Step 3: Apply to Investigation**
- Execute PowerShell commands with actual app IDs from incident
- Document Microsoft Learn URLs in investigation report
- Include official best practices in recommendations section

---

### Example 2: Block TOR Network Access

**Investigation Context:**
- User elviaa authenticated from TOR exit nodes (185.220.100.252, 45.134.225.36)
- Need to block all TOR/anonymization network access tenant-wide

**Skill Workflow:**

**Step 1: Search for Conditional Access Guidance**
```python
result = mcp_microsoft_lea_microsoft_docs_search(
    "block TOR network anonymous proxy Conditional Access Entra ID"
)
```

**Result:**
```
Found guidance:
1. "Configure named locations in Entra ID Conditional Access"
2. "Block access from anonymization networks"
3. "Create location-based Conditional Access policies"
```

**Step 2: Get Implementation Code**
```python
code = mcp_microsoft_lea_microsoft_code_sample_search(
    "New-MgIdentityConditionalAccessPolicy block location",
    language="powershell"
)
```

**Result:**
```powershell
# Create named location for blocking
$namedLocation = New-MgIdentityConditionalAccessNamedLocation `
    -DisplayName "Blocked - Anonymous Networks" `
    -IsTrusted $false `
    -IpRanges @(
        @{CidrAddress = "185.220.100.0/24"}  # TOR range
        @{CidrAddress = "45.134.225.0/24"}   # TOR range
    )

# Create Conditional Access policy to block
New-MgIdentityConditionalAccessPolicy `
    -DisplayName "Block TOR and Anonymous Networks" `
    -State "Enabled" `
    -Conditions @{
        Locations = @{
            IncludeLocations = $namedLocation.Id
        }
        Users = @{
            IncludeUsers = "All"
            ExcludeUsers = "BreakGlassAccount@contoso.com"  # Emergency access
        }
    } `
    -GrantControls @{
        Operator = "OR"
        BuiltInControls = @("Block")
    }
```

**Step 3: Include in Report**
```markdown
## Recommended Preventive Controls

**Block Anonymous Network Access (TOR/VPN)**
- Source: Microsoft Learn Conditional Access documentation
- Implementation: Create named location for TOR IP ranges + block policy
- Exclude emergency access accounts to prevent lockout
- Monitor SigninLogs for blocked attempts
```

---

### Example 3: Compromised User Investigation Playbook

**Investigation Context:**
- User user03 showing impossible travel: Seattle → Lagos in 30 minutes
- Need official investigation procedures from Microsoft

**Skill Workflow:**

**Step 1: Find Investigation Playbook**
```python
result = mcp_microsoft_lea_microsoft_docs_search(
    "investigate compromised user account impossible travel Defender XDR"
)
```

**Result:**
```
Found playbooks:
1. "Investigate users in Microsoft Defender XDR"
   - 8-step investigation checklist
   - User entity page walkthrough
   - Automated investigation & response (AIR)

2. "Address compromised user accounts with automated investigation"
   - Detection triggers
   - Investigation graph
   - Remediation actions
```

**Step 2: Get Full Investigation Guide**
```python
content = mcp_microsoft_lea_microsoft_docs_fetch(
    "https://learn.microsoft.com/en-us/defender-xdr/investigate-users"
)
```

**Result (excerpt):**
```markdown
# Investigate Users in Microsoft Defender XDR

## Investigation Checklist
1. ✅ Check if user is marked as sensitive/VIP
2. ✅ Review recent failed sign-in attempts
3. ✅ Identify unusual resource access patterns
4. ✅ Check lateral movement paths
5. ✅ Review recent password changes
6. ✅ Examine inbox rules and mail forwarding
7. ✅ Check OAuth application consents
8. ✅ Review multi-factor authentication status

## Remediation Actions
- Revoke active sessions: `Revoke-MgUserSignInSession`
- Disable account: `Update-MgUser -AccountEnabled:$false`
- Force password reset
- Review and revoke suspicious device registrations
```

**Step 3: Apply Microsoft's Checklist to user03**
- Execute each investigation step from official playbook
- Document findings against Microsoft's 8-step checklist
- Use Microsoft's recommended remediation actions
- Include Microsoft Learn URL in final report for audit compliance

---

## Integration with Other Skills

### Works With: incident-investigation

The `incident-investigation` skill automatically leverages Microsoft Learn documentation:

```python
# incident-investigation workflow
Phase 1: Get User ID
Phase 2: Parallel Data Collection (Sentinel + Graph queries)
Phase 3: Export Investigation JSON

# AUTOMATIC INTEGRATION POINT
Phase 4: Detect Threats
  ├─ If OAuth apps detected → Search "revoke OAuth Entra ID"
  ├─ If TOR IPs detected → Search "block TOR Conditional Access"
  ├─ If impossible travel → Search "investigate compromised user"
  └─ Include official remediation steps in report

Phase 5: Generate Report with Microsoft Learn citations
```

### Works With: threat-enrichment

After IP enrichment identifies threats, search for blocking procedures:

```python
# threat-enrichment identifies TOR IP
IP: 185.220.100.252
└─ is_tor: true
└─ abuse_confidence_score: 100

# Automatically trigger Microsoft Learn search
→ mcp_microsoft_lea_microsoft_docs_search("block TOR IP Conditional Access")
→ Include blocking procedures in enrichment report
```

### Works With: report-generation

Include Microsoft Learn citations in investigation reports:

```markdown
## Remediation Actions

All procedures follow official Microsoft security guidance:

1. **Revoke OAuth Application**
   - Source: [Microsoft Learn - Detect Illicit Consent Grants](https://learn.microsoft.com/...)
   - Command: `Remove-MgOauth2PermissionGrant -OAuth2PermissionGrantId <id>`

2. **Block TOR Networks**
   - Source: [Microsoft Learn - Conditional Access Named Locations](https://learn.microsoft.com/...)
   - Implementation: Create named location + block policy

3. **Disable Compromised Account**
   - Source: [Microsoft Learn - Investigate Users in Defender XDR](https://learn.microsoft.com/...)
   - Commands: `Revoke-MgUserSignInSession`, `Update-MgUser -AccountEnabled:$false`
```

---

## Best Practices

### Search Query Optimization

**✅ DO:**
- Include specific product names: "Entra ID", "Defender XDR", "Sentinel"
- Use action verbs: "revoke", "disable", "block", "investigate"
- Add context: "OAuth application", "TOR network", "compromised user"
- Be specific about technique: "impossible travel" not "suspicious login"

**❌ AVOID:**
- Generic queries: "security best practices"
- Non-Microsoft products: "SIEM integration" (use "Sentinel" instead)
- Outdated product names: "Azure AD" (use "Entra ID" for latest docs)
- Multiple unrelated topics in one query

### Code Sample Language Filtering

**Always specify language parameter when searching for code:**

```python
# ✅ GOOD - Specific language
mcp_microsoft_lea_microsoft_code_sample_search(
    "revoke user sessions",
    language="powershell"
)

# ❌ BAD - No language filter (returns mixed results)
mcp_microsoft_lea_microsoft_code_sample_search("revoke user sessions")
```

### Documentation Fetching

**Fetch full docs only when:**
- Search results are truncated or incomplete
- Need complete step-by-step procedures with all prerequisites
- Building comprehensive documentation for audit compliance
- Troubleshooting requires full context of multiple related scenarios

**Don't fetch if:**
- Search results already provide needed information
- Only need specific commands (use code sample search instead)
- Time-sensitive incident response (search is faster)

### Citation and Compliance

**Always include Microsoft Learn URLs in investigation reports:**

```markdown
## References

All remediation procedures follow official Microsoft guidance:
- OAuth Revocation: https://learn.microsoft.com/en-us/entra/identity/...
- Conditional Access: https://learn.microsoft.com/en-us/entra/identity/...
- User Investigation: https://learn.microsoft.com/en-us/defender-xdr/...
```

This ensures:
- ✅ Audit trail for compliance reviews
- ✅ Reproducible procedures for future incidents
- ✅ Training reference for junior analysts
- ✅ Validation against Microsoft's latest recommendations

---

## Troubleshooting

### Issue: No Relevant Results

**Symptom:** Search returns generic or unrelated documentation

**Solutions:**
1. **Add product specificity**: 
   - Change "block IP address" → "block IP address Conditional Access Entra ID"
   
2. **Use Microsoft terminology**:
   - Change "OAuth token" → "OAuth consent grant"
   - Change "VPN" → "anonymous network proxy"
   
3. **Include scenario context**:
   - Change "investigate user" → "investigate compromised user account impossible travel"

4. **Try code sample search instead**:
   - If searching for commands, use `mcp_microsoft_lea_microsoft_code_sample_search`

### Issue: Outdated Documentation

**Symptom:** Results reference deprecated PowerShell modules (Azure AD, MSOnline)

**Solutions:**
1. **Add "Microsoft Graph" to query**: Forces latest PowerShell modules
   - Query: "revoke user sessions Microsoft Graph PowerShell"
   
2. **Filter by recent products**: Use "Entra ID" not "Azure AD"

3. **Check publication date**: If URL shows old date, fetch newer documentation

### Issue: Code Doesn't Execute

**Symptom:** PowerShell cmdlets from documentation fail with "command not found"

**Solutions:**
1. **Verify module installed**:
   ```powershell
   Install-Module Microsoft.Graph -Scope CurrentUser -Force
   Import-Module Microsoft.Graph
   ```

2. **Check required permissions**: Documentation often lists needed scopes
   ```powershell
   Connect-MgGraph -Scopes "Application.ReadWrite.All", "Directory.ReadWrite.All"
   ```

3. **Use code sample search with language filter**: Ensures executable examples
   ```python
   mcp_microsoft_lea_microsoft_code_sample_search(
       "your query here",
       language="powershell"  # Returns only PowerShell examples
   )
   ```

---

## Resources

### Related Files
- `Investigation-Guide.md` - Section 4 (Microsoft Learn Documentation Integration)
- `Investigation-Guide.md` - Section 12 (Investigation Playbooks)
- `.github/skills/incident-investigation/SKILL.md` - Main investigation workflow
- `docs/AGENT_SKILLS.md` - Complete skills documentation

### Microsoft Learn Starting Points
- Entra ID Security: https://learn.microsoft.com/en-us/entra/identity/
- Defender XDR: https://learn.microsoft.com/en-us/defender-xdr/
- Microsoft Sentinel: https://learn.microsoft.com/en-us/azure/sentinel/
- Microsoft Graph PowerShell: https://learn.microsoft.com/en-us/powershell/microsoftgraph/

### Example Queries Library

**Authentication & Identity**
```
"configure MFA enforcement Entra ID Conditional Access"
"investigate risky sign-ins Identity Protection"
"detect password spray attacks KQL query"
"trace authentication chain SessionId SigninLogs"
```

**OAuth & Applications**
```
"detect illicit consent grants OAuth applications"
"review enterprise application permissions"
"revoke OAuth consent grants PowerShell"
"monitor application consent grant events audit logs"
```

**Conditional Access**
```
"create named location Conditional Access"
"block legacy authentication Conditional Access policy"
"configure risk-based access policy"
"require MFA for admin roles"
```

**Incident Response**
```
"investigate compromised user account Defender XDR"
"remediate malicious inbox rules Exchange Online"
"respond to suspicious OAuth application"
"block malicious IP address tenant-wide"
```

**Advanced Hunting (Defender XDR)**
```
"detect lateral movement Advanced Hunting KQL"
"find persistence mechanisms DeviceRegistryEvents"
"track malware execution DeviceProcessEvents"
"identify command and control communication DeviceNetworkEvents"
```

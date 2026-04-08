````skill
---
name: defender-response
description: Execute containment and remediation actions using Microsoft Defender XDR Response MCP tools. Use this skill when isolating devices, managing user compromise status, running AV scans, collecting forensic packages, managing incidents, or performing any active response action during incident handling.
---

# Defender Response Skill

This skill enables **active response and remediation** actions during security incidents using the Defender Response MCP VS Code Extension tools. It bridges the gap between investigation (read-only) and containment/eradication (write actions).

## When to Use This Skill

Use this skill when:
- Isolating compromised devices from the network
- Confirming user accounts as compromised or safe
- Disabling/enabling Active Directory accounts
- Forcing password resets for compromised credentials
- Running antivirus scans on endpoints
- Stopping and quarantining malicious processes/files
- Collecting forensic investigation packages from devices
- Managing incident lifecycle (assign, classify, comment, tag, status)
- Performing bulk device isolation during widespread attacks
- Restricting code execution on compromised endpoints
- Releasing devices after remediation is complete

## Prerequisites

1. **Defender Response MCP Extension**: Must be installed and enabled in VS Code
2. **Appropriate RBAC Permissions**: User must have Defender XDR response actions permissions
3. **Investigation Context**: Always investigate BEFORE taking response actions
4. **Approval Workflow**: For production environments, confirm destructive actions with the analyst

## ⚠️ Critical Safety Rules

**BEFORE executing ANY response action:**

1. ✅ **Investigate first** — Use incident-investigation or endpoint-device-investigation skills to gather evidence
2. ✅ **Confirm the target** — Verify device name, user UPN, or incident ID before acting
3. ✅ **Explain the impact** — Tell the analyst what the action will do before executing
4. ✅ **Ask for confirmation** — Always ask "Should I proceed?" for destructive actions (isolate, disable, quarantine)
5. ✅ **Document the action** — Add incident comments explaining what was done and why
6. ✅ **Track remediation** — Check action status after execution

**Destructive actions requiring explicit confirmation:**
- Device isolation (cuts network access)
- Account disable (blocks all sign-ins)
- Stop and quarantine (terminates processes)
- Force password reset (invalidates credentials)
- Bulk device isolation (affects multiple systems)

**Non-destructive actions (proceed without extra confirmation):**
- Add incident comment
- Add incident tags
- Assign incident
- Run antivirus scan
- Collect investigation package

## Response Action Categories

### Category 1: Device Response Actions

| Action | MCP Tool Activation | Description |
|--------|---------------------|-------------|
| **Isolate Device** | `activate_device_response_tools` → `defender_isolate_device` | Network isolation, Defender comms preserved |
| **Restrict Code Execution** | `activate_device_response_tools` → `defender_restrict_code_execution` | Only Microsoft-signed apps allowed |
| **Run AV Scan** | `activate_device_response_tools` → `defender_run_antivirus_scan` | On-demand malware detection |
| **Stop & Quarantine** | `activate_device_response_tools` → `defender_stop_and_quarantine` | Kill process + quarantine file |
| **Bulk Isolate** | `activate_bulk_device_management_tools` → `defender_isolate_multiple` | Isolate multiple devices at once |
| **Release Device** | `activate_bulk_device_management_tools` → `defender_release_device` | Restore network connectivity |

### Category 2: Identity Response Actions

| Action | MCP Tool Activation | Description |
|--------|---------------------|-------------|
| **Confirm Compromised** | `activate_user_compromise_management_tools` → `defender_confirm_user_compromised` | Escalate Entra ID risk |
| **Confirm Safe** | `activate_user_compromise_management_tools` → `defender_confirm_user_safe` | Dismiss user risk |
| **Disable AD Account** | `activate_active_directory_account_management_tools` → `defender_disable_ad_account` | Block all authentication |
| **Enable AD Account** | `activate_active_directory_account_management_tools` → `defender_enable_ad_account` | Re-enable after remediation |
| **Force Password Reset** | `activate_active_directory_account_management_tools` → `defender_force_ad_password_reset` | Mandate credential change |

### Category 3: Incident Management Actions

| Action | MCP Tool Activation | Description |
|--------|---------------------|-------------|
| **Add Comment** | `activate_incident_management_tools` → `defender_add_incident_comment` | Document investigation notes |
| **Add Tags** | `activate_incident_management_tools` → `defender_add_incident_tags` | Categorize incident |
| **Assign Incident** | `activate_incident_management_tools` → `defender_assign_incident` | Delegate to analyst |
| **Classify Incident** | `activate_incident_management_tools` → `defender_classify_incident` | True/False positive determination |
| **Update Status** | `activate_incident_management_tools` → `defender_update_incident_status` | Active → Resolved, etc. |

### Category 4: Forensic Collection

| Action | MCP Tool Activation | Description |
|--------|---------------------|-------------|
| **Collect Package** | `activate_forensic_investigation_tools` → `defender_collect_investigation_package` | Gather system info, logs, diagnostics |
| **Get Download URI** | `activate_forensic_investigation_tools` → `defender_get_investigation_package_uri` | Download the forensic package |

### Category 5: Device Monitoring (Read-Only)

| Action | MCP Tool Activation | Description |
|--------|---------------------|-------------|
| **Get Machine Actions** | `activate_device_monitoring_tools` → `defender_get_machine_actions` | List recent response actions |
| **Find Machine by Name** | `activate_device_monitoring_tools` → `defender_get_machine_by_name` | Device health, risk, exposure |

## Response Playbooks

### Playbook 1: Compromised User Account

**Trigger**: Investigation confirms account compromise (suspicious sign-ins, impossible travel, credential leak)

```
Step 1: Confirm compromise status
  → activate_user_compromise_management_tools
  → defender_confirm_user_compromised(userId)

Step 2: Disable AD account
  → activate_active_directory_account_management_tools
  → defender_disable_ad_account(accountName)

Step 3: Force password reset
  → activate_active_directory_account_management_tools
  → defender_force_ad_password_reset(accountName)

Step 4: Isolate user's devices (if malware suspected)
  → activate_device_monitoring_tools
  → defender_get_machine_by_name(deviceName)  // for each device
  → activate_device_response_tools
  → defender_isolate_device(machineId, isolationType="Full", comment="User compromise response")

Step 5: Document actions
  → activate_incident_management_tools
  → defender_add_incident_comment(incidentId, comment="Account disabled, password reset forced, devices isolated")

Step 6: Classify and update incident
  → defender_classify_incident(incidentId, classification="TruePositive", determination="CompromisedUser")
  → defender_update_incident_status(incidentId, status="InProgress")
```

### Playbook 2: Malware Containment

**Trigger**: Active malware detected on endpoint (AV alert, suspicious process, C2 communication)

```
Step 1: Isolate the device immediately
  → activate_device_response_tools
  → defender_isolate_device(machineId, isolationType="Full", comment="Active malware containment")

Step 2: Stop malicious process and quarantine
  → activate_device_response_tools
  → defender_stop_and_quarantine(machineId, sha1, comment="Malware quarantine")

Step 3: Restrict code execution
  → activate_device_response_tools
  → defender_restrict_code_execution(machineId, comment="Restrict to Microsoft-signed only")

Step 4: Run full AV scan
  → activate_device_response_tools
  → defender_run_antivirus_scan(machineId, scanType="Full")

Step 5: Collect forensic package
  → activate_forensic_investigation_tools
  → defender_collect_investigation_package(machineId, comment="Post-malware forensics")

Step 6: Check file spread across org
  → mcp_triage_GetDefenderFileRelatedMachines(fileHash)
  → If spread detected → Playbook 3 (Bulk Containment)

Step 7: Document and track
  → activate_incident_management_tools
  → defender_add_incident_comment(incidentId, comment="Device isolated, malware quarantined, AV scan running")
```

### Playbook 3: Ransomware / Bulk Containment

**Trigger**: Multiple devices compromised, lateral movement detected, ransomware spreading

```
Step 1: Bulk isolate all affected devices
  → activate_bulk_device_management_tools
  → defender_isolate_multiple(machineNames=["DEVICE1", "DEVICE2", "DEVICE3"], 
                              isolationType="Full", 
                              comment="Ransomware containment - bulk isolation")

Step 2: Disable affected user accounts
  → For each affected user:
  → activate_active_directory_account_management_tools
  → defender_disable_ad_account(accountName)

Step 3: Restrict code execution on all isolated devices
  → For each device:
  → activate_device_response_tools
  → defender_restrict_code_execution(machineId, comment="Ransomware containment")

Step 4: Run AV scans on all devices
  → For each device:
  → activate_device_response_tools
  → defender_run_antivirus_scan(machineId, scanType="Full")

Step 5: Collect forensic packages from patient zero
  → activate_forensic_investigation_tools
  → defender_collect_investigation_package(machineId, comment="Patient zero forensics")

Step 6: Tag and classify incident
  → activate_incident_management_tools
  → defender_add_incident_tags(incidentId, tags=["ransomware", "bulk-containment", "critical"])
  → defender_classify_incident(incidentId, classification="TruePositive", determination="Malware")
  → defender_assign_incident(incidentId, assignee="incident-commander@contoso.com")
```

### Playbook 4: Post-Remediation Recovery

**Trigger**: Threat eradicated, ready to restore operations

```
Step 1: Verify AV scan clean
  → activate_device_monitoring_tools
  → defender_get_machine_actions(machineId)  // Check scan results

Step 2: Release device from isolation
  → activate_bulk_device_management_tools
  → defender_release_device(machineId, comment="Threat eradicated, releasing device")

Step 3: Re-enable user account
  → activate_active_directory_account_management_tools
  → defender_enable_ad_account(accountName)

Step 4: Confirm user safe
  → activate_user_compromise_management_tools
  → defender_confirm_user_safe(userId)

Step 5: Update incident status
  → activate_incident_management_tools
  → defender_update_incident_status(incidentId, status="Resolved")
  → defender_add_incident_comment(incidentId, comment="Remediation complete. Device released. User re-enabled.")
```

## Workflow Integration with Other Skills

The defender-response skill fits into the CyberProbe investigation lifecycle:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    CyberProbe Investigation Lifecycle                       │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
  ┌──────────┐    ┌──────────┐    ┌──────────────┐    ┌──────────────────┐
  │ DETECT   │───▶│INVESTIGATE│───▶│   RESPOND    │───▶│     REPORT      │
  │          │    │          │    │              │    │                  │
  │ incident-│    │ incident-│    │  defender-   │    │ report-          │
  │correlat- │    │investiga-│    │  response    │    │ generation       │
  │ ion      │    │tion      │    │  ◄────────── │    │                  │
  │          │    │endpoint- │    │  THIS SKILL  │    │                  │
  │          │    │device-inv│    │              │    │                  │
  └──────────┘    └──────────┘    └──────────────┘    └──────────────────┘
                        │                │                      │
                        ▼                ▼                      ▼
                  ┌──────────┐    ┌──────────────┐    ┌──────────────────┐
                  │ threat-  │    │ ioc-         │    │ microsoft-       │
                  │enrichment│    │ management   │    │ learn-docs       │
                  └──────────┘    └──────────────┘    └──────────────────┘
```

**Skill Dependencies:**
- **Called by**: incident-investigation (remediation phase), endpoint-device-investigation (containment)
- **Uses**: incident-management tools, device-response tools, AD tools
- **References**: microsoft-learn-docs (for remediation guidance)
- **Feeds into**: report-generation (action log for final report)

## Example Scenarios

### Scenario 1: Isolate a Compromised Device
```
User: "Isolate device YOURPC01 — it has active malware"

Response:
1. Activate device monitoring tools
2. Find device: defender_get_machine_by_name("YOURPC01")
3. Confirm with analyst: "YOURPC01 (Windows 11, Risk: High) will be isolated. Proceed?"
4. Execute: defender_isolate_device(machineId, "Full", "Active malware containment")
5. Confirm: "YOURPC01 isolated successfully. Network access blocked except Defender."
```

### Scenario 2: Respond to Compromised User
```
User: "User alice@contoso.com is confirmed compromised, take containment actions"

Response:
1. Confirm user compromised: defender_confirm_user_compromised("alice@contoso.com")
2. Disable AD account: defender_disable_ad_account("alice")
3. Force password reset: defender_force_ad_password_reset("alice")
4. Report: "User alice@contoso.com: risk escalated, account disabled, password reset queued."
```

### Scenario 3: Classify and Close Incident
```
User: "Classify incident 44239 as true positive, compromised user, and assign to soc-lead@contoso.com"

Response:
1. Classify: defender_classify_incident(44239, "TruePositive", "CompromisedUser")
2. Assign: defender_assign_incident(44239, "soc-lead@contoso.com")
3. Comment: defender_add_incident_comment(44239, "Classified as TP - Compromised User. Assigned to SOC lead.")
4. Report: "Incident 44239 classified, assigned, and commented."
```

### Scenario 4: Collect Forensics from Endpoint
```
User: "Collect forensic investigation package from SERVER-DC01"

Response:
1. Find device: defender_get_machine_by_name("SERVER-DC01")
2. Collect: defender_collect_investigation_package(machineId, "Forensic collection for incident investigation")
3. Wait for completion, then: defender_get_investigation_package_uri(machineId)
4. Report: "Forensic package collected. Download link: <URI>"
```

## Error Handling

| Error | Cause | Resolution |
|-------|-------|------------|
| Device not found | Incorrect hostname or device not onboarded | Verify device name with `defender_get_machine_by_name` |
| Insufficient permissions | Missing RBAC role | Requires Security Operator or higher in Defender XDR |
| Device already isolated | Previous isolation still active | Use `defender_release_device` first, then re-isolate if needed |
| Account not found | Incorrect UPN or account not synced | Verify with Microsoft Graph user lookup |
| Action pending | Previous action still executing | Check with `defender_get_machine_actions` before retrying |

## Performance Expectations

| Action | Expected Time | Notes |
|--------|---------------|-------|
| Isolate device | ~30-60 seconds | Depends on device connectivity |
| Disable account | ~5-10 seconds | Immediate effect |
| Force password reset | ~5-10 seconds | Takes effect at next sign-in |
| Run AV scan (Quick) | ~5-15 minutes | Background execution |
| Run AV scan (Full) | ~30-120 minutes | Background execution |
| Collect forensic package | ~5-30 minutes | Size depends on system state |
| Bulk isolate (5 devices) | ~2-5 minutes | Parallel execution |

## Resources

- [Investigation-Guide.md - Part III: Response Actions](../../../Investigation-Guide.md#response-actions-via-mcp-tools)
- [Investigation-Guide.md - Response Playbook Integration](../../../Investigation-Guide.md#response-playbook-integration)
- [Microsoft Learn: Defender Response Actions](https://learn.microsoft.com/en-us/defender-endpoint/respond-machine-alerts)
- [Microsoft Learn: Manage Incidents](https://learn.microsoft.com/en-us/defender-xdr/manage-incidents)
````

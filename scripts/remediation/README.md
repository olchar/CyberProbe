# Attack Path Remediation & Monitoring

## Overview

This directory contains scripts and queries to remediate and monitor the attack paths identified by Microsoft Defender for Cloud CSPM.

## Files

| File | Description |
|------|-------------|
| `Remediate-AttackPaths.ps1` | PowerShell remediation scripts for choke points |
| `Deploy-SentinelRules.ps1` | Deploy Sentinel analytics rules for monitoring |
| `../queries/attack_path_monitoring.kql` | KQL queries for attack path tracking |

## Identified Choke Points

These resources appear in multiple attack paths - remediating them blocks multiple attack chains:

| Choke Point | Attack Paths | Priority |
|-------------|--------------|----------|
| **SampleAPI** (API) | 8 | High |
| **contoso-srv1** (VM) | 8 | Critical |
| **contoso-sql** (VM) | 3 | Critical |
| **contoso-proxy** (VM) | 1 | High |
| **contoso-secrets-vm** (VM) | 1 | High |

## High-Value Targets

| Target | Type | Risk |
|--------|------|------|
| contoso-security-vault | Key Vault | Critical |
| contoso-func-test | Function App | High |
| contoso-webapp-test | Web App | High |
| contosostorage001 | Storage | High |

## Usage

### 1. Preview Remediation Changes

```powershell
# Run in WhatIf mode (no changes)
. .\Remediate-AttackPaths.ps1
Start-AttackPathRemediation -WhatIf
```

### 2. Apply Remediation

```powershell
# Apply changes (requires Az module and appropriate permissions)
Connect-AzAccount
Start-AttackPathRemediation
```

### 3. Deploy Sentinel Rules

```powershell
# Preview rules
.\Deploy-SentinelRules.ps1 -WorkspaceName "your-workspace" -ResourceGroupName "your-rg" -WhatIf

# Deploy rules
.\Deploy-SentinelRules.ps1 -WorkspaceName "your-workspace" -ResourceGroupName "your-rg"
```

### 4. Run KQL Queries in Sentinel

1. Open Microsoft Sentinel
2. Go to **Logs**
3. Copy queries from `attack_path_monitoring.kql`
4. Schedule as Analytics Rules or Workbook visualizations

## Remediation Actions

### Phase 1: Critical (Week 1-2)
- [ ] Restrict internet exposure on `contoso-sql` and `contoso-srv1`
- [ ] Enable Key Vault firewall on `contoso-security-vault`
- [ ] Review managed identity permissions

### Phase 2: High Priority (Week 3-4)
- [ ] Secure `SampleAPI` API endpoint
- [ ] Enable storage account firewalls
- [ ] Patch vulnerable VMs

### Phase 3: Monitoring (Ongoing)
- [ ] Deploy Sentinel analytics rules
- [ ] Configure alert notifications
- [ ] Schedule weekly attack path reviews

## Sentinel Analytics Rules

| Rule | Severity | Frequency |
|------|----------|-----------|
| Choke Point Compromise Attempt | High | 15 min |
| Key Vault Access Anomaly | High | 15 min |
| Managed Identity Lateral Movement | Medium | 30 min |
| Storage Data Exfiltration | High | 15 min |
| API Endpoint Attack | Medium | 5 min |

## KPI Tracking

Track these metrics weekly:

- Total attack paths (target: reduce by 50%)
- Critical attack paths (target: 0)
- Unique choke points (target: reduce by 75%)
- High-value targets exposed (target: 0)

## References

- [Microsoft Defender for Cloud Attack Path Analysis](https://learn.microsoft.com/en-us/azure/defender-for-cloud/concept-attack-path)
- [Azure NSG Best Practices](https://learn.microsoft.com/en-us/azure/virtual-network/network-security-groups-overview)
- [Key Vault Security](https://learn.microsoft.com/en-us/azure/key-vault/general/security-features)

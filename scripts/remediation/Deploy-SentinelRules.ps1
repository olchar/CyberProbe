# Azure Sentinel Analytics Rules - Attack Path Monitoring
# Deploy these rules using Azure CLI or ARM templates
# Generated: 2026-02-10

param(
    [Parameter(Mandatory=$true)]
    [string]$WorkspaceName,
    
    [Parameter(Mandatory=$true)]
    [string]$ResourceGroupName,
    
    [switch]$WhatIf
)

$rules = @(
    @{
        displayName = "Critical Attack Path - Choke Point Compromise Attempt"
        description = "Detects potential compromise attempts on identified choke point VMs (contoso-sql, contoso-srv1, contoso-proxy)"
        severity = "High"
        enabled = $true
        query = @'
let ChokePointVMs = dynamic(["contoso-sql", "contoso-srv1", "contoso-proxy", "contoso-secrets-vm", "wap-01"]);
SecurityEvent
| where TimeGenerated > ago(1h)
| where Computer has_any (ChokePointVMs)
| where EventID in (4625, 4648, 4672, 4688)  // Failed logon, explicit creds, special privs, process creation
| summarize 
    FailedLogons = countif(EventID == 4625),
    ExplicitCreds = countif(EventID == 4648),
    PrivEscalation = countif(EventID == 4672),
    ProcessCreation = countif(EventID == 4688)
    by Computer, Account, IpAddress, bin(TimeGenerated, 15m)
| where FailedLogons > 5 or ExplicitCreds > 3 or PrivEscalation > 0
| extend AlertScore = FailedLogons + (ExplicitCreds * 2) + (PrivEscalation * 5)
| where AlertScore > 5
'@
        queryFrequency = "PT15M"
        queryPeriod = "PT1H"
        triggerOperator = "GreaterThan"
        triggerThreshold = 0
        entityMappings = @(
            @{ entityType = "Host"; fieldMappings = @(@{ identifier = "FullName"; columnName = "Computer" }) }
            @{ entityType = "Account"; fieldMappings = @(@{ identifier = "Name"; columnName = "Account" }) }
            @{ entityType = "IP"; fieldMappings = @(@{ identifier = "Address"; columnName = "IpAddress" }) }
        )
        tactics = @("InitialAccess", "PrivilegeEscalation", "LateralMovement")
    },
    @{
        displayName = "High-Value Key Vault Access Anomaly"
        description = "Detects unusual access patterns to the critical Key Vault (contoso-security-vault)"
        severity = "High"
        enabled = $true
        query = @'
AzureDiagnostics
| where TimeGenerated > ago(1h)
| where ResourceType == "VAULTS"
| where Resource =~ "contoso-security-vault"
| extend ClientIP = CallerIPAddress
| extend Operation = OperationName
| extend IsSecretAccess = Operation has_any ("SecretGet", "SecretList", "KeyGet", "KeyList")
| summarize 
    TotalOps = count(),
    SecretAccess = countif(IsSecretAccess),
    FailedOps = countif(ResultType != "Success"),
    UniqueCallers = dcount(ClientIP),
    Operations = make_set(Operation)
    by Resource, CallerIPAddress, bin(TimeGenerated, 15m)
| where SecretAccess > 10 or FailedOps > 5 or UniqueCallers > 3
'@
        queryFrequency = "PT15M"
        queryPeriod = "PT1H"
        triggerOperator = "GreaterThan"
        triggerThreshold = 0
        entityMappings = @(
            @{ entityType = "AzureResource"; fieldMappings = @(@{ identifier = "ResourceId"; columnName = "Resource" }) }
            @{ entityType = "IP"; fieldMappings = @(@{ identifier = "Address"; columnName = "CallerIPAddress" }) }
        )
        tactics = @("CredentialAccess", "Collection")
    },
    @{
        displayName = "Managed Identity Lateral Movement Detected"
        description = "Detects potential lateral movement using managed identities from compromised VMs"
        severity = "Medium"
        enabled = $true
        query = @'
AzureActivity
| where TimeGenerated > ago(1h)
| where Authorization has "managedIdentity"
| extend CallerType = tostring(parse_json(Authorization).evidence.principalType)
| where CallerType == "ServicePrincipal"
| extend TargetResource = tostring(parse_json(Properties).resource)
| extend ResourceType = tostring(parse_json(Properties).resourceType)
| summarize 
    OperationCount = count(),
    UniqueTargets = dcount(TargetResource),
    TargetTypes = make_set(ResourceType),
    Targets = make_set(TargetResource)
    by Caller, bin(TimeGenerated, 30m)
| where OperationCount > 30 or UniqueTargets > 5
'@
        queryFrequency = "PT30M"
        queryPeriod = "PT2H"
        triggerOperator = "GreaterThan"
        triggerThreshold = 0
        entityMappings = @(
            @{ entityType = "Account"; fieldMappings = @(@{ identifier = "AadUserId"; columnName = "Caller" }) }
        )
        tactics = @("LateralMovement", "Execution")
    },
    @{
        displayName = "Storage Account Data Exfiltration Attempt"
        description = "Detects large data transfers from sensitive storage accounts"
        severity = "High"
        enabled = $true
        query = @'
let TargetStorageAccounts = dynamic(["contosostorage001", "stcontososec001", "stcontosoent001"]);
StorageBlobLogs
| where TimeGenerated > ago(30m)
| where AccountName has_any (TargetStorageAccounts)
| where OperationName has_any ("GetBlob", "GetBlobProperties", "ListBlobs")
| summarize 
    TotalBytes = sum(ResponseBodySize),
    OperationCount = count(),
    UniqueIPs = dcount(CallerIpAddress),
    ClientIPs = make_set(CallerIpAddress, 10)
    by AccountName, bin(TimeGenerated, 15m)
| extend TotalMB = round(TotalBytes / 1048576.0, 2)
| where TotalMB > 500 or OperationCount > 1000
'@
        queryFrequency = "PT15M"
        queryPeriod = "PT30M"
        triggerOperator = "GreaterThan"
        triggerThreshold = 0
        entityMappings = @(
            @{ entityType = "AzureResource"; fieldMappings = @(@{ identifier = "ResourceId"; columnName = "AccountName" }) }
        )
        tactics = @("Exfiltration", "Collection")
    },
    @{
        displayName = "API Endpoint Attack Detected"
        description = "Detects attack attempts via exposed API endpoints (SampleAPI choke point)"
        severity = "Medium"
        enabled = $true
        query = @'
ApiManagementGatewayLogs
| where TimeGenerated > ago(15m)
| where OperationId has "SampleAPI" or ApiId has "petstore"
| extend IsError = ResponseCode >= 400
| extend IsSQLi = RequestBody has_any ("SELECT", "UNION", "DROP", "INSERT", "--", "/*", "*/", "OR 1=1", "' OR '")
| extend IsXSS = RequestBody has_any ("<script>", "javascript:", "onerror=", "onload=")
| summarize 
    TotalRequests = count(),
    ErrorCount = countif(IsError),
    SQLiAttempts = countif(IsSQLi),
    XSSAttempts = countif(IsXSS),
    UniqueClients = dcount(CallerIpAddress),
    AttackIPs = make_set_if(CallerIpAddress, IsSQLi or IsXSS, 20)
    by bin(TimeGenerated, 5m), OperationId
| where SQLiAttempts > 0 or XSSAttempts > 0 or ErrorCount > 50
'@
        queryFrequency = "PT5M"
        queryPeriod = "PT15M"
        triggerOperator = "GreaterThan"
        triggerThreshold = 0
        entityMappings = @()
        tactics = @("InitialAccess", "Execution")
    }
)

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  SENTINEL ANALYTICS RULE DEPLOYMENT" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

foreach ($rule in $rules) {
    Write-Host "Rule: $($rule.displayName)" -ForegroundColor Yellow
    Write-Host "  Severity: $($rule.severity)"
    Write-Host "  Tactics: $($rule.tactics -join ', ')"
    Write-Host "  Frequency: $($rule.queryFrequency)"
    
    if ($WhatIf) {
        Write-Host "  [WhatIf] Would create analytics rule" -ForegroundColor Cyan
    } else {
        Write-Host "  Creating rule..." -ForegroundColor Green
        # Use Az CLI or ARM template to deploy
        # az sentinel alert-rule create --workspace-name $WorkspaceName --resource-group $ResourceGroupName ...
    }
    Write-Host ""
}

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  Total Rules: $($rules.Count)" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan

# Export rules to JSON for ARM deployment
$exportPath = Join-Path $PSScriptRoot "sentinel-rules-export.json"
$rules | ConvertTo-Json -Depth 10 | Out-File $exportPath -Encoding UTF8
Write-Host "`nRules exported to: $exportPath" -ForegroundColor Green

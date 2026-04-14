# Required modules: Az.Accounts, Az.Compute, Az.Network, Az.KeyVault
# Install with: Install-Module -Name Az -Scope CurrentUser -Repository PSGallery -Force

<#
.SYNOPSIS
    Remediation scripts for Defender for Cloud Attack Paths
.DESCRIPTION
    This script provides remediation actions for the top choke points and attack paths
    identified in your Azure environment. Run sections individually based on priority.
.NOTES
    Author: CyberProbe Security Team
    Date: 2026-02-10
    Version: 1.1
#>

param(
    [Parameter(Mandatory=$true)]
    [string]$SubscriptionId,
    [switch]$WhatIf,
    [switch]$Verbose
)

# ============================================================================
# CONFIGURATION
# ============================================================================

$ChokePoints = @{
    "contoso-sql" = @{
        ResourceGroup = "rg-contoso-security"
        Subscription = $SubscriptionId
        Priority = "Critical"
        AttackPaths = 3
    }
    "contoso-srv1" = @{
        ResourceGroup = "rg-contoso-security"
        Subscription = $SubscriptionId
        Priority = "Critical"
        AttackPaths = 8
    }
    "SampleAPI" = @{
        ResourceGroup = "rg-contoso-security"
        Subscription = $SubscriptionId
        Priority = "High"
        AttackPaths = 8
        Type = "API"
    }
}

$HighValueTargets = @(
    @{ Name = "contoso-security-vault"; Type = "KeyVault"; ResourceGroup = "rg-contoso-security" }
    @{ Name = "contoso-func-test"; Type = "FunctionApp"; ResourceGroup = "rg-contoso-security" }
    @{ Name = "contoso-webapp-test"; Type = "WebApp"; ResourceGroup = "rg-contoso-security" }
    @{ Name = "contosostorage001"; Type = "StorageAccount"; ResourceGroup = "rg-contoso-security" }
)

# ============================================================================
# REMEDIATION 1: Restrict Internet Exposure on Critical VMs
# ============================================================================

function Repair-InternetExposure {
    param(
        [string]$VMName,
        [string]$ResourceGroupName,
        [switch]$WhatIf
    )
    
    Write-Host ""
    Write-Host "[REMEDIATION] Restricting internet exposure for VM: $VMName" -ForegroundColor Yellow
    
    # Get VM network interface
    $vm = Get-AzVM -Name $VMName -ResourceGroupName $ResourceGroupName -ErrorAction SilentlyContinue
    if (-not $vm) {
        Write-Host "  VM not found: $VMName" -ForegroundColor Red
        return
    }
    
    $nicId = $vm.NetworkProfile.NetworkInterfaces[0].Id
    $nic = Get-AzNetworkInterface -ResourceId $nicId
    
    # Get or create NSG
    $nsgName = "$VMName-nsg-restricted"
    
    if ($WhatIf) {
        Write-Host "  [WhatIf] Would create/update NSG: $nsgName" -ForegroundColor Cyan
        Write-Host "  [WhatIf] Would add rule: Deny-Internet-Inbound (Priority 100)" -ForegroundColor Cyan
        Write-Host "  [WhatIf] Would add rule: Allow-VNet-Only (Priority 200)" -ForegroundColor Cyan
        return
    }
    
    # Create restrictive NSG rules
    $rule1 = New-AzNetworkSecurityRuleConfig -Name "Deny-Internet-Inbound" `
        -Description "Block all internet inbound traffic" `
        -Access Deny -Protocol * -Direction Inbound -Priority 100 `
        -SourceAddressPrefix Internet -SourcePortRange * `
        -DestinationAddressPrefix * -DestinationPortRange *
    
    $rule2 = New-AzNetworkSecurityRuleConfig -Name "Allow-VNet-Inbound" `
        -Description "Allow VNet traffic only" `
        -Access Allow -Protocol * -Direction Inbound -Priority 200 `
        -SourceAddressPrefix VirtualNetwork -SourcePortRange * `
        -DestinationAddressPrefix * -DestinationPortRange *
    
    $rule3 = New-AzNetworkSecurityRuleConfig -Name "Allow-AzureLoadBalancer" `
        -Description "Allow Azure Load Balancer" `
        -Access Allow -Protocol * -Direction Inbound -Priority 300 `
        -SourceAddressPrefix AzureLoadBalancer -SourcePortRange * `
        -DestinationAddressPrefix * -DestinationPortRange *
    
    # Create NSG
    $nsg = New-AzNetworkSecurityGroup -Name $nsgName `
        -ResourceGroupName $ResourceGroupName `
        -Location $vm.Location `
        -SecurityRules $rule1, $rule2, $rule3 `
        -Force
    
    # Associate with NIC
    $nic.NetworkSecurityGroup = $nsg
    Set-AzNetworkInterface -NetworkInterface $nic
    
    Write-Host "  Applied restrictive NSG to $VMName" -ForegroundColor Green
}

# ============================================================================
# REMEDIATION 2: Restrict Key Vault Access
# ============================================================================

function Repair-KeyVaultAccess {
    param(
        [string]$VaultName,
        [string]$ResourceGroupName,
        [switch]$WhatIf
    )
    
    Write-Host ""
    Write-Host "[REMEDIATION] Securing Key Vault: $VaultName" -ForegroundColor Yellow
    
    if ($WhatIf) {
        Write-Host "  [WhatIf] Would enable firewall and virtual network rules" -ForegroundColor Cyan
        Write-Host "  [WhatIf] Would set default action to Deny" -ForegroundColor Cyan
        Write-Host "  [WhatIf] Would enable soft delete and purge protection" -ForegroundColor Cyan
        return
    }
    
    # Enable network restrictions
    Update-AzKeyVaultNetworkRuleSet -VaultName $VaultName `
        -ResourceGroupName $ResourceGroupName `
        -DefaultAction Deny `
        -Bypass AzureServices
    
    # Enable soft delete and purge protection
    Update-AzKeyVault -VaultName $VaultName `
        -ResourceGroupName $ResourceGroupName `
        -EnableSoftDelete $true `
        -EnablePurgeProtection $true
    
    Write-Host "  Key Vault secured with network restrictions" -ForegroundColor Green
}

# ============================================================================
# REMEDIATION 3: Restrict Storage Account Access
# ============================================================================

function Repair-StorageAccountAccess {
    param(
        [string]$StorageAccountName,
        [string]$ResourceGroupName,
        [switch]$WhatIf
    )
    
    Write-Host ""
    Write-Host "[REMEDIATION] Securing Storage Account: $StorageAccountName" -ForegroundColor Yellow
    
    if ($WhatIf) {
        Write-Host "  [WhatIf] Would enable firewall (default deny)" -ForegroundColor Cyan
        Write-Host "  [WhatIf] Would disable public blob access" -ForegroundColor Cyan
        Write-Host "  [WhatIf] Would require secure transfer (HTTPS)" -ForegroundColor Cyan
        return
    }
    
    # Enable firewall and restrict access
    Update-AzStorageAccountNetworkRuleSet -ResourceGroupName $ResourceGroupName `
        -Name $StorageAccountName `
        -DefaultAction Deny `
        -Bypass AzureServices
    
    # Disable public blob access
    Set-AzStorageAccount -ResourceGroupName $ResourceGroupName `
        -Name $StorageAccountName `
        -AllowBlobPublicAccess $false `
        -EnableHttpsTrafficOnly $true `
        -MinimumTlsVersion TLS1_2
    
    Write-Host "  Storage Account secured" -ForegroundColor Green
}

# ============================================================================
# REMEDIATION 4: Review and Restrict Managed Identity Permissions
# ============================================================================

function Get-ManagedIdentityPermissions {
    param(
        [string]$VMName,
        [string]$ResourceGroupName
    )
    
    Write-Host ""
    Write-Host "[AUDIT] Checking Managed Identity permissions for: $VMName" -ForegroundColor Yellow
    
    $vm = Get-AzVM -Name $VMName -ResourceGroupName $ResourceGroupName
    
    if ($vm.Identity) {
        $principalId = $vm.Identity.PrincipalId
        Write-Host "  Managed Identity Principal ID: $principalId" -ForegroundColor Cyan
        
        # Get role assignments
        $assignments = Get-AzRoleAssignment -ObjectId $principalId -ErrorAction SilentlyContinue
        
        if ($assignments) {
            Write-Host "  Role Assignments:" -ForegroundColor White
            foreach ($assignment in $assignments) {
                $scope = $assignment.Scope -replace '/subscriptions/[^/]+/', '.../'
                Write-Host "    - $($assignment.RoleDefinitionName) on $scope" -ForegroundColor Gray
            }
        }
        
        return $assignments
    } else {
        Write-Host "  No managed identity configured" -ForegroundColor Gray
        return $null
    }
}

# ============================================================================
# MAIN EXECUTION
# ============================================================================

function Start-AttackPathRemediation {
    param(
        [switch]$WhatIf
    )
    
    Write-Host "============================================================" -ForegroundColor Magenta
    Write-Host "  ATTACK PATH REMEDIATION - $(Get-Date -Format 'yyyy-MM-dd HH:mm')" -ForegroundColor Magenta
    Write-Host "============================================================" -ForegroundColor Magenta
    
    if ($WhatIf) {
        Write-Host ""
        Write-Host "*** RUNNING IN WHATIF MODE - NO CHANGES WILL BE MADE ***" -ForegroundColor Yellow
        Write-Host ""
    }
    
    # Phase 1: Critical Choke Points
    Write-Host ""
    Write-Host "=== PHASE 1: CRITICAL CHOKE POINTS ===" -ForegroundColor Red
    
    foreach ($chokePoint in $ChokePoints.GetEnumerator() | Where-Object { $_.Value.Priority -eq "Critical" }) {
        $name = $chokePoint.Key
        $config = $chokePoint.Value
        $priority = $config.Priority
        $pathCount = $config.AttackPaths
        
        Write-Host ""
        Write-Host "Processing: $name - Priority: $priority - Blocks $pathCount paths"
        
        # Set subscription context
        Set-AzContext -SubscriptionId $config.Subscription -ErrorAction SilentlyContinue | Out-Null
        
        # Restrict internet exposure
        Repair-InternetExposure -VMName $name -ResourceGroupName $config.ResourceGroup -WhatIf:$WhatIf
        
        # Audit managed identity
        Get-ManagedIdentityPermissions -VMName $name -ResourceGroupName $config.ResourceGroup
    }
    
    # Phase 2: High-Value Targets
    Write-Host ""
    Write-Host "=== PHASE 2: HIGH-VALUE TARGETS ===" -ForegroundColor Yellow
    
    foreach ($target in $HighValueTargets) {
        switch ($target.Type) {
            "KeyVault" {
                Repair-KeyVaultAccess -VaultName $target.Name -ResourceGroupName $target.ResourceGroup -WhatIf:$WhatIf
            }
            "StorageAccount" {
                Repair-StorageAccountAccess -StorageAccountName $target.Name -ResourceGroupName $target.ResourceGroup -WhatIf:$WhatIf
            }
            default {
                $targetName = $target.Name
                $targetType = $target.Type
                Write-Host ""
                Write-Host "[INFO] Manual remediation needed for: $targetName - Type: $targetType" -ForegroundColor Cyan
            }
        }
    }
    
    Write-Host ""
    Write-Host "============================================================" -ForegroundColor Magenta
    Write-Host "  REMEDIATION COMPLETE" -ForegroundColor Magenta
    Write-Host "============================================================" -ForegroundColor Magenta
}

# Run with WhatIf by default for safety
Write-Host ""
Write-Host "To run remediation in WhatIf mode (preview changes):"
Write-Host "  Start-AttackPathRemediation -WhatIf" -ForegroundColor Green
Write-Host ""
Write-Host "To apply changes:"
Write-Host "  Start-AttackPathRemediation" -ForegroundColor Yellow

#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Run CyberProbe IP enrichment with automatic virtual environment handling
.DESCRIPTION
    This wrapper script automatically activates the virtual environment and runs the enrichment script
.PARAMETER IPs
    Array of IP addresses to analyze
.EXAMPLE
    .\run-enrichment.ps1 109.70.100.7 176.65.134.8
#>

param(
    [Parameter(Mandatory=$true, ValueFromRemainingArguments=$true)]
    [string[]]$IPs
)

# Get script directory (enrichment folder)
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RootDir = Split-Path -Parent $ScriptDir
$VenvPython = Join-Path $RootDir ".venv\Scripts\python.exe"
$EnrichmentScript = Join-Path $ScriptDir "enrich_ips.py"

# Validate Python exists
if (-not (Test-Path $VenvPython)) {
    Write-Error "Virtual environment Python not found at: $VenvPython"
    Write-Host "Please run: python -m venv .venv" -ForegroundColor Yellow
    exit 1
}

# Validate enrichment script exists
if (-not (Test-Path $EnrichmentScript)) {
    Write-Error "Enrichment script not found at: $EnrichmentScript"
    exit 1
}

# Already in enrichment directory
try {
    # Run enrichment with full Python path
    Push-Location $ScriptDir
    Write-Host "Analyzing $($IPs.Count) IP address(es)..." -ForegroundColor Cyan
    & $VenvPython "enrich_ips.py" @IPs
    
    if ($LASTEXITCODE -eq 0) {
        Write-Host ""
        Write-Host "Enrichment completed successfully" -ForegroundColor Green
    } else {
        Write-Host "Enrichment failed with exit code: $LASTEXITCODE" -ForegroundColor Red
        exit $LASTEXITCODE
    }
} finally {
    Pop-Location
}

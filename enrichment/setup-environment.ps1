#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Set up CyberProbe Python environment
.DESCRIPTION
    Creates virtual environment and installs required packages
#>

# Script is in enrichment folder
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RootDir = Split-Path -Parent $ScriptDir
$VenvPath = Join-Path $RootDir ".venv"
$VenvPython = Join-Path $VenvPath "Scripts\python.exe"
$RequirementsFile = Join-Path $ScriptDir "requirements.txt"

Write-Host "Setting up CyberProbe environment..." -ForegroundColor Cyan

# Check if venv exists
if (Test-Path $VenvPython) {
    Write-Host "✓ Virtual environment already exists" -ForegroundColor Green
} else {
    Write-Host "Creating virtual environment..." -ForegroundColor Yellow
    python -m venv $VenvPath
    
    if ($LASTEXITCODE -ne 0) {
        Write-Error "Failed to create virtual environment"
        exit 1
    }
    Write-Host "✓ Virtual environment created" -ForegroundColor Green
}

# Install/upgrade pip
Write-Host "Upgrading pip..." -ForegroundColor Yellow
& $VenvPython -m pip install --upgrade pip --quiet

# Check if requirements file exists
if (Test-Path $RequirementsFile) {
    Write-Host "Installing packages from requirements.txt..." -ForegroundColor Yellow
    & $VenvPython -m pip install -r $RequirementsFile --quiet
} else {
    # Install known required packages
    Write-Host "Installing required packages..." -ForegroundColor Yellow
    & $VenvPython -m pip install requests --quiet
}

if ($LASTEXITCODE -eq 0) {
    Write-Host ""
    Write-Host "Environment setup complete!" -ForegroundColor Green
    Write-Host ""
    Write-Host "Usage:" -ForegroundColor Cyan
    Write-Host "  .\enrichment\run-enrichment.ps1 109.70.100.7 176.65.134.8" -ForegroundColor White
} else {
    Write-Host "Package installation failed" -ForegroundColor Red
    exit 1
}

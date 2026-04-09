# MCP Server Health Check
# Run this script to verify all MCP servers are reachable

# Force TLS 1.2 (PowerShell 5.1 defaults to TLS 1.0 which modern endpoints reject)
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$servers = @(
    @{ Name = "Azure"; Url = "https://azure.microsoft.com/mcp" },
    @{ Name = "Data Exploration"; Url = "https://sentinel.microsoft.com/mcp/data-exploration" },
    @{ Name = "Agent Creation"; Url = "https://sentinel.microsoft.com/mcp/security-copilot-agent-creation" },
    @{ Name = "Triage"; Url = "https://sentinel.microsoft.com/mcp/triage" },
    @{ Name = "Microsoft Learn"; Url = "https://learn.microsoft.com/api/mcp" },
    @{ Name = "GitHub"; Url = "https://api.githubcopilot.com/mcp" },
    @{ Name = "Sentinel Graph"; Url = "https://sentinel.microsoft.com/mcp/graph" }
)

$maxRetries = 2

Write-Host ""
Write-Host "MCP Server Health Check" -ForegroundColor Cyan
Write-Host ("=" * 50) -ForegroundColor Gray

$allHealthy = $true

foreach ($server in $servers) {
    $reachable = $false
    $lastError = $null

    for ($attempt = 1; $attempt -le $maxRetries; $attempt++) {
        try {
            $response = Invoke-WebRequest -Uri $server.Url -Method Head -TimeoutSec 10 -UseBasicParsing -ErrorAction Stop
            $status = $response.StatusCode
            if ($status -ge 200 -and $status -lt 400) {
                Write-Host "[OK] $($server.Name)" -ForegroundColor Green -NoNewline
                Write-Host " - Reachable ($status)" -ForegroundColor Gray
            }
            $reachable = $true
            break
        }
        catch {
            $errorStatus = $_.Exception.Response.StatusCode.value__
            $errMsg = $_.Exception.Message
            # MCP servers return 401/403/404/405 for unauthenticated/HEAD requests — server is reachable
            if ($errorStatus -in 401, 403, 404, 405) {
                Write-Host "[OK] $($server.Name)" -ForegroundColor Green -NoNewline
                Write-Host " - Reachable (auth required)" -ForegroundColor Gray
                $reachable = $true
                break
            }
            # SSE/streamable MCP servers reject raw HTTP but the connection was established
            if ($errMsg -match "closed unexpectedly|connection was closed") {
                Write-Host "[OK] $($server.Name)" -ForegroundColor Green -NoNewline
                Write-Host " - Reachable (MCP transport)" -ForegroundColor Gray
                $reachable = $true
                break
            }
            $lastError = $errMsg
            if ($attempt -lt $maxRetries) {
                Start-Sleep -Milliseconds 500
            }
        }
    }

    if (-not $reachable) {
        # Final fallback: try GET (some servers don't support HEAD)
        try {
            Invoke-WebRequest -Uri $server.Url -Method GET -TimeoutSec 10 -UseBasicParsing -ErrorAction Stop | Out-Null
            Write-Host "[OK] $($server.Name)" -ForegroundColor Green -NoNewline
            Write-Host " - Reachable" -ForegroundColor Gray
            $reachable = $true
        }
        catch {
            $errorStatus = $_.Exception.Response.StatusCode.value__
            $errMsg = $_.Exception.Message
            if ($errorStatus -in 401, 403, 404, 405) {
                Write-Host "[OK] $($server.Name)" -ForegroundColor Green -NoNewline
                Write-Host " - Reachable (auth required)" -ForegroundColor Gray
                $reachable = $true
            }
            elseif ($errMsg -match "closed unexpectedly|connection was closed") {
                Write-Host "[OK] $($server.Name)" -ForegroundColor Green -NoNewline
                Write-Host " - Reachable (MCP transport)" -ForegroundColor Gray
                $reachable = $true
            }
        }
    }

    if (-not $reachable) {
        Write-Host "[FAIL] $($server.Name)" -ForegroundColor Red -NoNewline
        Write-Host " - Unreachable: $lastError" -ForegroundColor Gray
        $allHealthy = $false
    }
}

Write-Host ("=" * 50) -ForegroundColor Gray

if ($allHealthy) {
    Write-Host "All MCP servers are reachable!" -ForegroundColor Green
} else {
    Write-Host "Some MCP servers may have issues. Check network/VPN." -ForegroundColor Yellow
}

# ── Azure CLI Authentication Check ──
Write-Host ""
Write-Host "Azure CLI Authentication" -ForegroundColor Cyan
Write-Host ("-" * 50) -ForegroundColor Gray

# Read tenant ID from config.json if available
$configPath = Join-Path $PSScriptRoot '..\enrichment\config.json'
$tenantId = $null
if (Test-Path $configPath) {
    $config = Get-Content $configPath -Raw | ConvertFrom-Json
    $tenantId = $config.tenant_id
}

# Check if az CLI is installed
$azCmd = Get-Command az -ErrorAction SilentlyContinue
if (-not $azCmd) {
    Write-Host "[SKIP] Azure CLI not installed" -ForegroundColor Yellow
    Write-Host "  Install: https://aka.ms/installazurecli" -ForegroundColor DarkGray
} else {
    # Check current login state
    $acct = $null
    try {
        $acct = az account show 2>$null | ConvertFrom-Json
    } catch {}

    if ($acct) {
        Write-Host "[OK] Signed in as: $($acct.user.name)" -ForegroundColor Green
        Write-Host "  Subscription: $($acct.name)" -ForegroundColor DarkGray
        Write-Host "  Tenant: $($acct.tenantId)" -ForegroundColor DarkGray

        # Warn if logged into a different tenant than config
        if ($tenantId -and $acct.tenantId -ne $tenantId) {
            Write-Host "[WARN] Config tenant ($tenantId) differs from az CLI tenant ($($acct.tenantId))" -ForegroundColor Yellow
            Write-Host "  Run: az login --tenant $tenantId" -ForegroundColor Yellow
        }
    } else {
        Write-Host "[AUTH] Not signed in — launching Azure CLI login..." -ForegroundColor Yellow
        if ($tenantId) {
            Write-Host "  Tenant: $tenantId" -ForegroundColor DarkGray
            az login --tenant $tenantId --only-show-errors
        } else {
            az login --only-show-errors
        }
        # Verify login succeeded
        try {
            $acct = az account show 2>$null | ConvertFrom-Json
            if ($acct) {
                Write-Host "[OK] Signed in as: $($acct.user.name)" -ForegroundColor Green
            } else {
                Write-Host "[FAIL] Azure CLI login did not complete" -ForegroundColor Red
            }
        } catch {
            Write-Host "[FAIL] Azure CLI login did not complete" -ForegroundColor Red
        }
    }

    # Pre-fetch a Graph token to warm the token cache (also detects expired refresh tokens)
    if ($acct) {
        $graphTokenOk = $false
        $tokenErr = az account get-access-token --resource https://graph.microsoft.com --query "expiresOn" -o tsv 2>&1
        if ($LASTEXITCODE -eq 0 -and $tokenErr -notmatch 'AADSTS') {
            Write-Host "[OK] Graph API token cached (expires: $tokenErr)" -ForegroundColor Green
            $graphTokenOk = $true
        } else {
            Write-Host "[WARN] Graph token expired or invalid — re-authenticating..." -ForegroundColor Yellow
            az logout --only-show-errors 2>$null
            if ($tenantId) {
                az login --tenant $tenantId --scope "https://graph.microsoft.com/.default" --only-show-errors
            } else {
                az login --only-show-errors
            }
            # Retry token fetch
            $tokenRetry = az account get-access-token --resource https://graph.microsoft.com --query "expiresOn" -o tsv 2>$null
            if ($LASTEXITCODE -eq 0 -and $tokenRetry) {
                Write-Host "[OK] Re-authenticated — Graph token cached (expires: $tokenRetry)" -ForegroundColor Green
                $graphTokenOk = $true
            } else {
                Write-Host "[FAIL] Could not obtain Graph API token" -ForegroundColor Red
            }
        }

        # Also warm the Log Analytics token for Sentinel queries
        if ($graphTokenOk) {
            $laToken = az account get-access-token --resource https://api.loganalytics.io --query "expiresOn" -o tsv 2>$null
            if ($LASTEXITCODE -eq 0 -and $laToken) {
                Write-Host "[OK] Log Analytics token cached (expires: $laToken)" -ForegroundColor Green
            } else {
                Write-Host "[WARN] Could not pre-cache Log Analytics token" -ForegroundColor Yellow
            }
        }
    }
}

Write-Host ""
Write-Host ("-" * 50) -ForegroundColor Gray
Write-Host "Note: MCP server auth happens when Copilot first calls a tool." -ForegroundColor DarkGray
Write-Host "  VS Code will prompt a browser sign-in on first MCP tool use." -ForegroundColor DarkGray
Write-Host ""
Write-Host "Sentinel Extension Setup:" -ForegroundColor Cyan
Write-Host "  To connect the Sentinel sidebar, run: Ctrl+Shift+P → 'Microsoft Sentinel: Sign In'" -ForegroundColor DarkGray
if ($tenantId) {
    Write-Host "  Tenant ID: $tenantId" -ForegroundColor DarkGray
} else {
    Write-Host "  Tenant ID: <not configured — copy enrichment/config.json.template to config.json>" -ForegroundColor DarkGray
}

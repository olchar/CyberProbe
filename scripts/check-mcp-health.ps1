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

Write-Host ""
Write-Host "Note: MCP authentication happens automatically through VS Code Copilot." -ForegroundColor DarkGray
Write-Host ""
Write-Host "Sentinel Extension Setup:" -ForegroundColor Cyan
Write-Host "  To connect the Sentinel sidebar, run: Ctrl+Shift+P → 'Microsoft Sentinel: Sign In'" -ForegroundColor DarkGray

# Read tenant ID from config.json if available
$configPath = Join-Path $PSScriptRoot '..\enrichment\config.json'
if (Test-Path $configPath) {
    $config = Get-Content $configPath -Raw | ConvertFrom-Json
    $tenantId = $config.tenant_id
} else {
    $tenantId = '<not configured — copy enrichment/config.json.template to config.json>'
}
Write-Host "  Tenant ID: $tenantId" -ForegroundColor DarkGray

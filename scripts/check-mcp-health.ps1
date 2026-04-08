# MCP Server Health Check
# Run this script to verify all MCP servers are reachable

$servers = @(
    @{ Name = "Data Exploration"; Url = "https://sentinel.microsoft.com/mcp/data-exploration" },
    @{ Name = "Agent Creation"; Url = "https://sentinel.microsoft.com/mcp/security-copilot-agent-creation" },
    @{ Name = "Triage"; Url = "https://sentinel.microsoft.com/mcp/triage" },
    @{ Name = "Microsoft Learn"; Url = "https://learn.microsoft.com/api/mcp" },
    @{ Name = "GitHub"; Url = "https://api.githubcopilot.com/mcp" },
    @{ Name = "Sentinel Graph"; Url = "https://sentinel.microsoft.com/mcp/graph" }
)

Write-Host ""
Write-Host "MCP Server Health Check" -ForegroundColor Cyan
Write-Host ("=" * 50) -ForegroundColor Gray

$allHealthy = $true

foreach ($server in $servers) {
    try {
        $response = Invoke-WebRequest -Uri $server.Url -Method Head -TimeoutSec 10 -UseBasicParsing -ErrorAction Stop
        $status = $response.StatusCode
        if ($status -ge 200 -and $status -lt 400) {
            Write-Host "✅ $($server.Name)" -ForegroundColor Green -NoNewline
            Write-Host " - Reachable ($status)" -ForegroundColor Gray
        } else {
            Write-Host "⚠️ $($server.Name)" -ForegroundColor Yellow -NoNewline
            Write-Host " - Status: $status" -ForegroundColor Gray
            $allHealthy = $false
        }
    }
    catch {
        # MCP servers often return 401/405 for unauthenticated requests, which is expected
        $errorStatus = $_.Exception.Response.StatusCode.value__
        if ($errorStatus -eq 401 -or $errorStatus -eq 405 -or $errorStatus -eq 403) {
            Write-Host "✅ $($server.Name)" -ForegroundColor Green -NoNewline
            Write-Host " - Reachable (auth required)" -ForegroundColor Gray
        } elseif ($null -eq $errorStatus) {
            Write-Host "❌ $($server.Name)" -ForegroundColor Red -NoNewline
            Write-Host " - Unreachable: $($_.Exception.Message)" -ForegroundColor Gray
            $allHealthy = $false
        } else {
            Write-Host "⚠️ $($server.Name)" -ForegroundColor Yellow -NoNewline
            Write-Host " - Status: $errorStatus" -ForegroundColor Gray
        }
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
Write-Host "  Tenant ID: 0527ecb7-06fb-4769-b324-fd4a3bb865eb" -ForegroundColor DarkGray

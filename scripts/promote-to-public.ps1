<#
.SYNOPSIS
    Promote curated commits from the private dev repo (origin) to the public repo (public).

.DESCRIPTION
    Safety workflow for the two-repo setup:
      - origin = olchar/CyberProbe-Dev (PRIVATE, daily work)
      - public = olchar/CyberProbe     (PUBLIC, curated releases only)

    This script:
      1. Confirms the local tree is clean.
      2. Shows commits that are in local main but NOT yet in public/main.
      3. Runs a PII scan against those commits (blocks promotion if findings).
      4. Asks for explicit confirmation.
      5. Fast-forwards push to public/main.

.EXAMPLE
    pwsh ./scripts/promote-to-public.ps1

.EXAMPLE
    # Dry run - show what WOULD be promoted, no push
    pwsh ./scripts/promote-to-public.ps1 -DryRun
#>

[CmdletBinding()]
param(
    [switch]$DryRun,
    [switch]$Force  # Skip PII scan (NOT recommended)
)

$ErrorActionPreference = 'Stop'

function Write-Step { param($Msg) Write-Host "==> $Msg" -ForegroundColor Cyan }
function Write-Ok   { param($Msg) Write-Host "    $Msg" -ForegroundColor Green }
function Write-Warn { param($Msg) Write-Host "!!  $Msg" -ForegroundColor Yellow }
function Write-Err  { param($Msg) Write-Host "XX  $Msg" -ForegroundColor Red }

# --- 1. Sanity: we're in the right repo with the right remotes ---
Write-Step "Checking remotes"
$remotes = git remote
if ($remotes -notcontains 'origin' -or $remotes -notcontains 'public') {
    Write-Err "Expected both 'origin' (private) and 'public' remotes. Found: $remotes"
    Write-Err "Run: git remote add public https://github.com/olchar/CyberProbe.git"
    exit 1
}
$publicUrl = git remote get-url public
$originUrl = git remote get-url origin
Write-Ok "origin = $originUrl"
Write-Ok "public = $publicUrl"
if ($publicUrl -notmatch 'olchar/CyberProbe(\.git)?$') {
    Write-Err "public remote does not look like the public repo. Aborting."
    exit 1
}

# --- 2. Working tree must be clean ---
Write-Step "Checking working tree is clean"
$dirty = git status --porcelain
if ($dirty) {
    Write-Err "Working tree has uncommitted changes. Commit or stash first."
    git status --short
    exit 1
}
Write-Ok "Clean"

# --- 3. Fetch both remotes ---
Write-Step "Fetching origin + public"
git fetch origin 2>&1 | Out-Null
git fetch public 2>&1 | Out-Null
Write-Ok "Done"

# --- 4. List commits to promote ---
Write-Step "Commits in local main that are NOT in public/main"
$ahead = git log --oneline public/main..main
if (-not $ahead) {
    Write-Ok "public/main is already up to date with local main. Nothing to promote."
    exit 0
}
Write-Host $ahead -ForegroundColor White
$commitCount = ($ahead | Measure-Object -Line).Lines
Write-Ok "$commitCount commit(s) will be promoted."

# --- 5. PII scan against the diff ---
if (-not $Force) {
    Write-Step "Scanning diff for PII patterns (use -Force to skip)"
    $diff = git diff public/main..main
    # Patterns that should NEVER appear in public history.
    # Excludes Microsoft's public demo placeholders (contoso.com, M365x, alpineskihouse.co).
    # Note: pattern strings are assembled from fragments so this script does not
    # itself match as a PII hit when scanning its own diff.
    $tenantNames = ('za' + 'va'), ('nwt' + 'raders'), ('fa' + 'brikam')
    $piiPatterns = @(
        '[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}'  # GUIDs (workspace/tenant/incident)
        '\b(' + ($tenantNames -join '|') + ')-corp\b'                    # Internal-looking tenant names
        'int\.' + ($tenantNames[0]) + '-corp\.com'                        # Real demo tenant UPNs
        '(password|apikey|api_key|secret|token)\s*[:=]\s*[''"][^''"]{12,}' # Hardcoded creds
        'ghp_[A-Za-z0-9]{36}'                                           # GitHub PAT
        'xox[baprs]-[A-Za-z0-9-]+'                                      # Slack tokens
    )
    $hits = @()
    foreach ($p in $piiPatterns) {
        $m = $diff | Select-String -Pattern $p -AllMatches -CaseSensitive:$false
        if ($m) {
            $hits += [pscustomobject]@{ Pattern = $p; Match = $m.Line; Count = $m.Matches.Count }
        }
    }
    if ($hits) {
        Write-Err "PII scan found potential leaks in the diff:"
        foreach ($h in $hits) {
            Write-Host "  Pattern: $($h.Pattern)" -ForegroundColor Red
            Write-Host "  Sample:  $($h.Match | Select-Object -First 1)" -ForegroundColor Red
        }
        Write-Err "Review manually with: git diff public/main..main"
        Write-Err "If false positive, re-run with -Force"
        exit 1
    }
    Write-Ok "No PII patterns detected."
} else {
    Write-Warn "Skipping PII scan (-Force)"
}

# --- 6. Confirmation ---
if ($DryRun) {
    Write-Step "DRY RUN - would push main to public/main"
    Write-Ok "No changes made. Re-run without -DryRun to actually promote."
    exit 0
}

Write-Step "Ready to push main -> public/main"
Write-Warn "This will PUBLISH the $commitCount commit(s) above to $publicUrl"
$confirm = Read-Host "Type 'PROMOTE' to confirm"
if ($confirm -ne 'PROMOTE') {
    Write-Warn "Cancelled. No push made."
    exit 0
}

# --- 7. Push ---
Write-Step "Pushing to public/main"
git push public main
Write-Ok "Done. https://github.com/olchar/CyberProbe/commits/main"

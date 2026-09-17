<#
.SYNOPSIS
    Remove URDS from this machine, reverting only what install.ps1 changed.

.DESCRIPTION
    Reads %ProgramData%\URDS\install-receipt.json and undoes what it says was
    done, in the reverse order it was done in. Two things in that sentence are
    doing real work.

    "Only what install.ps1 changed." The Windows file-system audit subcategory
    is machine-wide. Reverting it because an uninstaller assumes it owns it
    turns off file auditing for every other protected root, and for anything
    else on the machine that depends on it - a security tool, a compliance
    baseline, a Group Policy setting somebody else applied. The agent that
    loses attribution this way does not fail loudly: it keeps running, reports
    every write as `unknown`, and suspends nothing, for ever. That happened on
    this project's own development machine during a cleanup, and the receipt is
    why it cannot happen from here. If the subcategory was already on before
    URDS was installed, this script leaves it on and says so.

    "In the reverse order." The service is stopped before the canaries are
    removed, and that ordering is not tidiness. A canary is a decoy whose whole
    point is that deleting one is an unambiguous tripwire; the agent suspends
    whatever deleted it, immediately, with no threshold. An uninstaller that
    removes twenty of them with the agent still running gets suspended by the
    thing it is uninstalling.

    The ledger is kept. It is the evidence of everything the agent did while it
    was installed, and an uninstaller is not entitled to delete an audit trail.
    The path is printed at the end.

.PARAMETER Force
    Proceed without a receipt, reverting what can be identified from the
    checkout. The machine-wide audit subcategory is still left alone: without a
    receipt there is no way to know whether it was on beforehand, and the safe
    assumption is the one that does not break somebody else's auditing.

.PARAMETER RestoreShadowStorage
    Also resize shadow storage back to what it was. Off by default, because
    shrinking shadow storage deletes existing shadow copies - including restore
    points that have nothing to do with this project. The prior value and the
    exact command are printed instead.

.PARAMETER KeepCanaries
    Leave the decoy documents in the protected folders.

.PARAMETER Relaunched
    Set by the script on itself when it re-launches under UAC.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File uninstall.ps1
#>

[CmdletBinding()]
param(
    [switch]$Force,
    [switch]$RestoreShadowStorage,
    [switch]$KeepCanaries,
    [switch]$Relaunched
)

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "Re-launching as Administrator. Approve the UAC prompt." -ForegroundColor Yellow
    # -Command, for the reason spelled out in install.ps1's elevation block.
    $script = $PSCommandPath -replace "'", "''"
    $inner = "& '$script' -Relaunched"
    if ($Force)                { $inner += " -Force" }
    if ($RestoreShadowStorage) { $inner += " -RestoreShadowStorage" }
    if ($KeepCanaries)         { $inner += " -KeepCanaries" }
    try {
        $elevated = Start-Process powershell -Verb RunAs -PassThru -Wait `
            -ArgumentList "-NoProfile -ExecutionPolicy Bypass -Command `"$inner`""
        exit $elevated.ExitCode
    } catch {
        Write-Host "Elevation was declined or failed: $($_.Exception.Message)" -ForegroundColor Red
        exit 3
    }
}

$ErrorActionPreference = 'Continue'

$RepoRoot    = $PSScriptRoot

# Same reason install.ps1 does it: an elevated console starts in system32 and
# `python -m agent` finds the package through the working directory. Without
# this, `canary --remove` and `agent remove` both return "No module named
# agent", and an uninstall that cannot read the decoy manifest leaves twenty
# files behind in a folder nothing is watching any more.
Set-Location -LiteralPath $RepoRoot

$StateDir    = Join-Path $env:ProgramData 'URDS'
$ReceiptPath = Join-Path $StateDir 'install-receipt.json'
$ConfigPath  = Join-Path $StateDir 'agent.json'
$UninstallLog = Join-Path $StateDir 'uninstall.log'
$ServiceName = 'URDSAgent'
$FileSystemSubcategory = '{0CCE921D-69AE-11D9-BED3-505054503030}'

New-Item -ItemType Directory -Force -Path $StateDir | Out-Null
Start-Transcript -Path $UninstallLog -Force | Out-Null

$script:Failures = 0

function Write-Result {
    param([string]$Label, [bool]$Ok, [string]$Detail = '')
    $mark = if ($Ok) { '  ok  ' } else { ' FAIL ' }
    $line = "[$mark] $Label"
    if ($Detail) { $line += "  -  $Detail" }
    Write-Host $line -ForegroundColor $(if ($Ok) { 'Green' } else { 'Red' })
    if (-not $Ok) { $script:Failures++ }
}

function Write-Kept {
    param([string]$Label, [string]$Why)
    Write-Host "[ kept ] $Label" -ForegroundColor Cyan
    foreach ($row in ($Why -split "`n")) { Write-Host "         $row" -ForegroundColor DarkGray }
}

function Get-AuditPolicyState {
    $raw = & auditpol /get /subcategory:"$FileSystemSubcategory" /r 2>$null
    if (-not $raw) { return 'unknown' }
    $row = $raw | ConvertFrom-Csv | Select-Object -First 1
    if (-not $row) { return 'unknown' }
    return $row.'Inclusion Setting'
}

Write-Host ""
Write-Host "  URDS uninstall" -ForegroundColor White
Write-Host "  transcript: $UninstallLog" -ForegroundColor DarkGray
Write-Host ""

# ------------------------------------------------------------------- receipt

$receipt = $null
if (Test-Path $ReceiptPath) {
    try {
        $receipt = Get-Content $ReceiptPath -Raw | ConvertFrom-Json
        Write-Host "  receipt: $ReceiptPath (installed $($receipt.installed_at))" -ForegroundColor DarkGray
    } catch {
        Write-Host "  receipt at $ReceiptPath is unreadable: $($_.Exception.Message)" -ForegroundColor Red
    }
}

if (-not $receipt) {
    if (-not $Force) {
        Write-Host ""
        Write-Host "  No install receipt at $ReceiptPath." -ForegroundColor Red
        Write-Host ""
        Write-Host "  Without it this script does not know which of the machine-wide settings" -ForegroundColor Yellow
        Write-Host "  were already in place before URDS was installed - in particular whether" -ForegroundColor Yellow
        Write-Host "  file-system auditing was already on for something else. Reverting it" -ForegroundColor Yellow
        Write-Host "  blind would take attribution away from whatever that something else is." -ForegroundColor Yellow
        Write-Host ""
        Write-Host "  Re-run with -Force to remove the service, the SACLs and the canaries" -ForegroundColor Yellow
        Write-Host "  and leave every machine-wide setting exactly as it is." -ForegroundColor Yellow
        Stop-Transcript | Out-Null
        if ($Relaunched) { Read-Host "Press Enter to close" | Out-Null }
        exit 2
    }
    Write-Host "  -Force: proceeding without a receipt. Machine-wide settings stay as they are." -ForegroundColor Yellow
}

$venvPython = Join-Path $RepoRoot '.venv\Scripts\python.exe'

# ------------------------------------------------- 1. the demonstration stack

Write-Host ""
$stackScript = Join-Path $RepoRoot 'scripts\start_stack.ps1'
if (Test-Path $stackScript) {
    & powershell -NoProfile -ExecutionPolicy Bypass -File $stackScript -Stop | Out-Null
    Write-Result "dashboard and API services stopped" ($LASTEXITCODE -eq 0) "scripts\start_stack.ps1 -Stop"
}

# ----------------------------------------------------------- 2. stop the agent

# Before the canaries, and that order is the whole reason this script has an
# order. See the description.
$queried = & sc.exe query $ServiceName 2>&1
if ($LASTEXITCODE -eq 0) {
    & sc.exe stop $ServiceName | Out-Null
    $deadline = (Get-Date).AddSeconds(30)
    $state = ''
    while ((Get-Date) -lt $deadline) {
        Start-Sleep -Seconds 2
        $state = (& sc.exe query $ServiceName | Select-String 'STATE') -join ''
        if ($state -match 'STOPPED') { break }
    }
    Write-Result "agent stopped" ($state -match 'STOPPED') $state.Trim()
} else {
    Write-Host "[ skip ] agent stopped  -  $ServiceName is not registered" -ForegroundColor DarkGray
}

# --------------------------------------------------------------- 3. canaries

if ($KeepCanaries) {
    Write-Kept "canaries" "left in place by -KeepCanaries"
} elseif (Test-Path $venvPython) {
    # Reads the manifest the agent wrote. Matching decoys by filename instead
    # would delete any file a user happened to name the same way, and would miss
    # any the agent had renamed.
    $removal = & $venvPython -m agent canary --remove 2>&1
    $removed = 0
    try { $removed = [int](($removal -join "`n") | ConvertFrom-Json).removed } catch { }
    Write-Result "canaries removed" ($LASTEXITCODE -eq 0) "$removed decoy(s)"
} else {
    Write-Result "canaries removed" $false "no interpreter at $venvPython to read the manifest with"
}

# ------------------------------------------------------------ 4. the service

$queried = & sc.exe query $ServiceName 2>&1
if ($LASTEXITCODE -eq 0) {
    if (Test-Path $venvPython) {
        & $venvPython -m agent remove 2>&1 | Out-Null
    }
    & sc.exe query $ServiceName 2>&1 | Out-Null
    if ($LASTEXITCODE -eq 0) {
        # pywin32's remove can leave the registration behind if the service is
        # still marked for deletion; sc.exe finishes the job.
        & sc.exe delete $ServiceName | Out-Null
        Start-Sleep -Seconds 2
    }
    & sc.exe query $ServiceName 2>&1 | Out-Null
    Write-Result "service removed" ($LASTEXITCODE -ne 0) $ServiceName
} else {
    Write-Host "[ skip ] service removed  -  $ServiceName was not registered" -ForegroundColor DarkGray
}

# --------------------------------------------------------------- 5. the SACLs

$auditScript = Join-Path $RepoRoot 'scripts\setup_attribution_audit.ps1'
$paths = @()
if ($receipt -and $receipt.applied.sacl_paths) { $paths = @($receipt.applied.sacl_paths) }
elseif ($receipt -and $receipt.protected_paths) { $paths = @($receipt.protected_paths) }
elseif ($Force) { $paths = @((Join-Path $RepoRoot 'watched_files')) }

foreach ($path in $paths) {
    if (-not (Test-Path -LiteralPath $path)) {
        Write-Host "[ skip ] SACL on $path  -  the directory is gone" -ForegroundColor DarkGray
        continue
    }
    # -SaclOnly. Without it the audit script disables the machine-wide
    # subcategory on the first path, and every later path in this loop would be
    # un-audited before its SACL was even removed.
    & powershell -NoProfile -ExecutionPolicy Bypass -File $auditScript `
        -WatchPath $path -Revert -SaclOnly | Out-Null
    Write-Result "SACL removed from $path" ($LASTEXITCODE -eq 0) "-Revert -SaclOnly"
}

# ------------------------------------------------- 6. the machine-wide policy

$current = Get-AuditPolicyState
if (-not $receipt) {
    Write-Kept "File System audit subcategory (currently: $current)" `
        ("No receipt, so there is no record of whether it was on before URDS was`n" +
         "installed. Turning it off could break auditing that predates this project.`n" +
         "Turn it off yourself with:`n" +
         "  auditpol /set /subcategory:`"$FileSystemSubcategory`" /success:disable")
} elseif ($receipt.prior.audit_subcategory_was_enabled) {
    Write-Kept "File System audit subcategory (currently: $current)" `
        ("It was already enabled before URDS was installed - the receipt recorded`n" +
         "`"$($receipt.prior.audit_subcategory)`" - so something else on this machine is using it.`n" +
         "Left exactly as found.")
} else {
    & auditpol /set /subcategory:"$FileSystemSubcategory" /success:disable | Out-Null
    $now = Get-AuditPolicyState
    Write-Result "File System audit subcategory disabled" ($now -notmatch 'Success') `
        "was `"$($receipt.prior.audit_subcategory)`" before install, now `"$now`""
}

# ------------------------------------------------------- 7. the Security log

if ($receipt -and $receipt.prior.security_log_max_bytes) {
    $priorBytes = [int64]$receipt.prior.security_log_max_bytes
    & wevtutil sl Security /ms:$priorBytes 2>&1 | Out-Null
    $log = Get-WinEvent -ListLog Security -ErrorAction SilentlyContinue
    $actual = if ($log) { [int64]$log.MaximumSizeInBytes } else { 0 }
    Write-Result "Security log size restored" ($actual -eq $priorBytes) `
        ("{0:N0} MB" -f ($actual / 1MB))
} else {
    Write-Kept "Security log size" "No recorded prior size. A larger log is not a problem; shrink it with`n  wevtutil sl Security /ms:<bytes>"
}

# ------------------------------------------------------- 8. shadow storage

$shadowPrior = if ($receipt) { $receipt.prior.shadowstorage } else { $null }
if ($RestoreShadowStorage -and $shadowPrior) {
    Write-Host ""
    Write-Host "  -RestoreShadowStorage: the prior configuration was" -ForegroundColor Yellow
    foreach ($row in ($shadowPrior.raw -split "`n")) { Write-Host "    $row" -ForegroundColor DarkGray }
    Write-Host "  Resize it yourself from that, with vssadmin resize shadowstorage." -ForegroundColor Yellow
    Write-Host "  This script will not shrink it for you: shrinking deletes existing shadow" -ForegroundColor Yellow
    Write-Host "  copies, and some of them will be Windows restore points." -ForegroundColor Yellow
} else {
    Write-Kept "shadow copy storage" `
        ("Shrinking it deletes existing shadow copies, including restore points that`n" +
         "have nothing to do with this project. -RestoreShadowStorage prints what it`n" +
         "was so you can decide.")
}

# ---------------------------------------------------- 9. data directory ACL

if ($receipt -and $receipt.applied.data_dir_locked -and $receipt.prior.data_dir) {
    $dataDir = $receipt.prior.data_dir
    if (Test-Path -LiteralPath $dataDir) {
        & icacls $dataDir /reset /T /C /Q 2>&1 | Out-Null
        & icacls $dataDir /inheritance:e 2>&1 | Out-Null
        Write-Result "data directory permissions restored to inherited" ($LASTEXITCODE -eq 0) $dataDir
    }
}

# -------------------------------------------------------- 10. configuration

if (Test-Path $ConfigPath) {
    Remove-Item $ConfigPath -Force -ErrorAction SilentlyContinue
    Write-Result "agent configuration removed" (-not (Test-Path $ConfigPath)) $ConfigPath
}

if (Test-Path $ReceiptPath) {
    $spent = Join-Path $StateDir ('install-receipt.reverted-{0}.json' -f (Get-Date -Format 'yyyyMMddHHmmss'))
    Move-Item $ReceiptPath $spent -Force -ErrorAction SilentlyContinue
    Write-Host "[ kept ] receipt moved to $spent" -ForegroundColor Cyan
}

# ------------------------------------------------------------ what is kept

Write-Host ""
Write-Host ("=" * 72) -ForegroundColor DarkCyan
Write-Host ""

$ledger = if ($receipt -and $receipt.prior.data_dir) { Join-Path $receipt.prior.data_dir 'ledger.db' } else { Join-Path $RepoRoot 'data\agent\ledger.db' }
Write-Host "  Kept on purpose:" -ForegroundColor White
Write-Host "    $ledger" -ForegroundColor DarkGray
Write-Host "      the hash-chained record of everything the agent did. An uninstaller" -ForegroundColor DarkGray
Write-Host "      does not get to delete an audit trail. Delete it yourself if you want it gone." -ForegroundColor DarkGray
Write-Host "    $StateDir\agent.log" -ForegroundColor DarkGray
Write-Host "    $RepoRoot\.env" -ForegroundColor DarkGray
Write-Host "      the rotated signing keys. Restoring the committed placeholders would be" -ForegroundColor DarkGray
Write-Host "      a downgrade, not a revert." -ForegroundColor DarkGray

Write-Host ""
if ($script:Failures -gt 0) {
    Write-Host "  $($script:Failures) step(s) failed. Read the transcript at $UninstallLog." -ForegroundColor Red
    Stop-Transcript | Out-Null
    if ($Relaunched) { Read-Host "Press Enter to close" | Out-Null }
    exit 1
}
Write-Host "  Uninstalled. Nothing is watching these folders any more." -ForegroundColor Green
Stop-Transcript | Out-Null
if ($Relaunched) { Read-Host "Press Enter to close" | Out-Null }
exit 0

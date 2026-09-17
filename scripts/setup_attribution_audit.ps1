<#
.SYNOPSIS
    Enable the Windows file-system auditing the Monitor needs to name the
    process behind an alert.

.DESCRIPTION
    Windows will not tell an unprivileged process who wrote a file. Event ID
    4663 carries ObjectName, ProcessId and ProcessName for every audited
    access, and this script turns on the two things needed to produce one:

      1. the File System audit subcategory, for Success  (machine-wide)
      2. a SACL granting audit-on-write to the watched directory  (scoped)

    Both require Administrator. Step 2 is deliberately scoped to one directory:
    a machine-wide audit rule floods the Security log and the Monitor's ring
    buffer with writes it will never be asked about.

    Run -Verify on its own to check the current state without changing it, and
    -Revert to undo both steps.

.PARAMETER WatchPath
    The directory the Monitor watches. The SACL is applied here and inherited
    by everything below it.

.PARAMETER LogSizeMB
    Security log size. The default Windows size fills quickly once file
    auditing is on, and a wrapped log silently drops the records attribution
    depends on.

.PARAMETER SaclOnly
    Do step 2 and not step 1: touch the SACL on this one directory and leave
    the machine-wide audit policy exactly as it is.

    This exists because of what -Revert does without it. The subcategory is
    machine-wide and the SACL is per-directory, so reverting the *second* of
    two protected roots turns off auditing for the *first* as well - and the
    agent goes on running, reporting every write as `unknown`, suspending
    nothing, with no error anywhere. That happened on this project's own
    development machine while cleaning up after an acceptance run, and the only
    reason it was caught was a -Verify that had been added on a hunch.

    So: uninstall.ps1 removes each root's SACL with -Revert -SaclOnly, and
    decides about the subcategory once, at the end, from what it recorded
    before it changed anything. -SaclOnly on its own applies a SACL to an
    additional root on a machine where the policy is already on.

.EXAMPLE
    # From an Administrator PowerShell, at the repository root:
    powershell -ExecutionPolicy Bypass -File scripts/setup_attribution_audit.ps1 -WatchPath D:\watched_files

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File scripts/setup_attribution_audit.ps1 -WatchPath D:\watched_files -Verify

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File scripts/setup_attribution_audit.ps1 -WatchPath D:\watched_files -Revert
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$WatchPath,

    [int]$LogSizeMB = 128,

    [switch]$Verify,

    [switch]$Revert,

    [switch]$SaclOnly
)

$ErrorActionPreference = 'Stop'

# The identity the audit rule is written for. Everyone, because the point is to
# see whoever wrote the file, including a process running as a user this script
# has never heard of.
$AuditIdentity = 'Everyone'

function Test-Elevated {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($id)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Every failed check is counted here, and the script exits non-zero if any of
# them fired. It used to print `[ FAIL ]` and exit 0, which meant an installer
# branching on $LASTEXITCODE would configure a machine whose auditing does not
# work and report success - and everything the agent can do rests on auditing
# working. See docs/CORRECTIONS.md correction 7.
$script:Failures = 0

function Write-Result {
    param([string]$Label, [bool]$Ok, [string]$Detail = '')
    $mark = if ($Ok) { '  ok  ' } else { ' FAIL ' }
    $line = "[$mark] $Label"
    if ($Detail) { $line += "  -  $Detail" }
    if ($Ok) {
        Write-Host $line -ForegroundColor Green
    } else {
        $script:Failures++
        Write-Host $line -ForegroundColor Red
    }
}

function Get-AuditPolicyState {
    # auditpol's output is localised; the subcategory GUID is not. This is the
    # File System subcategory.
    $guid = '{0CCE921D-69AE-11D9-BED3-505054503030}'
    $raw = & auditpol /get /subcategory:"$guid" /r 2>$null
    if (-not $raw) { return 'unknown' }
    $row = $raw | ConvertFrom-Csv | Select-Object -First 1
    if (-not $row) { return 'unknown' }
    return $row.'Inclusion Setting'
}

function Get-WriteAuditRule {
    param([string]$Path)
    try {
        $acl = Get-Acl -Path $Path -Audit
    } catch {
        return $null
    }
    return $acl.Audit | Where-Object {
        $_.IdentityReference.Value -like "*$AuditIdentity" -and
        $_.AuditFlags -band [System.Security.AccessControl.AuditFlags]::Success
    } | Select-Object -First 1
}

# --------------------------------------------------------------------- checks

if (-not (Test-Path -LiteralPath $WatchPath -PathType Container)) {
    Write-Host "watch path does not exist or is not a directory: $WatchPath" -ForegroundColor Red
    exit 2
}
$WatchPath = (Resolve-Path -LiteralPath $WatchPath).Path

Write-Host ''
Write-Host 'URDS attribution - Windows file-system auditing' -ForegroundColor Cyan
Write-Host ("watch path: {0}" -f $WatchPath)
Write-Host ''

# ------------------------------------------------------------------- verify

if ($Verify) {
    $policy = Get-AuditPolicyState
    $policyOk = $policy -match 'Success'
    Write-Result 'File System audit subcategory (Success)' $policyOk "auditpol reports: $policy"

    $rule = Get-WriteAuditRule -Path $WatchPath
    Write-Result 'SACL on the watch path' ([bool]$rule) $(if ($rule) { "$($rule.FileSystemRights) for $($rule.IdentityReference)" } else { 'no Success audit rule found' })

    $log = Get-WinEvent -ListLog Security -ErrorAction SilentlyContinue
    if ($log) {
        Write-Result 'Security log readable' $true ("{0:N0} records, max {1:N0} MB" -f $log.RecordCount, ($log.MaximumSizeInBytes / 1MB))
    } else {
        Write-Result 'Security log readable' $false 'not readable - this shell is probably not elevated'
    }

    $recent = Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4663 } -MaxEvents 1 -ErrorAction SilentlyContinue
    Write-Result '4663 events present' ([bool]$recent) $(if ($recent) { "most recent: $($recent.TimeCreated)" } else { 'none yet - write a file under the watch path and re-run' })

    Write-Host ''
    if ($policyOk -and $rule) {
        Write-Host 'Attribution should work. Start the Monitor from an elevated shell and check GET /monitor/attribution.' -ForegroundColor Green
        exit 0
    }
    Write-Host 'Attribution is NOT set up. Re-run this script without -Verify, as Administrator.' -ForegroundColor Yellow
    exit 1
}

# ----------------------------------------------------------- mutating actions

if (-not (Test-Elevated)) {
    Write-Host 'This script must run from an Administrator PowerShell.' -ForegroundColor Red
    Write-Host 'Both the audit policy and the SACL are privileged operations; that is the OS boundary, not a limitation of this project.' -ForegroundColor Yellow
    exit 3
}

if ($Revert) {
    Write-Host 'Reverting.' -ForegroundColor Yellow

    $acl = Get-Acl -Path $WatchPath -Audit
    $removed = 0
    foreach ($rule in @($acl.Audit)) {
        if ($rule.IdentityReference.Value -like "*$AuditIdentity") {
            [void]$acl.RemoveAuditRule($rule)
            $removed++
        }
    }
    Set-Acl -Path $WatchPath -AclObject $acl
    Write-Result 'SACL removed from the watch path' $true "$removed rule(s)"

    if ($SaclOnly) {
        Write-Host '[ skip ] File System audit subcategory - left alone (-SaclOnly)' -ForegroundColor DarkGray
        Write-Host ''
        Write-Host 'This path is no longer audited. Any other protected root still is: the' -ForegroundColor Cyan
        Write-Host 'subcategory is machine-wide and was not touched. See -SaclOnly in the help.' -ForegroundColor Cyan
        exit 0
    }

    & auditpol /set /subcategory:"{0CCE921D-69AE-11D9-BED3-505054503030}" /success:disable | Out-Null
    Write-Result 'File System audit subcategory disabled' $true 'machine-wide'

    Write-Host ''
    Write-Host 'Reverted. The Monitor will report attribution as unavailable and responses will isolate rather than terminate.' -ForegroundColor Cyan
    Write-Host 'That is machine-wide, and it includes every other protected root on this' -ForegroundColor Yellow
    Write-Host 'machine. Use -Revert -SaclOnly if you meant only this one.' -ForegroundColor Yellow
    exit 0
}

# 1. audit policy -------------------------------------------------------------

if ($SaclOnly) {
    # Not skipped silently: an additional root on a machine whose policy is off
    # would get a SACL that produces nothing, and the caller has to know.
    $policy = Get-AuditPolicyState
    Write-Result 'File System audit subcategory (Success)' ($policy -match 'Success') "not changed (-SaclOnly); auditpol reports: $policy"
} else {
    & auditpol /set /subcategory:"{0CCE921D-69AE-11D9-BED3-505054503030}" /success:enable | Out-Null
    $policy = Get-AuditPolicyState
    Write-Result 'File System audit subcategory (Success)' ($policy -match 'Success') "auditpol reports: $policy"
}

# 2. SACL on the watch path ---------------------------------------------------

$acl = Get-Acl -Path $WatchPath -Audit
$rule = New-Object System.Security.AccessControl.FileSystemAuditRule(
    $AuditIdentity,
    # WriteData covers bytes into an existing file; AppendData covers a write
    # past the end; Delete covers removing it. Between them they are what the
    # parser filters 4663 on. Read rights are deliberately not audited: they
    # would multiply the log volume for events attribution never asks about.
    #
    # Delete is not optional. Two of the commonest ransomware shapes never
    # overwrite the original at all - 7z -sdel and a loop around openssl both
    # write somewhere else and unlink - and in both the process that wrote the
    # ciphertext has usually exited by the time the audit record arrives, while
    # the process doing the deleting is the long-lived one running the
    # campaign. Without this right the agent watches files disappear and cannot
    # say who removed them.
    [System.Security.AccessControl.FileSystemRights]'WriteData, AppendData, Delete',
    [System.Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit',
    [System.Security.AccessControl.PropagationFlags]'None',
    [System.Security.AccessControl.AuditFlags]'Success'
)
$acl.AddAuditRule($rule)
Set-Acl -Path $WatchPath -AclObject $acl
Write-Result 'SACL applied to the watch path' $true 'WriteData, AppendData, Delete - inherited by children'

# 3. Security log size --------------------------------------------------------

if ($SaclOnly) {
    Write-Host '[ skip ] Security log size - machine-wide, left alone (-SaclOnly)' -ForegroundColor DarkGray
} else {
    try {
        & wevtutil sl Security /ms:$($LogSizeMB * 1MB)
        Write-Result 'Security log size' $true "$LogSizeMB MB"
    } catch {
        Write-Result 'Security log size' $false $_.Exception.Message
    }
}

# 4. prove it actually produces a record --------------------------------------

$probe = Join-Path $WatchPath ('.urds_attribution_probe_{0}.tmp' -f ([guid]::NewGuid().ToString('N').Substring(0, 8)))
[System.IO.File]::WriteAllBytes($probe, [byte[]](1..64))

# Polled to four seconds, not slept for 800 ms.
#
# scripts/measure_attribution_lag.py measured this channel's delivery at four
# write rates and found it bounded at about 1010 ms and independent of rate - a
# flush timer, not queueing. A single check at 800 ms therefore sat *below* the
# ceiling and would report a correctly configured machine as broken whenever
# the probe write happened to land on the wrong side of a flush. Polling costs
# nothing when the record is early, which is the common case.
$deadline = (Get-Date).AddSeconds(4)
$hit = $null
while (-not $hit -and (Get-Date) -lt $deadline) {
    Start-Sleep -Milliseconds 250
    $hit = Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4663; StartTime = (Get-Date).AddSeconds(-15) } -ErrorAction SilentlyContinue |
        Where-Object { $_.Message -like "*$probe*" } |
        Select-Object -First 1
}

Remove-Item -LiteralPath $probe -Force -ErrorAction SilentlyContinue

if ($hit) {
    $pidField = ($hit.Message -split "`n" | Where-Object { $_ -match 'Process ID:' } | Select-Object -First 1).Trim()
    Write-Result 'End-to-end probe' $true "a write under the watch path produced a 4663 ($pidField)"
} else {
    Write-Result 'End-to-end probe' $false 'the probe write produced no 4663 within 4s - check the Security log is not full, and that the File System subcategory is enabled'
}

Write-Host ''
if ($script:Failures -gt 0) {
    Write-Host "$($script:Failures) check(s) failed. Attribution will not work on this path, so the agent will" -ForegroundColor Red
    Write-Host 'detect and record and suspend nothing: without a kernel-grade source no answer' -ForegroundColor Red
    Write-Host 'reaches CERTAIN, and it does not guess a PID.' -ForegroundColor Red
    exit 1
}

Write-Host 'Done. Start the Monitor from an elevated shell - the subscription needs the same privilege - then:' -ForegroundColor Cyan
Write-Host '    curl http://localhost:8001/monitor/attribution' -ForegroundColor White
Write-Host ''
Write-Host 'Undo with:  -Revert' -ForegroundColor DarkGray
exit 0

<#
.SYNOPSIS
    Enable the Windows file-system auditing the Monitor needs to name the
    process behind an alert - and put the machine back exactly as it was.

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
    -Revert to undo what setup did.

    WHAT IT RECORDS, AND WHY

    Defect 5 of the Windows integration test. Setup used to set the Security
    log to 128 MB unconditionally, and on the test VM that shrank a 1 GiB log
    another installer had configured. -Revert used to disable the File System
    subcategory unconditionally, including when another component had enabled
    it first, and to remove every audit rule for Everyone on the path,
    including rules it had not added.

    Now, before changing anything, setup records the prior state in a state
    file:

      * the Security log's maximum size
      * the File System subcategory's Success and Failure settings
      * for each watch path, which of the rights this script audits were
        already audited there, and which ones setup added

    The log size is only ever raised. -Revert restores exactly what was
    recorded: it removes only the audit rights setup added, and it restores
    the Success setting and the log size only where setup changed them. The
    two machine-wide settings are restored only when the last watch path this
    script set up is reverted, because they serve every path; fix/evidence-
    integrity found the hard way that reverting one root turned auditing off
    for all the others. A log size that something else has changed since
    setup is left alone. With no state file, -Revert changes nothing: it
    cannot know what to restore, and guessing is what this replaced. -Verify
    prints the recorded prior state beside the current one.

.PARAMETER WatchPath
    The directory the Monitor watches. The SACL is applied here and inherited
    by everything below it.

.PARAMETER LogSizeMB
    The Security log size to ensure. The default Windows size fills quickly
    once file auditing is on, and a wrapped log silently drops the records
    attribution depends on. A log that is already this size or larger is left
    as it is: this script only ever raises it.

.PARAMETER StatePath
    Where the prior state is recorded. Defaults to
    %ProgramData%\URDS\attribution_audit_state.json - outside the repository,
    so a fresh checkout or a clean does not lose the only record of what to
    restore.

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

    [string]$StatePath = (Join-Path $env:ProgramData 'URDS\attribution_audit_state.json')
)

# The File System audit subcategory. auditpol's output is localised; the GUID
# is not.
$FileSystemSubcategory = '{0CCE921D-69AE-11D9-BED3-505054503030}'

# The identity the audit rule is written for. Everyone, because the point is to
# see whoever wrote the file, including a process running as a user this script
# has never heard of. Held as a SID: the account *name* is localised, and a rule
# matched by name would go unrecognised on a machine that is not in English.
$EveryoneSid = New-Object System.Security.Principal.SecurityIdentifier('S-1-1-0')

# WriteData covers bytes into an existing file; AppendData covers a write past
# the end. Between them they are what the parser filters 4663 on. Read rights
# are deliberately not audited: they would multiply the log volume for events
# attribution never asks about.
$AuditRights = [System.Security.AccessControl.FileSystemRights]'WriteData, AppendData'
$AuditInheritance = [System.Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
$AuditPropagation = [System.Security.AccessControl.PropagationFlags]'None'

$StateSchema = 1

# Every failed check is counted here, and a run that had any exits non-zero.
# Ported from fix/evidence-integrity: this used to print `[ FAIL ]` and exit 0,
# so an installer branching on $LASTEXITCODE would report success on a machine
# whose auditing does not work.
$script:Failures = 0

function Test-Elevated {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($id)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

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

function Write-Skip {
    param([string]$Label, [string]$Detail = '')
    $line = "[ skip ] $Label"
    if ($Detail) { $line += "  -  $Detail" }
    Write-Host $line -ForegroundColor DarkGray
}

function Format-Rights {
    # Named here rather than by the enum, whose ToString picks CreateFiles and
    # CreateDirectories for these two bits - the same values, the directory names.
    param([int]$Mask)
    $names = @()
    if ($Mask -band [int][System.Security.AccessControl.FileSystemRights]::WriteData) { $names += 'WriteData' }
    if ($Mask -band [int][System.Security.AccessControl.FileSystemRights]::AppendData) { $names += 'AppendData' }
    if ($names.Count -eq 0) { return 'none' }
    return ($names -join ', ')
}

function Format-MB {
    param($Bytes)
    if ($null -eq $Bytes) { return 'unknown' }
    return ('{0:N0} MB' -f ([double]$Bytes / 1MB))
}

# ------------------------------------------------ the machine, through wrappers
#
# Everything that reads or changes the machine goes through one of these, and
# every native command through Invoke-Native, so the Pester tests
# (scripts/tests/setup_attribution_audit.Tests.ps1) can replace all of it and
# run with nothing real reachable.

function Invoke-Native {
    # Windows PowerShell turns a native command's redirected stderr into
    # terminating errors under -ErrorAction Stop; the exit code is the answer
    # wanted here, so this scope does not stop.
    param([string]$Command, [string[]]$Arguments)
    $ErrorActionPreference = 'Continue'
    $output = & $Command @Arguments 2>$null
    return [pscustomobject]@{ Output = @($output); ExitCode = $LASTEXITCODE }
}

function ConvertFrom-InclusionSetting {
    # auditpol's English values. Anything else - a localised build - is $null,
    # and setup refuses to change what it could not read back.
    param([string]$Setting)
    $text = "$Setting".Trim()
    if ($text -eq 'Success and Failure') { return @{ Success = $true; Failure = $true } }
    if ($text -eq 'Success') { return @{ Success = $true; Failure = $false } }
    if ($text -eq 'Failure') { return @{ Success = $false; Failure = $true } }
    if ($text -eq 'No Auditing') { return @{ Success = $false; Failure = $false } }
    return $null
}

function Get-AuditPolicyState {
    # The File System subcategory's Success and Failure settings, or $null when
    # auditpol's answer cannot be read.
    $result = Invoke-Native 'auditpol' @('/get', "/subcategory:$FileSystemSubcategory", '/r')
    $lines = @($result.Output | Where-Object { "$_".Trim() })
    if ($result.ExitCode -ne 0 -or $lines.Count -lt 2) { return $null }
    $row = $lines | ConvertFrom-Csv | Select-Object -First 1
    if (-not $row) { return $null }
    $setting = $row.'Inclusion Setting'
    $flags = ConvertFrom-InclusionSetting $setting
    if (-not $flags) { return $null }
    return [pscustomobject]@{ Success = $flags.Success; Failure = $flags.Failure; Setting = "$setting" }
}

function Set-FileSystemAuditSuccess {
    # Success only. Failure is never touched: setup does not change it, so
    # -Revert has nothing to restore there.
    param([bool]$Enabled)
    $value = if ($Enabled) { 'enable' } else { 'disable' }
    $result = Invoke-Native 'auditpol' @('/set', "/subcategory:$FileSystemSubcategory", "/success:$value")
    return ($result.ExitCode -eq 0)
}

function Get-SecurityLogMaxBytes {
    try {
        return [long](Get-WinEvent -ListLog Security -ErrorAction Stop).MaximumSizeInBytes
    } catch {
        return $null
    }
}

function Set-SecurityLogMaxBytes {
    param([long]$Bytes)
    $result = Invoke-Native 'wevtutil' @('sl', 'Security', "/ms:$Bytes")
    return ($result.ExitCode -eq 0)
}

function Get-SecurityLogStatus {
    try {
        return Get-WinEvent -ListLog Security -ErrorAction Stop
    } catch {
        return $null
    }
}

function Get-LatestAuditRecord {
    return Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4663 } -MaxEvents 1 -ErrorAction SilentlyContinue
}

function Get-WatchPathSecurity {
    param([string]$Path)
    return Get-Acl -LiteralPath $Path -Audit
}

function Set-WatchPathSecurity {
    param([string]$Path, $Acl)
    Set-Acl -LiteralPath $Path -AclObject $Acl
}

function Invoke-AuditProbe {
    # A real write under the watch path, and a real 4663 for it, so a green run
    # means the pipeline works rather than that three commands returned zero.
    # Returns the record's Process ID line, or $null when none arrived.
    #
    # Polled to four seconds, not slept for 800 ms. Ported from
    # fix/evidence-integrity, whose measurement found this channel's delivery
    # bounded at about 1010 ms and independent of write rate - a flush timer -
    # and the Windows integration VM measured 390-1032 ms over 35 writes. A
    # single look at 800 ms sat below that ceiling and would report a correctly
    # configured machine as broken whenever the probe landed on the wrong side
    # of a flush. Matched on the probe's unique name, not its full path, so the
    # case the kernel reports the directory in does not matter.
    param([string]$WatchPath)
    $name = '.urds_attribution_probe_{0}.tmp' -f ([guid]::NewGuid().ToString('N').Substring(0, 8))
    $probe = Join-Path $WatchPath $name
    [System.IO.File]::WriteAllBytes($probe, [byte[]](1..64))
    $hit = $null
    try {
        $deadline = (Get-Date).AddSeconds(4)
        while (-not $hit -and (Get-Date) -lt $deadline) {
            Start-Sleep -Milliseconds 250
            $hit = Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4663; StartTime = (Get-Date).AddSeconds(-15) } -ErrorAction SilentlyContinue |
                Where-Object { $_.Message -and $_.Message.IndexOf($name, [StringComparison]::OrdinalIgnoreCase) -ge 0 } |
                Select-Object -First 1
        }
    } finally {
        Remove-Item -LiteralPath $probe -Force -ErrorAction SilentlyContinue
    }
    if (-not $hit) { return $null }
    $line = $hit.Message -split "`n" | Where-Object { $_ -match 'Process ID:' } | Select-Object -First 1
    if ($line) { return $line.Trim() }
    return 'a 4663 for the probe'
}

# ------------------------------------------------------------- the audit rules

function New-WriteAuditRule {
    param([int]$Mask)
    return New-Object System.Security.AccessControl.FileSystemAuditRule(
        $EveryoneSid,
        [System.Security.AccessControl.FileSystemRights]$Mask,
        $AuditInheritance,
        $AuditPropagation,
        [System.Security.AccessControl.AuditFlags]::Success
    )
}

function Get-AuditedWriteRights {
    # Which of the audited rights an explicit rule on this directory already
    # covers: Success rules for Everyone, inherited by what is below the
    # directory the same way this script's rule is. Returned as a mask.
    # Inherited rules are not counted - -Revert must never be asked to remove
    # something set on a parent.
    param($Acl)
    $mask = 0
    foreach ($rule in $Acl.GetAuditRules($true, $false, [System.Security.Principal.SecurityIdentifier])) {
        if ($rule.IdentityReference.Value -ne $EveryoneSid.Value) { continue }
        if (-not ($rule.AuditFlags -band [System.Security.AccessControl.AuditFlags]::Success)) { continue }
        if ($rule.InheritanceFlags -ne $AuditInheritance -or $rule.PropagationFlags -ne $AuditPropagation) { continue }
        $mask = $mask -bor ([int]$rule.FileSystemRights -band [int]$AuditRights)
    }
    return $mask
}

function Test-WriteAuditEffective {
    # For -Verify: are both rights audited for Everyone, on files below the
    # path, by any Success rule - explicit or inherited from a parent?
    param($Acl)
    $mask = 0
    foreach ($rule in $Acl.GetAuditRules($true, $true, [System.Security.Principal.SecurityIdentifier])) {
        if ($rule.IdentityReference.Value -ne $EveryoneSid.Value) { continue }
        if (-not ($rule.AuditFlags -band [System.Security.AccessControl.AuditFlags]::Success)) { continue }
        if (-not ($rule.InheritanceFlags -band [System.Security.AccessControl.InheritanceFlags]::ObjectInherit)) { continue }
        $mask = $mask -bor ([int]$rule.FileSystemRights -band [int]$AuditRights)
    }
    return ($mask -eq [int]$AuditRights)
}

function Add-WriteAudit {
    param($Acl, [int]$Mask)
    if ($Mask -ne 0) { $Acl.AddAuditRule((New-WriteAuditRule $Mask)) }
    return $Acl
}

function Remove-WriteAudit {
    # Removes exactly `$Mask` from Everyone's Success rules of this script's
    # inheritance shape. RemoveAuditRule trims those bits from a matching rule
    # and keeps its others, so a rule someone else wrote with more rights than
    # these keeps the rest - and setup only ever records as added the bits that
    # were not already there.
    param($Acl, [int]$Mask)
    if ($Mask -eq 0) { return $false }
    return $Acl.RemoveAuditRule((New-WriteAuditRule $Mask))
}

# ------------------------------------------------------------- the state file

function Read-AuditState {
    # $null when there is no state file. Throws when there is one that cannot be
    # read: it is the only record of what to restore, and a run that replaced it
    # would lose that.
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $null }
    $state = Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-Json
    if (-not $state -or $state.schema -ne $StateSchema -or -not $state.machine) {
        throw "unrecognised state file: $Path"
    }
    return $state
}

function Write-AuditState {
    param([string]$Path, $State)
    $directory = Split-Path -Parent $Path
    if ($directory -and -not (Test-Path -LiteralPath $directory)) {
        New-Item -ItemType Directory -Path $directory | Out-Null
    }
    $json = ConvertTo-Json -InputObject $State -Depth 6
    [System.IO.File]::WriteAllText($Path, $json, (New-Object System.Text.UTF8Encoding($false)))
}

function Get-StatePaths {
    param($State)
    return @($State.paths | Where-Object { $null -ne $_ })
}

function Get-StatePathKey {
    # How a watch path is recorded and looked up: resolved, no trailing
    # separator (except a drive root). Compared case-insensitively, as NTFS does.
    param([string]$Path)
    $trimmed = $Path.TrimEnd('\', '/')
    if ($trimmed -match '^[A-Za-z]:$') { return $trimmed + '\' }
    return $trimmed
}

function Write-ManualRevertSteps {
    param([string]$WatchPath)
    Write-Host ''
    Write-Host 'Without a record this script cannot tell what it changed from what was already' -ForegroundColor Yellow
    Write-Host 'there, so it has changed nothing. To inspect and undo by hand:' -ForegroundColor Yellow
    Write-Host ("    auditpol /get /subcategory:""{0}""" -f $FileSystemSubcategory)
    Write-Host ("    auditpol /set /subcategory:""{0}"" /success:disable   - only if nothing else here needs it" -f $FileSystemSubcategory)
    Write-Host '    wevtutil gl Security                                   - maxSize is the log size'
    Write-Host ("    (Get-Acl -LiteralPath '{0}' -Audit).Audit              - remove only a rule you know was added" -f $WatchPath)
}

# ---------------------------------------------------------------------- verify

function Invoke-Verify {
    param([string]$WatchPath, [string]$StatePath)
    $script:Failures = 0

    $policy = Get-AuditPolicyState
    $policyOk = [bool]($policy -and $policy.Success)
    Write-Result 'File System audit subcategory (Success)' $policyOk $(if ($policy) { "auditpol reports: $($policy.Setting)" } else { 'auditpol could not be read - this shell is probably not elevated' })

    $acl = $null
    try { $acl = Get-WatchPathSecurity -Path $WatchPath } catch { $acl = $null }
    $ruleOk = [bool]($acl -and (Test-WriteAuditEffective -Acl $acl))
    Write-Result 'SACL on the watch path' $ruleOk $(if ($ruleOk) { 'WriteData, AppendData audited for Everyone' } elseif ($acl) { 'no Success audit rule for Everyone covering WriteData and AppendData' } else { 'SACL not readable - this shell is probably not elevated' })

    $log = Get-SecurityLogStatus
    if ($log) {
        Write-Result 'Security log readable' $true ("{0:N0} records, max {1}" -f $log.RecordCount, (Format-MB $log.MaximumSizeInBytes))
    } else {
        Write-Result 'Security log readable' $false 'not readable - this shell is probably not elevated'
    }

    $recent = Get-LatestAuditRecord
    Write-Result '4663 events present' ([bool]$recent) $(if ($recent) { "most recent: $($recent.TimeCreated)" } else { 'none yet - write a file under the watch path and re-run' })

    # What setup found before it changed anything - the values -Revert will put back.
    $state = $null
    $stateError = $null
    try { $state = Read-AuditState -Path $StatePath } catch { $stateError = $_.Exception.Message }
    if ($stateError) {
        Write-Result 'Recorded prior state' $false $stateError
    } elseif (-not $state) {
        Write-Result 'Recorded prior state' $true "none at $StatePath - this script has changed nothing here, or all of it has been reverted"
    } else {
        $machine = $state.machine
        Write-Result 'Recorded prior state' $true ("{0}, recorded {1}" -f $StatePath, $machine.recorded_at)
        $setBy = if ($null -ne $machine.security_log_max_bytes_set) { "raised by setup to $(Format-MB $machine.security_log_max_bytes_set)" } else { 'not changed by setup' }
        Write-Host ("           Security log size before setup:      {0} ({1})" -f (Format-MB $machine.security_log_max_bytes_before), $setBy)
        $enabledBy = if ($machine.audit_success_enabled_by_setup) { 'Success enabled by setup' } else { 'not changed by setup' }
        Write-Host ("           File System audit before setup:      {0} ({1})" -f $machine.audit_setting_before, $enabledBy)
        foreach ($entry in @(Get-StatePaths $state)) {
            Write-Host ("           {0}: audited before setup: {1}; added by setup: {2}" -f $entry.path, $entry.audited_before, $entry.added)
        }
    }

    Write-Host ''
    if ($policyOk -and $ruleOk) {
        Write-Host 'Attribution should work. Start the Monitor from an elevated shell and check GET /monitor/attribution.' -ForegroundColor Green
        return 0
    }
    Write-Host 'Attribution is NOT set up. Re-run this script without -Verify, as Administrator.' -ForegroundColor Yellow
    return 1
}

# ----------------------------------------------------------------------- setup

function Invoke-Setup {
    param([string]$WatchPath, [int]$LogSizeMB, [string]$StatePath)
    $script:Failures = 0
    $target = [long]$LogSizeMB * 1MB
    $key = Get-StatePathKey $WatchPath

    # 0. an earlier run's record, which is kept, never replaced
    try {
        $state = Read-AuditState -Path $StatePath
    } catch {
        Write-Result 'Recorded prior state' $false "$($_.Exception.Message) - nothing changed; it is the only record of what to restore"
        return 1
    }

    # 1. read everything this run could change, before changing any of it
    $policy = Get-AuditPolicyState
    $logBytes = Get-SecurityLogMaxBytes
    $acl = $null
    try { $acl = Get-WatchPathSecurity -Path $WatchPath } catch { $acl = $null }
    $unreadable = @()
    if (-not $policy) { $unreadable += 'the File System audit setting (auditpol)' }
    if ($null -eq $logBytes) { $unreadable += 'the Security log size' }
    if (-not $acl) { $unreadable += 'the SACL on the watch path' }
    if ($unreadable.Count -gt 0) {
        Write-Result 'Prior state read' $false ("could not read {0} - nothing changed, because it could not be put back" -f ($unreadable -join ', '))
        return 1
    }

    $auditedBefore = Get-AuditedWriteRights -Acl $acl
    $toAdd = [int]$AuditRights -band (-bnot $auditedBefore)
    $enableSuccess = -not $policy.Success
    $raiseLog = [long]$logBytes -lt $target

    # 2. record it, and what this run is about to change, before changing it.
    # -Revert restores recorded *values*, so a change recorded here that then
    # fails is undone as a no-op, not as damage.
    $now = (Get-Date).ToUniversalTime().ToString('o')
    if (-not $state) {
        $state = [pscustomobject]@{
            schema  = $StateSchema
            what    = 'setup_attribution_audit.ps1: this machine as it was before the script changed it. -Revert reads this.'
            machine = [pscustomobject]@{
                recorded_at                    = $now
                security_log_max_bytes_before  = [long]$logBytes
                security_log_max_bytes_set     = $null
                audit_setting_before           = $policy.Setting
                audit_success_before           = [bool]$policy.Success
                audit_failure_before           = [bool]$policy.Failure
                audit_success_enabled_by_setup = $false
            }
            paths   = @()
        }
    }
    $paths = @(Get-StatePaths $state)
    $entry = $paths | Where-Object { $_.path -eq $key } | Select-Object -First 1
    if (-not $entry) {
        $entry = [pscustomobject]@{
            path                = $key
            recorded_at         = $now
            audited_before_mask = [int]$auditedBefore
            audited_before      = Format-Rights $auditedBefore
            added_mask          = 0
            added               = 'none'
        }
        $paths = @($paths) + $entry
    }
    $entry.added_mask = [int]$entry.added_mask -bor $toAdd
    $entry.added = Format-Rights $entry.added_mask
    $state.paths = @($paths)
    if ($enableSuccess) { $state.machine.audit_success_enabled_by_setup = $true }
    if ($raiseLog) { $state.machine.security_log_max_bytes_set = $target }
    try {
        Write-AuditState -Path $StatePath -State $state
    } catch {
        Write-Result 'Prior state recorded' $false "$($_.Exception.Message) - nothing changed"
        return 1
    }
    Write-Result 'Prior state recorded' $true $StatePath

    # 3. the File System subcategory, Success
    if ($enableSuccess) {
        $ok = Set-FileSystemAuditSuccess -Enabled $true
        $after = Get-AuditPolicyState
        Write-Result 'File System audit subcategory (Success)' ([bool]($ok -and $after -and $after.Success)) ("enabled; it was: {0}" -f $policy.Setting)
    } else {
        Write-Result 'File System audit subcategory (Success)' $true ("already on ({0}); not changed" -f $policy.Setting)
    }

    # 4. the SACL on the watch path: only the rights not already audited
    if ($toAdd -ne 0) {
        try {
            $acl = Add-WriteAudit -Acl $acl -Mask $toAdd
            Set-WatchPathSecurity -Path $WatchPath -Acl $acl
            $already = if ($auditedBefore) { "; $(Format-Rights $auditedBefore) was already audited" } else { '' }
            Write-Result 'SACL applied to the watch path' $true ("added {0} for Everyone, inherited by children{1}" -f (Format-Rights $toAdd), $already)
        } catch {
            Write-Result 'SACL applied to the watch path' $false $_.Exception.Message
        }
    } else {
        Write-Result 'SACL applied to the watch path' $true 'WriteData, AppendData already audited for Everyone; not changed'
    }

    # 5. the Security log size: raised, never lowered
    if ($raiseLog) {
        $ok = Set-SecurityLogMaxBytes -Bytes $target
        Write-Result 'Security log size' $ok ("raised from {0} to {1}" -f (Format-MB $logBytes), (Format-MB $target))
    } else {
        Write-Result 'Security log size' $true ("{0}, not below the {1} asked for; not changed - this script only ever raises it" -f (Format-MB $logBytes), (Format-MB $target))
    }

    # 6. prove it produces a record
    $hit = Invoke-AuditProbe -WatchPath $WatchPath
    if ($hit) {
        Write-Result 'End-to-end probe' $true "a write under the watch path produced a 4663 ($hit)"
    } else {
        Write-Result 'End-to-end probe' $false 'the probe write produced no 4663 within 4s - check the Security log is not full, and that the File System subcategory is enabled'
    }

    Write-Host ''
    if ($script:Failures -gt 0) {
        Write-Host "$($script:Failures) check(s) failed. Attribution will not work on this path: without a kernel-grade" -ForegroundColor Red
        Write-Host 'source no answer reaches CERTAIN, and responses will isolate rather than terminate.' -ForegroundColor Red
        Write-Host "What was changed is recorded in $StatePath, so -Revert still restores it." -ForegroundColor Red
        return 1
    }
    Write-Host 'Done. Start the Monitor from an elevated shell - the subscription needs the same privilege - then:' -ForegroundColor Cyan
    Write-Host '    curl http://localhost:8001/monitor/attribution' -ForegroundColor White
    Write-Host ''
    Write-Host 'Undo with:  -Revert' -ForegroundColor DarkGray
    return 0
}

# ---------------------------------------------------------------------- revert

function Invoke-Revert {
    param([string]$WatchPath, [string]$StatePath)
    $script:Failures = 0
    $key = Get-StatePathKey $WatchPath

    try {
        $state = Read-AuditState -Path $StatePath
    } catch {
        Write-Result 'Recorded prior state' $false "$($_.Exception.Message) - nothing changed"
        return 1
    }
    if (-not $state) {
        Write-Result 'Recorded prior state' $false "no state file at $StatePath - nothing changed"
        Write-ManualRevertSteps -WatchPath $WatchPath
        return 1
    }

    $paths = @(Get-StatePaths $state)
    $entry = $paths | Where-Object { $_.path -eq $key } | Select-Object -First 1
    if (-not $entry -and $paths.Count -gt 0) {
        $recorded = ($paths | ForEach-Object { $_.path }) -join '; '
        Write-Result 'Recorded prior state' $false "this path was not set up by this script (recorded: $recorded) - nothing changed"
        Write-ManualRevertSteps -WatchPath $WatchPath
        return 1
    }
    Write-Result 'Recorded prior state' $true ("{0}, recorded {1}" -f $StatePath, $state.machine.recorded_at)

    # 1. this path's SACL: only the rights setup added
    if ($entry) {
        $mask = [int]$entry.added_mask
        if ($mask -ne 0) {
            try {
                $acl = Get-WatchPathSecurity -Path $WatchPath
                [void](Remove-WriteAudit -Acl $acl -Mask $mask)
                Set-WatchPathSecurity -Path $WatchPath -Acl $acl
                Write-Result 'SACL restored on the watch path' $true ("removed {0}, which setup added; every other audit rule left as it was" -f (Format-Rights $mask))
            } catch {
                # The record stays: it is still needed to finish the job.
                Write-Result 'SACL restored on the watch path' $false $_.Exception.Message
                return 1
            }
        } else {
            Write-Result 'SACL restored on the watch path' $true ("setup added nothing here ({0} was already audited); not changed" -f $entry.audited_before)
        }
        $paths = @($paths | Where-Object { $_.path -ne $key })
        $state.paths = $paths
        Write-AuditState -Path $StatePath -State $state
    }

    # 2. the machine-wide settings serve every path this script set up
    if ($paths.Count -gt 0) {
        $others = ($paths | ForEach-Object { $_.path }) -join '; '
        Write-Skip 'File System audit subcategory and Security log size' ("machine-wide, and still needed by {0} other watch path(s) set up by this script: {1}" -f $paths.Count, $others)
        Write-Host ''
        Write-Host 'This path is no longer audited. The others still are; revert them the same way.' -ForegroundColor Cyan
        return $(if ($script:Failures -gt 0) { 1 } else { 0 })
    }

    $machine = $state.machine
    if ($machine.audit_success_enabled_by_setup -and -not $machine.audit_success_before) {
        $ok = Set-FileSystemAuditSuccess -Enabled $false
        $after = Get-AuditPolicyState
        Write-Result 'File System audit subcategory (Success)' ([bool]($ok -and $after -and -not $after.Success)) ("restored to off, as recorded before setup ({0}); Failure not touched" -f $machine.audit_setting_before)
    } else {
        Write-Result 'File System audit subcategory (Success)' $true ("left as it was before setup ({0})" -f $machine.audit_setting_before)
    }

    if ($null -ne $machine.security_log_max_bytes_set) {
        $current = Get-SecurityLogMaxBytes
        if ($null -eq $current) {
            Write-Result 'Security log size' $false 'could not be read; not changed'
        } elseif ([long]$current -eq [long]$machine.security_log_max_bytes_set) {
            $ok = Set-SecurityLogMaxBytes -Bytes ([long]$machine.security_log_max_bytes_before)
            $detail = if ($ok) { "restored to {0}, as recorded before setup" -f (Format-MB $machine.security_log_max_bytes_before) } else { "Windows would not lower it to {0}; it will not while the log holds more than that, and this script never clears the Security log" -f (Format-MB $machine.security_log_max_bytes_before) }
            Write-Result 'Security log size' $ok $detail
        } else {
            Write-Skip 'Security log size' ("{0} now, not the {1} setup set - changed since by something else, so left alone (it was {2} before setup)" -f (Format-MB $current), (Format-MB $machine.security_log_max_bytes_set), (Format-MB $machine.security_log_max_bytes_before))
        }
    } else {
        Write-Result 'Security log size' $true ("not changed by setup (it was {0}); left alone" -f (Format-MB $machine.security_log_max_bytes_before))
    }

    Write-Host ''
    if ($script:Failures -gt 0) {
        Write-Host "The record is kept in $StatePath; run -Revert again to finish." -ForegroundColor Red
        return 1
    }
    Remove-Item -LiteralPath $StatePath -Force
    Write-Host 'Reverted to the recorded state. The Monitor will report attribution as unavailable on this path and' -ForegroundColor Cyan
    Write-Host 'responses will isolate rather than terminate.' -ForegroundColor Cyan
    return 0
}

# ------------------------------------------------------------------------ main

# Dot-sourced - the Pester tests do this to reach the functions - so stop here,
# before anything reads or changes the machine.
if ($MyInvocation.InvocationName -eq '.') { return }

$ErrorActionPreference = 'Stop'

if (-not (Test-Path -LiteralPath $WatchPath -PathType Container)) {
    Write-Host "watch path does not exist or is not a directory: $WatchPath" -ForegroundColor Red
    exit 2
}
$WatchPath = (Resolve-Path -LiteralPath $WatchPath).Path

Write-Host ''
Write-Host 'URDS attribution - Windows file-system auditing' -ForegroundColor Cyan
Write-Host ("watch path: {0}" -f $WatchPath)
Write-Host ("state file: {0}" -f $StatePath)
Write-Host ''

if ($Verify) {
    exit ([int](Invoke-Verify -WatchPath $WatchPath -StatePath $StatePath | Select-Object -Last 1))
}

if (-not (Test-Elevated)) {
    Write-Host 'This script must run from an Administrator PowerShell.' -ForegroundColor Red
    Write-Host 'Both the audit policy and the SACL are privileged operations; that is the OS boundary, not a limitation of this project.' -ForegroundColor Yellow
    exit 3
}

if ($Revert) {
    Write-Host 'Reverting to the recorded state.' -ForegroundColor Yellow
    exit ([int](Invoke-Revert -WatchPath $WatchPath -StatePath $StatePath | Select-Object -Last 1))
}

exit ([int](Invoke-Setup -WatchPath $WatchPath -LogSizeMB $LogSizeMB -StatePath $StatePath | Select-Object -Last 1))

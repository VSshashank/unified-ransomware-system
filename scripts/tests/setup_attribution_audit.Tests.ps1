# Pester 3.4 - the version Windows 10 and 11 ship with. From the repository root:
#
#   powershell -ExecutionPolicy Bypass -Command "Invoke-Pester scripts/tests"
#
# Defect 5 of the Windows integration test: setup shrank a 1 GiB Security log
# to 128 MB, and -Revert disabled an audit subcategory another component had
# enabled. These tests hold the script to recording the prior state before it
# changes anything, only ever raising the log, and restoring exactly what it
# recorded.
#
# Nothing here touches the machine. Every read or change goes through one of
# the script's wrapper functions and each is mocked against `$fake`, an
# in-memory machine. Invoke-Native - the only way the script runs a native
# command - and the cmdlets that could reach the real log or ACL are mocked to
# throw, so a wrapper this file forgot to mock fails the test instead of
# reaching auditpol, wevtutil or Set-Acl. The SACL is an in-memory
# DirectorySecurity object, which needs no privilege to edit.
#
# What these do NOT cover: auditpol's and Get-WinEvent's real output, and a
# real SACL write. Those need an elevated Windows host - the maintainer's
# re-check list in FIXES.md, defect 5.

$scriptPath = Join-Path $PSScriptRoot '..\setup_attribution_audit.ps1'
. $scriptPath -WatchPath $env:TEMP   # defines the functions; the script's guard stops before its main body

$WriteData = [int][System.Security.AccessControl.FileSystemRights]::WriteData
$AppendData = [int][System.Security.AccessControl.FileSystemRights]::AppendData
$Admins = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')

function New-TestAcl {
    # Explicit Success audit rules for Everyone, one per mask given.
    param([int[]]$EveryoneMasks = @(), [switch]$WithOtherIdentity)
    $acl = New-Object System.Security.AccessControl.DirectorySecurity
    foreach ($mask in $EveryoneMasks) { $acl.AddAuditRule((New-WriteAuditRule $mask)) }
    if ($WithOtherIdentity) {
        $acl.AddAuditRule((New-Object System.Security.AccessControl.FileSystemAuditRule(
            $Admins, [System.Security.AccessControl.FileSystemRights]::Delete,
            $AuditInheritance, $AuditPropagation, [System.Security.AccessControl.AuditFlags]::Success)))
    }
    return $acl
}

function Get-EveryoneMask {
    param($Acl)
    $mask = 0
    foreach ($rule in $Acl.GetAuditRules($true, $false, [System.Security.Principal.SecurityIdentifier])) {
        if ($rule.IdentityReference.Value -eq 'S-1-1-0') { $mask = $mask -bor [int]$rule.FileSystemRights }
    }
    return $mask
}

function Get-OtherIdentityRules {
    param($Acl)
    return @($Acl.GetAuditRules($true, $false, [System.Security.Principal.SecurityIdentifier]) |
        Where-Object { $_.IdentityReference.Value -eq $Admins.Value })
}

Describe 'setup_attribution_audit.ps1' {
    $fake = @{}

    # Guards: anything real that is reached is a failed test, not a changed machine.
    Mock Invoke-Native { throw "a real native command was reached: $Command $($Arguments -join ' ')" }
    Mock Get-WinEvent { throw 'the real event log was reached' }
    Mock Get-Acl { throw 'a real ACL was read' }
    Mock Set-Acl { throw 'a real ACL was written' }

    # The machine, as the script sees it.
    Mock Test-Elevated { $true }
    Mock Get-AuditPolicyState {
        if ($fake.Unreadable -contains 'policy') { return $null }
        $setting = if ($fake.Success -and $fake.Failure) { 'Success and Failure' } elseif ($fake.Success) { 'Success' } elseif ($fake.Failure) { 'Failure' } else { 'No Auditing' }
        [pscustomobject]@{ Success = $fake.Success; Failure = $fake.Failure; Setting = $setting }
    }
    Mock Set-FileSystemAuditSuccess {
        $fake.StateExistedAtChange += (Test-Path -LiteralPath $fake.StatePath)
        $fake.Success = $Enabled
        $fake.Calls += "audit-success:$Enabled"
        $true
    }
    Mock Get-SecurityLogMaxBytes {
        if ($fake.Unreadable -contains 'log') { return $null }
        $fake.LogBytes
    }
    Mock Set-SecurityLogMaxBytes {
        $fake.StateExistedAtChange += (Test-Path -LiteralPath $fake.StatePath)
        $fake.LogBytes = $Bytes
        $fake.Calls += "log:$Bytes"
        $true
    }
    Mock Get-SecurityLogStatus { [pscustomobject]@{ RecordCount = 10; MaximumSizeInBytes = $fake.LogBytes } }
    Mock Get-LatestAuditRecord { [pscustomobject]@{ TimeCreated = Get-Date } }
    Mock Get-WatchPathSecurity {
        if ($fake.Unreadable -contains 'sacl') { throw 'SACL not readable' }
        $fake.Acls[$Path.TrimEnd('\')]
    }
    Mock Set-WatchPathSecurity {
        $fake.StateExistedAtChange += (Test-Path -LiteralPath $fake.StatePath)
        $fake.Acls[$Path.TrimEnd('\')] = $Acl
        $fake.Calls += "sacl:$Path"
    }
    Mock Invoke-AuditProbe { if ($fake.ProbeFails) { $null } else { 'Process ID: 0x1a2b' } }

    $pathA = 'C:\watched_files'
    $pathB = 'D:\more_watched'

    BeforeEach {
        $fake.Clear()
        $fake.Success = $false
        $fake.Failure = $false
        $fake.LogBytes = [long]20MB
        $fake.Acls = @{ $pathA = (New-TestAcl); $pathB = (New-TestAcl) }
        $fake.Calls = @()
        $fake.StateExistedAtChange = @()
        $fake.Unreadable = @()
        $fake.ProbeFails = $false
        $fake.Lines = New-Object System.Collections.ArrayList
        $fake.StatePath = Join-Path $TestDrive 'state.json'
        Remove-Item -LiteralPath $fake.StatePath -Force -ErrorAction SilentlyContinue
    }

    function Invoke-TestSetup([string]$Path = $pathA, [int]$LogSizeMB = 128) {
        Invoke-Setup -WatchPath $Path -LogSizeMB $LogSizeMB -StatePath $fake.StatePath | Select-Object -Last 1
    }
    function Invoke-TestRevert([string]$Path = $pathA) {
        Invoke-Revert -WatchPath $Path -StatePath $fake.StatePath | Select-Object -Last 1
    }
    function Read-TestState { Get-Content -LiteralPath $fake.StatePath -Raw | ConvertFrom-Json }

    Context 'recording the prior state' {
        It 'records the log size, the audit setting and the SACL before changing any of them' {
            $fake.Failure = $true
            $fake.Acls[$pathA] = New-TestAcl -EveryoneMasks $WriteData

            Invoke-TestSetup | Should Be 0

            $fake.StateExistedAtChange.Count | Should Be 3   # audit, SACL, log - each after the record
            ($fake.StateExistedAtChange -contains $false) | Should Be $false
            $state = Read-TestState
            $state.machine.security_log_max_bytes_before | Should Be ([long]20MB)
            $state.machine.audit_setting_before | Should Be 'Failure'
            $state.machine.audit_success_before | Should Be $false
            $state.machine.audit_failure_before | Should Be $true
            $state.paths[0].path | Should Be $pathA
            $state.paths[0].audited_before | Should Be 'WriteData'
            $state.paths[0].added | Should Be 'AppendData'
        }

        It 'changes nothing when the prior audit setting cannot be read' {
            $fake.Unreadable = @('policy')
            Invoke-TestSetup | Should Be 1
            $fake.Calls.Count | Should Be 0
            Test-Path -LiteralPath $fake.StatePath | Should Be $false
        }

        It 'changes nothing when the prior log size cannot be read' {
            $fake.Unreadable = @('log')
            Invoke-TestSetup | Should Be 1
            $fake.Calls.Count | Should Be 0
        }

        It 'changes nothing when the SACL cannot be read' {
            $fake.Unreadable = @('sacl')
            Invoke-TestSetup | Should Be 1
            $fake.Calls.Count | Should Be 0
        }

        It 'a second setup keeps the first record rather than recording its own changes as the prior state' {
            Invoke-TestSetup $pathA | Should Be 0
            Invoke-TestSetup $pathB | Should Be 0

            $state = Read-TestState
            $state.machine.security_log_max_bytes_before | Should Be ([long]20MB)
            $state.machine.audit_success_before | Should Be $false
            @($state.paths).Count | Should Be 2
        }

        It 'an unreadable state file is kept and nothing changes' {
            Set-Content -LiteralPath $fake.StatePath -Value 'not json {' -Encoding UTF8
            Invoke-TestSetup | Should Be 1
            $fake.Calls.Count | Should Be 0
            (Get-Content -LiteralPath $fake.StatePath -Raw).Trim() | Should Be 'not json {'
        }
    }

    Context 'the Security log size' {
        It 'leaves a 1 GiB log at 1 GiB (the VM case)' {
            $fake.LogBytes = [long]1GB
            Invoke-TestSetup | Should Be 0
            $fake.LogBytes | Should Be ([long]1GB)
            Assert-MockCalled Set-SecurityLogMaxBytes -Times 0 -Exactly -Scope It
            $null -eq (Read-TestState).machine.security_log_max_bytes_set | Should Be $true
        }

        It 'raises a smaller log to the size asked for' {
            Invoke-TestSetup | Should Be 0
            $fake.LogBytes | Should Be ([long]128MB)
            (Read-TestState).machine.security_log_max_bytes_set | Should Be ([long]128MB)
        }

        It 'never lowers it, even when asked for less' {
            $fake.LogBytes = [long]128MB
            Invoke-TestSetup -LogSizeMB 64 | Should Be 0
            $fake.LogBytes | Should Be ([long]128MB)
            Assert-MockCalled Set-SecurityLogMaxBytes -Times 0 -Exactly -Scope It
        }
    }

    Context '-Revert' {
        It 'a 1 GiB log, setup, -Revert: the log is still 1 GiB and the audit setting as before (re-check row 5)' {
            $fake.LogBytes = [long]1GB
            $fake.Success = $true   # enabled earlier by another component
            Invoke-TestSetup | Should Be 0
            Invoke-TestRevert | Should Be 0

            $fake.LogBytes | Should Be ([long]1GB)
            $fake.Success | Should Be $true
            Assert-MockCalled Set-SecurityLogMaxBytes -Times 0 -Exactly -Scope It
            Assert-MockCalled Set-FileSystemAuditSuccess -Times 0 -Exactly -Scope It
            Test-Path -LiteralPath $fake.StatePath | Should Be $false
        }

        It 'restores the Success setting it enabled, and never touches Failure' {
            $fake.Failure = $true
            Invoke-TestSetup | Should Be 0
            $fake.Success | Should Be $true
            Invoke-TestRevert | Should Be 0

            $fake.Success | Should Be $false
            $fake.Failure | Should Be $true
            ($fake.Calls -join ',') | Should Match 'audit-success:True.*audit-success:False'
        }

        It 'restores a log size it raised' {
            Invoke-TestSetup | Should Be 0
            Invoke-TestRevert | Should Be 0
            $fake.LogBytes | Should Be ([long]20MB)
        }

        It 'leaves a log size that something else changed after setup' {
            Invoke-TestSetup | Should Be 0
            $fake.LogBytes = [long]256MB   # another installer, after ours
            Invoke-TestRevert | Should Be 0
            $fake.LogBytes | Should Be ([long]256MB)
            Assert-MockCalled Set-SecurityLogMaxBytes -Times 1 -Exactly -Scope It   # the raise only
        }

        It 'removes only the audit rights it added, and no one else''s rule' {
            $fake.Acls[$pathA] = New-TestAcl -EveryoneMasks $WriteData -WithOtherIdentity
            Invoke-TestSetup | Should Be 0
            (Get-EveryoneMask $fake.Acls[$pathA]) -band ($WriteData -bor $AppendData) | Should Be ($WriteData -bor $AppendData)

            Invoke-TestRevert | Should Be 0
            (Get-EveryoneMask $fake.Acls[$pathA]) | Should Be $WriteData
            (Get-OtherIdentityRules $fake.Acls[$pathA]).Count | Should Be 1
        }

        It 'keeps the other rights of a rule it added bits to' {
            $delete = [int][System.Security.AccessControl.FileSystemRights]::Delete
            $fake.Acls[$pathA] = New-TestAcl -EveryoneMasks ($WriteData -bor $delete)
            Invoke-TestSetup | Should Be 0
            Invoke-TestRevert | Should Be 0
            (Get-EveryoneMask $fake.Acls[$pathA]) | Should Be ($WriteData -bor $delete)
        }

        It 'a SACL that was already complete is not written at all' {
            $fake.Acls[$pathA] = New-TestAcl -EveryoneMasks ($WriteData -bor $AppendData)
            Invoke-TestSetup | Should Be 0
            Invoke-TestRevert | Should Be 0
            Assert-MockCalled Set-WatchPathSecurity -Times 0 -Exactly -Scope It
            (Get-EveryoneMask $fake.Acls[$pathA]) | Should Be ($WriteData -bor $AppendData)
        }

        It 'keeps the machine-wide settings until the last recorded path is reverted' {
            Invoke-TestSetup $pathA | Should Be 0
            Invoke-TestSetup $pathB | Should Be 0

            Invoke-TestRevert $pathA | Should Be 0
            $fake.Success | Should Be $true
            $fake.LogBytes | Should Be ([long]128MB)
            @((Read-TestState).paths).Count | Should Be 1

            Invoke-TestRevert $pathB | Should Be 0
            $fake.Success | Should Be $false
            $fake.LogBytes | Should Be ([long]20MB)
            Test-Path -LiteralPath $fake.StatePath | Should Be $false
        }

        It 'matches the recorded path whatever its case or trailing separator' {
            Invoke-TestSetup 'C:\Watched_Files' | Should Be 0
            Invoke-TestRevert 'c:\watched_files\' | Should Be 0
            Test-Path -LiteralPath $fake.StatePath | Should Be $false
        }

        It 'changes nothing without a state file, and says how to do it by hand' {
            Mock Write-Host { [void]$fake.Lines.Add([string]$Object) }

            Invoke-TestRevert | Should Be 1

            $fake.Calls.Count | Should Be 0
            ($fake.Lines -join "`n") | Should Match 'auditpol /get'
        }

        It 'does not touch a path this script did not set up' {
            Invoke-TestSetup $pathA | Should Be 0
            $callsAfterSetup = $fake.Calls.Count
            Invoke-TestRevert $pathB | Should Be 1
            $fake.Calls.Count | Should Be $callsAfterSetup
            @((Read-TestState).paths).Count | Should Be 1
        }
    }

    Context '-Verify' {
        It 'shows the recorded prior state' {
            $fake.LogBytes = [long]1GB
            $fake.Acls[$pathA] = New-TestAcl -EveryoneMasks $WriteData
            Invoke-TestSetup | Should Be 0
            Mock Write-Host { [void]$fake.Lines.Add([string]$Object) }

            Invoke-Verify -WatchPath $pathA -StatePath $fake.StatePath | Select-Object -Last 1 | Should Be 0

            $text = $fake.Lines -join "`n"
            $text | Should Match 'Security log size before setup: +1,024 MB \(not changed by setup\)'
            $text | Should Match 'File System audit before setup: +No Auditing \(Success enabled by setup\)'
            $text | Should Match ([regex]::Escape("${pathA}: audited before setup: WriteData; added by setup: AppendData"))
        }

        It 'says when nothing is recorded, without failing' {
            $fake.Success = $true
            $fake.Acls[$pathA] = New-TestAcl -EveryoneMasks ($WriteData -bor $AppendData)
            Mock Write-Host { [void]$fake.Lines.Add([string]$Object) }

            Invoke-Verify -WatchPath $pathA -StatePath $fake.StatePath | Select-Object -Last 1 | Should Be 0

            ($fake.Lines -join "`n") | Should Match '\[  ok  \] Recorded prior state  -  none at'
        }
    }

    Context 'exit codes and output style' {
        It 'a failed check makes the run exit non-zero (ported from fix/evidence-integrity)' {
            $fake.ProbeFails = $true
            Invoke-TestSetup | Should Be 1
        }

        It 'keeps the [  ok  ] / [ FAIL ] marks' {
            Mock Write-Host { [void]$fake.Lines.Add([string]$Object) }
            $fake.ProbeFails = $true
            Invoke-TestSetup | Out-Null
            ($fake.Lines -join "`n") | Should Match '\[  ok  \] Prior state recorded'
            ($fake.Lines -join "`n") | Should Match '\[ FAIL \] End-to-end probe'
        }
    }

    Context 'the pieces' {
        It 'reads auditpol''s English settings and refuses anything else' {
            (ConvertFrom-InclusionSetting 'Success and Failure').Success | Should Be $true
            (ConvertFrom-InclusionSetting 'No Auditing').Failure | Should Be $false
            (ConvertFrom-InclusionSetting 'Failure').Success | Should Be $false
            ConvertFrom-InclusionSetting 'Erfolg' | Should BeNullOrEmpty
        }

        It 'counts only explicit Everyone Success rules shaped like its own as already audited' {
            $acl = New-TestAcl -WithOtherIdentity
            $acl.AddAuditRule((New-Object System.Security.AccessControl.FileSystemAuditRule(
                $EveryoneSid, [System.Security.AccessControl.FileSystemRights]$AppendData,
                $AuditInheritance, $AuditPropagation, [System.Security.AccessControl.AuditFlags]::Failure)))
            $acl.AddAuditRule((New-Object System.Security.AccessControl.FileSystemAuditRule(
                $EveryoneSid, [System.Security.AccessControl.FileSystemRights]$WriteData,
                [System.Security.AccessControl.InheritanceFlags]::None, $AuditPropagation, [System.Security.AccessControl.AuditFlags]::Success)))
            Get-AuditedWriteRights -Acl $acl | Should Be 0

            Get-AuditedWriteRights -Acl (New-TestAcl -EveryoneMasks $WriteData) | Should Be $WriteData
        }
    }
}

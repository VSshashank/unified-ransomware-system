<#
.SYNOPSIS
    Install URDS on this machine. Right-click -> Run with PowerShell, once.

.DESCRIPTION
    One run leaves a machine that, with nobody logged in and across reboots,
    sees every write to the protected folders, knows which process made each
    one, suspends a process that is encrypting, snapshots, and records all of it
    in a hash-chained ledger - and refuses to claim any of that if it cannot do
    it, because the run ends with a self-test that has to pass.

    Everything it changes is recorded in an install receipt at
    %ProgramData%\URDS\install-receipt.json, including the state each setting
    was in *before* it was touched. `uninstall.ps1` reverts from that receipt
    and not from a list of assumptions. That distinction is not academic: the
    Windows file-system audit subcategory is machine-wide, and an uninstall that
    switches it off because it "was probably off" takes attribution away from
    every other protected root on the machine - and from anything else on it
    that depends on file auditing. It has happened on this project's own
    development machine, and the receipt is the fix.

    What this does NOT do: it does not protect your Documents folder unless you
    say so. The default protected root is `watched_files` inside this checkout,
    which is the demonstration folder. Suspending processes is a real action
    with a real blast radius, and pointing it at somebody's live documents is a
    decision they make, with -ProtectedPath, not one an installer makes for
    them.

.PARAMETER ProtectedPath
    One or more folders to protect. Defaults to `watched_files` in this
    checkout. A filesystem root, or anything overlapping the Windows or Program
    Files directories, is refused by `agent/config.py` and not by this script.

.PARAMETER SkipSelfTest
    Install without running the end-to-end test at the end. The installation is
    then unverified, and the script says so and exits non-zero.

.PARAMETER NoDashboard
    Do not start the API services or the Streamlit dashboard.

.PARAMETER ShadowStorageMaxPercent
    Shadow-copy storage cap for the protected volume. Below about 5% Windows
    silently discards older snapshots, which is the recovery story quietly
    failing.

.PARAMETER PortOffset
    Shift the API and dashboard ports by this much, for a machine where 8000 or
    8501 is already somebody else's. See scripts/start_stack.ps1.

.PARAMETER Relaunched
    Set by the script on itself when it re-launches under UAC. Makes the new
    window wait for a keypress at the end, so the output can be read.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File install.ps1

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File install.ps1 -ProtectedPath "C:\Users\me\Documents"

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File uninstall.ps1
#>

[CmdletBinding()]
param(
    [string[]]$ProtectedPath,
    [switch]$SkipSelfTest,
    [switch]$NoDashboard,
    [int]$ShadowStorageMaxPercent = 10,
    [int]$PortOffset = 0,
    [switch]$Relaunched
)

# ------------------------------------------------------------ 1. self-elevate

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "Re-launching as Administrator. Approve the UAC prompt." -ForegroundColor Yellow

    # The arguments have to survive the trip. Elevating and then quietly
    # dropping -ProtectedPath would install an agent watching the wrong folder,
    # and the only sign would be that nothing it was meant to protect is.
    #
    # -Command rather than -File, and that is not a style choice. With -File,
    # every argument arrives as a literal string and an array parameter gets
    # one element or none of the others. Measured, on this machine, PowerShell
    # 5.1, passing two folders:
    #
    #   -File ... -ProtectedPath "C:\one" "D:\two"   ->  count=1, D:\two dropped
    #   -File ... -ProtectedPath "C:\one","D:\two"   ->  count=1, ["C:\one,D:\two"]
    #   -Command "& '...' -ProtectedPath 'C:\one','D:\two'"  ->  count=2
    #
    # The first of those is the dangerous one: the installer would have run
    # happily and protected half of what it was asked to. Single-quoted and
    # doubled, so a folder with an apostrophe in it survives too.
    $script = $PSCommandPath -replace "'", "''"
    $inner = "& '$script' -Relaunched"
    if ($ProtectedPath) {
        $list = ($ProtectedPath | ForEach-Object { "'" + ($_ -replace "'", "''") + "'" }) -join ','
        $inner += " -ProtectedPath $list"
    }
    if ($SkipSelfTest) { $inner += " -SkipSelfTest" }
    if ($NoDashboard)  { $inner += " -NoDashboard" }
    $inner += " -ShadowStorageMaxPercent $ShadowStorageMaxPercent"
    $inner += " -PortOffset $PortOffset"

    try {
        $elevated = Start-Process powershell -Verb RunAs -PassThru -Wait `
            -ArgumentList "-NoProfile -ExecutionPolicy Bypass -Command `"$inner`""
        exit $elevated.ExitCode
    } catch {
        Write-Host "Elevation was declined or failed: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "Everything below this line needs Administrator: the audit policy, the" -ForegroundColor Yellow
        Write-Host "SACLs, the Security log size, shadow storage, and registering a service." -ForegroundColor Yellow
        exit 3
    }
}

$ErrorActionPreference = 'Continue'

$RepoRoot    = $PSScriptRoot

# An elevated console starts in C:\Windows\System32, and `python -m agent` finds
# the `agent` package on sys.path through the working directory. Without this
# every call below returns "No module named agent" - which is what the first run
# of this installer did, reporting that the configuration was rejected when in
# fact it had never been read.
Set-Location -LiteralPath $RepoRoot

$StateDir    = Join-Path $env:ProgramData 'URDS'
$ReceiptPath = Join-Path $StateDir 'install-receipt.json'
$ConfigPath  = Join-Path $StateDir 'agent.json'
$InstallLog  = Join-Path $StateDir 'install.log'
$ServiceName = 'URDSAgent'

#: The File System audit subcategory. auditpol's labels are localised; this
#: GUID is not.
$FileSystemSubcategory = '{0CCE921D-69AE-11D9-BED3-505054503030}'

New-Item -ItemType Directory -Force -Path $StateDir | Out-Null
Start-Transcript -Path $InstallLog -Force | Out-Null

$script:Failures = 0
$script:Steps = @()

function Write-Result {
    param([string]$Label, [bool]$Ok, [string]$Detail = '', [string]$Remediation = '')
    $mark = if ($Ok) { '  ok  ' } else { ' FAIL ' }
    $line = "[$mark] $Label"
    if ($Detail) { $line += "  -  $Detail" }
    Write-Host $line -ForegroundColor $(if ($Ok) { 'Green' } else { 'Red' })
    if (-not $Ok) {
        $script:Failures++
        if ($Remediation) {
            foreach ($row in ($Remediation -split "`n")) {
                Write-Host "         $row" -ForegroundColor Yellow
            }
        }
    }
    # No `return $Ok`. Nothing here consumes it, and a value returned from a
    # function called as a statement lands on the output stream - which put a
    # bare "True" or "False" under every single line of the first run's output.
    $script:Steps += [pscustomobject]@{ step = $Label; ok = $Ok; detail = $Detail }
}

function Write-Section {
    param([string]$Title)
    Write-Host ""
    Write-Host "-- $Title " -ForegroundColor Cyan -NoNewline
    Write-Host ("-" * [Math]::Max(0, 68 - $Title.Length)) -ForegroundColor DarkCyan
}

# ------------------------------------------------------------------- receipt

# Written after every captured prior state rather than once at the end. An
# installer that is interrupted half way has still changed the machine, and an
# uninstall needs to know what - a receipt that only exists on success is a
# receipt for the case that did not need one.
$script:Receipt = [ordered]@{
    schema        = 'urds.install-receipt/1'
    installed_at  = (Get-Date).ToUniversalTime().ToString('o')
    installed_by  = "$env:USERDOMAIN\$env:USERNAME"
    repo          = $RepoRoot
    config_path   = $ConfigPath
    note          = 'Prior state of everything this installer changed. uninstall.ps1 reverts from here.'
    prior         = [ordered]@{}
    applied       = [ordered]@{}
}

function Save-Receipt {
    try {
        $script:Receipt | ConvertTo-Json -Depth 6 | Set-Content -Path $ReceiptPath -Encoding utf8
    } catch {
        Write-Host "could not write the install receipt: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# "Prior" means before URDS was *first* installed, not before this particular
# run. Re-running the installer on a machine it has already configured would
# otherwise record its own handiwork as the state to return to: the second run
# reads auditing as already enabled - because the first run enabled it - and the
# uninstaller then never turns it off. The first receipt's `prior` is the only
# record of what the machine looked like untouched, so it is carried forward.
if (Test-Path $ReceiptPath) {
    try {
        $previous = Get-Content $ReceiptPath -Raw | ConvertFrom-Json
        if ($previous.prior) {
            foreach ($property in $previous.prior.PSObject.Properties) {
                $script:Receipt.prior[$property.Name] = $property.Value
            }
            $script:Receipt.prior_carried_from = $previous.installed_at
        }
    } catch {
        Write-Host "existing receipt at $ReceiptPath is unreadable; starting a new one" -ForegroundColor Yellow
    }
}

function Set-Prior {
    # Write a prior observation only if this is the first install to make one.
    param([string]$Key, $Value)
    if (-not $script:Receipt.prior.Contains($Key)) {
        $script:Receipt.prior[$Key] = $Value
    }
}

function Get-AuditPolicyState {
    $raw = & auditpol /get /subcategory:"$FileSystemSubcategory" /r 2>$null
    if (-not $raw) { return 'unknown' }
    $row = $raw | ConvertFrom-Csv | Select-Object -First 1
    if (-not $row) { return 'unknown' }
    return $row.'Inclusion Setting'
}

Write-Host ""
Write-Host "  URDS - Unified Ransomware Detection and Response" -ForegroundColor White
Write-Host "  installing on $env:COMPUTERNAME as $env:USERNAME" -ForegroundColor DarkGray
Write-Host "  transcript: $InstallLog" -ForegroundColor DarkGray

# --------------------------------------------------------------- 2. preflight

Write-Section "Preflight"

$os = Get-CimInstance Win32_OperatingSystem
$cs = Get-CimInstance Win32_ComputerSystem
$build = [int]$os.BuildNumber

Write-Result "Windows 10 1809 or later" ($build -ge 17763) `
    "$($os.Caption), build $build" `
    ("This build is $build; 17763 (Windows 10 1809) is the floor.`n" +
     "Event ID 4663 carries the fields attribution needs on older builds too,`n" +
     "but nothing here has been measured on them. Upgrade, or run in a VM.")

Write-Result "64-bit" ($os.OSArchitecture -like '*64*') $os.OSArchitecture `
    "pywin32 and the Security-channel subscription are installed 64-bit here.`nA 32-bit host is not supported."

$ramGB = [Math]::Round($cs.TotalPhysicalMemory / 1GB, 1)
Write-Result "8 GB RAM or more" ($cs.TotalPhysicalMemory -ge (7.5 * 1GB)) "$ramGB GB" `
    ("This machine reports $ramGB GB. The agent itself is small; the ml-engine`n" +
     "and the model are not. Close other work, or use -NoDashboard, which`n" +
     "leaves only the agent running.")

Write-Result "PowerShell 5.1 or later" ($PSVersionTable.PSVersion.Major -ge 5) `
    $PSVersionTable.PSVersion.ToString() `
    "Windows PowerShell 5.1 ships with Windows 10 and 11. Update Windows."

# The volume that matters for free space is the one being protected, which is
# not necessarily C:.
if (-not $ProtectedPath) {
    $ProtectedPath = @((Join-Path $RepoRoot 'watched_files'))
}
$resolvedPaths = @()
foreach ($path in $ProtectedPath) {
    if (-not (Test-Path -LiteralPath $path)) {
        New-Item -ItemType Directory -Force -Path $path | Out-Null
    }
    $resolvedPaths += (Resolve-Path -LiteralPath $path).Path
}
$protectedVolume = (Split-Path -Qualifier $resolvedPaths[0])
$drive = Get-PSDrive -Name $protectedVolume.TrimEnd(':') -ErrorAction SilentlyContinue
$freeGB = if ($drive) { [Math]::Round($drive.Free / 1GB, 1) } else { 0 }
Write-Result "20 GB free on $protectedVolume" ($freeGB -ge 20) "$freeGB GB free" `
    ("Shadow copies live on this volume and the ledger grows with every event.`n" +
     "Free space on $protectedVolume, or protect a folder on a roomier volume with`n" +
     "  -ProtectedPath <folder>")

Write-Host ""
Write-Host "  protecting:" -ForegroundColor White
foreach ($path in $resolvedPaths) { Write-Host "    $path" }
if (-not $PSBoundParameters.ContainsKey('ProtectedPath')) {
    Write-Host ""
    Write-Host "  That is this checkout's demonstration folder, not your documents." -ForegroundColor Yellow
    Write-Host "  To protect real folders, re-run with:" -ForegroundColor Yellow
    Write-Host "    -ProtectedPath `"$env:USERPROFILE\Documents`"" -ForegroundColor Yellow
}

if ($script:Failures -gt 0) {
    Write-Host ""
    Write-Host "Preflight failed. Nothing has been changed." -ForegroundColor Red
    Stop-Transcript | Out-Null
    if ($Relaunched) { Read-Host "Press Enter to close" | Out-Null }
    exit 1
}

$script:Receipt.protected_paths = $resolvedPaths
Save-Receipt

# ------------------------------------------------------------------ 3. Python

Write-Section "Python and dependencies"

$venvPython = Join-Path $RepoRoot '.venv\Scripts\python.exe'

function Get-UsablePython {
    # 3.11 is the floor: the services pin FastAPI and pydantic versions that do
    # not build on older interpreters.
    foreach ($candidate in @('py -3.13', 'py -3.12', 'py -3.11', 'python')) {
        $parts = $candidate -split ' '
        $exe = $parts[0]
        if (-not (Get-Command $exe -ErrorAction SilentlyContinue)) { continue }
        $arguments = @()
        if ($parts.Count -gt 1) { $arguments += $parts[1] }
        $arguments += @('-c', 'import sys; print(sys.version_info[0], sys.version_info[1]); print(sys.executable)')
        $out = & $exe @arguments 2>$null
        if ($LASTEXITCODE -ne 0 -or -not $out) { continue }
        $version = ($out[0] -split ' ')
        if ([int]$version[0] -eq 3 -and [int]$version[1] -ge 11) { return $out[1] }
    }
    return $null
}

if (Test-Path $venvPython) {
    Write-Result "virtual environment" $true "reusing $venvPython"
} else {
    $interpreter = Get-UsablePython
    if (-not $interpreter) {
        Write-Host "  no Python 3.11+ found; installing with winget" -ForegroundColor Yellow
        if (Get-Command winget -ErrorAction SilentlyContinue) {
            & winget install -e --id Python.Python.3.12 --silent `
                --accept-package-agreements --accept-source-agreements | Out-Null
            # winget puts it on the PATH of *new* processes, not this one.
            $env:Path = [System.Environment]::GetEnvironmentVariable('Path', 'Machine') + ';' +
                        [System.Environment]::GetEnvironmentVariable('Path', 'User')
            $interpreter = Get-UsablePython
        }
    }
    if (-not $interpreter) {
        Write-Result "Python 3.11 or later" $false "not found and could not be installed" `
            ("Install it by hand from https://www.python.org/downloads/ (tick`n" +
             "`"Add python.exe to PATH`"), then re-run this script.`n" +
             "Or:  winget install -e --id Python.Python.3.12")
    } else {
        Write-Result "Python 3.11 or later" $true $interpreter
        & $interpreter -m venv (Join-Path $RepoRoot '.venv')
        Write-Result "virtual environment" (Test-Path $venvPython) $venvPython `
            "python -m venv .venv failed. The transcript above has the error."
    }
}

if (Test-Path $venvPython) {
    Write-Host "  installing dependencies (this takes a few minutes the first time)"

    # --timeout and --retries, because pip's default is to wait indefinitely on
    # a stalled socket. Measured on this machine: a run sat for 19 minutes with
    # one ESTABLISHED connection to PyPI over IPv6, 6.9 seconds of CPU in total,
    # and nothing written to site-packages. Nothing in the output said so, and
    # an installer that hangs forever with no message is indistinguishable from
    # one that has crashed. 30 seconds and five retries turns that into a
    # failure with a name.
    $pipFlags = @('--quiet', '--disable-pip-version-check', '--timeout', '30', '--retries', '5')

    & $venvPython -m pip install --upgrade pip @pipFlags 2>&1 | Out-Null

    $requirementFiles = @(
        (Join-Path $RepoRoot 'agent\requirements.txt'),
        (Join-Path $RepoRoot 'services\monitor\requirements.txt'),
        (Join-Path $RepoRoot 'services\ml-engine\requirements.txt'),
        (Join-Path $RepoRoot 'services\ledger\requirements.txt'),
        (Join-Path $RepoRoot 'services\gateway\requirements.txt'),
        (Join-Path $RepoRoot 'services\response\requirements.txt')
    )
    if (-not $NoDashboard) {
        $requirementFiles += (Join-Path $RepoRoot 'services\dashboard\requirements.txt')
    }
    # One line per file before it starts, not after. pip resolves against PyPI
    # even when every pin is already satisfied, and on a slow link that is
    # minutes of silence per file - which reads as a hung installer. Measured
    # here: seven files, all pins already installed, still a network round trip
    # for each package's metadata.
    $installFailures = @()
    foreach ($file in $requirementFiles) {
        if (-not (Test-Path $file)) { continue }
        $component = Split-Path -Parent $file | Split-Path -Leaf
        Write-Host ("    {0,-12} {1}" -f $component, '...') -NoNewline
        $started = Get-Date
        & $venvPython -m pip install -r $file @pipFlags 2>&1 | Out-Null
        $took = ((Get-Date) - $started).TotalSeconds
        if ($LASTEXITCODE -ne 0) {
            $installFailures += $component
            Write-Host ("`r    {0,-12} failed after {1:N0}s" -f $component, $took) -ForegroundColor Red
        } else {
            Write-Host ("`r    {0,-12} ok ({1:N0}s)        " -f $component, $took)
        }
    }
    Write-Result "dependencies" ($installFailures.Count -eq 0) `
        $(if ($installFailures.Count -eq 0) { "$($requirementFiles.Count) requirement file(s)" } else { "failed: $($installFailures -join ', ')" }) `
        "Run the failing one by hand to see why:`n  .venv\Scripts\python.exe -m pip install -r <file>"

    # pywin32 hosts the service and provides the Security-channel subscription.
    # Its post-install step registers the DLLs; without it `import win32service`
    # can succeed while the service host cannot start.
    & $venvPython -c "import win32serviceutil, win32evtlog" 2>$null
    if ($LASTEXITCODE -ne 0) {
        & $venvPython -m pip install pywin32 --quiet 2>&1 | Out-Null
        $postinstall = Join-Path $RepoRoot '.venv\Scripts\pywin32_postinstall.py'
        if (Test-Path $postinstall) { & $venvPython $postinstall -install | Out-Null }
        & $venvPython -c "import win32serviceutil, win32evtlog" 2>$null
    }
    Write-Result "pywin32" ($LASTEXITCODE -eq 0) "win32serviceutil and win32evtlog import" `
        (".venv\Scripts\python.exe -m pip install pywin32`n" +
         ".venv\Scripts\python.exe .venv\Scripts\pywin32_postinstall.py -install`n" +
         "Without it there is no service host and no attribution source.")
}

# ------------------------------------------------- 4. configuration + 5. audit

Write-Section "Configuration"

$dataDir = Join-Path $RepoRoot 'data\agent'
$configJson = [ordered]@{
    '_comment'             = "Written by install.ps1 on $((Get-Date).ToString('yyyy-MM-dd HH:mm:ss')). The agent reads this in preference to agent/agent.default.json. Deleting it falls back to the checked-in default."
    protected_paths        = @($resolvedPaths)
    data_dir               = $dataDir
    allowlist_images       = @()
    canaries_per_root      = 20
    attribution_timeout_ms = 750.0
    dispatch_lanes         = 4
    dispatch_queue_max     = 512
}
$configJson | ConvertTo-Json -Depth 4 | Set-Content -Path $ConfigPath -Encoding utf8
Write-Result "agent configuration" (Test-Path $ConfigPath) $ConfigPath

# Read back through the agent's own validator rather than trusting that what
# was written parses. It refuses a filesystem root, and anything overlapping
# Windows or Program Files, and it is the only thing that decides the blast
# radius.
if (Test-Path $venvPython) {
    $check = (& $venvPython -m agent config 2>&1) -join "`n"
    $exit = $LASTEXITCODE

    # Parsed, not pattern-matched. `python -m agent config` prints JSON, in
    # which every backslash is doubled, so a regex built from the literal
    # Windows path never matches and a correctly configured agent is reported
    # as rejected - which is what the second run of this installer did, under
    # an exit code of 0 that should have been the clue.
    $ok = $false
    $resolved = @()
    if ($exit -eq 0) {
        try {
            $parsed = $check | ConvertFrom-Json
            $resolved = @($parsed.protected_paths)
            $ok = ($parsed.source -eq $ConfigPath) -and
                  ($resolved -contains $resolvedPaths[0])
        } catch { $ok = $false }
    }
    Write-Result "the agent accepts it" $ok `
        $(if ($ok) { "resolves $ConfigPath -> $($resolved -join '; ')" } else { "python -m agent config exited $exit" }) `
        ("$($check -join "`n")`n" +
         "agent/config.py refuses a protected root that is a filesystem root or`n" +
         "that overlaps the Windows or Program Files directories. That refusal is`n" +
         "the blast radius doing its job; choose a different -ProtectedPath.")
}

Write-Section "Windows file auditing (this is what makes attribution work)"

# Captured before anything is changed. An uninstall that turns the subcategory
# off because it assumes this installer turned it on would break auditing for
# anything else on the machine that was already using it.
$priorAudit = Get-AuditPolicyState
Set-Prior 'audit_subcategory' $priorAudit
Set-Prior 'audit_subcategory_was_enabled' ($priorAudit -match 'Success')
Save-Receipt
Write-Host "  before this run, auditpol reported: $priorAudit" -ForegroundColor DarkGray

$securityLog = Get-WinEvent -ListLog Security -ErrorAction SilentlyContinue
if ($securityLog) {
    Set-Prior 'security_log_max_bytes' ([int64]$securityLog.MaximumSizeInBytes)
    Save-Receipt
}

$auditScript = Join-Path $RepoRoot 'scripts\setup_attribution_audit.ps1'
$sacled = @()
foreach ($path in $resolvedPaths) {
    # The first root sets the machine-wide policy and the Security log size;
    # every later one only needs its own SACL. Calling the full version per root
    # would re-apply a machine-wide setting once per folder for no reason.
    $arguments = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $auditScript, '-WatchPath', $path)
    if ($sacled.Count -gt 0) { $arguments += '-SaclOnly' }
    & powershell @arguments
    $ok = ($LASTEXITCODE -eq 0)
    if ($ok) { $sacled += $path }
    Write-Result "auditing on $path" $ok "setup_attribution_audit.ps1 exited $LASTEXITCODE" `
        ("Re-run it on its own to see which check failed:`n" +
         "  powershell -ExecutionPolicy Bypass -File `"$auditScript`" -WatchPath `"$path`"`n" +
         "Until it passes the agent detects and suspends nothing: no attribution`n" +
         "reaches CERTAIN and it does not guess a PID.")
}
$script:Receipt.applied.sacl_paths = $sacled
Save-Receipt

# ------------------------------------------------------- 6. raise the Security log

Write-Section "Security log size"

# 1 GiB, per the build specification. Not optional and not cosmetic: once file
# auditing is on, the default log wraps in minutes on a busy machine, and the
# records attribution depends on are dropped silently. The agent then reports
# `unknown` rather than an error, which is the hardest kind of failure to see.
$targetLogBytes = 1073741824
& wevtutil sl Security /ms:$targetLogBytes 2>&1 | Out-Null
$securityLog = Get-WinEvent -ListLog Security -ErrorAction SilentlyContinue
$actualBytes = if ($securityLog) { [int64]$securityLog.MaximumSizeInBytes } else { 0 }
Write-Result "Security log raised to 1 GiB" ($actualBytes -ge $targetLogBytes) `
    ("{0:N0} MB (was {1:N0} MB)" -f ($actualBytes / 1MB), ($script:Receipt.prior.security_log_max_bytes / 1MB)) `
    ("wevtutil sl Security /ms:$targetLogBytes`n" +
     "A wrapped Security log drops 4663 records and attribution degrades to`n" +
     "`"unknown`" without reporting an error.")
$script:Receipt.applied.security_log_max_bytes = $actualBytes
Save-Receipt

# --------------------------------------------------------- 7. shadow storage

Write-Section "Shadow copy storage"

$shadowVolume = if ($protectedVolume) { $protectedVolume } else { 'C:' }
$priorShadow = (& vssadmin list shadowstorage /for=$shadowVolume 2>&1) -join "`n"
Set-Prior 'shadowstorage' ([ordered]@{
    volume = $shadowVolume
    raw    = $priorShadow
})
Save-Receipt

& vssadmin resize shadowstorage /for=$shadowVolume /on=$shadowVolume /maxsize=$ShadowStorageMaxPercent% 2>&1 | Out-Null
$afterShadow = (& vssadmin list shadowstorage /for=$shadowVolume 2>&1) -join "`n"
$shadowOk = ($afterShadow -notmatch 'Error') -and ($afterShadow -match 'Maximum Shadow Copy Storage space')
Write-Result "shadow storage on $shadowVolume" $shadowOk `
    "maxsize=$ShadowStorageMaxPercent%" `
    ("vssadmin resize shadowstorage /for=$shadowVolume /on=$shadowVolume /maxsize=$ShadowStorageMaxPercent%`n" +
     "Without room for shadow copies, Windows discards the oldest silently and`n" +
     "there is nothing to restore a file from.`n$afterShadow")
$script:Receipt.applied.shadowstorage_maxsize_percent = $ShadowStorageMaxPercent
Save-Receipt

# -------------------------------------------------------- 8. the signing key

Write-Section "Secrets"

$envFile = Join-Path $RepoRoot '.env'
$envExample = Join-Path $RepoRoot '.env.example'
if (-not (Test-Path $envFile) -and (Test-Path $envExample)) {
    Copy-Item $envExample $envFile
}

function New-Secret {
    param([int]$Bytes = 48)
    $buffer = New-Object byte[] $Bytes
    # RNGCryptoServiceProvider, not Get-Random. Get-Random is a seeded PRNG and
    # a token-signing key from it is guessable given the seed.
    $rng = [System.Security.Cryptography.RNGCryptoServiceProvider]::new()
    try { $rng.GetBytes($buffer) } finally { $rng.Dispose() }
    return [Convert]::ToBase64String($buffer)
}

$rotated = @()
if (Test-Path $envFile) {
    $lines = Get-Content $envFile
    $out = @()
    foreach ($line in $lines) {
        # Only the committed placeholders are replaced. Overwriting a secret
        # somebody had already set would invalidate every token they hold, and
        # a re-run of an installer should not do that.
        if ($line -match '^\s*JWT_SECRET\s*=\s*dev-only-change-me\s*$') {
            $out += "JWT_SECRET=$(New-Secret)"
            $rotated += 'JWT_SECRET'
        } elseif ($line -match '^\s*DEV_TOKEN_BOOTSTRAP_SECRET\s*=\s*dev-bootstrap-change-me\s*$') {
            # This one mints admin tokens on demand. Leaving the committed value
            # while rotating JWT_SECRET moves the lock and leaves the key under
            # the mat.
            $out += "DEV_TOKEN_BOOTSTRAP_SECRET=$(New-Secret 32)"
            $rotated += 'DEV_TOKEN_BOOTSTRAP_SECRET'
        } else {
            $out += $line
        }
    }
    Set-Content -Path $envFile -Value $out -Encoding utf8

    $stillDefault = (Get-Content $envFile | Where-Object { $_ -match 'dev-only-change-me|dev-bootstrap-change-me' })
    Write-Result "signing keys are not the committed defaults" (-not $stillDefault) `
        $(if ($rotated.Count -gt 0) { "rotated: $($rotated -join ', ')" } else { "already set by a previous run" }) `
        "Edit $envFile and replace every value that still reads dev-only-change-me."
    $script:Receipt.applied.rotated_secrets = $rotated
} else {
    Write-Result "signing keys are not the committed defaults" $false "no $envFile and no $envExample" `
        "Create .env from .env.example, then re-run."
}
Save-Receipt

# ---------------------------------------------------- 9. lock down the data dir

Write-Section "Data directory permissions"

New-Item -ItemType Directory -Force -Path $dataDir | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $dataDir 'snapshots') | Out-Null

# Tamper-*evident* is not tamper-*resistant*. The chain will show that a block
# was altered; it will not stop the alteration. The ledger and the snapshot root
# therefore must not be writable by the unprivileged account ransomware would be
# running as - which on a normal machine is the account of whoever is logged in.
#
# SIDs, not names: "Administrators" is localised, S-1-5-32-544 is not.
$priorAcl = (& icacls $dataDir 2>&1) -join "`n"
Set-Prior 'data_dir_acl' $priorAcl
Set-Prior 'data_dir' $dataDir
Save-Receipt

# Two commands, and it has to be two.
#
# The one-liner - `/inheritance:r /grant:r "SID:(OI)(CI)F" /T` - looks right and
# is not. (OI) and (CI) are *inheritance* flags; applied with /T directly to a
# file they carry nothing, while /inheritance:r has already stripped that file's
# inherited ACEs. The file is left with an **empty DACL**: no ACE for anybody,
# including SYSTEM. Measured on this machine, elevated:
#
#   /inheritance:r /grant:r (OI)(CI)F /T   -> file.txt ACL is blank,
#                                             open read-write DENIED to an
#                                             elevated Administrator
#   directory only, then DIR\* /reset /T   -> file.txt SYSTEM:(I)(F),
#                                             open read-write OK
#
# The first form shipped in the first run of this installer and locked the agent
# out of its own ledger: `sqlite3.OperationalError: unable to open database
# file`, the service registered and then stopped, and the only reason it was not
# mistaken for a bad build is that the "running" check below is a check.
& icacls $dataDir /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' /grant:r '*S-1-5-32-544:(OI)(CI)F' 2>&1 | Out-Null
& icacls "$dataDir\*" /reset /T /C /Q 2>&1 | Out-Null

$acl = (& icacls $dataDir 2>&1) -join "`n"
$hasSystem = $acl -match 'NT AUTHORITY\\SYSTEM|S-1-5-18'
$hasAdmins = $acl -match 'BUILTIN\\Administrators|S-1-5-32-544'
$hasUsers  = $acl -match 'BUILTIN\\Users|\\Everyone|Authenticated Users'

# The ACL on the directory is the setting. Whether the ledger can still be
# opened is the effect, and they came apart once already - the directory's ACL
# read exactly as intended while every file under it was unopenable. Check the
# effect.
$ledgerFile = Join-Path $dataDir 'ledger.db'
$ledgerOpens = $true
$ledgerDetail = 'no ledger yet; the service creates it on first start'
if (Test-Path $ledgerFile) {
    try {
        $handle = [System.IO.File]::Open($ledgerFile, 'Open', 'ReadWrite', 'ReadWrite')
        $ledgerDetail = "ledger.db opens read-write ({0:N0} KB)" -f ($handle.Length / 1KB)
        $handle.Close()
    } catch {
        $ledgerOpens = $false
        $ledgerDetail = "ledger.db is not openable even elevated: $($_.Exception.Message)"
    }
}

Write-Result "data directory is SYSTEM and Administrators only" `
    ($hasSystem -and $hasAdmins -and -not $hasUsers -and $ledgerOpens) `
    "$dataDir - $ledgerDetail" `
    ("icacls `"$dataDir`" /inheritance:r /grant:r `"*S-1-5-18:(OI)(CI)F`" /grant:r `"*S-1-5-32-544:(OI)(CI)F`"`n" +
     "icacls `"$dataDir\*`" /reset /T /C /Q`n" +
     "Current: $acl")
$script:Receipt.applied.data_dir_locked = $true
Save-Receipt

Write-Host "  A non-elevated shell can no longer read $dataDir." -ForegroundColor DarkGray
Write-Host "  That is the point. Open an Administrator console to inspect the ledger." -ForegroundColor DarkGray

# ------------------------------------------------------------ 10. the service

Write-Section "The service"

$existing = & sc.exe query $ServiceName 2>&1
$serviceExisted = ($LASTEXITCODE -eq 0)
Set-Prior 'service_existed' $serviceExisted
Save-Receipt

if ($serviceExisted) {
    Write-Host "  $ServiceName is already registered; stopping it to re-register" -ForegroundColor DarkGray
    & sc.exe stop $ServiceName | Out-Null
    Start-Sleep -Seconds 5
}

if (Test-Path $venvPython) {
    # `install` on a service that is already registered fails; `update`
    # re-points an existing registration at this interpreter and this checkout,
    # which is what a re-run after moving the repository needs.
    $verb = if ($serviceExisted) { 'update' } else { 'install' }
    & $venvPython -m agent $verb 2>&1 | Out-Null
    & sc.exe query $ServiceName 2>&1 | Out-Null
    Write-Result "registered with the SCM" ($LASTEXITCODE -eq 0) "$ServiceName ($verb)" `
        (".venv\Scripts\python.exe -m agent $verb`n" +
         "If it reports access denied, this console is not elevated.")

    # Auto-start, because protection that waits for a login is protection with a
    # documented hole in it.
    & sc.exe config $ServiceName start= auto | Out-Null
    Write-Result "start= auto" ($LASTEXITCODE -eq 0) "survives a reboot" `
        "sc.exe config $ServiceName start= auto"

    # Restart three times on failure, a minute apart, resetting the counter
    # daily. An agent that dies at 3am and stays dead until somebody notices is
    # not a protection path.
    & sc.exe failure $ServiceName reset= 86400 actions= restart/60000/restart/60000/restart/60000 | Out-Null
    Write-Result "restart on failure" ($LASTEXITCODE -eq 0) "3 restarts, 60s apart, counter resets daily" `
        "sc.exe failure $ServiceName reset= 86400 actions= restart/60000/restart/60000/restart/60000"

    & sc.exe description $ServiceName "URDS ransomware protection agent. Watches the configured protected folders, attributes writes to the process that made them, and suspends before it terminates." | Out-Null
    $script:Receipt.applied.service_installed = $true
    Save-Receipt

    & sc.exe start $ServiceName | Out-Null
    Start-Sleep -Seconds 12
    $state = (& sc.exe query $ServiceName | Select-String 'STATE') -join ''
    Write-Result "running" ($state -match 'RUNNING') $state.Trim() `
        ("sc.exe start $ServiceName`n" +
         "A service that registers and then stops has written why to`n" +
         "%ProgramData%\URDS\agent.log - the SCM only reports that it stopped.")
}

# ------------------------------------------------------------- 11. canaries

Write-Section "Canaries"

# The agent seeds these itself on start, which is the only moment that can
# guarantee they exist before the observers do. This checks that it did, rather
# than seeding them again from here.
if (Test-Path $venvPython) {
    $canaryJson = (& $venvPython -m agent canary 2>&1) -join "`n"
    $total = 0
    $parseError = ''
    try {
        $total = [int]($canaryJson | ConvertFrom-Json).total
    } catch {
        # Keep the raw output. A parse failure here means the command printed
        # something other than its JSON, and that something is the diagnosis -
        # the first run of this installer swallowed "No module named agent" and
        # reported "0 canaries", which reads as a seeding problem.
        $parseError = $canaryJson
    }
    $expected = 20 * $resolvedPaths.Count
    Write-Result "decoys in place" ($total -ge $expected) "$total canaries across $($resolvedPaths.Count) root(s)" `
        ("Expected $expected. The service seeds them at start:`n" +
         "  sc.exe stop $ServiceName ; sc.exe start $ServiceName`n" +
         "or seed them by hand:  .venv\Scripts\python.exe -m agent canary --seed" +
         $(if ($parseError) { "`n`npython -m agent canary said:`n$parseError" } else { '' }))
    $script:Receipt.applied.canaries = $total
    Save-Receipt
}

# ------------------------------------------------------------ 12. self-test

Write-Section "Self-test"

if ($SkipSelfTest) {
    Write-Host "  Skipped by -SkipSelfTest." -ForegroundColor Yellow
    Write-Host "  This installation is unverified: nothing here has shown that the agent" -ForegroundColor Yellow
    Write-Host "  can name a real PID, freeze it, or restore a file. A skipped check is a" -ForegroundColor Yellow
    Write-Host "  failed check." -ForegroundColor Yellow
    $script:Failures++
    $script:Steps += [pscustomobject]@{ step = 'self-test'; ok = $false; detail = 'skipped by -SkipSelfTest' }
} elseif (Test-Path $venvPython) {
    Write-Host "  Writing a high-entropy file from a child process into a protected folder"
    Write-Host "  and asking the agent's own ledger what it did about it. Takes a minute."
    Write-Host ""
    & $venvPython (Join-Path $RepoRoot 'scripts\selftest.py')
    $selfTestExit = $LASTEXITCODE
    Write-Result "end-to-end self-test" ($selfTestExit -eq 0) "scripts/selftest.py exited $selfTestExit" `
        ("Each failed check above prints what to run next. The report is at`n" +
         "  $dataDir\selftest.json")
    $script:Receipt.applied.selftest_exit = $selfTestExit
    Save-Receipt
}

# ------------------------------------------------------------ 13. dashboard

if (-not $NoDashboard) {
    Write-Section "Dashboard"
    & powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $RepoRoot 'scripts\start_stack.ps1') -PortOffset $PortOffset
    $stackExit = $LASTEXITCODE
    Write-Result "services and dashboard" ($stackExit -eq 0) "start_stack.ps1 exited $stackExit" `
        ("powershell -ExecutionPolicy Bypass -File scripts\start_stack.ps1`n" +
         "Logs are in %ProgramData%\URDS\logs. The agent is unaffected either way:`n" +
         "the dashboard is the demonstration surface, not the protection path.")

    if ($stackExit -eq 0 -and (Test-Path $venvPython)) {
        # The dashboard signs its own token from .env; this is the same token,
        # for curl and for anything else that wants to talk to the gateway.
        $token = & $venvPython -c @"
import os, sys, datetime
sys.path.insert(0, r'$RepoRoot')
from jose import jwt
secret = None
for line in open(r'$envFile', encoding='utf-8'):
    if line.strip().startswith('JWT_SECRET='):
        secret = line.split('=', 1)[1].strip()
now = datetime.datetime.now(datetime.timezone.utc)
print(jwt.encode({'sub': 'installer', 'role': 'admin', 'tier': 'enterprise',
                  'iat': int(now.timestamp()),
                  'exp': int((now + datetime.timedelta(hours=8)).timestamp())},
                 secret, algorithm='HS256'))
"@ 2>$null
        $dashboardUrl = "http://localhost:$(8501 + $PortOffset)"
        Write-Host ""
        Write-Host "  Dashboard:  $dashboardUrl" -ForegroundColor White
        if ($token) {
            Write-Host "  Admin token (8 hours, for the gateway on :$(8000 + $PortOffset)):" -ForegroundColor White
            Write-Host "  $token" -ForegroundColor DarkGray
        }
        # Through explorer, not directly. This process is elevated, and a
        # browser launched from it inherits that - a browser running as
        # Administrator to look at a local dashboard is a worse idea than any
        # convenience it buys. explorer hands the URL to the logged-in user's
        # shell, which opens it at the user's own integrity level.
        Start-Process explorer.exe -ArgumentList $dashboardUrl
    }
}

# ----------------------------------------------------------------- the verdict

$script:Receipt.applied.steps = $script:Steps
$script:Receipt.applied.failures = $script:Failures
$script:Receipt.completed_at = (Get-Date).ToUniversalTime().ToString('o')
Save-Receipt

Write-Host ""
Write-Host ("=" * 72) -ForegroundColor DarkCyan
if ($script:Failures -gt 0) {
    Write-Host ""
    Write-Host "  $($script:Failures) step(s) failed. This machine is not protected." -ForegroundColor Red
    Write-Host ""
    Write-Host "  Every failure above prints the exact command to run next." -ForegroundColor Yellow
    Write-Host "  Transcript: $InstallLog" -ForegroundColor DarkGray
    Write-Host "  Receipt:    $ReceiptPath" -ForegroundColor DarkGray
    Write-Host "  Undo:       powershell -ExecutionPolicy Bypass -File `"$(Join-Path $RepoRoot 'uninstall.ps1')`"" -ForegroundColor DarkGray
    Stop-Transcript | Out-Null
    if ($Relaunched) { Read-Host "Press Enter to close" | Out-Null }
    exit 1
}

Write-Host ""
Write-Host "  Installed, and verified end to end." -ForegroundColor Green
Write-Host ""
Write-Host "  $ServiceName is running as SYSTEM and starts itself after a reboot." -ForegroundColor White
foreach ($path in $resolvedPaths) { Write-Host "  protecting $path" }
Write-Host ""
Write-Host "  status:     .venv\Scripts\python.exe -m agent status" -ForegroundColor DarkGray
Write-Host "  agent log:  $StateDir\agent.log" -ForegroundColor DarkGray
Write-Host "  receipt:    $ReceiptPath" -ForegroundColor DarkGray
Write-Host "  uninstall:  powershell -ExecutionPolicy Bypass -File `"$(Join-Path $RepoRoot 'uninstall.ps1')`"" -ForegroundColor DarkGray
Stop-Transcript | Out-Null
if ($Relaunched) { Read-Host "Press Enter to close" | Out-Null }
exit 0

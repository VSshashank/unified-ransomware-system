<#
.SYNOPSIS
    Start (or stop) the API services and the Streamlit dashboard on this host.

.DESCRIPTION
    `install.ps1` calls this at the end so that one run of the installer ends
    with something to look at. It is also the thing to run after a reboot if you
    want the dashboard back: the *agent* survives a reboot because it is a
    service, and these do not, deliberately.

    WHAT THIS IS, AND WHAT IT IS NOT

    These five processes are the demonstration and integration surface. They are
    not the protection path. The protection path is `urds-agent`, which runs as
    a Windows Service under SYSTEM, watches the protected folders, and suspends
    processes. Everything here can be stopped without reducing protection by
    anything at all.

    THE LEDGER THIS STARTS IS NOT THE AGENT'S LEDGER

    The obvious wiring - point the ledger service at the agent's database so the
    dashboard shows the real chain - corrupts that chain, and this was measured
    rather than assumed:

        two processes, 150 appends each, one file
        -> 300 blocks, verify_chain valid=False, first broken block 116

    `HashChainLedger.add_block` reads the tip and then inserts, and those are
    two statements, not one transaction. Python's sqlite3 does not open a
    transaction for the SELECT, so two writers in different processes read the
    same tip and both append with the same `previous_hash`. The in-process lock
    that makes this safe for one service does not cross a process boundary.

    It is not a hypothetical either: the dashboard POSTs `/predict` on every
    refresh, and the gateway's `/predict` writes a block. So a dashboard pointed
    at the agent's ledger would fork the agent's chain roughly every time
    somebody looked at it.

    So the ledger service here gets its own database (`data/ledger.db`), and the
    agent keeps sole ownership of its own. The dashboard says which one it is
    reading. `python -m agent status` reports the agent's chain; the ledger
    under `data/agent/` is the evidence, and `scripts/verify_reproduction.py`
    reads it directly.

    The Response service is deliberately not started. It has no authentication
    of its own - a POST to :8004/response/isolate from any local process is
    enough to act on a PID - and the agent is already the thing responding on
    this host. docker-compose.yml makes the same call for the same reason and
    puts it behind a `demo` profile. The dashboard will show it as unavailable,
    which is true.

.PARAMETER Stop
    Stop whatever a previous run started, by PID, from the record it wrote.

.PARAMETER NoDashboard
    Start the four backends and not Streamlit.

.PARAMETER TimeoutSeconds
    How long to wait for each service to answer /health.

.PARAMETER PortOffset
    Shift every port by this much: 8000-8003 and 8501 become 8100-8103 and 8601
    with -PortOffset 100.

    8000 is a popular number. On the machine this was developed on it was held
    by `splunkd`, and 8001, 8003 and 8501 by a Docker Desktop forwarder running
    this project's own compose stack. Moving is the polite answer - an installer
    that stops somebody else's software to claim a port has made a decision that
    was not its to make.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File scripts/start_stack.ps1

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File scripts/start_stack.ps1 -Stop
#>

[CmdletBinding()]
param(
    [switch]$Stop,
    [switch]$NoDashboard,
    [int]$TimeoutSeconds = 90,
    [int]$PortOffset = 0
)

$ErrorActionPreference = 'Stop'

$RepoRoot  = Split-Path -Parent $PSScriptRoot
$StateDir  = Join-Path $env:ProgramData 'URDS'
$StateFile = Join-Path $StateDir 'stack.json'
$LogDir    = Join-Path $StateDir 'logs'

function Write-Result {
    param([string]$Label, [bool]$Ok, [string]$Detail = '')
    $mark = if ($Ok) { '  ok  ' } else { ' FAIL ' }
    $line = "[$mark] $Label"
    if ($Detail) { $line += "  -  $Detail" }
    Write-Host $line -ForegroundColor $(if ($Ok) { 'Green' } else { 'Red' })
}

# ------------------------------------------------------------------- stopping

if ($Stop) {
    if (-not (Test-Path $StateFile)) {
        Write-Host "Nothing to stop: no $StateFile" -ForegroundColor DarkGray
        exit 0
    }
    $state = Get-Content $StateFile -Raw | ConvertFrom-Json
    $stopped = 0
    $stillUp = @()
    foreach ($entry in $state.processes) {
        $process = Get-Process -Id $entry.pid -ErrorAction SilentlyContinue
        # A PID on its own is not an identity - it is reused. The start time
        # recorded at launch is what says this is still the process we started
        # and not whatever inherited its number.
        if ($process -and $process.StartTime.ToString('o') -eq $entry.started_at) {
            # The children first, and this is not belt and braces.
            #
            # `.venv\Scripts\python.exe` is a launcher: it starts the real
            # interpreter as its own child, and that child is the one holding
            # the socket. Killing only the recorded PID killed the launcher and
            # left the server running - measured, on this machine: -Stop printed
            # "5 process(es) stopped" and all five ports were still listening
            # afterwards. A stop that reports success while the thing is still
            # up is worse than one that fails.
            $children = Get-CimInstance Win32_Process -Filter "ParentProcessId = $($entry.pid)" -ErrorAction SilentlyContinue
            foreach ($child in $children) {
                Stop-Process -Id $child.ProcessId -Force -ErrorAction SilentlyContinue
            }
            Stop-Process -Id $entry.pid -Force -ErrorAction SilentlyContinue
            $stopped++
            Write-Host "  stopped $($entry.name) (pid $($entry.pid)$(if ($children) { " + $(@($children).Count) child(ren)" }))"
        } else {
            Write-Host "  $($entry.name) (pid $($entry.pid)) is already gone" -ForegroundColor DarkGray
        }
    }

    # Checked, not assumed. The port going quiet is the effect; the PID going
    # away is only the setting.
    Start-Sleep -Milliseconds 500
    foreach ($entry in $state.processes) {
        $holder = Get-NetTCPConnection -State Listen -LocalPort $entry.port -ErrorAction SilentlyContinue |
            Select-Object -First 1
        if ($holder) {
            $owner = Get-Process -Id $holder.OwningProcess -ErrorAction SilentlyContinue
            $stillUp += "$($entry.name) :$($entry.port) still held by $(if ($owner) { $owner.ProcessName } else { 'pid ' + $holder.OwningProcess }) (pid $($holder.OwningProcess))"
        }
    }

    Remove-Item $StateFile -Force -ErrorAction SilentlyContinue
    Write-Host ""
    if ($stillUp.Count -gt 0) {
        Write-Host "$stopped process(es) stopped, but these ports are still in use:" -ForegroundColor Red
        foreach ($row in $stillUp) { Write-Host "  $row" -ForegroundColor Red }
        Write-Host "The agent service is untouched." -ForegroundColor Cyan
        exit 1
    }
    Write-Host "$stopped process(es) stopped. The agent service is untouched." -ForegroundColor Cyan
    exit 0
}

# ------------------------------------------------------------------- starting

$python = Join-Path $RepoRoot '.venv\Scripts\python.exe'
if (-not (Test-Path $python)) {
    Write-Host "No interpreter at $python. Run install.ps1 first." -ForegroundColor Red
    exit 2
}

New-Item -ItemType Directory -Force -Path $LogDir | Out-Null

# Anything a previous run left behind goes first. Without this, re-running the
# installer leaks a process per service per run, and each one holds the port the
# next one needs - so the second install of the day fails on ports its own
# first install is sitting on.
if (Test-Path $StateFile) {
    Write-Host "  stopping what a previous run started" -ForegroundColor DarkGray
    & $PSCommandPath -Stop | Out-Null
}

# The token the dashboard signs with has to be the one the gateway verifies, so
# both read the same .env. A mismatch here produces a dashboard that shows
# nothing but 401s, which reads like a broken install rather than a wrong key.
$envFile = Join-Path $RepoRoot '.env'
$settings = @{}
if (Test-Path $envFile) {
    foreach ($line in Get-Content $envFile) {
        if ($line -match '^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$') {
            $settings[$Matches[1]] = $Matches[2].Trim()
        }
    }
}
$jwtSecret = $settings['JWT_SECRET']
if (-not $jwtSecret) { $jwtSecret = 'dev-only-change-me' }

# Shared by every child through inheritance.
$env:JWT_SECRET    = $jwtSecret
$env:JWT_ALGORITHM = 'HS256'
$env:URDS_ENV      = if ($settings['URDS_ENV']) { $settings['URDS_ENV'] } else { 'development' }
$env:MONITOR_URL   = "http://127.0.0.1:$(8001 + $PortOffset)"
$env:ML_URL        = "http://127.0.0.1:$(8002 + $PortOffset)"
$env:LEDGER_URL    = "http://127.0.0.1:$(8003 + $PortOffset)"
$env:RESPONSE_URL  = "http://127.0.0.1:$(8004 + $PortOffset)"
$env:GATEWAY_URL   = "http://127.0.0.1:$(8000 + $PortOffset)"
$env:LOG_LEVEL     = 'INFO'

# Its own database. See the header for the measurement behind that.
$env:LEDGER_DB_PATH = Join-Path $RepoRoot 'data\ledger.db'
$env:MODEL_DIR      = Join-Path $RepoRoot 'models'
$env:WATCH_PATH     = Join-Path $RepoRoot 'watched_files'

$started = @()

function Start-Backend {
    param(
        [string]$Name,
        [string]$WorkingDirectory,
        [string[]]$Arguments,
        [int]$Port
    )

    $out = Join-Path $LogDir "$Name.out.log"
    $err = Join-Path $LogDir "$Name.err.log"
    $process = Start-Process -FilePath $python -ArgumentList $Arguments `
        -WorkingDirectory $WorkingDirectory -WindowStyle Hidden -PassThru `
        -RedirectStandardOutput $out -RedirectStandardError $err
    $script:started += [pscustomobject]@{
        name       = $Name
        pid        = $process.Id
        port       = $Port
        started_at = $process.StartTime.ToString('o')
        log        = $out
        error_log  = $err
    }
    return $process
}

function Get-PortHolder {
    <#
        Who is already listening on this port, if anybody.

        Worth doing before starting anything, because the alternative is a
        ninety-second wait ending in "no answer". Measured on the development
        machine: :8000 was held by `splunkd` and :8001, :8003 and :8501 by a
        Docker Desktop port forwarder running this project's own compose stack.
    #>
    param([int]$Port)
    $listener = Get-NetTCPConnection -State Listen -LocalPort $Port -ErrorAction SilentlyContinue |
        Select-Object -First 1
    if (-not $listener) { return $null }
    $owner = Get-Process -Id $listener.OwningProcess -ErrorAction SilentlyContinue
    return [pscustomobject]@{
        Pid  = $listener.OwningProcess
        Name = if ($owner) { $owner.ProcessName } else { 'unknown' }
    }
}

function Test-OwnsPort {
    <#
        Is the process we started the one listening on this port?

        This is the check that matters, and its absence produced a false pass:
        the monitor and the ledger failed to bind because a container already
        held :8001 and :8003, and the health probe cheerfully got a 200 - from
        the container. Two services reported up, neither of them ours, and the
        dashboard would have been reading somebody else's stack.
    #>
    param([int]$Port, [int]$ProcessId)
    $holder = Get-PortHolder -Port $Port
    if (-not $holder) { return $false }
    if ($holder.Pid -eq $ProcessId) { return $true }
    # uvicorn with reload, and the venv launcher, both put the listener in a
    # child. Walk up one generation before calling it somebody else's.
    $parent = (Get-CimInstance Win32_Process -Filter "ProcessId = $($holder.Pid)" -ErrorAction SilentlyContinue).ParentProcessId
    return ($parent -eq $ProcessId)
}

function Wait-ForHealth {
    param([string]$Name, [int]$Port, [string]$Path = '/health', [int]$Seconds)
    $deadline = (Get-Date).AddSeconds($Seconds)
    while ((Get-Date) -lt $deadline) {
        try {
            # 15 seconds, not 3. The gateway's /health fans out to every
            # downstream service and waits for each, and with the Response
            # service deliberately not started it took 3.7s to answer on this
            # machine - just over a 3-second client timeout. The request threw
            # `The operation has timed out`, whose exception carries no
            # Response and therefore no status code, so the 503 branch below
            # never saw it and a gateway that was up and serving was reported
            # as "no answer in 90s".
            $response = Invoke-WebRequest -Uri "http://127.0.0.1:$Port$Path" -TimeoutSec 15 -UseBasicParsing
            return $true
        } catch {
            # Any HTTP status is an answer. The question here is whether
            # something is serving on this port, not whether it likes what it
            # found downstream - the gateway reports `degraded` by design while
            # the Response service is not running.
            if ($null -ne $_.Exception.Response -and
                $null -ne $_.Exception.Response.StatusCode) { return $true }
        }
        Start-Sleep -Milliseconds 500
    }
    return $false
}

Write-Host ""
Write-Host "URDS services (the demonstration surface, not the protection path)" -ForegroundColor Cyan
Write-Host ""

$backends = @(
    @{ Name = 'ledger';    Dir = 'services\ledger';    Module = 'main:app'; Port = 8003 + $PortOffset },
    @{ Name = 'ml-engine'; Dir = 'services\ml-engine'; Module = 'app:app';  Port = 8002 + $PortOffset },
    @{ Name = 'monitor';   Dir = 'services\monitor';   Module = 'app:app';  Port = 8001 + $PortOffset },
    @{ Name = 'gateway';   Dir = 'services\gateway';   Module = 'main:app'; Port = 8000 + $PortOffset }
)

$failures = 0
$taken = @()

# Every port, before anything starts. A port that is already busy is a fact
# available in a millisecond; finding it out from a health-check timeout costs
# ninety seconds and names the wrong cause.
foreach ($backend in $backends) {
    $holder = Get-PortHolder -Port $backend.Port
    if ($holder) {
        $taken += $backend.Name
        Write-Result "$($backend.Name) on :$($backend.Port)" $false `
            "port already held by $($holder.Name) (pid $($holder.Pid))"
        Write-Host "         Stop that process, or free the port, and re-run this script." -ForegroundColor Yellow
        Write-Host "         If it is this project's own containers:  docker compose down" -ForegroundColor Yellow
        Write-Host "         Or move out of its way:  -PortOffset 100" -ForegroundColor Yellow
        $failures++
    }
}

foreach ($backend in $backends) {
    if ($taken -contains $backend.Name) { continue }
    Start-Backend -Name $backend.Name `
        -WorkingDirectory (Join-Path $RepoRoot $backend.Dir) `
        -Arguments @('-m', 'uvicorn', $backend.Module, '--host', '127.0.0.1',
                     '--port', "$($backend.Port)") `
        -Port $backend.Port | Out-Null
}

foreach ($entry in $started) {
    $ok = Wait-ForHealth -Name $entry.name -Port $entry.port -Seconds $TimeoutSeconds
    # Answering is not enough. Something else answering on that port is the
    # failure this check exists to catch.
    $ours = Test-OwnsPort -Port $entry.port -ProcessId $entry.pid
    $alive = [bool](Get-Process -Id $entry.pid -ErrorAction SilentlyContinue)
    $detail = if (-not $ok) {
        "no answer in ${TimeoutSeconds}s - see $($entry.error_log)"
    } elseif (-not $alive) {
        "the process we started (pid $($entry.pid)) has exited - see $($entry.error_log)"
    } elseif (-not $ours) {
        $holder = Get-PortHolder -Port $entry.port
        "something answered on :$($entry.port), but it is $($holder.Name) (pid $($holder.Pid)), not the process we started"
    } else {
        "pid $($entry.pid)"
    }
    Write-Result "$($entry.name) on :$($entry.port)" ($ok -and $alive -and $ours) $detail
    if (-not ($ok -and $alive -and $ours)) { $failures++ }
}

if (-not $NoDashboard) {
    $streamlit = Join-Path $RepoRoot '.venv\Scripts\streamlit.exe'
    $dashboardPort = 8501 + $PortOffset
    $dashboardHolder = Get-PortHolder -Port $dashboardPort
    if ($dashboardHolder) {
        Write-Result 'dashboard on :8501' $false `
            "port already held by $($dashboardHolder.Name) (pid $($dashboardHolder.Pid)); try -PortOffset 100"
        $failures++
    } elseif (Test-Path $streamlit) {
        $out = Join-Path $LogDir 'dashboard.out.log'
        $err = Join-Path $LogDir 'dashboard.err.log'
        $process = Start-Process -FilePath $streamlit `
            -ArgumentList @('run', 'app.py', '--server.address=127.0.0.1', "--server.port=$dashboardPort", '--server.headless=true') `
            -WorkingDirectory (Join-Path $RepoRoot 'services\dashboard') -WindowStyle Hidden -PassThru `
            -RedirectStandardOutput $out -RedirectStandardError $err
        $started += [pscustomobject]@{
            name = 'dashboard'; pid = $process.Id; port = $dashboardPort
            started_at = $process.StartTime.ToString('o'); log = $out; error_log = $err
        }
        $ok = Wait-ForHealth -Name 'dashboard' -Port $dashboardPort -Path '/' -Seconds $TimeoutSeconds
        Write-Result "dashboard on :$dashboardPort" $ok $(if ($ok) { "pid $($process.Id)" } else { "no answer in ${TimeoutSeconds}s - see $err" })
        if (-not $ok) { $failures++ }
    } else {
        Write-Result "dashboard on :$dashboardPort" $false "no streamlit.exe at $streamlit"
        $failures++
    }
}

New-Item -ItemType Directory -Force -Path $StateDir | Out-Null
@{
    written_at = (Get-Date).ToUniversalTime().ToString('o')
    repo       = $RepoRoot
    ledger_db  = $env:LEDGER_DB_PATH
    port_offset = $PortOffset
    note       = 'The demonstration stack. Not the protection path, and not the agent ledger.'
    processes  = $started
} | ConvertTo-Json -Depth 5 | Set-Content -Path $StateFile -Encoding utf8

Write-Host ""
Write-Host "record: $StateFile"
Write-Host "logs:   $LogDir"
Write-Host ""
Write-Host "The Response service is not started on purpose - it has no authentication" -ForegroundColor DarkGray
Write-Host "of its own and the agent is the responder here. The dashboard shows it as" -ForegroundColor DarkGray
Write-Host "unavailable, which is accurate." -ForegroundColor DarkGray

if ($failures -gt 0) {
    Write-Host ""
    Write-Host "$failures service(s) did not come up." -ForegroundColor Red
    exit 1
}
exit 0

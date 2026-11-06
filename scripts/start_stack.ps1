<#
Start all six URDS services natively on Windows, no Docker, from one elevated
PowerShell. Services run as children of this elevated shell, so they inherit
Administrator rights and never prompt again. Then it starts the Monitor
watching watched_files and opens the projector page.

    powershell -ExecutionPolicy Bypass -File scripts\start_stack.ps1
    powershell -ExecutionPolicy Bypass -File scripts\start_stack.ps1 -Lan        # dashboard reachable from other machines
    powershell -ExecutionPolicy Bypass -File scripts\start_stack.ps1 -NoBrowser

Logs: run\logs\<service>.err.log. Stop with scripts\stop_stack.ps1.
Safe to re-run: anything already on the six ports is stopped first.
VSS stays real: RECOVERY_SNAPSHOT_ROOT is deliberately left unset.
#>
param(
    [string]$Watch = "",
    [string]$Run = "",
    [switch]$Lan,
    [switch]$NoBrowser,
    [switch]$NoWatch
)

$ErrorActionPreference = "Continue"
$ProgressPreference = "SilentlyContinue"
$Repo = Split-Path -Parent $PSScriptRoot
if (-not $Watch) { $Watch = Join-Path $Repo "watched_files" }
if (-not $Run) { $Run = Join-Path $Repo "run" }
$Py = Join-Path $Repo ".venv\Scripts\python.exe"

$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $admin) { Write-Host "Not elevated. Open PowerShell with 'Run as administrator' and run this again." -ForegroundColor Red; exit 1 }
if (-not (Test-Path $Py)) { Write-Host "No .venv at $Py. Run scripts\setup_vm.ps1 first." -ForegroundColor Red; exit 1 }

# Anything left over from an earlier run would hold the ports.
& powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot "stop_stack.ps1") -Run $Run -Quiet

New-Item -ItemType Directory -Force $Watch, (Join-Path $Run "data"), (Join-Path $Run "logs") | Out-Null

$env:ML_URL = "http://127.0.0.1:8002"; $env:LEDGER_URL = "http://127.0.0.1:8003"
$env:RESPONSE_URL = "http://127.0.0.1:8004"; $env:MONITOR_URL = "http://127.0.0.1:8001"
$env:GATEWAY_URL = "http://127.0.0.1:8000"
$env:WATCH_PATH = $Watch
$env:LEDGER_DB_PATH = Join-Path $Run "data\ledger.db"
$env:BEHAVIORAL_MODEL_PATH = Join-Path $Repo "models\behavioral_model.pkl"
$env:MODEL_PATH = Join-Path $Repo "models\xgboost_model.pkl"
$env:MODEL_DIR = Join-Path $Repo "models"
$env:URDS_ENV = "development"; $env:ALLOW_DEV_TOKENS = "true"
$env:JWT_SECRET = "dev-only-change-me"; $env:DEV_TOKEN_BOOTSTRAP_SECRET = "dev-bootstrap-change-me"
$env:RESPONSE_ISOLATION_ENABLED = "false"
$env:URDS_EXHIBITION_STATE = Join-Path $Run "exhibition_state.json"
# A cp1252/cp437 console cannot print every character the services log.
$env:PYTHONUTF8 = "1"; $env:PYTHONUNBUFFERED = "1"
Remove-Item Env:\URDS_WRITE_REPORTS -ErrorAction SilentlyContinue
Remove-Item Env:\RECOVERY_SNAPSHOT_ROOT -ErrorAction SilentlyContinue

if (-not (Test-Path $env:BEHAVIORAL_MODEL_PATH)) {
    Write-Warning "No behavioural model at $($env:BEHAVIORAL_MODEL_PATH): ML /predict will return 503. Run: .venv\Scripts\python.exe src\train_behavioral_model.py"
}

# 127.0.0.1 keeps Windows Firewall from popping up a dialog on the projector.
$dashAddress = if ($Lan) { "0.0.0.0" } else { "127.0.0.1" }
$services = @(
    @{ n = "ledger";    dir = "services\ledger";    args = "-m uvicorn main:app --host 127.0.0.1 --port 8003"; port = 8003; health = "/health" },
    @{ n = "ml-engine"; dir = "services\ml-engine"; args = "-m uvicorn app:app --host 127.0.0.1 --port 8002";  port = 8002; health = "/health" },
    @{ n = "response";  dir = "services\response";  args = "-m uvicorn app:app --host 127.0.0.1 --port 8004";  port = 8004; health = "/health" },
    @{ n = "monitor";   dir = "services\monitor";   args = "-m uvicorn app:app --host 127.0.0.1 --port 8001";  port = 8001; health = "/health" },
    @{ n = "gateway";   dir = "services\gateway";   args = "-m uvicorn main:app --host 127.0.0.1 --port 8000"; port = 8000; health = "/health" },
    @{ n = "dashboard"; dir = "services\dashboard"; args = "-m streamlit run app.py --server.port 8501 --server.address $dashAddress --server.headless true --browser.gatherUsageStats false --server.fileWatcherType none"; port = 8501; health = "/_stcore/health" }
)

$pids = @()
foreach ($s in $services) {
    $log = Join-Path $Run "logs\$($s.n)"
    $p = Start-Process -FilePath $Py -ArgumentList $s.args -WorkingDirectory (Join-Path $Repo $s.dir) `
        -RedirectStandardOutput "$log.out.log" -RedirectStandardError "$log.err.log" -WindowStyle Hidden -PassThru
    $pids += $p.Id
    Write-Host "started $($s.n) (pid $($p.Id))"
}
$pids | Set-Content (Join-Path $Run "pids.txt")

# Test-NetConnection pings first and takes seconds per call; a plain HTTP GET is instant.
function Test-Up([int]$port, [string]$path) {
    try {
        $r = Invoke-WebRequest -UseBasicParsing -Uri "http://127.0.0.1:$port$path" -TimeoutSec 3
        return $r.StatusCode -lt 500
    } catch {
        # The gateway answers 503 while a downstream service is still loading; that still means it is up.
        if ($_.Exception.Response) { return $true }
        return $false
    }
}

Write-Host "`nwaiting for the services (the ML engine can take ~30 s on a small VM) ..."
$allUp = $true
foreach ($s in $services) {
    $deadline = (Get-Date).AddSeconds(120)
    $up = $false
    while ((Get-Date) -lt $deadline) {
        if (Test-Up $s.port $s.health) { $up = $true; break }
        Start-Sleep -Milliseconds 500
    }
    if ($up) {
        Write-Host ("  {0,-10} :{1}  UP" -f $s.n, $s.port) -ForegroundColor Green
    } else {
        $allUp = $false
        Write-Host ("  {0,-10} :{1}  NOT UP - last lines of {2}:" -f $s.n, $s.port, "$Run\logs\$($s.n).err.log") -ForegroundColor Red
        Get-Content (Join-Path $Run "logs\$($s.n).err.log") -Tail 15 -ErrorAction SilentlyContinue | ForEach-Object { Write-Host "      $_" }
    }
}
if (-not $allUp) { exit 1 }

if (-not $NoWatch) {
    Write-Host ""
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot "start_watching.ps1") -Watch $Watch
}

Write-Host "`nWatch folder : $Watch"
Write-Host "Dashboard    : http://localhost:8501"
Write-Host "Projector    : http://localhost:8501/Exhibition_Story"
Write-Host "Guided demo  : powershell -ExecutionPolicy Bypass -File scripts\exhibition_demo.ps1"
if (-not $NoBrowser) { Start-Process "http://localhost:8501/Exhibition_Story" }
exit 0

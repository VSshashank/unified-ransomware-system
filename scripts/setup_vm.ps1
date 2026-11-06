<#
One command on a fresh Windows VM: installs Python 3.13 if needed, builds the
venv, installs every service's requirements, makes sure the ML model exists,
adds the Defender exclusions and the audit rule, then starts the stack.

Run from an ELEVATED PowerShell, from the repo root:

    powershell -ExecutionPolicy Bypass -File scripts\setup_vm.ps1

Safe to re-run: every step checks first and skips what is already done.

Flags:
    -SkipInstall   Never install Python (use one that is already there).
    -NoStart       Prepare everything but do not start the services.
    -Wheels <dir>  Install packages from a local wheelhouse (offline VM).

Why Python 3.13 exactly: the pinned numpy 2.5.1 has no wheel for 3.11, and
pandas 2.2.3 has none for 3.14, so pip would try to compile them and fail.
3.12 also works. The Microsoft Store "python.exe" stub is ignored on purpose.
#>
param(
    [switch]$SkipInstall,
    [switch]$NoStart,
    [string]$Wheels = ""
)

# "Continue", not "Stop": under Windows PowerShell 5.1 a native tool (pip, git)
# writing a harmless warning to stderr becomes a terminating error under "Stop".
# Every step below checks its own result instead.
$ErrorActionPreference = "Continue"
$ProgressPreference = "SilentlyContinue"
$Repo = Split-Path -Parent $PSScriptRoot
Set-Location $Repo
$env:PYTHONUTF8 = "1"
$env:PIP_DISABLE_PIP_VERSION_CHECK = "1"

function Step($m) { Write-Host "`n=== $m" -ForegroundColor Cyan }
function Ok($m) { Write-Host "  OK   $m" -ForegroundColor Green }
function Warn($m) { Write-Host "  WARN $m" -ForegroundColor Yellow }
function Die($m) { Write-Host "`n  FAILED: $m" -ForegroundColor Red; exit 1 }
function RefreshPath {
    $env:Path = [Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [Environment]::GetEnvironmentVariable("Path", "User")
}

$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $admin) { Die "Not elevated. Open PowerShell with 'Run as administrator' and run this again." }

function Get-PyVersion([string]$exe) {
    try {
        $v = & $exe -c "import sys; print('%d.%d' % sys.version_info[:2])" 2>$null
        if ($LASTEXITCODE -eq 0) { return ("$v").Trim() }
    } catch {}
    return $null
}

# A real CPython 3.13 or 3.12, never the WindowsApps Store stub.
function Find-Python {
    $candidates = New-Object System.Collections.Generic.List[string]
    if (Get-Command py -ErrorAction SilentlyContinue) {
        foreach ($v in "3.13", "3.12") {
            try {
                $p = & py "-$v" -c "import sys; print(sys.executable)" 2>$null
                if ($LASTEXITCODE -eq 0 -and $p) { $candidates.Add(("$p").Trim()) }
            } catch {}
        }
    }
    foreach ($ver in "313", "312") {
        $candidates.Add("$env:ProgramFiles\Python$ver\python.exe")
        $candidates.Add("$env:LOCALAPPDATA\Programs\Python\Python$ver\python.exe")
    }
    Get-Command python -All -CommandType Application -ErrorAction SilentlyContinue |
        Where-Object { $_.Source -notlike "*\WindowsApps\*" } |
        ForEach-Object { $candidates.Add($_.Source) }
    foreach ($c in $candidates) {
        if ($c -and (Test-Path $c) -and ((Get-PyVersion $c) -in @("3.13", "3.12"))) { return $c }
    }
    return $null
}

Step "1/7 Python 3.13"
RefreshPath
$BasePy = Find-Python
if (-not $BasePy -and -not $SkipInstall) {
    $installed = $false
    if (Get-Command winget -ErrorAction SilentlyContinue) {
        Write-Host "  installing Python 3.13 with winget ..."
        & winget install --id Python.Python.3.13 -e --silent --scope machine --accept-package-agreements --accept-source-agreements
        RefreshPath
        $BasePy = Find-Python
        $installed = [bool]$BasePy
    }
    if (-not $installed) {
        # winget is missing or broken on many fresh VM images; python.org always works.
        $ver = "3.13.9"
        $exe = Join-Path $env:TEMP "python-$ver-amd64.exe"
        Write-Host "  downloading Python $ver from python.org ..."
        try {
            [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
            Invoke-WebRequest -UseBasicParsing -Uri "https://www.python.org/ftp/python/$ver/python-$ver-amd64.exe" -OutFile $exe
        } catch { Die "could not download Python: $_" }
        Write-Host "  installing (about a minute) ..."
        $p = Start-Process -FilePath $exe -ArgumentList "/quiet", "InstallAllUsers=1", "PrependPath=1", "Include_launcher=1", "Include_test=0" -Wait -PassThru
        if ($p.ExitCode -ne 0) { Die "Python installer exited with $($p.ExitCode)" }
        RefreshPath
        $BasePy = Find-Python
    }
}
if (-not $BasePy) { Die "No Python 3.13/3.12 found. Install Python 3.13 (64-bit) from python.org, then re-run this script." }
Ok "Python $(Get-PyVersion $BasePy) at $BasePy"

Step "2/7 Virtual environment"
$Py = Join-Path $Repo ".venv\Scripts\python.exe"
if (Test-Path $Py) {
    $venvVer = Get-PyVersion $Py
    if ($venvVer -notin @("3.13", "3.12")) {
        Warn ".venv was built with Python '$venvVer' - rebuilding it"
        Remove-Item (Join-Path $Repo ".venv") -Recurse -Force
    }
}
if (-not (Test-Path $Py)) {
    & $BasePy -m venv (Join-Path $Repo ".venv")
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path $Py)) { Die "python -m venv failed" }
}
& $Py -m pip install --upgrade pip --quiet
Ok ".venv ready ($(Get-PyVersion $Py))"

Step "3/7 Python packages (all six services + scripts) - the slow part"
$reqs = @("gateway", "monitor", "ml-engine", "ledger", "response", "dashboard") | ForEach-Object { "-r"; "services\$_\requirements.txt" }
$reqs += @("-r", "scripts\requirements.txt")
$pipArgs = @("-m", "pip", "install", "--retries", "5", "--timeout", "60", "--prefer-binary") + $reqs + @("httpx")
if ($Wheels) { $pipArgs = @("-m", "pip", "install", "--no-index", "--find-links", $Wheels) + $reqs + @("httpx") }
& $Py @pipArgs
if ($LASTEXITCODE -ne 0) { Die "pip install failed (scroll up for the first red error). Check the VM has internet, then re-run." }
& $Py -c "import fastapi, uvicorn, streamlit, xgboost, sklearn, watchdog, psutil, httpx, win32evtlog; print('imports ok')"
if ($LASTEXITCODE -ne 0) { Die "packages installed but do not import - see the error above" }
Ok "packages installed"

Step "4/7 ML model"
if (Test-Path "models\behavioral_model.pkl") {
    Ok "models\behavioral_model.pkl present"
} else {
    Write-Host "  not found; training it now (a few minutes) ..."
    & $Py src\train_behavioral_model.py
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path "models\behavioral_model.pkl")) {
        Die "model training failed; copy the models\ folder from your laptop into $Repo and re-run"
    }
    Ok "model trained"
}

Step "5/7 Folders and Windows Defender exclusions"
New-Item -ItemType Directory -Force watched_files, run | Out-Null
try {
    Add-MpPreference -ExclusionPath $Repo -ErrorAction Stop
    # The simulator behaves like ransomware on purpose; without these Defender's
    # behaviour monitor can kill or quarantine it before URDS gets to act.
    Add-MpPreference -ExclusionProcess $Py -ErrorAction Stop
    Add-MpPreference -ExclusionProcess $BasePy -ErrorAction Stop
    Ok "Defender exclusions added for $Repo and the Python processes"
} catch { Warn "Could not add Defender exclusions ($_). If simulator files vanish, add $Repo by hand." }

Step "6/7 File-audit rule (lets the Monitor name - and stop - the writing process)"
$watch = Join-Path $Repo "watched_files"
& powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts\setup_attribution_audit.ps1 -WatchPath $watch
& powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts\setup_attribution_audit.ps1 -WatchPath $watch -Verify
if ($LASTEXITCODE -ne 0) { Warn "audit verification reported a problem: detection still works, but attackers will not be stopped" }

# Lets ". .\scripts\start_watching.ps1" (dot-sourcing) work in later windows.
try { Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned -Force -ErrorAction Stop } catch { Warn "could not set the execution policy ($_)" }

Step "7/7 Start the stack"
if ($NoStart) { Write-Host "skipped (-NoStart). Start later with:  powershell -ExecutionPolicy Bypass -File scripts\start_stack.ps1"; exit 0 }
& powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts\start_stack.ps1
if ($LASTEXITCODE -ne 0) { Die "the stack did not come up - see the NOT UP lines above" }

Write-Host "`nREADY." -ForegroundColor Green
Write-Host "Run the guided exhibition demo:   powershell -ExecutionPolicy Bypass -File scripts\exhibition_demo.ps1"
Write-Host "Dashboard:                        http://localhost:8501"

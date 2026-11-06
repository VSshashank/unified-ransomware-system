<#
The guided exhibition demo. Runs scripts\exhibition_demo.py with the venv's
Python; the projector page (http://localhost:8501/Exhibition_Story) follows
along step by step.

    powershell -ExecutionPolicy Bypass -File scripts\exhibition_demo.ps1                 # presenter mode: Enter = next step
    powershell -ExecutionPolicy Bypass -File scripts\exhibition_demo.ps1 --auto --loop   # unattended kiosk loop
    powershell -ExecutionPolicy Bypass -File scripts\exhibition_demo.ps1 --steps 2,6     # just some steps
    powershell -ExecutionPolicy Bypass -File scripts\exhibition_demo.ps1 --reset         # clean up between visitors
    powershell -ExecutionPolicy Bypass -File scripts\exhibition_demo.ps1 --help
#>
$Repo = Split-Path -Parent $PSScriptRoot
$Py = Join-Path $Repo ".venv\Scripts\python.exe"
if (-not (Test-Path $Py)) { Write-Host "No .venv - run scripts\setup_vm.ps1 first." -ForegroundColor Red; exit 1 }
$env:PYTHONUTF8 = "1"
$env:PYTHONUNBUFFERED = "1"
Set-Location $Repo
& $Py (Join-Path $Repo "scripts\exhibition_demo.py") @args
exit $LASTEXITCODE

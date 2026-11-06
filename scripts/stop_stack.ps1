<#
Stop the services started by scripts\start_stack.ps1.

    powershell -ExecutionPolicy Bypass -File scripts\stop_stack.ps1
#>
param([string]$Run = "", [switch]$Quiet)
$ErrorActionPreference = "Continue"
$Repo = Split-Path -Parent $PSScriptRoot
if (-not $Run) { $Run = Join-Path $Repo "run" }
$f = Join-Path $Run "pids.txt"
if (Test-Path $f) {
    foreach ($id in Get-Content $f) {
        if ($id -match '^\d+$') { Stop-Process -Id ([int]$id) -Force -ErrorAction SilentlyContinue }
    }
    Remove-Item $f -ErrorAction SilentlyContinue
}
# Streamlit/uvicorn (and the venv launcher's child interpreter) can outlive the PID
# we recorded; free the ports too.
foreach ($port in 8000, 8001, 8002, 8003, 8004, 8501) {
    Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue |
        ForEach-Object { if ($_.OwningProcess -gt 4) { Stop-Process -Id $_.OwningProcess -Force -ErrorAction SilentlyContinue } }
}
Start-Sleep -Milliseconds 500
if (-not $Quiet) { Write-Host "stopped" }

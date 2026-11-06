<#
Mint an admin token and start the Monitor watching watched_files.
start_stack.ps1 already does this; run it again after a restart of the Monitor,
or dot-source it to keep $t (token) and $h (headers) in your window:

    . .\scripts\start_watching.ps1
    powershell -ExecutionPolicy Bypass -File scripts\start_watching.ps1
#>
param([string]$Watch = "")
$Repo = Split-Path -Parent $PSScriptRoot
if (-not $Watch) { $Watch = Join-Path $Repo "watched_files" }
New-Item -ItemType Directory -Force $Watch | Out-Null

$token = $null
$deadline = (Get-Date).AddSeconds(60)
while (-not $token -and (Get-Date) -lt $deadline) {
    try {
        $token = (Invoke-RestMethod -Method Post http://127.0.0.1:8000/auth/token -ContentType "application/json" `
            -Headers @{"X-Bootstrap-Secret" = "dev-bootstrap-change-me"} `
            -Body '{"sub":"demo","role":"admin","tier":"enterprise"}' -TimeoutSec 5).access_token
    } catch { Start-Sleep -Seconds 1 }
}
if (-not $token) { Write-Host "Gateway on :8000 is not answering. Start the stack first: scripts\start_stack.ps1" -ForegroundColor Red; return }
$global:t = $token
$global:h = @{Authorization = "Bearer $token"}

try {
    $r = Invoke-RestMethod -Method Post http://127.0.0.1:8000/monitor/start -Headers $global:h -ContentType "application/json" `
        -Body (@{watch_path = $Watch; recursive = $true; file_patterns = @()} | ConvertTo-Json) -TimeoutSec 15
    Write-Host "Monitor watching $($r.watch_path) ($($r.monitor_id))" -ForegroundColor Green
} catch {
    Write-Host "Could not start the Monitor: $_" -ForegroundColor Red
    return
}

try {
    $a = Invoke-RestMethod http://127.0.0.1:8001/monitor/attribution -TimeoutSec 5
    if ($a.available) {
        Write-Host "Attribution LIVE ($($a.source)): URDS can name and stop the attacking process." -ForegroundColor Green
    } else {
        Write-Host "Attribution NOT available: $($a.error)" -ForegroundColor Yellow
        Write-Host "  Detection, AI and the ledger still work, but no process will be killed." -ForegroundColor Yellow
        Write-Host "  Fix: run this window as Administrator and re-run scripts\setup_vm.ps1 -SkipInstall -NoStart" -ForegroundColor Yellow
    }
} catch { Write-Host "Could not read attribution status: $_" -ForegroundColor Yellow }

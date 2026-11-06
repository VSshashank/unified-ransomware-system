<#
One-line install on a fresh Windows VM. Paste this into an ELEVATED PowerShell
("Run as administrator"); it is short on purpose so it survives copy/paste
from a PDF:

    irm https://raw.githubusercontent.com/VSshashank/unified-ransomware-system/main/scripts/bootstrap_vm.ps1 | iex

What it does:
  1. downloads the repository to C:\urds (git clone when Git is installed,
     otherwise the GitHub ZIP - no Git and no winget needed for this step);
     an existing C:\urds is updated in place and keeps its .venv, models\ and run\
  2. runs scripts\setup_vm.ps1, which installs Python 3.13 if needed, builds
     the venv, trains the model, sets up auditing and starts the stack.

Options (set before the command, in the same window):
    $env:URDS_DEST = "D:\urds"         # install somewhere else
    $env:URDS_BRANCH = "my-branch"     # rehearse a branch before it is merged
    $env:URDS_NOSTART = "1"            # prepare everything, start nothing
#>
& {
    $Dest = if ($env:URDS_DEST) { $env:URDS_DEST } else { "C:\urds" }
    $Branch = if ($env:URDS_BRANCH) { $env:URDS_BRANCH } else { "main" }
    $RepoSlug = "VSshashank/unified-ransomware-system"
    $NoStart = [bool]$env:URDS_NOSTART

    $ErrorActionPreference = "Stop"
    $ProgressPreference = "SilentlyContinue"   # PS 5.1's progress bar makes downloads ~10x slower
    try { [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12 } catch {}

    $admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $admin) {
        Write-Host "Not elevated. Close this window, right-click PowerShell, choose 'Run as administrator', and paste the command again." -ForegroundColor Red
        return
    }

    # Scripts in this window may run; nothing changes machine-wide.
    Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force

    Write-Host "`n=== Getting the code into $Dest" -ForegroundColor Cyan
    $git = Get-Command git -ErrorAction SilentlyContinue
    if ((Test-Path (Join-Path $Dest ".git")) -and $git) {
        Push-Location $Dest
        & git fetch origin $Branch
        & git checkout $Branch
        & git pull --ff-only origin $Branch
        Pop-Location
    } elseif ((-not (Test-Path $Dest)) -and $git) {
        & git clone --branch $Branch "https://github.com/$RepoSlug.git" $Dest
        if ($LASTEXITCODE -ne 0) { throw "git clone failed" }
    } else {
        $zip = Join-Path $env:TEMP "urds-$Branch.zip"
        $tmp = Join-Path $env:TEMP "urds-extract"
        $url = "https://github.com/$RepoSlug/archive/refs/heads/$Branch.zip"
        Write-Host "downloading $url"
        Invoke-WebRequest -UseBasicParsing -Uri $url -OutFile $zip
        if (Test-Path $tmp) { Remove-Item $tmp -Recurse -Force }
        Expand-Archive -Path $zip -DestinationPath $tmp -Force
        $src = Get-ChildItem $tmp -Directory | Select-Object -First 1
        New-Item -ItemType Directory -Force $Dest | Out-Null
        # Copy over the top: keeps an existing .venv, models\ and run\ (robocopy exit codes < 8 are success).
        & robocopy $src.FullName $Dest /E /NFL /NDL /NJH /NJS /NP | Out-Null
        if ($LASTEXITCODE -ge 8) { throw "copying the code into $Dest failed (robocopy $LASTEXITCODE)" }
        Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item $zip -Force -ErrorAction SilentlyContinue
    }
    Get-ChildItem (Join-Path $Dest "scripts") -Filter *.ps1 -ErrorAction SilentlyContinue | Unblock-File -ErrorAction SilentlyContinue

    Set-Location $Dest
    $setup = Join-Path $Dest "scripts\setup_vm.ps1"
    if (-not (Test-Path $setup)) { throw "$setup is missing - is '$Branch' the right branch?" }
    $setupArgs = @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", $setup)
    if ($NoStart) { $setupArgs += "-NoStart" }
    & powershell.exe @setupArgs
}

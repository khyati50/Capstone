<#
PowerShell helper to install the Python Uvicorn prediction microservice as a Windows Service using NSSM.
Run this script as Administrator from the project root.

It will:
- Ensure a .venv Python exists at .\.venv\Scripts\python.exe
- Download NSSM (if not present) to ./tools
- Install a service named CapstonePythonAI that runs: .venv\Scripts\python.exe -m uvicorn ai.server:app --host 127.0.0.1 --port 8000
- Configure working directory and log paths, then start the service.

Usage (Admin PowerShell):
  Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process
  .\scripts\install_uvicorn_service.ps1
#>

param(
  [string]$ServiceName = "CapstonePythonAI",
  [string]$RepoPath = "C:\Users\vanis\Desktop\capstone",
  [int]$Port = 8000
)

Write-Host "Installing service $ServiceName for repo path $RepoPath"

$venvPython = Join-Path $RepoPath ".venv\Scripts\python.exe"
if (-Not (Test-Path $venvPython)) {
  Write-Warning ".venv Python not found at $venvPython. Ensure your virtualenv exists and dependencies are installed."
  Write-Host "You can create one with:`npython -m venv .venv` and then `pip install -r requirements.txt`"
  # Continue, but installation will likely fail if python missing
}

$toolsDir = Join-Path $RepoPath "tools"
if (-Not (Test-Path $toolsDir)) { New-Item -Path $toolsDir -ItemType Directory | Out-Null }

# Try to locate nssm in PATH first
$nssmExe = (Get-Command nssm.exe -ErrorAction SilentlyContinue)?.Source
if (-Not $nssmExe) {
  Write-Host "NSSM not found in PATH. Downloading NSSM to $toolsDir (requires internet)."
  $nssmZip = Join-Path $toolsDir "nssm.zip"
  $nssmDownloadUrl = 'https://nssm.cc/release/nssm-2.24.zip'
  try {
    Invoke-WebRequest -Uri $nssmDownloadUrl -OutFile $nssmZip -UseBasicParsing -ErrorAction Stop
    Expand-Archive -LiteralPath $nssmZip -DestinationPath $toolsDir -Force
    # prefer win64 binary if present
    $possible = Get-ChildItem -Path $toolsDir -Recurse -Filter "nssm.exe" | Where-Object { $_.FullName -match "win64" } | Select-Object -First 1
    if (-Not $possible) { $possible = Get-ChildItem -Path $toolsDir -Recurse -Filter "nssm.exe" | Select-Object -First 1 }
    if ($possible) { $nssmExe = $possible.FullName } else { throw "nssm.exe not found in downloaded archive" }
  } catch {
    Write-Error "Failed to download or extract NSSM: $_. Exception.\nPlease manually download NSSM from https://nssm.cc/download and place nssm.exe in your PATH or $toolsDir."
    exit 1
  }
}

Write-Host "Using NSSM: $nssmExe"

# Create logs directory
$logDir = Join-Path $RepoPath "logs"
if (-Not (Test-Path $logDir)) { New-Item -Path $logDir -ItemType Directory | Out-Null }
$outLog = Join-Path $logDir "uvicorn_out.log"
$errLog = Join-Path $logDir "uvicorn_err.log"

# Build command
$appPath = $venvPython
$appArgs = "-m uvicorn ai.server:app --host 127.0.0.1 --port $Port --reload"

Write-Host "Installing Windows service '$ServiceName' to run:`n$appPath $appArgs`
Working directory: $RepoPath
Stdout: $outLog
Stderr: $errLog"

# Install service via NSSM
& $nssmExe install $ServiceName $appPath $appArgs
if ($LASTEXITCODE -ne 0) { Write-Error "nssm install failed with exit code $LASTEXITCODE"; exit 2 }

# Configure service parameters
& $nssmExe set $ServiceName AppDirectory $RepoPath
& $nssmExe set $ServiceName AppStdout $outLog
& $nssmExe set $ServiceName AppStderr $errLog
& $nssmExe set $ServiceName AppRotateFiles 1

# Start the service
& $nssmExe start $ServiceName
if ($LASTEXITCODE -ne 0) { Write-Error "Failed to start service (exit $LASTEXITCODE). Check $outLog and $errLog for details."; exit 3 }

Write-Host "Service '$ServiceName' installed and started successfully. Check logs in $logDir."
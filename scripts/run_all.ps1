# Master Orchestration Script to Launch All 3 Services Concurrently
Write-Host "=== Starting Explainable AI Threat Detection Platform ===" -ForegroundColor Cyan

$baseDir = Resolve-Path "$PSScriptRoot\.."

# 1. Start Python FastAPI Prediction Service (Port 8000)
Write-Host "Starting Python FastAPI Prediction Microservice (Port 8000)..." -ForegroundColor Green
$pythonExe = "$baseDir\.venv\Scripts\python.exe"
$pythonProc = Start-Process -FilePath $pythonExe -ArgumentList "-m uvicorn ai.server:app --host 0.0.0.0 --port 8000" -WorkingDirectory $baseDir -PassThru

# 2. Start Node.js Express Backend API (Port 5000)
Write-Host "Starting Node.js Express Backend Server (Port 5000)..." -ForegroundColor Green
$backendDir = "$baseDir\backend"
$nodeProc = Start-Process -FilePath "cmd.exe" -ArgumentList "/c npm start" -WorkingDirectory $backendDir -PassThru

# 3. Start Vite React Frontend Dashboard (Port 5173)
Write-Host "Starting Vite React Frontend Dashboard (Port 5173)..." -ForegroundColor Green
$frontendDir = "$baseDir\frontend"
$viteProc = Start-Process -FilePath "cmd.exe" -ArgumentList "/c npm run dev" -WorkingDirectory $frontendDir -PassThru

Write-Host "`nAll 3 Services Launched Successfully!" -ForegroundColor Yellow
Write-Host "  - Python FastAPI Service : http://localhost:8000" -ForegroundColor Gray
Write-Host "  - Express REST / Sockets : http://localhost:5000" -ForegroundColor Gray
Write-Host "  - React Web Dashboard    : http://localhost:5173" -ForegroundColor Gray

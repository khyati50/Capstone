# Master Orchestration Script to Launch All 3 Services Concurrently
Write-Host "=== Starting Explainable AI Threat Detection Platform ===" -ForegroundColor Cyan

# 1. Start Python FastAPI Prediction Service (Port 8000)
Write-Host "Starting Python FastAPI Prediction Microservice (Port 8000)..." -ForegroundColor Green
$pythonProc = Start-Process -FilePath "..\.venv\Scripts\python.exe" -ArgumentList "-m uvicorn ai.server:app --host 0.0.0.0 --port 8000" -WorkingDirectory "$PSScriptRoot\.." -PassThru

# 2. Start Node.js Express Backend API (Port 5000)
Write-Host "Starting Node.js Express Backend Server (Port 5000)..." -ForegroundColor Green
$nodeProc = Start-Process -FilePath "node" -ArgumentList "server.js" -WorkingDirectory "$PSScriptRoot\..\backend" -PassThru

# 3. Start Vite React Dashboard (Port 5173)
Write-Host "Starting Vite React Frontend Dashboard (Port 5173)..." -ForegroundColor Green
$viteProc = Start-Process -FilePath "npm" -ArgumentList "run dev" -WorkingDirectory "$PSScriptRoot\..\frontend" -PassThru

Write-Host "`nAll 3 Services Launched Successfully!" -ForegroundColor Yellow
Write-Host "  - Python FastAPI Service : http://localhost:8000" -ForegroundColor Gray
Write-Host "  - Express REST / Sockets : http://localhost:5000" -ForegroundColor Gray
Write-Host "  - React Web Dashboard    : http://localhost:5173" -ForegroundColor Gray

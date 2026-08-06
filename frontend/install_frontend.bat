@echo off
set "PATH=C:\Program Files\nodejs;%PATH%"
cd /d "C:\Users\vanis\Desktop\capstone\frontend"
call npm install --fetch-retries=10 --fetch-retry-mintimeout=5000 --fetch-retry-maxtimeout=60000 --no-audit --no-fund

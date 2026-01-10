@echo off
REM Professional Port Scanner - Quick Demo Script
REM This script demonstrates various features of the port scanner

echo ========================================
echo Professional Port Scanner - Demo
echo ========================================
echo.

echo 1. Testing Help Command
echo ------------------------
python portscanner.py --help
echo.
echo.

echo 2. Quick Scan Example (scanme.nmap.org)
echo ----------------------------------------
echo Running: python portscanner.py scanme.nmap.org --profile quick --no-color
python portscanner.py scanme.nmap.org --profile quick --no-color
echo.
echo.

echo 3. Launch Web Interface
echo ------------------------
echo To launch the web interface, run:
echo    python portscanner.py --web
echo.
echo Then open your browser to: http://localhost:5000
echo.

echo ========================================
echo Demo Complete!
echo ========================================
echo.
echo Try these commands yourself:
echo   - python portscanner.py localhost -p 1-1000
echo   - python portscanner.py scanme.nmap.org --profile quick --banner
echo   - python portscanner.py --web
echo.
pause

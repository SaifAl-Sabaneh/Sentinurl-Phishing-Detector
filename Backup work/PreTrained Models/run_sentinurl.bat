@echo off
echo ====================================================================
echo SENTINURL ULTIMATE PHISHING DETECTION SYSTEM
echo Version 3.0.0-ultimate
echo ====================================================================
echo.

REM Change to the script directory
cd /d "%~dp0"

REM Check if Python is installed
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: Python is not installed or not in PATH
    echo Please install Python 3.8 or higher
    pause
    exit /b 1
)

echo Starting SentinURL Ultimate...
echo.

REM Run the ultimate system
python sentinurl_ultimate.py

pause

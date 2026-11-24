@echo off
cd /d "%~dp0"
title SentinelShield AASS - Real-Time Attack Simulator CLI
color 0C
echo ===============================================================================
echo   SENTINEL SHIELD - ATTACK SIMULATION TERMINAL
echo   Module 2 Defense Demonstration Tool
echo ===============================================================================
echo.

set PYTHON_CMD=python
if exist "%LOCALAPPDATA%\Programs\Python\Python312\python.exe" (
    set PYTHON_CMD="%LOCALAPPDATA%\Programs\Python\Python312\python.exe"
)

%PYTHON_CMD% simulate_attack.py
if %ERRORLEVEL% neq 0 (
    echo.
    echo [ERROR] Trying system python...
    python simulate_attack.py
)
pause

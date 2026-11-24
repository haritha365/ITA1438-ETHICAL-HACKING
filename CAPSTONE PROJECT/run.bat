@echo off
cd /d "%~dp0"
title SentinelShield AASS - Web Security Server
color 0B
echo ===============================================================================
echo   SENTINEL SHIELD - ADAPTIVE AUTHENTICATION SECURITY SYSTEM (AASS)
echo   Real-Time Brute-Force Attack Detection and Prevention
echo ===============================================================================
echo.
echo [SYSTEM MODULES]
echo   Module 1: Adaptive User Authentication ^& Login Management
echo   Module 2: Real-Time Brute-Force Attack Detection ^& Prevention
echo.

:: Detect Python executable
set PYTHON_CMD=python
if exist "%LOCALAPPDATA%\Programs\Python\Python312\python.exe" (
    set PYTHON_CMD="%LOCALAPPDATA%\Programs\Python\Python312\python.exe"
)

echo [STARTUP] Using Python engine: %PYTHON_CMD%
echo [STARTUP] Initializing dual database engine (MySQL with SQLite automatic fallback)...
echo [STARTUP] Starting Flask Server on http://127.0.0.1:5000 ...
echo.
echo Opening browser in 3 seconds...
start "" http://127.0.0.1:5000

echo.
echo Access URLs:
echo   Landing Page:      http://127.0.0.1:5000/
echo   Admin Dashboard:   http://127.0.0.1:5000/dashboard.html
echo   Real-Time Radar:   http://127.0.0.1:5000/realtime.html
echo   Login Portal:      http://127.0.0.1:5000/login.html
echo.
echo Press Ctrl+C in this window to stop the server.
echo.

%PYTHON_CMD% app.py
if %ERRORLEVEL% neq 0 (
    echo.
    echo [ERROR] Server encountered an error. Trying system python...
    python app.py
)
pause

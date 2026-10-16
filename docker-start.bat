@echo off
setlocal enabledelayedexpansion

REM ==============================================================================
REM IoT Insecure Device Detection & Governance Platform - Quick Start Script (Windows)
REM Course: IT6027 - Cyber Security Policy and Governance
REM ==============================================================================

if "%1"=="--help" goto show_help
if "%1"=="-h" goto show_help
if "%1"=="/?" goto show_help

set MOCK_COUNT=4

if "%1"=="--real-only" set MOCK_COUNT=0
if "%1"=="real" set MOCK_COUNT=0
if "%1"=="0" set MOCK_COUNT=0
if "%1"=="1" set MOCK_COUNT=1
if "%1"=="2" set MOCK_COUNT=2
if "%1"=="3" set MOCK_COUNT=3
if "%1"=="4" set MOCK_COUNT=4

if "%1"=="--devices" (
    if "%2"=="0" set MOCK_COUNT=0
    if "%2"=="1" set MOCK_COUNT=1
    if "%2"=="2" set MOCK_COUNT=2
    if "%2"=="3" set MOCK_COUNT=3
    if "%2"=="4" set MOCK_COUNT=4
)
if "%1"=="-d" (
    if "%2"=="0" set MOCK_COUNT=0
    if "%2"=="1" set MOCK_COUNT=1
    if "%2"=="2" set MOCK_COUNT=2
    if "%2"=="3" set MOCK_COUNT=3
    if "%2"=="4" set MOCK_COUNT=4
)

echo ====================================================================
echo  Starting IoT Security and Insecure Device Governance Stack
echo  Course: IT6027 - Cyber Security
echo ====================================================================

if "%MOCK_COUNT%"=="0" (
    echo  Mode: 100%% REAL-WORLD OPERATION [0 Mock Devices]
    echo  The system will audit exclusively physical devices ^(Hotspot / IP Webcam^).
) else (
    echo  Mode: HYBRID DEMO OPERATION [%MOCK_COUNT% Mock Device^(s^) + Physical Devices]
)
echo ====================================================================

REM Ensure data directory exists for database persistence
if not exist "net-sec\data" mkdir "net-sec\data"

REM Auto-clean stale records from SQLite database
if "%MOCK_COUNT%"=="0" (
    if exist "net-sec\data\iot_security.db" python net-sec\clean_db.py --real-only
) else (
    if exist "net-sec\data\iot_security.db" python net-sec\clean_db.py
)

REM Synchronize Windows Mobile Hotspot & Physical IoT Telemetry Bridge
echo [*] Starting Real-time Physical IoT Telemetry Bridge (Hotspot / IP Webcam)...
start /b "" python net-sec\hotspot_bridge.py

echo [*] Building and launching Docker Compose services...
if "%MOCK_COUNT%"=="0" (
    docker compose up --build -d net-core-mqtt net-sec-platform
) else if "%MOCK_COUNT%"=="1" (
    docker compose --profile mock up --build -d net-core-mqtt net-sec-platform mock-device-01
) else if "%MOCK_COUNT%"=="2" (
    docker compose --profile mock up --build -d net-core-mqtt net-sec-platform mock-device-01 mock-device-02
) else if "%MOCK_COUNT%"=="3" (
    docker compose --profile mock up --build -d net-core-mqtt net-sec-platform mock-device-01 mock-device-02 mock-device-03
) else (
    docker compose --profile mock up --build -d
)

echo.
echo [*] Waiting 5 seconds for services to initialize...
timeout /t 5 /nobreak >nul

echo.
echo ====================================================================
echo  Service Status Summary:
echo ====================================================================
docker compose ps

echo.
echo ====================================================================
echo  [SUCCESS] System is ONLINE and fully operational!
echo ====================================================================
echo  - Web Governance Dashboard: http://localhost:8000
echo  - OpenAPI Documentation:    http://localhost:8000/docs
echo  - Database Health and Stats:  http://localhost:8000/api/db/stats
echo  - Central MQTT Broker:      mqtt://localhost:1883
echo  - Relational DB Storage:    .\net-sec\data\iot_security.db
echo ====================================================================
echo  To view live logs:    docker compose logs -f
echo  To stop the stack:    docker-stop.bat
echo ====================================================================
pause
exit /b 0

:show_help
echo ====================================================================
echo  IoT Security Platform - Launch Flags Help
echo ====================================================================
echo  Usage:
echo    docker-start.bat                 Default: 4 mock devices + physical devices
echo    docker-start.bat 0               Pure real-world mode (0 mock devices, only real devices)
echo    docker-start.bat --real-only     Alias for 0 mock devices
echo    docker-start.bat ^<1..4^>          Start with N simulated mock devices (e.g. docker-start.bat 2)
echo    docker-start.bat --devices ^<N^>   Specify device count explicitly
echo ====================================================================
exit /b 0

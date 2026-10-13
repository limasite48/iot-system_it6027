@echo off
REM ==============================================================================
REM IoT Insecure Device Detection & Governance Platform - Quick Start Script (Windows)
REM Course: IT6027 - Cyber Security Policy and Governance
REM ==============================================================================

echo ====================================================================
echo  Starting IoT Security and Insecure Device Governance Stack
echo  Course: IT6027 - Cyber Security
echo ====================================================================

REM Ensure data directory exists for database persistence
if not exist "net-sec\data" mkdir "net-sec\data"

echo [*] Building and launching Docker Compose services...
docker compose up --build -d

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
echo  To stop the stack:    docker compose down
echo ====================================================================
pause

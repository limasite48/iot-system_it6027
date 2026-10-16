@echo off
echo [*] Stopping and tearing down IoT Security containers...
docker compose --profile mock down

echo [*] Stopping Hotspot Telemetry Bridge background process...
if exist "net-sec\data\bridge.pid" (
    set /p BRIDGE_PID=<"net-sec\data\bridge.pid"
    if defined BRIDGE_PID (
        taskkill /F /PID %BRIDGE_PID% >nul 2>&1
        del "net-sec\data\bridge.pid" >nul 2>&1
    )
)

echo [+] System stopped cleanly. Persisted data remains in .\net-sec\data\.
pause

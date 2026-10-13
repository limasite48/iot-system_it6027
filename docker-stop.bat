@echo off
echo [*] Stopping and tearing down IoT Security containers...
docker compose down
echo [+] Containers stopped cleanly. Persisted data remains in .\net-sec\data\.
pause

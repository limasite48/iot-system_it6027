@echo off
REM Export built Docker images to a standalone tar archive for submission

set ARCHIVE_NAME=iot-security-images.tar

echo ====================================================================
echo  Exporting Docker Images to standalone archive: %ARCHIVE_NAME%
echo ====================================================================

echo [*] Ensuring latest images are built...
docker compose build

echo [*] Exporting images (iot-net-sec:latest, iot-mock-camera:latest, eclipse-mosquitto:2.0)...
docker save -o %ARCHIVE_NAME% iot-net-sec:latest iot-mock-camera:latest eclipse-mosquitto:2.0

echo.
echo [+] Successfully exported to %ARCHIVE_NAME%!
echo  To load these images on an offline machine or Mac laptop:
echo    docker load -i %ARCHIVE_NAME%
echo    docker compose up -d
echo ====================================================================
pause

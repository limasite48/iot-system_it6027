#!/usr/bin/env bash
# Export built Docker images to a standalone tar archive for submission
set -e

ARCHIVE_NAME="iot-security-images.tar.gz"

echo "===================================================================="
echo " Exporting Docker Images to standalone archive: ${ARCHIVE_NAME}"
echo "===================================================================="

# Ensure images are built
echo "[*] Ensuring latest images are built..."
docker compose build

echo "[*] Exporting images (iot-net-sec:latest, iot-mock-camera:latest, eclipse-mosquitto:2.0)..."
docker save iot-net-sec:latest iot-mock-camera:latest eclipse-mosquitto:2.0 | gzip > "${ARCHIVE_NAME}"

echo ""
echo "[+] Successfully exported to ${ARCHIVE_NAME} ($(du -h "${ARCHIVE_NAME}" | cut -f1))"
echo " To load these images on an offline machine / Mac / Linux laptop:"
echo "   docker load < ${ARCHIVE_NAME}"
echo "   docker compose up -d"
echo "===================================================================="

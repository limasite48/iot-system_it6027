#!/usr/bin/env bash
# ==============================================================================
# IoT Insecure Device Detection & Governance Platform - Quick Start Script
# Course: IT6027 - Cyber Security Policy and Governance
# Compatible with: macOS (Apple Silicon M1/M2/M3/M4 & Intel), Linux, Windows WSL2
# ==============================================================================

set -e

echo "===================================================================="
echo " Starting IoT Security & Insecure Device Governance Stack"
echo " Course: IT6027 - Cyber Security"
echo "===================================================================="

# Check if Docker daemon is running
if ! docker info >/dev/null 2>&1; then
    echo "[!] Error: Docker is not running. Please start Docker Desktop and retry."
    exit 1
fi

# Ensure data directory exists for database persistence
mkdir -p ./net-sec/data

echo "[*] Building and starting all Docker Compose services in detached mode..."
docker compose up --build -d

echo ""
echo "[*] Waiting 5 seconds for services to initialize..."
sleep 5

echo ""
echo "===================================================================="
echo " Service Status Summary:"
echo "===================================================================="
docker compose ps

echo ""
echo "===================================================================="
echo " [SUCCESS] System is ONLINE and fully operational!"
echo "===================================================================="
echo " - Web Governance Dashboard: http://localhost:8000"
echo " - OpenAPI Documentation:    http://localhost:8000/docs"
echo " - Database Health & Stats:  http://localhost:8000/api/db/stats"
echo " - Central MQTT Broker:      mqtt://localhost:1883"
echo " - Relational DB Storage:    ./net-sec/data/iot_security.db"
echo "===================================================================="
echo " To view live logs:    docker compose logs -f"
echo " To stop the stack:    docker compose down"
echo "===================================================================="

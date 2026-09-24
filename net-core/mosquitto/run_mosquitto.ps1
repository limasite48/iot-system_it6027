<#
.SYNOPSIS
    Launches the Mosquitto MQTT Broker for the IoT Core Network.
.DESCRIPTION
    Checks if Docker is available to run Eclipse Mosquitto container on port 1883.
#>

param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("start", "stop", "status", "logs")]
    [string]$Action = "start"
)

$containerName = "iot-mosquitto"
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$confPath = Join-Path $scriptDir "mosquitto.conf"

switch ($Action) {
    "start" {
        Write-Host "[*] Checking existing Mosquitto container..." -ForegroundColor Yellow
        $existing = docker ps -a --filter "name=$containerName" --format "{{.Names}}"
        if ($existing -eq $containerName) {
            Write-Host "[*] Starting existing $containerName container..." -ForegroundColor Green
            docker start $containerName
        } else {
            Write-Host "[*] Creating and starting $containerName on 0.0.0.0:1883..." -ForegroundColor Green
            docker run -d `
                --name $containerName `
                --restart unless-stopped `
                -p 1883:1883 `
                -v "${confPath}:/mosquitto/config/mosquitto.conf:ro" `
                eclipse-mosquitto:latest
        }
        Write-Host "[+] Mosquitto MQTT broker is active on port 1883." -ForegroundColor Cyan
        break
    }

    "stop" {
        Write-Host "[*] Stopping Mosquitto container..." -ForegroundColor Yellow
        docker stop $containerName
        break
    }

    "status" {
        docker ps --filter "name=$containerName"
        break
    }

    "logs" {
        docker logs --tail 50 -f $containerName
        break
    }
}

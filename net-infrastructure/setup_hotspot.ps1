<#
.SYNOPSIS
    Automated Windows Mobile Hotspot management and diagnostics utility for IoT System.
.DESCRIPTION
    Checks hotspot capability, queries current tethering status via WinRT API,
    and provides quick commands to toggle or configure Windows Mobile Hotspot.
#>

param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("Status", "Enable", "Disable", "OpenSettings")]
    [string]$Action = "Status"
)

function Get-TetheringManager {
    try {
        Add-Type -AssemblyName System.Runtime.WindowsRuntime
        $asTaskGeneric = ([System.WindowsRuntimeSystemExtensions].GetMethods() | Where-Object {
            $_.Name -eq 'AsTask' -and $_.GetParameters().Count -eq 1 -and $_.GetParameters()[0].ParameterType.Name -eq 'IAsyncOperation`1'
        })[0]

        [Windows.Networking.NetworkOperators.NetworkOperatorTetheringManager,Windows.Networking.NetworkOperators,ContentType=WindowsRuntime] | Out-Null
        
        $profile = [Windows.Networking.Connectivity.NetworkInformation,Windows.Networking.Connectivity,ContentType=WindowsRuntime]::GetInternetConnectionProfile()
        if ($null -eq $profile) {
            Write-Warning "No active internet connection profile found. Mobile hotspot may require an upstream connection to share."
            return $null
        }

        $mgr = [Windows.Networking.NetworkOperators.NetworkOperatorTetheringManager]::CreateFromConnectionProfile($profile)
        return @{ Manager = $mgr; Helper = $asTaskGeneric }
    } catch {
        Write-Warning "Could not initialize WinRT Tethering Manager: $_"
        return $null
    }
}

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "         IoT System - Windows Mobile Hotspot Utility       " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

switch ($Action) {
    "OpenSettings" {
        Write-Host "Opening Windows Mobile Hotspot Settings..." -ForegroundColor Green
        Start-Process "ms-settings:network-mobilehotspot"
        break
    }

    "Status" {
        Write-Host "[*] Inspecting Network Adapters & Wi-Fi Direct..." -ForegroundColor Yellow
        $adapters = Get-NetAdapter | Where-Object { $_.Status -eq "Up" -or $_.Name -like "*Local Area Connection*" -or $_.Name -like "*Wi-Fi*" }
        $adapters | Format-Table Name, InterfaceDescription, Status, MacAddress, LinkSpeed

        $ipAddresses = Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -notlike "127.*" }
        Write-Host "[*] Active IPv4 Addresses:" -ForegroundColor Yellow
        $ipAddresses | Format-Table IPAddress, InterfaceAlias, InterfaceIndex

        $tetherObj = Get-TetheringManager
        if ($null -ne $tetherObj) {
            $mgr = $tetherObj.Manager
            $opStatus = $mgr.TetheringOperationalState
            Write-Host "[*] Mobile Hotspot Operational State: $opStatus" -ForegroundColor Green
            Write-Host "[*] Connected Client Count: $($mgr.ClientCount)" -ForegroundColor Green
        } else {
            Write-Host "[i] Tip: You can toggle Mobile Hotspot directly via Windows Settings UI: ms-settings:network-mobilehotspot" -ForegroundColor Gray
        }

        Write-Host "`n[*] Expected Edge Subnet (Windows Default): 192.168.137.1 / 24" -ForegroundColor Cyan
        Write-Host "    Connected smartphones will typically receive IPs in: 192.168.137.2 - 192.168.137.254" -ForegroundColor Gray
        break
    }

    "Enable" {
        $tetherObj = Get-TetheringManager
        if ($null -ne $tetherObj) {
            $mgr = $tetherObj.Manager
            $helper = $tetherObj.Helper
            Write-Host "[*] Starting Mobile Hotspot..." -ForegroundColor Yellow
            $asyncOp = $mgr.StartTetheringAsync()
            $asTask = $helper.MakeGenericMethod([Windows.Networking.NetworkOperators.NetworkOperatorTetheringOperationResult]).Invoke($null, @($asyncOp))
            $asTask.Wait()
            $res = $asTask.Result
            Write-Host "[+] Start result: $($res.Status)" -ForegroundColor Green
        } else {
            Write-Host "Falling back to opening Settings..." -ForegroundColor Yellow
            Start-Process "ms-settings:network-mobilehotspot"
        }
        break
    }

    "Disable" {
        $tetherObj = Get-TetheringManager
        if ($null -ne $tetherObj) {
            $mgr = $tetherObj.Manager
            $helper = $tetherObj.Helper
            Write-Host "[*] Stopping Mobile Hotspot..." -ForegroundColor Yellow
            $asyncOp = $mgr.StopTetheringAsync()
            $asTask = $helper.MakeGenericMethod([Windows.Networking.NetworkOperators.NetworkOperatorTetheringOperationResult]).Invoke($null, @($asyncOp))
            $asTask.Wait()
            $res = $asTask.Result
            Write-Host "[+] Stop result: $($res.Status)" -ForegroundColor Green
        } else {
            Start-Process "ms-settings:network-mobilehotspot"
        }
        break
    }
}

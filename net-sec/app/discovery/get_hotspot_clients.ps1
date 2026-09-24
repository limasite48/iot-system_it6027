[Windows.Networking.Connectivity.NetworkInformation, Windows.Networking.Connectivity, ContentType = WindowsRuntime] | Out-Null
$profile = [Windows.Networking.Connectivity.NetworkInformation]::GetInternetConnectionProfile()
$mgr = [Windows.Networking.NetworkOperators.NetworkOperatorTetheringManager]::CreateFromConnectionProfile($profile)
if ($mgr) {
    $clients = @($mgr.GetTetheringClients())
    $list = @()
    foreach ($c in $clients) {
        $hn = ""
        if ($c.HostNames.Count -gt 0) {
            $hn = $c.HostNames[0].DisplayName
        }
        $list += [PSCustomObject]@{
            MacAddress = $c.MacAddress
            Hostname = $hn
        }
    }
    [PSCustomObject]@{
        State = $mgr.TetheringOperationalState.ToString()
        Count = $mgr.ClientCount
        Clients = $list
    } | ConvertTo-Json -Compress
} else {
    Write-Output '{"State":"Disabled","Count":0,"Clients":[]}'
}

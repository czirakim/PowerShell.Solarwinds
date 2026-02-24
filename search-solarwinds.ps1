 <#
.SYNOPSIS
 
    This is a script for searching in the Solarwinds NCM config files and  IPAM via Rest API
 
.DESCRIPTION
 
    Connects to Solarwinds API and searches in config files and IPAM.
    For the name, it will display everything it finds that contains that name.
    It was tested in PowerShell 7 
    Username,password are stored in an env file in Home folder of the user
 
.PARAMETER searchTerm
 
    The IP or Name that will be searched
 
.EXAMPLE
    .\search-solarwinds.ps1 webserver01
    .\search-solarwinds.ps1 172.16.1.100
#>

# CLI searchTerm parameter
param(
    [Parameter (Position=0, Mandatory=$true)]
    [string]$searchTerm,
    [Parameter (Position=1, Mandatory=$false)]
    [string]$days=7
    )

# Load var file
$configFile = Join-Path $HOME ".env.ps1"
.$configFile

#skip cert validation Powershell 7.0 
$PSDefaultParameterValues = @{
    "Invoke-WebRequest:SkipCertificateCheck" - $true
    "Invoke-RestMethod:SkipCertificateCheck" $true
}

# Get credentials
$hostname = $env:SOLARWINDS_HOST
$username = $env:SOLARWINDS_USER
$password = $env:SOLARWINDS_PASS

#Auth
$base64AuthInfo = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(("{0}:{1}" -f $username, $password)))

$headers = @{
    "Authorization" = "Basic $base64AuthInfo"
    "Content-Type" = "application/json"
}

$base_uri = "https://" + $hostname + ":17774/SolarWinds/InformationService/v3/Json/Query"
$uri = $base_uri

function search-ncm {

    $query = @{
    query = "SELECT 
OrionNodes.Caption AS DeviceName,
NcmArchive.ConfigType,
NcmArchive.DownloadTime,
NcmArchive.Config
FROM NCM.ConfigArchive AS NcmArchive
INNER JOIN NCM.Nodes AS NcmNodes ON NcmArchive.NodeID = NcmNodes.NodeID
INNER JOIN Orion.Nodes AS OrionNodes ON NcmNodes.CoreNodeID = OrionNodes.NodeID
WHERE NcmArchive.Config LIKE '%$searchTerm%'
AND NcmArchive.ConfigType = 'Running'
AND NcmArchive.DownloadTime > ADDDAY(-$days, GETUTCDATE())
ORDER BY NcmArchive.DownloadTime DESC"
}

    $body = $query | ConvertTo-Json -Compress

    try {
        $response = Invoke-RestMethod -Uri $uri -Method Post -Headers $headers -Body $body -UseBasicParsing
    } catch { 
        Write-Host "Status Code: $($_.Exception.Response.StatusCode.value)" -ForegroundColor Yellow
        Write-Host "Status Description: $($_.Exception.Response.StatusDescription)" -ForegroundColor Yellow
        Write-Host "Status Message: $($_.Exception.ToString())" -ForegroundColor Yellow
    }

    if ($null -eq $response.results -or $response.results.Count -eq 0) {
        Write-Warning "The SQL query returned no results from SolarWinds."
        Write-Host "No match found for $searchTerm in the config files." -ForegroundColor Red
        return # Stop the function here 
    }

    $finalResults = $response.results |
        # Exclude any DeviceName containing 'Standby' (case-insensitive)
        Where-Object { $_.DeviceName -notlike "*Standby*" } |
        # Group by DeviceName to remove duplicates
        Group-Object DeviceName |
        ForEach-Object {
            # Pick the newest config for each unique device
            $_.Group | Sort-Object DownloadTime -Descending | Select-Object -First 1
        }

    Write-Host "`nFound in $($finalResults.Count) config files." -ForegroundColor Green
    $finalResults | Format-Table -AutoSize

    $report = foreach ($entry in $finalResults) {
        # Split the config into lines and find the match
        $matchingLines = $entry.Config -split "`r`n" | Select-String -Pattern $searchTerm

        if ($matchingLines) {
            [PSCustomObject]@{
                DeviceName = $entry.DeviceName
                Matches = $matchingLines.Line -join "; "
            }
        }
    }

    Write-Host "`nNCM Matches found." -ForegroundColor Green
    $report | Format-Table -AutoSize

}

function search-Ipam { 
    $query = @{ 
    query = "SELECT n.IpAddress, 
    CASE n.Status 
        WHEN 1 THEN 'USED' 
        WHEN 2 THEN 'AVAILABLE' 
        WHEN 4 THEN 'RESERVED' 
        WHEN 8 THEN 'TRANSIENT' 
        ELSE 'UNKNOWN' 
    END AS Status, 
    n.DnsBackward, 
    n.LastSync, 
    n.Comments,
    s.Address AS SubnetAddress,
    s.AddressMask,
    s.FriendlyName,
    s.VLAN,
    s.Location
    FROM IPAM.IPNode n
    JOIN IPAM.Subnet s ON n.SubnetId = s.SubnetId
    WHERE n.IpAddress = '$searchTerm' 
    OR n.DnsBackward LIKE '%$searchTerm%'" 
    }
    
    $body = $query | ConvertTo-Json -Compress 
 
    try {         
        $response = Invoke-RestMethod -Uri $uri-Method Post -Headers $headers -Body $body -UseBasicParsing
    } catch {
        Write-Host "Status Code: $($_.Exception.Response.StatusCode.value__)" -ForegroundColor Yellow
        Write-Host "Status Description: $($_.Exception.Response.StatusDescription)" -ForegroundColor Yellow
        Write-Host "Status Message: $($_.Exception.ToString())" -ForegroundColor Yellow
    }
    
     
    if ($null -eq $response.results -or $response.results.Count -eq 0) {
        Write-Warning "The Solarwinds IPAM SQL query returned no results from SolarWinds."
        Write-Host "No match found for $searchTerm in IPAM" -ForegroundColor Red
        return # Stop the function here
    }
    
    Write-Host "nIPAM Matches found." -ForegroundColor Green
 
    $response.results | Format-Table -AutoSize
 
}

### main ###

# search in config files
search-ncm

# search in IPAM
search-Ipam

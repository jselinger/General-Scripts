<#

.SYNOPSIS
Determines the public IP address of the current machine using multiple public sources.

.DESCRIPTION
Uses multiple public sources to determine the public IP address. Returns found public IP addresses 
and detailed IP information including ASN, organization, and geolocation with a formatted console view.

.EXAMPLE
$results = .\What_Is_My_Public_IP.ps1
$results -> Returns formatted results for the public IP and detailed IP information.
$results.IPAddress -> Returns the public IP address information as a PowerShell object.
$results.IPDetail -> Returns the detailed IP information as a PowerShell object.

.\What_Is_My_Public_IP.ps1 - Returns formatted results with public IP and detailed IP information.

irm "https://raw.githubusercontent.com/jselinger/General-Scripts/refs/heads/main/Powershell/What_Is_My_Public_IP.ps1" | iex
irm https://thisip.com/ps | iex

.NOTES
Author: Joshua Selinger 2026 with AI
Date: 18-Nov-2026

The embedded format is cached in the temporary directory and registered once.
The cache is retained because PowerShell reloads registered format files.
Restart PowerShell once if an older version registered files that it then deleted.

#>

$httpSources = @(
    "https://api.ipify.org",
    "https://ifconfig.me",
    "https://icanhazip.com",
    "https://ipinfo.io/ip",
    "https://checkip.amazonaws.com",
    "https://ident.me",
    "https://ipecho.net/plain",
    "https://thisip.com/ip"
)

function Get-MyIpHttp {
    param(
        [string[]]$Sources
    )
    foreach ($url in $Sources) {
        try {
            $ip = (Invoke-RestMethod -Uri $url -TimeoutSec 5).Trim()
            if($ip -as [ipaddress]) {
                [PSCustomObject]@{
                    Source   = $url
                    Method   = "HTTPS"
                    PublicIP = $ip
                }
            }
            else{
                throw "Invalid IP address returned."

            }
        }
        catch {
            if ($_.Exception.Message -eq "Invalid IP address returned.") {
                Write-Warning "HTTP request to $url failed: $($_.Exception.Message)"
                $publicIP = "Invalid IP"
            }
            else{
                Write-Warning "HTTP request to $url failed: $($_.Exception.Message)"
                $publicIP = "Failed / Timeout"
            }
            [PSCustomObject]@{
                Source   = $url
                Method   = "HTTPS"
                PublicIP = $publicIP
            }
        }
    }
}

function Get-MyIpDns{
# Add a non-HTTP DNS check via OpenDNS
try {
    $dnsIP = (Resolve-DnsName -Name "myip.opendns.com" -Server "resolver1.opendns.com" -Type A -ErrorAction Stop).IPAddress
    [PSCustomObject]@{
        Source   = "myip.opendns.com"
        Method   = "DNS"
        PublicIP = $dnsIP
    }
}
catch {
    [PSCustomObject]@{
        Source   = "myip.opendns.com"
        Method   = "DNS"
        PublicIP = "Failed / Blocked"
    }
}
}

function Get-IpInfoDetail {
        try {
            $json = Invoke-WebRequest -Uri "https://ipinfo.io/json" -UseBasicParsing -TimeoutSec 5 | ConvertFrom-Json
            if($json.country -eq "US") {
                $regionKeyName = "State"
            }
            else{
                $regionKeyName = "Region"
            }
            [PSCustomObject]@{
                IP              = $json.ip
                ReverseDNS      = $json.hostname
                City            = $json.city
                $regionKeyName  = $json.region
                Country         = $json.country
                GPS             = $json.loc
                SourceASN       = $json.org.Split(" ")[0]
                SourceOrg       = $json.org.Substring($json.org.IndexOf(" ")+1)
            }
        }
        catch {
            Write-Warning "Http request to https://ipinfo.io/json failed: $($_.Exception.Message)"
        }
    
}


$formatXml = @'
<?xml version="1.0" encoding="utf-8"?>
<Configuration>
  <ViewDefinitions>
    <View>
      <Name>IpChecker.Result</Name>
      <ViewSelectedBy>
        <TypeName>IpChecker.Result</TypeName>
      </ViewSelectedBy>
      <CustomControl>
        <CustomEntries>
          <CustomEntry>
            <CustomItem>
              <Text>=== Your IP Address ===</Text>
              <NewLine />
              <ExpressionBinding>
                <ScriptBlock>$_.IPAddress | Format-Table -AutoSize | Out-String</ScriptBlock>
              </ExpressionBinding>
              <Text>=== Detailed IP Information ===</Text>
              <NewLine />
              <ExpressionBinding>
                <ScriptBlock>$_.IPDetail | Format-Table -AutoSize | Out-String</ScriptBlock>
              </ExpressionBinding>
            </CustomItem>
          </CustomEntry>
        </CustomEntries>
      </CustomControl>
    </View>
  </ViewDefinitions>
</Configuration>
'@
$formatPath = Join-Path ([System.IO.Path]::GetTempPath()) ("IpChecker.{0}.format.ps1xml" -f $PID)

if (-not (Get-FormatData -TypeName 'IpChecker.Result' -ErrorAction Stop)) {
    # Keep the registered file available for subsequent format-data updates.
    [System.IO.File]::WriteAllText($formatPath, $formatXml)
    Update-FormatData -PrependPath $formatPath -ErrorAction Stop
}

$IPResults = @(
    Get-MyIpHttp -Sources $httpSources
    Get-MyIpDns
)
$IPInfoDetail = Get-IpInfoDetail

[PSCustomObject]@{
    PSTypeName = 'IpChecker.Result'
    IPAddress  = $IPResults
    IPDetail   = $IPInfoDetail
}

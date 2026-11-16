# Joshua Selinger 2026 with AI
# Polls several Public Sources and returns Public IP
# irm "https://raw.githubusercontent.com/jselinger/General-Scripts/refs/heads/main/Powershell/What_Is_My_Public_IP.ps1" | iex


$httpSources = @(
    "https://api.ipify.org",
    "https://ifconfig.me",
    "https://icanhazip.com",
    "https://ipinfo.io/ip",
    "https://checkip.amazonaws.com",
    "https://ident.me",
    "https://thisip.com/ip"
)

$results = foreach ($url in $httpSources) {
    try {
        $ip = (Invoke-RestMethod -Uri $url -TimeoutSec 5).Trim()
        [PSCustomObject]@{
            Source   = $url
            Method   = "HTTPS"
            PublicIP = $ip
        }
    }
    catch {
        [PSCustomObject]@{
            Source   = $url
            Method   = "HTTPS"
            PublicIP = "Failed / Timeout"
        }
    }
}

# Add a non-HTTP DNS check via OpenDNS
try {
    $dnsIP = (Resolve-DnsName -Name "myip.opendns.com" -Server "resolver1.opendns.com" -Type A -ErrorAction Stop).IPAddress
    $results += [PSCustomObject]@{
        Source   = "myip.opendns.com"
        Method   = "DNS"
        PublicIP = $dnsIP
    }
}
catch {
    $results += [PSCustomObject]@{
        Source   = "myip.opendns.com"
        Method   = "DNS"
        PublicIP = "Failed / Blocked"
    }
}

$results | Format-Table -AutoSize

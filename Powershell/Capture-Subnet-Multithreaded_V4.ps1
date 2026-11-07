# (c)Josh Selinger   with AI assitance
# Capture screenshots from every usable IPv4 address and selected TCP ports.
# requires "Capture-WebPage-Function.ps1"
# This script uses ForEach-Object -Parallel, which requires PowerShell 7 or later.


# --------------------------- USER SETTINGS ---------------------------

$Subnet = "192.168.1.0/24"

# Leave empty ($null or @()) to use ports 80 and 443.
$Ports = @(80, 443)

# Leave blank ($null or "") to use C:\Temp.
$OutputDirectory = ""

# Path to the function script. By default, it is expected in this script's folder.
$CaptureScript = Join-Path $PSScriptRoot "Capture-WebPage-Function.ps1"

# Screenshot settings
$Width = 1920
$Height = 1080
$WaitSeconds = 3

# Maximum number of IP addresses processed at the same time.
$ThreadCount = 10

# ---------------------------------------------------------------------

$ErrorActionPreference = "Stop"

if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
    $OutputDirectory = "C:\Temp"
}

if ($null -eq $Ports -or @($Ports).Count -eq 0) {
    $Ports = @(80, 443)
}

# This script uses ForEach-Object -Parallel, which requires PowerShell 7 or later.
if ($PSVersionTable.PSVersion.Major -lt 7) {
    throw "PowerShell 7 or later is required. Run this script with pwsh.exe."
}

# Validate the capture function script. Each parallel worker loads its own copy.
if (-not (Test-Path -LiteralPath $CaptureScript)) {
    throw "Capture script not found: $CaptureScript"
}

if ($ThreadCount -lt 1) {
    throw "ThreadCount must be at least 1."
}

# Validate ports
$Ports = @($Ports | ForEach-Object { [int]$_ } | Select-Object -Unique)
foreach ($Port in $Ports) {
    if ($Port -lt 1 -or $Port -gt 65535) {
        throw "Invalid TCP port: $Port. Ports must be between 1 and 65535."
    }
}

# Parse and validate IPv4 CIDR
$CidrParts = $Subnet.Split("/")
if ($CidrParts.Count -ne 2) {
    throw "Subnet must be in CIDR format, for example 192.168.4.0/24."
}

$ParsedIP = $null
if (-not [System.Net.IPAddress]::TryParse($CidrParts[0], [ref]$ParsedIP) -or
    $ParsedIP.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork) {
    throw "Subnet must contain a valid IPv4 address."
}

$PrefixLength = 0
if (-not [int]::TryParse($CidrParts[1], [ref]$PrefixLength) -or
    $PrefixLength -lt 0 -or $PrefixLength -gt 32) {
    throw "CIDR prefix must be between 0 and 32."
}

# Convert IPv4 address to an unsigned 32-bit number.
$IPBytes = $ParsedIP.GetAddressBytes()
$IPNumber = ([uint64]$IPBytes[0] * 16777216) +
            ([uint64]$IPBytes[1] * 65536) +
            ([uint64]$IPBytes[2] * 256) +
            [uint64]$IPBytes[3]

if ($PrefixLength -eq 0) {
    $Mask = [uint64]0
}
else {
    $Mask = ([uint64]4294967295 -shl (32 - $PrefixLength)) -band [uint64]4294967295
}

$Network = $IPNumber -band $Mask
$Broadcast = $Network -bor ([uint64]4294967295 -bxor $Mask)

# For /31 both addresses are usable (RFC 3021); /32 contains one address.
if ($PrefixLength -le 30) {
    $FirstHost = $Network + 1
    $LastHost = $Broadcast - 1
}
else {
    $FirstHost = $Network
    $LastHost = $Broadcast
}

# Convert an unsigned IPv4 number back to dotted-decimal notation.
function ConvertFrom-IPv4Number {
    param([uint64]$Number)

    $Bytes = [byte[]]@(
        (($Number -shr 24) -band 255),
        (($Number -shr 16) -band 255),
        (($Number -shr 8) -band 255),
        ($Number -band 255)
    )

    return ([System.Net.IPAddress]::new($Bytes)).ToString()
}

# Create output folder
New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null

# Build the list of IP addresses before starting parallel workers.
$IPAddresses = [System.Collections.Generic.List[string]]::new()

for ([uint64]$IPValue = $FirstHost; $IPValue -le $LastHost; $IPValue++) {
    $Bytes = [byte[]]@(
        (($IPValue -shr 24) -band 255),
        (($IPValue -shr 16) -band 255),
        (($IPValue -shr 8) -band 255),
        ($IPValue -band 255)
    )

    $IPAddresses.Add(([System.Net.IPAddress]::new($Bytes)).ToString())

    # Avoid unsigned integer overflow at the maximum IPv4 address.
    if ($IPValue -eq $LastHost) {
        break
    }
}

$TotalHosts = $IPAddresses.Count
$TotalCaptures = $TotalHosts * $Ports.Count * 2

Write-Host "Subnet: $Subnet"
Write-Host "Ports: $($Ports -join ', ')"
Write-Host "Protocols: HTTP and HTTPS"
Write-Host "Output: $OutputDirectory"
Write-Host "Threads: $ThreadCount"
Write-Host "IP addresses: $TotalHosts"
Write-Host "Maximum captures (if every host responds): $TotalCaptures"
Write-Host ""
Write-Host "Starting parallel capture. Each worker pings one IP, then tries HTTP and HTTPS on every configured port."
Write-Host ""

# Each parallel worker is assigned one IP address. It loads the capture function
# in its own runspace, then processes the complete port list sequentially.
$Results = $IPAddresses | ForEach-Object -Parallel {
    $IPAddress = $_
    $ErrorActionPreference = "Stop"

    . $using:CaptureScript
    $WorkerPorts = $using:Ports

    $IPSuccess = 0
    $IPFailed = 0
    $Failures = [System.Collections.Generic.List[string]]::new()

    # Check each TCP port first. Only attempt HTTP/HTTPS captures when
    # Test-NetConnection confirms that the port is reachable.
    foreach ($Port in $WorkerPorts) {
        $PortOpen = $false

        try {
            $Connection = Test-NetConnection `
                -ComputerName $IPAddress `
                -Port $Port `
                -InformationLevel Quiet `
                -WarningAction SilentlyContinue `
                -ErrorAction SilentlyContinue

            $PortOpen = [bool]$Connection
        }
        catch {
            $PortOpen = $false
        }

        if (-not $PortOpen) {
            $ProtocolCount = if ($Port -eq 443) { 1 } else { 2 }
            $Failures.Add("${IPAddress}:$Port - TCP port is not reachable; $ProtocolCount protocol capture(s) skipped.")
            continue
        }

        # Port 443 is HTTPS-only. All other ports are tried with both protocols.
        $Schemes = if ($Port -eq 443) { @("https") } else { @("http", "https") }

        foreach ($Scheme in $Schemes) {
            $Url = "${Scheme}://${IPAddress}:${Port}/"
            $FileName = "${IPAddress}_${Port}_${Scheme}.png"
            $ScreenshotPath = Join-Path $using:OutputDirectory $FileName

            try {
                Capture-WebPage `
                    -Url $Url `
                    -OutputPath $ScreenshotPath `
                    -Width $using:Width `
                    -Height $using:Height `
                    -WaitSeconds $using:WaitSeconds |
                    Out-Null

                $IPSuccess++
            }
            catch {
                $IPFailed++
                $Failures.Add("$Url - $($_.Exception.Message)")
            }
        }
    }

    [PSCustomObject]@{
        IP         = $IPAddress
        Successful = $IPSuccess
        Failed     = $IPFailed
        Skipped    = (($WorkerPorts | ForEach-Object {
            if ($_ -eq 443) { 1 } else { 2 }
        } | Measure-Object -Sum).Sum) - ($IPSuccess + $IPFailed)
        Failures   = @($Failures)
    }
} -ThrottleLimit $ThreadCount

# Summarize the results after all workers have completed.
$Succeeded = ($Results | Measure-Object -Property Successful -Sum).Sum
$Failed = ($Results | Measure-Object -Property Failed -Sum).Sum
$SkippedCaptures = ($Results | Measure-Object -Property Skipped -Sum).Sum

if ($null -eq $Succeeded) { $Succeeded = 0 }
if ($null -eq $Failed) { $Failed = 0 }
if ($null -eq $SkippedCaptures) { $SkippedCaptures = 0 }

foreach ($Result in $Results | Sort-Object {
    $Parts = $_.IP.Split('.')
    [uint64]$Parts[0] * 16777216 +
    [uint64]$Parts[1] * 65536 +
    [uint64]$Parts[2] * 256 +
    [uint64]$Parts[3]
}) {
    Write-Host ("{0}: {1} successful, {2} failed, {3} skipped" -f
        $Result.IP, $Result.Successful, $Result.Failed, $Result.Skipped)

    foreach ($Failure in $Result.Failures) {
        Write-Warning $Failure
    }
}

Write-Host ""
Write-Host "Capture run complete."
Write-Host "IP addresses processed: $TotalHosts"
Write-Host "Captures skipped (TCP ports unreachable): $SkippedCaptures"
Write-Host "Threads used (maximum): $ThreadCount"
Write-Host "Successful: $Succeeded"
Write-Host "Failed:     $Failed"
Write-Host "Output:     $OutputDirectory"

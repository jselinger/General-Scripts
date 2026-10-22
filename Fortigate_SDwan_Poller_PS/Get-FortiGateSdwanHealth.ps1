<#
(c)2026 Josh Selinger  - using AI

.SYNOPSIS
    FortiGate SD-WAN health-check status via SNMP v2c (pure PowerShell, no Net-SNMP).

.DESCRIPTION
    Input : CSV with columns  firewallname, IP, community
            Defaults to .\firewalls.csv in the current directory if -CsvPath not given.
    For each device (SNMP v2c) collects:
      - Device name : sysName                        1.3.6.1.2.1.1.5.0
      - Uptime      : sysUpTime (TimeTicks 1/100s)   1.3.6.1.2.1.1.3.0
      - Serial      : fnSysSerial                    1.3.6.1.4.1.12356.100.1.1.1.0
      - Health-check link name       : fgVWLHealthCheckLinkName   1.3.6.1.4.1.12356.101.4.9.2.1.2  (walk)
      - SD-WAN member interface name : fgVWLHealthCheckLinkIfName 1.3.6.1.4.1.12356.101.4.9.2.1.14 (walk)
      - Health-check state per link   : fgVWLHealthCheckLinkState  1.3.6.1.4.1.12356.101.4.9.2.1.4  (walk)
        State: 0 = OK, 1 = BAD (verified empirically against live FortiOS)
    Builds an array of site objects ($sites), one per CSV row, each with a Links array
    pairing link name, interface, and state by table index.
    Exports results to sdwan_health.csv (next to the input CSV unless -ExportPath given).
    Exit code: 0 = all links OK, 1 = at least one BAD link or unreachable device.
    -Debug prints raw TX/RX hex and a TLV trace of every response.
#>

param(
    [string]$CsvPath,
    [string]$ExportPath,
    [int]$TimeoutMs = 2000,
    [int]$Retries   = 1,
    [switch]$Debug
)

# ---------- CSV pre-check ----------
if (-not $CsvPath) { $CsvPath = Join-Path (Get-Location) 'firewalls.csv' }
if (-not (Test-Path $CsvPath)) {
    throw "CSV not found: $CsvPath (pass -CsvPath <path> or place firewalls.csv in the current directory)"
}
if (-not $ExportPath) { $ExportPath = Join-Path (Split-Path $CsvPath -Parent) 'sdwan_health.csv' }

# ---------- BER encode ----------
function Encode-Length([int]$len) {
    if ($len -lt 128) { return [byte[]]@($len) }
    $bytes = @(); $l = $len
    while ($l -gt 0) { $bytes = @([byte]($l -band 0xFF)) + $bytes; $l = $l -shr 8 }
    return [byte[]](@((0x80 -bor $bytes.Count)) + $bytes)
}
function Encode-TLV([byte]$tag, [byte[]]$content) {
    return [byte[]](@($tag) + (Encode-Length $content.Length) + $content)
}
function Encode-Int([long]$v) {
    $bytes = @()
    do { $bytes = @([byte]($v -band 0xFF)) + $bytes; $v = $v -shr 8 } while ($v -gt 0)
    if ($bytes[0] -band 0x80) { $bytes = @(0) + $bytes }
    return Encode-TLV 0x02 ([byte[]]$bytes)
}
function Encode-String([string]$s) {
    return Encode-TLV 0x04 ([System.Text.Encoding]::ASCII.GetBytes($s))
}
function Encode-Oid([string]$oid) {
    $parts = $oid.TrimStart('.').Split('.')
    $body = New-Object System.Collections.Generic.List[byte]
    $body.Add([byte](40 * [int]$parts[0] + [int]$parts[1]))
    for ($i = 2; $i -lt $parts.Count; $i++) {
        $n = [long]$parts[$i]
        if ($n -lt 128) { $body.Add([byte]$n) }
        else {
            $stack = @([byte]($n -band 0x7F)); $n = $n -shr 7
            while ($n -gt 0) { $stack = @([byte](($n -band 0x7F) -bor 0x80)) + $stack; $n = $n -shr 7 }
            foreach ($b in $stack) { $body.Add([byte]$b) }
        }
    }
    return Encode-TLV 0x06 ($body.ToArray())
}

# ---------- BER decode ----------
function Decode-TLVList([byte[]]$data) {
    $tlvs = @()
    $pos = 0
    while ($pos -lt $data.Length) {
        $tag = $data[$pos]; $pos++
        $len = $data[$pos]; $pos++
        if ($len -band 0x80) {
            $n = $len -band 0x7F; $len = 0
            for ($i = 0; $i -lt $n; $i++) { $len = ($len -shl 8) -bor $data[$pos]; $pos++ }
        }
        if ($len -eq 0) { $content = [byte[]]@() }
        else { $content = [byte[]]$data[$pos..($pos + $len - 1)] }
        $pos += $len
        $tlvs += @{ Tag = $tag; Content = $content }
    }
    return ,$tlvs   # comma: prevent single-element array unwrapping
}
function Decode-Oid([byte[]]$c) {
    $oid = "$([int]($c[0] / 40)).$([int]($c[0] % 40))"
    $val = [long]0
    for ($i = 1; $i -lt $c.Count; $i++) {
        $val = ($val -shl 7) -bor ($c[$i] -band 0x7F)
        if (-not ($c[$i] -band 0x80)) { $oid += ".$val"; $val = 0 }
    }
    return $oid
}
function Decode-Value([byte]$tag, [byte[]]$c) {
    switch ($tag) {
        0x02 { $v = [long]0; foreach ($b in $c) { $v = ($v -shl 8) -bor $b }
               if ($c.Count -gt 0 -and ($c[0] -band 0x80)) { $v -= [long]1 -shl (8 * $c.Count) }; return $v }
        0x04 { return [System.Text.Encoding]::ASCII.GetString($c) }
        0x05 { return 'NULL' }
        0x06 { return Decode-Oid $c }
        0x40 { $v = [long]0; foreach ($b in $c) { $v = ($v -shl 8) -bor $b }; return $v }
        0x41 { $v = [long]0; foreach ($b in $c) { $v = ($v -shl 8) -bor $b }; return $v }
        0x43 { $v = [long]0; foreach ($b in $c) { $v = ($v -shl 8) -bor $b }; return $v }
        default { return ($c | ForEach-Object { $_.ToString('X2') }) -join ' ' }
    }
}

# ---------- SNMP v2c request ----------
$script:reqId = 0
function Invoke-SnmpRequest {
    param([string]$Ip, [string]$Community, [string[]]$Oids, [byte]$PduType, [int]$TimeoutMs, [int]$Retries)

    $script:reqId++
    $varbinds = [byte[]]@()
    foreach ($oid in $Oids) {
        $varbinds += Encode-TLV 0x30 ((Encode-Oid $oid) + (Encode-TLV 0x05 @()))
    }
    $varbindList = Encode-TLV 0x30 $varbinds
    $pdu = Encode-TLV $PduType ((Encode-Int $script:reqId) + (Encode-Int 0) + (Encode-Int 0) + $varbindList)
    $msg = Encode-TLV 0x30 ((Encode-Int 1) + (Encode-String $Community) + $pdu)   # version 1 = v2c

    if ($Debug) {
        Write-Host "  [TX] hex: $(($msg | ForEach-Object { $_.ToString('X2') }) -join ' ')" -ForegroundColor DarkGray
    }

    $udp = New-Object System.Net.Sockets.UdpClient
    $udp.Client.ReceiveTimeout = $TimeoutMs
    try {
        for ($attempt = 1; $attempt -le ($Retries + 1); $attempt++) {
            $null = $udp.Send($msg, $msg.Length, $Ip, 161)
            $remote = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, 0)
            try {
                $resp = $udp.Receive([ref]$remote)
                if ($Debug) {
                    Write-Host "  [RX] $($resp.Length) bytes hex: $(($resp | ForEach-Object { $_.ToString('X2') }) -join ' ')" -ForegroundColor DarkGray
                }

                $msgTlvs = Decode-TLVList $resp
                if ($msgTlvs.Count -lt 1) { throw "malformed response from $Ip (no SEQUENCE)" }
                $inner = Decode-TLVList ([byte[]]$msgTlvs[0].Content)
                if ($inner.Count -lt 3) { throw "malformed response from $Ip (expected version/community/PDU)" }
                $verTlv = $inner[0]; $comTlv = $inner[1]; $pduTlv = $inner[2]

                $pduParts = Decode-TLVList ([byte[]]$pduTlv.Content)
                if ($pduParts.Count -lt 4) { throw "malformed response from $Ip (PDU fields)" }
                $errStatus = Decode-Value $pduParts[1].Tag ([byte[]]$pduParts[1].Content)
                $errIndex  = Decode-Value $pduParts[2].Tag ([byte[]]$pduParts[2].Content)

                if ($Debug) {
                    Write-Host ("  [TLV] ver:{0} comm:'{1}' pdu tag:0x{2:X2} | errStatus:{3} errIndex:{4}" -f `
                        (Decode-Value $verTlv.Tag ([byte[]]$verTlv.Content)), `
                        (Decode-Value $comTlv.Tag ([byte[]]$comTlv.Content)), `
                        $pduTlv.Tag, $errStatus, $errIndex) -ForegroundColor DarkGray
                }

                $results = @()
                foreach ($vbSeq in (Decode-TLVList ([byte[]]$pduParts[3].Content))) {
                    $vbParts = Decode-TLVList ([byte[]]$vbSeq.Content)
                    if ($vbParts.Count -lt 2) { continue }
                    $results += [PSCustomObject]@{
                        Oid   = Decode-Oid ([byte[]]$vbParts[0].Content)
                        Tag   = $vbParts[1].Tag
                        Value = Decode-Value $vbParts[1].Tag ([byte[]]$vbParts[1].Content)
                    }
                }
                return @{ ErrorStatus = $errStatus; ErrorIndex = $errIndex; Varbinds = $results }
            }
            catch [System.Net.Sockets.SocketException] {
                if ($attempt -gt $Retries) { throw "timeout/no response from $Ip after $attempt attempts" }
            }
        }
    }
    finally { $udp.Close() }
}

function Invoke-SnmpWalk {
    param([string]$Ip, [string]$Community, [string]$RootOid, [int]$TimeoutMs, [int]$Retries)
    $out = @()
    $current = $RootOid
    for ($i = 0; $i -lt 200; $i++) {
        $r = Invoke-SnmpRequest -Ip $Ip -Community $Community -Oids @($current) -PduType 0xA1 -TimeoutMs $TimeoutMs -Retries $Retries
        $vb = $r.Varbinds[0]
        if ($null -eq $vb) { break }
        if ($vb.Tag -in 0x81, 0x82, 0x8A) { break }
        if ($vb.Oid -notlike "$RootOid.*") { break }
        $out += $vb
        $current = $vb.Oid
    }
    return ,$out
}

function Convert-TimeTicks([long]$ticks) {
    $totalSec = [math]::Floor($ticks / 100)
    $days  = [math]::Floor($totalSec / 86400)
    $hours = [math]::Floor(($totalSec % 86400) / 3600)
    $mins  = [math]::Floor(($totalSec % 3600) / 60)
    return [PSCustomObject]@{
        Days    = $days
        Hours   = $hours
        Minutes = $mins
        Text    = "{0}d {1}h {2}m" -f $days, $hours, $mins
    }
}

# ---------- main ----------
$sites = @()

foreach ($row in (Import-Csv $CsvPath)) {
    $name      = $row.firewallname
    $ip        = $row.IP
    $community = $row.community

    Write-Host "`n===== $name ($ip) =====" -ForegroundColor Cyan

    if (-not $ip -or -not $community) {
        Write-Host "  Skipping: missing IP or community in CSV row" -ForegroundColor Red
        continue
    }

    $site = [PSCustomObject]@{
        FirewallName = $name
        IP           = $ip
        DeviceName   = $null
        UptimeRaw    = $null
        UptimeDays   = $null
        UptimeText   = $null
        Serial       = $null
        Links        = @()
        Error        = $null
    }

    try {
        # --- scalars ---
        $r = Invoke-SnmpRequest -Ip $ip -Community $community `
             -Oids @('1.3.6.1.2.1.1.5.0','1.3.6.1.2.1.1.3.0','1.3.6.1.4.1.12356.100.1.1.1.0') `
             -PduType 0xA0 -TimeoutMs $TimeoutMs -Retries $Retries

        if ("$($r.ErrorStatus)" -ne '0' -and "$($r.ErrorStatus)" -ne '') {
            Write-Host "  agent error-status=$($r.ErrorStatus) index=$($r.ErrorIndex)" -ForegroundColor Yellow
        }

        foreach ($vb in $r.Varbinds) {
            switch -Wildcard ($vb.Oid) {
                '1.3.6.1.2.1.1.5.0' {
                    $site.DeviceName = $vb.Value
                }
                '1.3.6.1.2.1.1.3.0' {
                    $site.UptimeRaw  = $vb.Value
                    $up = Convert-TimeTicks ([long]$vb.Value)
                    $site.UptimeDays = $up.Days
                    $site.UptimeText = $up.Text
                }
                '1.3.6.1.4.1.12356.100.1.1.1.0' { $site.Serial = $vb.Value }
            }
        }

        # --- walks, paired by table index suffix ---
        $linkNameRoot = '1.3.6.1.4.1.12356.101.4.9.2.1.2'
        $stateRoot    = '1.3.6.1.4.1.12356.101.4.9.2.1.4'
        $ifNameRoot   = '1.3.6.1.4.1.12356.101.4.9.2.1.14'

        $linkNames = Invoke-SnmpWalk -Ip $ip -Community $community -RootOid $linkNameRoot -TimeoutMs $TimeoutMs -Retries $Retries
        $states    = Invoke-SnmpWalk -Ip $ip -Community $community -RootOid $stateRoot   -TimeoutMs $TimeoutMs -Retries $Retries
        $ifNames   = Invoke-SnmpWalk -Ip $ip -Community $community -RootOid $ifNameRoot  -TimeoutMs $TimeoutMs -Retries $Retries

        $nameByIndex = @{}
        foreach ($n in $linkNames) {
            $suffix = $n.Oid.Substring($linkNameRoot.Length).TrimStart('.')
            $nameByIndex[$suffix] = $n.Value
        }
        $stateByIndex = @{}
        foreach ($s in $states) {
            $suffix = $s.Oid.Substring($stateRoot.Length).TrimStart('.')
            $stateByIndex[$suffix] = [int]$s.Value
        }

        foreach ($n in $ifNames) {
            $suffix = $n.Oid.Substring($ifNameRoot.Length).TrimStart('.')
            $stateVal = $null
            if ($stateByIndex.ContainsKey($suffix)) { $stateVal = $stateByIndex[$suffix] }
            $linkName = $null
            if ($nameByIndex.ContainsKey($suffix)) { $linkName = $nameByIndex[$suffix] }
            switch ($stateVal) {
                0 { $stateText = 'OK' }
                1 { $stateText = 'BAD' }
                default { $stateText = "unexpected($stateVal)" }
            }
            $site.Links += [PSCustomObject]@{
                Index     = $suffix
                LinkName  = $linkName
                Interface = $n.Value
                State     = $stateVal
                StateText = $stateText
            }
        }

        # --- per-site output ---
        Write-Host ("  Device : {0}   Serial: {1}" -f $site.DeviceName, $site.Serial)
        Write-Host ("  Uptime : {0} ticks = {1} days ({2})" -f $site.UptimeRaw, $site.UptimeDays, $site.UptimeText)
        Write-Host "  SD-WAN health-check links:"
        $site.Links | ForEach-Object {
            $color = 'Gray'
            if ($_.StateText -eq 'OK')   { $color = 'Green' }
            elseif ($_.StateText -eq 'BAD') { $color = 'Red' }
            Write-Host ("    [{0}] {1} ({2}) = {3}" -f $_.Index, $_.Interface, $_.LinkName, $_.StateText) -ForegroundColor $color
        }
    }
    catch {
        $site.Error = $_.Exception.Message
        Write-Host "  ERROR: $($site.Error)" -ForegroundColor Red
    }

    $sites += $site
}

# ---------- summary ----------
Write-Host "`n===== Summary (`$sites) =====" -ForegroundColor Cyan
$sites | Format-Table FirewallName, IP, DeviceName, Serial, UptimeDays, UptimeText, Error -AutoSize
$sites | ForEach-Object {
    "[$($_.FirewallName)] Links: " + (($_.Links | ForEach-Object { "$($_.Interface)/$($_.LinkName)=$($_.StateText)" }) -join ', ')
}

# ---------- CSV export ----------
$sites | Select-Object FirewallName, IP, DeviceName, Serial, UptimeDays, UptimeText, Error,
    @{n='Links';e={($_.Links | ForEach-Object { "$($_.LinkName)/$($_.Interface)=$($_.StateText)" }) -join '; '}} |
    Export-Csv -Path $ExportPath -NoTypeInformation
Write-Host "`nExported: $ExportPath" -ForegroundColor Cyan

# ---------- exit code ----------
$badLinks = @($sites | ForEach-Object { $_.Links } | Where-Object { $_.StateText -eq 'BAD' })
$errored  = @($sites | Where-Object { $_.Error })
if ($badLinks.Count -gt 0 -or $errored.Count -gt 0) {
    if ($badLinks.Count -gt 0) {
        Write-Host "$($badLinks.Count) BAD link(s) detected:" -ForegroundColor Red
        $badLinks | ForEach-Object {
            $site = $sites | Where-Object { $_.Links -contains $_ } | Select-Object -First 1
        }
        $sites | ForEach-Object {
            $bad = @($_.Links | Where-Object { $_.StateText -eq 'BAD' })
            if ($bad.Count -gt 0) {
                Write-Host ("  {0} ({1}): {2}" -f $_.FirewallName, $_.IP, (($bad | ForEach-Object { "$($_.LinkName)/$($_.Interface)" }) -join ', ')) -ForegroundColor Red
            }
        }
    }
    if ($errored.Count -gt 0) {
        Write-Host "$($errored.Count) device(s) had errors: $(($errored | ForEach-Object { $_.FirewallName }) -join ', ')" -ForegroundColor Red
    }
    exit 1
}
Write-Host "All links OK on all devices." -ForegroundColor Green
exit 0
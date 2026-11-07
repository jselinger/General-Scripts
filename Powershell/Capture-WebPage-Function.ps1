# (c)Josh Selinger   with AI assitance

function Capture-WebPage {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Url,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$OutputPath,

        [int]$Width = 1920,
        [int]$Height = 1080,
        [int]$WaitSeconds = 3
    )

    $ErrorActionPreference = "Stop"

    # Locate Microsoft Edge
    $EdgePaths = @(
        "${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe",
        "$env:ProgramFiles\Microsoft\Edge\Application\msedge.exe",
        "$env:LOCALAPPDATA\Microsoft\Edge\Application\msedge.exe"
    )

    $Edge = $EdgePaths |
        Where-Object { $_ -and (Test-Path $_) } |
        Select-Object -First 1

    if (-not $Edge) {
        throw "Microsoft Edge was not found. Install Edge or update the Edge executable path."
    }

    # Validate URL
    $ParsedUrl = $null
    if (-not [Uri]::TryCreate(
        $Url,
        [UriKind]::Absolute,
        [ref]$ParsedUrl
    ) -or $ParsedUrl.Scheme -notin @("http", "https")) {
        throw "Please provide a valid HTTP or HTTPS URL."
    }

    # Resolve output path and create its directory
    $OutputPath = $ExecutionContext.SessionState.Path.
        GetUnresolvedProviderPathFromPSPath($OutputPath)

    $OutputDirectory = Split-Path -Parent $OutputPath
    if ($OutputDirectory -and !(Test-Path $OutputDirectory)) {
        New-Item -ItemType Directory -Path $OutputDirectory -Force |
            Out-Null
    }

    # Use a temporary browser profile for this capture
    $ProfilePath = Join-Path $env:TEMP (
        "EdgeScreenshot-" + [guid]::NewGuid().ToString("N")
    )

    try {
        $Arguments = @(
            "--headless"
            "--disable-gpu"
            "--no-first-run"
            "--no-default-browser-check"
            "--hide-scrollbars"
            "--disable-extensions"
            "--ignore-certificate-errors"
            "--user-data-dir=`"$ProfilePath`""
            "--window-size=$Width,$Height"
            "--run-all-compositor-stages-before-draw"
            "--virtual-time-budget=$($WaitSeconds * 1000)"
            "--screenshot=`"$OutputPath`""
            "`"$Url`""
        )

        Write-Host "Rendering: $Url"

        $Process = Start-Process `
            -FilePath $Edge `
            -ArgumentList $Arguments `
            -PassThru `
            -Wait

        if ($Process.ExitCode -ne 0 -or !(Test-Path $OutputPath)) {
            throw "Screenshot capture failed. Edge exit code: $($Process.ExitCode)"
        }

        Write-Host "Screenshot saved to: $OutputPath"
        Write-Host "Image size: $Width x $Height"

        return $OutputPath
    }
    finally {
        # Clean up the temporary browser profile
        if (Test-Path $ProfilePath) {
            Remove-Item $ProfilePath -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$UpstreamRoot,

    [string]$GatewayUrl = "http://127.0.0.1:8765",
    [string]$ReportName = "automation_upstream",
    [string]$OutputPath,
    [string]$PythonPath
)

$ErrorActionPreference = "Stop"

$resolvedUpstream = (Resolve-Path -LiteralPath $UpstreamRoot).Path
$upstreamCli = Join-Path $resolvedUpstream "cli\main.py"
$scanQueue = Join-Path $resolvedUpstream "dataset\scan_queue"

if (-not (Test-Path -LiteralPath $upstreamCli -PathType Leaf)) {
    throw "Upstream CLI not found: $upstreamCli"
}
if (-not (Test-Path -LiteralPath $scanQueue -PathType Container)) {
    throw "Upstream scan queue not found: $scanQueue"
}

if (-not $OutputPath) {
    $projectRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..")).Path
    $OutputPath = Join-Path $projectRoot "runs\upstream-shim"
}
$resolvedOutput = [System.IO.Path]::GetFullPath($OutputPath)
New-Item -ItemType Directory -Force -Path $resolvedOutput | Out-Null
$outputWithSeparator = $resolvedOutput.TrimEnd("\", "/") + [System.IO.Path]::DirectorySeparatorChar

$arguments = @(
    "cli/main.py",
    "scan",
    "--folder-path", $scanQueue,
    "--n8n-url", $GatewayUrl.TrimEnd("/"),
    "--report-name", $ReportName,
    "--output-path", $outputWithSeparator,
    "--output-format", "json"
)

$previousPythonUtf8 = $env:PYTHONUTF8
$previousPythonIoEncoding = $env:PYTHONIOENCODING
$env:PYTHONUTF8 = "1"
$env:PYTHONIOENCODING = "utf-8"

Push-Location $resolvedUpstream
try {
    if ($PythonPath) {
        $resolvedPython = (Resolve-Path -LiteralPath $PythonPath).Path
        & $resolvedPython @arguments
    }
    elseif (Get-Command poetry -ErrorAction SilentlyContinue) {
        & poetry run python @arguments
    }
    else {
        & python @arguments
    }
    if ($LASTEXITCODE -ne 0) {
        throw "Upstream Bastet exited with code $LASTEXITCODE"
    }
}
finally {
    Pop-Location
    $env:PYTHONUTF8 = $previousPythonUtf8
    $env:PYTHONIOENCODING = $previousPythonIoEncoding
}

$report = Join-Path $resolvedOutput "$ReportName.json"
if (-not (Test-Path -LiteralPath $report -PathType Leaf)) {
    throw "Upstream CLI completed without creating $report"
}

Write-Output "Upstream-compatible mock scan completed: $report"
Write-Output "This proves pipeline compatibility only; it is not a quality or win result."

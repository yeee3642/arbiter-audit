# Ablation sweep: turn one improvement off at a time and re-score.
# The response cache makes repeated arms cheap -- only the configurations that
# actually change a request payload cost tokens.
$ErrorActionPreference = "Stop"
Set-Location (Split-Path $PSScriptRoot -Parent)

$runs = @(
    @{ tag = "full";            args = @("--samples", "3") },
    @{ tag = "no_verify";       args = @("--samples", "3", "--no-verify") },
    @{ tag = "no_selfconsist";  args = @("--samples", "1") },
    @{ tag = "no_grounding";    args = @("--samples", "3", "--keep-ungrounded") },
    @{ tag = "no_slicing";      args = @("--samples", "3", "--no-slice") }
)

foreach ($r in $runs) {
    Write-Host "`n=== ablation: $($r.tag) ===" -ForegroundColor Cyan
    python -u -m bastet_plus bench --arms enhanced --tag $r.tag --concurrency 12 @($r.args)
}

Write-Host "`nsummarise with: python tools/summarise_ablations.py" -ForegroundColor Green

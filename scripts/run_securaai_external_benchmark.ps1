param(
    [ValidateRange(1, 10)]
    [int]$Repeats = 1,
    [string]$BackendPath = (Join-Path $PSScriptRoot '..\..\SecuraAI-Backend'),
    [string]$Output = (Join-Path $PSScriptRoot '..\reports\securaai_external_benchmark_runs.json')
)

$ErrorActionPreference = 'Stop'
$demo = Join-Path $BackendPath 'scripts\wazuh\demo-detection.ps1'
if (-not (Test-Path -LiteralPath $demo)) { throw "Missing SecuraAI demo script: $demo" }

$specs = @(
    [pscustomobject]@{ case = 'Normal'; count = $null; threshold = $null },
    [pscustomobject]@{ case = 'AuthBurst'; count = 2; threshold = 5 },
    [pscustomobject]@{ case = 'AuthBurst'; count = 4; threshold = 5 },
    [pscustomobject]@{ case = 'AuthBurst'; count = 5; threshold = 5 },
    [pscustomobject]@{ case = 'AuthBurst'; count = 6; threshold = 5 },
    [pscustomobject]@{ case = 'AuthBurst'; count = 10; threshold = 5 },
    [pscustomobject]@{ case = 'AppDenial'; count = 8; threshold = 10 },
    [pscustomobject]@{ case = 'AppDenial'; count = 10; threshold = 10 },
    [pscustomobject]@{ case = 'AppDenial'; count = 11; threshold = 10 },
    [pscustomobject]@{ case = 'AppDenial'; count = 15; threshold = 10 },
    [pscustomobject]@{ case = 'VpnBurst'; count = 2; threshold = 5 },
    [pscustomobject]@{ case = 'VpnBurst'; count = 4; threshold = 5 },
    [pscustomobject]@{ case = 'VpnBurst'; count = 5; threshold = 5 },
    [pscustomobject]@{ case = 'VpnBurst'; count = 6; threshold = 5 },
    [pscustomobject]@{ case = 'VpnBurst'; count = 10; threshold = 5 }
)

$runs = @()
$runNumber = 0
$batchOctet = Get-Random -Minimum 1 -Maximum 255
for ($repeat = 1; $repeat -le $Repeats; $repeat++) {
    foreach ($spec in $specs) {
        $runNumber++
        # Keep benchmark sessions independent. Reusing one source IP would correctly
        # turn consecutive runs into a cross-account password-spray sequence.
        $sourceIp = "198.19.$batchOctet.$runNumber"
        $arguments = @{ Case = $spec.case; Send = $true; SourceIp = $sourceIp }
        if ($null -ne $spec.count) { $arguments.BurstCount = $spec.count }
        $lines = & $demo @arguments *>&1 | ForEach-Object { $_.ToString() }
        $lines | Write-Host
        if (-not ($lines | Where-Object { $_ -match '^Dispatch complete\.' })) {
            throw "Dispatch was not confirmed for $($spec.case); no benchmark manifest was written."
        }
        $header = $lines | Where-Object { $_ -match '^Case: .* \| Run: ' } | Select-Object -First 1
        if (-not $header) { throw "No run ID returned for $($spec.case)" }
        $runId = ($header -split '\| Run: ', 2)[1].Trim()
        $runs += [pscustomobject]@{
            run_id = $runId
            scenario = $spec.case
            burst_count = $spec.count
            decision_threshold = $spec.threshold
            repeat = $repeat
            source_ip = $sourceIp
            data_role = 'EXTERNAL_TEST_ONLY'
        }
    }
}

$outputPath = [IO.Path]::GetFullPath($Output)
[IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($outputPath)) | Out-Null
[IO.File]::WriteAllText($outputPath, ($runs | ConvertTo-Json -Depth 4), (New-Object Text.UTF8Encoding($false)))
Write-Host "Saved $($runs.Count) external benchmark runs to $outputPath"

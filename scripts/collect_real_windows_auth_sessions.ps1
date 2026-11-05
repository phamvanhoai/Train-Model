param(
    [ValidateRange(10, 60)]
    [int]$Sessions = 30,
    [string]$Target = '\\192.168.1.63\IPC$',
    [string]$OutputDirectory = (Join-Path $PSScriptRoot '..\data\real_windows_auth_lab')
)

$ErrorActionPreference = 'Stop'
$runId = 'real-auth-' + [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
$runToken = $runId.Substring($runId.Length - 6)
$startedAt = [DateTimeOffset]::UtcNow
$sessionRows = @()

for ($sessionIndex = 0; $sessionIndex -lt $Sessions; $sessionIndex++) {
    $malicious = ($sessionIndex % 2) -eq 1
    $attemptCount = if ($malicious) { 5 + ($sessionIndex % 4) } else { 1 + ($sessionIndex % 4) }
    $splitBucket = $sessionIndex % 10
    $split = if ($splitBucket -lt 6) { 'TRAIN' } elseif ($splitBucket -lt 8) { 'VALIDATION' } else { 'TEST' }
    $sessionId = '{0}-session-{1:D3}' -f $runId, $sessionIndex
    $sessionStart = [DateTimeOffset]::UtcNow
    $accounts = @()
    for ($position = 1; $position -le $attemptCount; $position++) {
        # Sixteen characters, below the traditional Windows account-name limit.
        $account = 'SR{0}S{1:D2}E{2:D2}' -f $runToken, $sessionIndex, $position
        $accounts += $account
        $previousPreference = $ErrorActionPreference
        $ErrorActionPreference = 'Continue'
        & "$env:SystemRoot\System32\net.exe" use $Target 'SecuraAI-Invalid-Password!' "/user:$account" 2>$null | Out-Null
        $ErrorActionPreference = $previousPreference
        Start-Sleep -Seconds 2
    }
    $sessionRows += [ordered]@{
        scenarioId = $sessionId
        scenario = if ($malicious) { 'REAL_WINDOWS_PASSWORD_SPRAY' } else { 'REAL_WINDOWS_BENIGN_FAILURES' }
        sessionSplit = $split
        maliciousSession = $malicious
        attempts = $attemptCount
        operationalBoundary = 5
        accounts = $accounts
        startedAt = $sessionStart.ToString('o')
        endedAt = [DateTimeOffset]::UtcNow.ToString('o')
    }
    Start-Sleep -Seconds 1
}

$outputPath = [IO.Path]::GetFullPath($OutputDirectory)
[IO.Directory]::CreateDirectory($outputPath) | Out-Null
$manifest = [ordered]@{
    schemaVersion = 1
    runId = $runId
    groundTruthSource = 'CONTROLLED_REAL_WINDOWS_AUTH_LAB'
    dataRole = 'TRAIN_VALIDATION_AND_LOCKED_TEST_BY_WHOLE_SESSION'
    host = $env:COMPUTERNAME
    target = $Target
    startedAt = $startedAt.ToString('o')
    endedAt = [DateTimeOffset]::UtcNow.ToString('o')
    sessionCount = $Sessions
    sessions = $sessionRows
}
$manifestFile = Join-Path $outputPath "$runId.manifest.json"
[IO.File]::WriteAllText($manifestFile, ($manifest | ConvertTo-Json -Depth 8), (New-Object Text.UTF8Encoding($false)))
Write-Host "Run: $runId"
Write-Host "Sessions: $Sessions"
Write-Host "Manifest: $manifestFile"

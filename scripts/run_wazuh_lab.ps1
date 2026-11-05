param(
    [int]$FailedLoginAttempts = 12,
    [int]$DelayMilliseconds = 750
)

$ErrorActionPreference = 'Stop'
$runId = 'securaai-lab-' + [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
$invalidUser = 'SecuraAI_Lab_Invalid_' + $runId.Substring($runId.Length - 6)
$startedAt = [DateTimeOffset]::UtcNow

# Harmless baseline activity. These processes are useful when process creation
# auditing/Sysmon is enabled and otherwise have no persistent system effect.
$null = whoami.exe
$null = hostname.exe
$null = ipconfig.exe
$null = powershell.exe -NoProfile -NonInteractive -Command "Get-Date | Out-Null"

$attackStartedAt = [DateTimeOffset]::UtcNow
$previousErrorAction = $ErrorActionPreference
$ErrorActionPreference = 'Continue'
for ($index = 1; $index -le $FailedLoginAttempts; $index++) {
    # A random non-existent account prevents lockout of any real account. The
    # failed local SMB authentication creates Windows Security Event 4625.
    $attemptUser = $invalidUser + '_' + $index
    & net.exe use '\\127.0.0.1\IPC$' /user:$attemptUser 'SecuraAI-Lab-Wrong-Password!' *> $null
    Start-Sleep -Milliseconds $DelayMilliseconds
}
$ErrorActionPreference = $previousErrorAction
$attackEndedAt = [DateTimeOffset]::UtcNow

# Suspicious-looking but harmless process telemetry. The encoded command only
# assigns a marker string and produces no files, registry keys, or network I/O.
$encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes("`$marker='$runId'; `$null=`$marker.Length"))
$null = powershell.exe -NoProfile -NonInteractive -EncodedCommand $encoded
$endedAt = [DateTimeOffset]::UtcNow

$manifest = [ordered]@{
    run_id = $runId
    host = $env:COMPUTERNAME
    data_origin = 'CONTROLLED_LAB_VIA_WAZUH'
    started_at = $startedAt.ToString('o')
    attack_started_at = $attackStartedAt.ToString('o')
    attack_ended_at = $attackEndedAt.ToString('o')
    ended_at = $endedAt.ToString('o')
    invalid_username = $invalidUser
    failed_login_attempts = $FailedLoginAttempts
    ground_truth = @(
        [ordered]@{ phase = 'baseline'; label = 'BENIGN'; from = $startedAt.ToString('o'); to = $attackStartedAt.ToString('o') },
        [ordered]@{ phase = 'failed_login_burst'; label = 'MALICIOUS_APT'; from = $attackStartedAt.ToString('o'); to = $attackEndedAt.ToString('o') },
        [ordered]@{ phase = 'encoded_powershell_simulation'; label = 'MALICIOUS_APT'; from = $attackEndedAt.ToString('o'); to = $endedAt.ToString('o') }
    )
    safety = 'No malware, persistence, privilege escalation, destructive action, or real-account authentication.'
}

$outputDirectory = Join-Path $PSScriptRoot '..\data\securaai_lab'
New-Item -ItemType Directory -Path $outputDirectory -Force | Out-Null
$outputPath = Join-Path $outputDirectory ($runId + '.json')
$manifest | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $outputPath -Encoding utf8
$manifest | ConvertTo-Json -Depth 6
Write-Host "Manifest: $outputPath"

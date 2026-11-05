param(
    [ValidateRange(1, 20)]
    [int]$FailureCount = 6,
    [string]$OutputDirectory = (Join-Path $PSScriptRoot '..\data\windows_auth_lab')
)

$ErrorActionPreference = 'Stop'
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this script from an elevated PowerShell window (Run as administrator).'
}

$runId = 'securaai-real-auth-' + [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
$startedAt = [DateTimeOffset]::UtcNow
$labUser = 'SecuraAI_Lab_Nonexistent'
$outputPath = [IO.Path]::GetFullPath($OutputDirectory)
[IO.Directory]::CreateDirectory($outputPath) | Out-Null

# These are genuine Windows authentication attempts. The deliberately nonexistent
# user avoids locking or modifying any real account.
auditpol.exe /set /subcategory:'Logon' /success:enable /failure:enable | Out-Null
Restart-Service -Name WazuhSvc -Force
Start-Sleep -Seconds 5

$attempts = @()
for ($index = 1; $index -le $FailureCount; $index++) {
    $attemptedAt = [DateTimeOffset]::UtcNow
    $process = Start-Process -FilePath "$env:SystemRoot\System32\net.exe" `
        -ArgumentList @('use', '\\127.0.0.1\IPC$', 'SecuraAI-Invalid-Password!', "/user:$labUser") `
        -WindowStyle Hidden -Wait -PassThru
    $attempts += [ordered]@{
        eventIndex = $index
        attemptedAt = $attemptedAt.ToString('o')
        exitCode = $process.ExitCode
        expectedLabel = if ($index -ge 5) { 'MALICIOUS_APT' } else { 'BENIGN' }
    }
    net.exe use '\\127.0.0.1\IPC$' /delete /y 2>$null | Out-Null
    Start-Sleep -Seconds 3
}

Start-Sleep -Seconds 5
$endedAt = [DateTimeOffset]::UtcNow
$events = Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    Id = 4625
    StartTime = $startedAt.LocalDateTime.AddSeconds(-2)
    EndTime = $endedAt.LocalDateTime.AddSeconds(2)
} -ErrorAction SilentlyContinue | ForEach-Object {
    $xml = [xml]$_.ToXml()
    $fields = @{}
    foreach ($item in $xml.Event.EventData.Data) { $fields[$item.Name] = [string]$item.'#text' }
    [ordered]@{
        recordId = $_.RecordId
        timeCreated = $_.TimeCreated.ToUniversalTime().ToString('o')
        eventId = $_.Id
        targetUserName = $fields['TargetUserName']
        ipAddress = $fields['IpAddress']
        logonType = $fields['LogonType']
        status = $fields['Status']
        subStatus = $fields['SubStatus']
    }
}

$manifest = [ordered]@{
    schemaVersion = 1
    runId = $runId
    groundTruthSource = 'CONTROLLED_REAL_WINDOWS_AUTH_LAB'
    dataRole = 'EXTERNAL_TEST_ONLY_NEVER_TRAIN_UNTIL_REVIEWED'
    host = $env:COMPUTERNAME
    startedAt = $startedAt.ToString('o')
    endedAt = $endedAt.ToString('o')
    behavior = 'SMB authentication failures against localhost using a deliberately nonexistent account'
    labAccount = $labUser
    expectedEventId = 4625
    operationalBoundary = 5
    requestedAttempts = $FailureCount
    observedSecurityEvents = @($events).Count
    attempts = $attempts
    securityEvents = @($events)
}
$manifestFile = Join-Path $outputPath "$runId.manifest.json"
[IO.File]::WriteAllText($manifestFile, ($manifest | ConvertTo-Json -Depth 8), (New-Object Text.UTF8Encoding($false)))
Write-Host "Run: $runId"
Write-Host "Observed Windows Security 4625 events: $(@($events).Count)"
Write-Host "Manifest: $manifestFile"
if (@($events).Count -lt $FailureCount) {
    throw "Only $(@($events).Count)/$FailureCount Security events were observed; check local SMB and audit policy."
}

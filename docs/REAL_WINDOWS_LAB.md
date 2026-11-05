# Controlled real Windows authentication lab

This lab produces genuine Windows Security authentication telemetry rather than generated CSV
rows. It targets localhost with a deliberately nonexistent username, so no real user is modified
or locked. Windows records Event ID 4625, the Wazuh Agent collects it, and the run manifest records
the exact time range and controlled ground truth.

Run once from **PowerShell as Administrator**:

```powershell
cd C:\Users\Admin\Documents\GITHUB\Train-Model
powershell -ExecutionPolicy Bypass -File .\scripts\run_real_windows_auth_lab.ps1
```

The script enables success/failure Logon auditing, restarts the Wazuh Agent after enrollment,
performs six failed localhost SMB authentications, reads the resulting Security events and writes
an external-test-only manifest under `data/windows_auth_lab/`. Do not append the resulting events
to Train until an independent review confirms the event/run mapping.

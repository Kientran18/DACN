<#
.SYNOPSIS
  Generates harmless activity so Sysmon emits sample events (Issue #16).
.DESCRIPTION
  Run on the LAB VM only. Admin rights are NOT required to generate events.
  Every command line and file name carries a marker (EDR_POC_<timestamp>) so the
  export script can find the matching events.
  NOT yet run on a real machine: run it once after installing Sysmon and read the output.
.EXAMPLE
  powershell -ExecutionPolicy Bypass -File .\run-poc-activities.ps1
  powershell -ExecutionPolicy Bypass -File .\run-poc-activities.ps1 -RunKeyTest -SkipNetwork
#>
[CmdletBinding()]
param(
    [string]$WorkDir = (Join-Path $env:TEMP 'edr_poc'),
    [switch]$SkipNetwork,
    [switch]$RunKeyTest
)

$ErrorActionPreference = 'Stop'
$RunId  = Get-Date -Format 'yyyyMMdd_HHmmss'
$Marker = "EDR_POC_$RunId"
$Start  = (Get-Date).ToUniversalTime()
$Steps  = New-Object System.Collections.Generic.List[object]
$Sys32  = Join-Path $env:SystemRoot 'System32'

function Invoke-Step {
    param([string]$Name, [scriptblock]$Action)
    $t0 = (Get-Date).ToUniversalTime()
    $status = 'ok'
    $detail = ''
    try { & $Action } catch { $status = 'error'; $detail = $_.Exception.Message; Write-Warning "$Name failed: $detail" }
    $Steps.Add([ordered]@{ step = $Name; start_utc = $t0.ToString('o'); status = $status; detail = $detail })
    Write-Host ("[{0}] {1}" -f $status.ToUpper(), $Name)
}

Write-Host "Marker for this run: $Marker"
New-Item -ItemType Directory -Force -Path $WorkDir | Out-Null

# 1. Normal process creation (Sysmon 1, then 5 when it exits)
Invoke-Step '1_normal_process' {
    Start-Process -FilePath (Join-Path $Sys32 'cmd.exe') -ArgumentList "/c echo $Marker step1_normal" -WindowStyle Hidden -Wait
}

# 2. Parent-child activity: powershell -> cmd -> whoami / hostname, and powershell -> powershell
Invoke-Step '2_parent_child' {
    Start-Process -FilePath (Join-Path $Sys32 'cmd.exe') -ArgumentList "/c whoami.exe & hostname.exe & echo $Marker step2_parent_child" -WindowStyle Hidden -Wait
    $ps = Join-Path $Sys32 'WindowsPowerShell\v1.0\powershell.exe'
    Start-Process -FilePath $ps -ArgumentList "-NoProfile -Command Write-Output $Marker-step2b" -WindowStyle Hidden -Wait
}

# 3. File activity under %TEMP%\edr_poc (matches the \Temp\ rule)
#    create / truncating overwrite / append / rename / delete, then drop-execute-delete of a harmless signed binary
Invoke-Step '3_file_activity' {
    $f = Join-Path $WorkDir "$Marker.txt"
    Set-Content -Path $f -Value 'create'
    Start-Sleep -Milliseconds 500
    Set-Content -Path $f -Value 'overwrite (truncate)'
    Start-Sleep -Milliseconds 500
    Add-Content -Path $f -Value 'append'
    Start-Sleep -Milliseconds 500
    $renamed = "$Marker.renamed.txt"
    Rename-Item -Path $f -NewName $renamed
    Remove-Item -Path (Join-Path $WorkDir $renamed) -Force

    $drop = Join-Path $WorkDir "${Marker}_drop.exe"
    Copy-Item -Path (Join-Path $Sys32 'hostname.exe') -Destination $drop
    Start-Sleep -Seconds 1
    Start-Process -FilePath $drop -WindowStyle Hidden -Wait
    Start-Sleep -Seconds 1
    Remove-Item -Path $drop -Force
}

# 4. Safe registry activity under HKCU\Software\EDR_PoC (matches the \Software\EDR_PoC rule)
Invoke-Step '4_registry_activity' {
    $k = 'HKCU:\Software\EDR_PoC'
    New-Item -Path $k -Force | Out-Null
    New-ItemProperty -Path $k -Name 'TestString' -Value $Marker -PropertyType String -Force | Out-Null
    New-ItemProperty -Path $k -Name 'TestDword' -Value 1 -PropertyType DWord -Force | Out-Null
    Remove-ItemProperty -Path $k -Name 'TestString' -Force
    Remove-Item -Path $k -Recurse -Force

    if ($RunKeyTest) {
        # Optional: Run key pointing to a file that does not exist; removed immediately.
        $run  = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
        $name = "EDR_PoC_$RunId"
        try {
            New-ItemProperty -Path $run -Name $name -Value 'C:\EDR_PoC_nonexistent\noop.exe' -PropertyType String -Force | Out-Null
        } finally {
            Remove-ItemProperty -Path $run -Name $name -Force -ErrorAction SilentlyContinue
        }
    }
}

# 5. Safe network activity: HTTPS request to example.com (Sysmon 22 DNS, Sysmon 3 connection)
if (-not $SkipNetwork) {
    Invoke-Step '5_network_activity' {
        Invoke-WebRequest -Uri 'https://example.com' -UseBasicParsing -TimeoutSec 20 | Out-Null
    }
}

Start-Sleep -Seconds 3   # let Sysmon flush to the event log

$summary = [ordered]@{
    marker    = $Marker
    start_utc = $Start.ToString('o')
    end_utc   = (Get-Date).ToUniversalTime().ToString('o')
    host      = $env:COMPUTERNAME
    work_dir  = $WorkDir
    steps     = $Steps
}
$out = Join-Path $WorkDir "poc_run_$RunId.json"
$summary | ConvertTo-Json -Depth 5 | Set-Content -Path $out -Encoding UTF8
Write-Host "Run log: $out"
Write-Host "Next: run export-samples.ps1 as Administrator (Marker prefix EDR_POC_)."

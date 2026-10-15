<#
.SYNOPSIS
  Exports raw Sysmon events (XML) matching the PoC activity, for Issue #16.
.DESCRIPTION
  Must run as Administrator (reads the Sysmon channel). Writes one XML file per event type
  plus recent_events_all.xml and export_manifest.json. NOT yet run on a real machine.
  -Sanitize replaces the SID, computer name and user name with placeholders so samples can be
  committed; it slightly changes the raw text, so keep an unsanitized copy offline.
.EXAMPLE
  .\export-samples.ps1 -OutDir .\samples\raw -SinceMinutes 30 -Sanitize
#>
#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    [string]$OutDir = (Join-Path (Get-Location) 'samples\raw'),
    [int]$SinceMinutes = 60,
    [string]$Marker = 'EDR_POC_',
    [int]$RecentCount = 200,
    [switch]$Sanitize
)

$Channel = 'Microsoft-Windows-Sysmon/Operational'
$since   = (Get-Date).AddMinutes(-$SinceMinutes)
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

function Protect-Xml([string]$xml) {
    if (-not $Sanitize) { return $xml }
    $xml = $xml -replace 'S-1-5-21-[\d-]+', 'S-1-5-21-LAB'
    $xml = $xml -replace [regex]::Escape($env:COMPUTERNAME), 'LAB-HOST'
    $xml = $xml -replace [regex]::Escape($env:USERNAME), 'LABUSER'
    return $xml
}

# Name, Sysmon event id, regex that must appear in the event XML, how many events to keep
$specs = @(
    @{ Name = 'raw_process_create_event1';        Id = 1;  Pattern = $Marker;         Take = 3 },
    @{ Name = 'raw_process_terminate_event5';     Id = 5;  Pattern = 'cmd\.exe';      Take = 1 },
    @{ Name = 'raw_file_create_event11';          Id = 11; Pattern = $Marker;         Take = 4 },
    @{ Name = 'raw_file_delete_event26';          Id = 26; Pattern = $Marker;         Take = 2 },
    @{ Name = 'raw_file_executable_event29';      Id = 29; Pattern = '_drop\.exe';    Take = 1 },
    @{ Name = 'raw_registry_key_event12';         Id = 12; Pattern = 'EDR_PoC';       Take = 2 },
    @{ Name = 'raw_registry_setvalue_event13';    Id = 13; Pattern = 'EDR_PoC';       Take = 2 },
    @{ Name = 'raw_network_connect_event3';       Id = 3;  Pattern = 'powershell\.exe'; Take = 1 },
    @{ Name = 'raw_dns_query_event22';            Id = 22; Pattern = 'example\.com';  Take = 1 },
    @{ Name = 'raw_sysmon_state_event4';          Id = 4;  Pattern = '.';             Take = 1 },
    @{ Name = 'raw_sysmon_config_event16';        Id = 16; Pattern = '.';             Take = 1 }
)

$manifest = [ordered]@{ exported_utc = (Get-Date).ToUniversalTime().ToString('o'); sanitized = [bool]$Sanitize; files = @() }
try { $manifest.sysmon_version = (Get-Item (Join-Path $env:SystemRoot 'Sysmon64.exe')).VersionInfo.FileVersion } catch { $manifest.sysmon_version = 'unknown' }
try { $manifest.windows_version = (Get-CimInstance Win32_OperatingSystem).Version } catch { $manifest.windows_version = 'unknown' }

foreach ($s in $specs) {
    $events = Get-WinEvent -FilterHashtable @{ LogName = $Channel; Id = $s.Id; StartTime = $since } -ErrorAction SilentlyContinue
    $hits = @($events | Where-Object { $_.ToXml() -match $s.Pattern } | Select-Object -First $s.Take)
    if ($hits.Count -eq 0) {
        Write-Warning ("No Sysmon event {0} matching '{1}' in the last {2} minutes ({3})" -f $s.Id, $s.Pattern, $SinceMinutes, $s.Name)
        $manifest.files += [ordered]@{ name = $s.Name; event_id = $s.Id; count = 0 }
        continue
    }
    $xml  = ($hits | ForEach-Object { Protect-Xml $_.ToXml() }) -join "`r`n"
    $path = Join-Path $OutDir ($s.Name + '.xml')
    Set-Content -Path $path -Value $xml -Encoding UTF8
    $manifest.files += [ordered]@{ name = $s.Name; event_id = $s.Id; count = $hits.Count }
    Write-Host ("[OK] {0}: {1} event(s)" -f $s.Name, $hits.Count)
}

$recentRaw = (wevtutil qe $Channel /c:$RecentCount /rd:true /f:xml | Out-String)
Set-Content -Path (Join-Path $OutDir 'recent_events_all.xml') -Value (Protect-Xml $recentRaw) -Encoding UTF8

$manifest | ConvertTo-Json -Depth 4 | Set-Content -Path (Join-Path $OutDir 'export_manifest.json') -Encoding UTF8
Write-Host "Done. Output: $OutDir"

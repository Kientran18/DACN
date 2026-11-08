<#
.SYNOPSIS
  Kịch bản mô phỏng AN TOÀN cho DACN EDR (PH5-T02). CHỈ chạy trên Windows 10 VM lab có snapshot sạch.
.DESCRIPTION
  - Mọi hành động đều qua ShouldProcess: chạy với -WhatIf trước để xem sẽ làm gì mà không làm gì cả.
  - Chỉ ghi trong %TEMP%\dacn_lab\, %PUBLIC%\dacn_lab\ và HKCU (giá trị Run có tiền tố DACN_LAB_, xóa ngay).
  - KHÔNG tải mạng, KHÔNG tắt Defender/Sysmon, KHÔNG đổi chính sách bảo mật, KHÔNG khởi động lại, KHÔNG xóa theo wildcard.
  - Mọi tên tệp/giá trị/command line mang marker DACN_LAB_<RunId>_<SCxx> để đối chiếu (compare_expected.py).
  - Cuối cùng ghi lab_run_<RunId>.json (đường dẫn dạng %TEMP%, không có hostname).
  - Chưa được chạy trên máy thật khi viết: ĐỌC kỹ, chạy -WhatIf, rồi mới chạy thật.
.EXAMPLE
  powershell -ExecutionPolicy Bypass -File .\dacn_lab_scenarios.ps1 -WhatIf
  powershell -ExecutionPolicy Bypass -File .\dacn_lab_scenarios.ps1 -Scenario SC01,SC02,SC03,SC06,SC07
  powershell -ExecutionPolicy Bypass -File .\dacn_lab_scenarios.ps1 -Scenario SC04      # cần csc.exe (.NET Framework có sẵn)
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [ValidateSet('SC01','SC02','SC03','SC04','SC05','SC06','SC07')]
    [string[]]$Scenario = @('SC01','SC02','SC03','SC06','SC07'),
    [string]$RunId = (Get-Date -Format 'yyyyMMddHHmmss'),
    [switch]$Eicar   # chỉ dùng cho SC05; Windows Defender có thể chặn/xóa tệp, đó là kết quả cần ghi nhận trung thực
)

$ErrorActionPreference = 'Stop'
$Prefix   = "DACN_LAB_$RunId"
$LabDir   = Join-Path $env:TEMP 'dacn_lab'
$PubDir   = Join-Path $env:PUBLIC 'dacn_lab'
$Sys32    = Join-Path $env:SystemRoot 'System32'
$PsExe    = Join-Path $Sys32 'WindowsPowerShell\v1.0\powershell.exe'
$RunKey   = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
$TestKey  = 'HKCU:\Software\EDR_PoC'
$Results  = New-Object System.Collections.Generic.List[object]
$Created  = New-Object System.Collections.Generic.List[string]   # tệp do lần chạy này tạo (dọn từng tệp, không wildcard)
$RunValues = New-Object System.Collections.Generic.List[string]  # giá trị Run do lần chạy này tạo

function ConvertTo-Token([string]$p) {
    $p.Replace($env:TEMP, '%TEMP%').Replace($env:PUBLIC, '%PUBLIC%')
}

function Assert-InLab([string]$p) {
    $full = [System.IO.Path]::GetFullPath($p)
    $ok = $full.StartsWith($LabDir, [StringComparison]::OrdinalIgnoreCase) -or $full.StartsWith($PubDir, [StringComparison]::OrdinalIgnoreCase)
    if (-not $ok) { throw "Từ chối thao tác ngoài thư mục lab: $full" }
    if ($full.Contains('*') -or $full.Contains('?')) { throw "Từ chối wildcard: $full" }
    return $full
}

function Remove-LabFile([string]$p) {
    $full = Assert-InLab $p
    if (Test-Path -LiteralPath $full) { Remove-Item -LiteralPath $full -Force }
}

function Invoke-Scenario {
    param([string]$Id, [string]$Title, [scriptblock]$Action)
    $marker = "${Prefix}_$Id"
    $t0 = (Get-Date).ToUniversalTime()
    $status = 'ok'; $detail = ''
    if ($PSCmdlet.ShouldProcess("$Id $Title (marker $marker)", 'Run scenario')) {
        try { & $Action $marker } catch { $status = 'error'; $detail = $_.Exception.Message; Write-Warning "$Id lỗi: $detail" }
    } else { $status = 'whatif' }
    $Results.Add([ordered]@{ id = $Id; title = $Title; marker = $marker; status = $status; detail = $detail
        start_utc = $t0.ToString('o'); end_utc = (Get-Date).ToUniversalTime().ToString('o') })
    Write-Host ("[{0}] {1} {2}" -f $status.ToUpper(), $Id, $Title)
}

New-Item -ItemType Directory -Force -Path $LabDir | Out-Null
New-Item -ItemType Directory -Force -Path $PubDir | Out-Null
Write-Host "RunId: $RunId   Prefix: $Prefix   (nhớ chụp snapshot sạch trước khi chạy)"

try {
    if ($Scenario -contains 'SC01') {
        Invoke-Scenario 'SC01' 'PowerShell EncodedCommand vô hại' {
            param($m)
            $b64 = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes("Write-Output $m"))
            Start-Process -FilePath $PsExe -ArgumentList "-NoProfile -ExecutionPolicy Bypass -EncodedCommand $b64" -WindowStyle Hidden -Wait
        }
    }
    if ($Scenario -contains 'SC02') {
        Invoke-Scenario 'SC02' 'Giá trị Run key (xóa ngay, không khởi động lại)' {
            param($m)
            $name = $m
            $RunValues.Add($name)
            New-ItemProperty -Path $RunKey -Name $name -Value "cmd.exe /c echo $m" -PropertyType String -Force | Out-Null
            Start-Sleep -Milliseconds 800
            Remove-ItemProperty -Path $RunKey -Name $name -Force
            [void]$RunValues.Remove($name)
        }
    }
    if ($Scenario -contains 'SC03') {
        Invoke-Scenario 'SC03' 'Drop, execute, delete (whoami.exe đã ký của Windows)' {
            param($m)
            $drop = Assert-InLab (Join-Path $LabDir "${m}_whoami.exe")
            $Created.Add($drop)
            Copy-Item -LiteralPath (Join-Path $Sys32 'whoami.exe') -Destination $drop
            Start-Sleep -Seconds 1
            Start-Process -FilePath $drop -WindowStyle Hidden -Wait
            Start-Sleep -Seconds 1
            Remove-LabFile $drop
        }
    }
    if ($Scenario -contains 'SC04') {
        Invoke-Scenario 'SC04' 'Tệp thực thi duy nhất do nhóm tự biên dịch (IOC hash)' {
            param($m)
            $csc = Join-Path $env:SystemRoot 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
            if (-not (Test-Path -LiteralPath $csc)) { throw "Không thấy csc.exe; bỏ qua SC04" }
            $src = Assert-InLab (Join-Path $LabDir "${m}.cs")
            $exe = Assert-InLab (Join-Path $LabDir "${m}.exe")
            $Created.Add($src); $Created.Add($exe)
            Set-Content -LiteralPath $src -Value ('class P{static void Main(){System.Console.WriteLine("' + $m + '");}}') -Encoding ASCII
            & $csc /nologo /out:$exe $src | Out-Null
            $sha = (Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash.ToLower()
            $cand = Assert-InLab (Join-Path $LabDir "ioc_candidate_$RunId.yaml")
            $Created.Add($cand)
            Set-Content -LiteralPath $cand -Encoding ASCII -Value @(
                'version: lab-' + $RunId, 'ioc_hashes:',
                '  - sha256: ' + $sha, '    source: dacn-lab-self-built', '    note: tệp thử nghiệm do nhóm tự tạo, không phải mã độc')
            Write-Host "SHA-256 của tệp thử nghiệm: $sha  (ứng viên IOC: $(ConvertTo-Token $cand))"
            Start-Process -FilePath $exe -WindowStyle Hidden -Wait
            Remove-LabFile $exe; Remove-LabFile $src
        }
    }
    if ($Scenario -contains 'SC05') {
        Invoke-Scenario 'SC05' 'EICAR (tùy chọn)' {
            param($m)
            if (-not $Eicar) { throw "Cần cờ -Eicar để chạy SC05" }
            $f = Assert-InLab (Join-Path $LabDir "${m}_eicar.txt")
            $Created.Add($f)
            $e = 'X5O!P%@AP[4\PZX54(P^)7CC)7}$' + 'EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
            Set-Content -LiteralPath $f -Value $e -Encoding ASCII
            Start-Sleep -Seconds 3
            Remove-LabFile $f
        }
    }
    if ($Scenario -contains 'SC06') {
        Invoke-Scenario 'SC06' 'Kiểm soát lành tính (không được có alert đe dọa)' {
            param($m)
            Start-Process -FilePath $PsExe -ArgumentList "-NoProfile -Command Get-Date # $m" -WindowStyle Hidden -Wait
            $f = Assert-InLab (Join-Path $LabDir "${m}_note.txt")
            $Created.Add($f)
            Set-Content -LiteralPath $f -Value 'benign'
            Start-Sleep -Milliseconds 500
            Remove-LabFile $f
            New-Item -Path $TestKey -Force | Out-Null
            New-ItemProperty -Path $TestKey -Name $m -Value 'benign' -PropertyType String -Force | Out-Null
            Remove-ItemProperty -Path $TestKey -Name $m -Force
        }
    }
    if ($Scenario -contains 'SC07') {
        Invoke-Scenario 'SC07' 'Thiếu telemetry: xóa tệp ở nơi Sysmon không theo dõi xóa' {
            param($m)
            # Cấu hình repo: FileCreate có \Users\Public\ nhưng FileDeleteDetected chỉ có \Temp\, \Downloads\, \Desktop\
            $drop = Assert-InLab (Join-Path $PubDir "${m}_whoami.exe")
            $Created.Add($drop)
            Copy-Item -LiteralPath (Join-Path $Sys32 'whoami.exe') -Destination $drop
            Start-Sleep -Seconds 1
            Start-Process -FilePath $drop -WindowStyle Hidden -Wait
            Start-Sleep -Seconds 1
            Remove-LabFile $drop
        }
    }
}
finally {
    # Dọn từng mục do lần chạy này tạo; không wildcard, không đụng thứ khác.
    foreach ($v in @($RunValues)) { Remove-ItemProperty -Path $RunKey -Name $v -Force -ErrorAction SilentlyContinue }
    foreach ($f in @($Created)) { try { Remove-LabFile $f } catch { Write-Warning "Không dọn được $f" } }
    Start-Sleep -Seconds 3   # cho Sysmon ghi xong vào Event Log
    $manifest = [ordered]@{ tool = 'dacn_lab_scenarios'; run_id = $RunId; prefix = $Prefix
        whatif = [bool]$WhatIfPreference; scenarios = $Results }
    $out = Join-Path $LabDir "lab_run_$RunId.json"
    if (-not $WhatIfPreference) {
        $manifest | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $out -Encoding UTF8
        Write-Host "Manifest: $(ConvertTo-Token $out)"
    } else { Write-Host "WhatIf: không ghi manifest." }
}

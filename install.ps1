# Bootstrap installer MyDNS. Bisa dijalankan langsung:
#   powershell -c "irm https://raw.githubusercontent.com/EmhaHasyim/mydns/master/install.ps1 | iex"
# atau dipanggil oleh `mydns update`:
#   powershell -File install.ps1 -Update -Version v0.1.0
param(
    [string]$Version,
    [switch]$Update
)

$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$ZipName = 'mydns-x86_64-pc-windows-msvc.zip'
$Repo = 'EmhaHasyim/mydns'
$BinDir = Join-Path $env:LOCALAPPDATA 'MyDns\bin'

function Get-ReleaseTag {
    if ($Version) {
        $tag = $Version.Trim()
        if ($tag -notmatch '^v\d+\.\d+\.\d+$') {
            throw "tag rilis tidak valid: $tag"
        }
        return $tag
    }
    try {
        $release = Invoke-RestMethod -Uri "https://api.github.com/repos/$Repo/releases/latest" -Headers @{ 'User-Agent' = 'mydns-installer' }
        $tag = [string]$release.tag_name
    } catch {
        $detail = [string]$_.Exception.Message
        # Bedakan kegagalan API (rate limit / jaringan) dari rilis yang belum ada.
        throw "tidak bisa mengecek rilis GitHub: $detail"
    }
    if ($tag -notmatch '^v\d+\.\d+\.\d+$') {
        # Kontrak updater::check_now(): rilis belum tersedia.
        throw 'rilis GitHub belum tersedia'
    }
    return $tag
}

try {
    $tag = Get-ReleaseTag

    $temp = Join-Path ([IO.Path]::GetTempPath()) "mydns-install-$([guid]::NewGuid().ToString('N'))"
    [void](New-Item -ItemType Directory -Path $temp -Force)
    $zip = Join-Path $temp $ZipName
    $sums = Join-Path $temp 'SHA256SUMS'
    $base = "https://github.com/$Repo/releases/download/$tag"

    try {
        Invoke-WebRequest -Uri "$base/$ZipName" -OutFile $zip -Headers @{ 'User-Agent' = 'mydns-installer' }
        Invoke-WebRequest -Uri "$base/SHA256SUMS" -OutFile $sums -Headers @{ 'User-Agent' = 'mydns-installer' }

        $line = Get-Content $sums | Where-Object { $_ -match '\s+' + [regex]::Escape($ZipName) + '\s*$' } | Select-Object -First 1
        if (-not $line) {
            throw "SHA256SUMS tidak berisi hash untuk $ZipName"
        }
        if ($line -match '^([0-9a-fA-F]{64})\s') {
            $expected = $Matches[1].ToLowerInvariant()
        } else {
            throw "SHA256SUMS tidak berisi hash untuk $ZipName"
        }
        $actual = (Get-FileHash -Algorithm SHA256 -Path $zip).Hash.ToLowerInvariant()
        if ($actual -ne $expected) {
            throw "checksum tidak cocok untuk $ZipName (harap $expected, dapat $actual)"
        }

        # Verifikasi lolos - baru ekstrak.
        $extract = Join-Path $temp 'unpacked'
        [void](New-Item -ItemType Directory -Path $extract -Force)
        Expand-Archive -Path $zip -DestinationPath $extract -Force

        [void](New-Item -ItemType Directory -Path $BinDir -Force)
        $exeDest = Join-Path $BinDir 'mydns.exe'
        $oldExe = Join-Path $BinDir 'mydns.old.exe'
        # Windows mengunci file .exe yang sedang jalan untuk overwrite, tapi
        # membolehkan rename. Berganti nama dulu, lalu taruh biner baru.
        if (Test-Path -LiteralPath $exeDest) {
            if (Test-Path -LiteralPath $oldExe) { Remove-Item -LiteralPath $oldExe -Force -ErrorAction SilentlyContinue }
            Move-Item -LiteralPath $exeDest -Destination $oldExe -Force
        }
        try {
            Copy-Item -LiteralPath (Join-Path $extract 'mydns.exe') -Destination $exeDest -Force
            Copy-Item -LiteralPath (Join-Path $extract 'wintun.dll') -Destination (Join-Path $BinDir 'wintun.dll') -Force
        } catch {
            if (Test-Path -LiteralPath $oldExe) { Move-Item -LiteralPath $oldExe -Destination $exeDest -Force }
            throw "gagal menimpa biner: $_"
        }
        if (Test-Path -LiteralPath $oldExe) { Remove-Item -LiteralPath $oldExe -Force -ErrorAction SilentlyContinue }

        # installer dari rilis dipakai supaya perbaikan installer ikut terpasang.
        # Unduh ke file sementara dulu: gagal di tengah tidak boleh merusak skrip lama.
        $scriptDest = Join-Path $BinDir 'install.ps1'
        $scriptTemp = Join-Path $BinDir 'install.ps1.tmp'
        $scriptReady = $false
        try {
            Invoke-WebRequest -Uri "https://github.com/$Repo/releases/download/$tag/install.ps1" -OutFile $scriptTemp -Headers @{ 'User-Agent' = 'mydns-installer' }
            $scriptReady = $true
        } catch {
            $source = if ($PSCommandPath) { $PSCommandPath } else { $MyInvocation.MyCommand.Path }
            if ($source -and (Test-Path -LiteralPath $source) -and ([IO.Path]::GetFullPath($source) -ne [IO.Path]::GetFullPath($scriptDest))) {
                Copy-Item -LiteralPath $source -Destination $scriptTemp -Force
                $scriptReady = $true
            } elseif (Test-Path -LiteralPath $scriptDest) {
                $scriptReady = $true  # yang lama masih utuh, jangan timpa
            } else {
                Invoke-WebRequest -Uri "https://raw.githubusercontent.com/$Repo/master/install.ps1" -OutFile $scriptTemp -Headers @{ 'User-Agent' = 'mydns-installer' }
                $scriptReady = $true
            }
        }
        if ($scriptReady -and (Test-Path -LiteralPath $scriptTemp)) {
            Move-Item -LiteralPath $scriptTemp -Destination $scriptDest -Force
        }
        if (Test-Path -LiteralPath $scriptTemp) { Remove-Item -LiteralPath $scriptTemp -Force -ErrorAction SilentlyContinue }

        $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
        if ($userPath -notlike "*$BinDir*") {
            $sep = if ($userPath) { ';' } else { '' }
            [Environment]::SetEnvironmentVariable('Path', "$userPath$sep$BinDir", 'User')
        }

        Write-Host "MyDNS $tag terpasang di $BinDir"
        Write-Host "Buka terminal baru agar PATH diperbarui."
        exit 0
    } catch {
        # Bedakan error unduhan (jaringan / HTTP) dari rilis yang belum tersedia.
        $msg = [string]$_.Exception.Message
        if ($msg -match 'rate limit') {
            Write-Error "tidak bisa mengunduh rilis GitHub: rate limit - coba lagi nanti"
        } elseif ($msg -match '404|Not Found|Tidak ditemukan|timed out|timeout|connection|jaringan|network|WebException') {
            Write-Error "tidak bisa mengunduh rilis GitHub: $msg"
        } else {
            Write-Error $msg
        }
        exit 1
    } finally {
        Remove-Item -LiteralPath $temp -Recurse -Force -ErrorAction SilentlyContinue
    }
} catch {
    Write-Error $_.Exception.Message
    exit 1
}

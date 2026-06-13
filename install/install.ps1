#Requires -Version 5.0
[CmdletBinding()]
param(
    [string]$Version = $env:RASTRAY_VERSION,
    [string]$InstallDir = $(if ($env:RASTRAY_INSTALL_DIR) { $env:RASTRAY_INSTALL_DIR } else { Join-Path $env:LOCALAPPDATA "Programs\rastray" })
)

$ErrorActionPreference = "Stop"
$Repo = "balangyaoejuspher/rastray"
$Bin = "rastray.exe"

if ([string]::IsNullOrWhiteSpace($Version)) {
    $latest = Invoke-RestMethod -Uri "https://api.github.com/repos/$Repo/releases/latest" -Headers @{ "User-Agent" = "rastray-installer" }
    $Version = $latest.tag_name -replace "^v", ""
}
else {
    $Version = $Version -replace "^v", ""
}

if ([string]::IsNullOrWhiteSpace($Version)) {
    throw "Could not determine release version."
}

$arch = $env:PROCESSOR_ARCHITECTURE
if ($arch -ne "AMD64") {
    throw "Unsupported architecture '$arch'. Only x86_64 is currently published."
}
$target = "x86_64-pc-windows-msvc"

$archive = "rastray-v$Version-$target.zip"
$url = "https://github.com/$Repo/releases/download/v$Version/$archive"
$tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("rastray-install-" + [System.Guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $tmp -Force | Out-Null

try {
    $archivePath = Join-Path $tmp $archive
    Write-Host "Downloading $url"
    Invoke-WebRequest -Uri $url -OutFile $archivePath -UseBasicParsing

    $checksumPath = "$archivePath.sha256"
    Write-Host "Verifying checksum"
    Invoke-WebRequest -Uri "$url.sha256" -OutFile $checksumPath -UseBasicParsing

    $expected = (Get-Content $checksumPath -First 1).Split(" ")[0].ToLower()
    $actual = (Get-FileHash -Algorithm SHA256 $archivePath).Hash.ToLower()
    if ($expected -ne $actual) {
        throw "Checksum mismatch: expected $expected, got $actual"
    }

    Expand-Archive -Path $archivePath -DestinationPath $tmp -Force
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
    $extracted = Join-Path $tmp "rastray-v$Version-$target"
    Copy-Item -Path (Join-Path $extracted $Bin) -Destination (Join-Path $InstallDir $Bin) -Force

    Write-Host "Installed rastray v$Version to $(Join-Path $InstallDir $Bin)"

    $userPath = [System.Environment]::GetEnvironmentVariable("Path", "User")
    $segments = if ($userPath) { $userPath.Split(";") } else { @() }
    if ($segments -notcontains $InstallDir) {
        Write-Host ""
        Write-Host "Note: $InstallDir is not on your PATH. Add it with:"
        Write-Host "  [System.Environment]::SetEnvironmentVariable('Path', `"$InstallDir;`$env:Path`", 'User')"
    }
}
finally {
    Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
}

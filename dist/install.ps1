# install.ps1
# ZTTP Multi-Platform Installer Script for Windows

$ServerUrl = "http://127.0.0.1:8555" # Will be updated during deployment
$Arch = "amd64" # Currently we only compile for windows-amd64
$BinaryName = "zttp-windows-$Arch.exe"
$DownloadUrl = "$ServerUrl/release/$BinaryName"
$ChecksumUrl = "$ServerUrl/release/SHA256SUMS.txt"

$InstallDir = "C:\Program Files\ZTTP"
$ExePath = "$InstallDir\zttp.exe"

Write-Host "=== ZTTP CLI Installer for Windows ===" -ForegroundColor Cyan

# Requires Admin privileges
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "✗ This script requires Administrator privileges to install." -ForegroundColor Red
    Write-Host "Please close this window, open PowerShell as Administrator, and try again." -ForegroundColor Yellow
    Exit
}

# Create directory
if (-not (Test-Path -Path $InstallDir)) {
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
}

Write-Host "Downloading ZTTP CLI..."
Invoke-WebRequest -Uri $DownloadUrl -OutFile $ExePath -UseBasicParsing

# Optional: verify checksum if SHA256SUMS.txt is available
try {
    $ChecksumFile = "$env:TEMP\SHA256SUMS.txt"
    Invoke-WebRequest -Uri $ChecksumUrl -OutFile $ChecksumFile -UseBasicParsing -ErrorAction SilentlyContinue
    if (Test-Path $ChecksumFile) {
        $expectedHashLine = Select-String -Path $ChecksumFile -Pattern $BinaryName
        if ($expectedHashLine) {
            $expectedHash = ($expectedHashLine.Line -split '\s+')[0]
            $actualHash = (Get-FileHash -Path $ExePath -Algorithm SHA256).Hash.ToLower()
            if ($expectedHash -ne $actualHash) {
                Write-Host "✗ Checksum mismatch! Download may be corrupted." -ForegroundColor Red
                Remove-Item $ExePath
                Exit
            }
        }
    }
} catch {
    # Ignore checksum validation errors
}

Write-Host "Adding $InstallDir to system PATH..."
$oldPath = [Environment]::GetEnvironmentVariable("Path", "Machine")
if ($oldPath -notmatch [regex]::Escape($InstallDir)) {
    $newPath = $oldPath + ";$InstallDir"
    [Environment]::SetEnvironmentVariable("Path", $newPath, "Machine")
}

Write-Host "✓ Installation complete." -ForegroundColor Green
Write-Host "Please open a NEW terminal window (PowerShell or Windows Terminal) and type 'zttp' to connect." -ForegroundColor Yellow

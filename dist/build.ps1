# x7 cross-compilation build script
# Strictly pure static binary compilation (CGO_ENABLED=0)
# Binary size limit: Under 12MB

$ErrorActionPreference = "Stop"

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$rootDir = (Get-Item $scriptDir).Parent.FullName
if (-not (Test-Path "$rootDir/go.mod")) {
    $rootDir = $scriptDir
}
$distDir = "$rootDir/dist"

if (-not (Test-Path $distDir)) {
    New-Item -ItemType Directory -Path $distDir -Force | Out-Null
}

$commit = "release"
try {
    $gitCommit = git rev-parse --short HEAD 2>$null
    if ($gitCommit) {
        $commit = $gitCommit
    }
} catch {
    $commit = "static-v1.0.0"
}

$buildDate = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
$ldflags = "-s -w -X github.com/x7ssss/x7/cmd.GitCommit=$commit -X github.com/x7ssss/x7/cmd.BuildDate=$buildDate"

$targets = @(
    @{ OS = "linux";   Arch = "amd64"; Output = "x7-linux-amd64" },
    @{ OS = "linux";   Arch = "arm64"; Output = "x7-linux-arm64" },
    @{ OS = "darwin";  Arch = "amd64"; Output = "x7-darwin-amd64" },
    @{ OS = "darwin";  Arch = "arm64"; Output = "x7-darwin-arm64" },
    @{ OS = "windows"; Arch = "amd64"; Output = "x7-windows-amd64.exe" }
)

Write-Host "========================================================================================" -ForegroundColor Cyan
Write-Host "x7 Cross-Compilation Pipeline (v1.0.0)" -ForegroundColor Cyan
Write-Host "Static compilation: CGO_ENABLED=0 | Target size: Under 12MB" -ForegroundColor Cyan
Write-Host "Commit: $commit | Date: $buildDate" -ForegroundColor Cyan
Write-Host "========================================================================================" -ForegroundColor Cyan

$maxSize = 12 * 1024 * 1024
$failed = $false

foreach ($target in $targets) {
    $osName = $target.OS
    $archName = $target.Arch
    $outFile = Join-Path $distDir $target.Output

    Write-Host "Building for $osName/$archName -> $($target.Output)..." -NoNewline

    $env:CGO_ENABLED = "0"
    $env:GOOS = $osName
    $env:GOARCH = $archName

    & go build -trimpath -ldflags $ldflags -o $outFile "$rootDir/cmd/x7"
    if ($LASTEXITCODE -ne 0) {
        Write-Host " [FAILED]" -ForegroundColor Red
        $failed = $true
        continue
    }

    $sizeBytes = (Get-Item $outFile).Length
    $sizeMB = [math]::Round($sizeBytes / (1024 * 1024), 2)

    if ($sizeBytes -gt $maxSize) {
        Write-Host " [FAILED] ($sizeMB MB exceeds 12MB limit)" -ForegroundColor Red
        $failed = $true
    } else {
        Write-Host " [OK] ($sizeMB MB / $sizeBytes bytes)" -ForegroundColor Green
    }
}

# Provide local executable aliases for direct execution
Copy-Item (Join-Path $distDir "x7-windows-amd64.exe") (Join-Path $distDir "x7.exe") -Force
Copy-Item (Join-Path $distDir "x7-windows-amd64.exe") (Join-Path $distDir "x7") -Force

Write-Host "========================================================================================" -ForegroundColor Cyan
if ($failed) {
    Write-Host "BUILD FAILED: One or more targets failed or exceeded 12MB limit." -ForegroundColor Red
    exit 1
} else {
    Write-Host "BUILD SUCCESS: All static binaries verified under 12MB." -ForegroundColor Green
}

# AnixOps Agent Build Script for Windows PowerShell
# Usage: .\build.ps1 [-Platform <platform>] [-Arch <arch>] [-Tags <tags>] [-All]
#
# Release builds must be produced by GitHub Actions. This script is kept for
# development or emergency operator use only and requires ALLOW_LOCAL_BUILD=1
# for any build. -Clean remains available for removing local build artifacts.

param(
    [string]$Platform = "windows",
    [string]$Arch = "amd64",
    [string]$Tags = "xray sing hy2",
    [switch]$All,
    [switch]$Clean
)

$ErrorActionPreference = "Stop"

# 设置必需的环境变量
$env:GOEXPERIMENT = "jsonv2"
$env:CGO_ENABLED = "0"

# 项目信息
$ProjectName = "anix-agent"
$OutputDir = "build"
$Version = (git describe --tags --always 2>$null) -replace '^v', ''
if (-not $Version) { $Version = "dev" }
$BuildTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
$GitCommit = git rev-parse --short HEAD 2>$null
if (-not $GitCommit) { $GitCommit = "unknown" }

# LDFlags
$LDFlags = "-s -w -X 'github.com/AnixOps/anix-agent/v5/cmd.version=$Version'"

# 支持的平台和架构
$Platforms = @(
    @{ GOOS = "linux"; GOARCH = "amd64"; Ext = "" },
    @{ GOOS = "linux"; GOARCH = "arm64"; Ext = "" },
    @{ GOOS = "linux"; GOARCH = "386"; Ext = "" },
    @{ GOOS = "windows"; GOARCH = "amd64"; Ext = ".exe" },
    @{ GOOS = "windows"; GOARCH = "arm64"; Ext = ".exe" },
    @{ GOOS = "darwin"; GOARCH = "amd64"; Ext = "" },
    @{ GOOS = "darwin"; GOARCH = "arm64"; Ext = "" }
)

function Write-ColorOutput {
    param(
        [ConsoleColor]$ForegroundColor,
        [string]$Message
    )
    Write-Host $Message -ForegroundColor $ForegroundColor
}

function Require-LocalBuildOptIn {
    if ($env:ALLOW_LOCAL_BUILD -eq "1") {
        return
    }

    Write-Error "build.ps1 performs a local source-tree build. Release builds must be produced by GitHub Actions release workflows. For development or emergency operator use, rerun with ALLOW_LOCAL_BUILD=1."
}

function Build-Binary {
    param(
        [string]$GOOS,
        [string]$GOARCH,
        [string]$Ext
    )
    
    $OutputName = "${ProjectName}_${GOOS}_${GOARCH}${Ext}"
    $OutputPath = Join-Path $OutputDir $OutputName
    
    Write-ColorOutput -ForegroundColor Green -Message "Building $OutputName..."
    
    $env:GOOS = $GOOS
    $env:GOARCH = $GOARCH
    
    $buildArgs = @(
        "build",
        "-trimpath",
        "-tags", $Tags,
        "-ldflags", $LDFlags,
        "-o", $OutputPath,
        "."
    )
    
    & go @buildArgs
    
    if ($LASTEXITCODE -eq 0) {
        $size = (Get-Item $OutputPath).Length / 1MB
        Write-ColorOutput -ForegroundColor Cyan -Message ("  -> $OutputName ({0:N2} MB)" -f $size)
        return $true
    } else {
        Write-ColorOutput -ForegroundColor Red -Message "  -> Failed to build $OutputName"
        return $false
    }
}

# 清理
if ($Clean) {
    Write-ColorOutput -ForegroundColor Yellow -Message "Cleaning build directory..."
    if (Test-Path $OutputDir) {
        Remove-Item -Recurse -Force $OutputDir
    }
    Write-ColorOutput -ForegroundColor Green -Message "Clean completed."
    exit 0
}

Require-LocalBuildOptIn

# 创建输出目录
if (-not (Test-Path $OutputDir)) {
    New-Item -ItemType Directory -Path $OutputDir | Out-Null
}

Write-ColorOutput -ForegroundColor Cyan -Message "========================================"
Write-ColorOutput -ForegroundColor Cyan -Message "  AnixOps Agent Build Script"
Write-ColorOutput -ForegroundColor Cyan -Message "========================================"
Write-ColorOutput -ForegroundColor White -Message "Version:    $Version"
Write-ColorOutput -ForegroundColor White -Message "Git Commit: $GitCommit"
Write-ColorOutput -ForegroundColor White -Message "Build Time: $BuildTime"
Write-ColorOutput -ForegroundColor Cyan -Message "========================================"
Write-Output ""

$startTime = Get-Date
$successCount = 0
$failCount = 0

if ($All) {
    # 编译所有平台
    Write-ColorOutput -ForegroundColor Yellow -Message "Building for all platforms..."
    Write-Output ""
    
    foreach ($p in $Platforms) {
        $result = Build-Binary -GOOS $p.GOOS -GOARCH $p.GOARCH -Ext $p.Ext
        if ($result) { $successCount++ } else { $failCount++ }
    }
} else {
    # 编译指定平台
    $ext = if ($Platform -eq "windows") { ".exe" } else { "" }
    $result = Build-Binary -GOOS $Platform -GOARCH $Arch -Ext $ext
    if ($result) { $successCount++ } else { $failCount++ }
}

$endTime = Get-Date
$duration = $endTime - $startTime

Write-Output ""
Write-ColorOutput -ForegroundColor Cyan -Message "========================================"
Write-ColorOutput -ForegroundColor Green -Message "Build completed in $($duration.TotalSeconds.ToString('F2')) seconds"
Write-ColorOutput -ForegroundColor Green -Message "Success: $successCount, Failed: $failCount"
Write-ColorOutput -ForegroundColor Cyan -Message "========================================"

# 列出生成的文件
if (Test-Path $OutputDir) {
    Write-Output ""
    Write-ColorOutput -ForegroundColor Yellow -Message "Generated files:"
    Get-ChildItem $OutputDir | ForEach-Object {
        $size = $_.Length / 1MB
        Write-Output ("  {0,-35} {1,8:N2} MB" -f $_.Name, $size)
    }
}

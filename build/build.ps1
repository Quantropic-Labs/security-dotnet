#!/usr/bin/env pwsh
param(
    [ValidateSet("Build", "Test", "Pack", "Clean", "All")]
    [string]$Target = "Build",
    
    [string]$Configuration = "Release"
)

$ErrorActionPreference = "Stop"

# Исправлено: только ОДИН Split-Path -Parent
$projectRoot = Split-Path -Parent $PSScriptRoot
Set-Location $projectRoot

$outputPath = "./artifacts"

Write-Host "=== Quantropic Security Build ===" -ForegroundColor Cyan
Write-Host "Target: $Target | Configuration: $Configuration" -ForegroundColor Yellow
Write-Host "Location: $(Get-Location)" -ForegroundColor Gray
Write-Host ""

function Clean {
    Write-Host "=== Cleaning... ===" -ForegroundColor Green
    if (Test-Path $outputPath) { Remove-Item -Recurse -Force $outputPath }
    Get-ChildItem -Recurse -Directory -Filter "bin" | Remove-Item -Recurse -Force
    Get-ChildItem -Recurse -Directory -Filter "obj" | Remove-Item -Recurse -Force
    Write-Host "Clean completed" -ForegroundColor Green
}

function Build {
    Write-Host "=== Building... ===" -ForegroundColor Green
    dotnet restore Quantropic.Security.slnx
    dotnet build Quantropic.Security.slnx --configuration $Configuration --no-restore
    if ($LASTEXITCODE -ne 0) { throw "Build failed!" }
    Write-Host "Build completed" -ForegroundColor Green
}

function Test {
    Write-Host "=== Running tests... ===" -ForegroundColor Green
    dotnet test Quantropic.Security.slnx --configuration $Configuration --no-build --verbosity normal
    if ($LASTEXITCODE -ne 0) { throw "Tests failed!" }
    Write-Host "Tests completed" -ForegroundColor Green
}

function Pack {
    Write-Host "=== Packing NuGet packages (local)... ===" -ForegroundColor Green
    New-Item -ItemType Directory -Force -Path $outputPath/nuget | Out-Null
    dotnet pack Quantropic.Security.slnx --configuration $Configuration --output $outputPath/nuget
    Write-Host "Packages created in $outputPath/nuget" -ForegroundColor Green
}

switch ($Target) {
    "Clean" { Clean }
    "Build" { Clean; Build }
    "Test" { Build; Test }
    "Pack" { Build; Pack }
    "All" { Clean; Build; Test; Pack }
}

Write-Host ""
Write-Host "=== Done ===" -ForegroundColor Cyan
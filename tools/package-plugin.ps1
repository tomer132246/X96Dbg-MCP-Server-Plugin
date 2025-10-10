[CmdletBinding()]
param(
    [string]$Win32BuildDir = "build/win32",
    [string]$X64BuildDir = "build/x64",
    [string]$Configuration = "Release",
    [string]$ManifestPath = "MCPluginForX96Dbg.json",
    [string]$OutputPath = "dist/MCPluginForX96Dbg-bundle.zip"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Resolve-ProjectPath {
    param(
        [string]$ProjectRoot,
        [string]$Path,
        [switch]$AllowNonExisting
    )

    if([string]::IsNullOrWhiteSpace($Path)) {
        throw "Path cannot be empty."
    }

    if([System.IO.Path]::IsPathRooted($Path)) {
        if($AllowNonExisting) {
            return [System.IO.Path]::GetFullPath($Path)
        }
        return (Resolve-Path -Path $Path).ProviderPath
    }

    $candidate = [System.IO.Path]::Combine($ProjectRoot, $Path)
    if($AllowNonExisting) {
        return [System.IO.Path]::GetFullPath($candidate)
    }
    return (Resolve-Path -Path $candidate).ProviderPath
}

$repoRoot = (Resolve-Path -Path (Join-Path $PSScriptRoot ".." )).ProviderPath

$win32Root = Resolve-ProjectPath -ProjectRoot $repoRoot -Path $Win32BuildDir
$x64Root = Resolve-ProjectPath -ProjectRoot $repoRoot -Path $X64BuildDir
$manifestFile = Resolve-ProjectPath -ProjectRoot $repoRoot -Path $ManifestPath
$outputFullPath = Resolve-ProjectPath -ProjectRoot $repoRoot -Path $OutputPath -AllowNonExisting

$win32Binary = Join-Path $win32Root "bin/win32/$Configuration/MCPluginForX96Dbg.dp32"
$x64Binary = Join-Path $x64Root "bin/x64/$Configuration/MCPluginForX96Dbg.dp64"

if(-not (Test-Path -Path $win32Binary)) {
    throw "Missing 32-bit plugin binary: $win32Binary"
}
if(-not (Test-Path -Path $x64Binary)) {
    throw "Missing 64-bit plugin binary: $x64Binary"
}
if(-not (Test-Path -Path $manifestFile)) {
    throw "Missing manifest file: $manifestFile"
}

$stagingRoot = Join-Path ([System.IO.Path]::GetTempPath()) ([System.Guid]::NewGuid().ToString())
$null = New-Item -ItemType Directory -Path $stagingRoot

try {
    $files = @(
        @{ Source = $win32Binary; Destination = "MCPluginForX96Dbg.dp32" },
        @{ Source = $x64Binary; Destination = "MCPluginForX96Dbg.dp64" },
        @{ Source = $manifestFile; Destination = "MCPluginForX96Dbg.json" }
    )

    foreach($file in $files) {
        $destination = Join-Path $stagingRoot $file.Destination
        Copy-Item -Path $file.Source -Destination $destination -Force
    }

    $outputDirectory = Split-Path -Parent $outputFullPath
    if(-not (Test-Path -Path $outputDirectory)) {
        $null = New-Item -ItemType Directory -Path $outputDirectory -Force
    }

    if(Test-Path -Path $outputFullPath) {
        Remove-Item -Path $outputFullPath -Force
    }

    Compress-Archive -Path (Join-Path $stagingRoot '*') -DestinationPath $outputFullPath -Force

    Write-Host "Created package:" $outputFullPath
}
finally {
    if(Test-Path -Path $stagingRoot) {
        Remove-Item -Path $stagingRoot -Recurse -Force
    }
}

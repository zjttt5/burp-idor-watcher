<#
.SYNOPSIS
    Build the Burp extension jar.

.DESCRIPTION
    Requires JDK 17+ (javac, jar) and lib/montoya-api.jar.
    Run .\scripts\extract-montoya-api.ps1 first to obtain the API jar.

.EXAMPLE
    .\build.ps1
#>
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $root

$apiJar  = "lib\montoya-api.jar"
$src     = "src\IdorWatcher.java"
$outDir  = "out"
$distDir = "dist"
$jarName = "idor-watcher.jar"

if (-not (Test-Path $apiJar)) {
    Write-Error "missing $apiJar`nRun: .\scripts\extract-montoya-api.ps1 -BurpJar <path> -OutDir .\lib"
}

$javac = (Get-Command javac -ErrorAction SilentlyContinue)
if (-not $javac) {
    Write-Error "javac not found. Install a JDK 17+ (not just a JRE) and add it to PATH."
}

$ver = & javac -version 2>&1
Write-Host "[*] $ver"

Remove-Item $outDir, $distDir -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force -Path $outDir, $distDir | Out-Null

& javac --release 17 -encoding UTF-8 -cp $apiJar -d $outDir $src
if ($LASTEXITCODE -ne 0) { Write-Error "javac failed" }

& jar cf (Join-Path $distDir $jarName) -C $outDir .
if ($LASTEXITCODE -ne 0) { Write-Error "jar failed" }

$size = (Get-Item (Join-Path $distDir $jarName)).Length
Write-Host "[+] built: $distDir\$jarName ($size bytes)"
Write-Host "    load it in Burp: Extensions -> Installed -> Add -> Java"

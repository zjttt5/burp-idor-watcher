<#
.SYNOPSIS
    Extract montoya-api.jar from a Burp Suite installation.

.DESCRIPTION
    The Montoya API jar is bundled inside burpsuite.jar at:
        resources/Tooling/libraries/montoya-api.jar
    Using the API that ships with your Burp guarantees version compatibility.

.PARAMETER BurpJar
    Path to burpsuite.jar. Defaults to the common Kali install path.

.PARAMETER OutDir
    Output directory. Defaults to .\lib

.EXAMPLE
    .\extract-montoya-api.ps1 -BurpJar "C:\Program Files\BurpSuite\burpsuite.jar" -OutDir .\lib
#>
param(
    [string]$BurpJar = "C:\Program Files\BurpSuite Community Edition\burpsuite.jar",
    [string]$OutDir  = ".\lib"
)

$ErrorActionPreference = "Stop"
$entry   = "resources/Tooling/libraries/montoya-api.jar"
$outFile = Join-Path $OutDir "montoya-api.jar"

if (-not (Test-Path $BurpJar)) {
    Write-Error "burpsuite.jar not found: $BurpJar`nPass the real path with -BurpJar"
}

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

$py = @"
import sys, zipfile
src, entry, dst = sys.argv[1], sys.argv[2], sys.argv[3]
with zipfile.ZipFile(src) as z:
    data = z.read(entry)
open(dst, 'wb').write(data)
print('[+] wrote %s (%d bytes)' % (dst, len(data)))
"@

$python = Get-Command python -ErrorAction SilentlyContinue
if (-not $python) { $python = Get-Command python3 -ErrorAction SilentlyContinue }
if ($python) {
    & $python.Source -c $py $BurpJar $entry $outFile
} else {
    # fallback: .NET zip
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $zip = [System.IO.Compression.ZipFile]::OpenRead((Resolve-Path $BurpJar))
    $e = $zip.Entries | Where-Object { $_.FullName -eq $entry }
    if (-not $e) { $zip.Dispose(); Write-Error "entry not found inside jar: $entry" }
    [System.IO.Compression.ZipFileExtensions]::ExtractToFile($e, (Join-Path (Get-Location) $outFile), $true)
    $zip.Dispose()
    Write-Host "[+] wrote $outFile"
}

Write-Host "[+] done. Build with: .\build.ps1"

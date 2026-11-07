param(
    [string]$VcpkgRoot,
    [ValidateSet("x64", "x86", "both")]
    [string]$Architecture = "both"
)

$ErrorActionPreference = "Stop"

function Invoke-NativeCommand {
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [Parameter(Mandatory = $true)][string[]]$Arguments
    )

    & $FilePath @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw ("Command failed with exit code {0}: {1} {2}" -f $LASTEXITCODE, $FilePath, ($Arguments -join " "))
    }
}

$repositoryRoot = Split-Path -Parent $PSScriptRoot

if ([string]::IsNullOrWhiteSpace($VcpkgRoot)) {
    if (-not [string]::IsNullOrWhiteSpace($env:VCPKG_ROOT)) {
        $VcpkgRoot = $env:VCPKG_ROOT
    }
    else {
        $VcpkgRoot = Join-Path $repositoryRoot ".tools\vcpkg"
    }
}

$VcpkgRoot = [System.IO.Path]::GetFullPath($VcpkgRoot)
$vcpkgExecutable = Join-Path $VcpkgRoot "vcpkg.exe"
$bootstrapScript = Join-Path $VcpkgRoot "bootstrap-vcpkg.bat"

if (-not (Test-Path -LiteralPath $vcpkgExecutable -PathType Leaf)) {
    if (Test-Path -LiteralPath $VcpkgRoot) {
        if (-not (Test-Path -LiteralPath $bootstrapScript -PathType Leaf)) {
            $existingItems = @(Get-ChildItem -LiteralPath $VcpkgRoot -Force)
            if ($existingItems.Count -gt 0) {
                throw "VcpkgRoot exists but is not a vcpkg checkout: $VcpkgRoot"
            }
            Remove-Item -LiteralPath $VcpkgRoot -Force
        }
    }
    else {
        $parentDirectory = Split-Path -Parent $VcpkgRoot
        New-Item -ItemType Directory -Force -Path $parentDirectory | Out-Null
        Invoke-NativeCommand -FilePath "git" -Arguments @(
            "clone", "--depth", "1", "https://github.com/microsoft/vcpkg", $VcpkgRoot
        )
    }
}

if (-not (Test-Path -LiteralPath $bootstrapScript -PathType Leaf)) {
    throw "vcpkg bootstrap script was not found at: $bootstrapScript"
}

if (-not (Test-Path -LiteralPath $vcpkgExecutable -PathType Leaf)) {
    Invoke-NativeCommand -FilePath $bootstrapScript -Arguments @("-disableMetrics")
}

$triplets = switch ($Architecture) {
    "x64"  { @("x64-windows-static-md") }
    "x86"  { @("x86-windows-static-md") }
    "both" { @("x64-windows-static-md", "x86-windows-static-md") }
}

$packages = @()
foreach ($triplet in $triplets) {
    $packages += "openssl:$triplet"
    $packages += "yaml-cpp:$triplet"
}

Invoke-NativeCommand -FilePath $vcpkgExecutable -Arguments (
    @("install") + $packages + @("--disable-metrics")
)

# Do not report success based only on vcpkg's exit code: verify the exact files
# consumed by the Visual Studio projects for every requested architecture.
foreach ($triplet in $triplets) {
    $installedDir = Join-Path $VcpkgRoot ("installed\{0}" -f $triplet)
    $requiredFiles = @(
        (Join-Path $installedDir "include\openssl\ssl.h"),
        (Join-Path $installedDir "lib\libssl.lib"),
        (Join-Path $installedDir "lib\libcrypto.lib"),
        (Join-Path $installedDir "lib\yaml-cpp.lib")
    )

    $missingFiles = @($requiredFiles | Where-Object { -not (Test-Path -LiteralPath $_ -PathType Leaf) })
    if ($missingFiles.Count -gt 0) {
        $missingList = $missingFiles -join [Environment]::NewLine
        throw ("Dependency installation for {0} is incomplete. Missing files:{1}{2}" -f
            $triplet, [Environment]::NewLine, $missingList)
    }

    Write-Host ("Verified {0}: {1}" -f $triplet, $installedDir) -ForegroundColor Green
}

[Environment]::SetEnvironmentVariable("VCPKG_ROOT", $VcpkgRoot, "User")
$env:VCPKG_ROOT = $VcpkgRoot

Write-Host ""
Write-Host "Oblivion Windows dependencies are installed and verified." -ForegroundColor Green
Write-Host "VCPKG_ROOT: $VcpkgRoot"
Write-Host "Installed triplets: $($triplets -join ', ')"
Write-Host "Visual Studio will use the selected VCPKG_ROOT. Close and reopen Visual Studio before building."

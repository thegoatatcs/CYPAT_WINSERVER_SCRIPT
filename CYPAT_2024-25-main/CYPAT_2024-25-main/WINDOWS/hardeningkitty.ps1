# Ensure script is run as Administrator
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "You must run this script as an Administrator." -ForegroundColor Red
    exit 1
}

# Ensure running on Windows Server
try {
    $osInfo = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
    if ($osInfo.ProductType -ne 3) {
        Write-Host "This script is optimized for Windows Server and should be run on a server OS." -ForegroundColor Red
        exit 1
    }
} catch {
    Write-Host "Failed to retrieve OS information: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

function Get-HardeningKitty {
    # Enforce TLS 1.2 for GitHub connections
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    
    $originalLocation = Get-Location

    Write-Host "Fetching latest HardeningKitty release information..." -ForegroundColor Cyan
    try {
        # Retrieve release info from GitHub using REST API
        $releaseInfo = Invoke-RestMethod -Uri "https://api.github.com/repos/scipag/HardeningKitty/releases/latest" -ErrorAction Stop
    } catch {
        Write-Host "Failed to retrieve HardeningKitty release info: $($_.Exception.Message)" -ForegroundColor Red
        return
    }

    if (-not $releaseInfo) {
        Write-Host "No release information found." -ForegroundColor Red
        return
    }

    try {
        $version = $releaseInfo.Name.TrimStart('v')
        $downloadLink = $releaseInfo.zipball_url

        Write-Host "Latest HardeningKitty Version: $version"
        Write-Host "Downloading HardeningKitty archive..."
        $zipFileName = "HardeningKitty$version.zip"
        
        # Download the ZIP
        Invoke-WebRequest $downloadLink -OutFile $zipFileName -UseBasicParsing -ErrorAction Stop

        Write-Host "Extracting HardeningKitty files..."
        $extractFolder = "HardeningKitty$version"
        if (Test-Path $extractFolder) { Remove-Item $extractFolder -Recurse -Force }
        Expand-Archive -Path ".\$zipFileName" -DestinationPath ".\$extractFolder" -Force

        # GitHub source ZIPs usually have a single top-level folder
        $subFolder = (Get-ChildItem $extractFolder -Directory | Select-Object -First 1).FullName
        if (-not $subFolder) {
            Write-Host "Extraction failed: subfolder not found." -ForegroundColor Red
            return
        }

        # Move files from subFolder to extractFolder
        Get-ChildItem $subFolder -File -Recurse | Move-Item -Destination $extractFolder -Force
        Get-ChildItem $subFolder -Directory -Recurse | Move-Item -Destination $extractFolder -Force
        Remove-Item $subFolder -Recurse -Force

        # Prepare HardeningKitty module directory
        $moduleDir = Join-Path $Env:ProgramFiles "WindowsPowerShell\Modules\HardeningKitty\$version"
        if (Test-Path $moduleDir) {
            Remove-Item $moduleDir -Recurse -Force
        }
        New-Item -Path $moduleDir -ItemType Directory | Out-Null

        # Copy module files
        Set-Location $extractFolder
        Copy-Item .\HardeningKitty.psd1,.\HardeningKitty.psm1,.\lists\ -Destination $moduleDir -Recurse -Force
        Write-Host "HardeningKitty module files copied to $moduleDir." -ForegroundColor Green

        # Import the module
        Import-Module (Join-Path $moduleDir "HardeningKitty.psm1") -Force
        Write-Host "HardeningKitty module imported successfully." -ForegroundColor Green

        # Run HardeningKitty in HailMary mode
        Write-Host "Running HardeningKitty with HailMary mode..."
        Invoke-HardeningKitty -Mode HailMary -Log -Report -FileFindingList ".\lists\finding_list_0x6d69636b_machine.csv"
        Write-Host "HardeningKitty finished." -ForegroundColor Yellow
    } catch {
        Write-Host "An error occurred: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "Hardening Kitty failed. Please try running it manually." -ForegroundColor Red
    } finally {
        # Cleanup and return to original location
        Set-Location $originalLocation
        if (Test-Path $zipFileName) { Remove-Item $zipFileName -Force }
        if (Test-Path $extractFolder) { Remove-Item $extractFolder -Recurse -Force }
    }
}

Get-HardeningKitty

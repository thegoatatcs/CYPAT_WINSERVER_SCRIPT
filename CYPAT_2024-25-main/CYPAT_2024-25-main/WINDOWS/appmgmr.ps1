param(
    [Parameter(Mandatory=$false)]
    [string[]]$InstallPackages = @(),

    [Parameter(Mandatory=$false)]
    [string[]]$UninstallPackages = @(),

    [Parameter(Mandatory=$false)]
    [string[]]$UpdatePackages = @()
)

# Function: Write-Message for consistent logging
function Write-Message {
    param(
        [Parameter(Mandatory=$true)][string]$Message,
        [Parameter()][string]$Level = "INFO"
    )
    $timeStamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    Write-Host "[$timeStamp] [$Level] $Message"
}

# Ensure script is run as Administrator
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Message "You must run this script as an Administrator." -Level "ERROR"
    exit 1
}

# Check if running on Windows Server
try {
    $osInfo = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
    if ($osInfo.ProductType -ne 3) {
        Write-Message "This script is optimized for Windows Server and should be run on a server OS." -Level "ERROR"
        exit 1
    }
} catch {
    Write-Message "Failed to retrieve OS information: $_" -Level "ERROR"
    exit 1
}

# Function to Check and Install Chocolatey if not present
function Ensure-ChocolateyInstalled {
    if (-not (Get-Command "choco.exe" -ErrorAction SilentlyContinue)) {
        Write-Message "Chocolatey not found. Installing Chocolatey..."
        try {
            Set-ExecutionPolicy Bypass -Scope Process -Force
            Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
            Write-Message "Chocolatey installation completed."
        } catch {
            Write-Message "Failed to install Chocolatey: $_" -Level "ERROR"
            exit 1
        }
    } else {
        Write-Message "Chocolatey is already installed."
    }
}

# Function to Manage Chocolatey Packages
function Manage-ChocoPackage {
    param (
        [Parameter(Mandatory=$true)]
        [ValidateSet("install","uninstall","update")]
        [string]$Action,

        [Parameter(Mandatory=$true)]
        [string]$PackageName
    )

    try {
        switch ($Action) {
            "install" {
                Write-Message "Installing $PackageName..."
                choco install $PackageName -y | Out-Null
                Write-Message "Installed $PackageName."
            }
            "uninstall" {
                Write-Message "Uninstalling $PackageName..."
                choco uninstall $PackageName -y | Out-Null
                Write-Message "Uninstalled $PackageName."
            }
            "update" {
                Write-Message "Updating $PackageName..."
                choco upgrade $PackageName -y | Out-Null
                Write-Message "Updated $PackageName."
            }
        }
    } catch {
        Write-Message "Failed to $Action package $PackageName: $_" -Level "ERROR"
    }
}

# Ensure Chocolatey is Installed
Ensure-ChocolateyInstalled

# Process installations
foreach ($pkg in $InstallPackages) {
    Manage-ChocoPackage -Action install -PackageName $pkg
}

# Process uninstallations
foreach ($pkg in $UninstallPackages) {
    Manage-ChocoPackage -Action uninstall -PackageName $pkg
}

# Process updates
foreach ($pkg in $UpdatePackages) {
    # Special case: 'all' to update all packages
    if ($pkg -eq "all") {
        Write-Message "Updating all installed Chocolatey packages..."
        choco upgrade all -y | Out-Null
        Write-Message "All packages updated."
    } else {
        Manage-ChocoPackage -Action update -PackageName $pkg
    }
}

Write-Message "Chocolatey package management completed successfully."
exit 0

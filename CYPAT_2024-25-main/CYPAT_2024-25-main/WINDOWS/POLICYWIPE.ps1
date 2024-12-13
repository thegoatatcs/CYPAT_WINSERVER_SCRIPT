# Requires administrative privileges
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "You must run this script as an Administrator." -ForegroundColor Red
    exit 1
}

# Check if running on Windows Server
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

Write-Host "Resetting Local Group Policy to default..." -ForegroundColor Cyan

# Paths for registry.pol files
$registryPolPaths = @(
    "$env:WinDir\System32\GroupPolicy\Machine\registry.pol",
    "$env:WinDir\System32\GroupPolicy\User\registry.pol"
)

# Step 1: Reset security settings to default using default base INF
try {
    secedit /configure /db reset.sdb /cfg "$env:WinDir\inf\defltbase.inf" /overwrite /areas SECURITYPOLICY | Out-Null
    Write-Host "Security settings reset to default base." -ForegroundColor Green
} catch {
    Write-Host "Failed to reset security settings: $($_.Exception.Message)" -ForegroundColor Red
}

# Step 2: Remove registry.pol files if they exist
foreach ($path in $registryPolPaths) {
    if (Test-Path $path) {
        try {
            Remove-Item -Path $path -Force
            Write-Host "Removed $path" -ForegroundColor Green
        } catch {
            Write-Host "Failed to remove $path: $($_.Exception.Message)" -ForegroundColor Red
        }
    }
}

# Step 3: Remove existing local Group Policy directories
try {
    if (Test-Path "$env:WinDir\System32\GroupPolicy") {
        Remove-Item -Recurse -Force "$env:WinDir\System32\GroupPolicy" | Out-Null
    }
    if (Test-Path "$env:WinDir\System32\GroupPolicyUsers") {
        Remove-Item -Recurse -Force "$env:WinDir\System32\GroupPolicyUsers" | Out-Null
    }
    Write-Host "Removed existing Group Policy directories." -ForegroundColor Green
} catch {
    Write-Host "Failed to remove Group Policy directories: $($_.Exception.Message)" -ForegroundColor Red
}

# Step 4: Reapply default base security template
try {
    secedit /configure /cfg "$env:WinDir\inf\defltbase.inf" /db defltbase.sdb /verbose | Out-Null
    Write-Host "Reapplied default security template." -ForegroundColor Green
} catch {
    Write-Host "Failed to reapply default security template: $($_.Exception.Message)" -ForegroundColor Red
}

# Step 5: Force Group Policy Update
try {
    gpupdate /force | Out-Null
    Write-Host "Group policies updated." -ForegroundColor Green
} catch {
    Write-Host "Failed to update Group Policy: $($_.Exception.Message)" -ForegroundColor Red
}

# Step 6: Reset Windows Firewall rules
try {
    netsh advfirewall reset | Out-Null
    Write-Host "Windows Firewall reset to default rules." -ForegroundColor Green
} catch {
    Write-Host "Failed to reset Windows Firewall: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host "Local Group Policy has been reset to default. A system restart may be required." -ForegroundColor Yellow

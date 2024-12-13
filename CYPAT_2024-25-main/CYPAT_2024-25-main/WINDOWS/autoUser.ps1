param(
    [Parameter()]
    [string]$UsersFilePath = "users.txt",

    [Parameter()]
    [string]$DefaultPassword = "aPASSWORD12345!",

    [Parameter()]
    [string]$NewAdminName = "RenamedAdmin",

    [Parameter()]
    [string]$NewGuestName = "RenamedGuest"
)

# Function: Write-Message
function Write-Message {
    param(
        [Parameter(Mandatory=$true)][string]$Message,
        [Parameter()][string]$Level = "INFO"
    )
    $timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    $output = "[$timestamp] [$Level] $Message"
    Write-Host $output
}

# Check Administrator Privileges
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Message -Message "You must run this script as an Administrator." -Level "ERROR"
    exit 1
}

# Check if running on Windows Server
try {
    $osInfo = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
    if ($osInfo.ProductType -ne 3) {
        Write-Message -Message "This script is optimized for Windows Server and should be run on a server OS." -Level "ERROR"
        exit 1
    }
} catch {
    Write-Message -Message "Failed to retrieve OS information: $_" -Level "ERROR"
    exit 1
}

# Define whitelist (builtin accounts to ignore)
$whitelist = @("Administrator", "Guest", "DefaultAccount", "WDAGUtilityAccount")

# Verify users.txt existence
if (-not (Test-Path $UsersFilePath)) {
    Write-Message -Message "The file '$UsersFilePath' does not exist. Provide a valid file path." -Level "ERROR"
    exit 1
}

# Parse users.txt
try {
    $usersFileContent = Get-Content $UsersFilePath -ErrorAction Stop
} catch {
    Write-Message -Message "Error reading '$UsersFilePath': $_" -Level "ERROR"
    exit 1
}

$authorizedAdmins = @()
$authorizedUsers = @()
$isInAdminSection = $false

foreach ($line in $usersFileContent) {
    if ([string]::IsNullOrWhiteSpace($line)) { continue }

    if ($line -eq "Authorized Administrators:") {
        $isInAdminSection = $true
        continue
    } elseif ($line -eq "Authorized Users:") {
        $isInAdminSection = $false
        continue
    }

    if ($isInAdminSection) {
        $authorizedAdmins += $line.Trim()
    } else {
        $authorizedUsers += $line.Trim()
    }
}

# Function to manage user accounts
function Manage-UserAccount {
    param(
        [Parameter(Mandatory=$true)][string]$Username,
        [Parameter(Mandatory=$true)][bool]$IsAdmin
    )

    # Ignore whitelisted accounts
    if ($Username -in $whitelist) {
        Write-Message "User $Username is whitelisted and will be ignored."
        return
    }

    # Check if user exists
    $userExists = Get-LocalUser -Name $Username -ErrorAction SilentlyContinue

    # If user doesn't exist, create them
    if (-not $userExists) {
        Write-Message "Creating user $Username..."
        try {
            New-LocalUser -Name $Username -NoPassword -AccountNeverExpires -UserMayNotChangePassword | Out-Null
            Add-LocalGroupMember -Group "Users" -Member $Username -ErrorAction SilentlyContinue
            Write-Message "User $Username created and added to 'Users' group."
        } catch {
            Write-Message "Failed to create user $Username $_" -Level "ERROR"
            return
        }
    }

    # Manage membership in Administrators group
    try {
        if ($IsAdmin) {
            Add-LocalGroupMember -Group "Administrators" -Member $Username -ErrorAction SilentlyContinue
            Write-Message "Added $Username to Administrators group."
        } else {
            Remove-LocalGroupMember -Group "Administrators" -Member $Username -ErrorAction SilentlyContinue
            Write-Message "Removed $Username from Administrators group."
        }
    } catch {
        Write-Message "Failed to modify Administrators group for $Username $_" -Level "ERROR"
    }
}

Write-Message "Removing unauthorized users..."
# Remove unauthorized users
try {
    $localUsers = Get-LocalUser
    foreach ($localUser in $localUsers) {
        if (($localUser.Name -notin $authorizedUsers) -and ($localUser.Name -notin $authorizedAdmins) -and ($localUser.Name -notin $whitelist)) {
            try {
                Remove-LocalUser -Name $localUser.Name -ErrorAction Stop
                Write-Message "User $($localUser.Name) has been removed."
            } catch {
                Write-Message "Error removing user $($localUser.Name): $_" -Level "ERROR"
            }
        }
    }
} catch {
    Write-Message "Error retrieving local users: $_" -Level "ERROR"
    exit 1
}

Write-Message "Processing authorized administrators..."
foreach ($admin in $authorizedAdmins) {
    Manage-UserAccount -Username $admin -IsAdmin $true
}

Write-Message "Processing authorized users..."
foreach ($user in $authorizedUsers) {
    Manage-UserAccount -Username $user -IsAdmin $false
}

Write-Message "All authorized accounts are now managed."

# Change passwords for all local users
Write-Message "Changing passwords for all local users..."
try {
    $SecurePassword = ConvertTo-SecureString $DefaultPassword -AsPlainText -Force
    $UserAccounts = Get-LocalUser
    foreach ($UserAccount in $UserAccounts) {
        try {
            $UserAccount | Set-LocalUser -Password $SecurePassword -ErrorAction Stop
            Write-Message "Password for $($UserAccount.Name) has been changed."
        } catch {
            Write-Message "Failed to change password for $($UserAccount.Name): $_" -Level "ERROR"
        }
    }
} catch {
    Write-Message "Error setting default password: $_" -Level "ERROR"
}

# Rename and disable default accounts
Write-Message "Renaming and disabling default accounts..."
try {
    $adminAccount = Get-LocalUser -Name "Administrator" -ErrorAction SilentlyContinue
    if ($null -ne $adminAccount) {
        Rename-LocalUser -Name "Administrator" -NewName $NewAdminName -ErrorAction SilentlyContinue
        Disable-LocalUser -Name $NewAdminName -ErrorAction SilentlyContinue
        Write-Message "Administrator account renamed to $NewAdminName and disabled."
    }

    $guestAccount = Get-LocalUser -Name "Guest" -ErrorAction SilentlyContinue
    if ($null -ne $guestAccount) {
        Rename-LocalUser -Name "Guest" -NewName $NewGuestName -ErrorAction SilentlyContinue
        Disable-LocalUser -Name $NewGuestName -ErrorAction SilentlyContinue
        Write-Message "Guest account renamed to $NewGuestName and disabled."
    }
} catch {
    Write-Message "Error renaming/disabling default accounts: $_" -Level "ERROR"
}

Write-Message "User account management completed successfully."
exit 0

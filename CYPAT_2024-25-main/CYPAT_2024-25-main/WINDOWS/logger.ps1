# Check for administrator privileges
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
	Write-Error "You need to run this script as an Administrator."
	exit
}

# Check if Active Directory module is available
if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
	Write-Warning "Active Directory module not found. Proceeding with local user management."
}

# Define the path to the users.txt file
$usersFilePath = "users.txt"

# Define the whitelist of users to ignore
$whitelist = @("Administrator", "Guest", "DefaultAccount", "WDAGUtilityAccount")

# Define log file path
$logDirectory = "C:\Logs"
$LogFilePath = "$logDirectory\SecurityAuditLog.txt"

# Ensure log directory exists
if (-not (Test-Path $logDirectory)) {
	New-Item -ItemType Directory -Path $logDirectory | Out-Null
}

# Function to append text to the log file
function Write-ToLog {
	param ([string]$Text)
	Add-Content -Path $LogFilePath -Value $Text
}

# Log initialization
Write-ToLog "\nSecurity Audit Log - $(Get-Date)\n"

# Log SMB Shares
Write-ToLog "----- SMB Shares -----"
$smbShares = Get-SmbShare
if ($smbShares.Count -eq 0) {
	Write-ToLog "No SMB Shares found."
} else {
	$smbShares | ForEach-Object {
    	Write-ToLog $_.Name
	}
}

# Log Elevated Privileges
Write-ToLog "----- Users with Elevated Privileges -----"
$usersWithAdmin = Get-LocalGroupMember -Group "Administrators" | Select-Object -ExpandProperty Name
foreach ($user in $usersWithAdmin) {
	Write-ToLog $user
}

# Additional Security Checks
Write-ToLog "----- Unauthorized Scheduled Tasks -----"
Get-ScheduledTask | Where-Object { $_.Principal.RunLevel -eq 'Highest' } | ForEach-Object {
	Write-ToLog $_.TaskName
}

# Log inappropriate access to user directories
Write-ToLog "----- Inappropriate User Access to Other User Directories -----"
$userProfiles = Get-ChildItem C:\Users -Directory
foreach ($profile in $userProfiles) {
	$userDir = $profile.FullName
	$acl = Get-Acl $userDir
	foreach ($access in $acl.Access) {
    	if ($access.FileSystemRights -like "*FullControl*" -or $access.FileSystemRights -like "*Modify*") {
        	if ($access.IdentityReference -notlike "BUILTIN\\Administrators" -and $access.IdentityReference -notlike "NT AUTHORITY\\SYSTEM" -and $access.IdentityReference -notlike $profile.Name) {
            	$logEntry = "User $($access.IdentityReference) has $($access.FileSystemRights) access to $userDir"
            	Write-ToLog $logEntry
        	}
    	}
	}
}

# Log ACLs of user directories
Write-ToLog "----- ACLs of User Directories -----"
$outputFile = "$logDirectory\USERACLS.txt"
$userDirectories = Get-ChildItem -Path "C:\Users" -Directory
foreach ($dir in $userDirectories) {
	$acl = Get-Acl -Path $dir.FullName
	$acl | Out-File -FilePath $outputFile -Append
	Add-Content -Path $outputFile -Value "\n" # Add a new line for separation
}

# Read the content of the users.txt file
if (-not (Test-Path $usersFilePath)) {
	Write-Error "The file $usersFilePath does not exist. Please provide a valid file path."
	exit
}

$usersFileContent = Get-Content $usersFilePath

# Initialize variables
$authorizedAdmins = @()
$authorizedUsers = @()
$isInAdminSection = $false

# Parse the file
foreach ($line in $usersFileContent) {
	if ($line -eq "Authorized Administrators:") {
    	$isInAdminSection = $true
    	continue
	} elseif ($line -eq "Authorized Users:") {
    	$isInAdminSection = $false
    	continue
	}

	if ($isInAdminSection) {
    	$authorizedAdmins += $line
	} else {
    	$authorizedUsers += $line
	}
}

# Function to manage user account
function Manage-UserAccount {
	param (
    	[string]$username,
    	[boolean]$isAdmin
	)

	# Check if the user is in the whitelist
	if ($username -in $whitelist) {
    	Write-Host "User $username is in the whitelist and will be ignored."
    	return
	}

	# Check if the user exists
	$userExists = Get-LocalUser -Name $username -ErrorAction SilentlyContinue

	# If user does not exist, create the user
	if (-not $userExists) {
    	Write-Host "Creating user $username..."
    	New-LocalUser -Name $username -NoPassword -AccountNeverExpires -UserMayNotChangePassword
    	Add-LocalGroupMember -Group "Users" -Member $username -ErrorAction SilentlyContinue
	}

	# Add or remove user from Administrators group
	$adminGroup = Get-LocalGroup -Name "Administrators"
	if ($isAdmin) {
    	Add-LocalGroupMember -Group $adminGroup -Member $username -ErrorAction SilentlyContinue
    	Write-Host "Added $username to Administrators group."
	} else {
    	Remove-LocalGroupMember -Group $adminGroup -Member $username -ErrorAction SilentlyContinue
    	Write-Host "Removed $username from Administrators group."
	}
}

# Get current local users
$localUsers = Get-LocalUser

# Remove unauthorized users
foreach ($user in $localUsers) {
	if (($user.Name -notin $authorizedUsers) -and ($user.Name -notin $authorizedAdmins) -and ($user.Name -notin $whitelist)) {
    	try {
        	Remove-LocalUser -Name $user.Name
        	Write-Host "User $($user.Name) has been removed."
    	} catch {
        	Write-Host "Error removing user $($user.Name): $_"
    	}
	}
}

# Process authorized users and admins
foreach ($admin in $authorizedAdmins) {
	Manage-UserAccount -username $admin -isAdmin $true
}

foreach ($user in $authorizedUsers) {
	Manage-UserAccount -username $user -isAdmin $false
}

# Update administrator passwords
Write-Host "Changing passwords for all local users..."
$Password = ConvertTo-SecureString "aPASSWORD12345!" -AsPlainText -Force
$UserAccounts = Get-LocalUser

foreach ($UserAccount in $UserAccounts) {
	try {
    	$UserAccount | Set-LocalUser -Password $Password
    	Write-Host "Password for $($UserAccount.Name) has been changed."
	} catch {
    	Write-Host "Failed to change password for $($UserAccount.Name): $_"
	}
}

# Rename and disable default accounts
Write-Host "Renaming and disabling default accounts..."

$newAdminName = "NewAdminName"
$newGuestName = "NewGuestName"

$adminAccount = Get-LocalUser -Name "Administrator" -ErrorAction SilentlyContinue
if ($null -ne $adminAccount) {
	Rename-LocalUser -Name "Administrator" -NewName $newAdminName
	Disable-LocalUser -Name $newAdminName
}

$guestAccount = Get-LocalUser -Name "Guest" -ErrorAction SilentlyContinue
if ($null -ne $guestAccount) {
	Rename-LocalUser -Name "Guest" -NewName $newGuestName
	Disable-LocalUser -Name $newGuestName
}

Write-Host "Default accounts have been renamed and disabled."
Write-ToLog "----- End of Security Audit Log -----"

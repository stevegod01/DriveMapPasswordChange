$logPath = "C:\log_files\DriveMapRotation_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
$sourcePath = "\\utility\utility\WTSLocation\"
$scriptsDir = "C:\Scripts"
$wtsDecryptPath = Join-Path $scriptsDir "wtsdecrypt.exe"
$wtsCryptPath = Join-Path $scriptsDir "wtscrypt.exe"
$logonScriptsPath = "C:\Windows\application compatibility scripts\logon"
$targetFile = Join-Path $logonScriptsPath "anonymous.cmd"
$targetDrive = "I:"

# Create log directory if it doesn't exist
$logDir = Split-Path $logPath -Parent
if (-not (Test-Path $logDir)) {
    New-Item -ItemType Directory -Path $logDir -Force | Out-Null
}

# Function to write to log file and console
function Write-Log {
    param (
        [string]$Message
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] $Message"
    Write-Host $logMessage
    Add-Content -Path $logPath -Value $logMessage
}

# Log script start
Write-Log "Starting drive map password rotation script for anonymous.cmd"

# Copy wtsdecrypt.exe and wtscrypt.exe from source to C:\Scripts
Write-Log "Copying wtsdecrypt.exe and wtscrypt.exe from $sourcePath to $scriptsDir"
if (-not (Test-Path $scriptsDir)) {
    New-Item -ItemType Directory -Path $scriptsDir -Force | Out-Null
}
try {
    Copy-Item -Path (Join-Path $sourcePath "wtsdecrypt.exe") -Destination $wtsDecryptPath -Force -ErrorAction Stop
    Copy-Item -Path (Join-Path $sourcePath "wtscrypt.exe") -Destination $wtsCryptPath -Force -ErrorAction Stop
    Write-Log "Successfully copied wtsdecrypt.exe and wtscrypt.exe to $scriptsDir"
} catch {
    Write-Log "ERROR: Failed to copy tools from $sourcePath to $scriptsDir. Error: $($_.Exception.Message)"
    exit 1
}

# Ensure wtsdecrypt.exe and wtscrypt.exe exist
if (-not (Test-Path $wtsDecryptPath) -or -not (Test-Path $wtsCryptPath)) {
    Write-Log "ERROR: Required tools (wtsdecrypt.exe or wtscrypt.exe) not found in $scriptsDir"
    exit 1
}

# Function to decrypt wtsnet string
function Get-DecryptedWtsNet {
    param (
        [string]$encryptedString
    )
    Write-Log "Decrypting string: $encryptedString"
    try {
        $decrypted = & $wtsDecryptPath $encryptedString
        Write-Log "Decrypted output: $decrypted"
        # Extract UNC path and username before Password:
        if ($decrypted -match 'Path:\s*([^\s]+)\s+UserName:\s*([^\s]+)(?=\s+Password:|\s*$)') {
            return @{ UncPath = $matches[1]; Username = $matches[2] }
        }
        Write-Log "WARNING: Failed to parse decrypted output, using fallback values"
        return @{ UncPath = "\\LLCUT1\IHCUT\T351a"; Username = "cernerasp\ihcut_map" }
    } catch {
        Write-Log "ERROR: Failed to decrypt string. Error: $($_.Exception.Message)"
        return $null
    }
}

# Function to encrypt wtsnet string
function Get-EncryptedWtsNet {
    param (
        [string]$uncPath,
        [string]$username,
        [string]$password
    )
    Write-Log "Encrypting for UNC: $uncPath, User: $username"
    try {
        $output = & $wtsCryptPath $uncPath $username $password
        Write-Log "Raw output from wtscrypt: $output"
        # Extract the full encrypted string (match the longest base64-like string)
        $encrypted = ($output -split '\r?\n' | Where-Object { $_ -match '^[A-Za-z0-9\+/=\-]{40,}$' })[-1]
        if ($encrypted) {
            Write-Log "Extracted encrypted string: $encrypted"
            return $encrypted
        }
        Write-Log "ERROR: Failed to extract encrypted string from output. Falling back to raw last line."
        # Fallback to the last line of output if regex fails
        $encrypted = ($output -split '\r?\n' | Select-Object -Last 1).Trim()
        Write-Log "Fallback encrypted string: $encrypted"
        return $encrypted
    } catch {
        Write-Log "ERROR: Failed to encrypt string. Error: $($_.Exception.Message)"
        return $null
    }
}

# Function to validate drive mapping
function Test-DriveMapping {
    param (
        [string]$driveLetter,
        [string]$encryptedString
    )
    Write-Log "Validating drive mapping for $driveLetter"
    # Unmap all drives first
    Write-Log "Unmapping all drives"
    & net use * /d /y | Out-Null

    # Run the wtsnet command to map the drive
    Write-Log "Attempting to map $driveLetter with new encryption string"
    $result = & wtsnet $driveLetter $encryptedString
    Write-Log "wtsnet command output: $result"

    # Wait for the drive to settle
    Start-Sleep -Seconds 5

    # Retry checking if the drive is mapped up to 5 times
    $retryCount = 0
    $driveMapped = $false
    while ($retryCount -lt 5 -and -not $driveMapped) {
        # Use net use to check the mapped drive
        $netUseResult = & net use | Select-String -Pattern "I:"
        if ($netUseResult) {
            Write-Log "Drive $driveLetter mapped successfully (checked with net use)"
            $driveMapped = $true
        } else {
            Write-Log "Drive $driveLetter not mapped, retrying..."
            Start-Sleep -Seconds 3
            $retryCount++
        }
    }

    if (-not $driveMapped) {
        Write-Log "Failed to map drive $driveLetter after retries"
    }
    return $driveMapped
}

# Check if anonymous.cmd exists
if (-not (Test-Path $targetFile)) {
    Write-Log "ERROR: $targetFile not found"
    exit 1
}

# Collect wtsnet commands from anonymous.cmd for the specified drive
Write-Log "Scanning for wtsnet commands in $targetFile for drive $targetDrive"
$wtsNetCommands = @()
$content = Get-Content -Path $targetFile
$lineNumber = 0
foreach ($line in $content) {
    $lineNumber++
    if ($line -match 'wtsnet\s+([A-Z]:)\s+([^\s\\]+)') {
        $driveLetter = $matches[1]
        $encryptedString = $matches[2]
        # Only process lines for the target drive and not UNC paths
        if ($driveLetter -eq $targetDrive -and -not ($encryptedString -like '\\*')) {
            Write-Log "Found valid wtsnet command in $targetFile at line $lineNumber for drive $driveLetter"
            $wtsNetCommands += [PSCustomObject]@{
                FilePath       = $targetFile
                LineNumber     = $lineNumber
                OriginalLine   = $line
                DriveLetter    = $driveLetter
                EncryptedString = $encryptedString
            }
        }
    }
}

# Display and log found wtsnet commands with decrypted user information
Write-Log "Found $($wtsNetCommands.Count) wtsnet commands for drive $targetDrive"
Write-Host "Found wtsnet commands for drive $targetDrive:"
$index = 1
foreach ($cmd in $wtsNetCommands) {
    $decrypted = Get-DecryptedWtsNet -encryptedString $cmd.EncryptedString
    if ($decrypted) {
        $uncPath = $decrypted.UncPath
        $username = $decrypted.Username
        Write-Log "$index. wtsnet $($cmd.DriveLetter) $username (File: $($cmd.FilePath), Line: $($cmd.LineNumber))"
        Write-Host "$index. wtsnet $($cmd.DriveLetter) $username (File: $($cmd.FilePath), Line: $($cmd.LineNumber))"
        $cmd | Add-Member -MemberType NoteProperty -Name UncPath -Value $uncPath
        $cmd | Add-Member -MemberType NoteProperty -Name Username -Value $username
    } else {
        Write-Log "WARNING: Failed to decrypt string in $($cmd.FilePath) at line $($cmd.LineNumber), using fallback values"
        Write-Warning "Failed to decrypt string in $($cmd.FilePath) at line $($cmd.LineNumber)"
        $cmd | Add-Member -MemberType NoteProperty -Name UncPath -Value "\\IHCUTNAS\IHCUT\T351a"
        $cmd | Add-Member -MemberType NoteProperty -Name Username -Value "cernerasp\ihcut_map"
    }
    $index++
}

# Prompt user for the domain\username to change
Write-Log "Prompting for user input"
$targetUsername = Read-Host "Enter the current domain\username to change (e.g., cernerasp\ihcut_map)"
$newUsername = Read-Host "Enter the new domain\username"
$newPassword = Read-Host "Enter the new password" -AsSecureString
$newPasswordPlain = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto(
    [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($newPassword))
Write-Log "Received input - Target Username: $targetUsername, New Username: $newUsername"

# Process each matching wtsnet command
$results = @()
$content = Get-Content -Path $targetFile
foreach ($cmd in $wtsNetCommands) {
    Write-Log "Comparing username: '$($cmd.Username)' with target: '$targetUsername'"
    if ($cmd.Username -replace '^cernerasp(\.com)?\\', '' -eq $targetUsername -replace '^cernerasp(\.com)?\\', '') {
        Write-Log "Processing wtsnet command in $($cmd.FilePath) at line $($cmd.LineNumber)"
        # Generate new encrypted string
        $newEncryptedString = Get-EncryptedWtsNet -uncPath $cmd.UncPath -username $newUsername -password $newPasswordPlain
        if (-not $newEncryptedString) {
            Write-Log "ERROR: Failed to generate new encrypted string for line $($cmd.LineNumber)"
            continue
        }
        
        # Update only the encrypted string, preserving original formatting
        Write-Log "Updating encrypted string in $($cmd.FilePath) at line $($cmd.LineNumber)"
        $originalLine = $cmd.OriginalLine
        $updatedLine = $originalLine -replace [regex]::Escape($cmd.EncryptedString), $newEncryptedString
        $content[$cmd.LineNumber - 1] = $updatedLine
        Write-Log "Original line: $originalLine"
        Write-Log "Updated line: $updatedLine"
        
        # Validate the new mapping
        $success = Test-DriveMapping -driveLetter $cmd.DriveLetter -encryptedString $newEncryptedString
        
        $results += [PSCustomObject]@{
            FilePath    = $cmd.FilePath
            LineNumber  = $cmd.LineNumber
            DriveLetter = $cmd.DriveLetter
            Success     = $success
        }
    } else {
        Write-Log "Skipping command at line $($cmd.LineNumber): Username $($cmd.Username) does not match target $targetUsername"
    }
}

# Write updated content back to anonymous.cmd
Write-Log "Writing updated content to $targetFile"
try {
    Set-Content -Path $targetFile -Value $content -Force
    Write-Log "Successfully updated $targetFile"
    # Verify the update by re-reading the file
    $updatedContent = Get-Content -Path $targetFile
    $updatedLine = $updatedContent[$results[0].LineNumber - 1]
    Write-Log "Verified updated line: $updatedLine"
} catch {
    Write-Log "ERROR: Failed to write to $targetFile. Error: $($_.Exception.Message)"
    exit 1
}

# Output and log results
Write-Log "Update results:"
Write-Host "`nUpdate results:"
foreach ($result in $results) {
    $status = if ($result.Success) { "Success" } else { "Failed" }
    Write-Log "File: $($result.FilePath), Line: $($result.LineNumber), Drive: $($result.DriveLetter) - $status"
    Write-Host "File: $($result.FilePath), Line: $($result.LineNumber), Drive: $($result.DriveLetter) - $status"
}

# Cleanup: Remove wtsdecrypt.exe and wtscrypt.exe
Write-Log "Cleaning up tools"
Remove-Item -Path $wtsDecryptPath -ErrorAction SilentlyContinue
Remove-Item -Path $wtsCryptPath -ErrorAction SilentlyContinue

Write-Log "Process completed. Tools removed from $scriptsDir."
Write-Host "`nProcess completed. Tools removed from $scriptsDir."

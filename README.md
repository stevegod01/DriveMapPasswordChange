# Drive Map Account Password Change Automation Script

This PowerShell script automates the process of updating drive mapping account passwords in logon scripts, as outlined in the CernerWorks Drive Map Account Password Change WP (version 52). It is designed to handle the rotation of credentials for Active Directory (AD) accounts used in `wtsnet` commands within `.cmd` files, ensuring secure encryption and validation of drive mappings.

## Overview

The script:
- Copies required encryption tools (`wtscrypt.exe` and `wtsdecrypt.exe`) to a local directory.
- Updates `anonymous.cmd` and `explicit.cmd` (and potentially other logon scripts) with new AD credentials.
- Generates encrypted strings using `wtscrypt.exe` based on user-provided credentials.
- Validates drive mappings and logs all actions for auditing.

## Prerequisites

-  Environment : A Windows machine with administrative privileges (e.g., a GM in the domain).
-  Tools : Access to `\\utility\utility\WTSLocation\ to copy `wtscrypt.exe` and `wtsdecrypt.exe`.
-  Files : Existing logon scripts (e.g., `anonymous.cmd`, `explicit.cmd`) in `C:\Windows\application compatibility scripts\logon`.
-  Permissions : Read/write access to system directories and network shares.
-  PowerShell : Version 5.1 or higher with execution policy set to allow scripts (e.g., `Bypass`).

## Installation

1.  Clone the Repository :
   - Run `git clone https://github.com/yourusername/DriveMapPasswordChange.git` in your terminal.
   
2.  Set Up the Environment :
   - Ensure the target machine has access to the network share containing the encryption tools.
   - Manually back up existing logon scripts in `C:\Windows\application compatibility scripts\logon` before use.

3.  Copy Tools :
   - The script will attempt to copy `wtscrypt.exe` and `wtsdecrypt.exe` from `\\utility\utility\WTSLocation\` to `C:\Scripts`. Verify network access or copy them manually if needed.

4.  Edit the Script :
   - Open `DriveMapRotation.ps1` in a PowerShell editor.
   - Adjust the `$driveLetter` variable (e.g., `I:`) to match your environment.
   - Update the `$scriptFiles` array if additional logon scripts need processing.

## Usage

1.  Run the Script :
   - Open PowerShell with administrative privileges.
   - Navigate to the script directory: `cd path\to\DriveMapPasswordChange`.
   - Execute the script: `powershell -ExecutionPolicy Bypass -File .\DriveMapRotation.ps1 -Verbose`.

2.  Provide Credentials :
   - When prompted, enter the new `<domain>\<username>` (e.g., `cernerasp.com\<clientmn>_vda_mapp1`).
   - Enter the corresponding password generated from the Vault/AD.

3.  Monitor Output :
   - The script will display progress and any errors in the console.
   - Check the log file (e.g., `C:\log_files\DriveMapRotation_20250626_1416.log`) for detailed results.

4.  Validate :
   - After execution, open a Command Prompt and run `net use` to confirm the drive (e.g., `I:`) is mapped.
   - Ensure the log indicates "Drive mapping successful".

## Example Log Entry
```
2025-06-26 14:16:00 - Copied wtscrypt.exe and wtsdecrypt.exe to C:\Scripts
2025-06-26 14:16:01 - Received new credentials for cernerasp.com\test_vda_mapp1
2025-06-26 14:16:02 - Decrypted old string from anonymous.cmd: [old path/username/password]
2025-06-26 14:16:03 - Updated anonymous.cmd with new encrypted string: XC1x...
2025-06-26 14:16:04 - Drive mapping successful for I: in anonymous.cmd
2025-06-26 14:16:05 - Script execution completed. Check C:\log_files\DriveMapRotation_20250626_1416.log for details
```

## Troubleshooting

-  Errors : If `wtscrypt.exe` or `wtsdecrypt.exe` fails, ensure they are accessible and compatible with your environment.
-  Permissions : Run PowerShell as an administrator if access is denied.
-  Log Review : Check the log file for specific error messages and adjust paths or credentials accordingly.

## Contributing

Feel free to fork this repository, make improvements, and submit pull requests. Ensure any changes are tested in a non-production environment first.

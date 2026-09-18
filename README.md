# Drive mapping credential rotation

A Windows PowerShell utility for replacing encrypted WTS mapping tokens in an explicitly selected command file. It changes the mapping configuration; it does not change an Active Directory password. Supply credentials that have already been provisioned through your normal account process.

The earlier prototype contained a parse error, logged decrypted output, disconnected unrelated drives and saved changes even when verification failed. This version removes those behaviors and has offline regression tests. Real WTS tools and SMB access have not been exercised during this repair; verify vendor compatibility in a controlled maintenance session before operational use.

## Scope and behavior

- One command file and one target drive per invocation.
- Exact current identity matching, including the domain, case insensitive.
- Only standalone wtsnet or wtsnet.exe lines with an optional leading @ and one unquoted encrypted token are supported. Comments and unrelated lines are preserved. Compound commands, quoted executable paths/tokens, expansion and redirection on target lines are rejected.
- Decrypt/parse, encrypt and round-trip the replacement identity. Malformed/ambiguous output aborts; no fallback account or share is substituted.
- Validate on a separate, explicitly reserved, unused drive letter. Existing target and unrelated mappings are left in place. A failure or cleanup error aborts the entire rotation.
- Replace the file only after every matching command passes. Save an adjacent backup, preserve supported encoding/newlines, compare for concurrent edits, replace atomically and verify bytes. Failed post-write verification triggers restoration of the original.
- No decrypted output, password, token, native output or full command line is logged. The returned object reports Updated, NoMatch or Preview, the change count and backup path.

## Requirements

Windows PowerShell 5.1 or PowerShell 7 on Windows; SMB cmdlets and CIM; trusted, already-installed wtsdecrypt.exe, wtscrypt.exe and wtsnet.exe in one explicitly supplied directory. The script neither downloads nor deletes these tools. Verify their origin using your organization's software process.

The tool-output contract expected here is a Path / UserName / Password record from wtsdecrypt and exactly one token line of at least 40 base64-like characters from wtscrypt. Unexpected formats fail closed. Confirm the contract against your vendor version rather than weakening parsing around arbitrary output.

Use an exclusive maintenance session and reserve the validation drive letter for this invocation. Do not run concurrent rotations or let another process change the file or reuse that letter. The precommit comparison detects changes made during validation but is not a transaction with unrelated editors. Windows may reject a second connection to the same server under a different identity; use an isolated test session rather than disconnecting existing mappings.

The target must be a regular file, not a link, in a restricted directory. It must contain ASCII/UTF-8, UTF-8 with BOM, or UTF-16LE with BOM. Unsupported encodings are rejected. Backups contain the previous encrypted credentials and must be protected and retained according to your recovery policy. Atomic replacement must be supported by the target filesystem.

## Usage

Clone this repository, review the source and first run the mocked tests:

    git clone https://github.com/stevegod01/DriveMapPasswordChange.git
    cd DriveMapPasswordChange
    pwsh -NoProfile -File ./tests/Run-Tests.ps1

Prepare explicit inputs in a PowerShell session. These examples are placeholders:

    $credential = Get-Credential -UserName 'EXAMPLE\new-map-account'
    $rotation = @{
        TargetFile = 'C:\approved-logon-scripts\anonymous.cmd'
        TargetDrive = 'I:'
        ValidationDrive = 'Z:'
        CurrentUsername = 'EXAMPLE\old-map-account'
        NewCredential = $credential
        ToolsDirectory = 'C:\approved-tools\WTS'
    }
    ./drivemap.ps1 @rotation -WhatIf
    $result = ./drivemap.ps1 @rotation
    $result | Select-Object Status, Changed, BackupPath

WhatIf reads/decrypts the existing tokens so it can identify affected lines. It does not encrypt, map/unmap drives or write the command file. A no-match result performs no mutation.

The legacy encryption executable accepts a plaintext password argument. A SecureString prompt avoids storing it in the script/history, but the vendor interface still exposes plaintext transiently to the process environment/command-line inspection and managed memory. This utility cannot provide a stronger guarantee than that interface. Do not enable command transcripts or native tracing around real credentials, and use a supported vendor API if your policy disallows command-line secrets.

## Recovery

If post-write verification fails, the utility attempts to restore the original automatically. If that also fails, it stops and instructs you to recover the saved backup. Stop other writers and inspect the exact target and backup before restoring. For an intentionally reverted successful run, use the BackupPath returned by that run:

    Copy-Item -LiteralPath $result.BackupPath -Destination $rotation.TargetFile -Force

This manual command overwrites the current file; compare it first if subsequent authorized edits have occurred. Verify the restored contents and permissions. Temporary validation mappings are removed before commit, so there is no persistent drive change to roll back.

## Checks and limits

The dependency-free test harness replaces all WTS and SMB operations with fakes. It covers success and byte preservation, wrong/ambiguous tool output, round-trip mismatch, failed mapping, failed cleanup, occupied validation drive, no-match, preview, compound commands, multiple-target failure, concurrent edits, automatic rollback and UTF-16LE preservation. CI runs it under both Windows PowerShell and PowerShell 7.

These tests do not establish vendor compatibility, actual SMB behavior, filesystem ACL behavior, real password validity or live recovery. Record those integration results separately; this repository should not be presented as production-validated automation until they are completed.

The historical prototype is preserved in Git history at 11d2b7401a1fff9568a61a3f2a8ba273905d2d91. Environment-specific account/share paths were removed from the current implementation. No third-party WTS executables or new license claims are included.

# Native tool output is sensitive. Never include it in errors or logs.
Set-StrictMode -Version Latest

function ConvertFrom-WtsOutput {
    param([Parameter(Mandatory)][string]$Text)
    $match = [regex]::Match($Text.Trim(), '\APath:\s*(?<path>[^\r\n]+?)\s+UserName:\s*(?<user>[^\s]+)\s+Password:[^\r\n]*(?:\r?\n)?\z')
    if (-not $match.Success -or $match.Groups['path'].Value -notmatch '^\\\\[^\\\s]+\\[^\r\n]+$') {
        throw 'Unrecognized decrypted tool output; no fallback identity is permitted.'
    }
    [pscustomobject]@{ UncPath = $match.Groups['path'].Value.Trim(); Username = $match.Groups['user'].Value }
}

function ConvertTo-WtsToken {
    param([Parameter(Mandatory)][string]$Text)
    $tokens = @($Text -split '\r?\n' | Where-Object { $_ -cmatch '^[A-Za-z0-9+/=\-]{40,}$' })
    if ($tokens.Count -ne 1) { throw 'Encryption did not return exactly one valid token.' }
    $tokens[0]
}

function Invoke-WtsTool {
    param([string]$Path, [string[]]$Arguments)
    try {
        $output = & $Path @Arguments 2>$null
        if ($LASTEXITCODE -ne 0) { throw 'Tool failed.' }
        ($output -join "`n")
    } catch { throw 'WTS tool failed; sensitive native output was suppressed.' }
}

function New-NativeDriveOperations {
    param([string]$DecryptPath, [string]$CryptPath, [string]$WtsNetPath)
    $invoke = ${function:Invoke-WtsTool}
    @{
        Decrypt = { param($token) & $invoke $DecryptPath @($token) }.GetNewClosure()
        Encrypt = { param($unc, $user, $password) & $invoke $CryptPath @($unc, $user, $password) }.GetNewClosure()
        IsDriveInUse = {
            param($drive)
            $smb = @(Get-SmbMapping -ErrorAction Stop | Where-Object LocalPath -EQ $drive)
            $logical = @(Get-CimInstance Win32_LogicalDisk -ErrorAction Stop | Where-Object DeviceID -EQ $drive)
            ($smb.Count -gt 0 -or $logical.Count -gt 0)
        }
        Map = { param($drive, $token) $null = & $invoke $WtsNetPath @($drive, $token) }.GetNewClosure()
        Verify = {
            param($drive, $unc)
            for ($attempt = 0; $attempt -lt 5; $attempt++) {
                $mapping = @(Get-SmbMapping -ErrorAction Stop | Where-Object LocalPath -EQ $drive)
                if ($mapping.Count -eq 1 -and $mapping[0].RemotePath.TrimEnd('\') -ieq $unc.TrimEnd('\') -and [string]$mapping[0].Status -eq 'OK' -and (Test-Path -LiteralPath ($drive + '\') -ErrorAction Stop)) { return $true }
                if ($attempt -lt 4) { Start-Sleep -Seconds 1 }
            }
            $false
        }
        Unmap = {
            param($drive)
            $existing = @(Get-SmbMapping -ErrorAction Stop | Where-Object LocalPath -EQ $drive)
            if ($existing.Count -gt 0) { Remove-SmbMapping -LocalPath $drive -Force -UpdateProfile -ErrorAction Stop }
        }
    }
}

function Read-CommandFile {
    param([string]$Path)
    $bytes = [IO.File]::ReadAllBytes($Path)
    $offset = 0
    $encoding = [Text.UTF8Encoding]::new($false, $true)
    if ($bytes.Length -ge 3 -and $bytes[0] -eq 239 -and $bytes[1] -eq 187 -and $bytes[2] -eq 191) {
        $encoding = [Text.UTF8Encoding]::new($true, $true); $offset = 3
    } elseif ($bytes.Length -ge 2 -and $bytes[0] -eq 255 -and $bytes[1] -eq 254) {
        $encoding = [Text.UnicodeEncoding]::new($false, $true, $true); $offset = 2
    }
    try { $text = $encoding.GetString($bytes, $offset, $bytes.Length - $offset) } catch { throw 'Unsupported command-file encoding. Use ASCII, UTF-8, or UTF-16LE with BOM.' }
    if ($text.Contains([char]0)) { throw 'Unsupported command-file encoding.' }
    [pscustomobject]@{ Bytes = $bytes; Text = $text; Encoding = $encoding }
}

function Assert-CommandFileBytes {
    param([string]$Path, [byte[]]$Expected)
    if ([Convert]::ToBase64String([IO.File]::ReadAllBytes($Path)) -cne [Convert]::ToBase64String($Expected)) { throw 'Post-write verification failed.' }
}

function Invoke-DriveMapRotation {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][string]$TargetFile,
        [Parameter(Mandatory)][ValidatePattern('^[A-Za-z]:$')][string]$TargetDrive,
        [Parameter(Mandatory)][ValidatePattern('^[A-Za-z]:$')][string]$ValidationDrive,
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$CurrentUsername,
        [Parameter(Mandatory)][pscredential]$NewCredential,
        [Parameter(Mandatory)][hashtable]$Operations
    )
    $ErrorActionPreference = 'Stop'
    if ($TargetDrive -ieq $ValidationDrive) { throw 'ValidationDrive must differ from TargetDrive.' }
    foreach ($operation in 'Decrypt','Encrypt','IsDriveInUse','Map','Verify','Unmap') {
        if (-not $Operations.ContainsKey($operation) -or $Operations[$operation] -isnot [scriptblock]) { throw "Missing operation: $operation" }
    }
    $file = Get-Item -LiteralPath $TargetFile -ErrorAction Stop
    if ($file.PSIsContainer -or ($file.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'TargetFile must be a regular file, not a link.' }
    $TargetFile = $file.FullName
    $original = Read-CommandFile $TargetFile
    # Standalone wtsnet lines only; reject compound commands, redirection and expansion.
    $lines = [regex]::Split($original.Text, '(\r\n|\n|\r)')
    $candidates = @()
    for ($i = 0; $i -lt $lines.Length; $i += 2) {
        $line = $lines[$i]
        if ($line -match '^\s*@?(?:rem\b|::)') { continue }
        $m = [regex]::Match($line, '^(?<prefix>\s*@?wtsnet(?:\.exe)?\s+(?<drive>[A-Za-z]:)\s+)(?<token>[A-Za-z0-9+/=\-]{40,})(?<suffix>\s*)$', 'IgnoreCase')
        if (-not $m.Success) {
            if ($line -match ('(?i)\bwtsnet(?:\.exe)?\b.*\b' + [regex]::Escape($TargetDrive))) { throw 'Unsupported target wtsnet command syntax; file was not changed.' }
            continue
        }
        if ($m.Groups['drive'].Value -ine $TargetDrive) { continue }
        $identity = ConvertFrom-WtsOutput (& $Operations.Decrypt $m.Groups['token'].Value)
        if ($identity.Username -ieq $CurrentUsername) {
            $candidates += [pscustomobject]@{ Index = $i; Prefix = $m.Groups['prefix'].Value; Suffix = $m.Groups['suffix'].Value; Identity = $identity }
        }
    }
    if ($candidates.Count -eq 0) { return [pscustomobject]@{ Status = 'NoMatch'; Changed = 0; BackupPath = $null } }
    if (-not $PSCmdlet.ShouldProcess($TargetFile, "Validate and rotate $($candidates.Count) command(s) for ${TargetDrive}")) {
        return [pscustomobject]@{ Status = 'Preview'; Changed = 0; BackupPath = $null }
    }
    $plain = $null
    $bstr = [IntPtr]::Zero
    try {
        $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($NewCredential.Password)
        $plain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
        foreach ($candidate in $candidates) {
            $token = ConvertTo-WtsToken (& $Operations.Encrypt $candidate.Identity.UncPath $NewCredential.UserName $plain)
            $roundTrip = ConvertFrom-WtsOutput (& $Operations.Decrypt $token)
            if ($roundTrip.UncPath -ine $candidate.Identity.UncPath -or $roundTrip.Username -ine $NewCredential.UserName) { throw 'Encrypted token identity did not round-trip correctly.' }
            if (& $Operations.IsDriveInUse $ValidationDrive) { throw 'Validation drive is already in use.' }
            $attempted = $false
            try {
                $attempted = $true
                $null = & $Operations.Map $ValidationDrive $token
                if (-not (& $Operations.Verify $ValidationDrive $candidate.Identity.UncPath)) { throw 'Mapping validation failed.' }
            } finally {
                if ($attempted) { $null = & $Operations.Unmap $ValidationDrive }
            }
            $lines[$candidate.Index] = $candidate.Prefix + $token + $candidate.Suffix
        }
    } catch { throw 'Rotation failed before commit. The command file was not changed. Check tool compatibility, credentials, and the reserved validation drive.' }
    finally {
        if ($bstr -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
        $plain = $null
    }
    $updatedBytes = [byte[]](@($original.Encoding.GetPreamble()) + @($original.Encoding.GetBytes(($lines -join ''))))
    $backup = $TargetFile + '.bak.' + [guid]::NewGuid().ToString('N')
    $temporary = $TargetFile + '.pending.' + [guid]::NewGuid().ToString('N')
    $committed = $false
    try {
        $current = [IO.File]::ReadAllBytes($TargetFile)
        if ([Convert]::ToBase64String($current) -cne [Convert]::ToBase64String($original.Bytes)) { throw 'Command file changed during validation.' }
        [IO.File]::WriteAllBytes($temporary, $updatedBytes)
        [IO.File]::Replace($temporary, $TargetFile, $backup)
        $committed = $true
        Assert-CommandFileBytes $TargetFile $updatedBytes
    } catch {
        if ($committed) {
            try { [IO.File]::Replace($backup, $TargetFile, $temporary) } catch { throw 'Commit verification and automatic restore failed. Recover the saved backup before further changes.' }
            throw 'Commit verification failed; original file restored.'
        }
        throw 'Commit failed; original file retained. Check file permissions, filesystem support, or concurrent editing.'
    } finally { if ([IO.File]::Exists($temporary)) { [IO.File]::Delete($temporary) } }
    [pscustomobject]@{ Status = 'Updated'; Changed = $candidates.Count; BackupPath = $backup }
}

Export-ModuleMember -Function Invoke-DriveMapRotation, New-NativeDriveOperations, ConvertFrom-WtsOutput, ConvertTo-WtsToken

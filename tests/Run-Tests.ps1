# Dependency-free regression harness. All WTS/SMB operations are fakes.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$root = Split-Path $PSScriptRoot -Parent
$modulePath = Join-Path $root 'DriveMapRotation.psm1'
$failures = 0
$passed = 0
function Assert($condition, [string]$message) { if (-not $condition) { throw $message } }
function Expect-Failure([scriptblock]$action) {
    $failed = $false
    try { & $action | Out-Null } catch { $failed = $true; Assert ($_.Exception.Message -notmatch 'SENSITIVE') 'Sensitive error leaked.' }
    Assert $failed 'Expected a failure.'
}
function Run-Case([string]$name, [scriptblock]$body) {
    Import-Module $modulePath -Force
    $temporaryRoot = Join-Path ([IO.Path]::GetTempPath()) ('drivemap-test-' + [guid]::NewGuid().ToString('N'))
    $null = [IO.Directory]::CreateDirectory($temporaryRoot)
    try {
        $oldToken = 'A' * 48
        $newToken = 'B' * 48
        $file = Join-Path $temporaryRoot 'logon.cmd'
        $initial = "@echo off`r`n  @wtsnet.exe I: $oldToken  `r`nrem wtsnet I: ignored`r`nwtsnet J: $oldToken`r`n"
        [IO.File]::WriteAllText($file, $initial, [Text.UTF8Encoding]::new($false))
        $calls = [Collections.Generic.List[string]]::new()
        $operations = @{
            Decrypt = { param($token) if ($token -eq $newToken) { 'Path: \\server\share UserName: DOMAIN\new Password: SENSITIVE-NEW' } else { 'Path: \\server\share UserName: DOMAIN\old Password: SENSITIVE-OLD' } }.GetNewClosure()
            Encrypt = { param($unc,$user,$password) $calls.Add('encrypt'); $newToken }.GetNewClosure()
            IsDriveInUse = { param($drive) $calls.Add("query:$drive"); $false }.GetNewClosure()
            Map = { param($drive,$token) $calls.Add("map:$drive") }.GetNewClosure()
            Verify = { param($drive,$unc) $calls.Add("verify:$drive"); $true }.GetNewClosure()
            Unmap = { param($drive) $calls.Add("unmap:$drive") }.GetNewClosure()
        }
        $credential = [pscredential]::new('DOMAIN\new', (ConvertTo-SecureString 'SENSITIVE-NEW' -AsPlainText -Force))
        $arguments = @{ TargetFile=$file; TargetDrive='I:'; ValidationDrive='Z:'; CurrentUsername='DOMAIN\old'; NewCredential=$credential; Operations=$operations }
        & $body
        $script:passed++
        Write-Host "PASS $name"
    } catch { $script:failures++; Write-Host "FAIL $name`: $($_.Exception.Message)" }
    finally {
        # The sole cleanup target is the freshly created test directory.
        if ([IO.Path]::GetFullPath($temporaryRoot).StartsWith([IO.Path]::GetFullPath([IO.Path]::GetTempPath()), [StringComparison]::OrdinalIgnoreCase)) {
            Remove-Item -LiteralPath $temporaryRoot -Recurse -Force
        }
    }
}

Run-Case 'success preserves unrelated lines and bytes; backup and temporary mapping only' {
    $result = Invoke-DriveMapRotation @arguments
    Assert ($result.Status -eq 'Updated' -and $result.Changed -eq 1) 'Wrong result.'
    Assert ([IO.File]::ReadAllText($result.BackupPath) -ceq $initial) 'Backup differs.'
    Assert ([IO.File]::ReadAllText($file) -ceq $initial.Replace("I: $oldToken", "I: $newToken")) 'Unrelated content changed.'
    Assert (($calls -join ',') -eq 'encrypt,query:Z:,map:Z:,verify:Z:,unmap:Z:') 'Unexpected drive side effects.'
}
Run-Case 'mapping verification failure cannot write' {
    $operations.Verify = { $false }
    Expect-Failure { Invoke-DriveMapRotation @arguments }
    Assert ([IO.File]::ReadAllText($file) -ceq $initial) 'Failure changed file.'
    Assert ($calls.Contains('unmap:Z:')) 'Temporary mapping was not cleaned.'
}
Run-Case 'tool error cleanup suppresses raw secret output' {
    $operations.Map = { throw 'SENSITIVE TOOL OUTPUT' }
    Expect-Failure { Invoke-DriveMapRotation @arguments }
    Assert ([IO.File]::ReadAllText($file) -ceq $initial) 'Failure changed file.'
    Assert ($calls.Contains('unmap:Z:')) 'Partial mapping cleanup missing.'
}
Run-Case 'cleanup failure prevents commit' {
    $operations.Unmap = { throw 'SENSITIVE CLEANUP ERROR' }
    Expect-Failure { Invoke-DriveMapRotation @arguments }
    Assert ([IO.File]::ReadAllText($file) -ceq $initial) 'Cleanup failure wrote file.'
}
Run-Case 'occupied validation drive is never mapped or disconnected' {
    $operations.IsDriveInUse = { $true }
    Expect-Failure { Invoke-DriveMapRotation @arguments }
    Assert (-not $calls.Contains('map:Z:') -and -not $calls.Contains('unmap:Z:')) 'Occupied mapping touched.'
    Assert ([IO.File]::ReadAllText($file) -ceq $initial) 'Occupied-drive failure wrote file.'
}
Run-Case 'malformed decrypted output has no fallback' {
    $operations.Decrypt = { 'Path: BAD UserName: DOMAIN\old Password: SENSITIVE' }
    Expect-Failure { Invoke-DriveMapRotation @arguments }
    Assert ($calls.Count -eq 0) 'Malformed identity reached encryption or mapping.'
}
Run-Case 'ambiguous encryption output rejected' {
    $ambiguous = $newToken + "`n" + $oldToken
    $operations.Encrypt = { $ambiguous }.GetNewClosure()
    Expect-Failure { Invoke-DriveMapRotation @arguments }
    Assert (-not $calls.Contains('map:Z:')) 'Ambiguous token mapped.'
}
Run-Case 'round-trip identity mismatch rejected' {
    $operations.Decrypt = { 'Path: \\wrong\share UserName: DOMAIN\old Password: SENSITIVE' }
    Expect-Failure { Invoke-DriveMapRotation @arguments }
    Assert (-not $calls.Contains('map:Z:')) 'Wrong identity mapped.'
}
Run-Case 'no-match does not index empty results or write' {
    $arguments.CurrentUsername = 'OTHER\old'
    $result = Invoke-DriveMapRotation @arguments
    Assert ($result.Status -eq 'NoMatch' -and $calls.Count -eq 0) 'No-match had side effects.'
    Assert ([IO.File]::ReadAllText($file) -ceq $initial) 'No-match changed file.'
}
Run-Case 'WhatIf has no encryption, mapping, or file side effects' {
    $result = Invoke-DriveMapRotation @arguments -WhatIf
    Assert ($result.Status -eq 'Preview' -and $calls.Count -eq 0) 'Preview had side effects.'
}
Run-Case 'unsupported compound target command fails closed' {
    [IO.File]::WriteAllText($file, "wtsnet I: $oldToken & echo injected")
    Expect-Failure { Invoke-DriveMapRotation @arguments }
    Assert ($calls.Count -eq 0) 'Compound command was processed.'
}
Run-Case 'second validation failure leaves all commands untouched' {
    $initial = $initial + "wtsnet I: $oldToken`r`n"
    [IO.File]::WriteAllText($file, $initial)
    $counter = @{ n=0 }
    $operations.Verify = { $counter.n++; $counter.n -lt 2 }.GetNewClosure()
    Expect-Failure { Invoke-DriveMapRotation @arguments }
    Assert ([IO.File]::ReadAllText($file) -ceq $initial) 'Partial rotation written.'
}
Run-Case 'external edits during validation are preserved' {
    $editPath = $file
    $operations.Verify = { [IO.File]::AppendAllText($editPath, 'external edit'); $true }.GetNewClosure()
    Expect-Failure { Invoke-DriveMapRotation @arguments }
    Assert ([IO.File]::ReadAllText($file) -ceq ($initial + 'external edit')) 'External edit overwritten.'
}
Run-Case 'post-commit verification failure restores original automatically' {
    & (Get-Module DriveMapRotation) { function script:Assert-CommandFileBytes { throw 'Injected post-commit failure.' } }
    Expect-Failure { Invoke-DriveMapRotation @arguments }
    Assert ([IO.File]::ReadAllText($file) -ceq $initial) 'Automatic rollback failed.'
}
Run-Case 'UTF-16LE BOM and CRLF preserved' {
    [IO.File]::WriteAllText($file, $initial, [Text.UnicodeEncoding]::new($false,$true))
    $result = Invoke-DriveMapRotation @arguments
    $bytes = [IO.File]::ReadAllBytes($file)
    Assert ($bytes[0] -eq 255 -and $bytes[1] -eq 254) 'BOM lost.'
    Assert ([IO.File]::ReadAllText($file) -ceq $initial.Replace("I: $oldToken", "I: $newToken")) 'Encoding changed content.'
}
Run-Case 'success output does not expose credentials or encrypted tokens' {
    $output = (Invoke-DriveMapRotation @arguments *>&1 | Out-String)
    Assert ($output -notmatch 'SENSITIVE' -and -not $output.Contains($oldToken) -and -not $output.Contains($newToken)) 'Sensitive output leaked.'
}
Run-Case 'same validation and target drive rejected before mutation' {
    $arguments.ValidationDrive = 'i:'
    Expect-Failure { Invoke-DriveMapRotation @arguments }
    Assert ($calls.Count -eq 0 -and [IO.File]::ReadAllText($file) -ceq $initial) 'Same-drive guard failed.'
}
Run-Case 'echo-suppressed REM comments stay unchanged' {
    $initial = "@rem wtsnet I: archived example`r`n" + $initial
    [IO.File]::WriteAllText($file, $initial)
    $result = Invoke-DriveMapRotation @arguments
    Assert ($result.Changed -eq 1 -and [IO.File]::ReadAllText($file).StartsWith('@rem wtsnet')) 'Comment handling broke.'
}
Write-Host "$passed passed; $failures failed. No real WTS/SMB operations were performed."
if ($failures -gt 0) { exit 1 }

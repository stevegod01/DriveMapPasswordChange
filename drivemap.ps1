#requires -Version 5.1
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][string]$TargetFile,
    [Parameter(Mandatory)][ValidatePattern('^[A-Za-z]:$')][string]$TargetDrive,
    [Parameter(Mandatory)][ValidatePattern('^[A-Za-z]:$')][string]$ValidationDrive,
    [Parameter(Mandatory)][string]$CurrentUsername,
    [Parameter(Mandatory)][pscredential]$NewCredential,
    [Parameter(Mandatory)][string]$ToolsDirectory
)
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'DriveMapRotation.psm1') -Force
$tools = @{}
foreach ($name in 'wtsdecrypt','wtscrypt','wtsnet') {
    $path = Join-Path $ToolsDirectory ($name + '.exe')
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "Required trusted tool missing: $name.exe" }
    $tools[$name] = (Get-Item -LiteralPath $path).FullName
}
$operations = New-NativeDriveOperations -DecryptPath $tools.wtsdecrypt -CryptPath $tools.wtscrypt -WtsNetPath $tools.wtsnet
Invoke-DriveMapRotation -TargetFile $TargetFile -TargetDrive $TargetDrive -ValidationDrive $ValidationDrive -CurrentUsername $CurrentUsername -NewCredential $NewCredential -Operations $operations -WhatIf:$WhatIfPreference

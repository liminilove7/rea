[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
$compiler=Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
if(-not (Test-Path -LiteralPath $compiler)){throw 'Missing Windows .NET Framework x64 C# compiler; no software was installed.'}
& $compiler /nologo /target:winexe /platform:x64 /optimize+ /warnaserror+ /r:System.Windows.Forms.dll /r:System.Drawing.dll /r:System.Web.Extensions.dll /out:"$PSScriptRoot\AttackSpeedLab.exe" "$PSScriptRoot\AttackSpeedLab.cs"
if($LASTEXITCODE -ne 0){throw 'Compiler failed'}
Get-FileHash -LiteralPath (Join-Path $PSScriptRoot 'AttackSpeedLab.exe') -Algorithm SHA256

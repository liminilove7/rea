param([string]$OutputDirectory = (Join-Path $PSScriptRoot 'bin\verification'))
$ErrorActionPreference = 'Stop'
& (Join-Path $PSScriptRoot 'build.ps1')
$output = [IO.Path]::GetFullPath($OutputDirectory)
New-Item -ItemType Directory -Force -Path $output | Out-Null
$exe = Join-Path $PSScriptRoot 'bin\Release\net8.0-windows\win-x64\AionLab.exe'
foreach ($test in @(
    @('--self-test', (Join-Path $output 'controller.json')),
    @('--render-test', (Join-Path $output 'render'))
)) {
    $arguments = @($test[0], ('"' + $test[1] + '"'))
    $process = Start-Process -FilePath $exe -ArgumentList $arguments -PassThru -Wait -WindowStyle Hidden
    if ($process.ExitCode -ne 0) { throw "验证失败：$($test[0])，退出码 $($process.ExitCode)。查看程序目录 last-command-error.txt。" }
}
Get-Content -LiteralPath (Join-Path $output 'controller.json'), (Join-Path $output 'controller.json.core.json'), (Join-Path $output 'render\render-verification.json')

param([string]$OutputDirectory = (Join-Path $PSScriptRoot 'bin\verification'))
$ErrorActionPreference = 'Stop'
& (Join-Path $PSScriptRoot 'build.ps1')
$output = [IO.Path]::GetFullPath($OutputDirectory)
New-Item -ItemType Directory -Force -Path $output | Out-Null
$exe = Join-Path $PSScriptRoot 'bin\Release\net8.0-windows\win-x64\SpeedLab.exe'
foreach ($test in @(
    @('--self-test', (Join-Path $output 'controller.json')),
    @('--render-test', (Join-Path $output 'render')),
    @('--render-lock-test', (Join-Path $output 'controls'))
)) {
    $arguments = @($test[0], ('"' + $test[1] + '"'))
    $process = Start-Process -FilePath $exe -ArgumentList $arguments -PassThru -Wait -WindowStyle Hidden
    if ($process.ExitCode -ne 0) { throw "验证失败：$($test[0])，退出码 $($process.ExitCode)。查看程序目录 last-command-error.txt。" }
}
Get-Content -LiteralPath (Join-Path $output 'controller.json'), (Join-Path $output 'controller.json.core.json'), (Join-Path $output 'controller.json.movement.json'), (Join-Path $output 'controller.json.locks.json'), (Join-Path $output 'controller.json.weapon.json'), (Join-Path $output 'render\render-verification.json'), (Join-Path $output 'controls\render-verification.json')

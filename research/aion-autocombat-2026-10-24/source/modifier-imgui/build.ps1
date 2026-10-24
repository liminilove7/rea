param([switch]$Publish, [string]$PublishDirectory = (Join-Path $PSScriptRoot 'publish'))
$ErrorActionPreference = 'Stop'
$project = Join-Path $PSScriptRoot 'AionLab.csproj'
if (-not (Get-Command dotnet -ErrorAction SilentlyContinue)) { throw '需要已安装的 .NET 8 SDK。脚本不会安装软件。' }
& dotnet restore $project --locked-mode
if ($LASTEXITCODE -ne 0) { throw '依赖还原失败。' }
& dotnet build $project -c Release --no-restore
if ($LASTEXITCODE -ne 0) { throw '构建失败。' }
if ($Publish) {
    $destination = [IO.Path]::GetFullPath($PublishDirectory)
    & dotnet publish $project -c Release -r win-x64 --self-contained true --no-restore -o $destination
    if ($LASTEXITCODE -ne 0) { throw '发布构建失败。' }
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'architecture.html'), (Join-Path $PSScriptRoot 'README.txt'), (Join-Path $PSScriptRoot 'THIRD-PARTY-NOTICES.txt'), (Join-Path $PSScriptRoot 'start.cmd'), (Join-Path $PSScriptRoot 'preview.cmd') -Destination $destination
    $evidenceFiles = @(Get-ChildItem -LiteralPath (Join-Path $PSScriptRoot 'evidence') -File -ErrorAction SilentlyContinue)
    if ($evidenceFiles.Count -gt 0) {
        New-Item -ItemType Directory -Force -Path "$destination\evidence" | Out-Null
        $evidenceFiles | Copy-Item -Destination "$destination\evidence"
    }
    $runtimeConfig = Get-Content (Join-Path $destination 'SpeedLab.runtimeconfig.json') -Raw | ConvertFrom-Json
    $runtimeVersion = ($runtimeConfig.runtimeOptions.includedFrameworks | Where-Object name -EQ 'Microsoft.NETCore.App').version
    $assets = Get-Content (Join-Path $PSScriptRoot 'obj\project.assets.json') -Raw | ConvertFrom-Json
    $runtimeRoot = $assets.packageFolders.PSObject.Properties.Name |
        ForEach-Object { Join-Path $_ "microsoft.netcore.app.runtime.win-x64\$runtimeVersion" } |
        Where-Object { Test-Path -LiteralPath (Join-Path $_ 'LICENSE.TXT') } | Select-Object -First 1
    if (-not $runtimeRoot) { throw '找不到发布运行时的许可文件；停止打包。' }
    Copy-Item -LiteralPath (Join-Path $runtimeRoot 'LICENSE.TXT') -Destination (Join-Path $destination 'DOTNET-LICENSE.txt')
    Copy-Item -LiteralPath (Join-Path $runtimeRoot 'THIRD-PARTY-NOTICES.TXT') -Destination (Join-Path $destination 'DOTNET-THIRD-PARTY-NOTICES.txt')
    New-Item -ItemType Directory -Force -Path "$destination\verification", "$destination\screenshots" | Out-Null
    foreach ($test in @(
        @('--self-test', "$destination\verification\controller.json"),
        @('--render-test', "$destination\verification\render"),
        @('--render-lock-test', "$destination\verification\controls")
    )) {
        $process = Start-Process -FilePath "$destination\SpeedLab.exe" -ArgumentList @($test[0], ('"' + $test[1] + '"')) -WindowStyle Hidden -Wait -PassThru
        if ($process.ExitCode -ne 0) { throw "发布包验证失败：$($test[0])。" }
    }
    Add-Type -AssemblyName System.Drawing
    foreach ($pair in @(@('controls-4.bmp','attack-lock.png'), @('controls-12.bmp','both-locks.png'))) {
        $bitmap = [Drawing.Image]::FromFile("$destination\verification\controls\$($pair[0])")
        try { $bitmap.Save("$destination\screenshots\$($pair[1])", [Drawing.Imaging.ImageFormat]::Png) }
        finally { $bitmap.Dispose() }
    }
    $sources = @(Get-ChildItem -LiteralPath $PSScriptRoot -File | Where-Object Extension -In '.cs','.csproj','.ps1','.txt','.html','.cmd','.json')
    $sources += Get-Item -LiteralPath (Join-Path $PSScriptRoot '..\modifier\AttackSpeedLab.cs')
    [ordered]@{
        createdUtc = [DateTime]::UtcNow.ToString('o')
        runtimeVersion = $runtimeVersion
        apphostSHA256 = (Get-FileHash "$destination\SpeedLab.exe" -Algorithm SHA256).Hash.ToLowerInvariant()
        assemblySHA256 = (Get-FileHash "$destination\SpeedLab.dll" -Algorithm SHA256).Hash.ToLowerInvariant()
        sourceFiles = @($sources | ForEach-Object { [ordered]@{ path=$_.FullName; sha256=(Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant() } })
        evidenceFiles = @($evidenceFiles | ForEach-Object { [ordered]@{ path=$_.Name; sha256=(Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant() } })
        scope = 'Native self-process fixtures and actual ImGui synthetic interactions only; no live game writes.'
    } | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath "$destination\BUILD-IDENTITY.json" -Encoding UTF8
}

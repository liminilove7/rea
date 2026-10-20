param([switch]$Publish)
$ErrorActionPreference = 'Stop'
$project = Join-Path $PSScriptRoot 'AionLab.csproj'
if (-not (Get-Command dotnet -ErrorAction SilentlyContinue)) { throw '需要已安装的 .NET 8 SDK。脚本不会安装软件。' }
& dotnet restore $project --locked-mode
if ($LASTEXITCODE -ne 0) { throw '依赖还原失败。' }
& dotnet build $project -c Release --no-restore
if ($LASTEXITCODE -ne 0) { throw '构建失败。' }
if ($Publish) {
    & dotnet publish $project -c Release -r win-x64 --self-contained true -o (Join-Path $PSScriptRoot 'publish')
    if ($LASTEXITCODE -ne 0) { throw '发布构建失败。' }
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'architecture.html'), (Join-Path $PSScriptRoot 'README.txt'), (Join-Path $PSScriptRoot 'THIRD-PARTY-NOTICES.txt'), (Join-Path $PSScriptRoot 'start.cmd'), (Join-Path $PSScriptRoot 'preview.cmd') -Destination (Join-Path $PSScriptRoot 'publish')
    $runtimeConfig = Get-Content (Join-Path $PSScriptRoot 'publish\AionLab.runtimeconfig.json') -Raw | ConvertFrom-Json
    $runtimeVersion = ($runtimeConfig.runtimeOptions.includedFrameworks | Where-Object name -EQ 'Microsoft.NETCore.App').version
    $assets = Get-Content (Join-Path $PSScriptRoot 'obj\project.assets.json') -Raw | ConvertFrom-Json
    $runtimeRoot = $assets.packageFolders.PSObject.Properties.Name |
        ForEach-Object { Join-Path $_ "microsoft.netcore.app.runtime.win-x64\$runtimeVersion" } |
        Where-Object { Test-Path -LiteralPath (Join-Path $_ 'LICENSE.TXT') } | Select-Object -First 1
    if (-not $runtimeRoot) { throw '找不到发布运行时的许可文件；停止打包。' }
    Copy-Item -LiteralPath (Join-Path $runtimeRoot 'LICENSE.TXT') -Destination (Join-Path $PSScriptRoot 'publish\DOTNET-LICENSE.txt')
    Copy-Item -LiteralPath (Join-Path $runtimeRoot 'THIRD-PARTY-NOTICES.TXT') -Destination (Join-Path $PSScriptRoot 'publish\DOTNET-THIRD-PARTY-NOTICES.txt')
}

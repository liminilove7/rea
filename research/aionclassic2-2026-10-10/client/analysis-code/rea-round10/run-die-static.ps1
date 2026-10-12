param(
  [Parameter(Mandatory = $true)][string]$Command,
  [Parameter(Mandatory = $true)][string]$Output
)

$ErrorActionPreference = 'Stop'
$taskStudyRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..\..'))
if (-not [System.IO.Path]::IsPathRooted($Command) -or -not (Test-Path -LiteralPath $Command -PathType Leaf)) {
  throw 'Command must name an existing absolute diec.exe path.'
}
if (-not [System.IO.Path]::IsPathRooted($Output) -or (Test-Path -LiteralPath $Output)) {
  throw 'Output must be a new absolute directory.'
}
$taskExpectedHashes = [ordered]@{
  'Aion.bin' = '17c8de936526f119e16c1923ba5922d3a524698f04c01562fc878424653cda1e'
  'Game.dll' = '834300c2a85b6427de2d4a4be2931ff2ea59fd70f48f31754f5c2181753bd786'
  'CrySystem.dll' = '8705aeef77411a28e178832f2f242128b0b018b9546f58878c9e69df8f4e9061'
  'ScriptDLL64.dll' = 'ea42f2e51de3d46b14e958f11c4f33dc9e78a92cf62765c6a42f0cb79584ca27'
}
$taskSamples = @()
foreach ($taskName in $taskExpectedHashes.Keys) {
  $taskPath = Join-Path $taskStudyRoot ('samples\' + $taskName)
  $taskHash = (Get-FileHash -LiteralPath $taskPath -Algorithm SHA256).Hash.ToLowerInvariant()
  if ($taskHash -ne $taskExpectedHashes[$taskName]) { throw "Sample identity mismatch: $taskName" }
  $taskSamples += [pscustomobject]@{ Name = $taskName; Path = $taskPath; Sha256 = $taskHash }
}
New-Item -ItemType Directory -Path $Output | Out-Null
$taskManifest = [ordered]@{
  Command = $Command
  ToolSha256 = (Get-FileHash -LiteralPath $Command -Algorithm SHA256).Hash.ToLowerInvariant()
  Arguments = @('--json', 'explicit sample path')
  Results = @()
  TargetExecuted = $false
  Passed = $false
}
try {
  foreach ($taskSample in $taskSamples) {
    $taskStdout = Join-Path $Output ($taskSample.Name + '.die.json')
    $taskStderr = Join-Path $Output ($taskSample.Name + '.stderr.txt')
    $taskStarted = [DateTime]::UtcNow
    $taskProcess = Start-Process -FilePath $Command -ArgumentList @('--json', ('"' + $taskSample.Path + '"')) -WindowStyle Hidden -Wait -PassThru -RedirectStandardOutput $taskStdout -RedirectStandardError $taskStderr
    $taskAfterHash = (Get-FileHash -LiteralPath $taskSample.Path -Algorithm SHA256).Hash.ToLowerInvariant()
    $taskObserved = Get-Content -LiteralPath $taskStdout -Raw -Encoding utf8 | ConvertFrom-Json
    $taskRow = [ordered]@{
      Name = $taskSample.Name
      SourcePath = $taskSample.Path
      SourceSha256 = $taskSample.Sha256
      AfterSha256 = $taskAfterHash
      ExitCode = $taskProcess.ExitCode
      StartedUtc = $taskStarted.ToString('o')
      ElapsedSeconds = ([DateTime]::UtcNow - $taskStarted).TotalSeconds
      Observations = $taskObserved
      StderrFile = $taskStderr
    }
    $taskManifest.Results += $taskRow
    $taskManifest | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath (Join-Path $Output 'manifest.json') -Encoding utf8
    if ($taskProcess.ExitCode -ne 0 -or $taskAfterHash -ne $taskSample.Sha256) { throw "Inspection failed or input changed: $($taskSample.Name)" }
    [pscustomobject]@{ Name = $taskSample.Name; Exit = $taskProcess.ExitCode; ElapsedSeconds = $taskRow.ElapsedSeconds } | ConvertTo-Json -Compress
  }
  $taskManifest.Passed = $true
} finally {
  $taskManifest | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath (Join-Path $Output 'manifest.json') -Encoding utf8
}

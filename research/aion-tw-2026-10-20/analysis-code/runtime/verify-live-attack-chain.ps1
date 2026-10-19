[CmdletBinding()]
param([string]$OutputName='attack-context-readonly.json')
$ErrorActionPreference='Stop'
if($OutputName -notmatch '^[a-z0-9-]+\.json$'){throw 'Output must be a simple experiment filename.'}
$root=$PSScriptRoot
$identity=Get-Content -Raw -LiteralPath (Join-Path $root 'process-modules.json')|ConvertFrom-Json
$expectedStart=if($identity.StartedUtc -is [DateTime]){$identity.StartedUtc.ToUniversalTime()}else{[DateTime]::Parse($identity.StartedUtc).ToUniversalTime()}
$targetProcess=Get-Process -Id $identity.Pid -ErrorAction Stop
if($targetProcess.Path -ine $identity.Executable -or $targetProcess.StartTime.ToUniversalTime() -ne $expectedStart){throw 'Game process identity changed.'}
$modules=@($targetProcess.Modules)
$game=@($modules|Where-Object {$_.ModuleName -ieq 'Game.dll'})
if($game.Count -ne 1){throw 'Game.dll identity unavailable.'}
$moduleHash=(Get-FileHash -LiteralPath $game[0].FileName -Algorithm SHA256).Hash.ToLowerInvariant()
if($moduleHash -ne 'b3043f0eaf225b3dc7ba320ac7671cc5b28cefbd637135943dc9e67c114ccae7'){throw 'Unexpected Game.dll version.'}
[UInt64]$moduleBase=$game[0].BaseAddress.ToInt64()
if(-not ('TwReadOnlyProcess' -as [type])){Add-Type -Path (Join-Path $root 'ReadOnlyProcess.cs')}
$reader=$null;$reads=[System.Collections.Generic.List[object]]::new();$nodes=[System.Collections.Generic.List[object]]::new()
$record=[ordered]@{Method='Auxiliary bounded read-only traversal of the map layout observed through REA 0x1808CA320/0x18069A810';Pid=$identity.Pid;StartedUtc=$expectedStart.ToString('o');CapturedAtUtc=[DateTime]::UtcNow.ToString('o');ModuleBase=('0x{0:x}'-f $moduleBase);GameSHA256=$moduleHash;MemoryWritten=$false;RemoteFunctionsInvoked=$false;FoundExactKey=$false;Candidate=$null;GetEntityMethodPointer=$null;Failure=$null;HandleClosed=$false}
function Read-Field([UInt64]$address,[int]$length,[string]$role){
 if($address -lt 0x10000){throw 'Null or low candidate pointer; stopping traversal.'}
 $result=$reader.Read($address,$length)
 $reads.Add([ordered]@{Address=('0x{0:x}'-f $address);Role=$role;Requested=$length;BytesRead=$result.BytesRead;Success=$result.Success;Win32Error=$result.Win32Error;Hex=([BitConverter]::ToString($result.Bytes).Replace('-','').ToLowerInvariant())})
 if(-not $result.Success){throw ('Read failed, Win32Error='+$result.Win32Error+', role='+$role)}
 return ,$result.Bytes
}
try{
 $reader=[TwReadOnlyProcess]::new($identity.Pid,$identity.Executable,$expectedStart.ToFileTimeUtc())
 $spec=Get-Content -Raw -LiteralPath (Join-Path $root 'effective-speed-followup/original-critical-bytes.json')|ConvertFrom-Json
 $checks=[System.Collections.Generic.List[object]]::new()
 foreach($row in $spec.observations){
  [UInt64]$rva=[Convert]::ToUInt64($row.rva.Substring(2),16)
  $expected=[string]$row.bytes
  if($row.role -eq 'Player tick slot'){$expected=[BitConverter]::ToString([BitConverter]::GetBytes([UInt64]($moduleBase+0x1652A0))).Replace('-','').ToLowerInvariant()}
  $bytes=Read-Field ($moduleBase+$rva) ($expected.Length/2) $row.role
  $actual=[BitConverter]::ToString($bytes).Replace('-','').ToLowerInvariant()
  $checks.Add([ordered]@{Role=$row.role;RVA=$row.rva;ExpectedRuntimeHex=$expected;ActualRuntimeHex=$actual;Matched=($actual -eq $expected)})
 }
 $record.Checks=@($checks.ToArray());$record.AllCriticalBytesMatched=(@($checks|Where-Object {-not $_.Matched}).Count -eq 0)
 $record.Method='Auxiliary read-only live bytes versus original PE bytes for REA-traced virtual tick/controller/gate chain; vtable pointer translated to loaded base'
}catch{$record.Failure=[ordered]@{Type=$_.Exception.GetType().FullName;Message=$_.Exception.Message}}
finally{
 if($null -ne $reader){$reader.Dispose();$record.HandleClosed=$true}
 $record.Reads=@($reads.ToArray())
 $record|ConvertTo-Json -Depth 8|Set-Content -LiteralPath (Join-Path $root 'effective-speed-followup/live-critical-byte-verification.json') -Encoding UTF8
}
[pscustomobject]$record|Select-Object AllCriticalBytesMatched,Failure,HandleClosed|ConvertTo-Json

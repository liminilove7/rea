[CmdletBinding()]
param([string]$OutputName='before-food-status-readonly.json',[string]$ContextName='before-food-character-readonly.json')
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
 $context=Get-Content -Raw -LiteralPath (Join-Path $root $ContextName)|ConvertFrom-Json
 if(-not $context.IdentityReadbackMatched -or $null -ne $context.Failure){throw 'Context is not verified'}
 [UInt64]$component=[Convert]::ToUInt64($context.Character.C.Substring(2),16)
 [UInt64]$entity=[Convert]::ToUInt64($context.Character.Entity.Substring(2),16)
 $reader=[TwReadOnlyProcess]::new($identity.Pid,$identity.Executable,$expectedStart.ToFileTimeUtc())
 $back=Read-Field ($entity+0x380) 8 'current entity container pointer'
 if([BitConverter]::ToUInt64($back,0) -ne $component){throw 'Role context changed'}
 $data=[byte[]]::new(216)
 for($offset=0;$offset -lt 216;$offset+=64){
  $length=[Math]::Min(64,216-$offset)
  $bytes=Read-Field ($moduleBase+0x142DAD0+[UInt64]$offset) $length 'received status block chunk; exact meanings only where independently traced'
  [Array]::Copy($bytes,0,$data,$offset,$length)
 }
 $snapshotOverride=Read-Field ($component+0x1354) 4 'raw member used to overwrite UI snapshot +0x40 after clamp-to-nonnegative'
 $backAgain=Read-Field ($entity+0x380) 8 'entity container pointer readback'
 if([BitConverter]::ToUInt64($backAgain,0) -ne $component){throw 'Role changed during snapshot'}
 $record.Method='Auxiliary read-only status snapshot for food comparison; REA stat snapshot copy at RVA6D70B4 and UI HP/MP consumers at RVA530650'
 $record.Component=$context.Character.C
 $record.StatusBlock=[ordered]@{RVA='0x142DAD0';Bytes=216;Hex=[BitConverter]::ToString($data).Replace('-','').ToLowerInvariant();HPPanelCandidateRaw=[BitConverter]::ToUInt32($data,0x3C);MPPanelCandidateRaw=[BitConverter]::ToUInt32($data,0x44);Snapshot40StatusRaw=[BitConverter]::ToUInt32($data,0x40);Snapshot40OverrideRaw=[BitConverter]::ToInt32($snapshotOverride,0);Snapshot40OverrideNonnegative=[Math]::Max(0,[BitConverter]::ToInt32($snapshotOverride,0));Interpretation='HP offset 0x3C and MP offset 0x44 follow static UI consumers; snapshot+0x40 overwrite is retained without assigning it to MP; game panel has not yet been supplied for this food baseline. PVP defense mapping unverified.'}
}catch{$record.Failure=[ordered]@{Type=$_.Exception.GetType().FullName;Message=$_.Exception.Message}}
finally{
 if($null -ne $reader){$reader.Dispose();$record.HandleClosed=$true}
 $record.Reads=@($reads.ToArray())
 $record|ConvertTo-Json -Depth 8|Set-Content -LiteralPath (Join-Path $root $OutputName) -Encoding UTF8
}
[pscustomobject]$record|Select-Object Component,StatusBlock,Failure,HandleClosed|ConvertTo-Json -Depth 5

[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
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
 $engine=@($modules|Where-Object {$_.ModuleName -ieq 'CryEntitySystem.dll'})
 if($engine.Count -ne 1 -or (Get-FileHash -LiteralPath $engine[0].FileName -Algorithm SHA256).Hash.ToLowerInvariant() -ne 'fbca87e5a639551bf7653d464e2863c49800e73c124ae4666ea9fb11d40bef7a'){throw 'Engine version mismatch'}
 $reader=[TwReadOnlyProcess]::new($identity.Pid,$identity.Executable,$expectedStart.ToFileTimeUtc())
 $localHandleBytes=Read-Field ($moduleBase+0x1422648) 2 'local actor handle'
 [UInt16]$actorHandle=[BitConverter]::ToUInt16($localHandleBytes,0)
 $managerBytes=Read-Field ($moduleBase+0xF25C68) 8 'entity manager'
 [UInt64]$manager=[BitConverter]::ToUInt64($managerBytes,0)
 $sentinelBytes=Read-Field ($manager+0x58) 8 'engine handle map sentinel pointer per REA 0x180045f73'
 [UInt64]$head=[BitConverter]::ToUInt64($sentinelBytes,0)
 $headRaw=Read-Field $head 48 'engine handle map head'
 if($headRaw[25] -ne 1){throw 'Unexpected sentinel producer layout'}
 [UInt64]$current=[BitConverter]::ToUInt64($headRaw,8);[UInt64]$lower=$head
 $visited=[System.Collections.Generic.HashSet[UInt64]]::new();$selected=$null
 for($depth=0;$depth -lt 32;$depth++){
  if(-not $visited.Add($current)){throw 'Repeated engine map node'}
  $raw=Read-Field $current 48 'engine handle map node'
  if($raw[25] -ne 0){break}
  [UInt16]$key=[BitConverter]::ToUInt16($raw,32)
  $node=[ordered]@{Address=('0x{0:x}'-f $current);Key=$key;Entity=('0x{0:x}'-f [BitConverter]::ToUInt64($raw,40))}
  $nodes.Add($node)
  if($key -ge $actorHandle){$lower=$current;$selected=$node;$current=[BitConverter]::ToUInt64($raw,0)}else{$current=[BitConverter]::ToUInt64($raw,16)}
  if($depth -eq 31){throw 'Engine traversal limit exhausted'}
 }
 if($lower -eq $head -or $null -eq $selected -or $selected.Key -ne $actorHandle){throw 'No exact entity handle, fallback code is intentionally not invoked'}
 $record.FoundExactKey=$true;$record.Candidate=$selected
 $entryConfirm=Read-Field $lower 48 'engine exact entry readback'
 if([BitConverter]::ToUInt16($entryConfirm,32) -ne $actorHandle -or ('0x{0:x}'-f [BitConverter]::ToUInt64($entryConfirm,40)) -ne $selected.Entity){throw 'Entity mapping changed during sample'}
 [UInt64]$entity=[Convert]::ToUInt64($selected.Entity.Substring(2),16)
 $vbytes=Read-Field $entity 8 'entity vtable'
 [UInt64]$vtable=[BitConverter]::ToUInt64($vbytes,0)
 $slotBytes=Read-Field ($vtable+0xC0) 8 'component-container getter slot, no invocation'
 [UInt64]$method=[BitConverter]::ToUInt64($slotBytes,0)
 $owner=@($modules|Where-Object {$method -ge [UInt64]$_.BaseAddress.ToInt64() -and $method -lt ([UInt64]$_.BaseAddress.ToInt64()+[UInt64]$_.ModuleMemorySize)})
 $record.ContainerGetter=[ordered]@{Entity=$selected.Entity;Vtable=('0x{0:x}'-f $vtable);Address=('0x{0:x}'-f $method);Module=if($owner.Count -eq 1){$owner[0].ModuleName}else{$null};RVA=if($owner.Count -eq 1){('0x{0:x}'-f ($method-[UInt64]$owner[0].BaseAddress.ToInt64()))}else{$null}}
 $record.Method='Auxiliary read-only reproduction of REA CryEntitySystem.dll 0x180045f60 direct-map hit; no game function call and no counter increment'
}catch{$record.Failure=[ordered]@{Type=$_.Exception.GetType().FullName;Message=$_.Exception.Message}}
finally{
 if($null -ne $reader){$reader.Dispose();$record.HandleClosed=$true}
 $record.Reads=@($reads.ToArray());$record.Nodes=@($nodes.ToArray())
 $record|ConvertTo-Json -Depth 8|Set-Content -LiteralPath (Join-Path $root 'entity-pointer-readonly.json') -Encoding UTF8
}
[pscustomobject]$record|Select-Object Pid,FoundExactKey,Candidate,ContainerGetter,Failure,HandleClosed|ConvertTo-Json -Depth 6

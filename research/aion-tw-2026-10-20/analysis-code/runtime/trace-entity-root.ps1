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
 $reader=[TwReadOnlyProcess]::new($identity.Pid,$identity.Executable,$expectedStart.ToFileTimeUtc())
 $idBytes=Read-Field ($moduleBase+0x1416C00) 4 'S_STATUS object ID'
 $objectId=[BitConverter]::ToUInt32($idBytes,0)
 $headBytes=Read-Field ($moduleBase+0x14225F0) 8 'entity map sentinel pointer'
 [UInt64]$head=[BitConverter]::ToUInt64($headBytes,0)
 $headNode=Read-Field $head 40 'map head including root and nil flag'
 if($headNode[25] -ne 1){throw 'Map head nil flag differs from expected producer layout.'}
 [UInt64]$current=[BitConverter]::ToUInt64($headNode,8);[UInt64]$lower=$head
 $visited=[System.Collections.Generic.HashSet[UInt64]]::new();$selected=$null
 for($depth=0;$depth -lt 32;$depth++){
  if(-not $visited.Add($current)){throw 'Repeated node while traversing live map; no stable result claimed.'}
  $raw=Read-Field $current 40 'entity-map node'
  if($raw[25] -ne 0){break}
  $key=[BitConverter]::ToUInt32($raw,28)
  $node=[ordered]@{Address=('0x{0:x}'-f $current);Key=$key;Handle=[BitConverter]::ToUInt16($raw,32);Left=('0x{0:x}'-f [BitConverter]::ToUInt64($raw,0));Right=('0x{0:x}'-f [BitConverter]::ToUInt64($raw,16))}
  $nodes.Add($node)
  if($key -ge $objectId){$lower=$current;$selected=$node;$current=[BitConverter]::ToUInt64($raw,0)}else{$current=[BitConverter]::ToUInt64($raw,16)}
  if($depth -eq 31){throw 'Bounded traversal exhausted; map was not proven complete.'}
 }
 $record.ObjectId=$objectId
 if($lower -ne $head -and $null -ne $selected -and $selected.Key -eq $objectId){
  $confirm=Read-Field $lower 40 'selected entry readback'
  $againId=Read-Field ($moduleBase+0x1416C00) 4 'object ID readback'
  $record.FoundExactKey=($confirm[25] -eq 0 -and [BitConverter]::ToUInt32($confirm,28) -eq $objectId -and [BitConverter]::ToUInt16($confirm,32) -eq $selected.Handle -and [BitConverter]::ToUInt32($againId,0) -eq $objectId)
  $record.Candidate=$selected
 }
 $managerBytes=Read-Field ($moduleBase+0xF25C68) 8 'entity system pointer'
 [UInt64]$manager=[BitConverter]::ToUInt64($managerBytes,0)
 $vtBytes=Read-Field $manager 8 'entity system vtable pointer'
 [UInt64]$vt=[BitConverter]::ToUInt64($vtBytes,0)
 $methodBytes=Read-Field ($vt+0x30) 8 'GetEntity slot pointer, no invocation'
 [UInt64]$method=[BitConverter]::ToUInt64($methodBytes,0)
 $owner=@($modules|Where-Object {$method -ge [UInt64]$_.BaseAddress.ToInt64() -and $method -lt ([UInt64]$_.BaseAddress.ToInt64()+[UInt64]$_.ModuleMemorySize)})
 $record.GetEntityMethodPointer=[ordered]@{Manager=('0x{0:x}'-f $manager);Vtable=('0x{0:x}'-f $vt);Slot='0x30';Address=('0x{0:x}'-f $method);Module=if($owner.Count -eq 1){$owner[0].ModuleName}else{$null};ModulePath=if($owner.Count -eq 1){$owner[0].FileName}else{$null};ModuleBase=if($owner.Count -eq 1){('0x{0:x}'-f $owner[0].BaseAddress.ToInt64())}else{$null};RVA=if($owner.Count -eq 1){('0x{0:x}'-f ($method-[UInt64]$owner[0].BaseAddress.ToInt64()))}else{$null}}
}catch{$record.Failure=[ordered]@{Type=$_.Exception.GetType().FullName;Message=$_.Exception.Message}}
finally{
 if($null -ne $reader){$reader.Dispose();$record.HandleClosed=$true}
 $record.Reads=@($reads.ToArray());$record.Nodes=@($nodes.ToArray())
 $record|ConvertTo-Json -Depth 8|Set-Content -LiteralPath (Join-Path $root 'entity-root-readonly.json') -Encoding UTF8
}
[pscustomobject]$record|Select-Object Pid,FoundExactKey,Candidate,GetEntityMethodPointer,Failure,HandleClosed|ConvertTo-Json -Depth 6

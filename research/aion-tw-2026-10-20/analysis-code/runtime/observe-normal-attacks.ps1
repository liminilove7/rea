[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
$root=$PSScriptRoot
$output=Join-Path $root 'normal-attack-baseline.json'
if(Test-Path -LiteralPath $output){throw 'Baseline record already exists; refusing overwrite'}
$context=Get-Content -Raw -LiteralPath (Join-Path $root 'combat-baseline-context.json')|ConvertFrom-Json
$identity=Get-Content -Raw -LiteralPath (Join-Path $root 'process-modules.json')|ConvertFrom-Json
$birth=if($identity.StartedUtc -is [DateTime]){$identity.StartedUtc.ToUniversalTime()}else{[DateTime]::Parse($identity.StartedUtc).ToUniversalTime()}
$process=Get-Process -Id $identity.Pid -ErrorAction Stop
if($process.Path -ine $identity.Executable -or $process.StartTime.ToUniversalTime() -ne $birth){throw 'Game process identity mismatch'}
if(-not $context.IdentityReadbackMatched -or $null -ne $context.Failure){throw 'Character context not verified'}
$module=@($process.Modules|Where-Object {$_.ModuleName -ieq 'Game.dll'})
$hash='b3043f0eaf225b3dc7ba320ac7671cc5b28cefbd637135943dc9e67c114ccae7'
if($module.Count -ne 1 -or (Get-FileHash -LiteralPath $module[0].FileName -Algorithm SHA256).Hash.ToLowerInvariant() -ne $hash){throw 'Module version mismatch'}
[UInt64]$base=$module[0].BaseAddress.ToInt64()
if(('0x{0:x}'-f $base) -ne $context.ModuleBase){throw 'Module base changed'}
[UInt64]$component=[Convert]::ToUInt64($context.Character.C.Substring(2),16)
[UInt64]$entity=[Convert]::ToUInt64($context.Character.Entity.Substring(2),16)
[UInt64]$vtable=[Convert]::ToUInt64($context.Character.Vtable.Substring(2),16)
if(-not ('TwReadOnlyProcess' -as [type])){Add-Type -Path (Join-Path $root 'ReadOnlyProcess.cs')}
$reader=$null;$events=[System.Collections.Generic.List[object]]::new();$heartbeats=[System.Collections.Generic.List[object]]::new()
$record=[ordered]@{Method='Auxiliary Win32 bounded read-only observation of the REA-traced request-timing state; not packet capture';Pid=$identity.Pid;StartedUtc=$birth.ToString('o');GameSHA256=$hash;ModuleBase=$context.ModuleBase;Component=$context.Character.C;TimingAddress=$context.AttackContext.TimingAddress;DurationSeconds=45;RequestedSampleMilliseconds=100;CreatedUtc=[DateTime]::UtcNow.ToString('o');MemoryWritten=$false;RemoteFunctionsInvoked=$false;AtomicSnapshot=$false;TimingUnit='Not established';Failure=$null;HandleClosed=$false;Samples=0;Initial=$null;Final=$null}
function Read-Bytes([UInt64]$address,[int]$size){
 $raw=$reader.Read($address,$size)
 if(-not $raw.Success){throw ('Read failed, address 0x{0:x}, Win32 {1}'-f $address,$raw.Win32Error)}
 return ,$raw.Bytes
}
function Read-Observation([double]$elapsed){
 $state=Read-Bytes ($component+0x1E90) 4
 $global=Read-Bytes ($base+0x142DB40) 2
 $mirror=Read-Bytes ($base+0x142DC10) 4
 $animation=Read-Bytes ($component+0x530) 4
 return [ordered]@{ElapsedSeconds=[Math]::Round($elapsed,6);AtUtc=[DateTime]::UtcNow.ToString('o');TimingValue=[BitConverter]::ToUInt32($state,0);Interval=[BitConverter]::ToUInt16($global,0);Mirror=[BitConverter]::ToUInt32($mirror,0);U=[BitConverter]::ToUInt16($animation,0);V=[BitConverter]::ToUInt16($animation,2)}
}
function Check-Role {
 $liveVT=Read-Bytes $component 8
 $link=Read-Bytes ($component+8) 8
 $tick=Read-Bytes ($vtable+8) 8
 $container=Read-Bytes ($entity+0x380) 8
 $handle=Read-Bytes ($base+0x1422648) 2
 if([BitConverter]::ToUInt64($liveVT,0) -ne $vtable -or [BitConverter]::ToUInt64($link,0) -ne $entity -or [BitConverter]::ToUInt64($tick,0) -ne $base+0x1652A0 -or [BitConverter]::ToUInt64($container,0) -ne $component -or [BitConverter]::ToUInt16($handle,0) -ne 65535){throw 'Current role/pointer identity changed; stopping observation'}
}
try{
 $reader=[TwReadOnlyProcess]::new($identity.Pid,$identity.Executable,$birth.ToFileTimeUtc())
 Check-Role
 $record.Initial=Read-Observation 0
 $previous=$record.Initial
 $timer=[Diagnostics.Stopwatch]::StartNew();$nextIdentity=1.0;$nextProgress=5.0
 Write-Output (@{Phase='Recording';DurationSeconds=45;Instruction='Use normal attacks now; no skill activation or equipment changes';MemoryWritten=$false}|ConvertTo-Json -Compress)
 while($timer.Elapsed.TotalSeconds -lt 45){
  $elapsed=$timer.Elapsed.TotalSeconds
  if($elapsed -ge $nextIdentity){Check-Role;$nextIdentity=$elapsed+1}
  $row=Read-Observation $elapsed
  $record.Samples++
  if($row.TimingValue -ne $previous.TimingValue){
   $delta=([Int64]$row.TimingValue-[Int64]$previous.TimingValue+4294967296L)%4294967296L
   $row.ObservedTickDelta=$delta
   $row.SecondsSincePreviousObservedChange=[Math]::Round($elapsed-[double]$previous.ElapsedSeconds,6)
   $events.Add($row);$previous=$row
  }
  if($elapsed -ge $nextProgress){$heartbeats.Add($row);Write-Output (@{ElapsedSeconds=[Math]::Round($elapsed,1);TimingChanges=$events.Count;Interval=$row.Interval;U=$row.U;V=$row.V}|ConvertTo-Json -Compress);$nextProgress=$elapsed+5}
  Start-Sleep -Milliseconds 100
 }
 Check-Role
 $record.Final=Read-Observation $timer.Elapsed.TotalSeconds
}catch{$record.Failure=[ordered]@{Type=$_.Exception.GetType().FullName;Message=$_.Exception.Message}}
finally{
 if($null -ne $reader){$reader.Dispose();$record.HandleClosed=$true}
 $record.Events=@($events.ToArray());$record.Heartbeats=@($heartbeats.ToArray());$record.CompletedUtc=[DateTime]::UtcNow.ToString('o')
 $record|ConvertTo-Json -Depth 8|Set-Content -LiteralPath $output -Encoding UTF8
 Write-Output (@{Phase='Completed';Samples=$record.Samples;ObservedChanges=$events.Count;Failure=$record.Failure;HandleClosed=$record.HandleClosed}|ConvertTo-Json -Compress)
}

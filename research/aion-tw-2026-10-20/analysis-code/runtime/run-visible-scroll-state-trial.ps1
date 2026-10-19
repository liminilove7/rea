[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
$root=$PSScriptRoot
$output=Join-Path $root 'visible-scroll-state-trial-state.json'
if(Test-Path -LiteralPath $output){throw 'Baseline record already exists; refusing overwrite'}
$context=Get-Content -Raw -LiteralPath (Join-Path $root 'before-visible-scroll-state-context.json')|ConvertFrom-Json
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
if(-not ('TwVisibleScrollStateProcess' -as [type])){Add-Type -Path (Join-Path $root 'VisibleScrollStateTrialProcess.cs')}
$attempted=$false;$reader=$null;$events=[System.Collections.Generic.List[object]]::new();$heartbeats=[System.Collections.Generic.List[object]]::new()
$record=[ordered]@{Method='Auxiliary bounded 1200-to-800 three-field trial inspired by normal scroll changes; not a server buff or packet capture';Pid=$identity.Pid;StartedUtc=$birth.ToString('o');GameSHA256=$hash;ModuleBase=$context.ModuleBase;Component=$context.Character.C;TimingAddress=$context.AttackContext.TimingAddress;DurationSeconds=60;RequestedSampleMilliseconds=100;CreatedUtc=[DateTime]::UtcNow.ToString('o');MemoryWritten=$false;RemoteFunctionsInvoked=$false;AtomicSnapshot=$false;TimingUnit='Not established';Failure=$null;HandleClosed=$false;Samples=0;Initial=$null;Final=$null}
$record.OriginalTuple=@(1200,1200,1200);$record.TestTuple=@(800,800,800);$record.Apply=$null;$record.Restoration=$null;$record.RestoreStatus='NotNeeded';$record.PreservedByWriter='Animation U, scale, movement, active buff list, packet flags and executable/protection code';$record.UserReportedLevel='Not reverified after prior level5 report';$record.Fields=@('B+0x142DB40 uint16','B+0x142DC10 uint32','C+0x532 uint16')
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
function Check-Inputs {
 Check-Role
 $ib=Read-Bytes ($base+0x142DB40) 2
 $mb=Read-Bytes ($base+0x142DC10) 4
 $vb=Read-Bytes ($component+0x532) 2
 $sb=Read-Bytes ($component+0x51C) 4
 $ub=Read-Bytes ($component+0x530) 2
 if([BitConverter]::ToUInt16($ub,0) -ne 1200 -or [BitConverter]::ToSingle($sb,0) -ne 1.0){throw 'U or scale changed; stop trial'}
}
try{
 $reader=[TwVisibleScrollStateProcess]::new($identity.Pid,$identity.Executable,$birth.ToFileTimeUtc(),$base,$component)
 Check-Role
 Check-Inputs
 $record.Initial=Read-Observation 0
 if($record.Initial.U -ne 1200 -or $record.Initial.V -ne 1200 -or $record.Initial.Interval -ne 1200 -or $record.Initial.Mirror -ne 1200){throw 'Unbuffed baseline tuple not present'}
 $record|ConvertTo-Json -Depth 8|Set-Content -LiteralPath $output -Encoding UTF8
 $attempted=$true
 $record.Apply=$reader.ApplyState()
 $record.MemoryWritten=$reader.HasWriteAttempted
 $record.AppliedUtc=[DateTime]::UtcNow.ToString('o')
 $record|ConvertTo-Json -Depth 8|Set-Content -LiteralPath $output -Encoding UTF8
 if(-not $record.Apply.Success){throw 'Scroll-state tuple application incomplete'}
 $previous=$record.Initial
 $timer=[Diagnostics.Stopwatch]::StartNew();$nextIdentity=1.0;$nextProgress=5.0
 Write-Output (@{Phase='Applied';DurationSeconds=60;Component=$context.Character.C;Interval=800;Mirror=800;U=1200;V=800;ExpectedAuditedBranchRatio=(1200.0/800.0);Instruction='Use normal attacks now; no skill activation or equipment changes';MemoryWritten=$true}|ConvertTo-Json -Compress)
 while($timer.Elapsed.TotalSeconds -lt 60){
  $elapsed=$timer.Elapsed.TotalSeconds
  if($elapsed -ge $nextIdentity){Check-Inputs;$nextIdentity=$elapsed+1}
  $row=Read-Observation $elapsed
  $record.Samples++
  if($row.U -ne 1200 -or $row.V -ne 800 -or $row.Interval -ne 800 -or $row.Mirror -ne 800){$record.EarlyExitReason='Tuple changed externally; no reapplication';break}
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
 if($null -ne $reader){
  if($reader.HasWriteAttempted){
   try{
    $liveProcess=Get-Process -Id $identity.Pid -ErrorAction Stop
    if($liveProcess.Path -ine $identity.Executable -or $liveProcess.StartTime.ToUniversalTime() -ne $birth){throw 'Process identity changed'}
    $liveModule=@($liveProcess.Modules|Where-Object {$_.ModuleName -ieq 'Game.dll'})
    if($liveModule.Count -ne 1 -or [UInt64]$liveModule[0].BaseAddress.ToInt64() -ne $base -or (Get-FileHash -LiteralPath $liveModule[0].FileName -Algorithm SHA256).Hash.ToLowerInvariant() -ne $hash){throw 'Module identity changed'}
    Check-Inputs
    $record.Restoration=$reader.RestoreState()
    $record.RestoreStatus=if($record.Restoration.Success){'RestoredOriginalTupleAndReadBack'}else{'RestoreFailedOrExternalValuesPreserved'}
   }catch{$record.RestoreStatus='ContextChangedNoWrite';$record.RestoreFailure=$_.Exception.Message}
  }
  $reader.Dispose();$record.HandleClosed=$true
 }
 $record.Events=@($events.ToArray());$record.Heartbeats=@($heartbeats.ToArray());$record.CompletedUtc=[DateTime]::UtcNow.ToString('o')
 $record|ConvertTo-Json -Depth 8|Set-Content -LiteralPath $output -Encoding UTF8
 Write-Output (@{Phase='Completed';RestoreStatus=$record.RestoreStatus;Samples=$record.Samples;ObservedChanges=$events.Count;Failure=$record.Failure;HandleClosed=$record.HandleClosed}|ConvertTo-Json -Compress)
}

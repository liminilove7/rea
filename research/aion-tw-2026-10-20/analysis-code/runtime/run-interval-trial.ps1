[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
$root=$PSScriptRoot
$statePath=Join-Path $root 'interval-trial-state.json'
if(Test-Path -LiteralPath $statePath){throw 'This one-time trial already has a state record; refusing to repeat it.'}
$identity=Get-Content -Raw -LiteralPath (Join-Path $root 'process-modules.json')|ConvertFrom-Json
$birth=if($identity.StartedUtc -is [DateTime]){$identity.StartedUtc.ToUniversalTime()}else{[DateTime]::Parse($identity.StartedUtc).ToUniversalTime()}
$expectedHash='b3043f0eaf225b3dc7ba320ac7671cc5b28cefbd637135943dc9e67c114ccae7'
$targetProcess=Get-Process -Id $identity.Pid -ErrorAction Stop
if($targetProcess.Path -ine $identity.Executable -or $targetProcess.StartTime.ToUniversalTime() -ne $birth){throw 'Game identity changed'}
$module=@($targetProcess.Modules|Where-Object {$_.ModuleName -ieq 'Game.dll'})
if($module.Count -ne 1 -or (Get-FileHash -LiteralPath $module[0].FileName -Algorithm SHA256).Hash.ToLowerInvariant() -ne $expectedHash){throw 'Game.dll version mismatch'}
[UInt64]$base=$module[0].BaseAddress.ToInt64()
[UInt64]$address=$base+0x142DB40
Add-Type -Path (Join-Path $root 'IntervalTrialProcess.cs')
$reader=$null;$attempted=$false
$samples=[System.Collections.Generic.List[object]]::new()
$record=[ordered]@{Method='Auxiliary Win32 single-field temporary write; REA established field semantics but is not the runtime writer';Pid=$identity.Pid;StartedUtc=$birth.ToString('o');ModulePath=$module[0].FileName;ModuleBase=('0x{0:x}'-f $base);GameSHA256=$expectedHash;RVA='0x142DB40';Address=('0x{0:x}'-f $address);Original=1200;TestValue=1100;MaximumSeconds=60;AccessMask='0x1038';WriteAttempts=0;Apply=$null;Restoration=$null;RestoreStatus='NotNeeded';Failure=$null;HandleClosed=$false;PreservedFields='No writes to interval mirror, animation U/V, movement, code bytes, packet flags or protection state';AtomicWriteGuard=$false;UserReportedNonCombat=$true;CreatedUtc=[DateTime]::UtcNow.ToString('o')}
function Save-State {
 $record.Samples=@($samples.ToArray())
 $record|ConvertTo-Json -Depth 9|Set-Content -LiteralPath $statePath -Encoding UTF8
}
function Read-U16([UInt64]$where){
 $raw=$reader.Read($where,2)
 if(-not $raw.Success){throw ('Read failed at 0x{0:x}, Win32 {1}' -f $where,$raw.Win32Error)}
 return [BitConverter]::ToUInt16($raw.Bytes,0)
}
function Check-Module {
 $live=Get-Process -Id $identity.Pid -ErrorAction Stop
 if($live.Path -ine $identity.Executable -or $live.StartTime.ToUniversalTime() -ne $birth){throw 'Process identity no longer matches'}
 $liveModule=@($live.Modules|Where-Object {$_.ModuleName -ieq 'Game.dll'})
 if($liveModule.Count -ne 1 -or [UInt64]$liveModule[0].BaseAddress.ToInt64() -ne $base -or $liveModule[0].FileName -ine $record.ModulePath -or (Get-FileHash -LiteralPath $liveModule[0].FileName -Algorithm SHA256).Hash.ToLowerInvariant() -ne $expectedHash){throw 'Module identity no longer matches; no write authorized at old address'}
}
try {
 $reader=[TwIntervalTrialProcess]::new($identity.Pid,$identity.Executable,$birth.ToFileTimeUtc(),$address)
 $header=$reader.Read($base,2)
 if(-not $header.Success -or [BitConverter]::ToUInt16($header.Bytes,0) -ne 0x5A4D){throw 'Module header mismatch'}
 if((Read-U16 $address) -ne 1200 -or (Read-U16 ($base+0x142DC10)) -ne 1200 -or (Read-U16 ($base+0x1422648)) -ne 65535){throw 'Expected equipped-weapon baseline no longer present'}
 Save-State
 $attempted=$true;$record.WriteAttempts=1
 $record.Apply=$reader.ChangeInterval(1200,1100)
 $record.AppliedUtc=[DateTime]::UtcNow.ToString('o')
 Save-State
 if(-not $record.Apply.Success){throw 'Test write/readback did not establish 1100'}
 Write-Output (@{Phase='Applied';Address=$record.Address;Original=1200;Readback=1100;MaximumSeconds=60;Instruction='Remain out of combat; observe panel only.'}|ConvertTo-Json -Compress)
 $timer=[Diagnostics.Stopwatch]::StartNew()
 foreach($due in @(0,5,15,30,45,60)){
  while($timer.Elapsed.TotalSeconds -lt $due){Start-Sleep -Milliseconds 200}
  Check-Module
  $current=Read-U16 $address
  $row=[ordered]@{ElapsedSeconds=[Math]::Round($timer.Elapsed.TotalSeconds,3);AtUtc=[DateTime]::UtcNow.ToString('o');Interval=$current;Mirror=Read-U16 ($base+0x142DC10)}
  $samples.Add($row);Save-State
  Write-Output ($row|ConvertTo-Json -Compress)
  if($current -ne 1100){$record.EarlyExitReason='Field changed externally; no reapplication';break}
 }
}catch{
 $record.Failure=[ordered]@{Type=$_.Exception.GetType().FullName;Message=$_.Exception.Message}
}finally{
 if($null -ne $reader){
  if($attempted){
   try {
    Check-Module
    $now=Read-U16 $address
    if($now -eq 1100){
     $record.Restoration=$reader.ChangeInterval(1100,1200)
     $record.RestoreStatus=if($record.Restoration.Success){'RestoredOriginalAndReadBack'}else{'RestoreFailed'}
    }elseif($now -eq 1200){$record.RestoreStatus='AlreadyOriginalNoWrite'}
    else{$record.RestoreStatus='ExternalValuePreservedNoWrite';$record.ExternalValueAtEnd=$now}
   }catch{$record.RestoreStatus='RestoreUnavailable';$record.RestoreFailure=$_.Exception.Message}
  }
  $reader.Dispose();$record.HandleClosed=$true
 }
 $record.CompletedUtc=[DateTime]::UtcNow.ToString('o')
 Save-State
 Write-Output ([pscustomobject]$record|Select-Object RestoreStatus,Failure,HandleClosed,CompletedUtc|ConvertTo-Json -Compress)
}

[CmdletBinding()]
param([string]$OutputName='baseline-readonly.json')
$ErrorActionPreference='Stop'
if($OutputName -notmatch '^[a-z0-9-]+\.json$'){throw 'Output must be a simple experiment filename.'}
$runtimeRoot=$PSScriptRoot
$identity=Get-Content -Raw -LiteralPath (Join-Path $runtimeRoot 'process-modules.json')|ConvertFrom-Json
$expectedStart=if($identity.StartedUtc -is [DateTime]){$identity.StartedUtc.ToUniversalTime()}else{[DateTime]::Parse($identity.StartedUtc).ToUniversalTime()}
$targetProcess=Get-Process -Id $identity.Pid -ErrorAction Stop
if($targetProcess.Path -ine $identity.Executable -or $targetProcess.StartTime.ToUniversalTime() -ne $expectedStart){throw 'Selected game process identity changed.'}
$module=@($targetProcess.Modules|Where-Object {$_.ModuleName -ieq 'Game.dll'})
if($module.Count -ne 1){throw 'Expected exactly one Game.dll module.'}
$expectedHash='b3043f0eaf225b3dc7ba320ac7671cc5b28cefbd637135943dc9e67c114ccae7'
$actualHash=(Get-FileHash -LiteralPath $module[0].FileName -Algorithm SHA256).Hash.ToLowerInvariant()
if($actualHash -ne $expectedHash){throw 'Loaded module pathname now points to a different file; preserving analysis identity.'}
[UInt64]$moduleBase=$module[0].BaseAddress.ToInt64()
$before=[ordered]@{Path=$module[0].FileName;Base=('0x{0:x}'-f $moduleBase);Bytes=$module[0].ModuleMemorySize;OnDiskSHA256=$actualHash}
if(-not ('TwReadOnlyProcess' -as [type])){Add-Type -Path (Join-Path $runtimeRoot 'ReadOnlyProcess.cs')}
$observations=[System.Collections.Generic.List[object]]::new()
$reader=$null
$record=[ordered]@{Method='Auxiliary Win32 read-only field sampling against candidates established by REA; not an REA runtime provider';Pid=$identity.Pid;StartedUtc=$expectedStart.ToString('o');CapturedAtUtc=[DateTime]::UtcNow.ToString('o');ModuleBefore=$before;AccessMask='0x1010: VM_READ and QUERY_LIMITED_INFORMATION';GameMemoryWritten=$false;RemoteCodeExecuted=$false;DebuggerAttachedByThisScript=$false;Observations=@();Failure=$null;HandleClosed=$false;ModuleAfter=$null}
try {
  $reader=[TwReadOnlyProcess]::new($identity.Pid,$identity.Executable,$expectedStart.ToFileTimeUtc())
  $items=@(
    @{Name='image_header';RVA=[UInt64]0;Length=16;Type='bytes'},
    @{Name='received_attack_interval';RVA=[UInt64]0x142DB40;Length=2;Type='uint16'},
    @{Name='attack_interval_mirror';RVA=[UInt64]0x142DC10;Length=4;Type='uint32'},
    @{Name='local_move_speed_mirror';RVA=[UInt64]0x142DC14;Length=4;Type='float32'},
    @{Name='local_and_target_handles';RVA=[UInt64]0x1422648;Length=4;Type='uint16_pair'},
    @{Name='status_object_id';RVA=[UInt64]0x1416C00;Length=4;Type='uint32'},
    @{Name='entity_system_pointer';RVA=[UInt64]0xF25C68;Length=8;Type='uint64'},
    @{Name='entity_map_sentinel_pointer';RVA=[UInt64]0x14225F0;Length=8;Type='uint64'},
    @{Name='manager_object_first_qword';RVA=[UInt64]0x1415340;Length=8;Type='uint64'}
  )
  foreach($item in $items){
    if($item.RVA+$item.Length -gt $before.Bytes){throw 'Requested field is outside the observed image range.'}
    [UInt64]$address=$moduleBase+$item.RVA
    $sample=$reader.Read($address,$item.Length)
    $value=$null
    if($sample.Success){
      switch($item.Type){
        'uint16' {$value=[BitConverter]::ToUInt16($sample.Bytes,0)}
        'uint32' {$value=[BitConverter]::ToUInt32($sample.Bytes,0)}
        'uint64' {$value=('0x{0:x}'-f [BitConverter]::ToUInt64($sample.Bytes,0))}
        'float32' {$value=[BitConverter]::ToSingle($sample.Bytes,0)}
        'uint16_pair' {$value=@([BitConverter]::ToUInt16($sample.Bytes,0),[BitConverter]::ToUInt16($sample.Bytes,2))}
      }
    }
    $observations.Add([ordered]@{Name=$item.Name;RVA=('0x{0:x}'-f $item.RVA);Address=('0x{0:x}'-f $address);Type=$item.Type;Success=$sample.Success;Win32Error=$sample.Win32Error;BytesRead=$sample.BytesRead;Hex=([BitConverter]::ToString($sample.Bytes).Replace('-','').ToLowerInvariant());Value=$value})
    if($item.Name -eq 'image_header' -and (-not $sample.Success -or $sample.Bytes[0] -ne 0x4D -or $sample.Bytes[1] -ne 0x5A)){throw 'Runtime module header could not be validated; stopped field sampling.'}
  }
}catch{
  $record.Failure=[ordered]@{Type=$_.Exception.GetType().FullName;Message=$_.Exception.Message;HResult=$_.Exception.HResult}
}finally{
  if($null -ne $reader){$reader.Dispose();$record.HandleClosed=$true}
  $record.Observations=@($observations.ToArray())
  try{
    $afterProcess=Get-Process -Id $identity.Pid -ErrorAction Stop
    if($afterProcess.StartTime.ToUniversalTime() -ne $expectedStart -or $afterProcess.Path -ine $identity.Executable){throw 'Process identity changed after sampling.'}
    $afterModule=@($afterProcess.Modules|Where-Object {$_.ModuleName -ieq 'Game.dll'})
    if($afterModule.Count -ne 1){throw 'Module disappeared after sampling.'}
    $record.ModuleAfter=[ordered]@{Path=$afterModule[0].FileName;Base=('0x{0:x}'-f $afterModule[0].BaseAddress.ToInt64());Bytes=$afterModule[0].ModuleMemorySize;MetadataMatched=($afterModule[0].FileName -ieq $before.Path -and $afterModule[0].BaseAddress.ToInt64() -eq $moduleBase -and $afterModule[0].ModuleMemorySize -eq $before.Bytes)}
  }catch{$record.ModuleAfter=[ordered]@{Error=$_.Exception.Message}}
  $record|ConvertTo-Json -Depth 8|Set-Content -LiteralPath (Join-Path $runtimeRoot $OutputName) -Encoding UTF8
}
$record|ConvertTo-Json -Depth 8

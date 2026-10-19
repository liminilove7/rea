$ErrorActionPreference='Stop'
Add-Type -Path (Join-Path $PSScriptRoot 'FastScrollStateTrialProcess.cs')
$currentProcess=Get-Process -Id $PID
$memory=[Runtime.InteropServices.Marshal]::AllocHGlobal(0xE0)
$reader=$null;$checks=[System.Collections.Generic.List[string]]::new()
try{
 [UInt64]$address=$memory.ToInt64()
 [UInt64]$fakeBase=$address-0x142DB40
 [UInt64]$fakeComponent=$address+0xD8-0x532
 [Runtime.InteropServices.Marshal]::WriteInt16($memory,1200)
 [Runtime.InteropServices.Marshal]::WriteInt32($memory,0xD0,999)
 [Runtime.InteropServices.Marshal]::WriteInt16($memory,0xD8,1200)
 $reader=[TwFastScrollStateProcess]::new($PID,$currentProcess.Path,$currentProcess.StartTime.ToUniversalTime().ToFileTimeUtc(),$fakeBase,$fakeComponent)
 $refuse=$reader.ApplyState()
 if($refuse.Success -or $reader.HasWriteAttempted -or [Runtime.InteropServices.Marshal]::ReadInt16($memory) -ne 1200){throw 'Tuple mismatch must refuse all writes'}
 $checks.Add('Baseline tuple mismatch causes no writes')
 [Runtime.InteropServices.Marshal]::WriteInt32($memory,0xD0,1200)
 $apply=$reader.ApplyState()
 if(-not $apply.Success -or $apply.Fields.Count -ne 3 -or [Runtime.InteropServices.Marshal]::ReadInt16($memory) -ne 900 -or [Runtime.InteropServices.Marshal]::ReadInt32($memory,0xD0) -ne 900 -or [Runtime.InteropServices.Marshal]::ReadInt16($memory,0xD8) -ne 900){throw 'Fixed tuple application/readback failed'}
 $checks.Add('Exact uint16/uint32/uint16 fields applied and read back')
 [Runtime.InteropServices.Marshal]::WriteInt32($memory,0xD0,999)
 $external=$reader.RestoreState()
 if($external.Success -or $external.Fields.Count -ne 0 -or [Runtime.InteropServices.Marshal]::ReadInt16($memory) -ne 900 -or [Runtime.InteropServices.Marshal]::ReadInt32($memory,0xD0) -ne 999){throw 'Unknown external state must be preserved'}
 $checks.Add('Unknown external tuple refuses restoration writes')
 [Runtime.InteropServices.Marshal]::WriteInt32($memory,0xD0,900)
 $restore=$reader.RestoreState()
 if(-not $restore.Success -or [Runtime.InteropServices.Marshal]::ReadInt16($memory) -ne 1200 -or [Runtime.InteropServices.Marshal]::ReadInt32($memory,0xD0) -ne 1200 -or [Runtime.InteropServices.Marshal]::ReadInt16($memory,0xD8) -ne 1200){throw 'Original tuple restoration failed'}
 $checks.Add('Original tuple restored and read back')
 $rejected=$false
 try{$null=$reader.ApplyState()}catch{$rejected=$true}
 if(-not $rejected){throw 'Repeated application was allowed'}
 $checks.Add('Repeated application refused')
}finally{
 if($null -ne $reader){$reader.Dispose()}
 [Runtime.InteropServices.Marshal]::FreeHGlobal($memory)
}
@{AllPassed=$true;Checks=@($checks.ToArray());Scope='Scratch allocation owned by this helper process only, no game writes'}|ConvertTo-Json|Set-Content -LiteralPath (Join-Path $PSScriptRoot 'fast-scroll-state-helper-verification.json') -Encoding UTF8
Get-Content -LiteralPath (Join-Path $PSScriptRoot 'fast-scroll-state-helper-verification.json')

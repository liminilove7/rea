$ErrorActionPreference='Stop'
Add-Type -Path (Join-Path $PSScriptRoot 'AnimationTrialProcess.cs')
$currentProcess=Get-Process -Id $PID
$memory=[Runtime.InteropServices.Marshal]::AllocHGlobal(2)
$reader=$null
$checks=[System.Collections.Generic.List[string]]::new()
try {
 [Runtime.InteropServices.Marshal]::WriteInt16($memory,1200)
 $reader=[TwAnimationTrialProcess]::new($PID,$currentProcess.Path,$currentProcess.StartTime.ToUniversalTime().ToFileTimeUtc(),[UInt64]$memory.ToInt64())
 $noWrite=$reader.ChangeAnimationU(1500,1200)
 if($noWrite.Attempted -or [Runtime.InteropServices.Marshal]::ReadInt16($memory) -ne 1200){throw 'Mismatch guard failed'}
 $checks.Add('Unexpected current value refuses write')
 $apply=$reader.ChangeAnimationU(1200,1500)
 if(-not $apply.Success -or [Runtime.InteropServices.Marshal]::ReadInt16($memory) -ne 1500){throw 'Apply/readback failed'}
 $checks.Add('Fixed two-byte transition applies and reads back')
 $restore=$reader.ChangeAnimationU(1500,1200)
 if(-not $restore.Success -or [Runtime.InteropServices.Marshal]::ReadInt16($memory) -ne 1200){throw 'Restoration failed'}
 $checks.Add('Restoration writes original two bytes')
 $rejected=$false
 try {$null=$reader.ChangeAnimationU(1200,1000)}catch{$rejected=$true}
 if(-not $rejected -or [Runtime.InteropServices.Marshal]::ReadInt16($memory) -ne 1200){throw 'Unplanned value accepted'}
 $checks.Add('Unplanned values rejected')
}finally{
 if($null -ne $reader){$reader.Dispose()}
 [Runtime.InteropServices.Marshal]::FreeHGlobal($memory)
}
@{AllPassed=$true;Checks=@($checks.ToArray());Scope='Scratch allocation in this helper process only; no game memory touched'}|ConvertTo-Json|Set-Content -LiteralPath (Join-Path $PSScriptRoot 'animation-trial-helper-verification.json') -Encoding UTF8
Get-Content -LiteralPath (Join-Path $PSScriptRoot 'animation-trial-helper-verification.json')

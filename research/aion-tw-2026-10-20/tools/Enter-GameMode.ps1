[CmdletBinding()]
param(
    [switch]$Close,
    [switch]$ForceRemaining,
    [ValidateRange(1, 60)]
    [int]$WaitSeconds = 10
)

# List matching analysis tools by default. -Close requests normal window closure.
# -ForceRemaining is intended for the user's explicit one-click cleanup request.
# Save analysis databases before using that mode.
$ErrorActionPreference = 'Stop'
if (-not ('RveProcessReadOnly' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using System.Text;
public static class RveProcessReadOnly {
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern IntPtr OpenProcess(uint access, bool inherit, int id);
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    static extern bool QueryFullProcessImageName(IntPtr process, int flags, StringBuilder name, ref int size);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern bool IsProcessCritical(IntPtr process, out bool critical);
    [DllImport("kernel32.dll")]
    static extern bool CloseHandle(IntPtr handle);
    public static string ImagePath(int id) {
        IntPtr handle = OpenProcess(0x1000, false, id);
        if (handle == IntPtr.Zero) return null;
        try {
            int size = 32768;
            var text = new StringBuilder(size);
            return QueryFullProcessImageName(handle, 0, text, ref size) ? text.ToString() : null;
        } finally { CloseHandle(handle); }
    }
    public static bool Critical(int id) {
        IntPtr handle = OpenProcess(0x1000, false, id);
        if (handle == IntPtr.Zero) return false;
        try {
            bool critical;
            return IsProcessCritical(handle, out critical) && critical;
        } finally { CloseHandle(handle); }
    }
}
'@
}
$manifest = Get-Content -Raw -Encoding UTF8 -LiteralPath (Join-Path $PSScriptRoot 'close-tool-processes.json') | ConvertFrom-Json
$toolNames = @($manifest.processNames)
$allowedExecutables = @($manifest.executables)
$coreNames = @('ida', 'ida64', 'idat', 'idat64', 'x32dbg', 'x64dbg', 'x96dbg', 'dnSpy', 'ILSpy', 'die', 'diec', 'diel', 'cheatengine-x86_64', 'cheatengine-i386')
if ($ForceRemaining -and -not $Close) { throw '-ForceRemaining requires -Close.' }
$results = [System.Collections.Generic.List[object]]::new()
$candidates = @(Get-Process | Where-Object { $_.ProcessName -in $toolNames })

foreach ($candidate in $candidates) {
    $entry = [ordered]@{
        Name = $candidate.ProcessName
        Id = $candidate.Id
        Path = $null
        Status = 'Detected'
        Detail = ''
        _started = $null
    }
    try {
        $started = $candidate.StartTime.ToUniversalTime()
        $entry._started = $started
        $entry.Path = $candidate.Path
        if ([string]::IsNullOrWhiteSpace($entry.Path)) { $entry.Path = [RveProcessReadOnly]::ImagePath($candidate.Id) }
        if ([string]::IsNullOrWhiteSpace($entry.Path)) {
            $entry.Status = 'NeedsManualReview'
            $entry.Detail = 'Executable path could not be verified.'
        } elseif ($entry.Path -notin $allowedExecutables) {
            $entry.Status = $(if ($entry.Name -in $coreNames) { 'NeedsManualReview' } else { 'ExcludedDifferentExecutable' })
            $entry.Detail = 'Matching name outside the exact executable allowlist; not closed.'
        } elseif ([RveProcessReadOnly]::Critical($candidate.Id)) {
            $entry.Status = 'NeedsManualReview'
            $entry.Detail = 'Process is marked critical; stopping it may crash Windows. Not closed.'
        } elseif ($Close) {
            $current = Get-Process -Id $candidate.Id -ErrorAction SilentlyContinue
            if ($null -eq $current) {
                $entry.Status = 'AlreadyExited'
            } elseif ($current.StartTime.ToUniversalTime() -ne $started -or
                      [RveProcessReadOnly]::ImagePath($current.Id) -ne $entry.Path) {
                $entry.Status = 'NeedsManualReview'
                $entry.Detail = 'Process identity changed; no close request sent.'
            } elseif ($current.CloseMainWindow()) {
                $entry.Status = 'CloseRequested'
                $entry.Detail = 'Normal close requested; save any open work if prompted.'
                $entry['_process'] = $current
            } else {
                $entry.Status = 'NeedsManualClose'
                $entry.Detail = 'No closable main window; use the tool or session shutdown command.'
            }
        }
    } catch {
        $entry.Status = 'NeedsManualReview'
        $entry.Detail = $_.Exception.Message
    }
    $results.Add([pscustomobject]$entry)
}

# Use one shared deadline, rather than waiting the full timeout for each process.
$deadline = [DateTime]::UtcNow.AddSeconds($WaitSeconds)
foreach ($entry in $results) {
    if ($entry.Status -eq 'CloseRequested') {
        try {
            $remaining = [Math]::Max(0, [int]($deadline - [DateTime]::UtcNow).TotalMilliseconds)
            if ($entry._process.WaitForExit($remaining)) {
                $entry.Status = 'Exited'
                $entry.Detail = 'Process exited after a normal close request.'
            } else {
                $entry.Status = 'NeedsManualClose'
                $entry.Detail = 'Still running, possibly waiting for a save prompt. Not force-stopped.'
            }
        } catch {
            $entry.Status = 'NeedsManualReview'
            $entry.Detail = $_.Exception.Message
        }
    }
}

if ($Close -and $ForceRemaining) {
    foreach ($entry in $results) {
        if ($entry.Status -ne 'NeedsManualClose' -or $entry.Path -notin $allowedExecutables) { continue }
        try {
            $current = Get-Process -Id $entry.Id -ErrorAction SilentlyContinue
            if ($null -eq $current) {
                $entry.Status = 'AlreadyExited'
            } elseif ($current.StartTime.ToUniversalTime() -ne $entry._started -or [RveProcessReadOnly]::ImagePath($current.Id) -ne $entry.Path) {
                $entry.Status = 'NeedsManualReview'
                $entry.Detail = 'Process identity changed; not terminated.'
            } elseif ([RveProcessReadOnly]::Critical($current.Id)) {
                $entry.Status = 'NeedsManualReview'
                $entry.Detail = 'Process became critical; not terminated.'
            } else {
                Stop-Process -InputObject $current -Force -ErrorAction Stop
                if ($current.WaitForExit(3000)) {
                    $entry.Status = 'ForceExited'
                    $entry.Detail = 'Terminated the verified residual process on explicit cleanup request.'
                } else {
                    $entry.Status = 'NeedsManualReview'
                    $entry.Detail = 'Termination requested but process exit was not confirmed.'
                }
            }
        } catch {
            $entry.Status = 'NeedsManualReview'
            $entry.Detail = $_.Exception.Message
        }
    }
}

$unresolved = @($results | Where-Object { $_.Status -notin @('Exited', 'AlreadyExited', 'ForceExited', 'ExcludedDifferentExecutable') })
[pscustomobject]@{
    Mode = $(if ($Close) { 'RequestNormalClose' } else { 'InspectOnly' })
    MatchedProcesses = $results.Count
    ForceRemaining = [bool]$ForceRemaining
    UnresolvedProcesses = $unresolved.Count
    Processes = @($results | Select-Object Name, Id, Path, Status, Detail)
    Scope = "$($allowedExecutables.Count) recorded tool executable paths; no autorun or watchdog. Drivers, services and unrelated executables are excluded. No anti-cheat guarantee."
} | ConvertTo-Json -Depth 5

if ($unresolved.Count -gt 0) { exit 2 }

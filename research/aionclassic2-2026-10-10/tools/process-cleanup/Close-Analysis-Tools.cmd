@echo off
echo Closing recorded analysis tools. Save your work BEFORE using this button.
echo Remaining verified tool processes will be terminated after normal close.
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Enter-GameMode.ps1" -Close -ForceRemaining
set "rve_cleanup_result=%ERRORLEVEL%"
if not "%rve_cleanup_result%"=="0" echo Some processes need manual review. See the output above.
pause
exit /b %rve_cleanup_result%

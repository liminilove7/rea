@echo off
setlocal
rem Manual launch only. No RPC startup, game attachment, or autorun installation.
set "IDA_RESEARCH_ROOT=D:\TOOL\ANTI\IDA\IDA_Pro_v8.3_Portable"
if not exist "%IDA_RESEARCH_ROOT%\ida64.exe" exit /b 2
if not exist "%IDA_RESEARCH_ROOT%\python311\python3.dll" exit /b 3
if not exist "D:\RVE\.codex\local\aion-tw-20261019\Game-rea.i64" exit /b 4
set "PATH=%IDA_RESEARCH_ROOT%\python311;%IDA_RESEARCH_ROOT%;%PATH%"
set "PYTHONHOME=%IDA_RESEARCH_ROOT%\python311"
set "PYTHONPATH="
start "" /D "%IDA_RESEARCH_ROOT%" "%IDA_RESEARCH_ROOT%\ida64.exe" "D:\RVE\.codex\local\aion-tw-20261019\Game-rea.i64"
endlocal

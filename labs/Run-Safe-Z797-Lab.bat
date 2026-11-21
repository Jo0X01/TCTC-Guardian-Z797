@echo off
setlocal
cd /d "%~dp0"
where py >nul 2>nul
if not errorlevel 1 (
  py -3 safe_z797_lab.py prepare
) else (
  python safe_z797_lab.py prepare
)
if errorlevel 1 (
  echo.
  echo Safe lab preparation failed. No malware was run.
  pause
  exit /b 1
)
echo.
echo Now open TCTC Guardian and run a scan.
echo When finished, run Cleanup-Safe-Z797-Lab.bat.
pause

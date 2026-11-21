@echo off
setlocal
cd /d "%~dp0"
where py >nul 2>nul
if not errorlevel 1 (
  py -3 safe_z797_lab.py cleanup
) else (
  python safe_z797_lab.py cleanup
)
if errorlevel 1 pause

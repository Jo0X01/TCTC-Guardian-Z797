@echo off
setlocal
for %%I in ("%~dp0..") do set "PROJECT_ROOT=%%~fI"
pushd "%PROJECT_ROOT%"

rem Sysmon is checked and installed by the application itself on startup.
if exist "%PROJECT_ROOT%\dist\TCTC-Guardian-Z797.dist\TCTC-Guardian-Z797.exe" (
  "%PROJECT_ROOT%\dist\TCTC-Guardian-Z797.dist\TCTC-Guardian-Z797.exe"
) else if exist "%PROJECT_ROOT%\TCTC-Guardian-Z797.exe" (
  "%PROJECT_ROOT%\TCTC-Guardian-Z797.exe"
) else (
  where py >nul 2>nul
  if errorlevel 1 (
    python "%PROJECT_ROOT%\src\main.py"
  ) else (
    py -3 "%PROJECT_ROOT%\src\main.py"
  )
)
set "APP_EXIT=%ERRORLEVEL%"
if not "%APP_EXIT%"=="0" (
  echo.
  echo TCTC Guardian Z797 stopped with exit code %APP_EXIT%. Review the message above.
  pause
)
popd
exit /b %APP_EXIT%

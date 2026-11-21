@echo off
setlocal EnableExtensions

for %%I in ("%~dp0..") do set "PROJECT_ROOT=%%~fI"
pushd "%PROJECT_ROOT%"
if errorlevel 1 goto push_failed

set "PUSHD_OK=1"

where py >nul 2>nul
if not errorlevel 1 (
    set "PY=py -3"
) else (
    set "PY=python"
)

set "PYTHONPATH=%PROJECT_ROOT%\src"
set "OUTPUT_DIR=%PROJECT_ROOT%\bin"
set "OUTPUT_EXE=%OUTPUT_DIR%\TCTC-Guardian-Z797.exe"
set "WORK_DIR=%TEMP%\TCTC-Guardian-Z797-Nuitka"
set "WORK_EXE=%WORK_DIR%\TCTC-Guardian-Z797.exe"

echo.
echo ==========================================
echo       TCTC Guardian Z797 - Onefile
echo ==========================================

echo.
echo [1/5] Checking Python...
call %PY% --version
if errorlevel 1 goto failed

echo.
echo [2/5] Installing build dependencies...
call %PY% -m pip install --upgrade -r "%PROJECT_ROOT%\requirements.txt" nuitka zstandard
if errorlevel 1 goto failed

echo.
echo [3/5] Preparing output directories...

if not exist "%OUTPUT_DIR%" mkdir "%OUTPUT_DIR%"
if errorlevel 1 goto failed

if exist "%WORK_DIR%" rmdir /s /q "%WORK_DIR%"
if exist "%WORK_DIR%" (
    echo ERROR: Cannot clean temporary build directory.
    goto failed
)

mkdir "%WORK_DIR%"
if errorlevel 1 goto failed

echo.
echo [4/5] Compiling single-file executable...

call %PY% -m nuitka --onefile --remove-output --enable-plugin=pyside6 --include-package=guardian --include-package=watchdog --windows-console-mode=disable --windows-uac-admin --windows-icon-from-ico=assets\app-icon.ico --include-data-dir=assets=assets --include-data-file=src\Sysmon-TCTC-Z797.xml=Sysmon-TCTC-Z797.xml --output-dir="%WORK_DIR%" --output-filename=TCTC-Guardian-Z797.exe src\main.py

if errorlevel 1 goto failed

if not exist "%WORK_EXE%" (
    echo ERROR: Nuitka executable was not found.
    goto failed
)

echo.
echo [5/5] Installing final executable into bin...

move /y "%WORK_EXE%" "%OUTPUT_EXE%" >nul
if errorlevel 1 goto failed

if not exist "%OUTPUT_EXE%" (
    echo ERROR: Final executable was not created.
    goto failed
)

echo.
echo Cleaning temporary build files...
if exist "%WORK_DIR%" rmdir /s /q "%WORK_DIR%"

echo Removing obsolete project build directories...

if exist "%PROJECT_ROOT%\dist" (
    rmdir /s /q "%PROJECT_ROOT%\dist"
)

if exist "%PROJECT_ROOT%\build" (
    rmdir /s /q "%PROJECT_ROOT%\build"
)

echo.
echo ==========================================
echo             BUILD COMPLETE
echo ==========================================
echo.
echo Final executable:
echo %OUTPUT_EXE%
echo.
echo Only the final EXE is required for distribution.
echo Test the GUI and bundled resources on Windows.
echo.

popd
set "PUSHD_OK="
pause
exit /b 0

:failed
set "BUILD_EXIT=%ERRORLEVEL%"
if "%BUILD_EXIT%"=="0" set "BUILD_EXIT=1"

echo.
echo ==========================================
echo              BUILD FAILED
echo ==========================================
echo Exit code: %BUILD_EXIT%
echo Temporary build files, if any, are at:
echo %WORK_DIR%

if defined PUSHD_OK (
    popd
    set "PUSHD_OK="
)

pause
exit /b %BUILD_EXIT%

:push_failed
echo ERROR: Could not enter project directory.
pause
exit /b 1